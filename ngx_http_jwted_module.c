#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <openssl/evp.h>

static ngx_int_t ngx_http_jwted_pre_conf(ngx_conf_t *cf);
static ngx_int_t ngx_http_jwted_post_conf(ngx_conf_t *cf);
static void *ngx_http_jwted_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_jwted_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_http_jwted_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_jwted_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static char *ngx_http_jwted_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_jwted_set_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_jwted_cache_zone_init(ngx_shm_zone_t *shm_zone, void *data);
static ngx_int_t ngx_http_jwted_handler(ngx_http_request_t *req);
static ngx_int_t ngx_http_jwted_expose_claims(ngx_http_request_t *req, ngx_str_t token);
static ngx_int_t ngx_http_jwted_claims_getter(ngx_http_request_t *req, ngx_http_variable_value_t *value, uintptr_t var_name);
static ngx_int_t ngx_http_jwted_cache_token(ngx_http_request_t *req, ngx_str_t token);
static void ngx_http_jwted_free_cache_locked(ngx_queue_t *cache_expire_queue, ngx_rbtree_t *cache_tree, ngx_slab_pool_t *shpool);

typedef struct
{
    ngx_flag_t cache_enabled;
    ssize_t cache_size;
    ngx_shm_zone_t *shm_zone;
} ngx_http_jwted_main_conf_t;

typedef struct
{
    ngx_int_t flag;
    ngx_http_complex_value_t *token_cv;
    ngx_str_t public_key;
} ngx_http_jwted_loc_conf_t;

typedef struct
{
    ngx_str_t claims_json;
} ngx_http_jwted_data_t;

typedef struct
{
    ngx_rbtree_t cache_tree;
    ngx_rbtree_node_t cache_tree_sentinel;
    ngx_queue_t cache_expire_queue;
} ngx_http_jwted_shared_data_t;

typedef struct
{
    ngx_str_node_t *str_node;
    ngx_queue_t queue_item;
} ngx_http_jwted_queue_data_t;

static ngx_command_t ngx_http_jwted_commands[] = {
    {ngx_string("auth_jwt"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_http_jwted_set,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_jwted_loc_conf_t, flag),
     NULL},
    {ngx_string("auth_jwt_key"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_jwted_loc_conf_t, public_key),
     NULL},
    {ngx_string("auth_jwt_cache"),
     NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE12,
     ngx_http_jwted_set_cache,
     NGX_HTTP_MAIN_CONF_OFFSET,
     0,
     NULL},
    ngx_null_command};

static ngx_http_module_t ngx_http_jwted_module_ctx = {
    ngx_http_jwted_pre_conf,
    ngx_http_jwted_post_conf,
    ngx_http_jwted_create_main_conf,
    ngx_http_jwted_init_main_conf,
    NULL, // create server configuration
    NULL, // merge server configuration
    ngx_http_jwted_create_loc_conf,
    ngx_http_jwted_merge_loc_conf};

ngx_module_t ngx_http_jwted_module = {
    NGX_MODULE_V1,
    &ngx_http_jwted_module_ctx,
    ngx_http_jwted_commands,
    NGX_HTTP_MODULE,
    NULL, // init master
    NULL, // init module
    NULL, // init process
    NULL, // init thread
    NULL, // exit thread
    NULL, // exit process
    NULL, // exit master
    NGX_MODULE_V1_PADDING};

ngx_str_t var_name_jwt_claim = ngx_string("jwt_claims");
static ngx_int_t ngx_http_jwted_pre_conf(ngx_conf_t *cf)
{
    ngx_http_variable_t *var = ngx_http_add_variable(cf, &var_name_jwt_claim, 0);
    if (var == NULL)
        return NGX_ERROR;
    var->get_handler = ngx_http_jwted_claims_getter;
    var->data = 0;

    return NGX_OK;
}

static ngx_int_t ngx_http_jwted_post_conf(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t *core_conf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    ngx_http_handler_pt *h = ngx_array_push(&core_conf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL)
        return NGX_ERROR;

    *h = ngx_http_jwted_handler;

    return NGX_OK;
}

static char *ngx_http_jwted_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_jwted_loc_conf_t *loc_conf = conf;
    ngx_str_t *value = cf->args->elts;

    if (cf->args->nelts > 2) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "Only 1 argument is supported for `auth_jwt`");
        return NGX_CONF_ERROR;
    }

    if (ngx_strcmp(value[1].data, "on") == 0)
        loc_conf->flag = 1;
    else if (ngx_strcmp(value[1].data, "off") == 0)
        loc_conf->flag = 0;
    else {
        loc_conf->flag = 2;

        loc_conf->token_cv = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
        if (loc_conf->token_cv == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "Failed to allocate memory for compiling complex argument of `auth_jwt`");
            return NGX_CONF_ERROR;
        }

        ngx_http_compile_complex_value_t ccv;
        ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &value[1];
        ccv.complex_value = loc_conf->token_cv;

        if (ngx_http_compile_complex_value(&ccv) != NGX_OK)
            return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

ngx_str_t cache_zone_name = ngx_string("jwted_cache");
static char *ngx_http_jwted_set_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_jwted_main_conf_t *main_conf = conf;
    ngx_str_t *value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0)
    {
        main_conf->cache_enabled = 0;
        return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[1].data, "on") != 0)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "First parameter of `auth_jwt_cache` must be either \"on\" or \"off\"");
        return NGX_CONF_ERROR;
    }

    main_conf->cache_enabled = 1;
    main_conf->cache_size = ngx_align(256 * 1024, ngx_pagesize);

    ngx_uint_t i;
    ngx_str_t s;
    for (i = 2; i < cf->args->nelts; i++)
    {

        if (ngx_strncmp(value[i].data, "size=", 5) == 0)
        {
            s.data = value[i].data + 5;
            s.len = value[i].len - 5;
            main_conf->cache_size = ngx_parse_size(&s);

            if (main_conf->cache_size < (ssize_t)ngx_pagesize)
            {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "Invalid `auth_jwt_cache` size \"%V\"! Should be >=%d bytes", &value[i], ngx_pagesize);
                return NGX_CONF_ERROR;
            }

            main_conf->cache_size = 4 * ngx_pagesize + ngx_align(main_conf->cache_size, ngx_pagesize);
            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "Invalid parameter \"%V\"! Expected \"size=<size>\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    ngx_shm_zone_t *shm_zone = ngx_shared_memory_add(cf, &cache_zone_name, main_conf->cache_size, &ngx_http_jwted_module);
    if (shm_zone == NULL)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "Error adding shared memory zone for `auth_jwt_cache`");
        return NGX_CONF_ERROR;
    }

    shm_zone->init = ngx_http_jwted_cache_zone_init;

    main_conf->shm_zone = shm_zone;

    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_jwted_cache_zone_init(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_slab_pool_t *shpool = (ngx_slab_pool_t *)shm_zone->shm.addr;
    if (shm_zone->shm.exists)
    {
        shm_zone->data = shpool->data;
        return NGX_OK;
    }

    ngx_http_jwted_shared_data_t *shared_data = ngx_slab_alloc(shpool, sizeof(ngx_http_jwted_shared_data_t));
    if (!shared_data)
        return NGX_ERROR;

    ngx_rbtree_init(&shared_data->cache_tree, &shared_data->cache_tree_sentinel, ngx_str_rbtree_insert_value);

    ngx_queue_init(&shared_data->cache_expire_queue);

    shm_zone->data = shared_data;
    shpool->data = shared_data;
    shpool->log_nomem = 0;

    return NGX_OK;
}

static void *ngx_http_jwted_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_jwted_main_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_jwted_main_conf_t));
    if (conf == NULL)
        return NULL;

    conf->cache_enabled = NGX_CONF_UNSET;
    conf->cache_size = NGX_CONF_UNSET_SIZE;

    return conf;
}

static char *ngx_http_jwted_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_jwted_main_conf_t *main_conf = conf;

    ngx_conf_init_value(main_conf->cache_enabled, 0);
    ngx_conf_init_value(main_conf->cache_size, 256 * 1024);

    return NGX_CONF_OK;
}

static void *ngx_http_jwted_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_jwted_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_jwted_loc_conf_t));
    if (conf == NULL)
        return NULL;

    conf->flag = NGX_CONF_UNSET;
    ngx_str_null(&conf->public_key);

    return conf;
}

static char *ngx_http_jwted_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_jwted_loc_conf_t *prev = parent;
    ngx_http_jwted_loc_conf_t *next = child;

    if (next->flag == NGX_CONF_UNSET) {
        if (prev->flag == NGX_CONF_UNSET)
            next->flag = 0;
        else {
            next->flag = prev->flag;
            next->token_cv = prev->token_cv;
        }
    }
    ngx_conf_merge_str_value(next->public_key, prev->public_key, "");

    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_jwted_handler(ngx_http_request_t *req)
{
    ngx_http_jwted_main_conf_t *main_conf = ngx_http_get_module_main_conf(req, ngx_http_jwted_module);
    ngx_http_jwted_loc_conf_t *conf = ngx_http_get_module_loc_conf(req, ngx_http_jwted_module);

    if (!conf->flag)
        return NGX_DECLINED;

    if (req->method == NGX_HTTP_OPTIONS)
        return NGX_DECLINED;

    ngx_str_t token;
    if (conf->flag == 1) {
        if (!req->headers_in.authorization)
            return NGX_HTTP_UNAUTHORIZED;

        if (ngx_strncmp(req->headers_in.authorization->value.data, "Bearer ", 7) != 0)
            return NGX_HTTP_UNAUTHORIZED;

        token.data = req->headers_in.authorization->value.data + 7;
        token.len = req->headers_in.authorization->value.len - 7;
    } else {
        if (ngx_http_complex_value(req, conf->token_cv, &token) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, req->connection->log, 0, "Failed to get token from the complex variable defined by `auth_jwt`");
            return NGX_HTTP_UNAUTHORIZED;
        }

        if (token.len == 0)
            return NGX_HTTP_UNAUTHORIZED;
    }

    u_char *p_last_dot = token.data + token.len;
    while (p_last_dot > token.data)
    {
        if (*p_last_dot == '.')
            break;

        p_last_dot--;
    }

    if (p_last_dot == token.data)
        return NGX_HTTP_UNAUTHORIZED;

    ngx_str_t payload;
    payload.data = token.data;
    payload.len = p_last_dot - token.data;

    if (main_conf->cache_enabled)
    {
        uint32_t hash = ngx_crc32_long(token.data, token.len);
        ngx_http_jwted_shared_data_t *shared_data = (ngx_http_jwted_shared_data_t *)main_conf->shm_zone->data;
        ngx_slab_pool_t *shpool = (ngx_slab_pool_t *)main_conf->shm_zone->shm.addr;
        ngx_shmtx_lock(&shpool->mutex);
        ngx_str_node_t *found_node = ngx_str_rbtree_lookup(&shared_data->cache_tree, &token, hash);
        ngx_shmtx_unlock(&shpool->mutex);
        if (found_node != NULL)
        {
            ngx_http_jwted_expose_claims(req, payload);
            return NGX_DECLINED;
        }
    }

    ngx_str_t signature;
    signature.data = p_last_dot + 1;
    signature.len = token.len - payload.len - 1;

    if (conf->public_key.len == 0)
    {
        ngx_log_error(NGX_LOG_ERR, req->connection->log, 0, "Public key was not specified! Please use `auth_jwt_key`");
        return NGX_HTTP_UNAUTHORIZED;
    }

    ngx_str_t binary_pubkey;
    binary_pubkey.len = ngx_base64_decoded_length(conf->public_key.len);
    binary_pubkey.data = ngx_pcalloc(req->pool, binary_pubkey.len);
    if (binary_pubkey.data == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, req->connection->log, 0, "Failed to allocate memory for decoding public key");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_int_t decode_result = ngx_decode_base64(&binary_pubkey, &conf->public_key);
    if (decode_result == NGX_ERROR)
    {
        ngx_log_error(NGX_LOG_ERR, req->connection->log, 0, "`auth_jwt_key` has invalid value! It should be a 32 bytes Ed25519 public key, encoded in base64");
        return NGX_HTTP_UNAUTHORIZED;
    }

    ngx_str_t binary_signature;
    binary_signature.len = ngx_base64_decoded_length(signature.len);
    binary_signature.data = ngx_pcalloc(req->pool, binary_signature.len);
    if (binary_signature.data == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, req->connection->log, 0, "Failed to allocate memory for decoding JWT token signature");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    decode_result = ngx_decode_base64url(&binary_signature, &signature);
    if (decode_result == NGX_ERROR)
    {
        ngx_log_error(NGX_LOG_ERR, req->connection->log, 0, "Failed to decode JWT token signature, invalid input");
        return NGX_HTTP_UNAUTHORIZED;
    }

    EVP_PKEY *pkey;
    pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, binary_pubkey.data, binary_pubkey.len);
    if (!pkey)
    {
        ngx_log_error(NGX_LOG_ERR, req->connection->log, 0, "EVP_PKEY_new_raw_public_key returned NULL");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    EVP_MD_CTX *ctx;
    ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        ngx_log_error(NGX_LOG_ERR, req->connection->log, 0, "EVP_MD_CTX_new returned NULL");
        EVP_PKEY_free(pkey);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    int verify_init_result = EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey);
    if (verify_init_result <= 0)
    {
        ngx_log_error(NGX_LOG_ERR, req->connection->log, 0, "EVP_DigestVerifyInit returned %d", verify_init_result);
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(ctx);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (!EVP_DigestVerify(ctx, binary_signature.data, binary_signature.len, payload.data, payload.len))
    {
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(ctx);
        return NGX_HTTP_UNAUTHORIZED;
    }

    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(ctx);

    if (main_conf->cache_enabled)
        ngx_http_jwted_cache_token(req, token);

    return ngx_http_jwted_expose_claims(req, payload);
}

static ngx_int_t ngx_http_jwted_expose_claims(ngx_http_request_t *req, ngx_str_t payload)
{
    u_char *p_dot = ngx_strlchr(payload.data, payload.data + payload.len, '.');
    if (p_dot == NULL)
        return NGX_HTTP_UNAUTHORIZED;

    ngx_str_t claims;
    claims.data = p_dot + 1;
    claims.len = payload.data + payload.len - p_dot - 1;

    ngx_str_t decoded_claims;
    decoded_claims.len = ngx_base64_decoded_length(claims.len);
    decoded_claims.data = ngx_pcalloc(req->pool, decoded_claims.len);
    if (decoded_claims.data == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, req->connection->log, 0, "Failed to allocate decoded claims");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_int_t decode_result = ngx_decode_base64url(&decoded_claims, &claims);
    if (decode_result == NGX_ERROR)
    {
        ngx_log_error(NGX_LOG_ERR, req->connection->log, 0, "Failed to decode claims part of the token, even though signature verified");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_jwted_data_t *module_ctx_data = ngx_pcalloc(req->pool, sizeof(*module_ctx_data));
    if (module_ctx_data == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, req->connection->log, 0, "Failed to allocate module context");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    module_ctx_data->claims_json = decoded_claims;
    ngx_http_set_ctx(req, module_ctx_data, ngx_http_jwted_module);

    return NGX_DECLINED;
}

static ngx_int_t ngx_http_jwted_claims_getter(ngx_http_request_t *req, ngx_http_variable_value_t *value, uintptr_t var_name)
{
    ngx_http_jwted_data_t *data = ngx_http_get_module_ctx(req, ngx_http_jwted_module);
    value->not_found = 1;

    if (data == NULL || data->claims_json.len == 0)
        return NGX_OK;

    value->not_found = 0;
    value->data = data->claims_json.data;
    value->len = data->claims_json.len;
    value->valid = 1;

    return NGX_OK;
}

#define ngx_slab_alloc_locked_with_retry(shpool, shared_data, var, size) \
    var = ngx_slab_alloc_locked(shpool, size); \
    if (var == NULL) \
    { \
        ngx_http_jwted_free_cache_locked(&shared_data->cache_expire_queue, &shared_data->cache_tree, shpool); \
        var = ngx_slab_alloc_locked(shpool, size); \
    }

static ngx_int_t ngx_http_jwted_cache_token(ngx_http_request_t *req, ngx_str_t token)
{
    ngx_http_jwted_main_conf_t *main_conf = ngx_http_get_module_main_conf(req, ngx_http_jwted_module);
    ngx_http_jwted_shared_data_t *shared_data = (ngx_http_jwted_shared_data_t *)main_conf->shm_zone->data;
    ngx_slab_pool_t *shpool = (ngx_slab_pool_t *)main_conf->shm_zone->shm.addr;

    ngx_shmtx_lock(&shpool->mutex);
    ngx_str_node_t *str_node;
    ngx_slab_alloc_locked_with_retry(shpool, shared_data, str_node, sizeof(ngx_str_node_t));
    if (str_node == NULL)
    {
        ngx_shmtx_unlock(&shpool->mutex);
        ngx_log_error(NGX_LOG_ERR, req->connection->log, 0, "Failed to allocate memory for cache node");
        return NGX_ERROR;
    }
    uint32_t hash = ngx_crc32_long(token.data, token.len);
    str_node->node.key = hash;
    ngx_slab_alloc_locked_with_retry(shpool, shared_data, str_node->str.data, token.len);
    if (str_node->str.data == NULL)
    {
        ngx_slab_free_locked(shpool, str_node);
        ngx_shmtx_unlock(&shpool->mutex);
        ngx_log_error(NGX_LOG_ERR, req->connection->log, 0, "Failed to allocate memory for token cache");
        return NGX_ERROR;
    }
    ngx_memcpy(str_node->str.data, token.data, token.len);
    str_node->str.len = token.len;
    ngx_rbtree_insert(&shared_data->cache_tree, &str_node->node);

    ngx_http_jwted_queue_data_t *queue_data;
    ngx_slab_alloc_locked_with_retry(shpool, shared_data, queue_data, sizeof(ngx_http_jwted_queue_data_t));
    if (queue_data == NULL)
    {
        ngx_slab_free_locked(shpool, str_node->str.data);
        ngx_slab_free_locked(shpool, str_node);
        ngx_shmtx_unlock(&shpool->mutex);
        ngx_log_error(NGX_LOG_ERR, req->connection->log, 0, "Failed to allocate memory for cache queue data");
        return NGX_ERROR;
    }

    queue_data->str_node = str_node;
    ngx_queue_insert_head(&shared_data->cache_expire_queue, &queue_data->queue_item);

    ngx_shmtx_unlock(&shpool->mutex);

    return NGX_OK;
}

static void ngx_http_jwted_free_cache_locked(ngx_queue_t *cache_expire_queue, ngx_rbtree_t *cache_tree, ngx_slab_pool_t *shpool)
{
    if (ngx_queue_empty(cache_expire_queue))
        return;

    ngx_queue_t *last = ngx_queue_last(cache_expire_queue);
    ngx_http_jwted_queue_data_t *last_data = ngx_queue_data(last, ngx_http_jwted_queue_data_t, queue_item);
    ngx_queue_remove(last);

    ngx_rbtree_delete(cache_tree, &last_data->str_node->node);

    ngx_slab_free_locked(shpool, last_data->str_node->str.data);
    ngx_slab_free_locked(shpool, last_data->str_node);
    ngx_slab_free_locked(shpool, last_data);
}