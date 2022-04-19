#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <openssl/evp.h>

static ngx_int_t ngx_http_jwted_pre_conf(ngx_conf_t *cf);
static ngx_int_t ngx_http_jwted_post_conf(ngx_conf_t *cf);
static void *ngx_http_jwted_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_jwted_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_jwted_handler(ngx_http_request_t *req);
static ngx_int_t ngx_http_jwted_claims_getter(ngx_http_request_t *req, ngx_http_variable_value_t *value, uintptr_t var_name);

typedef struct
{
    ngx_flag_t flag;
    ngx_str_t public_key;
} ngx_http_jwted_loc_conf_t;

typedef struct
{
    ngx_str_t claims_json;
} ngx_http_jwted_data_t;

static ngx_command_t ngx_http_jwted_commands[] = {
    {ngx_string("auth_jwt"),
     NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_flag_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_jwted_loc_conf_t, flag),
     NULL},
    {ngx_string("auth_jwt_key"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_jwted_loc_conf_t, public_key),
     NULL},
    ngx_null_command};

static ngx_http_module_t ngx_http_jwted_module_ctx = {
    ngx_http_jwted_pre_conf,
    ngx_http_jwted_post_conf,
    NULL, // create main configuration
    NULL, // init main configuration
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
    ngx_http_variable_t* var = ngx_http_add_variable(cf, &var_name_jwt_claim, 0);
    if (var == NULL)
        return NGX_ERROR;
    var->get_handler = ngx_http_jwted_claims_getter;
    var->data = 0;

    return NGX_OK;
}

static ngx_int_t ngx_http_jwted_post_conf(ngx_conf_t *cf)
{
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL)
        return NGX_ERROR;

    *h = ngx_http_jwted_handler;

    return NGX_OK;
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

    ngx_conf_merge_value(next->flag, prev->flag, 0);
    ngx_conf_merge_str_value(next->public_key, prev->public_key, "");

    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_jwted_handler(ngx_http_request_t *req)
{
    ngx_http_jwted_loc_conf_t *conf;
    conf = ngx_http_get_module_loc_conf(req, ngx_http_jwted_module);

    if (!conf->flag)
        return NGX_DECLINED;

    if (req->method == NGX_HTTP_OPTIONS)
        return NGX_DECLINED;

    if (!req->headers_in.authorization)
        return NGX_HTTP_UNAUTHORIZED;

    if (ngx_strncmp(req->headers_in.authorization->value.data, "Bearer ", 7) != 0)
        return NGX_HTTP_UNAUTHORIZED;

    ngx_str_t token;
    token.data = req->headers_in.authorization->value.data + 7;
    token.len = req->headers_in.authorization->value.len - 7;

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

    ngx_str_t signature;
    signature.data = p_last_dot + 1;
    signature.len = token.len - payload.len - 1;

    if (conf->public_key.len == 0) {
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

    decode_result = ngx_decode_base64url(&decoded_claims, &claims);
    if (decode_result == NGX_ERROR)
    {
        ngx_log_error(NGX_LOG_ERR, req->connection->log, 0, "Failed to decode claims part of the token, even though signature verified");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_jwted_data_t *module_ctx_data = ngx_pcalloc(req->pool, sizeof(*module_ctx_data));
    if (ctx == NULL)
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
