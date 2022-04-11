#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <openssl/evp.h>

static ngx_int_t ngx_http_jwted_post_conf(ngx_conf_t *cf);
static void *ngx_http_jwted_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_jwted_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_jwted_handler(ngx_http_request_t *req);
static ngx_str_t decode_base64(ngx_http_request_t *req, ngx_str_t b64_s);
static ngx_str_t decode_base64url(ngx_http_request_t *req, ngx_str_t b64url_s);

typedef struct
{
    ngx_flag_t flag;
    ngx_str_t public_key;
} ngx_http_jwted_loc_conf_t;

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
    NULL, // preconfiguration
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
    payload.len = (p_last_dot - token.data);

    ngx_str_t signature;
    signature.data = p_last_dot + 1;
    signature.len = token.len - payload.len - 1;

    ngx_str_t binary_signature = decode_base64url(req, signature);
    if (binary_signature.len == 0) {
        ngx_log_error(NGX_LOG_ERR, req->connection->log, 0, "Failed to decode signature");
        return NGX_HTTP_UNAUTHORIZED;
    }

    if (conf->public_key.len == 0) {
        ngx_log_error(NGX_LOG_ERR, req->connection->log, 0, "Public key was not specified! Please use `auth_jwt_key`");
        return NGX_HTTP_UNAUTHORIZED;
    }

    ngx_str_t binary_pubkey = decode_base64(req, conf->public_key);
    if (binary_pubkey.len != 32) {
        ngx_log_error(NGX_LOG_ERR, req->connection->log, 0, "`auth_jwt_key` has invalid value! It should be a 32 bytes Ed25519 public key, encoded in base64");
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
    return NGX_DECLINED;
}

static ngx_str_t decode_base64(ngx_http_request_t *req, ngx_str_t b64_s)
{
    u_int padding = b64_s.len > 0 ? *(b64_s.data + b64_s.len - 1) == '=' : 0;
    padding += b64_s.len > 1 ? *(b64_s.data + b64_s.len - 2) == '=' : 0;

    u_int buf_size = 3 * b64_s.len / 4;
    u_char *buf = ngx_pcalloc(req->pool, buf_size + 1);
    int result = EVP_DecodeBlock(buf, b64_s.data, b64_s.len);

    ngx_str_t decoded = ngx_null_string;
    if (result <= 0)
        return decoded;
    decoded.data = buf;
    decoded.len = result - padding;
    return decoded;
}

static ngx_str_t decode_base64url(ngx_http_request_t *req, ngx_str_t b64url_s)
{
    ngx_str_t b64_s;
    int padding = b64url_s.len % 4 == 0 ? 0 : 4 - b64url_s.len % 4;
    b64_s.len = b64url_s.len + padding;
    b64_s.data = ngx_pcalloc(req->pool, b64_s.len);

    uint i;
    for (i = 0; i < b64_s.len; i++)
    {
        if (i >= b64url_s.len)
            b64_s.data[i] = '=';
        else if (b64url_s.data[i] == '-')
            b64_s.data[i] = '+';
        else if (b64url_s.data[i] == '_')
            b64_s.data[i] = '/';
        else
            b64_s.data[i] = b64url_s.data[i];
    }

    return decode_base64(req, b64_s);
}
