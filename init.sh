#!/bin/bash

VERSION=1.19.9.1
MODULE_PATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

cd /build/openresty-$VERSION \
    && ./configure \
        --prefix=/usr/share/nginx \
        -j2 \
        --with-cc-opt="-DNGX_LUA_ABORT_AT_PANIC -I/usr/local/openresty/zlib/include -I/usr/local/openresty/pcre/include -I/usr/local/openresty/openssl111/include" \
        --with-ld-opt="-L/usr/local/openresty/zlib/lib -L/usr/local/openresty/pcre/lib -L/usr/local/openresty/openssl111/lib -Wl,-rpath,/usr/local/openresty/zlib/lib:/usr/local/openresty/pcre/lib:/usr/local/openresty/openssl111/lib" \
        --conf-path=/etc/nginx/nginx.conf \
        --error-log-path=/var/log/nginx/error.log \
        --http-client-body-temp-path=/var/lib/nginx/body \
        --http-log-path=/var/log/nginx/access.log \
        --http-proxy-temp-path=/var/lib/nginx/proxy \
        --lock-path=/var/lock/nginx.lock \
        --pid-path=/run/nginx.pid \
        --without-http_fastcgi_module \
        --without-http_scgi_module \
        --without-http_uwsgi_module \
        --without-lua_rds_parser \
        --without-http_rds_json_module \
        --without-http_rds_csv_module \
        --without-http_redis_module \
        --without-http_redis2_module \
        --with-pcre-jit \
        --with-http_ssl_module \
        --with-http_v2_module \
        --with-stream \
        --with-stream_ssl_module \
        --add-module=$MODULE_PATH \
    && make -j2 \
    && sudo make install \
    && sudo mv /usr/share/nginx/nginx/sbin/nginx /usr/sbin/nginx \
    && sudo rm -r /usr/share/nginx/nginx/sbin \
    && sudo rm /usr/share/nginx/bin/openresty \
    && sudo rm /usr/share/nginx/bin/restydoc* \
    && sudo rm /usr/share/nginx/bin/md2pod.pl \
    && sudo rm -r /usr/share/nginx/pod \
    && sudo rm /etc/nginx/fastcgi* \
    && sudo rm /etc/nginx/uwsgi* \
    && sudo rm /etc/nginx/scgi* \
    && sudo mv /usr/share/nginx/nginx/html /usr/share/nginx/html \
    && sudo rm -r /usr/share/nginx/nginx \
    && sudo mkdir -p /var/lib/nginx
