#!/bin/bash

VERSION=1.19.9.1
SCRIPT_PATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

cd /build/openresty-$VERSION \
    && make -j2 \
    && sudo cp build/nginx-1.19.9/objs/nginx /usr/sbin/nginx \
    && sudo nginx -p $SCRIPT_PATH/test/ -c $SCRIPT_PATH/test/nginx.conf
