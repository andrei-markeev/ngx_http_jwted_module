# See here for image contents: https://github.com/microsoft/vscode-dev-containers/tree/v0.231.5/containers/debian/.devcontainer/base.Dockerfile

# [Choice] Debian version (use bullseye on local arm64/Apple Silicon): bullseye, buster
ARG VARIANT="buster"
FROM mcr.microsoft.com/vscode/devcontainers/base:0-${VARIANT}

RUN apt-get update \
    && export DEBIAN_FRONTEND=noninteractive \
    && apt-get install -y \
        libtemplate-perl \
        perl \
        gnupg \
        curl \
        make \
        build-essential \
        wget \
        systemtap-sdt-dev

RUN wget -O - https://openresty.org/package/pubkey.gpg | apt-key add - \
    && echo "deb http://openresty.org/package/debian buster openresty" | tee /etc/apt/sources.list.d/openresty.list \
    && apt-get update \
    && apt-get -y -qq install \
        openresty-zlib-dev \
        openresty-pcre-dev \
        openresty-openssl111-dev

RUN mkdir -p /build
WORKDIR /build

ARG VERSION=1.19.9.1
RUN wget https://openresty.org/download/openresty-${VERSION}.tar.gz \
    && tar xfz openresty-$VERSION.tar.gz
