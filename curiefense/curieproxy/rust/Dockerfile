# build container
FROM ubuntu:18.04

RUN apt-get update && \
    apt-get dist-upgrade -y && \
    apt-get -yq --no-install-recommends install \
        curl ca-certificates libhyperscan-dev \
        gcc pkg-config libssl-dev libluajit-5.1-dev python2.7 clang-10 libclang1-10 \
        luarocks libpcre2-dev libgeoip-dev make unzip luajit
RUN ln -s /usr/bin/python2.7 /usr/bin/python2

RUN luarocks install lrexlib-pcre2 && \
    luarocks install lua-cjson && \
    luarocks install lua-resty-string && \
    luarocks install luafilesystem && \
    luarocks install luasocket && \
    luarocks install redis-lua && \
    luarocks install compat53 && \
    luarocks install mmdblua && \
    luarocks install luaipc && \
    luarocks install lua-resty-injection

RUN useradd -m -s /bin/bash builder
USER builder
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="/home/builder/.cargo/bin:${PATH}"
RUN mkdir /home/builder/rust && mkdir /home/builder/lua && mkdir /home/builder/.cargo/registry
