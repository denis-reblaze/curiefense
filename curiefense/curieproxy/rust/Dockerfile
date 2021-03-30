FROM ubuntu:18.04


RUN apt-get update && \
    apt-get dist-upgrade -y && \
    apt-get -yq --no-install-recommends install \
        curl ca-certificates libhyperscan-dev \
        gcc pkg-config libssl-dev libluajit-5.1-dev python2.7 clang-10 libclang1-10 
RUN ln -s /usr/bin/python2.7 /usr/bin/python2

RUN useradd -m -s /bin/bash builder
USER builder
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="/home/builder/.cargo/bin:${PATH}"
RUN mkdir /home/builder/rust
RUN mkdir /home/builder/.cargo/registry
