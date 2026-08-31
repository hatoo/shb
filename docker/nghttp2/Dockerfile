# nghttp2's own proxy, which is two implementations in one build: nghttp2 is
# the HTTP/2 reference implementation, and its HTTP/3 support is ngtcp2 plus
# nghttp3. Neither is otherwise reachable except through a public test server.
#
# The QUIC side needs a TLS library with the QUIC API. OpenSSL 3.5 has one, so
# it is built here rather than taken from the distribution, which is still on
# 3.0.
FROM ubuntu:24.04 AS build
RUN apt-get update && apt-get install --yes --no-install-recommends \
        autoconf automake ca-certificates cmake g++-14 git libc-ares-dev \
        libev-dev libtool make perl pkg-config zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# nghttp2 uses <print>, so it needs C++23 and a compiler that has it. Noble
# ships GCC 13 as its default and GCC 14 as a package, which is the smaller
# change of the two available.
ENV CC=gcc-14 CXX=g++-14

ARG PREFIX=/opt/nghttp2
ENV PKG_CONFIG_PATH=$PREFIX/lib/pkgconfig
ENV LD_LIBRARY_PATH=$PREFIX/lib

RUN git clone --depth 1 -b openssl-3.5.8 https://github.com/openssl/openssl /src/openssl \
    && cd /src/openssl \
    && ./Configure --prefix=$PREFIX --libdir=lib no-docs no-tests shared \
    && make -j"$(nproc)" && make install_sw

RUN git clone --depth 1 --recursive https://github.com/ngtcp2/nghttp3 /src/nghttp3 \
    && cmake -S /src/nghttp3 -B /src/nghttp3/b -DCMAKE_INSTALL_PREFIX=$PREFIX \
        -DENABLE_LIB_ONLY=ON -DCMAKE_BUILD_TYPE=Release \
    && cmake --build /src/nghttp3/b -j"$(nproc)" && cmake --install /src/nghttp3/b

RUN git clone --depth 1 --recursive https://github.com/ngtcp2/ngtcp2 /src/ngtcp2 \
    && cmake -S /src/ngtcp2 -B /src/ngtcp2/b -DCMAKE_INSTALL_PREFIX=$PREFIX \
        -DCMAKE_PREFIX_PATH=$PREFIX -DOPENSSL_ROOT_DIR=$PREFIX \
        -DENABLE_OPENSSL=ON -DENABLE_LIB_ONLY=ON -DCMAKE_BUILD_TYPE=Release \
    && cmake --build /src/ngtcp2/b -j"$(nproc)" && cmake --install /src/ngtcp2/b

RUN git clone --depth 1 -b v1.70.0 --recurse-submodules --shallow-submodules https://github.com/nghttp2/nghttp2 /src/nghttp2 \
    && cmake -S /src/nghttp2 -B /src/nghttp2/b -DCMAKE_INSTALL_PREFIX=$PREFIX \
        -DCMAKE_PREFIX_PATH=$PREFIX -DOPENSSL_ROOT_DIR=$PREFIX \
        -DENABLE_APP=ON -DENABLE_HTTP3=ON -DCMAKE_BUILD_TYPE=Release \
    && cmake --build /src/nghttp2/b -j"$(nproc)" && cmake --install /src/nghttp2/b

FROM ubuntu:24.04
RUN apt-get update && apt-get install --yes --no-install-recommends \
        libc-ares2 libev4t64 libstdc++6 zlib1g \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /opt/nghttp2 /opt/nghttp2
ENV LD_LIBRARY_PATH=/opt/nghttp2/lib
EXPOSE 443
