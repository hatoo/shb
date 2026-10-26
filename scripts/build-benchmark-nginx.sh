#!/usr/bin/env bash
# Build the README benchmark server without installing system-wide.
set -euo pipefail
prefix=$(realpath -m "${1:-../nginx-h3}")
version=1.31.8
boringssl_revision=533902fb2e8fd0586db7d58879d697721726605a
jobs=${JOBS:-$(nproc)}
mkdir -p "$prefix/src"
cd "$prefix/src"
if [[ ! -f nginx-$version.tar.gz ]]; then
    curl -fL "https://nginx.org/download/nginx-$version.tar.gz" -o "nginx-$version.tar.gz"
fi
echo "0652b760b3b772d2ec17b47c2fc15d9a95e6fe35cd5b877eadc1a62d9bc75af1  nginx-$version.tar.gz" | sha256sum -c -
if [[ ! -d boringssl ]]; then
    git init boringssl
    git -C boringssl remote add origin https://boringssl.googlesource.com/boringssl
    git -C boringssl fetch --depth 1 origin "$boringssl_revision"
    git -C boringssl checkout --detach FETCH_HEAD
fi
test "$(git -C boringssl rev-parse HEAD)" = "$boringssl_revision"
cmake -S boringssl -B boringssl/build -GNinja -DCMAKE_BUILD_TYPE=Release
cmake --build boringssl/build --target ssl crypto -j "$jobs"
tar -xzf "nginx-$version.tar.gz"
cd "nginx-$version"
./configure --prefix="$prefix" \
    --with-http_ssl_module --with-http_v2_module --with-http_v3_module \
    --with-cc-opt='-O2 -I../boringssl/include' \
    --with-ld-opt='-L../boringssl/build -Wl,--no-as-needed -lstdc++'
make -j "$jobs"
make install
"$prefix/sbin/nginx" -V
