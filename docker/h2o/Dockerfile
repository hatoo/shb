# H2O, built from source: the project publishes no server image, and its own
# Dockerfiles under misc/docker-ci are build environments rather than
# something to run. quicly and picotls come along as submodules, which is the
# point - quicly is a QUIC implementation nothing else in this suite covers.
FROM ubuntu:24.04 AS build
RUN apt-get update && apt-get install --yes --no-install-recommends \
        ca-certificates cmake g++ git libssl-dev libuv1-dev make ninja-build \
        pkg-config zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --recurse-submodules --shallow-submodules \
        https://github.com/h2o/h2o.git /src
WORKDIR /src
# mruby is a scripting extension shb has no use for and the slowest part of
# the build
RUN cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DWITH_MRUBY=OFF . \
    && ninja h2o

FROM ubuntu:24.04
RUN apt-get update && apt-get install --yes --no-install-recommends \
        libssl3t64 libuv1 zlib1g \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/h2o /usr/local/bin/h2o
EXPOSE 443
CMD ["h2o", "-c", "/conf/h2o.conf"]
