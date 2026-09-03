# The published image: the release binary and nothing else.
#
# There is no compiler here and nothing to compile. The build context is the
# two binaries the release workflow's build jobs produce - statically linked
# against musl, so nothing else has to be in the image - and `docker buildx`
# picks the one matching the platform it is assembling. Building this from a
# checkout on its own will not work; see .github/workflows/release.yml.
#
# shb needs io_uring, which Docker's default seccomp profile denies. Run it
# with `--security-opt seccomp=unconfined`, or it will say so and stop.
FROM scratch
ARG TARGETARCH
COPY shb-linux-$TARGETARCH /shb
ENTRYPOINT ["/shb"]
