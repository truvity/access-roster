# One generic image for every executable of sluis on the local installation (decision D-9 of the first working
# version): a static binary on distroless static, as the nonroot user by default. Compose runs each container as its
# pinned uid (user:), so the image's own user never matters. `just local-up` builds the binaries (deploy/local/build.sh)
# and then one image per binary, with BINARY as the path below dist/local/bin, for example actors/store.
#
# The base is pinned by digest: gcr.io/distroless/static-debian12:nonroot, MEASURED 2026-11-04.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
ARG BINARY
COPY --chmod=0555 ${BINARY} /sluis
ENTRYPOINT ["/sluis"]
