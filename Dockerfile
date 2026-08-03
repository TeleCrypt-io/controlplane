# Exact version tag by operator policy; upgrade deliberately after validation.
FROM golang:1.26.4-alpine AS controlplane-build

# janitor's SMTP digest (net/smtp + STARTTLS) verifies the mail server's real TLS
# certificate, which needs a CA trust store — explicitly installed here rather than assumed
# present in the base image, so the runtime COPY below is guaranteed a real file to copy.
RUN apk add --no-cache ca-certificates

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/redpill ./cmd/redpill
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/janitor ./cmd/janitor
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/cashier ./cmd/cashier
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/steward ./cmd/steward

# The tier controller belongs to the control plane but runs in-process in Synapse. Keep the
# Synapse version exact: the controller uses callbacks and database tables validated against this
# release. The module is baked into the image instead of mounted from the server configuration or
# installed at startup, so an exact image tag is a complete, reproducible release artifact.
FROM ghcr.io/dotwee/matrix-synapse-s3:v1.155.0 AS synapse-tier-controller
COPY --chown=991:991 synapse/tier_controller /modules/tier_controller
ENV PYTHONPATH=/modules
USER 991:991

# Runtime: scratch — no shell, no package manager. The public control-plane image ships redpill,
# janitor, the transitional legacy cashier binary, and Plan. Production will invoke `/plan`; the
# private Cashier image owns the billing service.
# redpill needs no CA trust store (MAS is reached over plain HTTP on the internal telecrypt_net
# network) but janitor's SMTP digest does, so the bundle is copied in even though redpill itself
# never touches it.
#
# This must remain the final/default target. The Synapse module image is built explicitly with
# `--target synapse-tier-controller` and is published as a separate package.
# ENTRYPOINT defaults to redpill — deploying janitor or cashier means overriding the command on this
# same image, e.g. `docker run ... ghcr.io/telecrypt-io/telecrypt-controlplane:<release> /janitor`.
FROM scratch AS controlplane
COPY --from=controlplane-build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=controlplane-build /out/redpill /redpill
COPY --from=controlplane-build /out/janitor /janitor
COPY --from=controlplane-build /out/cashier /cashier
COPY --from=controlplane-build /out/steward /steward
USER 991:991
ENTRYPOINT ["/redpill"]
