# Exact version tag by operator policy; upgrade deliberately after validation.
FROM golang:1.26.4-alpine AS build

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

# Runtime: scratch — no shell, no package manager. All three binaries ship in this one image
# (CI builds a single untargeted `docker build .`); redpill needs no CA trust store (MAS is reached
# over plain HTTP on the internal telecrypt_net network) but janitor's SMTP digest does, so the
# bundle is copied in even though redpill itself never touches it.
#
# ENTRYPOINT defaults to redpill — deploying janitor or cashier means overriding the command on this
# same image, e.g. `docker run ... ghcr.io/telecrypt-io/controlplane:0.2.0 /janitor`.
FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/redpill /redpill
COPY --from=build /out/janitor /janitor
COPY --from=build /out/cashier /cashier
USER 991:991
ENTRYPOINT ["/redpill"]
