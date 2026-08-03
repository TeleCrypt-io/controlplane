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
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/steward ./cmd/steward

# Runtime: scratch — no shell, no package manager. The public control-plane image ships redpill,
# janitor, and Steward. The private Cashier image owns all billing service code and Dodo access.
# redpill needs no CA trust store (MAS is reached over plain HTTP on the internal telecrypt_net
# network) but janitor's SMTP digest does, so the bundle is copied in even though redpill itself
# never touches it.
#
# The tier controller is intentionally absent from this image. GitHub Actions releases it only as a
# wheel; the standalone telecrypt-synapse builder downloads that exact release asset and verifies
# its checksum.
#
# CMD defaults to the Redpill component. It is a default, rather than an ENTRYPOINT, because this
# one image contains three separately deployed components; Janitor and Steward replace CMD.
FROM scratch AS controlplane
COPY --from=controlplane-build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=controlplane-build /out/redpill /redpill
COPY --from=controlplane-build /out/janitor /janitor
COPY --from=controlplane-build /out/steward /steward
USER 991:991
CMD ["/redpill"]
