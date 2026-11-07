# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS TARGETARCH VERSION=dev
RUN apk add --no-cache ca-certificates
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# timetzdata: scratch has no zoneinfo, and TZ should still work.
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -tags timetzdata -ldflags "-s -w -X main.version=$VERSION" -o /out/whatsupd ./cmd/whatsupd
# SQLite falls back to the working directory when there is no temp dir.
RUN mkdir -p /out/data /out/tmp && chmod 1777 /out/tmp

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /out/whatsupd /usr/bin/whatsupd
COPY --from=build /out/tmp /tmp
COPY --from=build --chown=65532:65532 /out/data /data
USER 65532:65532
ENV WHATSUPD_DATA_DIR=/data WHATSUPD_LISTEN=0.0.0.0:8765
VOLUME /data
EXPOSE 8765
ENTRYPOINT ["/usr/bin/whatsupd"]
CMD ["serve"]
