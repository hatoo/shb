FROM golang:1.24-alpine AS build
COPY main.go /src/main.go
WORKDIR /src
RUN go mod init tfbgo >/dev/null && CGO_ENABLED=0 go build -o /server main.go

# Multi-stage so what stays on disk is one static binary, not a toolchain
FROM alpine:3.21
COPY --from=build /server /server
EXPOSE 80 443
CMD ["/server"]
