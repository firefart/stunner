FROM golang:latest AS build-env
WORKDIR /src
ENV CGO_ENABLED=0
COPY go.mod /src/
RUN go mod download
COPY . .
RUN  go build -a -o stunner -ldflags="-s -w" -gcflags="all=-trimpath=/src" -asmflags="all=-trimpath=/src"

FROM alpine:latest

RUN apk add --no-cache ca-certificates \
    && rm -rf /var/cache/*

RUN mkdir -p /app \
    && adduser -D stunner \
    && chown -R stunner:stunner /app

USER stunner
WORKDIR /app

COPY --from=build-env /src/stunner .

ENTRYPOINT [ "./stunner" ]
