FROM golang:1.18.2-alpine AS builder-backend

RUN echo ">> Downloading required apk's..." \
  && apk --no-cache add gcc musl-dev git \
  && echo ">> Cloning repository..." \
  && git clone https://github.com/firefart/stunner.git \
  && cd stunner \
  && echo ">> Starting go build..." \
  && go mod download \
  && go build \
  && cp ./stunner /home \
  && echo "#!/bin/sh" \
      > /home/run.sh \
  && echo '/usr/local/bin/stunner socks -s $SERVER_HOST:$SERVER_PORT -u $USER -p $PASSWORD --protocol tcp -x -l $LISTEN_ADDR' \
      >> /home/run.sh \
  && chmod +x /home/run.sh

FROM alpine:3.16.0 AS stunner
ENV USER="user" \
    PASSWORD="password" \
    SERVER_HOST="turn.example.com" \
    SERVER_PORT="3478" \
    LISTEN_ADDR="0.0.0.0:1080"

COPY --from=builder-backend /home /usr/local/bin

CMD ["/usr/local/bin/run.sh"]
