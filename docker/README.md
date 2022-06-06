### Docker Image

Run the docker image on your machine with:

`docker run -it firefart/stunner sh`

Perform the tests you would like to perform within the container, for example:

`stunner info -s turn.example.com:3478`

**[Available commands](https://github.com/firefart/stunner#available-commands)**

#### running stunner with socks enabled

To achieve this, tcp connection to TURN host is required.

```
docker run -d \
  --name stunner \
  --user 1000:1000 \
  --read-only \
  --security-opt no-new-privileges \
  --cap-drop=ALL \
  -p 1080:1080 \
  -e USER='user' \
  -e PASSWORD='password' \
  -e SERVER_HOST='turn.example.com' \
  -e SERVER_PORT='3478' \
  -e LISTEN_ADDR='0.0.0.0:1080' \
  firefart/stunner
```
