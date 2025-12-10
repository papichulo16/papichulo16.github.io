FROM ubuntu@sha256:7c06e91f61fa88c08cc74f7e1b7c69ae24910d745357e0dfe1d2c0322aaf20f9

WORKDIR /app

RUN apt-get update && apt-get install -y \
    python3 \
    socat

COPY flag.txt .
COPY shortcakeql .

RUN chmod 444 flag.txt
RUN chmod 555 shortcakeql

RUN useradd -Ms /bin/bash ctf

USER ctf

EXPOSE 1337

CMD socat tcp-l:1337,reuseaddr,fork exec:/app/shortcakeql,pty,echo=0,raw,iexten=0
