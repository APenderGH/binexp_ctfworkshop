FROM ubuntu:22.04 AS base
RUN apt update && apt install libc6-i386 -y

FROM pwn.red/jail
COPY --from=base / /srv

COPY src/hat-generator /srv/app/run
COPY src/flag /srv/app/flag.txt