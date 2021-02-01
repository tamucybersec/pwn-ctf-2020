FROM debian as build

RUN apt-get update -y
RUN apt-get install build-essential -y
ADD chall.c /tmp/chall.c
ADD Makefile /tmp/Makefile
RUN cd /tmp/; make all

FROM debian

RUN apt-get update -y
RUN apt-get install socat -y
COPY --from=build /tmp/chall /pwn/chall
WORKDIR /pwn

EXPOSE 2004

ENTRYPOINT ["sh", "-c", "exec socat -s TCP-LISTEN:2004,reuseaddr,fork EXEC:/pwn/chall,stderr"]
