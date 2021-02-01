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
COPY flag.txt /pwn/flag.txt
WORKDIR /pwn

EXPOSE 2000

ENTRYPOINT ["sh", "-c", "exec socat -s TCP-LISTEN:2000,reuseaddr,fork EXEC:/pwn/chall,stderr"]
