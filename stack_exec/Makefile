CC := $(or $(CC),gcc)
CFLAGS := -z execstack -m32
CONTAINER := stack_exec

all: chall

clean: .PHONY
	rm -f chall

chall: chall.c
	$(CC) $(CFLAGS) $^ -o $@

docker: Dockerfile
	docker build -t $(CONTAINER) .

run: docker
	docker run -d --name $(CONTAINER) -m 32m --memory-swap 32m --read-only --restart always --cpus=".1" -p 2001:2001 $(CONTAINER)

extract: docker
	$(eval id := $(shell docker create $(CONTAINER)))
	docker cp $(id):/pwn/chall - | tar xv chall
	docker rm -v $(id)

.PHONY:
