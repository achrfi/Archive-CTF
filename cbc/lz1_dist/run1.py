#!/usr/bin/env python3
import subprocess
import base64
import tempfile
import os

try:
    mode = input("(c)ompress or (d)ecompress: ").strip()
    if mode == 'c':
        pointer_length = int(input("Pointer length: "))
        if not 0 <= pointer_length <= 15:
            raise Exception("Invalid pointer length")
        data = input("Enter data to compress base64 encoded: ")
        with tempfile.NamedTemporaryFile(delete=False) as input_file, \
             tempfile.NamedTemporaryFile(delete=False) as output_file:
            input_file.write(base64.b64decode(data))
            input_file.flush()
            subprocess.check_call(["./lz1", "c", str(pointer_length), input_file.name, output_file.name])
            with open(output_file.name, "rb") as f:
                out = f.read()
            print("compressed(base64):", base64.b64encode(out).decode())
            with open("compressed.bin", "wb") as g:
                g.write(out)
            os.unlink(input_file.name)
            os.unlink(output_file.name)

    elif mode == 'd':
        data = input("Enter data to decompress base64 encoded: ")
        with tempfile.NamedTemporaryFile(delete=False) as input_file, \
             tempfile.NamedTemporaryFile(delete=False) as output_file:
            input_file.write(base64.b64decode(data))
            input_file.flush()
            subprocess.check_call(["./lz1", "d", input_file.name, output_file.name])
            with open(output_file.name, "rb") as f:
                out = f.read()
            print("decompressed(base64):", base64.b64encode(out).decode())
            with open("out.bin", "wb") as g:
                g.write(out)
            os.unlink(input_file.name)
            os.unlink(output_file.name)

    else:
        raise Exception("Invalid mode")

except Exception as e:
    print(e)
