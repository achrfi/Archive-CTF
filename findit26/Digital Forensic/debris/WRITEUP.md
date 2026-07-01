# debris Writeup

## Flag

`FindITCTF{h4v3_y0u_7r13d_c4rv1ng}`

## Steps

1. Identified `chall.img` as an ext4 filesystem image:

```bash
file chall.img
```

2. Read the live files from the image and found useful traces:

- `/home/researcher/.cache/.session_key` contained `session_key=jp3gm4f14`
- `/home/researcher/.bash_history` showed:

```bash
zip -P $(cat ~/.cache/.session_key) backup.zip keep.jpg
rm backup.zip
```

3. Carved deleted files from the raw image:

```bash
foremost -i chall.img -o carve_out
```

This recovered `carve_out/zip/00019460.zip`.

4. Opened the recovered ZIP with the recovered session key:

```bash
unzip -P jp3gm4f14 -o carve_out/zip/00019460.zip -d recovered
```

This extracted `recovered/keep.jpg`.

5. Tested the image for hidden data with `steghide` using the same password:

```bash
steghide extract -sf recovered/keep.jpg -p jp3gm4f14 -xf steg_out/extracted.bin -f
```

6. The extracted payload was base64 text:

```text
RmluZElUQ1RGe2g0djNfeTB1XzdyMTNkX2M0cnYxbmd9
```

7. Decoded it:

```bash
cat steg_out/extracted.bin | base64 -d
```

Output:

```text
FindITCTF{h4v3_y0u_7r13d_c4rv1ng}
```
