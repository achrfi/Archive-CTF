from __future__ import annotations

from pathlib import Path
import struct


def u8(buf: bytes, off: int) -> tuple[int, int]:
    return buf[off], off + 1


def u32(buf: bytes, off: int) -> tuple[int, int]:
    return struct.unpack_from("<I", buf, off)[0], off + 4


def chunk(buf: bytes, off: int) -> tuple[bytes, int, int]:
    size, off = u32(buf, off)
    data = buf[off : off + size]
    return data, size, off + size


def xor_cycle(data: bytearray, key: bytes) -> None:
    if not key:
        return
    klen = len(key)
    for i in range(len(data)):
        data[i] ^= key[i % klen]


def page_align(n: int, page: int = 0x1000) -> int:
    rem = n % page
    return n if rem == 0 else n + (page - rem)


def main() -> None:
    blob = Path("binary").read_bytes()
    hdr_off = 0xC6D
    stage1_size = struct.unpack_from("<I", blob, hdr_off)[0]
    control = blob[hdr_off + 4]
    stage1 = blob[hdr_off + 5 : hdr_off + 5 + stage1_size]

    print(f"stage1_size={stage1_size} control=0x{control:02x}")

    off = 0
    flag, off = u8(stage1, off)
    image_count, off = u32(stage1, off)
    entry_rva, off = u32(stage1, off)
    callback_rva, off = u32(stage1, off)
    extra_size, off = u32(stage1, off)

    parts = []
    for _ in range(7):
        data, size, off = chunk(stage1, off)
        parts.append({"size": size, "data": bytearray(data)})

    print(f"flag={flag} image_count={image_count} entry_rva=0x{entry_rva:x} callback_rva=0x{callback_rva:x} extra_size={extra_size}")
    for i, part in enumerate(parts):
        print(f"part{i}: size=0x{part['size']:x}")

    xor_cycle(parts[2]["data"], bytes(parts[6]["data"]))
    xor_cycle(parts[5]["data"], bytes(parts[6]["data"]))

    image_size = page_align(parts[0]["size"]) + parts[1]["size"] + parts[2]["size"] + extra_size
    ptr_table_off = image_size
    alloc_size = image_size + image_count * 8
    image = bytearray(alloc_size)

    cur = 0
    dest_ptrs: list[int] = []
    for idx in range(4):
        data = parts[idx]["data"]
        image[cur : cur + len(data)] = data
        dest_ptrs.append(cur)
        cur += page_align(len(data)) if idx == 0 else len(data)

    print(f"rebuilt_image_size=0x{image_size:x} alloc_size=0x{alloc_size:x}")
    print("dest_ptrs:", [hex(x) for x in dest_ptrs])

    ptr_table = stage1[off : off + image_count * 8]
    image[ptr_table_off : ptr_table_off + len(ptr_table)] = ptr_table
    off += len(ptr_table)
    print(f"ptr_table_size=0x{len(ptr_table):x}")

    stage2_size = struct.unpack_from("<I", stage1, off)[0]
    stage2_control = stage1[off + 4]
    stage2 = stage1[off + 5 :]
    print(f"stage2_size={stage2_size} stage2_control=0x{stage2_control:02x} stage2_payload_len=0x{len(stage2):x}")

    out = Path("work")
    out.mkdir(exist_ok=True)
    (out / "stage1_container.bin").write_bytes(stage1)
    (out / "stage1_image.bin").write_bytes(image[:image_size])
    (out / "stage1_ptr_table.bin").write_bytes(ptr_table)
    (out / "stage2_blob.bin").write_bytes(stage2)
    (out / "stage1_meta.txt").write_text(
        "\n".join(
            [
                f"stage1_size={stage1_size}",
                f"control={control}",
                f"flag={flag}",
                f"image_count={image_count}",
                f"entry_rva=0x{entry_rva:x}",
                f"callback_rva=0x{callback_rva:x}",
                f"extra_size=0x{extra_size:x}",
                *[f"part{i}_size=0x{p['size']:x}" for i, p in enumerate(parts)],
                f"image_size=0x{image_size:x}",
                f"stage2_size={stage2_size}",
                f"stage2_control={stage2_control}",
            ]
        )
    )


if __name__ == "__main__":
    main()
