---
title: "gatekeeper"
ctf: "picoCTF"
date: 2026-04-24
category: reverse
difficulty: easy
points: 0
flag_format: "picoCTF{...}"
author: "Codex"
---

# gatekeeper

## Summary

This challenge accepts either decimal or hexadecimal input, but also requires the original input length to be exactly 3 characters and the parsed numeric value to be greater than 999. That makes decimal impossible and leaves 3-digit hexadecimal as the working input class.

## Solution

### Step 1: Reverse the input checks

Disassembling `main`, `is_valid_decimal`, and `is_valid_hex` shows:

- decimal input is parsed with `atoi`
- hex input is parsed with `strtol(..., 16)`
- the parsed value must satisfy `1000 <= value <= 9999`
- the original string length must be exactly `3`

So any 3-character hex value from `3e8` to `fff` is accepted. A minimal valid input is `3e8`.

```python
from subprocess import check_output

raw = check_output(
    "printf '3e8\\n' | nc green-hill.picoctf.net 60591",
    shell=True,
    text=True,
)

encoded = raw.split("Access granted: ", 1)[1].strip()
flag = encoded.replace("ftc_oc_ip", "")[::-1]
print(flag)
```

### Step 2: Decode the flag output

The success path does not print the flag directly. The binary reads `/flag.txt`, prints it in reverse order, and inserts the marker `ftc_oc_ip` every four characters.

Removing that marker and reversing the remaining string yields the real flag.

Example remote output:

```text
Access granted: }847ftc_oc_ipd936ftc_oc_ipb_99ftc_oc_ip9_TGftc_oc_ip_xehftc_oc_ip_tigftc_oc_ipid_3ftc_oc_ip{FTCftc_oc_ipocipftc_oc_ip
```

Decoded output:

```text
picoCTF{3_digit_hex_GT_999_b639d748}
```

## Flag

```text
picoCTF{3_digit_hex_GT_999_b639d748}
```
