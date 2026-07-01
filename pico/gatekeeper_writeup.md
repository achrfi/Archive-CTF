# gatekeeper writeup

## Challenge

`gatekeeper` asks for a numeric code and reveals the flag only if the input passes its validation logic.

Remote service:

`nc green-hill.picoctf.net 60591`

## Triage

Basic inspection:

```bash
file gatekeeper
strings -a gatekeeper
```

Useful strings:

- `Enter a numeric code (must be > 999 ):`
- `Too small.`
- `Too high.`
- `Access Denied.`
- `/flag.txt`
- `ftc_oc_ip`

The binary is not stripped, so the important functions are visible:

- `main`
- `is_valid_decimal`
- `is_valid_hex`
- `reveal_flag`

## Reversing

Disassembling `main` shows this logic:

1. Read input as a string.
2. Store `strlen(input)`.
3. If the string is all decimal digits, parse it with `atoi`.
4. Otherwise, if the string is all hex digits, parse it with `strtol(..., 16)`.
5. Reject unless:
   - parsed value is `> 999`
   - parsed value is `<= 9999`
   - original string length is exactly `3`

That means plain decimal can never work, because a 3-digit decimal number is at most `999`.

The intended bypass is to use a 3-character hex string.

Accepted inputs are therefore:

```text
3e8 .. fff
```

because:

- `0x3e8 = 1000`
- `0xfff = 4095`
- both satisfy the numeric range
- both are exactly 3 characters long

One minimal working input is:

```text
3e8
```

## Remote solve

Submitting `3e8` to the remote service:

```bash
printf '3e8\n' | nc green-hill.picoctf.net 60591
```

returns:

```text
Access granted: }847ftc_oc_ipd936ftc_oc_ipb_99ftc_oc_ip9_TGftc_oc_ip_xehftc_oc_ip_tigftc_oc_ipid_3ftc_oc_ip{FTCftc_oc_ipocipftc_oc_ip
```

`reveal_flag` prints the flag file backwards and inserts the marker `ftc_oc_ip` every 4 characters.

So:

1. Remove every `ftc_oc_ip`
2. Reverse the remaining string

Cleaned string:

```text
}847d936b_999_TG_xeh_tigid_3{FTCocip
```

Reversed:

```text
picoCTF{3_digit_hex_GT_999_b639d748}
```

## Flag

```text
picoCTF{3_digit_hex_GT_999_b639d748}
```
