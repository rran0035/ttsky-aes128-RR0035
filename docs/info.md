## How it works

This project implements AES-128 encryption using a low-area, shared-resource architecture. A single case-statement S-box is time-multiplexed between the 16 SubBytes operations and the four key-expansion substitutions. The AES core performs the initial AddRoundKey, rounds 1 to 9 with MixColumns, and round 10 without MixColumns. A complete encryption takes 211 core clock cycles.

Because Tiny Tapeout exposes only byte-wide I/O, a wrapper loads the 128-bit plaintext and 128-bit key one byte at a time, starts encryption, and returns the 128-bit ciphertext one byte at a time.

### Command interface

`ui_in[7:0]` carries one data byte. `uio_in[2]` is asserted for one clock cycle to validate a command selected by `uio_in[1:0]`:

| Command | Operation |
|---|---|
| `00` | Load one plaintext byte, most-significant byte first |
| `01` | Load one key byte, most-significant byte first |
| `10` | Start AES encryption after 16 plaintext and 16 key bytes |
| `11` | Advance to the next ciphertext byte |

`uo_out[7:0]` presents the current ciphertext byte. Status outputs are:

- `uio_out[3]`: ciphertext result is ready
- `uio_out[4]`: AES core is busy
- `uio_out[5]`: all 16 plaintext bytes have been loaded
- `uio_out[6]`: all 16 key bytes have been loaded
- `uio_out[7]`: wrapper can accept a command

## How to test

1. Hold `rst_n` low for several clocks, then release it.
2. Send the 16 plaintext bytes most-significant byte first using command `00`.
3. Send the 16 key bytes most-significant byte first using command `01`.
4. Pulse command `10` to start encryption.
5. Wait until `uio_out[3]` becomes high.
6. Read the first ciphertext byte from `uo_out`.
7. Pulse command `11` after each byte to select the next ciphertext byte.

The cocotb regression checks two official known-answer vectors: FIPS-197 Appendix C.1 and NIST SP 800-38A block 1. The same test is used for RTL and gate-level verification.

## External hardware

No external hardware is required. A controller capable of driving the Tiny Tapeout byte and command pins can load inputs and read the ciphertext.
