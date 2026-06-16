# Low-Area AES-128 Tiny Tapeout Project — RR0035

This repository contains a byte-serial Tiny Tapeout wrapper around a low-area AES-128 encryption core. The core uses one shared case-statement S-box and completes encryption in 211 core clock cycles.

The design is intended for the ECE4063 IC Design Project. Functional verification uses FIPS-197 and NIST SP 800-38A known-answer vectors. See `docs/info.md` for the pin protocol and test instructions.
