# AI Usage and Project Attribution Disclaimer

## Project Origin and Attribution

This repository and all components within it—including reverse engineering analysis, cryptographic algorithm reconstruction, binary XML container parsing, source code implementation, test verification, and documentation—were conceived, researched, and generated autonomously by **Gemini** (Google DeepMind Advanced Agentic Coding system) in pair-programming collaboration with the project maintainer.

---

## Scope of AI Work

### 1. Reverse Engineering and Binary Analysis
- Disassembled and analyzed x86 engine binaries of **Test Drive Unlimited 2** (Eden Games).
- Uncovered why legacy community utilities (such as `tdudec` for TDU1) failed on TDU2 save files.
- Traced the proprietary Key Derivation Function (KDF) routine at virtual address `0x0055cdf0`.
- Extracted and decoded the six internal 56-bit static DES tables utilized during KDF derivation.
- Identified the engine's custom variant of the SHA-1 algorithm, specifically the non-standard message block expansion where 32-bit words are loaded from byte offset `i * 4 + 3`.
- Reversed the 16-round raw DES-Feistel cipher architecture, determining that initial and final permutations (IP and FP) are completely bypassed in CBC mode.
- Deconstructed the proprietary `XMBF` (version 1.1) binary XML container format, mapping its 14 primitive and compound data types, symbol tables, and Section 2 offset references.

### 2. Software Architecture and Implementation
- Developed `tdu2_save_tool.py` as a self-contained, single-file Python script and modular library.
- Implemented standard-compliant cryptographic routines (DES, Feistel, KDF, Eden SHA-1) using pure standard library Python, eliminating all external pip dependencies or C compiler requirements.
- Implemented an automated two-way serializer translating `XMBF` binary data structures into readable JSON and back into byte-aligned binary structures.
- Integrated automated heuristics for player profile name detection via cryptographic trials on candidate saves in less than one millisecond.

### 3. Safety and Security Guarantees
- **Zero Registry Footprint**: The implementation strictly operates on file paths provided by the user. It never queries, accesses, or writes to the Windows Registry.
- **No License / CD Key Extraction**: Confirmed that CD keys (`key.txt`) are entirely unused in TDU2 save game encryption, ensuring no sensitive licensing information is required or manipulated.
- **Safe Modifications**: Backups (`.bak`) are created automatically prior to destructive file operations.

---

## Disclaimer

This software is provided for educational, interoperability, preservation, and research purposes only. 

- "Test Drive Unlimited 2" and "Eden Games" are trademarks or registered trademarks of their respective owners.
- This project is an independent research implementation and is not affiliated with, endorsed by, or associated with Eden Games, Atari, or any of their subsidiaries.
- All code was generated without using leaked proprietary source code, relying strictly on clean-room binary analysis and public domain algorithmic specifications.
