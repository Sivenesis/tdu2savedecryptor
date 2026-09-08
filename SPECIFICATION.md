# Test Drive Unlimited 2 (TDU2) Save System Specification

Technical documentation and reverse-engineering findings for the save game cryptography and serialization architecture of **Test Drive Unlimited 2** (Eden Games).

---

## 1. Architectural Overview

In Test Drive Unlimited 1, save files were encrypted using standard XTEA. In Test Drive Unlimited 2, Eden Games replaced this entirely with a multi-layered security and serialization pipeline:

1. **Outer Layer**: Chunked container with Eden Games custom SHA-1 digests.
2. **Cipher Layer**: Non-standard DES-CBC Feistel cipher (omitting initial and final bit permutations).
3. **Key Derivation Layer**: 6-round DES Key Derivation Function (KDF) at virtual address `0x0055cdf0`.
4. **Data Layer**: Proprietary binary XML format (`XMBF` v1.1) containing typed schemas, symbol pools, and nested data structures.

---

## 2. Cryptographic Architecture

### A. Key Derivation Function (KDF)

The save game key is derived per-file using a 6-round DES routine located at virtual address `0x0055cdf0` in the x86 game binary.

#### Key String Format
The derivation input string is constructed as follows:
```text
key_string = "      " + profile_crc16_le + "PLAYERSAVE" + filename
```

Where:
- `profile_crc16_le`: The first 2 bytes of the player profile name's CRC16 (little-endian), preceded by 6 space characters (`0x20`) due to an 8-byte buffer formatting quirk in the engine.
- `profile_crc16` computation:
  $$\text{profile\_crc16} = \text{CRC32}(\text{ProfileName.encode('latin1')}) \ \& \ \text{0xFFFF}$$
- `filename`: Uppercase target save name (`"DATA"`, `"KEYMAP"`, or `"OPTIONS"`).

#### Derivation Rounds
The engine maintains six static 56-bit DES keys (`kdf_tables[0..5]`). For each round $r \in [0..5]$:
1. The 56-bit round key is loaded from `kdf_tables[r]`.
2. A standard 16-round DES subkey schedule is generated.
3. The key string buffer is encrypted in ECB mode.
4. The output is folded into the final 56-bit DES key used for file decryption.

### B. Initialization Vector (IV)

The CBC mode Initialization Vector (IV) is an 8-byte value derived directly from the player profile CRC16:
```text
IV = struct.pack('<Q', profile_crc16)
```
For example:
- Profile `"Player"`: `CRC16 = 0x7F53` -> `IV = \x53\x7f\x00\x00\x00\x00\x00\x00`
- Profile `"Driver"`: `CRC16 = 0x79EF` -> `IV = \xef\x79\x00\x00\x00\x00\x00\x00`

### C. Cipher Implementation (Raw DES-CBC)

The cipher is a 16-round balanced Feistel network using standard DES S-boxes and P-box permutations, with one critical variation:
- **No Initial Permutation (IP)**: Plaintext blocks enter the Feistel network directly.
- **No Final Permutation (FP / IP^-1)**: The round 16 swapped halves are concatenated directly into ciphertext.

#### Round Function
For each 64-bit block split into $(L_0, R_0)$:
$$L_{i} = R_{i-1}$$
$$R_{i} = L_{i-1} \oplus f(R_{i-1}, K_i) \quad (i = 1..16)$$
Where $f(R, K)$ is the standard DES cipher function:
1. 32-bit $R$ expanded to 48 bits using Expansion Table $E$.
2. XOR with 48-bit round subkey $K_i$.
3. 8 substitution boxes ($S_1..S_8$) reducing 48 bits to 32 bits.
4. 32-bit permutation $P$.

---

## 3. Container and Chunk Layout

Encrypted files (`DATA`, `KEYMAP`, `OPTIONS`) are divided into 4096-byte plaintext chunks before encryption.

### Container Structure

```text
+--------------------------------------------------------------------------+
| Block 0 (8 bytes) : [Partial Chunk Size (uint32)] + [0x00000000 (uint32)]|
| Block 1 (8 bytes) : [Total Plaintext Size (uint32)] + [0x00000000]       |
+--------------------------------------------------------------------------+
| Repeated for each 4096-byte chunk:                                       |
|   - Chunk Data (padded with zeros to an 8-byte boundary)                 |
|   - Hash Block (24 bytes):                                               |
|       [Eden SHA-1 Digest (20 bytes)] + [0x00000000 (uint32)]             |
+--------------------------------------------------------------------------+
| Container Footer (variable length):                                      |
|   "##" (2 bytes) + [Profile/Online ID (8 bytes)] +                       |
|   [Filename String] + "##" (2 bytes) + [Len(Filename) (1 byte)]          |
+--------------------------------------------------------------------------+
```

### Eden Games SHA-1 Variant

The integrity hash for each 4096-byte chunk uses standard SHA-1 initialization constants and 80-round message expansion, but the message schedule initialization differs from standard SHA-1:

Standard SHA-1 reads 16 big-endian 32-bit integers from the 64-byte message block:
$$W[t] = \text{uint32\_be}(\text{block}[t \times 4 .. t \times 4 + 4])$$

Eden Games SHA-1 takes only the byte at index $t \times 4 + 3$:
$$W[t] = \text{block}[t \times 4 + 3] \quad (t = 0..15)$$

The remaining 64 words ($W[16..79]$) use the standard recursive rotation:
$$W[t] = \text{ROTL}^1(W[t-3] \oplus W[t-8] \oplus W[t-14] \oplus W[t-16])$$

---

## 4. Binary XML (XMBF) Specification

Once decrypted, the plaintext is a proprietary binary XML container identified by the magic signature `XMBF` (`0x46424D58`), version `0x00000101` (Version 1.1).

### File Header (28 bytes)

| Offset | Field | Type | Description |
|---|---|---|---|
| `0x00` | `magic` | `char[4]` | `b'XMBF'` |
| `0x04` | `version` | `uint32` | `0x00000101` |
| `0x08` | `sec0_offset` | `uint32` | Offset to String / Symbol Table (typically `0x1C` = 28) |
| `0x0C` | `sec1_offset` | `uint32` | Offset to Schema / Struct Descriptor Table |
| `0x10` | `sec2_offset` | `uint32` | Offset to Data Payload Section |
| `0x14` | `root_name_off`| `uint32` | Relative offset in Section 0 to the root struct name |
| `0x18` | `root_type_id` | `uint32` | Index of the root struct descriptor in Section 1 |

### Section 0: String Table
A contiguous pool of null-terminated UTF-8 strings representing variable names, struct field identifiers, and schema labels.

### Section 1: Schema / Struct Descriptors
An array of 32-bit unsigned integers defining the object layout:
- Type Table Index: Points to descriptor headers.
- Descriptor Header (uint32):
  - Bits 0..3: Data Type (see Type IDs below).
  - Bits 4..14: Number of fields (`num_fields`).
  - Bits 15..31: Total byte size of the struct (`struct_size`).

#### Supported Data Types

| ID | Name | Size | Description |
|---|---|---|---|
| `0` | `OBJECT` | Variable | Compound structure containing `num_fields` child members |
| `1` | `BOOL` | 1 byte | Boolean (`0` = False, `1` = True) |
| `2` | `SINT8` | 1 byte | Signed 8-bit integer |
| `3` | `SINT16` | 2 bytes | Signed 16-bit integer (little-endian) |
| `4` | `SINT32` | 4 bytes | Signed 32-bit integer (little-endian) |
| `5` | `SINT64` | 8 bytes | Signed 64-bit integer (little-endian) |
| `6` | `UINT8` | 1 byte | Unsigned 8-bit integer |
| `7` | `UINT16` | 2 bytes | Unsigned 16-bit integer (little-endian) |
| `8` | `UINT32` | 4 bytes | Unsigned 32-bit integer (little-endian) |
| `9` | `UINT64` | 8 bytes | Unsigned 64-bit integer (little-endian) |
| `10` | `FLOAT` | 4 bytes | 32-bit IEEE 754 floating point |
| `11` | `DOUBLE` | 8 bytes | 64-bit IEEE 754 floating point |
| `12` | `STRING` | 4 bytes | Offset into Section 2 null-terminated UTF-8 string pool |
| `13` | `VIRTUAL` | 8 bytes | Polymorphic type pointer |

#### Field Definitions
Each field in an `OBJECT` descriptor consists of two 32-bit integers:
- `DWORD 0`: Offset in Section 0 to the field name string.
- `DWORD 1`:
  - Bit 31: Array flag (`is_array = (dw1 >> 31) & 1`).
  - Bits 0..30: Target Type ID in Section 1 (`target_type_id = dw1 & 0x3FFFFFFF`).

### Section 2: Data Payload
Contains the serialized instance data.
- **Inline Structs**: Directly occupy `struct_size` bytes at the parent's current offset.
- **Arrays**: Represented inline as 8 bytes:
  - `count` (uint32, little-endian): Number of elements.
  - `offset` (uint32, little-endian): Offset relative to the start of Section 2 where array items are stored consecutively.
- **Strings**: Represented as a 4-byte uint32 offset into Section 2 pointing to a null-terminated UTF-8 string.

---

## 5. Verification Metrics

The implementation was validated against original save files from various profiles:

| Profile | Target | Plaintext Size | Validated Chunks | Status |
|---|---|---|---|---|
| `Profile A` | `DATA` | 204,693 bytes | 50 chunks | Exact match |
| `Profile B` | `DATA` | 171,854 bytes | 42 chunks | Exact match |
| `Profile C` | `DATA` | 161,408 bytes | 40 chunks | Exact match |
| `Profile D` | `DATA` | 149,096 bytes | 37 chunks | Exact match |
| `Profile E` | `DATA` | 148,776 bytes | 37 chunks | Exact match |

All decrypted files roundtrip through JSON and back to binary with identical structural parity and valid checksum digests.

---

## 6. Progression Architecture and Objective Scoring

The game evaluates progression using four distinct skill pillars with dedicated point caps, verified against game engine memory and user interface metrics:

### A. Skill Pillars and Point Caps

| Skill | Max Points | In-Game Sub-Objectives |
|---|---|---|
| **Competition** | 10,000 | Racing School (1,000), Championships (5,370), Cups (1,030), Duels (600), Instant Challenges (1,000), Multiplayer (1,000) |
| **Collection** | 10,000 | Vehicles (6,250), Houses and Furniture (3,050), Clothes (350), Haircuts (150), Cosmetic Clinic (100), Stickers Shop (100) |
| **Discovery** | 14,500 | Roads (2,700), Events & Bomb Missions (5,780), Treasure Hunt Wrecks (4,220), Photographer Viewpoints (1,800) |
| **Social** | 10,000 | Friends (300), Club (4,300), Community Racing Center C.R.C. (1,300), Chase Mode (1,900), Co-op Challenges (2,200) |

### B. Island Discovery Areas and Road Distribution

Map discovery points in `PlayerLevels.CruisingLevels` are tracked per island zone, totaling exactly 14,500 points:

| Zone ID | Internal Identifier | Island Region | Max Discovery Points | Total Roads |
|---|---|---|---|---|
| `Area_0` | `/:CruisingAreaLevel_I1` | Ibiza Zone 1 | 2,080 pts | 467 roads |
| `Area_1` | `/:CruisingAreaLevel_I2` | Ibiza Zone 2 | 2,080 pts | 924 roads |
| `Area_2` | `/:CruisingAreaLevel_H1` | Hawaii Zone 1 | 2,425 pts | 309 roads |
| `Area_3` | `/:CruisingAreaLevel_H2` | Hawaii Zone 2 | 2,640 pts | 1,144 roads |
| `Area_4` | `/:CruisingAreaLevel_H3` | Hawaii Zone 3 | 2,550 pts | 426 roads |
| `Area_5` | `/:CruisingAreaLevel_H4` | Hawaii Zone 4 | 2,725 pts | 998 roads |
| **Total** | | | **14,500 pts** | **4,268 roads** |

