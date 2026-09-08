# Test Drive Unlimited 2 (TDU2) Save Game Tool

A complete, standalone, zero-dependency Python utility to decrypt, inspect, edit, and re-encrypt save game files (`DATA`, `KEYMAP`, `OPTIONS`) for **Test Drive Unlimited 2** (Eden Games).

This tool converts proprietary binary XML (`XMBF`) save files into human-readable, easily editable JSON, and repacks modified JSON back into fully valid, encrypted game containers with correct chunk-level checksums and authentic footers.

---

## Key Features

- **Pure Python 3 Implementation**: Zero external pip dependencies, zero compiled C extensions. Works on standard Python 3.7+ out of the box.
- **Zero Windows Registry Interaction**: Operates strictly on file paths in user-space. Never reads, queries, or modifies the Windows Registry.
- **No CD Key Needed**: CD keys (`key.txt`) are entirely unrelated to save game encryption in TDU2.
- **Full Bidirectional Pipeline**:
  - Encrypted Save -> Decrypted Binary XML (`.dec`) -> Formatted JSON (`.json`)
  - Formatted JSON (`.json`) -> Binary XML (`.dec`) -> Encrypted Save (`DATA`, `KEYMAP`, `OPTIONS`)
- **Automatic Profile Detection**: Auto-detects player profile names (e.g., `Player`, `MyProfile`) via cryptographic trial, folder hierarchy, or embedded metadata.
- **Authentic Checksum Generation**: Recomputes Eden Games custom SHA-1 digests for every 4096-byte chunk, ensuring the game accepts saves without corruption warnings.
- **Preserves Original Footers**: Automatically retains player online IDs and container footers.
- **Built-In Quick Save Editor**: Directly modify money, casino coupons, licenses, player levels, road discovery, or clean car damage without manual JSON editing.

---

## Prerequisites

- Python 3.7 or newer (Windows, Linux, or macOS).
- No third-party packages required (uses only standard library modules: `struct`, `zlib`, `json`, `argparse`, `pathlib`, `base64`, `os`, `sys`).

---

## Save File Locations

On Windows, TDU2 save files are typically located at:
```text
C:\Users\<Username>\Documents\Eden Games\Test Drive Unlimited 2\savegame\<ProfileName>\PLAYERSAVE\
```

Inside each `PLAYERSAVE` directory, there are three primary files:
- `DATA`: Player profile, bank account, garage vehicles, house ownership, licenses, discovery progress, and statistics.
- `KEYMAP`: Controller, steering wheel, and keyboard control bindings.
- `OPTIONS`: Audio, display, camera, and gameplay options.

---

## Quick Start Guide

### Step 1: Unpack a Save File to JSON

To unpack all save files in a profile directory into editable JSON:
```powershell
python tdu2_save_tool.py unpack "C:\Users\<Username>\Documents\Eden Games\Test Drive Unlimited 2\savegame\MyProfile\PLAYERSAVE"
```

Or unpack to a specific output folder:
```powershell
python tdu2_save_tool.py unpack "path\to\PLAYERSAVE" -o "path\to\decrypted_folder"
```

This generates:
- `DATA.json`: Structured representation of the full game state.
- `KEYMAP.json`: Control configuration.
- `OPTIONS.json`: User preferences.
- Automatic `.bak` backups of original save files.

### Step 2: Edit the Save

You can edit values in two ways:

#### Method A: Direct JSON Editing
Open `DATA.json` in any text editor (VS Code, Notepad++, etc.) and edit fields directly:
- `PlayerData.Driver.Money`: Set cash balance.
- `PlayerData.Driver.NbCoupon`: Set casino chips/coupons.
- `PlayerData.Garage`: Modify owned vehicles, performance upgrades, colors, and interior trims.
- `PlayerData.PlayerLevels`: Adjust Racing, Collection, Social, and Cruising experience points.

#### Method B: Built-in Command-Line Editor
Modify values directly on the encrypted save without opening JSON:
```powershell
# Set cash balance to $50,000,000
python tdu2_save_tool.py edit "path\to\PLAYERSAVE" --money 50000000

# Set casino coupons to 250,000
python tdu2_save_tool.py edit "path\to\PLAYERSAVE" --coupons 250000

# Maximize all progression skills and all in-game sub-objectives
python tdu2_save_tool.py edit "path\to\PLAYERSAVE" --max-levels

# Unlock 100% road discovery with exact zone points (Ibiza: 2080, 2080; Hawaii: 2425, 2640, 2550, 2725)
python tdu2_save_tool.py edit "path\to\PLAYERSAVE" --unlock-roads

# Unlock all driving school licenses (C4, B4, A7, A6, etc.) and pass all driving tests
python tdu2_save_tool.py edit "path\to\PLAYERSAVE" --unlock-licenses

# Clean dirt, mud, and scratches from all garage vehicles
python tdu2_save_tool.py edit "path\to\PLAYERSAVE" --clean-cars
```

### Step 3: Repack and Re-Encrypt

After editing JSON files, compile them back into encrypted save containers:
```powershell
python tdu2_save_tool.py pack "path\to\decrypted_folder" -o "path\to\PLAYERSAVE"
```

Or repack a single file:
```powershell
python tdu2_save_tool.py pack "path\to\decrypted_folder\DATA.json" -o "path\to\PLAYERSAVE\DATA"
```

### Step 4: Verify Save Integrity

Verify chunk hashes and container validity before launching the game:
```powershell
python tdu2_save_tool.py verify "path\to\PLAYERSAVE"
```

Expected output:
```text
[+] DATA    : VALID | Profile: MyProfile | Size: 160764  | Root: XMBF
[+] KEYMAP  : VALID | Profile: MyProfile | Size: 6052    | Root: XMBF
[+] OPTIONS : VALID | Profile: MyProfile | Size: 7676    | Root: XMBF
```

---

## CLI Command Reference

```text
usage: tdu2_save_tool.py [-h] [-p PROFILE] {unpack,pack,decrypt,encrypt,verify,edit} ...

Commands:
  unpack    Decrypt and unpack save file(s) into readable JSON.
            Options:
              path              Path to save file or PLAYERSAVE directory.
              -o, --output      Target output directory for JSON files.
              --raw             Also export raw decrypted XMBF (.dec) files.

  pack      Compile JSON file(s) back into encrypted save container(s).
            Options:
              path              Path to JSON file or directory containing JSON files.
              -o, --output      Target output directory or file path for encrypted saves.

  edit      Apply quick modifications directly to savegame.
            Options:
              path              Path to DATA file or PLAYERSAVE directory.
              -o, --output      Output directory or file path for modified save.
              --money INT       Set player cash amount.
              --coupons INT     Set casino coupons amount.
              --max-levels      Max out Competition (10,000), Collection (10,000),
                                Discovery (14,500), and Social (10,000) skills along
                                with all sub-objectives (Racing School, Championships,
                                Cups, Events, Wrecks, Photos, Shops, Club, Chase, Co-op).
              --unlock-roads    Discover 100% of roads with exact island zone points:
                                Ibiza 1 (2080), Ibiza 2 (2080),
                                Hawaii 1 (2425), Hawaii 2 (2640),
                                Hawaii 3 (2550), Hawaii 4 (2725).
              --unlock-licenses Pass all driving school licenses and tests.
              --clean-cars      Reset dirt, mud, and damage across all garage cars.

  verify    Check container integrity, chunk checksums, and profile matching.
            Options:
              path              Path to save file or PLAYERSAVE directory.

  decrypt   Decrypt save file directly to raw binary XML (.dec).
            Options:
              input             Input save file path.
              -o, --output      Output .dec path.

  encrypt   Encrypt raw binary XML (.dec) to save container.
            Options:
              input             Input .dec file path.
              -o, --output      Output save file path.
```

---

## Project Structure

```text
GITHUBrepo/
|-- tdu2_save_tool.py      # Complete standalone Python tool and library
|-- unpack_save.bat        # Windows drag-and-drop helper to unpack saves
|-- pack_save.bat          # Windows drag-and-drop helper to repack saves
|-- README.md              # Documentation and user guide
|-- SPECIFICATION.md       # Full reverse engineering and cryptographic specification
|-- AI_DISCLAIMER.md       # AI attribution, research, and generation disclosure
|-- LICENSE                # MIT Open Source License
|-- .gitignore             # Standard repository ignore rules
```

---

## Reverse Engineering Summary

Older modding tools (such as Luigi Auriemma's `tdudec`) functioned exclusively on **Test Drive Unlimited 1**, which used XTEA encryption. TDU2 completely redesigned the encryption and serialization pipeline:

1. **Cipher**: Raw 16-round DES-Feistel network in CBC mode (bypassing the standard DES Initial Permutation IP and Final Permutation FP).
2. **Key Derivation Function (KDF)**: A 6-round DES sequence derived at runtime from static internal lookup tables, the player profile CRC16, and the filename.
3. **Integrity Validation**: 4096-byte data chunks hashed with a customized Eden Games variant of SHA-1, followed by a 24-byte header block.
4. **Serialization**: Decrypted payloads use a proprietary binary XML format named `XMBF` (version 1.1) containing a symbol table, struct descriptors for 14 primitive and compound data types, and an indexed data section.

For a comprehensive technical breakdown including mathematical formulas, S-box details, and binary layouts, refer to [SPECIFICATION.md](SPECIFICATION.md).

---

## AI Usage and Attribution Disclaimer

This entire project - including reverse-engineering the binary formats, reconstructing the DES-CBC cipher and Eden SHA-1 routines, parsing the XMBF schema, implementing the complete Python suite, and authoring documentation - was researched, engineered, and generated autonomously by **Gemini** (Google DeepMind Advanced Agentic Coding).

For full details regarding methodologies, safety constraints, and attribution, see [AI_DISCLAIMER.md](AI_DISCLAIMER.md).

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
