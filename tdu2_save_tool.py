#!/usr/bin/env python3
"""
Test Drive Unlimited 2 (TDU2) Save Game Tool
Decrypt, unpack, edit, and re-encrypt TDU2 save files (DATA, KEYMAP, OPTIONS).

Fully self-contained: No external libraries, no native C compilation, and no registry access.
"""

import os
import sys
import zlib
import struct
import base64
import json
import argparse
from pathlib import Path

# ==============================================================================
# 1. EMBEDDED CRYPTOGRAPHIC CONSTANTS & TABLES
# ==============================================================================

# DES Key Schedule Permutation PC-2 (48 entries)
PC2 = [
    13, 16, 10, 23,  0,  4,  2, 27, 14,  5, 20,  9,
    22, 18, 11,  3, 25,  7, 15,  6, 26, 19, 12,  1,
    40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47,
    43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31
]

# Standard DES Bit Shifts per Round (16 rounds)
SHIFTS = (1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1)

# Standard DES Expansion Table E (48 entries)
E_STANDARD = [
    31,  0,  1,  2,  3,  4,
     3,  4,  5,  6,  7,  8,
     7,  8,  9, 10, 11, 12,
    11, 12, 13, 14, 15, 16,
    15, 16, 17, 18, 19, 20,
    19, 20, 21, 22, 23, 24,
    23, 24, 25, 26, 27, 28,
    27, 28, 29, 30, 31,  0
]

# 6 static 56-bit DES keys for Key Derivation Function (KDF at 0x0055cdf0)
KDF_TABLES_B64 = (
    b'AQABAAAAAAAAAQABAAABAQABAAABAQABAQEAAQEAAAAAAAEAAAEAAQEBAAAAAAEBAQAAAQABAQAB'
    b'AAEAAQEAAAAAAAEBAQEAAQAAAQEBAQABAAAAAAAAAQEAAQABAAAAAQEAAAAAAQEAAAAAAAAAAAEA'
    b'AAABAQEBAQABAAAAAQEAAAEAAAEAAQEAAAAAAAAAAQEBAAAAAQABAAAAAQAAAAEBAQEBAQAAAAEB'
    b'AAEAAAAAAQABAAAAAQEAAAEAAQABAQEAAAABAAABAQEAAQEAAQEBAQEBAAAAAQAAAQEBAAABAQAB'
    b'AAABAQABAQEBAAEBAQABAQABAQEAAQAAAQEAAAABAQABAAABAQEAAQABAAEBAAEAAAEBAAABAAEB'
    b'AQEAAAEBAQEAAQAAAQEBAAAAAQEBAAABAQAAAAEAAAAAAQEAAQAAAQEBAAABAAEBAQEA'
)

# Precomputed 8 SP-boxes (8 x 64 uint32 entries = 2048 bytes)
SP_TABLE_B64 = (
    b'AIKAAAAAAAAAgAAAAoKAAAKAgAACggAAAgAAAACAAAAAAgAAAIKAAAKCgAAAAgAAAgKAAAKAgAAAAIAAAgAAAAICAAAAAoAAAAKAAAC'
    b'CAAAAggAAAICAAACAgAACAoAAAoAAAAIAgAACAIAAAoAAAAAAAAACAgAAAoIAAAAAgAAAgAAAAoKAAAIAAAAAgIAAAIKAAAAAgAAAAIA'
    b'AAAIAAAKAgAAAgAAAAIIAAAIAgAAAAgAAAgAAAAICgAACggAAAoKAAAKAAAAAgIAAAgKAAAIAgAACAgAAAoIAAACCgAACAgAAAAKAAAA'
    b'CgAAAAAAAAoAAAACCAAAAAAAAAoCAABBACEAAQABAAEAAABBACAAAAAgAEAAAABAACEAQQABAEAAAQBBACEAAQAhAAAAAQABAAEAAAAg'
    b'AEAAAABAACEAAQAgAEAAIABBAAEAAAAAAAAAAQABAAAAQQAgAAAAIQBAACAAQAABAAAAAAABACAAQQAAAAEAIQAAACEAQQAAAAAAAABB'
    b'ACAAQAAhAAAAIABBAAEAAAAhAAEAIQABAAAAAAAhAAEAAQBAAAAAQQAhAEEAIABAAAAAAQAAAAAAAQBBAAAAAQAhAAAAIABAAAEAQAAg'
    b'AEEAAQBAAAEAQAAgAAEAIAAAAAAAAQABAEEAAAAAAAEAQAAhAEEAIQABACAAEAQAAAAEBBAAAAAAEAAEEAAEABAAAAAAEAQEAAAEABAQ'
    b'AAQAEAAAEBAAABAAAAQAEAQEEBAABAAAAAQQEAQAAAAAABAQAAAAAAQEEAAEAAAABAQAAAAEEBAABBAQBAQAEAQAEAAEBAAAAAQAEAQAE'
    b'BAAAAAQBAQQAAQAAAAAABAABAQQAAAAEBAABAAQBAAAAAAEAAAEBBAABAAQAAAAAAAEAAAQAAQAEAQEEAAEABAQAAAQAAQAAAAAAAAQA'
    b'AQQEAQAEAAABAAAAAAQEAQEEBAAAAAQBAQAAAQEABAAABAAAAQQEAQAEBAEAAAAAAQQEAQEABAAAAAQAAQQAAQEAABBAgEAQAIBAEACA'
    b'QAAAAEAQQABAAECAAABAgAAQAIAAAAAAABBAAAAQQABAEECAQAAAgAAAAABAAEAAAABAgAAAAIAAEAAAAABAAAAQQIBAAAAAAABAAAAQA'
    b'IBAEAAAQABAgAAAAIBAEAAAQABAAAAQAABAEEAAQBBAgEAAAIBAAEAAAABAgAAQQABAEECAQAAAgAAAAAAAAAAAABBAAEAQAABAAEAAQ'
    b'ABAgAAAAIAAEECAQBAAgEAQAIBAAAAAQBBAgEAAAIAAAACAABAAAAAAQIAAEACAQBBAAEAAQIAAEACAQBAAAAAAQAAAEECAQAAAAAAAQA'
    b'AAEAAAQBBAAIAAAACAAAQBAAAEAYAAACEAAAQAgAAAAAAAACAAAAQBgAAEIAAABACAAAABgAAEIIAAACEAAAQhgAAEAAAAACAAAAABAAA'
    b'EIAAABCAAAAAAgAAAIIAABCGAAAQhgAAAAQAABCGAAAAgAAAAAAAAACGAAAQBAAAAAQAAACGAAAQAAAAEAIAAACGAAAAAAAAAAQAAACA'
    b'AAAQBgAAAIYAABCCAAAABAAAAIAAABCGAAAQBgAAEIIAAAAAAAAABAAAEIYAABCGAAAQAAAAAIYAABCEAAAQBAAAAAAAABCAAAAAhgAA'
    b'EAIAAAAGAAAAgAAAEAAAAAAAAAAQggAAEAYAAACAIAAAQAAAgEAAgAAAIICAQAAAgEAgAAAAIICAQAAAgAAAgABAIICAAAAAgAAgAAB'
    b'AIACAAACAAEAAAABAIIAAAAAAAAAgAIAAIIAAQACAAAAAgIAAIIAAQCAAAAAgAIBAIACAQAAAAAAggIAAAICAQCCAAAAAgIAAAICAQAA'
    b'AAEAAgABAIAAAACAAgEAAgIAAIICAQAAAgAAggAAAIAAAQAAAgAAAgABAAAAAQCCAAAAgAABAIICAQACAgAAAAIBAIICAAACAgEAAAAA'
    b'AIACAQCAAAAAAgAAAAACAQCCAgAAAgAAAIACAACCAAEAAAAAAAICAQAAAAEAgAIAAIIAAQAAAQAAEAEAIBBAACAAAAAAAEAAABBAACAQ'
    b'QQAAAEEAIBBBACAAAQAAAAAAABAAACAQAAAAAAAAIBABACAQQAAAAEAAIBBBAAAQAQAAAEAAIBAAACAAAQAgAEEAIBABAAAAAQAgAEAA'
    b'ABBAAAAQQQAgAEEAABAAAAAAAAAgAEEAAAAAACAAQQAAAAEAABBAACAQQAAgEAEAIBABACAQAAAAEAEAAAAAACAAQAAgAAEAAABBACAQ'
    b'QAAAEEEAAABBACAQQAAAEAAAIBBBACAAAQAgAEEAAAAAAAAQAAAAEEEAIAAAAAAQQQAAAAEAIABAAAAQAAAgAEAAIABAAAAQAQACAIAA'
    b'gACAAAAAACACAIAggAAAAIIAgACCAAAAAAAAAIIAACAAAAAgggCAIIAAgCAAAIAgggCAIAAAgAACAAAAAAAAIIIAAACAAIAAggCAAAAAg'
    b'CACAAAgAgAAIIAAgCCCAIAAAAAAAAAAAAACAAAgggAAAIAAgACCAIAgAAAAIAIAgCAAAAAgAACAIIAAgAACAAAAAgAAIIAAgAACAIAgA'
    b'ACAAIIAAAACAAAAgAAAIIIAACCAAAAAgAAAIAIAgACAAAAAAgCAIIIAACACAAAAgAAAIIAAgACCAIAAgAAAAAIAgCCAAIAgAACAIAIAg'
    b'AACAIAAAgAAIAAAAACAAIAgg='
)

# Unpack embedded tables
_kdf_raw = base64.b64decode(KDF_TABLES_B64)
KDF_TABLES = [list(_kdf_raw[i*56 : (i+1)*56]) for i in range(6)]

_sp_raw = base64.b64decode(SP_TABLE_B64)
_sp_flat = struct.unpack('<512I', _sp_raw)
SP = [_sp_flat[i*64 : (i+1)*64] for i in range(8)]


# ==============================================================================
# 2. CIPHER, KEY DERIVATION, AND CHECKSUMS
# ==============================================================================

def des_key_schedule(key56):
    """Generates 16 round subkeys (48 bits each) from 56-bit key."""
    C = list(key56[:28])
    D = list(key56[28:56])
    subkeys = []
    for rnd in range(16):
        sh = SHIFTS[rnd]
        C = C[sh:] + C[:sh]
        D = D[sh:] + D[:sh]
        CD = C + D
        subkeys.append([CD[PC2[i]] for i in range(48)])
    return subkeys

def feistel_fast(R_u32, sk_bits):
    """Fast DES Feistel function evaluated using 8 precomputed SP-boxes."""
    out = 0
    sp = SP
    E = E_STANDARD
    for sb_idx in range(8):
        base = sb_idx * 6
        c_val = (
            (((R_u32 >> (31 - E[base    ])) & 1) ^ sk_bits[base    ]) << 5 |
            (((R_u32 >> (31 - E[base + 1])) & 1) ^ sk_bits[base + 1]) << 4 |
            (((R_u32 >> (31 - E[base + 2])) & 1) ^ sk_bits[base + 2]) << 3 |
            (((R_u32 >> (31 - E[base + 3])) & 1) ^ sk_bits[base + 3]) << 2 |
            (((R_u32 >> (31 - E[base + 4])) & 1) ^ sk_bits[base + 4]) << 1 |
            (((R_u32 >> (31 - E[base + 5])) & 1) ^ sk_bits[base + 5])
        )
        out ^= sp[sb_idx][c_val]
    return out

def des_encrypt_fast(L_u32, R_u32, subkeys):
    """Raw 16-round DES Feistel encryption without IP/FP permutations."""
    L = L_u32
    R = R_u32
    for rnd in range(15):
        f_out = feistel_fast(R, subkeys[rnd])
        L, R = R, L ^ f_out
    f_out = feistel_fast(R, subkeys[15])
    return (L ^ f_out), R

def des_decrypt_fast(L_u32, R_u32, subkeys):
    """Raw 16-round DES Feistel decryption without IP/FP permutations."""
    L = L_u32
    R = R_u32
    for rnd in range(15, 0, -1):
        f_out = feistel_fast(R, subkeys[rnd])
        L, R = R, L ^ f_out
    f_out = feistel_fast(R, subkeys[0])
    return (L ^ f_out), R

def kdf(key_str_bytes):
    """TDU2 6-round KDF algorithm from 0x0055cdf0."""
    bit_buffer = [0] * 64
    str_ptr = 0
    str_len = len(key_str_bytes)
    for r in range(6):
        for i in range(8):
            if str_ptr < str_len and key_str_bytes[str_ptr] != 0:
                c = key_str_bytes[str_ptr]
                str_ptr += 1
            else:
                c = 0
            for b in range(8):
                bit_buffer[i * 8 + b] ^= ((c >> (7 - b)) & 1)
        r_subkeys = des_key_schedule(KDF_TABLES[r])
        L = 0
        R = 0
        for b in range(32):
            if bit_buffer[b]: L |= (1 << (31 - b))
            if bit_buffer[32 + b]: R |= (1 << (31 - b))
        for rnd in range(15):
            f_out = feistel_fast(R, r_subkeys[rnd])
            L, R = R, L ^ f_out
        f_out = feistel_fast(R, r_subkeys[15])
        L = L ^ f_out
        for b in range(32):
            bit_buffer[b] = (L >> (31 - b)) & 1
            bit_buffer[32 + b] = (R >> (31 - b)) & 1
    file_key = bit_buffer[:56]
    return des_key_schedule(file_key)

def _rol32(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xffffffff

def eden_sha1(chunk):
    """
    Eden Games proprietary variant of SHA-1 chunk checksum.
    Reads each of 16 message words as a single byte at block[i*4 + 3].
    """
    bit_len = len(chunk) * 8
    padded = bytearray(chunk)
    padded.append(0x80)
    while len(padded) % 64 != 56:
        padded.append(0x00)
    padded.extend(bit_len.to_bytes(8, 'big'))
    h0, h1, h2, h3, h4 = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
    for blk_idx in range(0, len(padded), 64):
        blk = padded[blk_idx : blk_idx + 64]
        W = [blk[i * 4 + 3] for i in range(16)]
        for i in range(16, 80):
            W.append(_rol32(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1))
        a, b, c, d, e = h0, h1, h2, h3, h4
        for i in range(80):
            if i < 20: f, k = (b & c) | ((~b) & d), 0x5a827999
            elif i < 40: f, k = b ^ c ^ d, 0x6ed9eba1
            elif i < 60: f, k = (b & c) | (b & d) | (c & d), 0x8f1bbcdc
            else: f, k = b ^ c ^ d, 0xca62c1d6
            temp = (_rol32(a, 5) + f + e + k + W[i]) & 0xffffffff
            e, d, c, b, a = d, c, _rol32(b, 30), a, temp
        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff
    out = bytearray()
    for h in [h0, h1, h2, h3, h4]:
        out.extend(h.to_bytes(4, 'big'))
    return bytes(out)


# ==============================================================================
# 3. CONTAINER DECRYPTION & ENCRYPTION
# ==============================================================================

def get_profile_crc_bytes(profile_name):
    """Computes 8-byte profile CRC identifier (crc32 & 0xffff)."""
    crc = zlib.crc32(profile_name.encode('latin1')) & 0xffff
    return crc.to_bytes(8, 'little')

def decrypt_save_file(file_bytes, profile_name=None, filename_hint=None):
    """
    Decrypts an encrypted TDU2 save container into raw uncompressed XMBF data.
    Verifies chunk hashes and footer.
    """
    if len(file_bytes) < 32:
        raise ValueError("File is too small to be a valid TDU2 save.")

    # Parse authentic footer: ## + [8B Profile ID] + [Filename] + ## + [1B Filename Length]
    fname_len = file_bytes[-1]
    footer_len = 2 + 8 + fname_len + 2 + 1
    if len(file_bytes) < footer_len:
        raise ValueError("Corrupt save footer length.")
    
    footer = file_bytes[-footer_len:]
    if footer[:2] != b'##' or footer[-3:-1] != b'##':
        raise ValueError("Invalid save footer magic.")

    extracted_filename = footer[10 : 10 + fname_len].decode('ascii', errors='ignore')
    target_filename = filename_hint or extracted_filename

    # Resolve profile ID / CRC
    if profile_name:
        profile_crc_bytes = get_profile_crc_bytes(profile_name)
    else:
        # If not supplied, use profile ID from footer directly
        profile_crc_bytes = footer[2:10]

    key_str = b'      ' + profile_crc_bytes[:2] + b'PLAYERSAVE' + target_filename.encode('ascii')
    sk = kdf(key_str)

    ct = file_bytes[:-footer_len]
    if len(ct) % 8 != 0:
        raise ValueError("Ciphertext length is not a multiple of 8.")

    # DES-CBC Decrypt
    iv_L, iv_R = struct.unpack('>II', profile_crc_bytes)
    prev_L, prev_R = iv_L, iv_R
    pt_bytes = bytearray()
    for blk_idx in range(len(ct) // 8):
        c_L, c_R = struct.unpack_from('>II', ct, blk_idx * 8)
        dec_L, dec_R = des_decrypt_fast(c_L, c_R, sk)
        p_L = dec_L ^ prev_L
        p_R = dec_R ^ prev_R
        prev_L, prev_R = c_L, c_R
        pt_bytes.extend(struct.pack('>II', p_L, p_R))

    part_sz, tot_sz = struct.unpack('<II', pt_bytes[:4] + pt_bytes[8:12])
    
    curr_off = 16
    rem = tot_sz
    chunks = []
    chunk_idx = 0
    while rem > 0:
        c_len = min(rem, 4096)
        p_len = (c_len + 7) & ~7
        d_chunk = pt_bytes[curr_off : curr_off + c_len]
        curr_off += p_len
        h_chunk = pt_bytes[curr_off : curr_off + 20]
        curr_off += 24
        calc_h = eden_sha1(d_chunk)
        if calc_h != h_chunk:
            raise ValueError(f"Checksum mismatch in chunk {chunk_idx}.")
        chunks.append(d_chunk)
        rem -= c_len
        chunk_idx += 1

    return bytes(b''.join(chunks)), footer, target_filename

def encrypt_save_file(uncompressed_bytes, profile_name, filename_str, original_footer=None):
    """
    Encrypts uncompressed XMBF data into a full TDU2 save container with
    chunk padding, Eden-SHA1 checksums, DES-CBC cipher, and footer.
    """
    profile_crc_bytes = get_profile_crc_bytes(profile_name)
    key_str = b'      ' + profile_crc_bytes[:2] + b'PLAYERSAVE' + filename_str.encode('ascii')
    sk = kdf(key_str)

    total_size = len(uncompressed_bytes)
    partial_size = total_size % 4096 if total_size % 4096 != 0 else 4096

    # Construct plaintext chunked payload
    payload = bytearray()
    payload.extend(struct.pack('<II', partial_size, 0))
    payload.extend(struct.pack('<II', total_size, 0))

    offset = 0
    while offset < total_size:
        chunk = uncompressed_bytes[offset : offset + 4096]
        offset += len(chunk)
        pad_len = (len(chunk) + 7) & ~7
        padded_chunk = chunk + b'\x00' * (pad_len - len(chunk))
        h = eden_sha1(chunk) + b'\x00\x00\x00\x00'
        payload.extend(padded_chunk)
        payload.extend(h)

    # DES-CBC Encrypt
    iv_L, iv_R = struct.unpack('>II', profile_crc_bytes)
    prev_L, prev_R = iv_L, iv_R
    ct_out = bytearray()
    num_blks = len(payload) // 8
    for blk_idx in range(num_blks):
        p_L, p_R = struct.unpack_from('>II', payload, blk_idx * 8)
        c_L, c_R = des_encrypt_fast(p_L ^ prev_L, p_R ^ prev_R, sk)
        prev_L, prev_R = c_L, c_R
        ct_out.extend(struct.pack('>II', c_L, c_R))

    if original_footer:
        footer = original_footer
    else:
        # Build standard container footer
        fn_bytes = filename_str.encode('ascii')
        footer = b'##' + profile_crc_bytes + fn_bytes + b'##' + bytes([len(fn_bytes)])

    return bytes(ct_out) + footer


# ==============================================================================
# 4. BINARY XML (XMBF) ENCODER & DECODER
# ==============================================================================

TYPE_NAMES = {
    0: 'OBJECT', 1: 'BOOL', 2: 'SINT8', 3: 'SINT16', 4: 'SINT32', 5: 'SINT64',
    6: 'UINT8', 7: 'UINT16', 8: 'UINT32', 9: 'UINT64', 10: 'FLOAT', 11: 'DOUBLE',
    12: 'STRING', 13: 'VIRTUAL'
}

def decode_xmbf_to_dict(xmbf_bytes):
    """Decodes binary XMBF bytes into a Python dictionary."""
    if len(xmbf_bytes) < 28 or xmbf_bytes[:4] != b'XMBF':
        raise ValueError("Invalid XMBF magic header.")

    magic, ver, sec0_off, sec1_off, sec2_off, root_name_off, root_type_id = struct.unpack('<7I', xmbf_bytes[:28])
    sec0 = xmbf_bytes[sec0_off:sec1_off]
    sec1_dwords = struct.unpack(f'<{ (sec2_off - sec1_off) // 4 }I', xmbf_bytes[sec1_off:sec2_off])
    sec2 = xmbf_bytes[sec2_off:]

    def get_sym(off):
        end = sec0.find(b'\x00', off)
        if end == -1: return ""
        return sec0[off:end].decode('latin1')

    def get_str(off):
        if off == 0xffffffff: return None
        end = sec2.find(b'\x00', off)
        if end == -1: return ""
        return sec2[off:end].decode('utf-8', errors='replace')

    def parse_primitive(ntype, off):
        if ntype == 1: return bool(sec2[off])
        elif ntype == 2: return struct.unpack_from('<b', sec2, off)[0]
        elif ntype == 3: return struct.unpack_from('<h', sec2, off)[0]
        elif ntype == 4: return struct.unpack_from('<i', sec2, off)[0]
        elif ntype == 5: return struct.unpack_from('<q', sec2, off)[0]
        elif ntype == 6: return sec2[off]
        elif ntype == 7: return struct.unpack_from('<H', sec2, off)[0]
        elif ntype == 8: return struct.unpack_from('<I', sec2, off)[0]
        elif ntype == 9: return struct.unpack_from('<Q', sec2, off)[0]
        elif ntype == 10: return round(struct.unpack_from('<f', sec2, off)[0], 4)
        elif ntype == 11: return struct.unpack_from('<d', sec2, off)[0]
        elif ntype == 12: return get_str(struct.unpack_from('<I', sec2, off)[0])
        else: return None

    def parse_struct(type_id, offset):
        hdr = sec1_dwords[type_id]
        ntype = hdr & 0xf
        if ntype != 0:
            raise ValueError(f"Expected struct type (0), got {ntype}")
        num_fields = (hdr >> 4) & 0x7ff
        res = {}
        cur_off = offset
        for f in range(num_fields):
            dw0 = sec1_dwords[type_id + 2 + f*2]
            dw1 = sec1_dwords[type_id + 2 + f*2 + 1]
            fname = get_sym(dw0 & 0x7fffffff)
            is_arr = (dw1 >> 31) & 1
            t_id = dw1 & 0x3fffffff
            
            if is_arr:
                cnt, arr_off = struct.unpack_from('<II', sec2, cur_off)
                cur_off += 8
                elem_hdr = sec1_dwords[t_id]
                elem_type = elem_hdr & 0xf
                items = []
                if elem_type == 0:
                    elem_size = (elem_hdr >> 15) & 0x1ffff
                    for k in range(cnt):
                        items.append(parse_struct(t_id, arr_off + k * elem_size))
                elif elem_type == 12:
                    for k in range(cnt):
                        s_off = struct.unpack_from('<I', sec2, arr_off + k * 4)[0]
                        items.append(get_str(s_off))
                else:
                    elem_size = (elem_hdr >> 15) & 0x1ffff
                    for k in range(cnt):
                        items.append(parse_primitive(elem_type, arr_off + k * elem_size))
                res[fname] = items
            else:
                target_hdr = sec1_dwords[t_id]
                target_ntype = target_hdr & 0xf
                if target_ntype == 0:
                    res[fname] = parse_struct(t_id, cur_off)
                    cur_off += (target_hdr >> 15) & 0x1ffff
                elif target_ntype == 12:
                    s_off = struct.unpack_from('<I', sec2, cur_off)[0]
                    res[fname] = get_str(s_off)
                    cur_off += 4
                elif target_ntype == 13:
                    v_tid, v_off = struct.unpack_from('<II', sec2, cur_off)
                    res[fname] = parse_struct(v_tid, v_off)
                    cur_off += 8
                else:
                    p_size = (target_hdr >> 15) & 0x1ffff
                    res[fname] = parse_primitive(target_ntype, cur_off)
                    cur_off += p_size
        return res

    root_name = get_sym(root_name_off)
    root_obj = parse_struct(root_type_id, 0)
    return root_name, root_obj

def encode_dict_to_xmbf(template_xmbf_bytes, data_dict, root_name=None):
    """
    Encodes a Python dictionary into binary XMBF using the schema header
    (Sections 0 and 1) from template_xmbf_bytes.
    """
    magic, ver, sec0_off, sec1_off, sec2_off, root_name_off, root_type_id = struct.unpack('<7I', template_xmbf_bytes[:28])
    sec0 = template_xmbf_bytes[sec0_off:sec1_off]
    sec1_dwords = struct.unpack(f'<{ (sec2_off - sec1_off) // 4 }I', template_xmbf_bytes[sec1_off:sec2_off])

    def get_sym(off):
        end = sec0.find(b'\x00', off)
        return sec0[off:end].decode('latin1')

    sec2_buf = bytearray()
    hdr = sec1_dwords[root_type_id]
    root_size = (hdr >> 15) & 0x1ffff
    sec2_buf.extend(b'\x00' * root_size)
    
    string_cache = {}
    def add_string(s):
        if s is None: return 0xffffffff
        if s in string_cache: return string_cache[s]
        s_bytes = str(s).encode('utf-8') + b'\x00'
        off = len(sec2_buf)
        sec2_buf.extend(s_bytes)
        string_cache[s] = off
        return off

    def encode_primitive(ntype, val):
        if ntype == 1: return struct.pack('<?', bool(val))
        elif ntype == 2: return struct.pack('<b', int(val))
        elif ntype == 3: return struct.pack('<h', int(val))
        elif ntype == 4: return struct.pack('<i', int(val))
        elif ntype == 5: return struct.pack('<q', int(val))
        elif ntype == 6: return struct.pack('<B', int(val))
        elif ntype == 7: return struct.pack('<H', int(val))
        elif ntype == 8: return struct.pack('<I', int(val))
        elif ntype == 9: return struct.pack('<Q', int(val))
        elif ntype == 10: return struct.pack('<f', float(val))
        elif ntype == 11: return struct.pack('<d', float(val))
        else: raise ValueError(f"Unknown primitive type {ntype}")

    def encode_struct(type_id, d_dict, dest_off):
        hdr = sec1_dwords[type_id]
        num_fields = (hdr >> 4) & 0x7ff
        cur_off = dest_off
        for f in range(num_fields):
            dw0 = sec1_dwords[type_id + 2 + f*2]
            dw1 = sec1_dwords[type_id + 2 + f*2 + 1]
            fname = get_sym(dw0 & 0x7fffffff)
            is_arr = (dw1 >> 31) & 1
            t_id = dw1 & 0x3fffffff
            val = d_dict.get(fname)
            
            if is_arr:
                items = val if val is not None else []
                cnt = len(items)
                elem_hdr = sec1_dwords[t_id]
                elem_type = elem_hdr & 0xf
                if cnt == 0:
                    arr_off = 0
                else:
                    arr_off = len(sec2_buf)
                    if elem_type == 0:
                        elem_size = (elem_hdr >> 15) & 0x1ffff
                        sec2_buf.extend(b'\x00' * (cnt * elem_size))
                        for k, item in enumerate(items):
                            encode_struct(t_id, item, arr_off + k * elem_size)
                    elif elem_type == 12:
                        sec2_buf.extend(b'\x00' * (cnt * 4))
                        for k, item in enumerate(items):
                            s_off = add_string(item)
                            struct.pack_into('<I', sec2_buf, arr_off + k * 4, s_off)
                    else:
                        elem_size = (elem_hdr >> 15) & 0x1ffff
                        sec2_buf.extend(b'\x00' * (cnt * elem_size))
                        for k, item in enumerate(items):
                            p_bytes = encode_primitive(elem_type, item)
                            sec2_buf[arr_off + k * elem_size : arr_off + k * elem_size + len(p_bytes)] = p_bytes
                struct.pack_into('<II', sec2_buf, cur_off, cnt, arr_off)
                cur_off += 8
            else:
                target_hdr = sec1_dwords[t_id]
                target_ntype = target_hdr & 0xf
                if target_ntype == 0:
                    struct_size = (target_hdr >> 15) & 0x1ffff
                    encode_struct(t_id, val if val is not None else {}, cur_off)
                    cur_off += struct_size
                elif target_ntype == 12:
                    s_off = add_string(val)
                    struct.pack_into('<I', sec2_buf, cur_off, s_off)
                    cur_off += 4
                elif target_ntype == 13:
                    cur_off += 8
                else:
                    p_size = (target_hdr >> 15) & 0x1ffff
                    if val is not None:
                        p_bytes = encode_primitive(target_ntype, val)
                        sec2_buf[cur_off : cur_off + len(p_bytes)] = p_bytes
                    cur_off += p_size

    target_root_name = root_name or get_sym(root_name_off)
    target_data = data_dict.get(target_root_name, data_dict)
    encode_struct(root_type_id, target_data, 0)

    new_hdr = struct.pack('<7I', magic, ver, sec0_off, sec1_off, sec2_off, root_name_off, root_type_id)
    return new_hdr + template_xmbf_bytes[sec0_off:sec2_off] + bytes(sec2_buf)


# ==============================================================================
# 5. PROFILE DETECTION HELPER
# ==============================================================================

def find_matching_profile(file_bytes, filename_hint, candidate_names):
    """Tests candidate profile names against file_bytes and returns the one that produces valid XMBF."""
    fname_str = filename_hint.upper()
    for name in candidate_names:
        if not name or not isinstance(name, str): continue
        crc = zlib.crc32(name.encode('latin1')) & 0xffff
        profile_crc_bytes = crc.to_bytes(8, 'little')
        try:
            key_str = b'      ' + profile_crc_bytes[:2] + b'PLAYERSAVE' + fname_str.encode('ascii')
            sk = kdf(key_str)
            fname_len = file_bytes[-1]
            footer_len = 2 + 8 + fname_len + 2 + 1
            if len(file_bytes) <= footer_len + 24: continue
            ct = file_bytes[:-footer_len]
            iv_L, iv_R = struct.unpack('>II', profile_crc_bytes)

            c0_L, c0_R = struct.unpack_from('>II', ct, 0)
            d0_L, d0_R = des_decrypt_fast(c0_L, c0_R, sk)
            p0_L, p0_R = d0_L ^ iv_L, d0_R ^ iv_R

            c1_L, c1_R = struct.unpack_from('>II', ct, 8)
            d1_L, d1_R = des_decrypt_fast(c1_L, c1_R, sk)
            p1_L, p1_R = d1_L ^ c0_L, d1_R ^ c0_R

            hdr_bytes = struct.pack('>IIII', p0_L, p0_R, p1_L, p1_R)
            part_sz, tot_sz = struct.unpack('<II', hdr_bytes[:4] + hdr_bytes[8:12])
            if 0 < tot_sz < 50_000_000 and 0 < part_sz <= 4096:
                c2_L, c2_R = struct.unpack_from('>II', ct, 16)
                d2_L, d2_R = des_decrypt_fast(c2_L, c2_R, sk)
                p2_L, p2_R = d2_L ^ c1_L, d2_R ^ c1_R
                magic = struct.pack('>II', p2_L, p2_R)[:4]
                if magic == b'XMBF':
                    return name
        except Exception:
            pass
    return None

def detect_profile_name(file_path, file_bytes=None):
    """
    Intelligently auto-detects the user profile name from folder hierarchy,
    ProfileList.dat, and cryptographic trial of known profiles.
    """
    p = Path(file_path).resolve()
    candidates = []

    # 1. Folder structure: .../<ProfileName>/PLAYERSAVE/...
    parts = list(p.parts)
    for i in range(len(parts) - 1):
        if parts[i+1].upper() == 'PLAYERSAVE' and parts[i] not in ['savegame', 'Test Drive Unlimited 2']:
            candidates.append(parts[i])

    # 2. Check Documents/Eden Games/Test Drive Unlimited 2/savegame/ProfileList.dat
    user_docs = Path(os.environ.get('USERPROFILE', '')) / 'Documents' / 'Eden Games' / 'Test Drive Unlimited 2' / 'savegame'
    search_dirs = [user_docs, p.parent, p.parent.parent, p.parent.parent.parent]
    for s_dir in search_dirs:
        prof_list = s_dir / 'ProfileList.dat'
        if prof_list.is_file():
            try:
                with open(prof_list, 'rb') as f:
                    pld = f.read()
                # ProfileList has 10 bytes header, then 257-byte records
                for r_idx in range((len(pld) - 10) // 257):
                    rec = pld[10 + r_idx * 257 : 10 + (r_idx + 1) * 257]
                    pname = rec[:256].split(b'\x00')[0].decode('latin1')
                    if pname and pname not in candidates:
                        candidates.append(pname)
            except Exception:
                pass

    # 3. Generic profile defaults
    for default_p in ['Player', 'Player1', 'Default']:
        if default_p not in candidates:
            candidates.append(default_p)

    # 4. If file_bytes provided, find exact matching candidate
    if file_bytes:
        match = find_matching_profile(file_bytes, p.stem, candidates)
        if match:
            return match

    return candidates[0] if candidates else 'Player'


# ==============================================================================
# 6. COMMAND HANDLERS
# ==============================================================================

def cmd_unpack(args):
    """Unpack save file or folder into human-readable JSON."""
    target_path = Path(args.path).resolve()
    out_dir = Path(args.output).resolve() if args.output else None
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)

    if target_path.is_dir():
        save_files = [f for f in target_path.glob('*') if f.is_file() and f.suffix == '' and f.name.upper() in ['DATA', 'KEYMAP', 'OPTIONS']]
    else:
        save_files = [target_path]

    if not save_files:
        print(f"No valid TDU2 save files found at {target_path}")
        return

    for sf in save_files:
        with open(sf, 'rb') as f:
            data = f.read()
        prof_name = args.profile or detect_profile_name(sf, data)
        print(f"[*] Unpacking {sf.name} (Profile: {prof_name})...")

        # Backup original save if not already backed up
        bak_file = sf.with_suffix('.bak')
        if not bak_file.exists():
            with open(bak_file, 'wb') as f:
                f.write(data)
            print(f"    Created backup: {bak_file.name}")

        try:
            xmbf_data, footer, fname = decrypt_save_file(data, prof_name, sf.name)
            dest_dir = out_dir if out_dir else sf.parent
            
            # Save raw decrypted XMBF if requested
            if args.raw:
                dec_path = dest_dir / f"{sf.name}.dec"
                with open(dec_path, 'wb') as f:
                    f.write(xmbf_data)
                print(f"    Saved raw binary XMBF: {dec_path.name}")

            # Parse XMBF to JSON
            root_name, obj = decode_xmbf_to_dict(xmbf_data)
            json_path = dest_dir / f"{sf.name}.json"
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump({root_name: obj}, f, indent=2, ensure_ascii=False)
            print(f"    Successfully exported: {json_path.name} (Root: {root_name})")

        except Exception as e:
            print(f"    [!] Error unpacking {sf.name}: {e}")

def cmd_pack(args):
    """Pack modified JSON into binary XMBF, chunk, encrypt, and attach footer."""
    json_path = Path(args.path).resolve()
    if json_path.is_dir():
        json_files = [f for f in json_path.glob('*.json')]
    else:
        json_files = [json_path]

    if not json_files:
        print(f"No JSON files found at {json_path}")
        return

    out_target = Path(args.output).resolve() if getattr(args, 'output', None) else None
    if out_target and (len(json_files) > 1 or not out_target.suffix):
        out_target.mkdir(parents=True, exist_ok=True)

    for jf in json_files:
        save_stem = jf.stem.upper()
        if out_target:
            if out_target.is_dir() or len(json_files) > 1 or not out_target.suffix:
                out_save = out_target / save_stem
            else:
                out_save = out_target
        else:
            out_save = jf.parent / save_stem

        # Locate template schema: prefer .dec, then .bak, then existing save
        template_file = None
        for candidate in [jf.with_suffix('.dec'), jf.with_suffix('.bak'), out_save, jf.parent / save_stem]:
            if candidate.exists():
                template_file = candidate
                break

        if not template_file:
            print(f"    [!] Cannot pack {jf.name}: No template schema file found (.dec, .bak, or save).")
            continue

        with open(template_file, 'rb') as f:
            template_bytes = f.read()

        with open(jf, 'r', encoding='utf-8') as f:
            json_data = json.load(f)

        # Resolve profile name
        prof_name = args.profile
        if not prof_name:
            if 'PlayerData' in json_data and 'Driver' in json_data['PlayerData']:
                prof_name = json_data['PlayerData']['Driver'].get('Name')
            elif (jf.parent / 'DATA.json').exists():
                try:
                    with open(jf.parent / 'DATA.json', 'r', encoding='utf-8') as df:
                        d_json = json.load(df)
                    prof_name = d_json.get('PlayerData', {}).get('Driver', {}).get('Name')
                except Exception:
                    pass

        if not prof_name and template_bytes[:4] != b'XMBF':
            prof_name = detect_profile_name(template_file, template_bytes)

        if not prof_name:
            prof_name = detect_profile_name(jf)

        print(f"[*] Packing {jf.name} -> {out_save} (Profile: {prof_name})...")

        original_footer = None
        if template_bytes[:4] != b'XMBF':
            template_bytes, original_footer, _ = decrypt_save_file(template_bytes, prof_name, save_stem)
        else:
            # Check potential locations for original encrypted save to preserve authentic footer
            footer_candidates = [
                jf.with_suffix('.bak'),
                out_save if out_save.exists() and out_save.stat().st_size != 0 else None,
                jf.parent / save_stem if (jf.parent / save_stem).exists() else None,
                (jf.parent.parent / prof_name / 'PLAYERSAVE' / save_stem) if prof_name and (jf.parent.parent / prof_name / 'PLAYERSAVE' / save_stem).exists() else None,
            ]
            for fc in footer_candidates:
                if fc and fc.is_file():
                    try:
                        with open(fc, 'rb') as fcf:
                            fc_data = fcf.read()
                        if fc_data[-1] == len(save_stem):
                            flen = 2 + 8 + len(save_stem) + 2 + 1
                            if fc_data[-flen:-flen+2] == b'##' and fc_data[-3:-1] == b'##':
                                original_footer = fc_data[-flen:]
                                break
                    except Exception:
                        pass

        new_xmbf = encode_dict_to_xmbf(template_bytes, json_data)

        # Encrypt and write
        enc_data = encrypt_save_file(new_xmbf, prof_name, save_stem, original_footer)
        with open(out_save, 'wb') as f:
            f.write(enc_data)
        print(f"    Successfully generated encrypted save: {out_save.name} ({len(enc_data):,} bytes)")

def cmd_decrypt(args):
    """Decrypt save file to raw .dec (XMBF)."""
    in_path = Path(args.input).resolve()
    out_path = Path(args.output).resolve() if args.output else in_path.with_suffix('.dec')
    with open(in_path, 'rb') as f:
        data = f.read()
    prof_name = args.profile or detect_profile_name(in_path, data)

    print(f"[*] Decrypting {in_path.name} (Profile: {prof_name})...")
    xmbf, _, _ = decrypt_save_file(data, prof_name, in_path.name)
    with open(out_path, 'wb') as f:
        f.write(xmbf)
    print(f"    Wrote: {out_path.name} ({len(xmbf):,} bytes)")

def cmd_encrypt(args):
    """Encrypt raw .dec (XMBF) into save container."""
    in_path = Path(args.input).resolve()
    save_name = in_path.stem.upper()
    out_path = Path(args.output).resolve() if args.output else in_path.parent / save_name
    prof_name = args.profile or detect_profile_name(in_path)

    print(f"[*] Encrypting {in_path.name} -> {out_path.name} (Profile: {prof_name})...")
    with open(in_path, 'rb') as f:
        xmbf = f.read()
    enc = encrypt_save_file(xmbf, prof_name, save_name)
    with open(out_path, 'wb') as f:
        f.write(enc)
    print(f"    Wrote: {out_path.name} ({len(enc):,} bytes)")

def cmd_verify(args):
    """Verify integrity, chunk checksums, and profile matching of save file(s)."""
    target = Path(args.path).resolve()
    files = [f for f in target.glob('*') if f.is_file() and f.suffix == '' and f.name.upper() in ['DATA', 'KEYMAP', 'OPTIONS']] if target.is_dir() else [target]
    for sf in files:
        with open(sf, 'rb') as f: data = f.read()
        prof = args.profile or detect_profile_name(sf, data)
        try:
            pt, footer, fn = decrypt_save_file(data, prof, sf.name)
            print(f"[+] {sf.name:<8}: VALID | Profile: {prof:<8} | Size: {len(pt):<7} | Root: {pt[:4].decode('ascii', 'ignore')}")
        except Exception as e:
            print(f"[-] {sf.name:<8}: FAILED | {e}")

def cmd_edit(args):
    """High-level quick modifications on save file without manual JSON editing."""
    target_path = Path(args.path).resolve()
    # Find DATA save file
    source_dir = None
    if target_path.is_dir():
        if (target_path / 'DATA').exists():
            data_file = target_path / 'DATA'
            source_dir = target_path
        elif (target_path / 'PLAYERSAVE' / 'DATA').exists():
            data_file = target_path / 'PLAYERSAVE' / 'DATA'
            source_dir = target_path / 'PLAYERSAVE'
        else:
            data_file = target_path / 'DATA'
            source_dir = target_path
    else:
        data_file = target_path
        source_dir = target_path.parent

    if not data_file.exists():
        print(f"[!] DATA file not found at {data_file}")
        return

    with open(data_file, 'rb') as f:
        raw_data = f.read()

    prof_name = args.profile or detect_profile_name(data_file, raw_data)
    print(f"[*] Reading and modifying save: {data_file} (Profile: {prof_name})...")

    out_target = Path(args.output).resolve() if getattr(args, 'output', None) else None
    if out_target:
        if not out_target.suffix:
            out_target.mkdir(parents=True, exist_ok=True)
            out_file = out_target / 'DATA'
            if source_dir:
                import shutil
                for sibling in source_dir.glob('*'):
                    if sibling.is_file() and sibling.name.upper() in ['KEYMAP', 'OPTIONS']:
                        shutil.copyfile(sibling, out_target / sibling.name)
        else:
            out_target.parent.mkdir(parents=True, exist_ok=True)
            out_file = out_target
    else:
        out_file = data_file
        # Backup
        bak_file = data_file.with_suffix('.bak')
        if not bak_file.exists():
            with open(bak_file, 'wb') as f:
                f.write(raw_data)
            print(f"    Created backup: {bak_file.name}")

    xmbf_bytes, footer, fn = decrypt_save_file(raw_data, prof_name, 'DATA')
    root_name, data_obj = decode_xmbf_to_dict(xmbf_bytes)
    assert root_name == 'PlayerData', f"Expected PlayerData root, got {root_name}"

    changes = []

    # 1. Money
    if args.money is not None:
        old_val = data_obj['Driver']['Money']
        data_obj['Driver']['Money'] = int(args.money)
        changes.append(f"Money: ${old_val:,} -> ${args.money:,}")

    # 2. Casino Coupons
    if args.coupons is not None:
        old_val = data_obj['Driver']['NbCoupon']
        data_obj['Driver']['NbCoupon'] = int(args.coupons)
        changes.append(f"Casino Coupons: {old_val:,} -> {args.coupons:,}")

    # 3. Max Levels & Objectives
    if args.max_levels:
        lvl = data_obj.setdefault('PlayerLevels', {})
        lvl['RacingLevel'] = 10000
        lvl['CollectionLevel'] = 10000
        lvl['SocialLevel'] = 10000
        lvl['CruisingLevels'] = {
            'Area_0': 2080, # Ibiza 1 (2080/2080 = 100%)
            'Area_1': 2080, # Ibiza 2 (2080/2080 = 100%)
            'Area_2': 2425, # Hawaii 1 (2425/2425 = 100%)
            'Area_3': 2640, # Hawaii 2 (2640/2640 = 100%)
            'Area_4': 2550, # Hawaii 3 (2550/2550 = 100%)
            'Area_5': 2725  # Hawaii 4 (2725/2725 = 100%)
        }
        lvl['HaircutsBought'] = [10, 10, 10, 10]
        if 'AreaTotalRoads' in lvl:
            lvl['AreaRoadsUnlocked'] = list(lvl['AreaTotalRoads'])
        lvl['AirportUnlocked'] = True
        lvl['NewsAirportSend'] = True

        # Competition Objectives: Racing School, Championships & Cups
        lic = data_obj.setdefault('PlayerLicenses', {})
        lic['CurLicenseA'] = 3
        lic['CurLicenseB'] = 2
        lic['CurLicenseC'] = 2
        for l in lic.get('Licenses', []):
            l['Passed'] = True
            l['Looked'] = True
            l['RemainingReward'] = 0
            l['PhotoIndex'] = 1
            for t in l.get('DrivingTest', []):
                t['Success'] = True
                t['Try'] = True
                t['Score'] = 50000

        for c in lic.get('Contests', []):
            c['Passed'] = True
            c['Looked'] = True
            c['RemainingReward'] = 0
            c['Cup'] = 3   # Gold Cup
            c['State'] = 3 # Completed
            for ch in c.get('Challenge', []):
                ch['Success'] = True
                ch['Try'] = True
                ch['Score'] = 50000

        # Discovery Objectives: Events, Wrecks, and Viewpoints
        ev = data_obj.setdefault('EventsSave', {})
        for e in ev.get('Events', []):
            e['State'] = 5 # Completed / Won
            e['TimeBeforeRespawn'] = 0.0
        for e in ev.get('DLCEvents', []):
            e['State'] = 5
            e['TimeBeforeRespawn'] = 0.0

        wr = data_obj.setdefault('Wrecks', {})
        for k in ['Wrecks_IBIZA', 'Wrecks_HAWAI', 'Wrecks_CASINO']:
            for w in wr.get(k, []):
                w['Taken'] = True

        ph = data_obj.setdefault('PhotosGP', {})
        ph['Active'] = True
        ph['GotIslandReward'] = [True, True, True]
        for p in ph.get('PhotosGP', []):
            p['Taken'] = True

        # Social Objectives: Chase mode, Club, C.R.C., Co-op
        chase = data_obj.setdefault('Chase', {})
        chase['OutlawVictories'] = 10
        chase['OutlawMaxVictories'] = 10
        chase['PoliceVictories'] = 10
        chase['Rewards'] = 10
        chase['ResetNeeded'] = False

        # Shop visits and driver counters
        sc = data_obj.setdefault('SCPhoneCalls', {})
        sc['BeenInClothesShop'] = True
        sc['BeenInStickerShop'] = True
        sc['BeenInHairShop'] = True
        sc['BeenInSurgeryShop'] = True
        sc['BeenInCarWash'] = True
        sc['BeenInPhotograph'] = True
        sc['BeenInRSDirtHawai'] = True
        sc['BeenInRSClassicHawai'] = True

        drv = data_obj.setdefault('Driver', {})
        drv['NbSurgeries'] = 10
        drv['NbHaircuts'] = 40
        drv['HasBeenMillionaire'] = True
        drv['LastSeenClubRank'] = 3

        # StatisticsData counters
        stats = data_obj.setdefault('StatisticsData', {})
        stat_updates = {
            'SoloWon': 100, 'ICEvsBotWon': 50, 'ICEvsHumanWon': 50,
            'MultiRaceWon': 50, 'MultiRankedWon': 50, 'MultiNonRankedWon': 50,
            'MultiSpeedWon': 50, 'MultiTrapWon': 50, 'MultiOrientationWon': 50, 'MultiEliminatorWon': 50,
            'NbCarUpgrade': 100, 'NbBikeUpgrade': 50, 'NbCarPaint': 50, 'NbBikePaint': 50,
            'NbHouseBought': 25, 'NbClothesBought': 150, 'NbClothesChange': 50, 'NbWatchesBought': 20,
            'NbHaircutsBought': 40, 'NbCarWithStickersBought': 10, 'NbCarSticked': 20, 'NbStickersBought': 50,
            'NbFriendsInvited': 20, 'NbFriendsJoined': 20, 'NbClubMaker': 1, 'NbClubJoiner': 1,
            'ClubWon': 50, 'InterClubWonByTeam': 50, 'OdometerInnerClub': 100.0,
            'CrcChaWon': 50, 'CrcChaRuns': 50, 'ExtraChaWon': 50,
            'ChaseHunterWon': 20, 'ChasePreyWon': 20, 'TimeInCoop': 3600.0,
            'KYDWon': 20, 'FTLWon': 20, 'NbCodrivingAsPilot': 20, 'NbCodrivingAsCopilot': 20
        }
        for sk, sv in stat_updates.items():
            if sk in stats:
                stats[sk] = sv

        changes.append("Maxed out Competition, Collection, Discovery (14,500), and Social levels & all sub-objectives")
        changes.append("Set exact map discovery points: Ibiza 1 (2080), Ibiza 2 (2080), Hawaii 1-4 (2425, 2640, 2550, 2725)")

    # 4. Unlock Roads
    if args.unlock_roads:
        lvl = data_obj.setdefault('PlayerLevels', {})
        if 'AreaTotalRoads' in lvl:
            lvl['AreaRoadsUnlocked'] = list(lvl['AreaTotalRoads'])
        lvl['CruisingLevels'] = {
            'Area_0': 2080,
            'Area_1': 2080,
            'Area_2': 2425,
            'Area_3': 2640,
            'Area_4': 2550,
            'Area_5': 2725
        }
        changes.append("Unlocked 100% road discovery for all areas (Ibiza 1: 2080, Ibiza 2: 2080, Hawaii 1-4: 2425, 2640, 2550, 2725)")

    # 5. Unlock Licenses
    if args.unlock_licenses:
        lic = data_obj.setdefault('PlayerLicenses', {})
        lic['CurLicenseA'] = 3
        lic['CurLicenseB'] = 2
        lic['CurLicenseC'] = 2
        for l in lic.get('Licenses', []):
            l['Passed'] = True
            l['Looked'] = True
            l['RemainingReward'] = 0
            l['PhotoIndex'] = 1
            for t in l.get('DrivingTest', []):
                t['Success'] = True
                t['Try'] = True
                t['Score'] = 50000
        changes.append("Unlocked all driving school licenses and passed all tests")

    # 6. Clean and repair all cars
    if args.clean_cars:
        garage = data_obj.get('Garage', [])
        for car_entry in garage:
            car = car_entry.get('Car', {})
            if 'Car Dirt' in car:
                dirt = car['Car Dirt']
                dirt['BodyDirt'] = 0.0
                dirt['GlassDirt'] = 0.0
                dirt['RimsDirt'] = 0.0
                dirt['BodyScratches'] = 0.0
        changes.append(f"Cleaned and repaired all {len(garage)} cars in garage")

    if not changes:
        print("No edit options specified. Use --help to view available modification flags.")
        return

    for c in changes:
        print(f"    [+] {c}")

    # Re-encode and save
    new_xmbf = encode_dict_to_xmbf(xmbf_bytes, {root_name: data_obj}, root_name)
    enc_save = encrypt_save_file(new_xmbf, prof_name, 'DATA', footer)

    with open(out_file, 'wb') as f:
        f.write(enc_save)
    print(f"[*] Successfully saved modified savegame: {out_file}")


# ==============================================================================
# 7. MAIN CLI PARSER
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Test Drive Unlimited 2 (TDU2) Save Game Tool - Decrypt, Unpack, Edit, Repack."
    )
    parser.add_argument('-p', '--profile', type=str, help="Player profile name (e.g. Player). Auto-detected if omitted.")

    subparsers = parser.add_subparsers(dest='command', required=True)

    # unpack
    p_unpack = subparsers.add_parser('unpack', help="Decrypt and unpack save file(s) into readable JSON.")
    p_unpack.add_argument('path', type=str, help="Path to save file (DATA/KEYMAP/OPTIONS) or PLAYERSAVE directory.")
    p_unpack.add_argument('--raw', action='store_true', help="Also export raw decrypted XMBF (.dec) files.")
    p_unpack.add_argument('-o', '--output', type=str, help="Output directory to place unpacked files.")

    # pack
    p_pack = subparsers.add_parser('pack', help="Compile JSON file(s) back into encrypted save container(s).")
    p_pack.add_argument('path', type=str, help="Path to JSON file or directory.")
    p_pack.add_argument('-o', '--output', type=str, help="Output directory or file path for packed save file(s).")

    # decrypt
    p_dec = subparsers.add_parser('decrypt', help="Decrypt save file to raw .dec (XMBF).")
    p_dec.add_argument('input', type=str, help="Input encrypted save file.")
    p_dec.add_argument('-o', '--output', type=str, help="Output .dec file path.")

    # encrypt
    p_enc = subparsers.add_parser('encrypt', help="Encrypt raw .dec (XMBF) file to save file.")
    p_enc.add_argument('input', type=str, help="Input .dec file.")
    p_enc.add_argument('-o', '--output', type=str, help="Output save file path.")

    # verify
    p_ver = subparsers.add_parser('verify', help="Verify integrity and chunk checksums of save file(s).")
    p_ver.add_argument('path', type=str, help="Path to save file or PLAYERSAVE directory.")

    # edit
    p_edit = subparsers.add_parser('edit', help="Apply quick modifications to savegame directly.")
    p_edit.add_argument('path', type=str, help="Path to DATA save file or PLAYERSAVE directory.")
    p_edit.add_argument('-o', '--output', type=str, help="Output directory or file path for modified save.")
    p_edit.add_argument('--money', type=int, help="Set driver money amount.")
    p_edit.add_argument('--coupons', type=int, help="Set casino coupons amount.")
    p_edit.add_argument('--max-levels', action='store_true', help="Set Racing, Collection, Social, and Cruising levels to max.")
    p_edit.add_argument('--unlock-roads', action='store_true', help="Unlock 100% discovered roads for Ibiza and Hawaii.")
    p_edit.add_argument('--unlock-licenses', action='store_true', help="Unlock all driving school licenses.")
    p_edit.add_argument('--clean-cars', action='store_true', help="Reset dirt and damage on all owned cars.")

    args = parser.parse_args()

    if args.command == 'unpack':
        cmd_unpack(args)
    elif args.command == 'pack':
        cmd_pack(args)
    elif args.command == 'decrypt':
        cmd_decrypt(args)
    elif args.command == 'encrypt':
        cmd_encrypt(args)
    elif args.command == 'verify':
        cmd_verify(args)
    elif args.command == 'edit':
        cmd_edit(args)

if __name__ == '__main__':
    main()
