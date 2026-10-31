# SPDX-FileCopyrightText: 2026 Copyright Contributors to the anathema-ttyusb0-translator project
#

# SPDX-License-Identifier: LGPL-2.1-or-later WITH WxWindows-exception-3.1

import base64
import re

from numba import njit
import numpy as np

from . import constants

logger = constants.logger
B64_ALPHABET = constants.B64_ALPHABET

# gpg auto fix stuff

#region

@njit(cache=True)
def compute_cr24_checksum(data: bytes | np.typing.NDArray[np.uint8]) -> int:
    crc = 0xB704CE
    for octet in data:
        crc = ((crc << 8) & 0xFFFFFF) ^ CRC24_TABLE[((crc >> 16) ^ octet) & 0xFF]
    return crc

def make_checksum_table() -> np.ndarray:
    table = np.zeros(256, dtype=np.int64)
    for i in range(256):
        crc = i << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
        table[i] = crc & 0xFFFFFF
    return table


def fix_gpg_thing(gpg_block: str, gpg_brute_bytes: int = 1):
    logger.info('fixing gpg block')
    gpg_block = gpg_block
    output_gpg = ''
    gpg_parts = []
    applied_gpg_corrections = False
    
    armor_start_headers: list[str] = [
        "BEGIN PGP MESSAGE",
        "BEGIN PGP PUBLIC KEY BLOCK",
        "BEGIN PGP PRIVATE KEY BLOCK",
        "BEGIN PGP SIGNATURE",
    ]
    armor_end_headers = [
        "END PGP MESSAGE",
        "END PGP PUBLIC KEY BLOCK",
        "END PGP PRIVATE KEY BLOCK",
        "END PGP SIGNATURE",
    ]
    logger.info('finding gpg start header')
    
    used_start_header = ''
    used_end_header = ''
    found_header = False
    for start_header in armor_start_headers:
        header_line = '-'*5+start_header+'-'*5
        header_index = gpg_block.find(header_line)
        if header_index == -1:
            continue
        used_start_header = header_line
        found_header = True
        
    if found_header is False:
        return gpg_block, False, applied_gpg_corrections
        
    found_header = False
    logger.info('finding gpg end header')
    for end_header in armor_end_headers:
        header_line = '-'*5+end_header+'-'*5
        header_index = gpg_block.find(header_line)
        if header_index == -1:
            continue
        used_end_header = header_line
        found_header = True
    if found_header is False:
        return gpg_block, False, applied_gpg_corrections
    logger.info('finding gpg cr24 checksum')
    
    equal_sign_index = gpg_block.rfind('=')
    
    if equal_sign_index == -1:
        return gpg_block, False, applied_gpg_corrections
    
    gpg_parts.append(used_start_header.strip())
    gpg_parts.append(gpg_block[gpg_block.find(used_start_header)+len(used_start_header): equal_sign_index].strip())
    gpg_parts.append(gpg_block[equal_sign_index:gpg_block.find(used_end_header)].strip())
    gpg_parts.append(used_end_header.strip())
    logger.info('brute forcing the key')
    
    temp_text = re.sub(r'\s', '', "".join(char for char in gpg_parts[1] if char in B64_ALPHABET))
    checksum_bytes = int.from_bytes(base64.b64decode(gpg_parts[2].lstrip('=')), 'big')
    
    
    gpg_parts[1], fixed, applied_gpg_corrections = brute_force_gpg(temp_text, checksum_bytes, gpg_brute_bytes)
    
    # no correct code found
    if not fixed:
        return gpg_block, False, applied_gpg_corrections
    
    output_gpg += gpg_parts[0]
    output_gpg += '\n'
    output_gpg += '\n'
    current_line_length = 0
    line_to_add = ''
    for letter in gpg_parts[1]:
        current_line_length += 1
        line_to_add += letter
        if current_line_length == 76:
            output_gpg += line_to_add.strip()
            line_to_add = ''
            output_gpg += '\n'
            current_line_length = 0
    if line_to_add:
        output_gpg += line_to_add.strip()
        output_gpg += '\n'
    
    
    output_gpg += gpg_parts[2]
    output_gpg += '\n'
    output_gpg += gpg_parts[3]
    output_gpg += '\n'

    return output_gpg, True, applied_gpg_corrections



def brute_force_gpg(text: str, checksum: int, gpg_brute_bytes: int = 1):
    base64_text = text.rstrip('=')
    applied_gpg_corrections = False
    
    # tries to repair it if its too long
    if len(base64_text) % 4 == 1:
        for deleted_index in range(len(base64_text)):
            repaired_text = base64_text[:deleted_index] + base64_text[deleted_index + 1:]
            repaired_bytes = np.frombuffer(base64.b64decode(repaired_text), dtype=np.uint8)
            if compute_cr24_checksum(repaired_bytes) == checksum:
                applied_gpg_corrections = True
                return repaired_text, True, applied_gpg_corrections
        return None, False, applied_gpg_corrections

    # pad the base64
    padded_text = base64_text + '=' * (-len(base64_text) % 4)
    
    # convert the base64 into bytes
    original_bytes = np.frombuffer(base64.b64decode(padded_text), dtype=np.uint8).copy()

    
    fixed, fixed_bytes, applied_gpg_corrections = brute_force_gpg_bytes(original_bytes, checksum, gpg_brute_bytes)
    if not fixed:
        return None, False, applied_gpg_corrections

    return base64.b64encode(fixed_bytes.tobytes()).decode(), True, applied_gpg_corrections



@njit(cache=True)
def advance_combination(positions: np.ndarray, pool_size: int) -> bool:
    combination_size = len(positions)
    slot = combination_size - 1
    while slot >= 0 and positions[slot] == slot + pool_size - combination_size:
        slot -= 1
    if slot < 0:
        return False
    positions[slot] += 1
    for later_slot in range(slot + 1, combination_size):
        positions[later_slot] = positions[later_slot - 1] + 1
    return True


@njit(cache=True)
def brute_force_gpg_bytes(original_bytes: np.ndarray, expected_checksum: int, max_changes: int):
    byte_count = len(original_bytes)

    if compute_cr24_checksum(original_bytes) == expected_checksum:
        return True, original_bytes, False

    # sub
    candidate = original_bytes.copy()
    for change_count in range(1, max_changes + 1):
        if change_count > byte_count:
            break
        positions = np.arange(change_count)
        while True:
            value_offsets = np.ones(change_count, dtype=np.int64)
            while True:
                for slot in range(change_count):
                    candidate[positions[slot]] = (original_bytes[positions[slot]] + value_offsets[slot]) % 256
                if compute_cr24_checksum(candidate) == expected_checksum:
                    return True, candidate, True

                slot = change_count - 1
                while slot >= 0 and value_offsets[slot] == 255:
                    value_offsets[slot] = 1
                    slot -= 1
                if slot < 0:
                    break
                value_offsets[slot] += 1

            for slot in range(change_count):
                candidate[positions[slot]] = original_bytes[positions[slot]]
            if not advance_combination(positions, byte_count):
                break

    # del
    for change_count in range(1, max_changes + 1):
        if change_count > byte_count:
            break
        positions = np.arange(change_count)
        shortened = np.empty(byte_count - change_count, dtype=np.uint8)
        while True:
            write_index = 0
            next_deleted_slot = 0
            for read_index in range(byte_count):
                if next_deleted_slot < change_count and positions[next_deleted_slot] == read_index:
                    next_deleted_slot += 1
                    continue
                shortened[write_index] = original_bytes[read_index]
                write_index += 1
            if compute_cr24_checksum(shortened) == expected_checksum:
                return True, shortened, True
            if not advance_combination(positions, byte_count):
                break

    # insert
    lengthened = np.empty(byte_count + 1, dtype=np.uint8)
    for insert_index in range(byte_count + 1):
        lengthened[:insert_index] = original_bytes[:insert_index]
        lengthened[insert_index + 1:] = original_bytes[insert_index:]
        for inserted_value in range(256):
            lengthened[insert_index] = inserted_value
            if compute_cr24_checksum(lengthened) == expected_checksum:
                return True, lengthened, True

    return False, original_bytes, False

#endregion



CRC24_TABLE = make_checksum_table()
