import argparse
import logging
import sys
from pathlib import Path
import shutil
import base64
import re
import binascii
from itertools import combinations, product
import time
from functools import partial
import timeit

from numba import njit
import numpy as np

from bitstring import BitArray, Reader

from importlib.metadata import version, PackageNotFoundError

try:
    __version__ = version("anathema-ttyusb0-translator")
except PackageNotFoundError:
    __version__ = "unknown"

logging.basicConfig(
    level=logging.ERROR,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)



def decode_message(
    input_message: bytes,
    bit_correct: bool = False,
    decode_type: int = 0,
    statuses_detection: bool = False,
    gpg_block: bool = False,
    gpg_brute_bytes: int = 1,
    ) -> dict:
    # decode_type = 0 # text
    # decode_type = 1 # binary
    
    worked = True
    
    # the main decoded message
    message = None
    if decode_type == 0:
        message = ''
    elif decode_type ==1:
        message = bytes()
    # the control code meanings between 0x03 and 0x04
    statuses = ''
    statuses_array: list[int] = []
    
    # any extra info the function genrates, such as canceling
    footer = ''
    footer_array: list[int] = []
    
    # whether it skipped any bits
    applied_bit_corrections = False

    # whether or not it applied gpg corrections
    applied_gpg_corrections = False
    
    if input_message[-1] in footer_table:
        footer += f'\n{footer_table[input_message[-1]]}\n'
        footer_array.append(input_message[-1])

    if input_message[0] in footer_table:
        footer += f'\n{footer_table[input_message[0]]}\n'
        footer_array.append(input_message[0])

    message_bit_data = BitArray(input_message)

    total = len(message_bit_data)

    text_start = 0

    text_end = total

    transmission_end = total



    # set text_start to the start of START_OF_MESSAGE
    pointer = 0
    while pointer < len(input_message) and input_message[pointer] != START_OF_MESSAGE:
        pointer += 1
    text_start = (pointer + 1) * 8 - 8

    if statuses_detection:
        # set text_end to the start of END_OF_MESSAGE
        pointer = len(input_message) - 1
        while pointer > 0 and input_message[pointer-1] != END_OF_MESSAGE:
            pointer -= 1
        text_end = (pointer - 1) * 8



        # set transmission_end to the start of END_OF_TRANSMITION
        pointer = len(input_message)
        while pointer > 0 and input_message[pointer-1] != END_OF_TRANSMITION:
            pointer -= 1
        transmission_end = (pointer - 1) * 8
    else:
        text_end = (len(input_message)-1)*8
        transmission_end = len(input_message)*8


    logger.debug(f"text_start: {text_start}")
    logger.debug(f"text_end: {text_end}")
    logger.debug(f"transmission_end: {transmission_end}")

    # split the stream into the two diffrent parts
    text_section_array = message_bit_data[text_start+8:text_end]
    text_section = Reader(text_section_array)
    logger.debug(text_section_array)

    statuses_section_array = message_bit_data[text_end+8:transmission_end]
    statuses_section = Reader(statuses_section_array)
    logger.debug(statuses_section_array)

    # add the statues to the message from the end of the message
    if len(statuses_section) != 0:
        while statuses_section.pos < len(statuses_section):
            byte = int(statuses_section.read_bits(8).bin, 2)
            logger.debug(f"found byte: {byte} at {statuses_section.pos-8}, offset: {statuses_section.pos}, expected next offset: {text_section.pos+9}")
            statuses += status_table.get(byte, f'UNMAPPED STATUS: {byte}')
            statuses_array.append(byte)

    
    bits = text_section_array.bin
    posistion = 0
    # parse the main message payload
    while posistion < len(bits):
        remain = len(text_section) - posistion

        # if remain is less than 9 then move text_section.pos to byte alignment
        if remain < 9:
            posistion += (8 - posistion % 8) % 8
            break

        byte = int(bits[posistion + 1:posistion + 9], 2)

        if bit_correct:
            # i found out while making this a 9 bit part is caleld a nonet, sometimes
            # check if setment starts with a 1, if its a 0 discard the entire byte
            if bits[posistion] == '0':
                applied_bit_corrections = True
                posistion += 9
                continue

            # if its non printable, its probably not aligned, attempt to realign
            if byte not in allowed_printables:
                applied_bit_corrections = True
                posistion += 1
                continue

        # logger.debug(f"{byte} -> {byte.to_bytes()} start: {start}, {data}, offset: {text_section.pos}, expected next offset: {text_section.pos+9}")
        if decode_type == 0:
            message += byte.to_bytes().decode("latin-1")
        elif decode_type == 1:
            message += byte.to_bytes()
        posistion += 9


    if gpg_block == True and decode_type == 0:
        message, worked, applied_gpg_corrections = fix_gpg_thing(message, gpg_brute_bytes)
        if worked == False:
            message += '\n'
            message += '\nFAILED TO VERIFY CHECKSUM'
            message += '\nFAILED TO VERIFY CHECKSUM'
            message += '\nFAILED TO VERIFY CHECKSUM'
            
    return {
        "message": message,
        'statuses': statuses,
        'footer': footer,
        'applied_bit_corrections': applied_bit_corrections,
        'statuses_array': statuses_array,
        'footer_array': footer_array,
        'worked': worked,
        'applied_gpg_corrections': applied_gpg_corrections,
        }
    

def encode_message(message: str, statuses: list[int]) -> bytes:
    bit_array = BitArray()
    bit_array.append(f"uint:8={START_OF_MESSAGE}")

    # add the text to the bit_array and pad it
    for letter in message:
        letter_bits = BitArray.from_bytes(letter.encode('latin-1'))
        letter_bits.insert(0, [1])
        bit_array.append(letter_bits)

    pad = (8 - len(bit_array) % 8) % 8
    bit_array.append(BitArray.from_zeros(pad))

    bit_array.append(f"uint:8={END_OF_MESSAGE}")

    for status in statuses:
        bit_array.append(f"u8={int(status)}")

    bit_array.append(f"uint:8={END_OF_TRANSMITION}")




    return bit_array.to_bytes()

# gpg auto fix stuff

#region

@njit
def compute_cr24_checksum(data: bytes) -> int:
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


def fix_gpg_thing(gpg_block: str, gpg_brute_bytes: int = 2):
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



def brute_force_gpg(text: str, checksum: int, gpg_brute_bytes: int = 2):
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



@njit
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


@njit
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

def repeat_ask_for_input(display_text: str, allowed_inputs: list) -> str:

    while True:
        user_input = input(display_text)
        if user_input in allowed_inputs:
            return user_input
        print(f"not valid input, require: {allowed_inputs}")


# constants and init stuff

#region

# contol codes

START_OF_MESSAGE = 0x02
END_OF_MESSAGE = 0x03
END_OF_TRANSMITION = 0x04
CANCEL_TEXT = 0x18
END_OF_MEDIUM = 0x19


NUL = 0x00
ENQ = 0x05
ACK = 0x06
BEL = 0x07
SYN = 0x16

# status messages for betweem 0x03(ETX) & 0x04(EOT)
status_table: dict[int, str] = {
    NUL: "NUL",
    ENQ: "ENQ",
    ACK: "ACK",
    BEL: "BEL",
    SYN: "SYN",
}

# handle other control codes, such as END_OF_MEDIUM and CANCEL_TEXT
footer_table: dict[int, str] = {
    END_OF_MEDIUM: "END OF MEDIUM",
    CANCEL_TEXT: "cancel last message"
}

allowed_printables = []

# add ascii codes
allowed_printables.extend(range(32, 127))

# add newlines
allowed_printables.append(0x0A) # \n
allowed_printables.append(0x0D) # \r

B64_ALPHABET = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")

CRC24_TABLE = make_checksum_table()


JIT_FUNCTIONS = [
                        (compute_cr24_checksum, (b'\x00'*16))
                        
                        ]

TIME_FUNCTION_TIMES_TO_RUN = 10000
# warm up the JIT
for function, input_data in JIT_FUNCTIONS:
    for _ in range(3):
        function(input_data)

#endregion

def main() -> None:
    parser = argparse.ArgumentParser(description='a script to help decode ttyUSB0 [M.A.S.L] messages')
    parser.add_argument('--version', help='print version number', action='store_true')
    parser.add_argument('-v', '--verbose', help='adds extra logging, repeat for more logging levels, eg -vv', action='count', default=0)
    parser.add_argument('--time', help='times the execution time', action='store_true')
    mode_parsers = parser.add_subparsers(dest='mode')


    # extract mode parsers
    extract_mode = mode_parsers.add_parser('extract', help='extracts the text from the messages')

    extract_mode.add_argument('-b', '--bit-correct', help='apply extra bit corrections if needed, possibly corrupts data', action='store_true')

    extract_mode.add_argument('-r', '--raw', help='writes to a binary file', type=Path, default=None)
    extract_mode.add_argument('-s', '--statuses-detection', help='enables detection of the end of message', action='store_true')
    extract_mode.add_argument('--gpg-block', help='tries to fix the gpg message', action='store_true')
    extract_mode.add_argument('--gpg-brute-bytes', help='the amount of bytes to try and brute force the gpg block, dont set this above 1', type=int, default=1)


    # handle file input
    extract_group = extract_mode.add_mutually_exclusive_group(required=True)
    extract_group.add_argument('-d', '--dir', help='use on a folder with the downloaded messages to scan all of them, the order is by date modified', type=Path)
    extract_group.add_argument('-f', '--file', help='use on a single message file', type=Path)


    # write message parsers
    write_mode = mode_parsers.add_parser('write', help='writes the messages')
    write_mode.add_argument("-o", '--output', help='the file to write the output to', required=True, type=Path)

    args = parser.parse_args()

    if args.version:
        print(f'Version: {__version__}')
        return 0

    if args.verbose == 0:
        pass
    elif args.verbose == 1:
        logger.level = logging.WARNING
    elif args.verbose == 2:
        logger.level = logging.INFO
    elif args.verbose == 3:
        logger.level = logging.DEBUG
    else:
        print('already above highest logging level')
        logger.level = logging.DEBUG

    if args.time:
        for function, data in JIT_FUNCTIONS:
            jit_no_arg = partial(function, data)
            execution_times = timeit.repeat(jit_no_arg, number=TIME_FUNCTION_TIMES_TO_RUN, repeat=5)
            print(f"JIT execution time: {min(execution_times)/TIME_FUNCTION_TIMES_TO_RUN} seconds")
            python_no_arg = partial(function.py_func, data)
            execution_times = timeit.repeat(python_no_arg, number=TIME_FUNCTION_TIMES_TO_RUN, repeat=5)
            print(f"python execution time: {min(execution_times)/TIME_FUNCTION_TIMES_TO_RUN} seconds")

    start_time = time.time()
    if args.mode == 'extract':
        print(f"bit-correct: {args.bit_correct}, statuses-detection: {args.statuses_detection}, gpg-block: {args.gpg_block} gpg-brute-bytes: {args.gpg_brute_bytes}")
        files: list[Path] = []
        # check that the file type matchs the given arguments
        if args.dir is not None:
            if not args.dir.is_dir():
                print("-d / --dir must be a directory")
                sys.exit(1)
            files = list(args.dir .glob('*'))
        if args.file is not None:
            if not args.file.is_file():
                print("-f / --file must be a file")
                sys.exit(1)
            files = [args.file]

        # sort by time made
        files.sort(key=lambda file: file.stat().st_mtime)
        
        
        decode_type = None
        if args.raw is None:
            decode_type = 0 # text
        elif args.raw is not None:
            decode_type = 1 # binary

        
        for file_index, file in enumerate(files):
            terminal_size = shutil.get_terminal_size()
            file_devider = f"{file_index}, {file.name}"
            print(file_devider, '-'*(terminal_size.columns-len(file_devider)-1))
            logger.info(f'file size: {file.stat().st_size}')
            if file.stat().st_size == 0:
                print('File empty')
                continue
            transmission = decode_message(
                file.read_bytes(),
                bit_correct=args.bit_correct,
                decode_type=decode_type,
                statuses_detection=args.statuses_detection,
                gpg_block=args.gpg_block,
                gpg_brute_bytes=args.gpg_brute_bytes
                )

            message = transmission['message']
            statuses = transmission['statuses']
            footer = transmission['footer']
            applied_bit_corrections = transmission['applied_bit_corrections']
            applied_gpg_corrections = transmission['applied_gpg_corrections']

            print(f'Applied bit corrections: {applied_bit_corrections}')
            print(f"Applied gpg correction: {applied_gpg_corrections}")
            print('Message:')
            print("`````")
            if decode_type == 0:
                print(message)
            elif decode_type == 1:
                args.raw.write_bytes(message)
                print(f'Wrote to {str(args.raw)}')
            print("`````")
            print('Statuses:')
            print("````")
            print(statuses)
            print("````")
            print('Footer:')
            print("```")
            print(footer)
            print("```")

    elif args.mode == 'write':


        print("enter main message")

        main_message = input(": ")


        print("enter status")
        # add the statuses to the message
        print(f"statuses: {status_table}")
        writing_status = ''
        statuses: list[int] = []
        while True:
            user_input_type = repeat_ask_for_input('finish / code : ', ['finish','code'])
            if user_input_type == 'finish':
                break
            try:
                control_code_input = input(": ")
                byte_key = bytes([int(control_code_input)])
                control_code = status_table.get(int(control_code_input), None)
                if control_code == None:
                    print(f"invalid status code: {control_code_input}, {byte_key}")
                    continue

                statuses.append(int(control_code_input))
                text_to_write = control_code

                writing_status += text_to_write

                print(writing_status)
            except KeyboardInterrupt:
                print('canceled')
        
        message_bytes = encode_message(main_message, statuses)
        args.output.write_bytes(message_bytes)
    if args.time:
        print(f'took: {time.time()-start_time} seconds')

