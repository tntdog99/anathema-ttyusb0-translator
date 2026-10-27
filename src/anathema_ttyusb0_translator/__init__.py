import argparse
import logging
import sys
from pathlib import Path
import shutil

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


def decode_message(input_message: bytes, bit_correct=False, decode_type=0, statuses_detection=False) -> dict:
    # decode_type = 0 # text
    # decode_type = 1 # binary
    
    
    
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
    applied_corrections = False

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
                posistion += 9
                continue

            # if its non printable, its probably not aligned, attempt to realign
            if byte not in allowed_printables:
                applied_corrections = True
                posistion += 1
                continue

        # logger.debug(f"{byte} -> {byte.to_bytes()} start: {start}, {data}, offset: {text_section.pos}, expected next offset: {text_section.pos+9}")
        if decode_type == 0:
            message += byte.to_bytes().decode("latin-1")
        elif decode_type == 1:
            message += byte.to_bytes()
        posistion += 9




    return {
        "message": message,
        'statuses': statuses,
        'footer': footer,
        'applied_corrections': applied_corrections,
        'statuses_array': statuses_array,
        'footer_array': footer_array
        }
    

def encode_message(message: str, statuses: list[int]) -> bytes:
    bit_array = BitArray()
    bit_array.append(f"uint:8={START_OF_MESSAGE}")

    # add the text to the bit_array and pad it
    for letter in message:
        letter_bits = BitArray.from_bytes(letter.encode('latin-1 '))
        letter_bits.insert(0, [1])
        bit_array.append(letter_bits)

    pad = (8 - len(bit_array) % 8) % 8
    bit_array.append(BitArray.from_zeros(pad))

    bit_array.append(f"uint:8={END_OF_MESSAGE}")

    for status in statuses:
        bit_array.append(f"u8={int(status)}")

    bit_array.append(f"uint:8={END_OF_TRANSMITION}")




    return bit_array.to_bytes()





def repeat_ask_for_input(display_text: str, allowed_inputs: list) -> str:

    while True:
        user_input = input(display_text)
        if user_input in allowed_inputs:
            return user_input
        print(f"not valid input, require: {allowed_inputs}")


def main() -> None:
    parser = argparse.ArgumentParser(description='a script to help decode ttyUSB0 [M.A.S.L] messages')
    parser.add_argument('--version', help='print version number', action='store_true')
    parser.add_argument('-v', '--verbose', help='adds extra logging, repeat for more logging levels, eg -vv', action='count', default=0)
    mode_parsers = parser.add_subparsers(dest='mode')


    # extract mode parsers
    extract_mode = mode_parsers.add_parser('extract', help='extracts the text from the messages')

    extract_mode.add_argument('-b', '--bit-correct', help='apply extra bit corrections if needed, possibly corrupts data', action='store_true')

    extract_mode.add_argument('-r', '--raw', help='writes to a binary file', type=Path, default=None)
    extract_mode.add_argument('-s', '--statuses-detection', help='enables detection of the end of message', action='store_true')
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


    if args.mode == 'extract':
        print(f"bit-correct: {args.bit_correct}, statuses-detection: {args.statuses_detection}")
        
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

            transmission = decode_message(file.read_bytes(), bit_correct=args.bit_correct, decode_type=decode_type, statuses_detection=args.statuses_detection)

            message = transmission['message']
            statuses = transmission['statuses']
            footer = transmission['footer']
            applied_corrections = transmission['applied_corrections']
            print(f'applied corrections: {applied_corrections}')

            print("```")
            if decode_type == 0:
                print(message)
            elif decode_type == 1:
                args.raw.write_bytes(message)
                print(f'wrote to {str(args.raw)}')
            print("```")

            print("```")
            print(statuses)
            print("```")

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
            