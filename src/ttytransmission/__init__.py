import argparse
import logging
import sys
from pathlib import Path

from bitstring import BitArray, Reader

logging.basicConfig(
    level=logging.INFO,
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


def main() -> None:
    parser = argparse.ArgumentParser(description='a script to help decode ttyUSB0 [M.A.S.L] messages')

    parser.add_argument('-v', '--verbose', help='adds extra logging', action='store_true')
    mode_parsers = parser.add_subparsers(dest='mode', required=True)

    # extract mode parsers
    extract_mode = mode_parsers.add_parser('extract', help='extracts the text from the messages')
    
    # handle file input
    extract_group = extract_mode.add_mutually_exclusive_group(required=True)
    extract_group.add_argument('-d', '--dir', help='use on a folder with the downloaded messages to scan all of them, the order is by date modified', type=Path)
    extract_group.add_argument('-f', '--file', help='use on a single message file', type=Path)


    # write message parsers
    write_mode = mode_parsers.add_parser('write', help='writes the messages')
    write_mode.add_argument("-o", '--output', help='the file to write the output to', required=True, type=Path)

    args = parser.parse_args()

    if args.verbose:
        logger.level = logging.DEBUG

    def decode_message(input_message: bytes):        
        # the main decoded message
        message = ''

        # the control code meanings between 0x03 and 0x04
        statuses = ''

        # any extra info the function genrates, such as canceling 
        footer = ''
        
        
        if input_message[-1] in footer_table:
            footer += f'\n{footer_table[input_message[-1]]}\n'
        
        if input_message[0] in footer_table:
            footer += f'\n{footer_table[input_message[0]]}\n'
        
        message_bit_data = BitArray(input_message)
        
        total = len(message_bit_data)
        
        text_start = 0
        
        text_end = total
        
        transmission_end = total
        
        
        
        # set text_start to the start of START_OF_MESSAGE
        pointer = 0
        while pointer < len(message) and input_message[pointer] != START_OF_MESSAGE:
            pointer += 1
        text_start = (pointer + 1) * 8 - 8
        
        # set text_end to the start of END_OF_MESSAGE
        pointer = len(input_message) - 1
        while pointer > 0 and input_message[pointer-1] != END_OF_MESSAGE:
            pointer -= 1
        text_end = (pointer - 1) * 8
        
        
        # set transmission_end to the start of END_OF_TRANSMITION
        pointer = len(input_message) - 1
        while pointer > 0 and input_message[pointer-1] != END_OF_TRANSMITION:
            pointer -= 1
        transmission_end = (pointer - 1) * 8
        
        
        
        text_section = Reader(message_bit_data[text_start+8:text_end])
        
        statuses_section = Reader(message_bit_data[text_end+8:transmission_end])
        logger.debug(statuses_section)
        if len(statuses_section) != 0:
            while statuses_section.pos < len(statuses_section):
                byte = int(statuses_section.read_bits(8).bin, 2)
                logger.debug(f"found byte: {byte} at {statuses_section.pos-8}")
                statuses += status_table.get(byte, f'UNMAPPED STATUS: {byte}')



        
        while text_section.pos < len(text_section):
            remain = len(text_section) - text_section.pos
            
            # if remain is less than 9 then pad text_section.pos to byte alignment
            if remain < 9:
                text_section.pos += (8 - text_section.pos % 8) % 8
                break
            
            start = text_section.peek_bits(1)
            data = text_section.peek_bits(9)
            byte = int(data[1:].bin, 2)
            
            
            if start == '0':
                continue
                
            if byte not in allowed_printables:
                text_section.pos += 1
                continue

            logger.debug(f"{byte} -> {byte.to_bytes()} start: {start}, {data}")

            message += byte.to_bytes().decode("latin-1")
            text_section.pos += 8
            



        return {"message": message, 'statuses': statuses, 'footer': footer}










    def repeat_ask_for_input(display_text: str, allowed_inputs: list) -> str:
        
        while True:
            user_input = input(display_text)
            if user_input in allowed_inputs:
                return user_input
            print(f"not valid input, require: {allowed_inputs}")


    if args.mode == 'extract':

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


        for file_index, file in enumerate(files):
            print(f"{file_index}, {file.name}:")
            transmission = decode_message(file.read_bytes())

            message = transmission['message']
            statuses = transmission['statuses']
            footer = transmission['footer']

            print("```")
            print(message)
            print("```")
            
            print("```")
            print(statuses)
            print("```")
            
            print("```")
            print(footer)
            print("```")

    elif args.mode == 'write':
        bit_array = BitArray()
        bit_array.append(f"uint:8={START_OF_MESSAGE}")
        
        print("enter main message")
        
        writing_message = ''

        text_to_write = ''
        user_input = input(": ")
        text_to_write = user_input
            
        for letter in text_to_write:
            letter_bits = BitArray.from_bytes(letter.encode('ascii'))
            letter_bits.insert(0, [1])
            bit_array.append(letter_bits)
        
        pad = (8 - len(bit_array) % 8) % 8
        bit_array.append(BitArray.from_zeros(pad))
        writing_message += text_to_write
        
        print(writing_message)
        bit_array.append(f"uint:8={END_OF_MESSAGE}")

        print("enter status")

        print(f"statuses: {status_table}")
        writing_status = ''
        while True:
            user_input_type = repeat_ask_for_input('finish / code : ', ['finish','code'])
            if user_input_type == 'finish':
                break
            try:
                user_input = input(": ")
                text_to_write = user_input
                byte_key = bytes([int(user_input)])
                control_code = status_table.get(int(user_input), None)
                if control_code == None:
                    print(f"invalid status code: {user_input}, {byte_key}")
                    continue
                
                bit_array.append(f"u8={int(user_input)}")
                text_to_write = control_code
                
                writing_status += text_to_write
                
                print(writing_status)
            except KeyboardInterrupt:
                print('canceled')
        bit_array.append(f"uint:8={END_OF_TRANSMITION}")

        
        
        
        with open(args.output, 'wb') as output_file:
            bit_array.tofile(output_file)