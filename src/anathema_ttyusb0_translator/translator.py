# SPDX-FileCopyrightText: 2026 Copyright Contributors to the anathema-ttyusb0-translator project
#

# SPDX-License-Identifier: LGPL-2.1-or-later WITH WxWindows-exception-3.1

from bitstring import BitArray, Reader

from . import gpg_helpers
from . import constants

logger = constants.logger

START_OF_MESSAGE = constants.START_OF_MESSAGE
END_OF_MESSAGE = constants.END_OF_MESSAGE
END_OF_TRANSMITION = constants.END_OF_TRANSMITION
CANCEL_TEXT = constants.CANCEL_TEXT
END_OF_MEDIUM = constants.END_OF_MEDIUM

status_table: dict[int, str] = constants.status_table

footer_table: dict[int, str] = constants.footer_table

allowed_printables = constants.allowed_printables


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
    message: str | bytes
    
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
        if decode_type == 0 and isinstance(message, str):
            message += byte.to_bytes().decode("latin-1")
        elif decode_type == 1 and isinstance(message, bytes):
            message += byte.to_bytes()
        posistion += 9


    if gpg_block == True and decode_type == 0 and isinstance(message, str):
        message, worked, applied_gpg_corrections = gpg_helpers.fix_gpg_thing(message, gpg_brute_bytes)
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



