import argparse
import logging
import sys
from pathlib import Path
import shutil
import time
from functools import partial
import timeit
from typing import Any

from . import gpg_helpers
from . import constants
from . import translator

logger = constants.logger



def repeat_ask_for_input(display_text: str, allowed_inputs: list) -> str:

    while True:
        user_input = input(display_text)
        if user_input in allowed_inputs:
            return user_input
        print(f"not valid input, require: {allowed_inputs}")


# constants and init stuff

#region

# contol codes

status_table: dict[int, str] = constants.status_table


JIT_FUNCTIONS: list[tuple[Any, tuple[Any, ...]]] = [
                        (gpg_helpers.compute_cr24_checksum, (b'\x00'*16, ))
                        
                        ]
TIME_FUNCTION_TIMES_TO_RUN = 10000
#endregion



def main() -> int:
    logging.basicConfig(
    level=logging.ERROR,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
    )
    
    # handle args
    
    #region
    
    parser = argparse.ArgumentParser(description='a script to help decode ttyUSB0 [M.A.S.L] messages')
    parser.add_argument('--version', help='print version number', action='store_true')
    parser.add_argument('-v', '--verbose', help='adds extra logging, repeat for more logging levels, eg -vv', action='count', default=0)
    parser.add_argument('--time', help='times the execution time', action='store_true')
    mode_parsers = parser.add_subparsers(dest='mode')


    # extract mode parsers
    extract_mode = mode_parsers.add_parser('extract', help='extracts the text from the messages')

    extract_mode.add_argument('-b', '--bit-correct', help='apply extra bit corrections if needed, possibly corrupts data', action='store_true')

    extract_mode.add_argument('-r', '--raw', help='writes to a binary file, if used with --dir this must be a folder', type=Path, default=None)
    extract_mode.add_argument('-s', '--statuses-detection', help='enables detection of the end of message', action='store_true')
    extract_mode.add_argument('--gpg-block', help='tries to fix the gpg message', action='store_true')
    extract_mode.add_argument('--gpg-brute-bytes', help='the amount of bytes to try and brute force the gpg block, dont set this above 1', type=int, default=1)


    # handle file input
    extract_group = extract_mode.add_mutually_exclusive_group(required=True)
    extract_group.add_argument('-d', '--dir', help='input folder, the order is by date modified', type=Path)
    extract_group.add_argument('-f', '--file', help='input file', type=Path)


    # write message parsers
    write_mode = mode_parsers.add_parser('write', help='writes the messages')
    write_mode.add_argument("-o", '--output', help='the file to write the output to', required=True, type=Path)

    args = parser.parse_args()

    if args.version:
        print(f'Version: {constants.__version__}')
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
            jit_no_arg = partial(function, *data)
            execution_times = timeit.repeat(jit_no_arg, number=TIME_FUNCTION_TIMES_TO_RUN, repeat=5)
            print(f"JIT execution time: {min(execution_times)/TIME_FUNCTION_TIMES_TO_RUN} seconds")
            python_no_arg = partial(function.py_func, *data)
            execution_times = timeit.repeat(python_no_arg, number=TIME_FUNCTION_TIMES_TO_RUN, repeat=5)
            print(f"python execution time: {min(execution_times)/TIME_FUNCTION_TIMES_TO_RUN} seconds")

    #endregion

    start_time = time.time()
    if args.mode == 'extract':
        print(f"bit-correct: {args.bit_correct}, statuses-detection: {args.statuses_detection}, gpg-block: {args.gpg_block} gpg-brute-bytes: {args.gpg_brute_bytes}")
        
        decode_type = 0 if args.raw is None else 1
        
        files: list[Path] = []
        # check that the file type matchs the given arguments
        if args.dir is not None: # if args.dir is set
            if not args.dir.is_dir():
                print("-d / --dir must be a directory")
                sys.exit(1)
            if decode_type == 1:
                if args.raw.is_file():
                    print("-r / --raw must be a directory when with --dir")
                    sys.exit(1)
            files = list(args.dir .glob('*'))
        if args.file is not None: # if args.file is set
            if not args.file.is_file():
                print("-f / --file must be a file")
                sys.exit(1)
            files = [args.file]

        # sort by time made
        files.sort(key=lambda file: file.stat().st_mtime)
        

        
        for file_index, file in enumerate(files):
            terminal_size = shutil.get_terminal_size()
            file_devider = f"{file_index}, {file.name}"
            print(file_devider, '-'*(terminal_size.columns-len(file_devider)-1))
            logger.info(f'file size: {file.stat().st_size}')
            if file.stat().st_size == 0:
                print('File empty')
                continue
            transmission = translator.decode_message(
                file.read_bytes(),
                bit_correct=args.bit_correct,
                decode_type=decode_type,
                statuses_detection=args.statuses_detection,
                gpg_block=args.gpg_block,
                gpg_brute_bytes=args.gpg_brute_bytes
                )

            message = transmission['message']
            output_message_statuses = transmission['statuses']
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
                full_output_path = Path(args.raw) # if the output is not a dir or its not reading from a dir output to a file
                
                if args.dir is not None: # if args.dir is set, output to a dir
                    args.raw.mkdir(parents=True, exist_ok=True)
                    full_output_path = Path(args.raw, file.name)
                
                elif args.raw.is_dir(): # if args.dir is not set but the output path is already a folder write to the folder
                    full_output_path = Path(args.raw, file.name)
                
                full_output_path.write_bytes(message)
                print(f'Wrote to {str(full_output_path)}')
            print("`````")
            print('Statuses:')
            print("````")
            print(output_message_statuses)
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
        message_statuses: list[int] = []
        while True:
            user_input_type = repeat_ask_for_input('finish / code : ', ['finish','code'])
            if user_input_type == 'finish':
                break
            try:
                control_code_input = input(": ")
                byte_key = bytes([int(control_code_input)])
                control_code = status_table.get(int(control_code_input), None)
                if control_code == None:
                    print(f"invalid status code: {control_code_input}, {repr(byte_key)}")
                    continue

                message_statuses.append(int(control_code_input))
                text_to_write = control_code

                writing_status += text_to_write

                print(writing_status)
            except KeyboardInterrupt:
                print('canceled')
        
        message_bytes = translator.encode_message(main_message, message_statuses)
        args.output.write_bytes(message_bytes)
    if args.time:
        print(f'took: {time.time()-start_time} seconds')

    return 0 