# a script to help decode ttyUSB0 [M.A.S.L] messages

## installation

```bash
pip install anathema-ttyusb0-translator
```

## usage  

```bash
anathema-ttyusb0-translator --help
```

#### extract from file

```bash
anathema-ttyusb0-translator extract -f example_file
```

#### extract from file with error correction
```bash
anathema-ttyusb0-translator extract -f example_file --bit-correct
```

#### extract from folder  
```bash
anathema-ttyusb0-translator extract -d exaple_folder
```

#### writing message

````text
❯ anathema-ttyusb0-translator write -o example_file
enter main message
: hello, world!
hello, world!
enter status
statuses: {0: 'NUL', 5: 'ENQ', 6: 'ACK', 7: 'BEL', 22: 'SYN'}
finish / code : code
: 7
BEL
finish / code : finish

❯ anathema-ttyusb0-translator extract -f example_file
0, example_file ----------------
applied corrections: False
```
hello, world!
```
```
BEL
```
```

```
````


## binary schema
### control codes:  
each control code is 8 bits long  
normally so far they follow the standard ASCII control codes
statuses sit betweeb ETX and EOT, they are normal ASCII control codes

naming format: \<BYTE\>, \<NAME\>, \<MEANING\>   

#### framing:  
0x02: STX, start of message  
0x03: ETX, end of message  
0x04: EOT, end of transmission  

#### statuses:  
0x00: NUL  
0x05: ENQ  
0x06: ACK  
0x07: BEL  
0x016: SYN  

#### footer:  
0x19: EOM, end of medium  
0x18, CAN, cancel  

#### letters:  
each letter is 9 bits long  
each letter starts with a single leading "1" bit  
strip that bit to get the letter in ASCII  

## message framing:  

#### format:  

\<STX\>  
\<MESSAGE\>  
\<ETX\>  
\<STATUSES\>  
\<EOT\>  


## Licenses

Copyright Contributors to the anathema-ttyusb0-translator project.


the code is licensed under LGPL-2.1-or-later WITH WxWindows-exception-3.1.
this README is licensed under CC-BY-4.0. full texts are in the LICENSES/ folder.
all other files are licensed under CC0-1.0

versions up to and including 0.2.2 were released under GPL-3.0. copies of those
versions remain under that license. 0.3.0 and later are LGPL.