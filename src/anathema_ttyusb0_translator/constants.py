from importlib.metadata import version, PackageNotFoundError
import logging


try:
    __version__ = version("anathema-ttyusb0-translator")
except PackageNotFoundError:
    __version__ = "unknown"

logger = logging.getLogger("anathema_ttyusb0_translator")


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
allowed_printables_list: list[int] = []

# add ascii codes
allowed_printables_list.extend(range(32, 127))

# add newlines
allowed_printables_list.append(0x0A) # \n
allowed_printables_list.append(0x0D) # \r

B64_ALPHABET = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")


allowed_printables = frozenset(allowed_printables_list)