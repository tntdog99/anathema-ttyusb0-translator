from anathema-ttyusb0-translator import decode_message



test_messages = [
    (
     {'message': 'hello_world!', 'statuses': 'NULENQBEL', 'footer': '', 'applied_corrections': False, 'statuses_array': [0, 5, 7], 'footer_array': []},
     (bytes.fromhex('02b4596d96cb7d7eef6fb95b2c92100300050704'), False)
    ),
    (
     {'message': 'hello_world!', 'statuses': 'NULENQBEL', 'footer': '', 'applied_corrections': False, 'statuses_array': [0, 5, 7], 'footer_array': []},
     (bytes.fromhex('02b4596d96cb7d7eef6fb95b2c92100300050704'), True)
    )
]


def test_message_decoder():
    for message in test_messages:
        expected = message[0]
        encoder_settings = message[1]
        
        test_decode = decode_message(encoder_settings[0], bit_correct=encoder_settings[1])

        assert expected == test_decode