from anathema_ttyusb0_translator.translator import decode_message

test_messages = [
    (
     {
         'message': 'hello_world!',
         'statuses': 'NULENQBEL',
         'footer': '', 'applied_bit_corrections': False,
         'statuses_array': [0, 5, 7], 'footer_array': [],
         'worked': True,
         'applied_gpg_corrections': False
         },
     (bytes.fromhex('02b4596d96cb7d7eef6fb95b2c92100300050704'), False, 0, True, False, 1)
    ),
    (
     {
         'message': 'hello_world!',
         'statuses': 'NULENQBEL',
         'footer': '', 'applied_bit_corrections': False,
         'statuses_array': [0, 5, 7], 'footer_array': [],
         'worked': True,
         'applied_gpg_corrections': False
         },
     (bytes.fromhex('02b4596d96cb7d7eef6fb95b2c92100300050704'), True, 0, True, False, 1)
    )
]


def test_message_decoder():
    for message in test_messages:
        expected = message[0]
        encoder_settings = message[1]
        
        test_decode = decode_message(*encoder_settings)

        assert expected == test_decode