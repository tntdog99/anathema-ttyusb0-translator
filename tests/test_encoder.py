from anathema_ttyusb0_translator.translator import encode_message


test_messages = [
    (
        bytes.fromhex('02b4596d96cb7d7eef6fb95b2c921003050704'),
        (
            'hello_world!',
            [5,7]
        )
    )
]


def test_message_encoder():
    for message in test_messages:
        expected = message[0]
        encoder_settings = message[1]
        test_encode_bytes = encode_message(encoder_settings[0], encoder_settings[1])
        assert expected == test_encode_bytes