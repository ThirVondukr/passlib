from libpass.binary import B64_CHARS


def test_salt_alphabet():
    assert len(B64_CHARS) == len(set(B64_CHARS))
