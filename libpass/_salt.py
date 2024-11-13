import math
import secrets
import string

DEFAULT_CHARS = string.ascii_letters + string.digits


def generate_salt(length: int, chars: str = DEFAULT_CHARS) -> str:
    return "".join(secrets.choice(chars) for _ in range(length))


def generate_salt_by_entropy(entropy_bits: int, chars: str = DEFAULT_CHARS) -> str:
    length = math.ceil(entropy_bits / math.log2(len(chars)))
    return generate_salt(length=length, chars=chars)
