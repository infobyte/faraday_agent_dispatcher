import string
import random


def fuzzy_string(size: int = 6):
    """Generate a random string of fixed length"""
    letters = string.ascii_lowercase + string.ascii_uppercase + string.digits
    return "".join(random.choice(letters) for _ in range(size))
