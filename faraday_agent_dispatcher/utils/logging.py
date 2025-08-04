import sys


def log(msg, end="\n"):
    print(msg, file=sys.stderr, flush=True, end=end)
