import os
import sys
import time

if __name__ == '__main__':
    realstdout = os.fdopen(os.dup(1), 'w')
    os.dup2(2, 1)  # stderr(2) will be also available in fd 1 (stdout)

    print("Esto va a stderr")
    time.sleep(2)
    print("Esto va a stoudt", file=realstdout)