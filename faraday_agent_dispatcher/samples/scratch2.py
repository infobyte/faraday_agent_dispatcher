import sys
import time
import random
import os

if __name__ == '__main__':

    fifo_name = os.environ["FIFO_NAME"]
    with open(fifo_name, "w") as fifo_file:
        for _ in range(10):
            print("Esto va a stdout")
            time.sleep(random.choice([i * 0.1 for i in range(8,10)]))
            print("Esto va a stoerr", file=sys.stderr)
            time.sleep(random.choice([i * 0.1 for i in range(5,7)]))
            print("{\"Esto\": \"va a fifo\"", file=fifo_file)
            time.sleep(random.choice([i * 0.1 for i in range(1,3)]))
            print("{\"Esto\": \"va a fifo\"}", file=fifo_file)
            time.sleep(random.choice([i * 0.1 for i in range(1,3)]))
            fifo_file.flush()
