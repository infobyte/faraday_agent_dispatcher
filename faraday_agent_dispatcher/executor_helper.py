import aiofiles
import json
from json import JSONDecodeError

from faraday_agent_dispatcher import logger as logging

logger = logging.get_logger()

class Bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


async def __process_lines(line_getter, process_f, logger_f, name):
    while True:
        line = await line_getter()
        if line != "":
            process_f(line)
            logger_f(line)
        else:
            break
    print(f"{Bcolors.WARNING}{name} sent empty data, {Bcolors.ENDC}")


async def process_output(process):
    async def next_line():
        line = await process.stdout.readline()
        line = line.decode('utf-8')
        return line[:-1]

    def output_processing(line):
        print(f"{Bcolors.OKBLUE}{line}{Bcolors.ENDC}")

    def log(line):
        logger.debug(f"Output line: {line}")

    await __process_lines(next_line, output_processing, log, "stdout")


async def process_error(process):
    async def next_line():
        line = await process.stderr.readline()
        line = line.decode('utf-8')
        return line[:-1]

    def error_processing(line):
        print(f"{Bcolors.FAIL}{line}{Bcolors.ENDC}")

    def log(line):
        logger.debug(f"Error line: {line}")

    await __process_lines(next_line, error_processing, log, "stderr")


async def process_data(fifo_name):
    def next_line_f(fifo):

        async def next_line():
            line = await fifo.readline()
            return line[:-1]

        return next_line

    def fifo_processing(line):
        try:
            a = json.loads(line)
            print(f"{Bcolors.OKGREEN}{line} {a['Esto']}{Bcolors.ENDC}")
        except JSONDecodeError as e:
            print("TODO CLOSE FIFO")

    def log(line):
        logger.debug(f"FIFO line: {line}")

    async with aiofiles.open(fifo_name, "r") as fifo_file:
        await __process_lines(next_line_f(fifo_file), fifo_processing, log, "FIFO")
