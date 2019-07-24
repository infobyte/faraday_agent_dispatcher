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


async def _process_lines(line_getter, process_f, logger_f, name):
    while True:
        line = await line_getter()
        if line != "":
            process_f(line)
            logger_f(line)
        else:
            break
    print(f"{Bcolors.WARNING}{name} sent empty data, {Bcolors.ENDC}")


class FileLineProcessor:

    def __init__(self, disp):
        self.disp = disp

    def log(self, line):
        raise RuntimeError("Must be implemented")

    def processing(self, line):
        raise RuntimeError("Must be implemented")

    async def next_line(self):
        raise RuntimeError("Must be implemented")

    async def process_f(self):
        return await _process_lines(self.next_line, self.processing, self.log, self.disp)


class StdOutLineProcessor(FileLineProcessor):

    def __init__(self, process):
        super().__init__("stdout")
        self.process = process

    async def next_line(self):
        line = await self.process.stdout.readline()
        line = line.decode('utf-8')
        return line[:-1]

    def processing(self, line):
        print(f"{Bcolors.OKBLUE}{line}{Bcolors.ENDC}")

    def log(self, line):
        logger.debug(f"Output line: {line}")


class StdErrLineProcessor(FileLineProcessor):

    def __init__(self, process):
        super().__init__("stderr")
        self.process = process

    async def next_line(self):
        line = await self.process.stderr.readline()
        line = line.decode('utf-8')
        return line[:-1]

    def processing(self, line):
        print(f"{Bcolors.FAIL}{line}{Bcolors.ENDC}")

    def log(self, line):
        logger.debug(f"Error line: {line}")


class FIFOLineProcessor(FileLineProcessor):

    def __init__(self, fifo_file):
        super().__init__("FIFO")
        self.fifo_file = fifo_file

    async def next_line(self):
        line = await self.fifo_file.readline()
        return line[:-1]

    def processing(self, line):
        try:
            a = json.loads(line)
            print(f"{Bcolors.OKGREEN}{line} {a['Esto']}{Bcolors.ENDC}")
        except JSONDecodeError as e:
            print(f"{Bcolors.WARNING}Not json line{Bcolors.ENDC}")
            self.fifo_file.close()

    def log(self, line):
        logger.debug(f"FIFO line: {line}")