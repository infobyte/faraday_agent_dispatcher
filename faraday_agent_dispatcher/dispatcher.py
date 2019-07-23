# -*- coding: utf-8 -*-
import requests
from urllib.parse import urljoin

import json

from aiohttp import ClientSession
import asyncio
import websockets
import aiofiles

import os

import faraday_agent_dispatcher.logger as logging

class Bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

logger = logging.get_logger()

LOG = False

class Dispatcher:

    def __init__(self, url, workspace, agent_token, executor_filename, api_port="5985", websocket_port="9000"):
        self.__url = url
        self.__api_port = api_port
        self.__websocket_port = websocket_port
        self.__workspace = workspace
        self.__agent_token = agent_token
        self.__executor_filename = executor_filename
        self.__session = ClientSession()
        self.__websocket = None
        self.__websocket_token = None
        self.__command = None

    def __get_url(self, port):
        return f"{self.__url}:{port}"

    def __api_url(self, secure=False):
        prefix = "https://" if secure else "http://"
        return f"{prefix}{self.__get_url(self.__api_port)}"

    def __websocket_url(self, secure=False):
        prefix = "wss://" if secure else "ws://"
        return f"{prefix}{self.__get_url(self.__websocket_port)}"

    async def reset_websocket_token(self):
        # I'm built so I ask for websocket token
        headers = {"Authorization": f"Agent {self.__agent_token}"}
        d = f'{self.__api_url()}/_api/v2/agent_websocket_token/'
        websocket_token_response = await self.__session.post(
            f'{self.__api_url()}/_api/v2/agent_websocket_token/',
            headers=headers)

        websocket_token_json = await websocket_token_response.json()  # TODO ERRORS
        self.__websocket_token = websocket_token_json["token"]

    async def connect(self):
        # I'm built so I can connect
        if self.__websocket_token is None:
            await self.reset_websocket_token()

        async with websockets.connect(self.__websocket_url()) as websocket:
            await websocket.send(json.dumps({
                'action': 'JOIN_AGENT',
                'workspace': self.__workspace,
                'token': self.__websocket_token,
            }))

            self.__websocket = websocket

        await self.run()  # This line can we called from outside (in main)

    async def disconnect(self):
        await self.__session.close()
        await self.__websocket.close()

    # V2
    async def run(self):
        # Next line must be uncommented, when faraday (and dispatcher) maintains the keep alive
        # data = await self.__websocket.recv()
        # TODO Control data
        fifo_name = Dispatcher.rnd_fifo_name()
        Dispatcher.create_fifo(fifo_name)
        process = await self.create_process(fifo_name)
        tasks = [self.process_output(process), self.process_err(process), self.process_data(fifo_name),]
                 #self.run()]
        await asyncio.gather(*tasks)

    @staticmethod
    def create_fifo(fifo_name):
        if os.path.exists(fifo_name):
            os.remove(fifo_name)
        os.mkfifo(fifo_name)

    @staticmethod
    def rnd_fifo_name():
        import string
        from random import choice
        chars = string.ascii_letters + string.digits
        name = "".join(choice(chars) for _ in range(10))
        return f"/tmp/{name}"

    async def process_output(self, process):
        for i in range(3):
            line = await process.stdout.readline()
            line = line.decode('utf-8')
            if LOG:
                logger.debug(f"Output line: {line}")
            print(f"{Bcolors.OKBLUE}{line}{Bcolors.ENDC}")

    async def process_err(self, process):
        for i in range(3):
            line = await process.stderr.readline()
            line = line.decode('utf-8')
            if LOG:
                logger.info(f"Error line: {line}")
            print(f"{Bcolors.FAIL}{line}{Bcolors.ENDC}")

    async def process_data(self, fifo_name):
        async with aiofiles.open(fifo_name, "r") as fifo_file:
            for i in range(3):
                line = await fifo_file.readline()
                print(f"{Bcolors.OKGREEN}{line}{Bcolors.ENDC}")
                if LOG:
                    logger.debug(f"Data line: {line}")

    async def create_process(self, fifo_name):
        process = await asyncio.create_subprocess_exec(
            self.__executor_filename, fifo_name, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        return process

    async def send(self):
        # Any time can be called by IPC

        # Send by API and Agent Token the info
        url = urljoin(self.__url, "_api/v2/ws/"+ self.__workspace +"/hosts/")

        aa = requests.get(url, headers={"token": self.__token})
        aaa = requests.get(url, headers={"token": self.a})
        pass

