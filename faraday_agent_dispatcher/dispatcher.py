# -*- coding: utf-8 -*-
import requests
from urllib.parse import urljoin

import json

from aiohttp import ClientSession
import asyncio
import websockets

import os
# TODO CONNECT INTERFACE


class Dispatcher:

    def __init__(self, url, workspace, agent_token, executor_filename, api_port=5985, websocket_port=9000):
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

    def __api_url(self):
        return self.__get_url(self.__api_port)

    def __websocket_url(self):
        return self.__get_url(self.__websocket_port)

    async def reset_websocket_token(self):
        # I'm built so I ask for websocket token
        headers = {"Authorization": f"Agent {self.__agent_token}"}
        websocket_token_response = await self.__session.post(f'http://{self.__api_url()}/_api/v2/'
                                                             f'agent_websocket_token/',
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

    # V2
    async def run(self):
        data = await self.__websocket.recv()
        # TODO Control data
        fifo_name = Dispatcher.rnd_fifo_name()
        Dispatcher.create_fifo(fifo_name)
        process = await self.create_process()
        tasks = [self.process_output(process), self.process_err(process), self.process_data(fifo_name), self.run()]
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
        allchar = string.ascii_letters + string.digits
        return "".join(choice(allchar) for _ in range(10))

    async def process_output(self, process):
        pass

    async def process_err(self, process):
        pass

    async def process_data(self, fifo_name):
        pass

    async def create_process(self):
        process = await asyncio.create_subprocess_shell(
            self.__command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        return process

    # V1
    async def old_run(self):
        # This must be called from ws listener
        async def pp(prefix, text):
            if len(text) > 0:
                print(prefix + text)

        # Execute SH passed by config
        import time
        import subprocess
        result = subprocess.Popen(self.__executor_filename, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        while result.returncode is None:
            await pp("OUT", str(result.stdout.read().decode('utf-8')))
            await pp("ERR", str(result.stderr.read().decode('utf-8')))
            localtime = time.localtime()
            resultt = time.strftime("%I:%M:%S %p", localtime)
            print(resultt)
            result.poll()
            time.sleep(0.01)
        await pp("OUT", str(result.stdout.read().decode('utf-8')))
        await pp("ERR", str(result.stderr.read().decode('utf-8')))

    def ipc_callback(self):
        # Parse
        self.old_send()

    def old_send(self):
        # Any time can be called by IPC

        # Send by API and Agent Token the info
        url = urljoin(self.__url, "_api/v2/ws/"+ self.__workspace +"/hosts/")

        aa = requests.get(url, headers={"token": self.__token})
        aaa = requests.get(url, headers={"token": self.a})
        pass

