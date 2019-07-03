# -*- coding: utf-8 -*-
import subprocess

# TODO CONNECT INTERFACE

class Dispatcher:

    def connect(self):
        # I'm built so I can connect

        # Ask by API and Agent Token for WS token

        # Connect by WS, must be available to set receive handler

        pass

    def run(self):
        # This must be called from ws listener

        # Execute SH passed by config
        # subprocess.run()

        pass

    def send(self):
        # Any time can be called by IPC

        # Send by API and Agent Token the info
        pass

