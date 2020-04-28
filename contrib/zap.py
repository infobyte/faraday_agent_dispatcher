#!/usr/bin/env python
import os
import sys
from faraday_plugins.plugins.manager import PluginsManager
import time
from zapv2 import ZAPv2
import subprocess


def report_zap(target, api_key, dir_save):
    zap = ZAPv2(apikey=api_key)
    scanID = zap.spider.scan(target)
    while int(zap.spider.status(scanID)) < 100:
        time.sleep(1)

    file = open(dir_save, 'w')
    file.write(zap.core.xmlreport())
    file.close()
    zap.core.shutdown()
    return dir_save


def run_zap_proxy(path):
    pid = subprocess.Popen(path, shell=True).pid
    return pid


def main():
    target = os.environ.get('EXECUTOR_CONFIG_TARGET_URL')
    api_key = os.environ.get('API_KEY')
    my_env = os.environ
    dir_save = '/home/blas/Escritorio/report.xml'
    path = my_env["ZAP"] if 'ZAP' in my_env else "/home/blas/Descargas/ZAP_2.9.0/zap.sh"
    pid_zap = run_zap_proxy(path)
    if pid_zap == 0:
        print("Zap Proxy not found", file=sys.stderr)
    else:
        time.sleep(30)
        zap_xml = report_zap(target, api_key, dir_save)

    plugin = PluginsManager().get_plugin("zap")
    plugin.parseOutputString(zap_xml)
    print(plugin.get_json())


if __name__ == '__main__':
    main()