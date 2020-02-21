#!/usr/bin/env python
import os
import sys
from faraday_plugins.plugins.manager import PluginsManager
import time
import subprocess

# python crear basic.w3af --> PONER URL
# Python Ejecutar sh. --> run_w3af.sh
# Esperar a que termine sh.
# buscar el file
# ejecutar agente

def create_w3af_file(url_targe, path_file_w3af):
    text = "" \
           "plugins\n output console,xml_file\n output\n output config xml_file\n set output_file output-w3af.xml\n " \
           "set verbose True\n back\n output config console\n set verbose False\n back\n " \
           "crawl all, !bing_spider, !google_spider, !spider_man\n crawl\n grep all\n grep\n audit all\n audit\n " \
           "bruteforce all\n bruteforce\n back\n target\n set target {}\n back\n start\n exit".format(url_targe)
    file = open(path_file_w3af, "w")
    file.write(text)
    file.close()
    return path_file_w3af


def get_path_xml():
    path = os.path.join(os.path.expanduser('~'), 'Desarrollo', 'w3af')
    path_xml = "{}/output-w3af.xml".format(path)
    return path_xml


def main():
    #url_target = os.environ.get('EXECUTOR_CONFIG_TARGET_URL')
    url_target = "http://moth/w3af/"
    path_file_w3af = "/home/blas/Desarrollos/faraday_agent_dispatcher/contrib/config_report_file.w3af"
    create_w3af_file(url_target, path_file_w3af)
    subprocess.call("./run_w3af.sh")
    xml = get_path_xml()
    plugin = PluginsManager().get_plugin("W3af")
    plugin.parseOutputString(xml)
    print(plugin.get_json())


if __name__ == '__main__':
    main()