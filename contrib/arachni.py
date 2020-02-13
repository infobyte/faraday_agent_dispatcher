#!/usr/bin/env python
import os
import sys
from faraday_plugins.plugins.manager import PluginsManager


def get_arachni_path_xml(path):
    os.chdir(path)
    url = 'https://google.com'
    name_result = 'report.afr'
    xml_result = 'xml_arachni_report.xml'
    os.system("./arachni {} --report-save-path={}".format(url, name_result))
    os.system("./arachni_reporter {} --reporter=xml:outfile={}".format(name_result, xml_result))
    path_xml = os.path.join(os.getcwd(), xml_result)
    return path_xml


def main(data: str = None):
    path = os.path.join(os.path.expanduser('~'), 'Descargas', 'arachni-1.5.1-0.5.12', 'bin')
    xml_arachni = get_arachni_path_xml(path)
    plugin = PluginsManager().get_plugin("arachni")
    plugin.parseOutputString(xml_arachni)
    print(plugin.get_json())


if __name__ == '__main__':
    main()
