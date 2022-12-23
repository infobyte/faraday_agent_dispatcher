# Tenable.sc

The excecutor of tenable.sc will launch a scan in your account of tenable.sc. When the scan finish the executor
will download the report and export it to faraday.

## Envioroment variables

TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY can be generated in "My Account"->"API KEYS" in the tenable website.

TENABLE_PULL_INTERVAL is the interval between each request after the scan started

## Parameters

TENABLE_SCAN_REPO: the repository id for the scan

TENABLE_SCAN_NAME (optional): the name of the scan

TENABLE_SCAN_ID (optional): if you want to launch a scan that already exist you can pass its id

TENABLE_SCANNER_NAME (optional): if you want to run the scan with an scanner you can pass the scanner name:

TENABLE_SCAN_TARGETS: the scan targets separated by comma, can be an ip or hostname

TENABLE_SCAN_TEMPLATE (optional): if you want to use an specifict template 