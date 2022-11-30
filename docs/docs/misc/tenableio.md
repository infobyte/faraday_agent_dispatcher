# Tenable.io

The excecutor of tenable.io will launch a scan in your account of tenable.io. When the scan finish the executor
will download the report and export it to faraday.

## Envioroment variables

TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY can be generated in "My Account"->"API KEYS" in the tenable website.

TENABLE_PULL_INTERVAL is the interval between each request after the scan started

## Parameters

TENABLE_SCAN_NAME: the name of the scan

TENABLE_SCAN_ID: if you want to launch a scan that already exist you can pass its id

TENABLE_SCANNER_NAME: if you want to run the scan with an scanner you can pass the scanner name:

TENABLE_SCAN_TARGET: the scan target, can be an ip or hostname

TENABLE_SCAN_TEMPLATE: if you want to use an specifict template
