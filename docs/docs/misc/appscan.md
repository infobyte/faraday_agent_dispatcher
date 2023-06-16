# Faraday’s Appscan Executor 

The function of the Appscan Executor is to create and/or launch an Appscan scan.

### Environment Variables

The Appscan executor has 3 environment variables: HCL_KEY_ID, HCL_KEY_SECRET and HCL_APP_ID. 
HCL_KEY_ID and HCL_KEY_SECRET are used to create the token to authenticate against Appscan.

HCL_APP_ID is used to indicate in which app launch the scanner


### Parameters:
The Appscan executor has 1 mandatory parameters:
- Scan Type: can be SAST or DAST.

When creating a new scan the parameter HCL_SCAN_TARGET is required. If the target is not already register in Appscan the executor will not work. 
Also you can pass a scan name, if none are passed the scan will be named timestamp-faraday-agent.

The executor can also execute a scan already created, in that case the parameter HCL_SCAN_ID is required.

