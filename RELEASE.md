2.1.2 [Oct 19th, 2021]:
---
 * ADD script to nmap logic

2.1.1 [Aug 18th, 2021]:
---
 * ADD option via configuration YAML file to ignore ssl errors
 * MOD Wizard connection ports defaults vary if SSL value has changed in the previous configuration
 * [Faraday][faraday] versions: 3.16.0, 3.16.1, 3.16.2, 3.17.0, 3.17.1, 3.17.2

2.1.0 [Aug 9th, 2021]:
---
 * ADD Reminder message to run --token command after wizard
 * FIX `start_date` and `end_date` to be sent as UTC
 * FIX Receiving API error when faraday license is expired
 * ADD Executor for insightvm
 * REMOVE Host and api from burp executor parameters
 * [Faraday][faraday] versions: 3.16.0, 3.16.1, 3.16.2, 3.17.0, 3.17.1, 3.17.2

2.0.0 [Jun 29th, 2021]:
---
 * ADD Executor parameter typing
 * ADD versioning for manifests from typing package
 * FIX typo in wizard
 * [Faraday][faraday] versions: 3.16.0, 3.16.1, 3.16.2, 3.17.0, 3.17.1, 3.17.2

1.5.1 [May 6th, 2021]:
---
 * FIX Burp executor parse the IP
 * [Faraday][faraday] versions: 3.14.3, 3.15.0, 3.15.1

1.5.0 [Mar 30th, 2021]:
---
 * ADD having at least a executor is mandatory, if not it will not save the configuration
 * UPD executor pagination, now each executor have a "unique" id
 * MOD Update all reference to [faraday][faraday] to [API v3][api]
 * MOD Connectivity endpoint is now `/_api/v3/info`
 * MOD Now registration token is needed within the run command. Only needed the first time
 * MOD setting host in the wizard now accepts full urls, such as `https://my.server.com:12345`
 * ADD new plugin to support newer OpenVas/gvm versions (gvm_openvas). The old openvas executor was renamed to
 "openvas_legacy"
 * [Faraday][faraday] versions: 3.14.3, 3.15.0, 3.15.1

1.4.2 [Feb 26th, 2021]:
---
 * MOD Update faraday-plugins version, improving nessus plugin process
 * [Faraday][faraday] versions: 3.14.0, 3.14.1, 3.14.2

1.4.1 [Feb 17th, 2021]:
---
 * MOD Various UX improves in wizard:
    * ADD special character control in name executor
    * ADD More verbose info
    * It is possible to exit wizard if its misconfigurated (will not be saved)
    * FIX Not choosing executor (Using Q) generates correct config file
    * MOD max data sent to server option is a manual edit configuration
    * MOD more extensive default list of official executors
    * MOD change color for options "next page" "don't choose"
 * ADD new WPScan executor that does not need docker anymore
 * FIX in nuclei_exclude parameter for nuclei executor
 * [Faraday][faraday] versions: 3.14.0, 3.14.1, 3.14.2

1.4.0 [Dec 23rd, 2020]:
---
 * A base_route can be added before the root of the server (e.g:
https://my.company.com/faraday/ as / of faraday)
 * Add duration to bulk_create to be set correctly
 * The new official executors are:
    * [nuclei](https://github.com/projectdiscovery/nuclei)
    * reports: local report consumed by faraday-plugins
 * Add new flags for nmap executor: `-sC`,`-sV`,`-Pn`,`--script-timeout`,`--host-timeout`,`--top-ports`
 * Fix bug nmap and nessus executors to execute with the dispatcher environment
 * Fix nmap executor when http(s) scheme passed as target
 * [Faraday][faraday] versions: 3.14.0, 3.14.1, 3.14.2

1.3.1 [Sep 7th, 2020]:
---
 * Add proxy setup by HTTP_PROXY or HTTPS_PROXY environment variables
 * Fix default report name with the nessus executor
 * [Faraday][faraday] versions: 3.12.0

1.3.0 [Sep 3rd, 2020]:
---
 * An Agent can post data to multiples workspaces
 * The `run` command tries to migrate the configuration to the latest version from
 others as the `config-wizard` does
 * Improve agent signal management and server disconnection, affecting the exit code
 * The wizard page size can be customized (See:
`faraday-dispatcher config-wizard --help` )
 * The new official executors are:
    * burp
    * crackmapexec
 * Arachni executor generates reports in /tmp now
 * Nmap executor updates use of nmap plugin (byte-string to string response)
 * [Faraday][faraday] versions: 3.12.0

1.2.1 [Jun 22nd, 2020]:
---
 * Now the dispatcher runs the check commands before running an executor
 * Fix error when connects with faraday fails when trying to access with SSL to not SSL server
 * Fix error when connects with faraday fails when server does not respond
 * Fix error when connects with faraday fails when SSL verification fails
 * Fix error attempting to create an executor with a comma in the name
 * Now the wizard ask if you want use the default SSL behavior
 * Started the process of [documentation][doc]
 * The new official executors are:  
    * arachni
    * openvas
    * zap
 * Nmap executor now acepted multi target
 * Fix W3af executor now uses python2
 * Escape user-controlled executor parameters in order to prevent OS argument injection (not command injection)
 * [Faraday][faraday] versions: 3.11, 3.11.1, 3.11.2

1.2 [May 27th, 2020]:
---
 * Now we have official executors, packaged with the dispatcher
 * Fix error when killed by signal
 * Fix error when server close connection
 * Fix error when ssl certificate does not exists
 * Fix error when folder `~/.faraday` does not exists, creating it
 * The new official executors are:  
    * nessus
    * nikto
    * nmap
    * sublist3r
    * wpscan
    * w3af
 * [Faraday][faraday] versions: 3.11, 3.11.1, 3.11.2

1.1 [Apr 22th, 2020]:
---
 * The dispatcher now runs with a `faraday-dispatcher run` command
 * `faraday-dispatcher wizard` command added which generates configuration .ini file
 * Manage execution_id within WS and API communication
 * The route of [Faraday][faraday] ws comunication change from / to /websockets
 * Better error management, now shows error and exceptions depending on log levels
 * Better management of invalid token errors
 * Add ssl support
 * [Faraday][faraday] versions: 3.11, 3.11.1, 3.11.2

1.0 [Dec 17th, 2019]:
---
 * You can add fixed parameters than shouldn't came by the web (e.g. passwords) are set in the dispatcher.ini
 * Now its possible to manage multiple executors within one agent
 * Now is possible to receive params from the [Faraday][faraday] server
 * [Faraday][faraday] versions: 3.10, 3.10.1, 3.10.2

0.1 [Oct 31th, 2019]:
---
 * First beta version published
 * Basic structure implemented, with executor with fixed values
 * [Faraday][faraday] versions: 3.9.2, 3.9.3

[faraday]: https://github.com/infobyte/faraday
[doc]: https://docs.agents.faradaysec.com
[api]: https://api.faradaysec.com
