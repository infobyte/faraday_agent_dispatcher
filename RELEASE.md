3.3.0 [Mar 12th, 2024]:
---
 * [ADD] Add hotspots option to SonarQube. #197
 * [ADD] New GitHub CodeQL agent. #208
 * [ADD] Added new agent for GitHub Secrets Scanning. #209
 * [MOD] Now Nessus executor tries to login again after a 401 response from the Nessus's server. #203
 * [MOD] Change Dependabot agent to work with the new manifest of parameter types. #210
 * [FIX] We were not verifying the configuration value `ignore_ssl` at the moment of `socketio` connection. #212

3.2.0 [Feb 8th, 2024]:
---
 * [ADD] Add dependabot agent. #206

3.0.1 [Dec 22th, 2023]:
---
 * [FIX] Fix on_diconnect method and limit python-socketio to 5.8.0 #199

3.0.0 [Dec 13th, 2023]:
---
 * [MOD] Now faraday-dispatcher works with socketio. #195

2.6.3 [Aug 24th, 2023]:
---
 * [FIX] Check the code response for burp executor #194

2.6.2 [Aug 3rd, 2023]:
---
 * [MOD] Now you can download a existing report in tenableio #192

2.6.1 [July 20th, 2023]:
---
 * [FIX] Now nuclei executor use -j flag instead of -json. #187

2.6.0 [July 7th, 2023]:
---
 * [ADD] Add HCL Appscan executer #186

2.5.1 [Jan 3rd, 2023]:
---
 * [DEL] Now nuclei doesn't check if the target is an ip
 * [MOD] Add a fixes for bandit vuln:
   - Replace assert return code with a if
   - Remove default x_token in nessus executor

2.5.0 [Nov 30th, 2022]:
---
 * [ADD] Add new Sonar Qube executor
 * [ADD] Add tenableio executor
 * [FIX] Make gvm executor compatible with new version of python-gvm
 * [FIX] Now if a venv is int or float it will convert to string

2.4.0 [Oct 26th. 2022]:
---
 * Add Qualys executor
 * [MOD] Change pgrep for psutil in zap executor

2.3.0 [Sep 5th, 2022]:
---
 * Now InsighVM's executer will executa a scan if a site_id is provided
 * Add tags for plugins
 * Add installation in docker file for nmap script: vulners
 * Now the api-key from zap is a enviroment variable
 * [FIX] Change AGENT_CONFIG_HOSTNAME_RESOLUTION por AGENT_CONFIG_RESOLVE_HOSTNAME
 * Update docs

2.2.0 [Jul 25th, 2022]:
---
 * Add timeout parameter to arachni's executor
 * Add python2.7, w3af and its dependencies to docker image
 * Add ignore_info and hostname_resolution options for most executors.
 * Nessus now list in the logs the available templates and uses posixpath.join instead of concat strings.
Nikto now uses only requieres TARGET_URL argument.
 * Fix logs and change .format to fstrings
 * Remove ws from dispatcher.yaml.
 * Now faraday-dispatcher send the parameters of the executors when it
connects to faraday server. Also it checks if there are new enviroment
variables defined in the manifest file and warn the user.

2.1.3 [Dec 13th, 2021]:
---
 * Add --api-token --random-user-agent to wpscan
 * Move shodan executor to official and change logic to work with plugins

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
