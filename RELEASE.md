1.1 [Apr 22th, 2020]:
---
 * The dispatcher now runs with a `faraday-dispatcher run` command
 * `faraday-dispatcher wizard` command added which generates configuration .ini file
 * Manage execution_id within WS and API communication
 * The route of [Faraday](faraday) ws comunication change from / to /websockets 
 * Better error management, now shows error and exceptions depending on log levels
 * Better management of invalid token errors
 * Add ssl support

1.0 [Dec 17th, 2019]:
---
 * You can add fixed parameters than shouldn't came by the web (e.g. passwords) are set in the dispatcher.ini
 * Now its possible to manage multiple executors within one agent
 * Now is possible to receive params from the [Faraday](faraday) server

0.1 [Oct 31th, 2019]:
---
 * First beta version published 
 * Basic structure implemented, with executor with fixed values

[faraday]: http://github.com/infobyte/faraday