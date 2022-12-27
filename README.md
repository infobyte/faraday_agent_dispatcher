Faraday Agents Dispatcher helps user develop integrations with
[Faraday][faraday] written in any language. <!-- For more information, check [this
blogpost][blogpost] or continue reading. -->

[faraday]: https://github.com/infobyte/faraday/
[plugins]: https://github.com/infobyte/faraday_plugins
[blogpost]: https://medium.com/faraday

# Installation

Just run `pip3 install faraday_agent_dispatcher` and you should see the
`faraday-dispatcher` command in your system.

To setup a development environment (this is, to change code of the dispatcher
itself, not to write your own integrations), you should clone this repo and run
`pip install -e .`.

# Running Faraday Agent Dispatcher for first time

1. Generate a configuration file running `faraday-dispatcher
config-wizard`.

2. Run the agent with `faraday-dispatcher run` command. The config file
that it creates will be located in `~/.faraday/config/dispatcher.ini`
if you do not pass a custom path.

You should complete the agent configuration with your registration
token, located at http://localhost:5985/#/admin/agents. Check that the
server section has the correct information about your Faraday
Server instance. Then, complete the agent section with the desired name
of your agent. Finally, [add the executors](#configuring-a-executor)

# Executors

## Creating your own executors

An executor is a script that prints out **single-line** JSON data to
stdout. Remember that if you print any other data to stdout, the
dispatcher will trigger an error. If you want to print debugging or
logging information you should use stderr for that.

Every line written to stdout by the executor will be decoded by the
dispatcher and sent to Faraday using the Bulk Create endpoint.
Therefore, the JSON you print must have the schema that the endpoint
requires (this schema is detailed [below](#bulk-create-json-format)).
Otherwise, the dispatcher will complain because you supplied invalid
data to it.

If you want to debug your executor, the simplest way to do it is by
running it directly instead of running with the Dispatcher. Since the executor
just prints JSON data to stdout, you will be able to see all
information it wants to send to Faraday, but without actually sending
it.

## Configuring a executor

After writing your executor, you have to add it with the
`faraday-dispatcher config-wizard` within the executor section, adding
its name, command to execute and the max size of the JSON to send to
Faraday Server. Additionally, you can configure the Environment
variables and Arguments in their proper section.

## Running a executor

To run an executor use the `faraday-dispatcher config-wizard` command,
and play it from the Faraday Server. The executor will use the
environment variables set and ask for the arguments.

# Bulk Create JSON format

The data published to [faraday][faraday] must correspond to the
`bulk_create` endpoint of the [Faraday's REST API][API]

# Running multiple dispatchers

If you want to have more than one dispatcher, each one runninng its own
executors, the preferred of doing this is to create different
configuration files for each one (for example,
`~/.faraday/config/dispatcher-1.ini` and
`~/.faraday/config/dispatcher-2.ini`). Then, you can run two different
Dispatcher instances with `faraday-dispatcher --config-file
PATH_TO_A_CONFIG_FILE`.

# Executors

Inside the [executors][executors] directory you can find the already
created executors.

## Official

The [official executors][official_executors] are the collection of ready-to-go
executors (with minimum configuration with the wizard). They have a manifest
JSON file, which gives details about the uses of the executor and helps with
the configuration of them.

The current official executors are:

* [Arachni][arachni]
* [Burp][burp]
* [CrackMapExec][crackmap]
* [Nessus][nessus]
* [Nikto][nikto]
* [Nmap][nmap]
* [Nuclei][nuclei]
* [Openvas][openvas]
* Report processor: Consumes a local report where the dispatcher is with the [faraday plugins][plugins]
* [QualysGuard] [qualys]
* [Sonar Qube API][sonarqubeapi]
* [Sublist3r][sublist3r]
* [W3af][w3af]
* [Wpscan][wpscan]
* [Zap][zap]

## Development

The [development executors][dev_executors] are the collection of executors we
do **not** fully maintain, we have examples of use, conceptual, and in
development executors. The most important of them are:

* `basic_example.py`: The Hello World of Faraday executors. It will
  create a host with an associeted vulnerability to it
* `heroku_discovery_agent.py`: Load host and service information from
  your Heroku account
* `prowlerSample.py`: Run the [**prowler**][prowler] command and send
  its output to Faraday
* `brainfuck.sh`: A proof-of-concept to demonstrate you can create
  an executor in any programming language, including [Brainfuck][brainfuck]!

[executors]: https://github.com/infobyte/faraday_agent_dispatcher/tree/master/faraday_agent_dispatcher/static/executors
[official_executors]: https://github.com/infobyte/faraday_agent_dispatcher/tree/master/faraday_agent_dispatcher/static/executors/official
[dev_executors]: https://github.com/infobyte/faraday_agent_dispatcher/tree/master/faraday_agent_dispatcher/static/executors/dev
[brainfuck]: https://en.wikipedia.org/wiki/Brainfuck
[prowler]: https://github.com/toniblyx/prowler
[nessus]: https://www.nessus.org
[nikto]: https://cirt.net/Nikto2
[nmap]: https://nmap.org
[nuclei]: https://github.com/projectdiscovery/nuclei
[qualys]: https://www.qualys.com/
[sonarqubeapi]: https://www.sonarqube.org/
[sublist3r]: https://github.com/aboul3la/Sublist3r
[w3af]: http://w3af.org/
[wpscan]: https://wpscan.org/
[arachni]: https://www.arachni-scanner.com/
[openvas]: https://www.openvas.org/
[zap]: https://www.zaproxy.org/
[burp]: https://www.portswigger.net/burp
[crackmap]: https://github.com/byt3bl33d3r/CrackMapExec

# Roadmap

We are currently working on new executors, apart from improving the
experience using the agents.

We would like to give some agents read access to their workspace,
so they can benefit of the existing data in order to find more valuable
information.

# Documentation

For more info you can check our [documentation][doc]

[doc]: https://docs.agents.faradaysec.com
[API]: https://api.faradaysec.com/
