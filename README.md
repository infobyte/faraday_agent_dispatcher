Faraday Agents Dispatcher helps user develop integrations with
[Faraday][faraday] written in any language. <!-- For more information, check [this
blogpost][blogpost] or continue reading. -->

[faraday]: https://github.com/infobyte/faraday/
[blogpost]: https://medium.com/faraday

# Installation

Just run `pip3 install faraday_agent_dispatcher` and you should see the
`faraday-dispatcher` command in your system.

To setup a development environment (this is, to change code of the dispatcher
itself, not to write your own integrations), you should clone this repo and run
`python setup.py develop`.

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
running it directly instead of with the Dispatcher. Since the executor
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

TODO

# Running multiple dispatchers

If you want to have more than one dispatcher, each one runninng its own
executors, the preferred of doing this is to create different
configuration files for each one (for example,
`~/.faraday/config/dispatcher-1.ini` and
`~/.faraday/config/dispatcher-2.ini`). Then, you can run two different
Dispatcher instances with `faraday-dispatcher --config-file
PATH_TO_A_CONFIG_FILE`.

# Contributed executors

Inside the [`contrib/`][contrib] directory you can find some already
created executors. Here is a short description of each one:

* `basic_example.py`: The Hello World of Faraday executors. It will
  create a host with an associeted vulnerability to it
* `heroku_discovery_agent.py`: Load host and service information from
  your Heroku account
* `prowlerSample.py`: Run the [**prowler**][prowler] command and send
  its output to Faraday
* `responder.py`: Run [**Responder**][responder] and send its output
  to Faraday
* `brainfuck.sh`: A proof-of-concept to demonstrate you can create
  an executor in any programming language, including [Brainfuck][brainfuck]!

[contrib]: https://github.com/infobyte/faraday_agent_dispatcher/tree/master/contrib
[brainfuck]: https://en.wikipedia.org/wiki/Brainfuck
[prowler]: https://github.com/toniblyx/prowler
[responder]: https://github.com/lgandx/Responder

# Roadmap

We are currently working on new executors, apart from improving the
experience using the agents.

Currently, you have to manually add each parameter and environment
variable when adding a `contrib` executor. It will be possible to add
them quicker in a automatic way.

We would also like to give some agents read access to their workspace,
so they can benefit of the existing data in order to find more valuable
information.
