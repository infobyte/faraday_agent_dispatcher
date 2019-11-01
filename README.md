Faraday Agents Dispatcher helps user develop integrations with
[Faraday][faraday] written in any language. For more information, check [this
blogpost][blogpost] or continue reading.

[faraday]: https://github.com/infobyte/faraday/
[blogpost]: https://medium.com/faraday

# Installation

Just run `pip3 install faraday_agent_dispatcher` and you should see the
`faraday-dispatcher` command in your system.

To setup a development environment (this is, to change code of the dispatcher
itself, not to write your own integrations), you should clone this repo and run
`python setup.py develop`.

# Running Faraday Agent Dispatcher for first time

If you run the `faraday-dispatcher` command without any configuration
file, it will create a default one and ask you to fill the required
information. Here is the default config file that it creates (this will
be located in `~/.faraday/config/dispatcher.ini`):

```ini
[server]
workspace = example
host = localhost
api_port = 5985
websocket_port = 9000

[executor]
; Complete the cmd option with the command you want the dispatcher to run
; cmd =
agent_name = unnamed_agent

[tokens]
; To get your registration token, visit http://localhost:5985/#/admin/agents, copy
; the value and uncomment the line
; registration =
```

You should complete with your registration token, located at
http://localhost:5985/#/admin/agents. Check that the `[server]` section has the
correct information abour your Faraday Server instance. Finally, complete the
`[executor]` section with the desired name of your agent and the command to be
run.

# Creating your own executors

An executor is a script that prints out **single-line** JSON data to stdout.
Remember that if you print any other data to stdout, the dispatcher will
trigger an error. If you want to print debugging or logging information you
should use stderr for that.

Every line written to stdout by the executor will be decoded by the dispatcher
and sent to Faraday using the Bulk Create endpoint. Therefore, the JSON you
print must have the schema that the endpoint requires (this schema is detailed
[below](#bulk-create-json-format)). Otherwise, the dispatcher will complain
because you supplied invalid data to it.

If you want to debug your executor, the simplest way to do it is by running it
directly instead of with the Dispatcher. Since the executor just prints JSON
data to stdout, you will be able to see all information it wants to send to
Faraday, but without actually sending it.

# Bulk Create JSON format

TODO

# Running multiple executors

If you want to have more than one agent, each one runninng its own executor,
the preferred of doing this is to create different config files for each one
(for example, `~/.faraday/config/dispatcher-1.ini` and
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

After releasing Faraday 3.10 (that will be the first version with Python 3
support), we will improve agents features and usability. We are planning to add
a frontend to support configuring agents and running them with custom arguments
(this is being implemented in the `args` branch of this project).

We would also like to give some agents read access to their workspace, so they
can benefit of the existing data in order to find more valuable information.
