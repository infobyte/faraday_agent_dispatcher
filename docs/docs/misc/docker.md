# Agent Docker image

## Usage

The image is already published in our [dockehub page][dockerhub], so you just
 have to pull our image with the following command

```shell
$ docker pull faradaysec/faraday_agent_dispatcher
```

After that you only need a .yaml file to pass to the image. We already have some
 [templates](#templates) to use. For these you have to edit it in
 the first lines:

```yaml
server:
  api_port: '5985' # TODO be replaced with network configuration
  host: localhost
  ssl: 'False'
  ssl_cert: ''
  websocket_port: '9000'
```

After setting the values in the .yaml file, you can run the agent as:

```sh
$ docker run -v {ABSOLUTE_PATH_TO_YAML}:/root/.faraday/config/dispatcher.yaml faradaysec/faraday_agent_dispatcher --token={TOKEN}
```

??? info "Migrating from .ini"
    If you had an old version from agent-dispatcher, you can migrate your dispatcher.ini file as follows:
    ```
    docker run -v {ABSOLUTE_PATH_TO_INI}:/root/.faraday/config/dispatcher.ini -v {ABSOLUTE_PATH_TO_YAML}:/root/.faraday/config/dispatcher.yaml --entrypoint "/usr/local/bin/faraday-dispatcher" faradaysec/faraday_agent_dispatcher config-wizard
    ```

!!! warning
    As we explain in the [getting started guide][getting-started], you only need the token the first time you run
    an agent

### Templates

We currently have 2 templates:

=== "Base Agent"  
    This [template](template_dispatcher.yaml) use is as simple as shown above  
    ```shell
    $ docker run -v {ABSOLUTE_PATH_TO_INI}:/root/.faraday/config/dispatcher.ini -it faradaysec/faraday_agent_dispatcher --token={TOKEN}
    ```

    ??? info "old .ini version"
        This [template](template_dispatcher.ini) is the old .ini version of this template, it actually don't work
        with version 2.0.0

=== "With reports"  
    This [template](template_dispatcher_with_report.yaml) adds the possibility
    of use a path to read reports from the host machine.
    ```shell
    $ docker run -v {ABSOLUTE_PATH_TO_INI}:/root/.faraday/config/dispatcher.ini  -v {ABSOLUTE_PATH_TO_REPORT_FOLDER}:/root/reports/ -it faradaysec/faraday_agent_dispatcher --token={TOKEN}
    ```
    Then you can process any report by just specifying the route to the report
    file as an executor parameter

    ??? info "old .ini version"
        This [template](template_dispatcher_with_report.ini) is the old .ini version of this template, it actually
        don't work with version 2.0.0

[dockerhub]: https://hub.docker.com/u/faradaysec
[getting-started]: ../getting-started.md
