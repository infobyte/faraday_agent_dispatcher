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
  api_port: 5985 # port where faraday server is listening
  host: localhost  # replace with your host
  ssl: false
  ssl_cert: ''
  websocket_port: 5985  # same as api_port
```

In case your faraday server is running behind an nginx reverse proxy with ssl
enabled, you have to set the `ssl` value to `True`, and both ports to the same value.

```yaml
server:
  api_port: 443   # port where faraday server is listening
  host: https.host.com  # replace host with your host
  ssl: true
  ssl_cert: ''
  websocket_port: 443  # same as api_port
```

After setting the values in the .yaml file, you can run the agent with the
following command:

```sh
$ docker run -v {ABSOLUTE_PATH_TO_YAML}:/root/.faraday/config/dispatcher.yaml faradaysec/faraday_agent_dispatcher --token={TOKEN}
```

!!! warning
    As we explain in the [getting started guide][getting-started], you only need the token the first time you run
    an agent

### Templates

We currently have 2 templates:

=== "Base Agent"  
    This [template](template_dispatcher.yaml) use is as simple as shown above  
    ```shell
    $ docker run -v {ABSOLUTE_PATH_TO_YAML}:/root/.faraday/config/dispatcher.yaml -it faradaysec/faraday_agent_dispatcher --token={TOKEN}
    ```

=== "With reports"  
    This [template](template_dispatcher_with_report.yaml) adds the possibility
    of use a path to read reports from the host machine.
    ```shell
    $ docker run -v {ABSOLUTE_PATH_TO_YAML}:/root/.faraday/config/dispatcher.yaml  -v {ABSOLUTE_PATH_TO_REPORT_FOLDER}:/root/reports/ -it faradaysec/faraday_agent_dispatcher --token={TOKEN}
    ```
    Then you can process any report by just specifying the route to the report
    file as an executor parameter

[dockerhub]: https://hub.docker.com/u/faradaysec
[getting-started]: ../getting-started.md
