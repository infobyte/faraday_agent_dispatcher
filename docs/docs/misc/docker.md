# Agent Docker image

## Usage

The image is already published in our [dockehub page][dockerhub], so you just
 have to pull our image with the following command

```shell
$ docker pull faradaysec/faraday_agent_dispatcher
```

After that you only need a .ini file to pass to the image. We already have some
 [templates](#templates) to use. For these you have to edit it in
 the first lines:

```ini
[server]
; TODO be replaced with network configuration
host = localhost
ssl = False
api_port = 5985
websocket_port = 9000
ssl_cert =
; TODO be filled with available workspaces
workspaces =

[tokens]
; TODO be filled with the registration token (see https://docs.agents.faradaysec.com/getting-started/)
registration =
```

After setting the values in the .ini file, you can run the agent as:

```sh
$ docker run -v {ABSOLUTE_PATH_TO_INI}:/root/.faraday/config/dispatcher.ini -it faradaysec/faraday_agent_dispatcher
```

### Templates

We currently have 2 templates:

=== "Base Agent"  
    This [template](template_dispatcher.ini) use is as simple as shown above  
    ```shell
    $ docker run -v {ABSOLUTE_PATH_TO_INI}:/root/.faraday/config/dispatcher.ini -it faradaysec/faraday_agent_dispatcher
    ```

=== "With reports"  
    This [template](template_dispatcher_with_report.ini) adds the possibility
    of use a path to read reports from the host machine.
    ```shell
    $ docker run -v {ABSOLUTE_PATH_TO_INI}:/root/.faraday/config/dispatcher.ini  -v {ABSOLUTE_PATH_TO_REPORT_FOLDER}:/root/reports/ -it faradaysec/faraday_agent_dispatcher
    ```
    Then you can process any report by just specifying the route to the report
    file as an executor parameter

[dockerhub]: https://hub.docker.com/u/faradaysec
