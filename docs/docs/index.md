# Easier integrations with Faraday Agents
Integrating systems is an elusive but mandatory job in any software product's
life. Developers have to deal with languages they don't know, undocumented APIs
or new paradigms. This leads to the fact that many product teams decide not to
open the possibility to integrate to them.

In [Faraday][faraday]’s case, we are aware that integrations with other security
tools are a critical part of our product. However, we’ve realized that our
 [Plugin system][plugins] wasn't as easy as we expected to develop some
 integrations: it required some level of interactivity (either running a
 command from the console or importing a report), so it was hard to use on a
 periodic basis. It also forced integration developers to use our Python API,
 even when the tool to integrate with wasn't programmed in Python, making it
 harder for the developer.

To solve this problem, we have the **Faraday Agents**! You can use the [getting
started guide](getting-started.md) to use one of our official executors, or code
 and use one custom executor. Otherwise, you can [use our docker
image](misc/docker.md) with some tools already built and ready to
 go!

You can also check our [architecture](technical/arch.md) or
 [technical](technical/agents.md) section, to understand how the agents works.

[faraday]: https://github.com/infobyte/faraday
[plugins]: https://github.com/infobyte/faraday_plugins
