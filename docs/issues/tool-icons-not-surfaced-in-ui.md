# Tool icons for custom executors not surfaced in Faraday UI

**Status:** open — pending Faraday-side change
**Filed for:** offensive-checks branch `tkt_276_offensivecheck`
**Scope:** Faraday web UI + dispatcher → server JOIN_AGENT payload + server-side Executor model

## Problem

The Faraday Web UI renders each executor's icon by looking up
`static/media/tool_logo_<NAME>.<HASH>.png` from its **own webpack bundle**
(`main.330a47c0.chunk.js`). Only ~12 tools currently ship with a baked-in logo:

```
appscan, arachni, insightVM, nessus, nikto, nmap, openvas, qualys,
tenable, w3af, wpscan, zap
```

Every other executor — including most of the offensive-checks deployment —
renders with **no icon**. From our 10-agent / 48-executor deployment, the
following 37 executors have no UI icon:

```
amass, bandit, burp, checkov, cisco_cybervision, codeql, crackmapexec,
crowdstrike, dependabot, dnstwist, ffuf, github_secrets, gitleaks, grype,
kics, kube_bench, kubescape, masscan, microsoft_defender, naabu, nuclei,
prowler, report_processor, semgrep, sentinelone, shellcheck, shodan2,
snyk, sonarqube, subfinder, sublist3r, tfsec, theharvester, trivy,
trufflehog, vicarius, wazuh
```

## Why the manifest `image` field doesn't help today

Manifests carry an `image` field (`null` on every shipping manifest), but the
dispatcher's `JOIN_AGENT` payload in `dispatcher_io.py:656-679` only forwards
`executor_name`, `args`, `category`, and `tool` to the server — `image` is
never sent. There's also no executor-metadata REST endpoint
(`/_api/v3/executors_data`, `/_api/v3/agent_executors`, etc. all return 404).
So even if every manifest's `image` is populated, **no current Faraday surface
consumes it**.

## Suggested fix (server-side, three pieces)

1. **Dispatcher**: include the image in the JOIN_AGENT payload. In
   `dispatcher_io.on_connect`, alongside `category` add
   `"image": manifests.get(executor.repo_name, {}).get("image")`.
2. **Faraday server**: persist the image on the `Executor` model and expose
   it on nested executors in `GET /_api/v3/agents`.
3. **Faraday web UI**: when an executor record carries a non-null `image`,
   render that (as a data URI, URL, or short-string asset key); otherwise
   fall back to the existing `tool_logo_<NAME>` lookup.

Any new agent then ships its own icon via its manifest — no UI release per
added tool, no live container patching.

## Workaround until the above lands

Two ugly options, both kept here for reference:

- **PR each PNG + lookup entry into the Faraday frontend repo** and cut a UI
  release. Clean but requires a Faraday-team merge + redeploy per batch of
  added tools.
- **Live-patch `/static/media/` and the lookup chunk inside the running
  Faraday container.** Works immediately but is wiped on every Faraday
  release, and modifying the hashed/minified chunk in-place is brittle.

## How to verify after the fix

1. Set `"image": "data:image/png;base64,…"` (or a URL) on any manifest in
   `cloud_dispatcher/faraday_agent_dispatcher/static/manifests/`.
2. Rebuild the image, redeploy the affected dispatcher.
3. The Faraday Agents page should render the supplied icon next to that
   executor, without any change to the UI bundle.

## Cross-refs

- Dispatcher JOIN_AGENT shape: `faraday_agent_dispatcher/dispatcher_io.py:656-679`
- Manifest schema fields (already includes `"image": null` in every shipping
  manifest): `faraday_agent_dispatcher/static/manifests/*.json`,
  `faraday_agent_parameters_types/static/manifests/*.json`
- UI bundle reference (the lookup that would consume the new field):
  `static/js/main.<hash>.chunk.js` → search for `tool_logo_`
