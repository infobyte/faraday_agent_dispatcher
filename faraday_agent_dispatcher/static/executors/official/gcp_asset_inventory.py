#!/usr/bin/env python
"""Google Cloud Asset Inventory asset importer.

Pulls assets from GCP Cloud Asset Inventory (CAI) via the canonical
``google-cloud-asset`` SDK (``AssetServiceClient.list_assets``) and
emits Faraday bulk-create JSON to stdout. Each GCP asset surfaces as
one Faraday host — IP-bearing assets (compute Instances / Addresses /
ForwardingRules) extract a real IPv4 when the resource payload carries
one, everything else falls back to the synthetic ``0.0.0.0`` because
most GCP asset types live on resource paths, not on IPs. The executor
is the asset-side companion to ``gcp_scc`` (the findings-side
executor); when the two run against the same organization the assets
provide the hosts and the SCC findings attach to them via
``resource_name``.

Endpoints used:
  ``asset_v1.AssetServiceClient().list_assets(parent=..., asset_types=..., content_type=RESOURCE)``
      -> primary listing endpoint. ``parent`` is the organization /
      folder / project scope. ``asset_types`` is an optional list (e.g.
      ``["compute.googleapis.com/Instance", "storage.googleapis.com/Bucket"]``);
      ``content_type=RESOURCE`` returns the resource payload alongside
      the asset metadata so we can extract IPs / hostnames. The SDK
      paginator handles ``nextPageToken`` walking internally;
      ``fetch_assets`` stops at ``MAX_PAGES=200`` worth of result-page
      iterations as a safety net.

Auth: GCP Cloud Asset Inventory uses the standard Google Application
Default Credentials chain. A service account with the
``roles/cloudasset.viewer`` role (or equivalent custom role granting
``cloudasset.assets.listResource``) is required, with credentials
exposed to the dispatcher as a service-account JSON key file whose
path is set in ``GOOGLE_APPLICATION_CREDENTIALS``. The SDK picks the
file up automatically via ADC; the executor validates that the path
exists and is readable before instantiating the client.
"""

import json
import os
import socket
import sys
import time
from datetime import datetime, timezone

MAX_PAGES = 200
DEFAULT_CONTENT_TYPE = "RESOURCE"


def log(msg):
    print(f"{datetime.utcnow()} - GcpAssetInventory: {msg}", file=sys.stderr, flush=True)


def env(name, required=False, default=None):
    value = os.getenv(name, default)
    if required and not value:
        log(f"{name} is required")
        sys.exit(1)
    return value


def validate_organization_id(value):
    """Validate GCP_ORGANIZATION_ID.

    Accepts a bare numeric id, the fully-qualified ``organizations/{id}``
    form, plus typo-tolerant ``organisations/`` / ``org/`` prefixes.
    None / blank -> None so the caller can ``sys.exit`` with a clear
    message.
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    lowered = text.lower()
    for prefix in ("organizations/", "organisations/", "org/"):
        if lowered.startswith(prefix):
            text = text[len(prefix) :].strip()
            break
    return text or None


def validate_asset_types(value):
    """Validate ASSET_TYPES — a CSV list of GCP asset-type filters.

    Accepts a CSV string (``compute.googleapis.com/Instance,storage.googleapis.com/Bucket``)
    or a list / tuple of strings. Each entry is whitespace-trimmed; only
    entries that look like ``{service}.googleapis.com/{Type}`` are
    retained, garbage entries are logged + dropped. Empty / None /
    all-garbage -> None so ``list_assets`` returns every asset type the
    IAM principal can read.
    """
    if value is None:
        return None
    if isinstance(value, str):
        items = [piece.strip() for piece in value.split(",")]
    elif isinstance(value, (list, tuple)):
        items = []
        for piece in value:
            if piece is None:
                continue
            items.append(str(piece).strip())
    else:
        log(f"ASSET_TYPES '{value!r}' is not a CSV string or list; ignored")
        return None

    out = []
    seen = set()
    for piece in items:
        if not piece:
            continue
        if "/" not in piece or "." not in piece.split("/", 1)[0]:
            log(f"ASSET_TYPES entry '{piece}' does not look like {{service}}.googleapis.com/{{Type}}; dropped")
            continue
        if piece in seen:
            continue
        seen.add(piece)
        out.append(piece)
    return out or None


def build_parent(organization_id):
    """Build the Cloud Asset Inventory ``parent`` string.

    The asset-listing surface accepts organization / folder / project
    parents; this executor targets the organization scope because that
    is the canonical ``cnapp`` use-case (single org-wide inventory).
    """
    return f"organizations/{organization_id}"


def _parse_resource_name(resource_name):
    """Pull provider / resource_type / project / region / name out of a GCP asset name.

    GCP asset names follow
    ``//{service}.googleapis.com/projects/{proj}/{scope}/{loc}/{type}/{name}``
    (e.g. ``//compute.googleapis.com/projects/p/zones/us-east1-b/instances/vm-1``)
    or the shorter
    ``//{service}.googleapis.com/projects/{proj}/{type}/{name}``
    (e.g. ``//storage.googleapis.com/projects/p/buckets/bk``). Returns a
    dict — empty when the name doesn't match the canonical shape.
    """
    out = {}
    if not isinstance(resource_name, str) or not resource_name.strip():
        return out
    text = resource_name.strip()
    if text.startswith("//"):
        text = text[2:]
    parts = [p for p in text.split("/") if p]
    if not parts:
        return out

    service = parts[0]
    if service.endswith(".googleapis.com") or "." in service:
        out["service"] = service
        out["provider"] = service.split(".", 1)[0]
    parts = parts[1:]

    i = 0
    while i < len(parts) - 1:
        token = parts[i].lower()
        if token == "projects":
            out["project"] = parts[i + 1]
            i += 2
            continue
        if token in ("zones", "regions", "locations"):
            out["location"] = parts[i + 1]
            i += 2
            continue
        if token in ("folders",):
            out["folder"] = parts[i + 1]
            i += 2
            continue
        if token in ("organizations", "orgs"):
            out["organization"] = parts[i + 1]
            i += 2
            continue
        if "resource_type" not in out:
            provider = out.get("provider", "")
            type_label = f"{provider}/{parts[i]}" if provider else parts[i]
            out["resource_type"] = type_label
            out["resource_name"] = parts[i + 1] if i + 1 < len(parts) else ""
            if i + 2 < len(parts):
                out["resource_name"] = parts[-1]
            break
        i += 1
    if "resource_type" not in out and parts:
        out["resource_name"] = parts[-1]
    return out


def _extract_asset_name(asset):
    """Pick the canonical GCP asset name out of an Asset object/dict."""
    if not isinstance(asset, dict):
        return ""
    for key in ("name", "Name"):
        v = asset.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def _extract_asset_type(asset):
    """Return the asset_type token (e.g. ``compute.googleapis.com/Instance``)."""
    if not isinstance(asset, dict):
        return ""
    for key in ("asset_type", "assetType", "AssetType"):
        v = asset.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def _extract_resource(asset):
    """Return the ``resource`` blob of an Asset.

    CAI Asset shape:
        ``{name, asset_type, resource: {data, location, version, ...},
            iam_policy, update_time, ancestors, ...}``
    The resource ``data`` blob holds the type-specific payload (the
    actual Instance / Bucket / Database JSON).
    """
    if not isinstance(asset, dict):
        return {}
    res = asset.get("resource") or asset.get("Resource")
    if isinstance(res, dict):
        return res
    return {}


def _extract_resource_data(asset):
    res = _extract_resource(asset)
    data = res.get("data") or res.get("Data")
    if isinstance(data, dict):
        return data
    return {}


def asset_ip(asset):
    """Pull the best-fit IPv4 out of a CAI Asset.

    Compute Instances expose the public IP via
    ``networkInterfaces[].accessConfigs[].natIP`` and the private IP via
    ``networkInterfaces[].networkIP`` — we prefer public so external
    scanners can pivot, falling back to private and then to the
    synthetic ``0.0.0.0``. Address / GlobalAddress / ForwardingRule
    types surface a direct ``address`` / ``IPAddress`` field.
    """
    data = _extract_resource_data(asset)
    asset_type = _extract_asset_type(asset).lower()

    if "instance" in asset_type and "compute" in asset_type:
        nis = data.get("networkInterfaces") if isinstance(data, dict) else None
        if isinstance(nis, list):
            for ni in nis:
                if not isinstance(ni, dict):
                    continue
                acs = ni.get("accessConfigs") or ni.get("access_configs")
                if isinstance(acs, list):
                    for ac in acs:
                        if not isinstance(ac, dict):
                            continue
                        nat = ac.get("natIP") or ac.get("nat_ip") or ac.get("natIp")
                        if isinstance(nat, str) and nat.strip():
                            return nat.strip()
            for ni in nis:
                if not isinstance(ni, dict):
                    continue
                priv = ni.get("networkIP") or ni.get("network_ip") or ni.get("networkIp")
                if isinstance(priv, str) and priv.strip():
                    return priv.strip()

    for key in ("address", "IPAddress", "ipAddress", "ip_address", "natIp", "natIP"):
        v = data.get(key) if isinstance(data, dict) else None
        if isinstance(v, str) and v.strip():
            return v.strip()

    return "0.0.0.0"


def asset_mac(asset):
    data = _extract_resource_data(asset)
    if not isinstance(data, dict):
        return ""
    nis = data.get("networkInterfaces")
    if isinstance(nis, list):
        for ni in nis:
            if not isinstance(ni, dict):
                continue
            for key in ("macAddress", "mac_address", "MacAddress"):
                v = ni.get(key)
                if isinstance(v, str) and v.strip():
                    return v.strip()
    for key in ("macAddress", "mac_address"):
        v = data.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def asset_os(asset):
    """Best-effort OS label.

    Compute Instances don't carry an explicit OS string; the canonical
    surface is ``disks[].licenses[]`` which embeds the image family
    (``projects/ubuntu-os-cloud/global/licenses/ubuntu-2004-lts``). We
    take the tail segment of the first license; if no license is
    present we fall back to ``guestOsFeatures`` (``WINDOWS`` / ``UEFI``
    / ``VIRTIO_SCSI_MULTIQUEUE`` style).
    """
    data = _extract_resource_data(asset)
    if not isinstance(data, dict):
        return ""
    disks = data.get("disks")
    if isinstance(disks, list):
        for disk in disks:
            if not isinstance(disk, dict):
                continue
            licenses = disk.get("licenses")
            if isinstance(licenses, list):
                for lic in licenses:
                    if isinstance(lic, str) and lic.strip():
                        tail = lic.strip().rstrip("/").rsplit("/", 1)[-1]
                        if tail:
                            return tail
            feats = disk.get("guestOsFeatures") or disk.get("guest_os_features")
            if isinstance(feats, list):
                for feat in feats:
                    if isinstance(feat, dict):
                        ft = feat.get("type") or feat.get("Type")
                        if isinstance(ft, str) and ft.strip().upper() == "WINDOWS":
                            return "windows"
                    elif isinstance(feat, str) and feat.strip().upper() == "WINDOWS":
                        return "windows"
    for key in ("operatingSystem", "operating_system", "os", "platform"):
        v = data.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def resource_label(asset):
    """Build a friendly label for an asset's primary resource."""
    if not isinstance(asset, dict):
        return ""
    name = _extract_asset_name(asset)
    parsed = _parse_resource_name(name)
    rtype = parsed.get("resource_type", "")
    rname = parsed.get("resource_name", "")
    project = parsed.get("project", "")
    location = parsed.get("location", "")

    data = _extract_resource_data(asset)
    if isinstance(data, dict):
        for key in ("name", "displayName", "display_name"):
            v = data.get(key)
            if isinstance(v, str) and v.strip():
                rname = v.strip()
                break

    res = _extract_resource(asset)
    if isinstance(res, dict):
        loc = res.get("location") or res.get("Location")
        if isinstance(loc, str) and loc.strip() and not location:
            location = loc.strip()

    if rname and rtype:
        label = f"{rtype} {rname}"
    elif rname:
        label = rname
    elif rtype and name:
        label = f"{rtype} {name}"
    elif name:
        label = name
    else:
        label = rtype or ""

    suffix = ""
    if location and project:
        suffix = f" [{project}/{location}]"
    elif project:
        suffix = f" [{project}]"
    elif location:
        suffix = f" [{location}]"
    if suffix:
        label = f"{label}{suffix}" if label else suffix.strip(" []")
    return str(label).strip()


def host_bucket_key(asset):
    """Pick a stable bucket key — the canonical asset name."""
    if not isinstance(asset, dict):
        return "__unknown__"
    name = _extract_asset_name(asset)
    return name or "__unknown__"


def _serialise(obj):
    if obj is None:
        return ""
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, (str, int, float)):
        return str(obj)
    try:
        return json.dumps(obj, default=str, separators=(",", ":"))
    except (TypeError, ValueError):
        return str(obj)


def build_host(asset):
    """Build a Faraday host record from one CAI Asset."""
    if not isinstance(asset, dict):
        return None
    name = _extract_asset_name(asset)
    asset_type = _extract_asset_type(asset)
    parsed = _parse_resource_name(name)
    res = _extract_resource(asset)
    data = _extract_resource_data(asset)

    label = resource_label(asset)
    hostname = label or name or ""
    ip = asset_ip(asset)
    mac = asset_mac(asset)
    os_label = asset_os(asset)

    desc_parts = []
    if name:
        desc_parts.append(f"asset_name={name}")
    if asset_type:
        desc_parts.append(f"asset_type={asset_type}")
    rtype = parsed.get("resource_type", "")
    if rtype:
        desc_parts.append(f"resource_type={rtype}")
    rname = parsed.get("resource_name", "")
    if rname:
        desc_parts.append(f"resource_name={rname}")
    project = parsed.get("project", "")
    if project:
        desc_parts.append(f"project={project}")
    location = parsed.get("location", "")
    if not location and isinstance(res, dict):
        loc = res.get("location") or res.get("Location")
        if isinstance(loc, str) and loc.strip():
            location = loc.strip()
    if location:
        desc_parts.append(f"location={location}")
    provider = parsed.get("provider", "")
    if provider:
        desc_parts.append(f"provider={provider}")

    if isinstance(res, dict):
        for label_k, key in (
            ("resource_parent", "parent"),
            ("discovery_name", "discovery_name"),
            ("discovery_name", "discoveryName"),
            ("resource_version", "version"),
        ):
            v = res.get(key)
            if v and f"{label_k}={v}" not in desc_parts:
                desc_parts.append(f"{label_k}={_serialise(v)}")

    if isinstance(data, dict):
        for label_k, key in (
            ("display_name", "displayName"),
            ("self_link", "selfLink"),
            ("status", "status"),
            ("machine_type", "machineType"),
            ("zone", "zone"),
            ("description", "description"),
            ("storage_class", "storageClass"),
            ("creation_timestamp", "creationTimestamp"),
        ):
            v = data.get(key)
            if v is None or v == "":
                continue
            if isinstance(v, (dict, list)):
                continue
            desc_parts.append(f"{label_k}={_serialise(v)}")

    ancestors = asset.get("ancestors") or asset.get("Ancestors")
    if isinstance(ancestors, list) and ancestors:
        joined = ", ".join(str(a) for a in ancestors if a)
        if joined:
            desc_parts.append(f"ancestors={joined}")

    for key in ("update_time", "updateTime"):
        v = asset.get(key)
        if v:
            desc_parts.append(f"update_time={_serialise(v)}")
            break

    return {
        "ip": ip,
        "os": os_label,
        "hostnames": [hostname] if hostname else [],
        "mac": mac,
        "description": " | ".join(desc_parts),
        "vulnerabilities": [],
    }


def _asset_to_dict(asset):
    """Coerce an SDK ``Asset`` proto into a plain dict."""
    if isinstance(asset, dict):
        return asset
    to_dict = getattr(type(asset), "to_dict", None)
    if callable(to_dict):
        try:
            return to_dict(asset)
        except Exception:  # noqa: BLE001
            pass
    try:
        return json.loads(json.dumps(asset, default=lambda o: getattr(o, "__dict__", str(o))))
    except Exception:  # noqa: BLE001
        return {}


def fetch_assets(client, parent, asset_types, content_type=DEFAULT_CONTENT_TYPE, max_pages=MAX_PAGES):
    """Paginate ``AssetServiceClient.list_assets`` with the supplied filters."""
    assets = []
    request = {"parent": parent, "content_type": content_type}
    if asset_types:
        request["asset_types"] = list(asset_types)
    try:
        pager = client.list_assets(request=request)
    except Exception as exc:  # noqa: BLE001
        log(f"CAI list_assets failed: {exc}")
        return assets
    pages = 0
    for item in pager:
        as_dict = _asset_to_dict(item)
        if isinstance(as_dict, dict) and as_dict:
            assets.append(as_dict)
        if pages >= max_pages * 1000:
            log(f"hit MAX_PAGES safety net ({max_pages}); stopping")
            break
        pages += 1
    return assets


def main():
    started = time.time()
    organization_id = validate_organization_id(env("EXECUTOR_CONFIG_GCP_ORGANIZATION_ID"))
    if not organization_id:
        log("GCP_ORGANIZATION_ID is required")
        sys.exit(1)

    asset_types = validate_asset_types(env("EXECUTOR_CONFIG_ASSET_TYPES"))

    creds_path = env("GOOGLE_APPLICATION_CREDENTIALS")
    if not creds_path:
        log("GOOGLE_APPLICATION_CREDENTIALS is required (path to GCP service account JSON)")
        sys.exit(1)
    if not os.path.isfile(creds_path):
        log(f"GOOGLE_APPLICATION_CREDENTIALS path '{creds_path}' is not a readable file")
        sys.exit(1)

    try:
        from google.cloud import asset_v1  # noqa: WPS433 — lazy
    except ImportError:
        log("google-cloud-asset is not installed in the executor environment")
        sys.exit(1)

    client = asset_v1.AssetServiceClient()

    parent = build_parent(organization_id)
    assets = fetch_assets(client, parent, asset_types)
    log(
        f"Processing {len(assets)} GCP assets "
        f"(organization={organization_id}, "
        f"asset_types={','.join(asset_types) if asset_types else 'ALL'})"
    )

    seen_keys = set()
    hosts = []
    for asset in assets:
        key = host_bucket_key(asset)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        host = build_host(asset)
        if host is None:
            continue
        hosts.append(host)

    params_bits = [f"organization={organization_id}"]
    if asset_types:
        params_bits.append(f"asset_types={','.join(asset_types)}")

    output = {
        "hosts": hosts,
        "command": {
            "tool": "gcp_asset_inventory",
            "command": "gcp_asset_inventory",
            "params": ",".join(params_bits),
            "user": os.environ.get("USER", ""),
            "hostname": socket.gethostname(),
            "start_date": datetime.fromtimestamp(started, tz=timezone.utc).isoformat(),
            "duration": int((time.time() - started) * 1000),
            "import_source": "report",
        },
    }
    print(json.dumps(output))


if __name__ == "__main__":
    main()
