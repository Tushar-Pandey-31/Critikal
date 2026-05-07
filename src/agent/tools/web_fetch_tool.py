"""
WebFetchTool — HTTP GET with content extraction.

Fetches URLs and extracts readable content. Handles HTML (strips to text),
JSON, and plain text. Respects timeouts and size limits.
"""

import asyncio
import ipaddress
import json
import logging
import os
import socket
from urllib.parse import urlparse

from src.agent.context import ToolContext
from src.agent.tool import PermissionLevel, Tool, ToolResult

logger = logging.getLogger(__name__)

MAX_CONTENT_BYTES = 500_000  # 500KB
DEFAULT_TIMEOUT = 30

# Hostnames we never resolve — fast-path block for common internal names.
_BLOCKED_HOSTNAMES = frozenset({
    "localhost",
    "ip6-localhost",
    "ip6-loopback",
    "metadata",  # typical cloud metadata shortname
    "metadata.google.internal",
    "metadata.goog",
    "instance-data",
    "instance-data.ec2.internal",
})


def _is_private_ip(addr: str) -> bool:
    """True if `addr` is in a range we refuse to fetch from."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    # Catches loopback, link-local, private RFC1918/ULA, multicast,
    # unspecified, reserved ranges.
    if (
        ip.is_loopback
        or ip.is_link_local
        or ip.is_private
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
    ):
        return True
    # Explicit block: AWS/GCP/Azure IMDS.
    if str(ip) in {"169.254.169.254", "fd00:ec2::254"}:
        return True
    return False


def _validate_url_host(host: str) -> str | None:
    """Return an error string if the host should be blocked, else None.

    Explicitly resolves all A/AAAA records so an attacker can't bypass
    the guard by registering a DNS name that points at a private IP.
    """
    if not host:
        return "URL has no host."
    lowered = host.lower()
    if lowered in _BLOCKED_HOSTNAMES:
        return f"Blocked internal hostname: {host}"
    if lowered.endswith(".local") or lowered.endswith(".internal"):
        return f"Blocked internal TLD: {host}"

    # If the host is already a literal IP, check it directly.
    try:
        ip = ipaddress.ip_address(lowered.strip("[]"))
        if _is_private_ip(str(ip)):
            return f"Blocked private/reserved IP: {ip}"
        return None
    except ValueError:
        pass

    # DNS lookup — refuse if *any* resolved address is private.
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        return f"DNS resolution failed for {host}: {e}"

    for info in infos:
        addr = info[4][0]
        if _is_private_ip(addr):
            return f"Blocked: {host} resolves to private/reserved {addr}"
    return None


class WebFetchTool(Tool):

    def name(self) -> str:
        return "web_fetch"

    def description(self) -> str:
        return (
            "Fetch a URL and extract its content. Handles HTML (extracts text), "
            "JSON (pretty-prints), and plain text. Use for reading documentation, "
            "API responses, contract source from Etherscan, etc."
        )

    def permission_level(self) -> PermissionLevel:
        return PermissionLevel.READ_ONLY

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "The URL to fetch.",
                },
                "timeout": {
                    "type": "integer",
                    "description": f"Timeout in seconds (default: {DEFAULT_TIMEOUT}).",
                    "default": DEFAULT_TIMEOUT,
                },
                "raw": {
                    "type": "boolean",
                    "description": "Return raw response without content extraction. Default: false.",
                    "default": False,
                },
            },
            "required": ["url"],
        }

    async def execute(self, params: dict, ctx: ToolContext) -> ToolResult:
        if "input" in params and isinstance(params["input"], dict):
            params = params["input"]

        url = params.get("url") or params.get("href") or params.get("link") or ""
        if not url:
            return ToolResult.error(f"Missing 'url'. Got keys: {list(params.keys())}")
        timeout = params.get("timeout", DEFAULT_TIMEOUT)
        raw = params.get("raw", False)

        # Basic URL validation
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return ToolResult.error("Only http/https URLs are supported.")
        if not parsed.netloc:
            return ToolResult.error("Invalid URL: no host.")

        # SSRF guard — run in a thread so DNS resolution doesn't block the
        # event loop on a hostile nameserver.
        if os.getenv("CRITIKAL_WEB_FETCH_ALLOW_PRIVATE") != "1":
            host = parsed.hostname or ""
            ssrf_err = await asyncio.to_thread(_validate_url_host, host)
            if ssrf_err:
                return ToolResult.error(f"SSRF guard: {ssrf_err}")

        try:
            import aiohttp
        except ImportError:
            # Fallback to subprocess curl
            return await self._fetch_with_curl(url, timeout, raw)

        # Follow redirects manually so each hop is re-validated against
        # the SSRF guard — otherwise a public URL that redirects to a
        # private one would slip through.
        allow_private = os.getenv("CRITIKAL_WEB_FETCH_ALLOW_PRIVATE") == "1"
        current_url = url
        redirects_left = 5
        truncated = False
        text = ""
        content_type = ""
        status = 0

        try:
            async with aiohttp.ClientSession() as session:
                while True:
                    async with session.get(
                        current_url,
                        timeout=aiohttp.ClientTimeout(total=timeout),
                        headers={"User-Agent": "Critikal-Agent/1.0"},
                        allow_redirects=False,
                    ) as resp:
                        status = resp.status

                        # Handle redirect chain manually.
                        if status in (301, 302, 303, 307, 308):
                            if redirects_left <= 0:
                                return ToolResult.error(
                                    "Too many redirects (SSRF guard limit).",
                                )
                            location = resp.headers.get("Location")
                            if not location:
                                return ToolResult.error(
                                    f"HTTP {status} redirect without Location header.",
                                )
                            from urllib.parse import urljoin
                            next_url = urljoin(str(resp.url), location)
                            next_parsed = urlparse(next_url)
                            if next_parsed.scheme not in ("http", "https"):
                                return ToolResult.error(
                                    f"Refusing non-http redirect: {next_url}",
                                )
                            if not allow_private:
                                err = await asyncio.to_thread(
                                    _validate_url_host, next_parsed.hostname or "",
                                )
                                if err:
                                    return ToolResult.error(f"SSRF guard on redirect: {err}")
                            current_url = next_url
                            redirects_left -= 1
                            continue

                        if status >= 400:
                            return ToolResult.error(
                                f"HTTP {status}: {resp.reason}",
                                status=status,
                            )

                        content_type = resp.headers.get("Content-Type", "")
                        body = await resp.read()

                        if len(body) > MAX_CONTENT_BYTES:
                            body = body[:MAX_CONTENT_BYTES]
                            truncated = True

                        text = body.decode("utf-8", errors="replace")
                        break

        except TimeoutError:
            return ToolResult.error(f"Request timed out after {timeout}s.")
        except Exception as e:
            return ToolResult.error(f"Fetch failed: {e}")

        if raw:
            result = text
        elif "json" in content_type:
            try:
                parsed_json = json.loads(text)
                result = json.dumps(parsed_json, indent=2)
            except json.JSONDecodeError:
                result = text
        elif "html" in content_type:
            result = self._extract_html_text(text)
        else:
            result = text

        if truncated:
            result += "\n\n[Content truncated — exceeded 500KB limit]"

        return ToolResult.success(result, url=current_url, status=status)

    async def _fetch_with_curl(self, url: str, timeout: int, raw: bool) -> ToolResult:
        """Fallback when aiohttp is not installed."""
        # curl has its own redirect handler (-L), so we can't re-check per
        # hop. Strongly prefer aiohttp; if curl is our only option, disable
        # redirects entirely to avoid SSRF via Location headers.
        try:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "--max-time", str(timeout),
                "--max-redirs", "0",
                "-H", "User-Agent: Critikal-Agent/1.0",
                url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout + 5
            )
        except TimeoutError:
            return ToolResult.error(f"curl timed out after {timeout}s.")
        except FileNotFoundError:
            return ToolResult.error("Neither aiohttp nor curl available.")
        except Exception as e:
            return ToolResult.error(f"curl failed: {e}")

        if proc.returncode != 0:
            return ToolResult.error(f"curl error: {stderr.decode(errors='replace')}")

        text = stdout.decode("utf-8", errors="replace")
        if len(text) > MAX_CONTENT_BYTES:
            text = text[:MAX_CONTENT_BYTES] + "\n\n[Truncated]"

        if not raw and "<html" in text.lower():
            text = self._extract_html_text(text)

        return ToolResult.success(text, url=url)

    @staticmethod
    def _extract_html_text(html: str) -> str:
        """Extract readable text from HTML. Best-effort without heavy deps."""
        try:
            from html.parser import HTMLParser

            class _TextExtractor(HTMLParser):
                def __init__(self):
                    super().__init__()
                    self.parts = []
                    self._skip = False
                    self._skip_tags = {"script", "style", "noscript", "svg"}

                def handle_starttag(self, tag, attrs):
                    if tag in self._skip_tags:
                        self._skip = True
                    if tag in ("p", "br", "div", "h1", "h2", "h3", "h4", "li", "tr"):
                        self.parts.append("\n")

                def handle_endtag(self, tag):
                    if tag in self._skip_tags:
                        self._skip = False

                def handle_data(self, data):
                    if not self._skip:
                        self.parts.append(data)

            extractor = _TextExtractor()
            extractor.feed(html)
            text = "".join(extractor.parts)

            # Clean up whitespace
            lines = [line.strip() for line in text.splitlines()]
            lines = [l for l in lines if l]
            return "\n".join(lines)

        except Exception:
            # Fallback: strip tags with regex
            import re
            text = re.sub(r"<script[^>]*>.*?</script>", "", html, flags=re.DOTALL | re.IGNORECASE)
            text = re.sub(r"<style[^>]*>.*?</style>", "", text, flags=re.DOTALL | re.IGNORECASE)
            text = re.sub(r"<[^>]+>", " ", text)
            text = re.sub(r"\s+", " ", text)
            return text.strip()
