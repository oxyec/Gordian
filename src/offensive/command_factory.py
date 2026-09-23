"""Translate high-level offensive config into safe argv command specs."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re
import shlex
import shutil
from pathlib import Path
from urllib.parse import urlparse

from .config import Intensity, OffensiveConfig, SpeedProfile


_DISALLOWED_TARGET = re.compile(r"[\s;&|`$<>\n\r\t]")
_HOSTNAME = re.compile(r"^[A-Za-z0-9.-]+$")
_PLACEHOLDER_RE = re.compile(r"\{([a-z_]+)\}")
_SENTINEL_EMPTY_TOKENS = {"(none)", "none", "null"}
_KNOWN_OVERRIDE_PLACEHOLDERS = {
    "target",
    "url",
    "host",
    "domain",
    "wordlist",
}
_KNOWN_TEMPLATE_PLACEHOLDERS = {
    "target",
    "url",
    "host",
    "domain",
    "wordlist",
    "binary",
    "default_args",
    "extra_args",
    "fuzz_url",
}


@dataclass(frozen=True)
class CommandSpec:
    tool: str
    argv: tuple[str, ...]


class CommandFactoryError(ValueError):
    """Raised when a target/config cannot be converted into safe commands."""


class CommandFactory:
    def __init__(self, config: OffensiveConfig) -> None:
        self.config = config

    def build(self) -> list[CommandSpec]:
        if not self.config.target:
            return []

        target = _sanitize_target(self.config.target)
        context = _build_target_context(target=target, wordlist=self.config.ffuf_wordlist)
        commands: list[CommandSpec] = []

        for tool in self.config.enabled_tools():
            argv = self._build_tool(tool, context)
            if argv is not None:
                commands.append(CommandSpec(tool=tool, argv=_resolve_argv_binary(argv)))

        return commands

    def missing_tools(self, commands: list[CommandSpec]) -> list[str]:
        missing: list[str] = []
        for spec in commands:
            binary = spec.argv[0] if spec.argv else spec.tool
            # Already-absolute paths (from _resolve_argv_binary) are trusted —
            # if shutil.which couldn't resolve it earlier, the bare name is
            # still in argv[0] and PATH lookup is repeated here.
            if Path(binary).is_absolute():
                if not Path(binary).exists():
                    missing.append(spec.tool)
                continue
            if shutil.which(binary) is None:
                missing.append(spec.tool)
        return sorted(set(missing))

    def _build_tool(self, tool: str, context: "TargetContext") -> tuple[str, ...] | None:
        override = self.config.command_override_for(tool)
        if override is not None:
            argv = list(self._apply_command_override(tool, override, context))
            argv.extend(self.config.extra_args_for(tool))
            return tuple(argv)

        if tool == "nmap":
            return self._build_nmap(context.host or context.target)
        if tool == "ffuf":
            if context.url is None:
                return None
            return self._build_ffuf(context.url)
        if tool == "nuclei":
            if context.url is None:
                return None
            return self._build_nuclei(context.url)
        if tool == "subfinder":
            if context.domain is None:
                return None
            return self._build_subfinder(context.domain)
        if tool == "amass":
            if context.domain is None:
                return None
            return self._build_amass(context.domain)
        if tool == "bbot":
            return self._build_bbot(context)
        if tool == "katana":
            if context.url is None:
                return None
            return self._build_katana(context.url)
        if tool == "httpx":
            return self._build_httpx(context)
        if tool == "secretfinder":
            if context.url is None:
                return None
            return self._build_secretfinder(context.url)
        if tool == "linkfinder":
            if context.url is None:
                return None
            return self._build_linkfinder(context.url)
        if tool == "gitleaks":
            return self._build_gitleaks()
        if tool == "aquatone":
            return self._build_aquatone(context)
        if tool == "gowitness":
            return self._build_gowitness(context)
        return None

    def _apply_command_override(
        self,
        tool: str,
        override: tuple[str, ...],
        context: "TargetContext",
    ) -> tuple[str, ...]:
        if not override:
            raise CommandFactoryError(f"tool command override for {tool} is empty")

        values = {
            "target": context.target,
            "url": context.url,
            "host": context.host,
            "domain": context.domain,
            "wordlist": context.wordlist,
        }

        rendered: list[str] = []
        for token in override:
            out = token
            for name in _PLACEHOLDER_RE.findall(token):
                if name not in _KNOWN_OVERRIDE_PLACEHOLDERS:
                    continue
                value = values.get(name)
                if value is None:
                    raise CommandFactoryError(
                        f"tool command override for {tool} uses {{{name}}} but no value is available"
                    )
                out = out.replace(f"{{{name}}}", value)
            rendered.append(out)
        return tuple(rendered)

    def _build_nmap(self, target: str) -> tuple[str, ...]:
        default_args = self._build_nmap_default_args()

        extra_args = list(self.config.extra_args_for("nmap"))
        template = self.config.command_template_for("nmap")
        if template:
            return self._render_command_template(
                tool="nmap",
                template=template,
                context=_build_target_context(target=target, wordlist=self.config.ffuf_wordlist),
                default_args=tuple(default_args),
                extra_args=tuple(extra_args),
            )

        argv: list[str] = [self.config.binary_for("nmap"), *default_args]
        argv.append(target)
        argv.extend(extra_args)
        return tuple(argv)

    def _build_nmap_default_args(self) -> list[str]:
        default_args: list[str] = ["-Pn", "-sV"]
        self._apply_nmap_speed_profile(default_args)
        self._apply_nmap_intensity(default_args)
        self._apply_nmap_rate_cap(default_args)
        return default_args

    def _apply_nmap_speed_profile(self, argv: list[str]) -> None:
        if self.config.bugbounty_mode:
            argv.extend(["-T2", "--top-ports", "300", "--version-light", "--max-rate", "40", "--open"])
            return

        if self.config.speed is SpeedProfile.STEALTH:
            argv.extend(["-T2", "--top-ports", "200", "--version-light"])
            return
        if self.config.speed is SpeedProfile.AGGRESSIVE:
            argv.extend(["-T4", "-p-", "-sC"])
            return
        argv.extend(["-T3", "--top-ports", "1000"])

    def _apply_nmap_intensity(self, argv: list[str]) -> None:
        if self.config.intensity is Intensity.LOW:
            argv.extend(["--max-retries", "1"])
            return
        if self.config.intensity is Intensity.HIGH:
            if self.config.bugbounty_mode:
                argv.extend(["--max-retries", "2"])
            else:
                argv.extend(["--max-retries", "3", "--script", "vuln"])

    def _apply_nmap_rate_cap(self, argv: list[str]) -> None:
        if self.config.max_nmap_rate is None:
            return
        if "--max-rate" in argv:
            rate_idx = argv.index("--max-rate") + 1
            argv[rate_idx] = str(min(int(argv[rate_idx]), self.config.max_nmap_rate))
            return
        argv.extend(["--max-rate", str(self.config.max_nmap_rate)])

    def _build_ffuf(self, target_url: str) -> tuple[str, ...]:
        threads = "20"
        if self.config.speed is SpeedProfile.STEALTH:
            threads = "5"
        elif self.config.speed is SpeedProfile.AGGRESSIVE:
            threads = "60"

        if self.config.intensity is Intensity.LOW:
            threads = "10"
        elif self.config.intensity is Intensity.HIGH:
            threads = "80"

        if self.config.bugbounty_mode:
            threads = str(min(int(threads), 25))
        if self.config.max_ffuf_threads is not None:
            threads = str(min(int(threads), self.config.max_ffuf_threads))

        ext = ",".join(self.config.ffuf_extensions)
        fuzz_url = target_url.rstrip("/") + "/FUZZ"

        default_args: list[str] = [
            "-mc",
            "200,204,301,302,307,401,403",
            "-t",
            threads,
            "-s",
        ]
        if self.config.bugbounty_mode:
            default_args.extend(["-p", "0.05"])
        for header in self.config.request_headers:
            default_args.extend(["-H", header])
        if ext:
            default_args.extend(["-e", ext])

        extra_args = list(self.config.extra_args_for("ffuf"))
        template = self.config.command_template_for("ffuf")
        if template:
            context = _build_target_context(target=target_url, wordlist=self.config.ffuf_wordlist)
            return self._render_command_template(
                tool="ffuf",
                template=template,
                context=context,
                default_args=tuple(default_args),
                extra_args=tuple(extra_args),
            )

        argv: list[str] = [
            self.config.binary_for("ffuf"),
            "-u",
            fuzz_url,
            "-w",
            self.config.ffuf_wordlist,
            *default_args,
        ]
        argv.extend(extra_args)
        return tuple(argv)

    def _build_nuclei(self, target_url: str) -> tuple[str, ...]:
        default_args: list[str] = [
            "-jsonl",
            "-silent",
            "-severity",
            "medium,high,critical",
        ]

        if self.config.speed is SpeedProfile.STEALTH:
            default_args.extend(["-rl", "30"])
        elif self.config.speed is SpeedProfile.AGGRESSIVE:
            default_args.extend(["-rl", "250"])
        else:
            default_args.extend(["-rl", "100"])

        if self.config.bugbounty_mode:
            rl_idx = default_args.index("-rl") + 1
            safe_rate = min(int(default_args[rl_idx]), 80)
            default_args[rl_idx] = str(safe_rate)
            default_args.extend(["-timeout", "5"])

        if self.config.max_nuclei_rate is not None:
            rl_idx = default_args.index("-rl") + 1
            default_args[rl_idx] = str(min(int(default_args[rl_idx]), self.config.max_nuclei_rate))

        for header in self.config.request_headers:
            default_args.extend(["-H", header])

        if self.config.nuclei_templates:
            default_args.extend(["-t", self.config.nuclei_templates])

        extra_args = list(self.config.extra_args_for("nuclei"))
        template = self.config.command_template_for("nuclei")
        if template:
            context = _build_target_context(target=target_url, wordlist=self.config.ffuf_wordlist)
            return self._render_command_template(
                tool="nuclei",
                template=template,
                context=context,
                default_args=tuple(default_args),
                extra_args=tuple(extra_args),
            )

        argv: list[str] = [self.config.binary_for("nuclei"), "-u", target_url, *default_args]
        argv.extend(extra_args)

        return tuple(argv)

    def _build_subfinder(self, domain: str) -> tuple[str, ...]:
        argv: list[str] = [self.config.binary_for("subfinder"), "-silent", "-d", domain]
        if self.config.speed is SpeedProfile.AGGRESSIVE and not self.config.bugbounty_mode:
            argv.append("-all")
        argv.extend(self.config.extra_args_for("subfinder"))
        return tuple(argv)

    def _build_amass(self, domain: str) -> tuple[str, ...]:
        argv: list[str] = [self.config.binary_for("amass"), "enum", "-d", domain]
        if self.config.speed is SpeedProfile.AGGRESSIVE and not self.config.bugbounty_mode:
            argv.append("-active")
        else:
            argv.append("-passive")
        argv.extend(self.config.extra_args_for("amass"))
        return tuple(argv)

    def _build_bbot(self, context: "TargetContext") -> tuple[str, ...]:
        target = context.domain or context.host or context.target
        argv: list[str] = [self.config.binary_for("bbot"), "-t", target, "-y"]
        argv.extend(self.config.extra_args_for("bbot"))
        return tuple(argv)

    def _build_katana(self, target_url: str) -> tuple[str, ...]:
        depth = 2
        if self.config.intensity is Intensity.LOW:
            depth = 1
        elif self.config.intensity is Intensity.HIGH:
            depth = 4
        if self.config.bugbounty_mode:
            depth = min(depth, 2)

        argv: list[str] = [self.config.binary_for("katana"), "-u", target_url, "-silent", "-d", str(depth)]
        for header in self.config.request_headers:
            argv.extend(["-H", header])
        argv.extend(self.config.extra_args_for("katana"))
        return tuple(argv)

    def _build_httpx(self, context: "TargetContext") -> tuple[str, ...]:
        target = context.url or context.host or context.target
        threads = 60
        if self.config.speed is SpeedProfile.STEALTH:
            threads = 20
        elif self.config.speed is SpeedProfile.AGGRESSIVE:
            threads = 120
        if self.config.bugbounty_mode:
            threads = min(threads, 40)

        argv: list[str] = [
            self.config.binary_for("httpx"),
            "-u",
            target,
            "-silent",
            "-json",
            "-title",
            "-tech-detect",
            "-status-code",
            "-threads",
            str(threads),
        ]
        for header in self.config.request_headers:
            argv.extend(["-H", header])
        argv.extend(self.config.extra_args_for("httpx"))
        return tuple(argv)

    def _build_secretfinder(self, target_url: str) -> tuple[str, ...]:
        argv: list[str] = [self.config.binary_for("secretfinder"), "-i", target_url, "-o", "cli"]
        argv.extend(self.config.extra_args_for("secretfinder"))
        return tuple(argv)

    def _build_linkfinder(self, target_url: str) -> tuple[str, ...]:
        argv: list[str] = [self.config.binary_for("linkfinder"), "-i", target_url, "-o", "cli"]
        argv.extend(self.config.extra_args_for("linkfinder"))
        return tuple(argv)

    def _build_gitleaks(self) -> tuple[str, ...]:
        argv: list[str] = [
            self.config.binary_for("gitleaks"),
            "detect",
            "--no-banner",
            "--redact",
            "--source",
            ".",
            "--report-format",
            "json",
        ]
        argv.extend(self.config.extra_args_for("gitleaks"))
        return tuple(argv)

    def _build_aquatone(self, context: "TargetContext") -> tuple[str, ...]:
        target_url = context.url or f"http://{context.host or context.target}"
        argv: list[str] = [self.config.binary_for("aquatone"), "-url", target_url]
        argv.extend(self.config.extra_args_for("aquatone"))
        return tuple(argv)

    def _build_gowitness(self, context: "TargetContext") -> tuple[str, ...]:
        target_url = context.url or f"http://{context.host or context.target}"
        argv: list[str] = [self.config.binary_for("gowitness"), "scan", "single", "-u", target_url, "--quiet"]
        argv.extend(self.config.extra_args_for("gowitness"))

        return tuple(argv)

    def _render_command_template(
        self,
        *,
        tool: str,
        template: str,
        context: "TargetContext",
        default_args: tuple[str, ...],
        extra_args: tuple[str, ...],
    ) -> tuple[str, ...]:
        fuzz_url = ""
        if context.url is not None:
            fuzz_url = context.url.rstrip("/") + "/FUZZ"

        template_target = context.target
        if tool == "nmap" and context.host:
            template_target = context.host

        values = {
            "target": template_target,
            "url": context.url or "",
            "host": context.host or "",
            "domain": context.domain or "",
            "wordlist": context.wordlist,
            "binary": self.config.binary_for(tool),
            "default_args": shlex.join(default_args),
            "extra_args": shlex.join(extra_args),
            "fuzz_url": fuzz_url,
        }

        # Parse the trusted template first. Interpolated scalar values stay
        # inside ONE argument, including paths containing spaces/backslashes.
        try:
            tokens = shlex.split(template)
        except ValueError as exc:
            raise CommandFactoryError(f"invalid template for {tool}: {exc}") from exc
        expanded: list[str] = []
        sequences = {"default_args": default_args, "extra_args": extra_args}
        for token in tokens:
            if token in ("{default_args}", "{extra_args}"):
                expanded.extend(sequences[token[1:-1]])
                continue
            def replace_scalar(match: re.Match[str]) -> str:
                name = match.group(1)
                if name not in values or name in sequences:
                    raise CommandFactoryError(f"invalid scalar placeholder: {name}")
                return values[name]
            expanded.append(_PLACEHOLDER_RE.sub(replace_scalar, token))
        argv = tuple(expanded)

        argv = _sanitize_template_argv(argv)

        if not argv:
            raise CommandFactoryError(f"tool command template for {tool} produced an empty command")
        return argv


def _sanitize_template_argv(argv: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(
        token
        for token in argv
        if token and str(token).strip().lower() not in _SENTINEL_EMPTY_TOKENS
    )


@dataclass(frozen=True)
class TargetContext:
    target: str
    url: str | None
    host: str | None
    domain: str | None
    wordlist: str


def _build_target_context(*, target: str, wordlist: str) -> TargetContext:
    return TargetContext(
        target=target,
        url=_target_to_url(target),
        host=_target_to_host(target),
        domain=_target_to_domain(target),
        wordlist=wordlist,
    )


def _resolve_argv_binary(argv: tuple[str, ...]) -> tuple[str, ...]:
    """Replace argv[0] with the absolute path resolved via PATH lookup.

    Cross-platform consistency: on POSIX, ``asyncio.create_subprocess_exec``
    delegates to ``execvp`` which honours PATH, but on Windows it forwards to
    ``CreateProcess`` whose PATH search is less predictable (e.g. PATHEXT
    semantics). Resolving up-front means both platforms see the same argv
    and any "not found" error happens at preflight time with a clear message
    rather than as an opaque OSError at launch.
    """
    if not argv:
        return argv
    binary = argv[0]
    if Path(binary).is_absolute():
        return argv
    resolved = shutil.which(binary)
    if resolved is None:
        # Leave bare name in place so missing_tools() can still flag it.
        return argv
    return (resolved, *argv[1:])


def _sanitize_target(target: str) -> str:
    value = target.strip()
    if not value:
        raise CommandFactoryError("offensive target is empty")
    if value.startswith(("-", "@")) or any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise CommandFactoryError("target cannot be an option or contain control characters")
    if _DISALLOWED_TARGET.search(value):
        raise CommandFactoryError("target contains unsupported characters")

    # Parse literals before URLs: an IPv6 address also contains colons.
    try:
        ipaddress.ip_network(value, strict=False)
        return value
    except ValueError:
        pass
    parsed = urlparse(value)
    if parsed.scheme:
        if parsed.scheme not in {"http", "https"}:
            raise CommandFactoryError("only http/https targets are supported")
        if not parsed.hostname:
            raise CommandFactoryError("URL target must include hostname")
        if parsed.username is not None or parsed.password is not None:
            raise CommandFactoryError("URL credentials are not accepted")
        try:
            parsed.port
        except ValueError as exc:
            raise CommandFactoryError("invalid URL port") from exc
        _sanitize_target(parsed.hostname)
        return value

    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass

    try:
        ipaddress.ip_network(value, strict=False)
        return value
    except ValueError:
        pass

    labels = value.rstrip(".").split(".")
    if (len(value) > 253 or not _HOSTNAME.fullmatch(value)
            or any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
                   for label in labels)):
        raise CommandFactoryError("target must be a valid hostname, ip, cidr, or URL")
    return value


def _target_to_url(target: str) -> str | None:
    parsed = urlparse(target)
    if parsed.scheme in {"http", "https"}:
        return target
    try:
        ipaddress.ip_network(target, strict=False)
        return None
    except ValueError:
        return f"http://{target}"


def _target_to_host(target: str) -> str | None:
    try:
        ipaddress.ip_network(target, strict=False)
        return target
    except ValueError:
        pass
    parsed = urlparse(target)
    if parsed.scheme:
        return parsed.hostname
    return target


def _target_to_domain(target: str) -> str | None:
    host = _target_to_host(target)
    if not host:
        return None
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass
    try:
        ipaddress.ip_network(host, strict=False)
        return None
    except ValueError:
        return host
