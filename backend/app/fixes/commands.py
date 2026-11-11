"""Upgrade commands built by code from the package type, name and Trivy's fixed version.

The syntax of each command is checked in the package manager's official docs
(fix-commands skill, with the sources). A package type that is not verified
gets no command and a note that says so. Nothing here runs a command: they are
only shown. The words of a command come from an untrusted report, so a command
is built only from names and versions that match a strict pattern.
"""

import re
from collections.abc import Callable
from dataclasses import dataclass

MAX_VERSIONS = 8  # one command per fixed version, up to this many

# A name only in the shape its package manager uses; never a leading "-".
PLAIN_NAME = re.compile(r"[A-Za-z0-9._+][A-Za-z0-9._+-]*")
NPM_NAME = re.compile(r"(?:@[A-Za-z0-9._-]+/)?[A-Za-z0-9._+][A-Za-z0-9._+-]*")  # name or @scope/name
GO_NAME = re.compile(r"[A-Za-z0-9._~][A-Za-z0-9._~-]*(?:/[A-Za-z0-9._~-]+)*")  # a module path
# The same plus ":" (a Debian epoch) and "~"; never a leading "-".
SAFE_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+:~-]*")
SAFE_TYPE = re.compile(r"[A-Za-z0-9._-]{1,40}")

# Flags and settings that skip a safety check, from the same docs. A command
# that contains one is never shown as recommended (the AI's are removed).
UNSAFE_FLAGS = (
    "--allow-unauthenticated",
    "--allow-insecure-repositories",
    "--allow-releaseinfo-change",
    "--allow-downgrades",
    "--allow-remove-essential",
    "--allow-change-held-packages",
    "--force-yes",
    "--nogpgcheck",
    "gpgcheck=0",
    "--break-system-packages",
    "--ignore-installed",
    "--no-deps",
    "--no-build-isolation",
    "--ignore-scripts",
    "--ignore-rust-version",
    "-insecure",
    "--insecure",
    "--trusted-host",
    "--no-check-certificate",
    "--no-verify",
    "allowinsecurerepositories",
    "allowunauthenticated",
    "GOSUMDB=off",
    "GONOSUMDB",
    "GOINSECURE",
)
# A download piped straight into a shell runs code nobody checked.
PIPE_TO_SHELL = re.compile(r"\|\s*(?:sh|bash)\b")


@dataclass(frozen=True)
class FixCommand:
    """The lines of one command block; the label says which fixed version it is for."""

    label: str | None
    lines: tuple[str, ...]


@dataclass(frozen=True)
class BuiltFix:
    commands: tuple[FixCommand, ...]
    note: str | None  # why there is no command, or what to know about the ones shown


def _apt(name: str, version: str) -> tuple[str, ...]:
    # "An update should always be performed before an upgrade" (apt-get(8)).
    return ("apt-get update", f"apt-get install --only-upgrade {name}={version}")


def _dnf(name: str, version: str) -> tuple[str, ...]:
    return (f"dnf install {name}-{version}",)


def _pip(name: str, version: str) -> tuple[str, ...]:
    return (f"python -m pip install '{name}=={version}'",)


def _npm(name: str, version: str) -> tuple[str, ...]:
    return (f"npm install {name}@{version}",)


def _go(name: str, version: str) -> tuple[str, ...]:
    # Go versions start with "v"; Trivy often writes the number alone.
    return (f"go get {name}@{'v' + version if version[0].isdigit() else version}",)


def _cargo(name: str, version: str) -> tuple[str, ...]:
    return (f"cargo update {name} --precise {version}",)


# Trivy package type -> (the name shape, how to build the command); only verified ones, see the skill.
BUILDERS: dict[str, tuple[re.Pattern[str], Callable[[str, str], tuple[str, ...]]]] = {
    "debian": (PLAIN_NAME, _apt),
    "ubuntu": (PLAIN_NAME, _apt),
    "fedora": (PLAIN_NAME, _dnf),
    "rocky": (PLAIN_NAME, _dnf),
    "alma": (PLAIN_NAME, _dnf),
    "pip": (PLAIN_NAME, _pip),
    "python-pkg": (PLAIN_NAME, _pip),
    "npm": (NPM_NAME, _npm),
    "node-pkg": (NPM_NAME, _npm),
    "gomod": (GO_NAME, _go),
    "gobinary": (GO_NAME, _go),
    "cargo": (PLAIN_NAME, _cargo),
}
# Go reports the standard library as a package; it is fixed by upgrading Go itself.
GO_TOOLCHAIN_NAMES = ("stdlib", "toolchain")


def distinct_versions(fixed_versions: list[str]) -> list[str]:
    """Trivy's fixed versions, one per entry: a "1.2, 2.0" string is split. Order kept."""
    seen: dict[str, None] = {}
    for text in fixed_versions:
        for part in text.split(","):
            if part.strip():
                seen.setdefault(part.strip())
    return list(seen)


def build_fix_commands(name: str | None, package_type: str | None, fixed_versions: list[str]) -> BuiltFix:
    """The upgrade command for each fixed version Trivy lists, or a note on why there is none."""
    versions = distinct_versions(fixed_versions)
    if not versions:
        return BuiltFix((), "Trivy lists no fixed version, so there is no upgrade command.")
    if not package_type:
        return BuiltFix((), "The report does not say the package type, so no command is built.")
    entry = BUILDERS.get(package_type)
    if entry is None:
        shown = f" for {package_type}" if SAFE_TYPE.fullmatch(package_type) else ""
        return BuiltFix((), f"No command is built{shown}: its syntax is not verified.")
    name_shape, builder = entry
    if builder is _go and name in GO_TOOLCHAIN_NAMES:
        return BuiltFix((), "The Go standard library is fixed by upgrading Go itself, so no go get command is built.")
    if not name or not name_shape.fullmatch(name) or not all(SAFE_VERSION.fullmatch(v) for v in versions):
        return BuiltFix((), "The package name or version has unusual characters, so no command is built.")
    chosen = versions[:MAX_VERSIONS]
    label = (lambda version: f"Fixed version {version}") if len(versions) > 1 else (lambda version: None)
    commands = tuple(FixCommand(label(version), builder(name, version)) for version in chosen)
    notes = []
    if len(versions) > 1:
        notes.append(
            "Trivy lists several fixed versions (often one per release). Use the one that fits your release; "
            "versions are not compared here."
        )
    if len(versions) > MAX_VERSIONS:
        notes.append(f"Showing the first {MAX_VERSIONS} of {len(versions)} fixed versions.")
    return BuiltFix(commands, " ".join(notes) or None)


def is_unsafe_command(command: str) -> bool:
    """True if the command contains a flag or setting that skips a safety check."""
    lowered = command.lower()
    return any(flag.lower() in lowered for flag in UNSAFE_FLAGS) or bool(PIPE_TO_SHELL.search(lowered))
