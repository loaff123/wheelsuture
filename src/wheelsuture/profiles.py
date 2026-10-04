"""Fixed, evidence-versioned POSIX destination profile; no host discovery."""

import re
from .constants import PROFILE_ID, COVERAGE, MODEL_REVISION, VERIFIER_REVISION
from .errors import UnsupportedInput
from .zipscan import validate_path

SITE = "lib/python3.12/site-packages"


def profile_catalog():
    return {
        "schema_version": 1,
        "document_type": "profile_catalog",
        "profiles": [
            {
                "id": PROFILE_ID,
                "qualification": "enabled",
                "python": "3.12.14",
                "installer": "pip",
                "installer_version": "26.2.1",
                "adapter": "controller_pip_python_target_venv_without_pip",
                "scheme": {
                    "purelib": SITE,
                    "platlib": SITE,
                    "scripts": "bin",
                    "headers": "include/site/python3.12/{canonical_name}",
                    "data": "",
                },
                "assumptions": [
                    "case_sensitive_posix",
                    "sequential_successful_commands",
                    "known_empty_distribution_layer",
                    "protected_scaffolding",
                    "sanitized_environment",
                    "no_payload_imports",
                    "no_bytecode_compilation",
                    "no_unknown_mutation",
                ],
                "coverage": "declared_final_payload_and_provider_requirements",
                "evidence_revision": "wheelsuture-0.1.0a1-pip26.2.1-installer0.7.0",
            }
        ],
    }


def require_profile(profile):
    if profile.id != PROFILE_ID:
        raise UnsupportedInput("Unknown installer profile", code="unsupported_profile")


def _forbidden_parts(parts):
    for part in parts:
        lower = part.lower()
        if lower == "__pycache__" or lower.endswith(
            (".pth", ".egg-link", ".pyc", ".pyo", ".egg-info", ".egg")
        ):
            raise UnsupportedInput(
                "Unsupported bytecode, startup, or legacy distribution path",
                code="unsupported_layout",
            )


def validate_destination(destination, *, dist_info=None, own_metadata=False):
    parts = validate_path(destination)
    _forbidden_parts(parts)
    # These files exist independently of the modeled distribution payload layer.
    protected_files = (
        "pyvenv.cfg",
        "pip.conf",
        "bin/activate",
        "bin/activate.csh",
        "bin/activate.fish",
        "bin/Activate.ps1",
    )
    if destination == "lib64" or destination.startswith("lib64/"):
        raise UnsupportedInput(
            "Destination aliases protected lib64 scaffolding",
            code="protected_scaffolding",
        )
    for fixed in protected_files:
        if destination == fixed or destination.startswith(fixed + "/"):
            raise UnsupportedInput(
                "Destination overlaps interpreter configuration",
                code="protected_scaffolding",
            )
    for directory in (
        "bin",
        "include",
        "include/python3.12",
        "include/site",
        "include/site/python3.12",
        "lib",
        "lib/python3.12",
        SITE,
    ):
        if destination == directory:
            raise UnsupportedInput(
                "Destination is a protected scaffold directory",
                code="protected_scaffolding",
            )
    if (
        len(parts) >= 2
        and parts[0] == "bin"
        and (
            re.fullmatch(r"(?:python|pip)(?:[0-9]+(?:\.[0-9]+)?)?", parts[1])
            or parts[1] == "easy_install"
            or parts[1].startswith("easy_install-")
        )
    ):
        raise UnsupportedInput(
            "Destination overlaps protected interpreter or installer script",
            code="protected_scaffolding",
        )
    if destination.startswith(SITE + "/"):
        relative = destination[len(SITE) + 1 :]
        first = relative.split("/")[0]
        if (
            first == "pip"
            or (first.startswith("pip-") and first.endswith(".dist-info"))
            or any(
                first == s or first.startswith(s + ".")
                for s in ("sitecustomize", "usercustomize")
            )
        ):
            raise UnsupportedInput(
                "Destination overlaps protected startup namespace",
                code="protected_scaffolding",
            )
    metadata = [p for p in parts if p.lower().endswith(".dist-info")]
    if metadata:
        allowed = SITE + "/" + str(dist_info) + "/"
        if (
            len(metadata) != 1
            or not own_metadata
            or not destination.startswith(allowed)
            or metadata[0] != dist_info
        ):
            raise UnsupportedInput(
                "Destination aliases a reserved metadata namespace",
                code="reserved_metadata",
            )
    return destination


def map_member(member, *, dist_info, canonical_name):
    parts = validate_path(member)
    _forbidden_parts(parts)
    stem = dist_info[:-10]
    is_script = False
    if parts[0].endswith(".data"):
        if parts[0] != stem + ".data" or len(parts) < 3:
            raise UnsupportedInput(
                "Foreign or incomplete wheel data directory", code="unsupported_layout"
            )
        scheme = parts[1]
        rest = parts[2:]
        roots = {
            "purelib": SITE,
            "platlib": SITE,
            "scripts": "bin",
            "headers": "include/site/python3.12/" + canonical_name,
            "data": "",
        }
        if scheme not in roots:
            raise UnsupportedInput(
                "Unknown wheel data scheme", code="unsupported_layout"
            )
        if scheme == "scripts" and len(rest) != 1:
            raise UnsupportedInput(
                "Script subdirectories are unsupported", code="unsupported_layout"
            )
        root = roots[scheme]
        destination = "/".join(([root] if root else []) + rest)
        is_script = scheme == "scripts"
        own_metadata = False
    else:
        destination = SITE + "/" + member
        own_metadata = parts[0] == dist_info
    validate_destination(destination, dist_info=dist_info, own_metadata=own_metadata)
    if parts[0] == dist_info:
        rest = parts[1:]
        if rest and (
            rest[0]
            in (
                "INSTALLER",
                "REQUESTED",
                "direct_url.json",
                "RECORD.jws",
                "RECORD.p7s",
                "scripts",
            )
            or any("editable" in p.lower() for p in rest)
        ):
            raise UnsupportedInput(
                "Bundled generated or editable metadata is unsupported",
                code="unsupported_layout",
            )
    return destination, is_script
