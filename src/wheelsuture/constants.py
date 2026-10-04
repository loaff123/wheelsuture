"""Versioned constants shared by independent implementations, not algorithms."""

PROFILE_ID = "pip-26.2.1-cpython-3.12.14-posix-venv-nocompile-v1"
MODEL_REVISION = "wheelsuture-model-v1"
VERIFIER_REVISION = "wheelsuture-independent-verifier-v1"


class _FrozenDict(dict):
    def _immutable(self, *args, **kwargs):
        raise TypeError("Fixed profile constants are immutable")

    __setitem__ = __delitem__ = clear = pop = popitem = setdefault = update = (
        __ior__
    ) = _immutable

    def __deepcopy__(self, memo):
        return self


COVERAGE = _FrozenDict(
    {
        "assertion": "declared_final_payload_and_provider_requirements",
        "included": (
            "copied_regular_payloads",
            "rewritten_script_tokens",
            "entry_point_provider_tokens",
        ),
        "excluded": (
            "generated_control_bytes",
            "bytecode",
            "permissions",
            "directory_presence",
            "import_correctness",
            "dependencies",
            "abi",
            "application_behavior",
            "live_environment",
            "concurrent_installers",
        ),
    }
)
