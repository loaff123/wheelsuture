"""WheelSuture: offline declared wheel-transition rehearsal, never an installer.

Lazy public exports keep independent verification free of production algorithms.
"""

from importlib import import_module

__version__ = "0.1.0a1"
__all__ = (
    "Limits",
    "DEFAULT_LIMITS",
    "Budget",
    "Plan",
    "WheelSource",
    "Profile",
    "WheelInventory",
    "AnalysisReport",
    "RepairProposal",
    "InvalidInput",
    "UnsupportedInput",
    "LimitExceeded",
    "InputChanged",
    "OutputError",
    "VerificationError",
    "load_plan",
    "inventory_wheel",
    "simulate",
    "propose_repair",
    "analyze",
    "create_repair",
    "inspect_wheel",
    "verify_report",
)


def __getattr__(name):
    for module, names in (
        (
            "model",
            (
                "Limits",
                "DEFAULT_LIMITS",
                "Budget",
                "Plan",
                "WheelSource",
                "Profile",
                "WheelInventory",
                "AnalysisReport",
                "RepairProposal",
            ),
        ),
        (
            "errors",
            (
                "InvalidInput",
                "UnsupportedInput",
                "LimitExceeded",
                "InputChanged",
                "OutputError",
                "VerificationError",
            ),
        ),
        ("plan", ("load_plan",)),
        ("inventory", ("inventory_wheel",)),
        ("reducer", ("simulate",)),
        ("repair", ("propose_repair",)),
        ("api", ("analyze", "create_repair", "inspect_wheel")),
        ("verify", ("verify_report",)),
    ):
        if name in names:
            return getattr(import_module("." + module, __name__), name)
    raise AttributeError(name)
