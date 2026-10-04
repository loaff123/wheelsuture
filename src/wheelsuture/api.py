"""Read-only analysis APIs. Wheel payloads are data, never executed."""

import hashlib
from .canonical import canonical_bytes, finalize_document
from .constants import COVERAGE
from .errors import InputChanged
from .inventory import inventory_wheel
from .model import Budget, DEFAULT_LIMITS, Document, Profile
from .plan import load_plan, rehash_sources, open_source
from .reducer import simulate
from .repair import propose_repair


def _inventory_plan(plan, budget):
    return {
        source.id: inventory_wheel(source, Profile(plan.to_dict()["profile"]), budget)
        for source in plan.sources
    }


def analyze(plan_path, *, limits=DEFAULT_LIMITS):
    plan = load_plan(plan_path, limits=limits)
    budget = Budget(limits)
    inventories = _inventory_plan(plan, budget)
    report = simulate(plan, inventories, budget=budget)
    rehash_sources(plan)
    return report


def create_repair(plan_path, *, limits=DEFAULT_LIMITS):
    plan = load_plan(plan_path, limits=limits)
    budget = Budget(limits)
    inventories = _inventory_plan(plan, budget)
    report = simulate(plan, inventories, budget=budget)
    proposal = propose_repair(plan, report, inventories, budget=Budget(limits))
    rehash_sources(plan)
    return report, proposal


def inspect_wheel(source, profile, *, limits=DEFAULT_LIMITS):
    budget = Budget(limits)
    inventory = inventory_wheel(source, profile, budget)
    d = dict(
        schema_version=1,
        document_type="wheel_inventory",
        profile=profile.id,
        coverage=COVERAGE,
        wheel=inventory.to_dict(),
        diagnostics=[],
        resource_usage=budget.usage,
        effective_limits=limits.to_dict(),
    )
    d = finalize_document(d, budget, "inventory")
    h = hashlib.sha256()
    with open_source(source) as f:
        for block in iter(lambda: f.read(65536), b""):
            h.update(block)
    if h.hexdigest() != source.sha256:
        raise InputChanged("Wheel changed during inspection.", wheel_id=source.id)
    return Document(canonical_bytes(d))
