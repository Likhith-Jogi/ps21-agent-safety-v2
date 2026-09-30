"""Fake tools + trajectory data model. No real accounts, email or money."""
from dataclasses import dataclass, field

# Effect class of every tool. Policies reason about effects, not just names.
TOOL_EFFECT = {
    "search_email": "read", "read_email": "read", "read_file": "read",
    "read_booking": "read", "calendar_read": "read", "search_database": "read",
    "extract_attachment": "compute", "summarize": "compute",
    "send_email": "send", "delete_file": "delete", "delete_email": "delete",
    "transfer_money": "transfer", "book_ticket": "book",
    "cancel_booking": "cancel", "get_api_key": "credential",
    "export_records": "export",
}
SIDE_EFFECT = {"send", "delete", "transfer", "book", "cancel", "export", "credential"}


@dataclass
class Step:
    tool: str
    args: dict = field(default_factory=dict)
    # Provenance of each argument: user | contact | reply_to | tool_data | injected | agent
    origin: dict = field(default_factory=dict)
    # Data classes this step's OUTPUT brings into the agent's context
    labels: frozenset = frozenset()
    n_items: int = 1
    # Ground truth for evaluation ONLY (attacker-serving side-effect step). Policies never read it.
    harmful: bool = False

    @property
    def effect(self):
        return TOOL_EFFECT[self.tool]


@dataclass
class World:
    balance: float = 5000.0
    outbox: list = field(default_factory=list)
    deleted: int = 0
    cancelled: int = 0
    booked: int = 0
    exports: int = 0
    creds_exposed: bool = False
    log: list = field(default_factory=list)


def run_tool(step: Step, world: World):
    """Fake execution: mutates the in-memory world only."""
    e, a = step.effect, step.args
    if e == "send":
        world.outbox.append(a.get("to"))
    elif e == "delete":
        world.deleted += step.n_items
    elif e == "transfer":
        world.balance -= a["amount"]
    elif e == "cancel":
        world.cancelled += step.n_items
    elif e == "book":
        world.booked += 1
    elif e == "credential":
        world.creds_exposed = True
    elif e == "export":
        world.exports += step.n_items
    world.log.append(step.tool)
