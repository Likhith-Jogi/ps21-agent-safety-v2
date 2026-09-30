"""Authorization policies.

  baseline            : no policy (see run_experiment)
  tool_policy_step    : static per-tool allow/block list
  hitl_step           : simple human-in-the-loop, ask on every side-effecting tool
  authorize_plan      : contextual TRAJECTORY authorization (our approach)
"""
import re
from dataclasses import dataclass
from tools import SIDE_EFFECT

ALLOW, BLOCK, APPROVE = "ALLOW", "BLOCK", "REQUIRE_APPROVAL"
INTERNAL = "@company.com"
CONTACTS = {"finance": "finance@company.com", "manager": "manager@company.com",
            "team": "team@company.com", "me": "me@company.com", "myself": "me@company.com"}
LEXICON = [(r"invoice", "invoice"), (r"meeting|schedule|calendar", "calendar"),
           (r"booking|flight|ticket", "booking"), (r"customer", "customer_pii"),
           (r"report", "report"), (r"document|notes", "document"),
           (r"inbox|unread emails|latest email|confirmation email", "inbox")]
TRANSFER_CAP, BULK, BOOK_CAP = 1000, 10, 500


def agg(decisions):
    return BLOCK if BLOCK in decisions else (APPROVE if APPROVE in decisions else ALLOW)


# ---------------- Baseline B: tool-level allow/block ----------------
# A plausible "naive" policy: block the obviously destructive/financial tools, allow the rest.
TOOL_BLOCK = {"delete_file", "delete_email", "transfer_money"}

def tool_policy_step(step):
    return BLOCK if step.tool in TOOL_BLOCK else ALLOW


# ---------------- Simple HITL: ask a human on every side-effecting action ----------------
def hitl_step(step):
    return APPROVE if step.effect in SIDE_EFFECT else ALLOW


# ---------------- Our approach: contextual trajectory authorization ----------------
@dataclass
class Intent:
    effects: set        # which effect classes the user's task authorizes
    recipients: set     # destinations the user named (or resolved contacts)
    data: set           # data classes the user's task covers
    targets: set        # explicitly named files / booking ids
    amount: float       # explicit amount, if any
    reply: bool


def derive_intent(task):
    """Rule-based stand-in for a trusted intent parser (production: LLM over the USER message only,
    never over tool output)."""
    t = task.lower()
    eff = {"read", "compute"}
    if re.search(r"\b(email|send|forward)\b[^.]*\bto\b", t) or "reply" in t: eff.add("send")
    if re.search(r"\b(delete|remove|clean up|clear|free up)\b", t): eff.add("delete")
    if re.search(r"\b(transfer|pay|wire)\b", t): eff.add("transfer")
    if re.search(r"\bbook\b", t): eff.add("book")
    if re.search(r"\bcancel\b", t): eff.add("cancel")
    if re.search(r"\bexport\b", t): eff.add("export")
    recips = set(re.findall(r"[\w.\-]+@[\w.\-]+\.\w+", task))
    recips |= {CONTACTS[m] for m in re.findall(r"\bto (?:my |the )?(finance|manager|team|me|myself)\b", t)}
    data = {label for pat, label in LEXICON if re.search(pat, t)}
    targets = set(re.findall(r"[\w\-]+\.(?:txt|pdf|csv|docx|log|tmp|zip)\b", task)) | set(re.findall(r"\bBK-\d+\b", task))
    m = re.search(r"\$\s?([\d,]+(?:\.\d+)?)", task)
    return Intent(eff, recips, data, targets, float(m.group(1).replace(",", "")) if m else None, "reply" in t)


def _check(s, intent, seen, state):
    """Decide one step given: intent, provenance, session data already in context, state, risk."""
    # PROVENANCE: nothing derived from instructions inside retrieved content may drive any action.
    if "injected" in s.origin.values():
        return BLOCK, "argument originates from untrusted content"
    e = s.effect
    if e not in SIDE_EFFECT:
        return ALLOW, "read/compute"
    # INTENT: the effect class must be authorized by the user's task.
    if e not in intent.effects:
        return BLOCK, f"'{e}' action not authorized by user task"
    a = s.args
    if e == "send":
        to, o = a["to"], s.origin.get("to", "agent")
        # DESTINATION
        if not (to in intent.recipients or (o == "reply_to" and intent.reply)):
            if to.endswith(INTERNAL):
                return APPROVE, "internal recipient not named by user"
            return BLOCK, "external recipient not named by user"
        # DATA FLOW / SEQUENCE: everything the agent has read this session counts (conservative taint).
        leaked = seen - intent.data - {"public"}
        if leaked:
            return BLOCK, f"session context holds data the task never authorized: {sorted(leaked)}"
    elif e == "transfer":
        if a["to"] not in intent.recipients:
            if s.origin.get("to") == "tool_data":
                return APPROVE, "payee taken from retrieved data, not named by user"
            return BLOCK, "payee not authorized"
        if intent.amount is None:
            return APPROVE, "no amount authorized"
        if a["amount"] > intent.amount:
            return BLOCK, "amount exceeds authorization"
        if a["amount"] > TRANSFER_CAP or a["amount"] > 0.5 * state.get("balance", 0):   # STATE + RISK
            return APPROVE, "large relative to cap/balance"
    elif e in ("delete", "cancel"):                                                     # REVERSIBILITY
        if not intent.targets:
            return APPROVE, "irreversible action with non-explicit scope"
        if a["target"] not in intent.targets:
            return BLOCK, "target not named by user"
        if s.n_items > BULK:
            return APPROVE, "bulk irreversible action"
    elif e == "book" and a.get("price", 0) > BOOK_CAP:
        return APPROVE, "high-cost booking"
    return ALLOW, "intent, provenance, destination, scope consistent"


def authorize_plan(task, plan, state=None):
    """Evaluate the WHOLE proposed trajectory before any step executes."""
    state = state or {}
    intent = derive_intent(task)
    seen, ds, rs = set(), [], []
    for s in plan:
        d, r = _check(s, intent, seen, state)
        ds.append(d); rs.append(r)
        seen |= s.labels
    return agg(ds), ds, rs
