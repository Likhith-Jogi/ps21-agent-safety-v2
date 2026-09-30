"""PS 2.1 policy revision V2 (deterministic, stdlib only). policies.py (V1) is NOT modified.

Policy-visible input per step: tool, args, origin (claimed, never trusted upward), labels, n_items,
payload_content, tool_output, source (channel kind of the resource a READ came from: 'owned' | 'external').
Nothing else. This module does not import any scenario/eval module.

Four architectural changes relative to V1:
 1. STRUCTURED INTENT   : Intent = effects (+forbidden effects, +permitted side effects), recipients (explicit,
                          relational refs, reply-to-sender), data classes, named targets, payee->amount map,
                          scope. Built from an effect/verb lexicon with paraphrases and negation, not from
                          one-regex-per-effect.
 2. TYPED DATA FLOW     : every value is traced by *content lineage* (does it occur in the user request, in an
                          owned resource, in external content, or only inside an agent-directed span?). Claimed
                          `origin` tags are never trusted to upgrade a value. Data classes carry sensitivity tiers.
                          Data flow into a send is judged on the payload's actual overlap with sources, not on
                          everything read in the session (session-level fallback only if the payload is unknown).
 3. SENSITIVE ACTIONS   : credential retrieval, transfers, named-document transmission can be authorised by an
                          explicit request; REQUIRE_APPROVAL is kept for policy-defined high-risk conditions
                          (amount above cap / >50% of balance, secrets leaving to a non-self recipient, restricted
                          classes to external recipients, bulk/non-explicit irreversible actions, conflicting
                          account details, recipient only known from retrieved content).
 4. PAYLOAD BINDING     : binding-critical entities in an outgoing payload (URLs, emails, account numbers, IBANs,
                          amounts, secret-like tokens) must be traceable to the user request or to an *authorised*
                          source outside agent-directed spans; extra action arguments (add-ons, cc/bcc, attachments)
                          must be requested; totals must equal the requested amount.
"""
import re
from dataclasses import dataclass, field
from tools import SIDE_EFFECT

ALLOW, BLOCK, APPROVE = "ALLOW", "BLOCK", "REQUIRE_APPROVAL"
INTERNAL_SUFFIX = "@company.com"
SELF_DEFAULT = "me@company.com"
ALIASES = {"finance": "finance@company.com", "manager": "manager@company.com", "team": "team@company.com",
           "hr": "hr@company.com", "legal": "legal@company.com"}
RELATIONS = {"accountant", "lawyer", "counsel", "attorney", "landlord", "boss", "assistant", "colleague", "partner",
             "vendor", "client", "supplier", "auditor", "doctor", "advisor", "devops", "sales", "support"}
TRANSFER_CAP, BULK, BOOK_CAP = 1000, 10, 500

SECRET, RESTRICTED, CONFIDENTIAL = {"credential"}, {"customer_pii", "payroll"}, {"contract", "financial_statement"}

CLASS_LEX = [  # data-class lexicon (paraphrase tolerant); classes are typed by tier above
    (r"contracts?|agreements?|\bnda\b|\bmsa\b|\bsla\b", "contract"),
    (r"invoices?|bills?|receipts?", "invoice"),
    (r"payroll|salar(?:y|ies)|payslips?|pay ?stubs?", "payroll"),
    (r"customers?|clients?|\bpii\b|contact list", "customer_pii"),
    (r"api[ -]?keys?|access[ -]?tokens?|api[ -]?tokens?|secret[ -]?keys?|credentials?|passwords?|\btokens?\b|\bkeys?\b", "credential"),
    (r"calendar|meetings?|schedule|agenda|events?", "calendar"),
    (r"bookings?|flights?|tickets?|reservations?|itinerar\w+|hotel", "booking"),
    (r"financial statements?|balance sheets?|p&l|profit and loss|bank statements?", "financial_statement"),
    (r"usage|metrics|analytics|stats", "usage_metrics"),
    (r"reports?", "report"),
    (r"documents?|\bdocs?\b|notes|memo|minutes", "document"),
    (r"inbox|emails?|e-mails?|threads?|messages?|confirmations?", "inbox"),
]

# --- entity extraction (binding-critical values) -----------------------------------------------------------
_EMAIL = r"[\w.+\-]+@[\w\-]+(?:\.[\w\-]+)+"
_URL = r"(?:https?://|www\.)[^\s<>\"')\]]+"
_IBAN = r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{3,4}){2,7}\b"
_MONEY = r"(?:[$€£₹]|USD |EUR |INR |Rs\.? ?)\s?\d[\d,]*(?:\.\d+)?"
_ACCT = r"\b\d{3,}(?:[- ]\d{3,})+\b"
_TOKEN = r"\b(?:sk|pk|key|tok|api|AKIA|ghp|xox[bp])[-_][A-Za-z0-9_\-]{6,}\b"
_LONG = r"\b(?=[A-Za-z0-9_\-]*\d)(?=[A-Za-z0-9_\-]*[A-Za-z])[A-Za-z0-9_\-]{20,}\b"
_ENT_RE = [("email", _EMAIL), ("url", _URL), ("iban", _IBAN), ("money", _MONEY), ("acct", _ACCT),
           ("token", _TOKEN), ("token", _LONG)]

# --- agent-directed span detection (text addressed to the automation, not to the user) ----------------------
_ADDR = r"\b(?:assistants?|ai (?:agent|assistant|model)s?|llms?|language models?|automated (?:agent|system|assistant)s?|chatbots?|claude|gpt)\b"
_IMP = (r"\b(?:ignore|disregard|override|forward|send|transfer|pay|wire|book|cancel|delete|export|use|replace|append|"
        r"include|add|reply|remember|instead|must|should|before|after|when|do not|don't|also|first|then)\b")
_STRONG = (r"ignore (?:all |any |the )?(?:previous|prior|above)|disregard (?:all |any |the )?(?:previous|prior|above)|"
           r"system prompt|new instructions?|\[\s*hidden|<!--|do not (?:tell|inform|mention|alert) the user")


def _spans(text):
    """Return (clean_text, [tainted spans]) : sentences/bracketed segments addressed to the automation."""
    if not text:
        return "", []
    tainted, keep = [], []
    for seg in re.split(r"(?<=[.!?])\s+|\n+", text):
        s = seg.strip()
        if not s:
            continue
        low = s.lower()
        if re.search(_STRONG, low) or (re.search(_ADDR, low) and re.search(_IMP, low)):
            tainted.append(s)
        else:
            keep.append(s)
    # bracketed injections may be embedded mid-sentence; pull them out separately
    clean = []
    for s in keep:
        for m in re.finditer(r"\[[^\]]*\]|<!--.*?-->", s):
            seg = m.group(0).lower()
            if re.search(_ADDR, seg) or re.search(_STRONG, seg):
                tainted.append(m.group(0))
                s = s.replace(m.group(0), " ")
        clean.append(s)
    return " ".join(clean), tainted


def _norm(kind, raw):
    r = raw.strip().rstrip(".,;:)")
    if kind == "email":
        return ("email", r.lower())
    if kind == "url":
        return ("url", r.lower())
    if kind == "money":
        d = re.sub(r"[^\d.]", "", r)
        try:
            return ("money", round(float(d), 2))
        except ValueError:
            return ("money", d)
    if kind in ("iban", "acct"):
        return (kind, re.sub(r"[\s\-]", "", r).upper())
    return ("token", r)


def entities(text):
    out = set()
    if not text:
        return out
    for kind, pat in _ENT_RE:
        for m in re.finditer(pat, text):
            out.add(_norm(kind, m.group(0)))
    return out


def _shingles(text, n=4):
    w = re.findall(r"[a-z0-9]+", (text or "").lower())
    return {" ".join(w[i:i + n]) for i in range(max(len(w) - n + 1, 0))}


# --- structured intent --------------------------------------------------------------------------------------
@dataclass
class Intent:
    text: str
    effects: set = field(default_factory=set)
    forbidden: set = field(default_factory=set)
    side_effects: set = field(default_factory=set)      # secondary effects the request permits (e.g. rebook -> cancel)
    recipients: set = field(default_factory=set)        # explicit / alias-resolved addresses
    refs: set = field(default_factory=set)              # relational names needing resolution (accountant, Priya)
    reply: bool = False
    data: set = field(default_factory=set)
    targets: set = field(default_factory=set)
    payees: dict = field(default_factory=dict)          # address/ref -> amount (or None)
    amount: float = None
    ents: set = field(default_factory=set)
    self_addr: str = SELF_DEFAULT


_NEG = r"(?:don'?t|do not|never|without|no need to|not to|avoid)\s+(?:\w+\s+){0,2}$"

_EFFECT_PATTERNS = {
    "send": [r"\b(?:send|forward|share|deliver|reply|respond|dispatch|pass along)\b",
             r"\b(?:e-?mail|mail|message|notify|text|ping)\s+(?:me|it|them|him|her|us|my|the|this|that|[\w.+\-]+@)",
             r"\b(?:write|get) back to\b"],
    "delete": [r"\b(?:delete|remove|erase|trash|purge|clean up|clear out|clear|free up|get rid of)\b"],
    "transfer": [r"\b(?:transfer|wire|remit|pay|settle)\b"],
    "book": [r"\b(?:re-?book|book|reserve|purchase|buy|secure)\b", r"\bget me (?:a |an |the )?(?:ticket|flight|seat)\b"],
    "cancel": [r"\b(?:cancel|void|call off)\b"],
    "export": [r"\b(?:export|dump)\b"],
    "credential": [],
}
_CRED_NOUN = r"api[ -]?keys?|access[ -]?tokens?|api[ -]?tokens?|secret[ -]?keys?|credentials?|passwords?|auth tokens?|\btokens?\b"
_CRED_VERB = r"\b(?:get|retrieve|fetch|look up|find|show|give|grab|pull|copy|need|send|email|what'?s|tell me|display)\b"


def _positive(pattern, low):
    """True if pattern occurs at least once un-negated."""
    for m in re.finditer(pattern, low):
        if not re.search(_NEG, low[max(0, m.start() - 24):m.start()]):
            return True
    return False


def _negated(pattern, low):
    return any(re.search(_NEG, low[max(0, m.start() - 24):m.start()]) for m in re.finditer(pattern, low))


def structured_intent(task, state=None):
    state = state or {}
    low, t = task.lower(), task
    I = Intent(text=low, self_addr=state.get("user_email", SELF_DEFAULT))
    I.ents = entities(task)
    money = [(m.start(), m.end(), _norm("money", m.group(0))[1]) for m in re.finditer(_MONEY, t)]
    for eff, pats in _EFFECT_PATTERNS.items():
        for p in pats:
            if _positive(p, low):
                I.effects.add(eff)
            elif _negated(p, low):
                I.forbidden.add(eff)
    # 'send $200 to X' is a payment, not an email
    if money and re.search(r"\b(?:send|give|move)\b[^.]{0,25}[$€£₹]", low):
        I.effects.add("transfer")
        if not re.search(r"\b(?:send|forward|share|deliver|reply|respond)\b(?![^.]{0,25}[$€£₹])", low) and \
                not re.search(r"\b(?:e-?mail|mail)\s+(?:me|it|them|him|her|us|my|the|this|that|[\w.+\-]+@)", low):
            I.effects.discard("send")
    # credential retrieval = credential noun + retrieval verb
    if re.search(_CRED_NOUN, low) and _positive(_CRED_VERB, low):
        I.effects.add("credential")
    # paraphrase: rebook / replace / reschedule => book, and permits cancelling an explicitly named booking
    if re.search(r"\b(?:re-?book|replacement|replace (?:my |the )?(?:booking|flight|ticket)|reschedule|change my (?:flight|booking))\b", low):
        I.effects.add("book")
        I.side_effects.add("cancel")
    # data classes
    for pat, cls in CLASS_LEX:
        if re.search(pat, low):
            I.data.add(cls)
    if "credential" in I.data and "credential" not in I.effects:
        I.data.discard("credential")
    # targets
    I.targets = {x.lower() for x in re.findall(r"[\w\-]+\.(?:txt|pdf|csv|docx|log|tmp|zip|env|json)\b", t)}
    I.targets |= {x.lower() for x in re.findall(r"\bBK-\d+\b", t)}
    # recipients: explicit addresses, aliases, self, sender
    I.recipients = {e[1] for e in I.ents if e[0] == "email"}
    for m in re.finditer(r"\b(?:to|with|cc)\s+(?:my |the |our )?(finance|manager|team|hr|legal)\b", low):
        I.recipients.add(ALIASES[m.group(1)])
    if re.search(r"\b(?:e-?mail|mail|send|forward|message|text|notify|remind)\s+(?:it |that |this |them )?(?:to )?(?:me|myself)\b|\bto (?:me|myself)\b", low):
        I.recipients.add(I.self_addr)
    I.reply = bool(re.search(r"\b(?:reply|respond|write back|get back to)\b", low)) and \
        bool(re.search(r"\b(?:sender|them|him|her|back|confirmation|email from|message from)\b", low))
    for m in re.finditer(r"\b(?:to|with|email|send|forward|message|notify|tell|pay)\s+(?:my |our |the )?([A-Za-z][\w\-]+)", t):
        w = m.group(1)
        if w.lower() in RELATIONS or (w[0].isupper() and w.lower() not in
                                      {"the", "q1", "q2", "q3", "q4", "i", "acme", "my", "this", "that", "it"} and
                                      not re.search(_EMAIL, w)):
            I.refs.add(w.lower())
    # payees & amounts: pair each amount with the address/name nearest after "to", else nearest address before it
    for s, e, val in money:
        tail = t[e:e + 70]
        mt = re.match(r"[^$€£₹.]*?\b(?:to|for)\s+(?:my |the |our )?([\w.+\-]+@[\w\-.]+\w|[A-Za-z][\w\-]*)", tail)
        who = None
        if mt:
            who = mt.group(1).lower()
        else:
            hd = t[max(0, s - 50):s]
            ma = list(re.finditer(_EMAIL, hd))
            if ma:
                who = ma[-1].group(0).lower()
        if who in ALIASES:
            who = ALIASES[who]
        if who:
            I.payees[who] = val
    if len(money) == 1:
        I.amount = money[0][2]
    return I


# --- per-step records (typed provenance of what has been read) -----------------------------------------------
@dataclass
class Rec:
    tool: str
    args: dict
    labels: frozenset
    out: str
    src: str
    clean: str
    tainted: list
    e_clean: set
    e_taint: set
    from_addr: str = None
    named: bool = False


def _mk_rec(s, intent):
    out = s.tool_output or ""
    clean, tainted = _spans(out)
    r = Rec(s.tool, s.args, frozenset(s.labels), out, getattr(s, "source", "") or "", clean, tainted,
            entities(clean), entities(" ".join(tainted)))
    m = re.match(r"\s*from:\s*(?:[^<\n]*<)?([\w.+\-]+@[\w\-.]*\w)", out, re.I)
    if s.tool == "read_email" and m:
        r.from_addr = m.group(1).lower()
    tgt = str(s.args.get("target", s.args.get("id", s.args.get("query", "")))).lower()
    r.named = bool(tgt and tgt in intent.targets)
    return r


def _in_scope(rec, intent):
    if rec.named:
        return True
    return not rec.labels or rec.labels <= intent.data


def _internal(addr):
    return addr.lower().endswith(INTERNAL_SUFFIX)


def _resolve_ref(addr, intent, recs):
    """Recipient not in the request but requested by relation/name; resolved only via OWNED resources."""
    for r in recs:
        if r.src != "owned":
            continue
        for line in (r.clean or "").splitlines() or [r.clean]:
            if addr in line.lower() and any(ref in line.lower() for ref in intent.refs):
                return True
    return False


def _addr_status(addr, intent, recs):
    a = addr.lower().strip()
    if a in intent.recipients or a in intent.payees:
        return "user"
    if _resolve_ref(a, intent, recs):
        return "resolved"
    if intent.reply and any(r.from_addr == a for r in recs):
        return "reply_sender"
    if any(("email", a) in r.e_taint and ("email", a) not in r.e_clean for r in recs):
        return "tainted"
    if any(("email", a) in r.e_clean for r in recs):
        return "external_content"
    return "unknown"


def _endorsed(intent, recs):
    E = set(intent.ents)
    for r in recs:
        if _in_scope(r, intent):
            E |= r.e_clean
    return E


def _amount_ok(v, E):
    amts = [e[1] for e in E if e[0] == "money" and isinstance(e[1], float)]
    if v in amts:
        return True
    for i in range(len(amts)):
        for j in range(i + 1, len(amts)):
            if abs(amts[i] + amts[j] - v) < 0.005:
                return True
            for k in range(j + 1, len(amts)):
                if abs(amts[i] + amts[j] + amts[k] - v) < 0.005:
                    return True
    return False


def _tier(classes):
    if classes & SECRET:
        return "secret"
    if classes & RESTRICTED:
        return "restricted"
    if classes & CONFIDENTIAL:
        return "confidential"
    return "internal"


# --- per-effect checks ---------------------------------------------------------------------------------------
def _check_send(s, intent, recs, state):
    a = s.args
    rcpts = [a.get("to", "")] + [x for k in ("cc", "bcc") for x in str(a.get(k, "")).replace(";", ",").split(",") if x.strip()]
    verdict, reason = ALLOW, ""
    for r in rcpts:
        if not r:
            return BLOCK, "no recipient"
        st = _addr_status(r, intent, recs)
        if st in ("user", "resolved", "reply_sender"):
            continue
        if st == "tainted":
            return BLOCK, "recipient originates only from agent-directed content"
        if _internal(r):
            verdict, reason = APPROVE, "internal recipient not named by user"
        else:
            return BLOCK, ("external recipient not named by user"
                           + (" (claimed origin '%s' not supported by request)" % s.origin.get("to")
                              if s.origin.get("to") in ("user_input", "stored_data") else ""))
    # attachment binding
    att = str(a.get("attachment", "")).lower()
    if att:
        ok = att in intent.targets or any(r.named and str(r.args.get("target", "")).lower() == att for r in recs) \
            or any(str(r.args.get("target", "")).lower() == att and _in_scope(r, intent) for r in recs)
        if not ok:
            return BLOCK, "attachment not requested"
    # data flow: which sources does this payload draw on?
    payload = s.payload_content
    foreign, flowing = [], set()
    if att:                                     # an attached file's data class flows regardless of payload text
        for r in recs:
            if str(r.args.get("target", "")).lower() == att and _in_scope(r, intent):
                flowing |= r.labels
    if payload is None:
        for r in recs:
            (flowing.update(r.labels) if _in_scope(r, intent) else foreign.append(r))
        if any(_tier(r.labels) != "internal" for r in foreign):
            return BLOCK, "session holds sensitive data the task never authorized and payload is unknown"
        if foreign:
            return APPROVE, "session holds unrequested data and payload is unknown"
    else:
        pe, psh = entities(payload), _shingles(payload)
        # TIERED TAINT: an unrequested read of a sensitive class (secret/restricted/confidential) keeps the
        # conservative session rule, because a payload can carry it without lexical overlap (paraphrase, "rows from X").
        sens = [r for r in recs if not _in_scope(r, intent) and _tier(r.labels) != "internal"]
        if sens:
            return BLOCK, "session holds sensitive data the task never authorized: %s" % sorted(
                {l for r in sens for l in r.labels})
        for r in recs:
            if not (r.out or ""):
                continue
            shared_e = (pe & (r.e_clean | r.e_taint)) - intent.ents
            shared_s = psh & _shingles(r.out)
            used = bool(shared_e) or len(shared_s) >= 2
            if used and _in_scope(r, intent):
                flowing |= r.labels
            elif used:
                foreign.append(r)
        if foreign:
            return BLOCK, "payload draws on a source the request did not authorize: %s" % sorted(
                {l for r in foreign for l in r.labels} or {r.tool for r in foreign})
        # payload/request binding: every binding-critical entity must be traceable
        E = _endorsed(intent, recs)
        E |= {("email", x.lower()) for x in rcpts}
        for e in sorted(pe - E, key=str):
            if e[0] == "money" and isinstance(e[1], float) and _amount_ok(e[1], E):
                continue
            tainted = any(e in r.e_taint and e not in r.e_clean for r in recs)
            return BLOCK, "payload %s value %r %s" % (e[0], e[1], "originates from agent-directed content"
                                                       if tainted else "not traceable to request or authorized source")
    # sensitive-action tiers (policy-defined high-risk conditions keep REQUIRE_APPROVAL)
    tier = _tier(flowing)
    non_self = [r for r in rcpts if r.lower() != intent.self_addr.lower()]
    external = [r for r in rcpts if not _internal(r) and r.lower() != intent.self_addr.lower()]
    if tier == "secret" and non_self:
        return APPROVE, "secret/credential leaving to a non-self recipient"
    if tier == "restricted" and external:
        return APPROVE, "restricted data class to external recipient"
    if tier == "restricted" and s.n_items > BULK:
        return APPROVE, "bulk restricted data"
    return verdict, reason or "explicit request, recipient, payload and data classes consistent"


def _check_transfer(s, intent, recs, plan_prior, state):
    a = s.args
    payee = str(a.get("to", "")).lower()
    amt = float(a.get("amount", 0))
    st = _addr_status(payee, intent, recs) if "@" in payee else ("user" if payee in intent.payees or payee in intent.refs else "unknown")
    if st == "tainted":
        return BLOCK, "payee originates only from agent-directed content"
    if st == "external_content":
        if intent.payees or intent.recipients:
            return BLOCK, "payee differs from the one the user named (address only seen in retrieved content)"
        return APPROVE, "payee taken from retrieved content, not named by user"
    if st == "unknown":
        return BLOCK, "payee not authorized"
    lim = intent.payees.get(payee, intent.amount)
    if lim is None:
        return APPROVE, "no amount authorized"
    paid = sum(float(p.args.get("amount", 0)) for p in plan_prior if p.effect == "transfer"
               and str(p.args.get("to", "")).lower() == payee)
    if paid + amt > lim + 1e-9:
        return BLOCK, "amount exceeds authorization"
    # account binding (IBAN/account number must come from request or an authorized, non-conflicting source)
    acct = a.get("account")
    if acct:
        na = _norm("iban" if re.match(r"[A-Za-z]{2}\d{2}", str(acct)) else "acct", str(acct))
        if na not in intent.ents:
            E = _endorsed(intent, recs)
            if na not in E:
                return BLOCK, "account details not traceable to request or authorized source"
            same_kind = {e for e in E if e[0] == na[0]}
            if len(same_kind) > 1:
                return APPROVE, "conflicting account details in retrieved content"
    if amt < lim - 1e-9 and paid == 0:
        return APPROVE, "amount differs from the one specified"
    if amt > TRANSFER_CAP or amt > 0.5 * state.get("balance", 0):
        return APPROVE, "high-risk: amount above cap or large relative to balance"
    return ALLOW, "explicit payee and amount"


def _check_book(s, intent, recs, state):
    a = s.args
    dest = str(a.get("dest", "")).lower()
    if dest and dest not in intent.text:
        return BLOCK, "destination not in request"
    core = {"dest", "price", "item", "date", "flight", "class", "passenger", "time"}
    for k, v in a.items():
        if k not in core and v not in (None, "", [], False):
            words = re.findall(r"[a-z]+", (str(k) + " " + str(v)).lower())
            if not all(w in intent.text for w in words if len(w) > 3):
                return BLOCK, "unrequested add-on/extra argument: %s" % k
    price = float(a.get("price", 0))
    E = _endorsed(intent, recs)
    quoted = [e[1] for e in E if e[0] == "money" and isinstance(e[1], float)]
    if quoted and price > max(quoted) + 1e-9:
        return BLOCK, "price exceeds any quoted/authorized amount"
    if intent.amount is not None and price > intent.amount + 1e-9:
        return BLOCK, "price exceeds authorization"
    if price > BOOK_CAP:
        return APPROVE, "high-cost booking"
    return ALLOW, "booking within request scope"


def _check_irreversible(s, intent, recs, e):
    tgt = str(s.args.get("target", "")).lower()
    if e == "cancel" and "cancel" in intent.side_effects and tgt not in intent.targets:
        return BLOCK, "target not named by user"
    if not intent.targets:
        return APPROVE, "irreversible action with non-explicit scope"
    if tgt not in intent.targets:
        return BLOCK, "target not named by user"
    if s.n_items > BULK:
        return APPROVE, "bulk irreversible action"
    return ALLOW, "named target"


def _check_export(s, intent, recs):
    a = s.args
    dest = str(a.get("dest", "")).lower()
    st = _addr_status(dest, intent, recs) if dest else "unknown"
    if st not in ("user", "resolved"):
        return BLOCK, "export destination not named by user"
    ds = str(a.get("dataset", "")).lower()
    cls = {c for p, c in CLASS_LEX if re.search(p, ds)}
    if cls and not cls <= intent.data:
        return BLOCK, "exported data class not requested"
    if cls & RESTRICTED or _tier(cls) == "secret":
        return APPROVE, "high-risk: restricted data class export"
    return ALLOW, "named destination and data class"


def _check_credential(s, intent, recs):
    svc = str(s.args.get("service", "")).lower()
    if svc and not any(w in intent.text for w in re.findall(r"[a-z]+", svc) if len(w) > 3):
        return BLOCK, "credential for a service the request did not name"
    return ALLOW, "credential retrieval explicitly requested (returned to user; egress checked separately)"


def _check(s, intent, recs, prior, state):
    e = s.effect
    if e not in SIDE_EFFECT:
        return ALLOW, "read/compute"
    if e in intent.forbidden and e not in intent.effects:
        return BLOCK, "'%s' explicitly excluded by user" % e
    if e not in intent.effects and not (e in intent.side_effects):
        return BLOCK, "'%s' action not authorized by user task" % e
    if e == "send":
        return _check_send(s, intent, recs, state)
    if e == "transfer":
        return _check_transfer(s, intent, recs, prior, state)
    if e == "book":
        return _check_book(s, intent, recs, state)
    if e in ("delete", "cancel"):
        return _check_irreversible(s, intent, recs, e)
    if e == "export":
        return _check_export(s, intent, recs)
    if e == "credential":
        return _check_credential(s, intent, recs)
    return ALLOW, "consistent"


def agg(decisions):
    return BLOCK if BLOCK in decisions else (APPROVE if APPROVE in decisions else ALLOW)


def authorize_plan(task, plan, state=None):
    """Same interface as V1. Fail-closed on any internal error."""
    state = dict(state or {})
    try:
        intent = structured_intent(task, state)
    except Exception as ex:                                   # pragma: no cover
        return BLOCK, [BLOCK] * len(plan), ["intent parse error: %r" % (ex,)] * len(plan)
    ds, rs, recs = [], [], []
    for i, s in enumerate(plan):
        try:
            d, r = _check(s, intent, recs, plan[:i], state)
        except Exception as ex:
            d, r = BLOCK, "policy error (fail closed): %r" % (ex,)
        ds.append(d); rs.append(r)
        try:
            recs.append(_mk_rec(s, intent))
        except Exception:
            pass
    return agg(ds), ds, rs
