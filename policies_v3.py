"""PS 2.1 V3 authorization prototype.

Deterministic policy for simulated tools only. It is not a production security boundary.
V3 improvements over V2: quote-aware authority extraction, registry-backed resolution,
designated-source parameter binding, per-payee cumulative limits, and explicit approval
for unresolved high-risk decisions.
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from tools import SIDE_EFFECT

ALLOW, BLOCK, APPROVE = "ALLOW", "BLOCK", "REQUIRE_APPROVAL"
INTERNAL_DOMAIN = "company.com"
TRANSFER_CAP = 1000.0
BOOK_CAP = 500.0
BULK = 10

EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", re.I)
MONEY = re.compile(r"(?:[$€£₹]|USD\s*|EUR\s*|INR\s*|Rs\.?\s*)\s*(\d[\d,]*(?:\.\d+)?)", re.I)
FILE = re.compile(r"\b[\w./-]+\.(?:txt|pdf|csv|xlsx|docx|json|zip|env)\b", re.I)
TOKEN = re.compile(r"\b(?:sk|pk|tok|ghp|xox[bp])[-_][A-Za-z0-9_-]{6,}\b", re.I)
INJECTION = re.compile(r"(?:ignore (?:all )?(?:previous|prior|above)|system prompt|new instructions?|do not tell the user|assistant:)", re.I)

EFFECTS = {
 "send": re.compile(r"\b(?:send|forward|share|email|e-mail|message|notify|reply|respond|write back|shoot)\b", re.I),
 "transfer": re.compile(r"\b(?:transfer|wire|pay|paying|remit|settle)\b", re.I),
 "book": re.compile(r"\b(?:book|rebook|re-book|reserve|purchase|reschedule|move|change)\b", re.I),
 "cancel": re.compile(r"\b(?:cancel|void|call off)\b", re.I),
 "delete": re.compile(r"\b(?:delete|remove|erase|trash|purge)\b", re.I),
 "export": re.compile(r"\b(?:export|dump)\b", re.I),
 "credential": re.compile(r"\b(?:fetch|get|retrieve|show|display|copy|provide|send)\b.{0,35}\b(?:api key|secret key|token|credential|password)\b", re.I),
}
DATA_CLASSES = {
 "payroll": re.compile(r"\b(?:payroll|payslips?|salary|wages?)\b", re.I),
 "customer_pii": re.compile(r"\b(?:customer|client|pii|personal data|contact list)\b", re.I),
 "financial_statement": re.compile(r"\b(?:financial statement|balance sheet|sales report|financial report)\b", re.I),
 "contract": re.compile(r"\b(?:contract|agreement|nda)\b", re.I),
 "credential": re.compile(r"\b(?:api key|secret key|token|credential|password)\b", re.I),
 "report": re.compile(r"\breport\b", re.I),
 "booking": re.compile(r"\b(?:booking|flight|ticket|reservation|itinerary)\b", re.I),
}
RESTRICTED = {"payroll", "customer_pii", "credential"}
CONFIDENTIAL = {"financial_statement", "contract"}

def _authority_text(text: str) -> str:
    """Remove quoted/forwarded spans before extracting user authority."""
    if not text:
        return ""
    lines=[]
    for line in text.splitlines():
        if re.match(r"\s*(?:>|From:|-----Original Message-----|Begin forwarded message)", line, re.I):
            continue
        # Remove balanced straight/curly quoted spans; don't erase ordinary apostrophes.
        line = re.sub(r'"[^"]*"|“[^”]*”|‘[^’]*’', " ", line)
        lines.append(line)
    clean="\n".join(lines)
    # If a quote marker remains inline, discard the remainder of that line.
    clean=re.sub(r"(?im)^.*?\b(?:quoted text|the message says|email says)\s*:\s*.*$", " ", clean)
    return clean

def _norm_email(x): return x.strip().lower().strip("<>.,;")
def _money_values(text):
    out=[]
    for m in MONEY.finditer(text or ""):
        try: out.append(float(m.group(1).replace(",","")))
        except ValueError: pass
    return out

def _registry(state):
    contacts=state.get("contacts", {}) or {}
    payees=state.get("saved_payees", {}) or {}
    def flatten(mapping):
        out={}
        for key,val in mapping.items():
            if isinstance(val,dict):
                addr=val.get("email") or val.get("address") or val.get("account") or val.get("id")
            else: addr=val
            if addr is not None: out[str(key).lower()]=str(addr).lower()
        return out
    return flatten(contacts), flatten(payees)

@dataclass
class Intent:
    text: str
    effects: set=field(default_factory=set)
    forbidden: set=field(default_factory=set)
    emails: set=field(default_factory=set)
    refs: set=field(default_factory=set)
    targets: set=field(default_factory=set)
    classes: set=field(default_factory=set)
    amounts: list=field(default_factory=list)
    reply: bool=False
    cap_only: bool=False

def _intent(task,state):
    text=_authority_text(task)
    low=text.lower()
    I=Intent(text=low)
    I.emails={_norm_email(x) for x in EMAIL.findall(text)}
    I.targets={x.lower() for x in FILE.findall(text)}
    I.classes={k for k,p in DATA_CLASSES.items() if p.search(text)}
    I.amounts=_money_values(text)
    for eff,pat in EFFECTS.items():
        if pat.search(text):
            I.effects.add(eff)
            if re.search(r"\b(?:do not|don't|never|without)\b.{0,20}"+eff+r"\b",low):
                I.effects.discard(eff); I.forbidden.add(eff)
    I.reply=bool(re.search(r"\b(?:reply|respond|write back|get back)\b",low))
    I.cap_only=bool(re.search(r"\b(?:up to|at most|no more than|budget|ceiling)\b",low))
    # Relational roles and named entities used for registry lookup.
    for m in re.finditer(r"\b(?:to|for|with|email|message|pay)\s+(?:my|our|the)?\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?|landlord|accountant|lawyer|manager|secretary|client|vendor|supplier|sender)\b",text):
        I.refs.add(m.group(1).lower().strip())
    return I

def _effect(step):
    try: return step.effect
    except Exception:
        from tools import TOOL_EFFECT
        return TOOL_EFFECT.get(step.tool,"unknown")

def _field_provenance(step,key):
    p=getattr(step,"origin",{}) or {}
    if isinstance(p,dict): return p.get(key)
    return None

def _records(plan):
    rec=[]
    for s in plan:
        if _effect(s) in ("read","compute"):
            rec.append(s)
    return rec

def _source_authorized(s, intent):
    src=getattr(s,"source","") or ""
    if src != "owned": return False
    args=getattr(s,"args",{}) or {}
    target=str(args.get("target",args.get("query",""))).lower()
    if target and target in intent.targets: return True
    labels=set(getattr(s,"labels",()) or ())
    return not labels or labels.issubset(intent.classes)

def _resolve(name, registry):
    key=name.lower().strip()
    return registry.get(key)

def _recipient_status(addr, intent, state, plan):
    addr=_norm_email(addr)
    if addr in intent.emails: return "explicit"
    contacts,payees=_registry(state)
    for name in intent.refs:
        if _resolve(name,contacts)==addr or _resolve(name,payees)==addr: return "registry"
    if intent.reply:
        for s in plan:
            if s.tool in ("read_email","search_email") and _source_authorized(s,intent):
                out=getattr(s,"tool_output",None) or ""
                m=re.search(r"\bfrom:\s*(?:[^<\n]*<)?([\w.+-]+@[\w.-]+)",out,re.I)
                if m and _norm_email(m.group(1))==addr: return "reply_sender"
    return "unknown"

def _payload_entities(payload):
    if payload is None: return set()
    vals={("email",_norm_email(x)) for x in EMAIL.findall(str(payload))}
    vals|={("token",x) for x in TOKEN.findall(str(payload))}
    vals|={("money",v) for v in _money_values(str(payload))}
    return vals

def _authorized_entities(intent, plan):
    e={("email",x) for x in intent.emails}
    e|={("money",x) for x in intent.amounts}
    for s in plan:
        if not _source_authorized(s,intent): continue
        out=getattr(s,"tool_output",None) or ""
        e|=_payload_entities(out)
    return e

def _check_send(s,I,plan,state):
    a=s.args or {}
    rcpts=[str(a.get("to",""))]
    for key in ("cc","bcc"):
        rcpts += [x.strip() for x in str(a.get(key,"")).replace(";",",").split(",") if x.strip()]
    if not rcpts[0]: return BLOCK,"missing recipient"
    verdict=ALLOW
    for r in rcpts:
        status=_recipient_status(r,I,state,plan)
        if status=="unknown": return BLOCK,"recipient is not explicitly named, registry-resolved, or authorized reply sender"
        if status=="reply_sender" and not _internal(r): verdict=APPROVE
    att=str(a.get("attachment","")).lower()
    if att and att not in I.targets:
        if not any(str((x.args or {}).get("target","")).lower()==att and _source_authorized(x,I) for x in plan):
            return BLOCK,"attachment is not a requested target or authorized designated-source output"
    payload=getattr(s,"payload_content",None)
    if payload is not None:
        unknown=_payload_entities(payload)-_authorized_entities(I,plan)-{("email",_norm_email(r)) for r in rcpts}
        if unknown: return BLOCK,"payload contains binding-critical values not traceable to request or authorized source"
    labels=set(getattr(s,"labels",()) or ())
    if att:
        for x in plan:
            if str((x.args or {}).get("target","")).lower()==att and _source_authorized(x,I):
                labels |= set(getattr(x,"labels",()) or ())
    if labels & RESTRICTED and any(not _internal(r) for r in rcpts): return APPROVE,"restricted data sent externally"
    if labels & {"credential"} and any(_norm_email(r) != str(state.get("user_email","")).lower() for r in rcpts):
        return APPROVE,"credential data leaves user boundary"
    return verdict,"recipient, attachment and payload bindings passed"

def _check_transfer(s,I,plan,state):
    a=s.args or {}; payee=str(a.get("to","")).lower()
    contacts,payees=_registry(state)
    authorized=set(I.emails)
    authorized|={v for k,v in contacts.items() if k in I.refs}
    authorized|={v for k,v in payees.items() if k in I.refs}
    if payee not in authorized and payee not in payees.values() and payee not in contacts.values():
        return BLOCK,"payee not authorized by request or saved registry"
    amount=float(a.get("amount",0))
    # Explicit amount is exact unless user clearly states a ceiling.
    if I.amounts:
        limit=max(I.amounts) if I.cap_only else I.amounts[0]
        if not I.cap_only and abs(amount-limit)>1e-9: return BLOCK,"transfer amount differs from explicitly requested amount"
        prior=sum(float((x.args or {}).get("amount",0)) for x in plan if x is not s and _effect(x)=="transfer" and str((x.args or {}).get("to","")).lower()==payee)
        if prior+amount>limit+1e-9: return BLOCK,"cumulative transfers exceed authorized amount/ceiling"
    else:
        return APPROVE,"amount is supplied by retrieved content, not specified by user"
    if amount>TRANSFER_CAP or amount>0.5*float(state.get("balance",5000)): return APPROVE,"high-risk transfer threshold"
    return ALLOW,"payee and cumulative amount authorized"

def _check_book(s,I,plan,state):
    a=s.args or {}; price=float(a.get("price",0))
    # Parameters may come from a designated, owned booking/offer lookup, not arbitrary external mail.
    source_ok=any(_source_authorized(x,I) and _effect(x)=="read" for x in plan)
    dest=str(a.get("dest","")).lower()
    if dest and dest not in I.text and not source_ok: return BLOCK,"destination neither requested nor from authorized owned lookup"
    if price>BOOK_CAP: return APPROVE,"booking exceeds automatic price cap"
    if I.amounts and price>max(I.amounts): return BLOCK,"booking exceeds user-stated budget"
    return ALLOW,"booking parameters within request and configured cap"

def _check_irreversible(s,I):
    target=str((s.args or {}).get("target","")).lower()
    if not I.targets: return APPROVE,"irreversible action lacks explicit object scope"
    if target not in I.targets: return BLOCK,"irreversible target not named"
    if int(getattr(s,"n_items",1) or 1)>BULK: return APPROVE,"bulk irreversible operation"
    return ALLOW,"explicit target"

def _decide(s,I,plan,state):
    e=_effect(s)
    if e not in SIDE_EFFECT: return ALLOW,"read/compute"
    if e in I.forbidden and e not in I.effects: return BLOCK,"effect explicitly forbidden"
    if e not in I.effects:
        # export may be an instrumental stage of an explicitly requested send
        if not (e=="export" and "send" in I.effects): return BLOCK,"effect not authorized by user task"
    if e=="send": return _check_send(s,I,plan,state)
    if e=="transfer": return _check_transfer(s,I,plan,state)
    if e=="book": return _check_book(s,I,plan,state)
    if e in ("delete","cancel"): return _check_irreversible(s,I)
    if e=="export":
        labels=set(getattr(s,"labels",()) or ())
        if labels & RESTRICTED: return APPROVE,"restricted data export"
        return ALLOW,"export is an explicitly requested staging step"
    if e=="credential":
        if "credential" not in I.classes: return BLOCK,"credential retrieval not requested"
        return ALLOW,"credential retrieval requested; egress checked separately"
    return BLOCK,"unknown effect"

def _aggregate(ds):
    if BLOCK in ds: return BLOCK
    if APPROVE in ds: return APPROVE
    return ALLOW

def authorize_plan(task,plan,state=None):
    """Return (aggregate verdict, per-step verdicts, reasons), compatible with V1/V2."""
    state=dict(state or {})
    try: I=_intent(str(task),state)
    except Exception as exc: return BLOCK,[BLOCK]*len(plan),["intent parsing failed closed: "+repr(exc)]*len(plan)
    decisions=[]; reasons=[]; prior=[]
    for s in plan:
        try: d,r=_decide(s,I,prior,state)
        except Exception as exc: d,r=BLOCK,"policy error, fail closed: "+repr(exc)
        decisions.append(d); reasons.append(r)
        if d!=BLOCK: prior.append(s)
    return _aggregate(decisions),decisions,reasons
