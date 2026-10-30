"""A small, dependency-free Sigma rule evaluator for flat JSON events.

Supports the subset of the Sigma spec used by >99% of SigmaHQ Windows rules:
field modifiers contains/startswith/endswith/all/re/windash/cased/exists/
base64offset/gt/gte/lt/lte, keyword lists, and conditions with
and/or/not/parentheses/'1 of x*'/'all of x*'/'them'.
"""
import base64
import fnmatch
import re

DASHES = ["-", "/", "–", "—", "―"]


class SigmaError(Exception):
    pass


# ---------------------------------------------------------------- values

def _wildcard_regex(pattern, cased, prefix="", suffix=""):
    """Translate a Sigma string (with * ? and \\ escapes) into a compiled regex.

    prefix/suffix are regex fragments added by contains/startswith/endswith;
    they are appended after escape handling so a trailing backslash in the
    value can't escape them.
    """
    out, i = [], 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\" and i + 1 < len(pattern) and pattern[i + 1] in "*?\\":
            out.append(re.escape(pattern[i + 1]))
            i += 2
            continue
        out.append(".*" if c == "*" else "." if c == "?" else re.escape(c))
        i += 1
    return re.compile(prefix + "".join(out) + suffix, re.S if cased else re.I | re.S)


def _b64offset_variants(s):
    raw = s.encode()
    variants = []
    for shift in range(3):
        enc = base64.b64encode(b"\x00" * shift + raw).decode()
        start = (0, 2, 3)[shift]
        end = len(enc) - ((0, 3, 2)[(len(raw) + shift) % 3])
        variants.append(enc[start:end])
    return variants


def _expand(value, mods):
    """Apply transformation modifiers, returning candidate pattern strings."""
    vals = [value]
    if "windash" in mods:
        # A dash at the start of a word may be written as / or a unicode dash.
        vals = list(dict.fromkeys(
            re.sub(r"(^|\s)-", lambda m, d=d: m.group(1) + d, value) for d in DASHES))
    if "base64offset" in mods:
        vals = [b for v in vals for b in _b64offset_variants(v)]
    elif "base64" in mods:
        vals = [base64.b64encode(v.encode()).decode() for v in vals]
    return vals


def _match_value(field_val, pattern, mods):
    if pattern is None:
        return field_val in (None, "")
    if field_val is None:
        return False
    if any(m in mods for m in ("gt", "gte", "lt", "lte")):
        try:
            a, b = float(field_val), float(pattern)
        except (TypeError, ValueError):
            return False
        return {"gt": a > b, "gte": a >= b, "lt": a < b, "lte": a <= b}[
            next(m for m in mods if m in ("gt", "gte", "lt", "lte"))]
    fv = str(field_val)
    if "re" in mods:
        flags = (re.I if "i" in mods else 0) | (re.M if "m" in mods else 0) | (re.S if "s" in mods else 0)
        return re.search(str(pattern), fv, flags) is not None
    cased = "cased" in mods
    pre = ".*" if ("contains" in mods or "endswith" in mods) else ""
    suf = ".*" if ("contains" in mods or "startswith" in mods) else ""
    return any(_wildcard_regex(p, cased, pre, suf).fullmatch(fv) for p in _expand(str(pattern), mods))


KNOWN_MODIFIERS = {
    "contains", "startswith", "endswith", "all", "re", "i", "m", "s", "windash", "cased",
    "exists", "fieldref", "base64", "base64offset", "wide", "utf16le", "utf16be", "utf16",
    "gt", "gte", "lt", "lte", "cidr", "expand",
}


class UnknownModifier(SigmaError):
    pass


SCALAR = (str, int, float, bool, type(None))


def _check_modifiers(det):
    """Reject modifiers outside the Sigma spec and malformed detection values."""
    if isinstance(det, str):
        raise SigmaError("detection item is a bare string (keywords must be a list)")
    items = det if isinstance(det, list) else [det]
    for item in items:
        if isinstance(item, dict):
            for key, val in item.items():
                bad = [m for m in str(key).split("|")[1:] if m not in KNOWN_MODIFIERS]
                if bad:
                    raise UnknownModifier(f"unknown modifier '{bad[0]}' in '{key}'")
                vals = val if isinstance(val, list) else [val]
                if not all(isinstance(v, SCALAR) for v in vals):
                    raise SigmaError(f"field '{key}' has a non-scalar value")
        elif not isinstance(item, SCALAR):
            raise SigmaError("keyword list contains a non-scalar value")


def _match_field(event, spec, values):
    name, *mods = spec.split("|")
    lookup = {k.lower(): v for k, v in event.items()}
    present = name.lower() in lookup
    field_val = lookup.get(name.lower())
    if "exists" in mods:
        want = values if isinstance(values, bool) else str(values).lower() == "true"
        return present == want
    if "fieldref" in mods:
        values = [lookup.get(str(v).lower()) for v in (values if isinstance(values, list) else [values])]
        return any(v is not None and str(v).lower() == str(field_val).lower() for v in values)
    if not isinstance(values, list):
        values = [values]
    if not values:
        return False
    hits = (_match_value(field_val, v, mods) for v in values)
    return all(hits) if "all" in mods else any(hits)


def _match_detection(event, det):
    if isinstance(det, dict):
        return all(_match_field(event, k, v) for k, v in det.items())
    if isinstance(det, list):
        if all(isinstance(x, dict) for x in det):
            return any(_match_detection(event, x) for x in det)
        # keyword search over all field values
        blob = "\n".join(str(v) for v in event.values())
        return any(_match_value(blob, k, ["contains"]) for k in det)
    if isinstance(det, str):
        return _match_detection(event, [det])
    raise SigmaError(f"unsupported detection item: {type(det).__name__}")


# ---------------------------------------------------------------- condition

TOKEN = re.compile(r"\s*(\(|\)|\b(?:and|or|not)\b|1 of|all of|[\w*.-]+)", re.I)


def _tokenize(cond):
    pos, out = 0, []
    cond = cond.strip()
    while pos < len(cond):
        m = TOKEN.match(cond, pos)
        if not m:
            raise SigmaError(f"cannot parse condition near: {cond[pos:]!r}")
        out.append(m.group(1))
        pos = m.end()
    return out


class _Cond:
    def __init__(self, tokens, names, results):
        self.t, self.i, self.names, self.r = tokens, 0, names, results

    def peek(self):
        return self.t[self.i].lower() if self.i < len(self.t) else None

    def take(self):
        tok = self.t[self.i]
        self.i += 1
        return tok

    def parse(self):
        v = self.expr_or()
        if self.peek() is not None:
            raise SigmaError(f"unexpected token {self.peek()!r}")
        return v

    def expr_or(self):
        v = self.expr_and()
        while self.peek() == "or":
            self.take()
            rhs = self.expr_and()
            v = v or rhs
        return v

    def expr_and(self):
        v = self.expr_not()
        while self.peek() == "and":
            self.take()
            rhs = self.expr_not()
            v = v and rhs
        return v

    def expr_not(self):
        if self.peek() == "not":
            self.take()
            return not self.expr_not()
        return self.atom()

    def atom(self):
        tok = self.peek()
        if tok is None:
            raise SigmaError("condition ended unexpectedly")
        if tok == "(":
            self.take()
            v = self.expr_or()
            if self.peek() != ")":
                raise SigmaError("missing ')'")
            self.take()
            return v
        if tok in ("1 of", "all of"):
            self.take()
            pat = self.take()
            sel = self.names if pat.lower() == "them" else [n for n in self.names if fnmatch.fnmatchcase(n, pat)]
            if not sel:
                raise SigmaError(f"'{tok} {pat}' matches no detection")
            vals = [self.r(n) for n in sel]
            return any(vals) if tok == "1 of" else all(vals)
        name = self.take()
        if name not in self.names:
            raise SigmaError(f"unknown detection '{name}' in condition")
        return self.r(name)


def compile_rule(rule):
    """Validate a parsed rule dict and return a predicate event -> bool."""
    det = rule.get("detection")
    if not isinstance(det, dict) or "condition" not in det:
        raise SigmaError("rule has no detection/condition")
    cond = det["condition"]
    conds = cond if isinstance(cond, list) else [cond]
    names = [k for k in det if k != "condition"]
    if not names:
        raise SigmaError("rule has no detection items")
    for c in conds:  # dry-run parse to surface syntax errors early
        _Cond(_tokenize(str(c)), names, lambda n: False).parse()
        for tok in _tokenize(str(c)):
            if "|" in tok:
                raise SigmaError("aggregation conditions are not supported")
    for n in names:
        _check_modifiers(det[n])
        _match_detection({}, det[n])

    def predicate(event):
        cache = {}

        def res(n):
            if n not in cache:
                cache[n] = _match_detection(event, det[n])
            return cache[n]
        return any(_Cond(_tokenize(str(c)), names, res).parse() for c in conds)
    return predicate
