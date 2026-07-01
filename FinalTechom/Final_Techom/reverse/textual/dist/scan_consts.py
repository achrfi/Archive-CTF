import os, marshal, types, re, glob

def walk_consts(co):
    yield co
    for c in co.co_consts:
        if isinstance(c, types.CodeType):
            yield from walk_consts(c)

hits = []
for path in glob.glob("dumped_codes/*.pyc"):
    data = open(path, "rb").read()
    co = marshal.loads(data[16:])
    for sub in walk_consts(co):
        for c in sub.co_consts:
            if isinstance(c, (str, bytes)):
                s = c if isinstance(c, str) else c.decode("latin1", "ignore")
                if re.search(r"(pin|flag|ctf|secret|admin|pass|encrypt|rsa)", s, re.I):
                    hits.append((path, sub.co_name, s[:200]))

for h in hits[:200]:
    print("\n==", h[0], "::", h[1], "==\n", h[2])
