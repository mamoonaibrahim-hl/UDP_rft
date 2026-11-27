"""One-time helper: adds the three small hooks that extension E1 needs to rft/client.py.

    python rft\\apply_e1_hooks.py            (run from the repo root, then check with: git diff rft/client.py)

It changes text only when it finds the exact original lines, and tells you about every
edit it could not make so you can do it by hand. Safe to run twice.
"""
import sys
from pathlib import Path

path = Path(__file__).resolve().parent / "client.py"
text = path.read_text(encoding="utf-8")

EDITS = [
    ("1. class attribute and SYN option hook",
     "class Client:\n    def __init__(",
     "class Client:\n    selective = False        # E1: the SelectiveClient subclass sets this to True\n\n"
     "    def syn_options(self):\n        return b\"\"          # E1: extra bytes after the file name in the SYN\n\n"
     "    def __init__("),
    ("2. SYN carries the option bytes",
     "            len(name_bytes),\n        ) + name_bytes\n",
     "            len(name_bytes),\n        ) + name_bytes + self.syn_options()\n"),
    ("3. ACKs may carry a bitmap in selective mode",
     "            if expected_type in (P.SYN_ACK, P.ACK):\n                if packet.payload:\n                    continue\n",
     "            if expected_type == P.SYN_ACK and packet.payload:\n                continue\n\n"
     "            if expected_type == P.ACK and packet.payload and not self.selective:\n                continue\n"),
    ("4. --selective option",
     "    parser.add_argument(\"--log\", type=Path, default=None)\n",
     "    parser.add_argument(\"--log\", type=Path, default=None)\n"
     "    parser.add_argument(\n        \"--selective\",\n        action=\"store_true\",\n"
     "        help=\"selective retransmission (extension E1)\",\n    )\n"),
    ("5. choose the client class",
     "                    client = Client(\n                        sock,",
     "                    if args.selective:\n                        from rft.selective import SelectiveClient\n\n"
     "                        client_class = SelectiveClient\n                    else:\n                        client_class = Client\n\n"
     "                    client = client_class(\n                        sock,"),
]

failed = 0
for name, old, new in EDITS:
    if new in text:
        print(f"already done: {name}")
    elif old in text:
        text = text.replace(old, new, 1)
        print(f"done:         {name}")
    else:
        failed += 1
        print(f"NOT FOUND:    {name}  (client.py differs from the original; make this edit by hand)")
if failed == 0:
    path.write_text(text, encoding="utf-8")
    print("client.py updated.")
else:
    print(f"{failed} edit(s) not applied; client.py was left unchanged.")
sys.exit(1 if failed else 0)
