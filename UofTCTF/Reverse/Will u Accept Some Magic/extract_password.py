import re
from pathlib import Path


def main() -> None:
    wat = Path("program.wat").read_text(encoding="utf-8", errors="replace")

    # vtable globals for ProcessorA..ProcessorDD:
    # ProcessorA is global 134, then ProcessorB..ProcessorDD are globals 184..212.
    order_vtables = [134] + list(range(184, 213))

    # Extract: global index -> "get" function index
    vtable_pat = re.compile(
        r"\(global \(;(?P<g>\d+);\) \(ref 27\) ref\.null none "
        r"ref\.func 55 ref\.func (?P<get>\d+) ref\.func \d+ ref\.func \d+ ref\.func \d+ struct\.new 27\)"
    )
    vtable_get = {int(m.group("g")): int(m.group("get")) for m in vtable_pat.finditer(wat)}

    # Extract: function index -> constant returned (the expected character codepoint)
    func_pat = re.compile(
        r"\(func \(;(?P<f>\d+);\) \(type 9\) \(param \(ref null 5\)\) \(result i32\)\s*\n"
        r"\s*i32\.const (?P<c>-?\d+)\s*\n\s*\)"
    )
    func_const = {int(m.group("f")): int(m.group("c")) for m in func_pat.finditer(wat)}

    password = "".join(chr(func_const[vtable_get[g]]) for g in order_vtables)
    print(password)


if __name__ == "__main__":
    main()

