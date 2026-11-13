This fixture compares source comments with source-located `PANIC:` overrides.

- A source comment above `.first()` covers only that link; `.second()` remains
  reportable. Separate comments on both links discharge both obligations.
- A source statement marker covering both calls is ambiguous.
- Overrides prefer method/callee lines, then call/effect starts, then the
  nearest statement. Selecting `.first()` or `.second()` covers only that link.
  Selecting both method lines discharges both obligations. A method-line entry
  shadows a receiver-line entry for that call, without adding marker ambiguity.
- Both call spans in `chain` start at `widget`; selecting only that receiver
  line still covers both and is ambiguous.
- Selecting the multiline `let` header in `statement` covers its nested call;
  selecting `widget.first()` directly also works.
- `operation` checks statement fallback for compiler-generated division checks.
  `ordinary_block` verifies lookup does not ascend arbitrary blocks.

The CLI test `source_justification_overrides_resolve_method_lines_and_statements`
generates selectors from these source lines and checks each case. Related tests
check operations, block boundaries, and dependency-cache reuse when overrides
are toggled off and on.
