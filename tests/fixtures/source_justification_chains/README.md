This fixture compares source comments with source-located `PANIC:` overrides.

- A source comment above `.first()` covers only that link; `.second()` remains
  reportable. Separate comments on both links discharge both obligations.
- A source statement marker covering both calls is ambiguous.
- Overrides select call/effect source-range **starts**, without statement
  fallback or callee-segment lookup. Both calls in `chain` start at `widget`;
  selecting that receiver line covers both and is ambiguous. Selecting either
  method line currently covers neither.
- Selecting the multiline `let` header in `statement` does not cover the nested
  call. Selecting the `widget.first()` line does.

The CLI test `source_justification_overrides_select_call_starts_in_method_chains`
generates selectors from these source lines and checks each case.
