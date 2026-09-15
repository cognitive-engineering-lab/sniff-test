# Transitive safety obligations

This fixture mirrors `dependency_transitive_panic` with a raw pointer
dereference as the underlying effect and `# Safety` contracts on the wrappers.
The wrappers are deliberately safe functions so their documented obligations
exercise comment-effect propagation independently of unsafe-call obligations.
The app passes pointers to live, initialized local bytes.

Expected findings:

| App root | Leaf contract | Justification | Expected warnings |
| --- | --- | --- | --- |
| `undocumented_leaf` | None | None | One, for the call to middle |
| `documented_leaf` | `# Safety` | None | One, for the call to middle |
| `justified_leaf` | `# Safety` | In middle | One, for the call to middle |
| `justified_app` | `# Safety` | In app | None |

Middle's contract discharges both the raw effect from an undocumented leaf
and the documented obligation from a documented leaf. Its own contract still
requires justification at the app call. Neither the raw dereference nor the
leaf contract should produce an additional finding in the app.
