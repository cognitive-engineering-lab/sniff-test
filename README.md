# sniff-test

`sniff-test` finds effect paths inter-procedurally in Rust projects. It helps you document caller-visible effects and justify effects that are safe because of local invariants.

## Install
```sh
git clone https://github.com/cognitive-engineering-lab/sniff-test.git --branch refactor/sniff-test
cd sniff-test
cargo install --path crates/sniff-test
```

## Use

From the root of your Rust project, create the default configuration and run
the check:

```sh
cargo sniff-test init
cargo sniff-test
```

Use `-e` to select `panic`, `safety`, or `allocation`. By default, without
`-e`, panic and safety are checked; allocation is opt-in.

```sh
cargo sniff-test -e panic
cargo sniff-test -e allocation
```

Use `cargo sniff-test --sort` to put diagnostics with the greatest direct
justification impact first. Within each analyzed crate, warnings sharing a direct
effect operation or invocation and obligation are grouped by their count, then
by the number of affected report roots. Intermediate propagation calls are not
justification candidates. This changes human output ordering only.

Pass Cargo arguments after `--`:

```sh
cargo sniff-test -- --all-features
```

Run `cargo sniff-test --help` for options. See the [extended documentation](docs/README.md)
for configuration, output formats, analysis behavior, direct-driver usage, and
contributor commands.


## Effect Example
Use a `# Panics` section to document when callers may observe a panic, and a
`# Safety` section to document the requirements of a public unsafe API.
Use `# Allocations` to document a function that may allocate heap storage.


When a panic or unsafe operation is intentional, place a justification comment directly above it:

```rust
// PANIC: `denominator` was checked above and cannot be zero.
let ratio = total / denominator;

// SAFETY: `pointer` comes from a live reference and is properly aligned and non-null.
let value = unsafe { pointer.read() };
```

## Acknowledgments

See [ACKNOWLEDGMENTS.md](ACKNOWLEDGMENTS.md).

## Interactive audit

Start the local browser interface from the workspace you want to audit:

```sh
cargo sniff-test --audit gui
cargo sniff-test --audit gui -e panic -- --all-features
```

Select a finding to navigate its source, contract, and call trace. Write a
justification with **✓ Justify here** above the operation, or propagate an
obligation with **↑ Propagate to callers** at its enclosing function. These
inline prompts insert a blank template and focus the explanation; fill it in
before saving. You can also edit source directly.

Trace entries jump to the call site and show its verified file and line. In the
source editor, Cmd-click (macOS), Ctrl-click (other platforms), or F12 jumps to a
symbol's definition; **Back** returns to the previous location. Holding Cmd/Ctrl
while hovering over a resolvable identifier underlines it in green and shows a
pointer cursor. This uses
`rust-analyzer` from PATH, running in the audited workspace. Install it for that
workspace's toolchain with `rustup component add rust-analyzer` if navigation
reports that it is unavailable. Effect-source and trace navigation still work
without the language server. Definition lookup includes editor changes and
saved drafts without applying them to disk; dependency destinations remain
read-only. Source changed since analysis must be reanalyzed before its recorded
call-site positions can be trusted.

**Save draft** buffers an edit without changing source. **Review diff** shows the
changes; **Apply file & reanalyze** writes that file and runs the analyzer again.
Other files' drafts stay buffered. Existing source changes cause a conflict
instead of being overwritten. To resolve a conflict, copy your draft, discard
it, and reapply your changes against the current source.

Saved drafts survive server restarts in the Cargo target directory under
`sniff-test-audit/`. Unsaved editor changes do not. Dependency and toolchain
sources are read-only. For verified dependency sites, **Justify via override**
and **Propagate obligations via override** open a documentation editor using
the same comment templates. Saving changes the inline button to **Justified!** or
**Obligation propagated!** and hides the alternative action. Click the completed
button to edit the document or delete a new draft, restoring both actions. Applied
overrides remain editable; **Discard changes** restores their applied text.
Drafts show a source-style diff; **Apply overrides & reanalyze** writes the
annotations to an override file instead of editing dependency source. Editing an
existing override file requires confirmation; with multiple configured files,
select the destination in the review dialog. If none is configured, audit creates
`sniff-test-overrides.toml` beside the active configuration and registers it.

Guided insertion falls back to manual editing for
unsupported comment layouts, attributes, or ambiguous source positions.
A nonzero analysis exit is shown with its output; valid findings remain
available for auditing. Reanalysis checks saved source, not buffered drafts.

The server listens on loopback and prints a session URL before opening the
browser. Set `SNIFF_TEST_AUDIT_NO_OPEN=1` to open that URL yourself. Stop the server
with Ctrl-C. One server at a time can use a workspace's draft directory.

The GUI is backed by `sniff-test-audit-bridge`, a Rust library shared with future
frontends. `sniff-test-audit-gui` supplies HTTP and browser presentation. Neither
crate depends on rustc internals. `sniff-test-report` defines the shared report
envelope and frontend-neutral semantic facts. Report format 24 includes these
facts in ordinary JSON output: typed trace kinds and marker associations,
source/root/contract and annotation attachment locations, effect metadata, original UTF-8 file offsets,
and SHA-256 content hashes. Human output avoids constructing this extra source
metadata. The bridge derives supported editing actions from these facts and the
workspace boundaries; diagnostics has no audit mode or editing-action model.

To develop the frontend, install Node.js 22 or newer, then run:

```sh
cd crates/sniff-test-audit-gui/frontend
npm ci
npm run build
```

Production assets in `frontend/dist/` are checked in so a normal Cargo build or
installation needs no Node.js. Rebuild those assets after frontend edits. The
server embeds them in release builds; debug builds read them from that directory.
Run `cargo build -p sniff-test` before the real-browser integration tests:

```sh
cd crates/sniff-test-audit-gui/frontend
npx playwright install chromium
npm test
```

The browser tests create temporary Rust projects and verify applying an
obligation, reanalysis, draft recovery, and external-edit conflict handling.
