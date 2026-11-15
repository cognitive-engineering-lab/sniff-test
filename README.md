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

Drag the dividers beside the findings and details panels to resize them. Focus
a divider and use the arrow keys for smaller adjustments, or Home/End for the
minimum/maximum size. On narrower windows, drag the details divider vertically.

Trace entries jump to the call site and show its verified file and line. In the
source editor, Cmd-click (macOS), Ctrl-click (other platforms), or F12 jumps to a
symbol's definition; **Back** returns to the previous location. Holding Cmd/Ctrl
while hovering over a resolvable identifier underlines it in green and shows a
pointer cursor. This uses
`rust-analyzer` from PATH, running in the audited workspace. Install it for that
workspace's toolchain with `rustup component add rust-analyzer` if navigation
reports that it is unavailable. Effect-source and trace navigation still work
without the language server. Definition lookup includes live editor changes;
dependency destinations remain read-only. Source changed since analysis must be reanalyzed before its recorded
call-site positions can be trusted. Inline documentation prompts stay available
while findings are outdated: autosave tracks unchanged attachment sites as text
moves. Editing an attachment itself requires reanalysis to verify that site.

Workspace Rust edits **autosave after one second without typing**. Navigation,
editor focus loss, Cmd/Ctrl+S, and **Reanalyze** flush pending changes immediately.
The editor shows Unsaved changes, Saving, Saved, or Save failed. Autosaving keeps
your cursor, selection, and undo history intact; undo and redo also autosave.

Reanalysis is manual. It waits for pending saves and pauses source editing while
running. If saving fails, your text stays in the editor. **Retry** retries saving;
for an external-file conflict, **Copy edits** before choosing **Reload file**.
External changes are never automatically overwritten. Closing the page with
unsaved changes prompts before leaving.

There is no draft/review/apply step. Old `drafts.json` data is ignored. Saved
override metadata lives under `sniff-test-audit/saved-overrides.json` in the Cargo
target directory; source text is saved only to its Rust file.

Dependency and toolchain sources are read-only. For verified dependency sites, **Justify via override**
and **Propagate obligations via override** open a documentation editor using
the same comment templates. **Save** writes directly to the override file and
changes the inline button to **Justified!** or **Obligation propagated!**. Click
that button to edit the saved documentation. With multiple configured override
files, choose the destination in the documentation popup; edits default to the
file containing the override. Existing files need no additional confirmation.

When a new override file is needed, a filename popup opens with
`sniff-test-overrides.toml` prefilled. Enter a filename and click **Create & save**
to create it beside the active configuration and register it. Cancel returns to
the documentation editor without losing your text. Saving never edits dependency
source or starts analysis. You can save more overrides, then click **Reanalyze**
to refresh findings. Saved overrides remain editable after restarting the server.
Old draft state is not restored or migrated.

Guided insertion falls back to manual editing for
unsupported comment layouts, attributes, or ambiguous source positions.
A nonzero analysis exit is shown with its output; valid findings remain
available for auditing. Reanalysis checks the saved source after autosaves finish.

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

Install Node.js 22 or newer, with `node` and `npm` on `PATH`, before building.
Cargo automatically installs the locked frontend dependencies and builds the GUI:

```sh
cargo build
# Or install the CLI with its embedded GUI:
cargo install --path crates/sniff-test
```

The GUI build script runs `npm ci --include=dev` and `npm run build` inside Cargo's
output directory. It rebuilds when frontend inputs change and reinstalls npm
dependencies only when the package manifests change or dependencies are missing.
The first build needs access to the npm registry. Both debug and release binaries
embed the assets, so the installed CLI needs no Node.js or frontend files at runtime.
Run `cargo build -p sniff-test` before the real-browser integration tests:

```sh
cd crates/sniff-test-audit-gui/frontend
npx playwright install chromium
npm test
```

The browser tests create temporary Rust projects and verify applying an
autosaving, reanalysis, override persistence, and external-edit conflict handling.
