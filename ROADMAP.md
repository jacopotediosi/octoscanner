# Roadmap

## Publishing

- [x] Write README.md
    - [ ] Describe better the current rulesets and what's yet to do
- [ ] Implement Octoscanner (and rules) versioning and show versions in cli/json scan results
- [ ] Publish first release
- [ ] Consider splitting rule files into a separate project/repository

## Rules generation

### Handcrafted rules

- [x] Packaging rules, e.g. plugins still not using `pyproject.yaml`
- [x] Security rules, e.g. routes without authentication, PNotify and Knockout HTML binding XSS, etc
- [ ] Common code quality issues - TBD
- [ ] Check if all rule texts are well written or can be improved

### Automatically generated rules

- [ ] Setting paths
    - [ ] Access to deprecated setting paths (paths removed which still have a compatibility overlay)
        - [x] Python
            - [x] Access to removed global setting paths which still have a compatibility overlay (e.g. `global_get(["serial", ...])`, etc)
            - [x] Move rules from deprecation to removal when deprecated things get removed in later versions
        - [ ] JS
            - [] Access to removed global setting paths which still have a compatibility overlay
            - [ ] Move rules from deprecation to removal when deprecated things get removed in later versions
        - [ ] Access to global API Key `["api","key"]`
    - [ ] Access to removed setting paths, e.g. `["serial", ...]`
        - [ ] Python
            - [x] Access to removed global setting paths (e.g. `global_set(["serial", ...])`, etc)
            - [ ] Access to removed built-in plugins setting paths (e.g., under `global_get(["plugins"])`)
        - [ ] JS

- [ ] HTTP APIs
    - [ ] Call to deprecated HTTP APIs, e.g. `POST /api/system`
        - [ ] Python
            - [ ] Move rules from deprecation to removal when deprecated things get removed in later versions
        - [ ] JS
            - [ ] Move rules from deprecation to removal when deprecated things get removed in later versions
    - [ ] Call to removed HTTP APIs, e.g. `/api/logs/*`, `/api/users/*`, `/api/plugin/pluginmanager`
        - [ ] Python
        - [ ] JS

- [ ] Frontend changes
    - [ ] JS deprecations
        - [ ] Usage of any deprecated function (notice that there are many different ways to deprecated things in OctoPrint).
            Check to detect at least:
            - `SlicingViewModel.gcodeFilename`
            - `OctoPrintClient.access.users.update(admin=)`
            - `OctoPrintClient.printer.{issueSdCommand,getSdState,initSd,releaseSd,refreshSd}`
            - `AccessViewModel.isCurrentUser`
            - `FilesViewModel.{initSdCard,releaseSdCard,refreshSdFiles}`
            - `OctoPrintClient.plugins.appkeys.revokeKey`
            - Usage of `SettingsViewModel.users`
    - [ ] JS breaking changes
        - [ ] Diff between OctoPrint versions to generate all JavaScript removal rules. Perhaps use jsdoc and diff the longnames.
            Check to detect at least:
            - `usersViewModel` -> `accessViewModel.users`
            - `FilesViewModel.requestData(focus, switchToPath, force)` signature change
            - `FilesViewModel.fromResponse` signature change
            - `SettingsViewModel.requestData(callback)` signature change
            - `onWizardTabChange` -> `onBeforeWizardTabChange`
            - `OctoPrintClient.logs` -> `OctoPrintClient.plugins.logging`
            - `OctoPrintClient.users` -> `OctoPrintClient.access.users`
            - `OctoPrintClient.getRequestHeaders` signature change
            - `OctoPrintClient.deprecatedMethod` removed
            - `OctoPrintClient.deprecatedVariable` signature change
        - [ ] Detect usage of removed viewmodels (e.g. `usersViewModel`) (e.g., if a plugin pushes it to `OCTOPRINT_VIEWMODELS`)
    - [ ] Jinja usage of removed viewmodels or deprecated/removed viewmodel members,
            e.g. `bedlevelvisualizer_tab.jinja2` uses the removed `settingsViewModel.webcam_rotate90()`

- [x] Python changes
    - [x] Python deprecations
        - [x] Usage of any deprecated function (notice that there are many different ways to deprecated things in OctoPrint)
        - [x] Move rules from deprecation to removal when deprecated things get removed in later versions
    - [x] Python breaking changes
        - [x] Import classes/modules path changes
        - [x] Class/method/attribute renames (both private and non-private)
        - [x] Signature changes

- [ ] Generate and manually review/fix/improve all rules
- [ ] Check if all rule texts are well written or can be improved

## Advanced scanning

- [ ] Semgrep security / Snyk scan + other code quality scanners?
- [ ] Detect plugins using libraries without declaring them as dependencies
      or detect OctoPrint dependencies removed between versions
- [ ] Detect syntax errors / pycheck / linting suggestions

## GitHub Integration

- [ ] GitHub issue creation from scan results
- [ ] Markdown formatter for issue bodies
- [ ] Batch issue creation across multiple plugin repos
- [ ] Dry-run mode

## Tests

- [ ] Intensive manual testing against real plugins
- [ ] Unit tests
- [ ] Rules tests (with sample plugins)
