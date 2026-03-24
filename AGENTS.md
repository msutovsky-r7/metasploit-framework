# AI Agent Instructions for Metasploit Framework

## Project Overview
Metasploit Framework is an open-source penetration testing and exploitation framework written in Ruby. It provides infrastructure for developing, testing, and executing exploit code against remote targets.

## Project Structure
- `modules/` — Metasploit modules (exploits, auxiliary, post, payloads, encoders, evasion, nops)
- `lib/msf/` — Core framework library code
- `lib/rex/` — Rex (Ruby Exploitation) library
- `lib/metasploit/` — Metasploit namespace libraries
- `data/` — Data files used by modules (wordlists, templates, binaries)
- `spec/` — RSpec test suite
- `tools/` — Developer and operational tools
- `plugins/` — msfconsole plugins
- `scripts/` — Example automation scripts

## Coding Conventions
- Ruby (see `.ruby-version` for the current version). Minimum supported: 3.1+
- Follow the project's `.rubocop.yml` configuration — run `rubocop` on changed files before submitting
- Run `msftidy` to catch common module issues
- Add `# frozen_string_literal: true` to new files (the RuboCop cop is disabled project-wide for legacy code, but new files should include it)
- No enforced line length limit, but keep code readable
- Use `%q{}` for long multi-line strings (curly braces preferred for module descriptions)
- Multiline block comments are acceptable for embedded code snippets/payloads
- Don't use `get_`/`set_` prefixes for accessor methods in new code
- Method parameter names must be at least 2 characters (exception for well-known crypto abbreviations)

### Module Development
- Prefer writing modules in Ruby. Go and Python modules are accepted, but their external runtimes don't support the full framework API (e.g. network pivoting). Ruby modules do not have this limitation
- Before writing a new module, check that there is not an existing module or open pull request that already covers the same functionality
- Each module should be in its own file under the appropriate `modules/` subdirectory. In some scenarios adding module actions or targets is preferred.
- Exploits require a `DisclosureDate` field
- Exploits, auxiliary, and post modules require `Notes` with `SideEffects`
- Use the module mixin APIs — don't reinvent the wheel
- Use `create_process(executable, args: [], time_out: 15, opts: {})` instead of the deprecated `cmd_exec` with separate arguments
- License new code with `MSF_LICENSE` (the project default, defined in `lib/msf/core/constants.rb`)
- When overriding `cleanup`, always call `super` to ensure the parent mixin chain cleans up connections and sessions properly
- When possible don't set a default payload (`DefaultOptions` with `'PAYLOAD'`) in modules — let the framework choose the most appropriate payload automatically
- New modules require an associated markdown file in the `documentation/modules` folder with the same structure, including steps to set up the vulnerable environment for testing
- Module descriptions or documentation should list the range of vulnerable versions and the fixed version of the affected software, when known
- Implement a `check` method when possible to allow users to verify vulnerability before exploitation
- `check` methods must only return `CheckCode` values (e.g. `CheckCode::Vulnerable`, `CheckCode::Safe`) — never raise exceptions or call `fail_with`
- When writing a `check` method, verify it does not produce false positives when run against unrelated software or services
- Use `fail_with(Failure::UnexpectedReply, '...')` (and other `Failure::*` constants) to bail out of `exploit`/`run` methods — don't use `raise` or bare `return` for error conditions
- Prefer `prepend Msf::Exploit::Remote::AutoCheck` over manually calling `check` inside `exploit` — this lets the framework handle check-before-exploit automatically

### Library Code
- When adding complex binary or protocol parsing (e.g. BinData, RASN1, Rex::Struct2), include a code comment linking to the specification or RFC that defines the format being implemented
- Write RSpec tests for any library changes
- Follow [Better Specs](http://www.betterspecs.org/) conventions
- Write YARD documentation for public methods
- Keep PRs focused — small fixes are easier to review
- Any new hash cracking implementations require adding a test hash to `tools/dev/hash_cracker_validator.rb` and ensuring that passes without error

### Testing
- Tests live in `spec/` mirroring the `lib/` structure
- Run tests with: `rspec spec/path/to/spec.rb`
- Use `bundle exec rspec` to ensure correct gem versions

### Preferred Libraries
- Use the `RubySMB` library for SMB modules
- Use `Rex::Stopwatch.elapsed_time` to track elapsed time

## Common Patterns
- Register options with `register_options` and `register_advanced_options`
- Use `datastore['OPTION_NAME']` to access module options
- Use `print_status`, `print_good`, `print_error`, `print_warning` for console output
- Use `vprint_*` variants for verbose-only output
- Use `send_request_cgi` for HTTP requests in modules
- Use `connect` / `disconnect` for TCP socket operations

## Before Submitting
- Ensure `rubocop` and `msftidy` pass on any changed files with no new offenses
- Ensure `msftidy_docs` passes on any changed documentation markdown docs with no new offenses

## What NOT to Do
- Don't submit untested code — all code must be manually verified
- Don't include sensitive information (IPs, credentials, API keys, hashes of credentials) in code or docs
- Don't include more than one module per pull request
- Don't add new scripts to `scripts/` — use post modules instead
- Don't use `pack`/`unpack` with invalid directives (enforced by linter)

