# pytest-client-tools

Plugin for `pytest` to test RHSM client tools: `subscription-manager`,
`insights-client`, and `rhc`.

## Requirements

- dynaconf
- requests
- toml

## Installation

You can install it using `pip` from this git repository, i.e.

```bash
$ pip install git+https://github.com/RedHatInsights/pytest-client-tools@main
```

## Usage

It provides a set of fixtures for `pytest`, representing the various client tools
and some helper bits:
- `candlepin` -- a locally deployed Candlepin from sources with test data
- `external_candlepin` -- a remote Candlepin (requires a configuration pointing
  to it passed as `--test-config`)
- `any_candlepin` -- `external_candlepin` if available, otherwise `candlepin`
- `subman` -- `subscription-manager`
- `insights_client` -- `insights-client`
- `rhc` -- `rhc`

It also provides an autouse `check_avcs` fixture. When auditd and the required
audit tools are available, it checks each test's AVC window, saves one
`selinux.log` artifact when AVCs are present, and fails for unexpected denials.
AVC collection is disabled automatically when SELinux is disabled. Known exceptions are
maintained by consuming projects through the `client_tools_avc_skips` fixture.
Each fixture value is a list of `{"fields": {...}}` or `{"regex": ...}`
rules; without an override, no known AVCs are skipped. The plugin validates and
applies the rules supplied by the consuming project.

## License

Distributed under the terms of the `MIT`_ license.
