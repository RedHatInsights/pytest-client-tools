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

## License

Distributed under the terms of the `MIT`_ license.
