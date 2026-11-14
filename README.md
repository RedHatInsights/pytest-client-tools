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

## Configuration

The configuration is read with [Dynaconf][dynaconf], and it is fully
satisfiable from environment variables only: the settings files
(`settings.toml`, `.secrets.toml`) are an optional override, so no file needs
to exist. The name of an environment variable is the `PYTEST_CLIENT_TOOLS`
prefix followed by the path of the settings key with each `.` replaced by
`__`, all uppercase (for example, `candlepin.username` maps to
`PYTEST_CLIENT_TOOLS_CANDLEPIN__USERNAME`). `ENV_FOR_DYNACONF` (a Dynaconf
variable, without the prefix) selects the environment (`default`, `stage`,
`prod`, `satelliteNNN`, ...); the environment variables override the values
of the selected environment.

Environment variable values are parsed as TOML values: bare values are used
as strings unless they look like numbers, booleans or lists (for example
`true`, `8443`, `["key-1", "key-2"]`); use TOML quoting (for example
`'"12345"'`) to force a string that looks like a number.

See the [full configuration reference][config-docs] for the mapping of the
settings keys to environment variables and more details.

## License

Distributed under the terms of the [MIT](https://github.com/RedHatInsights/pytest-client-tools/blob/main/LICENSE) license.

[dynaconf]: https://www.dynaconf.com/ "Dynaconf"
[config-docs]: https://redhatinsights.github.io/pytest-client-tools/config/ "pytest-client-tools configuration reference"
