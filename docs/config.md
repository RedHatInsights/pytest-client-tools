# Configuration

pytest-client-tools uses [Dynaconf][dynaconf] for reading the configuration
for the tests. Please check its website for more details on it, including its
internals.

The configuration uses the Dynaconf environments, and `default` is the default
environment.

The `PYTEST_CLIENT_TOOLS` prefix is set for tweaking the Dynaconf configuration
using environment variables.

The format for the configuration file is [TOML][toml]; allowed file names for it
are `settings.toml`, and `.secrets.toml`.

The configuration file is optional; if not specified, pytest-client-tools
disables certain features or falls back to default values.

The supported Dynaconf versions depend on the Python version in use: on
Python 3.8 and newer, Dynaconf 3.2.13 or later (but below 4) is required,
which picks up the fix for CVE-2026-33154 (SSTI in Dynaconf's `@jinja`
resolver; the 3.2.13 release fixes both `@jinja` and `@format`
templating). On Python 3.6 and 3.7, the floor stays at the 3.1.x series
(below 3.2) — resolving to 3.1.5 on Python 3.6 and 3.1.11 on Python 3.7 —
as Dynaconf 3.2.x requires Python 3.8 or newer (and Dynaconf 3.1.7 through
3.1.11 require Python 3.7 or newer, which is why the two interpreters
resolve different versions).

Note that the configuration loading of pytest-client-tools does pass
values through Dynaconf's template resolvers: a `@jinja`-prefixed value in
a settings file or in a `PYTEST_CLIENT_TOOLS_*` variable is evaluated when
`jinja2` is installed (it is a dependency of neither this library nor
Dynaconf core). From Dynaconf 3.2.13 the `@jinja` resolver is sandboxed —
attribute access from the template is refused with a warning — while the
3.1.x series kept for Python 3.6 and 3.7 is unsandboxed and is not fixed
by any Dynaconf release: treat the settings source as trusted there, or
keep `jinja2` out of the test environment.

## Environment variables

Every configuration key can be provided through environment variables, so the
whole configuration is satisfiable from environment variables only, with the
settings files as an optional override.

The name of an environment variable is the `PYTEST_CLIENT_TOOLS` prefix,
followed by the path of the settings key with each `.` replaced by `__`
(the Dynaconf nested separator), all uppercase. For example, the
`candlepin.username` key maps to `PYTEST_CLIENT_TOOLS_CANDLEPIN__USERNAME`,
while a flat (top level) key `example` maps to
`PYTEST_CLIENT_TOOLS_EXAMPLE`.

The value of the variable is parsed as a TOML value:

- bare values that do not look like TOML values are strings;
- numbers (`8443`), booleans (`true`, `false`) and lists
  (`["key-1", "key-2"]`) are converted to their respective types;
- to force a string that looks like a number, use TOML quoting, for example
  `'"12345"'`.

Environment variables override the values from the settings files for the
Dynaconf environment selected with `ENV_FOR_DYNACONF` (a Dynaconf variable,
without the `PYTEST_CLIENT_TOOLS` prefix): the other keys of the same
section keep the values from the files of the selected environment.

An empty or whitespace-only `PYTEST_CLIENT_TOOLS_*` variable is treated as
unset: it neither overrides a value from the settings files nor fails
validation. This makes CI definitions like `VAR: ${{ vars.X }}` safe when
the referenced variable has no value configured.

### Reference

The following are the commonly used configuration keys; the naming rule
described above derives the environment variable of any other settings key
the same way:

| Settings key | Environment variable |
|---|---|
| `candlepin.host` | `PYTEST_CLIENT_TOOLS_CANDLEPIN__HOST` |
| `candlepin.port` | `PYTEST_CLIENT_TOOLS_CANDLEPIN__PORT` |
| `candlepin.prefix` | `PYTEST_CLIENT_TOOLS_CANDLEPIN__PREFIX` |
| `candlepin.insecure` | `PYTEST_CLIENT_TOOLS_CANDLEPIN__INSECURE` |
| `candlepin.username` | `PYTEST_CLIENT_TOOLS_CANDLEPIN__USERNAME` |
| `candlepin.password` | `PYTEST_CLIENT_TOOLS_CANDLEPIN__PASSWORD` |
| `candlepin.activation_keys` | `PYTEST_CLIENT_TOOLS_CANDLEPIN__ACTIVATION_KEYS` |
| `candlepin.org` | `PYTEST_CLIENT_TOOLS_CANDLEPIN__ORG` |
| `candlepin.environments` | `PYTEST_CLIENT_TOOLS_CANDLEPIN__ENVIRONMENTS` |
| `insights.legacy_upload` | `PYTEST_CLIENT_TOOLS_INSIGHTS__LEGACY_UPLOAD` |
| `insights.auto_update` | `PYTEST_CLIENT_TOOLS_INSIGHTS__AUTO_UPDATE` |
| `insights.base_url` | `PYTEST_CLIENT_TOOLS_INSIGHTS__BASE_URL` |
| `insights.ca_path` | `PYTEST_CLIENT_TOOLS_INSIGHTS__CA_PATH` |
| `insights.insecure` | `PYTEST_CLIENT_TOOLS_INSIGHTS__INSECURE` |
| `rhc.server` | `PYTEST_CLIENT_TOOLS_RHC__SERVER` |

For example, a full external Candlepin configuration without any settings
file:

```bash
$ export ENV_FOR_DYNACONF=stage
$ export PYTEST_CLIENT_TOOLS_CANDLEPIN__HOST=candlepin-stage.example.com
$ export PYTEST_CLIENT_TOOLS_CANDLEPIN__PORT=8443
$ export PYTEST_CLIENT_TOOLS_CANDLEPIN__PREFIX=/candlepin
$ export PYTEST_CLIENT_TOOLS_CANDLEPIN__USERNAME=dummy-username
$ export PYTEST_CLIENT_TOOLS_CANDLEPIN__PASSWORD=dummy-password
$ export PYTEST_CLIENT_TOOLS_CANDLEPIN__ACTIVATION_KEYS='["dummy-key-1"]'
$ export PYTEST_CLIENT_TOOLS_CANDLEPIN__ORG=dummy-org
$ export PYTEST_CLIENT_TOOLS_CANDLEPIN__ENVIRONMENTS='["dummy-env-1"]'
```

Note that `PYTEST_CLIENT_TOOLS_DISABLE_SELINUX` is read directly by the
plugin from the environment to disable the collection of the SELinux audit
denials: like any other `PYTEST_CLIENT_TOOLS_*` variable, its value is also
loaded (parsed as a TOML value) into the Dynaconf settings store, but the
plugin does not read it from there.

## Environments and merging

The settings files can define different Dynaconf environments (`default`,
`stage`, `prod`, ...); `ENV_FOR_DYNACONF` selects the one in use, and
`default` is the base of all of them.

The layers are merged with each other, from the lowest to the highest
precedence: the `[default]` environment, the selected environment, and
finally the environment variables on top of them; within the files,
`.secrets.toml` wins over `settings.toml`. A key omitted by a higher layer
keeps the value of the lower layers: for example, an environment that
overrides only `candlepin.host` keeps the credentials of `[default]`.

The merge is per key: the value of a scalar key in a higher layer replaces
the one of the lower layers. The list-valued keys
(`candlepin.activation_keys`, `candlepin.environments`) also replace the
value of the lower layers as a whole, instead of being concatenated with
it: for example, the activation keys of `[stage]` do not get mixed with the
ones of `[default]`, and an environment variable set for one of them
replaces the value from the files entirely.

## Settings keys

This is an example of the available configuration keys:

```toml
[default]
candlepin.host = "candlepin-hostname"
candlepin.port = 443
candlepin.prefix = "/candlepin-prefix"
candlepin.insecure = false
candlepin.username = "candlepin-username"
candlepin.password = "candlepin-password"
candlepin.activation_keys = ["activation-key-1", "activation-key-2"]
candlepin.org = "candlepin-organization"
candlepin.environments = ["environment-1", "environment-2"]
insights.legacy_upload = false
insights.auto_update = true
```

The various keys are grouped depending on their area; here follows the
explanation of each key, with the type of its value:

- `candlepin.host` (string)

    The hostname of the external Candlepin server.

- `candlepin.port` (number)

    The port of the external Candlepin server. Since it is a port number,
    it must be greater than 0 and less than 65536.

- `candlepin.prefix` (string)

    The prefix (starting with `/`) of the external Candlepin server.

- `candlepin.insecure` (boolean)

    This specifies whether to disable the validation of the SSL certificate
    of the external Candlepin server.

- `candlepin.username` (string)

    The username to use for registration to the external Candlepin server.

- `candlepin.password` (string)

    The password to use for registration to the external Candlepin server.

- `candlepin.activation_keys` (list of strings)

    The activation keys to use for registration to the external Candlepin
    server.

- `candlepin.org` (string)

    The organization to use for registration to the external Candlepin server.

- `candlepin.environments` (list of strings)

    The environments to use for registration to the external Candlepin server.

- `insights.legacy_upload` (boolean)

    Whether to set the `legacy_upload` configuration option for
    `insights-client` by default when a new instance of the `insights_client`
    fixture is returned. If not set, the value previous set in
    `insights-client.conf` is not changed.

- `insights.auto_update` (boolean)

    Whether to set the `auto_update` configuration option for
    `insights-client` by default when a new instance of the `insights_client`
    fixture is returned. If not set, the value previous set in
    `insights-client.conf` is not changed.

- `insights.base_url` (string)

    The base URL to use for REST API calls to the various Insights services.

- `insights.ca_path` (boolean)

    The default CA path/file to use for verifying the SSL connections to the
    Insights services. To be able to use the system CA store, this setting must
    be set to an empty string. Please note that this key is effectively used
    only if `insights.insecure` is `true`.

- `insights.insecure` (boolean)

    This specifies whether to disable the validation of the SSL certificate
    of the Insights services.

[dynaconf]: https://www.dynaconf.com/ "Dynaconf"
[toml]: https://toml.io/ "TOML"
