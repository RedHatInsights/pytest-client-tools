# Testing

## Inventory and Advisor API base URL selection

`InsightsClient.wait_for_inventory()` and `InsightsClient.wait_for_advisor()`
build their request URLs from the same services API base URL:

- For Satellite Dynaconf environments named `satelliteNNN` (for example,
  `satellite619`) or `satellite-capsule`, they use the full `insights.base_url`
  from the active Dynaconf environment, including its proxy path prefix.
  Inventory appends `/inventory/v1/host_exists`; Advisor appends
  `/insights/v1/system/{inventory_id}`. The Satellite environment must point
  `insights.base_url` at its Satellite endpoint.
- For other environments, the `base_url` in `insights-client.conf` selects the
  cloud API host: a value containing `.stage.` uses
  `https://cert.cloud.stage.redhat.com/api`; otherwise the base is
  `https://cert.cloud.redhat.com/api`. Inventory and Advisor append their
  corresponding `/inventory/v1/...` and `/insights/v1/...` paths.

This preserves the cloud API routes for non-Satellite runs and sends Satellite
waits through the configured proxy path.

## Inventory and Advisor TLS verification

Direct Inventory and Advisor `requests` use the same TLS verify setting as the
`external_inventory` fixture:

1. Dynaconf `insights.ca_path` when set (Satellite profiles typically point at
   `/etc/rhsm/ca/katello-server-ca.pem`)
2. Otherwise `not insights.insecure` (system CA store when insecure is false)
3. As a last resort inside `InsightsClient`, `cert_verify` from
   `insights-client.conf`, then `True`

Callers can also read the resolved value via
`InsightsClient.get_services_api_verify()`.

`wait_for_inventory()` skips (does not fail) on TLS verification errors, and
on HTTP 400 only for Satellite profiles (`ENV_FOR_DYNACONF` matching
`satelliteNNN` / `satellite-capsule`), where `host_exists` is not implemented.
A cloud HTTP 400 is still a failure (bad `insights_id` or API contract).
Transient 404s still retry until timeout.

## Per-test artifact bundle

Each test collects its artifacts in its own directory under `artifacts/`,
laid out as `artifacts/<module>[/<class>]/<test>/`. The bundle is
self-contained, so files that are identical across tests (the
insights-client configuration, the environment metadata, the AVC excerpt)
are still archived per test. It contains:

- `test.log`: the log of the test run, if the test logged anything
- `environment.txt`: metadata about the environment (see below), for
  every test
- `selinux.log`: the AVC excerpt of the test window (see
  "SELinux AVC monitoring" below), for every test when AVC monitoring is
  enabled
- `yggdrasil-journal.log`: the last lines of the yggdrasil service journal,
  for failed tests
- for tests using the `insights_client` fixture additionally:
    - the insights-client configuration and its log rotations
    - the registration markers and the machine-id (see
      "Registration state around insights-client tests" below)
    - `insights-client-status.txt`: the output of
      `insights-client --status`, captured at test end

The bundle is written to `artifacts/` relative to the directory pytest
runs in. On Testing Farm, the insights-client system test
(`systemtest/tests/integration/test.sh`) copies it to `$TMT_PLAN_DATA`,
so it is exported with the results of the request; on Jenkins it stays
as `artifacts/` in the job workspace. No secrets are captured: the
process environment (which carries, among the rest, the Vault
credentials) is never logged nor archived.

## Environment metadata

Every test archives an `environment.txt` file describing the environment
the test ran in, as `key: value` lines — the environment is shared by
the whole session, and the file is archived per test to keep each bundle
self-contained:

- `compose`: the build identifier of the OS, from `BUILD_ID` or
  `VERSION_ID` in `/etc/os-release`; `unknown` when neither is present
  (`PRETTY_NAME` is deliberately not used: it is identical across
  nightly composes of the same version, so it is not a compose
  identifier)
- `arch`: the architecture of the machine
- `fips`: whether FIPS mode is enabled or disabled, from
  `/proc/sys/crypto/fips_enabled`
- `ENV_FOR_DYNACONF`: the Dynaconf environment in use, possibly empty
- `test branch`: the branch of the test project, taken from the
  `GIT_BRANCH`, `BRANCH`, `CHANGE_BRANCH` or `GITHUB_HEAD_REF`
  environment variable, or from the git branch of the test sources
  (`$TMT_TREE` when set); `unknown` for a detached checkout or sources
  without a git checkout
- `test commit`: the short commit hash of the test sources, which is
  what makes a run reproducible; `unknown` for sources without a git
  checkout
- `insights-client`, `insights-core`, `selinux-policy`: the installed
  versions of the rpm packages relevant for the tests (`not installed`
  when absent, `unknown` when rpm is not available)

## SELinux AVC monitoring

The autouse `check_avcs` fixture monitors AVCs in a per-test window and
fails the test on any AVC not in the skip list. The whole monitoring path
lives in `pytest_client_tools.selinux` (single audit-tool helper, audit
flush, and `SELinuxAVCChecker.finish()` to close the window and collect
the AVCs).

When monitoring is enabled, every test archives a `selinux.log` artifact
with the `aureport` AVC excerpt for its window, including the
`<no events of interest were found>` placeholder on clean runs.

Monitoring requires SELinux enabled, auditd running, and the audit tools
available. Disable it with `PYTEST_CLIENT_TOOLS_DISABLE_SELINUX`. Known
AVCs can be excluded via rules in the `client_tools_avc_skips` fixture,
each a mapping with exactly one of `fields` (entry fields to match) or
`regex` (matched against the interpreted audit text).

## Registration state around insights-client tests

The registration markers of insights-client (`.registered` and
`.unregistered` in `/etc/insights-client/`) and the machine-id are backed
up before each test using the `insights_client` fixture, and the
pre-test state is restored exactly when the test finishes — files that
already existed are put back, files created during the test are removed.
They are archived when the test ends, before the fixture teardown
unregisters the system, so the bundle reflects the registration state the
test itself ended with rather than the unregistered state the teardown
leaves. The output of `insights-client --status` is archived alongside
them, as `insights-client-status.txt`, captured at the same time.
