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
