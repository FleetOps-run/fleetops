# Audit forwarding

Enterprise. FleetOps sends every audit log entry, as it is written, to your SIEM or log platform, and can keep the audit log for up to 10 years instead of Community's 90 days. Set both up in **Admin → Audit forwarding**.

## Sinks

A sink is somewhere audit entries go. Up to 10 sinks can run side by side, each at its own pace.

| Kind | Sends | Use it for |
|---|---|---|
| Syslog | One RFC 5424 message per entry over UDP, TCP or TLS. TCP and TLS use octet-counting framing (RFC 6587). | rsyslog, syslog-ng, Microsoft Sentinel (through the Azure Monitor Agent's syslog collector), QRadar, Graylog |
| Splunk HEC | Batches to Splunk's HTTP Event Collector, sourcetype `fleetops:audit` | Splunk Enterprise and Splunk Cloud |
| HTTPS (JSON) | Batches as a JSON array, with headers you choose | Datadog, Elastic (ingest pipeline or Logstash `http` input), Vector, Fluent Bit, your own service |

URLs, tokens and header values are stored encrypted and never shown again (many collectors put a token in the URL); the page shows only the host. Leave a field blank when editing to keep the stored value; a pasted CA certificate is kept the same way. Put credentials in a header or token, not in the URL: `https://user:password@…` is refused. **Send test** sends one sample entry (action `audit.sink.test`) without adding it to the audit log.

When you add a sink, choose where it starts: **New entries only** (the default), or **Every entry still kept**, which sends the whole audit log first.

### What an entry looks like

Every kind carries the same JSON the API returns from `GET /api/v1/audit`, plus `"source": "fleetops"`:

```json
{"id": 4182, "ts": 1795800000, "user_id": 3, "username": "dana", "environment_id": 2,
 "action": "container.restart", "target_type": "container", "target_id": "web",
 "result": "success", "detail": null, "source": "fleetops"}
```

A syslog message is `<PRI>1 TIMESTAMP fleetops fleetops - ACTION - JSON`. The facility is local0; the severity is notice for success and warning otherwise.

### Recipes

**Splunk.** Create an HTTP Event Collector token (Settings → Data inputs → HTTP Event Collector), then add a Splunk HEC sink with `https://<splunk>:8088/services/collector/event` and the token.

**Datadog.** Add an HTTPS (JSON) sink with `https://http-intake.logs.datadoghq.com/api/v2/logs` (use your site's intake host) and a header `DD-API-KEY` set to an API key.

**Elastic / Logstash.** Point an HTTPS (JSON) sink at a Logstash `http` input with `codec => json`, or at an ingest endpoint behind a proxy that adds `Authorization`.

**rsyslog over TLS.** Listen with `imtcp` and `StreamDriver.Mode="1"` on port 6514, then add a Syslog sink with transport TLS. If your receiver's certificate comes from a private CA, paste the CA's PEM.

**Microsoft Sentinel.** Send syslog (TCP) to a Linux machine running the Azure Monitor Agent with a syslog data collection rule for facility local0.

## Delivery

- **In order, at least once.** Each sink remembers the last entry its receiver accepted and moves on only after the next batch is accepted (a 2xx answer for HEC and HTTPS; written and flushed for TCP and TLS). Batches hold up to 500 entries. UDP is fire-and-forget.
- **Retries.** A failing sink shows the error (host only, never a URL path or secret) and is retried after 10 seconds, then 20, 40 and so on, up to every 5 minutes. When it recovers it sends everything it missed, oldest first.
- **Oversized entries.** An entry whose JSON would pass 8 KB for syslog, or 64 KB for Splunk HEC and HTTPS, is sent with its `detail` replaced by `{"truncated": true, "bytes": N}`, so one huge entry can't block a sink. The full entry stays in the audit log.
- **Stuck sinks.** If a receiver keeps refusing an entry, **Skip to now** on that sink moves it past everything not yet sent. The skipped entries count as a gap and stay in the audit log; the skip is itself audited (`audit.sink.skip`).
- **Status.** The sinks table shows "Up to date", how many entries a sink is behind, when it last sent, or its error.
- **Gaps.** If a receiver is down longer than retention keeps entries, the oldest unsent ones are deleted before they can go. The sink then says how many were lost and carries on. Raise retention, or fix the receiver sooner, to avoid this.
- Changes to sinks and retention are themselves audited (`audit.sink.create`, `audit.sink.update`, `audit.sink.delete`, `audit.retention.update`), so a new sink's first entry is usually its own creation.

## Retention

The Retention panel sets how many days of audit entries FleetOps keeps: 1 to 3650. The default is 90, which is also what Community keeps. Entries older than that are deleted once an hour.

## Without a license

When the license expires or is removed, nothing is sent and every sink keeps its place; once a license is back, each sink sends what it missed. Sinks stay listed and can be deleted, but not added or changed. The retention setting keeps its value; only changing it needs a license.
