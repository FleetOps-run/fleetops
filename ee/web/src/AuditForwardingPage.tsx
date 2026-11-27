import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Clock, Plus, Send, Trash2, Waypoints, X } from "lucide-react";
import { toast } from "sonner";
import type { SinkBody, SinkKind, SinkView, SyslogTransport } from "@/api/gen/types.gen";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { Page } from "@/components/Page";
import { Panel } from "@/components/Panel";
import { StateBadge } from "@/components/StateBadge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect } from "@/components/ui/native-select";
import { Textarea } from "@/components/ui/textarea";
import { useFeatures } from "@/ee-slots";
import { errorMessage, toastError } from "@/lib/errors";
import { formatAgo } from "@/lib/format";
import { FormDialog } from "@/pages/admin/FormDialog";
import { FrozenNotice } from "./FrozenNotice";
import {
  createSink,
  deleteSink,
  progress,
  putRetention,
  retentionQuery,
  siemKeys,
  SINK_LABEL,
  sinksQuery,
  testSink,
  updateSink,
} from "./siem";

function useInvalidate() {
  const qc = useQueryClient();
  return () => qc.invalidateQueries({ queryKey: siemKeys.all });
}

function Field({ id, label, children }: { id: string; label: string; children: React.ReactNode }) {
  return (
    <div className="grid gap-1.5">
      <Label htmlFor={id}>{label}</Label>
      {children}
    </div>
  );
}

interface Header {
  name: string;
  value: string;
}

/** Add or edit a sink. Secrets are never shown: blank keeps the stored ones. */
function SinkDialog({ sink, onClose }: { sink?: SinkView; onClose: () => void }) {
  const invalidate = useInvalidate();
  const editing = !!sink;
  const [name, setName] = useState(sink?.name ?? "");
  const [kind, setKind] = useState<SinkKind>(sink?.kind ?? "syslog");
  const [enabled, setEnabled] = useState(sink?.enabled ?? true);
  const [host, setHost] = useState(sink?.kind === "syslog" ? (sink.target.split(":")[0] ?? "") : "");
  const [port, setPort] = useState(sink?.kind === "syslog" ? (sink.target.split(":")[1] ?? "514") : "514");
  const [transport, setTransport] = useState<SyslogTransport>(sink?.transport ?? "udp");
  const [ca, setCa] = useState("");
  const [url, setUrl] = useState(sink?.url ?? "");
  const [token, setToken] = useState("");
  const [headers, setHeaders] = useState<Header[]>(sink?.header_names.map((n) => ({ name: n, value: "" })) ?? []);
  const [start, setStart] = useState<"now" | "all">("now");
  const body = (): SinkBody => ({
    name,
    kind,
    enabled,
    host: kind === "syslog" ? host : null,
    port: kind === "syslog" ? Number(port) : null,
    transport: kind === "syslog" ? transport : null,
    ca_pem: kind === "syslog" && transport === "tls" && ca.trim() ? ca : null,
    url: kind === "syslog" ? null : url,
    token: kind === "splunk_hec" ? token : null,
    headers: kind === "http" ? headers.filter((h) => h.name.trim()) : [],
    start: editing ? null : start,
  });
  const setHeader = (i: number, h: Partial<Header>) => setHeaders(headers.map((x, j) => (j === i ? { ...x, ...h } : x)));
  return (
    <FormDialog
      title={editing ? `Edit ${sink.name}` : "Add sink"}
      submitLabel={editing ? "Save" : "Add"}
      submitDisabled={!name.trim()}
      onClose={onClose}
      onSubmit={async () => {
        if (editing) await updateSink(sink.id, body());
        else await createSink(body());
        await invalidate();
      }}
    >
      <Field id="sink-name" label="Name">
        <Input id="sink-name" maxLength={64} value={name} onChange={(e) => setName(e.target.value)} placeholder="splunk-prod" />
      </Field>
      <Field id="sink-kind" label="Kind">
        <NativeSelect id="sink-kind" value={kind} disabled={editing} onChange={(e) => setKind(e.target.value as SinkKind)}>
          {(Object.keys(SINK_LABEL) as SinkKind[]).map((k) => (
            <option key={k} value={k}>
              {SINK_LABEL[k]}
            </option>
          ))}
        </NativeSelect>
      </Field>
      {kind === "syslog" && (
        <>
          <div className="grid gap-3 sm:grid-cols-3">
            <div className="sm:col-span-2">
              <Field id="sink-host" label="Host">
                <Input id="sink-host" className="font-ident" value={host} onChange={(e) => setHost(e.target.value)} placeholder="siem.example.com" />
              </Field>
            </div>
            <Field id="sink-port" label="Port">
              <Input id="sink-port" inputMode="numeric" value={port} onChange={(e) => setPort(e.target.value)} />
            </Field>
          </div>
          <Field id="sink-transport" label="Transport">
            <NativeSelect id="sink-transport" value={transport} onChange={(e) => setTransport(e.target.value as SyslogTransport)}>
              <option value="udp">UDP</option>
              <option value="tcp">TCP</option>
              <option value="tls">TLS</option>
            </NativeSelect>
          </Field>
          {transport === "tls" && (
            <Field id="sink-ca" label="Extra CA certificate (PEM, optional)">
              <Textarea
                id="sink-ca"
                className="font-ident text-xs"
                rows={4}
                value={ca}
                onChange={(e) => setCa(e.target.value)}
                placeholder={sink?.ca_set ? "Leave blank to keep the current certificate" : "-----BEGIN CERTIFICATE-----"}
              />
            </Field>
          )}
        </>
      )}
      {kind === "splunk_hec" && (
        <>
          <Field id="sink-url" label="HEC URL">
            <Input id="sink-url" className="font-ident" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://splunk.example.com:8088/services/collector/event" />
          </Field>
          <Field id="sink-token" label="HEC token">
            <Input
              id="sink-token"
              type="password"
              autoComplete="new-password"
              value={token}
              onChange={(e) => setToken(e.target.value)}
              placeholder={sink?.token_set ? "Leave blank to keep the current token" : ""}
            />
          </Field>
        </>
      )}
      {kind === "http" && (
        <>
          <Field id="sink-url" label="URL">
            <Input id="sink-url" className="font-ident" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://http-intake.logs.datadoghq.com/api/v2/logs" />
          </Field>
          <div className="grid gap-2">
            <span className="text-sm font-medium">Headers</span>
            {headers.map((h, i) => (
              <div key={i} className="flex gap-2">
                <Input aria-label={`Header ${i + 1} name`} className="font-ident" value={h.name} onChange={(e) => setHeader(i, { name: e.target.value })} placeholder="DD-API-KEY" />
                <Input
                  aria-label={`Header ${i + 1} value`}
                  type="password"
                  autoComplete="new-password"
                  value={h.value}
                  onChange={(e) => setHeader(i, { value: e.target.value })}
                  placeholder={editing && sink.header_names.includes(h.name) ? "Leave blank to keep" : ""}
                />
                <Button type="button" variant="ghost" size="sm" aria-label={`Remove header ${i + 1}`} onClick={() => setHeaders(headers.filter((_, j) => j !== i))}>
                  <X aria-hidden />
                </Button>
              </div>
            ))}
            <Button type="button" variant="outline" size="sm" className="justify-self-start" onClick={() => setHeaders([...headers, { name: "", value: "" }])}>
              <Plus aria-hidden />
              Add header
            </Button>
          </div>
        </>
      )}
      {!editing && (
        <Field id="sink-start" label="Start from">
          <NativeSelect id="sink-start" value={start} onChange={(e) => setStart(e.target.value as "now" | "all")}>
            <option value="now">New entries only</option>
            <option value="all">Every entry still kept</option>
          </NativeSelect>
        </Field>
      )}
      <Label className="flex items-center gap-2 font-normal">
        <Checkbox checked={enabled} onCheckedChange={(v) => setEnabled(v === true)} />
        Enabled
      </Label>
    </FormDialog>
  );
}

function SinkRow({ s, licensed }: { s: SinkView; licensed: boolean }) {
  const invalidate = useInvalidate();
  const [editing, setEditing] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const test = useMutation({
    mutationFn: () => testSink(s.id),
    onSuccess: () => toast.success(`Sent a test to ${s.name}`),
    onError: (e) => toast.error(errorMessage(e)),
  });
  return (
    <tr className="border-t border-border align-top">
      <td className="px-4 py-2 font-medium">{s.name}</td>
      <td className="px-4 py-2 text-ink-muted">{SINK_LABEL[s.kind]}</td>
      <td className="px-4 py-2 font-ident text-xs">{s.target}</td>
      <td className="px-4 py-2">
        <div className="grid gap-1">
          {s.last_error ? (
            <span title={s.last_error_at ? formatAgo(s.last_error_at) : undefined}>
              <StateBadge state={`Failing: ${s.last_error}`} tone="fail" />
            </span>
          ) : (
            <StateBadge state={progress(s)} tone={!s.enabled ? "wait" : s.behind > 0 ? "wait" : "run"} />
          )}
          {s.last_sent_at != null && <span className="text-xs text-meta">Last sent {formatAgo(s.last_sent_at)}</span>}
          {s.gap_rows > 0 && <span className="text-xs text-state-wait-text">{s.gap_rows} rows were removed by retention before they were sent</span>}
        </div>
      </td>
      <td className="px-4 py-2 text-right whitespace-nowrap">
        {licensed && (
          <>
            <Button size="sm" variant="outline" aria-label={`Send test to ${s.name}`} disabled={test.isPending} onClick={() => test.mutate()}>
              <Send aria-hidden />
              Send test
            </Button>
            <Button size="sm" variant="outline" aria-label={`Edit ${s.name}`} onClick={() => setEditing(true)}>
              Edit
            </Button>
          </>
        )}
        <Button size="sm" variant="ghost" aria-label={`Delete ${s.name}`} onClick={() => setDeleting(true)}>
          <Trash2 aria-hidden />
        </Button>
        {editing && <SinkDialog sink={s} onClose={() => setEditing(false)} />}
        <ConfirmDialog
          open={deleting}
          onOpenChange={setDeleting}
          title={`Delete ${s.name}?`}
          description="FleetOps stops sending the audit log here. What was already sent stays in your SIEM."
          confirmLabel="Delete"
          destructive
          onConfirm={() => deleteSink(s.id).then(invalidate)}
        />
      </td>
    </tr>
  );
}

function RetentionPanel({ days: current, licensed }: { days: number; licensed: boolean }) {
  const invalidate = useInvalidate();
  const [days, setDays] = useState(String(current));
  const save = useMutation({
    mutationFn: () => putRetention(Number(days)),
    onSuccess: () => {
      void invalidate();
      toast.success("Retention saved");
    },
    onError: toastError,
  });
  return (
    <Panel title="Retention" icon={Clock}>
      <div className="grid gap-3">
        <p className="text-sm text-ink-muted">
          How long FleetOps keeps audit entries. Community keeps 90 days; Enterprise can keep up to 10 years (3650 days). Older entries are
          deleted once an hour.
        </p>
        <div className="flex flex-wrap items-end gap-2">
          <Field id="retention-days" label="Keep audit entries for (days)">
            <Input id="retention-days" inputMode="numeric" className="max-w-32" value={days} onChange={(e) => setDays(e.target.value)} disabled={!licensed} />
          </Field>
          {licensed && (
            <Button disabled={save.isPending || !days} onClick={() => save.mutate()}>
              Save retention
            </Button>
          )}
        </div>
      </div>
    </Panel>
  );
}

/** Admin → Audit forwarding: send the audit log to a SIEM, and keep it longer. */
export function AuditForwardingPage() {
  const licensed = useFeatures().includes("audit_sinks");
  const sinks = useQuery(sinksQuery).data ?? [];
  const retention = useQuery(retentionQuery);
  const [adding, setAdding] = useState(false);
  return (
    <Page title="Audit forwarding" kicker="Enterprise">
      {!licensed && <FrozenNotice>Audit forwarding needs a license. Nothing is sent; you can still delete sinks.</FrozenNotice>}
      <div className="grid gap-5">
        <Panel
          title="Sinks"
          icon={Waypoints}
          flush
          actions={
            licensed && (
              <Button size="sm" onClick={() => setAdding(true)}>
                <Plus aria-hidden />
                Add sink
              </Button>
            )
          }
        >
          {sinks.length === 0 ? (
            <p className="p-4 text-sm text-ink-muted">
              No sinks yet. Every audit entry can go to syslog (rsyslog, syslog-ng, Microsoft Sentinel), Splunk, or any HTTPS endpoint such as
              Datadog or Elastic, as it happens.
            </p>
          ) : (
            <table aria-label="Audit sinks" className="w-full text-sm">
              <tbody>
                {sinks.map((s) => (
                  <SinkRow key={s.id} s={s} licensed={licensed} />
                ))}
              </tbody>
            </table>
          )}
        </Panel>
        {retention.isSuccess && <RetentionPanel key={retention.dataUpdatedAt} days={retention.data.days} licensed={licensed} />}
      </div>
      {adding && <SinkDialog onClose={() => setAdding(false)} />}
    </Page>
  );
}
