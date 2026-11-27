import { useMutation } from "@tanstack/react-query";
import { Cable, Copy, Download, X } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { createPortForward } from "@/api/gen/sdk.gen";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { errorMessage } from "@/lib/errors";
import { FormError } from "@/pages/AuthLayout";

export const CLI_RELEASES = "https://github.com/FleetOps-run/fleetops/releases/latest";

/** The first `containerPort` in a pod's YAML, if any. */
export function firstContainerPort(yaml: string | undefined): string {
  return yaml?.match(/containerPort:\s*(\d+)/)?.[1] ?? "";
}

/** Pod page: a single-use link for `fleetops-cli forward`, shown as a command to copy. */
export function PortForwardButton({ env, ns, name, yaml }: { env: string; ns: string; name: string; yaml?: string }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <Button variant="outline" size="sm" onClick={() => setOpen(true)}>
        <Cable aria-hidden />
        Port-forward
      </Button>
      {open && <PortForwardDialog env={env} ns={ns} name={name} yaml={yaml} onClose={() => setOpen(false)} />}
    </>
  );
}

function PortForwardDialog({ env, ns, name, yaml, onClose }: { env: string; ns: string; name: string; yaml?: string; onClose: () => void }) {
  const [port, setPort] = useState(() => firstContainerPort(yaml));
  const mint = useMutation({
    mutationFn: async () => (await createPortForward({ path: { env, ns, name }, body: { port: Number(port) } })).data,
    meta: { inline: true },
  });
  const server = mint.data?.server ?? window.location.origin;
  const command = mint.data ? `fleetops-cli forward --server ${server} ${mint.data.ticket} --local ${port}` : "";
  const copy = async () => {
    await navigator.clipboard.writeText(command);
    toast.success("Copied");
  };
  const valid = /^\d+$/.test(port) && Number(port) >= 1 && Number(port) <= 65535;
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Port-forward to {name}</DialogTitle>
          <DialogDescription>
            Reach a port inside this pod from your machine, so tools like psql or a browser on localhost connect to it.
          </DialogDescription>
        </DialogHeader>
        {!mint.data ? (
          <form
            className="grid gap-4"
            onSubmit={(e) => {
              e.preventDefault();
              if (valid) mint.mutate();
            }}
          >
            <div className="grid gap-1.5">
              <Label htmlFor="pf-port">Pod port</Label>
              <Input id="pf-port" inputMode="numeric" className="max-w-32" value={port} onChange={(e) => setPort(e.target.value.trim())} placeholder="5432" />
            </div>
            <FormError message={mint.error ? errorMessage(mint.error) : null} />
            <DialogFooter>
              <Button type="button" variant="outline" onClick={onClose}>
                <X aria-hidden />
                Cancel
              </Button>
              <Button type="submit" disabled={!valid || mint.isPending}>
                Create link
              </Button>
            </DialogFooter>
          </form>
        ) : (
          <div className="grid gap-3">
            <p className="text-sm text-ink-muted">Run this on your machine. The link works once, within 5 minutes; the forward then lasts up to 8 hours.</p>
            <div className="flex items-start gap-2">
              <code className="block flex-1 rounded-md bg-muted p-3 font-ident text-xs break-all">{command}</code>
              <Button variant="outline" size="sm" onClick={() => void copy()}>
                <Copy aria-hidden />
                Copy
              </Button>
            </div>
            <p className="text-sm text-ink-muted">
              Then connect to <code className="text-xs">localhost:{port}</code>.{" "}
              <a href={CLI_RELEASES} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 underline">
                <Download aria-hidden className="size-3.5" />
                Download fleetops-cli
              </a>{" "}
              for macOS, Linux or Windows.
            </p>
            <DialogFooter>
              <Button onClick={onClose}>Done</Button>
            </DialogFooter>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
