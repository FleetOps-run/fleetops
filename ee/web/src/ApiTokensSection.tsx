import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Copy, Plus } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect } from "@/components/ui/native-select";
import { FormDialog } from "@/pages/admin/FormDialog";
import { TokenTable } from "./TokenTable";
import { createToken, EXPIRY_CHOICES, myTokensQuery, tokenKeys } from "./tokens";

/** The Account page's API tokens: your own, for CI and scripts. */
export function ApiTokensSection() {
  const tokens = useQuery(myTokensQuery);
  const [creating, setCreating] = useState(false);
  const [secret, setSecret] = useState<string | null>(null);
  return (
    <section aria-label="API tokens">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-4">
          <CardTitle>API tokens</CardTitle>
          <Button size="sm" onClick={() => setCreating(true)}>
            <Plus aria-hidden />
            Create token
          </Button>
        </CardHeader>
        <CardContent className="grid gap-3">
          <p className="text-sm text-muted-foreground">
            Send a token as <code className="text-xs">Authorization: Bearer fo_…</code>. It acts as you, with your access, and
            everything it does is in the audit log under its name.
          </p>
          <TokenTable data={tokens.data} error={tokens.error} />
        </CardContent>
      </Card>
      {creating && <CreateDialog onClose={() => setCreating(false)} onCreated={setSecret} />}
      {secret && <SecretDialog secret={secret} onClose={() => setSecret(null)} />}
    </section>
  );
}

function CreateDialog({ onClose, onCreated }: { onClose: () => void; onCreated: (secret: string) => void }) {
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [readOnly, setReadOnly] = useState(false);
  const [expiry, setExpiry] = useState("90");
  return (
    <FormDialog
      title="Create API token"
      submitLabel="Create"
      submitDisabled={!name.trim()}
      onClose={onClose}
      onSubmit={async () => {
        const r = await createToken({
          name: name.trim(),
          read_only: readOnly,
          expires_in_days: expiry ? Number(expiry) : null,
        });
        await qc.invalidateQueries({ queryKey: tokenKeys.all });
        onCreated(r.secret);
      }}
    >
      <div className="grid gap-2">
        <Label htmlFor="token-name">Name</Label>
        <Input id="token-name" maxLength={64} required value={name} onChange={(e) => setName(e.target.value)} placeholder="ci-deploy" />
      </div>
      <div className="grid gap-2">
        <Label htmlFor="token-expiry">Expires</Label>
        <NativeSelect id="token-expiry" value={expiry} onChange={(e) => setExpiry(e.target.value)}>
          {EXPIRY_CHOICES.map((c) => (
            <option key={c.value} value={c.value}>
              {c.label}
            </option>
          ))}
        </NativeSelect>
      </div>
      <Label className="flex items-center gap-2 font-normal">
        <Checkbox checked={readOnly} onCheckedChange={(v) => setReadOnly(v === true)} />
        Read-only (no changes, no terminals)
      </Label>
    </FormDialog>
  );
}

function SecretDialog({ secret, onClose }: { secret: string; onClose: () => void }) {
  const copy = async () => {
    await navigator.clipboard.writeText(secret);
    toast.success("Copied");
  };
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Copy your token</DialogTitle>
          <DialogDescription>This is the only time it is shown. FleetOps keeps only a hash of it.</DialogDescription>
        </DialogHeader>
        <code className="block rounded-md bg-muted p-3 text-xs break-all">{secret}</code>
        <DialogFooter>
          <Button variant="outline" onClick={() => void copy()}>
            <Copy aria-hidden />
            Copy
          </Button>
          <Button onClick={onClose}>Done</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
