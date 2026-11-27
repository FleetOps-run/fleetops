import { useQueryClient } from "@tanstack/react-query";
import { ShieldX } from "lucide-react";
import { useState } from "react";
import type { TokenInfo } from "@/api/gen/types.gen";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { columns, DataTable, type Column } from "@/components/DataTable";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { formatTime } from "@/lib/format";
import { revokeToken, tokenKeys } from "./tokens";

const col = columns<TokenInfo>();

/** API tokens with a Revoke button each; `owners` adds the owner column. */
export function TokenTable({ data, error, owners }: { data: TokenInfo[] | undefined; error: unknown; owners?: boolean }) {
  const qc = useQueryClient();
  const [revoking, setRevoking] = useState<TokenInfo | null>(null);
  const cols: Column<TokenInfo>[] = [
    col.accessor("name", { header: "Name", cell: (c) => <span className="font-medium">{c.getValue()}</span> }),
    ...(owners ? [col.accessor("username", { header: "Owner" })] : []),
    col.accessor("prefix", { header: "Token", cell: (c) => <code className="text-xs">{c.getValue()}…</code> }),
    col.accessor("read_only", {
      header: "Scope",
      cell: (c) => <Badge variant="outline">{c.getValue() ? "Read-only" : "Read and write"}</Badge>,
    }),
    col.accessor("expires_at", {
      header: "Expires",
      cell: (c) => {
        const v = c.getValue();
        return v == null ? "Never" : formatTime(v);
      },
    }),
    col.accessor("last_used_at", {
      header: "Last used",
      cell: (c) => {
        const t = c.row.original;
        return t.last_used_at == null ? "Never used" : `${formatTime(t.last_used_at)} from ${t.last_used_ip ?? "unknown"}`;
      },
    }),
    col.display({
      id: "revoke",
      header: () => <span className="sr-only">Actions</span>,
      cell: (c) => (
        <Button variant="outline" size="sm" onClick={() => setRevoking(c.row.original)}>
          <ShieldX aria-hidden />
          Revoke
        </Button>
      ),
    }),
  ];
  return (
    <>
      <DataTable
        label="API tokens"
        data={data}
        error={error}
        columns={cols}
        getRowId={(t) => String(t.id)}
        empty="No API tokens yet."
        phoneColumns={["name", "revoke"]}
      />
      <ConfirmDialog
        open={revoking != null}
        onOpenChange={(open) => !open && setRevoking(null)}
        title={revoking ? `Revoke token ${revoking.name}?` : ""}
        description="Anything still using it stops working at once. This cannot be undone."
        confirmLabel="Revoke"
        destructive
        onConfirm={async () => {
          if (revoking) await revokeToken(revoking.id);
          await qc.invalidateQueries({ queryKey: tokenKeys.all });
        }}
      />
    </>
  );
}
