import { useQuery } from "@tanstack/react-query";
import { Page } from "@/components/Page";
import { TokenTable } from "./TokenTable";
import { allTokensQuery } from "./tokens";

/** Admin → API tokens: every user's tokens, to see and revoke. */
export function ApiTokensPage() {
  const tokens = useQuery(allTokensQuery);
  return (
    <Page title="API tokens" meta="Each user creates their own on the Account page. Revoking one stops it at once.">
      <TokenTable data={tokens.data} error={tokens.error} owners />
    </Page>
  );
}
