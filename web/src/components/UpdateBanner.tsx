import { useQuery } from "@tanstack/react-query";
import { ArrowUpCircle, ExternalLink, X } from "lucide-react";
import { useState } from "react";
import { versionQuery } from "@/api/queries";
import { useSession } from "@/auth/session";
import { Button } from "@/components/ui/button";

/** The release an admin last dismissed the notice for, in this browser. */
const DISMISSED_KEY = "fleetops.update.dismissed";

function readDismissed(): string | null {
  try {
    return localStorage.getItem(DISMISSED_KEY);
  } catch {
    return null;
  }
}

/** Tells admins a newer FleetOps release is out, until they dismiss that release. */
export function UpdateBanner() {
  const { user } = useSession();
  const { data } = useQuery({ ...versionQuery, enabled: user.role === "admin" });
  const [dismissed, setDismissed] = useState(readDismissed);
  if (!data?.update_available || !data.latest || data.latest === dismissed) return null;
  const latest = data.latest;
  const dismiss = () => {
    try {
      localStorage.setItem(DISMISSED_KEY, latest);
    } catch {
      // Storage refused (private window): hide it for this page view only.
    }
    setDismissed(latest);
  };
  return (
    <div role="status" className="mx-3 flex items-center gap-2 rounded-md bg-state-run/12 px-4 py-2 text-sm md:mx-6">
      <ArrowUpCircle aria-hidden className="size-4 shrink-0 text-state-run" />
      <span className="min-w-0 flex-1">
        FleetOps {latest} is available — you're on v{data.current}.{" "}
        {data.release_url && (
          <a href={data.release_url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 font-medium underline-offset-2 hover:underline">
            Release notes
            <ExternalLink aria-hidden className="size-3" />
          </a>
        )}
      </span>
      <Button variant="ghost" size="icon-xs" aria-label="Dismiss update notice" onClick={dismiss}>
        <X aria-hidden />
      </Button>
    </div>
  );
}
