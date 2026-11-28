# Port-forward

Reach a port inside a Kubernetes pod from your own machine, through FleetOps, so local tools connect to it as if it ran on `localhost`: `psql` to a database, `redis-cli` to a cache, or a browser to an admin UI. It works for every cluster FleetOps manages, including clusters connected by an agent, and needs nothing installed in the cluster.

## How it works

1. On a pod's page, choose **Port-forward**, enter the pod's port (filled in from the pod's first `containerPort`), and choose **Create link**.
2. FleetOps shows a command. Copy it and run it on your machine:

   ```sh
   fleetops-cli forward --server https://fleet.example.com fpt_… --local 5432
   ```

3. `fleetops-cli` prints `Forwarding 127.0.0.1:5432 -> prod/db/postgres-0:5432 (for 8h00m). Ctrl-C to stop.` Then connect as usual:

   ```sh
   psql -h 127.0.0.1 -p 5432 -U app
   ```

The link in the command works **once**, within **5 minutes**. A user can have up to 20 unused links and 10 running forwards; creating an 11th forward ends that user's oldest one. Once `fleetops-cli` has used it, the forward lasts up to **8 hours** or until you press Ctrl-C. Each local connection (each `psql` session, each browser request) gets its own stream to the pod, and up to 16 can be open at once. If FleetOps restarts, the forward ends; create a new link.

## Get fleetops-cli

Download it for Linux (amd64, arm64), macOS (Apple silicon, Intel) or Windows from the [latest release](https://github.com/FleetOps-run/fleetops/releases/latest), with a SHA-256 checksum next to each file. It is a single file of about 3 MB; put it on your `PATH`. When your copy is older than the FleetOps server it connects to, it prints a note with a link to the matching release; it asks nothing of GitHub itself.

```
fleetops-cli forward --server <URL> <link> [--local <port>] [--address <ip>] [--ca <file>]
```

| Option | Meaning |
|---|---|
| `--server` | FleetOps's address (also `FLEETOPS_SERVER`). The dialog fills it in. |
| `--local` | The port to listen on. Left out, it uses the pod's port; `0` picks a free one. |
| `--address` | The address to listen on. Default `127.0.0.1`, so only your machine can connect. |
| `--ca` | A PEM CA certificate to trust (also `FLEETOPS_CA`), for a server using its own certificate, such as the one FleetOps generates for its HTTPS listener. |

`http://` servers work too, but anything other than `localhost` gets a warning, since the link and your traffic are not encrypted.

## Who can do it

Port-forward needs **Shell** on pods in the pod's namespace, the same as the pod terminal: Operators, Admins, and custom roles with Shell on pods. Viewers don't see the button.

Access is checked when the link is created, on every new connection, and every minute while a connection is open. If someone's access is removed, their account is disabled, or the environment is deleted, new connections are refused at once (and `fleetops-cli` stops), and open ones close within a minute. Renaming the environment keeps forwards working. A passing database or cluster error during the minute check does not close open connections.

## Audit

Each forward is written to the audit log as `k8s.port_forward`, with the pod and port, under the user who created the link, when `fleetops-cli` starts it. A refusal is written as `access.denied`. Links and session credentials never appear in the audit log.

## Limits

- Pods only, one TCP port per forward. For several ports, run `fleetops-cli` once per port. UDP is not supported.
- Docker containers are not covered. Publish the port, or use the container's terminal.
- When a local program stops sending (shuts down its side of the connection), the whole connection closes, as with `kubectl port-forward`. psql, database clients and browsers are unaffected; a tool that sends a request, half-closes, then waits for the answer (`nc -N`) may get a cut-off reply.
- A connection ends if the pod restarts. `fleetops-cli` keeps listening, and the next connection reaches the new pod once it is ready under the same name, as with a StatefulSet.

## Behind a reverse proxy

If FleetOps sits behind nginx, a load balancer or an ingress, the proxy must pass WebSocket upgrades (`Upgrade` and `Connection` headers) and the `x-fleetops-forward` header on `/api/v1/port-forward/stream`. FleetOps pings each forward every 25 seconds, so idle connections survive the usual 60-second proxy timeouts. Set `FLEETOPS_PUBLIC_URL` when people reach FleetOps at a different address than the one the browser shows (for example, a separate hostname for command-line access), so the command in the dialog points there.

## Security

- The link is single-use and expires after 5 minutes. Redeeming is limited to 10 failed attempts per address every 5 minutes. FleetOps keeps only hashes of links and session credentials, in memory.
- `fleetops-cli` sends its credential in a header that browsers cannot set, so a web page elsewhere cannot use your FleetOps session to open a forward.
- Listening on `127.0.0.1` (the default) keeps the port to your machine. `--address 0.0.0.0` shares it with your network, so anyone who can reach your machine reaches the pod.
