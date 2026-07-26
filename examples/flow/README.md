# Flow example — run a contract flow (C# SDK)

A runnable website that demonstrates a **contract flow** end-to-end through the
`Allus.CompanyData` **C# / .NET SDK**: trigger a flow run, drive the company party
through it with type-checked step filling, hand a turn to the person's phone, and on
completion read the decrypted answers and — for the contract fixture — download the
generated signed document. Like the [identity example](../identity/), ~90 % of the
logic is a shared frontend fetched from a pinned release; this directory is the thin
.NET backend that implements the
[demo-backend contract](https://github.com/allme-sdk/example-test-suite)
(`CONTRACT.md`, flow family — **contract v2**).

Everything the handler does goes through the SDK's **intended top-level flow surface**
— `IdentityAsync()`, `TriggerFlowRunAsync()`, `FlowRunAsync()`, `ProcessFlowRunAsync()`,
`FlowRunAnswers()`, `FlowRunDocumentAsync()` — never internals, never raw platform HTTP.

---

## Run it — one command

Clone this SDK's public repo, enter the example, and run the one command:

```bash
git clone https://github.com/allus-fyi/company-data-csharp
cd company-data-csharp/examples/flow
dotnet run
```

`dotnet run` (the launcher lives in `Program.cs`):

1. wipes `.runtime/` (fresh state every boot),
2. on first run, downloads the **pinned** frontend release named in `frontend.lock`,
   **verifies its sha256**, and unpacks it to `.frontend/<tag>/` (a present, verified
   bundle is a cache hit — nothing is re-fetched),
3. checks the bundle's `contract.json` version against the backend's (flow = **v2**),
4. refuses a busy port with a clear message, then
5. serves `http://localhost:8091` — one Kestrel host. A serializing gate makes it
   effectively **single-worker** (the contract's "no cross-request concurrency to
   guard", so the file store stays lock-free).

Open **http://localhost:8091** and pick the **Run a contract flow** scenario. From
there the browser and the allus portal are the only surfaces you touch. The
scenario's **Save** button POSTs your settings to the backend, which writes them to a
canonical SDK **config file** (`.runtime/config/1.json`, the service PEM under
`.runtime/config/keys/`) — the same shape a real integrator wires by hand. The panel
shows the written path so you can open and read the real config; **Trigger** then
builds the SDK from that file (`Client.FromConfig`) and runs off it. You still never
hand-create or edit the file — the backend writes it from your browser inputs; it is
there to be read.

**Port.** `8091` is the default, overridable with the `PORT` env var:

```bash
PORT=8092 dotnet run
```

The default is deliberately the **same across all six SDK examples** (one browser
origin ⇒ your localStorage setup carries across SDKs) — the documented consequence is
that only one example runs at a time.

**Requirements:** the .NET SDK (net8.0 target; the project rolls forward, so any
installed .NET ≥ 8 runtime works) and network access on first run to fetch the
frontend bundle. `dotnet run` restores NuGet packages automatically.

---

## The scenario — set up, then run

A contract flow is a company-authored graph of steps. The demo ships **two fixtures**
you import into the portal (`fixtures/`):

| Fixture zip | Shape |
|---|---|
| `fixtures/info-gathering.zip` | `data_only` — a few company steps (text, an **email** validation-demo step, an address composite) then one person turn. |
| `fixtures/contract.zip` | `document` — a company step, then a signature leaf that generates a document. |

The scenario's setup checklist names the exact portal steps. In short:

1. In the **allus portal**, register a **data client** (client_credentials) for the
   service — its whitelist auto-grants `/api/company-data/*`. Create/reuse the
   **service** and download its **private key (PEM)** (it decrypts the answers +
   document).
2. **Import** the chosen fixture zip (service settings → Flows → Import) and
   **publish** the imported flow.
3. In the browser, enter the data-client id/secret, pick the service PEM + its
   passphrase, enter the **published flow id** and the target **connection id**, and
   pick the same **fixture** you imported. **Save**, then **Trigger the flow run**.

What you then observe:

- The **flow-run log** accumulates one row per company step as the SDK drives it: the
  `email` step is submitted once with a bad value → rejected (the SDK's
  `ValidationException`, shown ✗), then re-submitted valid → accepted ✓. The other
  steps submit valid and advance.
- When the flow reaches the person's turn it shows **"waiting — answer on your
  phone"**; polling resumes automatically once the person answers (and, for the
  contract fixture, **signs**) in the allme app.
- On completion the **decrypted answers** appear, and for the contract fixture the
  **document** is downloaded via `FlowRunDocumentAsync()`.
- **"What just happened"** lists the exact SDK methods the run called.

> **Phone required.** The person's turn — and the contract fixture's signature — are
> completed on a **physical phone** with the allme app, signed in as the connected
> demo person (a real phone, not a simulator).

---

## Which SDK call implements each step

| Step | SDK call the handler makes |
|---|---|
| Bind the company party | `Client.IdentityAsync()` → `Identity.CompanyUserId` |
| Bind the customer party | `Client.ConnectionAsync(connectionId)` → `Connection.PersonId` |
| Trigger the run | `Client.TriggerFlowRunAsync(flowId, connectionId, bindings)` |
| Each poll — read the run | `Client.FlowRunAsync(flowRunId)` |
| Drive one company step | `Client.ProcessFlowRunAsync(flowRunId, fillNode)` (a rejected value throws `ValidationException`) |
| On completion — answers | `Client.FlowRunAnswers(run)` (decrypted `{slug: value}`) |
| On completion — document | `Client.FlowRunDocumentAsync(flowRunId)` (contract fixture only) |

The platform flow-run id is never a browser input: the demo runId **is** the backend
run, and `TriggerFlowRunAsync`'s returned id is stored inside it. `GET /api/runs/{id}`
is both the drive loop and the resume — each poll drives at most one company step, or
reports the person's turn and waits.

---

## Default target — the deployed AWS platform

The scenario's advanced input (**API url**) defaults to the deployed platform
(`https://api.allme.fyi`) — **no environment setup**. You register the data client,
create the service, and import + publish the flow in the **allus portal at
https://portal.allus.fyi**. A physical phone with the allme app reaches the deployed
platform naturally.

Running against a **local stack** is an optional secondary target. In the browser, switch the advanced **API url** to
`http://localhost:8070`; no file in this example changes. The phone must be able to
reach the local API (e.g. `adb reverse tcp:8070 tcp:8070` on Android, or
the machine's LAN address).

---

## Bumping the frontend pin

The frontend ships as a checksummed release asset; the pin lives in `frontend.lock`:

```json
{"tag":"v0.2.0","sha256":"<sha256 of dist.tar.gz>"}
```

This example pins the **flow family bundle (contract v2)**. To move to a newer release:
set `tag` + `sha256` in `frontend.lock`, remove the cached bundle (`rm -rf .frontend/`),
and `dotnet run`. It downloads the new tag, verifies the checksum, and checks the
bundle's `contract.json` version against the backend; a **contract-version change**
means the backend must be updated in the same step (the startup guard refuses a
mismatch loudly). A pin bump is a per-example commit.

---

## What's in here

| Path | What it is |
|---|---|
| `FlowExample.csproj` | This example's own project — the SDK via project reference, nothing else. `IsPackable=false`; not in the SDK solution, so `dotnet pack` on the SDK never sees it. |
| `Program.cs` | The one-command launcher + Kestrel host (steps above) — static bundle + the contract's API endpoints. |
| `Server.cs` | The backend: the `flow:run` handler, config files + run stash, SDK wiring. |
| `Runtime.cs` | Cross-request file store: config files + run stash, TTL sweep, Clear. |
| `fixtures/` | The two importable flow packages (portal-export zips). |
| `frontend.lock` | The pinned frontend release (`{tag, sha256}`). |
| `.frontend/` | The fetched, verified frontend bundle (git-ignored). |
| `.runtime/` | The written SDK config files + per-run state, git-ignored, wiped every boot. |

`.runtime/`, `.frontend/`, `bin/`, and `obj/` are git-ignored — the fetched bundle and
build output never land in the repo.
