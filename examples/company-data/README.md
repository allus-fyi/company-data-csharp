# Company-data example — connections / request fields / change feed / webhooks / documents (C# SDK)

A runnable website that demonstrates the **regular company-data surface** a company
uses — reading connected people, request-field definitions, the change feed,
webhooks, and documents — through the `Allus.CompanyData` **C# SDK**. Like the
[identity example](../identity), ~90 % of the logic is a shared frontend fetched
from a pinned release; this directory is the thin C# backend that implements the
[demo-backend contract](https://github.com/allme-sdk/example-test-suite)
(`CONTRACT.md`) for the five `companydata:*` scenarios.

Everything the handlers do goes through the SDK's **intended top-level surface** —
`Client.ConnectionsAsync()`, `RequestFieldsAsync()`, `ProcessChangesAsync()` /
`DrainBatchAsync()`, `VerifyWebhook()` + `ParseWebhook()`, `CreateDocumentAsync()` —
never internals, never raw platform HTTP.

---

## Run it — one command

Clone this SDK's public repo, enter the example, and run the one command:

```bash
git clone https://github.com/allus-fyi/company-data-csharp
cd company-data-csharp/examples/company-data
dotnet run
```

That runs the launcher (`Program.cs`), which:

1. wipes `.runtime/` (fresh state every boot),
2. on first run, downloads the **pinned** frontend release named in
   `frontend.lock`, **verifies its sha256**, and unpacks it to `.frontend/<tag>/`
   (a present, verified bundle is a cache hit — nothing is re-fetched),
3. checks the bundle's `contract.json` version against the backend's,
4. refuses a busy port with a clear message, then
5. serves `http://localhost:8091` — one Kestrel host with a serializing gate that
   keeps it effectively **single-worker** (the contract's no-concurrency model).

Built against **net8.0** with `RollForward=Major`, so it launches on any installed
.NET ≥ 8 runtime (e.g. .NET 10). The project is **`IsPackable=false`** and is not in
`Allus.CompanyData.slnx`, so it is never packed into the published NuGet package; it
references the SDK by **project reference** (`../../src`).

Open **http://localhost:8091** and pick a scenario. Each scenario's setup panel has
a **Save** button: it POSTs your settings to the backend, which writes them to a
canonical SDK **config file** (`.runtime/config/{sid}.json`, the service PEM under
`.runtime/config/keys/`) — the same shape a real integrator wires by hand. The panel
shows the written path so you can open and read the real config; **Run** then builds
the SDK from that file (`Client.FromConfig`) and runs off it. You never hand-create
or edit the file — the backend writes it from your browser inputs.

**Port.** `8091` is the default, overridable with the `PORT` env var
(`PORT=8092 dotnet run`). The default is the **same across all SDK examples** (one
browser origin ⇒ your localStorage setup carries across SDKs), so only one runs at a
time.

**Requirements:** the .NET SDK (≥ 8), plus network access on first run to fetch the
pinned frontend bundle from GitHub Releases.

---

## The five scenarios

| Scenario | SDK call | What it shows |
|---|---|---|
| **Read connected people** | `Client.ConnectionsAsync()` | each connected person's decrypted values, grouped one card per person (two people who filled the same slug stay distinguishable) |
| **Request-field definitions** | `Client.RequestFieldsAsync()` | your request slugs → label / type / the folded `mandatory` flag + `one_time` |
| **Change-feed pump** | `Client.ProcessChangesAsync()` | a crash-safe drain of the change feed (idempotent per event on `Change.Id`), shown as a batch |
| **Webhook receiver** | `VerifyWebhook()` + `ParseWebhook()` | a public `POST /webhook` (401 on a bad HMAC, 200 otherwise) **plus** a change-feed fallback so it works with no tunnel |
| **Create the six document types** | `Client.CreateDocumentAsync()` | broadcast JSON / broadcast PDF / per-person file / private file / contract-requiring-signature / contract-requiring-acceptance |

Every scenario uses the **service role**, so the service PEM + passphrase are a
required input on all five (the SDK loads the key at `Client` construction).

---

## Default target — the deployed AWS platform

The scenario **advanced inputs default to the deployed platform** (owner decision
2026-07-24: pre-launch, the cluster is the test environment): API url
`https://api.allme.fyi`. You register the demo's **service + data client** in the
**allus portal at `portal.allus.fyi`**; each scenario's setup checklist names the
exact portal steps (create the service + download its PEM, register a data client on
it, configure request fields, connect a test person).

---

## The webhook scenario — setup first, no tunnel

This scenario is **setup-first**: register a webhook on your service in the portal,
then paste its **webhook id** and one-time **HMAC secret** into the scenario before
starting it — **the run refuses to start without them** (`Server.cs` answers
`409 not_configured`). Set `encrypt_payload` OFF; this example holds no account
private key.

Once it is started **you need no tunnel**. The same run **polls the change feed** as
an always-works fallback (results are labeled `feed` vs `webhook`), so events appear
whether or not any inbound webhook can reach you.

The pull feed is a dedup-upsert **state** feed (one latest-state row per identity),
while a real webhook stream delivers each event, so the fallback can look like it
"collapsed" events — that is expected.

### Optional / advanced — real inbound webhook delivery via a tunnel

To exercise the actual `POST /webhook` receiver against the deployed platform, the
cluster must reach your `localhost`, so open one tunnel and register its public URL:

```bash
cloudflared tunnel --url http://localhost:8091
```

Register the printed public URL with **`/webhook`** appended as the service webhook.
Set **`encrypt_payload` OFF** (this example holds no account private key; an encrypted
body cannot be decrypted here). Copy the **webhook id** and the one-time **HMAC
secret** shown at registration into the scenario's inputs. (Against a **local stack**,
the local delivery worker reaches `localhost` directly, so you can register
**`http://localhost:8091/webhook`** with no tunnel at all.)

The receiver runs the EXACT `verifyWebhook → parseWebhook` sequence (never the
combined `HandleWebhook`, which can't drive the 401-vs-200 split): an unknown/stale
webhook id or no active run → **200** discard; a bad HMAC → **401**; a verified
delivery that parses → append + **200**; a verified-but-unparseable delivery → **200**
acknowledge-and-note (`unparseable++`). Every accepted-and-dropped case is **200**
because the platform delivery worker counts EXACTLY 200 as success.

---

## Secondary target — a local stack

Running against a **local stack** instead is an optional secondary target. In the browser, switch the advanced **API url** to
`http://localhost:8070`. No file in **this** example changes.

---

## Bumping the frontend pin

The frontend ships as a checksummed release asset; the pin lives in `frontend.lock`
(`{"tag":"v0.3.0","sha256":"<sha256 of dist.tar.gz>"}`). To move to a newer release:
note the release **tag** and its `dist.tar.gz` checksum (`shasum -a 256
dist.tar.gz`), set `tag` + `sha256` in `frontend.lock`, `rm -rf .frontend/`, then
`dotnet run`. A **contract-version change** means the backend must be updated in the
same step; the startup guard refuses a mismatch loudly. A pin bump is a
**per-example commit**.

---

## What's in here

| Path | What it is |
|---|---|
| `CompanyDataExample.csproj` | This example's own project — the SDK via project reference, `IsPackable=false`. **Excluded from the published NuGet package.** |
| `Program.cs` | The one-command launcher + Kestrel host + route table + the public `POST /webhook`. |
| `Server.cs` | The backend: the five scenario handlers, the webhook receiver, the Change projection. |
| `Runtime.cs` | Cross-request state: config files + run store + the single webhook routing record + the pump cache dir. |
| `frontend.lock` | The pinned frontend release (`{tag, sha256}`). |
| `.frontend/` | The fetched, verified frontend bundle (git-ignored). |
| `.runtime/` | The written SDK config files, per-run state, webhook routing record, and pump cache — git-ignored, wiped every boot. |

`.runtime/`, `.frontend/`, `bin/`, and `obj/` are git-ignored — the fetched bundle
and build output never land in the repo.
