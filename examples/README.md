# allus company-data SDK — example test suite (C#)

A runnable website that demonstrates the allus / allme platform through the
`Allus.CompanyData` **C# / .NET SDK**, covering **all three scenario families** from
one server:

- **identity** — Sign in with allme, OIDC login, and 2FA by allme (scenarios 1–5, 7–8);
- **flow** — run a contract flow end-to-end (`flow:run`);
- **company-data** — connections, request-field definitions, the change feed,
  webhooks, and documents (the five `companydata:*`).

About 90 % of the logic is a shared frontend fetched from a pinned release; this
directory is the thin .NET backend that implements the
[demo-backend contract](https://github.com/allme-sdk/example-test-suite)
(**contractVersion 3**). Everything the handlers do goes through the SDK's
**intended top-level surface** — `OAuthClient`, `Client`, `Client.TwoFactor`, the
flow surface, `VerifyWebhook()` / `ParseWebhook()`, `CreateDocumentAsync()` — never
internals, never raw platform HTTP. The identity OIDC scenario (5) additionally
uses the standard third-party
[`IdentityModel.OidcClient`](https://www.nuget.org/packages/IdentityModel.OidcClient)
library — that a real OIDC client drives it is the point of the demonstration.

---

## Run it — one command

```bash
git clone https://github.com/allus-fyi/company-data-csharp.git
cd company-data-csharp/examples
dotnet run
```

`dotnet run` builds and runs **`Program.cs`**, the launcher, which fetches the
pinned portal bundle and serves the whole example test suite — **all three scenario
families on `http://localhost:8091`**. In detail it:

1. wipes `.runtime/` (fresh state every boot),
2. on first run, downloads the **pinned** frontend release named in `frontend.lock`,
   **verifies its sha256**, and unpacks it to `.frontend/<tag>/` (a present, verified
   bundle is a cache hit — nothing is re-fetched),
3. checks the bundle's `contract.json` version against the backend's (**3**),
4. refuses a busy port with a clear message, then
5. serves port `8091` on **all interfaces** and prints every URL it is reachable on —
   one Kestrel host. A serializing gate makes it
   effectively **single-worker** (the contract's "no cross-request concurrency to
   guard", so the file store stays lock-free).

Open **http://localhost:8091** and pick any scenario from any family. Each scenario's
setup panel has a **Save** button: it POSTs your settings to the backend, which writes
them to a canonical SDK **config file** (`.runtime/config/{scenario}.json`, any PEM
under `.runtime/config/keys/`) — the same shape a real integrator wires by hand. The
panel shows the written path so you can open and read the real config; **Run**
(**Trigger** for flow) then builds the SDK from that file (`OAuthClient.FromConfig` /
`Client.FromConfig`) and runs off it. You never hand-create or edit the file — the
backend writes it from your browser inputs; it is there to be read.

**From a phone or another machine on the same network.** The server binds **all
interfaces**, so any device on your network can reach it — startup prints the exact
`http://<your-lan-ip>:8091` URL to type, alongside the localhost one. Open that URL on
the phone and press **Save** there: the redirect URI written into the config file
follows the origin you used, so register the same `http://<your-lan-ip>:8091/callback`
on your OAuth app. Binding all interfaces also means **anyone on your network can reach
this demo**, and its setup panels accept and store real credentials under
`.runtime/config/` — OAuth and data-client secrets, private-key PEMs and their
passphrases, and webhook signing secrets. It is a local developer example, not a
hardened service: run it only on a network you trust, and only with sandbox
credentials.

**`localhost` and `127.0.0.1` are different origins.** Whichever address you open the
example on is the one the backend registers as the redirect URI — it never substitutes
a default — so open the example on the address you registered and stay on it for the
whole round-trip. Registering both spellings on the OAuth app makes either one work,
but that is a convenience, not a remedy for switching mid-flow: the browser also keeps
your saved setup per origin, so a flow that returns to the other spelling lands on a
page whose stored settings are simply not there.

**Port.** `8091` is the default, overridable with the `PORT` env var:

```bash
PORT=8092 dotnet run
```

The default is deliberately the **same across all six SDK examples** (one browser
origin ⇒ your localStorage setup carries across SDKs) — the documented consequence is
that only one example runs at a time.

### Prerequisites

- **A .NET SDK, version 8 or newer, on your PATH.** The project targets `net8.0` with
  `RollForward=Major`, so it builds and runs on any installed .NET ≥ 8 runtime (for
  example .NET 10). `dotnet run` restores NuGet packages automatically — no separate
  install step.
- **Network access on first run** to fetch the pinned frontend bundle from GitHub
  Releases (subsequent runs use the verified local cache).

The example is **`IsPackable=false`** and is not in `Allus.CompanyData.slnx`, so it is
never published as a NuGet package of its own — but since #493 its **source ships
inside** the `Allus.CompanyData` nupkg at `examples/`, so an installing developer gets
it. It resolves the SDK **by context**: a **project reference** (`../src`) in a
repository checkout, which is why a reader sees exactly which SDK call implements each
scenario, and a **package reference** to the released `Allus.CompanyData` when run from
an extracted package (where `src/` does not exist).

---

## Which SDK call implements each scenario

### identity (scenarios 1–5, 7–8)

| # | Scenario | SDK / OIDC calls the handler makes |
|---|---|---|
| 1 | Sign in — redirect | `OAuthClient.AuthorizeUrl("signin", …, "redirect", …)` → `/callback` → `OAuthClient.CompleteSignInAsync` |
| 2 | Sign in — detached | `OAuthClient.AuthorizeUrl("signin", …, "detached", …)` → `OAuthClient.PollResultAsync` (2s) → `OAuthClient.CompleteSignInAsync` |
| 3 | One-time claims | `OAuthClient.AuthorizeUrl("one_time", claims, …)` → `OAuthClient.CompleteSignInAsync` (decrypts values with the app private key from config) |
| 4 | Connect (stay-connected) | `OAuthClient.AuthorizeUrl("connect", …)` → `CompleteSignInAsync`, then `Client.ConnectionsAsync` matched by `share_code` for LIVE values |
| 5 | OIDC login | `(oidc) OidcClient.PrepareLoginAsync` → `/callback` → `(oidc) OidcClient.ProcessResponseAsync` (id_token verified) |
| 7 | 2FA at consent — GUIDE card | none — a checklist + links to scenarios 1 & 5 (no `/start`) |
| 8 | Standalone service-2FA + enrollment | `Client.TwoFactor.ChallengeAsync` → `TwoFactorClient.WaitForResultAsync` (2s); `/enroll` runs `OAuthClient.AuthorizeUrl("2fa_enroll", …)` in redirect & detached legs |

The handlers live in **`identity/IdentityHandlers.cs`** (`identity/Pkce.cs` generates
the PKCE pair for scenarios 1–4). The OIDC library (scenario 5) owns PKCE, `state`,
and id_token verification; its generated `state` **is** the run id, so `/callback`
finds the run by it.

### flow (`flow:run`)

| Step | SDK call the handler makes |
|---|---|
| Bind the company party | `Client.IdentityAsync()` → `Identity.CompanyUserId` |
| Bind the customer party | `Client.ConnectionAsync(connectionId)` → `Connection.PersonId` |
| Trigger the run | `Client.TriggerFlowRunAsync(flowId, connectionId, bindings)` |
| Each poll — read the run | `Client.FlowRunAsync(flowRunId)` |
| Drive one company step | `Client.ProcessFlowRunAsync(flowRunId, fillNode)` (a rejected value throws `ValidationException`) |
| On completion — answers | `Client.FlowRunAnswers(run)` (decrypted `{slug: value}`) |
| On completion — document | `Client.FlowRunDocumentAsync(flowRunId)` (contract fixture only) |

The handler lives in **`flow/FlowHandlers.cs`**. The platform flow-run id is never a
browser input: the demo runId **is** the backend run, and `TriggerFlowRunAsync`'s
returned id is stored inside it. `GET /api/runs/{id}` is both the drive loop and the
resume — each poll drives at most one company step, or reports the person's turn and
waits. The demo ships two importable flow packages in **`flow/fixtures/`**:

| Fixture zip | Shape |
|---|---|
| `flow/fixtures/info-gathering.zip` | `data_only` — a few company steps (text, an **email** validation-demo step, an address composite) then one person turn. |
| `flow/fixtures/contract.zip` | `document` — a company step, then a signature leaf that generates a document. |

### company-data (the five `companydata:*`)

| Scenario | SDK call | What it shows |
|---|---|---|
| **Read connected people** | `Client.ConnectionsAsync()` | each connected person's decrypted values, grouped one card per person |
| **Request-field definitions** | `Client.RequestFieldsAsync()` | your request slugs → label / type / the folded `mandatory` flag + `one_time` |
| **Change-feed pump** | `Client.ProcessChangesAsync()` | a crash-safe drain of the change feed (idempotent per event on `Change.Id`) |
| **Webhook receiver** | `VerifyWebhook()` + `ParseWebhook()` | a public `POST /webhook` (401 on a bad HMAC, 200 otherwise) **plus** a change-feed fallback so it works with no tunnel |
| **Create the six document types** | `Client.CreateDocumentAsync()` | broadcast JSON / broadcast PDF / per-person file / private file / contract-requiring-signature / contract-requiring-acceptance |

The handlers live in **`company-data/CompanyDataHandlers.cs`**. Every company-data
scenario uses the **service role**, so the service PEM + passphrase are a required
input on all five.

---

## Set-up in the portal

The scenario advanced inputs default to the **deployed AWS platform** (pre-launch, the
cluster is the test environment): API url `https://api.allme.fyi`, identity authorize
base `https://web.allme.fyi/auth`. Register the demo's OAuth apps, service, and data
clients in the **allus portal at https://portal.allus.fyi**; each scenario's setup
checklist names the exact portal pages, and a table beneath it gives the intended value
for every control on each of them — including the ones to leave alone. For the identity scenarios, register on
every OAuth app you create the redirect URI matching the origin you open the portal
on. The backend writes whichever origin your browser used into the scenario's
config file, so the two must match: use **`http://localhost:8091/callback`** when you
browse from this machine and **`http://<your-lan-ip>:8091/callback`** when you drive
the example from a phone (the startup output prints the exact address). Adjust the
port if you set `PORT`.

Running against a **local stack** instead is an optional secondary target: in the
browser, switch the advanced inputs to the local URLs. No file in this example
changes.

### The webhook scenario — set up first (tunnel optional)

The webhook scenario's **run needs a registered webhook id + its one-time HMAC
secret**, so set it up before running:

1. In the portal, register a service webhook and set **`encrypt_payload` OFF** (this
   example holds no account private key, so an encrypted body cannot be decrypted
   here). Copy the **webhook id** and the one-time **HMAC secret** into the scenario's
   inputs and **Save**.
2. Point the webhook at this server's `POST /webhook`:
   - **Local stack** — the local delivery worker reaches `localhost` directly, so
     register **`http://localhost:8091/webhook`**. No tunnel needed.
   - **Deployed platform** — the cluster cannot reach your `localhost`, so a tunnel is
     **optional but required for live deliveries**. Open one and register its public
     URL with **`/webhook`** appended:

     ```bash
     cloudflared tunnel --url http://localhost:8091
     ```

Either way the same run **also polls the change feed** as an always-works fallback
(rows labeled `feed` vs `webhook`), so events still appear even with no tunnel.

---

## What's in here

| Path | What it is |
|---|---|
| `ExampleTestSuite.csproj` | The single example project — the SDK by project reference in a checkout / package reference from an extracted package, plus the OIDC library. `IsPackable=false` (not published as its own package), but its **source ships inside** the SDK's nupkg at `examples/` (#493). |
| `Program.cs` | The one-command launcher + Kestrel host + the one route table for all three families. |
| `Runtime.cs` | Shared cross-request state store: config files + generic run store + TTL sweep + Clear + the webhook routing record + the pump cache dir. |
| `Dispatcher.cs` | Routes each request to the owning family by scenario id; merges the combined `/api/meta` scenario list. |
| `Web.cs` | Shared HTTP plumbing (JSON/text writers, body/header readers). |
| `identity/` | The identity scenario handlers (`IdentityHandlers.cs`) + `Pkce.cs`. |
| `flow/` | The flow scenario handler (`FlowHandlers.cs`) + `fixtures/` (importable flow packages). |
| `company-data/` | The company-data scenario handlers (`CompanyDataHandlers.cs`). |
| `frontend.lock` | The single pinned frontend release for the whole suite (`{tag, sha256}`). |
| `.frontend/` | The fetched, verified frontend bundle (git-ignored). |
| `.runtime/` | The written SDK config files, per-run state, webhook routing record, and pump cache — git-ignored, wiped every boot. |

`.runtime/`, `.frontend/`, `bin/`, and `obj/` are git-ignored — the fetched bundle and
build output never land in the repo.

---

## Bumping the frontend pin

The frontend ships as a checksummed release asset; the single pin lives in
`frontend.lock`:

```json
{ "tag": "v0.6.2", "sha256": "<sha256 of dist.tar.gz>" }
```

To move to a newer release: set `tag` + `sha256` in `frontend.lock`, remove the cached
bundle (`rm -rf .frontend/`), and `dotnet run`. It downloads the new tag, verifies the
checksum, and checks the bundle's `contract.json` version against the backend; a
**contract-version change** means the backend must be updated in the same step (the
startup guard refuses a mismatch loudly).
