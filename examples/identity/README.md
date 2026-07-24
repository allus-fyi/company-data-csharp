# Identity example — sign-in / OIDC / 2FA (C# SDK)

A runnable website that demonstrates **every identity scenario** of the allme
platform — Sign in with allme, OIDC login, and 2FA by allme — through the
`Allus.CompanyData` **C# / .NET SDK**. It is a port of the PHP reference example:
~90 % of the logic is a shared frontend fetched from a pinned release; this
directory is the thin .NET backend that implements the
[demo-backend contract](https://github.com/allme-sdk/example-test-suite) (`CONTRACT.md`).

Everything the handlers do goes through the SDK's **intended top-level surface**
(`OAuthClient`, `Client`, `Client.TwoFactor`; never internals, never raw platform
HTTP); the OIDC scenarios use the standard third-party
[`IdentityModel.OidcClient`](https://www.nuget.org/packages/IdentityModel.OidcClient)
library — that a real OIDC client drives them is the point of the demonstration.

---

## Run it — one command

```bash
cd examples/identity
dotnet run
```

`dotnet run` (the launcher lives in `Program.cs`):

1. wipes `.runtime/` (fresh state every boot),
2. on first run, downloads the **pinned** frontend release named in
   `frontend.lock`, **verifies its sha256**, and unpacks it to `.frontend/<tag>/`
   (a present, verified bundle is a cache hit — nothing is re-fetched),
3. checks the bundle's `contract.json` version against the backend's,
4. refuses a busy port with a clear message, then
5. serves `http://localhost:8091` — one Kestrel host. A serializing gate makes it
   effectively **single-worker** (the contract's "no cross-request concurrency to
   guard", so the file store stays lock-free).

Open **http://localhost:8091** and pick a scenario. Each scenario's setup panel
has a **Save** button: it POSTs your settings to the backend, which writes them to
a canonical SDK **config file** (`.runtime/config/{id}.json`, any PEM under
`.runtime/config/keys/`) — the same shape a real integrator wires by hand. The
panel shows the written path so you can open and read the real config; **Run** then
builds the SDK from that file (`OAuthClient.FromConfig` / `Client.FromConfig`) and
runs off it. You still never hand-create or edit the file — the backend writes it
from your browser inputs; it is there to be read.

**Port.** `8091` is the default, overridable with the `PORT` env var:

```bash
PORT=8092 dotnet run
```

The default is deliberately the **same across all six SDK examples** (one browser
origin ⇒ your localStorage setup carries across SDKs) — the documented consequence
is that only one example runs at a time.

**Requirements:** the .NET SDK (net8.0 target; the project rolls forward, so any
installed .NET ≥ 8 runtime works) and network access on first run to fetch the
frontend bundle. `dotnet run` restores NuGet packages automatically.

---

## Which SDK call implements each scenario

| # | Scenario | SDK / OIDC calls the handler makes |
|---|---|---|
| 1 | Sign in — redirect | `OAuthClient.AuthorizeUrl("signin", …, "redirect", …)` → `/callback` → `OAuthClient.CompleteSignInAsync` |
| 2 | Sign in — detached | `OAuthClient.AuthorizeUrl("signin", …, "detached", …)` → `OAuthClient.PollResultAsync` (2s) → `OAuthClient.CompleteSignInAsync` |
| 3 | One-time claims | `OAuthClient.AuthorizeUrl("one_time", claims, …)` → `OAuthClient.CompleteSignInAsync` (decrypts values with the app private key from config) |
| 4 | Connect (stay-connected) | `OAuthClient.AuthorizeUrl("connect", …)` → `CompleteSignInAsync`, then `Client.ConnectionsAsync` matched by `share_code` for LIVE values |
| 5 | OIDC login | `(oidc) OidcClient.PrepareLoginAsync` → `/callback` → `(oidc) OidcClient.ProcessResponseAsync` (id_token verified) |
| 6 | OIDC — continue on phone | same OIDC calls; completion via the phone (redirect leg) |
| 7 | 2FA at consent — GUIDE card | none — a checklist + links to scenarios 1 & 5 (no `/start`) |
| 8 | Standalone service-2FA + enrollment | `Client.TwoFactor.ChallengeAsync` → `TwoFactorClient.WaitForResultAsync` (2s); `/enroll` runs `OAuthClient.AuthorizeUrl("2fa_enroll", …)` in redirect & detached legs |

The OIDC library (scenarios 5/6) owns PKCE, `state`, and id_token verification; its
generated `state` **is** the run id, so `/callback` finds the run by it. It is
configured for `client_secret_post` (`TokenClientCredentialStyle = PostBody`) with
discovery-endpoint validation relaxed so a local-stack issuer override still works.

---

## Default target — the deployed AWS platform

The scenario advanced inputs default to the deployed platform (pre-launch, the
cluster is the test environment):

| Advanced input | Default |
|---|---|
| API url | `https://api.allme.fyi` |
| Authorize base | `https://web.allme.fyi/auth` |

Register the demo's OAuth apps / data clients in the **allus portal**; each
scenario's setup checklist names the exact pages. Register the redirect URI
**`http://localhost:8091/callback`** on every OAuth app you create (adjust the port
if you set `PORT`).

Running against a **local stack** is a documented secondary option: in the browser,
switch the advanced inputs to the local URLs (API `http://localhost:8070`, authorize
base `http://localhost:5174/auth`). No file in this example changes. For OIDC against
a local stack the local API must advertise itself in discovery (`OIDC_ISSUER`) — see
`docs/reference/software.html`.

---

## Bumping the frontend pin

The frontend ships as a checksummed release asset; the pin lives in `frontend.lock`:

```json
{"tag":"v0.1.0","sha256":"<sha256 of dist.tar.gz>"}
```

To move to a newer release: set `tag` + `sha256` in `frontend.lock`, remove the
cached bundle (`rm -rf .frontend/`), and `dotnet run`. It downloads the new tag,
verifies the checksum, and checks the bundle's `contract.json` version against the
backend; a **contract-version change** means the backend must be updated in the same
step (the startup guard refuses a mismatch loudly). A pin bump is a per-example
commit.

---

## What's in here

| Path | What it is |
|---|---|
| `IdentityExample.csproj` | This example's own project — the SDK via project reference, the OIDC library, nothing else. `IsPackable=false`; not in the SDK solution, so `dotnet pack` on the SDK never sees it. |
| `Program.cs` | The one-command launcher + Kestrel host (steps above) — static bundle + the contract's API endpoints. |
| `Server.cs` | The backend: contract endpoints, SDK + OIDC wiring. |
| `Runtime.cs` | Cross-request file store: config files + run stash, TTL sweep, Clear. |
| `Pkce.cs` | PKCE verifier/challenge for the "Sign in with allme" scenarios (1–4). |
| `frontend.lock` | The pinned frontend release (`{tag, sha256}`). |
| `.frontend/` | The fetched, verified frontend bundle (git-ignored). |
| `.runtime/` | The written SDK config files + per-run state, git-ignored, wiped every boot. |

`.runtime/`, `.frontend/`, `bin/`, and `obj/` are git-ignored — the fetched bundle
and build output never land in the repo.
