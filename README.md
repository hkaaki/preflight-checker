# PreFlight Checker

Pre-flight checks for autonomous agents — before an agent installs a package, calls another service, or trusts a domain, it runs one of these first. Paid for via [x402](https://x402.org) (HTTP 402 micropayments) on Base mainnet. No signup, no API keys — pay per call in USDC and get your result back in the same request. x402 is the payment rail, not the product; the product is the check itself.

**Live at:** `https://x402-api-catalog.onrender.com`

## Endpoints

**Code checks**

| Endpoint | Price | What it does |
|---|---|---|
| `GET /api/trust-check` | $0.02 | npm package trust/risk check: registry age, weekly downloads, GitHub org/stars, OSV.dev vulnerabilities |
| `GET /api/repo-health` | $0.02 | GitHub repo health check: stars, forks, open issues, last commit age, archived status, license |

**Network checks**

| Endpoint | Price | What it does |
|---|---|---|
| `GET /api/domain-check` | $0.02 | Domain liveness check: DNS resolution, mail routing, HTTP reachability |

**Ops checks**

| Endpoint | Price | What it does |
|---|---|---|
| `GET /api/x402-doctor` | $1.00 | Audits another x402 service for the common reasons directories mark it "down" — missing discovery descriptor, broken 402 challenge, malformed payment terms — and returns a concrete fix |

## Example

```bash
curl "https://x402-api-catalog.onrender.com/api/trust-check?package=left-pad"
```

An unpaid request returns `402 Payment Required` with the exact payment terms in the `payment-required` header (base64, per the [x402 v2 spec](https://x402.org)). Any x402-capable client — [`awal`](https://github.com/coinbase/awal), the [CDP SDK](https://docs.cdp.coinbase.com/x402), or your own signer — can complete the payment and get the real response in the same call.

Discovery descriptor: [`/.well-known/x402`](https://x402-api-catalog.onrender.com/.well-known/x402)

## x402 Doctor

`x402-doctor` is a diagnostic tool for other x402 service operators. Pass it the URL of any x402 service (yours or someone else's) and it checks:

- Does `/.well-known/x402` exist and validate?
- Does an unpaid request return a clean `402`, not a `500` or `404`?
- Is the payment challenge itself well-formed?
- Does the discovery descriptor match what the live endpoint actually advertises?

```bash
curl "https://x402-api-catalog.onrender.com/api/x402-doctor?url=https://your-service.example.com"
```

Every check it runs was found the hard way — on this exact service, in production, before being fixed.

## Stack

FastAPI + the official [`x402`](https://pypi.org/project/x402/) Python SDK, with the [CDP facilitator](https://docs.cdp.coinbase.com/x402/seller/facilitator) for mainnet settlement. Deployed on Render.
