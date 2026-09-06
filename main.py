"""
Ash Ops x402 API Catalog
A real, multi-endpoint x402-paid API — not a single isolated listing.
Endpoints:
  GET /api/trust-check   - npm package trust/risk score (ported from agent-trust-api)
  GET /api/repo-health   - GitHub repo health check
  GET /api/domain-check  - domain DNS/registration liveness check
All paid at $0.02 USDC on Base mainnet via x402.
"""
import os
import re
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

from x402.http import HTTPFacilitatorClient, PaymentOption
from x402.http.middleware.fastapi import PaymentMiddlewareASGI
from x402.http.types import RouteConfig
from x402.mechanisms.evm.exact import ExactEvmServerScheme
from x402.schemas import Network
from x402.server import x402ResourceServer
from x402.extensions.bazaar.resource_service import declare_discovery_extension, OutputConfig
from cdp.x402 import create_facilitator_config

app = FastAPI(title="Ash Ops x402 API Catalog")

PAY_TO = "0x9041f8a43D0B43209B9227DE2c7fb25c9FE3847E"  # Ash's CDP wallet, Base mainnet
CDP_API_KEY_ID = os.environ.get("CDP_API_KEY_ID")
CDP_API_KEY_SECRET = os.environ.get("CDP_API_KEY_SECRET")
EVM_NETWORK: Network = "eip155:8453"  # Base mainnet

# Real CDP facilitator (via the official cdp-sdk helper) if credentials are present —
# required for mainnet, since the free x402.org/facilitator is testnet-only and will
# reject "eip155:8453" outright with RouteConfigurationError.
if CDP_API_KEY_ID and CDP_API_KEY_SECRET:
    facilitator = HTTPFacilitatorClient(
        create_facilitator_config(api_key_id=CDP_API_KEY_ID, api_key_secret=CDP_API_KEY_SECRET)
    )
else:
    from x402.http import FacilitatorConfig

    facilitator = HTTPFacilitatorClient(FacilitatorConfig(url="https://x402.org/facilitator"))

server = x402ResourceServer(facilitator)
server.register(EVM_NETWORK, ExactEvmServerScheme())

routes: dict[str, RouteConfig] = {
    "GET /api/trust-check": RouteConfig(
        accepts=[PaymentOption(scheme="exact", pay_to=PAY_TO, price="$0.02", network=EVM_NETWORK)],
        mime_type="application/json",
        description="npm package trust/risk score: registry age, weekly downloads, GitHub org/stars, OSV.dev vulnerabilities.",
        service_name="npm Trust Check",
        tags=["npm", "security", "trust-score"],
        extensions=declare_discovery_extension(
            input={"package": "left-pad", "repo": "left-pad/left-pad"},
            input_schema={
                "properties": {
                    "package": {"type": "string", "description": "npm package name to check"},
                    "repo": {"type": "string", "description": "owner/repo override if npm metadata lacks a repo link"},
                },
                "required": ["package"],
            },
            output=OutputConfig(
                example={"package": "left-pad", "score": 72, "verdict": "trustworthy", "reasons": [], "signals": {}},
                schema={"properties": {"package": {"type": "string"}, "score": {"type": "number"}, "verdict": {"type": "string"}}},
            ),
        ),
    ),
    "GET /api/repo-health": RouteConfig(
        accepts=[PaymentOption(scheme="exact", pay_to=PAY_TO, price="$0.02", network=EVM_NETWORK)],
        mime_type="application/json",
        description="GitHub repo health check: stars, forks, open issues, last commit age, archived status, license.",
        service_name="GitHub Repo Health",
        tags=["github", "code-quality", "due-diligence"],
        extensions=declare_discovery_extension(
            input={"repo": "facebook/react"},
            input_schema={
                "properties": {"repo": {"type": "string", "description": "GitHub repo in owner/repo format"}},
                "required": ["repo"],
            },
            output=OutputConfig(
                example={"repo": "facebook/react", "score": 85, "verdict": "healthy", "reasons": [], "signals": {}},
                schema={"properties": {"repo": {"type": "string"}, "score": {"type": "number"}, "verdict": {"type": "string"}}},
            ),
        ),
    ),
    "GET /api/domain-check": RouteConfig(
        accepts=[PaymentOption(scheme="exact", pay_to=PAY_TO, price="$0.02", network=EVM_NETWORK)],
        mime_type="application/json",
        description="Domain liveness check: DNS resolution (A/MX/NS/TXT records), whether mail routing exists, HTTP reachability.",
        service_name="Domain Liveness Check",
        tags=["dns", "domain", "due-diligence"],
        extensions=declare_discovery_extension(
            input={"domain": "example.com"},
            input_schema={
                "properties": {"domain": {"type": "string", "description": "domain to check, e.g. example.com"}},
                "required": ["domain"],
            },
            output=OutputConfig(
                example={"domain": "example.com", "hasMailRouting": True, "hasWebPresence": True, "httpReachable": True, "verdict": "fully live"},
                schema={"properties": {"domain": {"type": "string"}, "verdict": {"type": "string"}}},
            ),
        ),
    ),
}

app.add_middleware(PaymentMiddlewareASGI, routes=routes, server=server)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


def _payment_info_block(price_usd: str) -> dict[str, Any]:
    return {
        "x-payment-info": {
            "price": {"mode": "fixed", "currency": "USD", "amount": price_usd},
            "protocols": [{"x402": {}}],
        },
        "x-guidance": "Pay via x402 (HTTP 402) on Base mainnet (eip155:8453) to this endpoint's advertised payTo address; see the PAYMENT-REQUIRED response header on an unpaid GET for the exact accepts array.",
    }


@app.get("/openapi-x402.json")
async def openapi_x402() -> dict[str, Any]:
    """Machine-readable catalog description for x402 discovery/Bazaar indexing (mirrors the pattern proven live on agent-trust-api)."""
    return {
        "openapi": "3.1.0",
        "info": {
            "title": "Ash Ops x402 API Catalog",
            "version": "1.0.0",
            "description": "Three real, deterministic API checks: npm package trust, GitHub repo health, domain liveness. All paid at $0.02 USDC on Base mainnet via x402.",
            "contact": {"email": "l.a.mayberg@gmail.com"},
        },
        "paths": {
            "/api/trust-check": {
                "get": {
                    "operationId": "trustCheck",
                    "summary": routes["GET /api/trust-check"].description,
                    "tags": ["Trust"],
                    **_payment_info_block("0.020000"),
                    "parameters": [
                        {"name": "package", "in": "query", "required": True, "schema": {"type": "string"}},
                        {"name": "repo", "in": "query", "required": False, "schema": {"type": "string"}},
                    ],
                }
            },
            "/api/repo-health": {
                "get": {
                    "operationId": "repoHealth",
                    "summary": routes["GET /api/repo-health"].description,
                    "tags": ["Trust"],
                    **_payment_info_block("0.020000"),
                    "parameters": [
                        {"name": "repo", "in": "query", "required": True, "schema": {"type": "string"}},
                    ],
                }
            },
            "/api/domain-check": {
                "get": {
                    "operationId": "domainCheck",
                    "summary": routes["GET /api/domain-check"].description,
                    "tags": ["Trust"],
                    **_payment_info_block("0.020000"),
                    "parameters": [
                        {"name": "domain", "in": "query", "required": True, "schema": {"type": "string"}},
                    ],
                }
            },
        },
    }


def score_npm_signals(age_days: int | None, downloads: int, gh_repo: dict | None, vulns: list[str]) -> dict:
    score = 50
    reasons = []
    if age_days is not None:
        if age_days > 365:
            score += 15
            reasons.append("package >1yr old")
        elif age_days < 30:
            score -= 15
            reasons.append("package <30 days old")
    if downloads > 10000:
        score += 10
        reasons.append("healthy weekly downloads")
    elif downloads < 50:
        score -= 10
        reasons.append("very low downloads")
    if gh_repo:
        if gh_repo.get("stargazers_count", 0) > 100:
            score += 10
            reasons.append("100+ GitHub stars")
        if gh_repo.get("owner", {}).get("type") == "Organization":
            score += 5
            reasons.append("owned by a GitHub org")
        if gh_repo.get("archived"):
            score -= 20
            reasons.append("repo is archived")
    else:
        score -= 10
        reasons.append("no resolvable GitHub repo")
    if vulns:
        score -= min(30, len(vulns) * 10)
        reasons.append(f"{len(vulns)} known vulnerabilities")
    score = max(0, min(100, score))
    verdict = "trustworthy" if score >= 70 else "reasonable, review before use" if score >= 40 else "high risk"
    return {"score": score, "verdict": verdict, "reasons": reasons}


@app.get("/api/trust-check")
async def trust_check(package: str, repo: str | None = None) -> dict[str, Any]:
    if not package or not re.match(r"^[a-zA-Z0-9._@/-]+$", package):
        raise HTTPException(status_code=400, detail="package query param is required and must be a valid npm package name")

    async with httpx.AsyncClient(timeout=10) as client:
        npm_res = await client.get(f"https://registry.npmjs.org/{package}")
        if npm_res.status_code != 200:
            raise HTTPException(status_code=404, detail=f"npm package '{package}' not found")
        npm_data = npm_res.json()

        created = npm_data.get("time", {}).get("created")
        age_days = None
        if created:
            created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
            age_days = (datetime.now(timezone.utc) - created_dt).days
        latest_version = npm_data.get("dist-tags", {}).get("latest")
        repo_field = npm_data.get("repository", {}).get("url", "") if isinstance(npm_data.get("repository"), dict) else ""
        repo_match = re.search(r"github\.com[:/]([^/]+/[^/.]+)", repo_field, re.I)
        repo_path = repo or (repo_match.group(1) if repo_match else None)

        downloads_res = await client.get(f"https://api.npmjs.org/downloads/point/last-week/{package}")
        downloads = downloads_res.json().get("downloads", 0) if downloads_res.status_code == 200 else 0

        gh_repo = None
        if repo_path:
            gh_res = await client.get(f"https://api.github.com/repos/{repo_path}", headers={"User-Agent": "ash-ops-x402-catalog"})
            gh_repo = gh_res.json() if gh_res.status_code == 200 else None

        vuln_res = await client.post(
            "https://api.osv.dev/v1/query",
            json={"package": {"name": package, "ecosystem": "npm"}},
        )
        vulns = [v["id"] for v in vuln_res.json().get("vulns", [])] if vuln_res.status_code == 200 else []

    result = score_npm_signals(age_days, downloads, gh_repo, vulns)
    return {
        "package": package,
        **result,
        "signals": {
            "npm": {"ageInDays": age_days, "latestVersion": latest_version, "weeklyDownloads": downloads},
            "github": (
                {
                    "org": gh_repo.get("owner", {}).get("login"),
                    "isOrg": gh_repo.get("owner", {}).get("type") == "Organization",
                    "stars": gh_repo.get("stargazers_count"),
                    "forks": gh_repo.get("forks_count"),
                    "archived": gh_repo.get("archived"),
                    "createdAt": gh_repo.get("created_at"),
                }
                if gh_repo
                else None
            ),
            "vulnerabilities": {"count": len(vulns), "ids": vulns},
        },
    }


@app.get("/api/repo-health")
async def repo_health(repo: str) -> dict[str, Any]:
    if not repo or not re.match(r"^[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+$", repo):
        raise HTTPException(status_code=400, detail="repo query param is required, format: owner/repo")

    async with httpx.AsyncClient(timeout=10) as client:
        gh_res = await client.get(f"https://api.github.com/repos/{repo}", headers={"User-Agent": "ash-ops-x402-catalog"})
        if gh_res.status_code != 200:
            raise HTTPException(status_code=404, detail=f"GitHub repo '{repo}' not found")
        gh = gh_res.json()

        commits_res = await client.get(
            f"https://api.github.com/repos/{repo}/commits",
            headers={"User-Agent": "ash-ops-x402-catalog"},
            params={"per_page": 1},
        )
        last_commit_date = None
        last_commit_age_days = None
        if commits_res.status_code == 200 and commits_res.json():
            last_commit_date = commits_res.json()[0]["commit"]["committer"]["date"]
            commit_dt = datetime.fromisoformat(last_commit_date.replace("Z", "+00:00"))
            last_commit_age_days = (datetime.now(timezone.utc) - commit_dt).days

    score = 50
    reasons = []
    if gh.get("archived"):
        score -= 40
        reasons.append("repository is archived")
    if last_commit_age_days is not None:
        if last_commit_age_days < 30:
            score += 20
            reasons.append("committed to within last 30 days")
        elif last_commit_age_days > 365:
            score -= 20
            reasons.append("no commits in over a year")
    if gh.get("stargazers_count", 0) > 500:
        score += 15
        reasons.append("500+ stars")
    if gh.get("open_issues_count", 0) > 200:
        score -= 10
        reasons.append("large open-issues backlog (200+)")
    if not gh.get("license"):
        score -= 10
        reasons.append("no license file detected")
    score = max(0, min(100, score))
    verdict = "healthy" if score >= 70 else "moderate" if score >= 40 else "concerning"

    return {
        "repo": repo,
        "score": score,
        "verdict": verdict,
        "reasons": reasons,
        "signals": {
            "stars": gh.get("stargazers_count"),
            "forks": gh.get("forks_count"),
            "openIssues": gh.get("open_issues_count"),
            "archived": gh.get("archived"),
            "license": (gh.get("license") or {}).get("spdx_id"),
            "lastCommitDate": last_commit_date,
            "lastCommitAgeDays": last_commit_age_days,
            "createdAt": gh.get("created_at"),
        },
    }


@app.get("/api/domain-check")
async def domain_check(domain: str) -> dict[str, Any]:
    if not domain or not re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", domain):
        raise HTTPException(status_code=400, detail="domain query param is required, e.g. example.com")

    import dns.resolver  # dnspython, pulled in as an x402 transitive dep

    records: dict[str, list[str]] = {}
    for rtype in ["A", "MX", "NS", "TXT"]:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=5)
            records[rtype] = [str(r) for r in answers]
        except Exception:
            records[rtype] = []

    http_reachable = False
    async with httpx.AsyncClient(timeout=5, follow_redirects=True) as client:
        try:
            resp = await client.get(f"https://{domain}")
            http_reachable = resp.status_code < 500
        except Exception:
            http_reachable = False

    has_mail_routing = len(records["MX"]) > 0
    has_web_presence = len(records["A"]) > 0

    return {
        "domain": domain,
        "hasMailRouting": has_mail_routing,
        "hasWebPresence": has_web_presence,
        "httpReachable": http_reachable,
        "records": records,
        "verdict": (
            "fully live" if has_mail_routing and has_web_presence and http_reachable
            else "partially live" if has_web_presence or has_mail_routing
            else "no DNS records — domain not currently routing anything"
        ),
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 4021)))
