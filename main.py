"""
Ash Ops x402 API Catalog
A real, multi-endpoint x402-paid API — not a single isolated listing.
Endpoints:
  GET /api/trust-check   - npm package trust/risk score (ported from agent-trust-api)
  GET /api/repo-health   - GitHub repo health check
  GET /api/domain-check  - domain DNS/registration liveness check
  GET /api/x402-doctor   - audits ANOTHER x402 service for the exact failure modes
                           we personally diagnosed and fixed on this service tonight
$0.02 USDC/call for the first 3; $1.00 for x402-doctor. All on Base mainnet via x402.
"""
import base64
import json
import os
import re
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse, HTMLResponse, PlainTextResponse

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
        description="npm package trust check / risk score / security audit: registry age, weekly downloads, GitHub org/stars, OSV.dev vulnerabilities, typosquat detection.",
        service_name="npm Trust Check",
        tags=["npm", "security", "trust-score", "trust-check", "audit", "verify", "due-diligence", "typosquat", "supply-chain"],
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
        description="GitHub repo health check / audit / verify: stars, forks, open issues, last commit age, archived status, license.",
        service_name="GitHub Repo Health",
        tags=["github", "code-quality", "due-diligence", "repo-check", "audit", "verify", "trust"],
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
        description="Domain liveness check / verify / audit: DNS resolution (A/MX/NS/TXT records), whether mail routing exists, HTTP reachability.",
        service_name="Domain Liveness Check",
        tags=["dns", "domain", "due-diligence", "domain-check", "audit", "verify", "liveness"],
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
    "GET /api/x402-doctor": RouteConfig(
        accepts=[PaymentOption(scheme="exact", pay_to=PAY_TO, price="$1.00", network=EVM_NETWORK)],
        mime_type="application/json",
        description=(
            "Audits another x402 service for the exact failure modes that cause aggregators "
            "(agent-tools.cloud, x402scan, Bazaar) to mark it 'down' or make its 402 challenge "
            "unreadable: missing/invalid /.well-known/x402 descriptor, an unpaid request "
            "returning 500/404 instead of a clean 402, a malformed or missing payment-required "
            "challenge, and drift between the descriptor's advertised terms and the live "
            "challenge. Returns a concrete diagnosis and fix for each failing check, not just "
            "pass/fail."
        ),
        service_name="x402 Doctor",
        tags=["x402", "diagnostics", "devtools"],
        extensions=declare_discovery_extension(
            input={"url": "https://example-service.onrender.com", "path": "/api/some-paid-endpoint"},
            input_schema={
                "properties": {
                    "url": {"type": "string", "description": "base URL of the x402 service to audit"},
                    "path": {"type": "string", "description": "a specific paid endpoint path to probe; omit to auto-discover from the service's /.well-known/x402"},
                },
                "required": ["url"],
            },
            output=OutputConfig(
                example={"url": "https://example-service.onrender.com", "score": 40, "verdict": "broken: aggregators will show this as down", "checks": [], "fixes": []},
                schema={"properties": {"url": {"type": "string"}, "score": {"type": "number"}, "verdict": {"type": "string"}}},
            ),
        ),
    ),
}

app.add_middleware(PaymentMiddlewareASGI, routes=routes, server=server)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


_HOMEPAGE_PATH = os.path.join(os.path.dirname(__file__), "homepage.html")
with open(_HOMEPAGE_PATH, encoding="utf-8") as _f:
    _HOMEPAGE_HTML = _f.read()


@app.get("/", response_class=HTMLResponse)
async def root() -> str:
    """A real landing page, not a 404. Several of our own listings (awesome-x402 PR, README,
    outreach emails) link people straight to the bare base URL. A human doing diligence before
    trusting an autonomous payment API should see something real, not 'Not Found' or bare JSON."""
    return _HOMEPAGE_HTML


@app.get("/robots.txt", response_class=PlainTextResponse)
async def robots() -> str:
    return "User-agent: *\nAllow: /\nSitemap: https://x402-api-catalog.onrender.com/sitemap.xml\n"


@app.get("/sitemap.xml", response_class=PlainTextResponse)
async def sitemap() -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        "  <url><loc>https://x402-api-catalog.onrender.com/</loc></url>\n"
        "</urlset>\n"
    )


@app.get("/api", response_class=JSONResponse)
async def api_summary() -> dict[str, Any]:
    """Machine-readable equivalent of the homepage, for anything that wants JSON at a stable path
    instead of parsing HTML."""
    return {
        "name": "x402 API Catalog",
        "description": "Four real x402 (HTTP 402 micropayment) APIs on Base mainnet. No signup, pay per call in USDC.",
        "docs": "https://github.com/hkaaki/x402-api-catalog",
        "discovery": "https://x402-api-catalog.onrender.com/.well-known/x402",
        "endpoints": {
            "GET /api/trust-check": "$0.02 - npm package trust/risk check",
            "GET /api/repo-health": "$0.02 - GitHub repo health check",
            "GET /api/domain-check": "$0.02 - domain liveness check",
            "GET /api/x402-doctor": "$1.00 - audit another x402 service",
        },
    }


USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"  # native USDC on Base mainnet
BASE_URL = "https://x402-api-catalog.onrender.com"


def _price_to_atomic_units(price: str) -> str:
    """'$1.00' -> '1000000' (USDC has 6 decimals). Real per-route price, not a hardcoded $0.02."""
    dollars = float(price.lstrip("$"))
    return str(round(dollars * 1_000_000))


def _resource_descriptor(path: str) -> dict[str, Any]:
    route = routes[f"GET {path}"]
    opt = route.accepts[0]
    return {
        "resource": f"{BASE_URL}{path}",
        "type": "http",
        "method": "GET",
        "description": route.description,
        "accepts": [
            {
                "scheme": "exact",
                "network": EVM_NETWORK,
                "asset": USDC_BASE,
                "amount": _price_to_atomic_units(opt.price),
                "payTo": PAY_TO,
                "maxTimeoutSeconds": 60,
            }
        ],
    }


@app.get("/.well-known/x402")
async def well_known_x402() -> dict[str, Any]:
    """x402 discovery descriptor — required by directories/aggregators (agent-tools.cloud,
    x402scan, Bazaar) that probe this well-known path to verify liveness and list pricing.
    Its absence (404) is what was marking this service "down" in third-party directories."""
    return {
        "x402Version": 1,
        "resources": [
            _resource_descriptor("/api/trust-check"),
            _resource_descriptor("/api/repo-health"),
            _resource_descriptor("/api/domain-check"),
            _resource_descriptor("/api/x402-doctor"),
        ],
    }


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
            "/api/x402-doctor": {
                "get": {
                    "operationId": "x402Doctor",
                    "summary": routes["GET /api/x402-doctor"].description,
                    "tags": ["Diagnostics"],
                    **_payment_info_block("1.000000"),
                    "parameters": [
                        {"name": "url", "in": "query", "required": True, "schema": {"type": "string"}},
                        {"name": "path", "in": "query", "required": False, "schema": {"type": "string"}},
                    ],
                }
            },
        },
    }


# A curated set of high-value, frequently-typosquatted npm packages — the real, well-documented
# attack: publish "lodahs" or "expres" hoping a mistyped install pulls malicious code instead of
# the real package. Comparing against a short, high-value list (not all 2M+ npm packages) keeps
# this fast and avoids false positives on obscure-but-legitimate names.
POPULAR_PACKAGES = {
    "react", "vue", "angular", "express", "lodash", "axios", "chalk", "commander", "webpack",
    "babel", "eslint", "jest", "mocha", "request", "moment", "uuid", "debug", "colors",
    "minimist", "yargs", "glob", "semver", "dotenv", "cors", "body-parser", "mongoose",
    "sequelize", "prisma", "next", "nuxt", "svelte", "tailwindcss", "typescript", "jquery",
    "bootstrap", "redux", "mobx", "rxjs", "socket.io", "ws", "node-fetch", "form-data",
    "multer", "passport", "jsonwebtoken", "bcrypt", "nodemailer", "sharp", "puppeteer",
    "playwright", "cypress", "vitest", "prettier", "husky", "lint-staged", "vite", "rollup",
    "esbuild", "postcss", "sass", "less", "underscore", "async", "bluebird", "rxjs", "immer",
    "zod", "yup", "joi", "ajv", "nock", "sinon", "chai", "supertest", "nodemon", "pm2",
    "winston", "pino", "morgan", "helmet", "compression", "cookie-parser", "express-session",
    "npm", "yarn", "pnpm", "left-pad", "is-odd", "is-even", "chalk", "figlet", "inquirer",
}


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            curr[j] = min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + (ca != cb))
        prev = curr
    return prev[-1]


def check_typosquat(package: str, downloads: int) -> dict | None:
    """Flag when `package` is a near-miss (edit distance 1-2) of a much more popular package
    and isn't already a well-known name itself — the classic typosquat shape. Real, free,
    deterministic; nobody else in the npm-checker space we found tonight does this."""
    if package.lower() in POPULAR_PACKAGES:
        return None
    for target in POPULAR_PACKAGES:
        dist = _levenshtein(package.lower(), target)
        if 0 < dist <= 2 and len(target) > 3:
            return {
                "likely_typosquat_of": target,
                "edit_distance": dist,
                "warning": f"'{package}' is very close to the much more popular package '{target}'. Verify this is the package you actually meant to install before trusting it.",
            }
    return None


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
    typosquat = check_typosquat(package, downloads)
    if typosquat:
        result["score"] = max(0, result["score"] - 40)
        result["verdict"] = "high risk"
        result["reasons"].append(f"possible typosquat of '{typosquat['likely_typosquat_of']}'")

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
            "typosquat": typosquat,
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
            else "no DNS records, domain not currently routing anything"
        ),
    }


REQUIRED_ACCEPT_FIELDS = ["scheme", "network", "asset", "amount", "payTo"]


def _add_check(checks: list[dict], name: str, passed: bool, detail: str, fix: str | None = None) -> None:
    checks.append({"check": name, "passed": passed, "detail": detail, "fix": (None if passed else fix)})


def _describe_exception(e: Exception) -> str:
    """httpx's connection errors (ConnectTimeout, ConnectError) frequently have an empty str(e) —
    fall back to the exception type name so the diagnosis is actually readable."""
    return str(e) or type(e).__name__


def _extract_challenge(res: httpx.Response) -> dict | None:
    """The 402 challenge lands in different places depending on implementation: some services
    (e.g. x402-list.com) put accepts[] directly in the JSON body; others (the CDP facilitator's
    own v2 middleware — confirmed on our own service tonight) return an empty body and carry
    the whole challenge, base64-encoded, in a payment-required (or X-PAYMENT-REQUIRED) header.
    A real doctor has to check both, or it wrongly fails every v2-style service."""
    try:
        body = res.json()
    except Exception:
        body = None
    if isinstance(body, dict) and isinstance(body.get("accepts"), list) and body["accepts"]:
        return body

    header_val = res.headers.get("payment-required") or res.headers.get("x-payment-required")
    if header_val:
        try:
            padded = header_val + "=" * (-len(header_val) % 4)
            decoded = json.loads(base64.b64decode(padded))
            if isinstance(decoded, dict) and isinstance(decoded.get("accepts"), list):
                return decoded
        except Exception:
            pass
    return body if isinstance(body, dict) else None


@app.get("/api/x402-doctor")
async def x402_doctor(url: str, path: str | None = None) -> dict[str, Any]:
    if not url or not re.match(r"^https?://", url):
        raise HTTPException(status_code=400, detail="url query param is required and must start with http:// or https://")
    base = url.rstrip("/")
    checks: list[dict] = []
    descriptor: dict | None = None
    candidate_path = path

    # Check 1: /.well-known/x402 exists and is valid.
    async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
        try:
            wk_res = await client.get(f"{base}/.well-known/x402")
        except Exception as e:
            _add_check(
                checks, "well_known_descriptor", False,
                f"Could not reach {base}/.well-known/x402: {_describe_exception(e)}",
                "Confirm the service is actually running and reachable at this base URL, and that DNS/TLS are correctly configured.",
            )
            wk_res = None

        if wk_res is not None:
            if wk_res.status_code != 200:
                _add_check(
                    checks, "well_known_descriptor", False,
                    f"GET /.well-known/x402 returned HTTP {wk_res.status_code}, expected 200.",
                    "Add a /.well-known/x402 route returning {\"x402Version\": 1, \"resources\": [...]}. "
                    "Its absence is why most directory aggregators mark a working service 'down'. "
                    "this was the exact bug found on our own service earlier tonight.",
                )
            else:
                try:
                    descriptor = wk_res.json()
                except Exception:
                    descriptor = None
                if descriptor is None:
                    _add_check(
                        checks, "well_known_descriptor", False,
                        "GET /.well-known/x402 returned HTTP 200 but the body is not valid JSON.",
                        "Return a JSON body: {\"x402Version\": 1, \"resources\": [...]}.",
                    )
                elif not isinstance(descriptor.get("resources"), list) or not descriptor["resources"]:
                    _add_check(
                        checks, "well_known_descriptor", False,
                        "Descriptor is valid JSON but has no non-empty \"resources\" array.",
                        "List every paid endpoint under \"resources\", each with resource/type/method/accepts.",
                    )
                else:
                    _add_check(checks, "well_known_descriptor", True, f"Valid descriptor with {len(descriptor['resources'])} resource(s).")
                    if not candidate_path:
                        first = descriptor["resources"][0]
                        # Two real shapes seen in production: an object with a "resource" field
                        # (our own convention), or a bare URL string (stableenrich.dev's, and
                        # apparently common) — never assume either without checking.
                        res_url = first.get("resource", "") if isinstance(first, dict) else (first if isinstance(first, str) else "")
                        candidate_path = res_url[len(base):] if res_url and res_url.startswith(base) else None

    # Check 2: the actual paid endpoint returns a clean 402, not 500/404/200.
    challenge_body: dict | None = None
    if not candidate_path:
        _add_check(
            checks, "unpaid_request_returns_402", False,
            "No endpoint path to probe. Pass ?path=/your/endpoint or fix the descriptor so one can be auto-discovered.",
            "Pass the path param explicitly, or fix the well-known descriptor's resources[0].resource.",
        )
    else:
        probe_url = f"{base}{candidate_path}"
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            try:
                probe_res = await client.get(probe_url)
            except Exception as e:
                _add_check(checks, "unpaid_request_returns_402", False, f"Could not reach {probe_url}: {_describe_exception(e)}", "Confirm the endpoint path is correct and the service is reachable.")
                probe_res = None

            # A 405 on GET often just means the route is POST-only (a normal REST pattern for
            # search/enrich-style endpoints that take a body) — confirmed live against
            # stableenrich.dev, a real, healthy service that correctly 402s on POST. Always
            # retry with POST on a 405 rather than gating on an Allow header: many real
            # deployments (this one included, fronted by Vercel) don't send one at all, so
            # gating on it silently skips the retry that would have proven the service fine.
            if probe_res is not None and probe_res.status_code == 405:
                async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client2:
                    try:
                        probe_res = await client2.post(probe_url, json={})
                    except Exception as e:
                        _add_check(checks, "unpaid_request_returns_402", False, f"Could not reach {probe_url} via POST: {_describe_exception(e)}")
                        probe_res = None

            if probe_res is not None:
                if probe_res.status_code == 402:
                    _add_check(checks, "unpaid_request_returns_402", True, f"{candidate_path} correctly returned HTTP 402.")
                    challenge_body = _extract_challenge(probe_res)
                elif probe_res.status_code == 405:
                    _add_check(
                        checks, "unpaid_request_returns_402", False,
                        f"GET {candidate_path} returned HTTP 405 (Method Not Allowed) and a POST retry didn't resolve to 402 either.",
                        "This check currently only probes GET/POST. If this endpoint uses a different "
                        "method, this result is inconclusive rather than a confirmed bug. Pass the "
                        "correct method's path, or verify manually.",
                    )
                elif probe_res.status_code == 500:
                    _add_check(
                        checks, "unpaid_request_returns_402", False,
                        f"GET {candidate_path} returned HTTP 500 instead of 402.",
                        "A 500 on an unpaid request almost always means the facilitator client failed to "
                        "initialize. Check CDP_API_KEY_ID/CDP_API_KEY_SECRET (or equivalent) are current, "
                        "not stale/rotated credentials. This exact bug hit our own production service "
                        "tonight: a stale key caused every unpaid request to 500 instead of challenging "
                        "for payment, invisible unless you read the service's own logs.",
                    )
                elif probe_res.status_code == 404:
                    _add_check(
                        checks, "unpaid_request_returns_402", False,
                        f"GET {candidate_path} returned HTTP 404.",
                        "Either the path is wrong, or the route isn't actually registered under the "
                        "payment middleware. Confirm the path matches exactly (including any /api prefix) "
                        "what's advertised in /.well-known/x402.",
                    )
                else:
                    _add_check(
                        checks, "unpaid_request_returns_402", False,
                        f"GET {candidate_path} returned HTTP {probe_res.status_code}, expected 402.",
                        "An unpaid request to a payment-gated route must return exactly 402 Payment Required.",
                    )

    # Check 3: the 402 challenge itself is well-formed.
    if challenge_body is not None:
        accepts = challenge_body.get("accepts")
        if not isinstance(accepts, list) or not accepts:
            _add_check(
                checks, "challenge_well_formed", False,
                "402 response body has no non-empty \"accepts\" array.",
                "The 402 body must include accepts: [{scheme, network, asset, amount, payTo, ...}].",
            )
        else:
            missing = [f for f in REQUIRED_ACCEPT_FIELDS if f not in accepts[0]]
            if missing:
                _add_check(
                    checks, "challenge_well_formed", False,
                    f"accepts[0] is missing required field(s): {', '.join(missing)}.",
                    f"Every accepts[] entry needs: {', '.join(REQUIRED_ACCEPT_FIELDS)}.",
                )
            else:
                _add_check(checks, "challenge_well_formed", True, "accepts[0] has every required field.")

    # Check 4: descriptor and live challenge agree (catches config drift after a redeploy).
    # Skipped entirely for descriptors that list bare resource-URL strings (no per-resource
    # accepts[] to compare against) — that shape has nothing for this check to verify.
    if descriptor and challenge_body and candidate_path:
        desc_accepts = None
        for r in descriptor.get("resources", []):
            if isinstance(r, dict) and r.get("resource", "").endswith(candidate_path):
                desc_accepts = (r.get("accepts") or [{}])[0]
                break
        live_accepts = (challenge_body.get("accepts") or [{}])[0]
        if desc_accepts is not None:
            drift = [
                f for f in ["payTo", "asset", "network"]
                if desc_accepts.get(f) and live_accepts.get(f) and str(desc_accepts.get(f)).lower() != str(live_accepts.get(f)).lower()
            ]
            if drift:
                _add_check(
                    checks, "descriptor_matches_live_challenge", False,
                    f"Descriptor and live 402 challenge disagree on: {', '.join(drift)}.",
                    "Redeploy so /.well-known/x402 reflects the same payTo/asset/network the live "
                    "route actually uses. Aggregators trust the descriptor and will show buyers "
                    "stale terms if it drifts from reality.",
                )
            else:
                _add_check(checks, "descriptor_matches_live_challenge", True, "Descriptor matches the live challenge.")

    passed_count = sum(1 for c in checks if c["passed"])
    score = round(100 * passed_count / len(checks)) if checks else 0
    verdict = (
        "healthy: should show correctly on aggregators" if score == 100
        else "partially broken: some buyers or aggregators will fail" if score >= 50
        else "broken: aggregators will very likely mark this service down"
    )
    return {
        "url": base,
        "probed_path": candidate_path,
        "score": score,
        "verdict": verdict,
        "checks": checks,
        "fixes": [c["fix"] for c in checks if not c["passed"] and c["fix"]],
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 4021)))
