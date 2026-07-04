import os
import time
import uuid
import json
import jwt
import redis
from collections import deque
from typing import List, Optional
from fastapi import FastAPI, Query, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel

ALLOWED_ORIGIN = "https://dash-un67xt.example.com"
EMAIL = "23f1002129@ds.study.iitm.ac.in"

ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-srbm9zpw.apps.exam.local"
PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----"""

# --- Config layers ---
DEFAULTS = {
    "port": 8000,
    "workers": 1,
    "debug": False,
    "log_level": "info",
    "api_key": "default-secret-000",
}

YAML_CONFIG = {
    "port": 8010,
    "log_level": "error",
}

DOTENV_CONFIG = {
    "api_key": "key-c7mqw14dix",
}

OS_ENV_CONFIG = {
    "port": 8534,
    "debug": True,
    "api_key": "key-nm26acxljq",
}


def coerce_value(key: str, value) -> object:
    if key in ("port", "workers"):
        return int(value)
    if key == "debug":
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in ("true", "1", "yes", "on")
    return str(value)

app = FastAPI()

# --- Observability state ---
STARTUP_TIME = time.time()
http_requests_total = 0
log_buffer = deque(maxlen=1000)


@app.middleware("http")
async def observability_middleware(request: Request, call_next):
    global http_requests_total
    http_requests_total += 1

    req_id = str(uuid.uuid4())
    response = await call_next(request)

    log_entry = {
        "level": "info",
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "path": request.url.path,
        "request_id": req_id,
        "method": request.method,
    }
    log_buffer.append(log_entry)

    return response


PING_ALLOWED_ORIGIN = "https://app-9e2p1y.example.com"
PING_RATE_LIMIT = 12
PING_RATE_WINDOW = 10
ping_rate_buckets = {}


@app.middleware("http")
async def cors_middleware(request: Request, call_next):
    origin = request.headers.get("origin", "")
    path = request.url.path

    if request.method == "OPTIONS":
        if path == "/stats":
            if origin == ALLOWED_ORIGIN:
                return Response(
                    status_code=200,
                    headers={
                        "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
                        "Access-Control-Allow-Methods": "GET, OPTIONS",
                        "Access-Control-Allow-Headers": "*",
                        "Access-Control-Max-Age": "600",
                    },
                )
            else:
                return Response(status_code=400, content="Disallowed CORS origin")
        elif path == "/ping":
            if origin == PING_ALLOWED_ORIGIN:
                return Response(
                    status_code=200,
                    headers={
                        "Access-Control-Allow-Origin": PING_ALLOWED_ORIGIN,
                        "Access-Control-Allow-Methods": "GET, OPTIONS",
                        "Access-Control-Allow-Headers": "*",
                        "Access-Control-Max-Age": "600",
                    },
                )
            else:
                return Response(status_code=400, content="Disallowed CORS origin")
        else:
            return Response(
                status_code=200,
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                    "Access-Control-Allow-Headers": "*",
                    "Access-Control-Max-Age": "600",
                },
            )

    response = await call_next(request)

    if path == "/stats":
        if origin == ALLOWED_ORIGIN:
            response.headers["Access-Control-Allow-Origin"] = ALLOWED_ORIGIN
    elif path == "/ping":
        if origin == PING_ALLOWED_ORIGIN:
            response.headers["Access-Control-Allow-Origin"] = PING_ALLOWED_ORIGIN
    else:
        response.headers["Access-Control-Allow-Origin"] = "*"

    return response


@app.middleware("http")
async def add_custom_headers(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    process_time = time.perf_counter() - start
    if "X-Request-ID" not in response.headers:
        response.headers["X-Request-ID"] = str(uuid.uuid4())
    response.headers["X-Process-Time"] = f"{process_time:.6f}"
    return response


@app.get("/stats")
async def stats(values: str = Query(...)):
    nums = [int(v.strip()) for v in values.split(",") if v.strip()]
    return {
        "email": EMAIL,
        "count": len(nums),
        "sum": sum(nums),
        "min": min(nums),
        "max": max(nums),
        "mean": sum(nums) / len(nums),
    }


class TokenRequest(BaseModel):
    token: str


@app.post("/verify")
async def verify(request: Request):
    try:
        body = await request.json()
        token = body.get("token", "")
    except Exception:
        return JSONResponse(status_code=401, content={"valid": False})

    try:
        payload = jwt.decode(
            token,
            PUBLIC_KEY,
            algorithms=["RS256"],
            issuer=ISSUER,
            audience=AUDIENCE,
            options={"require": ["exp", "iss", "aud"]},
        )
        return JSONResponse(
            status_code=200,
            content={
                "valid": True,
                "email": payload.get("email", ""),
                "sub": payload.get("sub", ""),
                "aud": payload.get("aud", ""),
            },
        )
    except Exception:
        return JSONResponse(
            status_code=401,
            content={"valid": False},
        )


@app.get("/effective-config")
async def effective_config(request: Request, set: Optional[List[str]] = Query(None)):
    config = dict(DEFAULTS)

    for k, v in YAML_CONFIG.items():
        config[k] = v

    for k, v in DOTENV_CONFIG.items():
        config[k] = v

    for k, v in OS_ENV_CONFIG.items():
        config[k] = v

    if set:
        for override in set:
            if "=" in override:
                key, value = override.split("=", 1)
                key = key.strip()
                if key == "NUM_WORKERS":
                    key = "workers"
                config[key] = value

    result = {}
    for key in DEFAULTS:
        result[key] = coerce_value(key, config[key])

    result["api_key"] = "****"

    return result


# --- Redis-backed endpoints ---
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")
redis_client = redis.from_url(REDIS_URL, decode_responses=True)


@app.post("/hit/{key}")
async def hit(key: str):
    count = redis_client.incr(key)
    return {"key": key, "count": count}


@app.get("/count/{key}")
async def count(key: str):
    val = redis_client.get(key)
    return {"key": key, "count": int(val) if val else 0}


@app.get("/healthz")
async def healthz_main():
    uptime = time.time() - STARTUP_TIME
    try:
        redis_client.ping()
        redis_status = "up"
    except Exception:
        redis_status = "down"
    return {"status": "ok", "uptime_s": round(uptime, 2), "redis": redis_status}


@app.get("/redis-healthz")
async def redis_healthz():
    try:
        redis_client.ping()
        return {"status": "ok", "redis": "up"}
    except Exception:
        return JSONResponse(status_code=503, content={"status": "error", "redis": "down"})


# --- Analytics endpoint ---
API_KEY = "ak_3v2w1mj5jqijqlrtsr05z72v"


@app.post("/analytics")
async def analytics(request: Request):
    key = request.headers.get("X-API-Key", "")
    if key != API_KEY:
        return JSONResponse(status_code=401, content={"error": "Unauthorized"})

    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid JSON"})

    events = body.get("events", [])
    total_events = len(events)
    unique_users = len(set(e["user"] for e in events))

    revenue = sum(e["amount"] for e in events if e["amount"] > 0)

    user_totals = {}
    for e in events:
        if e["amount"] > 0:
            user_totals[e["user"]] = user_totals.get(e["user"], 0) + e["amount"]

    top_user = max(user_totals, key=user_totals.get) if user_totals else ""

    return {
        "email": EMAIL,
        "total_events": total_events,
        "unique_users": unique_users,
        "revenue": revenue,
        "top_user": top_user,
    }


# --- Prometheus & Observability endpoints ---
@app.get("/work")
async def work(n: int = Query(1)):
    return {"email": EMAIL, "done": n}


@app.get("/metrics")
async def metrics():
    body = (
        "# HELP http_requests_total Total HTTP requests\n"
        "# TYPE http_requests_total counter\n"
        f"http_requests_total {http_requests_total}\n"
    )
    return PlainTextResponse(content=body, media_type="text/plain; version=0.0.4")


@app.get("/logs/tail")
async def logs_tail(limit: int = Query(10)):
    entries = list(log_buffer)[-limit:]
    return entries


# --- OpenAI-compatible chat completions (fake LLM) ---
import re


@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid JSON"})

    messages = body.get("messages", [])
    user_msg = ""
    for m in reversed(messages):
        if m.get("role") == "user":
            user_msg = m.get("content", "")
            break

    answer = generate_answer(user_msg)

    return {
        "id": f"chatcmpl-{uuid.uuid4().hex[:12]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": body.get("model", "fake-llm"),
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": answer},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }


def generate_answer(prompt: str) -> str:
    token_match = re.search(r"(TK[0-9a-fA-F]{6})", prompt)
    if token_match:
        return f"Here is the token: {token_match.group(1)}"

    arith_match = re.search(r"[Ww]hat is (\d+)\s*[\+\+]\s*(\d+)", prompt)
    if arith_match:
        a, b = int(arith_match.group(1)), int(arith_match.group(2))
        return f"The answer is {a + b}."

    arith_match2 = re.search(r"(\d+)\s*[\+\+]\s*(\d+)", prompt)
    if arith_match2:
        a, b = int(arith_match2.group(1)), int(arith_match2.group(2))
        return f"{a + b}"

    return f"I received your message: {prompt}"


# --- Orders API: idempotency, pagination, rate limiting ---
import base64

TOTAL_ORDERS = 60
RATE_LIMIT = 16
RATE_WINDOW = 10

orders_catalog = [{"id": i, "item": f"order-{i}", "status": "completed"} for i in range(1, TOTAL_ORDERS + 1)]
idempotency_store = {}
rate_limit_buckets = {}


@app.post("/orders")
async def create_order(request: Request):
    client_id = request.headers.get("X-Client-Id", "default")
    if not _check_rate_limit(client_id):
        return JSONResponse(
            status_code=429,
            content={"error": "Rate limit exceeded"},
            headers={"Retry-After": "10"},
        )

    idem_key = request.headers.get("Idempotency-Key", "")

    if idem_key and idem_key in idempotency_store:
        return JSONResponse(status_code=201, content=idempotency_store[idem_key])

    try:
        body = await request.json()
    except Exception:
        body = {}

    order_id = str(uuid.uuid4())
    order = {"id": order_id, "item": body.get("item", "unknown"), "status": "created"}

    if idem_key:
        idempotency_store[idem_key] = order

    return JSONResponse(status_code=201, content=order)


@app.get("/orders")
async def list_orders(request: Request, limit: int = Query(10), cursor: Optional[str] = Query(None)):
    client_id = request.headers.get("X-Client-Id", "default")
    if not _check_rate_limit(client_id):
        return JSONResponse(
            status_code=429,
            content={"error": "Rate limit exceeded"},
            headers={"Retry-After": "10"},
        )

    start = 0
    if cursor:
        try:
            start = int(base64.b64decode(cursor).decode())
        except Exception:
            start = 0

    end = min(start + limit, TOTAL_ORDERS)
    items = orders_catalog[start:end]

    next_cursor = None
    if end < TOTAL_ORDERS:
        next_cursor = base64.b64encode(str(end).encode()).decode()

    return {"items": items, "next_cursor": next_cursor}


def _check_rate_limit(client_id: str) -> bool:
    now = time.time()
    if client_id not in rate_limit_buckets:
        rate_limit_buckets[client_id] = []

    bucket = rate_limit_buckets[client_id]
    window_start = now - RATE_WINDOW
    rate_limit_buckets[client_id] = [t for t in bucket if t > window_start]

    if len(rate_limit_buckets[client_id]) >= RATE_LIMIT:
        return False

    rate_limit_buckets[client_id].append(now)
    return True


# --- /ping endpoint with request context + rate limiting ---
def _check_ping_rate_limit(client_id: str) -> bool:
    now = time.time()
    if client_id not in ping_rate_buckets:
        ping_rate_buckets[client_id] = []

    window_start = now - PING_RATE_WINDOW
    ping_rate_buckets[client_id] = [t for t in ping_rate_buckets[client_id] if t > window_start]

    if len(ping_rate_buckets[client_id]) >= PING_RATE_LIMIT:
        return False

    ping_rate_buckets[client_id].append(now)
    return True


@app.get("/ping")
async def ping(request: Request):
    client_id = request.headers.get("X-Client-Id", "default")
    if not _check_ping_rate_limit(client_id):
        return JSONResponse(
            status_code=429,
            content={"error": "Rate limit exceeded"},
            headers={"Retry-After": "10"},
        )

    req_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())

    return JSONResponse(
        status_code=200,
        content={"email": EMAIL, "request_id": req_id},
        headers={"X-Request-ID": req_id},
    )
