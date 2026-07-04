import os
import time
import uuid
import jwt
from typing import List, Optional
from fastapi import FastAPI, Query, Request, Response
from fastapi.responses import JSONResponse
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
    else:
        response.headers["Access-Control-Allow-Origin"] = "*"

    return response


@app.middleware("http")
async def add_custom_headers(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    process_time = time.perf_counter() - start
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
