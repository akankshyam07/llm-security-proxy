"""FastAPI proxy application with detector and policy enforcement."""
from __future__ import annotations

import time
import uuid
from collections.abc import AsyncGenerator
from typing import Any
from urllib.parse import urljoin

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse

from app.config import Settings, get_settings
from app.logging import LOGGER, redact_payload
from app.policies.engine import PolicyEngine


async def lifespan(app: FastAPI):
    settings = get_settings()
    app.state.http_client = httpx.AsyncClient(
        base_url=str(settings.upstream_base_url),
        timeout=settings.request_timeout,
    )
    yield
    await app.state.http_client.aclose()


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    policy_engine = PolicyEngine(policy_path=settings.policy_path)

    app = FastAPI(title=settings.app_name, lifespan=lifespan)

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request, settings: Settings = Depends(get_settings)):  # noqa: B008
        request_id = str(uuid.uuid4())
        payload: dict[str, Any] = await request.json()

        decision = policy_engine.evaluate_request(payload, request_id=request_id)

        if not decision.allowed:
            LOGGER.warning(
                "request_blocked",
                extra={
                    "extra_fields": {
                        "request_id": request_id,
                        "reason_codes": decision.reason_codes,
                        "decision": "blocked",
                        "latency_ms": decision.latency_ms,
                        "upstream": str(settings.upstream_base_url),
                        "payload": redact_payload(payload),
                    }
                },
            )
            return JSONResponse(
                status_code=403,
                content={
                    "error": {
                        "codes": decision.reason_codes,
                        "message": "Request blocked by security policy",
                        "request_id": request_id,
                        "reasons": [finding.message for finding in decision.reasons],
                    }
                },
            )

        try:
            client: httpx.AsyncClient = request.app.state.http_client
        except AttributeError:
            raise HTTPException(status_code=500, detail="HTTP client unavailable") from None

        forward_headers = {
            key: value
            for key, value in request.headers.items()
            if key.lower() not in {"host", "content-length"}
        }

        upstream_url = urljoin(
            str(settings.upstream_base_url) + "/", settings.upstream_path.lstrip("/")
        )

        # --- Streaming path ---
        if payload.get("stream"):
            async def stream_upstream() -> AsyncGenerator[bytes, None]:
                try:
                    async with client.stream(
                        "POST",
                        settings.upstream_path,
                        json=payload,
                        headers=forward_headers,
                    ) as upstream:
                        async for chunk in upstream.aiter_bytes():
                            yield chunk
                except httpx.HTTPError as exc:
                    LOGGER.error(
                        "upstream_error",
                        extra={
                            "extra_fields": {
                                "request_id": request_id,
                                "decision": "error",
                                "error": str(exc),
                                "upstream": upstream_url,
                                "payload": redact_payload(payload),
                            }
                        },
                    )

            LOGGER.info(
                "request_allowed_stream",
                extra={
                    "extra_fields": {
                        "request_id": request_id,
                        "decision": "allowed",
                        "upstream": upstream_url,
                        "payload": redact_payload(payload),
                    }
                },
            )
            return StreamingResponse(stream_upstream(), media_type="text/event-stream")

        # --- Non-streaming path ---
        start = time.perf_counter()

        try:
            upstream_response = await client.post(
                settings.upstream_path, json=payload, headers=forward_headers
            )
        except httpx.HTTPError as exc:  # pragma: no cover - network error path
            LOGGER.error(
                "upstream_error",
                extra={
                    "extra_fields": {
                        "request_id": request_id,
                        "decision": "error",
                        "error": str(exc),
                        "upstream": upstream_url,
                        "payload": redact_payload(payload),
                    }
                },
            )
            raise HTTPException(status_code=502, detail="Upstream request failed") from None

        try:
            response_json = upstream_response.json()
        except ValueError:
            response_json = {"raw": upstream_response.text}

        response_decision = policy_engine.evaluate_response(response_json, request_id=request_id)
        total_latency_ms = (time.perf_counter() - start) * 1000

        log_fields = {
            "request_id": request_id,
            "decision": "allowed" if response_decision.allowed else "blocked_response",
            "reason_codes": response_decision.reason_codes,
            "upstream": upstream_url,
            "latency_ms": total_latency_ms,
            "payload": redact_payload(payload),
            "response": redact_payload(response_json),
        }

        if response_decision.allowed:
            LOGGER.info("request_allowed", extra={"extra_fields": log_fields})
            return JSONResponse(status_code=upstream_response.status_code, content=response_json)

        LOGGER.warning("response_blocked", extra={"extra_fields": log_fields})
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "codes": response_decision.reason_codes,
                    "message": "Response blocked by security policy",
                    "request_id": request_id,
                    "reasons": [finding.message for finding in response_decision.reasons],
                }
            },
        )

    return app


app = create_app()

__all__ = ["create_app", "app"]
