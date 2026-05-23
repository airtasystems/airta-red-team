"""AIRTA local test target — Harborline AI playground for browser-bot automation."""

from __future__ import annotations

import os
import socket
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.datastructures import UploadFile

from llm import (
    ChatResult,
    MediaAttachment,
    gemini_configured,
    gemini_model,
    generate_reply,
    guess_mime_type,
)

ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"
HOME = STATIC / "home.html"
PLAYGROUND = STATIC / "playground.html"
ABOUT = STATIC / "about.html"

app = FastAPI(title="AIRTA Test Target", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")


@dataclass
class StoredDocument:
    document_id: str
    filename: str
    mime_type: str
    data: bytes
    created_at: datetime


DOCUMENTS: dict[str, StoredDocument] = {}


class ChatRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=8000)
    document_id: str | None = None


class ChatResponse(BaseModel):
    prompt: str
    response: str
    model: str
    source: str
    document_id: str | None = None
    attachment: dict | None = None


class UploadResponse(BaseModel):
    document_id: str
    filename: str
    mime_type: str
    size: int


async def _read_upload(upload: UploadFile) -> MediaAttachment:
    data = await upload.read()
    if not data:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")
    filename = (upload.filename or "upload.bin").strip() or "upload.bin"
    mime_type = (upload.content_type or "").strip()
    if not mime_type or mime_type == "application/octet-stream":
        mime_type = guess_mime_type(filename, data)
    return MediaAttachment(filename=filename, mime_type=mime_type, data=data)


def _store_document(attachment: MediaAttachment) -> StoredDocument:
    doc_id = uuid.uuid4().hex
    stored = StoredDocument(
        document_id=doc_id,
        filename=attachment.filename,
        mime_type=attachment.mime_type,
        data=attachment.data,
        created_at=datetime.now(timezone.utc),
    )
    DOCUMENTS[doc_id] = stored
    return stored


def _get_document(document_id: str) -> StoredDocument:
    stored = DOCUMENTS.get(document_id)
    if not stored:
        raise HTTPException(status_code=404, detail="document not found")
    return stored


def _chat_result_to_response(result: ChatResult, document_id: str | None = None) -> ChatResponse:
    attachment = None
    if result.attachment:
        attachment = {
            "filename": result.attachment.filename,
            "mime_type": result.attachment.mime_type,
            "size": len(result.attachment.data),
        }
    return ChatResponse(
        prompt=result.prompt,
        response=result.response,
        model=result.model,
        source=result.source,
        document_id=document_id,
        attachment=attachment,
    )


@app.get("/health")
def health() -> JSONResponse:
    return JSONResponse(
        {
            "ok": True,
            "llm": {
                "configured": gemini_configured(),
                "model": gemini_model(),
                "multimodal": gemini_configured(),
            },
            "documents_cached": len(DOCUMENTS),
        }
    )


@app.post("/api/documents/upload", response_model=UploadResponse)
async def upload_document(request: Request) -> UploadResponse:
    """Store an uploaded artifact and return a document_id for follow-up chat."""
    form = await request.form()
    upload = form.get("file")
    if upload is None or not isinstance(upload, UploadFile):
        raise HTTPException(status_code=400, detail="file field is required")
    attachment = await _read_upload(upload)
    stored = _store_document(attachment)
    return UploadResponse(
        document_id=stored.document_id,
        filename=stored.filename,
        mime_type=stored.mime_type,
        size=len(stored.data),
    )


@app.post("/api/chat", response_model=ChatResponse)
async def chat_api(request: Request) -> ChatResponse:
    """
    Chat with optional multimodal attachment.

    JSON body: ``{"prompt": "...", "document_id": "..."}``
    Multipart form: ``prompt``, optional ``file``, optional ``document_id``
    """
    content_type = (request.headers.get("content-type") or "").lower()
    attachment: MediaAttachment | None = None
    doc_id: str | None = None
    prompt = ""

    if "multipart/form-data" in content_type:
        form = await request.form()
        prompt = str(form.get("prompt") or "").strip()
        doc_id = str(form.get("document_id") or "").strip() or None
        upload = form.get("file")
        if upload is not None and isinstance(upload, UploadFile) and upload.filename:
            attachment = await _read_upload(upload)
        elif doc_id:
            stored = _get_document(doc_id)
            attachment = MediaAttachment(
                filename=stored.filename,
                mime_type=stored.mime_type,
                data=stored.data,
            )
    else:
        try:
            body = ChatRequest.model_validate(await request.json())
        except Exception as exc:
            raise HTTPException(status_code=400, detail="invalid JSON body") from exc
        prompt = body.prompt.strip()
        doc_id = body.document_id
        if doc_id:
            stored = _get_document(doc_id)
            attachment = MediaAttachment(
                filename=stored.filename,
                mime_type=stored.mime_type,
                data=stored.data,
            )

    if not prompt and not attachment:
        raise HTTPException(status_code=400, detail="prompt or file is required")

    try:
        result = generate_reply(prompt or "Please analyze the attached file.", attachment)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    return _chat_result_to_response(result, document_id=doc_id)


@app.get("/")
def home() -> FileResponse:
    return FileResponse(HOME)


@app.get("/playground")
def playground() -> FileResponse:
    return FileResponse(PLAYGROUND)


@app.get("/about")
def about() -> FileResponse:
    return FileResponse(ABOUT)


def _next_available_port(host: str, preferred: int) -> int:
    for port in range(preferred, preferred + 20):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind((host, port))
            except OSError:
                continue
            return port
    return preferred


def main() -> None:
    import uvicorn

    host = os.getenv("TEST_TARGET_HOST", "127.0.0.1")
    preferred = int(os.getenv("TEST_TARGET_PORT", "3000"))
    port = _next_available_port(host, preferred)
    if port != preferred:
        print(f"Port {preferred} is in use; starting test target on {port} instead.")
    llm_status = "Gemini multimodal" if gemini_configured() else "mock fallback (set GEMINI_API_KEY)"
    print(f"AIRTA test target: http://{host}:{port}/playground  [{llm_status}]")
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
