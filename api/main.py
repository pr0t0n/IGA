import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import time
import requests
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

import jwt
from cryptography.fernet import Fernet, InvalidToken
from fastapi import FastAPI, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator

from catalog import (DEFAULT_SETTINGS, FRAMEWORKS, MODULES, RULE_DETAILS, RULE_PARAMETERS, SCHEDULES, SEVERITY_ORDER,
                     classify_event, framework_report, identity_risk, merged_settings, risk_level, risk_score)
from connectors import REQUIREMENTS, ConnectorError, aws_expiry, describe_credential, discover, normalize_credential, probe, scope_entry

DB_PATH = os.getenv("DATABASE_PATH", "/data/iga.db")
DATABASE_URL = os.getenv("DATABASE_URL", "")
MASTER_KEY = os.getenv("CREDENTIAL_MASTER_KEY", "local-development-key-change-me")
JWT_SECRET = os.getenv("JWT_SECRET", MASTER_KEY)
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@nexo.local").lower()
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "change-me-now")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://ollama:11434")
QWEN_MODEL = os.getenv("QWEN_MODEL", "qwen3:1.7b")
fernet_key = base64.urlsafe_b64encode(hashlib.sha256(MASTER_KEY.encode()).digest())
cipher = Fernet(fernet_key)

app = FastAPI(title="Nexo IGA API", version="0.1.0", docs_url="/api/docs", openapi_url="/api/openapi.json")

RULE_CATALOG = {
    "PUBLIC_ACCESS": {"name": "Acesso público", "framework": "CIS GCP 3.0 / Prowler", "control": "IAM public principals", "providers": {"GCP"}, "why": "A política permite acesso anônimo ou a qualquer usuário autenticado.", "recommendation": "Remover allUsers e allAuthenticatedUsers e conceder acesso apenas a grupos corporativos.", "treatment": "Validar a necessidade pública, substituir o principal aberto e testar o serviço antes de revogar."},
    "SERVICE_ACCOUNT_ADMIN": {"name": "Conta de serviço administrativa", "framework": "CIS GCP 3.0 / Prowler", "control": "1.5 · iam_sa_no_administrative_privileges", "providers": {"GCP"}, "why": "Uma identidade não humana possui função administrativa ampla e pode ampliar o impacto de comprometimento.", "recommendation": "Trocar funções básicas ou administrativas por uma função predefinida ou customizada de menor privilégio.", "treatment": "Identificar o workload, confirmar permissões usadas, criar função mínima, aplicar em homologação e remover a função ampla."},
    "TOXIC_COMBINATION": {"name": "Combinação tóxica", "framework": "IGA / SoD", "control": "Segregação de funções", "providers": {"AWS", "Azure", "GCP"}, "why": "A mesma identidade pode administrar IAM e personificar outra conta, permitindo elevação ou movimento lateral.", "recommendation": "Separar administração de políticas e personificação entre identidades distintas, preferencialmente com acesso temporário.", "treatment": "Remover uma das funções conflitantes, exigir aprovação e monitorar tentativas de impersonation."},
    "ACCESS_CREEP": {"name": "Access Creep", "framework": "NIST AC-2 / IGA", "control": "Acúmulo comprovado de acesso", "providers": set()},
    "PERMISSION_USAGE": {"name": "Uso real de permissão", "framework": "Google IAM Recommender / Least Privilege", "control": "Telemetria de uso", "providers": set()},
    "JML": {"name": "Joiner / Mover / Leaver", "framework": "NIST AC-2 / ISO 27001", "control": "Ciclo de vida", "providers": set()},
    "ORPHAN_ACCOUNT": {"name": "Conta órfã", "framework": "CIS / IGA", "control": "Responsabilidade comprovada", "providers": set()},
    "AUTHENTICATION_POSTURE": {"name": "Postura de autenticação", "framework": "CIS Foundations", "control": "MFA", "providers": {"AWS"}},
    "ACCESS_REVIEW": {"name": "Access Review", "framework": "NIST AC-2 / ISO 27001", "control": "Recertificação", "providers": set()},
    "UEBA_ANOMALY": {"name": "Anomalia UEBA", "framework": "MITRE ATT&CK", "control": "Telemetria comportamental", "providers": set()},
}

DEFAULT_RULE_GUIDANCE = {"why": "A evidência coletada viola a regra de governança configurada.", "recommendation": "Aplicar menor privilégio e validar o acesso com o responsável.", "treatment": "Revisar, aprovar ou remover o acesso e registrar a justificativa na trilha de auditoria."}


def role_context(provider: str, role: str, resource_type: str) -> dict[str, str]:
    if provider == "GCP":
        known = {
            "roles/owner": ("Proprietário básico", "Controle total do projeto, incluindo IAM e recursos.", "critical"),
            "roles/editor": ("Editor básico do projeto", "Alteração ampla dos recursos do projeto; não significa editor de repositório.", "high"),
            "roles/viewer": ("Visualizador básico do projeto", "Leitura ampla de recursos e metadados do projeto.", "medium"),
            "roles/iam.securityAdmin": ("Administrador de segurança IAM", "Administra políticas IAM e controles de segurança.", "critical"),
            "roles/resourcemanager.projectIamAdmin": ("Administrador IAM do projeto", "Cria e altera concessões IAM no projeto.", "critical"),
            "roles/iam.serviceAccountTokenCreator": ("Criador de token de conta de serviço", "Pode personificar contas de serviço e emitir credenciais de curta duração.", "critical"),
            "roles/iam.serviceAccountAdmin": ("Administrador de contas de serviço", "Cria e administra contas de serviço, sem implicar uso automático delas.", "high"),
        }
        if role in known:
            label, capability, severity = known[role]
            return {"label": label, "capability": capability, "severity": severity}
        if role.startswith("roles/source."):
            return {"label": "Função do Cloud Source Repositories", "capability": "Permissões relacionadas a repositórios, no escopo indicado pela política.", "severity": "high" if "admin" in role or "writer" in role else "medium"}
    severity = "high" if any(term in role.lower() for term in ("admin", "owner", "editor", "contributor")) else "medium"
    return {"label": role, "capability": f"Função concedida no escopo de {resource_type} coletado pelo provedor.", "severity": severity}


class ScopeInput(BaseModel):
    id: str = Field(min_length=1, max_length=300)
    name: str = Field(min_length=1, max_length=300)
    label: str = Field(min_length=1, max_length=400)


class CredentialInput(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    provider: Literal["AWS", "Azure", "GCP"]
    credential: dict[str, Any]
    scopes: list[ScopeInput] | None = Field(default=None, max_length=5000)

    @field_validator("name")
    @classmethod
    def clean_name(cls, value: str) -> str:
        return value.strip()


class CredentialUpdate(CredentialInput):
    credential: dict[str, Any] | None = None


class CredentialValidation(BaseModel):
    provider: Literal["AWS", "Azure", "GCP"]
    credential: dict[str, Any]


class FindingUpdate(BaseModel):
    status: Literal["open", "resolved", "accepted", "dismissed", "remediating", "incident"]
    justification: str | None = Field(default=None, min_length=3, max_length=500)


class AccessRequestInput(BaseModel):
    note: str | None = Field(default=None, max_length=500)


class ReviewCampaignInput(BaseModel):
    name: str = Field(min_length=3, max_length=150)
    scope: Literal["privileged", "unused", "all", "identity"]
    credentialId: int | None = None
    identityId: int | None = None
    reviewer: str = Field(min_length=2, max_length=150)
    dueDays: int = Field(default=30, ge=1, le=365)


class ReviewDecisionInput(BaseModel):
    decision: Literal["keep", "revoke"]
    comment: str | None = Field(default=None, max_length=500)


class SettingsInput(BaseModel):
    rules: dict[str, int]
    schedule: Literal["manual", "daily", "6h", "hourly"]
    notifications: dict[str, bool]
    webhook: str = Field(default="", max_length=500)


class InviteInput(BaseModel):
    email: str = Field(min_length=5, max_length=200)
    role: Literal["admin", "analyst", "auditor", "reader"]
    name: str | None = Field(default=None, min_length=2, max_length=100)


class LoginInput(BaseModel):
    email: str
    password: str


class UserInput(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    email: str = Field(min_length=5, max_length=200)
    password: str = Field(min_length=8, max_length=200)
    role: Literal["admin", "analyst", "auditor", "reader"]


class UserUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=100)
    role: Literal["admin", "analyst", "auditor", "reader"] | None = None
    active: bool | None = None
    password: str | None = Field(default=None, min_length=8, max_length=200)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def hash_password(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 310_000)
    return f"pbkdf2_sha256${salt}${base64.b64encode(digest).decode()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, salt, expected = encoded.split("$", 2)
        if algorithm != "pbkdf2_sha256":
            return False
        actual = hash_password(password, salt).split("$", 2)[2]
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def issue_token(user: dict[str, Any]) -> str:
    return jwt.encode({
        "sub": str(user["id"]), "email": user["email"], "role": user["role"],
        "exp": datetime.now(timezone.utc) + timedelta(hours=8),
    }, JWT_SECRET, algorithm="HS256")


def public_user(row: Any) -> dict[str, Any]:
    return {"id": row["id"], "name": row["name"], "email": row["email"],
            "role": row["role"], "active": bool(row["active"]), "createdAt": row["created_at"],
            "lastLoginAt": row["last_login_at"] if "last_login_at" in row.keys() else None}


class DatabaseConnection:
    def __init__(self, connection: Any, postgres: bool):
        self.connection = connection
        self.postgres = postgres

    def execute(self, query: str, params: tuple[Any, ...] | list[Any] = ()):
        if self.postgres:
            query = query.replace("?", "%s")
        return self.connection.execute(query, tuple(params))

    def executescript(self, script: str) -> None:
        if not self.postgres:
            self.connection.executescript(script)
            return
        for statement in script.split(";"):
            statement = statement.strip()
            if statement:
                self.connection.execute(statement)

    def commit(self) -> None:
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()


@contextmanager
def db():
    postgres = DATABASE_URL.startswith(("postgres://", "postgresql://"))
    if postgres:
        import psycopg
        from psycopg.rows import dict_row
        raw_connection = psycopg.connect(DATABASE_URL, row_factory=dict_row)
    else:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        raw_connection = sqlite3.connect(DB_PATH)
        raw_connection.row_factory = sqlite3.Row
        raw_connection.execute("PRAGMA foreign_keys = ON")
    connection = DatabaseConnection(raw_connection, postgres)
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


def init_db() -> None:
    with db() as connection:
        serial = "BIGSERIAL PRIMARY KEY" if connection.postgres else "INTEGER PRIMARY KEY AUTOINCREMENT"
        blob = "BYTEA" if connection.postgres else "BLOB"
        connection.executescript(f"""
        CREATE TABLE IF NOT EXISTS credentials (
            id {serial},
            name TEXT NOT NULL,
            provider TEXT NOT NULL CHECK(provider IN ('AWS','Azure','GCP')),
            encrypted_payload {blob} NOT NULL,
            scope TEXT NOT NULL DEFAULT 'Análise pendente',
            status TEXT NOT NULL DEFAULT 'Pendente',
            last_synced_at TEXT,
            auth_kind TEXT,
            principal TEXT,
            scopes_json TEXT,
            last_error TEXT,
            expires_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit_events (
            id {serial},
            event_type TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            actor TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS scans (
            id {serial},
            credential_id INTEGER NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
            provider TEXT NOT NULL,
            status TEXT NOT NULL,
            identity_count INTEGER NOT NULL DEFAULT 0,
            access_count INTEGER NOT NULL DEFAULT 0,
            finding_count INTEGER NOT NULL DEFAULT 0,
            telemetry_event_count INTEGER NOT NULL DEFAULT 0,
            telemetry_status TEXT NOT NULL DEFAULT 'not_collected',
            started_at TEXT NOT NULL,
            finished_at TEXT
        );
        CREATE TABLE IF NOT EXISTS identities (
            id {serial},
            credential_id INTEGER NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
            external_id TEXT NOT NULL,
            display_name TEXT NOT NULL,
            identity_type TEXT NOT NULL,
            email TEXT,
            enabled INTEGER NOT NULL DEFAULT 1,
            mfa_enabled INTEGER,
            owner TEXT,
            lifecycle_status TEXT,
            last_seen_at TEXT,
            raw_json TEXT NOT NULL,
            UNIQUE(credential_id, external_id)
        );
        CREATE TABLE IF NOT EXISTS access_grants (
            id {serial},
            credential_id INTEGER NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
            identity_external_id TEXT NOT NULL,
            resource_id TEXT NOT NULL,
            resource_name TEXT NOT NULL,
            role_name TEXT NOT NULL,
            permissions_json TEXT NOT NULL,
            privileged INTEGER NOT NULL DEFAULT 0,
            granted_at TEXT,
            last_used_at TEXT,
            last_reviewed_at TEXT,
            raw_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS cloud_resources (
            id {serial},
            credential_id INTEGER NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
            external_id TEXT NOT NULL,
            display_name TEXT NOT NULL,
            resource_type TEXT NOT NULL,
            raw_json TEXT NOT NULL,
            UNIQUE(credential_id, external_id)
        );
        CREATE TABLE IF NOT EXISTS findings (
            id {serial},
            credential_id INTEGER NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
            scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            rule_code TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            identity_external_id TEXT,
            resource_id TEXT,
            status TEXT NOT NULL DEFAULT 'open',
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_access_identity ON access_grants(credential_id,identity_external_id);
        CREATE INDEX IF NOT EXISTS idx_findings_identity ON findings(credential_id,identity_external_id,status);
        CREATE TABLE IF NOT EXISTS ai_analyses (
            id {serial},
            credential_id INTEGER NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
            scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
            scope_type TEXT NOT NULL,
            scope_id TEXT NOT NULL,
            engine TEXT NOT NULL,
            summary TEXT NOT NULL,
            why TEXT NOT NULL,
            recommendation TEXT NOT NULL,
            treatment TEXT NOT NULL,
            priority TEXT NOT NULL,
            context_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(scan_id,scope_type,scope_id)
        );
        CREATE TABLE IF NOT EXISTS platform_users (
            id {serial},
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin','analyst','auditor','reader')),
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_identities_credential ON identities(credential_id);
        CREATE INDEX IF NOT EXISTS idx_access_credential ON access_grants(credential_id);
        CREATE INDEX IF NOT EXISTS idx_resources_credential ON cloud_resources(credential_id);
        CREATE INDEX IF NOT EXISTS idx_findings_credential ON findings(credential_id, status);
        CREATE INDEX IF NOT EXISTS idx_ai_analyses_credential ON ai_analyses(credential_id,scan_id);
        CREATE TABLE IF NOT EXISTS telemetry_events (
            id {serial},
            credential_id INTEGER NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
            scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
            identity_external_id TEXT,
            resource_id TEXT,
            occurred_at TEXT,
            method TEXT,
            caller_ip TEXT,
            denied INTEGER NOT NULL DEFAULT 0,
            anomalous INTEGER NOT NULL DEFAULT 0,
            risk_score REAL NOT NULL DEFAULT 0,
            description TEXT,
            source TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_telemetry_credential ON telemetry_events(credential_id,occurred_at);
        CREATE TABLE IF NOT EXISTS review_campaigns (
            id {serial},
            name TEXT NOT NULL,
            scope TEXT NOT NULL,
            credential_id INTEGER REFERENCES credentials(id) ON DELETE SET NULL,
            reviewer TEXT NOT NULL,
            due_at TEXT NOT NULL,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            completed_at TEXT
        );
        CREATE TABLE IF NOT EXISTS review_items (
            id {serial},
            campaign_id INTEGER NOT NULL REFERENCES review_campaigns(id) ON DELETE CASCADE,
            credential_id INTEGER NOT NULL,
            identity_external_id TEXT NOT NULL,
            identity_name TEXT NOT NULL,
            resource_id TEXT NOT NULL,
            resource_name TEXT NOT NULL,
            role_name TEXT NOT NULL,
            privileged INTEGER NOT NULL DEFAULT 0,
            decision TEXT,
            comment TEXT,
            decided_by TEXT,
            decided_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_review_items_campaign ON review_items(campaign_id);
        CREATE TABLE IF NOT EXISTS access_requests (
            id {serial},
            credential_id INTEGER NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
            identity_external_id TEXT NOT NULL,
            resource_id TEXT NOT NULL,
            role_name TEXT NOT NULL,
            action TEXT NOT NULL,
            status TEXT NOT NULL,
            note TEXT,
            requested_by TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS platform_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        """)
        ensure_columns(connection, "scans", {"risk_score": "INTEGER", "telemetry_event_count": "INTEGER NOT NULL DEFAULT 0",
                                             "telemetry_status": "TEXT NOT NULL DEFAULT 'not_collected'"})
        ensure_columns(connection, "credentials", {column: "TEXT" for column in (
            "last_synced_at", "auth_kind", "principal", "scopes_json", "last_error", "expires_at")})
        ensure_columns(connection, "audit_events", {column: "TEXT" for column in (
            "action", "target", "result", "source", "details_json", "record_hash")})
        ensure_columns(connection, "platform_users", {"last_login_at": "TEXT"})
        ensure_columns(connection, "findings", {"updated_at": "TEXT"})
        if connection.postgres:
            connection.execute("ALTER TABLE platform_users DROP CONSTRAINT IF EXISTS platform_users_role_check")
            connection.execute("ALTER TABLE platform_users ADD CONSTRAINT platform_users_role_check "
                               "CHECK(role IN ('admin','analyst','auditor','reader'))")
        backfill_audit_chain(connection)
        for legacy in connection.execute(
            "SELECT id,provider,encrypted_payload FROM credentials WHERE principal IS NULL OR principal=''"
        ).fetchall():
            try:
                kind, principal = describe_credential(legacy["provider"], json.loads(cipher.decrypt(legacy["encrypted_payload"]).decode()))
            except (InvalidToken, ValueError):
                continue
            connection.execute("UPDATE credentials SET auth_kind=?,principal=? WHERE id=?", (kind, principal, legacy["id"]))
        existing_admin = connection.execute("SELECT id FROM platform_users WHERE email=?", (ADMIN_EMAIL,)).fetchone()
        if not existing_admin:
            now = utc_now()
            connection.execute(
                "INSERT INTO platform_users(name,email,password_hash,role,active,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                ("Administrador", ADMIN_EMAIL, hash_password(ADMIN_PASSWORD), "admin", 1, now, now),
            )


def ensure_columns(connection: DatabaseConnection, table: str, columns: dict[str, str]) -> None:
    if connection.postgres:
        existing = {row["column_name"] for row in connection.execute(
            "SELECT column_name FROM information_schema.columns WHERE table_name=?", (table,)
        ).fetchall()}
    else:
        existing = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})").fetchall()}
    for column, definition in columns.items():
        if column not in existing:
            connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


@app.on_event("startup")
def startup() -> None:
    init_db()
    start_scheduler()


@app.middleware("http")
async def authentication_middleware(request: Request, call_next):
    path = request.url.path
    public_paths = {"/health", "/api/auth/login", "/api/openapi.json", "/api/docs"}
    if not path.startswith("/api/") or path in public_paths or path.startswith("/api/docs/"):
        return await call_next(request)
    authorization = request.headers.get("Authorization", "")
    if not authorization.startswith("Bearer "):
        return JSONResponse({"detail": "Autenticação necessária"}, status_code=401)
    try:
        claims = jwt.decode(authorization.removeprefix("Bearer "), JWT_SECRET, algorithms=["HS256"])
        with db() as connection:
            user = connection.execute("SELECT * FROM platform_users WHERE id=? AND active=1", (int(claims["sub"]),)).fetchone()
        if not user:
            raise ValueError("inactive user")
        request.state.user = public_user(user)
    except Exception:
        return JSONResponse({"detail": "Sessão inválida ou expirada"}, status_code=401)
    role = request.state.user["role"]
    if role in {"auditor", "reader"} and request.method not in {"GET", "HEAD", "OPTIONS"}:
        label = "Auditor" if role == "auditor" else "Leitor"
        return JSONResponse({"detail": f"Perfil {label} possui acesso somente leitura"}, status_code=403)
    if role == "reader" and path.startswith("/api/audit"):
        return JSONResponse({"detail": "Perfil Leitor não acessa a trilha de auditoria"}, status_code=403)
    if (path.startswith("/api/users") or (path.startswith("/api/settings") and request.method != "GET")) and role != "admin":
        return JSONResponse({"detail": "Operação exclusiva para administradores"}, status_code=403)
    return await call_next(request)


@app.post("/api/auth/login")
def login(payload: LoginInput) -> dict[str, Any]:
    with db() as connection:
        user = connection.execute("SELECT * FROM platform_users WHERE email=? AND active=1", (payload.email.strip().lower(),)).fetchone()
        if not user or not verify_password(payload.password, user["password_hash"]):
            raise HTTPException(401, "E-mail ou senha inválidos")
        connection.execute("UPDATE platform_users SET last_login_at=? WHERE id=?", (utc_now(), user["id"]))
        user = connection.execute("SELECT * FROM platform_users WHERE id=?", (user["id"],)).fetchone()
    visible = public_user(user)
    return {"token": issue_token(visible), "user": visible}


@app.get("/api/auth/me")
def current_user(request: Request) -> dict[str, Any]:
    return request.state.user


@app.get("/api/users")
def list_users() -> list[dict[str, Any]]:
    with db() as connection:
        rows = connection.execute("SELECT * FROM platform_users ORDER BY name").fetchall()
    return [public_user(row) for row in rows]


@app.post("/api/users", status_code=status.HTTP_201_CREATED)
def create_user(payload: UserInput, request: Request) -> dict[str, Any]:
    email = payload.email.strip().lower()
    now = utc_now()
    with db() as connection:
        if connection.execute("SELECT id FROM platform_users WHERE email=?", (email,)).fetchone():
            raise HTTPException(409, "Já existe um usuário com este e-mail")
        cursor = connection.execute(
            "INSERT INTO platform_users(name,email,password_hash,role,active,created_at,updated_at) VALUES(?,?,?,?,?,?,?) RETURNING id",
            (payload.name.strip(), email, hash_password(payload.password), payload.role, 1, now, now),
        )
        user_id = cursor.fetchone()["id"]
        audit(connection, "admin", "Usuário criado", f"{email} recebeu o perfil {payload.role}.", request.state.user["email"])
        row = connection.execute("SELECT * FROM platform_users WHERE id=?", (user_id,)).fetchone()
    return public_user(row)


@app.post("/api/users/invite", status_code=status.HTTP_201_CREATED)
def invite_user(payload: InviteInput, request: Request) -> dict[str, Any]:
    email = payload.email.strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise HTTPException(422, "Informe um e-mail válido")
    temporary = secrets.token_urlsafe(12)
    name = payload.name.strip() if payload.name else email.split("@")[0]
    now = utc_now()
    with db() as connection:
        if connection.execute("SELECT id FROM platform_users WHERE email=?", (email,)).fetchone():
            raise HTTPException(409, "Já existe um usuário com este e-mail")
        cursor = connection.execute(
            "INSERT INTO platform_users(name,email,password_hash,role,active,created_at,updated_at) VALUES(?,?,?,?,?,?,?) RETURNING id",
            (name, email, hash_password(temporary), payload.role, 1, now, now))
        user_id = cursor.fetchone()["id"]
        audit(connection, "admin", "Usuário convidado", f"{email} recebeu o perfil {payload.role} com senha temporária.",
              request.state.user["email"], action="user.invited", target=email, details={"role": payload.role})
        row = connection.execute("SELECT * FROM platform_users WHERE id=?", (user_id,)).fetchone()
    return {"user": public_user(row), "temporaryPassword": temporary}


@app.patch("/api/users/{user_id}")
def update_user(user_id: int, payload: UserUpdate, request: Request) -> dict[str, Any]:
    with db() as connection:
        row = connection.execute("SELECT * FROM platform_users WHERE id=?", (user_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Usuário não encontrado")
        name = payload.name.strip() if payload.name is not None else row["name"]
        role = payload.role or row["role"]
        active = int(payload.active) if payload.active is not None else row["active"]
        password_hash = hash_password(payload.password) if payload.password else row["password_hash"]
        if user_id == request.state.user["id"] and not active:
            raise HTTPException(409, "O administrador não pode desativar a própria sessão")
        connection.execute(
            "UPDATE platform_users SET name=?,role=?,active=?,password_hash=?,updated_at=? WHERE id=?",
            (name, role, active, password_hash, utc_now(), user_id),
        )
        audit(connection, "admin", "Acesso administrativo alterado",
              f"{row['email']}: perfil {row['role']} → {role}; ativo={bool(active)}.", request.state.user["email"])
        updated = connection.execute("SELECT * FROM platform_users WHERE id=?", (user_id,)).fetchone()
    return public_user(updated)


@app.delete("/api/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(user_id: int, request: Request) -> Response:
    if user_id == request.state.user["id"]:
        raise HTTPException(409, "O administrador não pode remover a própria conta")
    with db() as connection:
        row = connection.execute("SELECT * FROM platform_users WHERE id=?", (user_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Usuário não encontrado")
        connection.execute("DELETE FROM platform_users WHERE id=?", (user_id,))
        audit(connection, "admin", "Usuário removido", f"{row['email']} foi removido da plataforma.", request.state.user["email"])
    return Response(status_code=204)


def validate_provider(provider: str, payload: dict[str, Any]) -> list[str]:
    alternatives = REQUIREMENTS[provider]["required"]
    missing_by_set = [[key for key in required_set if not payload.get(key)] for required_set in alternatives]
    if any(not missing for missing in missing_by_set):
        if provider == "GCP" and payload.get("type") != "service_account":
            return ["O campo type deve ser service_account."]
        return []
    closest = min(missing_by_set, key=len)
    return [f"Campos obrigatórios ausentes para {provider}: {', '.join(closest)}."]


def prepare_credential(provider: str, payload: dict[str, Any]) -> dict[str, Any]:
    credential = normalize_credential(provider, payload)
    errors = validate_provider(provider, credential)
    if errors:
        raise HTTPException(422, {"provider": provider, "errors": errors})
    return credential


def decrypt_credential(row: Any) -> dict[str, Any]:
    try:
        return json.loads(cipher.decrypt(row["encrypted_payload"]).decode())
    except InvalidToken as exc:
        raise HTTPException(500, "Não foi possível descriptografar a credencial") from exc


def credential_view(row: Any, discovered_scopes: list[dict[str, str]] | None = None) -> dict[str, Any]:
    """Public view: secrets are never returned once stored."""
    selected = json.loads(row["scopes_json"]) if row["scopes_json"] else None
    return {
        "id": row["id"], "name": row["name"], "provider": row["provider"],
        "kind": row["auth_kind"] or REQUIREMENTS[row["provider"]]["kind"],
        "principal": row["principal"] or "",
        "scopes": selected if selected is not None else (discovered_scopes or []),
        "scopeSelection": "selected" if selected is not None else "all",
        "scope": row["scope"], "status": row["status"], "lastError": row["last_error"],
        "expiresAt": row["expires_at"],
        "createdAt": row["created_at"], "updatedAt": row["updated_at"],
        "lastSyncedAt": row["last_synced_at"],
        "synced": row["last_synced_at"] or "Nunca",
    }


def discovered_scopes(connection: DatabaseConnection, credential_id: int | None = None) -> dict[int, list[dict[str, str]]]:
    filter_sql = " AND r.credential_id=?" if credential_id is not None else ""
    params: tuple[Any, ...] = (credential_id,) if credential_id is not None else ()
    rows = connection.execute(
        f"""SELECT r.credential_id,r.external_id,r.display_name,c.provider FROM cloud_resources r
            JOIN credentials c ON c.id=r.credential_id
            WHERE r.resource_type<>'repository'{filter_sql} ORDER BY r.display_name""", params,
    ).fetchall()
    result: dict[int, list[dict[str, str]]] = {}
    for row in rows:
        result.setdefault(row["credential_id"], []).append(scope_entry(row["provider"], row["external_id"], row["display_name"]))
    return result


def single_credential_view(connection: DatabaseConnection, credential_id: int) -> dict[str, Any]:
    row = connection.execute("SELECT * FROM credentials WHERE id=?", (credential_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Credencial não encontrada")
    return credential_view(row, discovered_scopes(connection, credential_id).get(credential_id))


def audit_record_hash(previous: str | None, record: dict[str, Any]) -> str:
    canonical = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(f"{previous or ''}{canonical}".encode()).hexdigest()


def audit_payload(event_type: str, title: str, description: str, actor: str, created_at: str,
                  action: str | None, target: str | None, result: str, details: dict[str, Any] | None) -> dict[str, Any]:
    return {"type": event_type, "title": title, "description": description, "actor": actor, "createdAt": created_at,
            "action": action, "target": target, "result": result, "details": details or {}}


def audit(connection: DatabaseConnection, event_type: str, title: str, description: str,
          actor: str = "Administrador local", *, action: str | None = None, target: str | None = None,
          result: str = "Sucesso", details: dict[str, Any] | None = None) -> None:
    """Append-only trail: every record hashes the previous one (SHA-256 chain)."""
    created_at = utc_now()
    previous = connection.execute("SELECT record_hash FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()
    record = audit_payload(event_type, title, description, actor, created_at, action, target, result, details)
    connection.execute(
        """INSERT INTO audit_events(event_type,title,description,actor,created_at,action,target,result,source,details_json,record_hash)
           VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
        (event_type, title, description, actor, created_at, action, target, result, "Plataforma",
         json.dumps(details or {}, ensure_ascii=False), audit_record_hash(previous["record_hash"] if previous else None, record)),
    )


def backfill_audit_chain(connection: DatabaseConnection) -> None:
    pending = connection.execute("SELECT id FROM audit_events WHERE record_hash IS NULL ORDER BY id LIMIT 1").fetchone()
    if not pending:
        return
    previous = connection.execute(
        "SELECT record_hash FROM audit_events WHERE id<? ORDER BY id DESC LIMIT 1", (pending["id"],)
    ).fetchone()
    previous_hash = previous["record_hash"] if previous else None
    for row in connection.execute("SELECT * FROM audit_events WHERE id>=? ORDER BY id", (pending["id"],)).fetchall():
        result = row["result"] or ("Falha" if "Falha" in row["title"] else "Sucesso")
        details = json.loads(row["details_json"]) if row["details_json"] else {}
        record = audit_payload(row["event_type"], row["title"], row["description"], row["actor"], row["created_at"],
                               row["action"], row["target"], result, details)
        previous_hash = audit_record_hash(previous_hash, record)
        connection.execute("UPDATE audit_events SET result=?,source=?,details_json=?,record_hash=? WHERE id=?",
                           (result, row["source"] or "Plataforma", json.dumps(details, ensure_ascii=False), previous_hash, row["id"]))


def parse_date(value: Any) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def days_since(value: Any) -> int | None:
    parsed = parse_date(value)
    if not parsed:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - parsed).days


def finding(rule: str, severity: str, title: str, description: str,
            identity_id: str | None = None, resource_id: str | None = None) -> dict[str, Any]:
    return {"rule": rule, "severity": severity, "title": title, "description": description,
            "identityId": identity_id, "resourceId": resource_id}


def calculate_risk_score(findings: list[dict[str, Any]], assessed_objects: int = 1) -> int:
    weights = {"critical": 4, "high": 2, "medium": 1, "low": 0.5}
    weighted_failures = sum(weights.get(item.get("severity", "low"), 0.5) for item in findings)
    penalty = round((weighted_failures / max(1, assessed_objects)) * 100)
    return max(0, 100 - min(100, penalty))


def load_settings(connection: DatabaseConnection) -> dict[str, Any]:
    row = connection.execute("SELECT value FROM platform_settings WHERE key='platform'").fetchone()
    return merged_settings(json.loads(row["value"]) if row else None)


def store_settings(connection: DatabaseConnection, settings: dict[str, Any]) -> None:
    connection.execute(
        """INSERT INTO platform_settings(key,value,updated_at) VALUES('platform',?,?)
           ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at""",
        (json.dumps(settings, ensure_ascii=False), utc_now()),
    )


def as_utc(value: datetime | None) -> datetime:
    if value is None:
        return datetime.min.replace(tzinfo=timezone.utc)
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def hours_since(value: Any) -> float | None:
    parsed = parse_date(value)
    if not parsed:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - parsed).total_seconds() / 3600


def evaluate_rules(identities: list[dict[str, Any]], accesses: list[dict[str, Any]],
                   events: list[dict[str, Any]], rules: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    limits = {**DEFAULT_SETTINGS["rules"], **(rules or {})}
    results: list[dict[str, Any]] = []
    identities_by_id = {str(item.get("id")): item for item in identities}
    grants_by_identity: dict[str, list[dict[str, Any]]] = {}
    for grant in accesses:
        identity_id = str(grant.get("identityId", ""))
        grants_by_identity.setdefault(identity_id, []).append(grant)

        unused_days = days_since(grant.get("lastUsedAt"))
        if grant.get("unused") is True or (unused_days is not None and unused_days > limits["unused_days"]):
            results.append(finding("PERMISSION_USAGE", "high", "Permissão sem uso real",
                f"O acesso {grant.get('role', 'sem função')} não é utilizado há mais de {limits['unused_days']} dias.", identity_id, str(grant.get("resourceId", ""))))

        review_days = days_since(grant.get("lastReviewedAt"))
        if grant.get("reviewDue") is True or (review_days is not None and review_days > limits["review_days"]):
            results.append(finding("ACCESS_REVIEW", "medium", "Revisão de acesso pendente",
                "O acesso precisa ser recertificado pelo responsável.", identity_id, str(grant.get("resourceId", ""))))

        permissions = set(grant.get("permissions") or [])
        toxic_pairs = [
            ({"iam:CreateUser", "iam:AttachUserPolicy"}, "Criação de usuário e concessão de política"),
            ({"users.create", "roles.assign"}, "Criação de identidade e atribuição de função"),
            ({"Microsoft.Authorization/roleAssignments/write", "Microsoft.Resources/subscriptions/resourceGroups/write"}, "Criação de recurso e concessão de função"),
        ]
        for required, label in toxic_pairs:
            if required.issubset(permissions):
                results.append(finding("TOXIC_COMBINATION", "critical", "Combinação tóxica de permissões",
                    label, identity_id, str(grant.get("resourceId", ""))))

    for identity_id, identity in identities_by_id.items():
        grants = grants_by_identity.get(identity_id, [])
        orphan_days = days_since(identity.get("orphanSince"))
        if identity.get("orphan") is True and (orphan_days is None or orphan_days >= limits["orphan_days"]):
            results.append(finding("ORPHAN_ACCOUNT", "high", "Conta sem responsável",
                "A identidade não possui proprietário válido.", identity_id))
        if identity.get("mfaEnabled") is False and identity.get("enabled", True):
            results.append(finding("AUTHENTICATION_POSTURE", "high", "MFA não configurado",
                "A identidade ativa não possui autenticação multifator.", identity_id))
        key_age = days_since(identity.get("accessKeyCreatedAt"))
        if key_age is not None and key_age > limits["key_age_days"] and identity.get("enabled", True):
            results.append(finding("AUTHENTICATION_POSTURE", "high", "Chave de acesso antiga",
                f"A chave de acesso ativa tem {key_age} dias (limite: {limits['key_age_days']}).", identity_id))
        lifecycle = identity.get("lifecycleStatus")
        changed_hours = hours_since(identity.get("lifecycleChangedAt"))
        if lifecycle == "leaver" and grants and (changed_hours is None or changed_hours > limits["leaver_hours"]):
            results.append(finding("JML", "critical", "Acesso incompatível com ciclo de vida",
                f"Identidade desligada mantém {len(grants)} acesso(s).", identity_id))
        if lifecycle == "mover" and grants:
            results.append(finding("JML", "high", "Acesso incompatível com ciclo de vida",
                f"Identidade em movimentação mantém {len(grants)} acesso(s).", identity_id))
        mover_creep = lifecycle == "mover" and changed_hours is not None and changed_hours / 24 > limits["creep_days"]
        if mover_creep or any(grant.get("accessCreep") is True for grant in grants):
            evidence = (f"Em movimentação há mais de {limits['creep_days']} dias mantendo {len(grants)} concessão(ões) anteriores."
                        if mover_creep else "A fonte de telemetria marcou crescimento indevido de privilégios.")
            results.append(finding("ACCESS_CREEP", "high", "Acúmulo progressivo de acessos", evidence, identity_id))

        roles = {str(grant.get("role", "")) for grant in grants}
        administrative_roles = {"roles/owner", "roles/editor", "roles/iam.securityAdmin", "roles/resourcemanager.projectIamAdmin"}
        if identity.get("type") == "service":
            for grant in (item for item in grants if item.get("role") in administrative_roles):
                results.append(finding("SERVICE_ACCOUNT_ADMIN", "high", "Conta de serviço com privilégio administrativo",
                    f"A função {grant.get('role')} concede administração ampla em {grant.get('resourceName', grant.get('resourceId'))}.",
                    identity_id, str(grant.get("resourceId", ""))))
        gcp_toxic_pairs = [
            ({"roles/iam.serviceAccountTokenCreator", "roles/iam.serviceAccountAdmin"}, "Administração e personificação de contas de serviço"),
            ({"roles/iam.serviceAccountTokenCreator", "roles/resourcemanager.projectIamAdmin"}, "Personificação e administração de IAM do projeto"),
        ]
        for required, label in gcp_toxic_pairs:
            if required.issubset(roles):
                related_grants = [grant for grant in grants if grant.get("role") in required]
                scopes = sorted({str(grant.get("resourceName", grant.get("resourceId", ""))) for grant in related_grants})
                description = f"{label}. Escopos correlacionados: {', '.join(scopes)}."
                results.append(finding("TOXIC_COMBINATION", "critical", "Combinação tóxica de funções", description,
                    identity_id, str(related_grants[0].get("resourceId", "")) if related_grants else None))

        if identity.get("type") == "public" or identity_id in {"allUsers", "allAuthenticatedUsers"}:
            results.append(finding("PUBLIC_ACCESS", "critical", "Recurso acessível publicamente",
                "A política IAM concede acesso a allUsers ou allAuthenticatedUsers.", identity_id,
                str(grants[0].get("resourceId", "")) if grants else None))

    anomaly_groups: dict[tuple[str, str, str], dict[str, Any]] = {}
    for event in events:
        score = float(event.get("riskScore", 0))
        if score * 100 < limits["ueba_threshold"]:
            continue
        identity_id = str(event.get("identityId", ""))
        resource_id = str(event.get("resourceId", ""))
        description = str(event.get("description", "Evento fora do padrão comportamental."))
        key = (identity_id, resource_id, description)
        group = anomaly_groups.setdefault(key, {"count": 0, "score": 0.0})
        group["count"] += 1
        group["score"] = max(group["score"], score)
    for (identity_id, resource_id, description), group in anomaly_groups.items():
        evidence = f"{group['count']} ocorrência(s) nos últimos 7 dias. {description}"
        results.append(finding("UEBA_ANOMALY", "critical" if group["score"] >= 0.9 else "high",
            "Comportamento de acesso anômalo", evidence, identity_id, resource_id))
    return results


def normalize_discovery(discovery: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    identities = discovery.get("identities", [])
    accesses = discovery.get("accesses", [])
    events = discovery.get("events", [])
    if not all(isinstance(items, list) for items in (identities, accesses, events)):
        raise HTTPException(502, "O conector retornou inventários em formato inválido")
    for item in identities:
        if not isinstance(item, dict) or not item.get("id") or not item.get("name"):
            raise HTTPException(422, "Cada identidade precisa de id e name")
    for item in accesses:
        if not isinstance(item, dict) or not item.get("identityId") or not item.get("resourceId") or not item.get("role"):
            raise HTTPException(422, "Cada acesso precisa de identityId, resourceId e role")
    return identities, accesses, events


@app.get("/health")
def health() -> dict[str, str]:
    with db() as connection:
        connection.execute("SELECT 1").fetchone()
    return {"status": "healthy"}


@app.get("/api/credentials")
def list_credentials() -> list[dict[str, Any]]:
    with db() as connection:
        rows = connection.execute("SELECT * FROM credentials ORDER BY updated_at DESC").fetchall()
        scopes = discovered_scopes(connection)
    return [credential_view(row, scopes.get(row["id"])) for row in rows]


@app.get("/api/credentials/requirements")
def credential_requirements() -> dict[str, Any]:
    fields = ("kind", "scopeKind", "roles", "required", "checks", "sample")
    return {"providers": [{"provider": provider, **{key: spec[key] for key in fields}}
                          for provider, spec in REQUIREMENTS.items()]}


@app.post("/api/credentials/validate")
def validate_credential(payload: CredentialValidation) -> dict[str, Any]:
    credential = prepare_credential(payload.provider, payload.credential)
    try:
        result = probe(payload.provider, credential)
    except ConnectorError as exc:
        raise HTTPException(422, str(exc)) from exc
    kind, _ = describe_credential(payload.provider, credential)
    return {"provider": payload.provider, "kind": kind, **result}


@app.get("/api/credentials/{credential_id}")
def get_credential(credential_id: int) -> dict[str, Any]:
    with db() as connection:
        return single_credential_view(connection, credential_id)


def scopes_json(scopes: list[ScopeInput] | None) -> str | None:
    if scopes is None:
        return None
    if not scopes:
        raise HTTPException(422, "Selecione ao menos um escopo para analisar.")
    unique = {item.id: item.model_dump() for item in scopes}
    return json.dumps(list(unique.values()))


@app.post("/api/credentials", status_code=status.HTTP_201_CREATED)
def create_credential(payload: CredentialInput, request: Request) -> dict[str, Any]:
    credential = prepare_credential(payload.provider, payload.credential)
    kind, principal = describe_credential(payload.provider, credential)
    selected = scopes_json(payload.scopes)
    now = utc_now()
    encrypted = cipher.encrypt(json.dumps(credential).encode())
    with db() as connection:
        cursor = connection.execute(
            """INSERT INTO credentials(name,provider,encrypted_payload,scope,status,auth_kind,principal,scopes_json,
               expires_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?) RETURNING id""",
            (payload.name, payload.provider, encrypted, "Ainda não analisado", "Pendente", kind, principal, selected,
             aws_expiry(credential) if payload.provider == "AWS" else None, now, now),
        )
        credential_id = cursor.fetchone()["id"]
        scope_text = f"{len(payload.scopes)} escopo(s) selecionado(s)" if payload.scopes else "todos os escopos visíveis"
        audit(connection, "credential", "Credencial adicionada",
              f"{payload.name} ({payload.provider}) aguarda a primeira análise real em {scope_text}.", request.state.user["email"])
        return single_credential_view(connection, credential_id)


@app.put("/api/credentials/{credential_id}")
def update_credential(credential_id: int, payload: CredentialUpdate, request: Request) -> dict[str, Any]:
    with db() as connection:
        row = connection.execute("SELECT * FROM credentials WHERE id=?", (credential_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Credencial não encontrada")
        if payload.credential is None and payload.provider != row["provider"]:
            raise HTTPException(422, "Informe uma nova credencial JSON ao trocar o provedor.")
        selected = scopes_json(payload.scopes) if payload.scopes is not None else row["scopes_json"]
        if payload.credential is None and selected == row["scopes_json"]:
            connection.execute("UPDATE credentials SET name=?,updated_at=? WHERE id=?", (payload.name, utc_now(), credential_id))
            if payload.name != row["name"]:
                audit(connection, "credential", "Credencial renomeada", f"{row['name']} → {payload.name}.", request.state.user["email"])
            return single_credential_view(connection, credential_id)
        if payload.credential is not None:
            credential = prepare_credential(payload.provider, payload.credential)
            kind, principal = describe_credential(payload.provider, credential)
            encrypted = cipher.encrypt(json.dumps(credential).encode())
            expires_at = aws_expiry(credential) if payload.provider == "AWS" else None
        else:
            kind, principal, encrypted, expires_at = row["auth_kind"], row["principal"], row["encrypted_payload"], row["expires_at"]
        connection.execute("DELETE FROM scans WHERE credential_id=?", (credential_id,))
        connection.execute("DELETE FROM identities WHERE credential_id=?", (credential_id,))
        connection.execute("DELETE FROM access_grants WHERE credential_id=?", (credential_id,))
        connection.execute("DELETE FROM cloud_resources WHERE credential_id=?", (credential_id,))
        connection.execute(
            """UPDATE credentials SET name=?,provider=?,encrypted_payload=?,scope=?,status=?,auth_kind=?,principal=?,
               scopes_json=?,last_error=NULL,expires_at=?,last_synced_at=NULL,updated_at=? WHERE id=?""",
            (payload.name, payload.provider, encrypted, "Ainda não analisado", "Pendente", kind, principal,
             selected, expires_at, utc_now(), credential_id),
        )
        audit(connection, "credential", "Credencial atualizada", f"{payload.name} aguarda uma nova análise real.", request.state.user["email"])
        return single_credential_view(connection, credential_id)


@app.delete("/api/credentials/{credential_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_credential(credential_id: int, request: Request) -> Response:
    with db() as connection:
        row = connection.execute("SELECT name,provider FROM credentials WHERE id=?", (credential_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Credencial não encontrada")
        severities = connection.execute(
            "SELECT severity,COUNT(*) count FROM findings WHERE credential_id=? AND status='open' GROUP BY severity",
            (credential_id,),
        ).fetchall()
        labels = {"critical": "crítico(s)", "high": "alto(s)", "medium": "médio(s)", "low": "baixo(s)"}
        summary = ", ".join(f"{item['count']} {labels.get(item['severity'], item['severity'])}" for item in severities)
        connection.execute("DELETE FROM credentials WHERE id=?", (credential_id,))
        audit(connection, "credential", "Credencial removida",
              f"{row['name']} ({row['provider']}) foi desconectada do ambiente. "
              f"Achados abertos no momento da remoção: {summary or 'nenhum'}.", request.state.user["email"])
    return Response(status_code=status.HTTP_204_NO_CONTENT)


def audit_view(row: Any) -> dict[str, Any]:
    return {"id": row["id"], "type": row["event_type"], "title": row["title"], "text": row["description"],
            "actor": row["actor"], "createdAt": row["created_at"], "action": row["action"] or row["title"],
            "target": row["target"] or "", "result": row["result"] or "Sucesso", "source": row["source"] or "Plataforma",
            "details": json.loads(row["details_json"]) if row["details_json"] else {}, "hash": row["record_hash"]}


@app.get("/api/audit")
def list_audit() -> list[dict[str, Any]]:
    with db() as connection:
        rows = connection.execute("SELECT * FROM audit_events ORDER BY id DESC LIMIT 200").fetchall()
    return [audit_view(row) for row in rows]


@app.get("/api/audit/trail")
def audit_trail(limit: int = Query(1000, ge=1, le=5000)) -> dict[str, Any]:
    """Platform events (hash-chained) merged with provider audit logs collected by the connectors."""
    day_ago = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    with db() as connection:
        platform = connection.execute("SELECT * FROM audit_events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        provider = connection.execute(
            """SELECT t.*,c.name environment FROM telemetry_events t JOIN credentials c ON c.id=t.credential_id
               ORDER BY t.occurred_at DESC LIMIT ?""", (limit,)).fetchall()
        counts = {row["source"]: row["count"] for row in connection.execute(
            "SELECT source,COUNT(*) count FROM telemetry_events WHERE occurred_at>=? GROUP BY source", (day_ago,)).fetchall()}
        counts["Plataforma"] = connection.execute(
            "SELECT COUNT(*) count FROM audit_events WHERE created_at>=?", (day_ago,)).fetchone()["count"]
        collected = {row["provider"] for row in connection.execute(
            """SELECT DISTINCT c.provider FROM scans s JOIN credentials c ON c.id=s.credential_id
               WHERE s.status='completed' AND s.telemetry_status IN ('collected','partial')""").fetchall()}
    events = [{"key": f"A-{row['id']}", **audit_view(row)} for row in platform]
    for row in provider:
        details = {"environment": row["environment"], "callerIp": row["caller_ip"], "anomalous": bool(row["anomalous"]),
                   "riskScore": row["risk_score"], "description": row["description"]}
        record = {"timestamp": row["occurred_at"], "actor": row["identity_external_id"], "action": row["method"],
                  "target": row["resource_id"], "source": row["source"], "details": details}
        events.append({"key": f"T-{row['id']}", "id": row["id"], "type": "provider", "title": row["method"] or "Evento do provedor",
                       "text": row["description"] or "", "actor": row["identity_external_id"] or "—", "createdAt": row["occurred_at"],
                       "action": row["method"] or "—", "target": row["resource_id"] or "", "result": "Falha" if row["denied"] else "Sucesso",
                       "source": row["source"], "details": details,
                       "hash": hashlib.sha256(json.dumps(record, sort_keys=True, ensure_ascii=False).encode()).hexdigest()})
    events.sort(key=lambda item: item["createdAt"] or "", reverse=True)
    provider_sources = {"GCP": "GCP Audit Logs", "AWS": "AWS CloudTrail", "Azure": "Azure Activity Log"}
    sources = [{"name": "Plataforma", "count": counts.get("Plataforma", 0), "collected": True}]
    sources += [{"name": label, "count": counts.get(label, 0), "collected": name in collected} for name, label in provider_sources.items()]
    return {"events": events[:limit], "sources": sources}


@app.get("/api/overview")
def overview() -> dict[str, Any]:
    with db() as connection:
        credentials = connection.execute("SELECT provider, COUNT(*) count FROM credentials GROUP BY provider").fetchall()
        audit_count = connection.execute("SELECT COUNT(*) count FROM audit_events").fetchone()["count"]
    return {
        "connectedEnvironments": sum(row["count"] for row in credentials),
        "providers": {row["provider"]: row["count"] for row in credentials},
        "auditEvents": audit_count,
        "analysisStatus": "pending" if credentials else "waiting_for_credentials",
    }


@app.get("/api/dashboard")
def dashboard(credential_id: int | None = None) -> dict[str, Any]:
    filter_sql = " AND credential_id=?" if credential_id is not None else ""
    params: tuple[Any, ...] = (credential_id,) if credential_id is not None else ()
    with db() as connection:
        identity_count = connection.execute(f"SELECT COUNT(*) count FROM identities WHERE 1=1{filter_sql}", params).fetchone()["count"]
        access_count = connection.execute(f"SELECT COUNT(*) count FROM access_grants WHERE 1=1{filter_sql}", params).fetchone()["count"]
        privileged_count = connection.execute(f"SELECT COUNT(*) count FROM access_grants WHERE privileged=1{filter_sql}", params).fetchone()["count"]
        resource_count = connection.execute(f"SELECT COUNT(*) count FROM cloud_resources WHERE 1=1{filter_sql}", params).fetchone()["count"]
        severity_rows = connection.execute(
            f"SELECT severity,COUNT(*) count FROM findings WHERE status='open'{filter_sql} GROUP BY severity", params
        ).fetchall()
        credentials = connection.execute("SELECT id,name,provider,scope,status,last_synced_at FROM credentials ORDER BY name").fetchall()
        assessed_count = connection.execute(
            "SELECT COUNT(*) count FROM credentials WHERE last_synced_at IS NOT NULL"
        ).fetchone()["count"]
        risk_by_credential = connection.execute(
            """SELECT c.id,c.name,c.provider,f.severity,COUNT(f.id) count FROM credentials c
               LEFT JOIN findings f ON f.credential_id=c.id AND f.status='open'
               GROUP BY c.id,c.name,c.provider,f.severity ORDER BY c.name"""
        ).fetchall()
    severities = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for row in severity_rows:
        severities[row["severity"]] = row["count"]
    weighted_failures = severities["critical"] * 4 + severities["high"] * 2 + severities["medium"] + severities["low"] * 0.5
    penalty = round((weighted_failures / max(1, identity_count + access_count)) * 100)
    risk_score = max(0, 100 - min(100, penalty)) if assessed_count else 0
    environment_map: dict[int, dict[str, Any]] = {}
    for row in risk_by_credential:
        environment = environment_map.setdefault(row["id"], {"id": row["id"], "name": row["name"], "provider": row["provider"], "risks": {"critical": 0, "high": 0, "medium": 0, "low": 0}})
        if row["severity"]:
            environment["risks"][row["severity"]] = row["count"]
    risk_level = "critical" if severities["critical"] else "high" if severities["high"] else "moderate" if severities["medium"] else "low"
    compliance = compliance_report(credential_id)["score"] if assessed_count else None
    return {
        "riskScore": risk_score,
        "riskLevel": risk_level,
        "severities": severities,
        "identities": identity_count,
        "accesses": access_count,
        "privilegedAccesses": privileged_count,
        "resources": resource_count,
        "compliance": compliance,
        "assessedEnvironments": assessed_count,
        "environments": list(environment_map.values()),
        "credentials": [dict(row) for row in credentials],
    }


TELEMETRY_SOURCE = {"GCP": "GCP Audit Logs", "AWS": "AWS CloudTrail", "Azure": "Azure Activity Log"}
CARRIED_STATUSES = ("accepted", "remediating", "incident", "dismissed")
SCANS_GUARD = threading.Lock()
RUNNING_SCANS: set[int] = set()


class ScanError(Exception):
    """Connector failure already recorded on the credential and in the audit trail."""


def finding_key(rule: Any, identity_id: Any, resource_id: Any, title: Any) -> tuple[str, str, str, str]:
    return (str(rule), str(identity_id or ""), str(resource_id or ""), str(title))


def notify(kind: str, text: str, settings: dict[str, Any] | None = None) -> bool:
    """Post a Slack/Teams-compatible message to the configured webhook when the notification kind is enabled."""
    if settings is None:
        with db() as connection:
            settings = load_settings(connection)
    webhook = settings.get("webhook") or ""
    if not webhook or not settings["notifications"].get(kind):
        return False
    try:
        response = requests.post(webhook, json={"text": f"[Nexo IGA] {text}"}, timeout=10)
        response.raise_for_status()
        return True
    except requests.RequestException as exc:
        with db() as connection:
            audit(connection, "admin", "Falha ao enviar notificação", f"{kind}: {type(exc).__name__}", "notificações",
                  action="notification.failed", target=kind, result="Falha")
        return False


def run_scan(credential_id: int, actor: str) -> dict[str, Any]:
    with SCANS_GUARD:
        if credential_id in RUNNING_SCANS:
            raise HTTPException(409, "Já existe uma análise em andamento para esta credencial.")
        RUNNING_SCANS.add(credential_id)
    try:
        return execute_scan(credential_id, actor)
    finally:
        with SCANS_GUARD:
            RUNNING_SCANS.discard(credential_id)


def execute_scan(credential_id: int, actor: str) -> dict[str, Any]:
    started_at = utc_now()
    with db() as connection:
        row = connection.execute("SELECT * FROM credentials WHERE id=?", (credential_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Credencial não encontrada")
        settings = load_settings(connection)
        credential = decrypt_credential(row)
        selected_scopes = [item["id"] for item in json.loads(row["scopes_json"])] if row["scopes_json"] else None
        try:
            discovered = discover(row["provider"], credential, scopes=selected_scopes)
        except ConnectorError as exc:
            connection.execute(
                "UPDATE credentials SET status=?,last_error=?,updated_at=? WHERE id=?",
                ("Erro", str(exc), utc_now(), credential_id),
            )
            audit(connection, "credential", "Falha na análise cloud", f"{row['name']}: {exc}", actor,
                  action="analysis.failed", target=row["name"], result="Falha", details={"error": str(exc), "provider": row["provider"]})
            connection.commit()
            failure = ScanError(str(exc))
            failure.credential_name = row["name"]
            failure.settings = settings
            raise failure from exc
        identities, accesses, events = normalize_discovery(discovered)
        reviewed = {}
        for item in connection.execute(
            """SELECT identity_external_id,resource_id,role_name,MAX(decided_at) decided_at FROM review_items
               WHERE credential_id=? AND decision='keep' GROUP BY identity_external_id,resource_id,role_name""", (credential_id,)
        ).fetchall():
            reviewed[(item["identity_external_id"], item["resource_id"], item["role_name"])] = item["decided_at"]
        for item in accesses:
            decided = reviewed.get((str(item["identityId"]), str(item["resourceId"]), str(item["role"])))
            if decided and (not item.get("lastReviewedAt") or decided > str(item["lastReviewedAt"])):
                item["lastReviewedAt"] = decided
        telemetry_status = discovered.get("telemetryStatus", "collected" if events else "not_collected")
        projects = discovered.get("projects", [])
        findings = evaluate_rules(identities, accesses, events, settings["rules"])
        risk_score_value = calculate_risk_score(findings, len(identities) + len(accesses))
        cursor = connection.execute(
            "INSERT INTO scans(credential_id,provider,status,started_at) VALUES(?,?,?,?) RETURNING id",
            (credential_id, row["provider"], "running", started_at),
        )
        scan_id = cursor.fetchone()["id"]
        current = connection.execute(
            "SELECT rule_code,identity_external_id,resource_id,title,status,severity FROM findings WHERE credential_id=? AND status NOT IN ('superseded','resolved')",
            (credential_id,),
        ).fetchall()
        carried = {finding_key(item["rule_code"], item["identity_external_id"], item["resource_id"], item["title"]): item["status"]
                   for item in current if item["status"] in CARRIED_STATUSES}
        previous_critical = {finding_key(item["rule_code"], item["identity_external_id"], item["resource_id"], item["title"])
                             for item in current if item["severity"] == "critical"}
        connection.execute("DELETE FROM identities WHERE credential_id=?", (credential_id,))
        connection.execute("DELETE FROM access_grants WHERE credential_id=?", (credential_id,))
        connection.execute("DELETE FROM cloud_resources WHERE credential_id=?", (credential_id,))
        connection.execute("DELETE FROM telemetry_events WHERE credential_id=?", (credential_id,))
        connection.execute("UPDATE findings SET status='superseded' WHERE credential_id=? AND status NOT IN ('superseded','resolved')", (credential_id,))
        for item in identities:
            connection.execute(
                """INSERT INTO identities(credential_id,external_id,display_name,identity_type,email,enabled,
                   mfa_enabled,owner,lifecycle_status,last_seen_at,raw_json) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (credential_id, str(item["id"]), item["name"], item.get("type", "user"), item.get("email"),
                 int(item.get("enabled", True)), None if item.get("mfaEnabled") is None else int(item["mfaEnabled"]),
                 item.get("owner"), item.get("lifecycleStatus"), item.get("lastSeenAt"), json.dumps(item)),
            )
        for item in accesses:
            connection.execute(
                """INSERT INTO access_grants(credential_id,identity_external_id,resource_id,resource_name,role_name,
                   permissions_json,privileged,granted_at,last_used_at,last_reviewed_at,raw_json)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (credential_id, str(item["identityId"]), str(item["resourceId"]), item.get("resourceName", item["resourceId"]),
                 item["role"], json.dumps(item.get("permissions", [])), int(item.get("privileged", False)),
                 item.get("grantedAt"), item.get("lastUsedAt"), item.get("lastReviewedAt"), json.dumps(item)),
            )
        for item in projects:
            if not isinstance(item, dict) or not item.get("id"):
                continue
            connection.execute(
                "INSERT INTO cloud_resources(credential_id,external_id,display_name,resource_type,raw_json) VALUES(?,?,?,?,?)",
                (credential_id, str(item["id"]), item.get("name", str(item["id"])), item.get("type", "project"), json.dumps(item)),
            )
        source = TELEMETRY_SOURCE.get(row["provider"], row["provider"])
        for event in events:
            connection.execute(
                """INSERT INTO telemetry_events(credential_id,scan_id,identity_external_id,resource_id,occurred_at,method,
                   caller_ip,denied,anomalous,risk_score,description,source) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (credential_id, scan_id, str(event.get("identityId") or ""), str(event.get("resourceId") or ""),
                 event.get("timestamp"), event.get("method"), event.get("callerIp"), int(bool(event.get("denied"))),
                 int(bool(event.get("anomalous"))), float(event.get("riskScore") or 0), event.get("description"), source),
            )
        now = utc_now()
        new_critical = []
        for item in findings:
            key = finding_key(item["rule"], item["identityId"], item["resourceId"], item["title"])
            if item["severity"] == "critical" and key not in previous_critical:
                new_critical.append(item)
            connection.execute(
                """INSERT INTO findings(credential_id,scan_id,rule_code,severity,title,description,
                   identity_external_id,resource_id,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (credential_id, scan_id, item["rule"], item["severity"], item["title"], item["description"],
                 item["identityId"], item["resourceId"], carried.get(key, "open"), now, now),
            )
        finished_at = utc_now()
        connection.execute(
            "UPDATE scans SET status='completed',identity_count=?,access_count=?,finding_count=?,telemetry_event_count=?,telemetry_status=?,risk_score=?,finished_at=? WHERE id=?",
            (len(identities), len(accesses), len(findings), len(events), telemetry_status, risk_score_value, finished_at, scan_id),
        )
        scope = f"{len(projects)} projetos/contas · {len(identities)} identidades · {len(accesses)} acessos"
        expires_at = discovered.get("expiresAt") or row["expires_at"]
        connection.execute(
            """UPDATE credentials SET scope=?,status=?,last_error=NULL,expires_at=?,principal=COALESCE(?,principal),
               last_synced_at=?,updated_at=? WHERE id=?""",
            (scope, "Conectado", expires_at, discovered.get("principal"), finished_at, finished_at, credential_id),
        )
        audit(connection, "risk", "Análise de acesso concluída",
              f"{row['name']}: {len(identities)} identidades, {len(accesses)} acessos e {len(findings)} riscos.", actor,
              action="analysis.completed", target=row["name"],
              details={"identities": len(identities), "grants": len(accesses), "risks": len(findings),
                       "telemetryEvents": len(events), "riskScore": risk_score_value})
    ueba_alerts = [item for item in findings if item["rule"] == "UEBA_ANOMALY"]
    if new_critical:
        notify("critical", f"{len(new_critical)} novo(s) risco(s) crítico(s) em {row['name']}: "
               + "; ".join(item["title"] for item in new_critical[:5]), settings)
    if ueba_alerts:
        notify("ueba", f"{len(ueba_alerts)} anomalia(s) UEBA acima de {settings['rules']['ueba_threshold']} pts em {row['name']}.", settings)
    expiry = parse_date(expires_at) if expires_at else None
    if expiry and (expiry - datetime.now(timezone.utc)).days <= 7:
        notify("credential", f"A credencial {row['name']} expira em {max(0, (expiry - datetime.now(timezone.utc)).days)} dia(s).", settings)
    ai_analysis = generate_platform_analysis(
        credential_id, scan_id, row["name"], row["provider"], identities, accesses, findings, projects
    )
    return {"scanId": scan_id, "status": "completed", "provider": row["provider"], "source": "live",
            "identities": len(identities), "accesses": len(accesses), "findings": len(findings),
            "riskScore": risk_score_value, "finishedAt": finished_at,
            "ueba": {"eventsEvaluated": len(events), "status": telemetry_status, "anomalies": len(ueba_alerts)},
            "aiAnalysis": {"id": ai_analysis["id"], "engine": ai_analysis["engine"], "priority": ai_analysis["priority"]}}


@app.post("/api/credentials/{credential_id}/scan")
def scan_credential(credential_id: int, request: Request) -> dict[str, Any]:
    try:
        return run_scan(credential_id, request.state.user["email"])
    except ScanError as exc:
        notify("credential", f"Falha na análise de {exc.credential_name}: {exc}", exc.settings)
        raise HTTPException(502, str(exc)) from exc


def next_scheduled_run(settings: dict[str, Any], credentials: list[Any]) -> str | None:
    interval = SCHEDULES.get(settings["schedule"])
    if not interval or not credentials:
        return None
    now = datetime.now(timezone.utc)
    candidates = []
    for item in credentials:
        last = parse_date(item["last_synced_at"]) if item["last_synced_at"] else None
        candidates.append(now if last is None else max(now, last + timedelta(seconds=interval)))
    return min(candidates).isoformat()


def scheduler_tick() -> None:
    with db() as connection:
        settings = load_settings(connection)
        credentials = connection.execute("SELECT id,name,last_synced_at FROM credentials ORDER BY id").fetchall()
        weekly = connection.execute("SELECT value FROM platform_settings WHERE key='weekly'").fetchone()
    interval = SCHEDULES.get(settings["schedule"])
    now = datetime.now(timezone.utc)
    if interval:
        for item in credentials:
            last = parse_date(item["last_synced_at"]) if item["last_synced_at"] else None
            if last is not None and (now - last).total_seconds() < interval:
                continue
            try:
                run_scan(item["id"], "agendador")
            except ScanError as exc:
                notify("credential", f"Falha na análise agendada de {exc.credential_name}: {exc}", exc.settings)
            except HTTPException:
                continue
    last_weekly = parse_date(json.loads(weekly["value"]).get("sentAt")) if weekly else None
    if settings["notifications"].get("weekly") and settings["webhook"] and (last_weekly is None or (now - last_weekly).days >= 7):
        overview = dashboard_overview(None, None, 7)
        sent = notify("weekly", f"Resumo semanal: nota de risco {overview['score']}/100, {overview['total']} riscos ativos "
                      f"({overview['severities']['critical']} críticos), {overview['newRisks']} novos em 7 dias.", settings)
        if sent:
            with db() as connection:
                connection.execute(
                    """INSERT INTO platform_settings(key,value,updated_at) VALUES('weekly',?,?)
                       ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at""",
                    (json.dumps({"sentAt": now.isoformat()}), now.isoformat()),
                )


SCHEDULER_STARTED = threading.Event()


def start_scheduler() -> None:
    if os.getenv("SCHEDULER_ENABLED", "1") == "0" or SCHEDULER_STARTED.is_set():
        return
    SCHEDULER_STARTED.set()

    def loop() -> None:
        while True:
            time.sleep(60)
            try:
                scheduler_tick()
            except Exception as exc:  # the scheduler must survive transient database or provider failures
                print(f"scheduler: {type(exc).__name__}: {exc}", flush=True)

    threading.Thread(target=loop, name="nexo-scheduler", daemon=True).start()


def placeholders(values: list[Any]) -> str:
    return ",".join("?" for _ in values) or "NULL"


def scoped_credentials(connection: DatabaseConnection, credential_id: int | None, provider: str | None) -> list[Any]:
    rows = connection.execute("SELECT * FROM credentials ORDER BY name").fetchall()
    return [row for row in rows if (credential_id is None or row["id"] == credential_id)
            and (provider is None or row["provider"] == provider)]


def credential_health(row: Any) -> tuple[str, bool]:
    """(label, needs attention) for a credential, shared by the dashboard and the sidebar."""
    if row["status"] == "Erro":
        return "Falha na última análise", True
    expiry = parse_date(row["expires_at"]) if row["expires_at"] else None
    if expiry:
        days = (expiry - datetime.now(timezone.utc)).days
        if days <= 0:
            return "Credencial expirada", True
        if days <= 15:
            return f"Credencial expira em {days}d", True
    return ("Analisado", False) if row["last_synced_at"] else ("Aguardando análise", False)


def compliance_metrics(connection: DatabaseConnection, ids: list[int]) -> dict[str, Any]:
    marks, params = placeholders(ids), tuple(ids)
    rules: dict[str, dict[str, int]] = {}
    for row in connection.execute(
        f"""SELECT rule_code,COUNT(*) total,SUM(CASE WHEN severity IN ('critical','high') THEN 1 ELSE 0 END) severe
            FROM findings WHERE status='open' AND credential_id IN ({marks}) GROUP BY rule_code""", params
    ).fetchall():
        rules[row["rule_code"]] = {"total": row["total"], "severe": row["severe"] or 0}
    count = lambda query: connection.execute(query, params).fetchone()["count"]
    now = utc_now()
    latest_telemetry = connection.execute(
        f"""SELECT s.telemetry_status FROM scans s WHERE s.id IN (SELECT MAX(id) FROM scans WHERE status='completed'
            AND credential_id IN ({marks}) GROUP BY credential_id)""", params
    ).fetchall()
    campaigns = connection.execute(
        f"""SELECT c.id,c.due_at,c.completed_at,(SELECT COUNT(*) FROM review_items i WHERE i.campaign_id=c.id AND i.decision IS NULL) pending
            FROM review_campaigns c WHERE c.credential_id IS NULL OR c.credential_id IN ({marks})""", params
    ).fetchall()
    privileged = count(f"SELECT COUNT(*) count FROM access_grants WHERE privileged=1 AND credential_id IN ({marks})")
    jit = count(f"""SELECT COUNT(*) count FROM access_grants a WHERE a.privileged=1 AND a.credential_id IN ({marks}) AND EXISTS(
                    SELECT 1 FROM access_requests r WHERE r.credential_id=a.credential_id AND r.identity_external_id=a.identity_external_id
                    AND r.resource_id=a.resource_id AND r.role_name=a.role_name AND r.action='jit')""")
    scans = count(f"SELECT COUNT(*) count FROM scans WHERE status='completed' AND credential_id IN ({marks})")
    return {
        "assessed": scans > 0, "scans": scans, "rules": rules, "environments": len(ids),
        "mfa_known": count(f"SELECT COUNT(*) count FROM identities WHERE identity_type='user' AND enabled=1 AND mfa_enabled IS NOT NULL AND credential_id IN ({marks})"),
        "mfa_missing": count(f"SELECT COUNT(*) count FROM identities WHERE identity_type='user' AND enabled=1 AND mfa_enabled=0 AND credential_id IN ({marks})"),
        "audit_events": connection.execute("SELECT COUNT(*) count FROM audit_events").fetchone()["count"],
        "telemetry_envs": sum(1 for row in latest_telemetry if row["telemetry_status"] in {"collected", "partial"}),
        "grants": count(f"SELECT COUNT(*) count FROM access_grants WHERE credential_id IN ({marks})"),
        "campaigns": len(campaigns),
        "campaigns_overdue": sum(1 for row in campaigns if not row["completed_at"] and row["pending"] and row["due_at"] < now),
        "privileged": privileged, "privileged_standing": privileged - jit,
        "critical_open": count(f"SELECT COUNT(*) count FROM findings WHERE status='open' AND severity='critical' AND credential_id IN ({marks})"),
    }


def first_seen(connection: DatabaseConnection, row: Any) -> str:
    found = connection.execute(
        """SELECT MIN(created_at) first FROM findings WHERE credential_id=? AND rule_code=? AND title=?
           AND COALESCE(identity_external_id,'')=? AND COALESCE(resource_id,'')=?""",
        (row["credential_id"], row["rule_code"], row["title"], row["identity_external_id"] or "", row["resource_id"] or ""),
    ).fetchone()
    return found["first"] or row["created_at"]


def identity_label(connection: DatabaseConnection, credential_id: int, external_id: str | None) -> str:
    if not external_id:
        return "Ambiente"
    row = connection.execute("SELECT display_name FROM identities WHERE credential_id=? AND external_id=?",
                             (credential_id, external_id)).fetchone()
    return row["display_name"] if row else external_id


def resource_label(connection: DatabaseConnection, credential_id: int, resource_id: str | None) -> str:
    if not resource_id:
        return ""
    row = connection.execute("SELECT display_name FROM cloud_resources WHERE credential_id=? AND external_id=?",
                             (credential_id, resource_id)).fetchone()
    if row:
        return row["display_name"]
    grant = connection.execute("SELECT resource_name FROM access_grants WHERE credential_id=? AND resource_id=? LIMIT 1",
                               (credential_id, resource_id)).fetchone()
    return grant["resource_name"] if grant else resource_id


def trend_series(scans: list[Any], weights: dict[int, int], period: int) -> list[dict[str, Any]]:
    """Daily consolidated risk: each credential contributes its latest score up to that day, weighted by identities."""
    if not scans:
        return []
    today = datetime.now(timezone.utc).date()
    first_day = min(parse_date(row["finished_at"]).date() for row in scans)
    start = max(first_day, today - timedelta(days=period - 1))
    days = [start + timedelta(days=offset) for offset in range((today - start).days + 1)]
    step = max(1, len(days) // 14)
    sampled = days[::step]
    if sampled[-1] != today:
        sampled.append(today)
    points = []
    for day in sampled:
        latest: dict[int, int] = {}
        for row in scans:
            if parse_date(row["finished_at"]).date() <= day:
                latest[row["credential_id"]] = row["risk_score"]
        if not latest:
            continue
        total_weight = sum(max(1, weights.get(key, 1)) for key in latest)
        posture = sum(value * max(1, weights.get(key, 1)) for key, value in latest.items()) / total_weight
        points.append({"date": day.isoformat(), "risk": round(100 - posture)})
    return points


def dashboard_overview(credential_id: int | None, provider: str | None, period: int) -> dict[str, Any]:
    period = period if period in {7, 30, 90} else 90
    now = datetime.now(timezone.utc)
    window_start = (now - timedelta(days=period)).isoformat()
    with db() as connection:
        every = connection.execute("SELECT * FROM credentials ORDER BY name").fetchall()
        scoped = scoped_credentials(connection, credential_id, provider)
        ids = [row["id"] for row in scoped]
        all_ids = [row["id"] for row in every]
        marks, params = placeholders(ids), tuple(ids)
        all_marks, all_params = placeholders(all_ids), tuple(all_ids)
        open_all = connection.execute(
            f"""SELECT f.*,c.provider FROM findings f JOIN credentials c ON c.id=f.credential_id
                WHERE f.status='open' AND f.credential_id IN ({all_marks})""", all_params
        ).fetchall()
        open_scoped = [row for row in open_all if row["credential_id"] in ids]
        identity_by_credential = {row["credential_id"]: row["count"] for row in connection.execute(
            f"SELECT credential_id,COUNT(*) count FROM identities WHERE credential_id IN ({all_marks}) GROUP BY credential_id", all_params).fetchall()}
        grants_by_credential = {row["credential_id"]: row["count"] for row in connection.execute(
            f"SELECT credential_id,COUNT(*) count FROM access_grants WHERE credential_id IN ({all_marks}) GROUP BY credential_id", all_params).fetchall()}
        privileged = connection.execute(f"SELECT COUNT(*) count FROM access_grants WHERE privileged=1 AND credential_id IN ({marks})", params).fetchone()["count"]
        scans = connection.execute(
            f"""SELECT credential_id,risk_score,identity_count,access_count,finished_at FROM scans
                WHERE status='completed' AND risk_score IS NOT NULL AND credential_id IN ({marks}) ORDER BY finished_at""", params
        ).fetchall()
        known_before = {finding_key(row["rule_code"], row["identity_external_id"], row["resource_id"], row["title"]) + (row["credential_id"],)
                        for row in connection.execute(
                            f"""SELECT DISTINCT credential_id,rule_code,identity_external_id,resource_id,title FROM findings
                                WHERE created_at<? AND credential_id IN ({marks})""", (window_start, *params)).fetchall()}
        resources = connection.execute(
            f"""SELECT r.credential_id,r.external_id,r.display_name,r.resource_type,
                COUNT(DISTINCT a.identity_external_id) identity_count,COUNT(a.id) grant_count
                FROM cloud_resources r LEFT JOIN access_grants a ON a.credential_id=r.credential_id AND a.resource_id=r.external_id
                WHERE r.resource_type<>'repository' AND r.credential_id IN ({marks})
                GROUP BY r.credential_id,r.external_id,r.display_name,r.resource_type""", params
        ).fetchall()
        anomalies_24h = connection.execute(
            f"SELECT COUNT(*) count FROM telemetry_events WHERE anomalous=1 AND occurred_at>=? AND credential_id IN ({marks})",
            ((now - timedelta(hours=24)).isoformat(), *params)).fetchone()["count"]
        recent_events = connection.execute(
            f"""SELECT t.*,c.provider FROM telemetry_events t JOIN credentials c ON c.id=t.credential_id
                WHERE t.anomalous=1 AND t.credential_id IN ({marks}) ORDER BY t.occurred_at DESC LIMIT 5""", params
        ).fetchall()
        top = sorted(open_scoped, key=lambda row: (SEVERITY_ORDER.get(row["severity"], 9), row["id"]))[:5]
        priorities = [{"id": row["id"], "severity": row["severity"], "rule": RULE_CATALOG.get(row["rule_code"], {}).get("name", row["rule_code"]),
                       "title": row["title"], "who": identity_label(connection, row["credential_id"], row["identity_external_id"]),
                       "where": f"{row['provider']} {resource_label(connection, row['credential_id'], row['resource_id'])}".strip(),
                       "firstSeen": first_seen(connection, row)} for row in top]
        recent = [{"time": row["occurred_at"], "title": row["description"] or row["method"], "who": row["identity_external_id"],
                   "provider": row["provider"], "category": classify_event(row["method"], bool(row["denied"]), row["occurred_at"])}
                  for row in recent_events]
        metrics = compliance_metrics(connection, ids)
        orphan = sum(1 for row in open_scoped if row["rule_code"] == "ORPHAN_ACCOUNT")
    severities = {level: sum(1 for row in open_scoped if row["severity"] == level) for level in ("critical", "high", "medium", "low")}
    identities = sum(identity_by_credential.get(key, 0) for key in ids)
    accesses = sum(grants_by_credential.get(key, 0) for key in ids)
    assessed = bool(scans)
    score = risk_score([row["severity"] for row in open_scoped], identities + accesses) if assessed else None

    def baseline(field: str) -> int | None:
        before: dict[int, int] = {}
        for row in scans:
            if row["finished_at"] < window_start:
                before[row["credential_id"]] = row[field]
        return sum(before.values()) if before else None

    providers = []
    for name in ("GCP", "AWS", "Azure"):
        provider_ids = [row["id"] for row in every if row["provider"] == name]
        if not provider_ids:
            continue
        rows = [row for row in open_all if row["credential_id"] in provider_ids]
        objects = sum(identity_by_credential.get(key, 0) + grants_by_credential.get(key, 0) for key in provider_ids)
        synced = any(row["last_synced_at"] for row in every if row["id"] in provider_ids)
        providers.append({"provider": name, "environments": len(provider_ids),
                          "score": risk_score([row["severity"] for row in rows], objects) if synced else None,
                          "risks": len(rows), "critical": sum(1 for row in rows if row["severity"] == "critical"),
                          "identities": sum(identity_by_credential.get(key, 0) for key in provider_ids)})
    findings_by_resource: dict[tuple[int, str], list[str]] = {}
    for row in open_scoped:
        if row["resource_id"]:
            findings_by_resource.setdefault((row["credential_id"], row["resource_id"]), []).append(row["severity"])
    credential_by_id = {row["id"]: row for row in every}
    environment_rows = []
    for row in resources:
        severities_here = findings_by_resource.get((row["credential_id"], row["external_id"]), [])
        health, attention = credential_health(credential_by_id[row["credential_id"]])
        environment_rows.append({
            "credentialId": row["credential_id"], "resourceId": row["external_id"], "name": row["display_name"],
            "type": row["resource_type"], "provider": credential_by_id[row["credential_id"]]["provider"],
            "identities": row["identity_count"], "critical": severities_here.count("critical"), "high": severities_here.count("high"),
            "score": risk_score(severities_here, row["identity_count"] + row["grant_count"]),
            "status": health, "attention": attention,
        })
    environment_rows.sort(key=lambda item: (-item["score"], -item["critical"], -item["identities"], item["name"]))
    heatmap = []
    provider_names = [item["provider"] for item in providers]
    for module, codes in MODULES:
        heatmap.append({"module": module, "cells": {name: sum(1 for row in open_all if row["provider"] == name
                                                              and (codes is None or row["rule_code"] in codes)) for name in provider_names}})
    frameworks = framework_report(metrics)
    return {
        "period": period, "assessed": assessed, "score": score,
        "level": risk_level(score) if score is not None else None,
        "severities": severities, "total": len(open_scoped),
        "newRisks": sum(1 for row in open_scoped if finding_key(row["rule_code"], row["identity_external_id"], row["resource_id"], row["title"]) + (row["credential_id"],) not in known_before),
        "environmentCount": len(scoped), "providerCount": len({row["provider"] for row in scoped}),
        "orphanAccounts": orphan,
        "providers": providers,
        "kpis": {"identities": identities, "identitiesBefore": baseline("identity_count"),
                 "accesses": accesses, "accessesBefore": baseline("access_count"),
                 "privileged": privileged, "orphanAccounts": orphan, "anomalies24h": anomalies_24h,
                 "compliance": round(sum(item["percent"] for item in frameworks) / len(frameworks)) if assessed else None},
        "trend": trend_series(scans, identity_by_credential, period),
        "rules": [{"code": code, "name": rule["name"], "count": sum(1 for row in open_scoped if row["rule_code"] == code)}
                  for code, rule in RULE_CATALOG.items()],
        "heatmap": heatmap, "environments": environment_rows[:10], "environmentTotal": len(environment_rows),
        "priorities": priorities, "ueba": recent,
        "frameworks": [{"key": item["key"], "name": item["name"], "percent": item["percent"], "met": item["met"],
                        "total": item["total"]} for item in frameworks],
        "credentials": [{"id": row["id"], "name": row["name"], "provider": row["provider"]} for row in every],
        "lastAnalysisAt": scans[-1]["finished_at"] if scans else None,
    }


@app.get("/api/dashboard/overview")
def dashboard_overview_endpoint(credential_id: int | None = None, provider: Literal["GCP", "AWS", "Azure"] | None = None,
                                period: int = Query(90, ge=1, le=365)) -> dict[str, Any]:
    return dashboard_overview(credential_id, provider, period)


@app.get("/api/platform/status")
def platform_status() -> dict[str, Any]:
    with db() as connection:
        rows = connection.execute("SELECT * FROM credentials").fetchall()
        last = connection.execute("SELECT MAX(finished_at) last FROM scans WHERE status='completed'").fetchone()["last"]
        critical = connection.execute("SELECT COUNT(*) count FROM findings WHERE status='open' AND severity='critical'").fetchone()["count"]
    attention = sum(1 for row in rows if credential_health(row)[1])
    return {"integrations": len(rows), "connected": sum(1 for row in rows if row["last_synced_at"]),
            "attention": attention, "lastAnalysisAt": last, "criticalOpen": critical}


RISK_WEIGHT_SQL = "CASE f.severity WHEN 'critical' THEN 40 WHEN 'high' THEN 25 WHEN 'medium' THEN 10 ELSE 5 END"


@app.get("/api/identities")
def list_identities(credential_id: int | None = None, q: str | None = None,
                    offset: int = Query(0, ge=0), limit: int = Query(200, ge=1, le=10000)) -> list[dict[str, Any]]:
    query = f"""SELECT i.*, c.name AS credential_name, c.provider,
        (SELECT COUNT(*) FROM access_grants a WHERE a.credential_id=i.credential_id AND a.identity_external_id=i.external_id) AS access_count,
        (SELECT COUNT(*) FROM access_grants a WHERE a.credential_id=i.credential_id AND a.identity_external_id=i.external_id AND a.privileged=1) AS privileged_count,
        (SELECT COUNT(DISTINCT a.resource_id) FROM access_grants a WHERE a.credential_id=i.credential_id AND a.identity_external_id=i.external_id) AS resource_count,
        (SELECT COUNT(*) FROM findings f WHERE f.credential_id=i.credential_id AND f.identity_external_id=i.external_id AND f.status='open') AS finding_count,
        (SELECT COALESCE(SUM({RISK_WEIGHT_SQL}),0) FROM findings f WHERE f.credential_id=i.credential_id AND f.identity_external_id=i.external_id AND f.status='open') AS risk_weight,
        (SELECT COUNT(*) FROM findings f WHERE f.credential_id=i.credential_id AND f.identity_external_id=i.external_id AND f.status='open' AND f.rule_code='ORPHAN_ACCOUNT') AS orphan_count,
        (SELECT f.severity FROM findings f WHERE f.credential_id=i.credential_id AND f.identity_external_id=i.external_id AND f.status='open'
         ORDER BY CASE f.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END LIMIT 1) AS max_severity
        FROM identities i JOIN credentials c ON c.id=i.credential_id"""
    clauses: list[str] = []
    params: list[Any] = []
    if credential_id is not None:
        clauses.append("i.credential_id=?")
        params.append(credential_id)
    if q and q.strip():
        clauses.append("(LOWER(i.display_name) LIKE ? OR LOWER(i.external_id) LIKE ? OR LOWER(COALESCE(i.email,'')) LIKE ?)")
        term = f"%{q.strip().lower()}%"
        params.extend((term, term, term))
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY risk_weight DESC, i.display_name LIMIT ? OFFSET ?"
    params.extend((limit, offset))
    with db() as connection:
        rows = connection.execute(query, tuple(params)).fetchall()
    return [{"id": row["id"], "credentialId": row["credential_id"], "externalId": row["external_id"],
             "name": row["display_name"], "type": row["identity_type"], "email": row["email"],
             "enabled": bool(row["enabled"]), "mfaEnabled": None if row["mfa_enabled"] is None else bool(row["mfa_enabled"]),
             "owner": row["owner"], "lifecycleStatus": row["lifecycle_status"], "lastSeenAt": row["last_seen_at"],
             "environment": row["credential_name"], "provider": row["provider"],
             "accessCount": row["access_count"], "privilegedCount": row["privileged_count"],
             "resourceCount": row["resource_count"], "findingCount": row["finding_count"],
             "orphan": bool(row["orphan_count"]), "riskScore": min(100, int(row["risk_weight"] or 0)),
             "maxSeverity": row["max_severity"]} for row in rows]


@app.get("/api/identities/summary")
def identities_summary(credential_id: int | None = None) -> dict[str, Any]:
    clause, params = (" AND credential_id=?", (credential_id,)) if credential_id is not None else ("", ())
    inactive_before = (datetime.now(timezone.utc) - timedelta(days=90)).isoformat()
    with db() as connection:
        count = lambda condition, extra=(): connection.execute(
            f"SELECT COUNT(*) count FROM identities WHERE {condition}{clause}", (*extra, *params)).fetchone()["count"]
        orphan = connection.execute(
            f"SELECT COUNT(DISTINCT identity_external_id) count FROM findings WHERE status='open' AND rule_code='ORPHAN_ACCOUNT'{clause}",
            params).fetchone()["count"]
        return {"total": count("1=1"), "humans": count("identity_type='user'"), "services": count("identity_type='service'"),
                "groups": count("identity_type='group'"), "orphan": orphan,
                "noMfa": count("identity_type='user' AND enabled=1 AND mfa_enabled=0"),
                "mfaKnown": count("identity_type='user' AND enabled=1 AND mfa_enabled IS NOT NULL"),
                "inactive90": count("last_seen_at IS NOT NULL AND last_seen_at<?", (inactive_before,)),
                "lastSeenKnown": count("last_seen_at IS NOT NULL")}


@app.get("/api/identities/{identity_id}")
def identity_dossier(identity_id: int) -> dict[str, Any]:
    with db() as connection:
        identity = connection.execute(
            """SELECT i.*,c.name AS credential_name,c.provider FROM identities i
               JOIN credentials c ON c.id=i.credential_id WHERE i.id=?""", (identity_id,)
        ).fetchone()
        if not identity:
            raise HTTPException(status_code=404, detail="Identidade não encontrada.")
        grants = connection.execute(
            """SELECT a.*,COALESCE(r.resource_type,'resource') AS resource_type FROM access_grants a
               LEFT JOIN cloud_resources r ON r.credential_id=a.credential_id AND r.external_id=a.resource_id
               WHERE a.credential_id=? AND a.identity_external_id=? ORDER BY a.privileged DESC,a.resource_name,a.role_name LIMIT 1000""",
            (identity["credential_id"], identity["external_id"]),
        ).fetchall()
        findings = connection.execute(
            """SELECT * FROM findings WHERE credential_id=? AND identity_external_id=? AND status='open'
               ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END,id DESC""",
            (identity["credential_id"], identity["external_id"]),
        ).fetchall()
    accesses = []
    for row in grants:
        context = role_context(identity["provider"], row["role_name"], row["resource_type"])
        accesses.append({"id": row["id"], "resourceId": row["resource_id"], "resourceName": row["resource_name"],
                         "resourceType": row["resource_type"], "role": row["role_name"], "roleLabel": context["label"],
                         "capability": context["capability"], "severity": context["severity"],
                         "privileged": bool(row["privileged"]), "lastUsedAt": row["last_used_at"],
                         "lastReviewedAt": row["last_reviewed_at"]})
    risks = []
    for row in findings:
        guidance = RULE_CATALOG.get(row["rule_code"], DEFAULT_RULE_GUIDANCE)
        risks.append({"id": row["id"], "rule": row["rule_code"], "severity": row["severity"],
                      "title": row["title"], "description": row["description"], "resourceId": row["resource_id"],
                      "why": guidance.get("why", DEFAULT_RULE_GUIDANCE["why"]),
                      "recommendation": guidance.get("recommendation", DEFAULT_RULE_GUIDANCE["recommendation"]),
                      "treatment": guidance.get("treatment", DEFAULT_RULE_GUIDANCE["treatment"])})
    return {"id": identity["id"], "externalId": identity["external_id"], "name": identity["display_name"],
            "type": identity["identity_type"], "email": identity["email"], "owner": identity["owner"],
            "enabled": bool(identity["enabled"]),
            "mfaEnabled": None if identity["mfa_enabled"] is None else bool(identity["mfa_enabled"]),
            "lifecycleStatus": identity["lifecycle_status"], "lastSeenAt": identity["last_seen_at"],
            "credentialId": identity["credential_id"], "environment": identity["credential_name"],
            "provider": identity["provider"], "accesses": accesses, "findings": risks,
            "riskScore": identity_risk([item["severity"] for item in risks]),
            "resourceCount": len({item["resourceId"] for item in accesses}),
            "privilegedCount": sum(1 for item in accesses if item["privileged"])}


@app.get("/api/inventory/projects")
def inventory_by_project(limit: int = Query(1000, ge=1, le=10000)) -> list[dict[str, Any]]:
    with db() as connection:
        rows = connection.execute(
            """SELECT a.credential_id,c.name AS environment,c.provider,a.resource_id,a.resource_name,
               COALESCE(r.resource_type,'resource') AS resource_type,
               COUNT(*) AS access_count,COUNT(DISTINCT a.identity_external_id) AS identity_count,
               SUM(CASE WHEN a.privileged=1 THEN 1 ELSE 0 END) AS privileged_count,
               (SELECT COUNT(*) FROM findings f WHERE f.credential_id=a.credential_id AND f.resource_id=a.resource_id AND f.status='open') AS finding_count,
               (SELECT f.severity FROM findings f WHERE f.credential_id=a.credential_id AND f.resource_id=a.resource_id AND f.status='open'
                ORDER BY CASE f.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END LIMIT 1) AS max_severity
               FROM access_grants a JOIN credentials c ON c.id=a.credential_id
               LEFT JOIN cloud_resources r ON r.credential_id=a.credential_id AND r.external_id=a.resource_id
               GROUP BY a.credential_id,c.name,c.provider,a.resource_id,a.resource_name,r.resource_type
               ORDER BY privileged_count DESC,access_count DESC,a.resource_name LIMIT ?""", (limit,)
        ).fetchall()
    return [{"credentialId": row["credential_id"], "environment": row["environment"], "provider": row["provider"],
             "resourceId": row["resource_id"], "name": row["resource_name"], "type": row["resource_type"],
             "identityCount": row["identity_count"], "accessCount": row["access_count"],
             "privilegedCount": row["privileged_count"], "findingCount": row["finding_count"],
             "maxSeverity": row["max_severity"]} for row in rows]


@app.get("/api/inventory/roles")
def inventory_by_role(limit: int = Query(1000, ge=1, le=10000)) -> list[dict[str, Any]]:
    with db() as connection:
        rows = connection.execute(
            """SELECT a.credential_id,c.name AS environment,c.provider,a.role_name,
               COUNT(*) AS access_count,COUNT(DISTINCT a.identity_external_id) AS identity_count,
               COUNT(DISTINCT a.resource_id) AS resource_count,
               SUM(CASE WHEN a.privileged=1 THEN 1 ELSE 0 END) AS privileged_count,
               (SELECT COUNT(DISTINCT f.id) FROM findings f WHERE f.credential_id=a.credential_id AND f.status='open'
                AND f.identity_external_id IN (SELECT x.identity_external_id FROM access_grants x WHERE x.credential_id=a.credential_id AND x.role_name=a.role_name)) AS finding_count
               FROM access_grants a JOIN credentials c ON c.id=a.credential_id
               GROUP BY a.credential_id,c.name,c.provider,a.role_name
               ORDER BY privileged_count DESC,access_count DESC,a.role_name LIMIT ?""", (limit,)
        ).fetchall()
    result = []
    for row in rows:
        context = role_context(row["provider"], row["role_name"], "resource")
        result.append({"credentialId": row["credential_id"], "environment": row["environment"], "provider": row["provider"],
                       "role": row["role_name"], "roleLabel": context["label"], "capability": context["capability"],
                       "severity": context["severity"], "identityCount": row["identity_count"],
                       "resourceCount": row["resource_count"], "accessCount": row["access_count"],
                       "privilegedCount": row["privileged_count"], "findingCount": row["finding_count"]})
    return result


@app.get("/api/inventory/accounts")
def inventory_by_account(limit: int = Query(1000, ge=1, le=10000)) -> list[dict[str, Any]]:
    return list_identities(credential_id=None, q=None, offset=0, limit=limit)


@app.get("/api/inventory/project-detail")
def project_drilldown(credential_id: int, resource_id: str) -> dict[str, Any]:
    with db() as connection:
        credential = connection.execute("SELECT id,name,provider FROM credentials WHERE id=?", (credential_id,)).fetchone()
        if not credential:
            raise HTTPException(404, "Ambiente não encontrado.")
        resource = connection.execute(
            "SELECT display_name,resource_type FROM cloud_resources WHERE credential_id=? AND external_id=?",
            (credential_id, resource_id),
        ).fetchone()
        grants = connection.execute(
            """SELECT a.*,i.id AS identity_db_id,i.display_name,i.identity_type,i.email
               FROM access_grants a LEFT JOIN identities i ON i.credential_id=a.credential_id AND i.external_id=a.identity_external_id
               WHERE a.credential_id=? AND a.resource_id=? ORDER BY a.role_name,i.display_name""",
            (credential_id, resource_id),
        ).fetchall()
        risk_rows = connection.execute(
            """SELECT severity,COUNT(*) AS count FROM findings WHERE credential_id=? AND resource_id=? AND status='open'
               GROUP BY severity""", (credential_id, resource_id),
        ).fetchall()
    if not grants and not resource:
        raise HTTPException(404, "Projeto ou recurso não encontrado no inventário.")
    roles_by_name: dict[str, dict[str, Any]] = {}
    for row in grants:
        role = roles_by_name.get(row["role_name"])
        if role is None:
            context = role_context(credential["provider"], row["role_name"], resource["resource_type"] if resource else "resource")
            role = {"role": row["role_name"], "roleLabel": context["label"], "capability": context["capability"],
                    "severity": context["severity"], "privileged": False, "accounts": []}
            roles_by_name[row["role_name"]] = role
        role["privileged"] = role["privileged"] or bool(row["privileged"])
        role["accounts"].append({"id": row["identity_db_id"], "externalId": row["identity_external_id"],
                                  "name": row["display_name"] or row["identity_external_id"],
                                  "type": row["identity_type"] or "unknown", "email": row["email"],
                                  "privileged": bool(row["privileged"])})
    severities = {row["severity"]: row["count"] for row in risk_rows}
    return {"credentialId": credential_id, "environment": credential["name"], "provider": credential["provider"],
            "resourceId": resource_id, "name": resource["display_name"] if resource else grants[0]["resource_name"],
            "type": resource["resource_type"] if resource else "resource", "roles": list(roles_by_name.values()),
            "roleCount": len(roles_by_name), "accountCount": len({row["identity_external_id"] for row in grants}),
            "accessCount": len(grants), "risks": severities}


WILDCARD_ROLES = {"roles/owner", "AdministratorAccess", "Owner", "*:*"}


def grant_origin(identity_type: str | None) -> str:
    return {"group": "Grupo", "public": "Público"}.get(identity_type or "", "Direta")


@app.get("/api/accesses")
def list_accesses(credential_id: int | None = None, limit: int = Query(200, ge=1, le=20000)) -> list[dict[str, Any]]:
    query = """SELECT a.*,i.display_name identity_name,i.identity_type,i.id identity_db_id,c.name environment,c.provider,
               COALESCE(r.resource_type,'resource') resource_type FROM access_grants a
               JOIN credentials c ON c.id=a.credential_id
               LEFT JOIN identities i ON i.credential_id=a.credential_id AND i.external_id=a.identity_external_id
               LEFT JOIN cloud_resources r ON r.credential_id=a.credential_id AND r.external_id=a.resource_id"""
    params: tuple[Any, ...] = ()
    if credential_id is not None:
        query += " WHERE a.credential_id=?"
        params = (credential_id,)
    query += " ORDER BY a.privileged DESC,a.id DESC LIMIT ?"
    params = (*params, limit)
    with db() as connection:
        rows = connection.execute(query, params).fetchall()
    result = []
    for row in rows:
        permissions = json.loads(row["permissions_json"])
        result.append({"id": row["id"], "credentialId": row["credential_id"], "identityId": row["identity_external_id"],
                       "identityDbId": row["identity_db_id"], "identityName": row["identity_name"] or row["identity_external_id"],
                       "identityType": row["identity_type"], "origin": grant_origin(row["identity_type"]),
                       "environment": row["environment"], "provider": row["provider"], "resourceType": row["resource_type"],
                       "resourceId": row["resource_id"], "resourceName": row["resource_name"], "role": row["role_name"],
                       "permissions": permissions, "privileged": bool(row["privileged"]),
                       "wildcard": row["role_name"] in WILDCARD_ROLES or any("*" in str(item) for item in permissions),
                       "grantedAt": row["granted_at"], "lastUsedAt": row["last_used_at"],
                       "lastReviewedAt": row["last_reviewed_at"]})
    return result


@app.get("/api/accesses/summary")
def accesses_summary(credential_id: int | None = None) -> dict[str, Any]:
    with db() as connection:
        unused_days = load_settings(connection)["rules"]["unused_days"]
        rows = connection.execute(
            """SELECT a.role_name,a.permissions_json,a.last_used_at,i.identity_type,c.provider FROM access_grants a
               JOIN credentials c ON c.id=a.credential_id
               LEFT JOIN identities i ON i.credential_id=a.credential_id AND i.external_id=a.identity_external_id"""
            + (" WHERE a.credential_id=?" if credential_id is not None else ""), (credential_id,) if credential_id is not None else ()
        ).fetchall()
        resources = connection.execute(
            "SELECT COUNT(*) count FROM cloud_resources" + (" WHERE credential_id=?" if credential_id is not None else ""),
            (credential_id,) if credential_id is not None else ()).fetchone()["count"]
    cutoff = datetime.now(timezone.utc) - timedelta(days=unused_days)
    by_provider: dict[str, dict[str, int]] = {}
    unused = with_usage = direct = group = wildcard = 0
    for row in rows:
        stats = by_provider.setdefault(row["provider"], {"total": 0, "withUsage": 0, "unused": 0})
        stats["total"] += 1
        last = parse_date(row["last_used_at"]) if row["last_used_at"] else None
        if last:
            last = last if last.tzinfo else last.replace(tzinfo=timezone.utc)
            with_usage += 1
            stats["withUsage"] += 1
            if last < cutoff:
                unused += 1
                stats["unused"] += 1
        if grant_origin(row["identity_type"]) == "Grupo":
            group += 1
        else:
            direct += 1
        if row["role_name"] in WILDCARD_ROLES or "*" in (row["permissions_json"] or ""):
            wildcard += 1
    return {"total": len(rows), "resources": resources, "unusedDays": unused_days, "unused": unused, "withUsage": with_usage,
            "direct": direct, "group": group, "wildcard": wildcard,
            "byProvider": [{"provider": key, **value} for key, value in sorted(by_provider.items())]}


@app.get("/api/resources")
def list_resources(credential_id: int | None = None, limit: int = Query(200, ge=1, le=20000)) -> list[dict[str, Any]]:
    query = "SELECT * FROM cloud_resources"
    params: tuple[Any, ...] = ()
    if credential_id is not None:
        query += " WHERE credential_id=?"
        params = (credential_id,)
    query += " ORDER BY display_name LIMIT ?"
    params = (*params, limit)
    with db() as connection:
        rows = connection.execute(query, params).fetchall()
    return [{"id": row["id"], "credentialId": row["credential_id"], "externalId": row["external_id"],
             "name": row["display_name"], "type": row["resource_type"]} for row in rows]


CURRENT_FINDING_STATUSES = ("open", "remediating", "accepted", "incident", "dismissed")


@app.get("/api/findings")
def list_findings(credential_id: int | None = None, finding_status: str = "open", rule: str | None = None,
                  limit: int = Query(200, ge=1, le=20000)) -> list[dict[str, Any]]:
    statuses = CURRENT_FINDING_STATUSES if finding_status == "current" else (finding_status,)
    clauses = [f"f.status IN ({placeholders(list(statuses))})"]
    params: list[Any] = list(statuses)
    if credential_id is not None:
        clauses.append("f.credential_id=?")
        params.append(credential_id)
    if rule:
        clauses.append("f.rule_code=?")
        params.append(rule)
    params.append(limit)
    with db() as connection:
        rows = connection.execute(
            f"""SELECT f.*,c.name environment,c.provider,COALESCE(i.display_name,f.identity_external_id) identity_name,
                COALESCE(r.display_name,f.resource_id) resource_name,
                (SELECT MIN(f2.created_at) FROM findings f2 WHERE f2.credential_id=f.credential_id AND f2.rule_code=f.rule_code
                 AND f2.title=f.title AND COALESCE(f2.identity_external_id,'')=COALESCE(f.identity_external_id,'')
                 AND COALESCE(f2.resource_id,'')=COALESCE(f.resource_id,'')) first_seen
                FROM findings f JOIN credentials c ON c.id=f.credential_id
                LEFT JOIN identities i ON i.credential_id=f.credential_id AND i.external_id=f.identity_external_id
                LEFT JOIN cloud_resources r ON r.credential_id=f.credential_id AND r.external_id=f.resource_id
                WHERE {' AND '.join(clauses)}
                ORDER BY CASE f.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END, f.id DESC LIMIT ?""",
            tuple(params),
        ).fetchall()
    result = []
    for row in rows:
        guidance = RULE_CATALOG.get(row["rule_code"], DEFAULT_RULE_GUIDANCE)
        result.append({"id": row["id"], "credentialId": row["credential_id"], "scanId": row["scan_id"],
                       "rule": row["rule_code"], "ruleName": RULE_CATALOG.get(row["rule_code"], {}).get("name", row["rule_code"]),
                       "severity": row["severity"], "title": row["title"], "description": row["description"],
                       "identityId": row["identity_external_id"], "identityName": row["identity_name"],
                       "resourceId": row["resource_id"], "resourceName": row["resource_name"],
                       "environment": row["environment"], "provider": row["provider"],
                       "status": row["status"], "createdAt": row["created_at"], "firstSeen": row["first_seen"] or row["created_at"],
                       "updatedAt": row["updated_at"],
                       "why": guidance.get("why", DEFAULT_RULE_GUIDANCE["why"]),
                       "recommendation": guidance.get("recommendation", DEFAULT_RULE_GUIDANCE["recommendation"]),
                       "treatment": guidance.get("treatment", DEFAULT_RULE_GUIDANCE["treatment"]),
                       "framework": RULE_CATALOG.get(row["rule_code"], {}).get("framework", "IGA")})
    return result


@app.get("/api/rules")
def rule_assessments(credential_id: int | None = None) -> list[dict[str, Any]]:
    finding_filter = " AND credential_id=?" if credential_id is not None else ""
    params: tuple[Any, ...] = (credential_id,) if credential_id is not None else ()
    credential_filter = " WHERE id=?" if credential_id is not None else ""
    with db() as connection:
        counts = {row["rule_code"]: row["count"] for row in connection.execute(
            f"SELECT rule_code,COUNT(*) count FROM findings WHERE status='open'{finding_filter} GROUP BY rule_code", params
        ).fetchall()}
        providers = {row["provider"] for row in connection.execute(
            f"SELECT provider FROM credentials{credential_filter}", params
        ).fetchall()}
        limits = load_settings(connection)["rules"]
    result = []
    for code, rule in RULE_CATALOG.items():
        count = counts.get(code, 0)
        supported = bool(providers.intersection(rule["providers"]))
        description, criterion = RULE_DETAILS.get(code, ("", ""))
        result.append({"code": code, "name": rule["name"], "framework": rule["framework"],
                       "control": rule["control"], "findings": count, "description": description,
                       "criterion": criterion.format(**limits),
                       "status": "failed" if count else "passed" if supported else "not_assessed"})
    return result


FINDING_STATUS_LABEL = {"open": "Aberto", "resolved": "Resolvido", "accepted": "Risco aceito", "dismissed": "Descartado",
                        "remediating": "Em remediação", "incident": "Incidente aberto"}


@app.patch("/api/findings/{finding_id}")
def update_finding(finding_id: int, payload: FindingUpdate, request: Request) -> dict[str, Any]:
    if payload.status in {"accepted", "dismissed"} and not payload.justification:
        raise HTTPException(422, "Informe a justificativa para aceitar ou descartar o risco.")
    with db() as connection:
        row = connection.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Achado não encontrado")
        previous = row["status"]
        connection.execute("UPDATE findings SET status=?,updated_at=? WHERE id=?", (payload.status, utc_now(), finding_id))
        justification = payload.justification or f"{FINDING_STATUS_LABEL[payload.status]} por {request.state.user['email']}."
        audit(connection, "risk", "Postura de risco alterada",
              f"{row['title']}: {previous} → {payload.status}. Justificativa: {justification}", request.state.user["email"],
              action=f"finding.{payload.status}", target=f"F-{finding_id} · {row['title']}",
              details={"from": previous, "to": payload.status, "justification": justification, "rule": row["rule_code"]})
        updated = connection.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
    return {"id": updated["id"], "rule": updated["rule_code"], "severity": updated["severity"],
            "title": updated["title"], "status": updated["status"]}


PRIVILEGE_BASE_SCORE = {"critical": 85, "high": 70, "medium": 45, "low": 20}
BREAK_GLASS_MARKERS = ("break-glass", "breakglass", "break_glass", "emergency")


def privileged_rows(connection: DatabaseConnection, credential_id: int | None, limit: int) -> list[dict[str, Any]]:
    clauses = ["a.privileged=1"]
    params: list[Any] = []
    if credential_id is not None:
        clauses.append("a.credential_id=?")
        params.append(credential_id)
    params.append(limit)
    rows = connection.execute(
        f"""SELECT a.*,i.display_name identity_name,i.identity_type,i.email,i.mfa_enabled,i.id identity_db_id,
                   c.name environment,c.provider,COALESCE(r.resource_type,'project') resource_type,
                   (SELECT q.created_at FROM access_requests q WHERE q.credential_id=a.credential_id AND q.identity_external_id=a.identity_external_id
                    AND q.resource_id=a.resource_id AND q.role_name=a.role_name AND q.action='jit' ORDER BY q.id DESC LIMIT 1) jit_requested_at
            FROM access_grants a
            LEFT JOIN identities i ON i.credential_id=a.credential_id AND i.external_id=a.identity_external_id
            JOIN credentials c ON c.id=a.credential_id
            LEFT JOIN cloud_resources r ON r.credential_id=a.credential_id AND r.external_id=a.resource_id
            WHERE {' AND '.join(clauses)} ORDER BY c.name,i.display_name LIMIT ?""", tuple(params)
    ).fetchall()
    unused_days = load_settings(connection)["rules"]["unused_days"]
    result = []
    for row in rows:
        context = role_context(row["provider"], row["role_name"], row["resource_type"])
        unused = days_since(row["last_used_at"])
        mfa = None if row["mfa_enabled"] is None else bool(row["mfa_enabled"])
        score = PRIVILEGE_BASE_SCORE.get(context["severity"], 45) + (10 if mfa is False else 0) + (5 if unused is not None and unused > unused_days else 0)
        name = row["identity_name"] or row["identity_external_id"]
        result.append({"id": row["id"], "credentialId": row["credential_id"], "identityId": row["identity_external_id"],
                       "identityDbId": row["identity_db_id"], "identityName": name, "identityType": row["identity_type"],
                       "email": row["email"], "environment": row["environment"], "provider": row["provider"],
                       "resourceId": row["resource_id"], "resourceName": row["resource_name"], "resourceType": row["resource_type"],
                       "role": row["role_name"], "roleLabel": context["label"], "capability": context["capability"],
                       "severity": context["severity"], "lastUsedAt": row["last_used_at"], "lastReviewedAt": row["last_reviewed_at"],
                       "mfaEnabled": mfa, "unused": unused is not None and unused > unused_days,
                       "model": "JIT solicitado" if row["jit_requested_at"] else "Permanente", "jitRequestedAt": row["jit_requested_at"],
                       "breakGlass": any(marker in name.lower() for marker in BREAK_GLASS_MARKERS),
                       "riskScore": min(100, score)})
    return result


@app.get("/api/privileged-access")
def privileged_access(credential_id: int | None = None, limit: int = Query(200, ge=1, le=20000)) -> list[dict[str, Any]]:
    with db() as connection:
        rows = privileged_rows(connection, credential_id, limit)
    return sorted(rows, key=lambda item: (-item["riskScore"], item["identityName"]))


@app.get("/api/privileged-access/summary")
def privileged_summary(credential_id: int | None = None) -> dict[str, Any]:
    with db() as connection:
        rows = privileged_rows(connection, credential_id, 20000)
        identities = connection.execute(
            "SELECT COUNT(*) count FROM identities" + (" WHERE credential_id=?" if credential_id is not None else ""),
            (credential_id,) if credential_id is not None else ()).fetchone()["count"]
    roles: dict[tuple[str, str], int] = {}
    for row in rows:
        roles[(row["role"], row["provider"])] = roles.get((row["role"], row["provider"]), 0) + 1
    privileged_identities = {(row["credentialId"], row["identityId"]) for row in rows}
    return {"grants": len(rows), "identities": len(privileged_identities), "totalIdentities": identities,
            "standing": sum(1 for row in rows if row["model"] == "Permanente"),
            "jit": sum(1 for row in rows if row["model"] != "Permanente"),
            "noMfa": len({(row["credentialId"], row["identityId"]) for row in rows if row["mfaEnabled"] is False}),
            "unused": sum(1 for row in rows if row["unused"]),
            "breakGlass": len({(row["credentialId"], row["identityId"]) for row in rows if row["breakGlass"]}),
            "roles": [{"role": role, "provider": provider, "count": count}
                      for (role, provider), count in sorted(roles.items(), key=lambda item: -item[1])[:7]]}


@app.post("/api/privileged-access/{grant_id}/jit")
def request_jit(grant_id: int, payload: AccessRequestInput, request: Request) -> dict[str, Any]:
    with db() as connection:
        grant = connection.execute(
            "SELECT a.*,c.name environment FROM access_grants a JOIN credentials c ON c.id=a.credential_id WHERE a.id=? AND a.privileged=1",
            (grant_id,)).fetchone()
        if not grant:
            raise HTTPException(404, "Acesso privilegiado não encontrado")
        exists = connection.execute(
            """SELECT id FROM access_requests WHERE credential_id=? AND identity_external_id=? AND resource_id=? AND role_name=? AND action='jit'""",
            (grant["credential_id"], grant["identity_external_id"], grant["resource_id"], grant["role_name"])).fetchone()
        if not exists:
            connection.execute(
                """INSERT INTO access_requests(credential_id,identity_external_id,resource_id,role_name,action,status,note,requested_by,created_at)
                   VALUES(?,?,?,?,?,?,?,?,?)""",
                (grant["credential_id"], grant["identity_external_id"], grant["resource_id"], grant["role_name"], "jit", "requested",
                 payload.note, request.state.user["email"], utc_now()))
            audit(connection, "risk", "Conversão para JIT solicitada",
                  f"{grant['identity_external_id']}: {grant['role_name']} em {grant['resource_name']} ({grant['environment']}) deve deixar de ser permanente.",
                  request.state.user["email"], action="privileged.jit_requested", target=grant["identity_external_id"],
                  details={"role": grant["role_name"], "resource": grant["resource_id"], "note": payload.note or ""})
        rows = privileged_rows(connection, grant["credential_id"], 20000)
    return next(item for item in rows if item["id"] == grant_id)


def privileged_dossier(grant_id: int) -> dict[str, Any]:
    with db() as connection:
        grant = connection.execute(
            """SELECT a.*,i.display_name identity_name,i.identity_type,i.email,c.name environment,c.provider,
                      COALESCE(r.resource_type,'project') resource_type
               FROM access_grants a
               JOIN credentials c ON c.id=a.credential_id
               LEFT JOIN identities i ON i.credential_id=a.credential_id AND i.external_id=a.identity_external_id
               LEFT JOIN cloud_resources r ON r.credential_id=a.credential_id AND r.external_id=a.resource_id
               WHERE a.id=? AND a.privileged=1""", (grant_id,)
        ).fetchone()
        if not grant:
            raise HTTPException(404, "Acesso privilegiado não encontrado")
        related = connection.execute(
            """SELECT id,rule_code,severity,title,description,resource_id FROM findings
               WHERE credential_id=? AND identity_external_id=? AND status='open'
               ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END,id DESC LIMIT 50""",
            (grant["credential_id"], grant["identity_external_id"]),
        ).fetchall()
        grants = connection.execute(
            """SELECT resource_id,resource_name,role_name,privileged FROM access_grants
               WHERE credential_id=? AND identity_external_id=? ORDER BY resource_name,role_name LIMIT 200""",
            (grant["credential_id"], grant["identity_external_id"]),
        ).fetchall()
    context = role_context(grant["provider"], grant["role_name"], grant["resource_type"])
    return {
        "grantId": grant["id"], "credentialId": grant["credential_id"], "credential": grant["environment"],
        "provider": grant["provider"], "identityId": grant["identity_external_id"],
        "identityName": grant["identity_name"] or grant["identity_external_id"], "identityType": grant["identity_type"],
        "email": grant["email"], "project": grant["resource_name"], "resourceId": grant["resource_id"],
        "resourceType": grant["resource_type"], "repository": grant["resource_name"] if grant["resource_type"] == "repository" else None,
        "role": grant["role_name"], "roleLabel": context["label"], "capability": context["capability"],
        "severity": context["severity"], "recommendation": "Substituir a função por uma função de menor privilégio compatível com as atividades comprovadas.",
        "treatment": "Confirmar o responsável e o workload, testar a função mínima e remover a concessão ampla com mudança auditada.",
        "relatedFindings": [dict(item) for item in related], "accessPath": [dict(item) for item in grants],
    }


def run_qwen_analysis(context: dict[str, Any], baseline: dict[str, str], known_roles: set[str] | None = None) -> tuple[str, dict[str, str]]:
    prompt = (
        "Analise este contexto de IGA usando somente os fatos do JSON; não invente recursos, atividades, uso ou proprietários. "
        "Responda em português com JSON contendo summary, why, recommendation, treatment e priority. "
        f"Contexto: {json.dumps(context, ensure_ascii=False)}"
    )
    try:
        response = requests.post(f"{OLLAMA_URL}/api/chat", json={
            "model": QWEN_MODEL, "stream": False, "think": False, "format": "json",
            "messages": [{"role": "system", "content": "Você é um analista IGA. Seja preciso, acionável e não extrapole evidências."},
                         {"role": "user", "content": prompt}],
            "options": {"temperature": 0.1, "num_predict": 500},
        }, timeout=120)
        response.raise_for_status()
        analysis = json.loads(response.json()["message"]["content"])
        generated_text = json.dumps(analysis, ensure_ascii=False)
        unknown_roles = set(re.findall(r"roles/[A-Za-z0-9_.]+", generated_text)) - (known_roles or set())
        analysis["recommendation"] = baseline["recommendation"]
        analysis["treatment"] = baseline["treatment"]
        analysis["priority"] = baseline["priority"]
        engine = f"{QWEN_MODEL}+policy-guardrails" if not unknown_roles else f"{QWEN_MODEL}+factual-guardrails"
        return engine, analysis
    except (requests.RequestException, ValueError, KeyError, TypeError):
        return "deterministic-fallback", {
            "summary": baseline["summary"], "why": baseline["why"],
            "recommendation": baseline["recommendation"], "treatment": baseline["treatment"],
            "priority": baseline["priority"],
        }


def save_ai_analysis(credential_id: int, scan_id: int, scope_type: str, scope_id: str,
                     engine: str, analysis: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    now = utc_now()
    with db() as connection:
        existing = connection.execute(
            "SELECT id FROM ai_analyses WHERE scan_id=? AND scope_type=? AND scope_id=?",
            (scan_id, scope_type, scope_id),
        ).fetchone()
        values = (engine, str(analysis.get("summary", "")), str(analysis.get("why", "")),
                  str(analysis.get("recommendation", "")), str(analysis.get("treatment", "")),
                  str(analysis.get("priority", "medium")), json.dumps(context, ensure_ascii=False), now)
        if existing:
            connection.execute(
                """UPDATE ai_analyses SET engine=?,summary=?,why=?,recommendation=?,treatment=?,priority=?,context_json=?,created_at=?
                   WHERE id=?""", (*values, existing["id"]),
            )
            analysis_id = existing["id"]
        else:
            cursor = connection.execute(
                """INSERT INTO ai_analyses(credential_id,scan_id,scope_type,scope_id,engine,summary,why,recommendation,
                   treatment,priority,context_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) RETURNING id""",
                (credential_id, scan_id, scope_type, scope_id, *values),
            )
            analysis_id = cursor.fetchone()["id"]
    return {"id": analysis_id, "engine": engine, "createdAt": now, **analysis}


def generate_platform_analysis(credential_id: int, scan_id: int, credential_name: str, provider: str,
                               identities: list[dict[str, Any]], accesses: list[dict[str, Any]],
                               findings: list[dict[str, Any]], projects: list[dict[str, Any]]) -> dict[str, Any]:
    severities = {level: sum(1 for item in findings if item["severity"] == level)
                  for level in ("critical", "high", "medium", "low")}
    rules: dict[str, int] = {}
    for item in findings:
        rules[item["rule"]] = rules.get(item["rule"], 0) + 1
    critical_evidence = [{"rule": item["rule"], "identityId": item["identityId"],
                          "resourceId": item["resourceId"], "description": item["description"]}
                         for item in findings if item["severity"] == "critical"][:20]
    priority = "critical" if severities["critical"] else "high" if severities["high"] else "medium" if severities["medium"] else "low"
    context = {"credential": credential_name, "provider": provider, "scanId": scan_id,
               "counts": {"projects": len(projects), "identities": len(identities), "accesses": len(accesses),
                          "privileged": sum(1 for item in accesses if item.get("privileged")), "findings": len(findings)},
               "severities": severities, "rules": rules, "criticalEvidence": critical_evidence}
    baseline = {
        "summary": f"A análise encontrou {len(findings)} achados em {len(identities)} identidades e {len(accesses)} acessos.",
        "why": "A prioridade deriva das regras determinísticas e das evidências coletadas diretamente do provedor.",
        "recommendation": "Priorizar combinações tóxicas e privilégios administrativos; validar workloads e substituir funções amplas por menor privilégio.",
        "treatment": "Tratar primeiro achados críticos, registrar responsáveis e prazos, testar funções mínimas e reexecutar a análise para comprovar a redução.",
        "priority": priority,
    }
    known_roles = {str(item.get("role")) for item in accesses}
    engine, analysis = run_qwen_analysis(context, baseline, known_roles)
    return save_ai_analysis(credential_id, scan_id, "platform", str(credential_id), engine, analysis, context)


@app.get("/api/privileged-access/{grant_id}")
def privileged_access_detail(grant_id: int) -> dict[str, Any]:
    return privileged_dossier(grant_id)


@app.post("/api/privileged-access/{grant_id}/analysis")
def analyze_privileged_access(grant_id: int) -> dict[str, Any]:
    dossier = privileged_dossier(grant_id)
    with db() as connection:
        scan = connection.execute(
            "SELECT id FROM scans WHERE credential_id=? AND status='completed' ORDER BY id DESC LIMIT 1",
            (dossier["credentialId"],),
        ).fetchone()
        if not scan:
            raise HTTPException(409, "Execute uma análise da credencial antes de solicitar a correlação")
        cached = connection.execute(
            "SELECT * FROM ai_analyses WHERE scan_id=? AND scope_type='grant' AND scope_id=?",
            (scan["id"], str(grant_id)),
        ).fetchone()
    if cached:
        analysis = {"summary": cached["summary"], "why": cached["why"], "recommendation": cached["recommendation"],
                    "treatment": cached["treatment"], "priority": cached["priority"]}
        return {"engine": cached["engine"], "cached": True, "analysisId": cached["id"],
                "createdAt": cached["created_at"], "dossier": dossier, "analysis": analysis}
    safe_context = {key: dossier[key] for key in (
        "provider", "identityName", "identityType", "project", "resourceId", "resourceType",
        "repository", "role", "roleLabel", "capability", "severity", "relatedFindings", "accessPath"
    )}
    baseline = {"summary": dossier["capability"], "why": "A função possui impacto elevado no escopo coletado.",
                "recommendation": dossier["recommendation"], "treatment": dossier["treatment"],
                "priority": dossier["severity"]}
    known_roles = {dossier["role"], *(item["role_name"] for item in dossier["accessPath"])}
    engine, analysis = run_qwen_analysis(safe_context, baseline, known_roles)
    stored = save_ai_analysis(dossier["credentialId"], scan["id"], "grant", str(grant_id), engine, analysis, safe_context)
    return {"engine": engine, "cached": False, "analysisId": stored["id"], "createdAt": stored["createdAt"],
            "dossier": dossier, "analysis": analysis}


@app.get("/api/ai-analyses")
def list_ai_analyses(credential_id: int | None = None, limit: int = Query(100, ge=1, le=500)) -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if credential_id is not None:
        clauses.append("credential_id=?")
        params.append(credential_id)
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(limit)
    with db() as connection:
        rows = connection.execute(f"SELECT * FROM ai_analyses{where} ORDER BY id DESC LIMIT ?", tuple(params)).fetchall()
    return [{"id": row["id"], "credentialId": row["credential_id"], "scanId": row["scan_id"],
             "scopeType": row["scope_type"], "scopeId": row["scope_id"], "engine": row["engine"],
             "summary": row["summary"], "why": row["why"], "recommendation": row["recommendation"],
             "treatment": row["treatment"], "priority": row["priority"], "createdAt": row["created_at"]}
            for row in rows]


@app.get("/api/ueba/overview")
def ueba_overview(credential_id: int | None = None) -> dict[str, Any]:
    clause, params = (" AND credential_id=?", (credential_id,)) if credential_id is not None else ("", ())
    now = datetime.now(timezone.utc)
    day_ago = now - timedelta(hours=24)
    with db() as connection:
        threshold = load_settings(connection)["rules"]["ueba_threshold"]
        recent = connection.execute(
            f"SELECT occurred_at,anomalous FROM telemetry_events WHERE occurred_at>=?{clause}", (day_ago.isoformat(), *params)).fetchall()
        findings = connection.execute(
            f"""SELECT f.*,c.provider FROM findings f JOIN credentials c ON c.id=f.credential_id
                WHERE f.rule_code='UEBA_ANOMALY' AND f.status IN ('open','incident'){clause.replace('credential_id', 'f.credential_id')}
                ORDER BY f.id DESC LIMIT 500""", params).fetchall()
        events = connection.execute(
            f"SELECT * FROM telemetry_events WHERE 1=1{clause} ORDER BY occurred_at DESC LIMIT 20000", params).fetchall()
        privileged = {(row["credential_id"], row["identity_external_id"]) for row in connection.execute(
            f"SELECT DISTINCT credential_id,identity_external_id FROM access_grants WHERE privileged=1{clause}", params).fetchall()}
        coverage = ueba_status(credential_id)
        labels = {(row["credential_id"], row["external_id"]): row["display_name"] for row in connection.execute(
            f"SELECT credential_id,external_id,display_name FROM identities WHERE 1=1{clause}", params).fetchall()}
    hours = []
    for offset in range(23, -1, -1):
        start = (now - timedelta(hours=offset)).replace(minute=0, second=0, microsecond=0)
        end = start + timedelta(hours=1)
        bucket = [row for row in recent if row["occurred_at"] and start <= as_utc(parse_date(row["occurred_at"])) < end]
        hours.append({"start": start.isoformat(), "events": len(bucket), "anomalies": sum(1 for row in bucket if row["anomalous"])})
    by_identity: dict[tuple[int, str], list[Any]] = {}
    for row in events:
        by_identity.setdefault((row["credential_id"], row["identity_external_id"]), []).append(row)
    anomalies = []
    for row in findings:
        identity_events = by_identity.get((row["credential_id"], row["identity_external_id"] or ""), [])
        matched = [item for item in identity_events if item["anomalous"] and (item["resource_id"] or "") == (row["resource_id"] or "")
                   and item["description"] and item["description"] in row["description"]]
        latest = matched[0] if matched else None
        category = classify_event(latest["method"], bool(latest["denied"]), latest["occurred_at"]) if latest else "Operação sensível"
        deviation = round(max((item["risk_score"] for item in matched), default=0.9 if row["severity"] == "critical" else 0.8) * 100)
        baseline = [item for item in identity_events if not item["anomalous"]]
        expected = (f"Média de {len(baseline) / 7:.1f} evento(s) administrativos por dia desta identidade nos últimos 7 dias"
                    if baseline else "Sem atividade administrativa regular desta identidade no período coletado")
        observed = (f"{len(matched)} ocorrência(s) de {latest['method'] or 'operação'} em {latest['resource_id'] or 'ambiente'}"
                    + (f" · IP {latest['caller_ip']}" if latest and latest["caller_ip"] else "")) if latest else row["description"]
        anomalies.append({"id": row["id"], "occurredAt": latest["occurred_at"] if latest else row["created_at"],
                          "identityId": row["identity_external_id"],
                          "who": labels.get((row["credential_id"], row["identity_external_id"]), row["identity_external_id"]),
                          "provider": row["provider"], "category": category, "title": row["description"].split(". ", 1)[-1],
                          "deviation": deviation, "confidence": "alta confiança" if deviation >= 80 else "média confiança",
                          "expected": expected, "observed": observed, "status": row["status"],
                          "privileged": (row["credential_id"], row["identity_external_id"]) in privileged})
    categories: dict[str, int] = {}
    for item in anomalies:
        categories[item["category"]] = categories.get(item["category"], 0) + 1
    return {"threshold": threshold, "hours": hours,
            "kpis": {"anomalies24h": sum(item["anomalies"] for item in hours),
                     "highConfidence": sum(1 for item in anomalies if item["deviation"] >= 80),
                     "identities": len({item["identityId"] for item in anomalies}),
                     "privilegedIdentities": len({item["identityId"] for item in anomalies if item["privileged"]}),
                     "eventsEvaluated": coverage["eventsEvaluated"]},
            "categories": [{"name": name, "count": count} for name, count in sorted(categories.items(), key=lambda entry: -entry[1])],
            "anomalies": sorted(anomalies, key=lambda item: item["occurredAt"] or "", reverse=True),
            "coverage": coverage["environments"]}


@app.get("/api/ueba")
def ueba_findings(credential_id: int | None = None, limit: int = Query(200, ge=1, le=20000)) -> list[dict[str, Any]]:
    clauses = ["rule_code='UEBA_ANOMALY'", "status='open'"]
    params: list[Any] = []
    if credential_id is not None:
        clauses.append("credential_id=?")
        params.append(credential_id)
    params.append(limit)
    with db() as connection:
        rows = connection.execute(
            f"SELECT * FROM findings WHERE {' AND '.join(clauses)} ORDER BY id DESC LIMIT ?", tuple(params)
        ).fetchall()
    return [{"id": row["id"], "severity": row["severity"], "title": row["title"],
             "description": row["description"], "identityId": row["identity_external_id"],
             "resourceId": row["resource_id"], "createdAt": row["created_at"]} for row in rows]


@app.get("/api/ueba/status")
def ueba_status(credential_id: int | None = None) -> dict[str, Any]:
    params: list[Any] = [credential_id] if credential_id is not None else []
    credential_filter = " WHERE c.id=?" if credential_id is not None else ""
    with db() as connection:
        rows = connection.execute(
            f"""SELECT c.id,c.name,c.provider,s.id AS scan_id,s.finished_at,s.telemetry_status,s.telemetry_event_count,
                (SELECT COUNT(*) FROM findings f WHERE f.scan_id=s.id AND f.rule_code='UEBA_ANOMALY' AND f.status='open') AS anomaly_count
                FROM credentials c LEFT JOIN scans s ON s.id=(SELECT MAX(s2.id) FROM scans s2 WHERE s2.credential_id=c.id AND s2.status='completed')
                {credential_filter} ORDER BY c.name""", tuple(params)
        ).fetchall()
    environments = []
    for row in rows:
        telemetry = row["telemetry_status"] if row["scan_id"] else "analysis_pending"
        messages = {
            "collected": "Telemetria coletada e avaliada.",
            "partial": "Telemetria parcial: alguns projetos recusaram a consulta.",
            "permission_denied": "Cloud Logging recusou a consulta. Conceda logging.logEntries.list (Logs Viewer) à credencial.",
            "unavailable": "A fonte de telemetria ficou indisponível durante a análise.",
            "not_collected": "A análise anterior não coletou telemetria comportamental; execute uma nova análise.",
            "analysis_pending": "Execute a análise da credencial para iniciar o UEBA.",
        }
        environments.append({"credentialId": row["id"], "environment": row["name"], "provider": row["provider"],
                             "scanId": row["scan_id"], "status": telemetry, "message": messages.get(telemetry, telemetry),
                             "eventsEvaluated": row["telemetry_event_count"] or 0,
                             "anomalies": row["anomaly_count"] or 0, "finishedAt": row["finished_at"]})
    return {"environments": environments, "eventsEvaluated": sum(item["eventsEvaluated"] for item in environments),
            "anomalies": sum(item["anomalies"] for item in environments),
            "coverage": "available" if any(item["status"] in {"collected", "partial"} for item in environments) else "unavailable"}


@app.get("/api/compliance")
def compliance_report(credential_id: int | None = None) -> dict[str, Any]:
    filter_sql = " AND credential_id=?" if credential_id is not None else ""
    params: tuple[Any, ...] = (credential_id,) if credential_id is not None else ()
    with db() as connection:
        identities = connection.execute(f"SELECT COUNT(*) count FROM identities WHERE 1=1{filter_sql}", params).fetchone()["count"]
        active_users = connection.execute(f"SELECT COUNT(*) count FROM identities WHERE identity_type='user' AND enabled=1{filter_sql}", params).fetchone()["count"]
        known_mfa_users = connection.execute(f"SELECT COUNT(*) count FROM identities WHERE identity_type='user' AND enabled=1 AND mfa_enabled IS NOT NULL{filter_sql}", params).fetchone()["count"]
        mfa_users = connection.execute(f"SELECT COUNT(*) count FROM identities WHERE identity_type='user' AND enabled=1 AND mfa_enabled=1{filter_sql}", params).fetchone()["count"]
        accesses = connection.execute(f"SELECT COUNT(*) count FROM access_grants WHERE 1=1{filter_sql}", params).fetchone()["count"]
        reviewed = connection.execute(f"SELECT COUNT(*) count FROM access_grants WHERE last_reviewed_at IS NOT NULL{filter_sql}", params).fetchone()["count"]
        orphan = connection.execute(f"SELECT COUNT(*) count FROM findings WHERE rule_code='ORPHAN_ACCOUNT' AND status='open'{filter_sql}", params).fetchone()["count"]
        toxic = connection.execute(f"SELECT COUNT(*) count FROM findings WHERE rule_code='TOXIC_COMBINATION' AND status='open'{filter_sql}", params).fetchone()["count"]

    if identities == 0 and accesses == 0:
        return {"score": 0, "controls": [
            {"code": "IAM-01", "name": "Inventário de identidades", "score": 0, "status": "not_assessed"},
            {"code": "IAM-02", "name": "Autenticação multifator", "score": 0, "status": "not_assessed"},
            {"code": "IGA-01", "name": "Revisão periódica de acessos", "score": 0, "status": "not_assessed"},
            {"code": "IGA-02", "name": "Contas com responsável", "score": 0, "status": "not_assessed"},
            {"code": "SOD-01", "name": "Segregação de funções", "score": 0, "status": "not_assessed"},
        ], "generatedAt": utc_now()}

    def percentage(numerator: int, denominator: int) -> int:
        return round((numerator / denominator) * 100) if denominator else 100

    mfa_status = "not_assessed" if known_mfa_users == 0 else "compliant" if known_mfa_users == mfa_users else "non_compliant"
    review_status = "not_assessed" if reviewed == 0 else "compliant" if accesses == reviewed else "non_compliant"
    controls = [
        {"code": "IAM-01", "name": "Inventário de identidades", "score": 100 if identities else 0, "status": "compliant" if identities else "not_assessed"},
        {"code": "IAM-02", "name": "Autenticação multifator", "score": percentage(mfa_users, known_mfa_users) if known_mfa_users else 0, "status": mfa_status},
        {"code": "IGA-01", "name": "Revisão periódica de acessos", "score": percentage(reviewed, accesses) if reviewed else 0, "status": review_status},
        {"code": "IGA-02", "name": "Contas com responsável", "score": 0, "status": "not_assessed"},
        {"code": "SOD-01", "name": "Segregação de funções", "score": 100 if toxic == 0 else 0, "status": "compliant" if toxic == 0 else "non_compliant"},
    ]
    assessed = [control for control in controls if control["status"] != "not_assessed"]
    overall = round(sum(control["score"] for control in assessed) / len(assessed)) if assessed else 0
    return {"score": overall, "controls": controls, "generatedAt": utc_now()}


@app.get("/api/compliance/frameworks")
def compliance_frameworks(credential_id: int | None = None) -> dict[str, Any]:
    with db() as connection:
        ids = [row["id"] for row in scoped_credentials(connection, credential_id, None)]
        metrics = compliance_metrics(connection, ids)
    return {"frameworks": framework_report(metrics), "generatedAt": utc_now()}


def campaign_view(connection: DatabaseConnection, row: Any) -> dict[str, Any]:
    stats = connection.execute(
        """SELECT COUNT(*) total,SUM(CASE WHEN decision IS NOT NULL THEN 1 ELSE 0 END) decided,
           SUM(CASE WHEN decision='keep' THEN 1 ELSE 0 END) kept,SUM(CASE WHEN decision='revoke' THEN 1 ELSE 0 END) revoked
           FROM review_items WHERE campaign_id=?""", (row["id"],)).fetchone()
    credential = connection.execute("SELECT name FROM credentials WHERE id=?", (row["credential_id"],)).fetchone() if row["credential_id"] else None
    total, decided = stats["total"] or 0, stats["decided"] or 0
    return {"id": row["id"], "name": row["name"], "scope": row["scope"], "credentialId": row["credential_id"],
            "environment": credential["name"] if credential else "Todos os ambientes", "reviewer": row["reviewer"],
            "dueAt": row["due_at"], "createdAt": row["created_at"], "createdBy": row["created_by"], "completedAt": row["completed_at"],
            "total": total, "decided": decided, "kept": stats["kept"] or 0, "revoked": stats["revoked"] or 0,
            "percent": round(decided / total * 100) if total else 100,
            "overdue": not row["completed_at"] and decided < total and row["due_at"] < utc_now()}


@app.get("/api/reviews")
def list_reviews() -> list[dict[str, Any]]:
    with db() as connection:
        rows = connection.execute("SELECT * FROM review_campaigns ORDER BY completed_at IS NOT NULL, due_at").fetchall()
        return [campaign_view(connection, row) for row in rows]


@app.post("/api/reviews", status_code=status.HTTP_201_CREATED)
def create_review(payload: ReviewCampaignInput, request: Request) -> dict[str, Any]:
    clauses, params = ["1=1"], []
    with db() as connection:
        if payload.credentialId is not None:
            clauses.append("a.credential_id=?")
            params.append(payload.credentialId)
        if payload.scope == "privileged":
            clauses.append("a.privileged=1")
        elif payload.scope == "unused":
            cutoff = (datetime.now(timezone.utc) - timedelta(days=load_settings(connection)["rules"]["unused_days"])).isoformat()
            clauses.append("a.last_used_at IS NOT NULL AND a.last_used_at<?")
            params.append(cutoff)
        elif payload.scope == "identity":
            identity = connection.execute("SELECT credential_id,external_id FROM identities WHERE id=?", (payload.identityId,)).fetchone()
            if not identity:
                raise HTTPException(404, "Identidade não encontrada")
            clauses.append("a.credential_id=? AND a.identity_external_id=?")
            params.extend((identity["credential_id"], identity["external_id"]))
        grants = connection.execute(
            f"""SELECT a.*,COALESCE(i.display_name,a.identity_external_id) identity_name FROM access_grants a
                LEFT JOIN identities i ON i.credential_id=a.credential_id AND i.external_id=a.identity_external_id
                WHERE {' AND '.join(clauses)} ORDER BY a.privileged DESC,a.id LIMIT 5000""", tuple(params)).fetchall()
        if not grants:
            raise HTTPException(422, "Nenhuma concessão encontrada para o escopo selecionado.")
        now = utc_now()
        due = (datetime.now(timezone.utc) + timedelta(days=payload.dueDays)).isoformat()
        cursor = connection.execute(
            """INSERT INTO review_campaigns(name,scope,credential_id,reviewer,due_at,created_by,created_at)
               VALUES(?,?,?,?,?,?,?) RETURNING id""",
            (payload.name.strip(), payload.scope, payload.credentialId, payload.reviewer.strip(), due, request.state.user["email"], now))
        campaign_id = cursor.fetchone()["id"]
        for grant in grants:
            connection.execute(
                """INSERT INTO review_items(campaign_id,credential_id,identity_external_id,identity_name,resource_id,resource_name,
                   role_name,privileged) VALUES(?,?,?,?,?,?,?,?)""",
                (campaign_id, grant["credential_id"], grant["identity_external_id"], grant["identity_name"], grant["resource_id"],
                 grant["resource_name"], grant["role_name"], grant["privileged"]))
        audit(connection, "admin", "Campanha de revisão criada", f"{payload.name}: {len(grants)} concessão(ões), revisor {payload.reviewer}.",
              request.state.user["email"], action="review.created", target=payload.name,
              details={"scope": payload.scope, "items": len(grants), "dueAt": due})
        row = connection.execute("SELECT * FROM review_campaigns WHERE id=?", (campaign_id,)).fetchone()
        return campaign_view(connection, row)


@app.get("/api/reviews/{campaign_id}")
def review_detail(campaign_id: int) -> dict[str, Any]:
    with db() as connection:
        row = connection.execute("SELECT * FROM review_campaigns WHERE id=?", (campaign_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Campanha não encontrada")
        items = connection.execute("SELECT * FROM review_items WHERE campaign_id=? ORDER BY decision IS NOT NULL,privileged DESC,id",
                                   (campaign_id,)).fetchall()
        view = campaign_view(connection, row)
    view["items"] = [{"id": item["id"], "identity": item["identity_name"], "identityId": item["identity_external_id"],
                      "resource": item["resource_name"], "role": item["role_name"], "privileged": bool(item["privileged"]),
                      "decision": item["decision"], "comment": item["comment"], "decidedBy": item["decided_by"],
                      "decidedAt": item["decided_at"]} for item in items]
    return view


@app.patch("/api/reviews/{campaign_id}/items/{item_id}")
def decide_review_item(campaign_id: int, item_id: int, payload: ReviewDecisionInput, request: Request) -> dict[str, Any]:
    now = utc_now()
    with db() as connection:
        item = connection.execute("SELECT * FROM review_items WHERE id=? AND campaign_id=?", (item_id, campaign_id)).fetchone()
        if not item:
            raise HTTPException(404, "Item de revisão não encontrado")
        connection.execute("UPDATE review_items SET decision=?,comment=?,decided_by=?,decided_at=? WHERE id=?",
                           (payload.decision, payload.comment, request.state.user["email"], now, item_id))
        if payload.decision == "keep":
            connection.execute(
                "UPDATE access_grants SET last_reviewed_at=? WHERE credential_id=? AND identity_external_id=? AND resource_id=? AND role_name=?",
                (now, item["credential_id"], item["identity_external_id"], item["resource_id"], item["role_name"]))
        elif connection.execute("SELECT id FROM credentials WHERE id=?", (item["credential_id"],)).fetchone():
            connection.execute(
                """INSERT INTO access_requests(credential_id,identity_external_id,resource_id,role_name,action,status,note,requested_by,created_at)
                   VALUES(?,?,?,?,?,?,?,?,?)""",
                (item["credential_id"], item["identity_external_id"], item["resource_id"], item["role_name"], "revoke", "requested",
                 payload.comment, request.state.user["email"], now))
        decision = "mantido" if payload.decision == "keep" else "revogação solicitada"
        audit(connection, "admin", "Decisão de revisão de acesso",
              f"{item['identity_name']} · {item['role_name']} em {item['resource_name']}: {decision}.", request.state.user["email"],
              action=f"review.{payload.decision}", target=f"{item['identity_name']} · {item['role_name']}",
              details={"campaign": campaign_id, "comment": payload.comment or ""})
        pending = connection.execute("SELECT COUNT(*) count FROM review_items WHERE campaign_id=? AND decision IS NULL",
                                     (campaign_id,)).fetchone()["count"]
        connection.execute("UPDATE review_campaigns SET completed_at=? WHERE id=?", (now if pending == 0 else None, campaign_id))
    return review_detail(campaign_id)


@app.get("/api/settings")
def get_settings() -> dict[str, Any]:
    with db() as connection:
        settings = load_settings(connection)
        credentials = connection.execute("SELECT id,last_synced_at FROM credentials").fetchall()
    return {**settings, "nextRunAt": next_scheduled_run(settings, credentials),
            "parameters": [{"key": key, "name": name, "description": description, "unit": unit, "min": low, "max": high,
                            "value": settings["rules"][key]} for key, name, description, unit, low, high in RULE_PARAMETERS]}


@app.put("/api/settings")
def update_settings(payload: SettingsInput, request: Request) -> dict[str, Any]:
    rules = {}
    for key, name, _description, unit, low, high in RULE_PARAMETERS:
        value = payload.rules.get(key, DEFAULT_SETTINGS["rules"][key])
        if not low <= value <= high:
            raise HTTPException(422, f"{name}: informe um valor entre {low} e {high} {unit}.")
        rules[key] = value
    webhook = payload.webhook.strip()
    if webhook and not re.fullmatch(r"https://[^\s]+", webhook):
        raise HTTPException(422, "O webhook precisa ser uma URL https://")
    settings = {"rules": rules, "schedule": payload.schedule, "webhook": webhook,
                "notifications": {key: bool(payload.notifications.get(key, default))
                                  for key, default in DEFAULT_SETTINGS["notifications"].items()}}
    with db() as connection:
        before = load_settings(connection)
        store_settings(connection, settings)
        changed = sorted(key for key in rules if rules[key] != before["rules"][key])
        audit(connection, "admin", "Configurações atualizadas",
              f"Agendamento: {payload.schedule}. Parâmetros alterados: {', '.join(changed) or 'nenhum'}.", request.state.user["email"],
              action="settings.updated", target="platform",
              details={"schedule": payload.schedule, "changedRules": changed, "notifications": settings["notifications"],
                       "webhookConfigured": bool(webhook)})
    return get_settings()


@app.get("/api/scans")
def list_scans(credential_id: int | None = None) -> list[dict[str, Any]]:
    query = "SELECT * FROM scans"
    params: tuple[Any, ...] = ()
    if credential_id is not None:
        query += " WHERE credential_id=?"
        params = (credential_id,)
    query += " ORDER BY id DESC LIMIT 100"
    with db() as connection:
        rows = connection.execute(query, params).fetchall()
    return [{"id": row["id"], "credentialId": row["credential_id"], "provider": row["provider"],
             "status": row["status"], "identities": row["identity_count"], "accesses": row["access_count"],
             "findings": row["finding_count"], "riskScore": row["risk_score"],
             "startedAt": row["started_at"], "finishedAt": row["finished_at"]} for row in rows]


@app.get("/api/risk-history")
def risk_history(credential_id: int | None = None, limit: int = 30) -> list[dict[str, Any]]:
    safe_limit = max(1, min(limit, 180))
    clauses = ["s.status='completed'", "s.risk_score IS NOT NULL"]
    params: list[Any] = []
    if credential_id is not None:
        clauses.append("s.credential_id=?")
        params.append(credential_id)
    params.append(safe_limit)
    with db() as connection:
        rows = connection.execute(
            f"""SELECT s.id,s.credential_id,s.risk_score,s.finding_count,s.finished_at,c.name,c.provider
                FROM scans s JOIN credentials c ON c.id=s.credential_id
                WHERE {' AND '.join(clauses)} ORDER BY s.id DESC LIMIT ?""", tuple(params)
        ).fetchall()
    return [{"scanId": row["id"], "credentialId": row["credential_id"], "environment": row["name"],
             "provider": row["provider"], "riskScore": row["risk_score"], "findings": row["finding_count"],
             "finishedAt": row["finished_at"]} for row in reversed(rows)]
