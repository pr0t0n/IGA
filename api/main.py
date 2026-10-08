import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import requests
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

import jwt
from cryptography.fernet import Fernet, InvalidToken
from fastapi import FastAPI, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator

from connectors import ConnectorError, discover

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


class CredentialInput(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    provider: Literal["AWS", "Azure", "GCP"]
    credential: dict[str, Any]

    @field_validator("name")
    @classmethod
    def clean_name(cls, value: str) -> str:
        return value.strip()


class FindingUpdate(BaseModel):
    status: Literal["open", "resolved", "accepted", "dismissed"]
    justification: str = Field(min_length=3, max_length=500)


class LoginInput(BaseModel):
    email: str
    password: str


class UserInput(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    email: str = Field(min_length=5, max_length=200)
    password: str = Field(min_length=8, max_length=200)
    role: Literal["admin", "analyst", "auditor"]


class UserUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=100)
    role: Literal["admin", "analyst", "auditor"] | None = None
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
            "role": row["role"], "active": bool(row["active"]), "createdAt": row["created_at"]}


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
            role TEXT NOT NULL CHECK(role IN ('admin','analyst','auditor')),
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_identities_credential ON identities(credential_id);
        CREATE INDEX IF NOT EXISTS idx_access_credential ON access_grants(credential_id);
        CREATE INDEX IF NOT EXISTS idx_resources_credential ON cloud_resources(credential_id);
        CREATE INDEX IF NOT EXISTS idx_findings_credential ON findings(credential_id, status);
        CREATE INDEX IF NOT EXISTS idx_ai_analyses_credential ON ai_analyses(credential_id,scan_id);
        """)
        if connection.postgres:
            scan_columns = {row["column_name"] for row in connection.execute(
                "SELECT column_name FROM information_schema.columns WHERE table_name='scans'"
            ).fetchall()}
        else:
            scan_columns = {row["name"] for row in connection.execute("PRAGMA table_info(scans)").fetchall()}
        if "risk_score" not in scan_columns:
            connection.execute("ALTER TABLE scans ADD COLUMN risk_score INTEGER")
        if "telemetry_event_count" not in scan_columns:
            connection.execute("ALTER TABLE scans ADD COLUMN telemetry_event_count INTEGER NOT NULL DEFAULT 0")
        if "telemetry_status" not in scan_columns:
            connection.execute("ALTER TABLE scans ADD COLUMN telemetry_status TEXT NOT NULL DEFAULT 'not_collected'")
        if connection.postgres:
            credential_columns = {row["column_name"] for row in connection.execute(
                "SELECT column_name FROM information_schema.columns WHERE table_name='credentials'"
            ).fetchall()}
        else:
            credential_columns = {row["name"] for row in connection.execute("PRAGMA table_info(credentials)").fetchall()}
        if "last_synced_at" not in credential_columns:
            connection.execute("ALTER TABLE credentials ADD COLUMN last_synced_at TEXT")
        existing_admin = connection.execute("SELECT id FROM platform_users WHERE email=?", (ADMIN_EMAIL,)).fetchone()
        if not existing_admin:
            now = utc_now()
            connection.execute(
                "INSERT INTO platform_users(name,email,password_hash,role,active,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                ("Administrador", ADMIN_EMAIL, hash_password(ADMIN_PASSWORD), "admin", 1, now, now),
            )


@app.on_event("startup")
def startup() -> None:
    init_db()


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
    if role == "auditor" and request.method not in {"GET", "HEAD", "OPTIONS"}:
        return JSONResponse({"detail": "Perfil Auditor possui acesso somente leitura"}, status_code=403)
    if path.startswith("/api/users") and role != "admin":
        return JSONResponse({"detail": "Operação exclusiva para administradores"}, status_code=403)
    return await call_next(request)


@app.post("/api/auth/login")
def login(payload: LoginInput) -> dict[str, Any]:
    with db() as connection:
        user = connection.execute("SELECT * FROM platform_users WHERE email=? AND active=1", (payload.email.strip().lower(),)).fetchone()
        if not user or not verify_password(payload.password, user["password_hash"]):
            raise HTTPException(401, "E-mail ou senha inválidos")
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
    accepted = {
        "AWS": [
            ("accountId", "roleArn"),
            ("accessKeyId", "secretAccessKey"),
            ("aws_access_key_id", "aws_secret_access_key"),
        ],
        "Azure": [("tenantId", "clientId", "clientSecret"), ("tenant_id", "client_id", "client_secret")],
        "GCP": [("type", "project_id", "private_key", "client_email")],
    }
    for required_set in accepted[provider]:
        missing = [key for key in required_set if not payload.get(key)]
        if not missing:
            if provider == "GCP" and payload.get("type") != "service_account":
                return ["type deve ser service_account"]
            return []
    alternatives = [" + ".join(items) for items in accepted[provider]]
    return [f"campos obrigatórios: {' ou '.join(alternatives)}"]


def credential_view(row: sqlite3.Row, include_secret: bool = False) -> dict[str, Any]:
    result = {
        "id": row["id"], "name": row["name"], "provider": row["provider"],
        "scope": row["scope"], "status": row["status"],
        "createdAt": row["created_at"], "updatedAt": row["updated_at"],
        "lastSyncedAt": row["last_synced_at"],
        "synced": row["last_synced_at"] or "Nunca",
    }
    if include_secret:
        try:
            result["credential"] = json.loads(cipher.decrypt(row["encrypted_payload"]).decode())
        except InvalidToken as exc:
            raise HTTPException(500, "Não foi possível descriptografar a credencial") from exc
    return result


def audit(connection: DatabaseConnection, event_type: str, title: str, description: str,
          actor: str = "Administrador local") -> None:
    connection.execute(
        "INSERT INTO audit_events(event_type,title,description,actor,created_at) VALUES(?,?,?,?,?)",
        (event_type, title, description, actor, utc_now()),
    )


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


def evaluate_rules(identities: list[dict[str, Any]], accesses: list[dict[str, Any]],
                   events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    identities_by_id = {str(item.get("id")): item for item in identities}
    grants_by_identity: dict[str, list[dict[str, Any]]] = {}
    for grant in accesses:
        identity_id = str(grant.get("identityId", ""))
        grants_by_identity.setdefault(identity_id, []).append(grant)

        unused_days = days_since(grant.get("lastUsedAt"))
        if grant.get("unused") is True or (unused_days is not None and unused_days > 90):
            results.append(finding("PERMISSION_USAGE", "high", "Permissão sem uso real",
                f"O acesso {grant.get('role', 'sem função')} não é utilizado há mais de 90 dias.", identity_id, str(grant.get("resourceId", ""))))

        review_days = days_since(grant.get("lastReviewedAt"))
        if grant.get("reviewDue") is True or (review_days is not None and review_days > 90):
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
        if identity.get("orphan") is True:
            results.append(finding("ORPHAN_ACCOUNT", "high", "Conta sem responsável",
                "A identidade não possui proprietário válido.", identity_id))
        if identity.get("mfaEnabled") is False and identity.get("enabled", True):
            results.append(finding("AUTHENTICATION_POSTURE", "high", "MFA não configurado",
                "A identidade ativa não possui autenticação multifator.", identity_id))
        if identity.get("lifecycleStatus") in {"mover", "leaver"} and grants:
            results.append(finding("JML", "critical" if identity.get("lifecycleStatus") == "leaver" else "high",
                "Acesso incompatível com ciclo de vida", f"Identidade em estado {identity.get('lifecycleStatus')} mantém {len(grants)} acesso(s).", identity_id))
        if any(grant.get("accessCreep") is True for grant in grants):
            results.append(finding("ACCESS_CREEP", "high", "Acúmulo progressivo de acessos",
                "A fonte de telemetria marcou crescimento indevido de privilégios.", identity_id))

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
        if event.get("anomalous") is not True and score < 0.8:
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
    return [credential_view(row) for row in rows]


@app.get("/api/credentials/{credential_id}")
def get_credential(credential_id: int) -> dict[str, Any]:
    with db() as connection:
        row = connection.execute("SELECT * FROM credentials WHERE id=?", (credential_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Credencial não encontrada")
    return credential_view(row, include_secret=True)


@app.post("/api/credentials", status_code=status.HTTP_201_CREATED)
def create_credential(payload: CredentialInput, request: Request) -> dict[str, Any]:
    errors = validate_provider(payload.provider, payload.credential)
    if errors:
        raise HTTPException(422, {"provider": payload.provider, "errors": errors})
    now = utc_now()
    encrypted = cipher.encrypt(json.dumps(payload.credential).encode())
    with db() as connection:
        cursor = connection.execute(
            "INSERT INTO credentials(name,provider,encrypted_payload,scope,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?) RETURNING id",
            (payload.name, payload.provider, encrypted, "Ainda não analisado", "Pendente", now, now),
        )
        credential_id = cursor.fetchone()["id"]
        audit(connection, "credential", "Credencial adicionada", f"{payload.name} ({payload.provider}) aguarda a primeira análise real.", request.state.user["email"])
        row = connection.execute("SELECT * FROM credentials WHERE id=?", (credential_id,)).fetchone()
    return credential_view(row)


@app.put("/api/credentials/{credential_id}")
def update_credential(credential_id: int, payload: CredentialInput, request: Request) -> dict[str, Any]:
    errors = validate_provider(payload.provider, payload.credential)
    if errors:
        raise HTTPException(422, {"provider": payload.provider, "errors": errors})
    with db() as connection:
        exists = connection.execute("SELECT id FROM credentials WHERE id=?", (credential_id,)).fetchone()
        if not exists:
            raise HTTPException(404, "Credencial não encontrada")
        connection.execute("DELETE FROM scans WHERE credential_id=?", (credential_id,))
        connection.execute("DELETE FROM identities WHERE credential_id=?", (credential_id,))
        connection.execute("DELETE FROM access_grants WHERE credential_id=?", (credential_id,))
        connection.execute("DELETE FROM cloud_resources WHERE credential_id=?", (credential_id,))
        connection.execute(
            "UPDATE credentials SET name=?,provider=?,encrypted_payload=?,scope=?,status=?,last_synced_at=NULL,updated_at=? WHERE id=?",
            (payload.name, payload.provider, cipher.encrypt(json.dumps(payload.credential).encode()),
             "Ainda não analisado", "Pendente", utc_now(), credential_id),
        )
        audit(connection, "credential", "Credencial atualizada", f"{payload.name} aguarda uma nova análise real.", request.state.user["email"])
        row = connection.execute("SELECT * FROM credentials WHERE id=?", (credential_id,)).fetchone()
    return credential_view(row)


@app.delete("/api/credentials/{credential_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_credential(credential_id: int, request: Request) -> Response:
    with db() as connection:
        row = connection.execute("SELECT name FROM credentials WHERE id=?", (credential_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Credencial não encontrada")
        connection.execute("DELETE FROM credentials WHERE id=?", (credential_id,))
        audit(connection, "credential", "Credencial removida", f"{row['name']} foi desconectada do ambiente.", request.state.user["email"])
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.get("/api/audit")
def list_audit() -> list[dict[str, Any]]:
    with db() as connection:
        rows = connection.execute("SELECT * FROM audit_events ORDER BY id DESC LIMIT 200").fetchall()
    return [{"id": row["id"], "type": row["event_type"], "title": row["title"],
             "text": row["description"], "actor": row["actor"], "createdAt": row["created_at"]} for row in rows]


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


@app.post("/api/credentials/{credential_id}/scan")
def scan_credential(credential_id: int, request: Request) -> dict[str, Any]:
    started_at = utc_now()
    with db() as connection:
        row = connection.execute("SELECT * FROM credentials WHERE id=?", (credential_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Credencial não encontrada")
        try:
            credential = json.loads(cipher.decrypt(row["encrypted_payload"]).decode())
        except InvalidToken as exc:
            raise HTTPException(500, "Não foi possível descriptografar a credencial") from exc
        try:
            discovered = discover(row["provider"], credential)
        except ConnectorError as exc:
            connection.execute(
                "UPDATE credentials SET status=?,updated_at=? WHERE id=?",
                ("Erro", utc_now(), credential_id),
            )
            audit(connection, "credential", "Falha na análise cloud", f"{row['name']}: {exc}", request.state.user["email"])
            connection.commit()
            raise HTTPException(502, str(exc)) from exc
        identities, accesses, events = normalize_discovery(discovered)
        telemetry_status = discovered.get("telemetryStatus", "collected" if events else "not_collected")
        projects = discovered.get("projects", [])
        findings = evaluate_rules(identities, accesses, events)
        risk_score = calculate_risk_score(findings, len(identities) + len(accesses))
        cursor = connection.execute(
            "INSERT INTO scans(credential_id,provider,status,started_at) VALUES(?,?,?,?) RETURNING id",
            (credential_id, row["provider"], "running", started_at),
        )
        scan_id = cursor.fetchone()["id"]
        connection.execute("DELETE FROM identities WHERE credential_id=?", (credential_id,))
        connection.execute("DELETE FROM access_grants WHERE credential_id=?", (credential_id,))
        connection.execute("DELETE FROM cloud_resources WHERE credential_id=?", (credential_id,))
        connection.execute("UPDATE findings SET status='superseded' WHERE credential_id=? AND status='open'", (credential_id,))
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
        for item in findings:
            connection.execute(
                """INSERT INTO findings(credential_id,scan_id,rule_code,severity,title,description,
                   identity_external_id,resource_id,created_at) VALUES(?,?,?,?,?,?,?,?,?)""",
                (credential_id, scan_id, item["rule"], item["severity"], item["title"], item["description"],
                 item["identityId"], item["resourceId"], utc_now()),
            )
        finished_at = utc_now()
        connection.execute(
            "UPDATE scans SET status='completed',identity_count=?,access_count=?,finding_count=?,telemetry_event_count=?,telemetry_status=?,risk_score=?,finished_at=? WHERE id=?",
            (len(identities), len(accesses), len(findings), len(events), telemetry_status, risk_score, finished_at, scan_id),
        )
        scope = f"{len(projects)} projetos/contas · {len(identities)} identidades · {len(accesses)} acessos"
        connection.execute(
            "UPDATE credentials SET scope=?,status=?,last_synced_at=?,updated_at=? WHERE id=?",
            (scope, "Conectado", finished_at, finished_at, credential_id),
        )
        audit(connection, "risk", "Análise de acesso concluída",
              f"{row['name']}: {len(identities)} identidades, {len(accesses)} acessos e {len(findings)} riscos.", request.state.user["email"])
    ai_analysis = generate_platform_analysis(
        credential_id, scan_id, row["name"], row["provider"], identities, accesses, findings, projects
    )
    return {"scanId": scan_id, "status": "completed", "provider": row["provider"], "source": "live",
            "identities": len(identities), "accesses": len(accesses), "findings": len(findings),
            "riskScore": risk_score, "finishedAt": finished_at,
            "ueba": {"eventsEvaluated": len(events), "status": telemetry_status,
                     "anomalies": sum(1 for item in findings if item["rule"] == "UEBA_ANOMALY")},
            "aiAnalysis": {"id": ai_analysis["id"], "engine": ai_analysis["engine"], "priority": ai_analysis["priority"]}}


@app.get("/api/identities")
def list_identities(credential_id: int | None = None, q: str | None = None,
                    offset: int = Query(0, ge=0), limit: int = Query(200, ge=1, le=10000)) -> list[dict[str, Any]]:
    query = """SELECT i.*, c.name AS credential_name, c.provider,
        (SELECT COUNT(*) FROM access_grants a WHERE a.credential_id=i.credential_id AND a.identity_external_id=i.external_id) AS access_count,
        (SELECT COUNT(*) FROM access_grants a WHERE a.credential_id=i.credential_id AND a.identity_external_id=i.external_id AND a.privileged=1) AS privileged_count,
        (SELECT COUNT(DISTINCT a.resource_id) FROM access_grants a WHERE a.credential_id=i.credential_id AND a.identity_external_id=i.external_id) AS resource_count,
        (SELECT COUNT(*) FROM findings f WHERE f.credential_id=i.credential_id AND f.identity_external_id=i.external_id AND f.status='open') AS finding_count,
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
    query += " ORDER BY i.display_name LIMIT ? OFFSET ?"
    params.extend((limit, offset))
    with db() as connection:
        rows = connection.execute(query, tuple(params)).fetchall()
    return [{"id": row["id"], "credentialId": row["credential_id"], "externalId": row["external_id"],
             "name": row["display_name"], "type": row["identity_type"], "email": row["email"],
             "enabled": bool(row["enabled"]), "mfaEnabled": None if row["mfa_enabled"] is None else bool(row["mfa_enabled"]),
             "owner": row["owner"], "lifecycleStatus": row["lifecycle_status"],
             "environment": row["credential_name"], "provider": row["provider"],
             "accessCount": row["access_count"], "privilegedCount": row["privileged_count"],
             "resourceCount": row["resource_count"], "findingCount": row["finding_count"],
             "maxSeverity": row["max_severity"]} for row in rows]


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


@app.get("/api/accesses")
def list_accesses(credential_id: int | None = None, limit: int = Query(200, ge=1, le=20000)) -> list[dict[str, Any]]:
    query = "SELECT * FROM access_grants"
    params: tuple[Any, ...] = ()
    if credential_id is not None:
        query += " WHERE credential_id=?"
        params = (credential_id,)
    query += " ORDER BY id DESC LIMIT ?"
    params = (*params, limit)
    with db() as connection:
        rows = connection.execute(query, params).fetchall()
    return [{"id": row["id"], "credentialId": row["credential_id"], "identityId": row["identity_external_id"],
             "resourceId": row["resource_id"], "resourceName": row["resource_name"], "role": row["role_name"],
             "permissions": json.loads(row["permissions_json"]), "privileged": bool(row["privileged"]),
             "grantedAt": row["granted_at"], "lastUsedAt": row["last_used_at"],
             "lastReviewedAt": row["last_reviewed_at"]} for row in rows]


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


@app.get("/api/findings")
def list_findings(credential_id: int | None = None, finding_status: str = "open",
                  limit: int = Query(200, ge=1, le=20000)) -> list[dict[str, Any]]:
    clauses = ["status=?"]
    params: list[Any] = [finding_status]
    if credential_id is not None:
        clauses.append("credential_id=?")
        params.append(credential_id)
    params.append(limit)
    with db() as connection:
        rows = connection.execute(
            f"SELECT * FROM findings WHERE {' AND '.join(clauses)} ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 ELSE 3 END, id DESC LIMIT ?",
            tuple(params),
        ).fetchall()
    return [{"id": row["id"], "credentialId": row["credential_id"], "scanId": row["scan_id"],
             "rule": row["rule_code"], "severity": row["severity"], "title": row["title"],
             "description": row["description"], "identityId": row["identity_external_id"],
             "resourceId": row["resource_id"], "status": row["status"], "createdAt": row["created_at"],
             "why": RULE_CATALOG.get(row["rule_code"], DEFAULT_RULE_GUIDANCE).get("why", DEFAULT_RULE_GUIDANCE["why"]),
             "recommendation": RULE_CATALOG.get(row["rule_code"], DEFAULT_RULE_GUIDANCE).get("recommendation", DEFAULT_RULE_GUIDANCE["recommendation"]),
             "treatment": RULE_CATALOG.get(row["rule_code"], DEFAULT_RULE_GUIDANCE).get("treatment", DEFAULT_RULE_GUIDANCE["treatment"]),
             "framework": RULE_CATALOG.get(row["rule_code"], {}).get("framework", "IGA")}
            for row in rows]


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
    result = []
    for code, rule in RULE_CATALOG.items():
        count = counts.get(code, 0)
        supported = bool(providers.intersection(rule["providers"]))
        result.append({"code": code, "name": rule["name"], "framework": rule["framework"],
                       "control": rule["control"], "findings": count,
                       "status": "failed" if count else "passed" if supported else "not_assessed"})
    return result


@app.patch("/api/findings/{finding_id}")
def update_finding(finding_id: int, payload: FindingUpdate, request: Request) -> dict[str, Any]:
    with db() as connection:
        row = connection.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Achado não encontrado")
        previous = row["status"]
        connection.execute("UPDATE findings SET status=? WHERE id=?", (payload.status, finding_id))
        audit(connection, "risk", "Postura de risco alterada",
              f"{row['title']}: {previous} → {payload.status}. Justificativa: {payload.justification}", request.state.user["email"])
        updated = connection.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
    return {"id": updated["id"], "rule": updated["rule_code"], "severity": updated["severity"],
            "title": updated["title"], "status": updated["status"]}


@app.get("/api/privileged-access")
def privileged_access(credential_id: int | None = None, limit: int = Query(200, ge=1, le=20000)) -> list[dict[str, Any]]:
    clauses = ["a.privileged=1"]
    params: list[Any] = []
    if credential_id is not None:
        clauses.append("a.credential_id=?")
        params.append(credential_id)
    params.append(limit)
    with db() as connection:
        rows = connection.execute(
            f"""SELECT a.*,i.display_name identity_name,i.identity_type,i.email,c.name environment,c.provider,
                       COALESCE(r.resource_type,'project') resource_type
                FROM access_grants a
                LEFT JOIN identities i ON i.credential_id=a.credential_id AND i.external_id=a.identity_external_id
                JOIN credentials c ON c.id=a.credential_id
                LEFT JOIN cloud_resources r ON r.credential_id=a.credential_id AND r.external_id=a.resource_id
                WHERE {' AND '.join(clauses)} ORDER BY c.name,i.display_name LIMIT ?""", tuple(params)
        ).fetchall()
    result = []
    for row in rows:
        context = role_context(row["provider"], row["role_name"], row["resource_type"])
        result.append({"id": row["id"], "credentialId": row["credential_id"], "identityId": row["identity_external_id"],
                       "identityName": row["identity_name"] or row["identity_external_id"], "identityType": row["identity_type"],
                       "email": row["email"], "environment": row["environment"], "provider": row["provider"],
                       "resourceId": row["resource_id"], "resourceName": row["resource_name"], "resourceType": row["resource_type"],
                       "role": row["role_name"], "roleLabel": context["label"], "capability": context["capability"],
                       "severity": context["severity"], "lastUsedAt": row["last_used_at"], "lastReviewedAt": row["last_reviewed_at"]})
    return result


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
