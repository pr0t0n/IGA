"""Static governance catalogs and pure scoring helpers shared by the API endpoints."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

SEVERITY_WEIGHT = {"critical": 4, "high": 2, "medium": 1, "low": 0.5}
IDENTITY_RISK_WEIGHT = {"critical": 40, "high": 25, "medium": 10, "low": 5}
SEVERITY_ORDER = {"critical": 1, "high": 2, "medium": 3, "low": 4}

# Tunable rule parameters (Administração → Regras de validação). Every key is consumed by evaluate_rules.
DEFAULT_SETTINGS: dict[str, Any] = {
    "rules": {"creep_days": 30, "unused_days": 90, "leaver_hours": 24, "orphan_days": 7,
              "key_age_days": 90, "review_days": 90, "ueba_threshold": 70},
    "schedule": "manual",
    "notifications": {"critical": True, "ueba": True, "credential": True, "weekly": False},
    "webhook": "",
}
RULE_PARAMETERS = [
    ("creep_days", "Access Creep", "Tempo em movimentação (mover) até acusar acúmulo", "dias", 1, 365),
    ("unused_days", "Uso real de permissão", "Concessão sem uso por mais de", "dias", 7, 730),
    ("leaver_hours", "Joiner / Mover / Leaver", "Tolerância para revogação após desligamento", "horas", 0, 720),
    ("orphan_days", "Orphan Account", "Sem dono ativo por mais de", "dias", 0, 365),
    ("key_age_days", "Authentic Posture", "Idade máxima de chaves de acesso", "dias", 1, 730),
    ("review_days", "Access Review", "Periodicidade das revisões", "dias", 7, 730),
    ("ueba_threshold", "UEBA", "Pontuação mínima de desvio para alertar", "pts", 1, 100),
]
SCHEDULES = {"manual": None, "daily": 24 * 3600, "6h": 6 * 3600, "hourly": 3600}

RULE_DETAILS = {
    "ACCESS_CREEP": ("Acúmulo de permissões ao longo do tempo, normalmente após mudanças de função, projeto ou área, sem revogar acessos anteriores.",
                     "Identidade em movimentação há mais de {creep_days} dias mantendo concessões anteriores"),
    "PERMISSION_USAGE": ("Compara o que foi concedido com o que foi de fato usado, a partir da telemetria de uso do provedor.",
                         "Concessão sem uso há mais de {unused_days} dias"),
    "TOXIC_COMBINATION": ("Pares de permissões que, na mesma identidade, violam a segregação de funções (SoD).",
                          "Pares conflitantes de administração de IAM, personificação e concessão de funções"),
    "JML": ("Acessos inconsistentes com o ciclo de vida: movimentação sem revogação ou desligamento sem bloqueio.",
            "Desligado com acesso ativo há mais de {leaver_hours} h"),
    "ORPHAN_ACCOUNT": ("Contas sem um responsável ativo: service accounts sem dono, usuários de fornecedor, contas locais.",
                       "Sem responsável válido há mais de {orphan_days} dias"),
    "AUTHENTICATION_POSTURE": ("Força da autenticação: MFA e idade das chaves de acesso de longa duração.",
                               "Identidade ativa sem MFA ou chave com mais de {key_age_days} dias"),
    "ACCESS_REVIEW": ("Revisões de acesso vencidas ou nunca realizadas para concessões ativas.",
                      "Concessão sem recertificação há mais de {review_days} dias"),
    "UEBA_ANOMALY": ("Desvios do comportamento de cada identidade identificados nos logs de auditoria do provedor.",
                     "Evento anômalo com pontuação de desvio ≥ {ueba_threshold}"),
    "PUBLIC_ACCESS": ("Políticas que concedem acesso a qualquer pessoa (allUsers) ou a qualquer conta autenticada.",
                      "Principal allUsers ou allAuthenticatedUsers em política IAM"),
    "SERVICE_ACCOUNT_ADMIN": ("Identidades não humanas com funções administrativas amplas.",
                              "Conta de serviço com owner, editor ou administração de IAM"),
}

# Rows of the "Risco por módulo × provedor" heatmap: open findings of these rules (None = all rules).
MODULES = [
    ("Identity Inventory", {"ORPHAN_ACCOUNT", "JML"}),
    ("Access Inventory", {"PERMISSION_USAGE", "ACCESS_CREEP"}),
    ("Access Intelligence", {"TOXIC_COMBINATION", "PUBLIC_ACCESS"}),
    ("Access Risk", None),
    ("Privileged Access", {"SERVICE_ACCOUNT_ADMIN"}),
    ("UEBA", {"UEBA_ANOMALY"}),
    ("Compliance Audit", {"ACCESS_REVIEW", "AUTHENTICATION_POSTURE"}),
]

# Compliance frameworks: (control id, description, linked rule label, evaluator, evaluator argument).
FRAMEWORKS = {
    "iso": ("ISO 27001", [
        ("A.5.15", "Controle de acesso definido por política e necessidade de negócio", "Uso real de permissão", "rule", "PERMISSION_USAGE"),
        ("A.5.16", "Gestão do ciclo de vida de identidades", "Joiner / Mover / Leaver", "rule", "JML"),
        ("A.5.18", "Direitos de acesso revisados periodicamente", "Access Review", "reviews", None),
        ("A.8.2", "Direitos de acesso privilegiado restritos e gerenciados", "Privileged Access", "privileged", None),
        ("A.8.5", "Autenticação segura", "Authentic Posture", "mfa", None),
        ("A.8.15", "Registro de eventos (logging)", "Auditoria", "audit", None),
    ]),
    "sox": ("SOX ITGC", [
        ("AC-01", "Segregação de funções em sistemas financeiros", "Toxic Combination", "rule", "TOXIC_COMBINATION"),
        ("AC-02", "Concessões recertificadas pelo responsável", "Access Review", "rule", "ACCESS_REVIEW"),
        ("AC-03", "Revogação tempestiva no desligamento", "Joiner / Mover / Leaver", "rule", "JML"),
        ("AC-04", "Revisão periódica de acessos", "Access Review", "reviews", None),
        ("AC-05", "Acesso privilegiado monitorado", "UEBA", "telemetry", None),
    ]),
    "lgpd": ("LGPD", [
        ("Art. 46", "Medidas de segurança contra acessos não autorizados", "Access Risk", "critical", None),
        ("Art. 37", "Registro das operações de tratamento", "Auditoria", "audit", None),
        ("Art. 49", "Sistemas estruturados para atender requisitos de segurança", "Authentic Posture", "mfa", None),
        ("Art. 50", "Governança e boas práticas", "Compliance Audit", "reports", None),
    ]),
    "cis": ("CIS Benchmarks", [
        ("1.10", "MFA para todos os usuários com console", "Authentic Posture", "mfa", None),
        ("1.12", "Credenciais sem uso desativadas", "Uso real de permissão", "rule", "PERMISSION_USAGE"),
        ("1.5 (GCP)", "Service accounts sem privilégios de administrador", "Privileged Access", "rule", "SERVICE_ACCOUNT_ADMIN"),
        ("1.1 (GCP)", "Recursos sem acesso público em políticas IAM", "Access Intelligence", "rule", "PUBLIC_ACCESS"),
        ("1.16", "Contas sem responsável removidas", "Orphan Account", "rule", "ORPHAN_ACCOUNT"),
    ]),
}

ESCALATION_METHODS = ("SetIamPolicy", "AttachUserPolicy", "PutUserPolicy", "AttachRolePolicy", "roleAssignments/write",
                      "GenerateAccessToken", "SignJwt", "SignBlob")
CREDENTIAL_METHODS = ("CreateServiceAccountKey", "CreateAccessKey", "CreateLoginProfile")
BUSINESS_HOURS_UTC_OFFSET = -3  # America/Sao_Paulo (no DST since 2019)


def parse_iso(value: Any) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def merged_settings(stored: dict[str, Any] | None) -> dict[str, Any]:
    stored = stored or {}
    return {
        "rules": {**DEFAULT_SETTINGS["rules"], **(stored.get("rules") or {})},
        "schedule": stored.get("schedule") if stored.get("schedule") in SCHEDULES else DEFAULT_SETTINGS["schedule"],
        "notifications": {**DEFAULT_SETTINGS["notifications"], **(stored.get("notifications") or {})},
        "webhook": stored.get("webhook") or "",
    }


def posture_score(severities: list[str], assessed_objects: int) -> int:
    weighted = sum(SEVERITY_WEIGHT.get(item, 0.5) for item in severities)
    penalty = round((weighted / max(1, assessed_objects)) * 100)
    return max(0, 100 - min(100, penalty))


def risk_score(severities: list[str], assessed_objects: int) -> int:
    """Risk is the complement of posture: 0 = no exposure, 100 = maximum."""
    return 100 - posture_score(severities, assessed_objects)


def identity_risk(severities: list[str]) -> int:
    return min(100, sum(IDENTITY_RISK_WEIGHT.get(item, 5) for item in severities))


def risk_level(score: int) -> str:
    return "critical" if score >= 85 else "high" if score >= 70 else "medium" if score >= 40 else "low"


def classify_event(method: str | None, denied: bool, timestamp: str | None) -> str:
    method = method or ""
    if any(method.endswith(name) or name in method for name in ESCALATION_METHODS):
        return "Escalada de privilégio"
    if any(method.endswith(name) for name in CREDENTIAL_METHODS):
        return "Criação de credencial"
    if denied:
        return "Acesso negado"
    occurred = parse_iso(timestamp)
    if occurred:
        local_hour = (occurred + timedelta(hours=BUSINESS_HOURS_UTC_OFFSET)).hour
        if local_hour < 7 or local_hour >= 20:
            return "Horário atípico"
    return "Operação sensível"


def control_status(evaluator: str, argument: str | None, metrics: dict[str, Any]) -> tuple[str, str]:
    """Return (status, evidence) for one control using only collected metrics."""
    if not metrics["assessed"] and evaluator not in {"audit", "reviews"}:
        return "Não avaliado", "Execute uma análise para gerar evidência"
    if evaluator == "rule":
        counts = metrics["rules"].get(argument, {"total": 0, "severe": 0})
        if counts["total"] == 0:
            return "Atendido", "Nenhum achado aberto"
        status = "Não atendido" if counts["severe"] else "Parcial"
        return status, f"{counts['total']} achado(s) aberto(s)"
    if evaluator == "mfa":
        known, missing = metrics["mfa_known"], metrics["mfa_missing"]
        if known == 0:
            return "Não avaliado", "O provedor não informa MFA das identidades"
        if missing == 0:
            return "Atendido", f"MFA em {known} identidade(s) ativas"
        return ("Parcial" if missing / known < 0.1 else "Não atendido"), f"{missing} de {known} sem MFA"
    if evaluator == "audit":
        if metrics["audit_events"] == 0:
            return "Não atendido", "Nenhum evento registrado"
        if metrics["telemetry_envs"]:
            return "Atendido", f"Trilha da plataforma e telemetria de {metrics['telemetry_envs']} ambiente(s)"
        return "Parcial", "Trilha da plataforma ativa; logs do provedor não coletados"
    if evaluator == "reviews":
        if metrics["grants"] == 0 and metrics["campaigns"] == 0:
            return "Não avaliado", "Sem concessões coletadas"
        if metrics["campaigns"] == 0:
            return "Não atendido", "Nenhuma campanha de revisão registrada"
        if metrics["campaigns_overdue"]:
            return "Parcial", f"{metrics['campaigns_overdue']} campanha(s) vencida(s)"
        return "Atendido", f"{metrics['campaigns']} campanha(s) em dia"
    if evaluator == "privileged":
        standing = metrics["privileged_standing"]
        if metrics["privileged"] == 0:
            return "Atendido", "Nenhum acesso privilegiado coletado"
        return ("Parcial" if standing < metrics["privileged"] else "Não atendido"), f"{standing} acesso(s) privilegiado(s) permanente(s)"
    if evaluator == "telemetry":
        if metrics["environments"] == 0:
            return "Não avaliado", "Nenhum ambiente conectado"
        if metrics["telemetry_envs"] == metrics["environments"]:
            return "Atendido", "Telemetria comportamental em todos os ambientes"
        if metrics["telemetry_envs"]:
            return "Parcial", f"Telemetria em {metrics['telemetry_envs']} de {metrics['environments']} ambiente(s)"
        return "Não atendido", "Nenhum ambiente com telemetria comportamental"
    if evaluator == "critical":
        critical = metrics["critical_open"]
        return ("Atendido", "Nenhum risco crítico aberto") if critical == 0 else ("Não atendido", f"{critical} risco(s) crítico(s) aberto(s)")
    if evaluator == "reports":
        scans = metrics["scans"]
        return ("Atendido", f"{scans} análise(s) concluída(s) com evidência") if scans else ("Não atendido", "Nenhuma análise concluída")
    return "Não avaliado", "Controle sem avaliador"


def framework_report(metrics: dict[str, Any]) -> list[dict[str, Any]]:
    result = []
    for key, (name, controls) in FRAMEWORKS.items():
        rows = []
        for control_id, description, rule_label, evaluator, argument in controls:
            status, evidence = control_status(evaluator, argument, metrics)
            rows.append({"id": control_id, "description": description, "rule": rule_label, "status": status, "evidence": evidence})
        assessed = [row for row in rows if row["status"] != "Não avaliado"]
        met = sum(1 for row in assessed if row["status"] == "Atendido")
        partial = sum(1 for row in assessed if row["status"] == "Parcial")
        percent = round((met + partial * 0.5) / len(assessed) * 100) if assessed else 0
        result.append({"key": key, "name": name, "percent": percent, "met": met, "assessed": len(assessed),
                       "total": len(rows), "controls": rows})
    return result
