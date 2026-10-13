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
    "corporateDomains": [],
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
    "IMPERSONATION_PATH": ("Identidades que chegam a privilégios administrativos indiretamente, personificando uma conta de serviço "
                           "(emissão de tokens, actAs, workload identity ou trust policy).",
                           "Cadeia de personificação até uma conta com papel privilegiado que a identidade não tem diretamente"),
}

# Rows of the "Risco por módulo × provedor" heatmap: open findings of these rules (None = all rules).
MODULES = [
    ("Identity Inventory", {"ORPHAN_ACCOUNT", "JML"}),
    ("Access Inventory", {"PERMISSION_USAGE", "ACCESS_CREEP"}),
    ("Access Intelligence", {"TOXIC_COMBINATION", "PUBLIC_ACCESS", "IMPERSONATION_PATH"}),
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
        ("1.6 (GCP)", "Usuários sem papéis de personificação de contas de serviço", "Caminhos de acesso", "rule", "IMPERSONATION_PATH"),
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
        "corporateDomains": [str(item) for item in stored.get("corporateDomains") or []][:20],
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


DENIED_CATEGORY = "Tentativa negada pelo provedor"
VERBS = {
    "insert": "criar", "create": "criar", "delete": "excluir", "remove": "remover", "patch": "alterar", "update": "alterar",
    "get": "ler", "list": "listar", "search": "pesquisar", "access": "acessar", "generate": "gerar", "sign": "assinar",
    "start": "iniciar", "stop": "parar", "reset": "reiniciar", "undelete": "restaurar", "enable": "habilitar",
    "disable": "desabilitar", "attach": "anexar", "detach": "desanexar", "put": "gravar", "upload": "enviar",
    "download": "baixar", "copy": "copiar", "rewrite": "reescrever", "compose": "compor", "move": "mover",
    "setiampolicy": "alterar a política IAM de", "getiampolicy": "ler a política IAM de",
    "testiampermissions": "testar permissões em", "setmetadata": "alterar metadados de", "setlabels": "alterar rótulos de",
}
OBJECTS = {
    "targethttpsproxies": "Target HTTPS Proxy", "targethttpproxies": "Target HTTP Proxy", "urlmaps": "URL Map",
    "backendservices": "Backend Service", "forwardingrules": "Forwarding Rule", "globalforwardingrules": "Forwarding Rule global",
    "instances": "VM", "instancetemplates": "template de VM", "instancegroups": "grupo de VMs", "firewalls": "regra de firewall",
    "networks": "rede VPC", "subnetworks": "sub-rede", "routers": "Cloud Router", "disks": "disco", "snapshots": "snapshot",
    "images": "imagem", "addresses": "endereço IP", "globaladdresses": "endereço IP global", "sslcertificates": "certificado SSL",
    "healthchecks": "health check", "buckets": "bucket", "objects": "objeto do Cloud Storage", "serviceaccountkey": "chave de service account",
    "serviceaccountkeys": "chave de service account", "serviceaccount": "service account", "serviceaccounts": "service account",
    "secretversion": "versão de segredo", "secret": "segredo", "secrets": "segredo", "projects": "projeto", "project": "projeto",
    "accesstoken": "token de acesso", "jwt": "JWT", "blob": "dados", "iampolicy": "política IAM", "clusters": "cluster GKE",
    "nodepools": "node pool", "pods": "pod", "deployments": "deployment", "databases": "banco de dados", "users": "usuário",
    "roles": "papel", "keys": "chave", "cryptokeys": "chave do KMS", "topics": "tópico Pub/Sub", "subscriptions": "assinatura Pub/Sub",
    "functions": "Cloud Function", "services": "serviço", "datasets": "dataset do BigQuery", "tables": "tabela do BigQuery",
    "jobs": "job",
}
VERSION_TOKENS = {"v1", "v1beta", "v1beta1", "v1alpha", "v2", "v2beta", "v3", "beta", "alpha", "google", "cloud", "io", "k8s", "admin"}
AUTOMATION_HINTS = (("crossplane", "Crossplane"), ("terraform", "Terraform"), ("github", "GitHub Actions"), ("gitlab", "GitLab CI"),
                    ("jenkins", "Jenkins"), ("argocd", "Argo CD"), ("cloudbuild", "Cloud Build"), ("cicd", "um pipeline de CI/CD"),
                    ("deploy", "um pipeline de deploy"), ("composer", "Cloud Composer"), ("dataflow", "Dataflow"))


PAST = {"criar": "criou", "excluir": "excluiu", "remover": "removeu", "alterar": "alterou", "ler": "leu", "listar": "listou",
        "pesquisar": "pesquisou", "acessar": "acessou", "gerar": "gerou", "assinar": "assinou", "iniciar": "iniciou",
        "parar": "parou", "reiniciar": "reiniciou", "restaurar": "restaurou", "habilitar": "habilitou", "desabilitar": "desabilitou",
        "anexar": "anexou", "desanexar": "desanexou", "gravar": "gravou", "enviar": "enviou", "baixar": "baixou", "copiar": "copiou",
        "reescrever": "reescreveu", "compor": "compôs", "mover": "moveu", "testar": "testou", "executar": "executou"}


def past_tense(phrase: str) -> str:
    head, _, rest = phrase.partition(" ")
    return f"{PAST.get(head, head)} {rest}".strip()


def _split_camel(value: str) -> list[str]:
    import re as _re
    return [part for part in _re.split(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])", value) if part]


def _object_label(token: str) -> str:
    key = token.lower()
    for candidate in (key, f"{key}s", key[:-1] if key.endswith("s") else key):
        if candidate in OBJECTS:
            return OBJECTS[candidate]
    words = " ".join(_split_camel(token)).lower()
    return words[:-3] + "y" if words.endswith("ies") else words[:-1] if words.endswith("s") and not words.endswith("ss") else words


def humanize_method(method: str | None) -> dict[str, str]:
    """Translate a provider API method into Portuguese: verb, object and the permission it most likely needs."""
    method = method or ""
    tokens = [token for token in method.replace("/", ".").split(".") if token]
    meaningful = [token for token in tokens if token.lower() not in VERSION_TOKENS]
    last = meaningful[-1] if meaningful else method
    verb, obj, permission = "executar", "operação", ""
    camel = _split_camel(last) if last else []
    if last and last[0].islower() and len(meaningful) >= 2 and last.lower() not in VERBS and camel and camel[0].lower() in VERBS:
        verb = f"{VERBS[camel[0].lower()]} {_object_label(''.join(camel[1:]))} de"
        obj = _object_label(meaningful[-2])
        verb_key = ""
    elif last and last[0].islower() and len(meaningful) >= 2:
        verb_key = last.lower()
        verb = VERBS.get(verb_key, last)
        obj = _object_label(meaningful[-2])
        if len(meaningful) >= 3 and verb_key in VERBS and "iam" not in verb_key:
            service = meaningful[0]
            permission = f"{service}.{meaningful[-2]}.{ {'insert': 'create', 'patch': 'update'}.get(verb_key, verb_key) }".replace(" ", "")
    elif last:
        parts = _split_camel(last)
        head = parts[0].lower() if parts else ""
        if last.lower() in {"setiampolicy", "getiampolicy"} and len(meaningful) == 1:
            verb, obj = ("alterar a política IAM do" if last.lower() == "setiampolicy" else "ler a política IAM do"), "projeto"
        elif last.lower() in VERBS:
            verb, obj = VERBS[last.lower()], "recurso"
        elif head in VERBS:
            verb, obj = VERBS[head], _object_label("".join(parts[1:])) or "recurso"
        else:
            verb, obj = "executar", " ".join(parts).lower()
    return {"verb": verb, "object": obj, "permission": permission, "method": method}


def classify_event(method: str | None, denied: bool, timestamp: str | None) -> str:
    method = method or ""
    escalation = any(method.endswith(name) or name in method for name in ESCALATION_METHODS)
    if escalation:
        return "Tentativa de escalada negada" if denied else "Escalada de privilégio"
    if any(method.endswith(name) for name in CREDENTIAL_METHODS):
        return "Tentativa de criar credencial negada" if denied else "Criação de credencial"
    if denied:
        return DENIED_CATEGORY
    occurred = parse_iso(timestamp)
    if occurred:
        local_hour = (occurred + timedelta(hours=BUSINESS_HOURS_UTC_OFFSET)).hour
        if local_hour < 7 or local_hour >= 20:
            return "Horário atípico"
    return "Operação sensível"


def local_time(value: Any, with_date: bool = True) -> str:
    moment = parse_iso(value) if isinstance(value, str) else value
    if not moment:
        return "—"
    local = moment + timedelta(hours=BUSINESS_HOURS_UTC_OFFSET)
    return local.strftime("%d/%m %H:%M") if with_date else local.strftime("%H:%M")


def _cadence(times: list[datetime]) -> tuple[str, bool]:
    """Human cadence of repeated occurrences and whether it is regular (automation-like)."""
    if len(times) < 3:
        return "", False
    gaps = sorted((later - earlier).total_seconds() for earlier, later in zip(times, times[1:]))
    median = gaps[len(gaps) // 2]
    if median < 1:
        return "em rajadas (várias no mesmo segundo)", False
    regular = sum(1 for gap in gaps if abs(gap - median) <= max(5, median * 0.2)) / len(gaps) >= 0.7
    if median < 90:
        label = "cerca de 1 por minuto" if median >= 40 else f"a cada ~{round(median)} s"
    elif median < 3600:
        label = f"a cada ~{round(median / 60)} min"
    else:
        label = f"a cada ~{round(median / 3600)} h"
    return label, regular


def _plural(count: int, singular: str, plural: str) -> str:
    return f"{count} {singular if count == 1 else plural}"


def explain_anomaly(events: list[dict[str, Any]], identity: str, provider: str, resource: str,
                    baseline_events: int = 0, window_days: int = 7) -> dict[str, Any]:
    """Plain-language explanation of a group of anomalous audit events from one identity on one resource."""
    ordered = sorted(events, key=lambda item: item.get("timestamp") or "")
    times = [moment for moment in (parse_iso(item.get("timestamp")) for item in ordered) if moment]
    first = ordered[0] if ordered else {}
    method = first.get("method") or ""
    denied = any(item.get("denied") for item in ordered)
    count = len(ordered)
    action = humanize_method(method)
    category = classify_event(method, denied, first.get("timestamp"))
    is_service = "gserviceaccount.com" in identity or identity.startswith("serviceAccount:") or ":role/" in identity
    kind = "service account" if is_service else "identidade"
    short = identity.split("@")[0].split("/")[-1] if identity else "identidade desconhecida"
    tool = next((label for key, label in AUTOMATION_HINTS if key in identity.lower()), "")
    cadence, regular = _cadence(times)
    internal = {"private", "gce-internal-ip", "0.0.0.0"}
    ips = sorted({item.get("callerIp") for item in ordered if item.get("callerIp") and item.get("callerIp") not in internal})
    from_internal = any(item.get("callerIp") in internal for item in ordered)
    ip_text = (f", a partir do IP {ips[0]}" if len(ips) == 1 else f", a partir de {len(ips)} IPs ({', '.join(ips[:3])})" if ips
               else ", a partir da rede interna do provedor" if from_internal else "")
    span = ("" if not times else f" às {local_time(times[0])}" if len(times) == 1 or local_time(times[0]) == local_time(times[-1])
            else f" entre {local_time(times[0])} e {local_time(times[-1], with_date=times[0].date() != times[-1].date())}")
    what = f"{action['verb']} {action['object']}"
    if action["object"] == "projeto" and resource:
        what, where = f"{what} {resource}", ""
    else:
        where = f" no projeto {resource}" if resource else ""
    occurrences = _plural(count, "vez", "vezes")
    rhythm = f" ({cadence})" if cadence else ""
    provider_name = {"GCP": "GCP", "AWS": "AWS", "Azure": "Azure"}.get(provider, provider)
    escalation = category in {"Escalada de privilégio", "Tentativa de escalada negada"}
    if escalation and "política IAM" in action["verb"]:
        title = ("Tentativas negadas de alterar a política IAM" if denied else "Alteração da política IAM") + (f" em {resource}" if resource else "")
    elif denied:
        title = f"Tentativas negadas de {what}" + (f" em {resource}" if resource else "")
    else:
        title = f"{what[0].upper()}{what[1:]}" + (f" em {resource}" if resource else "")
    if denied:
        happened = (f"A {kind} {identity} tentou {what}{where} {occurrences}{span}{rhythm}{ip_text}. "
                    f"O {provider_name} recusou {'a tentativa' if count == 1 else 'todas as tentativas'}.")
        why = ("Uma conta repetindo uma operação para a qual não tem permissão indica configuração quebrada ou tentativa de uso indevido."
               if count > 1 else "A conta tentou uma operação para a qual não tem permissão.")
    else:
        happened = f"A {kind} {identity} {past_tense(what)}{where} {occurrences}{span}{rhythm}{ip_text}. A operação foi concluída."
        why = {
            "Escalada de privilégio": "Alterar políticas IAM permite conceder privilégios a si mesmo ou a terceiros; feito por uma conta fora de um processo aprovado, é um caminho conhecido de escalada de privilégio.",
            "Criação de credencial": "Chaves e tokens criados para contas de serviço funcionam fora do provedor; cada nova credencial amplia a superfície de vazamento.",
            "Horário atípico": "A operação ocorreu fora do horário comercial (07h–20h, horário de Brasília).",
        }.get(category, "A operação é sensível e foi destacada pelos logs de auditoria do provedor.")
    if baseline_events:
        expected = f"≈ {baseline_events / window_days:.1f} evento(s) administrativo(s) por dia desta identidade" + (", sem tentativas negadas" if denied else "")
    else:
        expected = "Nenhuma atividade administrativa regular desta identidade no período coletado"
        why += " Essa identidade não tem atividade administrativa regular no período coletado."
    observed = (f"{_plural(count, 'tentativa negada', 'tentativas negadas') if denied else _plural(count, 'ocorrência', 'ocorrências')}"
                f" de {method or 'operação'}" + (f", {cadence}" if cadence else "") + (f" · última às {local_time(times[-1], with_date=False)}" if times else ""))
    if regular and count >= 5:
        interpretation = (f"O ritmo constante ({cadence}) indica automação em loop" + (f" — o nome da conta sugere {tool}" if tool else "")
                          + (": um recurso declarado está sendo criado ou reconciliado repetidamente e falhando por falta de permissão. Parece mais uma configuração quebrada do que um ataque."
                             if denied else ": um processo automatizado executa a operação continuamente."))
    elif is_service:
        interpretation = ("Uma service account normalmente executa ações de um workload ou pipeline" + (f" ({tool})" if tool else "")
                          + "; confirme se esta operação faz parte do que ela deveria fazer.")
    else:
        interpretation = ("Ação de um usuário: pode ser falta de permissão para uma tarefa legítima ou exploração do ambiente."
                          if denied else "Ação de um usuário: confirme com a pessoa se a operação foi intencional.")
    actions: list[str] = []
    if denied:
        target = f"no projeto {resource}" if resource else "no escopo correto"
        actions.append(f"Confirme com o responsável pela conta {short} se a operação é esperada.")
        if action["permission"]:
            actions.append(f"Se for esperada, conceda a permissão {action['permission']} (provável permissão ausente) somente {target}.")
        actions.append("Se não for, corrija ou remova o recurso ou job que dispara a operação"
                       + (f" (ex.: o recurso do {tool} que aponta para {resource})" if tool and resource else "") + ".")
    elif category == "Escalada de privilégio":
        actions += ["Verifique no Cloud Audit Logs qual vínculo IAM foi adicionado ou removido.",
                    "Restrinja a alteração de políticas IAM a pipelines aprovados e retire o papel administrativo da conta se não for necessário."]
    elif category == "Criação de credencial":
        actions += ["Confirme quem criou a credencial e para qual uso.",
                    "Prefira Workload Identity Federation; se a credencial não for necessária, desative-a e exclua."]
    else:
        actions.append(f"Confirme com o responsável pela conta {short} se a operação foi planejada.")
    actions.append("Depois de confirmar, marque como comportamento esperado (com justificativa) ou abra um incidente.")
    return {"title": title, "category": category, "happened": happened, "why": why, "interpretation": interpretation,
            "actions": actions, "expected": expected, "observed": observed, "permission": action["permission"],
            "method": method, "denied": denied, "count": count,
            "lastAt": times[-1].isoformat() if times else first.get("timestamp")}


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
