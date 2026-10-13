"""Read-only governance analytics: least-privilege recommendations, non-human identities and the access graph.

Everything here is pure (no I/O) so it can be tested in isolation and reused by the scan and the API."""
from __future__ import annotations

import hashlib
from collections import deque
from datetime import datetime, timezone
from typing import Any, Iterable

BASIC_ROLES = {"roles/owner": 3, "roles/editor": 2, "roles/viewer": 1}
ADMIN_ROLES = {"roles/owner", "roles/iam.securityAdmin", "roles/resourcemanager.projectIamAdmin", "AdministratorAccess", "Owner",
               "User Access Administrator"}
IMPERSONATION_GRANT_ROLES = {"roles/iam.serviceAccountTokenCreator", "roles/iam.serviceAccountUser", "roles/iam.workloadIdentityUser",
                             "roles/iam.serviceAccountOpenIdTokenCreator"}
GOOGLE_MANAGED_MARKERS = ("@cloudservices.gserviceaccount.com", "-compute@developer.gserviceaccount.com", "@appspot.gserviceaccount.com",
                          "@system.gserviceaccount.com", "@cloudbuild.gserviceaccount.com", "@gcp-sa-", "gcp-sa-",
                          "@container-engine-robot.", "@compute-system.", "@serverless-robot-prod.", "@gae-api-prod.",
                          "@dataflow-service-producer-prod.", "@gs-project-accounts.")
AI_MARKERS = (("gcp-sa-aiplatform-re", "Agente do Vertex AI Agent Engine"), ("gcp-sa-aiplatform-cc", "Agente de código do Vertex AI"),
              ("gcp-sa-aiplatform", "Agente de serviço do Vertex AI"), ("gcp-sa-discoveryengine", "Agente do Vertex AI Search / Agent Builder"),
              ("gcp-sa-dialogflow", "Agente do Dialogflow / Conversational Agents"), ("gcp-sa-cloudaicompanion", "Agente do Gemini para Google Cloud"),
              ("gcp-sa-notebooks", "Agente do Vertex AI Workbench"), ("gcp-sa-ml", "Agente do AI Platform"),
              ("bedrock", "Role do Amazon Bedrock"), ("sagemaker", "Role do Amazon SageMaker"))
AI_ROLE_PREFIXES = ("roles/aiplatform.", "roles/discoveryengine.", "roles/dialogflow.", "roles/cloudaicompanion.", "roles/ml.",
                    "AmazonBedrock", "AmazonSageMaker", "Cognitive Services", "Azure AI")
ACTION_LABEL = {"remove": "Remover", "replace": "Substituir", "move_to_group": "Mover para grupo"}


def parse_iso(value: Any) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def days_ago(value: Any) -> int | None:
    parsed = parse_iso(value)
    return None if parsed is None else max(0, (datetime.now(timezone.utc) - parsed).days)


def is_google_managed(identity_id: str) -> bool:
    lowered = identity_id.lower()
    return any(marker in lowered for marker in GOOGLE_MANAGED_MARKERS)


def ai_kind(identity_id: str, roles: Iterable[str] = ()) -> str | None:
    lowered = identity_id.lower()
    for marker, label in AI_MARKERS:
        if marker in lowered:
            return label
    if any(str(role).startswith(AI_ROLE_PREFIXES) for role in roles):
        return "Conta com acesso a serviços de IA"
    return None


def member_name(identity_id: str) -> str:
    """Readable account name from a provider principal (GCP member, AWS ARN)."""
    value = identity_id.split("?uid=")[0]
    for prefix in ("deleted:", "serviceAccount:", "user:", "group:", "domain:"):
        if value.startswith(prefix):
            value = value[len(prefix):]
    return value.rsplit("/", 1)[-1] if value.startswith("arn:") else value


# ── least privilege ──────────────────────────────────────────────────────────────────────────────

def recommendation_key(provider: str, identity_id: str, resource_id: str, role: str) -> str:
    """One recommendation per grant: the provider's own recommendation wins over platform rules for the same grant."""
    return hashlib.sha1(f"{provider}|{identity_id}|{resource_id}|{role}".encode()).hexdigest()


def fix_command(provider: str, identity_id: str, resource_id: str, role: str, action: str, suggested: list[str],
                permissions: list[str] | None = None) -> str:
    """Command an operator runs in the provider to apply the recommendation (the platform itself never writes)."""
    if provider == "GCP":
        if "/" in resource_id:  # repositories and other sub-resources are changed on the resource itself
            return f"# Ajuste a política IAM do recurso {resource_id} removendo {identity_id} de {role}."
        lines = []
        if action == "move_to_group":
            lines.append(f"gcloud projects add-iam-policy-binding {resource_id} --member='group:GRUPO@SEU-DOMINIO' --role='{role}'")
        for new_role in suggested:
            lines.append(f"gcloud projects add-iam-policy-binding {resource_id} --member='{identity_id}' --role='{new_role}'")
        lines.append(f"gcloud projects remove-iam-policy-binding {resource_id} --member='{identity_id}' --role='{role}'")
        return "\n".join(lines)
    if provider == "AWS":
        name = member_name(identity_id)
        kind = "role" if ":role/" in identity_id else "user"
        policy_arn = next((item for item in permissions or [] if str(item).startswith("arn:")), None)
        if policy_arn:
            command = f"aws iam detach-{kind}-policy --{kind}-name {name} --policy-arn {policy_arn}"
        else:
            command = f"aws iam delete-{kind}-policy --{kind}-name {name} --policy-name {role}"
        if action == "move_to_group":
            return f"aws iam attach-group-policy --group-name GRUPO --policy-arn {policy_arn or 'ARN-DA-POLITICA'}\naws iam add-user-to-group --group-name GRUPO --user-name {name}\n{command}"
        return command
    scope = resource_id if resource_id.startswith("/") else f"/subscriptions/{resource_id}"
    command = f'az role assignment delete --assignee {identity_id} --role "{role}" --scope {scope}'
    if action == "move_to_group":
        return f'az role assignment create --assignee-object-id ID-DO-GRUPO --role "{role}" --scope {scope}\n{command}'
    return command


def build_recommendations(provider: str, identities: list[dict[str, Any]], accesses: list[dict[str, Any]],
                          recommender: list[dict[str, Any]], role_severity) -> list[dict[str, Any]]:
    """Merge Google IAM Recommender output with deterministic platform rules into one prioritized list."""
    types = {str(item.get("id")): item.get("type", "user") for item in identities}
    names = {str(item.get("id")): item.get("name") or member_name(str(item.get("id"))) for item in identities}
    roles_by_pair: dict[tuple[str, str], set[str]] = {}
    for grant in accesses:
        roles_by_pair.setdefault((str(grant["identityId"]), str(grant["resourceId"])), set()).add(str(grant["role"]))
    result: dict[str, dict[str, Any]] = {}

    def add(grant: dict[str, Any] | None, identity_id: str, resource_id: str, resource_name: str, role: str, action: str,
            suggested: list[str], reason: str, source: str) -> None:
        key = recommendation_key(provider, identity_id, resource_id, role)
        if key in result and result[key]["source"].startswith("Google") and not source.startswith("Google"):
            return
        severity = role_severity(role)
        result[key] = {
            "key": key, "provider": provider, "identityId": identity_id, "identityName": names.get(identity_id, member_name(identity_id)),
            "identityType": types.get(identity_id, "user"), "resourceId": resource_id, "resourceName": resource_name or resource_id,
            "role": role, "action": action, "suggestedRoles": suggested, "reason": reason, "source": source,
            "privileged": bool(grant.get("privileged")) if grant else (role in ADMIN_ROLES or (role in BASIC_ROLES and role != "roles/viewer")),
            "severity": severity,
            "command": fix_command(provider, identity_id, resource_id, role, action, suggested, (grant or {}).get("permissions")),
        }

    grants_by_key = {(str(g["identityId"]), str(g["resourceId"]), str(g["role"])): g for g in accesses}
    for grant in accesses:
        identity_id, resource_id, role = str(grant["identityId"]), str(grant["resourceId"]), str(grant["role"])
        resource_name = str(grant.get("resourceName") or resource_id)
        identity_type = types.get(identity_id, "user")
        held = roles_by_pair.get((identity_id, resource_id), set())
        if identity_type == "deleted":
            add(grant, identity_id, resource_id, resource_name, role, "remove", [],
                "O principal foi excluído, mas o vínculo continua na política IAM; se um principal com o mesmo nome for recriado, herda o acesso.",
                "Regras da plataforma")
        elif identity_type == "public":
            add(grant, identity_id, resource_id, resource_name, role, "remove", [],
                "O papel está concedido a qualquer pessoa na internet (allUsers) ou a qualquer conta Google autenticada.", "Regras da plataforma")
        elif role in BASIC_ROLES and any(BASIC_ROLES.get(other, 0) > BASIC_ROLES[role] for other in held):
            higher = max((other for other in held if other in BASIC_ROLES), key=BASIC_ROLES.get)
            add(grant, identity_id, resource_id, resource_name, role, "remove", [],
                f"Redundante: a mesma identidade já tem {higher} neste projeto, que inclui todas as permissões de {role}.", "Regras da plataforma")
        elif grant.get("totalPermissions") and grant.get("usedPermissions") == 0:
            add(grant, identity_id, resource_id, resource_name, role, "remove", [],
                f"Nenhuma das {grant['totalPermissions']} permissões do papel foi usada no período observado pelo provedor.",
                "Google IAM Recommender (uso)")
        elif provider == "GCP" and role in {"roles/owner", "roles/editor"} and identity_type == "service" and not is_google_managed(identity_id):
            add(grant, identity_id, resource_id, resource_name, role, "replace", [],
                "Papel básico amplo em conta de serviço: substitua por papéis predefinidos com só o que o workload usa "
                "(com o IAM Recommender habilitado, a plataforma indica os papéis exatos).", "Regras da plataforma")
        elif provider == "GCP" and role in {"roles/owner", "roles/editor"} and identity_type == "user":
            add(grant, identity_id, resource_id, resource_name, role, "move_to_group", [],
                "Papel básico de alto impacto concedido diretamente a uma pessoa: conceda a um grupo para que entradas e saídas "
                "da equipe sejam controladas em um só lugar.", "Regras da plataforma")
        elif provider == "AWS" and role == "AdministratorAccess" and identity_type == "user":
            add(grant, identity_id, resource_id, resource_name, role, "move_to_group", [],
                "AdministratorAccess anexada diretamente a um usuário IAM: use grupo ou role assumida com sessão temporária.",
                "Regras da plataforma")
        elif provider == "Azure" and role in {"Owner", "Contributor", "User Access Administrator"} and identity_type == "user":
            add(grant, identity_id, resource_id, resource_name, role, "move_to_group", [],
                "Papel de alto impacto atribuído diretamente a uma pessoa: atribua a um grupo do Entra ID.", "Regras da plataforma")
    for item in recommender:
        identity_id, resource_id, role = str(item["member"]), str(item["projectId"]), str(item["role"])
        grant = grants_by_key.get((identity_id, resource_id, role))
        add(grant, identity_id, resource_id, (grant or {}).get("resourceName", resource_id), role, item["action"], item.get("suggestedRoles", []),
            item.get("description") or ("Permissões não usadas nos últimos 90 dias." if item["action"] == "remove"
                                        else "Papel menor cobre o uso dos últimos 90 dias."),
            "Google IAM Recommender")
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted(result.values(), key=lambda rec: (not rec["privileged"], order.get(rec["severity"], 4), rec["identityName"]))


# ── non-human identities ─────────────────────────────────────────────────────────────────────────

def owner_of(identity: dict[str, Any], account: dict[str, Any] | None) -> tuple[str | None, str]:
    """Owner and the evidence used: provider tag, account description, creation log or Google management."""
    if identity.get("owner"):
        return identity["owner"], "Tag de responsável no provedor"
    if account and account.get("ownerHint"):
        return account["ownerHint"], "Descrição da conta"
    if account and account.get("createdBy"):
        return account["createdBy"], "Criou a conta (logs de auditoria)"
    if is_google_managed(str(identity.get("id", ""))):
        return "Google (conta gerenciada)", "Conta gerenciada pelo Google"
    return None, "Sem evidência de responsável"


def nhi_flags(item: dict[str, Any], key_age_limit: int, unused_limit: int) -> list[str]:
    flags = []
    if item["privilegedCount"] and not item["owner"]:
        flags.append("Privilegiada sem responsável identificado")
    if item["oldestKeyDays"] is not None and item["oldestKeyDays"] > key_age_limit:
        flags.append(f"Chave com {item['oldestKeyDays']} dias (limite {key_age_limit})")
    if item["unusedKeys"]:
        flags.append(f"{item['unusedKeys']} chave(s) sem uso registrado")
    if item["lastUsedDays"] is not None and item["lastUsedDays"] > unused_limit:
        flags.append(f"Sem uso há {item['lastUsedDays']} dias")
    if item["impersonators"]:
        flags.append(f"{item['impersonators']} identidade(s) podem personificá-la")
    if item["disabled"] and item["grantCount"]:
        flags.append("Desativada, mas ainda com concessões")
    return flags


# ── access graph ─────────────────────────────────────────────────────────────────────────────────

def impersonation_edges(accesses: list[dict[str, Any]], stored_edges: list[dict[str, Any]],
                        accounts_by_project: dict[str, list[str]]) -> list[dict[str, Any]]:
    """Account-level bindings plus project-level impersonation roles (which apply to every account of the project)."""
    edges = [dict(edge) for edge in stored_edges]
    for grant in accesses:
        if grant["role"] in IMPERSONATION_GRANT_ROLES:
            for target in accounts_by_project.get(str(grant["resourceId"]), []):
                if target != grant["identityId"]:
                    edges.append({"source": str(grant["identityId"]), "target": target, "role": grant["role"],
                                  "scope": "project", "resourceId": str(grant["resourceId"])})
    unique = {}
    for edge in edges:
        unique.setdefault((edge["source"], edge["target"]), edge)
    return list(unique.values())


def corporate_domains(identities: list[dict[str, Any]], configured: list[str]) -> list[str]:
    if configured:
        return sorted({domain.strip().lower().lstrip("@") for domain in configured if domain.strip()})
    counts: dict[str, int] = {}
    humans = [item for item in identities if item.get("type") in {"user", "group"}]
    for item in humans:
        email = item.get("email") or member_name(str(item.get("id", "")))
        if "@" in email:
            domain = email.rsplit("@", 1)[1].lower()
            counts[domain] = counts.get(domain, 0) + 1
    total = sum(counts.values())
    return sorted(domain for domain, count in counts.items() if total and count / total >= 0.05)


def is_external(identity: dict[str, Any], domains: list[str]) -> bool:
    if identity.get("type") == "public":
        return True
    if identity.get("type") not in {"user", "group", "domain"}:
        return False
    email = identity.get("email") or member_name(str(identity.get("id", "")))
    domain = email.rsplit("@", 1)[-1].lower() if "@" in email else email.lower()
    return bool(domains) and not any(domain == item or domain.endswith(f".{item}") for item in domains)


class AccessGraph:
    """Identity → (impersonation)* → service account → grants, with breadth-first reachability."""

    def __init__(self, accesses: list[dict[str, Any]], edges: list[dict[str, Any]], max_depth: int = 4):
        self.grants: dict[str, list[dict[str, Any]]] = {}
        for grant in accesses:
            self.grants.setdefault(str(grant["identityId"]), []).append(grant)
        self.out: dict[str, list[dict[str, Any]]] = {}
        self.inbound: dict[str, list[dict[str, Any]]] = {}
        for edge in edges:
            self.out.setdefault(edge["source"], []).append(edge)
            self.inbound.setdefault(edge["target"], []).append(edge)
        self.max_depth = max_depth

    def reachable(self, start: str) -> dict[str, list[dict[str, Any]]]:
        """Service accounts reachable from `start`, each with the shortest chain of edges."""
        paths: dict[str, list[dict[str, Any]]] = {}
        queue = deque([(start, [])])
        seen = {start}
        while queue:
            node, chain = queue.popleft()
            if len(chain) >= self.max_depth:
                continue
            for edge in self.out.get(node, []):
                target = edge["target"]
                if target in seen:
                    continue
                seen.add(target)
                paths[target] = chain + [edge]
                queue.append((target, paths[target]))
        return paths

    def reach(self, identity: str) -> dict[str, Any]:
        own = self.grants.get(identity, [])
        via = self.reachable(identity)
        indirect = [{"grant": grant, "chain": chain} for target, chain in via.items() for grant in self.grants.get(target, [])]
        own_keys = {(g["resourceId"], g["role"]) for g in own}
        new_indirect = [item for item in indirect if (item["grant"]["resourceId"], item["grant"]["role"]) not in own_keys]
        direct_resources = {g["resourceId"] for g in own}
        indirect_resources = {item["grant"]["resourceId"] for item in new_indirect} - direct_resources
        return {"direct": own, "indirect": new_indirect, "accounts": via,
                "directResources": len(direct_resources), "indirectResources": len(indirect_resources),
                "privilegedDirect": sum(1 for g in own if g.get("privileged")),
                "privilegedIndirect": sum(1 for item in new_indirect if item["grant"].get("privileged"))}

    def escalation_paths(self, identities: dict[str, dict[str, Any]], domains: list[str], limit: int = 2000) -> list[dict[str, Any]]:
        """Chains that give an identity privileged access it does not hold directly."""
        result = []
        for source in self.out:
            reach = self.reach(source)
            for item in reach["indirect"]:
                grant = item["grant"]
                if not grant.get("privileged"):
                    continue
                identity = identities.get(source, {"id": source, "type": "user"})
                admin = grant["role"] in ADMIN_ROLES
                result.append({"source": source, "sourceType": identity.get("type"), "external": is_external(identity, domains),
                               "chain": [{"target": edge["target"], "role": edge["role"], "scope": edge["scope"]} for edge in item["chain"]],
                               "role": grant["role"], "resourceId": grant["resourceId"], "resourceName": grant.get("resourceName") or grant["resourceId"],
                               "severity": "critical" if admin or identity.get("type") == "public" or is_external(identity, domains) else "high"})
                if len(result) >= limit:
                    return result
        order = {"critical": 0, "high": 1}
        return sorted(result, key=lambda path: (order.get(path["severity"], 2), not path["external"], len(path["chain"])))
