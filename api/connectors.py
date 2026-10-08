from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from typing import Any


class ConnectorError(Exception):
    """Safe error raised when a cloud discovery cannot be completed."""


GCP_TOKEN_URI = "https://oauth2.googleapis.com/token"

# Single source of truth for what each connector needs: accepted JSON field sets,
# the roles to grant, the permissions probed before saving and a template payload.
REQUIREMENTS: dict[str, dict[str, Any]] = {
    "GCP": {
        "kind": "Service account (JSON)",
        "scopeKind": "Projeto",
        "roles": ["roles/iam.securityReviewer", "roles/browser", "roles/logging.viewer",
                  "roles/recommender.iamViewer (uso real)", "roles/policyanalyzer.activityAnalysisViewer (uso real)"],
        "required": [["type", "project_id", "private_key", "client_email"]],
        "checks": [
            {"permission": "resourcemanager.projects.get", "required": True},
            {"permission": "resourcemanager.projects.getIamPolicy", "required": True},
            {"permission": "logging.logEntries.list", "required": False},
            {"permission": "source.repos.list", "required": False},
            {"permission": "iam.serviceAccountKeys.get", "required": False},
            {"permission": "recommender.iamPolicyInsights.list", "required": False},
            {"permission": "policyanalyzer.serviceAccountLastAuthenticationActivities.query", "required": False},
        ],
        "sample": {
            "type": "service_account", "project_id": "meu-projeto", "private_key_id": "…",
            "private_key": "-----BEGIN PRIVATE KEY-----\n…\n-----END PRIVATE KEY-----\n",
            "client_email": "iga-reader@meu-projeto.iam.gserviceaccount.com", "client_id": "…",
            "token_uri": GCP_TOKEN_URI,
        },
    },
    "AWS": {
        "kind": "IAM Role ou access key",
        "scopeKind": "Conta",
        "roles": ["SecurityAudit", "IAMReadOnlyAccess", "organizations:ListAccounts"],
        "required": [
            ["accessKeyId", "secretAccessKey"],
            ["aws_access_key_id", "aws_secret_access_key"],
            ["accountId", "roleArn"],
        ],
        "checks": [
            {"permission": "sts:GetCallerIdentity", "required": True},
            {"permission": "iam:ListUsers", "required": True},
            {"permission": "iam:ListRoles", "required": True},
            {"permission": "organizations:ListAccounts", "required": False},
        ],
        "sample": {
            "accessKeyId": "AKIA…", "secretAccessKey": "…",
            "roleArn": "arn:aws:iam::123456789012:role/NexoIGAAudit", "externalId": "…", "region": "us-east-1",
        },
    },
    "Azure": {
        "kind": "App registration",
        "scopeKind": "Assinatura",
        "roles": ["Reader (assinaturas)", "Microsoft.Authorization/*/read", "Application.Read.All (opcional)"],
        "required": [["tenantId", "clientId", "clientSecret"], ["tenant_id", "client_id", "client_secret"]],
        "checks": [
            {"permission": "Microsoft.Resources/subscriptions/read", "required": True},
            {"permission": "Microsoft.Authorization/roleDefinitions/read", "required": True},
            {"permission": "Microsoft.Authorization/roleAssignments/read", "required": True},
            {"permission": "Application.Read.All", "required": False},
        ],
        "sample": {"tenantId": "00000000-0000-0000-0000-000000000000", "clientId": "…", "clientSecret": "…"},
    },
}

AWS_KEY_ALIASES = {
    "AccessKeyId": "accessKeyId", "SecretAccessKey": "secretAccessKey", "SessionToken": "sessionToken",
    "RoleArn": "roleArn", "ExternalId": "externalId", "Region": "region", "AccountId": "accountId",
    "Expiration": "expiration",
}


def iso(value: Any) -> str | None:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()
    return str(value) if value else None


def parse_iso(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not value or not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def normalize_credential(provider: str, credential: dict[str, Any]) -> dict[str, Any]:
    """Accept the formats emitted by the provider CLIs (e.g. `aws sts` PascalCase output)."""
    if provider != "AWS":
        return dict(credential)
    source = credential.get("Credentials") if isinstance(credential.get("Credentials"), dict) else credential
    normalized = {AWS_KEY_ALIASES.get(key, key): value for key, value in source.items()}
    for key, value in credential.items():
        if key != "Credentials":
            normalized.setdefault(AWS_KEY_ALIASES.get(key, key), value)
    return normalized


def mask(value: str) -> str:
    return value if len(value) <= 8 else f"{value[:4]}…{value[-4:]}"


def describe_credential(provider: str, credential: dict[str, Any]) -> tuple[str, str]:
    """Non-secret description (kind, principal) safe to persist and list."""
    if provider == "GCP":
        return REQUIREMENTS["GCP"]["kind"], str(credential.get("client_email", ""))
    if provider == "AWS":
        if credential.get("roleArn"):
            return "IAM Role (AssumeRole)", str(credential["roleArn"])
        access_key = str(credential.get("accessKeyId") or credential.get("aws_access_key_id") or "")
        return "Access key (IAM)", mask(access_key)
    tenant = credential.get("tenantId") or credential.get("tenant_id") or ""
    return REQUIREMENTS["Azure"]["kind"], f"tenant {tenant}"


def scope_entry(provider: str, scope_id: Any, name: Any = None) -> dict[str, str]:
    scope_id = str(scope_id)
    name = str(name) if name else scope_id
    if provider == "GCP":
        label = scope_id
    elif provider == "AWS":
        label = f"{scope_id} · {name}" if name != scope_id else scope_id
    else:
        label = name
    return {"id": scope_id, "name": name, "label": label}


def guarded(provider: str, operation, *args, **kwargs):
    try:
        return operation(*args, **kwargs)
    except ConnectorError:
        raise
    except Exception as exc:
        name = type(exc).__name__
        raise ConnectorError(f"Falha de autenticação ou autorização no conector {provider} ({name}).") from exc


def discover(provider: str, credential: dict[str, Any], scopes: list[str] | None = None) -> dict[str, list[dict[str, Any]]]:
    connectors = {"AWS": discover_aws, "Azure": discover_azure, "GCP": discover_gcp}
    if provider not in connectors:
        raise ConnectorError(f"Provedor não suportado: {provider}")
    return guarded(provider, connectors[provider], credential, scopes)


def probe(provider: str, credential: dict[str, Any]) -> dict[str, Any]:
    """Read-only access check run before a credential is saved."""
    probes = {"AWS": probe_aws, "Azure": probe_azure, "GCP": probe_gcp}
    if provider not in probes:
        raise ConnectorError(f"Provedor não suportado: {provider}")
    return guarded(provider, probes[provider], credential)


def succeeds(operation) -> bool:
    try:
        operation()
        return True
    except Exception:
        return False


def probe_result(provider: str, identity: str, scopes: list[dict[str, str]], granted: set[str],
                 expires_at: str | None) -> dict[str, Any]:
    checks = [{**item, "granted": item["permission"] in granted} for item in REQUIREMENTS[provider]["checks"]]
    missing = [item["permission"] for item in checks if item["required"] and not item["granted"]]
    if missing:
        raise ConnectorError(f"Permissão obrigatória ausente: {', '.join(missing)}.")
    if not scopes:
        raise ConnectorError(f"Nenhum escopo ({REQUIREMENTS[provider]['scopeKind'].lower()}) visível para esta credencial.")
    return {"identity": identity, "scopes": scopes, "checks": checks, "expiresAt": expires_at}


def restrict(items: list[Any], wanted: list[str] | None, key, provider: str) -> list[Any]:
    if not wanted:
        return items
    selected = [item for item in items if str(key(item)) in set(wanted)]
    if not selected:
        kind = REQUIREMENTS[provider]["scopeKind"].lower()
        raise ConnectorError(f"Nenhum escopo selecionado ({kind}) continua acessível para esta credencial.")
    return selected


def aws_expiry(credential: dict[str, Any]) -> str | None:
    parsed = parse_iso(credential.get("expiration"))
    return parsed.isoformat() if parsed else None


def aws_session(credential: dict[str, Any]):
    import boto3

    access_key = credential.get("accessKeyId") or credential.get("aws_access_key_id")
    secret_key = credential.get("secretAccessKey") or credential.get("aws_secret_access_key")
    session_token = credential.get("sessionToken") or credential.get("aws_session_token")
    region = credential.get("region", "us-east-1")
    base = boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token,
        region_name=region,
    )
    if credential.get("roleArn"):
        kwargs = {"RoleArn": credential["roleArn"], "RoleSessionName": "NexoIGAReadOnly"}
        if credential.get("externalId"):
            kwargs["ExternalId"] = credential["externalId"]
        assumed = base.client("sts").assume_role(**kwargs)["Credentials"]
        return boto3.Session(
            aws_access_key_id=assumed["AccessKeyId"],
            aws_secret_access_key=assumed["SecretAccessKey"],
            aws_session_token=assumed["SessionToken"],
            region_name=region,
        )
    return base


def aws_accounts(session, account_id: str) -> tuple[list[dict[str, Any]], bool]:
    try:
        organizations = session.client("organizations")
        accounts = [{"id": item["Id"], "name": item["Name"], "type": "account"}
                    for page in organizations.get_paginator("list_accounts").paginate()
                    for item in page.get("Accounts", []) if item.get("Status") == "ACTIVE"]
        return accounts or [{"id": account_id, "name": f"AWS Account {account_id}", "type": "account"}], True
    except Exception:
        return [{"id": account_id, "name": f"AWS Account {account_id}", "type": "account"}], False


def probe_aws(credential: dict[str, Any]) -> dict[str, Any]:
    session = aws_session(credential)
    caller = session.client("sts").get_caller_identity()
    iam = session.client("iam")
    granted = {"sts:GetCallerIdentity"}
    if succeeds(lambda: iam.list_users(MaxItems=1)):
        granted.add("iam:ListUsers")
    if succeeds(lambda: iam.list_roles(MaxItems=1)):
        granted.add("iam:ListRoles")
    accounts, organizations_readable = aws_accounts(session, caller["Account"])
    if organizations_readable:
        granted.add("organizations:ListAccounts")
    scopes = [scope_entry("AWS", item["id"], item["name"]) for item in accounts]
    return probe_result("AWS", caller["Arn"], scopes, granted, aws_expiry(credential))


def discover_aws(credential: dict[str, Any], scopes: list[str] | None = None) -> dict[str, list[dict[str, Any]]]:
    session = aws_session(credential)
    sts = session.client("sts")
    caller = sts.get_caller_identity()
    account_id = caller["Account"]
    iam = session.client("iam")
    identities: list[dict[str, Any]] = []
    accesses: list[dict[str, Any]] = []
    usage_reads = {"ok": 0, "denied": 0}

    for page in iam.get_paginator("list_users").paginate():
        for user in page.get("Users", []):
            username = user["UserName"]
            arn = user["Arn"]
            tags = {tag["Key"].lower(): tag["Value"] for tag in iam.list_user_tags(UserName=username).get("Tags", [])}
            mfa = bool(iam.list_mfa_devices(UserName=username, MaxItems=1).get("MFADevices"))
            active_keys = [key for key in iam.list_access_keys(UserName=username).get("AccessKeyMetadata", [])
                           if key.get("Status") == "Active" and key.get("CreateDate")]
            key_dates = [key["CreateDate"] for key in active_keys]
            activity = [user.get("PasswordLastUsed")]
            for key in active_keys:
                try:
                    activity.append(iam.get_access_key_last_used(AccessKeyId=key["AccessKeyId"])["AccessKeyLastUsed"].get("LastUsedDate"))
                    usage_reads["ok"] += 1
                except Exception:
                    usage_reads["denied"] += 1
            last_activity = max((item for item in activity if isinstance(item, datetime)), default=None)
            identities.append({
                "id": arn, "name": username, "type": "user", "enabled": True,
                "mfaEnabled": mfa, "owner": tags.get("owner"), "lifecycleStatus": tags.get("lifecycle", "active"),
                "lifecycleChangedAt": tags.get("lifecycle-changed-at"),
                "lastSeenAt": iso(last_activity),
                "accessKeyCreatedAt": iso(min(key_dates)) if key_dates else None,
            })
            for policy in iam.list_attached_user_policies(UserName=username).get("AttachedPolicies", []):
                accesses.append({
                    "identityId": arn, "resourceId": f"aws:account:{account_id}", "resourceName": f"AWS {account_id}",
                    "role": policy["PolicyName"], "permissions": [policy["PolicyArn"]],
                    "privileged": "admin" in policy["PolicyName"].lower(), "grantedAt": iso(user.get("CreateDate")),
                    "lastUsedAt": iso(last_activity),
                })
            for policy_name in iam.list_user_policies(UserName=username).get("PolicyNames", []):
                accesses.append({
                    "identityId": arn, "resourceId": f"aws:account:{account_id}", "resourceName": f"AWS {account_id}",
                    "role": policy_name, "permissions": [f"inline:{policy_name}"],
                    "privileged": "admin" in policy_name.lower(), "grantedAt": iso(user.get("CreateDate")),
                    "lastUsedAt": iso(last_activity),
                })

    for page in iam.get_paginator("list_roles").paginate():
        for role in page.get("Roles", []):
            role_name = role["RoleName"]
            arn = role["Arn"]
            tags = {tag["Key"].lower(): tag["Value"] for tag in role.get("Tags", [])}
            try:
                role_used = iam.get_role(RoleName=role_name)["Role"].get("RoleLastUsed", {}).get("LastUsedDate")
                usage_reads["ok"] += 1
            except Exception:
                role_used = None
                usage_reads["denied"] += 1
            role_used = role_used if isinstance(role_used, datetime) else None
            identities.append({
                "id": arn, "name": role_name, "type": "service", "enabled": True, "mfaEnabled": None,
                "owner": tags.get("owner"), "lifecycleStatus": tags.get("lifecycle", "active"),
                "lastSeenAt": iso(role_used),
            })
            for policy in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
                accesses.append({
                    "identityId": arn, "resourceId": f"aws:account:{account_id}", "resourceName": f"AWS {account_id}",
                    "role": policy["PolicyName"], "permissions": [policy["PolicyArn"]],
                    "privileged": "admin" in policy["PolicyName"].lower(), "grantedAt": iso(role.get("CreateDate")),
                    "lastUsedAt": iso(role_used),
                })

    projects, _ = aws_accounts(session, account_id)
    projects = restrict(projects, scopes, lambda item: item["id"], "AWS")
    usage_status = ("collected" if not usage_reads["denied"] else "partial" if usage_reads["ok"] else "permission_denied")
    return {"identities": identities, "accesses": accesses, "events": [], "projects": projects,
            "principal": caller.get("Arn"), "expiresAt": aws_expiry(credential), "usageStatus": usage_status}


def azure_parts(credential: dict[str, Any]) -> tuple[str, str, str]:
    tenant = credential.get("tenantId") or credential.get("tenant_id")
    client = credential.get("clientId") or credential.get("client_id")
    secret = credential.get("clientSecret") or credential.get("client_secret")
    return tenant, client, secret


def azure_secret_expiry(token: Any, client: str, secret: str) -> tuple[str | None, bool]:
    """Expiry of the client secret in use (matched by Graph's 3-char hint); needs Application.Read.All."""
    import requests

    try:
        access = token.get_token("https://graph.microsoft.com/.default").token
        response = requests.get(
            f"https://graph.microsoft.com/v1.0/applications(appId='{client}')",
            params={"$select": "passwordCredentials"}, headers={"Authorization": f"Bearer {access}"}, timeout=15,
        )
    except Exception:
        return None, False
    if not response.ok:
        return None, False
    for item in response.json().get("passwordCredentials", []):
        if item.get("hint") and str(secret).startswith(item["hint"]):
            parsed = parse_iso(item.get("endDateTime"))
            return (parsed.isoformat() if parsed else None), True
    return None, True


def probe_azure(credential: dict[str, Any]) -> dict[str, Any]:
    from azure.identity import ClientSecretCredential
    from azure.mgmt.authorization import AuthorizationManagementClient
    from azure.mgmt.resource import SubscriptionClient

    tenant, client, secret = azure_parts(credential)
    token = ClientSecretCredential(tenant_id=tenant, client_id=client, client_secret=secret)
    subscriptions = list(SubscriptionClient(token).subscriptions.list())
    granted: set[str] = set()
    if subscriptions:
        granted.add("Microsoft.Resources/subscriptions/read")
        first = f"/subscriptions/{subscriptions[0].subscription_id}"
        auth = AuthorizationManagementClient(token, subscriptions[0].subscription_id)
        if succeeds(lambda: next(iter(auth.role_definitions.list(scope=first)), None)):
            granted.add("Microsoft.Authorization/roleDefinitions/read")
        if succeeds(lambda: next(iter(auth.role_assignments.list_for_scope(scope=first)), None)):
            granted.add("Microsoft.Authorization/roleAssignments/read")
    expires_at, graph_readable = azure_secret_expiry(token, client, secret)
    if graph_readable:
        granted.add("Application.Read.All")
    scopes = [scope_entry("Azure", item.subscription_id, item.display_name) for item in subscriptions]
    return probe_result("Azure", f"tenant {tenant}", scopes, granted, expires_at)


def discover_azure(credential: dict[str, Any], scopes: list[str] | None = None) -> dict[str, list[dict[str, Any]]]:
    from azure.identity import ClientSecretCredential
    from azure.mgmt.authorization import AuthorizationManagementClient
    from azure.mgmt.resource import SubscriptionClient

    tenant, client, secret = azure_parts(credential)
    token = ClientSecretCredential(tenant_id=tenant, client_id=client, client_secret=secret)
    subscriptions = restrict(list(SubscriptionClient(token).subscriptions.list()), scopes,
                             lambda item: item.subscription_id, "Azure")
    identities_by_id: dict[str, dict[str, Any]] = {}
    accesses: list[dict[str, Any]] = []
    projects: list[dict[str, Any]] = []
    for subscription in subscriptions:
        subscription_id = subscription.subscription_id
        projects.append({"id": subscription_id, "name": subscription.display_name, "type": "subscription"})
        auth = AuthorizationManagementClient(token, subscription_id)
        definitions: dict[str, str] = {}
        for definition in auth.role_definitions.list(scope=f"/subscriptions/{subscription_id}"):
            definitions[definition.id.lower()] = definition.role_name
        for assignment in auth.role_assignments.list_for_scope(scope=f"/subscriptions/{subscription_id}"):
            principal_id = str(assignment.principal_id)
            principal_type = str(assignment.principal_type or "Unknown")
            identities_by_id.setdefault(principal_id, {
                "id": principal_id, "name": principal_id, "type": "service" if "service" in principal_type.lower() else "user",
                "enabled": True, "mfaEnabled": None, "owner": None, "lifecycleStatus": "active",
            })
            role_name = definitions.get(str(assignment.role_definition_id).lower(), str(assignment.role_definition_id).split("/")[-1])
            accesses.append({
                "identityId": principal_id, "resourceId": assignment.scope, "resourceName": subscription.display_name,
                "role": role_name, "permissions": [role_name],
                "privileged": role_name.lower() in {"owner", "user access administrator", "contributor"},
            })
    expires_at, _ = azure_secret_expiry(token, client, secret)
    return {"identities": list(identities_by_id.values()), "accesses": accesses, "events": [], "projects": projects,
            "principal": f"tenant {tenant}", "expiresAt": expires_at}


def gcp_session(credential: dict[str, Any]):
    from google.auth.transport.requests import AuthorizedSession
    from google.oauth2 import service_account

    connector_options = {"organizationId", "projectQuery"}
    info = {key: value for key, value in credential.items() if key not in connector_options}
    info.setdefault("token_uri", GCP_TOKEN_URI)
    oauth_scopes = ["https://www.googleapis.com/auth/cloud-platform.read-only"]
    credentials = service_account.Credentials.from_service_account_info(info, scopes=oauth_scopes)
    return credentials, AuthorizedSession(credentials)


def gcp_key_expiry(session: Any, credential: dict[str, Any]) -> str | None:
    """validBeforeTime of the key in use; user-managed keys without expiry report year 9999."""
    key_id, email = credential.get("private_key_id"), credential.get("client_email")
    if not key_id or not email:
        return None
    try:
        response = session.get(f"https://iam.googleapis.com/v1/projects/-/serviceAccounts/{email}/keys/{key_id}", timeout=15)
        parsed = parse_iso(response.json().get("validBeforeTime")) if response.ok else None
    except Exception:
        return None
    return parsed.isoformat() if parsed and parsed.year < 9999 else None


def gcp_list_projects(session: Any, credential: dict[str, Any]) -> tuple[list[dict[str, Any]], int | None]:
    query = credential.get("projectQuery", "state:ACTIVE")
    if credential.get("organizationId") and "parent:" not in query:
        query = f"parent:organizations/{credential['organizationId']} {query}"
    projects_raw: list[dict[str, Any]] = []
    page_token: str | None = None
    search_status: int | None = None
    while True:
        params = {"query": query, "pageSize": 1000}
        if page_token:
            params["pageToken"] = page_token
        response = session.get(
            "https://cloudresourcemanager.googleapis.com/v3/projects:search",
            params=params,
            timeout=30,
        )
        search_status = response.status_code
        if not response.ok:
            break
        payload = response.json()
        projects_raw.extend(payload.get("projects", []))
        page_token = payload.get("nextPageToken")
        if not page_token:
            break

    configured_project = credential.get("project_id")
    if not projects_raw and configured_project:
        project_response = session.get(
            f"https://cloudresourcemanager.googleapis.com/v3/projects/{configured_project}", timeout=30
        )
        if project_response.ok:
            project = project_response.json()
            projects_raw = [{
                "projectId": project.get("projectId", configured_project),
                "displayName": project.get("displayName", configured_project),
            }]
        else:
            projects_raw = [{"projectId": configured_project, "displayName": configured_project}]
    return projects_raw, search_status


def probe_gcp(credential: dict[str, Any]) -> dict[str, Any]:
    _, session = gcp_session(credential)
    projects_raw, search_status = gcp_list_projects(session, credential)
    if not projects_raw:
        raise ConnectorError(
            f"GCP Resource Manager não retornou projetos acessíveis (HTTP {search_status}). "
            "Conceda resourcemanager.projects.get/list à service account."
        )
    configured = credential.get("project_id")
    target = configured if any(item["projectId"] == configured for item in projects_raw) else projects_raw[0]["projectId"]
    response = session.post(
        f"https://cloudresourcemanager.googleapis.com/v1/projects/{target}:testIamPermissions",
        json={"permissions": [item["permission"] for item in REQUIREMENTS["GCP"]["checks"]]}, timeout=20,
    )
    granted = set(response.json().get("permissions", [])) if response.ok else set()
    scopes = [scope_entry("GCP", item["projectId"], item.get("displayName")) for item in projects_raw]
    return probe_result("GCP", str(credential.get("client_email", "")), scopes, granted, gcp_key_expiry(session, credential))


USAGE_HINT = {
    "GCP": "Conceda roles/recommender.iamViewer e roles/policyanalyzer.activityAnalysisViewer à service account "
           "e habilite as APIs Recommender e Policy Analyzer no projeto da credencial.",
    "AWS": "Conceda iam:GetAccessKeyLastUsed e iam:GetRole para ler o último uso de chaves e roles.",
    "Azure": "O conector Azure ainda não coleta telemetria de uso.",
}


def gcp_paginated(session: Any, url: str, key: str) -> tuple[list[dict[str, Any]], int]:
    items: list[dict[str, Any]] = []
    token = None
    while True:
        response = session.get(url, params={"pageSize": 1000, **({"pageToken": token} if token else {})}, timeout=30)
        if not response.ok:
            return items, response.status_code
        payload = response.json()
        items.extend(payload.get(key, []))
        token = payload.get("nextPageToken")
        if not token:
            return items, response.status_code


def gcp_usage(credentials: Any, project_ids: list[str]) -> dict[str, Any]:
    """Real permission usage: IAM Recommender policy insights (exercised permissions per binding, 90-day
    observation) and Policy Analyzer service-account last authentication. Both are optional."""
    from google.auth.transport.requests import AuthorizedSession

    def read(project_id: str) -> tuple[str, list[dict[str, Any]], int, list[dict[str, Any]], int]:
        project_session = AuthorizedSession(credentials)
        try:
            insights, insight_status = gcp_paginated(
                project_session,
                f"https://recommender.googleapis.com/v1/projects/{project_id}/locations/global/insightTypes/google.iam.policy.Insight/insights",
                "insights")
        except Exception:
            insights, insight_status = [], 599
        try:
            activities, activity_status = gcp_paginated(
                project_session,
                f"https://policyanalyzer.googleapis.com/v1/projects/{project_id}/locations/global/activityTypes/serviceAccountLastAuthentication/activities:query",
                "activities")
        except Exception:
            activities, activity_status = [], 599
        return project_id, insights, insight_status, activities, activity_status

    bindings: dict[tuple[str, str, str], dict[str, Any]] = {}
    last_auth: dict[str, str] = {}
    insight_ok = activity_ok = 0
    failures: set[int] = set()
    with ThreadPoolExecutor(max_workers=min(12, max(1, len(project_ids)))) as executor:
        results = []
        for future in as_completed([executor.submit(read, project_id) for project_id in project_ids]):
            try:
                results.append(future.result())
            except Exception:
                failures.add(599)
    for project_id, insights, insight_status, activities, activity_status in results:
        if insight_status == 200:
            insight_ok += 1
        else:
            failures.add(insight_status)
        if activity_status == 200:
            activity_ok += 1
        else:
            failures.add(activity_status)
        for insight in insights:
            content = insight.get("content") or {}
            member, role = content.get("member"), content.get("role")
            if not member or not role:
                continue
            exercised = len(content.get("exercisedPermissions") or [])
            total = int(content.get("currentTotalPermissionsCount") or 0) or exercised + len(content.get("inferredPermissions") or [])
            bindings[(project_id, member, role)] = {"used": exercised, "total": total}
        for item in activities:
            activity = item.get("activity") or {}
            name = (activity.get("serviceAccount") or {}).get("fullResourceName") or item.get("fullResourceName") or ""
            email = name.rsplit("/serviceAccounts/", 1)[-1] if "/serviceAccounts/" in name else ""
            moment = activity.get("lastAuthenticatedTime")
            if "@" in email and moment and moment > last_auth.get(email, ""):
                last_auth[email] = moment
    status = ("collected" if insight_ok == len(project_ids) and activity_ok == len(project_ids)
              else "partial" if insight_ok or activity_ok
              else "permission_denied" if failures.intersection({401, 403}) else "unavailable")
    return {"bindings": bindings, "lastAuth": last_auth, "status": status}


def apply_gcp_usage(usage: dict[str, Any], identities: list[dict[str, Any]], accesses: list[dict[str, Any]],
                    events: list[dict[str, Any]]) -> None:
    seen: dict[str, str] = {}
    for event in events:
        principal = event.get("identityId") or ""
        if principal and (event.get("timestamp") or "") > seen.get(principal, ""):
            seen[principal] = event["timestamp"]
    for member, moment in usage["lastAuth"].items():
        key = f"serviceAccount:{member}"
        if moment > seen.get(key, ""):
            seen[key] = moment
    for identity in identities:
        email = identity.get("email") or str(identity["id"]).partition(":")[2]
        moment = max((seen.get(key) or "" for key in (identity["id"], f"user:{email}", email)), default="")
        if moment and moment > (identity.get("lastSeenAt") or ""):
            identity["lastSeenAt"] = moment
    for grant in accesses:
        binding = usage["bindings"].get((grant["resourceId"], grant["identityId"], grant["role"]))
        if binding:
            grant["usedPermissions"], grant["totalPermissions"] = binding["used"], binding["total"]
            if binding["used"] == 0:
                grant["unused"] = True
        moment = usage["lastAuth"].get(str(grant["identityId"]).partition(":")[2]) if str(grant["identityId"]).startswith("serviceAccount:") else None
        if moment:
            grant["lastUsedAt"] = moment


def discover_gcp(credential: dict[str, Any], scopes: list[str] | None = None) -> dict[str, list[dict[str, Any]]]:
    from google.auth.transport.requests import AuthorizedSession

    credentials, session = gcp_session(credential)
    projects_raw, search_status = gcp_list_projects(session, credential)
    if not projects_raw:
        raise ConnectorError(
            f"GCP Resource Manager não retornou projetos acessíveis (HTTP {search_status}). "
            "Conceda resourcemanager.projects.get/list à service account."
        )
    projects_raw = restrict(projects_raw, scopes, lambda item: item["projectId"], "GCP")
    identities_by_id: dict[str, dict[str, Any]] = {}
    accesses: list[dict[str, Any]] = []
    projects: list[dict[str, Any]] = []
    readable_policies = 0
    policy_statuses: set[int] = set()
    for project in projects_raw:
        project_id = project["projectId"]
        projects.append({"id": project_id, "name": project.get("displayName", project_id), "type": "project"})

    def read_policy(project: dict[str, Any]) -> tuple[dict[str, Any], Any, Any]:
        project_session = AuthorizedSession(credentials)
        policy_response = project_session.post(
            f"https://cloudresourcemanager.googleapis.com/v1/projects/{project['projectId']}:getIamPolicy",
            json={"options": {"requestedPolicyVersion": 3}}, timeout=20,
        )
        repository_response = None
        if policy_response.ok and any(
            str(binding.get("role", "")).startswith("roles/source.")
            for binding in policy_response.json().get("bindings", [])
        ):
            repository_response = project_session.get(
                f"https://sourcerepo.googleapis.com/v1/projects/{project['projectId']}/repos", timeout=15,
            )
        return project, policy_response, repository_response

    worker_count = min(12, max(1, len(projects_raw)))
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = [executor.submit(read_policy, project) for project in projects_raw]
        policy_results = [future.result() for future in as_completed(futures)]

    for project, policy_response, repository_response in policy_results:
        project_id = project["projectId"]
        repositories = repository_response.json().get("repos", []) if repository_response is not None and repository_response.ok else []
        for repository in repositories:
            repository_name = repository.get("name")
            if repository_name:
                projects.append({"id": repository_name, "name": repository_name.rsplit("/", 1)[-1],
                                 "type": "repository", "projectId": project_id})
        if not policy_response.ok:
            policy_statuses.add(policy_response.status_code)
            continue
        readable_policies += 1
        for binding in policy_response.json().get("bindings", []):
            role = binding["role"]
            for member in binding.get("members", []):
                member_type, _, member_name = member.partition(":")
                identity_type = "public" if member in {"allUsers", "allAuthenticatedUsers"} else "service" if member_type == "serviceAccount" else "group" if member_type == "group" else "user"
                identities_by_id.setdefault(member, {
                    "id": member, "name": member_name or member, "email": member_name if "@" in member_name else None,
                    "type": identity_type, "enabled": True, "mfaEnabled": None, "owner": None, "lifecycleStatus": "active",
                })
                accesses.append({
                    "identityId": member, "resourceId": project_id, "resourceName": project.get("displayName", project_id),
                    "role": role, "permissions": [role],
                    "privileged": role in {"roles/owner", "roles/editor", "roles/iam.securityAdmin", "roles/resourcemanager.projectIamAdmin"},
                })
                if role.startswith("roles/source."):
                    for repository in repositories:
                        repository_name = repository.get("name")
                        if repository_name:
                            accesses.append({
                                "identityId": member, "resourceId": repository_name,
                                "resourceName": repository_name.rsplit("/", 1)[-1], "role": role,
                                "permissions": [role], "privileged": "admin" in role or "writer" in role,
                            })
    if projects and readable_policies == 0:
        statuses = ", ".join(str(code) for code in sorted(policy_statuses)) or "sem resposta"
        raise ConnectorError(
            f"GCP IAM recusou a leitura das políticas dos projetos (HTTP {statuses}). "
            "Conceda resourcemanager.projects.getIamPolicy à service account."
        )
    events: list[dict[str, Any]] = []
    telemetry_status = "collected"
    project_ids = [item["projectId"] for item in projects_raw]
    since = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat().replace("+00:00", "Z")
    sensitive_methods = ("SetIamPolicy", "CreateServiceAccountKey", "GenerateAccessToken", "SignJwt", "SignBlob")
    telemetry_http_statuses: set[int] = set()
    telemetry_successes = 0
    def read_audit_logs(project_id: str) -> tuple[str, Any]:
        logging_session = AuthorizedSession(credentials)
        response = logging_session.post(
            "https://logging.googleapis.com/v2/entries:list",
            json={"resourceNames": [f"projects/{project_id}"],
                  "filter": f'(log_id("cloudaudit.googleapis.com/activity") OR log_id("cloudaudit.googleapis.com/policy")) AND timestamp>="{since}"',
                  "orderBy": "timestamp desc", "pageSize": 250}, timeout=30,
        )
        return project_id, response

    with ThreadPoolExecutor(max_workers=min(12, max(1, len(project_ids)))) as executor:
        log_results = []
        futures = [executor.submit(read_audit_logs, project_id) for project_id in project_ids]
        for future in as_completed(futures):
            try:
                log_results.append(future.result())
            except Exception:
                telemetry_http_statuses.add(599)
    for project_id, response in log_results:
        if not response.ok:
            telemetry_http_statuses.add(response.status_code)
            continue
        telemetry_successes += 1
        for entry in response.json().get("entries", []):
            payload = entry.get("protoPayload") or {}
            authentication = payload.get("authenticationInfo") or {}
            principal = authentication.get("principalEmail") or authentication.get("principalSubject")
            if not principal:
                continue
            method = str(payload.get("methodName", ""))
            status_code = (payload.get("status") or {}).get("code", 0)
            denied = bool(status_code) or any(item.get("granted") is False for item in payload.get("authorizationInfo", []))
            sensitive = any(method.endswith(name) for name in sensitive_methods)
            is_platform_system = principal.startswith("system:")
            anomalous = sensitive or (denied and not is_platform_system)
            if denied:
                description = f"Tentativa negada registrada no Cloud Audit Logs: {method or 'operação não identificada'}."
                risk_score = 0.9
            elif sensitive:
                description = f"Operação sensível registrada no Cloud Audit Logs: {method}."
                risk_score = 0.85
            else:
                description = f"Atividade administrativa avaliada: {method or 'operação não identificada'}."
                risk_score = 0
            labels = (entry.get("resource") or {}).get("labels") or {}
            events.append({"identityId": principal, "resourceId": labels.get("project_id") or project_id,
                           "timestamp": entry.get("timestamp"), "method": method, "callerIp": (payload.get("requestMetadata") or {}).get("callerIp"),
                           "denied": denied, "anomalous": anomalous, "riskScore": risk_score if anomalous else 0,
                           "description": description})
    if telemetry_http_statuses and telemetry_successes == 0:
        telemetry_status = "permission_denied" if telemetry_http_statuses.intersection({401, 403}) else "unavailable"
    elif telemetry_http_statuses:
        telemetry_status = "partial"
    try:
        usage = gcp_usage(credentials, project_ids)
    except Exception:
        usage = {"bindings": {}, "lastAuth": {}, "status": "unavailable"}
    identities = list(identities_by_id.values())
    apply_gcp_usage(usage, identities, accesses, events)
    return {"identities": identities, "accesses": accesses, "events": events, "projects": projects,
            "usageStatus": usage["status"],
            "telemetryStatus": telemetry_status, "telemetryHttpStatuses": sorted(telemetry_http_statuses),
            "principal": credential.get("client_email"), "expiresAt": gcp_key_expiry(session, credential)}
