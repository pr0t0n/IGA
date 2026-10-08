from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from typing import Any


class ConnectorError(Exception):
    """Safe error raised when a cloud discovery cannot be completed."""


def iso(value: Any) -> str | None:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()
    return str(value) if value else None


def discover(provider: str, credential: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    try:
        if provider == "AWS":
            return discover_aws(credential)
        if provider == "Azure":
            return discover_azure(credential)
        if provider == "GCP":
            return discover_gcp(credential)
        raise ConnectorError(f"Provedor não suportado: {provider}")
    except ConnectorError:
        raise
    except Exception as exc:
        name = type(exc).__name__
        raise ConnectorError(f"Falha de autenticação ou autorização no conector {provider} ({name}).") from exc


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


def discover_aws(credential: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    session = aws_session(credential)
    sts = session.client("sts")
    caller = sts.get_caller_identity()
    account_id = caller["Account"]
    iam = session.client("iam")
    identities: list[dict[str, Any]] = []
    accesses: list[dict[str, Any]] = []

    for page in iam.get_paginator("list_users").paginate():
        for user in page.get("Users", []):
            username = user["UserName"]
            arn = user["Arn"]
            tags = {tag["Key"].lower(): tag["Value"] for tag in iam.list_user_tags(UserName=username).get("Tags", [])}
            mfa = bool(iam.list_mfa_devices(UserName=username, MaxItems=1).get("MFADevices"))
            identities.append({
                "id": arn, "name": username, "type": "user", "enabled": True,
                "mfaEnabled": mfa, "owner": tags.get("owner"), "lifecycleStatus": tags.get("lifecycle", "active"),
                "lastSeenAt": iso(user.get("PasswordLastUsed")),
            })
            for policy in iam.list_attached_user_policies(UserName=username).get("AttachedPolicies", []):
                accesses.append({
                    "identityId": arn, "resourceId": f"aws:account:{account_id}", "resourceName": f"AWS {account_id}",
                    "role": policy["PolicyName"], "permissions": [policy["PolicyArn"]],
                    "privileged": "admin" in policy["PolicyName"].lower(), "grantedAt": iso(user.get("CreateDate")),
                })
            for policy_name in iam.list_user_policies(UserName=username).get("PolicyNames", []):
                accesses.append({
                    "identityId": arn, "resourceId": f"aws:account:{account_id}", "resourceName": f"AWS {account_id}",
                    "role": policy_name, "permissions": [f"inline:{policy_name}"],
                    "privileged": "admin" in policy_name.lower(), "grantedAt": iso(user.get("CreateDate")),
                })

    for page in iam.get_paginator("list_roles").paginate():
        for role in page.get("Roles", []):
            role_name = role["RoleName"]
            arn = role["Arn"]
            tags = {tag["Key"].lower(): tag["Value"] for tag in role.get("Tags", [])}
            identities.append({
                "id": arn, "name": role_name, "type": "service", "enabled": True, "mfaEnabled": None,
                "owner": tags.get("owner"), "lifecycleStatus": tags.get("lifecycle", "active"),
            })
            for policy in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
                accesses.append({
                    "identityId": arn, "resourceId": f"aws:account:{account_id}", "resourceName": f"AWS {account_id}",
                    "role": policy["PolicyName"], "permissions": [policy["PolicyArn"]],
                    "privileged": "admin" in policy["PolicyName"].lower(), "grantedAt": iso(role.get("CreateDate")),
                })

    projects = [{"id": account_id, "name": f"AWS Account {account_id}", "type": "account"}]
    try:
        organizations = session.client("organizations")
        projects = [{"id": item["Id"], "name": item["Name"], "type": "account"}
                    for page in organizations.get_paginator("list_accounts").paginate()
                    for item in page.get("Accounts", []) if item.get("Status") == "ACTIVE"] or projects
    except Exception:
        pass
    return {"identities": identities, "accesses": accesses, "events": [], "projects": projects}


def discover_azure(credential: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    from azure.identity import ClientSecretCredential
    from azure.mgmt.authorization import AuthorizationManagementClient
    from azure.mgmt.resource import SubscriptionClient

    tenant = credential.get("tenantId") or credential.get("tenant_id")
    client = credential.get("clientId") or credential.get("client_id")
    secret = credential.get("clientSecret") or credential.get("client_secret")
    token = ClientSecretCredential(tenant_id=tenant, client_id=client, client_secret=secret)
    subscriptions = list(SubscriptionClient(token).subscriptions.list())
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
    return {"identities": list(identities_by_id.values()), "accesses": accesses, "events": [], "projects": projects}


def discover_gcp(credential: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    from google.auth.transport.requests import AuthorizedSession
    from google.oauth2 import service_account

    connector_options = {"organizationId", "projectQuery"}
    info = {key: value for key, value in credential.items() if key not in connector_options}
    scopes = ["https://www.googleapis.com/auth/cloud-platform.read-only"]
    credentials = service_account.Credentials.from_service_account_info(info, scopes=scopes)
    session = AuthorizedSession(credentials)
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
    if not projects_raw:
        raise ConnectorError(
            f"GCP Resource Manager não retornou projetos acessíveis (HTTP {search_status}). "
            "Conceda resourcemanager.projects.get/list à service account."
        )
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
                           "anomalous": anomalous, "riskScore": risk_score if anomalous else 0, "description": description})
    if telemetry_http_statuses and telemetry_successes == 0:
        telemetry_status = "permission_denied" if telemetry_http_statuses.intersection({401, 403}) else "unavailable"
    elif telemetry_http_statuses:
        telemetry_status = "partial"
    return {"identities": list(identities_by_id.values()), "accesses": accesses, "events": events, "projects": projects,
            "telemetryStatus": telemetry_status, "telemetryHttpStatuses": sorted(telemetry_http_statuses)}
