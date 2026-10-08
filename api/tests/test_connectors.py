import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import connectors


class FakePaginator:
    def __init__(self, pages):
        self.pages = pages

    def paginate(self, **_kwargs):
        return self.pages


class FakeResponse:
    def __init__(self, payload, ok=True, status_code=200):
        self.payload = payload
        self.ok = ok
        self.status_code = status_code

    def json(self):
        return self.payload


class ConnectorNormalizationTest(unittest.TestCase):
    @patch("connectors.aws_session")
    def test_aws_inventory_normalization(self, session_factory):
        session = MagicMock()
        session_factory.return_value = session
        sts = MagicMock()
        sts.get_caller_identity.return_value = {"Account": "123456789012"}
        iam = MagicMock()
        iam.get_paginator.side_effect = lambda name: {
            "list_users": FakePaginator([{"Users": [{"UserName": "alice", "Arn": "arn:aws:iam::123456789012:user/alice"}]}]),
            "list_roles": FakePaginator([{"Roles": [{"RoleName": "NexoAdmin", "Arn": "arn:aws:iam::123456789012:role/NexoAdmin", "Tags": [{"Key": "owner", "Value": "Security"}]}]}]),
        }[name]
        iam.list_user_tags.return_value = {"Tags": [{"Key": "owner", "Value": "Platform"}]}
        iam.list_mfa_devices.return_value = {"MFADevices": [{"SerialNumber": "mfa"}]}
        iam.list_attached_user_policies.return_value = {"AttachedPolicies": [{"PolicyName": "ReadOnlyAccess", "PolicyArn": "arn:policy/readonly"}]}
        iam.list_user_policies.return_value = {"PolicyNames": []}
        iam.list_attached_role_policies.return_value = {"AttachedPolicies": [{"PolicyName": "AdministratorAccess", "PolicyArn": "arn:policy/admin"}]}
        organizations = MagicMock()
        organizations.get_paginator.return_value = FakePaginator([{"Accounts": [{"Id": "123456789012", "Name": "Production", "Status": "ACTIVE"}]}])
        session.client.side_effect = lambda name: {"sts": sts, "iam": iam, "organizations": organizations}[name]

        result = connectors.discover_aws({"accessKeyId": "test", "secretAccessKey": "test"})
        self.assertEqual(len(result["projects"]), 1)
        self.assertEqual(len(result["identities"]), 2)
        self.assertEqual(len(result["accesses"]), 2)
        self.assertTrue(any(item["privileged"] for item in result["accesses"]))
        self.assertTrue(next(item for item in result["identities"] if item["name"] == "alice")["mfaEnabled"])

    @patch("azure.mgmt.authorization.AuthorizationManagementClient")
    @patch("azure.mgmt.resource.SubscriptionClient")
    @patch("azure.identity.ClientSecretCredential")
    def test_azure_rbac_normalization(self, credential_class, subscription_class, authorization_class):
        credential_class.return_value = object()
        subscription_class.return_value.subscriptions.list.return_value = [
            SimpleNamespace(subscription_id="sub-001", display_name="Corporate")
        ]
        authorization = authorization_class.return_value
        authorization.role_definitions.list.return_value = [
            SimpleNamespace(id="/subscriptions/sub-001/providers/Microsoft.Authorization/roleDefinitions/owner", role_name="Owner")
        ]
        authorization.role_assignments.list_for_scope.return_value = [
            SimpleNamespace(principal_id="principal-001", principal_type="User",
                            role_definition_id="/subscriptions/sub-001/providers/Microsoft.Authorization/roleDefinitions/owner",
                            scope="/subscriptions/sub-001")
        ]

        result = connectors.discover_azure({"tenantId": "tenant", "clientId": "client", "clientSecret": "secret"})
        self.assertEqual(result["projects"][0]["id"], "sub-001")
        self.assertEqual(result["identities"][0]["id"], "principal-001")
        self.assertEqual(result["accesses"][0]["role"], "Owner")
        self.assertTrue(result["accesses"][0]["privileged"])

    @patch("google.auth.transport.requests.AuthorizedSession")
    @patch("google.oauth2.service_account.Credentials.from_service_account_info")
    def test_gcp_iam_normalization(self, credential_factory, session_class):
        credential_factory.return_value = object()
        session = session_class.return_value
        session.get.side_effect = [
            FakeResponse({"projects": [{"projectId": "data-prod", "displayName": "Data Production"}]}),
            FakeResponse({"repos": [{"name": "projects/data-prod/repos/platform-api"}]}),
        ]
        session.post.return_value = FakeResponse(
            {"bindings": [
                {"role": "roles/owner", "members": ["user:alice@example.com"]},
                {"role": "roles/source.admin", "members": ["user:alice@example.com"]},
            ]}
        )
        result = connectors.discover_gcp({
            "type": "service_account", "project_id": "bootstrap", "private_key": "test",
            "client_email": "reader@bootstrap.iam.gserviceaccount.com", "token_uri": "https://oauth2.googleapis.com/token",
        })
        self.assertEqual(result["projects"][0]["id"], "data-prod")
        self.assertEqual(result["identities"][0]["email"], "alice@example.com")
        self.assertEqual(result["accesses"][0]["role"], "roles/owner")
        self.assertTrue(result["accesses"][0]["privileged"])
        self.assertTrue(any(item["type"] == "repository" for item in result["projects"]))
        self.assertTrue(any(item["resourceName"] == "platform-api" for item in result["accesses"]))
        self.assertEqual(session.get.call_args_list[0].kwargs["params"]["query"], "state:ACTIVE")

    @patch("google.auth.transport.requests.AuthorizedSession")
    @patch("google.oauth2.service_account.Credentials.from_service_account_info")
    def test_gcp_discovery_restricted_to_selected_scopes(self, credential_factory, session_class):
        credential_factory.return_value = object()
        session = session_class.return_value
        session.get.return_value = FakeResponse({"projects": [
            {"projectId": "data-prod", "displayName": "Data Production"},
            {"projectId": "data-dev", "displayName": "Data Development"},
        ]})
        session.post.return_value = FakeResponse({"bindings": [{"role": "roles/viewer", "members": ["user:bob@example.com"]}]})
        credential = {"type": "service_account", "project_id": "data-prod", "private_key": "test",
                      "client_email": "reader@data-prod.iam.gserviceaccount.com"}

        result = connectors.discover_gcp(credential, scopes=["data-dev"])
        self.assertEqual([item["id"] for item in result["projects"]], ["data-dev"])
        self.assertEqual({item["resourceId"] for item in result["accesses"]}, {"data-dev"})
        self.assertEqual(credential_factory.call_args.args[0]["token_uri"], connectors.GCP_TOKEN_URI)
        with self.assertRaises(connectors.ConnectorError):
            connectors.discover_gcp(credential, scopes=["missing-project"])

    @patch("google.auth.transport.requests.AuthorizedSession")
    @patch("google.oauth2.service_account.Credentials.from_service_account_info")
    def test_gcp_probe_reports_granted_permissions(self, credential_factory, session_class):
        credential_factory.return_value = object()
        session = session_class.return_value
        session.get.side_effect = [
            FakeResponse({"projects": [{"projectId": "data-prod", "displayName": "Data Production"}]}),
            FakeResponse({"validBeforeTime": "2027-01-31T00:00:00Z"}),
        ]
        session.post.return_value = FakeResponse({"permissions": [
            "resourcemanager.projects.get", "resourcemanager.projects.getIamPolicy", "logging.logEntries.list",
        ]})
        result = connectors.probe("GCP", {
            "type": "service_account", "project_id": "data-prod", "private_key": "test", "private_key_id": "key-1",
            "client_email": "reader@data-prod.iam.gserviceaccount.com",
        })
        self.assertEqual(result["identity"], "reader@data-prod.iam.gserviceaccount.com")
        self.assertEqual(result["scopes"], [{"id": "data-prod", "name": "Data Production", "label": "data-prod"}])
        granted = {item["permission"]: item["granted"] for item in result["checks"]}
        self.assertTrue(granted["logging.logEntries.list"])
        self.assertFalse(granted["source.repos.list"])
        self.assertTrue(result["expiresAt"].startswith("2027-01-31"))

        session.get.side_effect = [FakeResponse({"projects": [{"projectId": "data-prod"}]})]
        session.post.return_value = FakeResponse({"permissions": ["resourcemanager.projects.get"]})
        with self.assertRaisesRegex(connectors.ConnectorError, "getIamPolicy"):
            connectors.probe("GCP", {"type": "service_account", "project_id": "data-prod", "private_key": "test",
                                     "client_email": "reader@data-prod.iam.gserviceaccount.com"})

    @patch("connectors.aws_session")
    def test_aws_probe_checks_required_and_optional_permissions(self, session_factory):
        session = MagicMock()
        session_factory.return_value = session
        sts = MagicMock()
        sts.get_caller_identity.return_value = {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/reader"}
        iam = MagicMock()
        organizations = MagicMock()
        organizations.get_paginator.side_effect = Exception("AccessDenied")
        session.client.side_effect = lambda name: {"sts": sts, "iam": iam, "organizations": organizations}[name]

        result = connectors.probe("AWS", {"accessKeyId": "AKIA", "secretAccessKey": "secret", "expiration": "2030-01-01T00:00:00Z"})
        self.assertEqual(result["identity"], "arn:aws:iam::123456789012:user/reader")
        self.assertEqual(result["scopes"][0]["id"], "123456789012")
        granted = {item["permission"]: item["granted"] for item in result["checks"]}
        self.assertTrue(granted["iam:ListUsers"])
        self.assertFalse(granted["organizations:ListAccounts"])
        self.assertTrue(result["expiresAt"].startswith("2030-01-01"))

        iam.list_users.side_effect = Exception("AccessDenied")
        with self.assertRaisesRegex(connectors.ConnectorError, "iam:ListUsers"):
            connectors.probe("AWS", {"accessKeyId": "AKIA", "secretAccessKey": "secret"})

    def test_credential_normalization_and_description(self):
        normalized = connectors.normalize_credential("AWS", {"Credentials": {
            "AccessKeyId": "AKIAEXAMPLE12345678", "SecretAccessKey": "secret", "Expiration": "2030-01-01T00:00:00Z",
        }, "RoleArn": "arn:aws:iam::123456789012:role/Audit"})
        self.assertEqual(normalized["accessKeyId"], "AKIAEXAMPLE12345678")
        self.assertEqual(normalized["roleArn"], "arn:aws:iam::123456789012:role/Audit")
        self.assertEqual(connectors.describe_credential("AWS", normalized), ("IAM Role (AssumeRole)", "arn:aws:iam::123456789012:role/Audit"))
        self.assertEqual(connectors.describe_credential("AWS", {"accessKeyId": "AKIAEXAMPLE12345678"})[1], "AKIA…5678")
        self.assertEqual(connectors.describe_credential("Azure", {"tenantId": "tenant-1"}), ("App registration", "tenant tenant-1"))
        self.assertEqual(connectors.scope_entry("AWS", "123", "prod")["label"], "123 · prod")
        self.assertEqual(connectors.scope_entry("Azure", "sub-1", "ERP")["label"], "ERP")


    def test_gcp_usage_enriches_grants_and_identities(self):
        usage = {"status": "collected",
                 "bindings": {("data-prod", "user:alice@example.com", "roles/editor"): {"used": 0, "total": 3200},
                              ("data-prod", "serviceAccount:etl@data-prod.iam.gserviceaccount.com", "roles/viewer"): {"used": 12, "total": 900}},
                 "lastAuth": {"etl@data-prod.iam.gserviceaccount.com": "2026-09-30T10:00:00Z"}}
        identities = [{"id": "user:alice@example.com", "name": "alice@example.com", "email": "alice@example.com"},
                      {"id": "serviceAccount:etl@data-prod.iam.gserviceaccount.com", "name": "etl", "email": "etl@data-prod.iam.gserviceaccount.com"}]
        accesses = [{"identityId": "user:alice@example.com", "resourceId": "data-prod", "role": "roles/editor"},
                    {"identityId": "serviceAccount:etl@data-prod.iam.gserviceaccount.com", "resourceId": "data-prod", "role": "roles/viewer"}]
        events = [{"identityId": "alice@example.com", "timestamp": "2026-10-06T08:00:00Z"}]
        connectors.apply_gcp_usage(usage, identities, accesses, events)
        self.assertEqual((accesses[0]["usedPermissions"], accesses[0]["totalPermissions"], accesses[0]["unused"]), (0, 3200, True))
        self.assertEqual(accesses[1]["lastUsedAt"], "2026-09-30T10:00:00Z")
        self.assertNotIn("unused", accesses[1])
        self.assertEqual(identities[0]["lastSeenAt"], "2026-10-06T08:00:00Z")
        self.assertEqual(identities[1]["lastSeenAt"], "2026-09-30T10:00:00Z")

    @patch("google.auth.transport.requests.AuthorizedSession")
    def test_gcp_usage_reads_recommender_and_policy_analyzer(self, session_class):
        session = session_class.return_value
        def get(url, **_kwargs):
            if "recommender" in url:
                return FakeResponse({"insights": [{"content": {"member": "user:bob@example.com", "role": "roles/owner",
                                                               "exercisedPermissions": [{"permission": "a"}], "currentTotalPermissionsCount": "8000"}}]})
            return FakeResponse({"activities": [{"activity": {"lastAuthenticatedTime": "2026-10-01T00:00:00Z",
                                 "serviceAccount": {"fullResourceName": "//iam.googleapis.com/projects/p/serviceAccounts/sa@p.iam.gserviceaccount.com"}}}]})
        session.get.side_effect = get
        usage = connectors.gcp_usage(object(), ["p"])
        self.assertEqual(usage["status"], "collected")
        self.assertEqual(usage["bindings"][("p", "user:bob@example.com", "roles/owner")], {"used": 1, "total": 8000})
        self.assertEqual(usage["lastAuth"]["sa@p.iam.gserviceaccount.com"], "2026-10-01T00:00:00Z")
        session.get.side_effect = lambda url, **_kwargs: FakeResponse({}, ok=False, status_code=403)
        self.assertEqual(connectors.gcp_usage(object(), ["p"])["status"], "permission_denied")


if __name__ == "__main__":
    unittest.main()
