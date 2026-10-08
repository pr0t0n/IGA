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


if __name__ == "__main__":
    unittest.main()
