import os
import json
import sqlite3
import unittest
from unittest.mock import Mock, patch

os.environ.setdefault("DATABASE_PATH", "/tmp/nexo-iga-test.db")
os.environ.setdefault("CREDENTIAL_MASTER_KEY", "automated-test-master-key")
os.environ.setdefault("JWT_SECRET", "automated-test-jwt-secret-longer-than-32-bytes")
os.environ.setdefault("ADMIN_EMAIL", "admin@test.local")
os.environ.setdefault("ADMIN_PASSWORD", "automated-admin-password")
os.environ.setdefault("SCHEDULER_ENABLED", "0")
os.environ.setdefault("AI_PREGENERATE", "0")

from fastapi.testclient import TestClient

from connectors import ConnectorError
from main import app


AWS_CREDENTIAL = {
    "accountId": "123456789012",
    "roleArn": "arn:aws:iam::123456789012:role/NexoIGAReadOnly",
}

DISCOVERY_RESULT = {
        "projects": [{"id": "123456789012", "name": "AWS Test", "type": "account"}],
        "identities": [
            {"id": "active-user", "name": "Active User", "type": "user", "enabled": True,
             "mfaEnabled": False, "owner": "Security", "lifecycleStatus": "active"},
            {"id": "former-user", "name": "Former User", "type": "user", "enabled": True,
             "mfaEnabled": False, "orphan": True, "lifecycleStatus": "leaver"},
        ],
        "accesses": [
            {"identityId": "active-user", "resourceId": "aws:account:123456789012", "resourceName": "AWS Test",
             "role": "IAM Admin", "permissions": ["iam:CreateUser", "iam:AttachUserPolicy"], "privileged": True,
             "lastUsedAt": "2024-01-01T00:00:00Z", "lastReviewedAt": "2024-01-01T00:00:00Z"},
            {"identityId": "former-user", "resourceId": "aws:s3:::finance", "resourceName": "Finance",
             "role": "Reader", "permissions": ["s3:GetObject"], "accessCreep": True},
        ],
        "events": [
            {"identityId": "active-user", "resourceId": "aws:account:123456789012", "riskScore": 0.95,
             "anomalous": True, "description": "Administrative access from a new location."}
        ],
}


class PlatformEndToEndTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.path.exists(os.environ["DATABASE_PATH"]):
            os.remove(os.environ["DATABASE_PATH"])
        cls.client_context = TestClient(app)
        cls.client = cls.client_context.__enter__()
        login = cls.client.post("/api/auth/login", json={
            "email": "admin@test.local", "password": "automated-admin-password"
        })
        if login.status_code != 200:
            raise AssertionError(f"Admin login failed: {login.text}")
        cls.client.headers.update({"Authorization": f"Bearer {login.json()['token']}"})

    @classmethod
    def tearDownClass(cls):
        cls.client_context.__exit__(None, None, None)
        if os.path.exists(os.environ["DATABASE_PATH"]):
            os.remove(os.environ["DATABASE_PATH"])

    def test_complete_iga_workflow(self):
        me = self.client.get("/api/auth/me")
        self.assertEqual(me.status_code, 200)
        self.assertEqual(me.json()["role"], "admin")
        empty_dashboard = self.client.get("/api/dashboard").json()
        self.assertEqual(empty_dashboard["riskScore"], 0)
        self.assertEqual(empty_dashboard["identities"], 0)
        self.assertEqual(empty_dashboard["accesses"], 0)
        self.assertEqual(sum(empty_dashboard["severities"].values()), 0)
        empty_compliance = self.client.get("/api/compliance").json()
        self.assertEqual(empty_compliance["score"], 0)
        self.assertTrue(all(control["status"] == "not_assessed" for control in empty_compliance["controls"]))

        analyst = self.client.post("/api/users", json={
            "name": "Risk Analyst", "email": "analyst@test.local",
            "password": "analyst-test-password", "role": "analyst"
        })
        self.assertEqual(analyst.status_code, 201)
        analyst_id = analyst.json()["id"]
        changed = self.client.patch(f"/api/users/{analyst_id}", json={"role": "auditor"})
        self.assertEqual(changed.json()["role"], "auditor")
        auditor_login = self.client.post("/api/auth/login", json={
            "email": "analyst@test.local", "password": "analyst-test-password"
        })
        auditor_headers = {"Authorization": f"Bearer {auditor_login.json()['token']}"}
        self.assertEqual(self.client.get("/api/dashboard", headers=auditor_headers).status_code, 200)
        denied = self.client.post("/api/credentials", headers=auditor_headers, json={
            "name": "Denied", "provider": "AWS", "credential": AWS_CREDENTIAL
        })
        self.assertEqual(denied.status_code, 403)
        self.assertEqual(self.client.delete(f"/api/users/{analyst_id}").status_code, 204)

        invalid = self.client.post("/api/credentials", json={
            "name": "Invalid AWS", "provider": "AWS", "credential": {"accountId": "123"}
        })
        self.assertEqual(invalid.status_code, 422)

        created = self.client.post("/api/credentials", json={
            "name": "AWS Automated Test", "provider": "AWS", "credential": AWS_CREDENTIAL
        })
        self.assertEqual(created.status_code, 201)
        credential_id = created.json()["id"]

        listed = self.client.get("/api/credentials").json()
        self.assertEqual(len(listed), 1)
        self.assertNotIn("credential", listed[0])

        with sqlite3.connect(os.environ["DATABASE_PATH"]) as connection:
            encrypted = connection.execute(
                "SELECT encrypted_payload FROM credentials WHERE id=?", (credential_id,)
            ).fetchone()[0]
        self.assertNotIn(b"iam:CreateUser", encrypted)

        detail = self.client.get(f"/api/credentials/{credential_id}")
        self.assertEqual(detail.status_code, 200)
        self.assertNotIn("credential", detail.json())
        self.assertEqual(detail.json()["principal"], AWS_CREDENTIAL["roleArn"])
        self.assertEqual(detail.json()["kind"], "IAM Role (AssumeRole)")

        updated = self.client.put(f"/api/credentials/{credential_id}", json={
            "name": "AWS Automated Updated", "provider": "AWS", "credential": AWS_CREDENTIAL
        })
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.json()["name"], "AWS Automated Updated")

        with patch("main.discover", return_value=DISCOVERY_RESULT) as live_discovery:
            scan = self.client.post(f"/api/credentials/{credential_id}/scan")
        live_discovery.assert_called_once_with("AWS", AWS_CREDENTIAL, scopes=None)
        self.assertEqual(scan.status_code, 200)
        self.assertEqual(scan.json()["source"], "live")
        self.assertEqual(scan.json()["identities"], 2)
        self.assertEqual(scan.json()["accesses"], 2)
        self.assertGreater(scan.json()["findings"], 7)
        self.assertGreaterEqual(scan.json()["riskScore"], 0)

        identities = self.client.get(f"/api/identities?credential_id={credential_id}").json()
        self.assertEqual(len(identities), 2)
        self.assertIn("accessCount", identities[0])
        identity_detail = self.client.get(f"/api/identities/{identities[0]['id']}")
        self.assertEqual(identity_detail.status_code, 200)
        self.assertEqual(identity_detail.json()["environment"], "AWS Automated Updated")
        self.assertIn("accesses", identity_detail.json())
        self.assertIn("findings", identity_detail.json())
        self.assertEqual(len(self.client.get(f"/api/identities?credential_id={credential_id}&q=active").json()), 1)
        project_inventory = self.client.get("/api/inventory/projects").json()
        self.assertEqual(len(project_inventory), 2)
        project_detail = self.client.get("/api/inventory/project-detail", params={
            "credential_id": project_inventory[0]["credentialId"], "resource_id": project_inventory[0]["resourceId"]
        })
        self.assertEqual(project_detail.status_code, 200)
        self.assertGreater(project_detail.json()["roleCount"], 0)
        self.assertGreater(project_detail.json()["accountCount"], 0)
        self.assertEqual(len(self.client.get("/api/inventory/roles").json()), 2)
        self.assertEqual(len(self.client.get("/api/inventory/accounts").json()), 2)
        self.assertEqual(len(self.client.get(f"/api/accesses?credential_id={credential_id}").json()), 2)
        self.assertEqual(len(self.client.get(f"/api/resources?credential_id={credential_id}").json()), 1)
        privileged = self.client.get(f"/api/privileged-access?credential_id={credential_id}").json()
        self.assertEqual(len(privileged), 1)
        privileged_id = privileged[0]["id"]
        dossier = self.client.get(f"/api/privileged-access/{privileged_id}")
        self.assertEqual(dossier.status_code, 200)
        self.assertEqual(dossier.json()["credential"], "AWS Automated Updated")
        qwen_response = Mock()
        qwen_response.raise_for_status.return_value = None
        qwen_response.json.return_value = {"message": {"content": json.dumps({
            "summary": "Acesso administrativo correlacionado.", "why": "Função ampla.",
            "recommendation": "Texto do modelo.", "treatment": "Texto do modelo.", "priority": "low"
        })}}
        with patch("main.requests.post", return_value=qwen_response):
            analysis = self.client.post(f"/api/privileged-access/{privileged_id}/analysis")
        self.assertEqual(analysis.status_code, 200)
        self.assertEqual(analysis.json()["analysis"]["priority"], dossier.json()["severity"])
        self.assertEqual(analysis.json()["analysis"]["recommendation"], dossier.json()["recommendation"])
        cached_analysis = self.client.post(f"/api/privileged-access/{privileged_id}/analysis")
        self.assertTrue(cached_analysis.json()["cached"])
        persisted_ai = self.client.get(f"/api/ai-analyses?credential_id={credential_id}").json()
        self.assertEqual({item["scopeType"] for item in persisted_ai}, {"platform", "grant"})
        self.assertEqual(len(self.client.get(f"/api/ueba?credential_id={credential_id}").json()), 1)
        ueba_status = self.client.get(f"/api/ueba/status?credential_id={credential_id}").json()
        self.assertEqual(ueba_status["eventsEvaluated"], 1)
        self.assertEqual(ueba_status["anomalies"], 1)

        findings = self.client.get(f"/api/findings?credential_id={credential_id}").json()
        rules = {item["rule"] for item in findings}
        expected_rules = {"ACCESS_CREEP", "PERMISSION_USAGE", "TOXIC_COMBINATION", "JML",
                          "ORPHAN_ACCOUNT", "AUTHENTICATION_POSTURE", "ACCESS_REVIEW", "UEBA_ANOMALY"}
        self.assertTrue(expected_rules.issubset(rules))

        dashboard = self.client.get(f"/api/dashboard?credential_id={credential_id}").json()
        self.assertEqual(dashboard["identities"], 2)
        self.assertEqual(dashboard["accesses"], 2)
        self.assertEqual(dashboard["privilegedAccesses"], 1)
        self.assertGreater(sum(dashboard["severities"].values()), 0)

        compliance = self.client.get(f"/api/compliance?credential_id={credential_id}").json()
        self.assertEqual(len(compliance["controls"]), 5)
        self.assertGreaterEqual(compliance["score"], 0)
        self.assertLessEqual(compliance["score"], 100)

        history = self.client.get(f"/api/risk-history?credential_id={credential_id}").json()
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["riskScore"], scan.json()["riskScore"])

        finding_id = findings[0]["id"]
        resolved = self.client.patch(f"/api/findings/{finding_id}", json={
            "status": "resolved", "justification": "Validated by automated end-to-end test"
        })
        self.assertEqual(resolved.status_code, 200)
        self.assertEqual(resolved.json()["status"], "resolved")
        audit = self.client.get("/api/audit").json()
        self.assertTrue(any(item["title"] == "Postura de risco alterada" for item in audit))

        matrix = [
            ("Azure", {"tenantId": "tenant-test", "clientId": "client-test", "clientSecret": "secret-test"}),
            ("GCP", {"type": "service_account", "project_id": "test-project", "private_key": "test-private-key",
                     "client_email": "reader@test-project.iam.gserviceaccount.com"}),
        ]
        matrix_ids = []
        for provider, provider_credential in matrix:
            response = self.client.post("/api/credentials", json={
                "name": f"{provider} Automated Test", "provider": provider, "credential": provider_credential
            })
            self.assertEqual(response.status_code, 201)
            matrix_id = response.json()["id"]
            matrix_ids.append(matrix_id)
            with patch("main.discover", return_value=DISCOVERY_RESULT) as live_discovery:
                provider_scan = self.client.post(f"/api/credentials/{matrix_id}/scan")
            live_discovery.assert_called_once_with(provider, provider_credential, scopes=None)
            self.assertEqual(provider_scan.status_code, 200)
            self.assertEqual(provider_scan.json()["provider"], provider)
            self.assertEqual(provider_scan.json()["source"], "live")

        multi_cloud_dashboard = self.client.get("/api/dashboard").json()
        self.assertEqual(len(multi_cloud_dashboard["credentials"]), 3)
        self.assertEqual({item["provider"] for item in multi_cloud_dashboard["environments"]}, {"AWS", "Azure", "GCP"})

        for matrix_id in matrix_ids:
            self.assertEqual(self.client.delete(f"/api/credentials/{matrix_id}").status_code, 204)

        deleted = self.client.delete(f"/api/credentials/{credential_id}")
        self.assertEqual(deleted.status_code, 204)
        self.assertEqual(self.client.get(f"/api/credentials/{credential_id}").status_code, 404)
        self.assertEqual(self.client.get(f"/api/identities?credential_id={credential_id}").json(), [])
        self.assertEqual(self.client.get(f"/api/accesses?credential_id={credential_id}").json(), [])
        self.assertEqual(self.client.get(f"/api/resources?credential_id={credential_id}").json(), [])
        self.assertEqual(self.client.get(f"/api/findings?credential_id={credential_id}").json(), [])
        final_audit = self.client.get("/api/audit").json()
        removed_event = next(item for item in final_audit if item["title"] == "Credencial removida")
        self.assertEqual(removed_event["actor"], "admin@test.local")


    def test_credential_validation_scope_selection_and_lifecycle(self):
        requirements = self.client.get("/api/credentials/requirements").json()["providers"]
        self.assertEqual({item["provider"] for item in requirements}, {"AWS", "Azure", "GCP"})
        self.assertTrue(all(item["roles"] and item["checks"] and item["sample"] and item["required"] for item in requirements))

        missing = self.client.post("/api/credentials/validate", json={
            "provider": "GCP", "credential": {"type": "service_account"}
        })
        self.assertEqual(missing.status_code, 422)
        self.assertIn("Campos obrigatórios ausentes para GCP", missing.json()["detail"]["errors"][0])

        with patch("main.probe", side_effect=ConnectorError("Permissão obrigatória ausente: iam:ListUsers.")):
            denied = self.client.post("/api/credentials/validate", json={"provider": "AWS", "credential": AWS_CREDENTIAL})
        self.assertEqual(denied.status_code, 422)
        self.assertIn("iam:ListUsers", denied.json()["detail"])

        scopes = [
            {"id": "123456789012", "name": "prod", "label": "123456789012 · prod"},
            {"id": "210987654321", "name": "dev", "label": "210987654321 · dev"},
        ]
        probe_result = {
            "identity": "arn:aws:iam::123456789012:user/reader", "scopes": scopes, "expiresAt": None,
            "checks": [{"permission": "sts:GetCallerIdentity", "required": True, "granted": True}],
        }
        sts_output = {"Credentials": {
            "AccessKeyId": "AKIATESTKEY12345678", "SecretAccessKey": "secret-test",
            "SessionToken": "token-test", "Expiration": "2030-01-01T00:00:00Z",
        }}
        with patch("main.probe", return_value=probe_result) as live_probe:
            validated = self.client.post("/api/credentials/validate", json={"provider": "AWS", "credential": sts_output})
        self.assertEqual(validated.status_code, 200)
        self.assertEqual(validated.json()["kind"], "Access key (IAM)")
        self.assertEqual(validated.json()["scopes"], scopes)
        self.assertEqual(live_probe.call_args.args[1]["accessKeyId"], "AKIATESTKEY12345678")

        no_scope = self.client.post("/api/credentials", json={
            "name": "Sem escopo", "provider": "AWS", "credential": sts_output, "scopes": []
        })
        self.assertEqual(no_scope.status_code, 422)

        created = self.client.post("/api/credentials", json={
            "name": "AWS Scoped", "provider": "AWS", "credential": sts_output, "scopes": [scopes[0]]
        })
        self.assertEqual(created.status_code, 201)
        body = created.json()
        credential_id = body["id"]
        self.assertNotIn("credential", body)
        self.assertEqual(body["scopes"], [scopes[0]])
        self.assertEqual(body["scopeSelection"], "selected")
        self.assertEqual(body["principal"], "AKIA…5678")
        self.assertTrue(body["expiresAt"].startswith("2030-01-01"))
        self.assertNotIn("credential", self.client.get(f"/api/credentials/{credential_id}").json())

        with patch("main.discover", side_effect=ConnectorError("Falha simulada no provedor.")):
            failed = self.client.post(f"/api/credentials/{credential_id}/scan")
        self.assertEqual(failed.status_code, 502)
        failed_view = self.client.get(f"/api/credentials/{credential_id}").json()
        self.assertEqual(failed_view["status"], "Erro")
        self.assertEqual(failed_view["lastError"], "Falha simulada no provedor.")

        discovery = {**DISCOVERY_RESULT, "principal": "arn:aws:iam::123456789012:user/reader"}
        with patch("main.discover", return_value=discovery) as live_discovery:
            scanned = self.client.post(f"/api/credentials/{credential_id}/scan")
        self.assertEqual(scanned.status_code, 200)
        self.assertEqual(live_discovery.call_args.kwargs["scopes"], ["123456789012"])
        connected = self.client.get(f"/api/credentials/{credential_id}").json()
        self.assertEqual(connected["status"], "Conectado")
        self.assertIsNone(connected["lastError"])
        self.assertEqual(connected["principal"], "arn:aws:iam::123456789012:user/reader")

        renamed = self.client.put(f"/api/credentials/{credential_id}", json={"name": "AWS Renamed", "provider": "AWS"})
        self.assertEqual(renamed.status_code, 200)
        self.assertEqual(renamed.json()["name"], "AWS Renamed")
        self.assertEqual(renamed.json()["lastSyncedAt"], connected["lastSyncedAt"])
        self.assertEqual(renamed.json()["status"], "Conectado")

        switched = self.client.put(f"/api/credentials/{credential_id}", json={"name": "AWS Renamed", "provider": "GCP"})
        self.assertEqual(switched.status_code, 422)

        rescoped = self.client.put(f"/api/credentials/{credential_id}", json={
            "name": "AWS Renamed", "provider": "AWS", "credential": sts_output, "scopes": [scopes[1]]
        })
        self.assertEqual(rescoped.status_code, 200)
        self.assertEqual(rescoped.json()["scopes"], [scopes[1]])
        self.assertEqual(rescoped.json()["status"], "Pendente")
        self.assertIsNone(rescoped.json()["lastSyncedAt"])
        self.assertEqual(self.client.get(f"/api/identities?credential_id={credential_id}").json(), [])

        self.assertEqual(self.client.delete(f"/api/credentials/{credential_id}").status_code, 204)
        removed = next(item for item in self.client.get("/api/audit").json() if item["title"] == "Credencial removida")
        self.assertIn("Achados abertos no momento da remoção", removed["text"])


    def test_governance_workflows(self):
        from datetime import datetime, timedelta, timezone
        import main as platform

        now = datetime.now(timezone.utc)
        discovery = {
            "projects": [{"id": "111122223333", "name": "prod", "type": "account"}],
            "identities": [
                {"id": "alice", "name": "Alice", "type": "user", "mfaEnabled": False, "lastSeenAt": (now - timedelta(days=120)).isoformat()},
                {"id": "builder", "name": "builder", "type": "service", "accessKeyCreatedAt": (now - timedelta(days=200)).isoformat()},
            ],
            "accesses": [
                {"identityId": "alice", "resourceId": "111122223333", "resourceName": "prod", "role": "AdministratorAccess",
                 "permissions": ["*"], "privileged": True, "lastUsedAt": (now - timedelta(days=120)).isoformat()},
                {"identityId": "builder", "resourceId": "111122223333", "resourceName": "prod", "role": "ReadOnlyAccess",
                 "permissions": ["arn:policy/readonly"]},
            ],
            "events": [
                {"identityId": "builder", "resourceId": "111122223333", "timestamp": (now - timedelta(hours=2)).isoformat(),
                 "method": "SetIamPolicy", "anomalous": True, "riskScore": 0.85, "description": "Operação sensível registrada: SetIamPolicy."},
                {"identityId": "builder", "resourceId": "111122223333", "timestamp": (now - timedelta(hours=3)).isoformat(),
                 "method": "storage.objects.get", "anomalous": False, "riskScore": 0, "description": "Atividade avaliada."},
            ],
        }
        created = self.client.post("/api/credentials", json={"name": "Governance AWS", "provider": "AWS", "credential": AWS_CREDENTIAL})
        credential_id = created.json()["id"]
        webhook = Mock()
        webhook.raise_for_status.return_value = None
        settings = self.client.get("/api/settings").json()
        self.assertEqual(settings["schedule"], "manual")
        self.assertEqual(len(settings["parameters"]), 7)
        self.assertEqual(self.client.put("/api/settings", json={**settings, "rules": {"unused_days": 1}}).status_code, 422)
        saved = self.client.put("/api/settings", json={"rules": {key: item["value"] for key, item in
                                                                 ((p["key"], p) for p in settings["parameters"])},
                                                       "schedule": "daily", "notifications": {"critical": True, "ueba": True,
                                                       "credential": True, "weekly": False}, "webhook": "https://hooks.example.com/abc"})
        self.assertEqual(saved.status_code, 200)
        self.assertEqual(saved.json()["schedule"], "daily")
        with patch("main.discover", return_value=discovery), patch("main.requests.post", return_value=webhook) as posted:
            self.assertEqual(self.client.post(f"/api/credentials/{credential_id}/scan").status_code, 200)
        self.assertTrue(any(call.args[0] == "https://hooks.example.com/abc" for call in posted.call_args_list))
        self.assertIsNotNone(self.client.get("/api/settings").json()["nextRunAt"])

        overview = self.client.get(f"/api/dashboard/overview?credential_id={credential_id}&period=30").json()
        self.assertTrue(overview["assessed"])
        self.assertIsNotNone(overview["score"])
        self.assertEqual(overview["kpis"]["identities"], 2)
        self.assertEqual(overview["kpis"]["anomalies24h"], 1)
        self.assertEqual(len(overview["frameworks"]), 4)
        self.assertEqual(len(overview["trend"]), 1)
        self.assertEqual(overview["environments"][0]["name"], "prod")
        self.assertEqual(self.client.get("/api/platform/status").json()["connected"], 1)

        summary = self.client.get(f"/api/identities/summary?credential_id={credential_id}").json()
        self.assertEqual((summary["total"], summary["noMfa"], summary["inactive90"]), (2, 1, 1))
        identities = self.client.get(f"/api/identities?credential_id={credential_id}").json()
        self.assertGreater(identities[0]["riskScore"], 0)
        accesses = self.client.get(f"/api/accesses/summary?credential_id={credential_id}").json()
        self.assertEqual((accesses["total"], accesses["unused"], accesses["wildcard"]), (2, 1, 1))

        findings = self.client.get(f"/api/findings?credential_id={credential_id}&finding_status=current").json()
        rules = {item["rule"] for item in findings}
        self.assertTrue({"PERMISSION_USAGE", "AUTHENTICATION_POSTURE", "UEBA_ANOMALY"}.issubset(rules))
        self.assertTrue(any(item["title"] == "Chave de acesso antiga" for item in findings))
        target = next(item for item in findings if item["rule"] == "PERMISSION_USAGE")
        self.assertEqual(self.client.patch(f"/api/findings/{target['id']}", json={"status": "accepted"}).status_code, 422)
        accepted = self.client.patch(f"/api/findings/{target['id']}", json={"status": "accepted", "justification": "Exceção aprovada"})
        self.assertEqual(accepted.json()["status"], "accepted")
        remediating = next(item for item in findings if item["title"] == "MFA não configurado")
        self.assertEqual(self.client.patch(f"/api/findings/{remediating['id']}", json={"status": "remediating"}).status_code, 200)

        privileged = self.client.get(f"/api/privileged-access?credential_id={credential_id}").json()
        self.assertEqual(privileged[0]["model"], "Permanente")
        jit = self.client.post(f"/api/privileged-access/{privileged[0]['id']}/jit", json={"note": "Converter via PIM"})
        self.assertEqual(jit.json()["model"], "JIT solicitado")

        with patch("main.discover", return_value=discovery), patch("main.requests.post", return_value=webhook):
            self.assertEqual(self.client.post(f"/api/credentials/{credential_id}/scan").status_code, 200)
        carried = {item["rule"]: item["status"] for item in self.client.get(
            f"/api/findings?credential_id={credential_id}&finding_status=current").json() if item["rule"] in {"PERMISSION_USAGE", "AUTHENTICATION_POSTURE"} and item["title"] != "Chave de acesso antiga"}
        self.assertEqual(carried, {"PERMISSION_USAGE": "accepted", "AUTHENTICATION_POSTURE": "remediating"})
        self.assertEqual(self.client.get(f"/api/privileged-access/summary?credential_id={credential_id}").json()["jit"], 1)

        ueba = self.client.get(f"/api/ueba/overview?credential_id={credential_id}").json()
        self.assertEqual(len(ueba["hours"]), 24)
        self.assertEqual(ueba["anomalies"][0]["category"], "Escalada de privilégio")
        self.assertIn("SetIamPolicy", ueba["anomalies"][0]["observed"])
        anomaly = ueba["anomalies"][0]
        self.assertEqual(anomaly["engine"], "regras")
        self.assertIn("builder", anomaly["happened"])
        self.assertTrue(anomaly["actions"])
        llm = Mock()
        llm.raise_for_status.return_value = None
        llm.json.return_value = {"message": {"content": json.dumps({"resumo": "O acesso veio do IP 10.9.9.9 e parece um ataque em andamento."})}}
        with patch("main.requests.post", return_value=llm):
            rejected = self.client.post(f"/api/ueba/{anomaly['id']}/explanation").json()
        self.assertEqual((rejected["engine"], rejected["summary"]), ("regras", ""))
        llm.json.return_value = {"message": {"content": json.dumps({
            "resumo": "A conta builder alterou permissões de acesso no projeto prod sem um processo aprovado; confirme com o responsável qual vínculo mudou."})}}
        with patch("main.requests.post", return_value=llm):
            explained = self.client.post(f"/api/ueba/{anomaly['id']}/explanation").json()
        self.assertIn("guardrails", explained["engine"])
        self.assertTrue(explained["summary"].startswith("A conta builder"))
        self.assertEqual(explained["happened"], anomaly["rules"]["happened"])
        self.assertTrue(self.client.post(f"/api/ueba/{anomaly['id']}/explanation").json()["cached"])
        self.assertEqual(self.client.get(f"/api/ueba/overview?credential_id={credential_id}").json()["anomalies"][0]["summary"], explained["summary"])
        self.assertEqual(self.client.patch(f"/api/findings/{anomaly['id']}", json={"status": "incident"}).status_code, 200)

        trail = self.client.get("/api/audit/trail").json()
        self.assertEqual([item["name"] for item in trail["sources"]], ["Plataforma", "GCP Audit Logs", "AWS CloudTrail", "Azure Activity Log"])
        self.assertTrue(any(item["source"] == "AWS CloudTrail" and item["action"] == "SetIamPolicy" for item in trail["events"]))
        with sqlite3.connect(os.environ["DATABASE_PATH"]) as connection:
            connection.row_factory = sqlite3.Row
            chain = connection.execute("SELECT * FROM audit_events ORDER BY id").fetchall()
        previous = None
        for row in chain:
            record = platform.audit_payload(row["event_type"], row["title"], row["description"], row["actor"], row["created_at"],
                                            row["action"], row["target"], row["result"], json.loads(row["details_json"] or "{}"))
            previous = platform.audit_record_hash(previous, record)
            self.assertEqual(row["record_hash"], previous)

        frameworks = self.client.get(f"/api/compliance/frameworks?credential_id={credential_id}").json()["frameworks"]
        self.assertEqual([item["key"] for item in frameworks], ["iso", "sox", "lgpd", "cis"])
        campaign = self.client.post("/api/reviews", json={"name": "Privilegiados Q4", "scope": "privileged", "credentialId": credential_id,
                                                           "reviewer": "ciso@test.local", "dueDays": 15})
        self.assertEqual(campaign.status_code, 201)
        detail = self.client.get(f"/api/reviews/{campaign.json()['id']}").json()
        self.assertEqual(detail["total"], 1)
        decided = self.client.patch(f"/api/reviews/{detail['id']}/items/{detail['items'][0]['id']}", json={"decision": "keep"}).json()
        self.assertEqual(decided["percent"], 100)
        self.assertIsNotNone(decided["completedAt"])
        self.assertIsNotNone(self.client.get(f"/api/accesses?credential_id={credential_id}").json()[1]["lastReviewedAt"] or
                             self.client.get(f"/api/accesses?credential_id={credential_id}").json()[0]["lastReviewedAt"])

        pending = self.client.post("/api/credentials", json={"name": "Never scanned", "provider": "AWS", "credential": AWS_CREDENTIAL}).json()
        with patch("main.run_scan") as scheduled:
            platform.scheduler_tick()
        self.assertEqual([call.args[0] for call in scheduled.call_args_list], [pending["id"]])

        invited = self.client.post("/api/users/invite", json={"email": "leitor@test.local", "role": "reader"})
        self.assertEqual(invited.status_code, 201)
        reader_login = self.client.post("/api/auth/login", json={"email": "leitor@test.local", "password": invited.json()["temporaryPassword"]})
        reader = {"Authorization": f"Bearer {reader_login.json()['token']}"}
        self.assertEqual(self.client.get("/api/dashboard/overview", headers=reader).status_code, 200)
        self.assertEqual(self.client.get("/api/audit/trail", headers=reader).status_code, 403)
        self.assertEqual(self.client.post("/api/reviews", headers=reader, json={}).status_code, 403)
        self.assertEqual(self.client.put("/api/settings", headers=reader, json={}).status_code, 403)
        self.assertIsNotNone(next(user for user in self.client.get("/api/users").json() if user["email"] == "leitor@test.local")["lastLoginAt"])

        for item in (credential_id, pending["id"]):
            self.assertEqual(self.client.delete(f"/api/credentials/{item}").status_code, 204)


    def test_least_privilege_nhi_and_access_graph(self):
        project = "proj-graph"
        discovery = {
            "projects": [{"id": project, "name": "Graph", "type": "project"}],
            "identities": [
                {"id": "user:dev@corp.com", "name": "dev@corp.com", "email": "dev@corp.com", "type": "user"},
                {"id": "user:ana@corp.com", "name": "ana@corp.com", "email": "ana@corp.com", "type": "user"},
                {"id": "serviceAccount:deployer@proj-graph.iam.gserviceaccount.com", "name": "deployer", "type": "service"},
                {"id": "deleted:user:old@corp.com?uid=9", "name": "old@corp.com", "type": "deleted"},
            ],
            "accesses": [
                {"identityId": "user:dev@corp.com", "resourceId": project, "resourceName": "Graph", "role": "roles/iam.serviceAccountTokenCreator", "permissions": []},
                {"identityId": "user:ana@corp.com", "resourceId": project, "resourceName": "Graph", "role": "roles/owner", "permissions": [], "privileged": True},
                {"identityId": "serviceAccount:deployer@proj-graph.iam.gserviceaccount.com", "resourceId": project, "resourceName": "Graph",
                 "role": "roles/owner", "permissions": [], "privileged": True},
                {"identityId": "deleted:user:old@corp.com?uid=9", "resourceId": project, "resourceName": "Graph", "role": "roles/viewer", "permissions": []},
            ],
            "events": [],
            "serviceAccounts": [{"id": "serviceAccount:deployer@proj-graph.iam.gserviceaccount.com", "email": "deployer@proj-graph.iam.gserviceaccount.com",
                                 "projectId": project, "displayName": "Deployer", "description": "", "disabled": False,
                                 "keys": [{"id": "k1", "createdAt": "2024-01-01T00:00:00Z", "disabled": False, "expiresAt": None, "lastUsedAt": None}],
                                 "createdBy": "ana@corp.com", "createdAt": "2025-01-01T00:00:00Z", "ownerHint": None}],
            "impersonation": [],
            "recommendations": [],
        }
        credential_id = self.client.post("/api/credentials", json={"name": "Graph GCP", "provider": "GCP", "credential": {
            "type": "service_account", "project_id": project, "private_key": "k", "client_email": "reader@proj-graph.iam.gserviceaccount.com"}}).json()["id"]
        with patch("main.discover", return_value=discovery):
            self.assertEqual(self.client.post(f"/api/credentials/{credential_id}/scan").status_code, 200)

        findings = self.client.get(f"/api/findings?credential_id={credential_id}").json()
        path_finding = next(item for item in findings if item["rule"] == "IMPERSONATION_PATH")
        self.assertEqual(path_finding["identityId"], "user:dev@corp.com")
        self.assertIn("emitir tokens como deployer@proj-graph.iam.gserviceaccount.com", path_finding["description"])
        self.assertTrue(any(item["title"] == "Chave de acesso antiga" for item in findings))

        recs = self.client.get(f"/api/recommendations?credential_id={credential_id}").json()
        actions = {(item["identityId"], item["role"]): item["action"] for item in recs}
        self.assertEqual(actions[("deleted:user:old@corp.com?uid=9", "roles/viewer")], "remove")
        self.assertEqual(actions[("user:ana@corp.com", "roles/owner")], "move_to_group")
        self.assertEqual(actions[("serviceAccount:deployer@proj-graph.iam.gserviceaccount.com", "roles/owner")], "replace")
        deleted = next(item for item in recs if item["identityId"].startswith("deleted:"))
        self.assertEqual(self.client.patch(f"/api/recommendations/{deleted['id']}", json={"status": "dismissed"}).status_code, 422)
        ana = next(item for item in recs if item["identityId"] == "user:ana@corp.com")
        self.assertEqual(self.client.patch(f"/api/recommendations/{ana['id']}", json={"status": "dismissed", "justification": "Dona do projeto"}).json()["status"], "dismissed")

        cleaned = {**discovery, "accesses": [item for item in discovery["accesses"] if not item["identityId"].startswith("deleted:")],
                   "identities": [item for item in discovery["identities"] if item["type"] != "deleted"]}
        with patch("main.discover", return_value=cleaned):
            self.assertEqual(self.client.post(f"/api/credentials/{credential_id}/scan").status_code, 200)
        summary = self.client.get(f"/api/recommendations/summary?credential_id={credential_id}").json()
        self.assertEqual((summary["implemented"], summary["dismissed"]), (1, 1))
        self.assertEqual(self.client.get(f"/api/recommendations?credential_id={credential_id}&status=resolved").json()[0]["identityId"],
                         "deleted:user:old@corp.com?uid=9")

        nhi = self.client.get(f"/api/nhi?credential_id={credential_id}").json()
        deployer = next(item for item in nhi if item["id"].startswith("serviceAccount:deployer"))
        self.assertEqual((deployer["owner"], deployer["ownerSource"]), ("ana@corp.com", "Criou a conta (logs de auditoria)"))
        self.assertEqual((deployer["activeKeys"], deployer["impersonators"], deployer["privilegedCount"]), (1, 1, 1))
        self.assertGreater(deployer["oldestKeyDays"], 90)
        detail = self.client.get("/api/nhi/detail", params={"credential_id": credential_id, "identity": deployer["id"]}).json()
        self.assertEqual(detail["impersonatedBy"][0]["source"], "user:dev@corp.com")
        nhi_summary = self.client.get(f"/api/nhi/summary?credential_id={credential_id}").json()
        self.assertEqual((nhi_summary["withKeys"], nhi_summary["oldKeys"], nhi_summary["impersonable"]), (1, 1, 1))

        graph = self.client.get(f"/api/graph/summary?credential_id={credential_id}").json()
        self.assertEqual((graph["paths"], graph["edges"]), (1, 1))
        self.assertEqual(graph["topBlast"][0]["identity"], "user:dev@corp.com")
        paths = self.client.get(f"/api/graph/paths?credential_id={credential_id}").json()
        self.assertEqual(paths[0]["steps"][0]["name"], "deployer@proj-graph.iam.gserviceaccount.com")
        reach = self.client.get("/api/graph/identity", params={"credential_id": credential_id, "identity": "user:dev@corp.com"}).json()
        self.assertEqual((reach["privilegedIndirect"], reach["canImpersonate"][0]["name"]), (1, "deployer@proj-graph.iam.gserviceaccount.com"))
        frameworks = self.client.get(f"/api/compliance/frameworks?credential_id={credential_id}").json()["frameworks"]
        cis = next(item for item in frameworks if item["key"] == "cis")
        self.assertEqual(next(item for item in cis["controls"] if item["id"] == "1.6 (GCP)")["status"], "Não atendido")
        self.assertEqual(self.client.delete(f"/api/credentials/{credential_id}").status_code, 204)


if __name__ == "__main__":
    unittest.main()
