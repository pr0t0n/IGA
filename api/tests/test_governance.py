import unittest

import governance


def severity(role):
    return "critical" if role in {"roles/owner", "AdministratorAccess"} else "high" if role == "roles/editor" else "medium"


class RecommendationTest(unittest.TestCase):
    def test_rules_and_provider_recommendations(self):
        identities = [
            {"id": "deleted:serviceAccount:old@p.iam.gserviceaccount.com?uid=1", "type": "deleted", "name": "old"},
            {"id": "allUsers", "type": "public", "name": "allUsers"},
            {"id": "user:ana@corp.com", "type": "user", "name": "ana@corp.com"},
            {"id": "serviceAccount:etl@p.iam.gserviceaccount.com", "type": "service", "name": "etl"},
            {"id": "serviceAccount:123-compute@developer.gserviceaccount.com", "type": "service", "name": "compute"},
            {"id": "user:bob@corp.com", "type": "user", "name": "bob@corp.com"},
        ]
        grant = lambda identity, role, privileged=False: {"identityId": identity, "resourceId": "proj-a", "resourceName": "Projeto A", "role": role, "privileged": privileged}
        accesses = [grant(identities[0]["id"], "roles/viewer"), grant("allUsers", "roles/storage.objectViewer"),
                    grant("user:ana@corp.com", "roles/owner", True), grant("user:ana@corp.com", "roles/editor", True),
                    grant(identities[3]["id"], "roles/editor", True), grant(identities[4]["id"], "roles/editor", True),
                    grant("user:bob@corp.com", "roles/bigquery.admin", True)]
        recommender = [{"projectId": "proj-a", "member": "user:bob@corp.com", "role": "roles/bigquery.admin", "action": "replace",
                        "suggestedRoles": ["roles/bigquery.dataViewer"], "description": "Substitua por um papel menor."}]
        recs = {(rec["identityId"], rec["role"]): rec for rec in governance.build_recommendations("GCP", identities, accesses, recommender, severity)}
        self.assertEqual(recs[(identities[0]["id"], "roles/viewer")]["action"], "remove")
        self.assertIn("principal foi excluído", recs[(identities[0]["id"], "roles/viewer")]["reason"])
        self.assertEqual(recs[("allUsers", "roles/storage.objectViewer")]["action"], "remove")
        self.assertIn("Redundante", recs[("user:ana@corp.com", "roles/editor")]["reason"])
        self.assertEqual(recs[("user:ana@corp.com", "roles/owner")]["action"], "move_to_group")
        self.assertEqual(recs[(identities[3]["id"], "roles/editor")]["action"], "replace")
        self.assertNotIn((identities[4]["id"], "roles/editor"), recs, "Google-managed accounts are not right-sized by the platform")
        bob = recs[("user:bob@corp.com", "roles/bigquery.admin")]
        self.assertEqual((bob["source"], bob["suggestedRoles"]), ("Google IAM Recommender", ["roles/bigquery.dataViewer"]))
        self.assertIn("add-iam-policy-binding proj-a --member='user:bob@corp.com' --role='roles/bigquery.dataViewer'", bob["command"])
        self.assertIn("remove-iam-policy-binding proj-a --member='user:bob@corp.com' --role='roles/bigquery.admin'", bob["command"])

    def test_aws_command_uses_policy_arn(self):
        identities = [{"id": "arn:aws:iam::1:user/alice", "type": "user", "name": "alice"}]
        accesses = [{"identityId": "arn:aws:iam::1:user/alice", "resourceId": "aws:account:1", "role": "AdministratorAccess",
                     "permissions": ["arn:aws:iam::aws:policy/AdministratorAccess"], "privileged": True}]
        rec = governance.build_recommendations("AWS", identities, accesses, [], severity)[0]
        self.assertEqual(rec["action"], "move_to_group")
        self.assertIn("aws iam detach-user-policy --user-name alice --policy-arn arn:aws:iam::aws:policy/AdministratorAccess", rec["command"])


class GraphTest(unittest.TestCase):
    def test_escalation_through_project_level_token_creator(self):
        accesses = [
            {"identityId": "user:dev@corp.com", "resourceId": "proj-a", "resourceName": "A", "role": "roles/iam.serviceAccountTokenCreator", "privileged": False},
            {"identityId": "serviceAccount:deployer@proj-a.iam.gserviceaccount.com", "resourceId": "proj-b", "resourceName": "B", "role": "roles/owner", "privileged": True},
            {"identityId": "user:ext@gmail.com", "resourceId": "proj-a", "resourceName": "A", "role": "roles/viewer", "privileged": False},
        ]
        stored = [{"source": "user:ext@gmail.com", "target": "serviceAccount:deployer@proj-a.iam.gserviceaccount.com",
                   "role": "roles/iam.serviceAccountUser", "scope": "service_account", "resourceId": "proj-a"}]
        edges = governance.impersonation_edges(accesses, stored, {"proj-a": ["serviceAccount:deployer@proj-a.iam.gserviceaccount.com"]})
        self.assertEqual(len(edges), 2)
        identities = {"user:dev@corp.com": {"id": "user:dev@corp.com", "type": "user", "email": "dev@corp.com"},
                      "user:ext@gmail.com": {"id": "user:ext@gmail.com", "type": "user", "email": "ext@gmail.com"},
                      **{f"user:u{i}@corp.com": {"id": f"user:u{i}@corp.com", "type": "user", "email": f"u{i}@corp.com"} for i in range(30)}}
        domains = governance.corporate_domains(list(identities.values()), [])
        self.assertEqual(domains, ["corp.com"])
        graph = governance.AccessGraph(accesses, edges)
        reach = graph.reach("user:dev@corp.com")
        self.assertEqual((reach["privilegedIndirect"], reach["indirectResources"]), (1, 1))
        paths = graph.escalation_paths(identities, domains)
        self.assertEqual(len(paths), 2)
        external = next(path for path in paths if path["source"] == "user:ext@gmail.com")
        self.assertTrue(external["external"])
        self.assertEqual(external["severity"], "critical")
        self.assertEqual(paths[0]["source"], "user:ext@gmail.com", "external paths come first")

    def test_nhi_owner_and_flags(self):
        owner, source = governance.owner_of({"id": "serviceAccount:etl@p.iam.gserviceaccount.com", "owner": None},
                                            {"ownerHint": None, "createdBy": "ana@corp.com"})
        self.assertEqual((owner, source), ("ana@corp.com", "Criou a conta (logs de auditoria)"))
        owner, _ = governance.owner_of({"id": "serviceAccount:service-1@gcp-sa-aiplatform.iam.gserviceaccount.com", "owner": None}, None)
        self.assertEqual(owner, "Google (conta gerenciada)")
        self.assertEqual(governance.ai_kind("serviceAccount:service-1@gcp-sa-aiplatform-re.iam.gserviceaccount.com"), "Agente do Vertex AI Agent Engine")
        item = {"privilegedCount": 2, "owner": None, "oldestKeyDays": 400, "unusedKeys": 1, "lastUsedDays": None, "impersonators": 3,
                "disabled": False, "grantCount": 2}
        flags = governance.nhi_flags(item, 90, 90)
        self.assertEqual(len(flags), 4)


if __name__ == "__main__":
    unittest.main()
