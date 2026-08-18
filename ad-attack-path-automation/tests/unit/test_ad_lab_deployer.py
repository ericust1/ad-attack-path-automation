import pytest
import json
import os
from pathlib import Path
from unittest.mock import patch, MagicMock

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from src.core.ad_lab_deployer import ADLabDeployer


class TestADLabDeployer:

    @pytest.fixture
    def deployer(self, tmp_path):
        return ADLabDeployer(lab_dir=str(tmp_path / "lab_output"))

    @pytest.fixture
    def sample_config(self, deployer):
        return deployer.generate_domain_config(
            domain_name="test.local",
            admin_password="TestPass123!",
            n_users=10,
            n_groups=3,
            n_computers=5,
        )

    def test_generate_domain_config_creates_expected_users(self, sample_config):
        assert len(sample_config["users"]) == 10
        for user in sample_config["users"]:
            assert "name" in user
            assert "username" in user
            assert "password" in user
            assert "displayname" in user
            assert "TEST.LOCAL" in user["name"]

    def test_generate_domain_config_creates_expected_groups(self, sample_config):
        assert len(sample_config["groups"]) >= 3
        builtin_groups = [g for g in sample_config["groups"]
                         if "DOMAIN ADMINS" in g["name"] or "ENTERPRISE ADMINS" in g["name"]]
        assert len(builtin_groups) >= 2

    def test_generate_domain_config_creates_expected_computers(self, sample_config):
        assert len(sample_config["computers"]) == 5
        for comp in sample_config["computers"]:
            assert "name" in comp
            assert "hostname" in comp
            assert "operating_system" in comp
            assert "test.local" in comp["name"]

    def test_generate_domain_config_has_ous(self, sample_config):
        assert len(sample_config["ous"]) > 0
        ou_names = [ou["name"] for ou in sample_config["ous"]]
        assert "Computers" in ou_names
        assert "Users" in ou_names

    def test_generate_domain_config_has_gpos(self, sample_config):
        assert len(sample_config["gpos"]) > 0
        misconfigured_gpos = [g for g in sample_config["gpos"] if g.get("is_misconfigured")]
        assert len(misconfigured_gpos) > 0

    def test_config_has_kerberoastable_users(self, sample_config):
        kerberoastable = [u for u in sample_config["users"] if u.get("hasspn")]
        assert len(kerberoastable) > 0
        for user in kerberoastable:
            assert "serviceprincipalname" in user
            assert user["serviceprincipalname"] != ""

    def test_config_has_asrep_roastable_users(self, sample_config):
        asrep = [u for u in sample_config["users"] if u.get("dont_require_preauth")]
        assert len(asrep) > 0

    def test_config_has_misconfigured_acls(self, sample_config):
        assert len(sample_config["acls"]) > 0
        for acl in sample_config["acls"]:
            assert "principal" in acl
            assert "target" in acl
            assert "rights" in acl
            assert len(acl["rights"]) > 0
            assert acl["risk"] in ["Critical", "High", "Medium", "Low"]

    def test_config_users_belong_to_domain_users(self, sample_config):
        domain_users_group = None
        for g in sample_config["groups"]:
            if "DOMAIN USERS" in g["name"]:
                domain_users_group = g["name"]
                break
        assert domain_users_group is not None
        for user in sample_config["users"]:
            assert domain_users_group in user.get("member_of", [])

    def test_write_docker_compose_generates_file(self, deployer, sample_config, tmp_path):
        output_path = str(tmp_path / "docker-compose.yml")
        result = deployer.write_docker_compose(sample_config, output_path)
        assert os.path.exists(output_path)

        with open(output_path) as f:
            content = f.read()
        assert "version" in content or "services" in content
        assert "neo4j" in content

    def test_write_provisioning_scripts_generates_files(self, deployer, sample_config, tmp_path):
        output_dir = str(tmp_path / "provisioning")
        result = deployer.write_provisioning_scripts(sample_config, output_dir)
        assert os.path.exists(result["provision_script"])
        assert os.path.exists(result["collect_script"])
        assert os.path.exists(result["config_file"])

        config_content = json.loads(Path(result["config_file"]).read_text())
        assert config_content["domain_name"] == "TEST.LOCAL"

    def test_generate_default_config_domain_name(self, deployer):
        config = deployer.generate_domain_config("corp.local", "Admin123!")
        assert config["domain_name"] == "CORP.LOCAL"
        assert config["domain_fqdn"] == "corp.local"
        assert config["admin_password"] == "Admin123!"

    def test_nested_group_membership_creates_escalation(self, sample_config):
        groups_with_parents = [g for g in sample_config["groups"]
                               if g.get("member_of") and len(g.get("member_of", [])) > 0]
        assert len(groups_with_parents) > 0

    def test_random_password_meets_complexity(self, deployer):
        for _ in range(20):
            pw = deployer._random_password()
            assert len(pw) >= 16
            assert any(c.isupper() for c in pw)
            assert any(c.islower() for c in pw)
            assert any(c.isdigit() for c in pw)

    @patch("src.core.ad_lab_deployer.subprocess.run")
    def test_deploy_lab_runs_docker_compose(self, mock_run, deployer, sample_config, tmp_path):
        mock_run.return_value = MagicMock(returncode=0, stdout="done", stderr="")
        deployer.write_docker_compose(sample_config, str(tmp_path / "lab_output" / "docker-compose.yml"))
        result = deployer.deploy_lab()
        assert result["success"] is True

    @patch("src.core.ad_lab_deployer.subprocess.run")
    def test_destroy_lab_runs_docker_compose_down(self, mock_run, deployer, tmp_path):
        mock_run.return_value = MagicMock(returncode=0, stdout="done", stderr="")
        compose_path = tmp_path / "lab_output" / "docker-compose.yml"
        compose_path.parent.mkdir(parents=True, exist_ok=True)
        compose_path.write_text("services: {}")
        result = deployer.destroy_lab()
        assert result["success"] is True
