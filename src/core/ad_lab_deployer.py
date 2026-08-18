import os
import sys
import json
import random
import string
import argparse
import subprocess
import yaml
from pathlib import Path
from datetime import datetime


FIRST_NAMES = [
    "James", "Maria", "Robert", "Jennifer", "Michael", "Linda", "David", "Patricia",
    "William", "Elizabeth", "Richard", "Barbara", "Joseph", "Susan", "Thomas", "Jessica",
    "Charles", "Sarah", "Christopher", "Karen", "Daniel", "Lisa", "Matthew", "Nancy",
    "Anthony", "Betty", "Mark", "Margaret", "Donald", "Sandra"
]

LAST_NAMES = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis",
    "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson",
    "Thomas", "Taylor", "Moore", "Jackson", "Martin", "Lee", "Perez", "Thompson",
    "White", "Harris", "Sanchez", "Clark", "Ramirez", "Lewis", "Robinson"
]

DEPARTMENTS = [
    "IT", "Finance", "HR", "Engineering", "Marketing", "Sales", "Legal", "Operations"
]

SERVICE_SPNS = [
    "MSSQLSvc/dc01.lab.local:1433",
    "HTTP/web01.lab.local",
    "HTTP/intranet.lab.local",
    "cifs/fs01.lab.local",
    "HTTP/portal.lab.local",
    "HOST/app01.lab.local",
    "MSSQLSvc/db01.lab.local:1433",
]

GROUP_TEMPLATES = [
    {"name": "IT Administrators", "description": "IT admin team"},
    {"name": "Server Administrators", "description": "Server management group"},
    {"name": "Helpdesk Support", "description": "Tier 1 and 2 support"},
    {"name": "Database Administrators", "description": "DBA team"},
    {"name": "Security Auditors", "description": "Security review team"},
    {"name": "Development Team", "description": "Application developers"},
    {"name": "Finance Managers", "description": "Finance leadership"},
    {"name": "HR Specialists", "description": "Human resources team"},
]


class ADLabDeployer:

    def __init__(self, lab_dir="./lab_output"):
        self.lab_dir = Path(lab_dir)
        self.lab_dir.mkdir(parents=True, exist_ok=True)

    def _random_password(self, length=16):
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        password = [
            random.choice(string.ascii_uppercase),
            random.choice(string.ascii_lowercase),
            random.choice(string.digits),
            random.choice("!@#$%^&*"),
        ]
        password += [random.choice(chars) for _ in range(length - 4)]
        random.shuffle(password)
        return "".join(password)

    def _generate_username(self, first_name, last_name, existing):
        base = f"{first_name[0].lower()}{last_name.lower()}"
        username = base
        counter = 1
        while username in existing:
            username = f"{base}{counter}"
            counter += 1
        return username

    def generate_domain_config(self, domain_name, admin_password,
                              n_users=20, n_groups=5, n_computers=10):
        config = {
            "domain_name": domain_name.upper(),
            "domain_fqdn": domain_name.lower(),
            "admin_password": admin_password,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "users": [],
            "groups": [],
            "computers": [],
            "gpos": [],
            "ous": [],
            "acls": [],
        }

        domain_upper = domain_name.upper()
        domain_lower = domain_name.lower()

        ous = [
            {"name": "Computers", "path": f"OU=Computers,DC={domain_lower.replace('.', ',DC=')}"},
            {"name": "Users", "path": f"OU=Users,DC={domain_lower.replace('.', ',DC=')}"},
            {"name": "Servers", "path": f"OU=Servers,DC={domain_lower.replace('.', ',DC=')}"},
            {"name": "Service Accounts", "path": f"OU=Service Accounts,DC={domain_lower.replace('.', ',DC=')}"},
            {"name": "Production", "path": f"OU=Production,DC={domain_lower.replace('.', ',DC=')}"},
        ]
        config["ous"] = ous

        builtin_groups = [
            {
                "name": f"DOMAIN ADMINS@{domain_upper}",
                "description": "Domain Administrators",
                "members": [f"Administrator@{domain_upper}"],
                "is_privileged": True,
            },
            {
                "name": f"ENTERPRISE ADMINS@{domain_upper}",
                "description": "Enterprise Administrators",
                "members": [f"Administrator@{domain_upper}"],
                "is_privileged": True,
            },
            {
                "name": f"DOMAIN USERS@{domain_upper}",
                "description": "Domain Users",
                "is_privileged": False,
            },
        ]
        config["groups"].extend(builtin_groups)

        num_custom_groups = min(n_groups, len(GROUP_TEMPLATES))
        existing_usernames = {"administrator"}

        for i in range(n_users):
            first = random.choice(FIRST_NAMES)
            last = random.choice(LAST_NAMES)
            username = self._generate_username(first, last, existing_usernames)
            existing_usernames.add(username)
            display_name = f"{first} {last}"

            user = {
                "name": f"{username}@{domain_upper}",
                "displayname": display_name,
                "username": username,
                "password": self._random_password(),
                "department": random.choice(DEPARTMENTS),
                "enabled": True,
                "password_never_expires": False,
                "hasspn": False,
                "dont_require_preauth": False,
                "is_admin": False,
                "member_of": [f"DOMAIN USERS@{domain_upper}"],
            }
            config["users"].append(user)

        num_kerb = min(4, n_users)
        kerberoastable_indices = random.sample(range(n_users), num_kerb)
        remaining = [i for i in range(n_users) if i not in kerberoastable_indices]
        num_asrep = min(2, len(remaining))
        asrep_indices = random.sample(remaining, num_asrep) if remaining else []

        for idx in kerberoastable_indices:
            user = config["users"][idx]
            user["hasspn"] = True
            spn = random.choice(SERVICE_SPNS).replace("lab.local", domain_lower)
            user["serviceprincipalname"] = spn
            user["description"] = f"Service account for {spn}"
            user["password_never_expires"] = True

        for idx in asrep_indices:
            user = config["users"][idx]
            user["dont_require_preauth"] = True

        for i in range(num_custom_groups):
            template = GROUP_TEMPLATES[i]
            group = {
                "name": f"{template['name'].upper()}@{domain_upper}",
                "description": template["description"],
                "members": [],
                "is_privileged": False,
            }
            member_pool = config["users"][(i * 3):((i + 1) * 3)]
            for user in member_pool:
                group["members"].append(user["name"])
                user["member_of"].append(group["name"])
            config["groups"].append(group)

        config["groups"][3]["is_privileged"] = True
        config["groups"][3]["acl_rights"] = ["GenericAll"]
        config["groups"][3]["acl_target"] = f"DC={domain_lower.replace('.', ',DC=')}"

        vulnerable_user = config["users"][0]
        config["acls"].append({
            "principal": vulnerable_user["name"],
            "target": f"DC={domain_lower.replace('.', ',DC=')}",
            "rights": ["WriteDacl", "WriteOwner"],
            "risk": "Critical",
        })

        nested_group = config["groups"][4]
        nested_group["member_of"] = [f"DOMAIN ADMINS@{domain_upper}"]
        nested_group["nested_members"] = nested_group["members"][:2]

        for i in range(n_computers):
            if i < 2:
                hostname = f"DC0{i + 1}"
                os_name = "Windows Server 2022"
            elif i < 6:
                hostname = f"WS{i - 1:03d}"
                os_name = "Windows 11 Enterprise"
            else:
                hostname = f"SRV{i - 5:02d}"
                os_name = "Windows Server 2022"

            computer = {
                "name": f"{hostname}.{domain_lower}",
                "hostname": hostname,
                "operating_system": os_name,
                "enabled": True,
                "ou": random.choice(["Computers", "Servers", "Production"]),
            }
            config["computers"].append(computer)

        admin_sessions = random.sample(config["computers"], min(4, n_computers))
        for comp in admin_sessions:
            for user in random.sample(config["users"], min(2, len(config["users"]))):
                user["member_of"].append(f"REMOTE MANAGEMENT USERS@{domain_upper}")

        gpos = [
            {
                "name": "Default Domain Policy",
                "gpo_id": "{31B2F340-016D-11D2-945F-00C04FB984F9}",
                "applies_to": f"DC={domain_lower.replace('.', ',DC=')}",
                "is_misconfigured": False,
            },
            {
                "name": "Restricted Groups Policy",
                "gpo_id": "{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}",
                "applies_to": f"OU=Computers,DC={domain_lower.replace('.', ',DC=')}",
                "is_misconfigured": True,
                "misconfiguration": "Adds Helpdesk group to local Administrators via GPO",
                "edit_rights": [config["groups"][2]["name"]],
            },
            {
                "name": "Password Policy Override",
                "gpo_id": "{B2C3D4E5-F6A7-8901-BCDE-F12345678901}",
                "applies_to": f"OU=Service Accounts,DC={domain_lower.replace('.', ',DC=')}",
                "is_misconfigured": True,
                "misconfiguration": "Minimum password length set to 1, complexity disabled",
                "edit_rights": [vulnerable_user["name"]],
            },
        ]
        config["gpos"] = gpos

        return config

    def write_docker_compose(self, config, output_path):
        domain = config["domain_fqdn"]
        admin_pw = config["admin_password"]

        compose = {
            "version": "3.9",
            "services": {
                "ad-dc": {
                    "image": "mythicagents/adlab-dc:latest",
                    "container_name": f"dc01.{domain}",
                    "restart": "unless-stopped",
                    "environment": {
                        "DOMAIN": config["domain_name"],
                        "DOMAIN_FQDN": domain,
                        "ADMIN_PASSWORD": admin_pw,
                    },
                    "networks": ["ad-lab"],
                    "volumes": [
                        "ad_data:/var/lib/samba",
                        f"./provisioning:/provisioning:ro",
                    ],
                },
                "neo4j": {
                    "image": "neo4j:5.15",
                    "container_name": "ad-lab-neo4j",
                    "restart": "unless-stopped",
                    "ports": ["7474:7474", "7687:7687"],
                    "environment": {
                        "NEO4J_AUTH": "neo4j/password123",
                        "NEO4J_PLUGINS": '["apoc"]',
                    },
                    "volumes": ["neo4j_data:/data"],
                    "networks": ["ad-lab"],
                },
            },
            "volumes": {
                "ad_data": {"driver": "local"},
                "neo4j_data": {"driver": "local"},
            },
            "networks": {
                "ad-lab": {
                    "driver": "bridge",
                    "ipam": {"config": [{"subnet": "172.28.0.0/16"}]},
                }
            },
        }

        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "w") as f:
            yaml.dump(compose, f, default_flow_style=False)

        return output_file

    def write_provisioning_scripts(self, config, output_dir):
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        provision_script = self._build_provision_script(config)
        provision_file = output_path / "provision_ad.ps1"
        provision_file.write_text(provision_script, encoding="utf-8")

        collect_script = self._build_collect_script(config)
        collect_file = output_path / "collect_data.ps1"
        collect_file.write_text(collect_script, encoding="utf-8")

        config_file = output_path / "domain_config.json"
        with open(config_file, "w") as f:
            json.dump(config, f, indent=2)

        return {
            "provision_script": str(provision_file),
            "collect_script": str(collect_file),
            "config_file": str(config_file),
        }

    def _build_provision_script(self, config):
        lines = [
            "$DomainName = '" + config["domain_fqdn"] + "'",
            "$AdminPassword = '" + config["admin_password"] + "'",
            "",
            "Import-Module ActiveDirectory",
            "",
        ]

        for user in config["users"]:
            sam = user["username"]
            lines.append("$securePw = ConvertTo-SecureString -String $AdminPassword -AsPlainText -Force")
            lines.append(f"New-ADUser -SamAccountName {sam} -Name \"{user['displayname']}\" -DisplayName \"{user['displayname']}\" -Enabled $true -AccountPassword $securePw")

            if user.get("hasspn"):
                spn = user.get("serviceprincipalname", "")
                spn_line = "Set-ADUser -Identity {sam} -ServicePrincipalName @{{Add='{spn}'}}".format(sam=sam, spn=spn)
                lines.append(spn_line)
                lines.append(f"Set-ADUser -Identity {sam} -PasswordNeverExpires $true")

            if user.get("dont_require_preauth"):
                lines.append(f"Set-ADAccountControl -Identity {sam} -DoesNotRequirePreAuth $true")

        for group in config["groups"]:
            group_name = group["name"].split("@")[0]
            lines.append(f"New-ADGroup -Name \"{group_name}\" -GroupScope DomainLocal -Description \"{group['description']}\"")

        for acl in config["acls"]:
            principal = acl["principal"].split("@")[0]
            lines.append(f"$acl = Get-Acl -Path 'AD:\\DC={config['domain_fqdn'].replace('.', ',DC=')}'")
            lines.append(f"$rule = New-Object System.DirectoryServices.DirectoryAccessRule('{principal}', 'WriteDacl', 'Allow')")
            lines.append("$acl.AddAccessRule($rule)")
            lines.append(f"Set-Acl -Path 'AD:\\DC={config['domain_fqdn'].replace('.', ',DC=')}' -AclObject $acl")

        return "\r\n".join(lines)

    def _build_collect_script(self, config):
        lines = [
            "Import-Module ActiveDirectory",
            "",
            "$results = @{ Nodes = @(); Edges = @() }",
            "",
            "$users = Get-ADUser -Filter * -Properties *",
            "foreach ($u in $users) {",
            '    $results.Nodes += @{ type="User"; name="$($u.SamAccountName)@LAB.LOCAL"; properties=$u }',
            "}",
            "",
            "$groups = Get-ADGroup -Filter *",
            "foreach ($g in $groups) {",
            '    $results.Nodes += @{ type="Group"; name="$($g.Name)@LAB.LOCAL"; properties=$g }',
            "    $members = Get-ADGroupMember -Identity $g -Recursive",
            "    foreach ($m in $members) {",
            '        $results.Edges += @{ source="$($m.SamAccountName)@LAB.LOCAL"; target="$($g.Name)@LAB.LOCAL"; type="MemberOf" }',
            "    }",
            "}",
            "",
            "$results | ConvertTo-Json -Depth 10 | Out-File -FilePath 'C:\\Collection\\ad_data.json'",
        ]
        return "\r\n".join(lines)

    def deploy_lab(self):
        compose_file = self.lab_dir / "docker-compose.yml"
        if not compose_file.exists():
            config = self.generate_domain_config("lab.local", "Welcome123!")
            self.write_docker_compose(config, str(compose_file))

        result = subprocess.run(
            ["docker", "compose", "-f", str(compose_file), "up", "-d"],
            capture_output=True, text=True
        )
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }

    def destroy_lab(self):
        compose_file = self.lab_dir / "docker-compose.yml"
        if not compose_file.exists():
            return {"success": False, "stderr": "No docker-compose.yml found"}

        result = subprocess.run(
            ["docker", "compose", "-f", str(compose_file), "down", "-v"],
            capture_output=True, text=True
        )
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }


def main():
    parser = argparse.ArgumentParser(description="AD Lab Deployer")
    parser.add_argument("--domain", default="lab.local", help="Domain FQDN")
    parser.add_argument("--admin-password", default="Welcome123!", help="Admin password")
    parser.add_argument("--users", type=int, default=20, help="Number of users")
    parser.add_argument("--groups", type=int, default=5, help="Number of groups")
    parser.add_argument("--computers", type=int, default=10, help="Number of computers")
    parser.add_argument("--output", default="./lab_output", help="Output directory")
    parser.add_argument("--deploy", action="store_true", help="Deploy lab with Docker")
    args = parser.parse_args()

    deployer = ADLabDeployer(lab_dir=args.output)
    config = deployer.generate_domain_config(
        domain_name=args.domain,
        admin_password=args.admin_password,
        n_users=args.users,
        n_groups=args.groups,
        n_computers=args.computers,
    )

    output_dir = Path(args.output)
    config_path = output_dir / "domain_config.json"
    with open(config_path, "w") as f:
        json.dump(config, f, indent=2)

    deployer.write_docker_compose(config, str(output_dir / "docker-compose.yml"))
    deployer.write_provisioning_scripts(config, str(output_dir / "provisioning"))

    print(f"Generated config with {len(config['users'])} users, "
          f"{len(config['groups'])} groups, {len(config['computers'])} computers")
    print(f"Kerberoastable accounts: {sum(1 for u in config['users'] if u.get('hasspn'))}")
    print(f"AS-REP roastable accounts: {sum(1 for u in config['users'] if u.get('dont_require_preauth'))}")
    print(f"ACL misconfigurations: {len(config['acls'])}")
    print(f"Output written to {args.output}")

    if args.deploy:
        result = deployer.deploy_lab()
        if result["success"]:
            print("Lab deployed successfully")
        else:
            print(f"Deploy failed: {result['stderr']}")


if __name__ == "__main__":
    main()
