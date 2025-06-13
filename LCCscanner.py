#!/usr/bin/env python3

import argparse
import boto3
import base64
import json
import re

# ANSI color codes for formatted output
class colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_banner():
    """Prints the tool's banner."""
    print(f"{colors.HEADER}{'='*60}")
    print(f"{colors.BOLD}   SageMaker LCC Security Scanner   ")
    print(f"{'='*60}{colors.ENDC}\n")

def print_heading(title):
    """Prints a formatted heading."""
    print(f"\n{colors.OKBLUE}{'─'*20} {title} {'─'*20}{colors.ENDC}")

def print_finding(level, message, remediation):
    """Prints a formatted finding with remediation advice."""
    color_map = {
        "INFO": colors.OKGREEN,
        "WARN": colors.WARNING,
        "CRITICAL": colors.FAIL
    }
    color = color_map.get(level, colors.ENDC)
    print(f"[{color}{level}{colors.ENDC}] {message}")
    print(f"    {colors.BOLD}Remediation:{colors.ENDC} {remediation}\n")


class SageMakerScanner:
    """
    A class to scan for common security misconfigurations in SageMaker.
    """
    def __init__(self, region=None):
        self.sagemaker_client = boto3.client('sagemaker', region_name=region)
        self.iam_client = boto3.client('iam', region_name=region)

    def check_notebook_root_access(self):
        """
        Checks all SageMaker notebook instances for enabled root access.
        """
        print_heading("Checking Notebook Instance Root Access")
        try:
            paginator = self.sagemaker_client.get_paginator('list_notebook_instances')
            pages = paginator.paginate()
            found_vuln = False
            for page in pages:
                for instance in page['NotebookInstances']:
                    instance_name = instance['NotebookInstanceName']
                    instance_details = self.sagemaker_client.describe_notebook_instance(
                        NotebookInstanceName=instance_name
                    )
                    if instance_details.get('RootAccess', 'Disabled') == 'Enabled':
                        found_vuln = True
                        print_finding(
                            "WARN",
                            f"Instance '{instance_name}' has RootAccess enabled.",
                            "Disable root access when creating notebook instances unless it is strictly required. This reduces the blast radius of a compromise."
                        )
            if not found_vuln:
                print(f"{colors.OKGREEN}[INFO] No notebook instances found with root access enabled.{colors.ENDC}")
        except Exception as e:
            print(f"{colors.FAIL}Error checking notebook root access: {e}{colors.ENDC}")

    def check_lcc_scripts(self):
        """
        Scans all Notebook and Studio LCCs for suspicious script content.
        """
        suspicious_patterns = {
            "Reverse Shell": r"nc |ncat |/dev/tcp/|bash -i",
            "Remote Code Execution": r"curl .*\|.*sh|wget .*\|.*sh",
            "IMDS Credential Access": r"169\.254\.169\.254",
            "Crontab Modification": r"crontab",
            "SSH Backdoor": r"authorized_keys"
        }

        # Scan Notebook Instance LCCs
        print_heading("Scanning Notebook Instance LCCs for Suspicious Content")
        try:
            paginator = self.sagemaker_client.get_paginator('list_notebook_instance_lifecycle_configs')
            pages = paginator.paginate()
            found_suspicious_notebook_lcc = False
            for page in pages:
                for lcc_summary in page['NotebookInstanceLifecycleConfigs']:
                    lcc_name = lcc_summary['NotebookInstanceLifecycleConfigName']
                    lcc_details = self.sagemaker_client.describe_notebook_instance_lifecycle_config(
                        NotebookInstanceLifecycleConfigName=lcc_name
                    )
                    
                    scripts = []
                    if lcc_details.get('OnCreate'):
                        scripts.extend(lcc_details['OnCreate'])
                    if lcc_details.get('OnStart'):
                        scripts.extend(lcc_details['OnStart'])

                    for script in scripts:
                        if 'Content' in script:
                            decoded_content = base64.b64decode(script['Content']).decode('utf-8')
                            for threat, pattern in suspicious_patterns.items():
                                if re.search(pattern, decoded_content, re.IGNORECASE):
                                    found_suspicious_notebook_lcc = True
                                    print_finding(
                                        "CRITICAL",
                                        f"Notebook LCC '{lcc_name}' contains a suspicious pattern indicating a potential '{threat}'.",
                                        "Manually review the script content for malicious code. Tightly control `sagemaker:CreateNotebookInstanceLifecycleConfig` permissions."
                                    )
            if not found_suspicious_notebook_lcc:
                 print(f"{colors.OKGREEN}[INFO] No suspicious content found in Notebook LCCs.{colors.ENDC}")

        except Exception as e:
            print(f"{colors.FAIL}Error scanning notebook LCCs: {e}{colors.ENDC}")
            
        # Scan Studio LCCs
        print_heading("Scanning Studio LCCs for Suspicious Content")
        try:
            paginator = self.sagemaker_client.get_paginator('list_studio_lifecycle_configs')
            pages = paginator.paginate()
            found_suspicious_studio_lcc = False
            for page in pages:
                for lcc_summary in page['StudioLifecycleConfigs']:
                    lcc_name = lcc_summary['StudioLifecycleConfigName']
                    lcc_details = self.sagemaker_client.describe_studio_lifecycle_config(
                        StudioLifecycleConfigName=lcc_name
                    )
                    decoded_content = base64.b64decode(lcc_details['StudioLifecycleConfigContent']).decode('utf-8')
                    for threat, pattern in suspicious_patterns.items():
                        if re.search(pattern, decoded_content, re.IGNORECASE):
                            found_suspicious_studio_lcc = True
                            print_finding(
                                "CRITICAL",
                                f"Studio LCC '{lcc_name}' contains a suspicious pattern indicating a potential '{threat}'.",
                                "Manually review the script content. A compromised Studio LCC can affect many users. Tightly control `sagemaker:CreateStudioLifecycleConfig` and `sagemaker:UpdateDomain` permissions."
                            )
            if not found_suspicious_studio_lcc:
                print(f"{colors.OKGREEN}[INFO] No suspicious content found in Studio LCCs.{colors.ENDC}")

        except Exception as e:
            print(f"{colors.FAIL}Error scanning Studio LCCs: {e}{colors.ENDC}")

    def check_sagemaker_roles(self):
        """
        Checks IAM roles associated with SageMaker notebooks for overly permissive policies.
        """
        print_heading("Analyzing IAM Roles attached to SageMaker Notebooks")
        try:
            paginator = self.sagemaker_client.get_paginator('list_notebook_instances')
            pages = paginator.paginate()
            checked_roles = set()
            found_vuln = False
            for page in pages:
                for instance in page['NotebookInstances']:
                    role_arn = instance.get('RoleArn')
                    if role_arn and role_arn not in checked_roles:
                        checked_roles.add(role_arn)
                        role_name = role_arn.split('/')[-1]
                        print(f"\n--- Analyzing Role: {colors.BOLD}{role_name}{colors.ENDC} ---")
                        self._check_single_role(role_name)
                        found_vuln = True
            
            if not found_vuln:
                print(f"{colors.OKGREEN}[INFO] No active notebook instances found to analyze roles.{colors.ENDC}")

        except Exception as e:
            print(f"{colors.FAIL}Error checking SageMaker roles: {e}{colors.ENDC}")

    def _check_single_role(self, role_name):
        """Helper function to analyze policies for a single IAM role."""
        high_risk_permissions = {
            # Privilege Escalation Permissions
            "iam:CreateUser": "Allows creation of new IAM users.",
            "iam:CreateAccessKey": "Allows creation of access keys for users.",
            "iam:AttachUserPolicy": "Allows attaching policies (like AdministratorAccess) to users.",
            "iam:PassRole": "Allows passing roles to other AWS services, enabling privilege escalation.",
            "iam:CreatePolicyVersion": "Allows modifying existing policies to grant more permissions.",
            # LCC Management Permissions
            "sagemaker:CreateNotebookInstanceLifecycleConfig": "Allows creation of potentially malicious Notebook LCCs.",
            "sagemaker:CreateStudioLifecycleConfig": "Allows creation of potentially malicious Studio LCCs.",
            "sagemaker:UpdateNotebookInstance": "Allows attaching an LCC to a notebook instance.",
            "sagemaker:UpdateDomain": "Allows attaching an LCC to all users in a Studio Domain (high impact).",
            "sagemaker:UpdateUserProfile": "Allows attaching an LCC to a specific Studio user."
        }
        
        try:
            # Check attached policies
            attached_policies = self.iam_client.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
            for policy in attached_policies:
                policy_arn = policy['PolicyArn']
                policy_version = self.iam_client.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
                policy_document = self.iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version)['PolicyVersion']['Document']
                self._analyze_policy_document(role_name, policy_arn.split('/')[-1], policy_document, high_risk_permissions)

            # Check inline policies
            inline_policies = self.iam_client.list_role_policies(RoleName=role_name)['PolicyNames']
            for policy_name in inline_policies:
                policy_document = self.iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)['PolicyDocument']
                self._analyze_policy_document(role_name, policy_name, policy_document, high_risk_permissions)

        except Exception as e:
             print(f"{colors.FAIL}Could not analyze role '{role_name}': {e}{colors.ENDC}")

    def _analyze_policy_document(self, role_name, policy_name, document, risk_map):
        """Analyzes a policy document for high-risk permissions."""
        if 'Statement' in document:
            statements = document['Statement']
            if not isinstance(statements, list):
                statements = [statements]
            
            for stmt in statements:
                if stmt['Effect'] == 'Allow':
                    actions = stmt.get('Action', [])
                    if not isinstance(actions, list):
                        actions = [actions]
                    
                    for action in actions:
                        # Check for wildcard actions
                        if action == '*' or action == 'iam:*' or action == 'sagemaker:*':
                            print_finding("CRITICAL", f"Role '{role_name}' has wildcard permissions (`{action}`) in policy '{policy_name}'.", "Follow the principle of least privilege. Avoid using wildcards (`*`) in IAM policies, especially for `iam` and `sagemaker` actions.")
                            if action == '*' or action == 'iam:*': return # No need to check further if it's already admin
                        
                        # Check for specific risky permissions
                        if action in risk_map:
                             # Special check for iam:PassRole
                            if action == 'iam:PassRole' and stmt.get('Resource') == '*':
                                print_finding("CRITICAL", f"Role '{role_name}' has `iam:PassRole` on all resources (`*`) in policy '{policy_name}'.", "Restrict `iam:PassRole` to only allow passing specific, least-privilege roles. A wildcard resource is extremely dangerous.")
                            else:
                                print_finding("WARN", f"Role '{role_name}' has risky permission `{action}` in policy '{policy_name}'. Reason: {risk_map[action]}", "Review this permission and remove it if not absolutely necessary. Tightly control all LCC and IAM modification permissions.")

if __name__ == "__main__":
    print_banner()
    parser = argparse.ArgumentParser(
        description="SageMaker LCC Security Scanner. Scans for common misconfigurations.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        '--check',
        required=True,
        choices=['all', 'root-access', 'lcc-scripts', 'iam-roles'],
        help="""The check to perform:
- all: Run all checks.
- root-access: Check for enabled root access on notebook instances.
- lcc-scripts: Scan LCC scripts for suspicious content.
- iam-roles: Analyze IAM roles for risky privesc and LCC management permissions."""
    )
    parser.add_argument(
        '--region',
        help="The AWS region to scan. Defaults to the environment's default region."
    )

    args = parser.parse_args()

    scanner = SageMakerScanner(region=args.region)

    if args.check == 'all' or args.check == 'root-access':
        scanner.check_notebook_root_access()
    if args.check == 'all' or args.check == 'lcc-scripts':
        scanner.check_lcc_scripts()
    if args.check == 'all' or args.check == 'iam-roles':
        scanner.check_sagemaker_roles()

    print(f"\n{colors.OKGREEN}Scan complete.{colors.ENDC}")
