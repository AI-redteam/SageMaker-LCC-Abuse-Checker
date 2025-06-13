# SageMaker-LCC-Abuse-Checker

# **SageMaker Lifecycle Configuration (LCC) Security Scanner**

A command-line tool to scan your AWS SageMaker environment for common security misconfigurations related to Lifecycle Configurations (LCCs), IAM roles, and instance settings. This tool is designed to be run from within a SageMaker notebook environment to help administrators and security teams proactively identify and remediate potential vulnerabilities.

## **Overview**

SageMaker Lifecycle Configurations are powerful tools for automating notebook environments, but they can also be abused by attackers for persistence, privilege escalation, and data exfiltration. This scanner automates the detection of several key attack vectors and misconfigurations based on known TTPs (Tactics, Techniques, and Procedures).

## **Features**

The scanner performs the following checks:

1. **Notebook Instance Root Access:** Detects SageMaker notebook instances where RootAccess is enabled, which increases the potential impact of a compromise.  
2. **Suspicious LCC Scripts:** Scans the content of all Notebook and Studio LCCs for patterns indicating malicious activity, such as reverse shells, remote code execution, credential theft, and backdoor installation.  
3. **Overly Permissive IAM Roles:** Analyzes the IAM execution roles attached to active notebook instances for high-risk permissions that could lead to privilege escalation or allow an attacker to create malicious LCCs. This includes checking for:  
   * Privilege escalation permissions (e.g., iam:CreateUser, iam:PassRole on \*).  
   * Permissions to create or attach LCCs (e.g., sagemaker:CreateNotebookInstanceLifecycleConfig, sagemaker:UpdateDomain).  
   * Broad wildcard permissions (e.g., iam:\*, sagemaker:\*).

## **Prerequisites**

For the scanner to function correctly, it must be run from an environment with the necessary permissions to describe AWS resources.

### **IAM Permissions**

The SageMaker Execution Role attached to the notebook where you run this script **must** have an IAM policy granting it, at a minimum, the following read-only permissions.
```bash
{  
    "Version": "2012-10-17",  
    "Statement": [  
        {  
            "Effect": "Allow",  
            "Action": [  
                "sagemaker:ListNotebookInstances",  
                "sagemaker:DescribeNotebookInstance",  
                "sagemaker:ListNotebookInstanceLifecycleConfigs",  
                "sagemaker:DescribeNotebookInstanceLifecycleConfig",  
                "sagemaker:ListStudioLifecycleConfigs",  
                "sagemaker:DescribeStudioLifecycleConfig",  
                "iam:ListAttachedRolePolicies",  
                "iam:ListRolePolicies",  
                "iam:GetPolicy",  
                "iam:GetPolicyVersion",  
                "iam:GetRolePolicy"  
            ],  
            "Resource": "*"  
        }  
    ]  
}
```
Without these permissions, the script will fail with AccessDenied errors.

### **Python Environment**

The script uses the boto3 library, which comes pre-installed in standard AWS SageMaker environments. No additional package installation is required.

## **How to Use**

1. **Upload the Script:** Upload the sagemaker\_security\_scanner.py file to your SageMaker notebook environment.  
2. **Open a Terminal or Notebook:** You can run the script from a terminal within JupyterLab or directly from a notebook cell using the \! magic command.  
3. **Run the Scanner:** Execute the script with the desired check.

### **Examples**

**To run all checks:**
```bash
!python sagemaker_security_scanner.py --check all
```
**To check only for risky IAM roles in the us-east-1 region:**
```bash
!python sagemaker_security_scanner.py --check iam-roles --region us-east-1
```
**To scan LCC scripts for suspicious content:**
```bash
!python sagemaker_security_scanner.py --check lcc-scripts
```
## **Interpreting the Output**

The tool provides color-coded output to help you quickly identify issues:

* **\[INFO\]**: General information or confirmation that no issues were found in a specific check.  
* **\[WARN\]**: A potential security misconfiguration was detected. This requires review but may not be an immediate compromise.  
* **\[CRITICAL\]**: A high-risk issue was found, such as a script containing a reverse shell pattern or an IAM role with administrative privileges. These findings should be investigated immediately.

For each finding, a clear **Remediation** suggestion is provided to help you secure your environment.

## **Disclaimer**

This tool is intended for security auditing and educational purposes. Use it responsibly in environments you are authorized to assess. The detection patterns are based on common techniques and may produce false positives or miss novel threats. Always perform a manual review of critical findings.
