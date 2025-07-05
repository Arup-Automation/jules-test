# Azure AD User Migration & Device Compliance Script

This project contains a Python script designed to automate parts of an Azure AD user migration process based on device compliance. It's intended to be deployed as two AWS Lambda functions.

## Overview

The solution consists of two main processes, implemented as separate Lambda functions:

1.  **Compliance Checker & Initial Processing Lambda (`lambda_handler`)**:
    *   Fetches users from a specified initial Azure AD group.
    *   For each user, checks their owned devices (Windows and macOS) for compliance status and recent sign-in activity (within the last 7 days) using the Microsoft Graph API.
    *   **If a user has no compliant and recently active device**: Creates a ticket in Freshservice with user and device details.
    *   **If a user has a compliant and recently active device**:
        *   Sends an email to the user via AWS SES, informing them they are ready for migration and providing a scheduled migration date.
        *   Records/updates the user's status and scheduled migration date in an AWS DynamoDB table.
    *   This Lambda is typically triggered on a schedule (e.g., daily).

2.  **Migration Monitor & Completion Lambda (`migration_monitor_handler`)**:
    *   Queries the DynamoDB table for users whose scheduled `migration_date` is due (today or in the past) and whose status indicates they are awaiting final migration.
    *   For each due user:
        *   Removes the user from the initial Azure AD group.
        *   Adds the user to a new, specified Azure AD group (target migrated group).
        *   Sends a "Migration Complete" email to the user via AWS SES.
        *   Updates the user's status in DynamoDB to `MIGRATION_COMPLETE`.
    *   This Lambda is also typically triggered on a schedule (e.g., daily, after the compliance checker might have run).

All sensitive credentials and service configurations (API keys, group IDs, domain names, etc.) are managed securely using HashiCorp Vault.

## Core Components

*   **`src/azure_ad_migration.py`**: The main Python script containing all logic.
*   **`requirements.txt`**: Python dependencies (`boto3`, `requests`, `hvac`).
*   **`.github/workflows/deploy.yml`**: GitHub Actions workflow for packaging and deploying the Lambda functions.
*   **`lambda_compliance_checker_env.json` / `lambda_migration_monitor_env.json`**: Template files showing the structure for Lambda environment variables. **Do not commit actual secrets here.**
*   **`tests/`**: Directory containing unit tests.

## Setup and Configuration

### 1. HashiCorp Vault Setup

The script requires secrets to be stored in HashiCorp Vault. You will need to configure a KV v2 secrets engine path (e.g., `secret/data/app/azure_migration_compliance` and `secret/data/app/azure_migration_monitor` or a shared path) with the following keys:

*   `AZURE_TENANT_ID`: Your Azure AD Tenant ID.
*   `AZURE_CLIENT_ID`: Client ID of the Azure AD App Registration.
*   `AZURE_CLIENT_SECRET`: Client Secret of the Azure AD App Registration.
*   `AZURE_INITIAL_GROUP_ID`: Object ID of the source Azure AD group (e.g., "SCWX O365 migrated group").
*   `AZURE_MIGRATED_GROUP_ID`: Object ID of the target Azure AD group for migrated users.
*   `FRESHSERVICE_DOMAIN`: Your Freshservice domain (e.g., `yourcompany`).
*   `FRESHSERVICE_API_KEY`: API Key for Freshservice.
*   `SES_SENDER_EMAIL`: Verified sender email address in AWS SES.
*   `SES_REGION`: AWS Region for SES (e.g., `us-east-1`).
*   `DYNAMODB_TABLE_NAME`: Name of the DynamoDB table for tracking migration status.

**Azure AD App Registration Permissions (Microsoft Graph API - Application type):**
*   `User.Read.All`
*   `GroupMember.Read.All`
*   `GroupMember.ReadWrite.All`
*   `Device.Read.All`

### 2. AWS Lambda Environment Variables

The Lambda functions require the following environment variables to be set:

*   `VAULT_ADDR`: URL of your Vault server (e.g., `https://your-vault.example.com:8200`).
*   `VAULT_NAMESPACE`: The Vault namespace to use.
*   `VAULT_SECRET_PATH`: Path in Vault to the secrets (e.g., `secret/data/app/azure_migration_compliance`). This will be different for each lambda if they use different secret paths.
*   `VAULT_KV_MOUNT_POINT`: The mount point for the KV secrets engine (defaults to `secret` in the script if this variable is not set, but the deploy workflow sets it).
*   `MIGRATION_DAY_OFFSET` (for Compliance Checker Lambda): Number of days from now to schedule the migration (defaults to 14).

**For Vault Authentication (choose one method per Lambda):**

*   **AWS IAM Authentication (Recommended for Lambda):**
    *   The Lambda execution role's temporary credentials (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`) will be automatically used by the script to authenticate against Vault's AWS IAM auth method.
    *   Ensure Vault's AWS auth method is configured to trust the Lambda execution role(s).
*   **AppRole Authentication (Alternative):**
    *   `VAULT_ROLE_ID`: The RoleID for AppRole.
    *   `VAULT_SECRET_ID`: The SecretID for AppRole.

### 3. DynamoDB Table

Create a DynamoDB table with the following primary key:

*   **Partition Key (PK):** `user_id` (String) - User's Azure AD Object ID.

**Suggested Attributes:**
*   `user_email` (String)
*   `migration_status` (String) - e.g., "PENDING\_COMPLIANCE\_CHECK", "MIGRATION\_SCHEDULED\_EMAIL\_SENT", "NON\_COMPLIANT\_TICKET\_CREATED", "MIGRATION\_COMPLETE", "ERROR\_FETCHING\_DEVICES", etc.
*   `last_updated_at` (String) - ISO 8601 timestamp.
*   `migration_date` (String, optional) - Scheduled migration date (ISO 8601).
*   `compliant_device_id` (String, optional)
*   `error_details` (String, optional) - e.g., Freshservice Ticket ID or error messages.

**Recommendation for `migration_monitor_handler` Lambda:**
For efficient querying of users due for migration, create a Global Secondary Index (GSI) on the DynamoDB table:
*   **GSI Partition Key:** `migration_status` (String)
*   **GSI Sort Key:** `migration_date` (String)

### 4. GitHub Actions Secrets for Deployment

The `.github/workflows/deploy.yml` workflow requires the following secrets to be configured in your GitHub repository:

*   `AWS_OIDC_ROLE_ARN`: ARN of the IAM role configured for GitHub OIDC access to your AWS account.
*   `AWS_DEFAULT_REGION`: AWS region for deployment (e.g., `us-east-1`).
*   `LAMBDA_EXECUTION_ROLE_ARN`: ARN of the IAM execution role for the Lambda functions. This role needs permissions for:
    *   CloudWatch Logs (create log group, create log stream, put log events).
    *   AWS SES (ses:SendEmail).
    *   AWS DynamoDB (dynamodb:PutItem, dynamodb:Query, dynamodb:Scan on the specified table).
    *   If using Vault's AWS IAM auth method where the Lambda assumes *another* role that Vault trusts: `sts:AssumeRole` for that target Vault IAM role.
*   `LAMBDA_COMPLIANCE_CHECKER_NAME`: Name for the Compliance Checker Lambda function (e.g., `azure-ad-user-compliance-checker`).
*   `LAMBDA_MIGRATION_MONITOR_NAME`: Name for the Migration Monitor Lambda function (e.g., `azure-ad-user-migration-monitor`).

And for the Lambda environment variables (these will be written into the Lambda configuration by the workflow):
*   `VAULT_ADDR`
*   `VAULT_NAMESPACE`
*   `VAULT_SECRET_PATH_COMPLIANCE` (Vault path for the compliance checker Lambda)
*   `VAULT_SECRET_PATH_MONITOR` (Vault path for the migration monitor Lambda)
*   `VAULT_KV_MOUNT_POINT` (Optional, defaults to `secret` in workflow)
*   `MIGRATION_DAY_OFFSET` (Optional, defaults to `14` in workflow)
    *(If using AppRole for Vault auth, add `VAULT_ROLE_ID_...` and `VAULT_SECRET_ID_...` secrets for each Lambda)*

## Deployment

Deployment is handled via the GitHub Actions workflow in `.github/workflows/deploy.yml`. This workflow will:
1.  Trigger on push to the `main` branch.
2.  Authenticate to AWS using OIDC.
3.  Install Python dependencies.
4.  Package the Lambda deployment zip files (one for each handler).
5.  Update the function code for the two pre-existing Lambda functions.
6.  Update the environment variables for these Lambda functions using values from the `lambda_compliance_checker_env.json` and `lambda_migration_monitor_env.json` files.
    **Security Note:** For production, actual secret values in these JSON files should be placeholders, and the values should be substituted dynamically in the workflow from GitHub Secrets, or the Lambdas should fetch them from AWS Secrets Manager / Parameter Store at runtime. The current workflow uses the JSON files as templates for the `--environment` parameter.

## Running Unit Tests

To run the unit tests locally:
1.  Ensure Python 3.9+ is installed.
2.  Install dependencies: `pip install -r requirements.txt`
3.  Navigate to the project root directory.
4.  Run: `python -m unittest discover -s tests`

This README provides a starting point. You'll likely need to adjust paths, names, and specific configurations to match your environment.
