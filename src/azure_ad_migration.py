# Main script for Azure AD user migration and device compliance check.

import logging
import os
import hvac
import requests # Added for Graph API calls
import json # Added for Graph API calls
from datetime import datetime, timedelta, timezone # Added timezone for device activity check

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# --- Configuration (Global, ideally from environment variables populated by Vault/Lambda config) ---
VAULT_ADDR = os.environ.get('VAULT_ADDR')
VAULT_TOKEN = os.environ.get('VAULT_TOKEN') # For local dev
VAULT_SECRET_PATH = os.environ.get('VAULT_SECRET_PATH')
# VAULT_AWS_AUTH_ROLE = os.environ.get('VAULT_AWS_AUTH_ROLE') # Deprioritized in favor of explicit IAM keys
VAULT_ROLE_ID = os.environ.get('VAULT_ROLE_ID')
VAULT_SECRET_ID = os.environ.get('VAULT_SECRET_ID')
VAULT_NAMESPACE = os.environ.get('VAULT_NAMESPACE') # Added
VAULT_KV_MOUNT_POINT = os.environ.get('VAULT_KV_MOUNT_POINT', 'secret') # Added, defaults to 'secret'

# These will be populated from Vault
AZURE_TENANT_ID = None
AZURE_CLIENT_ID = None
AZURE_CLIENT_SECRET = None
AZURE_INITIAL_GROUP_ID = None # Group ID for "SCWX O365 migrated group"
AZURE_MIGRATED_GROUP_ID = None # Group ID for the new group after migration

FRESHSERVICE_DOMAIN = None
FRESHSERVICE_API_KEY = None

DYNAMODB_TABLE_NAME = None
SES_SENDER_EMAIL = None
SES_REGION = None # e.g., us-east-1

# --- End Configuration ---

# --- Global variable for Graph API token ---
graph_api_token_cache = {
    "token": None,
    "expires_at": datetime.now(timezone.utc)
}
# --- End Global variable ---

# --- Azure AD / Microsoft Graph API Functions ---

def get_azure_ad_token():
    """
    Retrieves an Azure AD access token for Microsoft Graph API using client credentials.
    Caches the token until it's about to expire.
    """
    global graph_api_token_cache, AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET

    if not all([AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET]):
        logger.error("Azure AD credentials (Tenant ID, Client ID, Client Secret) are not configured.")
        return None

    # Check cache, refresh if token is missing or expiring within 5 minutes
    if graph_api_token_cache["token"] and graph_api_token_cache["expires_at"] > (datetime.now(timezone.utc) + timedelta(minutes=5)):
        logger.info("Using cached Azure AD token.")
        return graph_api_token_cache["token"]

    token_url = f"https://login.microsoftonline.com/{AZURE_TENANT_ID}/oauth2/v2.0/token"
    payload = {
        'client_id': AZURE_CLIENT_ID,
        'scope': 'https://graph.microsoft.com/.default',
        'client_secret': AZURE_CLIENT_SECRET,
        'grant_type': 'client_credentials'
    }
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    try:
        response = requests.post(token_url, headers=headers, data=payload)
        response.raise_for_status()  # Raise an exception for HTTP errors
        token_data = response.json()

        access_token = token_data.get('access_token')
        expires_in = token_data.get('expires_in', 3599) # Default to just under 1 hour

        graph_api_token_cache["token"] = access_token
        graph_api_token_cache["expires_at"] = datetime.now(timezone.utc) + timedelta(seconds=expires_in)

        logger.info("Successfully obtained new Azure AD token.")
        return access_token
    except requests.exceptions.RequestException as e:
        logger.error(f"Error obtaining Azure AD token: {e}")
        if hasattr(e, 'response') and e.response is not None:
            logger.error(f"Response content: {e.response.text}")
        return None
    except json.JSONDecodeError as e:
        logger.error(f"Error decoding JSON response for Azure AD token: {e}")
        return None

def _graph_api_request(method, endpoint_suffix, params=None, json_payload=None, headers=None):
    """Helper function to make Graph API requests."""
    token = get_azure_ad_token()
    if not token:
        return None

    default_headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }
    if headers:
        default_headers.update(headers)

    url = f"https://graph.microsoft.com/v1.0/{endpoint_suffix}"
    try:
        logger.debug(f"Making Graph API {method} request to {url} with params: {params}, payload: {json_payload}")
        response = requests.request(method, url, headers=default_headers, params=params, json=json_payload)
        response.raise_for_status()

        if response.status_code == 204: # No content, e.g. for DELETE or remove member
            return True
        return response.json()
    except requests.exceptions.HTTPError as e:
        logger.error(f"Graph API HTTP error: {e.response.status_code} for URL: {url}. Response: {e.response.text}")
        return None
    except requests.exceptions.RequestException as e:
        logger.error(f"Graph API request error: {e} for URL: {url}")
        return None
    except json.JSONDecodeError as e:
        logger.error(f"Graph API JSON decode error: {e} for URL: {url}. Response text: {response.text if 'response' in locals() else 'N/A'}")
        return None


def get_users_from_azure_group(group_id):
    """
    Fetches all users (members) from a specified Azure AD group.
    Handles pagination.
    """
    if not group_id:
        logger.error("Azure Group ID not provided for fetching users.")
        return None

    users = []
    endpoint = f"groups/{group_id}/members/microsoft.graph.user" # OData cast to get only user objects
    # Select only necessary fields to reduce payload size and improve performance
    params = {"$select": "id,userPrincipalName,displayName,mail,onPremisesSamAccountName"}

    while endpoint:
        response_data = _graph_api_request("GET", endpoint, params=params if not users else None) # params only for first request
        if not response_data or 'value' not in response_data:
            logger.error(f"Failed to get users from group {group_id} or empty response.")
            break

        users.extend(response_data['value'])
        endpoint = response_data.get('@odata.nextLink') # For pagination
        if endpoint:
            # Remove the base URL part for the next _graph_api_request call
            endpoint = endpoint.replace("https://graph.microsoft.com/v1.0/", "")
            params = None # Clear params for subsequent paginated requests
            logger.info(f"Fetching next page of users for group {group_id}")

    logger.info(f"Found {len(users)} users in Azure AD group {group_id}.")
    return users

def get_user_devices(user_id_or_principal_name):
    """
    Fetches devices registered to a specific user.
    Selects properties relevant for compliance and activity check.
    """
    if not user_id_or_principal_name:
        logger.error("User ID or Principal Name not provided for fetching devices.")
        return None

    # Select specific properties. Add more if needed.
    # approximateLastSignInDateTime is preferred over lastSignInDateTime for accuracy.
    # trustType: 0 (Unknown), 1 (Workplace), 2 (AzureAD), 3 (ServerAD). AzureAD Joined = 2.
    select_fields = "id,deviceId,displayName,operatingSystem,osVersion,isCompliant,isManaged,approximateLastSignInDateTime,trustType,registrationDateTime"
    endpoint = f"users/{user_id_or_principal_name}/ownedDevices" # or /registeredDevices, or /memberOf for device objects
    # To get devices a user is registered owner of:
    # endpoint = f"users/{user_id_or_principal_name}/registereddevices"
    # To get devices a user has signed into (more comprehensive but might be too broad):
    # This requires Directory.Read.All and potentially other permissions.
    # endpoint = f"devices?$filter=userPrincipalName eq '{user_id_or_principal_name}'"
    # For now, let's stick to ownedDevices which is more common for Intune scenarios.
    # If you need devices the user is primary user of, Intune API might be better.
    # ownedDevices includes devices where the user is an owner.
    # registeredDevices includes devices user registered (often same as owned).

    params = {"$select": select_fields}
    response_data = _graph_api_request("GET", endpoint, params=params)

    if response_data and 'value' in response_data:
        logger.info(f"Found {len(response_data['value'])} devices for user {user_id_or_principal_name}.")
        return response_data['value']
    else:
        logger.info(f"No devices found or error for user {user_id_or_principal_name}.")
        return []

def add_user_to_azure_group(user_id, group_id):
    """
    Adds a user to a specified Azure AD group.
    """
    if not user_id or not group_id:
        logger.error("User ID or Group ID not provided for adding user to group.")
        return False

    endpoint = f"groups/{group_id}/members/$ref"
    payload = {
        "@odata.id": f"https://graph.microsoft.com/v1.0/directoryObjects/{user_id}"
    }
    response = _graph_api_request("POST", endpoint, json_payload=payload)
    if response is True: # For 204 No Content on success
        logger.info(f"Successfully added user {user_id} to group {group_id}.")
        return True
    # Handle cases where the user might already be in the group (Graph API often returns 400 Bad Request)
    # A more robust check would be to list members first, but for now, we'll rely on the success/fail of POST.
    # If response is None due to an error, it's already logged by _graph_api_request.
    logger.warning(f"Failed to add user {user_id} to group {group_id}. Response: {response}")
    return False

def remove_user_from_azure_group(user_id, group_id):
    """
    Removes a user from a specified Azure AD group.
    """
    if not user_id or not group_id:
        logger.error("User ID or Group ID not provided for removing user from group.")
        return False

    # The member ID for group operations is the user's object ID.
    endpoint = f"groups/{group_id}/members/{user_id}/$ref"
    response = _graph_api_request("DELETE", endpoint)

    if response is True: # For 204 No Content on success
        logger.info(f"Successfully removed user {user_id} from group {group_id}.")
        return True
    logger.warning(f"Failed to remove user {user_id} from group {group_id}. Response: {response}")
    return False

# --- End Azure AD / Microsoft Graph API Functions ---

# --- Device Compliance and Activity Logic ---

def parse_datetime_string(datetime_str):
    """
    Parses an ISO 8601 datetime string, trying a few common formats.
    Returns a datetime object or None if parsing fails.
    """
    if not datetime_str:
        return None
    try:
        # datetime.fromisoformat handles many ISO 8601 formats, including those with 'Z' and offsets like +00:00
        # If the string ends with 'Z', replace it with '+00:00' for broader compatibility with fromisoformat
        if datetime_str.endswith('Z'):
            datetime_str = datetime_str[:-1] + '+00:00'

        dt = datetime.fromisoformat(datetime_str)
        # Ensure the datetime is UTC if it's naive, or convert to UTC if it has other timezone
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        else:
            return dt.astimezone(timezone.utc)

    except ValueError:
        # Fallback for formats not directly supported by fromisoformat if necessary,
        # or if a specific older format is common in your data.
        # For now, we rely on fromisoformat's capabilities.
        logger.warning(f"Could not parse datetime string: {datetime_str} using fromisoformat.")
        return None

def is_device_compliant_and_active(user_devices, days_active_threshold=7):
    """
    Checks if a user has at least one compliant Windows or macOS device
    that has been active within the specified number of days.

    Args:
        user_devices (list): A list of device dictionaries from Graph API.
        days_active_threshold (int): Number of days for activity check (e.g., 7).

    Returns:
        tuple: (bool, dict|None)
               - True if a compliant and active device is found, False otherwise.
               - The compliant and active device dictionary if found, otherwise None.
    """
    if not user_devices:
        return False, None

    compliant_active_device_found = False
    selected_device_info = None

    # Sort devices: prefer compliant, then more recently active
    # This helps if multiple devices meet criteria, we pick one consistently.
    # However, the requirement is "any one if compliant is fine", so sorting is optional
    # but good for deterministic selection if we needed to pick just one.

    for device in user_devices:
        os = device.get('operatingSystem', '').lower()
        is_compliant = device.get('isCompliant', False)
        # approximateLastSignInDateTime is preferred. Fallback to registrationDateTime if needed,
        # though registrationDateTime is not a sign-in activity.
        # For this use case, we need 'sign-in' activity.
        last_activity_str = device.get('approximateLastSignInDateTime')

        logger.debug(f"Checking device: ID={device.get('deviceId')}, OS={os}, Compliant={is_compliant}, LastSignIn={last_activity_str}")

        if os in ['windows', 'macos', 'mac os x'] and is_compliant: # mac os x is sometimes reported
            if not last_activity_str:
                logger.debug(f"Device {device.get('deviceId')} is compliant but has no approximateLastSignInDateTime. Skipping for activity check.")
                continue

            last_activity_date = parse_datetime_string(last_activity_str)
            if not last_activity_date:
                logger.warning(f"Could not parse last activity date for device {device.get('deviceId')}: {last_activity_str}")
                continue

            # Ensure last_activity_date is offset-aware for comparison with offset-aware datetime.now(timezone.utc)
            # parse_datetime_string should handle making it UTC.

            threshold_date = datetime.now(timezone.utc) - timedelta(days=days_active_threshold)

            if last_activity_date >= threshold_date:
                logger.info(f"Compliant and active device found: Name='{device.get('displayName')}', ID='{device.get('deviceId')}', OS='{os}', LastSignIn='{last_activity_str}'")
                compliant_active_device_found = True
                selected_device_info = device # Return the first one found that matches
                break # Found a suitable device
            else:
                logger.debug(f"Device {device.get('deviceId')} is compliant but last sign-in ({last_activity_date}) is older than threshold ({threshold_date}).")
        else:
            if not (os in ['windows', 'macos', 'mac os x']):
                logger.debug(f"Device {device.get('deviceId')} skipped: OS '{os}' is not Windows or macOS.")
            elif not is_compliant:
                logger.debug(f"Device {device.get('deviceId')} skipped: Not compliant.")


    if compliant_active_device_found and selected_device_info:
        return True, selected_device_info
    else:
        return False, None

# --- End Device Compliance and Activity Logic ---

# --- Freshservice Integration ---

def create_freshservice_ticket(subject, description, email, priority=1, status=2, cc_emails=None):
    """
    Creates a ticket in Freshservice.

    Args:
        subject (str): The subject of the ticket.
        description (str): The HTML description of the ticket.
        email (str): The requester's email address.
        priority (int): Priority of the ticket (1: Low, 2: Medium, 3: High, 4: Urgent).
        status (int): Status of the ticket (2: Open, 3: Pending, 4: Resolved, 5: Closed).
        cc_emails (list, optional): List of email addresses to CC.

    Returns:
        dict: The JSON response from Freshservice API if successful, None otherwise.
    """
    global FRESHSERVICE_DOMAIN, FRESHSERVICE_API_KEY

    if not FRESHSERVICE_DOMAIN or not FRESHSERVICE_API_KEY:
        logger.error("Freshservice domain or API key not configured.")
        return None

    url = f"https://{FRESHSERVICE_DOMAIN}.freshservice.com/api/v2/tickets"

    headers = {
        "Content-Type": "application/json",
    }
    # Freshservice API uses Basic Auth with API key as username and 'X' as password.
    auth = (FRESHSERVICE_API_KEY, "X")

    data = {
        "subject": subject,
        "description": description, # HTML format
        "email": email, # Requester's email
        "priority": priority, # 1:Low, 2:Medium, 3:High, 4:Urgent
        "status": status,     # 2:Open, 3:Pending, 4:Resolved, 5:Closed
    }
    if cc_emails:
        data["cc_emails"] = cc_emails

    try:
        logger.info(f"Creating Freshservice ticket for {email} with subject: {subject}")
        response = requests.post(url, headers=headers, auth=auth, json=data)
        response.raise_for_status() # Raise an exception for HTTP errors 4xx/5xx
        ticket_data = response.json()
        logger.info(f"Successfully created Freshservice ticket ID: {ticket_data.get('ticket',{}).get('id')} for {email}.")
        return ticket_data
    except requests.exceptions.HTTPError as e:
        logger.error(f"HTTP error creating Freshservice ticket: {e.response.status_code} - {e.response.text}")
        return None
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error creating Freshservice ticket: {e}")
        return None
    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error for Freshservice ticket response: {e}")
        return None

# --- End Freshservice Integration ---

# --- AWS SES Integration ---

def send_email_ses(subject, body_html, recipient_emails, sender_email=None, region_name=None, cc_emails=None, bcc_emails=None):
    """
    Sends an email using AWS SES.

    Args:
        subject (str): The subject of the email.
        body_html (str): The HTML body of the email.
        recipient_emails (list or str): A list of recipient email addresses or a single email string.
        sender_email (str, optional): The sender's email address. Defaults to global SES_SENDER_EMAIL.
        region_name (str, optional): AWS region for SES. Defaults to global SES_REGION.
        cc_emails (list or str, optional): CC recipient(s).
        bcc_emails (list or str, optional): BCC recipient(s).

    Returns:
        bool: True if the email was sent successfully, False otherwise.
    """
    global SES_SENDER_EMAIL, SES_REGION

    actual_sender_email = sender_email or SES_SENDER_EMAIL
    actual_region_name = region_name or SES_REGION

    if not actual_sender_email:
        logger.error("SES sender email not configured.")
        return False
    if not actual_region_name:
        logger.error("SES region not configured.")
        return False
    if not recipient_emails:
        logger.error("No recipient emails provided for SES.")
        return False

    if isinstance(recipient_emails, str):
        recipient_emails = [recipient_emails]

    destination = {'ToAddresses': recipient_emails}
    if cc_emails:
        destination['CcAddresses'] = [cc_emails] if isinstance(cc_emails, str) else cc_emails
    if bcc_emails:
        destination['BccAddresses'] = [bcc_emails] if isinstance(bcc_emails, str) else bcc_emails

    try:
        # boto3 will use the Lambda execution role's permissions for SES.
        # Ensure the role has `ses:SendEmail` and `ses:SendRawEmail` permissions.
        import boto3
        ses_client = boto3.client('ses', region_name=actual_region_name)

        response = ses_client.send_email(
            Destination=destination,
            Message={
                'Body': {
                    'Html': {
                        'Charset': 'UTF-8',
                        'Data': body_html,
                    },
                },
                'Subject': {
                    'Charset': 'UTF-8',
                    'Data': subject,
                },
            },
            Source=actual_sender_email,
            # ReplyToAddresses=['reply_address@example.com'], # Optional
        )
        logger.info(f"Email sent via SES to {', '.join(recipient_emails)}. Message ID: {response.get('MessageId')}")
        return True
    except Exception as e:
        logger.error(f"Error sending email via SES: {e}")
        return False

# --- End AWS SES Integration ---

# --- AWS DynamoDB Integration ---

def upsert_user_migration_status(user_id, user_email, status, migration_date_iso=None, compliant_device_id=None, error_message=None, table_name=None, region_name=None):
    """
    Adds or updates a user's migration status in DynamoDB.

    Args:
        user_id (str): The user's Azure AD Object ID (Primary Key).
        user_email (str): The user's email address.
        status (str): Migration status (e.g., "PENDING_COMPLIANCE_CHECK", "READY_TO_MIGRATE",
                                         "NON_COMPLIANT_TICKETED", "MIGRATION_SCHEDULED",
                                         "MIGRATION_COMPLETE", "ERROR").
        migration_date_iso (str, optional): ISO 8601 format string for the scheduled migration date.
        compliant_device_id (str, optional): ID of the compliant device, if applicable.
        error_message (str, optional): Error message if status is "ERROR".
        table_name (str, optional): DynamoDB table name. Defaults to global DYNAMODB_TABLE_NAME.
        region_name (str, optional): AWS region for DynamoDB. Defaults to global SES_REGION (can be different).

    Returns:
        bool: True if the operation was successful, False otherwise.
    """
    global DYNAMODB_TABLE_NAME, SES_REGION # Using SES_REGION as a fallback for DynamoDB region if not specified

    actual_table_name = table_name or DYNAMODB_TABLE_NAME
    actual_region_name = region_name or SES_REGION # Consider a separate DYNAMODB_REGION if different from SES

    if not actual_table_name:
        logger.error("DynamoDB table name not configured.")
        return False
    if not actual_region_name: # Should be set if SES_REGION is set, or explicitly
        logger.error("DynamoDB region not configured.")
        return False

    try:
        import boto3
        # Consider using a specific region for DynamoDB if it's different from SES
        dynamodb_resource = boto3.resource('dynamodb', region_name=actual_region_name)
        table = dynamodb_resource.Table(actual_table_name)

        timestamp = datetime.now(timezone.utc).isoformat()

        item = {
            'user_id': user_id, # Partition Key
            'user_email': user_email,
            'migration_status': status,
            'last_updated_at': timestamp,
        }
        # Optional attributes
        if migration_date_iso:
            item['migration_date'] = migration_date_iso
        if compliant_device_id:
            item['compliant_device_id'] = compliant_device_id
        if error_message:
            item['error_details'] = error_message

        # Using put_item will overwrite the item if it exists, or create it if it doesn't.
        # This serves as an "upsert".
        table.put_item(Item=item)
        logger.info(f"Successfully upserted user {user_id} ({user_email}) with status '{status}' to DynamoDB table {actual_table_name}.")
        return True
    except Exception as e:
        logger.error(f"Error upserting item to DynamoDB for user {user_id}: {e}")
        return False

# --- End AWS DynamoDB Integration ---


def get_vault_secrets(vault_addr=None, token=None, secret_path=None, role_id=None, secret_id=None, vault_namespace_override=None, kv_mount_point_override=None):
    """
    Fetches secrets from HashiCorp Vault.
    Supports AWS IAM (explicit keys), AppRole, and Token authentication methods.

    Args:
        vault_addr (str): URL of the Vault server. Defaults to VAULT_ADDR env var.
        token (str, optional): Vault token for authentication.
        secret_path (str): Path to the secret in Vault. Defaults to VAULT_SECRET_PATH env var.
        role_id (str, optional): RoleID for AppRole authentication.
        secret_id (str, optional): SecretID for AppRole authentication.
        vault_namespace_override (str, optional): Overrides global VAULT_NAMESPACE.
        kv_mount_point_override (str, optional): Overrides global VAULT_KV_MOUNT_POINT.


    Returns:
        dict: A dictionary containing the secrets, or None if an error occurs.
    """
    current_vault_addr = vault_addr or VAULT_ADDR
    current_secret_path = secret_path or VAULT_SECRET_PATH
    current_namespace = vault_namespace_override or VAULT_NAMESPACE
    current_kv_mount_point = kv_mount_point_override or VAULT_KV_MOUNT_POINT


    if not current_vault_addr:
        logger.error("Vault address (VAULT_ADDR) is not configured.")
        return None
    if not current_secret_path:
        logger.error("Vault secret path (VAULT_SECRET_PATH) is not configured.")
        return None
    if not current_namespace:
        logger.error("Vault namespace (VAULT_NAMESPACE) is not configured.")
        return None
    if not current_kv_mount_point:
        logger.error("Vault KV mount point (VAULT_KV_MOUNT_POINT) is not configured.")
        return None

    try:
        client = hvac.Client(url=current_vault_addr, namespace=current_namespace)

        # AWS IAM Authentication using explicit environment variables (primary for Lambda)
        aws_access_key_id = os.environ.get("AWS_ACCESS_KEY_ID")
        aws_secret_access_key = os.environ.get("AWS_SECRET_ACCESS_KEY")
        aws_session_token = os.environ.get("AWS_SESSION_TOKEN")

        if aws_access_key_id and aws_secret_access_key and aws_session_token and os.environ.get('AWS_LAMBDA_FUNCTION_NAME'):
            logger.info("Attempting Vault authentication using AWS IAM credentials from environment.")
            try:
                client.auth.aws.iam_login(
                    access_key=aws_access_key_id,
                    secret_key=aws_secret_access_key,
                    session_token=aws_session_token,
                )
                if client.is_authenticated():
                    logger.info("Successfully authenticated to Vault using AWS IAM credentials.")
                else:
                    logger.error("Vault AWS IAM authentication failed (is_authenticated=False after login call). Trying other methods.")
            except Exception as e:
                logger.error(f"Error during Vault AWS IAM login attempt: {e}. Trying other methods.")

        # Fallback or alternative authentication methods if not already authenticated by IAM
        if not client.is_authenticated():
            current_role_id = role_id or VAULT_ROLE_ID
            current_secret_id = secret_id or VAULT_SECRET_ID
            current_token = token or VAULT_TOKEN

            if current_role_id and current_secret_id:
                logger.info("Attempting Vault authentication using AppRole.")
                client.auth.approle.login(role_id=current_role_id, secret_id=current_secret_id, raise_on_error=True)
                logger.info("Successfully authenticated to Vault using AppRole.")
            elif current_token:
                logger.info("Attempting Vault authentication using Token.")
                client.token = current_token
                if not client.is_authenticated(): # Verify token
                    logger.error("Vault token authentication failed. Token is invalid or expired.")
                    return None # If token auth fails, it's a hard stop for this path.
                logger.info("Successfully authenticated to Vault using Token.")
            else:
                logger.error("No suitable Vault authentication method credentials provided (AWS IAM env vars for Lambda, AppRole, or Token).")
                return None

        if not client.is_authenticated(): # Final check
            logger.error("Vault authentication failed after attempting all configured methods.")
            return None

        logger.info(f"Attempting to read secret from Vault path: '{current_secret_path}' on mount point: '{current_kv_mount_point}'")
        response = client.secrets.kv.v2.read_secret(
            path=current_secret_path,
            mount_point=current_kv_mount_point
        )
        secrets = response['data']['data']
        logger.info(f"Successfully fetched secrets from Vault path: '{current_secret_path}'")
        return secrets

    except hvac.exceptions.VaultError as e:
        logger.error(f"Vault error: {e}")
        return None
    except Exception as e:
        logger.error(f"An unexpected error occurred while fetching secrets from Vault: {e}")
        return None


def lambda_handler(event, context):
    """
    AWS Lambda handler function.
    """
    logger.info("Lambda function execution started.")

    # Fetch credentials from Vault
    # For Lambda, prefer AWS IAM auth. Set VAULT_AWS_AUTH_ROLE environment variable.
    # For local dev, you can set VAULT_TOKEN or VAULT_ROLE_ID and VAULT_SECRET_ID.
    vault_aws_auth_role = os.environ.get('VAULT_AWS_AUTH_ROLE') # e.g., 'lambda-azure-migration'
    vault_role_id = os.environ.get('VAULT_ROLE_ID')
    vault_secret_id = os.environ.get('VAULT_SECRET_ID')

    secrets = get_vault_secrets(
        aws_auth_role=vault_aws_auth_role,
        role_id=vault_role_id,
        secret_id=vault_secret_id
    )

    if not secrets:
        logger.error("Failed to retrieve credentials from Vault. Exiting.")
        return {
            'statusCode': 500,
            'body': 'Error: Could not fetch critical secrets from Vault.'
        }

    logger.info(f"Successfully retrieved secrets. Keys: {list(secrets.keys())}")
    # Example: azure_client_id = secrets.get('AZURE_CLIENT_ID')
    #          freshservice_api_key = secrets.get('FRESHSERVICE_API_KEY')

    # Populate global Azure AD config variables from secrets
    global AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_INITIAL_GROUP_ID, AZURE_MIGRATED_GROUP_ID
    global FRESHSERVICE_DOMAIN, FRESHSERVICE_API_KEY
    global SES_SENDER_EMAIL, SES_REGION
    global DYNAMODB_TABLE_NAME # Added DynamoDB global

    AZURE_TENANT_ID = secrets.get('AZURE_TENANT_ID')
    AZURE_CLIENT_ID = secrets.get('AZURE_CLIENT_ID')
    AZURE_CLIENT_SECRET = secrets.get('AZURE_CLIENT_SECRET')
    AZURE_INITIAL_GROUP_ID = secrets.get('AZURE_INITIAL_GROUP_ID')
    AZURE_MIGRATED_GROUP_ID = secrets.get('AZURE_MIGRATED_GROUP_ID')

    FRESHSERVICE_DOMAIN = secrets.get('FRESHSERVICE_DOMAIN')
    FRESHSERVICE_API_KEY = secrets.get('FRESHSERVICE_API_KEY')

    SES_SENDER_EMAIL = secrets.get('SES_SENDER_EMAIL')
    SES_REGION = secrets.get('SES_REGION') # Also used as default for DynamoDB region

    DYNAMODB_TABLE_NAME = secrets.get('DYNAMODB_TABLE_NAME')


    if not all([AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_INITIAL_GROUP_ID]):
        logger.error("Critical Azure AD configuration missing from Vault secrets (TenantID, ClientID, ClientSecret, InitialGroupID).")
        return {'statusCode': 500, 'body': 'Error: Azure AD configuration incomplete.'}

    # Check DynamoDB config (optional, but good practice)
    # if not DYNAMODB_TABLE_NAME:
    #    logger.warning("DynamoDB table name is missing. Status updates will fail.")
    #    # Potentially return error if this is critical path

    # Check SES config (optional, but good practice)
    # if not all([SES_SENDER_EMAIL, SES_REGION]):
    #     logger.warning("SES configuration (Sender Email, Region) is missing. Email sending will fail.")

    # Check Freshservice config (optional here, but good practice if it's critical for all runs)
    # if not all([FRESHSERVICE_DOMAIN, FRESHSERVICE_API_KEY]):
    #     logger.warning("Freshservice configuration (Domain, API Key) is missing from Vault. Ticket creation will fail.")
        # Depending on requirements, you might choose to return an error here or just log a warning.

    # --- Main Orchestration Logic ---
    logger.info(f"Starting main orchestration. Fetching users from Azure AD Group ID: {AZURE_INITIAL_GROUP_ID}")
    initial_users = get_users_from_azure_group(AZURE_INITIAL_GROUP_ID)

    if initial_users is None: # Indicates an error during Graph API call
        logger.error("Failed to fetch users from the initial Azure AD group. Aborting.")
        return {'statusCode': 500, 'body': 'Error fetching users from Azure AD group.'}

    if not initial_users:
        logger.info("No users found in the initial Azure AD group. Nothing to process.")
        return {'statusCode': 200, 'body': 'No users to process.'}

    logger.info(f"Processing {len(initial_users)} users from group {AZURE_INITIAL_GROUP_ID}.")

    processed_users_count = 0
    compliant_users_count = 0
    non_compliant_ticketed_count = 0
    errors_count = 0

    # Define a fixed migration window/date for this run, e.g., 14 days from now.
    # This could also come from event data or be calculated based on other criteria.
    migration_day_offset = int(os.environ.get("MIGRATION_DAY_OFFSET", 14))
    default_migration_datetime = datetime.now(timezone.utc) + timedelta(days=migration_day_offset)
    default_migration_date_iso = default_migration_datetime.isoformat()
    default_migration_date_display = default_migration_datetime.strftime('%Y-%m-%d')


    for user in initial_users:
        user_id = user.get('id')
        user_upn = user.get('userPrincipalName')
        user_email = user.get('mail')
        user_display_name = user.get('displayName')

        if not all([user_id, user_upn, user_email, user_display_name]):
            logger.warning(f"User data incomplete for an entry, skipping: {user}")
            errors_count +=1
            continue

        logger.info(f"Processing user: {user_display_name} (UPN: {user_upn}, ID: {user_id})")

        # 1. Initial DynamoDB status update (optional, good for tracking)
        upsert_user_migration_status(
            user_id=user_id, user_email=user_email, status="PENDING_COMPLIANCE_CHECK"
        )

        user_devices = get_user_devices(user_id) # Use user_id for consistency
        if user_devices is None: # Error fetching devices
            logger.error(f"Could not fetch devices for user {user_display_name} ({user_upn}). Skipping.")
            upsert_user_migration_status(
                user_id=user_id, user_email=user_email, status="ERROR_FETCHING_DEVICES",
                error_message="Failed to retrieve device list from Graph API."
            )
            errors_count +=1
            continue

        is_compliant, compliant_device = is_device_compliant_and_active(user_devices, days_active_threshold=7)

        if is_compliant and compliant_device:
            logger.info(f"User {user_display_name} IS compliant and active. Device: {compliant_device.get('displayName')}")
            compliant_users_count += 1

            # 5. Send "ready to migrate" email
            email_subject = f"Your Upcoming Migration - Device Ready for {user_display_name}"
            email_body = (
                f"<html><body>"
                f"<p>Hello {user_display_name},</p>"
                f"<p>Good news! Your device (<b>{compliant_device.get('displayName', 'N/A')}</b>, OS: {compliant_device.get('operatingSystem', 'N/A')}) "
                f"has been confirmed as compliant and has shown recent activity.</p>"
                f"<p>You are scheduled to be migrated on or around: <b>{default_migration_date_display}</b>.</p>"
                f"<p>Please ensure your device remains powered on and connected to the network, especially around this date, to facilitate a smooth migration.</p>"
                f"<p>If you have any questions, please contact the IT helpdesk.</p>"
                f"<p>Thank you,<br>IT Department</p>"
                f"</body></html>"
            )
            email_sent = send_email_ses(email_subject, email_body, user_email)

            if email_sent:
                logger.info(f"'Ready to Migrate' email sent to {user_email}.")
                # 6. Add record to DynamoDB
                upsert_user_migration_status(
                    user_id=user_id,
                    user_email=user_email,
                    status="MIGRATION_SCHEDULED_EMAIL_SENT", # More specific status
                    migration_date_iso=default_migration_date_iso,
                    compliant_device_id=compliant_device.get('id')
                )
            else:
                logger.error(f"Failed to send 'Ready to Migrate' email to {user_email}. Recording status without email confirmation.")
                upsert_user_migration_status(
                    user_id=user_id,
                    user_email=user_email,
                    status="MIGRATION_SCHEDULED_EMAIL_FAILED",
                    migration_date_iso=default_migration_date_iso,
                    compliant_device_id=compliant_device.get('id'),
                    error_message="SES email sending failed."
                )
                errors_count +=1

        else: # Not compliant or not active
            logger.info(f"User {user_display_name} is NOT compliant or active. Creating Freshservice ticket.")

            # 3. Create Freshservice ticket
            ticket_subject = f"User Device Non-Compliant/Inactive: {user_display_name} ({user_upn})"
            ticket_description_html = (
                f"<h3>User Device Compliance Issue</h3>"
                f"<p><b>User:</b> {user_display_name}</p>"
                f"<p><b>User Principal Name:</b> {user_upn}</p>"
                f"<p><b>User Email:</b> {user_email}</p>"
                f"<p><b>User ID:</b> {user_id}</p>"
                f"<p><b>Issue:</b> No compliant and recently active (within last 7 days) Windows or macOS device found.</p>"
                f"<h4>Device Details Checked:</h4>"
            )
            if user_devices:
                ticket_description_html += "<ul>"
                for dev in user_devices:
                    ticket_description_html += (
                        f"<li><b>Name:</b> {dev.get('displayName', 'N/A')}<br>"
                        f"&nbsp;&nbsp;<b>OS:</b> {dev.get('operatingSystem', 'N/A')} {dev.get('osVersion', 'N/A')}<br>"
                        f"&nbsp;&nbsp;<b>Compliant:</b> {dev.get('isCompliant', 'N/A')}<br>"
                        f"&nbsp;&nbsp;<b>Managed:</b> {dev.get('isManaged', 'N/A')}<br>"
                        f"&nbsp;&nbsp;<b>Last Sign-In:</b> {dev.get('approximateLastSignInDateTime', 'N/A')}<br>"
                        f"&nbsp;&nbsp;<b>Device ID:</b> {dev.get('deviceId', 'N/A')}</li>"
                    )
                ticket_description_html += "</ul>"
            else:
                ticket_description_html += "<p>No devices found registered to this user in Azure AD.</p>"

            ticket_created = create_freshservice_ticket(
                subject=ticket_subject,
                description=ticket_description_html,
                email=user_email, # Requester email for the ticket
                priority=2, # Medium
                status=2    # Open
            )

            if ticket_created and ticket_created.get('ticket', {}).get('id'):
                logger.info(f"Freshservice ticket created for {user_display_name}. Ticket ID: {ticket_created['ticket']['id']}")
                upsert_user_migration_status(
                    user_id=user_id, user_email=user_email, status="NON_COMPLIANT_TICKET_CREATED",
                    error_message=f"Ticket ID: {ticket_created['ticket']['id']}" # Store ticket ID for reference
                )
                non_compliant_ticketed_count += 1
            else:
                logger.error(f"Failed to create Freshservice ticket for {user_display_name}.")
                upsert_user_migration_status(
                    user_id=user_id, user_email=user_email, status="NON_COMPLIANT_TICKET_FAILED",
                    error_message="Failed to create Freshservice ticket."
                )
                errors_count +=1

        processed_users_count += 1

    summary_message = (
        f"Orchestration complete. Processed {processed_users_count}/{len(initial_users)} users. "
        f"Compliant & Emailed: {compliant_users_count}. "
        f"Non-Compliant & Ticketed: {non_compliant_ticketed_count}. "
        f"Errors: {errors_count}."
    )
    logger.info(summary_message)
    return {'statusCode': 200, 'body': summary_message}
    # --- End Main Orchestration Logic ---

# --- Migration Monitoring and Completion Logic (for a separate, scheduled Lambda) ---

def query_users_ready_for_migration(table_name=None, region_name=None):
    """
    Queries DynamoDB for users whose migration_date is today or in the past
    and whose status indicates they are ready for final migration steps
    (e.g., MIGRATION_SCHEDULED_EMAIL_SENT).

    Args:
        table_name (str, optional): DynamoDB table name. Defaults to global DYNAMODB_TABLE_NAME.
        region_name (str, optional): AWS region. Defaults to global SES_REGION.

    Returns:
        list: A list of user items from DynamoDB that are due for migration.
    """
    global DYNAMODB_TABLE_NAME, SES_REGION
    actual_table_name = table_name or DYNAMODB_TABLE_NAME
    actual_region_name = region_name or SES_REGION

    if not actual_table_name or not actual_region_name:
        logger.error("DynamoDB table name or region not configured for querying.")
        return []

    import boto3
    from boto3.dynamodb.conditions import Key, Attr

    dynamodb = boto3.resource('dynamodb', region_name=actual_region_name)
    table = dynamodb.Table(actual_table_name)

    today_iso = datetime.now(timezone.utc).isoformat()

    users_to_migrate = []
    try:
        # This scan can be inefficient on very large tables.
        # For production, a GSI on migration_status and migration_date would be much better.
        # GSI: PK=migration_status, SK=migration_date
        # Then query GSI where PK='MIGRATION_SCHEDULED_EMAIL_SENT' and SK <= today_iso
        response = table.scan(
            FilterExpression=Attr('migration_status').eq('MIGRATION_SCHEDULED_EMAIL_SENT') & Attr('migration_date').lte(today_iso)
        )
        users_to_migrate.extend(response.get('Items', []))

        # Handle pagination if necessary for scan
        while 'LastEvaluatedKey' in response:
            logger.info("Scanning DynamoDB for more users to migrate...")
            response = table.scan(
                FilterExpression=Attr('migration_status').eq('MIGRATION_SCHEDULED_EMAIL_SENT') & Attr('migration_date').lte(today_iso),
                ExclusiveStartKey=response['LastEvaluatedKey']
            )
            users_to_migrate.extend(response.get('Items', []))

        logger.info(f"Found {len(users_to_migrate)} users due for migration processing.")
        return users_to_migrate
    except Exception as e:
        logger.error(f"Error querying DynamoDB for users ready for migration: {e}")
        return []

def migration_monitor_handler(event, context):
    """
    AWS Lambda handler for the scheduled job that monitors and completes migrations.
    - Queries DynamoDB for users due for migration.
    - Moves users between Azure AD groups.
    - Sends migration complete email.
    - Updates DynamoDB status.
    """
    logger.info("Migration monitor Lambda execution started.")

    # Fetch and set up global configurations (similar to the main lambda_handler)
    # This ensures this handler can run independently.
    vault_aws_auth_role = os.environ.get('VAULT_AWS_AUTH_ROLE')
    vault_role_id = os.environ.get('VAULT_ROLE_ID')
    vault_secret_id = os.environ.get('VAULT_SECRET_ID')
    secrets = get_vault_secrets(
        aws_auth_role=vault_aws_auth_role, role_id=vault_role_id, secret_id=vault_secret_id
    )
    if not secrets:
        logger.error("Failed to retrieve Vault secrets in migration_monitor_handler. Exiting.")
        return {'statusCode': 500, 'body': 'Vault secrets error.'}

    global AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_INITIAL_GROUP_ID, AZURE_MIGRATED_GROUP_ID
    global SES_SENDER_EMAIL, SES_REGION, DYNAMODB_TABLE_NAME

    AZURE_TENANT_ID = secrets.get('AZURE_TENANT_ID')
    AZURE_CLIENT_ID = secrets.get('AZURE_CLIENT_ID')
    AZURE_CLIENT_SECRET = secrets.get('AZURE_CLIENT_SECRET')
    AZURE_INITIAL_GROUP_ID = secrets.get('AZURE_INITIAL_GROUP_ID')
    AZURE_MIGRATED_GROUP_ID = secrets.get('AZURE_MIGRATED_GROUP_ID')
    SES_SENDER_EMAIL = secrets.get('SES_SENDER_EMAIL')
    SES_REGION = secrets.get('SES_REGION')
    DYNAMODB_TABLE_NAME = secrets.get('DYNAMODB_TABLE_NAME')

    if not all([AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_INITIAL_GROUP_ID, AZURE_MIGRATED_GROUP_ID,
                SES_SENDER_EMAIL, SES_REGION, DYNAMODB_TABLE_NAME]):
        logger.error("One or more critical configurations are missing after Vault fetch in migration_monitor_handler.")
        return {'statusCode': 500, 'body': 'Configuration error.'}

    logger.info("Configuration loaded for migration monitor.")

    users_for_final_migration = query_users_ready_for_migration()

    if not users_for_final_migration:
        logger.info("No users currently due for final migration steps.")
        return {'statusCode': 200, 'body': 'No users to process for final migration.'}

    processed_count = 0
    success_count = 0
    error_count = 0

    for user_item in users_for_final_migration:
        user_id = user_item.get('user_id')
        user_email = user_item.get('user_email')
        # user_display_name might not be in DynamoDB item, fetch from Azure if needed for email
        # or ensure it's added to DynamoDB during the initial processing.
        # For simplicity, we'll assume user_email is sufficient for now.

        if not user_id or not user_email:
            logger.warning(f"Skipping item due to missing user_id or user_email: {user_item}")
            error_count +=1
            continue

        logger.info(f"Processing final migration for user ID: {user_id}, Email: {user_email}")
        processed_count += 1

        # 8. Remove user from initial Azure AD group and add to new group
        removed_from_old_group = False
        if AZURE_INITIAL_GROUP_ID:
            removed_from_old_group = remove_user_from_azure_group(user_id, AZURE_INITIAL_GROUP_ID)
            if not removed_from_old_group:
                logger.warning(f"Failed to remove user {user_id} from initial group {AZURE_INITIAL_GROUP_ID}. Continuing with adding to new group.")
                # Decide if this is a critical failure or if you should proceed.

        added_to_new_group = False
        if AZURE_MIGRATED_GROUP_ID:
            added_to_new_group = add_user_to_azure_group(user_id, AZURE_MIGRATED_GROUP_ID)
            if not added_to_new_group:
                logger.error(f"CRITICAL: Failed to add user {user_id} to migrated group {AZURE_MIGRATED_GROUP_ID}.")
                upsert_user_migration_status(
                    user_id=user_id, user_email=user_email, status="ERROR_GROUP_MOVE_FAILED",
                    error_message=f"Failed to add to target group {AZURE_MIGRATED_GROUP_ID}."
                )
                error_count += 1
                continue # Skip email and further processing for this user if adding to new group fails

        # 9. Send migration complete email
        email_subject = "Your Migration is Complete!"
        email_body = (
            f"<html><body>"
            f"<p>Hello,</p>" # Consider fetching displayName if important for email personalization
            f"<p>Your migration process has been successfully completed.</p>"
            f"<p>You have been moved to the new Azure AD group. If you experience any issues, please contact the IT helpdesk.</p>"
            f"<p>Thank you,<br>IT Department</p>"
            f"</body></html>"
        )
        email_sent = send_email_ses(email_subject, email_body, user_email)
        if not email_sent:
            logger.warning(f"Failed to send migration complete email to {user_email} for user {user_id}.")
            # Not critical enough to stop, but log and potentially update DynamoDB with a note.

        # Update DynamoDB status to MIGRATION_COMPLETE
        status_update_payload = {
            "user_id": user_id,
            "user_email": user_email,
            "status": "MIGRATION_COMPLETE"
        }
        if not email_sent:
            status_update_payload["error_message"] = "Migration complete email failed to send."

        upsert_user_migration_status(**status_update_payload)

        logger.info(f"User {user_id} successfully processed for final migration steps.")
        success_count +=1

    summary = f"Migration monitor run complete. Users checked: {len(users_for_final_migration)}. Successfully processed: {success_count}. Errors: {error_count}."
    logger.info(summary)
    return {'statusCode': 200, 'body': summary}


# --- End Migration Monitoring and Completion Logic ---


    # --- Example Usage (for testing, remove/comment out for production) ---
    # if AZURE_INITIAL_GROUP_ID:
    #     test_users = get_users_from_azure_group(AZURE_INITIAL_GROUP_ID)
    #     if test_users and len(test_users) > 0:
    #         first_user = test_users[0]
    #         user_id = first_user.get('id')
    #         user_upn = first_user.get('userPrincipalName')
    #         user_email = first_user.get('mail')
    #         user_display_name = first_user.get('displayName')
    #
    #         if user_id:
    #             devices = get_user_devices(user_id)
    #             is_compliant, compliant_device = is_device_compliant_and_active(devices, days_active_threshold=7)
    #
    #             if not is_compliant:
    #                 logger.info(f"Test: User {user_display_name} ({user_upn}) is NOT compliant/active.")
    #                 if user_email and FRESHSERVICE_DOMAIN and FRESHSERVICE_API_KEY: # Freshservice ticket
    #                     # ... (Freshservice ticket creation code as before) ...
    #                     pass
    #             else: # Compliant and active
    #                 logger.info(f"Test: User {user_display_name} ({user_upn}) IS compliant/active with device: {compliant_device.get('displayName') if compliant_device else 'N/A'}")
    #                 # Example of sending SES email
    #                 if user_email and SES_SENDER_EMAIL and SES_REGION:
    #                     email_subject = "Your Upcoming Migration - Device Ready"
    #                     migration_date_dt = datetime.utcnow() + timedelta(days=14) # Example migration date as datetime
    #                     migration_date_iso_str = migration_date_dt.isoformat()
    #                     email_body = (
    #                         f"<html><body>"
    #                         f"<p>Hello {user_display_name},</p>"
    #                         f"<p>Good news! Your primary device ({compliant_device.get('displayName', 'N/A') if compliant_device else 'device'}) has been confirmed as compliant and active.</p>"
    #                         f"<p>You are scheduled to be migrated on or around: <b>{migration_date_dt.strftime('%Y-%m-%d')}</b>.</p>"
    #                         f"<p>Please ensure your device remains powered on and connected to the network during this period.</p>"
    #                         f"<p>Thank you,<br>IT Department</p>"
    #                         f"</body></html>"
    #                     )
    #                     logger.info(f"Test: Sending 'Ready to Migrate' email to {user_email}")
    #                     email_sent_successfully = send_email_ses(email_subject, email_body, user_email)
    #
    #                     # Example of DynamoDB update
    #                     if email_sent_successfully and DYNAMODB_TABLE_NAME: # Only update DynamoDB if email was sent
    #                         logger.info(f"Test: Upserting user {user_id} to DynamoDB as READY_TO_MIGRATE")
    #                         upsert_user_migration_status(
    #                             user_id=user_id,
    #                             user_email=user_email,
    #                             status="READY_TO_MIGRATE", # Or perhaps "MIGRATION_EMAIL_SENT"
    #                             migration_date_iso=migration_date_iso_str,
    #                             compliant_device_id=compliant_device.get('id') if compliant_device else None
    #                         )
    #                 else:
    #                     logger.warning("Test: Skipping SES email for compliant user due to missing user email or SES config.")
    #
            # Example: Add/Remove (Use with extreme caution)
            # if AZURE_MIGRATED_GROUP_ID and user_id:
            #     logger.info(f"Test: Attempting to add user {user_id} to group {AZURE_MIGRATED_GROUP_ID}")
            #     add_user_to_azure_group(user_to_test, AZURE_MIGRATED_GROUP_ID)
            #     logger.info(f"Test: Attempting to remove user {user_to_test} from group {AZURE_INITIAL_GROUP_ID}")
            #     remove_user_from_azure_group(user_to_test, AZURE_INITIAL_GROUP_ID)
    # --- End Example Usage ---


    # Placeholder response
    return {
        'statusCode': 200,
        'body': 'Successfully fetched secrets. Azure AD functions ready (implementation of migration logic pending).'
    }

if __name__ == "__main__":
    # This block allows local testing of the script, bypassing the Lambda handler.
    # For local testing, you might want to simulate an event and context,
    # or directly call the core logic functions.
    logger.info("Running script locally.")

    # --- FOR LOCAL TESTING OF VAULT ---
    # Ensure VAULT_ADDR is set in your environment.
    #
    # Option 1: Token Auth (set VAULT_TOKEN and VAULT_SECRET_PATH)
    # os.environ['VAULT_TOKEN'] = "your_vault_dev_token"
    # os.environ['VAULT_SECRET_PATH'] = "secret/data/app/azure_migration"
    #
    # Option 2: AppRole Auth (set VAULT_ROLE_ID, VAULT_SECRET_ID, VAULT_SECRET_PATH)
    # os.environ['VAULT_ROLE_ID'] = "your_approle_role_id"
    # os.environ['VAULT_SECRET_ID'] = "your_approle_secret_id"
    # os.environ['VAULT_SECRET_PATH'] = "secret/data/app/azure_migration"
    #
    # Option 3: AWS IAM Auth (if running locally with AWS credentials configured)
    # This is more complex locally and usually tested within Lambda.
    # You'd need to set VAULT_AWS_AUTH_ROLE and ensure your local AWS env is set up.
    # os.environ['VAULT_AWS_AUTH_ROLE'] = "your_iam_auth_role_in_vault"
    # os.environ['VAULT_SECRET_PATH'] = "secret/data/app/azure_migration"

    if not os.environ.get('VAULT_ADDR'):
        print("Please set VAULT_ADDR environment variable for local testing.")
    elif not os.environ.get('VAULT_SECRET_PATH'):
        print("Please set VAULT_SECRET_PATH environment variable for local testing.")
    else:
        print(f"Attempting to fetch secrets for local testing from VAULT_ADDR: {os.environ.get('VAULT_ADDR')} and path {os.environ.get('VAULT_SECRET_PATH')}")

        retrieved_secrets = get_vault_secrets(
            # Provide appropriate auth params for local test if not using global env vars
            # token=os.environ.get('VAULT_TOKEN'),
            # role_id=os.environ.get('VAULT_ROLE_ID'),
            # secret_id=os.environ.get('VAULT_SECRET_ID'),
            # aws_auth_role=os.environ.get('VAULT_AWS_AUTH_ROLE')
        )
        if retrieved_secrets:
            print("Successfully retrieved secrets locally:")
            for key, value in retrieved_secrets.items():
                # Be careful printing sensitive values, even locally.
                print(f"  {key}: {'*' * len(value) if isinstance(value, str) else type(value)}")
        else:
            print("Failed to retrieve secrets locally.")

    # Example of simulating a Lambda call:
    # lambda_handler({}, None)
    pass
