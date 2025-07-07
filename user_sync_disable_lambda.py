import os
import json
import requests
from requests.auth import HTTPBasicAuth
from azure.identity import ClientSecretCredential
from msgraph import GraphServiceClient
from msgraph.generated.users.users_request_builder import UsersRequestBuilder
from msgraph.generated.models.o_data_errors.o_data_error import ODataError

# --- Environment Variables ---
# Microsoft Graph API Configuration
MSGRAPH_CLIENT_ID = os.environ.get("MSGRAPH_CLIENT_ID")
MSGRAPH_CLIENT_SECRET = os.environ.get("MSGRAPH_CLIENT_SECRET") # Use Secrets Manager in production
MSGRAPH_TENANT_ID = os.environ.get("MSGRAPH_TENANT_ID")
MSGRAPH_USER_IDENTIFIER_FIELD = "employeeId" # As specified by user

# Saviynt Configuration
SAVIYNT_BASE_URL = os.environ.get("SAVIYNT_BASE_URL") # e.g., https://your.saviyntcloud.com/saviynt
SAVIYNT_USERNAME = os.environ.get("SAVIYNT_USERNAME") # Use Secrets Manager
SAVIYNT_PASSWORD = os.environ.get("SAVIYNT_PASSWORD") # Use Secrets Manager

# Saviynt API Endpoint & Field Configuration (Based on user input and common patterns)
# User confirmed "/users" and filtering on employeeId is okay.
# Assuming Saviynt filter syntax is like OData or a common query param.
# This might need adjustment based on actual Saviynt capabilities.
SAVIYNT_USER_SEARCH_ENDPOINT_TEMPLATE = "/api/v5/user?filter=employeeid eq '{identifier_value}'"
# User confirmed "/users/{saviynt_user_id}" for update with PATCH
SAVIYNT_USER_UPDATE_ENDPOINT_TEMPLATE = "/api/v5/user/{saviynt_user_id}"
SAVIYNT_USER_ID_FIELD_IN_RESPONSE = "id" # Field name in Saviynt's GET user response that holds the user's Saviynt ID
SAVIYNT_STATUS_FIELD = "accountstatus" # Field name in Saviynt for status
SAVIYNT_ACTIVE_STATUS_VALUE = "1"     # Value for active user in Saviynt
SAVIYNT_DISABLE_STATUS_VALUE = "0"    # Value to set for disabling a user in Saviynt
# Constructing the payload for disabling. Assuming only accountStatus needs to be changed.
# If other fields are mandatory in PATCH, this template needs to be adjusted.
SAVIYNT_DISABLE_PAYLOAD_TEMPLATE = json.dumps({SAVIYNT_STATUS_FIELD: SAVIYNT_DISABLE_STATUS_VALUE})


# --- Helper Functions ---
def validate_env_vars():
    """Validates that all necessary environment variables are set."""
    required = [
        "MSGRAPH_CLIENT_ID", "MSGRAPH_CLIENT_SECRET", "MSGRAPH_TENANT_ID",
        "SAVIYNT_BASE_URL", "SAVIYNT_USERNAME", "SAVIYNT_PASSWORD"
    ]
    missing = [var for var in required if not globals().get(var)]
    if missing:
        return f"Missing environment variables: {', '.join(missing)}"
    return None

def get_graph_service_client():
    """Initializes and returns a GraphServiceClient."""
    credential = ClientSecretCredential(
        tenant_id=MSGRAPH_TENANT_ID,
        client_id=MSGRAPH_CLIENT_ID,
        client_secret=MSGRAPH_CLIENT_SECRET
    )
    return GraphServiceClient(credentials=credential, scopes=['https://graph.microsoft.com/.default'])

def get_disabled_users_from_graph(graph_client):
    """Fetches users from Microsoft Graph where accountEnabled is false."""
    print("Fetching disabled users from Microsoft Graph API...")

    query_params = UsersRequestBuilder.UsersRequestBuilderGetQueryParameters(
        filter="accountEnabled eq false",
        select=["id", "userPrincipalName", "mail", MSGRAPH_USER_IDENTIFIER_FIELD], # Ensure employeeId is selected
        count=True,
        top=100 # Adjust page size as needed
    )
    request_configuration = UsersRequestBuilder.UsersRequestBuilderGetRequestConfiguration(
        query_parameters=query_params,
        headers={"ConsistencyLevel": "eventual"}
    )

    disabled_users = []
    try:
        response = graph_client.users.get(request_configuration=request_configuration)
        while response:
            if response.value:
                for user in response.value:
                    identifier = getattr(user, MSGRAPH_USER_IDENTIFIER_FIELD, None)
                    if identifier: # Only process users who have the specified identifier
                        disabled_users.append({
                            "graph_id": user.id,
                            "userPrincipalName": user.user_principal_name,
                            "mail": user.mail,
                            MSGRAPH_USER_IDENTIFIER_FIELD: identifier
                        })
                    else:
                        print(f"User {user.user_principal_name or user.id} skipped: missing {MSGRAPH_USER_IDENTIFIER_FIELD}.")

            if response.odata_next_link:
                response = graph_client.users.with_url(response.odata_next_link).get()
            else:
                response = None

        print(f"Found {len(disabled_users)} disabled users in Graph with {MSGRAPH_USER_IDENTIFIER_FIELD}.")
        return disabled_users
    except ODataError as o_data_error:
        error_details = "Unknown OData error"
        if o_data_error.error:
            error_details = f"{o_data_error.error.code} - {o_data_error.error.message}"
        print(f"Microsoft Graph API error: {error_details}")
        raise Exception(f"Graph API error: {error_details}")
    except Exception as e:
        print(f"Unexpected error fetching users from Graph: {str(e)}")
        raise

def find_saviynt_user(identifier_value):
    """Finds a user in Saviynt by the specified identifier_value (employeeId from Graph)."""
    if not identifier_value:
        print("Skipping Saviynt search: identifier_value is missing.")
        return None

    search_url = f"{SAVIYNT_BASE_URL.rstrip('/')}{SAVIYNT_USER_SEARCH_ENDPOINT_TEMPLATE.format(identifier_value=identifier_value)}"
    print(f"Searching Saviynt for user with {MSGRAPH_USER_IDENTIFIER_FIELD} '{identifier_value}' at {search_url}")

    try:
        response = requests.get(
            search_url,
            auth=HTTPBasicAuth(SAVIYNT_USERNAME, SAVIYNT_PASSWORD),
            headers={"Accept": "application/json"},
            timeout=15
        )
        response.raise_for_status()
        users_found = response.json()

        # Saviynt search might return a list, even if filtering for a unique ID.
        # Or it might return a specific structure. This part needs to adapt to Saviynt's response.
        # Assuming it returns a list of users, or an object containing a list e.g. {"users": [...] } or {"response": [...] }

        actual_users_list = []
        if isinstance(users_found, list): # Direct list of users
            actual_users_list = users_found
        elif isinstance(users_found, dict): # Object containing list
            if "users" in users_found and isinstance(users_found["users"], list):
                actual_users_list = users_found["users"]
            elif "response" in users_found and isinstance(users_found["response"], list): # Common in Saviynt
                actual_users_list = users_found["response"]
            # Add other common Saviynt response structures if known

        if not actual_users_list:
            print(f"User with {MSGRAPH_USER_IDENTIFIER_FIELD} '{identifier_value}' not found in Saviynt.")
            return None
        if len(actual_users_list) > 1:
            print(f"Warning: Found {len(actual_users_list)} users in Saviynt for {MSGRAPH_USER_IDENTIFIER_FIELD} '{identifier_value}'. Using the first one.")

        saviynt_user = actual_users_list[0] # Take the first match
        user_id = saviynt_user.get(SAVIYNT_USER_ID_FIELD_IN_RESPONSE)
        current_status = str(saviynt_user.get(SAVIYNT_STATUS_FIELD, "")).strip() # Ensure string for comparison

        if not user_id:
            print(f"Saviynt user found but missing '{SAVIYNT_USER_ID_FIELD_IN_RESPONSE}'. Cannot proceed with disable.")
            return None

        print(f"Found Saviynt user: ID '{user_id}', Status '{current_status}'")
        return {"id": user_id, "status": current_status, "details": saviynt_user}

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404: # Not found is not an error in this context
            print(f"User with {MSGRAPH_USER_IDENTIFIER_FIELD} '{identifier_value}' not found in Saviynt (404).")
            return None
        print(f"Saviynt API HTTP error during user search: {e.response.status_code} - {e.response.text}")
        raise Exception(f"Saviynt API search error: {e.response.status_code}")
    except Exception as e:
        print(f"Error finding Saviynt user: {str(e)}")
        raise

def disable_saviynt_user(saviynt_user_id):
    """Disables a user in Saviynt by setting their accountStatus."""
    update_url = f"{SAVIYNT_BASE_URL.rstrip('/')}{SAVIYNT_USER_UPDATE_ENDPOINT_TEMPLATE.format(saviynt_user_id=saviynt_user_id)}"
    payload = json.loads(SAVIYNT_DISABLE_PAYLOAD_TEMPLATE) # Convert template string to dict

    print(f"Disabling Saviynt user ID '{saviynt_user_id}' at {update_url} with payload: {payload}")

    try:
        response = requests.patch( # Assuming PATCH, could be PUT
            update_url,
            json=payload,
            auth=HTTPBasicAuth(SAVIYNT_USERNAME, SAVIYNT_PASSWORD),
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            timeout=15
        )
        response.raise_for_status()
        print(f"Successfully disabled Saviynt user ID '{saviynt_user_id}'. Status: {response.status_code}")
        return True
    except requests.exceptions.HTTPError as e:
        print(f"Saviynt API HTTP error during user disable: {e.response.status_code} - {e.response.text}")
        raise Exception(f"Saviynt API disable error: {e.response.status_code}")
    except Exception as e:
        print(f"Error disabling Saviynt user {saviynt_user_id}: {str(e)}")
        raise

# --- Lambda Handler ---
def lambda_handler(event, context):
    env_check = validate_env_vars()
    if env_check:
        print(f"Configuration error: {env_check}")
        return {"statusCode": 400, "body": json.dumps({"error": env_check})}

    print("Starting Saviynt user disable sync process...")
    actions_summary = {
        "graph_users_checked": 0,
        "saviynt_users_found_active": 0,
        "saviynt_users_disabled_success": 0,
        "saviynt_users_already_disabled": 0,
        "saviynt_users_not_found": 0,
        "errors": []
    }

    try:
        graph_client = get_graph_service_client()
        disabled_graph_users = get_disabled_users_from_graph(graph_client)
        actions_summary["graph_users_checked"] = len(disabled_graph_users)

        if not disabled_graph_users:
            print("No disabled users found in Graph to process.")
            return {
                "statusCode": 200,
                "body": json.dumps({"message": "No disabled users found in Graph to process.", "summary": actions_summary})
            }

        for graph_user in disabled_graph_users:
            graph_user_identifier_value = graph_user.get(MSGRAPH_USER_IDENTIFIER_FIELD)
            if not graph_user_identifier_value:
                print(f"Skipping Graph user {graph_user.get('userPrincipalName')} - missing identifier '{MSGRAPH_USER_IDENTIFIER_FIELD}'.")
                actions_summary["errors"].append(f"Graph user {graph_user.get('userPrincipalName')} missing {MSGRAPH_USER_IDENTIFIER_FIELD}")
                continue

            print(f"\nProcessing Graph user: UPN='{graph_user.get('userPrincipalName')}', {MSGRAPH_USER_IDENTIFIER_FIELD}='{graph_user_identifier_value}'")

            try:
                saviynt_user_info = find_saviynt_user(graph_user_identifier_value)

                if saviynt_user_info:
                    saviynt_id = saviynt_user_info["id"]
                    saviynt_status = saviynt_user_info["status"]

                    if saviynt_status == SAVIYNT_ACTIVE_STATUS_VALUE:
                        print(f"Saviynt user {saviynt_id} is ACTIVE. Attempting to disable.")
                        actions_summary["saviynt_users_found_active"] += 1
                        if disable_saviynt_user(saviynt_id):
                            actions_summary["saviynt_users_disabled_success"] += 1
                    elif saviynt_status == SAVIYNT_DISABLE_STATUS_VALUE:
                        print(f"Saviynt user {saviynt_id} is already disabled (Status: {saviynt_status}). No action needed.")
                        actions_summary["saviynt_users_already_disabled"] += 1
                    else:
                        print(f"Saviynt user {saviynt_id} has an unknown status '{saviynt_status}'. No action taken.")
                        actions_summary["errors"].append(f"Saviynt user {saviynt_id} (Graph {MSGRAPH_USER_IDENTIFIER_FIELD}: {graph_user_identifier_value}) has unknown status: {saviynt_status}")
                else:
                    print(f"User with {MSGRAPH_USER_IDENTIFIER_FIELD} '{graph_user_identifier_value}' not found or error during search in Saviynt.")
                    actions_summary["saviynt_users_not_found"] += 1

            except Exception as user_proc_error:
                err_msg = f"Failed to process user {graph_user_identifier_value} in Saviynt: {str(user_proc_error)}"
                print(err_msg)
                actions_summary["errors"].append(err_msg)
                # Continue to the next user

    except Exception as e:
        # Catch critical errors like Graph client init or initial Graph search failure
        crit_err_msg = f"A critical error occurred: {str(e)}"
        print(crit_err_msg)
        actions_summary["errors"].append(crit_err_msg)
        return {
            "statusCode": 500,
            "body": json.dumps({"error": "Critical failure in Lambda execution.", "details": str(e), "summary": actions_summary})
        }

    final_message = f"Saviynt user disable sync process completed. Summary: {json.dumps(actions_summary)}"
    print(final_message)

    status_code = 200
    if actions_summary["errors"]:
        status_code = 207 # Multi-Status if there were partial successes/failures

    return {
        "statusCode": status_code,
        "body": json.dumps({"message": "Process completed.", "summary": actions_summary})
    }


if __name__ == "__main__":
    # --- For Local Testing ---
    # Set environment variables:
    # MSGRAPH_CLIENT_ID, MSGRAPH_CLIENT_SECRET, MSGRAPH_TENANT_ID
    # SAVIYNT_BASE_URL, SAVIYNT_USERNAME, SAVIYNT_PASSWORD

    print("--- Simulating Local Lambda Execution for User Sync Disable ---")
    if not all([MSGRAPH_CLIENT_ID, SAVIYNT_BASE_URL]): # Basic check
        print("Please set all required MSGRAPH_* and SAVIYNT_* environment variables for local testing.")
    else:
        mock_event = {}
        mock_context = {}
        result = lambda_handler(mock_event, mock_context)
        print("\n--- Lambda Result ---")
        print(json.dumps(result, indent=2))
    print("--- End Local Simulation ---")
