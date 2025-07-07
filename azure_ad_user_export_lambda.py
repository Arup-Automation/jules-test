import os
import json
import pandas as pd
from azure.identity import ClientSecretCredential
from msgraph import GraphServiceClient
from msgraph.generated.users.users_request_builder import UsersRequestBuilder
from msgraph.generated.models.o_data_errors.o_data_error import ODataError

# Configuration: Read from environment variables
CLIENT_ID = os.environ.get("AZURE_CLIENT_ID")
CLIENT_SECRET = os.environ.get("AZURE_CLIENT_SECRET")
TENANT_ID = os.environ.get("AZURE_TENANT_ID")

# Define the scopes required for the Microsoft Graph API
SCOPES = ['https://graph.microsoft.com/.default']

# Define the path for the output Excel file in Lambda's temporary directory
EXCEL_FILE_PATH = "/tmp/active_azure_ad_users.xlsx"

def lambda_handler(event, context):
    """
    AWS Lambda handler function to retrieve active users from Azure AD
    and save them to an Excel file.
    """
    if not all([CLIENT_ID, CLIENT_SECRET, TENANT_ID]):
        return {
            "statusCode": 400,
            "body": json.dumps({
                "error": "Missing Azure AD credentials in environment variables (AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID)"
            })
        }

    try:
        # Create a credential object
        credential = ClientSecretCredential(
            tenant_id=TENANT_ID,
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET
        )

        # Create a GraphServiceClient
        graph_client = GraphServiceClient(credentials=credential, scopes=SCOPES)

        active_users_data = []

        # Define query parameters
        # Select specific fields and filter for active users
        query_params = UsersRequestBuilder.UsersRequestBuilderGetQueryParameters(
            select=["id", "displayName", "userPrincipalName", "mail", "accountEnabled"],
            filter="accountEnabled eq true",
            count=True, # Request a count of items
            top=999 # Max page size
        )

        request_configuration = UsersRequestBuilder.UsersRequestBuilderGetRequestConfiguration(
            query_parameters=query_params,
            headers={"ConsistencyLevel": "eventual"} # Required for count and advanced queries
        )

        # Initial request to get users
        users_response = graph_client.users.get(request_configuration=request_configuration)

        if users_response and users_response.value:
            for user in users_response.value:
                active_users_data.append({
                    "ID": user.id,
                    "DisplayName": user.display_name,
                    "UserPrincipalName": user.user_principal_name,
                    "Mail": user.mail,
                    "AccountEnabled": user.account_enabled
                })

            # Handle pagination if there are more users
            next_page_request = users_response.odata_next_link
            while next_page_request:
                # The SDK handles constructing the next page request from the odata_next_link
                users_response = graph_client.users.with_url(next_page_request).get()
                if users_response and users_response.value:
                    for user in users_response.value:
                        active_users_data.append({
                            "ID": user.id,
                            "DisplayName": user.display_name,
                            "UserPrincipalName": user.user_principal_name,
                            "Mail": user.mail,
                            "AccountEnabled": user.account_enabled
                        })
                    next_page_request = users_response.odata_next_link
                else:
                    next_page_request = None

        if not active_users_data:
            return {
                "statusCode": 200,
                "body": json.dumps({"message": "No active users found."})
            }

        # Convert to Pandas DataFrame
        df = pd.DataFrame(active_users_data)

        # Save to Excel
        df.to_excel(EXCEL_FILE_PATH, index=False, engine='openpyxl')

        return {
            "statusCode": 200,
            "body": json.dumps({
                "message": f"Successfully retrieved {len(active_users_data)} active users and saved to {EXCEL_FILE_PATH}",
                "filePath": EXCEL_FILE_PATH
            })
        }

    except ODataError as odata_error:
        error_details = "Unknown OData error"
        if odata_error.error:
            error_details = f"{odata_error.error.code} - {odata_error.error.message}"
        return {
            "statusCode": 500,
            "body": json.dumps({
                "error": "Microsoft Graph API error",
                "details": error_details
            })
        }
    except Exception as e:
        return {
            "statusCode": 500,
            "body": json.dumps({
                "error": "An unexpected error occurred",
                "details": str(e)
            })
        }

if __name__ == "__main__":
    # For local testing (ensure environment variables are set)
    # Example:
    # export AZURE_CLIENT_ID="your-client-id"
    # export AZURE_CLIENT_SECRET="your-client-secret"
    # export AZURE_TENANT_ID="your-tenant-id"

    if not all([os.environ.get("AZURE_CLIENT_ID"), os.environ.get("AZURE_CLIENT_SECRET"), os.environ.get("AZURE_TENANT_ID")]):
        print("Please set AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, and AZURE_TENANT_ID environment variables for local testing.")
    else:
        print("Simulating Lambda execution locally...")
        event = {}
        context = {}
        result = lambda_handler(event, context)
        print("\nLambda Result:")
        print(json.dumps(result, indent=2))

        if result.get("statusCode") == 200 and result.get("body"):
            body_json = json.loads(result["body"])
            if body_json.get("filePath") and os.path.exists(body_json["filePath"]):
                print(f"\nExcel file created at: {body_json['filePath']}")
            elif "No active users found" in body_json.get("message", ""):
                 print("\nNo active users were found to create an Excel file.")
            else:
                print("\nExcel file was not created or path not found in response.")
        else:
            print("\nLambda execution failed or did not produce an Excel file.")
