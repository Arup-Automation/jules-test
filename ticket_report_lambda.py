import os
import json
import pandas as pd
import requests
from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta
from jira import JIRA

# --- Environment Variables ---
# General
TARGET_EMAIL = os.environ.get("TARGET_EMAIL") # Used for Jira assignee and FS requester

# Jira
JIRA_URL = os.environ.get("JIRA_URL") # e.g., "https://your-domain.atlassian.net"
JIRA_USER_EMAIL = os.environ.get("JIRA_USER_EMAIL") # Email of the user for API auth
JIRA_API_TOKEN = os.environ.get("JIRA_API_TOKEN")

# Freshservice
FRESHSERVICE_DOMAIN = os.environ.get("FRESHSERVICE_DOMAIN") # e.g., "your-domain.freshservice.com"
FRESHSERVICE_API_KEY = os.environ.get("FRESHSERVICE_API_KEY")

# --- Constants ---
JIRA_COMPLETED_STATUS = "Done"
# Freshservice status for "Closed" is typically 5. Resolved is 4.
# We'll assume "Done" implies "Closed" for Freshservice.
FRESHSERVICE_COMPLETED_STATUS_ID = 5
EXCEL_FILE_PATH = "/tmp/ticket_report.xlsx"

def validate_env_vars():
    """Checks if all required environment variables are set."""
    required_vars = {
        "TARGET_EMAIL": TARGET_EMAIL,
        "JIRA_URL": JIRA_URL,
        "JIRA_USER_EMAIL": JIRA_USER_EMAIL,
        "JIRA_API_TOKEN": JIRA_API_TOKEN,
        "FRESHSERVICE_DOMAIN": FRESHSERVICE_DOMAIN,
        "FRESHSERVICE_API_KEY": FRESHSERVICE_API_KEY
    }
    missing_vars = [name for name, value in required_vars.items() if not value]
    if missing_vars:
        return f"Missing environment variables: {', '.join(missing_vars)}"
    return None

def fetch_jira_tickets():
    """Fetches last 10 completed Jira tickets assigned to TARGET_EMAIL."""
    print(f"Fetching Jira tickets for {TARGET_EMAIL} with status '{JIRA_COMPLETED_STATUS}' from {JIRA_URL}")
    try:
        jira_client = JIRA(
            server=JIRA_URL,
            basic_auth=(JIRA_USER_EMAIL, JIRA_API_TOKEN)
        )

        # JQL to find tickets assigned to the target email, with "Done" status, ordered by last updated
        jql_query = f'assignee = "{TARGET_EMAIL}" AND status = "{JIRA_COMPLETED_STATUS}" ORDER BY updated DESC'

        issues = jira_client.search_issues(jql_query, maxResults=10)

        jira_data = []
        for issue in issues:
            jira_data.append({
                "Key": issue.key,
                "Summary": issue.fields.summary,
                "Status": issue.fields.status.name,
                "Assignee": issue.fields.assignee.displayName if issue.fields.assignee else "N/A",
                "Reporter": issue.fields.reporter.displayName if issue.fields.reporter else "N/A",
                "Created": issue.fields.created,
                "Updated": issue.fields.updated,
                "Resolved": issue.fields.resolutiondate
            })
        print(f"Successfully fetched {len(jira_data)} Jira tickets.")
        return jira_data
    except Exception as e:
        print(f"Error fetching Jira tickets: {str(e)}")
        raise Exception(f"Jira API Error: {str(e)}")


def fetch_freshservice_tickets():
    """
    Fetches Freshservice tickets for TARGET_EMAIL (as requester)
    that were completed (status ID 5) in the last 1 month.
    """
    print(f"Fetching Freshservice tickets for requester {TARGET_EMAIL} completed in the last month from {FRESHSERVICE_DOMAIN}")
    fs_url = f"https://{FRESHSERVICE_DOMAIN}/api/v2/tickets"

    # Calculate "one month ago"
    one_month_ago = datetime.utcnow() - relativedelta(months=1)
    # Freshservice API expects timestamps in ISO 8601 format, UTC
    # Example: updated_since='2023-09-15T10:00:00Z'
    # For "completed in last 1 month", we can check `updated_at` or `resolved_at`
    # Let's use `updated_at` for tickets that might have been updated after closing.
    # A more precise filter might be `resolved_at` or `closed_at` if available and desired.
    # The Freshservice API v2 uses `updated_since` which checks `updated_at`.
    # To filter by "completed in the last month", we need to fetch tickets updated in the last month
    # and then filter them by status and potentially resolution/closed date locally if API doesn't support it precisely.
    # Let's try filtering by status and `updated_since` first.

    query_params = {
        "email": TARGET_EMAIL, # This filters by requester's email
        "updated_since": one_month_ago.strftime('%Y-%m-%dT%H:%M:%SZ'),
        "status": FRESHSERVICE_COMPLETED_STATUS_ID, # Filter by completed status
        "per_page": 100 # Max items per page
    }

    headers = {
        "Content-Type": "application/json",
    }
    auth = (FRESHSERVICE_API_KEY, "X") # API key, password 'X'

    all_fs_tickets = []
    page = 1

    try:
        while True:
            query_params["page"] = page
            print(f"Fetching Freshservice tickets page {page} with params: {query_params}")
            response = requests.get(fs_url, headers=headers, params=query_params, auth=auth)
            response.raise_for_status() # Raises an exception for bad status codes

            data = response.json()
            tickets_on_page = data.get("tickets", [])

            if not tickets_on_page:
                break # No more tickets

            for ticket in tickets_on_page:
                # Ensure the ticket was indeed resolved/closed in the last month
                # The `updated_since` filter is on `updated_at`. A ticket could be updated for other reasons.
                # Let's check `resolved_at` or `closed_at`.
                resolved_at_str = ticket.get("resolved_at")
                closed_at_str = ticket.get("closed_at")

                ticket_completion_date_str = resolved_at_str or closed_at_str

                if ticket_completion_date_str:
                    # Freshservice dates are like "2023-10-26T10:00:00Z"
                    ticket_completion_date = datetime.strptime(ticket_completion_date_str, "%Y-%m-%dT%H:%M:%SZ")
                    if ticket_completion_date >= one_month_ago:
                        all_fs_tickets.append({
                            "ID": ticket.get("id"),
                            "Subject": ticket.get("subject"),
                            "Status": ticket.get("status"), # This will be the numeric status
                            "Status Name": map_fs_status_id_to_name(ticket.get("status")), # Helper for readability
                            "Requester ID": ticket.get("requester_id"),
                            "Created At": ticket.get("created_at"),
                            "Updated At": ticket.get("updated_at"),
                            "Resolved At": resolved_at_str,
                            "Closed At": closed_at_str,
                            "Source": ticket.get("source")
                        })

            # Freshservice API v2 doesn't use Link headers for pagination in the same way as v1 for some endpoints.
            # It relies on incrementing page numbers until an empty list is returned.
            # If 'tickets' key is missing or list is empty, assume end of results.
            if len(tickets_on_page) < query_params["per_page"]: # Last page
                break
            page += 1
            if page > 10: # Safety break for pagination, adjust if needed
                print("Warning: Exceeded 10 pages for Freshservice tickets. Stopping.")
                break

        print(f"Successfully fetched {len(all_fs_tickets)} Freshservice tickets matching criteria.")
        return all_fs_tickets
    except requests.exceptions.HTTPError as e:
        print(f"HTTP Error fetching Freshservice tickets: {e.response.status_code} - {e.response.text}")
        raise Exception(f"Freshservice API HTTP Error: {e.response.status_code} - {e.response.text}")
    except Exception as e:
        print(f"Error fetching Freshservice tickets: {str(e)}")
        raise Exception(f"Freshservice API Error: {str(e)}")

def map_fs_status_id_to_name(status_id):
    """Maps common Freshservice status IDs to names for readability."""
    # These are common defaults, might vary per Freshservice instance
    mapping = {
        2: "Open",
        3: "Pending",
        4: "Resolved",
        5: "Closed"
    }
    return mapping.get(status_id, f"Unknown ({status_id})")


def lambda_handler(event, context):
    """
    AWS Lambda handler to fetch Jira and Freshservice tickets
    and save them to an Excel file.
    """
    env_validation_error = validate_env_vars()
    if env_validation_error:
        print(f"Validation Error: {env_validation_error}")
        return {
            "statusCode": 400,
            "body": json.dumps({"error": env_validation_error})
        }

    print("Starting ticket report generation...")
    try:
        jira_tickets = fetch_jira_tickets()
        freshservice_tickets = fetch_freshservice_tickets()

        # Create Pandas DataFrames
        df_jira = pd.DataFrame(jira_tickets)
        if not jira_tickets: # Ensure columns exist even if no data
             df_jira = pd.DataFrame(columns=["Key", "Summary", "Status", "Assignee", "Reporter", "Created", "Updated", "Resolved"])


        df_freshservice = pd.DataFrame(freshservice_tickets)
        if not freshservice_tickets: # Ensure columns exist even if no data
            df_freshservice = pd.DataFrame(columns=["ID", "Subject", "Status", "Status Name", "Requester ID", "Created At", "Updated At", "Resolved At", "Closed At", "Source"])


        # Create Excel file with two sheets
        with pd.ExcelWriter(EXCEL_FILE_PATH, engine='openpyxl') as writer:
            df_jira.to_excel(writer, sheet_name='Jira_Tickets', index=False)
            df_freshservice.to_excel(writer, sheet_name='Freshservice_Tickets', index=False)

        print(f"Successfully created Excel report at {EXCEL_FILE_PATH}")
        return {
            "statusCode": 200,
            "body": json.dumps({
                "message": "Ticket report generated successfully.",
                "jira_tickets_found": len(jira_tickets),
                "freshservice_tickets_found": len(freshservice_tickets),
                "excel_file_path": EXCEL_FILE_PATH
            })
        }

    except Exception as e:
        print(f"Error in lambda_handler: {str(e)}")
        return {
            "statusCode": 500,
            "body": json.dumps({
                "error": "Failed to generate ticket report.",
                "details": str(e)
            })
        }

if __name__ == "__main__":
    # --- For Local Testing ---
    # Set environment variables before running:
    # export TARGET_EMAIL="user@example.com"
    # export JIRA_URL="https://your-domain.atlassian.net"
    # export JIRA_USER_EMAIL="your-jira-api-email@example.com"
    # export JIRA_API_TOKEN="your_jira_api_token"
    # export FRESHSERVICE_DOMAIN="yourdomain.freshservice.com"
    # export FRESHSERVICE_API_KEY="your_freshservice_api_key"

    print("--- Simulating Local Lambda Execution ---")
    if not os.environ.get("TARGET_EMAIL"): # Basic check
        print("TARGET_EMAIL environment variable not set. Please set all required env vars for local testing.")
    else:
        result = lambda_handler({}, {})
        print("\n--- Lambda Result ---")
        print(json.dumps(result, indent=2))
        if result.get("statusCode") == 200:
            print(f"Excel file should be at: {EXCEL_FILE_PATH}")
            if os.path.exists(EXCEL_FILE_PATH):
                print("Local test: Excel file found.")
            else:
                print("Local test: Excel file NOT found.")
    print("--- End Local Simulation ---")
