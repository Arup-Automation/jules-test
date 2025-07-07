import os
import json
from datetime import datetime, timedelta
from jira import JIRA, JIRAError
import requests

# --- Environment Variables ---
JIRA_URL = os.environ.get("JIRA_URL")  # e.g., "https://your-domain.atlassian.net"
JIRA_USER_EMAIL = os.environ.get("JIRA_USER_EMAIL")  # Email for Jira API authentication
JIRA_API_TOKEN = os.environ.get("JIRA_API_TOKEN")
TEAMS_WEBHOOK_URL = os.environ.get("TEAMS_WEBHOOK_URL") # MS Teams Incoming Webhook URL

# Configuration for the Jira query and actions
JIRA_BLOCKER_PRIORITY_NAME = os.environ.get("JIRA_BLOCKER_PRIORITY_NAME", "Blocker")
JIRA_URGENT_LABEL = os.environ.get("JIRA_URGENT_LABEL", "urgent")
JIRA_NO_UPDATE_DAYS = int(os.environ.get("JIRA_NO_UPDATE_DAYS", 3))

def validate_env_vars():
    """Checks if all required environment variables are set."""
    required_vars = {
        "JIRA_URL": JIRA_URL,
        "JIRA_USER_EMAIL": JIRA_USER_EMAIL,
        "JIRA_API_TOKEN": JIRA_API_TOKEN,
        "TEAMS_WEBHOOK_URL": TEAMS_WEBHOOK_URL,
        "JIRA_BLOCKER_PRIORITY_NAME": JIRA_BLOCKER_PRIORITY_NAME,
        "JIRA_URGENT_LABEL": JIRA_URGENT_LABEL
    }
    missing_vars = [name for name, value in required_vars.items() if not value]
    if missing_vars:
        return f"Missing environment variables: {', '.join(missing_vars)}"
    if JIRA_NO_UPDATE_DAYS <= 0:
        return "JIRA_NO_UPDATE_DAYS must be a positive integer."
    return None

def search_jira_issues(jira_client):
    """Searches for Jira issues matching the criteria."""
    jql_query = (
        f'priority = "{JIRA_BLOCKER_PRIORITY_NAME}" '
        f'AND updated <= "-{JIRA_NO_UPDATE_DAYS}d" '
        f'AND (labels IS EMPTY OR labels NOT IN ("{JIRA_URGENT_LABEL}"))'
    )
    print(f"Executing JQL query: {jql_query}")
    try:
        issues = jira_client.search_issues(jql_query, maxResults=50) # Limiting results for safety
        print(f"Found {len(issues)} issues matching criteria.")
        return issues
    except JIRAError as e:
        print(f"Jira API Error during search: {e.status_code} - {e.text}")
        raise  # Re-raise to be caught by Lambda handler

def add_jira_label(jira_client, issue_key, label):
    """Adds a label to a Jira issue."""
    print(f"Adding label '{label}' to issue {issue_key}")
    try:
        issue = jira_client.issue(issue_key)
        issue.add_field_value('labels', label)
        print(f"Successfully added label '{label}' to {issue_key}.")
    except JIRAError as e:
        print(f"Jira API Error adding label to {issue_key}: {e.status_code} - {e.text}")
        # Decide if this is fatal or if we should continue with other issues/notifications
        # For now, we'll log and let the main loop continue if possible.
        # If notification is critical even if tagging fails, this might need adjustment.
        raise # Re-raise to be caught by Lambda handler for this issue

def send_teams_notification(issue_key, issue_summary, issue_url, assignee_name):
    """Sends a notification to Microsoft Teams."""
    if not TEAMS_WEBHOOK_URL:
        print("TEAMS_WEBHOOK_URL not set. Skipping notification.")
        return

    message = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": "FF0000",  # Red for urgent
        "summary": f"Urgent Jira Issue: {issue_key}",
        "sections": [{
            "activityTitle": f"**Urgent Jira Issue Needs Attention: {issue_key}**",
            "activitySubtitle": f"{issue_summary}",
            "facts": [{
                "name": "Issue Key:",
                "value": f"[{issue_key}]({issue_url})"
            }, {
                "name": "Summary:",
                "value": issue_summary
            }, {
                "name": "Assignee:",
                "value": assignee_name if assignee_name else "Unassigned"
            }, {
                "name": "Priority:",
                "value": JIRA_BLOCKER_PRIORITY_NAME
            }, {
                "name": "Details:",
                "value": f"This issue has not been updated in over {JIRA_NO_UPDATE_DAYS} days and has been automatically tagged as '{JIRA_URGENT_LABEL}'."
            }],
            "markdown": True
        }],
        "potentialAction": [{
            "@type": "OpenUri",
            "name": "View Jira Issue",
            "targets": [{
                "os": "default",
                "uri": issue_url
            }]
        }]
    }

    print(f"Sending Teams notification for {issue_key}...")
    try:
        response = requests.post(TEAMS_WEBHOOK_URL, json=message, timeout=10)
        response.raise_for_status()  # Raises an exception for HTTP errors
        print(f"Successfully sent Teams notification for {issue_key}. Status: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Error sending Teams notification for {issue_key}: {str(e)}")
        # Log error but don't let it stop processing other issues

def lambda_handler(event, context):
    """
    AWS Lambda handler to find old Blocker Jira issues, tag them, and notify Teams.
    """
    env_error = validate_env_vars()
    if env_error:
        print(f"Environment variable validation error: {env_error}")
        return {"statusCode": 400, "body": json.dumps({"error": env_error})}

    print("Starting Jira auto-tag and notification process...")

    processed_issues = 0
    tagged_issues = 0
    notified_issues = 0
    errors_occurred = []

    try:
        jira_client = JIRA(
            server=JIRA_URL,
            basic_auth=(JIRA_USER_EMAIL, JIRA_API_TOKEN)
        )

        issues_to_process = search_jira_issues(jira_client)

        if not issues_to_process:
            print("No issues found matching the criteria. Exiting.")
            return {
                "statusCode": 200,
                "body": json.dumps({"message": "No issues found to process."})
            }

        for issue in issues_to_process:
            processed_issues += 1
            issue_key = issue.key
            issue_summary = issue.fields.summary
            issue_url = f"{JIRA_URL.rstrip('/')}/browse/{issue_key}"
            assignee_name = issue.fields.assignee.displayName if issue.fields.assignee else "N/A"

            print(f"Processing issue: {issue_key} - {issue_summary} (Assignee: {assignee_name})")

            try:
                # 1. Add label
                add_jira_label(jira_client, issue_key, JIRA_URGENT_LABEL)
                tagged_issues +=1

                # 2. Send Teams notification
                send_teams_notification(issue_key, issue_summary, issue_url, assignee_name)
                notified_issues +=1

            except JIRAError as je: # Catch JIRA errors from add_jira_label
                error_detail = f"Failed to process Jira issue {issue_key} due to Jira API error: {je.status_code} - {je.text}"
                print(error_detail)
                errors_occurred.append(error_detail)
            except Exception as e: # Catch other errors (like Teams notification failure if it were to raise)
                error_detail = f"An unexpected error occurred while processing issue {issue_key}: {str(e)}"
                print(error_detail)
                errors_occurred.append(error_detail)
                # Continue to the next issue

        summary_message = (
            f"Jira auto-tag and notification process completed. "
            f"Issues found: {len(issues_to_process)}. "
            f"Successfully tagged: {tagged_issues}. "
            f"Successfully notified: {notified_issues}."
        )
        if errors_occurred:
            summary_message += f" Errors encountered for {len(errors_occurred)} issues. Check logs for details."
            print(f"Errors: {errors_occurred}")
            return {
                "statusCode": 207, # Multi-Status, as some operations might have succeeded
                "body": json.dumps({"message": summary_message, "errors": errors_occurred})
            }

        print(summary_message)
        return {
            "statusCode": 200,
            "body": json.dumps({"message": summary_message})
        }

    except JIRAError as e: # Catch JIRA errors from initial search or client instantiation
        print(f"A critical Jira API error occurred: {e.status_code} - {e.text}")
        return {
            "statusCode": 500,
            "body": json.dumps({"error": "Jira API Error", "details": e.text})
        }
    except Exception as e:
        print(f"An unexpected critical error occurred in lambda_handler: {str(e)}")
        return {
            "statusCode": 500,
            "body": json.dumps({"error": "Unexpected critical error", "details": str(e)})
        }

if __name__ == "__main__":
    # --- For Local Testing ---
    # Set environment variables before running:
    # export JIRA_URL="https://your-domain.atlassian.net"
    # export JIRA_USER_EMAIL="your-jira-api-email@example.com"
    # export JIRA_API_TOKEN="your_jira_api_token"
    # export TEAMS_WEBHOOK_URL="your_teams_webhook_url"
    # export JIRA_BLOCKER_PRIORITY_NAME="Blocker" # Or your equivalent
    # export JIRA_URGENT_LABEL="urgent_test" # Use a test label
    # export JIRA_NO_UPDATE_DAYS="3"

    print("--- Simulating Local Lambda Execution for Jira Auto-Tag & Notify ---")

    # Basic check for one var to prevent accidental real runs without setup
    if not os.environ.get("JIRA_URL") or not os.environ.get("TEAMS_WEBHOOK_URL"):
        print("Please set all required JIRA_* and TEAMS_WEBHOOK_URL environment variables for local testing.")
    else:
        # Mock event and context
        mock_event = {}
        mock_context = {}
        result = lambda_handler(mock_event, mock_context)
        print("\n--- Lambda Result ---")
        print(json.dumps(result, indent=2))

    print("--- End Local Simulation ---")
