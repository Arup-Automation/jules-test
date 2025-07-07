import os
import requests
import json
from datetime import datetime, timedelta
import boto3

# Configuration will be loaded from environment variables in Lambda
# Example:
# FRESHSERVICE_DOMAIN = os.environ['FRESHSERVICE_DOMAIN']
# FRESHSERVICE_API_KEY = os.environ['FRESHSERVICE_API_KEY']
# SENDER_EMAIL = os.environ['SENDER_EMAIL']
# RECIPIENT_EMAIL_ACTUAL = os.environ['RECIPIENT_EMAIL_ACTUAL']
# AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1') # Default if not set

FRESHSERVICE_TICKET_STATUS_OPEN = 2
FRESHSERVICE_TICKET_STATUS_PENDING = 3
FRESHSERVICE_TICKET_STATUS_RESOLVED = 4
FRESHSERVICE_TICKET_STATUS_CLOSED = 5

# --- Freshservice API Functions ---

def get_stale_tickets(freshservice_domain, api_key):
    """
    Fetches tickets from Freshservice that have not been updated for 10 days
    and are currently in 'Open' or 'Pending' status.
    """
    stale_tickets = []
    ten_days_ago_dt = datetime.utcnow() - timedelta(days=10)
    # Freshservice API expects updated_at filter in 'YYYY-MM-DDTHH:MM:SSZ' format
    # but their filter query seems to work best with just date for 'less than or equal to'
    ten_days_ago_str = ten_days_ago_dt.strftime('%Y-%m-%dT%H:%M:%SZ')

    # Using the simple filter first, then refining with query if needed.
    # The 'updated_since' parameter is for tickets updated *after* a date.
    # We need tickets updated *before or on* a date.
    # So, we use the query parameter.
    # Status: Open (2), Pending (3)
    # updated_at: <= ten_days_ago_str (URL encoded)

    # Constructing the query: (status:2 OR status:3) AND updated_at:<='YYYY-MM-DDTHH:MM:SSZ'
    # URL encoding for query:
    # (status:2 OR status:3) AND updated_at:<='2023-10-16T12:00:00Z'
    # becomes:
    # %28status%3A2%20OR%20status%3A3%29%20AND%20updated_at%3A%3C%3D%27YYYY-MM-DDTHH%3Amm%3AssZ%27
    # The API docs for "Filter Tickets" state:
    # Query Format(query) - "(ticket_field:integer OR ticket_field:'string') AND ticket_field:boolean"
    # Input for date fields should be in UTC Format and enclosed in single quotes.

    query = f"(status:{FRESHSERVICE_TICKET_STATUS_OPEN} OR status:{FRESHSERVICE_TICKET_STATUS_PENDING}) AND updated_at:<='{ten_days_ago_str}'"

    url = f"https://{freshservice_domain}/api/v2/tickets"
    headers = {
        "Content-Type": "application/json",
    }
    auth = (api_key, "X") # API key as username, dummy password

    page = 1
    while True:
        params = {'query': query, 'page': page, 'per_page': 30} # Max per_page is 100, using 30 for safety
        print(f"Fetching page {page} with query: {query}")
        try:
            response = requests.get(url, headers=headers, auth=auth, params=params, timeout=30)
            response.raise_for_status() # Raise an exception for bad status codes

            data = response.json()
            current_page_tickets = data.get("tickets", [])
            stale_tickets.extend(current_page_tickets)

            # Check for pagination: Freshservice uses a 'Link' header for next page
            # or simply stops returning tickets. If less than per_page items returned, it's likely the last page.
            if len(current_page_tickets) < 30: # Assuming 30 per_page
                break
            page += 1
            # More robust pagination would check 'Link' header:
            # if 'Link' in response.headers and 'rel="next"' in response.headers['Link']:
            #    page +=1
            # else:
            #    break
            # For now, simple length check.
            if not current_page_tickets: # If a page returns empty, stop.
                break

        except requests.exceptions.RequestException as e:
            print(f"Error fetching tickets: {e}")
            # Potentially add retry logic here or more specific error handling
            return [] # Return empty on error to prevent further processing
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON response: {e}")
            print(f"Response text: {response.text}")
            return []

    print(f"Found {len(stale_tickets)} stale tickets.")
    return stale_tickets

def close_freshservice_ticket(freshservice_domain, api_key, ticket_id):
    """
    Closes a specific Freshservice ticket by its ID.
    """
    url = f"https://{freshservice_domain}/api/v2/tickets/{ticket_id}"
    headers = {
        "Content-Type": "application/json",
    }
    auth = (api_key, "X")
    payload = {"status": FRESHSERVICE_TICKET_STATUS_CLOSED} # Status 5 for Closed

    print(f"Attempting to close ticket ID: {ticket_id}")
    try:
        response = requests.put(url, headers=headers, auth=auth, json=payload, timeout=30)
        response.raise_for_status()
        print(f"Successfully closed ticket ID: {ticket_id}, Status: {response.status_code}")
        return True
    except requests.exceptions.RequestException as e:
        print(f"Error closing ticket ID {ticket_id}: {e}")
        if response is not None:
            print(f"Response content: {response.text}")
        return False

# --- Email Sending Function (SES) ---

def send_closure_email_ses(sender_email, recipient_email, subject, html_body):
    """
    Sends an email notification using AWS SES.
    """
    aws_region = os.environ.get('AWS_REGION', 'us-east-1') # Default if not set, or get from env
    ses_client = boto3.client('ses', region_name=aws_region)

    try:
        # If recipient_email is a comma-separated string, convert it to a list
        if isinstance(recipient_email, str):
            recipient_addresses = [email.strip() for email in recipient_email.split(',')]
        elif isinstance(recipient_email, list):
            recipient_addresses = recipient_email
        else:
            print(f"Recipient email is of an unexpected type: {type(recipient_email)}")
            return False

        response = ses_client.send_email(
            Source=sender_email,
            Destination={'ToAddresses': recipient_addresses},
            Message={
                'Subject': {'Data': subject, 'Charset': 'UTF-8'},
                'Body': {'Html': {'Data': html_body, 'Charset': 'UTF-8'}}
            }
        )
        print(f"Email sent! Message ID: {response['MessageId']}")
        return True
    except Exception as e: # Catching a generic exception, boto3 has specific ones like ClientError
        print(f"Error sending email via SES: {e}")
        return False

# --- Lambda Handler ---

def lambda_handler(event, context):
    """
    Main Lambda function to fetch stale tickets, close them, and send notifications.
    """
    FRESHSERVICE_DOMAIN = os.environ.get('FRESHSERVICE_DOMAIN')
    FRESHSERVICE_API_KEY = os.environ.get('FRESHSERVICE_API_KEY')
    SENDER_EMAIL = os.environ.get('SENDER_EMAIL')
    RECIPIENT_EMAIL_ACTUAL = os.environ.get('RECIPIENT_EMAIL_ACTUAL') # Actual email for IT Change Manager

    if not all([FRESHSERVICE_DOMAIN, FRESHSERVICE_API_KEY, SENDER_EMAIL, RECIPIENT_EMAIL_ACTUAL]):
        error_message = "Configuration error: Missing one or more critical environment variables (FRESHSERVICE_DOMAIN, FRESHSERVICE_API_KEY, SENDER_EMAIL, RECIPIENT_EMAIL_ACTUAL)."
        print(f"Error: {error_message}")
        return {
            'statusCode': 500,
            'body': json.dumps(error_message)
        }

    print("Starting ticket closure process triggered by Lambda...")
    stale_tickets = get_stale_tickets(FRESHSERVICE_DOMAIN, FRESHSERVICE_API_KEY)

    closed_count = 0
    notified_count = 0

    for ticket in stale_tickets:
        ticket_id = ticket.get("id")
        ticket_subject = ticket.get("subject", "N/A")
        ticket_requester_id = ticket.get("requester_id", "N/A") # For email body

        if not ticket_id:
            print(f"Skipping ticket due to missing ID: {ticket}")
            continue

        print(f"Processing ticket ID: {ticket_id} - Subject: {ticket_subject}")

        if close_freshservice_ticket(FRESHSERVICE_DOMAIN, FRESHSERVICE_API_KEY, ticket_id):
            closed_count += 1

            email_subject = f"Freshservice Ticket Closed: [{ticket_id}] - {ticket_subject}"
            ticket_url = f"https://{FRESHSERVICE_DOMAIN}/a/tickets/{ticket_id}"
            html_body = f"""
            <html>
            <head></head>
            <body>
                <p>Hello,</p>
                <p>The following Freshservice ticket has been automatically closed due to inactivity for 10 days:</p>
                <ul>
                    <li><b>Ticket ID:</b> {ticket_id}</li>
                    <li><b>Subject:</b> {ticket_subject}</li>
                    <li><b>Requester ID:</b> {ticket_requester_id}</li>
                    <li><b>Link:</b> <a href="{ticket_url}">{ticket_url}</a></li>
                </ul>
                <p>Thank you.</p>
            </body>
            </html>
            """

            if send_closure_email_ses(SENDER_EMAIL, RECIPIENT_EMAIL_ACTUAL, email_subject, html_body):
                notified_count += 1
            else:
                print(f"Failed to send notification for closed ticket ID: {ticket_id}")
        else:
            print(f"Failed to close ticket ID: {ticket_id}. Notification will not be sent.")

    summary_message = (
        f"Process Summary: Stale tickets found: {len(stale_tickets)}, "
        f"Tickets successfully closed: {closed_count}, "
        f"Notifications successfully sent: {notified_count}"
    )
    print(summary_message)

    return {
        'statusCode': 200,
        'body': json.dumps(summary_message)
    }

# Example usage (for local testing, not for Lambda direct call)
if __name__ == "__main__":
    print("Running local test of lambda_handler...")

    # --- IMPORTANT: For local testing, set these environment variables or replace directly ---
    # --- DO NOT COMMIT ACTUAL KEYS/SECRETS TO VERSION CONTROL ---
    # Mock environment variables for local testing
    os.environ['FRESHSERVICE_DOMAIN'] = os.environ.get("TEST_FRESHSERVICE_DOMAIN", "yourcompany.freshservice.com")
    os.environ['FRESHSERVICE_API_KEY'] = os.environ.get("TEST_FRESHSERVICE_API_KEY", "YOUR_API_KEY") # Keep this as a placeholder unless testing actual API calls
    os.environ['SENDER_EMAIL'] = os.environ.get("TEST_SENDER_EMAIL", "itnotification@sophos.com")
    os.environ['RECIPIENT_EMAIL_ACTUAL'] = os.environ.get("TEST_RECIPIENT_EMAIL_ACTUAL", "test-recipient@example.com") # For local test, use a test email
    os.environ['AWS_REGION'] = os.environ.get("TEST_AWS_REGION", "us-east-1") # Mock AWS region

    if os.environ['FRESHSERVICE_API_KEY'] == "YOUR_API_KEY" or os.environ['FRESHSERVICE_DOMAIN'] == "yourcompany.freshservice.com":
        print("\nWARNING: Using placeholder Freshservice domain or API key for local test.")
        print("Actual Freshservice API calls will be skipped or might fail.")
        print("To test fully, set TEST_FRESHSERVICE_DOMAIN and TEST_FRESHSERVICE_API_KEY environment variables with real (test) values.")
        # Mock get_stale_tickets to avoid actual API call if not configured for test
        def mock_get_stale_tickets(domain, key):
            print(f"Mocking get_stale_tickets for {domain} (No actual API call)")
            return [
                {"id": "101", "subject": "Mock Stale Ticket 1", "requester_id": "R101"},
                {"id": "102", "subject": "Mock Stale Ticket 2", "requester_id": "R102"},
            ]
        get_stale_tickets_original = get_stale_tickets
        get_stale_tickets = mock_get_stale_tickets

        # Mock close_freshservice_ticket
        def mock_close_freshservice_ticket(domain, key, ticket_id):
            print(f"Mocking close_freshservice_ticket for ID {ticket_id} on {domain} (No actual API call)")
            return True # Assume success for mock
        close_freshservice_ticket_original = close_freshservice_ticket
        close_freshservice_ticket = mock_close_freshservice_ticket

    # Call the lambda_handler with mock event and context
    mock_event = {}
    mock_context = {}
    response = lambda_handler(mock_event, mock_context)
    print(f"\nLambda handler local test response: {response}")

    # Restore original functions if they were mocked
    if 'get_stale_tickets_original' in locals():
        get_stale_tickets = get_stale_tickets_original
    if 'close_freshservice_ticket_original' in locals():
        close_freshservice_ticket = close_freshservice_ticket_original

    print("\nLocal test finished.")

print("freshservice_ticket_closer.py loaded")
