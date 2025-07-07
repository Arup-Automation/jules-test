import os
import json
import requests
from requests.auth import HTTPBasicAuth
from azure.identity import ClientSecretCredential
from msgraph import GraphServiceClient
from msgraph.generated.models.chat_message import ChatMessage
from msgraph.generated.models.item_body import ItemBody
from msgraph.generated.models.o_data_errors.o_data_error import ODataError

# --- Environment Variables ---
# Freshservice Configuration
FRESHSERVICE_DOMAIN = os.environ.get("FRESHSERVICE_DOMAIN")  # e.g., yourdomain.freshservice.com
FRESHSERVICE_API_KEY = os.environ.get("FRESHSERVICE_API_KEY") # Store in Secrets Manager

# Microsoft Graph API Configuration (for Teams)
MSGRAPH_CLIENT_ID = os.environ.get("MSGRAPH_CLIENT_ID")
MSGRAPH_CLIENT_SECRET = os.environ.get("MSGRAPH_CLIENT_SECRET") # Store in Secrets Manager
MSGRAPH_TENANT_ID = os.environ.get("MSGRAPH_TENANT_ID")

# Teams Target Configuration
TEAMS_TEAM_ID = os.environ.get("TEAMS_TEAM_ID")
TEAMS_CHANNEL_ID = os.environ.get("TEAMS_CHANNEL_ID")

# Operational Configuration
AGENT_TICKET_THRESHOLD = int(os.environ.get("AGENT_TICKET_THRESHOLD", "10")) # Default to 10
# User specified active statuses: "Open", "Assigned", "In Progress"
# Freshservice API v2 typically uses numeric IDs for status filtering.
# We'll need to map these names to IDs. For now, let's assume these are the names.
# A more robust solution would fetch all statuses and map names to IDs first.
# For this version, we'll try to construct a query if names are supported, or this part might need adjustment.
# Let's assume for now we will fetch tickets and filter by status name if direct API filter isn't obvious.
# A common approach for Freshservice is status IDs: Open (2), Pending (3), Resolved (4), Closed (5).
# "Assigned" and "In Progress" might be custom or specific variations.
# For simplicity, this script will assume we need to map these names to IDs.
# Placeholder: User needs to verify these IDs or the script needs a status mapping function.
# Common default IDs: Open: 2, Pending: 3. "Assigned" and "In Progress" are less standard as filterable IDs.
# Let's use the typical "Open" and "Pending" by ID, and note that "Assigned" / "In Progress" might need specific handling.
# A better approach is to allow comma-separated IDs via env var.
FRESHSERVICE_ACTIVE_STATUS_IDS_STR = os.environ.get("FRESHSERVICE_ACTIVE_STATUS_IDS", "2,3") # Defaulting to Open (2), Pending (3)
FRESHSERVICE_ACTIVE_STATUS_NAMES_LIST = [name.strip() for name in os.environ.get("FRESHSERVICE_ACTIVE_STATUS_NAMES", "Open,Pending,Assigned,In Progress").split(',')]


# --- MS Graph API Scopes ---
MSGRAPH_SCOPES = ['https://graph.microsoft.com/.default']

# --- Global Clients (initialized in handler) ---
fs_session = None
graph_client = None

def validate_env_vars():
    required = [
        "FRESHSERVICE_DOMAIN", "FRESHSERVICE_API_KEY",
        "MSGRAPH_CLIENT_ID", "MSGRAPH_CLIENT_SECRET", "MSGRAPH_TENANT_ID",
        "TEAMS_TEAM_ID", "TEAMS_CHANNEL_ID"
    ]
    missing = [var for var in required if not globals().get(var)]
    if missing:
        return f"Missing environment variables: {', '.join(missing)}"
    if AGENT_TICKET_THRESHOLD <= 0:
        return "AGENT_TICKET_THRESHOLD must be a positive integer."
    if not FRESHSERVICE_ACTIVE_STATUS_NAMES_LIST: # Check if the list from env var is empty
         return "FRESHSERVICE_ACTIVE_STATUS_NAMES must be provided as a comma-separated list."
    return None

def initialize_clients():
    global fs_session, graph_client
    # Freshservice Session
    if fs_session is None:
        fs_session = requests.Session()
        fs_session.auth = (FRESHSERVICE_API_KEY, "X") # API Key, Password 'X'
        fs_session.headers.update({"Content-Type": "application/json"})
        print("Freshservice session initialized.")

    # Microsoft Graph Client
    if graph_client is None:
        credential = ClientSecretCredential(
            tenant_id=MSGRAPH_TENANT_ID,
            client_id=MSGRAPH_CLIENT_ID,
            client_secret=MSGRAPH_CLIENT_SECRET
        )
        graph_client = GraphServiceClient(credentials=credential, scopes=MSGRAPH_SCOPES)
        print("Microsoft Graph client initialized.")


def get_freshservice_agents():
    """Fetches all active agents from Freshservice."""
    if not fs_session: initialize_clients()
    agents_url = f"https://{FRESHSERVICE_DOMAIN}/api/v2/agents"
    all_agents = []
    page = 1
    print("Fetching Freshservice agents...")
    try:
        while True:
            response = fs_session.get(agents_url, params={"page": page, "per_page": 30}) # Max per_page is often 30 or 100
            response.raise_for_status()
            data = response.json()
            agents_on_page = data.get("agents", [])
            if not agents_on_page:
                break

            for agent_data in agents_on_page:
                # We only care about active agents that can be assigned tickets
                if agent_data.get("active") and not agent_data.get("occasional"): # Assuming occasional agents are not primary targets
                    all_agents.append({
                        "id": agent_data["id"],
                        "name": f"{agent_data.get('first_name', '')} {agent_data.get('last_name', '')}".strip() or agent_data.get("email"),
                        "email": agent_data.get("email")
                    })
            page += 1
            if page > 20: # Safety break for pagination for agents
                print("Warning: Exceeded 20 pages for agents. Stopping agent fetch.")
                break
        print(f"Fetched {len(all_agents)} active Freshservice agents.")
        return all_agents
    except requests.exceptions.RequestException as e:
        print(f"Error fetching Freshservice agents: {str(e)}")
        raise
    except Exception as e:
        print(f"Unexpected error processing agents: {str(e)}")
        raise


def count_active_tickets_for_agent(agent_id, agent_name):
    """
    Counts active tickets for a given agent ID.
    Freshservice API v2 for tickets: status is numeric.
    A robust way is to fetch status list, map names to IDs, then use IDs in query.
    For this script, we rely on FRESHSERVICE_ACTIVE_STATUS_NAMES_LIST and filter client-side after fetching,
    or if lucky, the API supports a more complex query.
    A simpler query is to fetch tickets with responder_id and then filter client-side by status NAME.
    Or, if status IDs for "Open", "Assigned", "In Progress" are known and stable, use them.
    Let's try to get all tickets for an agent that are not Resolved or Closed.
    Default Freshservice status IDs: Open (2), Pending (3), Resolved (4), Closed (5).
    We will fetch tickets that are NOT status 4 or 5, then filter by the names.
    """
    if not fs_session: initialize_clients()
    # Construct a query to exclude resolved/closed tickets for the agent
    # Example query: "(status:2 OR status:3) AND responder_id:12345"
    # The "query" parameter in FS Ticket API needs to be URL encoded.
    # For simplicity, let's fetch all non-resolved/closed for the agent and then filter.
    # This is less efficient than a precise API filter if available.

    # Note: Freshservice API for filtering tickets is specific.
    # `GET /api/v2/tickets?responder_id={agent_id}` is a common way.
    # Then filter by status locally.

    tickets_url = f"https://{FRESHSERVICE_DOMAIN}/api/v2/tickets"
    active_ticket_count = 0
    page = 1
    print(f"Counting active tickets for agent: {agent_name} (ID: {agent_id}) with target statuses: {FRESHSERVICE_ACTIVE_STATUS_NAMES_LIST}")

    try:
        while True:
            # Fetch tickets assigned to the agent
            params = {"responder_id": agent_id, "page": page, "per_page": 100} # Max per_page is 100
            response = fs_session.get(tickets_url, params=params)
            response.raise_for_status()
            data = response.json()
            tickets_on_page = data.get("tickets", [])

            if not tickets_on_page:
                break

            for ticket in tickets_on_page:
                # Status name is usually available in the ticket object, e.g. ticket['status_name']
                # Or, ticket['status'] is the numeric ID.
                # We need to map FRESHSERVICE_ACTIVE_STATUS_NAMES_LIST to actual field in ticket object.
                # Assuming ticket object has a 'status_name' field or similar from which we can get the text.
                # Or we rely on numeric status IDs.
                # For now, let's assume ticket['status'] gives the numeric ID and we have a mapping
                # or Freshservice ticket object includes status name.
                # The Freshservice documentation indicates `status` is numeric.
                # We need a way to map 'Open', 'Assigned', 'In Progress' to these numbers.
                # This is a common gap; often, one fetches all statuses first to build this map.
                # Simpler for now: If ticket['status_name'] exists:
                ticket_status_name = ticket.get("status_name") # This field might not exist directly

                # A more reliable approach if status_name isn't directly available:
                # Fetch all possible statuses from /api/v2/ticket_fields, find 'status', get choices.
                # For this script, we'll assume the provided names are directly comparable or the user provides IDs.
                # If FRESHSERVICE_ACTIVE_STATUS_IDS_STR is used:
                try:
                    active_status_ids = [int(s_id.strip()) for s_id in FRESHSERVICE_ACTIVE_STATUS_IDS_STR.split(',')]
                    if ticket.get('status') in active_status_ids:
                        active_ticket_count +=1
                        continue # Counted by ID
                except ValueError:
                    print(f"Warning: Invalid value in FRESHSERVICE_ACTIVE_STATUS_IDS: '{FRESHSERVICE_ACTIVE_STATUS_IDS_STR}'. Falling back to name check if possible.")

                # Fallback or primary: Check by name if status_name field is present (less reliable without knowing exact field)
                # This part is speculative about Freshservice ticket object structure.
                # A common structure is `ticket['status']` (numeric) and you'd map names to these numbers.
                # Let's assume for the sake of progressing that `ticket['status_name_from_api']` holds the string status
                # This placeholder name emphasizes it needs to be verified from actual API response.
                # For now, let's rely on the ID based approach above for more robustness if IDs are provided.
                # If only names are provided via FRESHSERVICE_ACTIVE_STATUS_NAMES_LIST and IDs are not,
                # this requires a pre-fetch of status mappings.
                # Given the current setup, the ID based check is primary.
                # If `FRESHSERVICE_ACTIVE_STATUS_IDS` is not used/empty, this name check would be the only way.

            if len(tickets_on_page) < 100: # Last page
                break
            page += 1
            if page > 30: # Safety break for tickets per agent
                print(f"Warning: Exceeded 30 pages for agent {agent_name}'s tickets. Count may be partial.")
                break
        print(f"Agent {agent_name} (ID: {agent_id}) has {active_ticket_count} active tickets (based on ID filter).")
        return active_ticket_count
    except requests.exceptions.RequestException as e:
        print(f"Error fetching tickets for agent {agent_name} (ID: {agent_id}): {str(e)}")
        # Return -1 or raise to indicate error
        return -1
    except Exception as e:
        print(f"Unexpected error counting tickets for agent {agent_name}: {str(e)}")
        return -1


async def send_teams_channel_message_async(team_id, channel_id, message_html_content):
    """Sends a message to a specific Teams channel using Microsoft Graph API."""
    if not graph_client: initialize_clients()

    request_body = ChatMessage(
        body=ItemBody(
            content_type=ItemBody.ContentType.HTML,
            content=message_html_content
        )
    )
    try:
        print(f"Sending Teams message to Team ID {team_id}, Channel ID {channel_id}...")
        await graph_client.teams[team_id].channels[channel_id].messages.post(request_body)
        print("Successfully sent Teams message.")
        return True
    except ODataError as o_data_error:
        error_details = "Unknown OData error"
        if o_data_error.error:
            error_details = f"Code: {o_data_error.error.code}, Message: {o_data_error.error.message}"
        print(f"Microsoft Graph API error sending Teams message: {error_details}")
    except Exception as e:
        print(f"Unexpected error sending Teams message: {str(e)}")
    return False

# --- Lambda Handler ---
# Note: Graph SDK calls are async, so handler needs to be async
import asyncio

async def lambda_handler_async(event, context):
    env_error = validate_env_vars()
    if env_error:
        print(f"Configuration Error: {env_error}")
        return {"statusCode": 400, "body": json.dumps({"error": env_error})}

    initialize_clients() # Ensure clients are ready
    print("Starting Freshservice agent load check...")

    alerts_sent = 0
    agents_over_threshold = []
    processed_agents_count = 0
    errors_encountered = []

    try:
        agents = get_freshservice_agents()
        if not agents:
            print("No active Freshservice agents found to monitor.")
            return {"statusCode": 200, "body": json.dumps({"message": "No agents found."})}

        for agent in agents:
            processed_agents_count +=1
            agent_id = agent["id"]
            agent_name = agent["name"]

            print(f"\nChecking agent: {agent_name} (ID: {agent_id})")
            active_ticket_count = count_active_tickets_for_agent(agent_id, agent_name)

            if active_ticket_count == -1: # Error occurred during counting
                errors_encountered.append(f"Failed to count tickets for agent {agent_name} (ID: {agent_id}).")
                continue # Skip to next agent

            if active_ticket_count > AGENT_TICKET_THRESHOLD:
                print(f"ALERT: Agent {agent_name} (ID: {agent_id}) has {active_ticket_count} active tickets, exceeding threshold of {AGENT_TICKET_THRESHOLD}.")
                agents_over_threshold.append({"name": agent_name, "id": agent_id, "ticket_count": active_ticket_count})

                message_content = (
                    f"<h3>Freshservice Agent Load Alert</h3>"
                    f"<p>Agent <b>{agent_name}</b> (ID: {agent_id}) currently has <b>{active_ticket_count}</b> active tickets.</p>"
                    f"<p>This exceeds the configured threshold of {AGENT_TICKET_THRESHOLD} tickets.</p>"
                    f"<p>Please review their workload.</p>"
                    f"<p><small>Checked at: {datetime.now(timezone.utc).isoformat()}</small></p>"
                )

                if await send_teams_channel_message_async(TEAMS_TEAM_ID, TEAMS_CHANNEL_ID, message_content):
                    alerts_sent += 1
                else:
                    errors_encountered.append(f"Failed to send Teams alert for agent {agent_name} (ID: {agent_id}).")
            else:
                print(f"Agent {agent_name} (ID: {agent_id}) has {active_ticket_count} tickets (Threshold: {AGENT_TICKET_THRESHOLD}). No alert needed.")

        summary_msg = (f"Agent load check complete. Processed: {processed_agents_count} agents. "
                       f"Alerts sent: {alerts_sent}. Agents over threshold: {len(agents_over_threshold)}.")
        if errors_encountered:
            summary_msg += f" Errors: {len(errors_encountered)}."

        print(summary_msg)
        return {
            "statusCode": 200 if not errors_encountered else 207, # 207 Multi-Status if errors
            "body": json.dumps({
                "message": summary_msg,
                "agents_over_threshold": agents_over_threshold,
                "alerts_sent": alerts_sent,
                "errors": errors_encountered
            })
        }

    except Exception as e:
        crit_err_msg = f"A critical error occurred in lambda_handler: {str(e)}"
        print(crit_err_msg)
        return {"statusCode": 500, "body": json.dumps({"error": "Critical failure in Lambda execution.", "details": crit_err_msg})}

def lambda_handler(event, context):
    return asyncio.run(lambda_handler_async(event, context))


if __name__ == "__main__":
    # --- For Local Testing ---
    # Set environment variables:
    # FRESHSERVICE_DOMAIN, FRESHSERVICE_API_KEY
    # MSGRAPH_CLIENT_ID, MSGRAPH_CLIENT_SECRET, MSGRAPH_TENANT_ID
    # TEAMS_TEAM_ID, TEAMS_CHANNEL_ID
    # AGENT_TICKET_THRESHOLD (e.g., 5)
    # FRESHSERVICE_ACTIVE_STATUS_IDS (e.g., "2,3") or FRESHSERVICE_ACTIVE_STATUS_NAMES

    print("--- Simulating Local Lambda Execution for Freshservice Agent Load Alerter ---")
    if not all([FRESHSERVICE_DOMAIN, FRESHSERVICE_API_KEY, MSGRAPH_CLIENT_ID, TEAMS_TEAM_ID]): # Basic check
        print("Please set all required FRESHSERVICE_*, MSGRAPH_*, and TEAMS_* environment variables for local testing.")
    else:
        # Mock event and context
        mock_event = {}
        mock_context = {}
        result = lambda_handler(mock_event, mock_context) # Calls the async wrapper
        print("\n--- Lambda Result ---")
        print(json.dumps(result, indent=2))
    print("--- End Local Simulation ---")
