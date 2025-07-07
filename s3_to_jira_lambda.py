import boto3
import os
import json
from jira import JIRA, JIRAError
import urllib.parse
from email.parser import BytesParser # For parsing email content from bytes
from email.policy import default as default_email_policy # Sensible defaults for parsing

# --- Environment Variables ---
# S3 Configuration
# SOURCE_S3_BUCKET = os.environ.get("SOURCE_S3_BUCKET") # Validated in S3 event config usually

# Jira Configuration
JIRA_URL = os.environ.get("JIRA_URL")  # e.g., "https://your-domain.atlassian.net"
JIRA_USER_EMAIL = os.environ.get("JIRA_USER_EMAIL")  # Email for Jira API authentication
JIRA_API_TOKEN = os.environ.get("JIRA_API_TOKEN")    # API Token (Store in Secrets Manager ideally)
JIRA_PROJECT_KEY = os.environ.get("JIRA_PROJECT_KEY") # e.g., "HELPDESK"
JIRA_ISSUE_TYPE = os.environ.get("JIRA_ISSUE_TYPE", "Task") # Default to Task as per user
JIRA_PRIORITY_NAME = os.environ.get("JIRA_PRIORITY_NAME", "Blocker") # Default to Blocker as per user

# Initialize Jira client (can be outside handler if credentials don't change per invocation)
# However, for safety and to ensure env vars are read per invocation, initialize in handler or validate first.
jira_client = None

def validate_env_vars():
    """Validates that all necessary environment variables are set."""
    required = [
        "JIRA_URL", "JIRA_USER_EMAIL", "JIRA_API_TOKEN",
        "JIRA_PROJECT_KEY", "JIRA_ISSUE_TYPE", "JIRA_PRIORITY_NAME"
    ]
    missing = [var for var in required if not globals().get(var)]
    if missing:
        return f"Missing environment variables: {', '.join(missing)}"
    return None

def parse_email_content(email_bytes_content):
    """
    Parses email content (bytes) and extracts subject, body, and sender.
    Returns a dictionary with 'subject', 'body', 'sender_email'.
    """
    try:
        # Use BytesParser for robust parsing of email content, including headers and body
        msg = BytesParser(policy=default_email_policy).parsebytes(email_bytes_content)

        subject = msg.get('subject', 'No Subject')
        sender_full = msg.get('from', 'unknown@example.com') # Full From: header

        # Extract just the email address from "Display Name <email@example.com>"
        if '<' in sender_full and '>' in sender_full:
            sender_email = sender_full.split('<', 1)[1].split('>', 1)[0].strip()
        else:
            sender_email = sender_full.strip() # Assume it's just an email if no <>

        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get('Content-Disposition'))

                if "attachment" not in content_disposition: # Don't add attachments as body
                    if content_type == "text/plain":
                        # Get plain text part, decode if necessary
                        payload = part.get_payload(decode=True)
                        charset = part.get_content_charset() or 'utf-8' # Default to utf-8
                        body += payload.decode(charset, errors='replace') + "\n"
                    elif content_type == "text/html" and not body: # Fallback to HTML if no plain text found yet
                        # (Could also strip HTML tags here if desired)
                        payload = part.get_payload(decode=True)
                        charset = part.get_content_charset() or 'utf-8'
                        body += payload.decode(charset, errors='replace') + "\n" # For now, keep HTML as is
        else: # Not multipart, try to get body directly
            payload = msg.get_payload(decode=True)
            charset = msg.get_content_charset() or 'utf-8'
            body = payload.decode(charset, errors='replace')

        return {
            'subject': str(subject).strip(),
            'body': body.strip(),
            'sender_email': sender_email.strip()
        }
    except Exception as e:
        print(f"Error parsing email content: {str(e)}")
        # Return default values or raise to indicate parsing failure
        return {
            'subject': 'Error Parsing Subject',
            'body': f'Error parsing email body: {str(e)}',
            'sender_email': 'unknown@example.com'
        }

def create_jira_issue_from_email(parsed_email_data, project_key, issue_type_name, priority_name):
    """Creates a Jira issue using the parsed email data."""
    global jira_client
    if not jira_client: # Initialize if not already done
        jira_client = JIRA(
            server=JIRA_URL,
            basic_auth=(JIRA_USER_EMAIL, JIRA_API_TOKEN)
        )

    issue_dict = {
        'project': {'key': project_key},
        'summary': parsed_email_data['subject'],
        'description': parsed_email_data['body'],
        'issuetype': {'name': issue_type_name},
        'priority': {'name': priority_name},
        # Reporter: Jira Cloud often requires user to exist and uses accountId.
        # Setting reporter by email might only work if that email is a valid Jira user's email.
        # For Jira Server, it might be more lenient with email as reporter.
        # If it fails, Jira typically creates it with the API user as reporter.
        # 'reporter': {'name': parsed_email_data['sender_email']}, # This might fail if user doesn't exist or email not primary
    }

    # Attempt to set reporter by email. If this is problematic, it might need to be removed
    # or a lookup for Jira accountId by email would be needed (more complex).
    # For now, let's try setting it directly if the sender_email is not 'unknown@example.com'
    if parsed_email_data['sender_email'] and parsed_email_data['sender_email'] != 'unknown@example.com':
         # Jira Cloud typically expects 'accountId' for reporter. Setting by 'name' (email)
         # might work if the user exists and email is their username/primary.
         # It's safer to let the API user be the reporter if this causes issues.
         # Alternatively, one could search for the user by email to get their accountId.
         # For simplicity, we'll try with email as name. If it fails, Jira usually defaults to the API user.
        issue_dict['reporter'] = {'emailAddress': parsed_email_data['sender_email']}
        # Note: For some Jira versions/configs, 'name' is used for username.
        # 'emailAddress' is specific to some newer Jira Cloud APIs for user identification.
        # If 'reporter' setting fails, remove this line or adjust based on Jira error messages.


    print(f"Attempting to create Jira issue with fields: {json.dumps(issue_dict, indent=2)}")
    try:
        new_issue = jira_client.create_issue(fields=issue_dict)
        print(f"Successfully created Jira issue: {new_issue.key} - {new_issue.permalink()}")
        return new_issue
    except JIRAError as e:
        error_message = f"Jira API Error creating issue: Status {e.status_code} - {e.text}"
        # If reporter setting failed, try without it as a fallback
        if "reporter" in str(e.text).lower() and 'reporter' in issue_dict:
            print("Reporter setting failed. Trying to create issue without explicit reporter field...")
            del issue_dict['reporter']
            try:
                new_issue = jira_client.create_issue(fields=issue_dict)
                print(f"Successfully created Jira issue (without explicit reporter): {new_issue.key} - {new_issue.permalink()}")
                return new_issue
            except JIRAError as e2:
                error_message_fallback = f"Jira API Error (fallback): Status {e2.status_code} - {e2.text}"
                print(error_message_fallback)
                raise Exception(error_message_fallback) # Re-raise the specific exception
        else:
            print(error_message)
            raise Exception(error_message) # Re-raise the specific exception

# --- Lambda Handler ---
def lambda_handler(event, context):
    global jira_client # Allow modification of global client instance

    env_error = validate_env_vars()
    if env_error:
        print(f"Configuration Error: {env_error}")
        return {"statusCode": 400, "body": json.dumps({"error": env_error})}

    # Initialize Jira client once if not already (e.g. due to Lambda container reuse)
    if not jira_client:
        try:
            jira_client = JIRA(
                server=JIRA_URL,
                basic_auth=(JIRA_USER_EMAIL, JIRA_API_TOKEN),
                timeout=20 # Increased timeout for Jira client
            )
            print("Jira client initialized.")
        except Exception as e_jira_init:
            print(f"Failed to initialize Jira client: {str(e_jira_init)}")
            return {"statusCode": 500, "body": json.dumps({"error": "Jira client initialization failed", "details": str(e_jira_init)})}


    print(f"Received event: {json.dumps(event)}")
    s3_client = boto3.client('s3')
    processed_files = 0
    error_files = 0
    results = []

    if 'Records' not in event:
        print("Warning: Event does not contain 'Records' key.")
        return {"statusCode": 200, "body": json.dumps({"message": "No records found in event."})}

    for record in event['Records']:
        try:
            s3_entity = record.get('s3', {})
            bucket_name = s3_entity.get('bucket', {}).get('name')
            object_key_encoded = s3_entity.get('object', {}).get('key')

            if not bucket_name or not object_key_encoded:
                print(f"Skipping record: Missing bucket name or object key. Record: {str(record)[:200]}")
                results.append({"status": "error", "reason": "Missing bucket/key in S3 event record"})
                error_files +=1
                continue

            object_key = urllib.parse.unquote_plus(object_key_encoded)
            print(f"Processing S3 object: s3://{bucket_name}/{object_key}")

            # 1. Fetch S3 Object Content
            s3_object = s3_client.get_object(Bucket=bucket_name, Key=object_key)
            email_bytes_content = s3_object['Body'].read()
            print(f"Fetched {len(email_bytes_content)} bytes from s3://{bucket_name}/{object_key}")

            # 2. Parse Email Content
            parsed_email = parse_email_content(email_bytes_content)
            if "Error Parsing Subject" in parsed_email['subject']: # Check if parsing failed critically
                 print(f"Critical error parsing email content for {object_key}. Skipping Jira creation.")
                 results.append({"s3_object": f"s3://{bucket_name}/{object_key}", "status": "error", "reason": "Email parsing failed", "details": parsed_email['body']})
                 error_files +=1
                 continue

            print(f"Parsed email: Subject='{parsed_email['subject']}', Sender='{parsed_email['sender_email']}'")

            # 3. Create Jira Issue
            new_jira_issue = create_jira_issue_from_email(
                parsed_email,
                JIRA_PROJECT_KEY,
                JIRA_ISSUE_TYPE,
                JIRA_PRIORITY_NAME
            )
            results.append({
                "s3_object": f"s3://{bucket_name}/{object_key}",
                "status": "success",
                "jira_issue_key": new_jira_issue.key,
                "jira_issue_url": new_jira_issue.permalink()
            })
            processed_files += 1

        except Exception as e:
            error_message = f"Error processing S3 object {object_key if 'object_key' in locals() else 'unknown'}: {str(e)}"
            print(error_message)
            results.append({
                "s3_object": f"s3://{bucket_name}/{object_key}" if 'bucket_name' in locals() and 'object_key' in locals() else "Unknown S3 object",
                "status": "error",
                "reason": str(e)
            })
            error_files +=1
            # Continue to next record

    summary_message = f"Processed {processed_files + error_files} S3 event(s). Success: {processed_files}, Errors: {error_files}."
    print(summary_message)

    status_code = 200
    if error_files > 0 and processed_files == 0 : status_code = 500 # All failed
    elif error_files > 0 : status_code = 207 # Partial success

    return {
        "statusCode": status_code,
        "body": json.dumps({"message": summary_message, "results": results})
    }

if __name__ == "__main__":
    # --- For Local Testing ---
    # Set environment variables:
    # export JIRA_URL="https://your-domain.atlassian.net"
    # export JIRA_USER_EMAIL="your-jira-api-email@example.com"
    # export JIRA_API_TOKEN="your_jira_api_token"
    # export JIRA_PROJECT_KEY="YOURPROJKEY"
    # export JIRA_ISSUE_TYPE="Task"
    # export JIRA_PRIORITY_NAME="Blocker"
    # (Optional) export SOURCE_S3_BUCKET="your-s3-bucket-name" - for validation if implemented

    print("--- Simulating Local Lambda Execution for S3 to Jira ---")
    if not all([JIRA_URL, JIRA_USER_EMAIL, JIRA_API_TOKEN, JIRA_PROJECT_KEY]):
        print("Please set JIRA_URL, JIRA_USER_EMAIL, JIRA_API_TOKEN, JIRA_PROJECT_KEY env vars for local testing.")
    else:
        # Create a dummy .eml file content (bytes) for testing
        dummy_email_content_str = (
            "From: Test Sender <test.sender@example.com>\n"
            "To: recipient@example.com\n"
            "Subject: This is a Test Email from S3 for Jira\n"
            "Date: Fri, 27 Oct 2023 10:00:00 +0000\n"
            "Message-ID: <test12345@example.com>\n"
            "\n"
            "This is the body of the test email.\n"
            "It has multiple lines.\n"
            "This should go into the Jira description."
        )
        dummy_email_bytes = dummy_email_content_str.encode('utf-8')

        # Mock S3 client and get_object
        class MockS3Client:
            def get_object(self, Bucket, Key):
                print(f"MockS3Client: Called get_object for Bucket={Bucket}, Key={Key}")
                if Key == "test/sample_email.eml":
                    return {'Body': MockS3Body(dummy_email_bytes), 'ContentType': 'message/rfc822'}
                raise Exception(f"MockS3Client: Object s3://{Bucket}/{Key} not found in mock setup.")

        class MockS3Body:
            def __init__(self, content_bytes):
                self.content_bytes = content_bytes
            def read(self):
                return self.content_bytes

        original_boto3_client = boto3.client
        boto3.client = lambda service_name, **kwargs: MockS3Client() if service_name == 's3' else original_boto3_client(service_name, **kwargs)


        mock_s3_event = {
            "Records": [{
                "eventSource": "aws:s3",
                "awsRegion": "us-east-1",
                "eventTime": datetime.now(timezone.utc).isoformat(),
                "eventName": "ObjectCreated:Put",
                "s3": {
                    "bucket": {"name": "my-email-drop-bucket"},
                    "object": {"key": "test/sample_email.eml", "size": len(dummy_email_bytes), "eTag": "test-etag"}
                }
            }]
        }
        mock_context = {}
        result = lambda_handler(mock_s3_event, mock_context)
        print("\n--- Lambda Result ---")
        print(json.dumps(result, indent=2))

        # Restore original boto3 client if multiple tests are run in one go
        boto3.client = original_boto3_client
    print("--- End Local Simulation ---")
