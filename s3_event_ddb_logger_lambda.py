import boto3
import os
import json
from datetime import datetime, timezone
import urllib.parse

# --- Environment Variables ---
DYNAMODB_LOG_TABLE_NAME = os.environ.get("DYNAMODB_LOG_TABLE_NAME")

# Initialize DynamoDB client (can be outside handler for reuse)
dynamodb_resource = boto3.resource('dynamodb')
log_table = None # Will be initialized in handler after checking env var

def validate_env_vars():
    """Validates that all necessary environment variables are set."""
    if not DYNAMODB_LOG_TABLE_NAME:
        return "DYNAMODB_LOG_TABLE_NAME environment variable is not set."
    return None

def lambda_handler(event, context):
    """
    AWS Lambda handler to process S3 object creation events and log them to DynamoDB.
    """
    global log_table
    env_error = validate_env_vars()
    if env_error:
        print(f"Configuration Error: {env_error}")
        # Consider raising an exception or returning a specific error structure
        # if this needs to be handled by a Dead Letter Queue (DLQ)
        return {"statusCode": 400, "body": json.dumps({"error": env_error})}

    if log_table is None or log_table.name != DYNAMODB_LOG_TABLE_NAME:
        log_table = dynamodb_resource.Table(DYNAMODB_LOG_TABLE_NAME)

    print(f"Received event: {json.dumps(event)}") # Log the incoming event for debugging

    processed_records = 0
    error_records = 0
    errors = []

    if 'Records' not in event:
        print("Warning: Event does not contain 'Records' key. Nothing to process.")
        return {"statusCode": 200, "body": json.dumps({"message": "No records found in event."})}

    for record in event['Records']:
        try:
            # --- 1. Parse S3 Event Record ---
            s3_event_name = record.get('eventName', 'UnknownEvent')
            s3_event_time_iso = record.get('eventTime', datetime.now(timezone.utc).isoformat())

            s3_entity = record.get('s3', {})
            if not s3_entity:
                print(f"Skipping record: 's3' entity missing. Record: {json.dumps(record)}")
                errors.append({"record_snippet": str(record)[:200], "error": "Missing 's3' entity"})
                error_records +=1
                continue

            bucket_info = s3_entity.get('bucket', {})
            object_info = s3_entity.get('object', {})

            s3_bucket_name = bucket_info.get('name')
            # S3 object keys with spaces or special characters are URL-encoded in events
            s3_object_key_encoded = object_info.get('key')
            if s3_object_key_encoded:
                s3_object_key = urllib.parse.unquote_plus(s3_object_key_encoded)
            else:
                s3_object_key = None

            etag = object_info.get('eTag') # S3 ETag often has quotes, DynamoDB might not want them if used as string.
                                           # For this design, it's part of a composite string key, so it's fine.
            size = object_info.get('size') # Size in bytes

            if not all([s3_bucket_name, s3_object_key, etag]):
                error_msg = f"Skipping record: Missing essential S3 info (bucket, key, or etag). Key: {s3_object_key}"
                print(error_msg)
                errors.append({"record_key": s3_object_key, "error": error_msg})
                error_records +=1
                continue

            # --- 2. Construct DynamoDB Item ---
            # Sort Key: s3_event_time_plus_etag
            # Example: 2023-10-27T10:30:00.123Z_a1b2c3d4e5f67890a1b2c3d4e5f67890
            # Ensure s3_event_time_iso is consistently formatted for sorting.
            # S3 eventTime is already ISO8601.
            sort_key_value = f"{s3_event_time_iso}_{etag}"

            dynamodb_logged_at_iso = datetime.now(timezone.utc).isoformat()

            item_to_log = {
                's3_object_key': s3_object_key,
                's3_event_time_plus_etag': sort_key_value,
                's3_bucket_name': s3_bucket_name,
                'etag': etag,
                's3_event_name': s3_event_name,
                's3_event_time_iso': s3_event_time_iso,
                'dynamodb_logged_at_iso': dynamodb_logged_at_iso
            }
            if size is not None: # Size can be 0 for empty files, but None if not present in event
                item_to_log['size'] = int(size) # DynamoDB expects Number type

            # --- 3. Log to DynamoDB ---
            print(f"Logging item to DynamoDB table {DYNAMODB_LOG_TABLE_NAME}: {json.dumps(item_to_log)}")
            log_table.put_item(Item=item_to_log)
            print(f"Successfully logged: s3://{s3_bucket_name}/{s3_object_key}")
            processed_records += 1

        except Exception as e:
            error_records += 1
            error_message = f"Error processing record: {str(e)}. Record snippet: {str(record)[:500]}"
            print(error_message)
            errors.append({"record_event_id": record.get("eventID", "N/A"), "error": str(e)})
            # Continue to next record if possible

    # --- Return Summary ---
    summary_message = (
        f"Processed {processed_records} S3 event(s) successfully. "
        f"Encountered errors on {error_records} record(s)."
    )
    print(summary_message)

    if error_records > 0:
        # If any record failed, you might want to return a non-200 status or ensure DLQ handles it.
        # For now, returning 200 to acknowledge receipt of event, but with error details.
        # SQS redrive policy would be better for retrying failed individual messages if Lambda is fed by SQS.
        # If S3 directly invokes Lambda and a record fails, it's harder to retry just that record.
        return {
            "statusCode": 207, # Multi-Status
            "body": json.dumps({
                "message": summary_message,
                "processed_count": processed_records,
                "error_count": error_records,
                "errors_details": errors
            })
        }

    return {
        "statusCode": 200,
        "body": json.dumps({
            "message": summary_message,
            "processed_count": processed_records
        })
    }

if __name__ == "__main__":
    # --- For Local Testing ---
    # Set environment variables:
    # export DYNAMODB_LOG_TABLE_NAME="YourDynamoDBLogTableName"

    print("--- Simulating Local Lambda Execution for S3 Event Logger ---")
    if not DYNAMODB_LOG_TABLE_NAME:
        print("DYNAMODB_LOG_TABLE_NAME environment variable not set. Please set it for local testing.")
    else:
        # Example S3 PUT event structure
        mock_s3_event = {
            "Records": [
                {
                    "eventVersion": "2.1",
                    "eventSource": "aws:s3",
                    "awsRegion": "us-east-1",
                    "eventTime": datetime.now(timezone.utc).isoformat(), # "2023-10-27T12:34:56.789Z"
                    "eventName": "ObjectCreated:Put",
                    "userIdentity": {"principalId": "EXAMPLE"},
                    "requestParameters": {"sourceIPAddress": "127.0.0.1"},
                    "responseElements": {
                        "x-amz-request-id": "EXAMPLE12345",
                        "x-amz-id-2": "EXAMPLEabcdef"
                    },
                    "s3": {
                        "s3SchemaVersion": "1.0",
                        "configurationId": "testConfigRule",
                        "bucket": {
                            "name": "my-test-bucket-for-lambda",
                            "ownerIdentity": {"principalId": "EXAMPLE"},
                            "arn": "arn:aws:s3:::my-test-bucket-for-lambda"
                        },
                        "object": {
                            "key": "testfolder/new file with spaces.txt", # Example with spaces/special chars
                            "size": 1024,
                            "eTag": "0123456789abcdef0123456789abcdef",
                            "versionId": "EXAMPLEVERSIONID", # May not always be present
                            "sequencer": "0A1B2C3D4E5F678901"
                        }
                    }
                },
                { # Example of another event in the same batch
                    "eventVersion": "2.1",
                    "eventSource": "aws:s3",
                    "awsRegion": "us-east-1",
                    "eventTime": (datetime.now(timezone.utc) + timedelta(seconds=1)).isoformat(),
                    "eventName": "ObjectCreated:CompleteMultipartUpload",
                    "s3": {
                        "bucket": {"name": "my-test-bucket-for-lambda"},
                        "object": {
                            "key": "another/sample.zip",
                            "size": 12345678,
                            "eTag": "fedcba9876543210fedcba9876543210"
                        }
                    }
                }
            ]
        }
        # Mock context
        mock_context = {}
        result = lambda_handler(mock_s3_event, mock_context)
        print("\n--- Lambda Result ---")
        print(json.dumps(result, indent=2))

    print("--- End Local Simulation ---")
