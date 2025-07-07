import boto3
import os
import json
from datetime import datetime, timedelta, timezone

# --- Environment Variables & Configuration ---
# CPU Utilization Threshold (percentage)
CPU_THRESHOLD_PERCENT = float(os.environ.get("CPU_THRESHOLD_PERCENT", "10.0"))
# Evaluation period for CPU metrics (days)
CPU_EVALUATION_PERIOD_DAYS = int(os.environ.get("CPU_EVALUATION_PERIOD_DAYS", "7"))
# Tag to exempt instances from termination
EXCLUSION_TAG_KEY = os.environ.get("EXCLUSION_TAG_KEY") # e.g., "Auto-Delete-Exempt"
EXCLUSION_TAG_VALUE = os.environ.get("EXCLUSION_TAG_VALUE") # e.g., "true"
# Dry Run Mode: "true" to log actions without terminating, "false" to terminate.
# IMPORTANT: Defaults to "true" if not set or invalid value for safety.
DRY_RUN_STR = os.environ.get("DRY_RUN", "true").lower()
DRY_RUN = False if DRY_RUN_STR == "false" else True

# (Optional) SNS Topic ARN for notifications
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")

# --- IAM & SAFETY WARNINGS ---
# This Lambda requires the following IAM permissions:
# - ec2:DescribeRegions
# - ec2:DescribeInstances (for all regions)
# - ec2:TerminateInstances (for all regions) - HIGHLY SENSITIVE PERMISSION
# - cloudwatch:GetMetricData (for all regions, for AWS/EC2 namespace, CPUUtilization)
# - (Optional) sns:Publish (if SNS_TOPIC_ARN is set)
# - logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents (basic Lambda logging)
#
# !!! WARNING: THIS SCRIPT CAN TERMINATE EC2 INSTANCES. !!!
# !!! ALWAYS TEST THOROUGHLY WITH DRY_RUN=true IN A NON-PRODUCTION ENVIRONMENT FIRST. !!!
# !!! ENSURE YOUR EXCLUSION TAGS ARE CORRECTLY SET ON CRITICAL INSTANCES. !!!
# !!! USE LEAST PRIVILEGE IAM ROLES. !!!

def validate_env_vars():
    """Validates critical environment variables."""
    if not EXCLUSION_TAG_KEY or not EXCLUSION_TAG_VALUE:
        return ("CRITICAL: EXCLUSION_TAG_KEY and EXCLUSION_TAG_VALUE environment variables "
                "must be set to prevent accidental deletion of all instances.")
    if CPU_EVALUATION_PERIOD_DAYS <= 0:
        return "CPU_EVALUATION_PERIOD_DAYS must be a positive integer."
    if not 0 < CPU_THRESHOLD_PERCENT < 100:
        return "CPU_THRESHOLD_PERCENT must be between 0 and 100 (exclusive of 0)."
    return None

def is_instance_exempt(instance_tags):
    """Checks if an instance has the exclusion tag."""
    if not EXCLUSION_TAG_KEY or not EXCLUSION_TAG_VALUE: # Should be caught by validate_env_vars
        print("Warning: Exclusion tag key or value not configured. Assuming not exempt (dangerous).")
        return False
    if not instance_tags:
        return False
    for tag in instance_tags:
        if tag['Key'] == EXCLUSION_TAG_KEY and tag['Value'] == EXCLUSION_TAG_VALUE:
            return True
    return False

def get_average_cpu_utilization(cw_client, instance_id, evaluation_period_days):
    """
    Fetches the average CPU utilization for an instance over the evaluation period.
    Returns a single average value for the entire period.
    """
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=evaluation_period_days)

    # Period for GetMetricData should be the total duration to get one datapoint representing the average
    # The period must be a multiple of 60 seconds.
    metric_query_period_seconds = evaluation_period_days * 24 * 60 * 60

    # Ensure period is at least 60s and a multiple of 60
    if metric_query_period_seconds < 60 : metric_query_period_seconds = 60
    metric_query_period_seconds = (metric_query_period_seconds // 60) * 60


    print(f"Querying CPU for {instance_id} from {start_time.isoformat()} to {end_time.isoformat()} with period {metric_query_period_seconds}s")

    try:
        response = cw_client.get_metric_data(
            MetricDataQueries=[
                {
                    'Id': 'avg_cpu',
                    'MetricStat': {
                        'Metric': {
                            'Namespace': 'AWS/EC2',
                            'MetricName': 'CPUUtilization',
                            'Dimensions': [{'Name': 'InstanceId', 'Value': instance_id}]
                        },
                        'Period': metric_query_period_seconds,
                        'Stat': 'Average',
                    },
                    'ReturnData': True,
                },
            ],
            StartTime=start_time,
            EndTime=end_time,
            ScanBy='TimestampAscending' # Does not matter much for a single datapoint
        )
        if response['MetricDataResults'] and response['MetricDataResults'][0]['Values']:
            avg_cpu = response['MetricDataResults'][0]['Values'][0]
            print(f"Instance {instance_id}: Average CPU over {evaluation_period_days} days = {avg_cpu:.2f}%")
            return avg_cpu
        else:
            print(f"Instance {instance_id}: No CPU data found for the period.")
            return None
    except Exception as e:
        print(f"Error fetching CPU for {instance_id}: {str(e)}")
        return None # Treat error as "cannot determine CPU", so don't terminate

def terminate_ec2_instance(ec2_client, instance_id, region, dry_run_mode):
    """Terminates an EC2 instance or logs if in dry run mode."""
    action_taken = "None (Dry Run)"
    if dry_run_mode:
        message = f"DRY RUN: Would terminate EC2 instance {instance_id} in region {region}."
        print(message)
        action_taken = "Logged for termination (Dry Run)"
        return True, message, action_taken # Success in dry run context
    else:
        message = f"ATTEMPTING TERMINATION of EC2 instance {instance_id} in region {region}."
        print(message)
        try:
            ec2_client.terminate_instances(InstanceIds=[instance_id])
            action_taken = f"Termination initiated for {instance_id}"
            print(action_taken)
            return True, message, action_taken
        except Exception as e:
            error_message = f"Error terminating instance {instance_id} in {region}: {str(e)}"
            print(error_message)
            action_taken = f"Termination failed for {instance_id}: {str(e)}"
            return False, error_message, action_taken


def send_sns_notification(sns_client, topic_arn, subject, message_body):
    """Sends a notification to an SNS topic."""
    if not topic_arn:
        return
    try:
        print(f"Sending SNS notification to {topic_arn}: {subject}")
        sns_client.publish(
            TopicArn=topic_arn,
            Subject=subject,
            Message=message_body
        )
    except Exception as e:
        print(f"Error sending SNS notification: {str(e)}")


def lambda_handler(event, context):
    print(f"Starting EC2 low CPU terminator. DRY_RUN={DRY_RUN}. Threshold={CPU_THRESHOLD_PERCENT}%, Period={CPU_EVALUATION_PERIOD_DAYS} days.")
    print(f"Exclusion Tag: Key='{EXCLUSION_TAG_KEY}', Value='{EXCLUSION_TAG_VALUE}'")

    env_validation_error = validate_env_vars()
    if env_validation_error:
        print(f"CRITICAL CONFIGURATION ERROR: {env_validation_error}")
        if SNS_TOPIC_ARN:
            try:
                sns_client_local = boto3.client('sns')
                send_sns_notification(sns_client_local, SNS_TOPIC_ARN, "EC2 Terminator Lambda - CRITICAL CONFIG ERROR", env_validation_error)
            except Exception as e_sns:
                print(f"Failed to send SNS for config error: {str(e_sns)}")
        return {"statusCode": 400, "body": json.dumps({"error": env_validation_error})}

    summary = {
        "regions_scanned": 0,
        "instances_scanned": 0,
        "instances_exempt": 0,
        "instances_low_cpu": 0,
        "instances_action_taken": [], # Stores details of actions
        "errors": []
    }

    global_ec2_client = boto3.client('ec2', region_name='us-east-1') # For describing regions
    sns_client = boto3.client('sns') if SNS_TOPIC_ARN else None

    try:
        regions_response = global_ec2_client.describe_regions(Filters=[{'Name': 'opt-in-status', 'Values': ['opt-in-not-required', 'opted-in']}])
        aws_regions = [region['RegionName'] for region in regions_response['Regions']]
        summary["regions_scanned"] = len(aws_regions)
        print(f"Scanning {len(aws_regions)} regions: {aws_regions}")
    except Exception as e:
        err_msg = f"Error describing regions: {str(e)}"
        print(err_msg)
        summary["errors"].append(err_msg)
        if sns_client: send_sns_notification(sns_client, SNS_TOPIC_ARN, "EC2 Terminator Lambda - Region Error", err_msg)
        return {"statusCode": 500, "body": json.dumps(summary)}

    for region in aws_regions:
        print(f"\n--- Processing Region: {region} ---")
        regional_ec2_client = boto3.client('ec2', region_name=region)
        regional_cw_client = boto3.client('cloudwatch', region_name=region)

        try:
            paginator = regional_ec2_client.get_paginator('describe_instances')
            instance_iterator = paginator.paginate(
                Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
            )

            for page in instance_iterator:
                for reservation in page['Reservations']:
                    for instance in reservation['Instances']:
                        summary["instances_scanned"] += 1
                        instance_id = instance['InstanceId']
                        instance_tags = instance.get('Tags', [])
                        name_tag_list = [tag['Value'] for tag in instance_tags if tag['Key'] == 'Name']
                        instance_name = name_tag_list[0] if name_tag_list else "N/A"

                        print(f"Checking instance: {instance_id} (Name: {instance_name}, Region: {region})")

                        if is_instance_exempt(instance_tags):
                            summary["instances_exempt"] += 1
                            print(f"Instance {instance_id} is EXEMPT due to tag '{EXCLUSION_TAG_KEY}={EXCLUSION_TAG_VALUE}'. Skipping.")
                            continue

                        avg_cpu = get_average_cpu_utilization(regional_cw_client, instance_id, CPU_EVALUATION_PERIOD_DAYS)

                        if avg_cpu is None:
                            print(f"Could not retrieve CPU data for {instance_id}. Skipping.")
                            summary["errors"].append(f"No CPU data for {instance_id} in {region}")
                            continue

                        if avg_cpu < CPU_THRESHOLD_PERCENT:
                            summary["instances_low_cpu"] += 1
                            log_entry = {
                                "instance_id": instance_id,
                                "instance_name": instance_name,
                                "region": region,
                                "avg_cpu_percent": f"{avg_cpu:.2f}",
                                "threshold_percent": f"{CPU_THRESHOLD_PERCENT:.2f}",
                                "action": "Pending Termination" if DRY_RUN else "Termination Initiated",
                                "dry_run": DRY_RUN
                            }
                            print(f"Instance {instance_id} (CPU: {avg_cpu:.2f}%) is BELOW threshold ({CPU_THRESHOLD_PERCENT}%).")

                            success, term_message, action_detail = terminate_ec2_instance(regional_ec2_client, instance_id, region, DRY_RUN)
                            log_entry["termination_message"] = term_message
                            log_entry["action_detail"] = action_detail

                            if not success and not DRY_RUN: # Actual termination failed
                                summary["errors"].append(f"Termination FAILED for {instance_id}: {term_message}")

                            summary["instances_action_taken"].append(log_entry)

                            if sns_client:
                                sns_subject = (f"{'DRY RUN: ' if DRY_RUN else ''}EC2 Instance Low CPU - "
                                               f"{'Action Proposed' if DRY_RUN else 'Action Taken'}: {instance_id}")
                                sns_message = json.dumps(log_entry, indent=2)
                                send_sns_notification(sns_client, SNS_TOPIC_ARN, sns_subject, sns_message)
                        else:
                            print(f"Instance {instance_id} (CPU: {avg_cpu:.2f}%) is ABOVE threshold. No action.")
        except Exception as e_region:
            err_msg_region = f"Error processing instances in region {region}: {str(e_region)}"
            print(err_msg_region)
            summary["errors"].append(err_msg_region)
            # Continue to the next region

    final_report_message = f"EC2 Low CPU Terminator Lambda finished. Summary: {json.dumps(summary, indent=2)}"
    print(final_report_message)
    if sns_client and (summary["instances_action_taken"] or summary["errors"]): # Send summary if actions or errors
         send_sns_notification(sns_client, SNS_TOPIC_ARN, "EC2 Terminator Lambda - Run Summary", final_report_message)

    return {
        "statusCode": 200, # Lambda itself completed, specific errors in summary
        "body": json.dumps(summary)
    }

if __name__ == "__main__":
    # --- For Local Testing ---
    # Set environment variables. CRITICAL: EXCLUSION_TAG_KEY and EXCLUSION_TAG_VALUE must be set!
    # export EXCLUSION_TAG_KEY="DoNotTerminateMe"
    # export EXCLUSION_TAG_VALUE="true"
    # export DRY_RUN="true" # HIGHLY RECOMMENDED FOR TESTING
    # export CPU_THRESHOLD_PERCENT="5.0"
    # export CPU_EVALUATION_PERIOD_DAYS="1" # Use shorter period for testing if desired
    # export AWS_PROFILE="your-aws-profile-if-not-default" # If needed
    # export SNS_TOPIC_ARN="arn:aws:sns:your-region:your-account-id:your-topic-name" # Optional

    print("--- Simulating Local Lambda Execution for EC2 Low CPU Terminator ---")

    if not os.environ.get("EXCLUSION_TAG_KEY") or not os.environ.get("EXCLUSION_TAG_VALUE"):
        print("CRITICAL: EXCLUSION_TAG_KEY and EXCLUSION_TAG_VALUE must be set in your environment for local testing.")
    else:
        print(f"Local Test: DRY_RUN is set to '{DRY_RUN}' (Derived from env: '{DRY_RUN_STR}')")
        if DRY_RUN is False:
            print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            print("!!! WARNING: DRY_RUN IS FALSE. ACTUAL TERMINATIONS WILL OCCUR !!!")
            print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            # input("Press Enter to continue if you are absolutely sure, or Ctrl+C to abort...") # Uncomment for safety prompt

        mock_event = {}
        mock_context = {}
        result = lambda_handler(mock_event, mock_context)
        print("\n--- Lambda Result ---")
        print(json.dumps(result, indent=2))

    print("--- End Local Simulation ---")
