import boto3
# pandas and openpyxl removed as they are no longer needed for JSON output
import os
import json
from datetime import datetime, timedelta, timezone

# --- Configuration from Environment Variables ---
S3_BUCKET_NAME = os.environ.get("S3_BUCKET_NAME")
S3_KEY_PREFIX = os.environ.get("S3_KEY_PREFIX", "ec2_reports/")
# CPU Metric Configuration
DEFAULT_CPU_PERIOD_MINUTES = 60
DEFAULT_CPU_STATISTIC = "Average"
CPU_METRIC_PERIOD_MINUTES = int(os.environ.get("CPU_METRIC_PERIOD_MINUTES", DEFAULT_CPU_PERIOD_MINUTES))
CPU_METRIC_STATISTIC = os.environ.get("CPU_METRIC_STATISTIC", DEFAULT_CPU_STATISTIC)
VALID_CPU_STATS = ['SampleCount', 'Average', 'Sum', 'Minimum', 'Maximum']

if CPU_METRIC_STATISTIC not in VALID_CPU_STATS:
    print(f"Warning: Invalid CPU_METRIC_STATISTIC '{CPU_METRIC_STATISTIC}'. Defaulting to '{DEFAULT_CPU_STATISTIC}'. Valid options: {VALID_CPU_STATS}")
    CPU_METRIC_STATISTIC = DEFAULT_CPU_STATISTIC

# --- IAM Permissions Reminder (for Lambda Role) ---
# ec2:DescribeRegions
# ec2:DescribeInstances (for all regions)
# ec2:DescribeInstanceTypes (for all regions, to get memory info)
# cloudwatch:GetMetricData (for all regions, for AWS/EC2 namespace, specifically CPUUtilization)
# s3:PutObject (for the target S3_BUCKET_NAME and S3_KEY_PREFIX)
# logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents (basic Lambda logging)

def get_instance_name_tag(tags):
    """Extracts the 'Name' tag from a list of tags."""
    if not tags:
        return "N/A"
    for tag in tags:
        if tag['Key'] == 'Name':
            return tag['Value']
    return "N/A"

def get_instance_memory_info(ec2_client, instance_types):
    """
    Fetches memory information for a list of instance types.
    Returns a dictionary mapping instance_type to memory_in_mib.
    """
    memory_map = {}
    if not instance_types:
        return memory_map

    # DescribeInstanceTypes can take up to 100 types at a time
    unique_types = list(set(instance_types))
    try:
        for i in range(0, len(unique_types), 100):
            batch = unique_types[i:i+100]
            response = ec2_client.describe_instance_types(InstanceTypes=batch)
            for itype_info in response.get('InstanceTypes', []):
                memory_map[itype_info['InstanceType']] = itype_info.get('MemoryInfo', {}).get('SizeInMiB', 'N/A')
    except Exception as e:
        print(f"Error describing instance types to get memory: {str(e)}. Memory info might be incomplete.")
        # Fallback for types not fetched
        for itype in unique_types:
            if itype not in memory_map:
                 memory_map[itype] = "Error fetching"
    return memory_map

def get_cpu_utilization(cw_client, instance_id, end_time, period_minutes, statistic):
    """Fetches CPU utilization for a given instance."""
    try:
        response = cw_client.get_metric_data(
            MetricDataQueries=[
                {
                    'Id': 'cpu',
                    'MetricStat': {
                        'Metric': {
                            'Namespace': 'AWS/EC2',
                            'MetricName': 'CPUUtilization',
                            'Dimensions': [
                                {
                                    'Name': 'InstanceId',
                                    'Value': instance_id
                                },
                            ]
                        },
                        'Period': period_minutes * 60, # Period in seconds
                        'Stat': statistic,
                    },
                    'ReturnData': True,
                },
            ],
            StartTime=end_time - timedelta(minutes=period_minutes),
            EndTime=end_time,
            ScanBy='TimestampDescending' # Get the latest datapoint if multiple
        )
        if response['MetricDataResults'] and response['MetricDataResults'][0]['Values']:
            return round(response['MetricDataResults'][0]['Values'][0], 2)
        return "N/A" # No data points
    except Exception as e:
        print(f"Error fetching CPU for {instance_id}: {str(e)}")
        return "Error"

def lambda_handler(event, context):
    """
    Lambda handler to list EC2s, get details, generate Excel, and upload to S3.
    """
    if not S3_BUCKET_NAME:
        return {
            "statusCode": 400,
            "body": json.dumps({"error": "S3_BUCKET_NAME environment variable not set."})
        }

    print(f"Starting EC2 report generation. Uploading to s3://{S3_BUCKET_NAME}/{S3_KEY_PREFIX}")

    all_instances_data = []
    # Use a default region client to get all regions
    global_ec2_client = boto3.client('ec2', region_name='us-east-1')

    try:
        regions_response = global_ec2_client.describe_regions()
        aws_regions = [region['RegionName'] for region in regions_response['Regions'] if region['OptInStatus'] != 'not-opted-in']
        print(f"Found {len(aws_regions)} enabled regions: {aws_regions}")
    except Exception as e:
        print(f"Error describing regions: {str(e)}")
        return {"statusCode": 500, "body": json.dumps({"error": f"Failed to describe regions: {str(e)}"}) }

    current_time_utc = datetime.now(timezone.utc)

    for region in aws_regions:
        print(f"Processing region: {region}...")
        try:
            regional_ec2_client = boto3.client('ec2', region_name=region)
            regional_cw_client = boto3.client('cloudwatch', region_name=region)

            paginator = regional_ec2_client.get_paginator('describe_instances')
            instance_pages = paginator.paginate(
                Filters=[{'Name': 'instance-state-name', 'Values': ['pending', 'running', 'shutting-down', 'stopping', 'stopped']}]
            )

            region_instance_types = []
            instances_in_region_temp = []

            for page in instance_pages:
                for reservation in page['Reservations']:
                    for instance in reservation['Instances']:
                        instances_in_region_temp.append(instance)
                        region_instance_types.append(instance['InstanceType'])

            if not instances_in_region_temp:
                print(f"No instances found in {region} matching state filters.")
                continue

            # Get memory info for all unique instance types in the region in a batch
            print(f"Fetching memory info for {len(set(region_instance_types))} unique instance types in {region}...")
            instance_type_memory_map = get_instance_memory_info(regional_ec2_client, region_instance_types)

            for instance in instances_in_region_temp:
                instance_id = instance['InstanceId']
                instance_type = instance['InstanceType']
                name_tag = get_instance_name_tag(instance.get('Tags'))
                state = instance['State']['Name']
                launch_time = instance['LaunchTime'].strftime("%Y-%m-%d %H:%M:%S %Z") if instance.get('LaunchTime') else "N/A"
                private_ip = instance.get('PrivateIpAddress', "N/A")
                public_ip = instance.get('PublicIpAddress', "N/A")

                total_ram_mib = instance_type_memory_map.get(instance_type, "N/A")

                cpu_util = "N/A"
                # Only fetch CPU for running instances, or recently active ones if desired
                if state == 'running':
                    cpu_util = get_cpu_utilization(regional_cw_client, instance_id, current_time_utc, CPU_METRIC_PERIOD_MINUTES, CPU_METRIC_STATISTIC)

                all_instances_data.append({
                    "Region": region,
                    "Instance ID": instance_id,
                    "Name Tag": name_tag,
                    "Instance Type": instance_type,
                    "Total RAM (MiB)": total_ram_mib,
                    "State": state,
                    "Launch Time (UTC)": launch_time,
                    "Private IP": private_ip,
                    "Public IP": public_ip,
                    f"CPU Utilization ({CPU_METRIC_STATISTIC} % over {CPU_METRIC_PERIOD_MINUTES}min)": cpu_util
                })
            print(f"Processed {len(instances_in_region_temp)} instances in {region}.")

        except Exception as e:
            print(f"Error processing region {region}: {str(e)}")
            # Continue to other regions

    if not all_instances_data:
        print("No instances found across any regions.")
        return {
            "statusCode": 200,
            "body": json.dumps({"message": "No instances found to report."})
        }

    # Generate JSON file
    json_file_name = f"ec2_instances_report_{current_time_utc.strftime('%Y%m%d_%H%M%S')}.json"
    local_json_path = f"/tmp/{json_file_name}"

    try:
        with open(local_json_path, 'w') as f:
            # Serialize datetime objects if any are present (e.g. Launch Time)
            # For simplicity, launch_time was already stringified. If other datetime objects exist,
            # a custom JSON encoder might be needed: json.dump(all_instances_data, f, indent=4, default=str)
            json.dump(all_instances_data, f, indent=4)
        print(f"JSON report generated locally: {local_json_path}")
    except Exception as e:
        print(f"Error generating JSON file: {str(e)}")
        return {"statusCode": 500, "body": json.dumps({"error": f"Failed to generate JSON: {str(e)}"}) }

    # Upload to S3
    s3_client = boto3.client('s3')
    s3_object_key = f"{S3_KEY_PREFIX.rstrip('/')}/{json_file_name}"
    if S3_KEY_PREFIX.startswith('/'): # Ensure prefix doesn't start with /
        s3_object_key = f"{S3_KEY_PREFIX.lstrip('/').rstrip('/')}/{json_file_name}"

    try:
        s3_client.upload_file(local_json_path, S3_BUCKET_NAME, s3_object_key, ExtraArgs={'ContentType': 'application/json'})
        s3_path = f"s3://{S3_BUCKET_NAME}/{s3_object_key}"
        print(f"Successfully uploaded report to {s3_path}")
        return {
            "statusCode": 200,
            "body": json.dumps({
                "message": f"EC2 report generated and uploaded to S3 as JSON. Found {len(all_instances_data)} instances.",
                "s3_path": s3_path
            })
        }
    except Exception as e:
        print(f"Error uploading to S3: {str(e)}")
        return {"statusCode": 500, "body": json.dumps({"error": f"Failed to upload to S3: {str(e)}"}) }

if __name__ == "__main__":
    # --- For Local Testing ---
    # Set environment variables:
    # export S3_BUCKET_NAME="your-s3-bucket-name"
    # export S3_KEY_PREFIX="ec2_lambda_reports/"
    # (Optional) export CPU_METRIC_PERIOD_MINUTES="30"
    # (Optional) export CPU_METRIC_STATISTIC="Maximum"
    # Ensure your local AWS credentials are configured (e.g., via ~/.aws/credentials or env vars)
    # and have the necessary IAM permissions listed above.

    print("--- Simulating Local Lambda Execution for EC2 Report (JSON) ---")
    if not S3_BUCKET_NAME:
        print("S3_BUCKET_NAME environment variable not set. Please set it for local testing.")
    else:
        # Mock event and context
        mock_event = {}
        mock_context = {}
        result = lambda_handler(mock_event, mock_context)
        print("\n--- Lambda Result ---")
        print(json.dumps(result, indent=2))
        if result.get("statusCode") == 200 and "s3_path" in json.loads(result.get("body", "{}")):
            print(f"Local test: Report should be at {json.loads(result['body'])['s3_path']}")
            print(f"Local JSON file (if not cleaned up by OS) would be at /tmp/ec2_instances_report_*.json")
        else:
            print("Local test: Report generation or upload may have failed.")
    print("--- End Local Simulation ---")
