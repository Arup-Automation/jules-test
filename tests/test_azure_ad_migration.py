import os # Added import
import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta, timezone

# Assuming your main script is in src.azure_ad_migration
# Adjust the import path if your structure is different or if you move the file
from src.azure_ad_migration import (
    get_vault_secrets,
    get_azure_ad_token,
    # _graph_api_request, # Typically not directly tested, but through its callers
    get_users_from_azure_group,
    get_user_devices,
    add_user_to_azure_group,
    remove_user_from_azure_group,
    parse_datetime_string,
    is_device_compliant_and_active,
    create_freshservice_ticket,
    send_email_ses,
    upsert_user_migration_status,
    # lambda_handler, # E2E/Integration test - harder to unit test directly without significant mocking
    # migration_monitor_handler # E2E/Integration test
)

# --- Constants for Testing ---
MOCK_VAULT_ADDR = "http://mock-vault:8200"
MOCK_VAULT_TOKEN = "mock_vault_token"
MOCK_SECRET_PATH = "secret/data/app/mock_app"
MOCK_VAULT_NAMESPACE = "mock_namespace"
MOCK_VAULT_KV_MOUNT_POINT = "secret" # or your test specific mount point
MOCK_AZURE_TENANT_ID = "mock_tenant_id"
MOCK_AZURE_CLIENT_ID = "mock_client_id"
MOCK_AZURE_CLIENT_SECRET = "mock_client_secret"
MOCK_AZURE_GROUP_ID = "mock_group_id"
MOCK_USER_ID = "mock_user_id"
MOCK_FRESHSERVICE_DOMAIN = "mockdomain"
MOCK_FRESHSERVICE_API_KEY = "mock_fs_apikey"
MOCK_SES_SENDER = "sender@example.com"
MOCK_SES_REGION = "us-east-1"
MOCK_DDB_TABLE = "mock_migration_table"

class TestAzureADMigration(unittest.TestCase):

    def setUp(self):
        """Setup common test variables and patch global config variables."""
        # Patch the global config variables in the module where they are defined and used
        self.patch_azure_tenant_id = patch('src.azure_ad_migration.AZURE_TENANT_ID', MOCK_AZURE_TENANT_ID)
        self.patch_azure_client_id = patch('src.azure_ad_migration.AZURE_CLIENT_ID', MOCK_AZURE_CLIENT_ID)
        self.patch_azure_client_secret = patch('src.azure_ad_migration.AZURE_CLIENT_SECRET', MOCK_AZURE_CLIENT_SECRET)
        self.patch_fs_domain = patch('src.azure_ad_migration.FRESHSERVICE_DOMAIN', MOCK_FRESHSERVICE_DOMAIN)
        self.patch_fs_api_key = patch('src.azure_ad_migration.FRESHSERVICE_API_KEY', MOCK_FRESHSERVICE_API_KEY)
        self.patch_ses_sender = patch('src.azure_ad_migration.SES_SENDER_EMAIL', MOCK_SES_SENDER)
        self.patch_ses_region = patch('src.azure_ad_migration.SES_REGION', MOCK_SES_REGION)
        self.patch_ddb_table = patch('src.azure_ad_migration.DYNAMODB_TABLE_NAME', MOCK_DDB_TABLE)
        self.patch_vault_namespace = patch('src.azure_ad_migration.VAULT_NAMESPACE', MOCK_VAULT_NAMESPACE)
        self.patch_vault_kv_mount_point = patch('src.azure_ad_migration.VAULT_KV_MOUNT_POINT', MOCK_VAULT_KV_MOUNT_POINT)


        self.patch_azure_tenant_id.start()
        self.patch_azure_client_id.start()
        self.patch_azure_client_secret.start()
        self.patch_fs_domain.start()
        self.patch_fs_api_key.start()
        self.patch_ses_sender.start()
        self.patch_ses_region.start()
        self.patch_ddb_table.start()
        self.patch_vault_namespace.start()
        self.patch_vault_kv_mount_point.start()

        # Reset graph API token cache before each test if it's a global
        self.graph_cache_patch = patch('src.azure_ad_migration.graph_api_token_cache', {"token": None, "expires_at": datetime.now(timezone.utc)})
        self.graph_cache_patch.start()


    def tearDown(self):
        self.graph_cache_patch.stop()
        self.patch_azure_tenant_id.stop()
        self.patch_azure_client_id.stop()
        self.patch_azure_client_secret.stop()
        self.patch_fs_domain.stop()
        self.patch_fs_api_key.stop()
        self.patch_ses_sender.stop()
        self.patch_ses_region.stop()
        self.patch_ddb_table.stop()
        self.patch_vault_namespace.stop()
        self.patch_vault_kv_mount_point.stop()
        patch.stopall() # Stops all patches started with patch()

    @patch.dict(os.environ, {
        "AWS_ACCESS_KEY_ID": "mock_access_key",
        "AWS_SECRET_ACCESS_KEY": "mock_secret_key",
        "AWS_SESSION_TOKEN": "mock_session_token",
        "AWS_LAMBDA_FUNCTION_NAME": "mock_lambda_name" # To trigger IAM auth path
    })
    @patch('src.azure_ad_migration.hvac.Client')
    def test_get_vault_secrets_iam_auth_success(self, MockHvacClient):
        mock_client_instance = MockHvacClient.return_value
        # Simulate successful IAM login
        mock_client_instance.auth.aws.iam_login.return_value = None
        mock_client_instance.is_authenticated.return_value = True # Ensure is_authenticated is True after login call

        mock_client_instance.secrets.kv.v2.read_secret.return_value = {
            'data': {'data': {'API_KEY': 'iam_key', 'API_SECRET': 'iam_secret'}}
        }

        # Call with no explicit token/role_id to force IAM path based on env vars
        secrets = get_vault_secrets(vault_addr=MOCK_VAULT_ADDR, secret_path=MOCK_SECRET_PATH)

        self.assertIsNotNone(secrets)
        self.assertEqual(secrets.get('API_KEY'), 'iam_key')
        MockHvacClient.assert_called_with(url=MOCK_VAULT_ADDR, namespace=MOCK_VAULT_NAMESPACE)
        mock_client_instance.auth.aws.iam_login.assert_called_once_with(
            access_key="mock_access_key",
            secret_key="mock_secret_key",
            session_token="mock_session_token"
        )
        mock_client_instance.secrets.kv.v2.read_secret.assert_called_with(
            path=MOCK_SECRET_PATH,
            mount_point=MOCK_VAULT_KV_MOUNT_POINT
        )

    @patch('src.azure_ad_migration.hvac.Client')
    def test_get_vault_secrets_token_auth(self, MockHvacClient):
        # Ensure AWS IAM env vars are not set, and AppRole IDs are not set to test token auth fallback
        with patch.dict(os.environ, {}, clear=True):
            # Patch global VAULT_ROLE_ID and VAULT_SECRET_ID to None for this test context
            # to ensure AppRole auth path is not taken.
            with patch('src.azure_ad_migration.VAULT_ROLE_ID', None), \
                 patch('src.azure_ad_migration.VAULT_SECRET_ID', None):

                mock_client_instance = MockHvacClient.return_value

                # Sequence of is_authenticated calls:
                # 1. After client init (before specific auth attempts if IAM keys/AppRole ID not present) -> False
                # This is checked by "if not client.is_authenticated():" before AppRole/Token.
                # 2. Inside token block, after token is set, this check "if not client.is_authenticated():" should pass. -> True
                # 3. Final check before reading secret -> True
                mock_client_instance.is_authenticated.side_effect = [False, True, True]

                mock_client_instance.secrets.kv.v2.read_secret.return_value = {
                    'data': {'data': {'API_KEY': 'token_key', 'API_SECRET': 'token_secret'}}
                }

                # Pass MOCK_VAULT_NAMESPACE and MOCK_VAULT_KV_MOUNT_POINT as overrides
                secrets = get_vault_secrets(
                    vault_addr=MOCK_VAULT_ADDR,
                    token=MOCK_VAULT_TOKEN,
                    secret_path=MOCK_SECRET_PATH,
                    vault_namespace_override=MOCK_VAULT_NAMESPACE, # Use override
                    kv_mount_point_override=MOCK_VAULT_KV_MOUNT_POINT  # Use override
                )
                self.assertIsNotNone(secrets, "Secrets should not be None after token auth")
                self.assertEqual(secrets.get('API_KEY'), 'token_key')
                # hvac.Client is called with the namespace from the override
                MockHvacClient.assert_called_with(url=MOCK_VAULT_ADDR, namespace=MOCK_VAULT_NAMESPACE)
                self.assertEqual(mock_client_instance.token, MOCK_VAULT_TOKEN)
                # read_secret is called with the mount_point from the override
                mock_client_instance.secrets.kv.v2.read_secret.assert_called_with(
                    path=MOCK_SECRET_PATH,
                    mount_point=MOCK_VAULT_KV_MOUNT_POINT
                )


    @patch('src.azure_ad_migration.requests.post')
    def test_get_azure_ad_token_success(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'access_token': 'mock_access_token',
            'expires_in': 3600
        }
        mock_post.return_value = mock_response

        token = get_azure_ad_token()
        self.assertEqual(token, 'mock_access_token')
        expected_url = f"https://login.microsoftonline.com/{MOCK_AZURE_TENANT_ID}/oauth2/v2.0/token"
        mock_post.assert_called_once()
        self.assertEqual(mock_post.call_args[0][0], expected_url)


    def test_parse_datetime_string(self):
        # Test with Zulu time
        dt_str_with_z = "2023-01-01T12:00:00Z"
        dt_obj = parse_datetime_string(dt_str_with_z)
        self.assertIsNotNone(dt_obj)
        self.assertEqual(dt_obj, datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc))

        # Test with microseconds and Z
        dt_str_with_micros_z = "2023-01-01T12:00:00.123456Z"
        dt_obj_micros = parse_datetime_string(dt_str_with_micros_z)
        self.assertIsNotNone(dt_obj_micros)
        self.assertEqual(dt_obj_micros, datetime(2023, 1, 1, 12, 0, 0, 123456, tzinfo=timezone.utc))

        # Test with offset
        dt_str_with_offset = "2023-01-01T12:00:00.123456+00:00"
        dt_obj_offset = parse_datetime_string(dt_str_with_offset)
        self.assertIsNotNone(dt_obj_offset)
        self.assertEqual(dt_obj_offset, datetime(2023, 1, 1, 12, 0, 0, 123456, tzinfo=timezone.utc))

        # Test with different offset that should convert to UTC
        dt_str_with_other_offset = "2023-01-01T15:00:00.000+03:00" # This is 12:00 UTC
        dt_obj_other_offset = parse_datetime_string(dt_str_with_other_offset)
        self.assertIsNotNone(dt_obj_other_offset)
        self.assertEqual(dt_obj_other_offset, datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc))

        # Test invalid date string
        self.assertIsNone(parse_datetime_string("invalid-date-string"))
        # Test None input
        self.assertIsNone(parse_datetime_string(None))


    def test_is_device_compliant_and_active(self):
        now = datetime.now(timezone.utc)
        # Using fromisoformat compatible strings for testing
        recent_activity = (now - timedelta(days=3)).isoformat()
        old_activity = (now - timedelta(days=10)).isoformat()

        devices_compliant_active_windows = [
            {'operatingSystem': 'Windows', 'isCompliant': True, 'approximateLastSignInDateTime': recent_activity, 'displayName': 'Win1'}
        ]
        is_compliant, device = is_device_compliant_and_active(devices_compliant_active_windows)
        self.assertTrue(is_compliant)
        self.assertEqual(device['displayName'], 'Win1')

        devices_compliant_active_mac = [
            {'operatingSystem': 'macOS', 'isCompliant': True, 'approximateLastSignInDateTime': recent_activity, 'displayName': 'Mac1'}
        ]
        is_compliant, device = is_device_compliant_and_active(devices_compliant_active_mac)
        self.assertTrue(is_compliant)
        self.assertEqual(device['displayName'], 'Mac1')

        devices_compliant_inactive = [
            {'operatingSystem': 'Windows', 'isCompliant': True, 'approximateLastSignInDateTime': old_activity}
        ]
        is_compliant, _ = is_device_compliant_and_active(devices_compliant_inactive)
        self.assertFalse(is_compliant)

        devices_non_compliant = [
            {'operatingSystem': 'Windows', 'isCompliant': False, 'approximateLastSignInDateTime': recent_activity}
        ]
        is_compliant, _ = is_device_compliant_and_active(devices_non_compliant)
        self.assertFalse(is_compliant)

        devices_other_os = [
            {'operatingSystem': 'Linux', 'isCompliant': True, 'approximateLastSignInDateTime': recent_activity}
        ]
        is_compliant, _ = is_device_compliant_and_active(devices_other_os)
        self.assertFalse(is_compliant)

        # Test with one compliant and one non-compliant, should pick compliant
        mixed_devices = [
            {'operatingSystem': 'Windows', 'isCompliant': False, 'approximateLastSignInDateTime': recent_activity, 'displayName': 'WinNonCompliant'},
            {'operatingSystem': 'macOS', 'isCompliant': True, 'approximateLastSignInDateTime': recent_activity, 'displayName': 'MacCompliantActive'}
        ]
        is_compliant, device = is_device_compliant_and_active(mixed_devices)
        self.assertTrue(is_compliant)
        self.assertEqual(device['displayName'], 'MacCompliantActive')

        self.assertFalse(is_device_compliant_and_active([])[0]) # Empty list

    @patch('src.azure_ad_migration.requests.post') # Mocking Graph API for Freshservice
    @patch('src.azure_ad_migration.get_azure_ad_token', return_value="mock_graph_token") # Mock Graph token for FS
    def test_create_freshservice_ticket(self, mock_get_token, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 201 # Freshservice uses 201 Created
        mock_response.json.return_value = {"ticket": {"id": 12345}}
        mock_post.return_value = mock_response

        ticket = create_freshservice_ticket("Test Subject", "<p>Test Desc</p>", "user@example.com")
        self.assertIsNotNone(ticket)
        self.assertEqual(ticket['ticket']['id'], 12345)
        expected_url = f"https://{MOCK_FRESHSERVICE_DOMAIN}.freshservice.com/api/v2/tickets"
        mock_post.assert_called_once()
        self.assertEqual(mock_post.call_args[0][0], expected_url)
        self.assertEqual(mock_post.call_args[1]['auth'], (MOCK_FRESHSERVICE_API_KEY, "X"))

    @patch('boto3.client') # Patch boto3.client directly
    def test_send_email_ses(self, mock_boto_client_constructor):
        mock_ses_client_instance = MagicMock()
        mock_ses_client_instance.send_email.return_value = {'MessageId': 'mock_message_id'}
        mock_boto_client_constructor.return_value = mock_ses_client_instance

        success = send_email_ses("Test Subject", "<h1>Test</h1>", "recipient@example.com")
        self.assertTrue(success)
        mock_boto_client_constructor.assert_called_with('ses', region_name=MOCK_SES_REGION)
        mock_ses_client_instance.send_email.assert_called_once()
        call_args = mock_ses_client_instance.send_email.call_args[1]
        self.assertEqual(call_args['Source'], MOCK_SES_SENDER)
        self.assertIn('recipient@example.com', call_args['Destination']['ToAddresses'])

    @patch('boto3.resource') # Patch boto3.resource directly
    def test_upsert_user_migration_status(self, mock_boto_resource_constructor):
        mock_table_instance = MagicMock()
        mock_dynamodb_resource_instance = MagicMock()
        mock_dynamodb_resource_instance.Table.return_value = mock_table_instance
        mock_boto_resource_constructor.return_value = mock_dynamodb_resource_instance

        success = upsert_user_migration_status("user123", "user@example.com", "TEST_STATUS")
        self.assertTrue(success)
        mock_boto_resource_constructor.assert_called_with('dynamodb', region_name=MOCK_SES_REGION)
        mock_dynamodb_resource_instance.Table.assert_called_with(MOCK_DDB_TABLE)

        self.assertTrue(mock_table_instance.put_item.called)
        item_arg = mock_table_instance.put_item.call_args[1]['Item']
        self.assertEqual(item_arg['user_id'], "user123")
        self.assertEqual(item_arg['user_email'], "user@example.com")
        self.assertEqual(item_arg['migration_status'], "TEST_STATUS")
        self.assertIn('last_updated_at', item_arg)

    @patch('src.azure_ad_migration.get_azure_ad_token', return_value="mock_graph_token_for_graph_call")
    @patch('src.azure_ad_migration.requests.request')
    def test_get_users_from_azure_group_mocked_graph_api(self, mock_requests_request, mock_get_ad_token):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "value": [{"id": "user1", "userPrincipalName": "user1@example.com"}],
            "@odata.nextLink": None # No pagination for this test
        }
        mock_requests_request.return_value = mock_response

        users = get_users_from_azure_group(MOCK_AZURE_GROUP_ID)
        self.assertIsNotNone(users)
        self.assertEqual(len(users), 1)
        self.assertEqual(users[0]['id'], 'user1')

        # Verify the Graph API call structure
        expected_url = f"https://graph.microsoft.com/v1.0/groups/{MOCK_AZURE_GROUP_ID}/members/microsoft.graph.user"
        mock_requests_request.assert_called_once()
        args, kwargs = mock_requests_request.call_args
        self.assertEqual(args[0], "GET") # Method
        self.assertEqual(args[1], expected_url) # URL
        self.assertIn("Authorization", kwargs['headers'])
        self.assertEqual(kwargs['headers']['Authorization'], "Bearer mock_graph_token_for_graph_call")
        self.assertIn("$select", kwargs['params'])


if __name__ == '__main__':
    unittest.main()
