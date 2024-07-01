import datetime
from datetime import datetime
from unittest.mock import patch
from unittest import TestCase

from alert import Alert
import find_stale_keys
from threshold import Threshold


class Test(TestCase):
    def setUp(self):
        self.test_dict = {"user": "break.glass", "arn": "arn:aws:iam::12345678:user/break.glass",\
                          "user_creation_time": "2023-04-12T21:23:57+00:00", "password_enabled": "false",\
                          "password_last_used": "N/A", "password_last_changed": "N/A",\
                          "password_next_rotation": ('foo',), "mfa_active": "false", "access_key_1_active": "true",\
                          "access_key_1_last_rotated": "2023-04-12T21:23:58+00:00",\
                          "access_key_1_last_used_date": "N/A", "access_key_1_last_used_region": "N/A",\
                          "access_key_1_last_used_service": "N/A", "access_key_2_active": "false",\
                          "access_key_2_last_rotated": "N/A", "access_key_2_last_used_date": "N/A",\
                          "access_key_2_last_used_region": "N/A", "access_key_2_last_used_service": "N/A",\
                          "cert_1_active": "false", "cert_1_last_rotated": "N/A",\
                          "cert_2_active": "false", "cert_2_last_rotated": "N/A"}
        self.aws_users = [
            Threshold(account_type="Operators", is_wildcard=False, warn=90, violation=180, alert=True, user="Ben"),
            Threshold(account_type="Platform", is_wildcard=False, warn=90, violation=180, alert=True, user="cg-ecr-somelongishthing"),
            Threshold(account_type="Customer", is_wildcard=True, warn=180, violation=270, alert=False, user="cg-s3-somelonguidishname"),
            Threshold(account_type="Operators", is_wildcard=False, warn=90, violation=180, alert=True, user="Robert"),
            Threshold(account_type="Platform", is_wildcard=False, warn=90, violation=180, alert=True, user="Mark"),
            Threshold(account_type="Platform", is_wildcard=False, warn=90, violation=180, alert=True, user="James")
        ]

    @patch('find_stale_keys.datetime')
    def test_check_retention(self, mock_datetime):
        mock_date = datetime(2024,4,25)
        mock_datetime.now.return_value = mock_date
        actual = find_stale_keys.check_retention(90, 180, "2024-04-12T21:23:58+00:00")
        expected = Alert(find_stale_keys.OK, datetime(2024,7,11,21,23,58), datetime(2024,10,9,21, 23,58))
        self.assertEqual(actual, expected)

    def test_find_known_user(self):
        # This should fail due to typo in name
        actual = find_stale_keys.find_known_user("cg-s3-somelonguidishname", self.aws_users)
        expected = Threshold(account_type="Customer", is_wildcard=False, warn=180, violation=270, alert=False, user="cg-s3-smelonguidishname")
        self.assertNotEqual(actual, expected)

        # This passes due to expected being the same as actual
        actual = find_stale_keys.find_known_user("cg-s3-somelonguidishname", self.aws_users)
        expected = Threshold(account_type="Customer", is_wildcard=True, warn=180, violation=270, alert=False, user="cg-s3-somelonguidishname")
        self.assertEqual(actual, expected)

        # This passes and is an example of exact matching for name
        actual = find_stale_keys.find_known_user("Ben", self.aws_users)
        expected = Threshold(account_type="Operators", is_wildcard=False, warn=90, violation=180, alert=True, user="Ben")
        self.assertEqual(actual, expected)

        # This passes and is an example of Fuzzy searching for a Platform user
        actual = find_stale_keys.find_known_user("cg-ecr-somelongishthing", self.aws_users)
        expected = Threshold(account_type="Platform", is_wildcard=False, warn=90, violation=180, alert=True, user="cg-ecr-somelongishthing")
        self.assertEqual(actual, expected)

    def test_account_for_arn(self):
        # This will pass and is the standard use case
        actual = find_stale_keys.account_for_arn("arn:aws:iam::12345678:user/break.glass")
        expected = '12345678'
        self.assertEqual(actual, expected)

        # This will also pass but is not a use case so more logic is needed for account_for_arn
        actual = find_stale_keys.account_for_arn("")
        expected = ''
        self.assertEqual(actual, expected)

    def test_username_from_row(self):
        # This will pass and is the standard use case
        actual = find_stale_keys.username_from_row(self.test_dict)
        expected = "break.glass-5678"

        # This will not pass as it's missing the last 4 of the account
        actual = find_stale_keys.username_from_row(self.test_dict)
        expected = "break.glass-"
