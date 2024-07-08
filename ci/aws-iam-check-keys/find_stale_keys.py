#!/usr/bin/env python

import argparse
import dataclasses
from copy import copy
import csv
from datetime import timedelta, datetime
from typing import Any

from dateutil.parser import parse
from environs import Env
from pathlib import Path
import re
import sys
import time
import yaml

import boto3
from prometheus_client import CollectorRegistry, Gauge, pushadd_to_gateway

from alert import Alert
from threshold import Threshold

VIOLATION = "violation"
WARNING = "warning"
OK = ""
uncleared_alerts = []
cleared_alerts = []


def main():
    """
    This is where the loading of the various files for reference occurs. This also kicks off the process
    to find the stale keys and then push any alerts out as well.
    """

    # grab the state files, user files and outputs from cg-provision from the
    # s3 buckets for com and gov users
    local_env = Env()
    debug = False
    base_dir = local_env.str("BASE_DIR", None)
    if not base_dir:
        base_dir = "../../.."
    base_path = Path(base_dir)

    # Parse the CLI for any arguments
    # Note that the default value of 1 is following to allow for levels or other
    # info to be passed later if needed
    parser = argparse.ArgumentParser(description='Arguments for find_stale_keys')
    parser.add_argument('-d', '--debug', action="store_true", help='debug mode no levels for now')
    args = parser.parse_args()
    if args.debug:
        debug = True

    # Debug code goes here
    if debug:
        thresholds_filename = "ci/aws-iam-check-keys/thresholds.yml"
        base_dir = ".."
        base_path = Path(base_dir)
    else:
        thresholds_filename = "thresholds.yml"

    com_state_file = base_path / "terraform-prod-com-yml/state.yml"
    gov_state_file = base_path / "terraform-prod-gov-yml/state.yml"
    com_users_filename = base_path / "aws-admin/stacks/gov/sso/users.yaml"
    gov_users_filename = base_path / "aws-admin/stacks/com/sso/users.yaml"
    tf_state_filename = base_path / "terraform-yaml-production/state.yml"
    other_users_filename = base_path / "other-iam-users-yml/other_iam_users.yml"

    # AWS regions
    com_region = "us-east-1"
    gov_region = "us-gov-west-1"

    thresholds = load_thresholds(thresholds_filename)
    com_users_list = load_system_users(com_users_filename, thresholds)
    gov_users_list = load_system_users(gov_users_filename, thresholds)
    tf_users = load_tf_users(tf_state_filename, thresholds)
    other_users = load_other_users(other_users_filename)

    (com_state_dict, gov_state_dict) = load_profiles(com_state_file,
                                                     gov_state_file)

    for com_key in com_state_dict:
        all_com_users = com_users_list + tf_users + other_users
        # print(f"about to search com using key: {com_key}")
        search_for_keys(com_region, com_state_dict[com_key], all_com_users)
    for gov_key in gov_state_dict:
        all_gov_users = gov_users_list + tf_users + other_users
        # print(f"about to search gov using key: {gov_key}")
        search_for_keys(gov_region, gov_state_dict[gov_key], all_gov_users)
    print(f'about to send {len(uncleared_alerts)} uncleared and {len(cleared_alerts)} cleared')
    send_data_via_client()


def account_for_arn(arn) -> str:
    """
     The format of an arn is:
     arn:aws-us-gov:iam::account-here:user/cf-production/s3/cg-s3-some-guid-here
     This pulls out the account number and returns it
    """
    arn_components = arn.split(':')
    account = ""
    if len(arn_components) > 1:
        account = arn_components[4]
    return account.strip()


def username_from_row(row: dict) -> str:
    """
    Returns the user name in the format: user name-last four of the account number
    """
    account_num = account_for_arn(row['arn'])
    user = row['user']
    return f"{user}-{str(account_num)[-4:]}"


def check_retention(warn_days: int, violation_days: int, access_key_date: str) -> Alert:
    """
    Returns an Alert dataclass with alert type violation when keys were last rotated
    more than :violation_days: ago and alert type warning when keys were last rotated
    :warn_days: ago if it is neither OK is returned for the alert_type
    """
    key_date = parse(access_key_date, ignoretz=True)
    violation_days_delta = key_date + timedelta(days=violation_days)
    warning_days_delta = key_date + timedelta(days=warn_days)
    alert_type = OK
    if violation_days_delta <= datetime.now():
        alert_type = VIOLATION
    if warning_days_delta <= datetime.now():
        alert_type = WARNING
    return Alert(alert_type=alert_type,
                 warn_date=warning_days_delta,
                 violation_date=violation_days_delta)


def find_known_user(report_user: str, aws_users: list[Threshold]) -> Threshold:
    """
    Return the row as a Threshold, from the users dictionary matching the report user if it exists.
    This will be used for validating thresholds for the key rotation date timeframes
    """
    aws_user = None
    found = [aws_user for aws_user in aws_users if aws_user.user in report_user]
    if found:
        aws_user = copy(found[0])
    return aws_user


def check_retention_for_key(access_key_last_rotated: str, access_key_num: int, aws_user: Threshold):
    """
    Given the last rotated date, which access key number and the threshold for the given user, check
    to see if an alert is needed for either a warning, violation or both
    """
    alert = check_retention(int(aws_user.warn), int(aws_user.violation), access_key_last_rotated)

    alert.last_rotated = parse(access_key_last_rotated, ignoretz=True)
    alert.key_num = access_key_num
    alert.username = aws_user.user
    alert_dict: dict[str, Any] = dataclasses.asdict(alert)

    if alert.alert_type != OK:
        print(f'adding uncleared alert: {alert_dict}')
        uncleared_alerts.append(alert_dict)
    else:
        print(f'adding cleared alert: {alert_dict}')
        cleared_alerts.append(alert_dict)


def send_data_via_client():
    """
    Send uncleared and cleared alerts to Prometheus via the Pushgateway
    """
    registry = CollectorRegistry()
    gateway = f'{env.str("GATEWAY_HOST")}:{env.str("GATEWAY_PORT","9091")}'

    key_info = Gauge("stale_key_num", "Stale key needs to be rotated (1) or not (0)",
                     ['username', 'alert_type', 'key_num', 'last_rotated', 'warn_date', 'violation_date'],
                     registry=registry)
    for uncleared_alert in uncleared_alerts:
        key_info.labels(**uncleared_alert).set(1)
        pushadd_to_gateway(gateway,  job='find_stale_keys', registry=registry)

    for cleared_alert in cleared_alerts:
        key_info.labels(**cleared_alert).set(0)
        pushadd_to_gateway(gateway,  job='find_stale_keys', registry=registry)


def check_access_keys(user_row: dict, aws_user: Threshold):
    """
    Validate key staleness for both access keys, provided they exist, for a
    given user
    """
    last_rotated_key1 = user_row['access_key_1_last_rotated']
    last_rotated_key2 = user_row['access_key_2_last_rotated']

    # note that if we decide to alert customers, we'll need to modify the threshold info
    # setting alert to True for customers
    if aws_user.alert:
        aws_user.user = username_from_row(user_row)

        if last_rotated_key1 != "N/A":
            check_retention_for_key(last_rotated_key1, 1, aws_user)

        if last_rotated_key2 != "N/A":
            check_retention_for_key(last_rotated_key2, 2, aws_user)


def check_user_thresholds(aws_user: Threshold, report_row: dict):
    """
    Grab the thresholds and pass them on with the row
    from the credentials report to be used for checking the keys
    """
    warn_days = aws_user.warn
    violation_days = aws_user.violation
    local_env = Env()

    if warn_days == 0 or violation_days == 0:
        aws_user.warn = local_env.int("WARN_DAYS", 60)
        aws_user.violation = local_env.int("VIOLATION_DAYS", 90)
    check_access_keys(report_row, aws_user)


def search_for_keys(region_name: str, profile: dict, all_users: list[Threshold]):
    """
    The main search function that reaches out to AWS IAM to grab the
    credentials report as csv and load it into a list of dictionaries.
    This list is then used to determine if a user has stale keys or not based on
    the last rotation date for each of the access keys.
    """

    # First let's get a session based on the user access key,
    # so we can get all the users for a given account via the Python boto3 lib
    session = boto3.Session(region_name=region_name,
                            aws_access_key_id=profile['id'],
                            aws_secret_access_key=profile['secret'])
    iam = session.client('iam')
    # Generate credential report for the given profile
    # Generating the report is an async operation, so wait for it by sleeping
    # If Python has async await type of construct it would be good to use here
    w_time = 0
    while iam.generate_credential_report()['State'] != 'COMPLETE':
        w_time = w_time + 5
        print("Waiting...{}".format(w_time))
        time.sleep(w_time)
    report = iam.get_credential_report()
    content = report["Content"].decode("utf-8")
    content_lines = content.split("\n")

    # Initiate the reader, convert the csv contents to a list and turn each row
    # into a dictionary to use for the credentials check
    csv_reader = csv.DictReader(content_lines, delimiter=",")
    not_found = []
    row: dict
    for row in csv_reader:
        user_name = row['user']

        # Note: second return value in tuple below is ignored for now
        # When we want to do something with unknown users we can hook it up here
        aws_user = find_known_user(user_name, all_users)
        if not aws_user:
            # print(f"about to add {user_name} to not_found list")
            not_found.append(user_name)
        else:
            check_user_thresholds(aws_user, row)


def state_file_to_dict(all_outputs: dict):
    """ Convert the production state file to a dict
    data structure
    {profile_key = {id:value, secret:value}}
    """
    output_dict = {}
    for key, value in all_outputs.items():
        new_key = re.sub("_.*", "", key)
        if new_key not in output_dict:
            output_dict[new_key] = {}
        if 'id' in key:
            output_dict[new_key]['id'] = value
        if 'secret' in key:
            output_dict[new_key]['secret'] = value

    return output_dict


def get_platform_thresholds(thresholds: list[Threshold], account_type: str):
    found_thresholds = [threshold_dict for threshold_dict in thresholds
                        if threshold_dict.account_type == account_type]
    if found_thresholds:
        return copy(found_thresholds[0])
    else:
        return None


def format_user_dicts(users_list: list, thresholds: list[Threshold], account_type) -> list[Threshold]:
    """
    Augment the users list to have the threshold information.
    """
    augmented_user_list = []
    for key in users_list:
        found_user_threshold = get_platform_thresholds(thresholds, account_type)
        found_user_threshold.user = key
        augmented_user_list.append(found_user_threshold)
    return augmented_user_list


def load_profiles(com_state_file: Path, gov_state_file: Path):
    """
    Clean up yaml from state files for com and gov
    These are the secrets used for assume_role to pull
    user info from the accounts
    """
    with com_state_file.open() as f:
        com_state = yaml.safe_load(f)
    with gov_state_file.open() as f:
        gov_state = yaml.safe_load(f)
    all_outputs_com = com_state['terraform_outputs']
    all_outputs_gov = gov_state['terraform_outputs']
    com_state_dict = state_file_to_dict(all_outputs_com)
    gov_state_dict = state_file_to_dict(all_outputs_gov)
    return com_state_dict, gov_state_dict


def load_tf_users(tf_filename: Path, thresholds: list[Threshold]) -> list[Threshold]:
    """
    Schema for tf_users - need to verify this is correct
    {
      user:user_name,
      account_type:"Platform",
      is_wildcard: False,
      alert: True,
      warn: 165,
      violation: 180
    }
    Note that all values are hardcoded except the username
    This file is scraped for more users to search for stale keys
    """
    tf_users: list[Threshold] = []
    with open(tf_filename) as f:
        tf_yaml = yaml.safe_load(f)
    outputs = tf_yaml['terraform_outputs']
    for key in list(outputs):
        if "username" in key:
            found_user_threshold = get_platform_thresholds(thresholds, "Platform")
            found_user_threshold.user = outputs[key]
            tf_users.append(found_user_threshold)
    return tf_users


def load_other_users(other_users_filename: Path) -> list[Threshold]:
    """
    Schema for other_users is
    {   user: user_name,
        account_type:account_type,
        is_wildcard: True|False,
        alert: True|False,
        warn: warn,
        violation: violation
    }
    Note that all values are hardcoded in the yaml
    Threshold is a dataclass which has the properties in the above schema
    """
    with open(other_users_filename) as f:
        other_users_yaml = yaml.safe_load(f)

    return [Threshold(**other) for other in other_users_yaml]


def load_system_users(filename: Path, thresholds: list[Threshold]) -> list[Threshold]:
    """
    Schema for gov or com users after pull out the "users" dict
    {"user.name":{'aws_groups': ['Operators', 'OrgAdmins']}}
    translated to:
    {"user":user_name, "account_type":"Operators"} - note Operators is
    hardcoded for now
    """
    with open(filename) as f:
        users_list = list(yaml.safe_load(f)["users"])
    users_list = format_user_dicts(users_list, thresholds, "Operator")
    return users_list


def load_thresholds(filename: str) -> list[Threshold]:
    """
    This is the file that holds all the threshold information to be added to
    the user list dictionaries.
    """
    with open(filename) as f:
        thresholds_yaml = yaml.safe_load(f)
    return [Threshold(**threshold) for threshold in thresholds_yaml]


if __name__ == "__main__":
    # Set up the GATEWAY to send alerts to Prometheus
    env = Env()
    try:
        env.str("GATEWAY_HOST")
    except ValueError as err:
        print(f"GATEWAY_HOST missing: {err}")
        sys.exit(1)
    main()
