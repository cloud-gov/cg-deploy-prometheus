from datetime import date
import os
from peewee import *

"""
Reference Table data structure info:
reference_table['user'] = r['user_string']
reference_table['is_wildcard'] = r['is_wildcard']
reference_table['account_type'] = r['account_type']
reference_table['alert'] = r['alert']
reference_table['warning'] = r['warn']
reference_table['violation'] = r['violation']

Credential Report columns:
user
arn
user_creation_time ISO 8601
password_enabled Boolean
password_last_used ISO 8601, N/A
password_last_changed ISO 8601, N/A
password_next_rotation ISO 8601
mfa_active Boolean
access_key_1_active Boolean
access_key_1_last_rotated ISO 8601, N/A
access_key_1_last_used_date ISO 8601, N/A
access_key_1_last_used_region String, N/A
access_key_1_last_used_service String, N/A
access_key_2_active Boolean
access_key_2_last_rotated ISO 8601, N/A
access_key_2_last_used_date ISO 8601, N/A
access_key_2_last_used_region String, N/
access_key_2_last_used_service String, N/
cert_1_active Boolean
cert_1_last_rotated ISO 8601, N/A
cert_2_active Boolean
cert_2_last_rotated ISO 8601, N/A

reference:
https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html
"""

keys_db = os.getenv('IAM_KEYS_DB')
user = os.getenv('IAM_KEYS_USER')
password = os.getenv('IAM_KEYS_PASSWORD')
host = os.getenv('IAM_KEYS_HOST')
port = os.getenv('IAM_KEYS_PORT')


db = PostgresqlDatabase(
    keys_db,
    user=user,
    password=password,
    host=host,
    port=port)

class BaseModel(Model):
    """A base model that will use our Postgresql database"""
    class Meta:
        database = db

# Model for IAM_Keys, note the attributes that allow null and those that don't
class IAM_Keys(BaseModel):
    iam_user = CharField()
    aws_account = CharField()
    arn = CharField(unique=True)
    user_creation_time = DateTimeField(null=True)
    password_enabled = BooleanField()
    password_last_used = DateTimeField(null=True)
    password_last_changed = DateTimeField(null=True)
    password_next_rotation = DateTimeField(null=True)
    mfa_active = BooleanField()
    access_key_1_active = BooleanField()
    access_key_1_last_rotated = DateTimeField(null=True)
    access_key_1_last_used_date = DateTimeField(null=True)
    access_key_1_last_used_region = CharField(null=True)
    access_key_1_last_used_service = CharField(null=True)
    access_key_2_active = BooleanField()
    access_key_2_last_rotated = DateTimeField(null=True)
    access_key_2_last_used_date = DateTimeField(null=True)
    access_key_2_last_used_region = CharField(null=True)
    access_key_2_last_used_service = CharField(null=True)
    cert_1_active = BooleanField()
    cert_1_last_rotated = DateTimeField(null=True)
    cert_2_active = BooleanField()
    cert_2_last_rotated = DateTimeField(null=True)
    created_at = DateTimeField()
    updated_at = DateTimeField(null=True)

    @classmethod
    def account_for_arn(cls, arn):
        # arn:aws-us-gov:iam::account-here:user/cf-production/s3/cg-s3-some-guid-here
        arn_components = arn.split(':')
        account = ""
        if len(arn_components) > 1:
            account = arn_components[4]
        return account

    @classmethod
    def clean_dict(cls, keys_dict):
        for key in keys_dict:
            if keys_dict[key] == 'N/A':
                keys_dict[key] = None
        return keys_dict

    @classmethod
    def user_from_dict(cls, keys_dict):
        keys_dict = cls.clean_dict(keys_dict)

        user, created = IAM_Keys.get_or_create(
            iam_user=keys_dict['user'],
            aws_account=cls.account_for_arn(keys_dict['arn']),
            arn=keys_dict['arn'],
            user_creation_time=keys_dict['user_creation_time'],
            password_enabled=keys_dict['password_enabled'],
            password_last_used=keys_dict['password_last_used'],
            password_last_changed=keys_dict['password_last_changed'],
            password_next_rotation=keys_dict['password_next_rotation'],
            mfa_active=keys_dict['mfa_active'],
            access_key_1_active=keys_dict['access_key_1_active'],
            access_key_1_last_rotated=keys_dict['access_key_1_last_rotated'],
            access_key_1_last_used_date=keys_dict['access_key_1_last_used_date'],
            access_key_1_last_used_region=keys_dict['access_key_1_last_used_region'],
            access_key_1_last_used_service=keys_dict['access_key_1_last_used_service'],
            access_key_2_active=keys_dict['access_key_2_active'],
            access_key_2_last_rotated=keys_dict['access_key_2_last_rotated'],
            access_key_2_last_used_date=keys_dict['access_key_2_last_used_date'],
            access_key_2_last_used_region=keys_dict['access_key_2_last_used_region'],
            access_key_2_last_used_service=keys_dict['access_key_2_last_used_service'],
            cert_1_active=keys_dict['cert_1_active'],
            cert_1_last_rotated=keys_dict['cert_1_last_rotated'],
            cert_2_active=keys_dict['cert_2_active'],
            cert_2_last_rotated=keys_dict['cert_2_last_rotated'],
            created_at=date.today(),
            updated_at=date.today(),

        )
        return user


# Event Type stores the various event types such as warning and violation
class Event_Type(BaseModel):
    event_type_name = CharField(unique=True)
    created_at = DateTimeField()

    @classmethod
    def insert_event_type(cls, name):
        event_type, created = Event_Type.get_or_create(event_type_name=name,
                                                       created_at=date.today())
        return event_type, created


# The events as they happen based on IAM creds not being rotated in a
# timely manner
class Event(BaseModel):
    user = ForeignKeyField(IAM_Keys, backref='events')
    event_type = ForeignKeyField(Event_Type, backref='events')
    access_key_num = IntegerField()
    cleared = BooleanField()
    cleared_date = DateTimeField(null=True)
    alert_sent = BooleanField()
    created_at = DateTimeField()

    @classmethod
    def new_event_type_user(cls, event_type, user, access_key_num):
        print(f'In data model: user: {user} event_type: {event_type} key: {access_key_num} type:{type(access_key_num)}\n')
        event = Event.create(user=user, event_type=event_type, cleared=False,
                             alert_sent=False, created_at=date.today(),
                             access_key_num=access_key_num)
        return event

    @classmethod
    def all_cleared_events(cls):
        events = Event.select().where(Event.cleared == True)
        return events

    @classmethod
    def all_uncleared_events(cls):
        events = Event.select().where(Event.cleared == False)
        return events


def drop_all_tables():
    if not db.is_connection_usable:
        db.connect()
    with db:
        db.drop_tables([IAM_Keys, Event_Type, Event])


def create_tables():
    """
    Convenience for creating the tables, can be dropped in favor of sql scripts
    if preferred
    NOTE: This is destructive! The tables all get dropped before it's created!

    """
    db.connect()  # can check if this is True to go on
    with db:
        drop_all_tables()
        db.create_tables([IAM_Keys, Event_Type, Event])
    # Set up event types here!


def connect():
    db.connect()
