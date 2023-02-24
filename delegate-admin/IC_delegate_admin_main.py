import boto3
import os
import json
import logging
from time import sleep

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def delegate_sso_admin(event, context):
    delegate = event["delegate"]
    print(f'Input value for delegate {delegate}')
    if delegate.lower() != 'true':
        print(f'Delegate: {delegate.lower()}. Delegation not requested')
        return

    account_id = event["account_id"]
    print(f'Input value for account ID to delegate AWS IC to: {account_id}')

    org_client = boto3.client('organizations')

    # List the delegated administrators for IC
    admins = org_client.list_delegated_administrators(
        ServicePrincipal='sso.amazonaws.com'
    )
    sleep(0.1)

    # Check if any other accounts are delegated admins for IC
    other_admins = [admin['Id']
                    for admin in admins['DelegatedAdministrators'] if admin['Id'] != account_id]
    if other_admins:
        # Deregister the other delegated admins for IC
        for admin_id in other_admins:
            print('Deregistreing other delegated administrators for AWS IC')
            org_client.deregister_delegated_administrator(
                AccountId=admin_id,
                ServicePrincipal='sso.amazonaws.com'
            )
            print(f'Deregistered {admin_id}')
            sleep(0.1)

    # Check if the specified account is already a delegated admin for IC
    found = False
    for admin in admins['DelegatedAdministrators']:
        if admin['Id'] == account_id:
            found = True
            print(f'{account_id} is already a delegated administrator for AWS IC')
            break

    if not found:
        # Delegate the specified account as an administrator for IC
        org_client.register_delegated_administrator(
            AccountId=account_id,
            ServicePrincipal='sso.amazonaws.com'
        )
        print(f'Delegated {account_id} as administrator for AWS IC')
        sleep(0.1)


def lambda_handler(event, context):
    logger.info(event)
    logger.debug(context)
    try:
        delegate_sso_admin(event, context)
    except Exception as e:
        logger.exception(e)
