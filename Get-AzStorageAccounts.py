#!/usr/bin/env python3

import os
import sys
from azure.identity import DefaultAzureCredential
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.resource import SubscriptionClient
from azure.core.exceptions import HttpResponseError,ClientAuthenticationError

# Authenticate with Azure
def get_credentials():
    try:
        return DefaultAzureCredential()
    except ClientAuthenticationError as e:
        print(f"Authentication failed: {e.message}")
        sys.exit(1)

# Analyze each storage account
def analyze_storage_account(client, sa, resource_group):
    print(f"\n🔎 Storage Account: {sa.name} (RG: {resource_group})")
    https_only = sa.enable_https_traffic_only
    print(f" - HTTPS Only: {'✅ Enforced' if https_only else '❌ Not enforced'}")
    public_access = sa.allow_blob_public_access
    if public_access is False:
        print(" - Public Blob Access: ❌ Disabled (Secure)")
    elif public_access is True:
        print(" - Public Blob Access: ⚠️ Enabled (Risky)")
    else:
        print(" - Public Blob Access: ⚠️ Unknown (May default toenabled)")

    try:
        properties = client.storage_accounts.get_properties(resource_group, sa.name)
        net_rules = properties.network_rule_set
        trusted = net_rules and net_rules.bypass and "AzureServices" in net_rules.bypass
        print(f" - Microsoft Trusted Services Access: {'✅ Enabled' if trusted else '❌ Not allowed'}")
    except HttpResponseError as e:
        print(f" - Error retrieving network rules: {e.message}")

    encryption = sa.encryption
    if encryption:
        source = encryption.key_source
        print(f" - Encryption: ✅ Enabled with {source}")
        if source == "Microsoft.Keyvault":
            print("      - Customer Managed Key (CMK): ✅ Used")
    else:
        print(" - Encryption: ❌ Not configured")

    try:
        keys = client.storage_accounts.list_keys(resource_group,sa.name)
        if keys and keys.keys:
            print(" - Access Keys: ✅ Present (Access Key Auth possible)")
    except HttpResponseError as e:
        print(f" - Error listing access keys: {e.message}")

    print(" - Key Rotation: ⚠️ Not detectable via SDK. Check AzureMonitor or Key Vault settings.")

def scan_subscription(subscription, credential):
    sub_id = subscription.subscription_id
    print(f"\n📦 Scanning Subscription: {subscription.display_name} ({sub_id})")

    try:
        storage_client = StorageManagementClient(credential, sub_id)
        accounts = storage_client.storage_accounts.list()
    except HttpResponseError as e:
        print(f" - Skipping subscription due to error: {e.message}")
        return

    for sa in accounts:
        resource_group = sa.id.split("/")[4]
        analyze_storage_account(storage_client, sa, resource_group)

def main():
    print("🔐 Azure Storage Account Security Audit Across All Subscriptions\n")

    credential = get_credentials()
    sub_client = SubscriptionClient(credential)

    try:
        subs = list(sub_client.subscriptions.list())
        if not subs:
            print("No subscriptions found for the authenticated account.")
            sys.exit(1)
    except HttpResponseError as e:
        print(f"Failed to list subscriptions: {e.message}")
        sys.exit(1)

    for subscription in subs:
        if subscription.state.lower() == "enabled":
            scan_subscription(subscription, credential)
        else:
            print(f" - Skipping subscription {subscription.display_name} (state: {subscription.state})")

if __name__ == "__main__":
    main()
