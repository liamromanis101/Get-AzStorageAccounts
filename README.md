# Get-AzStorageAccounts
Python3 script which enumerates available subscriptions and storage accounts in each. It then tests for weak configuration items. 

It flags issues related to:

- 🔐 Transparent Data Encryption (TDE)
- 📊 Auditing and retention
- 🚨 Threat Detection policies and alerts
- 🌐 Insecure firewall rules (e.g. AllowAllIPs)
- 📩 Missing alert email recipients
- 📉 Insufficient threat detection retention
- 🔁 Lack of geo-replication

## 📌 Features

For each Azure Storage Account, this script checks:

| Security Setting                  | Description                                                  |
|----------------------------------|--------------------------------------------------------------|
| **HTTPS Enforcement**            | Ensures only HTTPS traffic is allowed                        |
| **Public Blob Access**           | Detects if anonymous access is allowed to blobs              |
| **Microsoft Trusted Services**   | Verifies bypass for trusted Microsoft services               |
| **Encryption with CMK**          | Checks if Customer-Managed Keys are in use                   |
| **Access Key Availability**      | Warns if account keys are active and may be used for access  |
| **Key Rotation (not direct)**    | Flags that key rotation status is not detectable via SDK     |

---

## ⚙️ Prerequisites

- Python 3.7+
- Azure CLI (`az login`) or service principal authentication
- Python packages:
  ```bash
  pip install azure-identity azure-mgmt-resource azure-mgmt-storage

## 🔧 Usage

### 1. Clone the repository

```bash
git clone https://github.com/liamromanis101/Get-AzStorageAccounts/
cd Get-AzStorageAccounts

### 2. Authenticate with Azure

az login

alternatively, set environment variables:

  export AZURE_CLIENT_ID="your-client-id"
  export AZURE_TENANT_ID="your-tenant-id"
  export AZURE_CLIENT_SECRET="your-client-secret"

To limit to a single subscription, also set:

    export AZURE_SUBSCRIPTION_ID="your-subscription-id"

### 3. Install required Python packages

pip install azure-identity azure-mgmt-resource azure-mgmt-storage

### 4. Run the script:

  python3 azure_storage_audit.py



##  ✅ Example Output

```plaintext
📦 Subscription: My Company Prod Subscription (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
  🖥️ SQL Server: my-sql-server-prod (uksouth, RG: prod-resources)
    ⚠️ Insecure firewall rule: AllowAllIPs allows all IPs
    ❌ Server-level threat detection is disabled!
    ⚠️ No email addresses configured for threat alerts.
    ⚠️ Email to admins is not enabled.
    ⚠️ Threat detection retention period is 0 days.

    📂 Database: customerdb (Status: Online)
      ❌ TDE (encryption at rest) is not enabled!
      ❌ Auditing is not enabled!
      ⚠️ Threat detection is disabled at DB level!
      ⚠️ No email addresses configured for DB threat alerts.
      ⚠️ Email to admins not enabled at DB level.
      ⚠️ Threat detection retention period is 0 days.
      ⚠️ No geo-replication configured.

    📂 Database: ordersdb (Status: Online)
      🔁 Geo-replication: Linked to sql-server-dr in northeurope

