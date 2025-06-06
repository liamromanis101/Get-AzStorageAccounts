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
  ```
  bash
  pip install azure-identity azure-mgmt-resource azure-mgmt-storage
  ```

## 🔧 Usage

### 1. Clone the repository
```
bash
git clone https://github.com/liamromanis101/Get-AzStorageAccounts/
cd Get-AzStorageAccounts
```

### 2. Authenticate with Azure

az login

alternatively, set environment variables:
```
  export AZURE_CLIENT_ID="your-client-id"
  export AZURE_TENANT_ID="your-tenant-id"
  export AZURE_CLIENT_SECRET="your-client-secret"
```

To limit to a single subscription, also set:
```
    export AZURE_SUBSCRIPTION_ID="your-subscription-id"
```

### 3. Install required Python packages
```
  pip install azure-identity azure-mgmt-resource azure-mgmt-storage
```
### 4. Run the script:
```
  python3 azure_storage_audit.py
```

## 🖥️ Example Output

```bash
🔐 Azure Storage Account Security Audit Across All Subscriptions

📦 Scanning Subscription: Production Subscription (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)

🔎 Storage Account: mystorageprod (RG: rg-prod-storage)
 - HTTPS Only: ✅ Enforced
 - Public Blob Access: ❌ Disabled (Secure)
 - Microsoft Trusted Services Access: ✅ Enabled
 - Encryption: ✅ Enabled with Microsoft.Keyvault
   - Customer Managed Key (CMK): ✅ Used
 - Access Keys: ✅ Present (Access Key Auth possible)
 - Key Rotation: ⚠️ Not detectable via SDK. Check Azure Monitor or Key Vault settings.

🔎 Storage Account: devstoragetest (RG: rg-dev-resources)
 - HTTPS Only: ❌ Not enforced
 - Public Blob Access: ⚠️ Enabled (Risky)
 - Microsoft Trusted Services Access: ❌ Not allowed
 - Encryption: ✅ Enabled with Microsoft.Storage
 - Access Keys: ✅ Present (Access Key Auth possible)
 - Key Rotation: ⚠️ Not detectable via SDK. Check Azure Monitor or Key Vault settings.

📦 Scanning Subscription: Sandbox (yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy)

🔎 Storage Account: sandboxlogs (RG: sandbox-rg)
 - HTTPS Only: ✅ Enforced
 - Public Blob Access: ❌ Disabled (Secure)
 - Microsoft Trusted Services Access: ✅ Enabled
 - Encryption: ✅ Enabled with Microsoft.Storage
 - Access Keys: ❌ Not retrievable (insufficient permissions)
 - Key Rotation: ⚠️ Not detectable via SDK. Check Azure Monitor or Key Vault settings.
