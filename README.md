# Crayon Azure Cost Control Onboarding PowerShell Script

- [Overview](#overview)
- [Version Information](#version-information)
- [Prerequisites](#prerequisites)
  - [PowerShell Modules](#powershell-modules)
  - [PowerShell Environment](#powershell-environment)
  - [System Requirements](#system-requirements)
  - [Azure Environment Prerequisites](#azure-environment-prerequisites)
  - [Role Required](#role-required)
- [Usage](#usage)
- [Output Files](#output-files)
- [Q&A / Troubleshooting](#qa--troubleshooting)
- [Release Notes](#release-notes)

## Overview

This PowerShell script automates the setup and validation of permissions for onboarding customers to the Crayon Azure Cost Control Service. It creates a service principal with the required read-only role assignments across Azure management, billing, reservations, and savings plans. The script supports Enterprise Agreement (EA), Microsoft Customer Agreement (MCA), and Cloud Solution Provider (CSP) environments.

## Prerequisites

### PowerShell Modules

The following PowerShell modules are required. The script will automatically install them if not present (falls back to `CurrentUser` scope if system-wide install fails):

- **Az.Accounts** - Azure authentication and account management
- **Az.Reservations** - Azure reservations management
- **Az.BillingBenefits** - Azure savings plans and billing benefits
- **Az.Resources** - Azure resource management and RBAC
- **Az.Billing** - Azure billing account management
- **Microsoft.Graph.Authentication** - Microsoft Graph authentication
- **Microsoft.Graph.Applications** - Microsoft Graph app registration management
- **Microsoft.Graph.Identity.DirectoryManagement** - Microsoft Graph directory operations

> **Note:** On bastion hosts or air-gapped networks without internet access, modules must be pre-installed. The script detects this and provides guidance. Azure Cloud Shell is recommended as an alternative since all modules are pre-installed.

### PowerShell Environment

- **PowerShell 5.1** or **PowerShell 7.x** (recommended)
- **Windows PowerShell**, **PowerShell Core**, or **Azure Cloud Shell** (recommended)
- **Execution Policy** set to allow script execution:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### System Requirements

- **Local file system access** for creating directories and files:
  - Windows: `C:\crayon`
  - Linux/macOS: `~/crayon`
- **Administrative privileges** may be required for module installation (script falls back to CurrentUser scope if unavailable)

### Azure Environment Prerequisites

- Valid Azure subscription with active billing account
- Appropriate agreement type: **Enterprise Agreement (EA)**, **Microsoft Customer Agreement (MCA)**, or **Cloud Solution Provider (CSP)**
- For EA customers: Enrollment must be onboarded to Azure portal for modern billing API access

### Role Required

#### Microsoft Entra ID (Azure AD) Permissions

- **Global Administrator** or **Application Administrator** role in Microsoft Entra ID
- **Elevated access to Azure resources** must be enabled for Global Administrators:
  - Navigate to: Microsoft Entra ID → Properties → "Access management for Azure resources" → **Yes**
  - Documentation: https://learn.microsoft.com/en-us/azure/role-based-access-control/elevate-access-global-admin?tabs=azure-portal
  - **Important:** Remove elevated access immediately after running the script

#### Azure RBAC Permissions

- **User Access Administrator** role at the root management group level (granted automatically with elevated Global Admin access)
- **Management Group Reader** role (minimum) to access management group hierarchy
- Permission to register Azure resource providers (Microsoft.Management, Microsoft.Capacity, Microsoft.BillingBenefits)

### Agreement-Specific Requirements

**For Enterprise Agreement (EA) customers:**

- **Enterprise Administrator** role in the EA portal (ea.azure.com or billing.microsoft.com)
- EA enrollment must be **onboarded to Azure portal** for modern billing API access

**For Microsoft Customer Agreement (MCA) customers:**

- **Billing Account Owner** or **Billing Profile Owner** role
- Access to Cost Management + Billing in Azure portal

**For Cloud Solution Provider (CSP) customers:**

- **Admin Agent** role in Partner Center
- Access to customer's Azure subscriptions

#### Microsoft Graph API Permissions

The script requests the following Microsoft Graph scopes:

- `Application.ReadWrite.All` - To create and manage app registrations
- `Directory.Read.All` - To read directory information

## Usage

1. Run the script in **Azure Cloud Shell** (recommended) or a local PowerShell environment.

2. The script will ask about authentication method:
   - **Option 1:** Interactive Browser (default)
   - **Option 2:** Device Code (required for headless/bastion environments)
   - Azure Cloud Shell uses existing authentication automatically.

3. The script will prompt for a specific tenant ID (optional — leave empty for default tenant).

4. **Billing-first flow:** The script fetches and lists all billing accounts, then lets you select one. Agreement type is auto-detected from the selected billing account. Manual agreement type selection only appears as a fallback if billing accounts cannot be accessed (e.g. CSP tenants or missing billing permissions).

5. **Pre-flight permission checks:** Before creating anything, the script validates all required permissions:
   - Root management group access
   - Role assignment permissions
   - Microsoft Graph permissions
   - Billing account access
   - Checks for existing `CrayonCloudEconomicsReader` app registration
   - Resource provider registration

   If blocking issues are found, the script exits cleanly without creating any resources.

6. The script will then:
   - Create an Azure AD Application and Service Principal (`CrayonCloudEconomicsReader`)
   - Set expiration date for the service principal (default 36 months, customizable)
   - Assign the following roles to the service principal:
     - **Reader** (at management group root level)
     - **Cost Management Reader** (at management group root level)
     - **Reservations Reader** (at Microsoft.Capacity provider level)
     - **Savings Plan Reader** (at Microsoft.BillingBenefits provider level)
     - **Carbon Optimization Reader** (at management group root level)
     - **Reader** role to individual savings plans (if any exist)
   - Assign billing-specific roles based on agreement type:
     - **EA:** Enrollment Reader role via Billing API
     - **MCA:** Billing Account Reader role via Billing API
   - Display a **role assignment summary table** showing success/failed/skipped status for each role
   - Export two CSV files (see [Output Files](#output-files))
   - Perform comprehensive validation tests using the created service principal

## Output Files

The script generates **two separate CSV files** in the `crayon` directory:

| File | Contents | Sensitivity |
|------|----------|-------------|
| `CrayonCloudEconomics-<TenantName>-<Date>.csv` | Tenant ID, tenant name, domain, country code, agreement type, App ID, secret expiry date | Safe to store |
| `CrayonCloudEconomics-<TenantName>-<Date>-SECRET.csv` | Tenant ID, App ID, client secret, secret expiry date | **Sensitive — handle with care** |

> **Important:** The SECRET file contains the client secret credential. Send it separately and securely. Delete it after transfer.

Both files should be securely sent using https://deila.sensa.is to your Crayon representative. Remove the `crayon` directory after transfer.

## Q&A / Troubleshooting

### Q: Which environment should I run this script in?

**A:** Azure Cloud Shell (https://shell.azure.com) is the recommended environment. It has all required modules pre-installed, avoids local execution policy issues, and is already authenticated. If you prefer running locally, use PowerShell 7.x on Windows, macOS, or Linux.

---

### Q: I get "Access management for Azure resources" error — what do I do?

**A:** You need to enable elevated access as a Global Administrator:

1. Go to **Azure Portal → Microsoft Entra ID → Properties**
2. Set **"Access management for Azure resources"** to **Yes**
3. Click **Save**
4. Re-run the script

Remember to set it back to **No** after the script completes successfully.

---

### Q: The script says "App registration 'CrayonCloudEconomicsReader' already exists" — what now?

**A:** A previous run (or partial run) already created the app registration. You need to delete it before re-running:

1. Go to **Azure Portal → Microsoft Entra ID → App registrations**
2. Search for `CrayonCloudEconomicsReader`
3. Select it and click **Delete**
4. Also check **Deleted applications** and permanently delete it there
5. Re-run the script

---

### Q: I'm on a bastion host with no internet — can I still run this?

**A:** Yes, but all required modules must be pre-installed. From a machine with internet access:

```powershell
Save-Module Az.Accounts, Az.Reservations, Az.BillingBenefits, Az.Resources, Az.Billing, Microsoft.Graph.Authentication, Microsoft.Graph.Applications, Microsoft.Graph.Identity.DirectoryManagement -Path C:\Modules
```

Copy the `C:\Modules` folder to the bastion host and import them. Alternatively, use Azure Cloud Shell which always has internet access and pre-installed modules.

---

### Q: Which login method should I choose — Interactive Browser or Device Code?

**A:** 
- **Interactive Browser (Option 1):** Use this if you're running the script on a machine with a web browser. A browser window will open for you to sign in.
- **Device Code (Option 2):** Use this if you're on a headless server, bastion host, or remote session without a browser. You'll get a URL and a code to enter on any device with a browser.

---

### Q: I have multiple billing accounts listed — which one do I pick?

**A:** Select the billing account that corresponds to the Azure environment you want Crayon to get cost data for. Look at the **display name**, **agreement type**, and **status**. Choose an **Active** account. If you're unsure, ask your Azure billing administrator which enrollment or billing account covers the subscriptions in scope.

---

### Q: The script shows a billing account as "Deactivated" — can I still use it?

**A:** The script will warn you and ask for confirmation. A deactivated billing account typically means the enrollment has expired or been migrated. If Microsoft migrated your EA to MCA, the old EA enrollment will show as deactivated — select the new MCA account instead.

---

### Q: What does "agreement type mismatch" mean?

**A:** This happens when the billing account's actual agreement type differs from what was expected. The most common cause is Microsoft migrating an EA enrollment to MCA. The script auto-detects the agreement type from the selected billing account, so this should be rare in v1.2.0+.

---

### Q: The Reservations Reader check fails during validation — is that a problem?

**A:** Not necessarily. Provider-scoped roles (like Reservations Reader at `/providers/Microsoft.Capacity`) can take several minutes to propagate across Azure. The script waits 60 seconds and retries, but on some tenants it may take longer. If the role assignment itself succeeded (shown in the summary table), the validation failure is just a propagation delay. Wait 5–10 minutes and verify manually in the Azure Portal.

---

### Q: The Savings Plan Reader role was "Skipped" — is that an error?

**A:** No. The provider-level Savings Plan Reader role (`/providers/Microsoft.BillingBenefits`) is only supported on EA billing accounts. For MCA customers, savings plan data is accessible through the Cost Management Reader role, which is always assigned. This is expected behavior.

---

### Q: How long is the service principal secret valid?

**A:** By default, 36 months (3 years). The script prompts you to enter a custom duration in months. Choose a value that matches your Crayon agreement length.

---

### Q: What permissions does the created service principal have?

**A:** The service principal is **read-only**. It can:
- Read subscription and resource metadata (Reader)
- Read cost and usage data (Cost Management Reader)
- Read reservation details (Reservations Reader)
- Read savings plan details (Savings Plan Reader / Reader on individual plans)
- Read carbon optimization data (Carbon Optimization Reader)
- Read billing account information (Enrollment Reader or Billing Account Reader)

It **cannot** create, modify, or delete any Azure resources, subscriptions, or billing settings.

---

### Q: Can I run this script multiple times on the same tenant?

**A:** Not without cleanup. The script checks for an existing `CrayonCloudEconomicsReader` app registration and will block if one exists. Delete the existing app registration first (see the question above about "already exists").

---

### Q: The script failed halfway through — are there orphaned resources?

**A:** Starting with v1.0.9, the script performs pre-flight checks before creating anything. If it fails during pre-flight, nothing was created. If it fails after creating the service principal (during role assignments), the app registration exists but may have incomplete permissions. You can either:
- Delete the app registration and re-run from scratch
- Manually assign the missing roles shown in the summary table

---

### Q: I get a "module version conflict" / "Assembly with same name" error — how do I fix it?

**A:** This happens when multiple versions of Az modules are loaded in the same PowerShell session. Fix it by:

1. **Easiest:** Close PowerShell completely, open a new terminal, and run this script first before any other commands.
2. **Clean install:**
   ```powershell
   Get-Module Az* | Remove-Module -Force
   Uninstall-Module Az -AllVersions -Force
   Install-Module Az -Force -AllowClobber
   ```
3. **Recommended:** Use Azure Cloud Shell, which always has compatible module versions.

---

### Q: Do I need to keep elevated access enabled after the script finishes?

**A:** No. Set "Access management for Azure resources" back to **No** immediately after the script completes. The service principal's role assignments persist independently of your elevated access.

---

### Q: How do I send the output files to Crayon?

**A:** Use the secure file transfer portal at https://deila.sensa.is. Send both CSV files to your Crayon representative. After confirmed receipt, delete the local `crayon` directory (Windows: `C:\crayon`, Linux/macOS: `~/crayon`).

---

### Q: What if I don't know my agreement type (EA, MCA, or CSP)?

**A:** The script handles this automatically. It fetches your billing accounts and auto-detects the agreement type. If you want to check beforehand:
- Go to **Azure Portal → Cost Management + Billing**
- Your billing account will show the agreement type (Enterprise Agreement, Microsoft Customer Agreement, etc.)
- If you access Azure through a partner/reseller, you're likely on CSP

---

### Q: The script asks for "length of the Crayon agreement in months" — what should I enter?

**A:** Enter the duration of your contract with Crayon for the Cost Control service. This sets the expiry date on the service principal's client secret. If unsure, press Enter to use the default of 36 months. You can always create a new secret later if needed.

---

## Release Notes

### Version 1.2.1

#### Improved validation reliability
- Increased propagation wait from 20s to 60s before SPN self-check
- Added retry logic with clear propagation-delay messaging for Reservations Reader check (fixes false failures on tenants where provider-scoped roles take longer to propagate)

### Version 1.2.0

#### Billing-first flow with auto-detection
- Script now fetches and lists billing accounts **before** asking for agreement type
- Agreement type is **auto-detected** from the selected billing account, eliminating manual selection and mismatch issues
- Manual agreement type prompt only appears as fallback when billing accounts cannot be accessed (e.g. CSP tenants or missing billing permissions)

### Version 1.1.0

#### Interactive billing account selection
- Replaced blind first-billing-account selection with interactive listing of all billing accounts
- Operator now sees every account (ID, display name, agreement type, status) and selects explicitly
- Deactivated account selection triggers a confirmation warning before proceeding
- Fixes onboarding failures on tenants with mixed EA/MCA billing accounts (e.g. post-migration tenants)

### Version 1.0.9

#### Major error handling and safety overhaul
- Added **pre-flight permission validation** that checks all required permissions before creating anything — no more orphaned app registrations from permission failures
- Added agreement type auto-detection with mismatch warning (catches EA-to-MCA migrations)
- Wrapped all role assignments in try/catch with individual error handling
- Added **role assignment summary table** at the end of execution
- Clear error guidance for every failure mode
- Module install falls back to `CurrentUser` scope if system-wide install fails
- SPN propagation uses retry loop instead of fixed sleep
- **Two separate CSV files**: tenant info (safe) and secrets (sensitive) — previously a single file
- CSV always generates even if some role assignments fail

### Version 1.0.8

#### Login, tenant selection, and BillingBenefits support
- Added login method selection (Interactive Browser / Device Code)
- Added tenant selection capability
- Aligned Microsoft Graph authentication with Azure authentication method
- Improved secure token handling using `NetworkCredential` with `AsSecureString` parameter
- Added role assignments for BillingBenefits provider roles (read-only savings plan access)

### Version 1.0.7

#### Improved support for MCA agreements
- Improved support for Microsoft Customer Agreement (MCA) billing accounts, allowing the script to fetch billing account IDs for both EA and MCA agreements

### Version 1.0.6

#### Fixed propagation issue on some environments
- Fixed Service Principal propagation time issue by increasing wait time after creating the Service Principal

### Version 1.0.5

#### Deprecated Azure module behaviour
- Updated `Get-AzAccessToken` calls to use `-AsSecureString:$false` to prepare for Az version 14.0.0 breaking changes

### Version 1.0.4

#### Deprecated Azure AD replacement
- Replaced deprecated AzureAD modules with Microsoft Graph PowerShell SDK
- **Removed:** AzureAD, AzureAD.Standard.Preview
- **Added:** Microsoft.Graph.Authentication, Microsoft.Graph.Applications, Microsoft.Graph.Identity.DirectoryManagement
- Updated all Azure AD operations to use Microsoft Graph API
- Changed connection method from `Connect-AzureAD` to `Connect-MgGraph` with appropriate scopes

---

Feel free to reach out to the authors or the [Crayon FinOps Team](mailto:CloudCostControl@crayon.com) for any assistance or feedback related to this script.
