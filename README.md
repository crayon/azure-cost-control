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
  - [Release Notes](#release-notes)
    - [Version 1.2.0](#version-120)
    - [Version 1.1.0](#version-110)
    - [Version 1.0.9](#version-109)
    - [Version 1.0.8](#version-108)
    - [Version 1.0.7](#version-107)
    - [Version 1.0.6](#version-106)
    - [Version 1.0.5](#version-105)
    - [Version 1.0.4](#version-104)

## Overview

This PowerShell script automates the setup and validation of permissions for onboarding customers to the Crayon Azure Cost Control Service. It creates a service principal with the required read-only role assignments across Azure management, billing, reservations, and savings plans. The script supports Enterprise Agreement (EA), Microsoft Customer Agreement (MCA), and Cloud Solution Provider (CSP) environments.

## Version Information
- **Version**: 1.2.0 **Authors**: Tómas Harry Ottósson, Karol Kępka
- **Version**: 1.0.4 - 1.1.0 **Authors**: Karol Kępka
- **Version**: 1.0.3 (initial) **Authors**: Claus Sonderstrup, Suman Bhushal, Antti Mustonen
- **Company**: Crayon

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
4. **Billing-first flow (new in v1.2.0):** The script fetches and lists all billing accounts, then lets you select one. Agreement type is auto-detected from the selected account. Manual agreement type selection only appears as a fallback if billing accounts cannot be accessed (e.g. CSP tenants or missing billing permissions).
5. **Pre-flight permission checks (new in v1.0.9):** Before creating anything, the script validates all required permissions:
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

## Release Notes

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
