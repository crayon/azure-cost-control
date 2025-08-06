# Crayon Azure Cost Control Onboarding PowerShell Script
  - [Overview](#overview)
  - [Version Information](#version-information)
  - [Prerequisites](#prerequisites)
    - [Powershell modules](#powershell-modules)
    - [Powershell environment](#powershell-environment)
    - [System requirements](#powershell-modules)
    - [Azure requirements](#azure-requirements)
    - [Role Required](#role-required)
  - [Usage](#usage)
  - [Release Notes](#release-notes)
    - [Version 1.0.8](#version-108)
    - [Version 1.0.7](#version-107)
    - [Version 1.0.6](#version-106)
    - [Version 1.0.5](#version-105)
    - [Version 1.0.4](#version-104)
   

## Overview

This PowerShell script is designed to automate the setup and validation of permissions for onbarding customers in Crayon Azure Cost Control Service. It focuses on enabling various role assignments and permissions related to Azure management, billing, and subscriptions. The script is intended for use in environments with different agreement types, such as Enterprise Agreement (EA), Microsoft Customer Agreement (MCA), and Cloud Solution Provider (CSP).


## Version Information
- **Version**: 1.0.8 **Authors**: Tómas Harry Ottósson, Karol Kępka
- **Version**: 1.0.4 - 1.0.7 **Authors**: Karol Kępka
- **Version**: 1.0.3 (initial) **Authors**: Claus Sonderstrup, Suman Bhushal, Antti Mustonen
- **Company**: Crayon





## Prerequisites

### PowerShell Modules
The following PowerShell modules are required. The script will automatically install them if not present:
- **Az.Accounts** - Azure authentication and account management
- **Az.Reservations** - Azure reservations management
- **Az.BillingBenefits** - Azure savings plans and billing benefits
- **Az.Resources** - Azure resource management and RBAC
- **Az.Billing** - Azure billing account management
- **Microsoft.Graph.Authentication** - Microsoft Graph authentication
- **Microsoft.Graph.Applications** - Microsoft Graph app registration management
- **Microsoft.Graph.Identity.DirectoryManagement** - Microsoft Graph directory operations

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
- ***Administrative privileges*** may be required for module installation

### Azure Environment Prerequisites
- Valid Azure subscription with active billing account
- Appropriate agreement type: ***Enterprise Agreement (EA)***, ***Microsoft Customer Agreement (MCA)***, or ***Cloud Solution Provider (CSP)***
- For EA customers: Enrollment must be onboarded to Azure portal for modern billing API access


### Role Required

#### Microsoft Entra ID (Azure AD) Permissions
- ***Global Administrator*** or ***Application Administrator*** role in Microsoft Entra ID
- ***Elevated access to Azure resources** must be enabled for Global Administrators:
  - Navigate to: Microsoft Entra ID → Properties → "Access management for Azure resources" → ***Yes***
  - Documentation: https://learn.microsoft.com/en-us/azure/role-based-access-control/elevate-access-global-admin?tabs=azure-portal
  - **Important:** Remove elevated access immediately after running the script

#### Azure RBAC Permissions
- **User Access Administrator** role at the root management group level (granted automatically with elevated Global Admin access)
- **Management Group Reader** role (minimum) to access management group hierarchy
- Permission to register Azure resource providers (Microsoft.Management, Microsoft.Capacity, Microsoft.BillingBenefits)

### Agreement-Specific Requirements

***For Enterprise Agreement (EA) customers:***
- **Enterprise Administrator** role in the EA portal (ea.azure.com or billing.microsoft.com)
- EA enrollment must be **onboarded to Azure portal** for modern billing API access
- Without proper EA onboarding, the script will fail with billing account access errors

***For Microsoft Customer Agreement (MCA) customers:***
- **Billing Account Administrator*** or ** Billing Profile Owner** role
- Access to Cost Management + Billing in Azure portal

***For Cloud Solution Provider (CSP) customers:***
- **Admin Agent** role in Partner Center
- Access to customer's Azure subscriptions

#### Microsoft Graph API Permissions
The script requests the following Microsoft Graph scopes:
- `Application.ReadWrite.All` - To create and manage app registrations
- `Directory.Read.All` - To read directory information


## Usage

1. Run the script in Azure Cloud Shell (recommended) or PowerShell environment.
2. The script will ask about authentication method:
   - **Option 1:** Interactive Browser (default)
   - **Option 2:** Device Code
3. The script will prompt for a specific tenant ID (optional - leave empty for default tenant).
4. The script will prompt you to select an Agreement Type:
   - **1:** Enterprise Agreement (EA)
   - **2:** Microsoft Customer Agreement (MCA) 
   - **3:** Cloud Solution Provider (CSP)
5. The script will perform the following tasks:
   - Install necessary PowerShell modules if not already installed
   - Authenticate to Azure using `Connect-AzAccount`
   - Connect to Microsoft Graph with required permissions
   - Fetch billing account ID if agreement type is EA or MCA
   - Create a directory named "crayon" on the local machine (C:\crayon on Windows, ~/crayon on Linux/macOS)
   - Verify no existing "CrayonCloudEconomicsReader" app registration exists
   - Create an Azure Active Directory Application and Service Principal (SPN)
   - Set expiration date for the service principal (default 36 months, customizable)
   - Assign the following roles to the service principal:
     - Reader (at management group level)
     - Cost Management Reader (at management group level)  
     - Reservations Reader (at Microsoft.Capacity provider level)
     - Savings Plan Reader (at Microsoft.BillingBenefits provider level)
     - Carbon Optimization Reader (at management group level)
     - Reader role to individual savings plans (if any exist)
   - Assign billing-specific roles based on agreement type:
     - **EA:** Enrollment Reader role via Billing API
     - **MCA:** Billing Account Reader role via Billing API
   - Validate permissions for subscriptions, management groups, reservations, savings plans, and billing accounts
   - Export tenant information and service principal details to a CSV file in the "crayon" directory
   - Perform comprehensive validation tests using the created service principal to verify all permissions are working correctly
  
 Collected data from generated CSV file should be securely sent using https://deila.sensa.is to Crayon representative.

## Release Notes

### Version 1.0.8
#### Introduced logging, tenant, BillingBenefits and token retrieval changes
Added login method selection (Interactive Browser/Device Code) 
Added tenant selection capability
Aligned Microsoft Graph authentication with Azure authentication method
Improved secure token handling using NetworkCredential with AsSecureString parameter
Added role assignments for BillingBenefits provider role enabling future capabilities of:
- View and read savings plans across the entire tenant
- Access details about existing savings plans including commitment amounts, terms, utilization, and savings
- See savings plan recommendations and eligibility
New role assignment cannot modify, create, or delete savings plans (read-only access)

### Version 1.0.7
#### Improved support for MCA agreements

Improved support for Microsoft Customer Agreement (MCA) billing accounts, allowing the script to fetch billing account IDs for both EA and MCA agreements.

### Version 1.0.6
#### Fixed propagation issue on some environments

Fixed Service Principal propagation time issue by increasing wait time after creating the Service Principal.

### Version 1.0.5
#### Deprecated Azure module behaviour

Updated Get-AzAccessToken calls to use -AsSecureString:$false to prepare for Az version 14.0.0 breaking changes

### Version 1.0.4
#### Deprecated Azure AD replacement

1.0.4 update is replacing the deprecated AzureAD modules with Microsoft Graph PowerShell SDK, ensuring compatibility beyond the Microsoft Entra retirement dates in 2025.
- **Modules Changed:**
  - **Removed:** AzureAD, AzureAD.Standard.Preview
  - **Added:** Microsoft.Graph.Authentication, Microsoft.Graph.Applications, Microsoft.Graph.Identity.DirectoryManagement
- **Updated all Azure AD operations** to use Microsoft Graph API
- **Changed connection method from Connect-AzureAD** to Connect-MgGraph with appropriate scopes
- Initial version of the script.

Feel free to reach out to the authors or the [Crayon FinOps Team](mailto:CloudCostControl@crayon.com) team for any assistance or feedback related to this script.

