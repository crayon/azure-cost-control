# Crayon Azure Cost Control Onboarding PowerShell Script

## Table of Contents

- [Crayon Azure Cost Control Onboarding PowerShell Script](#crayon-azure-cost-control-onboarding-powershell-script)
  - [Table of Contents](#table-of-contents)
  - [Overview](#overview)
  - [Version Information](#version-information)
  - [Role Required](#role-required)
  - [Prerequisites](#prerequisites)
  - [Script Information](#script-information)
    - [Assign-AzureFinOpsRole](#assign-azurefinopsrole)
  - [Usage](#usage)
  - [Usage Instructions](#usage-instructions)
    - [Download the Script:](#download-the-script)
  - [Notes](#notes)
  - [Release Notes](#release-notes)
    - [Version 1.0.6](#version-106)
    - [Version 1.0.5](#version-105)
    - [Version 1.0.4](#version-104)
   

## Overview

This PowerShell script is designed to automate the setup and validation of permissions for onbarding customers in Crayon Azure Cost Control Service. It focuses on enabling various role assignments and permissions related to Azure management, billing, and subscriptions. The script is intended for use in environments with different agreement types, such as Enterprise Agreement (EA), Microsoft Customer Agreement (MCA), and Cloud Solution Provider (CSP).


## Version Information
- **Version**: 1.0.7 **Authors**: Karol Kępka
- **Version**: 1.0.6 **Authors**: Karol Kępka
- **Version**: 1.0.5 **Authors**: Karol Kępka
- **Version**: 1.0.4 **Authors**: Karol Kępka
- **Version**: 1.0.3 (initial) **Authors**: Claus Sonderstrup, Suman Bhushal, Antti Mustonen
- **Company**: Crayon


## Role Required
- **Global Administrator with elevated access** in Microsoft Entra ID.

    Elevating your access provides permissions to all subscriptions and management groups in your directory. This can be helpful in situations where Global Administrator rights alone do not grant the required access.

    Here is the link to elevate your access: https://learn.microsoft.com/en-us/azure/role-based-access-control/elevate-access-global-admin?tabs=azure-portal 
    This involves settings the "Access management for Azure Resources" to enabled.

  - **Note:** Please note that elevated access should be removed immediately after running the necessary scripts.
- If an **Enterprise Agreement** with Microsoft, additionally, the **Enterprise Administrator** role is required to assign the "Enrollment Reader" role to the service principal name.


## Prerequisites

- PowerShell modules: Az, Az.Accounts, Az.Reservations, Az.BillingBenefits, Az.Resources, Az.Billing, Microsoft.Graph.Authentication, Microsoft.Graph.Applications, Microsoft.Graph.Identity.DirectoryManagement

Ensure that the required modules are installed before running the script. The script will attempt to install them if they are not already present.

## Script Information
### Assign-AzureFinOpsRole
The script will perform the following tasks:
   - Install necessary PowerShell modules if not already installed.
   - Authenticate to Azure using `Login-AzAccount`.
   - Create a location named "c:\crayon" on the local machine windows machine and on Linux $home/crayon. 
   - Create an Azure Active Directory Application and Service Principal (SPN).
   - Assign Reader, Carbon Optimization Reader, Cost Management Reader, Reservation Reader, and Reader to SavingsPlans roles.
   - Check and validate permissions for subscriptions, management groups, reservations, and billing accounts.
   - Save information about tenants and secrets to a CSV file in the "Crayon" directory.

## Usage

1. Run the script in a PowerShell environment.
2. The script will prompt you to select an Agreement Type (EA, MCA, or CSP).
3. The script will perform the following tasks:
   - Install necessary PowerShell modules if not already installed.
   - Authenticate to Azure using `Login-AzAccount`.
   - Fetch billing account id if agreement type is EA or MCA
   - Create a directory named "Crayon" on the local machine.
   - Create an Azure Active Directory Application and Service Principal (SPN).
   - Assign Reader, Cost Management Reader, Reservation Reader, and Reader to SavingsPlans roles.
   - Check and validate permissions for subscriptions, management groups, reservations, and billing accounts.
   - Export information about tenants and secrets to a CSV file in the "Crayon" directory.


## Usage Instructions
### Download the Script:

1. Visit the [GitHub repository](https://github.com/CrayonCustomers/azure-cost-control/)
2. Locate the "Assign-AzureFinOpsRole.ps1" file to assign Azure FinOps Roles.
3. Click on the file to view its contents.
4. Right-click on the "Raw" button or the script contents and select "Save As" to download the script.
5. Navigate to the folder where the script is downloaded, right-click on the file, and choose "Open with PowerShell."


## Notes

- The script checks and validates various permissions related to Azure subscriptions, management groups, reservations, SavingsPlans, and billing accounts.
- It performs role assignments to ensure proper access for the created Azure Active Directory Application.
- Results and summary information are displayed at the end of the script execution.
- Securely send the generated CSV file to [Crayon](mailto:CloudCostControl@crayon.com) and delete the "Crayon" directory from the local machine after the email has been sent.

## Release Notes

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

