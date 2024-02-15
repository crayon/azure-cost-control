# Crayon Azure Cost Control Onboarding PowerShell Script

## Table of Contents

- [Overview](#overview)
- [Role Required](#role-required)
- [Prerequisites](#prerequisites)
- [Script Information](#script-information)
  - [Assign-AzureFinOpsRole](#assign-azurefinopsrole)
  - [Assign-CarbonOptimizationReader](#assign-carbonoptimizationreader)
- [Usage Instructions](#usage-instructions)

## Overview

This PowerShell script is designed to automate the setup and validation of permissions for onbarding cusotmers in Crayon Azure Cost Control Service. It focuses on enabling various role assignments and permissions related to Azure management, billing, and subscriptions. The script is intended for use in environments with different agreement types, such as Enterprise Agreement (EA), Microsoft Customer Agreement (MCA), and Cloud Solution Provider (CSP).

## Version Information

- **Version**: 1.0.0
- **Authors**: Claus Sonderstrup, Suman Bhushal, Antti Mustonen
- **Company**: Crayon

## Role Required
- **Global Administrator** at the Tenant level.
- If an **Enterprise Agreement** with Microsoft, additionally, the **Enterprise Administrator** role is required to assign the "Enrollment Reader" role to the service principal name.


## Prerequisites

- PowerShell modules: Az, Az.Accounts, Az.Reservations, Az.BillingBenefits, Az.Resources, Az.Billing

Ensure that the required modules are installed before running the script. The script will attempt to install them if they are not already present.

## Script Information
### Assign-AzureFinOpsRole
The script will perform the following tasks:
   - Install necessary PowerShell modules if not already installed.
   - Authenticate to Azure using `Login-AzAccount`.
   - Create a directory named "Crayon" on the local machine.
   - Create an Azure Active Directory Application and Service Principal (SPN).
   - Assign Reader, Cost Management Reader, Reservation Reader, and Reader to SavingsPlans roles.
   - Check and validate permissions for subscriptions, management groups, reservations, and billing accounts.
   - Save information about tenants and secrets to a CSV file in the "Crayon" directory.

### Assign-CarbonOptimizationReader
The script will perform the following tasks:
   - Install necessary PowerShell modules if not already installed.
   - Authenticate to Azure using `Login-AzAccount`.
   - The user is prompted to provide the Object ID of the Enterprise Application.
   - The script fetches all accessible subscriptions.
   - For each subscription, it checks if the specified role is already assigned to the Enterprise Application.
   - If not assigned, it assigns the "Carbon Optimization Reader" role to the Enterprise Application for each subscription.
   
## Usage

1. Run the script in a PowerShell environment.
2. The script will prompt you to select an Agreement Type (EA, MCA, or CSP).
3. Depending on the Agreement Type selected, additional information such as [Azure Enrollment Id](https://learn.microsoft.com/en-us/azure/cost-management-billing/manage/direct-ea-administration#view-enrollment-details) or [Billing Id](https://learn.microsoft.com/en-us/azure/cost-management-billing/manage/direct-ea-administration#to-select-a-billing-scope) may be required.
4. The script will perform the following tasks:
   - Install necessary PowerShell modules if not already installed.
   - Authenticate to Azure using `Login-AzAccount`.
   - Create a directory named "Crayon" on the local machine.
   - Create an Azure Active Directory Application and Service Principal (SPN).
   - Assign Reader, Cost Management Reader, Reservation Reader, and Reader to SavingsPlans roles.
   - Check and validate permissions for subscriptions, management groups, reservations, and billing accounts.
   - Export information about tenants and secrets to a CSV file in the "Crayon" directory.


## Usage Instructions
### Download the Script:

1. Visit the [GitHub repository](https://github.com/CrayonCustomers/azure-cost-control/)
2. Locate the "Assign-AzureFinOpsRole.ps1" file to assign Azure FinOps Role and "Assign-CarbonOptimizationReader.ps1" file to assign Carbon Optimization Reader.
3. Click on the file to view its contents.
4. Right-click on the "Raw" button or the script contents and select "Save As" to download the script.
5. Navigate to the folder where the script is downloaded, right-click on the file, and choose "Open with PowerShell."


## Notes

- The script checks and validates various permissions related to Azure subscriptions, management groups, reservations, SavingsPlans, and billing accounts.
- It performs role assignments to ensure proper access for the created Azure Active Directory Application.
- Results and summary information are displayed at the end of the script execution.
- Securely send the generated CSV file to [Crayon](mailto:finops.dk@crayon.com) and delete the "Crayon" directory from the local machine after the email has been sent.

## Release Notes

### Version 1.0.0
- Initial version of the script.

Feel free to reach out to the authors or the [Crayon DK FinOps Team](finops.dk@crayon.com) team for any assistance or feedback related to this script.