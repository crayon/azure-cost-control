# Crayon Azure Cost Control Onboarding PowerShell Script

## Overview

This PowerShell script is designed to automate the setup and validation of permissions for onbarding cusotmers in Crayon Azure Cost Control Service. It focuses on enabling various role assignments and permissions related to Azure management, billing, and subscriptions. The script is intended for use in environments with different agreement types, such as Enterprise Agreement (EA), Microsoft Customer Agreement (MCA), and Cloud Solution Provider (CSP).

## Version Information

- **Version**: 1.0.0
- **Authors**: Claus Sonderstrup, Suman Bhushal, Antti Mustonen
- **Company**: Crayon

## Prerequisites

- PowerShell modules: Az, Az.Accounts, Az.Reservations, Az.BillingBenefits, Az.Resources, Az.Billing

Ensure that the required modules are installed before running the script. The script will attempt to install them if they are not already present.

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

## Notes

- The script checks and validates various permissions related to Azure subscriptions, management groups, reservations, SavingsPlans, and billing accounts.
- It performs role assignments to ensure proper access for the created Azure Active Directory Application.
- Results and summary information are displayed at the end of the script execution.
- Ensure secure transmission of the generated CSV file to Crayon and remove the "Crayon" directory from the local machine after use.



## Release Notes

### Version 1.0.0
- Initial version of the script.

Feel free to reach out to the authors or the [Crayon DK FinOps Tema](finops.dk@crayon.com) team for any assistance or feedback related to this script.