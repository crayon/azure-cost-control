<#PSScriptInfo

.VERSION 1.0.7

.AUTHOR Claus Sonderstrup, Suman Bhushal, Karol Kępka Crayon. http://www.crayon.com

.COMPANYNAME Crayon

.RELEASENOTES
Change Log:
1.0.0 - Initial Version
1.0.1 - Self check and powershell change made. Also $roleDefinitionName = "Carbon Optimization Reader" has been added.
1.0.2 - Check of Module import and Linux / Windows OS added.
1.0.3 - AzureAD change to AzureAD.Standard.Preview, "Tenant.id" change to "$RootTenantID", Linie 344 "Start-Sleep -Seconds 20" added and linie 401 "-Scope "/providers/Microsoft.Management/managementGroups/$RootTenantID"" added.
1.0.4 - Updated to use Microsoft Graph PowerShell SDK instead of deprecated AzureAD modules. Changed login method to use DeviceCode flow for better compatibility, and added error handling for module installation and import.
1.0.5 - Updated Get-AzAccessToken calls to use -AsSecureString:$false to prepare for Az version 14.0.0 breaking changes
1.0.6 - Fixed Service Principal propagation time issue that could happen at some environments by increasing wait time after creating the Service Principal.
1.0.7 - Improved support for Microsoft Customer Agreement (MCA) billing accounts, allowing the script to fetch billing account IDs for both EA and MCA agreements.
#>
# Requires -Modules Az
$ErrorActionPreference = "stop"

#//------------------------------------------------------------------------------------
#//  Install Az and Microsoft Graph Module If Needed
#//------------------------------------------------------------------------------------
function Install-Module-If-Needed {
    param([string]$ModuleName)
    
    if (Get-Module -ListAvailable -Name $ModuleName) {
        Write-Host "Module '$($ModuleName)' already exists, continue..." -ForegroundColor Green
    }
    else {
        Write-Host "Module '$($ModuleName)' does not exist, installing..." -ForegroundColor Yellow
        Install-Module $ModuleName -Force -AllowClobber -ErrorAction Stop
        Write-Host "Module '$($ModuleName)' installed." -ForegroundColor Green
    }
}

function Fetch-EEAMCABillingAccounts{
    param(
        [Parameter(Mandatory=$true)]
        [string]$bearerToken
    )

        <#
    .SYNOPSIS
    Fetches the Billing id for MCA or EA billing accounts

    .DESCRIPTION
    This function checks if the application has the necessary permissions to read billing accounts using the provided bearer token.

    .PARAMETER bearerToken
    The OAuth 2.0 bearer token used for authentication to azure.

    .INPUTS
    None. You can't pipe objects to Fetch-EEAMCABillingAccounts.

    .OUTPUTS
    Returns the billing account id

    .EXAMPLE
    PS> Fetch-EEAMCABillingAccounts -bearerToken "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6I..."
    #>


    $ApiUri = "https://management.azure.com/providers/Microsoft.Billing/billingAccounts?api-version=2019-10-01-preview"
    $Headers = @{
        'Content-Type'  = "application/json"
        'Authorization' = "Bearer $bearerToken"
    }
    try {
        $billingAcccounts = Invoke-RestMethod -Uri $ApiUri -Headers $Headers -Method Get
    }
    catch {
        Throw "Failed to authenticate to Azure services to fetch billingaccounts please confirm that customer has an EA/MCA agreement or has the permission to list billing accounts" + $_
    }
    

    if(-not $billingAcccounts.value){
        Throw "Failed to authenticate to Azure services to fetch billingaccounts please confirm that customer has an EA (enterprise agreement) or has provided the application permission Enrollment Reader"
    }

    $billingAccountID = $billingAcccounts.value[0] | select -ExpandProperty name

    return $billingAccountID
    
}


#CHECK PS MODULE PREREQUISITES
Write-Host "Checking PowerShell module prerequisites..."

#//------------------------------------------------------------------------------------
#//  Install Modules If Needed
#//------------------------------------------------------------------------------------
Install-Module-If-Needed Az.Accounts
Install-Module-If-Needed Az.Reservations
Install-Module-If-Needed Az.BillingBenefits
Install-Module-If-Needed Az.Resources
Install-Module-If-Needed Az.Billing
Install-Module-If-Needed Microsoft.Graph.Authentication
Install-Module-If-Needed Microsoft.Graph.Applications
Install-Module-If-Needed Microsoft.Graph.Identity.DirectoryManagement
Install-Module-If-Needed Az.Accounts
Install-Module-If-Needed Az.Resources

#//------------------------------------------------------------------------------------
#//  Import the modules into the session
#//------------------------------------------------------------------------------------

function Import-Modules {
    param (
        [string[]]$moduleNames
    )

    foreach ($moduleName in $moduleNames) {
        if (Get-Module -Name $moduleName -ListAvailable) {
            if (Get-Module -Name $moduleName) {
                Write-Output "Module '$moduleName' is already imported."
            }
            else {
                try {
                    Import-Module -Name $moduleName -DisableNameChecking -ErrorAction Stop
                    Write-Output "Module '$moduleName' has been imported."
                }
                catch {
                    Write-Output "Failed to import module '$moduleName'. Error: $_"
                }
            }
        }
        else {
            Write-Output "Module '$moduleName' is not available."
        }
    }
}

# List of modules to check and import
$modules = @("Az.Accounts", "Az.Reservations", "Az.BillingBenefits", "Az.Resources", "Az.Billing", "Microsoft.Graph.Authentication", "Microsoft.Graph.Applications", "Microsoft.Graph.Identity.DirectoryManagement")

# Import the modules
Import-Modules -moduleNames $modules

#//------------------------------------------------------------------------------------
#//  Variables
#//------------------------------------------------------------------------------------
$ReservationRoleAssignment = "Reservations Reader"
$SavingsPlanRoleAssignment = "Reader"
$CarbonOptimizationRoleAssignment = "fa0d39e6-28e5-40cf-8521-1eb320653a4c" # "Carbon Optimization Reader"


#//------------------------------------------------------------------------------------
#//  Login to Azure
#//------------------------------------------------------------------------------------
# Prompt for login method
$loginChoice = Read-Host "Choose login method (1: Interactive Browser 2: Device Code ) [default: 1]"
if ([string]::IsNullOrWhiteSpace($loginChoice) -or ($loginChoice -ne "1" -and $loginChoice -ne "2")) {
    $loginChoice = "1"
}

# Ask for specific tenant ID
$tenantIdPrompt = Read-Host "Enter specific tenant ID to log into (leave empty for default tenant)"
$tenantParam = @{}
if (-not [string]::IsNullOrWhiteSpace($tenantIdPrompt)) {
    $tenantParam = @{TenantId = $tenantIdPrompt}
    Write-Host "Will connect to tenant: $tenantIdPrompt" -ForegroundColor Cyan
}

# Execute login based on choice
switch ($loginChoice) {
    "2" {
        Write-Host "Logging in with device code authentication..." -ForegroundColor Cyan
        Connect-AzAccount -WarningAction SilentlyContinue -UseDeviceAuthentication @tenantParam
    }
    default {
        Write-Host "Logging in with interactive browser authentication..." -ForegroundColor Cyan
        Connect-AzAccount -WarningAction SilentlyContinue @tenantParam
    }
}

Write-Host "Authentication Success" -ForegroundColor Green

# Prepare empty list for information about tenants and secrets
$tenantInfo = @()

#//------------------------------------------------------------------------------------
#//  Tenant
#//------------------------------------------------------------------------------------
$azContext = Get-AzContext

# Ensure Microsoft.Management provider is registered
$provider = Get-AzResourceProvider -ProviderNamespace Microsoft.Management
if ($provider.RegistrationState -ne 'Registered') {
    Register-AzResourceProvider -ProviderNamespace Microsoft.Management
    Start-Sleep -Seconds 10
}

$tenantRootMG = Get-AzManagementGroup -GroupId $azContext.tenant.ID -WarningAction SilentlyContinue
$tenant = Get-AzTenant

if ($tenant) {

    #//------------------------------------------------------------------------------------
    #//  Create folder on local machine
    #//------------------------------------------------------------------------------------

    # Determine the operating system
    if ($IsWindows) {
        $DirectoryPath = "C:\crayon"
    }else {
        $DirectoryPath = "$home/crayon"
    }

    # Check if the directory exists, if not, create it
    if (-Not (Test-Path -Path $DirectoryPath)) {
        New-Item -Path $DirectoryPath -ItemType "directory"
        Write-Host "Directory created: $DirectoryPath" -ForegroundColor Green
    }
    else {
        Write-Host "Directory already exists: $DirectoryPath" -ForegroundColor Green
    }

    #//------------------------------------------------------------------------------------
    #//                                 Root Tenant
    #//------------------------------------------------------------------------------------
    $RootTenantID = $tenantRootMG.TenantId

    #//------------------------------------------------------------------------------------
    #//                              Connect to Microsoft Graph
    #//------------------------------------------------------------------------------------
    # Connect to Microsoft Graph with required permissions
    # Use the same tenant ID that was specified for Azure login
    $graphTenantId = $RootTenantID
    if (-not [string]::IsNullOrWhiteSpace($tenantIdPrompt)) {
        $graphTenantId = $tenantIdPrompt
    }

    # Use the same authentication method as Azure login
    if ($loginChoice -eq "1") {
        Write-Host "Connecting to Microsoft Graph with interactive browser authentication..." -ForegroundColor Cyan
        Connect-MgGraph -TenantId $graphTenantId -Scopes "Application.ReadWrite.All", "Directory.Read.All"
    } else {
        Write-Host "Connecting to Microsoft Graph with device code authentication..." -ForegroundColor Cyan
        Connect-MgGraph -TenantId $graphTenantId -Scopes "Application.ReadWrite.All", "Directory.Read.All" -UseDeviceCode
    }

    #//------------------------------------------------------------------------------------
    #//  List Agreement Types
    #//------------------------------------------------------------------------------------
    Write-Host "Choose an Agreement Type:"
    Write-Host "1) Enterprise Agreement (EA)"
    Write-Host "2) Microsoft Customer Agreement (MCA)"
    Write-Host "3) Cloud Solution Provider (CSP)"

    #//------------------------------------------------------------------------------------
    #//  Ask for User Input
    #//------------------------------------------------------------------------------------
    $choice = Read-Host "Enter the number corresponding to the Agreement Type (1, 2, or 3)"

    # Validate User Input
    switch ($choice) {
        1 { $agreementType = "EA" }
        2 { $agreementType = "MCA" }
        3 { $agreementType = "CSP" }
        default {
            Write-Host "Invalid choice. Please enter a valid number (1, 2, or 3)." -ForegroundColor Red
            exit
        }
    }

    # Print the Selected Agreement Type
    Write-Host "You selected the Agreement Type: $agreementType" -ForegroundColor Green
    switch ($choice) {
        1 {
            $agreementType = "EA"
            $accessToken = [Net.NetworkCredential]::new('', ((Get-AzAccessToken -ResourceUrl "https://management.azure.com/" -AsSecureString).Token)).Password
            $enrolmentId = Fetch-EEAMCABillingAccounts -bearerToken $accessToken
        }
        2 {
            $agreementType = "MCA" 
            $accessToken = [Net.NetworkCredential]::new('', ((Get-AzAccessToken -ResourceUrl "https://management.azure.com/" -AsSecureString).Token)).Password
            $enrolmentId = Fetch-EEAMCABillingAccounts -bearerToken $accessToken
        }
        3 {
            $agreementType = "CSP"
            $enrolmentId = $null # No input required for CSP
        }
    }

    #//------------------------------------------------------------------------------------
    #//                   Azure Active Directory Application Variables
    #//------------------------------------------------------------------------------------
    $appDisplayName = "CrayonCloudEconomicsReader"
    $ReplyUrl = "https://localhost"

    $EndDateMonths = Read-Host "Enter length of the Crayon agreement in months. Press Enter to use the default value (36 months from now)"
    if (-not $EndDateMonths) {
        $EndDate = (Get-Date).AddMonths(36)
        Write-Host "Default end date set to: $EndDate" -ForegroundColor Green
    }
    else {
        $EndDate = (Get-Date).AddMonths([int]$EndDateMonths)
        Write-Host "End date set to: $EndDate" -ForegroundColor Green
    }

    #//------------------------------------------------------------------------------------
    #//             Verify that the App Registration doesn't exit already
    #//------------------------------------------------------------------------------------
    # Define the app registration name to check
    $appName = $appDisplayName

    # Get the app registration
    $app = Get-MgApplication -Filter "DisplayName eq '$appName'"

    # Check if the app registration exists
    if ($app) {
        # Stop the script with a bold red text message
        Write-Host -ForegroundColor Red -BackgroundColor Black "`nPlease remove all CrayonCloudEconomicsReader App Registration in Azure and run the script again`n"
        exit
    }
    else {
        Write-Host -ForegroundColor Yellow -BackgroundColor Black "`nNo existing app registration found with the name '$appName'.`n"
    }

    #//------------------------------------------------------------------------------------
    #//                       Create a new AD Application and SPN
    #//------------------------------------------------------------------------------------
        $sp = New-AzADServicePrincipal -DisplayName $appDisplayName -Description "AzureCostControl" -EndDate $EndDate
        Write-Host "Waiting for Service Principal to be created..." -ForegroundColor Yellow
        Start-Sleep -Seconds 25        
        if ($sp) {
            Write-Host "Service Principal succesfully created with AppId: $($sp.AppId)" -ForegroundColor Green
            Update-AzADApplication -ApplicationId $sp.AppId -ReplyUrls $ReplyUrl
            # Get the service principal of the enterprise application
            $servicePrincipal = Get-MgServicePrincipal -Filter "DisplayName eq '$appDisplayName'"
            # Get the ObjectID of the enterprise application
            $EnterpriseObjectID = $servicePrincipal.Id
            # Get the AppId
            $appId = $servicePrincipal.AppId

            $tenantInfo += [pscustomobject]@{
                TenantId          = $RootTenantID
                TenantName        = $tenant.Name
                TenantDomain      = $tenant.Domains | Out-String -Width 150
                CountryCode       = $tenant.CountryCode
                AppId             = $sp.AppId
                SecretCredential  = $sp.PasswordCredentials.secretText
                SecretEndDateTime = $sp.PasswordCredentials.endDateTime
    }

        #//------------------------------------------------------------------------------------
        #//                                 Assign Reader Role
        #//------------------------------------------------------------------------------------
        Try {
            New-AzRoleAssignment -ServicePrincipalName $appId -RoleDefinitionName "Reader" -Scope $tenantRootMG.Id
            Write-Host "Successful Reader Role Assignment" -ForegroundColor Green
        }
        Catch {
            Write-Host "Failed Reader Role Assignment" -ForegroundColor Red
        }     
        
        #//------------------------------------------------------------------------------------
        #//                           Assign Cost Management Reader
        #//------------------------------------------------------------------------------------
        Try {
            New-AzRoleAssignment -ServicePrincipalName $appId -RoleDefinitionName "Cost Management Reader" -Scope $tenantRootMG.Id
            Write-Host "Successful Cost Management Reader Role Assignment" -ForegroundColor Green
        }
        Catch {
            Write-Host "Failed Cost Management Reader Role Assignment" -ForegroundColor Red
        }
        
        #//------------------------------------------------------------------------------------
        #//                            Assign Reservation Reader
        #//------------------------------------------------------------------------------------
        New-AzRoleAssignment -Scope "/providers/Microsoft.Capacity" -PrincipalId $EnterpriseObjectId -RoleDefinitionName $ReservationRoleAssignment

        #//------------------------------------------------------------------------------------
        #//                            Assign Savings Plan Reader
        #//------------------------------------------------------------------------------------
        New-AzRoleAssignment -Scope "/providers/Microsoft.BillingBenefits" -PrincipalId $EnterpriseObjectId -RoleDefinitionName "Savings Plan Reader"

        #//------------------------------------------------------------------------------------
        #//                         Assign Carbon Optimization Reader
        #//------------------------------------------------------------------------------------
        New-AzRoleAssignment -Scope "/providers/Microsoft.Management/managementGroups/$RootTenantID" -PrincipalId $EnterpriseObjectId -RoleDefinitionId $CarbonOptimizationRoleAssignment

        #//------------------------------------------------------------------------------------
        #//                           Assign Reader to SavingsPlans
        #//------------------------------------------------------------------------------------
        # Get SavingsPlans
        $savingsPlansObjects = Get-AzBillingBenefitsSavingsPlanOrder
        
        if ($savingsPlansObjects) {
            foreach ($savingPlan in $savingsPlansObjects) {
                $savingsPlanOrderId = $savingPlan.Id

                # Check if the SavingsPlans already has been assigned the "Reader" role
                $scope = Get-AzRoleAssignment -Scope $savingsPlanOrderId -ObjectId $EnterpriseObjectId -RoleDefinitionName $SavingsPlanRoleAssignment
                $RoleAssignmentId = $scope.RoleDefinitionName

                if ($RoleAssignmentId -contains 'Reader') {
                    Write-Host "SavingsPlans Order already assigned Role" $RoleAssignmentId.Split("/")[-1]"" -ForegroundColor green 
                }
                else {
                    Write-Host "Assigning "$SavingsPlanRoleAssignment" to "$savingsPlanOrderId 
                    New-AzRoleAssignment -Scope $savingsPlanOrderId -ApplicationId $appId -RoleDefinitionName $SavingsPlanRoleAssignment 
                }
            }
        }
        else {
            Write-Host "No SavingsPlans Found in this tenant. Or the user does not have access to" -ForegroundColor Red
        }
        
        if ($agreementType -eq "EA") {
            #//------------------------------------------------------------------------------------
            #//                           Assign Enrollment Reader to SPN
            #//------------------------------------------------------------------------------------
            $token = [Net.NetworkCredential]::new('', ((Get-AzAccessToken -ResourceUrl "https://management.azure.com/" -AsSecureString).Token)).Password
            $url = "https://management.azure.com/providers/Microsoft.Billing/billingAccounts/$enrolmentId/billingRoleAssignments/24f8edb6-1668-4659-b5e2-40bb5f3a7d7e?api-version=2019-10-01-preview"
            $headers = @{'Authorization' = "Bearer $token" }
            $contentType = "application/json"
            $data = @{        
                properties = @{
                    principalid       = "$EnterpriseObjectId";
                    principalTenantId = "$RootTenantID";
                    RoleDefinitionID  = "/providers/Microsoft.Billing/billingAccounts/$enrolmentId/billingRoleDefinitions/24f8edb6-1668-4659-b5e2-40bb5f3a7d7e"
                }
            }
            $json = $data | ConvertTo-Json
            Invoke-WebRequest -Method PUT -Uri $url -ContentType $contentType -Headers $headers -Body $json
        }
        if ($agreementType -eq "MCA") {
            $token = [Net.NetworkCredential]::new('', ((Get-AzAccessToken -ResourceUrl "https://management.azure.com/" -AsSecureString).Token)).Password
            $url = "https://management.azure.com/providers/Microsoft.Billing/billingAccounts/$enrolmentId/createBillingRoleAssignment?api-version=2019-10-01-preview"
            $headers = @{'Authorization' = "Bearer $token" }
            $contentType = "application/json"
            $data = @{        
                properties = @{
                    principalid      = "$EnterpriseObjectId";
                    RoleDefinitionID = "/providers/Microsoft.Billing/billingAccounts/$enrolmentId/billingRoleDefinitions/50000000-aaaa-bbbb-cccc-100000000002"
                }
            }
            $json = $data | ConvertTo-Json
            Invoke-WebRequest -Method POST -Uri $url -ContentType $contentType -Headers $headers -Body $json
        }
    }
    
    # Converts the list to a csv, path defined at the top of this script
    $dateKey = Get-Date -Format "yyyyMMdd"
    $filepath = "$DirectoryPath\CrayonCloudEconomics-" + $tenant.Name + "-" + $dateKey + ".csv"
    $tenantInfo | Export-Csv -Path $filepath
    Write-Host "Securely send the file from the $DirectoryPath directory to Crayon, then remove the folder." -ForegroundColor Green

    Start-Sleep -Seconds 20

    #//------------------------------------------------------------------------------------
    #//                                 Choose subscription
    #//------------------------------------------------------------------------------------

    # Get all subscriptions
    $subscriptions = Get-AzSubscription

    # Select the first subscription
    $firstSubscription = $subscriptions[0]

    # Set the context to the first subscription
    Set-AzContext -SubscriptionId $firstSubscription.Id

    # Assuming $tenantInfo is an array of objects
    foreach ($tenantObject in $tenantInfo) {
        $currentTenantId = $RootTenantID
        $currentAppId = $tenantObject.AppId
        $currentSecretCredential = $tenantObject.SecretCredential
        $secret = $tenantObject.SecretCredential | ConvertTo-SecureString -AsPlainText -Force
        $psCredential = New-Object System.Management.Automation.PsCredential($currentAppId, $secret)
        Connect-AzAccount -ServicePrincipal -Credential $psCredential -TenantId $currentTenantId -Warningaction SilentlyContinue
        
        #//------------------------------------------------------------------------------------
        #//                         CHECK SUBSCRIPTION READER ACCESS
        #//------------------------------------------------------------------------------------
        Write-Host "Checking subscriptions..."

        try {
            $subs = Get-AzSubscription
        }
        catch {
            $suberror = $_.Exception.Message 
        }

        $subs | Select-Object Name, Id | Format-Table

        $subcount = $subs.Count

        if ($subcount -gt 1) {
            Write-Host "There are $subcount subscriptions readable for Application ID: $currentAppId" -ForegroundColor Green
            $sub = "$subcount subscriptions: OK"
        }
        elseif ($subcount -eq 1) {
            Write-Host "There is only $subcount subscription readable for Application ID: $currentAppId. Check with the customer if this is correct." -ForegroundColor Yellow
            $sub = "Subscription count: CHECK. Only $subcount subscription visible. Check with the customer."
        }
        else {
            Write-Host "There are no subscriptions readable for Application ID: $currentAppId. Check with the customer if this is correct." -ForegroundColor Red
            $sub = "Subscription count: FAILED. No subscriptions visible. Check with the customer. Check that IAM role is set to Reader on the Management Group Root for CrayonCloudEconomics app."
        }
        
        #//------------------------------------------------------------------------------------
        #//                             CHECK READER ROLES FOR APP
        #//------------------------------------------------------------------------------------
        Write-Host "Checking Reader roles level..."

        try {
            $roles = Get-AzRoleAssignment -ServicePrincipalName $currentAppId -Scope "/providers/Microsoft.Management/managementGroups/$RootTenantID"
        }
        catch {
            $mgmterror = $_.Exception.Message 
        }

        $roles | Select-Object DisplayName, RoleDefinitionName, Scope | Format-Table

        # Check if both RoleDefinitions are assigned at the management group level
        $managementGroupRoles = $roles | Where-Object {
            $_.Scope -like '/providers/Microsoft.Management/managementGroups*' -and
            ($_.RoleDefinitionName -eq 'Reader' -or $_.RoleDefinitionName -eq 'Cost Management Reader' -or $_.RoleDefinitionName -eq "Carbon Optimization Reader")
        }

        if ($managementGroupRoles.Count -eq 3) {
            Write-Host "Permissions are set on management group level." -ForegroundColor Green
            $mgmt = "Permissions set on Management Group level: OK. There are $subcount subscriptions visible."
        } 
        else {
            if ($null -ne $managementGroupRoles) {
                $missingRoles = @('Reader', 'Cost Management Reader') | Where-Object {
                    $roleName = $_
                    -not $managementGroupRoles.RoleDefinitionName.Contains($roleName)
                }

                $missingRolesString = $missingRoles -join ', '

                Write-Host "FAILED: Permissions look to be set on subscription level. The following RoleDefinitionName(s) are missing at the management group level: '$missingRolesString'. Check if this is correct." -ForegroundColor Red
                $mgmt = "Management Group level reader access: FAILED. There are $subcount subscriptions visible. Check that IAM role is set to '$missingRolesString' on Management Group Root for CrayonCloudEconomics app."
            }
            else {
                Write-Host "ERROR: Management group roles object is null. Check that IAM roles is set to 'Reader' and 'Cost Management Reader' on Management Group Root for CrayonCloudEconomics app." -ForegroundColor Red
            }
        }
        
        #//------------------------------------------------------------------------------------
        #//                                 CHECK RESERVATIONS
        #//------------------------------------------------------------------------------------
        try {
            $reservationObjects = Get-AzReservation
        }
        catch {
            $reserror = $_.Exception.Message
        }

        $reservationcount = $reservationObjects.Count

        #//------------------------------------------------------------------------------------
        #//                             CHECK RESERVATION NUMBERS
        #//------------------------------------------------------------------------------------
        Write-Host "Checking how many reservations are readable..."

        if ($reservationcount -gt 0) {
            Write-Host "There are $reservationcount reservations readable for Application ID: $currentAppId" -ForegroundColor Green
            $res = "Reservations visible: OK. There are $reservationcount reservations"
        }
        else {
            Write-Host "There are $reservationcount reservations readable for Application ID: $currentAppId." -ForegroundColor Yellow
            $res = "Reservations visible: CHECK. $reservationcount reservations are visible. Looks like reservations have not been bought."
        }
        #//------------------------------------------------------------------------------------
        #//                                 CHECK SavingsPlan 
        #//------------------------------------------------------------------------------------
        try {
            $savingsPlanObjects = Get-AzBillingBenefitsSavingsPlanOrder
        }
        catch {
            $reserror = $_.Exception.Message
        }

        $savingsPlanCount = $savingsPlanObjects.Count

        #//------------------------------------------------------------------------------------
        #//                             CHECK SavingsPlan NUMBERS
        #//------------------------------------------------------------------------------------
        Write-Host "Checking how many SavingsPlan are readable..."

        if ($savingsPlanCount -gt 0) {
            Write-Host "There are $savingsPlanCount savingsplans readable for Application ID: $currentAppId" -ForegroundColor Green
            $sav = "SavingsPlan visible: OK. There are $savingsPlanCount savingsplans"
        }
        else {
            Write-Host "There are $savingsPlanCount savingsplans readable for Application ID: $currentAppId." -ForegroundColor Yellow
            $sav = "Savingsplan visible: CHECK. $savingsPlanCount savingsplans are visible. Looks like savingsplans have not been bought."
        }
        
        #//------------------------------------------------------------------------------------
        #//                 GET - BILLING API TEST - READ BILLING ACCOUNTS
        #//------------------------------------------------------------------------------------
        if ($agreementType -ne "CSP") {
            Write-Host "Checking Enrollment reader permissions..."

            $body = @{
                grant_type    = 'client_credentials'
                client_id     = $currentAppId
                client_secret = $currentSecretCredential
                scope         = "$currentTenantId/.default"
                resource      = 'https://management.azure.com'
            }

            $contentType = 'application/x-www-form-urlencoded'

            # GET ACCESS TOKEN
            $oauth = Invoke-WebRequest -Method POST -Uri "https://login.microsoftonline.com/$currentTenantId/oauth2/token" -Body $body -ContentType $contentType
            $accessToken = ($oauth.Content | ConvertFrom-Json).access_token

            # GET RESULTS
            $results = Invoke-WebRequest -Uri "https://management.azure.com/providers/Microsoft.Billing/billingAccounts?api-version=2019-10-01-preview" -Method GET -Headers @{Authorization = "Bearer $accessToken" } -ContentType $contentType
            $content = ConvertFrom-Json $results.Content
            $agreement = $content.value.properties.agreementType

            if ($null -ne $content.value.properties.agreementType) {
                Write-Host "Reader access to the billing account is OK. Agreement type is $agreement" -ForegroundColor Green
                $bill = "Billing Account reader access to agreement: OK. Agreement type is $agreement"
            }
            else {
                Write-Host "FAILURE: Unable to verify reader permissions to the Billing Account" -ForegroundColor Red
                $bill = "Billing Account reader access: FAILED. Check that you have permissions to (EA Agreement) or (EA MCA Agreement) agreement set properly."
            }
        }
        
        #//------------------------------------------------------------------------------------
        #//                                 SUMMARIZE RESULTS
        #//------------------------------------------------------------------------------------
        Write-Host "---SUMMARY---" -ForegroundColor Yellow

        if ($sub.Contains("OK")) {
            Write-Host "1) $sub" -ForegroundColor Green
        }
        elseif ($sub.Contains("CHECK")) {
            Write-Host "1) $sub" -ForegroundColor Yellow
        }
        else {
            Write-Host "1) $sub" -ForegroundColor Red
            Write-Host "$suberror"
        }

        if ($mgmt.Contains("OK")) {
            Write-Host "2) $mgmt" -ForegroundColor Green
        }
        else {
            Write-Host "2) $mgmt" -ForegroundColor Red
            Write-Host "$mgmterror" -ForegroundColor Red
        }

        if ($res.Contains("OK")) {
            Write-Host "3) $res" -ForegroundColor Green
        }
        elseif ($res.Contains("CHECK")) {
            Write-Host "3) $res"
        }
        else {
            Write-Host "3) $res"
            Write-Host "$reserror" -ForegroundColor Red
        }
        
        if ($sav.Contains("OK")) {
            Write-Host "4) $sav" -ForegroundColor Green
        }
        elseif ($sav.Contains("CHECK")) {
            Write-Host "4) $sav"
        }
        else {
            Write-Host "4) $sav"
            Write-Host "$reserror" -ForegroundColor Red
        }
        if ($agreementType -ne "CSP") {
            if ($bill.Contains("OK")) {
                Write-Host "5) $bill" -ForegroundColor Green
            }
            else {
                Write-Host "5) $bill" -ForegroundColor Red
            }
        }
    }

}
    else {
    Write-Host "No tenant can be read" -ForegroundColor Red
}

#//------------------------------------------------------------------------------------
#//                                     DISCONNECT
#//------------------------------------------------------------------------------------
Write-Host "Disconnecting..."
Disconnect-AzAccount > $null
Disconnect-MgGraph > $null