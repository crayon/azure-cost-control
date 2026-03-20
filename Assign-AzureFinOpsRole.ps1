<#PSScriptInfo

.VERSION 1.2.0

.AUTHOR Crayon. http://www.crayon.com

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
1.0.8 - Added login method selection (Interactive Browser/Device Code), added tenant selection capability, aligned Microsoft Graph authentication with Azure authentication method, improved secure token handling using NetworkCredential with AsSecureString parameter, added role assignments for BillingBenefits provider roles.
1.0.9 - Major error handling and safety overhaul. Added pre-flight permission validation that checks all required permissions (management group access, role assignment rights, Graph permissions, billing account access, existing app registration) BEFORE creating anything - no more orphaned app registrations from permission failures. Added agreement type auto-detection with mismatch warning (catches EA-to-MCA migrations). Wrapped all role assignments in try/catch. Added role assignment summary table. Clear error guidance for every failure mode. Module install falls back to CurrentUser scope. SPN propagation uses retry loop. CSV always generates even if some assignments fail.
1.1.0 - Replaced blind first-billing-account selection with interactive listing of all billing accounts. Operator now sees every account (ID, display name, agreement type, status) and selects explicitly. Deactivated account selection triggers a confirmation warning before proceeding. Fixes onboarding failures on tenants with mixed EA/MCA billing accounts (e.g. post-migration tenants).
1.2.0 - Billing-first flow: script now fetches and lists billing accounts BEFORE asking for agreement type. Agreement type is auto-detected from the selected billing account, eliminating manual selection and mismatch issues. Manual agreement type prompt only appears as fallback when billing accounts cannot be accessed (e.g. CSP tenants or missing billing permissions).
#>
# Requires -Modules Az
$ErrorActionPreference = "Stop"

# ============================================================================
#  ENVIRONMENT DETECTION
# ============================================================================
# Detect OS reliably across PowerShell 5.1 and 7+
# $IsWindows is only auto-defined in PS 7+. On PS 5.1, it doesn't exist.
# We use our own $script:RunningOnWindows etc. to avoid writing to the readonly
# automatic variables ($IsWindows, $IsLinux, $IsMacOS) that PS 6+ enforces.
if ($null -eq $IsWindows) {
    # PowerShell 5.1 on Windows
    $script:RunningOnWindows = $true
    $script:RunningOnLinux   = $false
    $script:RunningOnMacOS   = $false
}
else {
    $script:RunningOnWindows = $IsWindows
    $script:RunningOnLinux   = $IsLinux
    $script:RunningOnMacOS   = $IsMacOS
}

# Detect if running in Azure Cloud Shell
$script:isCloudShell = $false
if ($env:AZUREPS_HOST_ENVIRONMENT -like "*cloud-shell*" -or $env:ACC_CLOUD -eq "true" -or (Test-Path "/home/*/.azure/cloudshell" -ErrorAction SilentlyContinue)) {
    $script:isCloudShell = $true
}

# Detect if we have internet access to PSGallery (bastion/air-gapped detection)
# Cloud Shell always has internet access, so skip the probe there — the HEAD
# request to PSGallery can fail in Cloud Shell due to proxy/networking quirks
# even though Install-Module works perfectly fine.
$script:hasInternetAccess = $true
if (-not $script:isCloudShell) {
    try {
        $null = Invoke-RestMethod -Uri "https://www.powershellgallery.com/api/v2/" -Method Head -TimeoutSec 5 -ErrorAction Stop
    }
    catch {
        $script:hasInternetAccess = $false
    }
}

# Detect PowerShell version
$script:psVersion = $PSVersionTable.PSVersion
$script:isPSCore = $PSVersionTable.PSEdition -eq "Core"

# ============================================================================
#  ROLE ASSIGNMENT TRACKING
# ============================================================================
# We track every role assignment result so we can show a clear summary at the end
$script:roleAssignmentResults = @()

function Add-RoleAssignmentResult {
    param(
        [string]$RoleName,
        [string]$Scope,
        [string]$Status, # "Success", "Failed", "Skipped"
        [string]$Message = ""
    )
    $script:roleAssignmentResults += [pscustomobject]@{
        Role    = $RoleName
        Scope   = $Scope
        Status  = $Status
        Message = $Message
    }
}

# ============================================================================
#  MODULE MANAGEMENT
# ============================================================================
function Install-Module-If-Needed {
    param([string]$ModuleName)
    
    if (Get-Module -ListAvailable -Name $ModuleName) {
        Write-Host "  [OK] Module '$($ModuleName)' already installed" -ForegroundColor Green
    }
    else {
        if (-not $script:hasInternetAccess) {
            Write-Host ""
            Write-Host "  ================================================================" -ForegroundColor Red
            Write-Host "  FATAL: Module '$ModuleName' is not installed and this machine" -ForegroundColor Red
            Write-Host "  cannot reach the PowerShell Gallery (no internet access)." -ForegroundColor Red
            Write-Host "  ================================================================" -ForegroundColor Red
            Write-Host ""
            Write-Host "  You are likely running from a bastion host or air-gapped network." -ForegroundColor Yellow
            Write-Host ""
            Write-Host "  Options:" -ForegroundColor Cyan
            Write-Host "  1. Pre-install modules on this machine from an online machine:" -ForegroundColor Yellow
            Write-Host "     Save-Module $ModuleName -Path C:\Modules" -ForegroundColor White
            Write-Host "     Then copy and import on bastion." -ForegroundColor Yellow
            Write-Host ""
            Write-Host "  2. Use Azure Cloud Shell instead (https://shell.azure.com)" -ForegroundColor Yellow
            Write-Host "     Cloud Shell has all required modules pre-installed." -ForegroundColor Yellow
            Write-Host ""
            throw "Required module '$ModuleName' is missing and no internet access is available."
        }

        Write-Host "  [INSTALLING] Module '$($ModuleName)'..." -ForegroundColor Yellow
        try {
            Install-Module $ModuleName -Force -AllowClobber -ErrorAction Stop
            Write-Host "  [OK] Module '$($ModuleName)' installed" -ForegroundColor Green
        }
        catch {
            # Try CurrentUser scope if system-wide install fails (no admin rights)
            Write-Host "  [RETRY] System-wide install failed, trying CurrentUser scope..." -ForegroundColor Yellow
            try {
                Install-Module $ModuleName -Force -AllowClobber -Scope CurrentUser -ErrorAction Stop
                Write-Host "  [OK] Module '$($ModuleName)' installed (CurrentUser scope)" -ForegroundColor Green
            }
            catch {
                Write-Host ""
                Write-Host "  [FATAL] Could not install module '$($ModuleName)'." -ForegroundColor Red
                Write-Host "  Try running PowerShell as Administrator, or install manually:" -ForegroundColor Yellow
                Write-Host "    Install-Module $ModuleName -Scope CurrentUser -Force" -ForegroundColor Yellow
                throw "Required module '$ModuleName' could not be installed."
            }
        }
    }
}

function Import-Modules {
    param ([string[]]$moduleNames)

    $assemblyConflict = $false

    foreach ($moduleName in $moduleNames) {
        if (Get-Module -Name $moduleName -ListAvailable) {
            if (-not (Get-Module -Name $moduleName)) {
                try {
                    Import-Module -Name $moduleName -DisableNameChecking -ErrorAction Stop
                }
                catch {
                    $importError = "$_"
                    if ($importError -like "*Assembly with same name is already loaded*" -or $importError -like "*AssemblyLoading*") {
                        Write-Host "  [WARNING] Module '$moduleName' has an assembly version conflict" -ForegroundColor Yellow
                        $assemblyConflict = $true
                    }
                    else {
                        Write-Host "  [WARNING] Failed to import module '$moduleName': $importError" -ForegroundColor Yellow
                    }
                }
            }
        }
        else {
            Write-Host "  [WARNING] Module '$moduleName' is not available." -ForegroundColor Yellow
        }
    }

    if ($assemblyConflict) {
        Write-Host ""
        Write-Host "  ================================================================" -ForegroundColor Red
        Write-Host "  FATAL: PowerShell module version conflict detected." -ForegroundColor Red
        Write-Host "  ================================================================" -ForegroundColor Red
        Write-Host ""
        Write-Host "  Multiple versions of the Az modules are loaded in this session." -ForegroundColor Yellow
        Write-Host "  This prevents the script from running." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  HOW TO FIX:" -ForegroundColor Cyan
        Write-Host "  Option 1 (easiest): Close PowerShell completely, open a NEW" -ForegroundColor Yellow
        Write-Host "  terminal, and run this script FIRST before any other commands." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Option 2 (clean install): Run these commands in a new terminal:" -ForegroundColor Yellow
        Write-Host "    Get-Module Az* | Remove-Module -Force" -ForegroundColor White
        Write-Host "    Uninstall-Module Az -AllVersions -Force" -ForegroundColor White
        Write-Host "    Install-Module Az -Force -AllowClobber" -ForegroundColor White
        Write-Host ""
        Write-Host "  Option 3 (recommended): Use Azure Cloud Shell instead." -ForegroundColor Yellow
        Write-Host "    Go to: https://shell.azure.com" -ForegroundColor White
        Write-Host "    Cloud Shell always has compatible module versions." -ForegroundColor White
        Write-Host ""
        exit 1
    }
}

# ============================================================================
#  BILLING ACCOUNT FUNCTIONS
# ============================================================================
function Fetch-BillingAccounts {
    param(
        [Parameter(Mandatory = $true)]
        [string]$bearerToken
    )

    $ApiUri = "https://management.azure.com/providers/Microsoft.Billing/billingAccounts?api-version=2019-10-01-preview"
    $Headers = @{
        'Content-Type'  = "application/json"
        'Authorization' = "Bearer $bearerToken"
    }
    try {
        $billingAccounts = Invoke-RestMethod -Uri $ApiUri -Headers $Headers -Method Get
    }
    catch {
        Write-Host ""
        Write-Host "  ================================================================" -ForegroundColor Red
        Write-Host "  ERROR: Cannot access billing accounts." -ForegroundColor Red
        Write-Host "  ================================================================" -ForegroundColor Red
        Write-Host ""
        Write-Host "  Common causes:" -ForegroundColor Yellow
        Write-Host "  - EA: You need the Enterprise Administrator role" -ForegroundColor Yellow
        Write-Host "    (assigned in ea.azure.com or billing.microsoft.com)" -ForegroundColor Yellow
        Write-Host "  - MCA: You need Billing Account Owner or Billing Profile Owner" -ForegroundColor Yellow
        Write-Host "    (assigned in Azure Portal -> Cost Management + Billing)" -ForegroundColor Yellow
        Write-Host "  - The EA enrollment may not be onboarded to the Azure portal" -ForegroundColor Yellow
        Write-Host ""
        throw "Failed to fetch billing accounts. Please check billing permissions. Error: $_"
    }

    if (-not $billingAccounts.value) {
        throw "No billing accounts found. Please confirm that the customer has an active EA or MCA agreement and the user has the required billing permissions."
    }

    return $billingAccounts.value
}

# NEW in 1.1.0: Instead of blindly taking [0], present all accounts to the operator
# and let them pick explicitly. This fixes failures on tenants with mixed EA/MCA accounts
# (e.g. post-Microsoft-migration tenants that still have both an old EA and a new MCA account).
function Select-BillingAccount {
    param(
        [Parameter(Mandatory = $true)]
        $billingAccountValues
    )

    Write-Host ""
    Write-Host "  Found $($billingAccountValues.Count) billing account(s):" -ForegroundColor Cyan
    Write-Host ""

    $index = 1
    foreach ($account in $billingAccountValues) {
        $name        = $account.name
        $displayName = $account.properties.displayName
        $agreement   = $account.properties.agreementType
        $status      = $account.properties.accountStatus

        # Active = green, anything else (Deactivated, Expired, etc.) = yellow
        $statusColor = if ($status -eq "Active") { "Green" } else { "Yellow" }

        Write-Host "  [$index] $displayName" -ForegroundColor White
        Write-Host "      ID        : $name" -ForegroundColor DarkGray
        Write-Host "      Agreement : $agreement" -ForegroundColor DarkGray
        Write-Host "      Status    : " -ForegroundColor DarkGray -NoNewline
        Write-Host "$status" -ForegroundColor $statusColor
        Write-Host ""

        $index++
    }

    # Loop until a valid selection is made
    $selection = $null
    while ($null -eq $selection) {
        $userInput = Read-Host "  Select billing account to use (1-$($billingAccountValues.Count))"
        $parsed = 0
        if ([int]::TryParse($userInput, [ref]$parsed) -and $parsed -ge 1 -and $parsed -le $billingAccountValues.Count) {
            $selection = $billingAccountValues[$parsed - 1]
        }
        else {
            Write-Host "  Invalid selection. Please enter a number between 1 and $($billingAccountValues.Count)." -ForegroundColor Red
        }
    }

    $selectedAgreement = $selection.properties.agreementType
    $selectedStatus    = $selection.properties.accountStatus

    Write-Host ""
    Write-Host "  Selected: $($selection.properties.displayName)" -ForegroundColor Green
    Write-Host "  Agreement: $selectedAgreement | Status: $selectedStatus" -ForegroundColor Green

    # Warn if the selected account is not Active — but allow the operator to override
    if ($selectedStatus -ne "Active") {
        Write-Host ""
        Write-Host "  [WARNING] This billing account is not Active (Status: $selectedStatus)." -ForegroundColor Yellow
        $confirm = Read-Host "  Are you sure you want to proceed with this account? (Y/N) [default: N]"
        if ([string]::IsNullOrWhiteSpace($confirm) -or ($confirm -ne "Y" -and $confirm -ne "y")) {
            Write-Host "  Exiting. Please re-run and select a different account." -ForegroundColor Red
            exit 1
        }
    }

    return $selection
}

function Get-DetectedAgreementType {
    param(
        [Parameter(Mandatory = $true)]
        $billingAccountValues
    )

    # NOTE: In 1.1.0 this function now receives the SELECTED account object rather than
    # the full array, so we read agreementType directly from properties.
    $agreementType = $billingAccountValues.properties.agreementType

    switch ($agreementType) {
        "EnterpriseAgreement"         { return "EA" }
        "MicrosoftCustomerAgreement"  { return "MCA" }
        "MicrosoftPartnerAgreement"   { return "CSP" }
        default                       { return $agreementType }
    }
}

# ============================================================================
#  PREREQUISITE CHECKS
# ============================================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Crayon Azure Cost Control - Onboarding Script v1.2.0" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Show detected environment
$osName = if ($IsWindows) { "Windows" } elseif ($IsMacOS) { "macOS" } elseif ($IsLinux) { "Linux" } else { "Unknown" }
$shellInfo = if ($script:isCloudShell) { "Azure Cloud Shell" } else { "Local" }
$netInfo = if ($script:hasInternetAccess) { "Online" } else { "No internet (bastion/air-gapped)" }

Write-Host "  Environment: $osName | PowerShell $($script:psVersion) | $shellInfo | $netInfo" -ForegroundColor DarkGray
Write-Host ""

if (-not $script:hasInternetAccess) {
    Write-Host "  [WARNING] No internet access detected. Module installation will fail" -ForegroundColor Yellow
    Write-Host "  if required modules are not already present on this machine." -ForegroundColor Yellow
    Write-Host "  Consider using Azure Cloud Shell (https://shell.azure.com) instead." -ForegroundColor Yellow
    Write-Host ""
}

Write-Host "Step 1: Checking PowerShell module prerequisites..." -ForegroundColor Cyan

$modules = @(
    "Az.Accounts", "Az.Reservations", "Az.BillingBenefits",
    "Az.Resources", "Az.Billing",
    "Microsoft.Graph.Authentication", "Microsoft.Graph.Applications",
    "Microsoft.Graph.Identity.DirectoryManagement"
)

foreach ($mod in $modules) {
    Install-Module-If-Needed $mod
}

Import-Modules -moduleNames $modules

# ============================================================================
#  VARIABLES
# ============================================================================
$ReservationRoleAssignment = "Reservations Reader"
$SavingsPlanRoleAssignment = "Reader"
$CarbonOptimizationRoleAssignment = "fa0d39e6-28e5-40cf-8521-1eb320653a4c" # Carbon Optimization Reader

# ============================================================================
#  LOGIN TO AZURE
# ============================================================================
Write-Host ""
Write-Host "Step 2: Azure Authentication" -ForegroundColor Cyan

# On Cloud Shell, we're already authenticated — skip login choice
if ($script:isCloudShell) {
    Write-Host "  Azure Cloud Shell detected — using existing authentication." -ForegroundColor Green
    $loginChoice = "cloudshell"
    # Cloud Shell may already have an Az context
    $existingContext = Get-AzContext -ErrorAction SilentlyContinue
    if ($existingContext) {
        Write-Host "  [OK] Already connected as: $($existingContext.Account.Id)" -ForegroundColor Green
    }
    else {
        Write-Host "  Connecting to Azure in Cloud Shell..." -ForegroundColor Cyan
        try {
            Connect-AzAccount -Identity -WarningAction SilentlyContinue -ErrorAction Stop
        }
        catch {
            # Fall back to interactive in Cloud Shell
            Connect-AzAccount -WarningAction SilentlyContinue -ErrorAction Stop
        }
    }
}
else {
    $loginChoice = Read-Host "Choose login method (1: Interactive Browser  2: Device Code) [default: 1]"
    if ([string]::IsNullOrWhiteSpace($loginChoice) -or ($loginChoice -ne "1" -and $loginChoice -ne "2")) {
        $loginChoice = "1"
    }
}

$tenantIdPrompt = Read-Host "Enter specific tenant ID to log into (leave empty for default tenant)"
$tenantParam = @{}
if (-not [string]::IsNullOrWhiteSpace($tenantIdPrompt)) {
    $tenantParam = @{TenantId = $tenantIdPrompt }
    Write-Host "  Will connect to tenant: $tenantIdPrompt" -ForegroundColor Cyan
}

if ($loginChoice -ne "cloudshell") {
    switch ($loginChoice) {
        "2" {
            Write-Host "  Logging in with device code authentication..." -ForegroundColor Cyan
            try {
                Connect-AzAccount -WarningAction SilentlyContinue -UseDeviceAuthentication @tenantParam -ErrorAction Stop
            }
            catch {
                Write-Host "  [FATAL] Azure login failed: $_" -ForegroundColor Red
                Write-Host ""
                Write-Host "  If interactive browser login failed, try Device Code instead:" -ForegroundColor Yellow
                Write-Host "  Re-run the script and choose option 2." -ForegroundColor Yellow
                Write-Host ""
                Write-Host "  If you are on a bastion/headless machine with no browser," -ForegroundColor Yellow
                Write-Host "  Device Code is required. You will see a URL and code to" -ForegroundColor Yellow
                Write-Host "  enter on any device with a browser." -ForegroundColor Yellow
                exit 1
            }
        }
        default {
            Write-Host "  Logging in with interactive browser authentication..." -ForegroundColor Cyan
            try {
                Connect-AzAccount -WarningAction SilentlyContinue @tenantParam -ErrorAction Stop
            }
            catch {
                $loginError = "$_"
                Write-Host "  [FAILED] Interactive browser login failed." -ForegroundColor Red
                Write-Host ""
                if ($loginError -like "*browser*" -or $loginError -like "*AADSTS*" -or $loginError -like "*interactive*") {
                    Write-Host "  No browser available. Falling back to Device Code..." -ForegroundColor Yellow
                    try {
                        Connect-AzAccount -WarningAction SilentlyContinue -UseDeviceAuthentication @tenantParam -ErrorAction Stop
                    }
                    catch {
                        Write-Host "  [FATAL] Device Code login also failed: $_" -ForegroundColor Red
                        Write-Host "  Please check network connectivity to login.microsoftonline.com" -ForegroundColor Yellow
                        exit 1
                    }
                    $loginChoice = "2"  # Remember we fell back to device code for Graph later
                }
                else {
                    Write-Host "  [FATAL] Azure login failed: $loginError" -ForegroundColor Red
                    Write-Host "  Please check your credentials and try again." -ForegroundColor Yellow
                    exit 1
                }
            }
        }
    }
    # If a specific tenant was requested but wasn't in the initial login, set context
    if (-not [string]::IsNullOrWhiteSpace($tenantIdPrompt)) {
        $currentContext = Get-AzContext
        if ($currentContext.Tenant.Id -ne $tenantIdPrompt) {
            try {
                Set-AzContext -TenantId $tenantIdPrompt -ErrorAction Stop | Out-Null
            }
            catch {
                Write-Host "  [WARNING] Could not switch to tenant $tenantIdPrompt : $_" -ForegroundColor Yellow
            }
        }
    }
}

Write-Host "  [OK] Azure authentication successful" -ForegroundColor Green

$tenantInfo = @()

# ============================================================================
#  TENANT SETUP
# ============================================================================
$azContext = Get-AzContext

$provider = Get-AzResourceProvider -ProviderNamespace Microsoft.Management
if ($provider.RegistrationState -ne 'Registered') {
    Register-AzResourceProvider -ProviderNamespace Microsoft.Management
    Start-Sleep -Seconds 10
}

$tenantRootMG = $null
try {
    $tenantRootMG = Get-AzManagementGroup -GroupName $azContext.tenant.ID -WarningAction SilentlyContinue -ErrorAction Stop
}
catch {
    Write-Host ""
    Write-Host "  ================================================================" -ForegroundColor Red
    Write-Host "  FATAL: Cannot access the root management group." -ForegroundColor Red
    Write-Host "  ================================================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "  This usually means elevated access has not been enabled." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  To fix this:" -ForegroundColor Yellow
    Write-Host "  1. Go to: Azure Portal -> Microsoft Entra ID -> Properties" -ForegroundColor Yellow
    Write-Host "  2. Set 'Access management for Azure resources' to YES" -ForegroundColor Yellow
    Write-Host "  3. Click Save" -ForegroundColor Yellow
    Write-Host "  4. Re-run this script" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  IMPORTANT: You must be a Global Administrator to do this." -ForegroundColor Yellow
    Write-Host "  Remember to set it back to NO after running this script." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Docs: https://learn.microsoft.com/en-us/azure/role-based-access-control/elevate-access-global-admin" -ForegroundColor DarkGray
    exit 1
}

$tenant = Get-AzTenant

if (-not $tenant) {
    Write-Host "[FATAL] No tenant can be read. Exiting." -ForegroundColor Red
    exit 1
}

# ============================================================================
#  CREATE OUTPUT FOLDER
# ============================================================================
if ($IsWindows) {
    $DirectoryPath = Join-Path -Path $env:SystemDrive -ChildPath "crayon"
    # Fallback if SystemDrive is not set
    if (-not $env:SystemDrive) { $DirectoryPath = "C:\crayon" }
}
else {
    $DirectoryPath = Join-Path -Path $HOME -ChildPath "crayon"
}

if (-Not (Test-Path -Path $DirectoryPath)) {
    New-Item -Path $DirectoryPath -ItemType "directory" | Out-Null
    Write-Host "  [OK] Directory created: $DirectoryPath" -ForegroundColor Green
}
else {
    Write-Host "  [OK] Directory exists: $DirectoryPath" -ForegroundColor Green
}

$RootTenantID = $tenantRootMG.TenantId

# ============================================================================
#  CONNECT TO MICROSOFT GRAPH
# ============================================================================
Write-Host ""
Write-Host "Step 3: Connecting to Microsoft Graph..." -ForegroundColor Cyan

$graphTenantId = $RootTenantID
if (-not [string]::IsNullOrWhiteSpace($tenantIdPrompt)) {
    $graphTenantId = $tenantIdPrompt
}

try {
    if ($script:isCloudShell -or $loginChoice -eq "2") {
        Write-Host "  Connecting with device code authentication..." -ForegroundColor Cyan
        Connect-MgGraph -TenantId $graphTenantId -Scopes "Application.ReadWrite.All", "Directory.Read.All" -UseDeviceCode -NoWelcome -ErrorAction Stop
    }
    else {
        try {
            Connect-MgGraph -TenantId $graphTenantId -Scopes "Application.ReadWrite.All", "Directory.Read.All" -NoWelcome -ErrorAction Stop
        }
        catch {
            # Fallback to device code if browser auth fails (headless/bastion)
            Write-Host "  Interactive browser failed, falling back to device code..." -ForegroundColor Yellow
            Connect-MgGraph -TenantId $graphTenantId -Scopes "Application.ReadWrite.All", "Directory.Read.All" -UseDeviceCode -NoWelcome -ErrorAction Stop
        }
    }
    Write-Host "  [OK] Microsoft Graph connected" -ForegroundColor Green
}
catch {
    Write-Host ""
    Write-Host "  ================================================================" -ForegroundColor Red
    Write-Host "  FATAL: Could not connect to Microsoft Graph." -ForegroundColor Red
    Write-Host "  ================================================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "  The script needs these Microsoft Graph permissions:" -ForegroundColor Yellow
    Write-Host "  - Application.ReadWrite.All (to create the app registration)" -ForegroundColor Yellow
    Write-Host "  - Directory.Read.All (to read directory info)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  You need one of these Entra ID roles:" -ForegroundColor Yellow
    Write-Host "  - Global Administrator" -ForegroundColor Yellow
    Write-Host "  - Application Administrator" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Error: $_" -ForegroundColor DarkGray
    exit 1
}

# ============================================================================
#  BILLING ACCOUNT DISCOVERY & AGREEMENT TYPE DETECTION
# ============================================================================
Write-Host ""
Write-Host "Step 4: Billing Account & Agreement Type" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Fetching billing accounts to determine agreement type..." -ForegroundColor Cyan

$enrolmentId = $null
$agreementType = $null
$billingAccountAccessible = $false

try {
    $accessToken = [Net.NetworkCredential]::new('', ((Get-AzAccessToken -ResourceUrl "https://management.azure.com/" -AsSecureString).Token)).Password
    $billingAccountValues = Fetch-BillingAccounts -bearerToken $accessToken
    $billingAccountAccessible = $true

    # Let the operator explicitly pick which billing account to use.
    $selectedAccount = Select-BillingAccount -billingAccountValues $billingAccountValues
    $enrolmentId = $selectedAccount.name
    $agreementType = Get-DetectedAgreementType -billingAccountValues $selectedAccount

    Write-Host ""
    Write-Host "  [OK] Billing Account ID: $enrolmentId" -ForegroundColor Green
    Write-Host "  [OK] Agreement Type (auto-detected): $agreementType" -ForegroundColor Green
}
catch {
    Write-Host ""
    Write-Host "  [WARNING] Could not fetch billing accounts: $_" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  This can happen if:" -ForegroundColor Yellow
    Write-Host "  - This is a CSP tenant (no direct billing account access)" -ForegroundColor Yellow
    Write-Host "  - You don't have billing permissions yet" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Falling back to manual agreement type selection..." -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Choose an Agreement Type:"
    Write-Host "  1) Enterprise Agreement (EA)"
    Write-Host "  2) Microsoft Customer Agreement (MCA)"
    Write-Host "  3) Cloud Solution Provider (CSP)"
    Write-Host ""

    $choice = Read-Host "Enter the number corresponding to the Agreement Type (1, 2, or 3)"

    switch ($choice) {
        1 { $agreementType = "EA" }
        2 { $agreementType = "MCA" }
        3 { $agreementType = "CSP" }
        default {
            Write-Host "  [FATAL] Invalid choice. Please enter 1, 2, or 3." -ForegroundColor Red
            exit 1
        }
    }

    Write-Host "  You selected: $agreementType" -ForegroundColor Green
}

# ============================================================================
#  PRE-FLIGHT PERMISSION CHECKS (before creating anything)
# ============================================================================
Write-Host ""
Write-Host "Step 5: Pre-flight Permission Checks" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Validating that you have the required permissions BEFORE" -ForegroundColor Cyan
Write-Host "  creating the app registration..." -ForegroundColor Cyan
Write-Host ""

$preflightPassed = $true
$preflightWarnings = @()
$preflightFailures = @()

# --- Check 1: Can we read the management group? (already done above, but confirm) ---
if ($tenantRootMG) {
    Write-Host "  [OK] Root management group accessible" -ForegroundColor Green
}
else {
    # This should never happen since we exit above, but just in case
    $preflightFailures += "Cannot access root management group. Enable elevated access."
    $preflightPassed = $false
}

# --- Check 2: Can we assign roles at the management group scope? ---
try {
    # Test by listing existing role assignments - if we can list them, we likely have User Access Administrator
    $testRoles = Get-AzRoleAssignment -Scope $tenantRootMG.Id -ErrorAction Stop | Select-Object -First 1
    Write-Host "  [OK] Can read role assignments at management group scope" -ForegroundColor Green
}
catch {
    $testError = "$_"
    if ($testError -like "*AuthorizationFailed*" -or $testError -like "*does not have authorization*") {
        Write-Host "  [FAILED] Cannot read role assignments at management group root" -ForegroundColor Red
        Write-Host "           You need User Access Administrator at the root management group." -ForegroundColor Yellow
        Write-Host "           This is automatically granted when you enable elevated access" -ForegroundColor Yellow
        Write-Host "           as Global Administrator." -ForegroundColor Yellow
        $preflightFailures += "No permission to manage role assignments at root management group."
        $preflightPassed = $false
    }
    else {
        Write-Host "  [WARNING] Could not verify role assignment permissions: $testError" -ForegroundColor Yellow
        $preflightWarnings += "Could not verify role assignment permissions (may still work)."
    }
}

# --- Check 3: Can we create app registrations? (test with Graph) ---
try {
    $mgContext = Get-MgContext -ErrorAction Stop
    if ($mgContext.Scopes -contains "Application.ReadWrite.All") {
        Write-Host "  [OK] Microsoft Graph Application.ReadWrite.All scope granted" -ForegroundColor Green
    }
    else {
        Write-Host "  [WARNING] Application.ReadWrite.All scope may not be granted" -ForegroundColor Yellow
        $preflightWarnings += "Graph scope Application.ReadWrite.All not confirmed."
    }
}
catch {
    Write-Host "  [WARNING] Could not verify Graph permissions: $_" -ForegroundColor Yellow
    $preflightWarnings += "Could not verify Graph permissions."
}

# --- Check 4: Does an app registration already exist? ---
$appDisplayName = "CrayonCloudEconomicsReader"
$existingApp = $null
try {
    $existingApp = Get-MgApplication -Filter "DisplayName eq '$appDisplayName'" -ErrorAction Stop
}
catch {
    Write-Host "  [WARNING] Could not check for existing app registrations: $_" -ForegroundColor Yellow
    $preflightWarnings += "Could not verify if app registration already exists."
}

if ($existingApp) {
    Write-Host "  [FAILED] App registration '$appDisplayName' already exists!" -ForegroundColor Red
    Write-Host "           Delete it first: Azure Portal -> Entra ID -> App registrations" -ForegroundColor Yellow
    Write-Host "           -> Search '$appDisplayName' -> Delete" -ForegroundColor Yellow
    $preflightFailures += "App registration '$appDisplayName' already exists."
    $preflightPassed = $false
}
else {
    Write-Host "  [OK] No existing '$appDisplayName' app registration" -ForegroundColor Green
}

# --- Check 5: Billing account accessible? (for EA/MCA) ---
if ($agreementType -ne "CSP") {
    if ($billingAccountAccessible -and $enrolmentId) {
        Write-Host "  [OK] Billing account accessible (ID: $enrolmentId)" -ForegroundColor Green
    }
    elseif (-not $billingAccountAccessible) {
        Write-Host "  [WARNING] Billing accounts could not be fetched earlier" -ForegroundColor Yellow
        Write-Host "           Billing role assignments may fail without a billing account ID." -ForegroundColor Yellow
        $preflightWarnings += "Billing account not accessible. Billing-specific role assignments may fail."
    }
    else {
        Write-Host "  [FAILED] Could not access billing account" -ForegroundColor Red
        Write-Host "           EA: You need Enterprise Administrator role" -ForegroundColor Yellow
        Write-Host "           MCA: You need Billing Account Owner or Billing Profile Owner" -ForegroundColor Yellow
        $preflightFailures += "Cannot access billing account."
        $preflightPassed = $false
    }
}

# --- Check 6: Can we register resource providers? ---
try {
    $capacityProvider = Get-AzResourceProvider -ProviderNamespace Microsoft.Capacity -ErrorAction Stop
    Write-Host "  [OK] Can query resource providers" -ForegroundColor Green
    
    # Also try registering Microsoft.BillingBenefits if needed
    $bbProvider = Get-AzResourceProvider -ProviderNamespace Microsoft.BillingBenefits -ErrorAction Stop
    if ($bbProvider.RegistrationState -ne 'Registered') {
        try {
            Register-AzResourceProvider -ProviderNamespace Microsoft.BillingBenefits -ErrorAction Stop
            Write-Host "  [OK] Registered Microsoft.BillingBenefits provider" -ForegroundColor Green
        }
        catch {
            Write-Host "  [WARNING] Could not register Microsoft.BillingBenefits provider" -ForegroundColor Yellow
            $preflightWarnings += "Could not register BillingBenefits provider (Savings Plan roles may fail)."
        }
    }
}
catch {
    Write-Host "  [WARNING] Could not check resource providers: $_" -ForegroundColor Yellow
    $preflightWarnings += "Could not verify resource provider registration."
}

# --- PRE-FLIGHT SUMMARY ---
Write-Host ""
Write-Host "  ============================================================" -ForegroundColor Cyan
Write-Host "  PRE-FLIGHT RESULTS" -ForegroundColor Cyan
Write-Host "  ============================================================" -ForegroundColor Cyan

if ($preflightFailures.Count -gt 0) {
    Write-Host ""
    Write-Host "  BLOCKING ISSUES ($($preflightFailures.Count)):" -ForegroundColor Red
    foreach ($failure in $preflightFailures) {
        Write-Host "    X  $failure" -ForegroundColor Red
    }
}

if ($preflightWarnings.Count -gt 0) {
    Write-Host ""
    Write-Host "  WARNINGS ($($preflightWarnings.Count)):" -ForegroundColor Yellow
    foreach ($warning in $preflightWarnings) {
        Write-Host "    !  $warning" -ForegroundColor Yellow
    }
}

if ($preflightFailures.Count -eq 0 -and $preflightWarnings.Count -eq 0) {
    Write-Host ""
    Write-Host "  All pre-flight checks passed!" -ForegroundColor Green
}

if (-not $preflightPassed) {
    Write-Host ""
    Write-Host "  ================================================================" -ForegroundColor Red
    Write-Host "  CANNOT PROCEED: Please fix the blocking issues above and re-run." -ForegroundColor Red
    Write-Host "  No app registration or roles were created." -ForegroundColor Red
    Write-Host "  ================================================================" -ForegroundColor Red
    exit 1
}

if ($preflightWarnings.Count -gt 0) {
    Write-Host ""
    $proceedChoice = Read-Host "  There are warnings. Continue anyway? (Y/N) [default: Y]"
    if ($proceedChoice -eq "N" -or $proceedChoice -eq "n") {
        Write-Host "  Exiting. No app registration or roles were created." -ForegroundColor Yellow
        exit 0
    }
}

Write-Host ""
Write-Host "  Pre-flight checks complete. Proceeding to create app registration..." -ForegroundColor Green

# ============================================================================
#  APP REGISTRATION SETUP
# ============================================================================
Write-Host ""
Write-Host "Step 6: Service Principal Setup" -ForegroundColor Cyan

$ReplyUrl = "https://localhost"

$EndDateMonths = Read-Host "Enter length of the Crayon agreement in months. Press Enter for default (36 months)"
if (-not $EndDateMonths) {
    $EndDate = (Get-Date).AddMonths(36)
    Write-Host "  Default end date: $EndDate" -ForegroundColor Green
}
else {
    $EndDate = (Get-Date).AddMonths([int]$EndDateMonths)
    Write-Host "  End date: $EndDate" -ForegroundColor Green
}

# Create Service Principal
$sp = $null
try {
    $sp = New-AzADServicePrincipal -DisplayName $appDisplayName -Description "AzureCostControl" -EndDate $EndDate -ErrorAction Stop
}
catch {
    $spCreateError = "$_"
    Write-Host ""
    Write-Host "  ================================================================" -ForegroundColor Red
    Write-Host "  FATAL: Could not create the Service Principal." -ForegroundColor Red
    Write-Host "  ================================================================" -ForegroundColor Red
    Write-Host ""
    if ($spCreateError -like "*Insufficient privileges*" -or $spCreateError -like "*Authorization_RequestDenied*" -or $spCreateError -like "*Permission*") {
        Write-Host "  You do not have permission to create app registrations." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Required role (one of):" -ForegroundColor Yellow
        Write-Host "  - Global Administrator" -ForegroundColor Yellow
        Write-Host "  - Application Administrator" -ForegroundColor Yellow
        Write-Host "  - Cloud Application Administrator" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Check: Azure Portal -> Microsoft Entra ID -> Roles and administrators" -ForegroundColor Yellow
    }
    else {
        Write-Host "  Error: $spCreateError" -ForegroundColor Red
    }
    exit 1
}

if (-not $sp) {
    Write-Host "  [FATAL] Service Principal creation returned no result. Exiting." -ForegroundColor Red
    exit 1
}

Write-Host "  [OK] Service Principal created with AppId: $($sp.AppId)" -ForegroundColor Green

# Wait for SPN to propagate with retry logic
Write-Host "  Waiting for Service Principal to propagate..." -ForegroundColor Yellow
$servicePrincipal = $null
$maxRetries = 6
$retryDelay = 10

for ($i = 1; $i -le $maxRetries; $i++) {
    Start-Sleep -Seconds $retryDelay
    try {
        $servicePrincipal = Get-MgServicePrincipal -Filter "DisplayName eq '$appDisplayName'" -ErrorAction Stop
        if ($servicePrincipal) {
            Write-Host "  [OK] Service Principal propagated (attempt $i)" -ForegroundColor Green
            break
        }
    }
    catch {
        if ($i -lt $maxRetries) {
            Write-Host "  Waiting... (attempt $i/$maxRetries)" -ForegroundColor Yellow
        }
    }
}

if (-not $servicePrincipal) {
    Write-Host ""
    Write-Host "  [FATAL] Service Principal was created but could not be found after $($maxRetries * $retryDelay) seconds." -ForegroundColor Red
    Write-Host "  This is a propagation delay issue in Azure AD. Please wait a few minutes and re-run the script." -ForegroundColor Yellow
    Write-Host "  IMPORTANT: You will need to delete the '$appDisplayName' app registration first." -ForegroundColor Yellow
    exit 1
}

Update-AzADApplication -ApplicationId $sp.AppId -ReplyUrls $ReplyUrl | Out-Null
$EnterpriseObjectID = $servicePrincipal.Id
$appId = $servicePrincipal.AppId

$tenantInfo += [pscustomobject]@{
    TenantId          = $RootTenantID
    TenantName        = $tenant.Name
    TenantDomain      = $tenant.Domains | Out-String -Width 150
    CountryCode       = $tenant.CountryCode
    AgreementType     = $agreementType
    AppId             = $sp.AppId
    SecretCredential  = $sp.PasswordCredentials.secretText
    SecretEndDateTime = $sp.PasswordCredentials.endDateTime
}

# ============================================================================
#  ROLE ASSIGNMENTS
# ============================================================================
Write-Host ""
Write-Host "Step 7: Role Assignments" -ForegroundColor Cyan
Write-Host ""

# --- Reader ---
try {
    New-AzRoleAssignment -ServicePrincipalName $appId -RoleDefinitionName "Reader" -Scope $tenantRootMG.Id -ErrorAction Stop | Out-Null
    Write-Host "  [OK] Reader" -ForegroundColor Green
    Add-RoleAssignmentResult -RoleName "Reader" -Scope "Management Group Root" -Status "Success"
}
catch {
    Write-Host "  [FAILED] Reader: $_" -ForegroundColor Red
    Add-RoleAssignmentResult -RoleName "Reader" -Scope "Management Group Root" -Status "Failed" -Message "$_"
}

# --- Cost Management Reader ---
try {
    New-AzRoleAssignment -ServicePrincipalName $appId -RoleDefinitionName "Cost Management Reader" -Scope $tenantRootMG.Id -ErrorAction Stop | Out-Null
    Write-Host "  [OK] Cost Management Reader" -ForegroundColor Green
    Add-RoleAssignmentResult -RoleName "Cost Management Reader" -Scope "Management Group Root" -Status "Success"
}
catch {
    Write-Host "  [FAILED] Cost Management Reader: $_" -ForegroundColor Red
    Add-RoleAssignmentResult -RoleName "Cost Management Reader" -Scope "Management Group Root" -Status "Failed" -Message "$_"
}

# --- Reservations Reader ---
try {
    New-AzRoleAssignment -Scope "/providers/Microsoft.Capacity" -PrincipalId $EnterpriseObjectId -RoleDefinitionName $ReservationRoleAssignment -ErrorAction Stop | Out-Null
    Write-Host "  [OK] Reservations Reader" -ForegroundColor Green
    Add-RoleAssignmentResult -RoleName "Reservations Reader" -Scope "Microsoft.Capacity" -Status "Success"
}
catch {
    Write-Host "  [FAILED] Reservations Reader: $_" -ForegroundColor Red
    Add-RoleAssignmentResult -RoleName "Reservations Reader" -Scope "Microsoft.Capacity" -Status "Failed" -Message "$_"
}

# --- Savings Plan Reader (provider-level) ---
try {
    New-AzRoleAssignment -Scope "/providers/Microsoft.BillingBenefits" -PrincipalId $EnterpriseObjectId -RoleDefinitionName "Savings Plan Reader" -ErrorAction Stop | Out-Null
    Write-Host "  [OK] Savings Plan Reader" -ForegroundColor Green
    Add-RoleAssignmentResult -RoleName "Savings Plan Reader" -Scope "Microsoft.BillingBenefits" -Status "Success"
}
catch {
    $spError = "$_"
    if ($spError -like "*PUT operation*only*EA*" -or $spError -like "*UnprocessableEntity*") {
        Write-Host "  [SKIPPED] Savings Plan Reader - This role assignment is only supported on EA billing accounts." -ForegroundColor Yellow
        Write-Host "            For MCA, savings plan data is accessible through Cost Management Reader." -ForegroundColor Yellow
        Add-RoleAssignmentResult -RoleName "Savings Plan Reader" -Scope "Microsoft.BillingBenefits" -Status "Skipped" -Message "Not supported on MCA. Cost Management Reader provides access."
    }
    else {
        Write-Host "  [FAILED] Savings Plan Reader: $spError" -ForegroundColor Red
        Add-RoleAssignmentResult -RoleName "Savings Plan Reader" -Scope "Microsoft.BillingBenefits" -Status "Failed" -Message "$spError"
    }
}

# --- Carbon Optimization Reader ---
try {
    New-AzRoleAssignment -Scope "/providers/Microsoft.Management/managementGroups/$RootTenantID" -PrincipalId $EnterpriseObjectId -RoleDefinitionId $CarbonOptimizationRoleAssignment -ErrorAction Stop | Out-Null
    Write-Host "  [OK] Carbon Optimization Reader" -ForegroundColor Green
    Add-RoleAssignmentResult -RoleName "Carbon Optimization Reader" -Scope "Management Group Root" -Status "Success"
}
catch {
    Write-Host "  [FAILED] Carbon Optimization Reader: $_" -ForegroundColor Red
    Add-RoleAssignmentResult -RoleName "Carbon Optimization Reader" -Scope "Management Group Root" -Status "Failed" -Message "$_"
}

# --- Individual Savings Plan Reader assignments ---
Write-Host ""
Write-Host "  Checking for individual Savings Plans..." -ForegroundColor Cyan

try {
    $savingsPlansObjects = Get-AzBillingBenefitsSavingsPlanOrder -ErrorAction Stop

    if ($savingsPlansObjects) {
        foreach ($savingPlan in $savingsPlansObjects) {
            $savingsPlanOrderId = $savingPlan.Id

            try {
                $scope = Get-AzRoleAssignment -Scope $savingsPlanOrderId -ObjectId $EnterpriseObjectId -RoleDefinitionName $SavingsPlanRoleAssignment -ErrorAction Stop
                $RoleAssignmentId = $scope.RoleDefinitionName

                if ($RoleAssignmentId -contains 'Reader') {
                    Write-Host "  [OK] Savings Plan already has Reader: $savingsPlanOrderId" -ForegroundColor Green
                    Add-RoleAssignmentResult -RoleName "Reader (Savings Plan)" -Scope $savingsPlanOrderId -Status "Success" -Message "Already assigned"
                }
                else {
                    New-AzRoleAssignment -Scope $savingsPlanOrderId -ApplicationId $appId -RoleDefinitionName $SavingsPlanRoleAssignment -ErrorAction Stop | Out-Null
                    Write-Host "  [OK] Reader assigned to Savings Plan: $savingsPlanOrderId" -ForegroundColor Green
                    Add-RoleAssignmentResult -RoleName "Reader (Savings Plan)" -Scope $savingsPlanOrderId -Status "Success"
                }
            }
            catch {
                Write-Host "  [FAILED] Reader for Savings Plan $savingsPlanOrderId : $_" -ForegroundColor Red
                Add-RoleAssignmentResult -RoleName "Reader (Savings Plan)" -Scope $savingsPlanOrderId -Status "Failed" -Message "$_"
            }
        }
    }
    else {
        Write-Host "  [INFO] No Savings Plans found in this tenant. This is normal if none have been purchased." -ForegroundColor Yellow
    }
}
catch {
    Write-Host "  [WARNING] Could not query Savings Plans: $_" -ForegroundColor Yellow
    Write-Host "           This may be a permissions issue or the BillingBenefits provider is not registered." -ForegroundColor Yellow
}

# --- Billing Role Assignment (EA or MCA specific) ---
Write-Host ""
Write-Host "  Assigning billing-specific roles ($agreementType)..." -ForegroundColor Cyan

if ($agreementType -eq "EA") {
    try {
        $token = [Net.NetworkCredential]::new('', ((Get-AzAccessToken -ResourceUrl "https://management.azure.com/" -AsSecureString).Token)).Password
        $url = "https://management.azure.com/providers/Microsoft.Billing/billingAccounts/$enrolmentId/billingRoleAssignments/24f8edb6-1668-4659-b5e2-40bb5f3a7d7e?api-version=2019-10-01-preview"
        $headers = @{'Authorization' = "Bearer $token" }
        $contentType = "application/json"
        $data = @{
            properties = @{
                principalid       = "$EnterpriseObjectId"
                principalTenantId = "$RootTenantID"
                RoleDefinitionID  = "/providers/Microsoft.Billing/billingAccounts/$enrolmentId/billingRoleDefinitions/24f8edb6-1668-4659-b5e2-40bb5f3a7d7e"
            }
        }
        $json = $data | ConvertTo-Json
        Invoke-WebRequest -Method PUT -Uri $url -ContentType $contentType -Headers $headers -Body $json | Out-Null
        Write-Host "  [OK] EA Enrollment Reader" -ForegroundColor Green
        Add-RoleAssignmentResult -RoleName "Enrollment Reader" -Scope "Billing Account (EA)" -Status "Success"
    }
    catch {
        $eaError = "$_"
        if ($eaError -like "*PUT operation*only*EA*" -or $eaError -like "*UnprocessableEntity*") {
            Write-Host ""
            Write-Host "  ================================================================" -ForegroundColor Red
            Write-Host "  ERROR: EA Enrollment Reader assignment failed." -ForegroundColor Red
            Write-Host "  Azure says this billing account does not support EA operations." -ForegroundColor Red
            Write-Host "" -ForegroundColor Red
            Write-Host "  This usually means the billing account has been migrated to MCA" -ForegroundColor Yellow
            Write-Host "  by Microsoft, even though it may still have an EA enrollment number." -ForegroundColor Yellow
            Write-Host "" -ForegroundColor Yellow
            Write-Host "  ACTION: Re-run this script and select the correct billing account." -ForegroundColor Yellow
            Write-Host "  If it shows 'Microsoft Customer Agreement', select MCA instead." -ForegroundColor Yellow
            Write-Host "  ================================================================" -ForegroundColor Red
        }
        else {
            Write-Host "  [FAILED] EA Enrollment Reader: $eaError" -ForegroundColor Red
        }
        Add-RoleAssignmentResult -RoleName "Enrollment Reader" -Scope "Billing Account (EA)" -Status "Failed" -Message "$eaError"
    }
}

if ($agreementType -eq "MCA") {
    try {
        $token = [Net.NetworkCredential]::new('', ((Get-AzAccessToken -ResourceUrl "https://management.azure.com/" -AsSecureString).Token)).Password
        $url = "https://management.azure.com/providers/Microsoft.Billing/billingAccounts/$enrolmentId/createBillingRoleAssignment?api-version=2019-10-01-preview"
        $headers = @{'Authorization' = "Bearer $token" }
        $contentType = "application/json"
        $data = @{
            properties = @{
                principalid      = "$EnterpriseObjectId"
                RoleDefinitionID = "/providers/Microsoft.Billing/billingAccounts/$enrolmentId/billingRoleDefinitions/50000000-aaaa-bbbb-cccc-100000000002"
            }
        }
        $json = $data | ConvertTo-Json
        Invoke-WebRequest -Method POST -Uri $url -ContentType $contentType -Headers $headers -Body $json | Out-Null
        Write-Host "  [OK] MCA Billing Account Reader" -ForegroundColor Green
        Add-RoleAssignmentResult -RoleName "Billing Account Reader" -Scope "Billing Account (MCA)" -Status "Success"
    }
    catch {
        Write-Host "  [FAILED] MCA Billing Account Reader: $_" -ForegroundColor Red
        Add-RoleAssignmentResult -RoleName "Billing Account Reader" -Scope "Billing Account (MCA)" -Status "Failed" -Message "$_"
    }
}

# ============================================================================
#  EXPORT CSV (always runs, even if some assignments failed)
# ============================================================================
Write-Host ""
Write-Host "Step 8: Exporting CSV files..." -ForegroundColor Cyan

$dateKey = Get-Date -Format "yyyyMMdd"
$baseName = "CrayonCloudEconomics-" + $tenant.Name + "-" + $dateKey

# --- File 1: Tenant info WITHOUT secrets (safe to share/store) ---
$infoFilename = $baseName + ".csv"
$infoFilepath = Join-Path -Path $DirectoryPath -ChildPath $infoFilename

$tenantInfoNoSecret = $tenantInfo | Select-Object TenantId, TenantName, TenantDomain, CountryCode, AgreementType, AppId, SecretEndDateTime

try {
    $tenantInfoNoSecret | Export-Csv -Path $infoFilepath -NoTypeInformation -ErrorAction Stop
    Write-Host "  [OK] Tenant info CSV (no secrets): $infoFilepath" -ForegroundColor Green
}
catch {
    Write-Host "  [FAILED] Could not export tenant info CSV: $_" -ForegroundColor Red
    Write-Host "  Tenant info for manual use:" -ForegroundColor Yellow
    $tenantInfoNoSecret | Format-List
}

# --- File 2: Secrets only (sensitive — handle with care) ---
$secretFilename = $baseName + "-SECRET.csv"
$secretFilepath = Join-Path -Path $DirectoryPath -ChildPath $secretFilename

$tenantSecretInfo = $tenantInfo | Select-Object TenantId, AppId, SecretCredential, SecretEndDateTime

try {
    $tenantSecretInfo | Export-Csv -Path $secretFilepath -NoTypeInformation -ErrorAction Stop
    Write-Host "  [OK] Secret CSV: $secretFilepath" -ForegroundColor Green
}
catch {
    Write-Host "  [FAILED] Could not export secret CSV: $_" -ForegroundColor Red
    Write-Host "  Secret info for manual use:" -ForegroundColor Yellow
    $tenantSecretInfo | Format-List
}

Write-Host ""
Write-Host "  NOTE: The SECRET file contains sensitive credentials." -ForegroundColor Yellow
Write-Host "  Send it separately and securely. Delete it after transfer." -ForegroundColor Yellow

# ============================================================================
#  ROLE ASSIGNMENT SUMMARY
# ============================================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  ROLE ASSIGNMENT SUMMARY" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

$successCount = ($script:roleAssignmentResults | Where-Object { $_.Status -eq "Success" }).Count
$failedCount = ($script:roleAssignmentResults | Where-Object { $_.Status -eq "Failed" }).Count
$skippedCount = ($script:roleAssignmentResults | Where-Object { $_.Status -eq "Skipped" }).Count

foreach ($result in $script:roleAssignmentResults) {
    $color = switch ($result.Status) {
        "Success" { "Green" }
        "Failed"  { "Red" }
        "Skipped" { "Yellow" }
    }
    $statusTag = switch ($result.Status) {
        "Success" { "[OK]     " }
        "Failed"  { "[FAILED] " }
        "Skipped" { "[SKIPPED]" }
    }
    Write-Host "  $statusTag $($result.Role) @ $($result.Scope)" -ForegroundColor $color
    if ($result.Message -and $result.Status -ne "Success") {
        Write-Host "           $($result.Message)" -ForegroundColor DarkGray
    }
}

Write-Host ""
Write-Host "  Total: $successCount succeeded, $failedCount failed, $skippedCount skipped" -ForegroundColor Cyan

if ($failedCount -gt 0) {
    Write-Host ""
    Write-Host "  Some role assignments failed. The CSV has still been generated." -ForegroundColor Yellow
    Write-Host "  Please review the failures above and address them before sending" -ForegroundColor Yellow
    Write-Host "  the CSV to Crayon." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "  Securely send BOTH files from $DirectoryPath to Crayon using:" -ForegroundColor Green
Write-Host "  https://deila.sensa.is" -ForegroundColor Green
Write-Host "  Then remove the $DirectoryPath folder." -ForegroundColor Green

Start-Sleep -Seconds 20

# ============================================================================
#  VALIDATION (Self-check with SPN credentials)
# ============================================================================
Write-Host ""
Write-Host "Step 9: Validation (connecting as Service Principal)..." -ForegroundColor Cyan
Write-Host ""

$subscriptions = Get-AzSubscription
$firstSubscription = $subscriptions[0]
Set-AzContext -SubscriptionId $firstSubscription.Id | Out-Null

foreach ($tenantObject in $tenantInfo) {
    $currentTenantId = $RootTenantID
    $currentAppId = $tenantObject.AppId
    $currentSecretCredential = $tenantObject.SecretCredential
    $secret = $tenantObject.SecretCredential | ConvertTo-SecureString -AsPlainText -Force
    $psCredential = New-Object System.Management.Automation.PsCredential($currentAppId, $secret)

    try {
        Connect-AzAccount -ServicePrincipal -Credential $psCredential -TenantId $currentTenantId -WarningAction SilentlyContinue | Out-Null
    }
    catch {
        Write-Host "  [FAILED] Could not authenticate as Service Principal: $_" -ForegroundColor Red
        continue
    }

    # --- Check Subscriptions ---
    Write-Host "  Checking subscription access..."
    try {
        $subs = Get-AzSubscription
        $subcount = $subs.Count

        if ($subcount -gt 1) {
            Write-Host "  [OK] $subcount subscriptions visible" -ForegroundColor Green
            $sub = "$subcount subscriptions: OK"
        }
        elseif ($subcount -eq 1) {
            Write-Host "  [CHECK] Only $subcount subscription visible. Verify with customer." -ForegroundColor Yellow
            $sub = "Subscription count: CHECK. Only $subcount subscription visible."
        }
        else {
            Write-Host "  [FAILED] No subscriptions visible" -ForegroundColor Red
            $sub = "Subscription count: FAILED. No subscriptions visible."
        }
    }
    catch {
        Write-Host "  [FAILED] Subscription check: $_" -ForegroundColor Red
        $sub = "Subscription check: FAILED. $_"
    }

    # --- Check Reader Roles ---
    Write-Host "  Checking management group roles..."
    try {
        $roles = Get-AzRoleAssignment -ServicePrincipalName $currentAppId -Scope "/providers/Microsoft.Management/managementGroups/$RootTenantID"
        
        $managementGroupRoles = $roles | Where-Object {
            $_.Scope -like '/providers/Microsoft.Management/managementGroups*' -and
            ($_.RoleDefinitionName -eq 'Reader' -or $_.RoleDefinitionName -eq 'Cost Management Reader' -or $_.RoleDefinitionName -eq "Carbon Optimization Reader")
        }

        if ($managementGroupRoles.Count -eq 3) {
            Write-Host "  [OK] All 3 management group roles assigned" -ForegroundColor Green
            $mgmt = "Management Group roles: OK (Reader, Cost Management Reader, Carbon Optimization Reader)"
        }
        else {
            $assignedNames = ($managementGroupRoles.RoleDefinitionName | Sort-Object -Unique) -join ", "
            $allExpected = @('Reader', 'Cost Management Reader', 'Carbon Optimization Reader')
            $missingRoles = $allExpected | Where-Object { $_ -notin $managementGroupRoles.RoleDefinitionName }
            $missingString = $missingRoles -join ", "
            Write-Host "  [WARNING] Missing management group roles: $missingString" -ForegroundColor Yellow
            $mgmt = "Management Group roles: PARTIAL. Found: $assignedNames. Missing: $missingString"
        }
    }
    catch {
        Write-Host "  [FAILED] Management group role check: $_" -ForegroundColor Red
        $mgmt = "Management Group roles: FAILED. $_"
    }

    # --- Check Reservations ---
    Write-Host "  Checking reservation access..."
    try {
        $reservationObjects = Get-AzReservation -ErrorAction Stop
        $reservationcount = $reservationObjects.Count

        if ($reservationcount -gt 0) {
            Write-Host "  [OK] $reservationcount reservations visible" -ForegroundColor Green
            $res = "Reservations: OK. $reservationcount visible"
        }
        else {
            Write-Host "  [INFO] 0 reservations visible (none purchased or no access)" -ForegroundColor Yellow
            $res = "Reservations: CHECK. 0 visible."
        }
    }
    catch {
        Write-Host "  [WARNING] Reservation check failed: $_" -ForegroundColor Yellow
        $res = "Reservations: FAILED. $_"
    }

    # --- Check Savings Plans ---
    Write-Host "  Checking savings plan access..."
    try {
        $savingsPlanObjects = Get-AzBillingBenefitsSavingsPlanOrder -ErrorAction Stop
        $savingsPlanCount = $savingsPlanObjects.Count

        if ($savingsPlanCount -gt 0) {
            Write-Host "  [OK] $savingsPlanCount savings plans visible" -ForegroundColor Green
            $sav = "Savings Plans: OK. $savingsPlanCount visible"
        }
        else {
            Write-Host "  [INFO] 0 savings plans visible (none purchased or no access)" -ForegroundColor Yellow
            $sav = "Savings Plans: CHECK. 0 visible."
        }
    }
    catch {
        Write-Host "  [WARNING] Savings plan check failed: $_" -ForegroundColor Yellow
        $sav = "Savings Plans: FAILED. $_"
    }

    # --- Check Billing Account ---
    if ($agreementType -ne "CSP") {
        Write-Host "  Checking billing account access..."
        try {
            $body = @{
                grant_type    = 'client_credentials'
                client_id     = $currentAppId
                client_secret = $currentSecretCredential
                scope         = "$currentTenantId/.default"
                resource      = 'https://management.azure.com'
            }
            $contentType = 'application/x-www-form-urlencoded'
            $oauth = Invoke-WebRequest -Method POST -Uri "https://login.microsoftonline.com/$currentTenantId/oauth2/token" -Body $body -ContentType $contentType
            $accessToken = ($oauth.Content | ConvertFrom-Json).access_token

            $results = Invoke-WebRequest -Uri "https://management.azure.com/providers/Microsoft.Billing/billingAccounts?api-version=2019-10-01-preview" -Method GET -Headers @{Authorization = "Bearer $accessToken" } -ContentType $contentType
            $content = ConvertFrom-Json $results.Content
            $agreement = $content.value.properties.agreementType

            if ($null -ne $agreement) {
                Write-Host "  [OK] Billing account accessible. Agreement: $agreement" -ForegroundColor Green
                $bill = "Billing Account: OK. Agreement type: $agreement"
            }
            else {
                Write-Host "  [FAILED] Cannot read billing account" -ForegroundColor Red
                $bill = "Billing Account: FAILED."
            }
        }
        catch {
            Write-Host "  [FAILED] Billing account check: $_" -ForegroundColor Red
            $bill = "Billing Account: FAILED. $_"
        }
    }

    # --- Validation Summary ---
    Write-Host ""
    Write-Host "  ============================================================" -ForegroundColor Yellow
    Write-Host "  VALIDATION SUMMARY" -ForegroundColor Yellow
    Write-Host "  ============================================================" -ForegroundColor Yellow

    $checks = @(
        @{ Num = "1"; Text = $sub },
        @{ Num = "2"; Text = $mgmt },
        @{ Num = "3"; Text = $res },
        @{ Num = "4"; Text = $sav }
    )

    if ($agreementType -ne "CSP") {
        $checks += @{ Num = "5"; Text = $bill }
    }

    foreach ($check in $checks) {
        if ($check.Text -like "*OK*") {
            Write-Host "  $($check.Num)) $($check.Text)" -ForegroundColor Green
        }
        elseif ($check.Text -like "*CHECK*" -or $check.Text -like "*PARTIAL*") {
            Write-Host "  $($check.Num)) $($check.Text)" -ForegroundColor Yellow
        }
        else {
            Write-Host "  $($check.Num)) $($check.Text)" -ForegroundColor Red
        }
    }
}

# ============================================================================
#  DISCONNECT
# ============================================================================
Write-Host ""
Write-Host "Disconnecting..."
Disconnect-AzAccount > $null
Disconnect-MgGraph > $null

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Script complete. " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
