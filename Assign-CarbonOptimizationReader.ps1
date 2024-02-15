<#PSScriptInfo

.VERSION 1.0.0

.AUTHOR Suman Bhushal, Crayon. http://www.crayon.com

.COMPANYNAME Crayon

.RELEASENOTES
Change Log:
1.0.0 - Initial Version
#>
# Requires -Modules Az

## Install msonline If Needed
function Install-Module-If-Needed {
    param([string]$ModuleName)
  
    if (Get-Module -ListAvailable -Name $ModuleName) {
        Write-Host "Module '$($ModuleName)' already exists, continue..." -ForegroundColor Green
    }
    else {
        Write-Host "Module '$($ModuleName)' does not exist, installing..." -ForegroundColor Yellow
        Install-Module $ModuleName -Force -AllowClobber -Scope CurrentUser -ErrorAction Stop
        Write-Host "Module '$($ModuleName)' installed." -ForegroundColor Green
    }
}

#CHECK PS MODULE PREREQUISITES
Write-Host "Checking PowerShell module prerequisites..."

## Install Modules If Needed
Install-Module-If-Needed Az.Accounts
Install-Module-If-Needed Az.Resources


# Import the modules in to the session
Import-Module -Name Az.Accounts
Import-Module -Name Az.Resources

####################################
##  Variables
####################################
$roleDefinitionName = "Carbon Optimization Reader"

####################################
##  Login to Azure
####################################
Login-AzAccount  -WarningAction silentlyContinue
Write-Host "Authentication Success"  -ForegroundColor Green

# Ask for User Input for the Application (App) Registration's Enterprise Object ID
$enterpriseObjectId = Read-Host "Please enter the Object ID of your Enterprise Application: "

# Fetch all subscriptions the user has access to
$subscriptions = Get-AzSubscription
$subcount = $subscriptions.Count
if ($subcount -gt 1) {
    Write-Host "There are $subcount subscriptions readable" -ForegroundColor Green
}
elseif ($subcount -eq 1) {
    Write-Host "There is only $subcount subscription readable." -ForegroundColor Yellow
}
else {
    Write-Host "There are no subscriptions readable. Check if this is correct." -ForegroundColor Red
}

if ($subcount -ge 1) {
    foreach ($subscription in $subscriptions) {
        # Set the context to the current subscription in the loop
        $subscriptionId = $subscription.Id
        Select-AzSubscription -SubscriptionId $subscriptionId | Out-Null
    
        # Check if the role already has been assigned
        $scope = Get-AzRoleAssignment -Scope "/subscriptions/$subscriptionId" -ObjectId $EnterpriseObjectId -RoleDefinitionName $roleDefinitionName
        $RoleAssignmentId = $scope.RoleDefinitionName

        if ($RoleAssignmentId -contains $roleDefinitionName) {
            Write-Host "Subscription '$subscriptionId' already assigned Role" $RoleAssignmentId.Split("/")[-1]"" -ForegroundColor Green 
        }
        else {
            Write-Host "Assigning "$roleDefinitionName" to "$subscriptionId -ForegroundColor DarkGray 
            New-AzRoleAssignment -Scope "/subscriptions/$subscriptionId" -ObjectId $enterpriseObjectId -RoleDefinitionName $roleDefinitionName 
            Write-Host "Assigned the '$roleDefinitionName' role to the Enterprise Application (Object ID: $enterpriseObjectId) for subscription $subscriptionId." -ForegroundColor Green 
        }
    }
}