### Ensure TLS 1.2 is forced and must happen before connections of any kind ###
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

### Set API Parameters for Ninja
$NinjaOneInstance = 'Your-Ninja-Instance'
$NinjaOneClientID = 'Your-Ninja-ClientID'
$NinjaOneClientSecret = 'Your-Ninja-ClientSecret'

### Set Company Name and Doc Template Name
$OrgID = $env:NINJA_ORGANIZATION_ID
$NinjaDocTemplateName = "Srv - DHCP Configuration"
#####################################################################

try {
    $moduleName = "NinjaOneDocs"
    if (-not (Get-Module -ListAvailable -Name $moduleName)) {
        Install-Module -Name $moduleName -Force -AllowClobber
    } else {
        $latestVersion = (Find-Module -Name $moduleName).Version
        $installedVersion = (Get-Module -ListAvailable -Name $moduleName).Version | Sort-Object -Descending | Select-Object -First 1

        if ($installedVersion -ne $latestVersion) {
            Update-Module -Name $moduleName -Force
        }
    }
Import-Module $moduleName
} Catch {
    Write-Host "Error Importing module $moduleName"
}

  
#Set Ninja API Login
Connect-NinjaOne -NinjaOneInstance $NinjaOneInstance -NinjaOneClientID $NinjaOneClientID -NinjaOneClientSecret $NinjaOneClientSecret

$DHCPTemplate = [PSCustomObject]@{
    name          = $NinjaDocTemplateName
    allowMultiple = $true
    fields        = @([PSCustomObject]@{
            fieldLabel                = 'DHCP Server Name'
            fieldName                 = 'dhcpservername'
            fieldType                 = 'TEXT'
            fieldTechnicianPermission = 'READ_ONLY'
            fieldScriptPermission     = 'READ_WRITE'
            fieldApiPermission        = 'READ_WRITE'
            fieldContent              = @{
                required         = $False
                advancedSettings = @{
                    expandLargeValueOnRender = $True
                }
            }
        },
        [PSCustomObject]@{
            fieldLabel                = 'DHCP Server Settings'
            fieldName                 = 'dhcpserversettings'
            fieldType                 = 'WYSIWYG'
            fieldTechnicianPermission = 'READ_ONLY'
            fieldScriptPermission     = 'READ_WRITE'
            fieldApiPermission        = 'READ_WRITE'
            fieldContent              = @{
                required         = $False
                advancedSettings = @{
                    expandLargeValueOnRender = $False
                }
            }
        },
        [PSCustomObject]@{
            fieldLabel                = 'DHCP Server Database Info'
            fieldName                 = 'dhcpserverdatabaseinfo'
            fieldType                 = 'WYSIWYG'
            fieldTechnicianPermission = 'READ_ONLY'
            fieldScriptPermission     = 'READ_WRITE'
            fieldApiPermission        = 'READ_WRITE'
            fieldContent              = @{
                required         = $False
                advancedSettings = @{
                    expandLargeValueOnRender = $False
                }
            }               
        },
        [PSCustomObject]@{
            fieldLabel                = 'DHCP Domain Authorisation'
            fieldName                 = 'dhcpdomainauthorisation'
            fieldType                 = 'WYSIWYG'
            fieldTechnicianPermission = 'READ_ONLY'
            fieldScriptPermission     = 'READ_WRITE'
            fieldApiPermission        = 'READ_WRITE'
            fieldContent              = @{
                required         = $False
                advancedSettings = @{
                    expandLargeValueOnRender = $False
                }
            }               
        },
        [PSCustomObject]@{
            fieldLabel                = 'DHCP Scopes'
            fieldName                 = 'dhcpscopes'
            fieldType                 = 'WYSIWYG'
            fieldTechnicianPermission = 'READ_ONLY'
            fieldScriptPermission     = 'READ_WRITE'
            fieldApiPermission        = 'READ_WRITE'
            fieldContent              = @{
                required         = $False
                advancedSettings = @{
                    expandLargeValueOnRender = $False
                }
            }               
        },
        [PSCustomObject]@{
            fieldLabel                = 'DHCP Scope Info'
            fieldName                 = 'dhcpscopeinfo'
            fieldType                 = 'WYSIWYG'
            fieldTechnicianPermission = 'READ_ONLY'
            fieldScriptPermission     = 'READ_WRITE'
            fieldApiPermission        = 'READ_WRITE'
            fieldContent              = @{
                required         = $False
                advancedSettings = @{
                    expandLargeValueOnRender = $False
                }
            }               
        },
        [PSCustomObject]@{
            fieldLabel                = 'DHCP Statistics'
            fieldName                 = 'dhcpstatistics'
            fieldType                 = 'WYSIWYG'
            fieldTechnicianPermission = 'READ_ONLY'
            fieldScriptPermission     = 'READ_WRITE'
            fieldApiPermission        = 'READ_WRITE'
            fieldContent              = @{
                required         = $False
                advancedSettings = @{
                    expandLargeValueOnRender = $False
                }
            }               
        }          
    )
}

$DHCPDocTemplate = Invoke-NinjaOneDocumentTemplate $DHCPTemplate
$DHCPDocs = Invoke-NinjaOneRequest -Method GET -Path 'organization/documents' -QueryParams "templateIds=$($DHCPDocTemplate.id)"
[System.Collections.Generic.List[PSCustomObject]]$NinjaDocUpdates = @()
[System.Collections.Generic.List[PSCustomObject]]$NinjaDocCreation = @()
	
$DCHPServerSettings = Get-DhcpServerSetting | select-object ActivatePolicies, ConflictDetectionAttempts, DynamicBootp, IsAuthorized, IsDomainJoined, NapEnabled, NpsUnreachableAction, RestoreStatus | ConvertTo-Html -Fragment| Out-String
$databaseinfo = Get-DhcpServerDatabase | Select-Object BackupInterval, BackupPath, CleanupInterval, FileName, LoggingEnabled, RestoreFromBackup | ConvertTo-Html -Fragment | Out-String
$DHCPDCAuth = Get-DhcpServerInDC | Select-Object IPAddress, DnsName  | ConvertTo-Html -Fragment | Out-String
$Scopes = Get-DhcpServerv4Scope
$ScopesAvailable = $Scopes | Select-Object ScopeId, SubnetMask, StartRange, EndRange, ActivatePolicies, Delay, Description, LeaseDuration, MaxBootpClients, Name, NapEnable, NapProfile, State, SuperscopeName, Type | ConvertTo-Html -Fragment  | Out-String
$ScopeInfo = foreach ($Scope in $Scopes) {
  $Scope | Get-DhcpServerv4Lease | Select-Object ScopeId, IPAddress, AddressState, ClientId, ClientType, Description, DnsRegistration, DnsRR, HostName, LeaseExpiryTime | ConvertTo-Html -Fragment -PreContent "<h2>Scope Information: $($Scope.name) - $($scope.ScopeID) </h2>" | Out-String}
$DHCPServerStats = Get-DhcpServerv4Statistics | Select-Object InUse, Available, Acks, AddressesAvailable, AddressesInUse, Declines, DelayedOffers, Discovers, Naks, Offers, PendingOffers, PercentageAvailable, PercentageInUse, PercentagePendingOffers, Releases, Requests, ScopesWithDelayConfigured, ServerStartTime, TotalAddresses, TotalScope | ConvertTo-Html -Fragment -As List | Out-String

# Populate Asset Fields
$AssetFields = @{
	'dhcpservername'                 = $env:computername
	'dhcpserversettings'             = @{'html' = $DCHPServerSettings }
	'dhcpserverdatabaseinfo' = @{'html' = $databaseinfo }
	'dhcpdomainauthorisation'        = @{'html' = $DHCPDCAuth }
	'dhcpscopes'                      = @{'html' = $ScopesAvailable }
	'dhcpscopeinfo'           = @{'html' = $ScopeInfo }
	'dhcpstatistics'                  = @{'html' = $DHCPServerStats }
}

$DocTitle = "$env:computername - DHCP Configuration"

try {
    $MatchedDoc = $DHCPDocs | Where-Object { $_.documentName -eq $DocTitle }
    $MatchCount = ($MatchedDoc | measure-object).count

    # Match to a CloudMonitor
    if ($MatchCount -eq 0) {
	    Write-Host "The DHCP Server was not matched to a Document Name in NinjaOne. Please add a DHCP Apps and Services document with the name matching $DocTitle"    
    } elseif ($MatchCount -gt 1) {
        Throw "Multiple NinjaOne Documents ($($MatchedDoc.documentId -join '')) matched to $($DocTitle)"
        continue
    } else {
        $NinjaMatch = $MatchedDoc.organizationId
     }
} Catch {
    Write-Host "Unable to complete search for matching documentation"
}

if ($MatchedDoc) {
    $UpdateObject = [PSCustomObject]@{
    documentId   = $MatchedDoc.documentId
    documentName = $DocTitle
    fields       = $AssetFields
	}
	$NinjaDocUpdates.Add($UpdateObject)

} else {
    $CreateObject = [PSCustomObject]@{
    documentName = $DocTitle
    documentTemplateId = $DHCPDocTemplate.id
    organizationId = [int]$OrgID
    fields = $AssetFields
    }
    $NinjaDocCreation.Add($CreateObject)
}

## Perform the bulk updates of data
try {
    # Create New Document
    if (($NinjaDocCreation | Measure-Object).count -ge 1) {
        Write-Host "Creating Documents"
        $CreatedDocs = Invoke-NinjaOneRequest -Path "organization/documents" -Method POST -InputObject $NinjaDocCreation -AsArray
        Write-Host "Created $(($CreatedDocs | Measure-Object).count) Documents"
        Write-Host "The Asset Fields to create was: $ScopeInfo"
    }
} Catch {
    Write-Host "Creation Error on Doc ID: $DHCPDocTemplate.id for Org ID: $OrgID, but may have been successful, issue that could have been the cause: $_"
    Write-Host "The Asset Fields to create was: $ScopeInfo"
}

try {
    # Update Document
    if (($NinjaDocUpdates | Measure-Object).count -ge 1) {
        Write-Host "Updating Documents"
        $UpdatedDocs = Invoke-NinjaOneRequest -Path "organization/documents" -Method PATCH -InputObject $NinjaDocUpdates -AsArray
        Write-Host "Updated $(($UpdatedDocs | Measure-Object).count) Documents"
        Write-Host "The Asset Fields to create was: $ScopeInfo"
    }
} Catch {
    Write-Host "Update Doc Error on Doc ID: $DHCPDocTemplate.id for Org ID: $OrgID, but may have been successful, issue that could have been the cause: $_"
    Write-Host "The Asset Fields to create was: $ScopeInfo"
}

