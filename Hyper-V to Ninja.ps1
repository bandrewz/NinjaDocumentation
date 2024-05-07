### Ensure TLS 1.2 is forced and must happen before connections of any kind ###
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

### Set API Parameters for Ninja
$NinjaOneInstance = 'Your-Ninja-Instance'
$NinjaOneClientID = 'Your-Ninja-ClientID'
$NinjaOneClientSecret = 'Your-Ninja-ClientSecret'

#####################################################################
### Set Company Name and Doc Template Name
$OrgID = $env:NINJA_ORGANIZATION_ID
$NinjaDocTemplateName = "SRV - Virtualization"
$RecursiveDepth = 2
$TableHeader = "<table style=`"width: 100%; border-collapse: collapse; border: 1px solid black;`">"
$Whitespace = "<br/>"
$TableStyling = "<th>", "<th align=`"left`" style=`"background-color:#003C71; border: 1px solid black; color: white;`">"
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

$HVTemplate = [PSCustomObject]@{
    name          = $NinjaDocTemplateName
    allowMultiple = $true
    fields        = @([PSCustomObject]@{
            fieldLabel                = 'Host Name'
            fieldName                 = 'hostname'
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
            fieldLabel                = 'Virtualization Technology'
            fieldName                 = 'virtualizationTechnology'
            fieldType                 = 'TEXT'
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
            fieldLabel                = 'Virtual Machines'
            fieldName                 = 'virtualmachines'
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
            fieldLabel                = 'Network Settings'
            fieldName                 = 'networksettings'
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
            fieldLabel                = 'Replication Settings'
            fieldName                 = 'replicationsettings'
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
            fieldLabel                = 'Host Settings'
            fieldName                 = 'hostsettings'
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

$HVDocTemplate = Invoke-NinjaOneDocumentTemplate $HVTemplate
$HVDocs = Invoke-NinjaOneRequest -Method GET -Path 'organization/documents' -QueryParams "templateIds=$($HVDocTemplate.id)"
[System.Collections.Generic.List[PSCustomObject]]$NinjaDocUpdates = @()
[System.Collections.Generic.List[PSCustomObject]]$NinjaDocCreation = @()

write-host "Start documentation process." -foregroundColor green
        
$VirtualMachines = get-vm | select-object VMName, Generation, Path, Automatic*, @{n = "Minimum(gb)"; e = { $_.memoryminimum / 1gb } }, @{n = "Maximum(gb)"; e = { $_.memorymaximum / 1gb } }, @{n = "Startup(gb)"; e = { $_.memorystartup / 1gb } }, @{n = "Currently Assigned(gb)"; e = { $_.memoryassigned / 1gb } }, ProcessorCount | ConvertTo-Html -Fragment | Out-String
$VirtualMachines = $TableHeader + ($VirtualMachines -replace $TableStyling) + $Whitespace
$NetworkSwitches = Get-VMSwitch | select-object name, switchtype, NetAdapterInterfaceDescription, AllowManagementOS | convertto-html -Fragment | Out-String
$VMNetworkSettings = Get-VMNetworkAdapter * | Select-Object Name, IsManagementOs, VMName, SwitchName, MacAddress, @{Name = 'IP'; Expression = { $_.IPaddresses -join "," } } | ConvertTo-Html -Fragment | Out-String
$NetworkSettings = $TableHeader + ($NetworkSwitches -replace $TableStyling) + ($VMNetworkSettings -replace $TableStyling) + $Whitespace
$ReplicationSettings = get-vmreplication | Select-Object VMName, State, Mode, FrequencySec, PrimaryServer, ReplicaServer, ReplicaPort, AuthType | convertto-html -Fragment | Out-String
$ReplicationSettings = $TableHeader + ($ReplicationSettings -replace $TableStyling) + $Whitespace
$HostSettings = get-vmhost | Select-Object  Computername, LogicalProcessorCount, iovSupport, EnableEnhancedSessionMode,MacAddressMinimum, *max*, NumaspanningEnabled, VirtualHardDiskPath, VirtualMachinePath, UseAnyNetworkForMigration, VirtualMachineMigrationEnabled | convertto-html -Fragment -as List | Out-String
        
$AssetFields = @{
    'hostname'            = $env:COMPUTERNAME
    'virtualmachines'     = @{'html' = $VirtualMachines }
    'virtualizationTechnology'     = 'Hyper-V'
    'networksettings'     = @{'html' = $NetworkSettings }
    'replicationsettings' = @{'html' = $ReplicationSettings }
    'hostsettings'        = @{'html' = $HostSettings }
}
        
$DocTitle = "$env:ComputerName - Hyper-V Configuration"

try {
    $MatchedDoc = $HVDocs | Where-Object { $_.documentName -eq $DocTitle }
    $MatchCount = ($MatchedDoc | measure-object).count

    # Match to a CloudMonitor
    if ($MatchCount -eq 0) {
        Write-Host "The Hyper-V host was not matched to a Document Name in NinjaOne. Please add a Hyper-V Virtualization Apps and Services document with the name matching $DocTitle"    
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
    documentTemplateId = $HVDocTemplate.id
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
    }
} Catch {
    Write-Host "Creation Error on Doc ID: $HVDocTemplate.id for Org ID: $OrgID, but may have been successful, issue that could have been the cause: $_"
}

try {
    # Update Document
    if (($NinjaDocUpdates | Measure-Object).count -ge 1) {
        Write-Host "Updating Documents"
        $UpdatedDocs = Invoke-NinjaOneRequest -Path "organization/documents" -Method PATCH -InputObject $NinjaDocUpdates -AsArray
        Write-Host "Updated $(($UpdatedDocs | Measure-Object).count) Documents"
    }
} Catch {
    Write-Host "Update Doc Error on Doc ID: $HVDocTemplate.id for Org ID: $OrgID, but may have been successful, issue that could have been the cause: $_"
}
