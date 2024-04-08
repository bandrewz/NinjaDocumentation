### Ensure TLS 1.2 is forced and must happen before connections of any kind ###
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
#####################################################################
### Set API Parameters for Ninja
$NinjaOneInstance = 'Your-Ninja-Instance'
$NinjaOneClientID = 'Your-Ninja-ClientID'
$NinjaOneClientSecret = 'Your-Ninja-ClientSecret'

### Set Company Org ID and Doc Template Name
$OrgID = $env:NINJA_ORGANIZATION_ID
$NinjaDocTemplateName = "Sec - AD Groups"
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
    
$ADGrpsTemplate = [PSCustomObject]@{
    name          = $NinjaDocTemplateName
    allowMultiple = $true
    fields        = @([PSCustomObject]@{
            fieldLabel                = 'Group Name'
            fieldName                 = 'groupName'
            fieldType                 = 'TEXT'
            fieldTechnicianPermission = 'READ_ONLY'
            fieldScriptPermission     = 'NONE'
            fieldApiPermission        = 'READ_WRITE'
        },
        [PSCustomObject]@{
            fieldLabel                = 'Last Updated'
            fieldName                 = 'lastUpdated'
            fieldType                 = 'TEXT'
            fieldTechnicianPermission = 'READ_ONLY'
            fieldScriptPermission     = 'NONE'
            fieldApiPermission        = 'READ_WRITE'
        },
        [PSCustomObject]@{
            fieldLabel                = 'Members'
            fieldName                 = 'members'
            fieldType                 = 'WYSIWYG'
            fieldTechnicianPermission = 'READ_ONLY'
            fieldScriptPermission     = 'NONE'
            fieldApiPermission        = 'READ_WRITE'
            fieldContent              = @{
                required         = $False
                advancedSettings = @{
                    expandLargeValueOnRender = $False
                }
            }
        },
        [PSCustomObject]@{
            fieldLabel                = 'GUID'
            fieldName                 = 'guid'
            fieldType                 = 'TEXT'
            fieldTechnicianPermission = 'READ_ONLY'
            fieldScriptPermission     = 'NONE'
            fieldApiPermission        = 'READ_WRITE'
        }       
    )
}

$currentDate = Get-Date -Format "dddd dd/MM/yyyy HH:mm K"
    
#Collect Data
$AllGroups = get-adgroup -filter *
foreach($Group in $AllGroups){
    $ADGrpsDocTemplate = Invoke-NinjaOneDocumentTemplate $ADGrpsTemplate
    $ADGrpsDocs = Invoke-NinjaOneRequest -Method GET -Path 'organization/documents' -QueryParams "templateIds=$($ADGrpsDocTemplate.id)"
    [System.Collections.ArrayList]$Contacts = @()
    [System.Collections.Generic.List[PSCustomObject]]$NinjaDocUpdates = @()
    [System.Collections.Generic.List[PSCustomObject]]$NinjaDocCreation = @()
    Write-Host "Group: $($group.name)"
    $Members = get-adgroupmember $Group
    $MembersTable = $members | Select-Object Name, distinguishedName | ConvertTo-Html -Fragment | Out-String

    # Set the group's asset fields
    $AssetFields = @{
        'groupName' = $($group.name)
        'lastUpdated' = $currentDate
        'members' = @{'html' = $MembersTable}
        'guid' = $($group.objectguid.guid)
    }

    try {
        $MatchedDoc = $ADGrpsDocs | Where-Object { $_.documentName -eq $($group.name) }
        $MatchCount = ($MatchedDoc | measure-object).count

        # Match to a Doc
        if ($MatchCount -eq 0) {
            Write-Host "The group was not matched to a Document Name in NinjaOne. Please add a group document with the name matching $($group.name)"    
        } elseif ($MatchCount -gt 1) {
            Throw "Multiple NinjaOne Documents ($($MatchedDoc.documentId -join '')) matched to $($group.name)"
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
        documentName = $($group.name)
        fields       = $AssetFields
        }
        $NinjaDocUpdates.Add($UpdateObject)

    } else {
        $CreateObject = [PSCustomObject]@{
        documentName = $($group.name)
        documentTemplateId = $ADGrpsDocTemplate.id
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
        Write-Host "Creation Error on Doc ID: $ADGrpsDocTemplate.id for Org ID: $OrgID, but may have been successful, issue that could have been the cause: $_"
    }

    try {
        # Update Document
        if (($NinjaDocUpdates | Measure-Object).count -ge 1) {
            Write-Host "Updating Documents"
            $UpdatedDocs = Invoke-NinjaOneRequest -Path "organization/documents" -Method PATCH -InputObject $NinjaDocUpdates -AsArray
            Write-Host "Updated $(($UpdatedDocs | Measure-Object).count) Documents"
        }
    } Catch {
        Write-Host "Update Doc Error on Doc ID: $ADGrpsDocTemplate.id for Org ID: $OrgID, but may have been successful, issue that could have been the cause: $_"
    }
}
