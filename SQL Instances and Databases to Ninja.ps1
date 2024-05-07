### Ensure TLS 1.2 is forced and must happen before connections of any kind ###
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

### Set API Parameters for Ninja
$NinjaOneInstance = 'Your-Ninja-Instance'
$NinjaOneClientID = 'Your-Ninja-ClientID'
$NinjaOneClientSecret = 'Your-Ninja-ClientSecret'

### Set Company Name and Doc Template Name
$OrgID = $env:NINJA_ORGANIZATION_ID
$NinjaDocTemplateName = "Srv - SQL Instances and DBs"
#####################################################################

if (Get-Module -ListAvailable -Name SQLServer) {
        Import-Module SQLServer
    } else {
        Install-Module SQLServer -Force -AllowClobber
        Import-Module SQLServer
    }

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

$SQLTemplate = [PSCustomObject]@{
    name          = $NinjaDocTemplateName
    allowMultiple = $true
    fields        = @([PSCustomObject]@{
            fieldLabel                = 'Instance Name'
            fieldName                 = 'instancename'
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
            fieldLabel                = 'Instance Settings'
            fieldName                 = 'instancesettings'
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
            fieldLabel                = 'Databases'
            fieldName                 = 'databases'
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
            fieldLabel                = 'Instance Host'
            fieldName                 = 'instancehost'
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

$Instances = Get-ChildItem "SQLSERVER:\SQL\$($ENV:COMPUTERNAME)"

    foreach ($Instance in $Instances) {
      $SQLDocTemplate = Invoke-NinjaOneDocumentTemplate $SQLTemplate
    $SQLDocs = Invoke-NinjaOneRequest -Method GET -Path 'organization/documents' -QueryParams "templateIds=$($SQLDocTemplate.id)"
    [System.Collections.Generic.List[PSCustomObject]]$NinjaDocUpdates = @()
    [System.Collections.Generic.List[PSCustomObject]]$NinjaDocCreation = @()
        $databaseList = get-childitem "SQLSERVER:\SQL\$($ENV:COMPUTERNAME)\$($Instance.Displayname)\Databases"
        $Databases = @()
        foreach ($Database in $databaselist) {
            $Databaseobj = New-Object -TypeName PSObject
            $Databaseobj | Add-Member -MemberType NoteProperty -Name "Name" -value $Database.Name
            $Databaseobj | Add-Member -MemberType NoteProperty -Name "Status" -value $Database.status
            $Databaseobj | Add-Member -MemberType NoteProperty -Name  "RecoveryModel" -value $Database.RecoveryModel
            $Databaseobj | Add-Member -MemberType NoteProperty -Name  "LastBackupDate" -value $Database.LastBackupDate
            $Databaseobj | Add-Member -MemberType NoteProperty -Name  "DatabaseFiles" -value $database.filegroups.files.filename
            $Databaseobj | Add-Member -MemberType NoteProperty -Name  "Logfiles"      -value $database.LogFiles.filename
            $Databaseobj | Add-Member -MemberType NoteProperty -Name  "MaxSize" -value $database.filegroups.files.MaxSize
            $Databases += $Databaseobj
        }
        $InstanceInfo = $Instance | Select-Object DisplayName, Collation, AuditLevel, BackupDirectory, DefaultFile, DefaultLog, Edition, ErrorLogPath | convertto-html -Fragment | Out-String
        $Instanceinfo = $instanceinfo -replace "&lt;th>", "&lt;th style=`"background-color:#4CAF50`">"
        $InstanceInfo = $InstanceInfo -replace "&lt;table>", "&lt;table class=`"table table-bordered table-hover`" style=`"width:80%`">"
        $DatabasesHTML = $Databases | ConvertTo-Html -fragment | Out-String
        $DatabasesHTML = $DatabasesHTML -replace "&lt;th>", "&lt;th style=`"background-color:#4CAF50`">"
        $DatabasesHTML = $DatabasesHTML -replace "&lt;table>", "&lt;table class=`"table table-bordered table-hover`" style=`"width:80%`">"

        $AssetFields = @{
                    "instancename"     = "$($ENV:COMPUTERNAME)\$($Instance.displayname)"
                    "instancesettings" = @{'html' = $InstanceInfo }
                    "databases"         = @{'html' = $DatabasesHTML }
                    "instancehost"    = @{'html' = $ENV:COMPUTERNAME }
                    }

        $DocTitle = "$($ENV:COMPUTERNAME)\$($Instance.displayname)"
        
try {
    $MatchedDoc = $SQLDocs | Where-Object { $_.documentName -eq $DocTitle }
    $MatchCount = ($MatchedDoc | measure-object).count

    # Match to a CloudMonitor
    if ($MatchCount -eq 0) {
        Write-Host "The SQL Instance was not matched to a Document Name in NinjaOne. Please add a SQL Apps and Services document with the name matching $DocTitle"    
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
    documentTemplateId = $SQLDocTemplate.id
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
    Write-Host "Creation Error on Doc ID: $SQLDocTemplate.id for Org ID: $OrgID, but may have been successful, issue that could have been the cause: $_"
}

try {
    # Update Document
    if (($NinjaDocUpdates | Measure-Object).count -ge 1) {
        Write-Host "Updating Documents"
        $UpdatedDocs = Invoke-NinjaOneRequest -Path "organization/documents" -Method PATCH -InputObject $NinjaDocUpdates -AsArray
        Write-Host "Updated $(($UpdatedDocs | Measure-Object).count) Documents"
    }
} Catch {
    Write-Host "Update Doc Error on Doc ID: $SQLDocTemplate.id for Org ID: $OrgID, but may have been successful, issue that could have been the cause: $_"
}

}
