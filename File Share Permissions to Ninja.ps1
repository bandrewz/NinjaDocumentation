### Ensure TLS 1.2 is forced and must happen before connections of any kind ###
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

### Set API Parameters for Ninja
$NinjaOneInstance = 'Your-Ninja-Instance'
$NinjaOneClientID = 'Your-Ninja-ClientID'
$NinjaOneClientSecret = 'Your-Ninja-ClientSecret'

### Set Company Name and Doc Template Name
$OrgID = $env:NINJA_ORGANIZATION_ID
$NinjaDocTemplateName = "Srv - File Sharing"
$RecursiveDepth = 2

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

$FSPTemplate = [PSCustomObject]@{
    name          = $NinjaDocTemplateName
    allowMultiple = $true
    fields        = @([PSCustomObject]@{
            fieldLabel                = 'File Share Name'
            fieldName                 = 'fileshareName'
            fieldType                 = 'TEXT'
            fieldTechnicianPermission = 'EDITABLE'
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
            fieldLabel                = 'Server'
            fieldName                 = 'server'
            fieldType                 = 'WYSIWYG'
            fieldTechnicianPermission = 'EDITABLE'
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
            fieldLabel                = 'Share Path'
            fieldName                 = 'sharepath'
            fieldType                 = 'WYSIWYG'
            fieldTechnicianPermission = 'EDITABLE'
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
            fieldLabel                = 'Full Control Permissions'
            fieldName                 = 'fullcontrolPermissions'
            fieldType                 = 'WYSIWYG'
            fieldTechnicianPermission = 'EDITABLE'
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
            fieldLabel                = 'Modify Permissions'
            fieldName                 = 'modifyPermissions'
            fieldType                 = 'WYSIWYG'
            fieldTechnicianPermission = 'EDITABLE'
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
            fieldLabel                = 'Ready Permissions'
            fieldName                 = 'readPermissions'
            fieldType                 = 'WYSIWYG'
            fieldTechnicianPermission = 'EDITABLE'
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
            fieldLabel                = 'Deny Permissions'
            fieldName                 = 'denypermissions'
            fieldType                 = 'WYSIWYG'
            fieldTechnicianPermission = 'EDITABLE'
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
	
#Collect Data
        #Set Ninja API Login
        Connect-NinjaOne -NinjaOneInstance $NinjaOneInstance -NinjaOneClientID $NinjaOneClientID -NinjaOneClientSecret $NinjaOneClientSecret
        $FSPDocTemplate = Invoke-NinjaOneDocumentTemplate $FSPTemplate
        $FSPDocs = Invoke-NinjaOneRequest -Method GET -Path 'organization/documents' -QueryParams "templateIds=$($FSPDocTemplate.id)"
        [System.Collections.Generic.List[PSCustomObject]]$NinjaDocUpdates = @()
        [System.Collections.Generic.List[PSCustomObject]]$NinjaDocCreation = @()
		$AllsmbShares = Get-SmbShare | Where-Object {( (@('Remote Admin', 'Default share', 'Remote IPC') -notcontains $_.Description) ) -and $_.ShareType -eq 'FileSystemDirectory'}
		foreach($SMBShare in $AllSMBShares){
		$Permissions = get-item $SMBShare.path | get-ntfsaccess
		$Permissions += get-childitem -Depth $RecursiveDepth -Recurse $SMBShare.path | get-ntfsaccess
		$FullAccess = $permissions | where-object {$_.'AccessRights' -eq "FullControl" -AND $_.IsInherited -eq $false -AND $_.'AccessControlType' -ne "Deny"}| Select-Object FullName,Account,AccessRights,AccessControlType  | ConvertTo-Html -Fragment | Out-String
		$Modify = $permissions | where-object {$_.'AccessRights' -Match "Modify" -AND $_.IsInherited -eq $false -and $_.'AccessControlType' -ne "Deny"}| Select-Object FullName,Account,AccessRights,AccessControlType  | ConvertTo-Html -Fragment | Out-String
		$ReadOnly = $permissions | where-object {$_.'AccessRights' -Match "Read" -AND $_.IsInherited -eq $false -and $_.'AccessControlType' -ne "Deny"}| Select-Object FullName,Account,AccessRights,AccessControlType  | ConvertTo-Html -Fragment | Out-String
		$Deny =   $permissions | where-object {$_.'AccessControlType' -eq "Deny" -AND $_.IsInherited -eq $false} | Select-Object FullName,Account,AccessRights,AccessControlType | ConvertTo-Html -Fragment | Out-String
		if($FullAccess.Length /1kb -gt 64) { $FullAccess = "The table is too long to display. Please see included CSV file."}
		if($ReadOnly.Length /1kb -gt 64) { $ReadOnly = "The table is too long to display. Please see included CSV file."}
		if($Modify.Length /1kb -gt 64) { $Modify = "The table is too long to display. Please see included CSV file."}
		if($Deny.Length /1kb -gt 64) { $Deny = "The table is too long to display. Please see included CSV file."}
		$PermCSV = ($Permissions | ConvertTo-Csv -NoTypeInformation -Delimiter ",") -join [Environment]::NewLine
		$Bytes = [System.Text.Encoding]::UTF8.GetBytes($PermCSV)
		$Base64CSV =[Convert]::ToBase64String($Bytes)    
		$AssetLink = "<a href=$($ParentAsset.url)>$($ParentAsset.name)</a>"
		
		$AssetFields = @{
						"fileshareName" = $($smbshare.name)
						"sharepath" = @{'html' = $($smbshare.path)}
						"fullcontrolPermissions" = @{'html' = $FullAccess}
						"readPermissions" = @{'html' = $ReadOnly}
						"modifyPermissions" = @{'html' = $Modify}
						"denypermissions" = @{'html' = $Deny}
						"server" = @{'html' = $AssetLink}
						
					}

$DocTitle = "$env:ComputerName - $($smbshare.name)"
		
try {
    $MatchedDoc = $FSPDocs | Where-Object { $_.documentName -eq $DocTitle }
    $MatchCount = ($MatchedDoc | measure-object).count

    # Match to a CloudMonitor
    if ($MatchCount -eq 0) {
	    Write-Host "The share was not matched to a Document Name in NinjaOne. Please add a File Share Apps and Services document with the name matching $DocTitle"    
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
    documentTemplateId = $FSPDocTemplate.id
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
    Write-Host "Creation Error on Doc ID: $FSPDocTemplate.id for Org ID: $OrgID, but may have been successful, issue that could have been the cause: $_"
}

try {
    # Update Document
    if (($NinjaDocUpdates | Measure-Object).count -ge 1) {
        Write-Host "Updating Documents"
        $UpdatedDocs = Invoke-NinjaOneRequest -Path "organization/documents" -Method PATCH -InputObject $NinjaDocUpdates -AsArray
        Write-Host "Updated $(($UpdatedDocs | Measure-Object).count) Documents"
    }
} Catch {
    Write-Host "Update Doc Error on Doc ID: $FSPDocTemplate.id for Org ID: $OrgID, but may have been successful, issue that could have been the cause: $_"
}
}
