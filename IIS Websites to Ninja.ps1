### Ensure TLS 1.2 is forced and must happen before connections of any kind ###
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

### Set API Parameters for Ninja
$NinjaOneInstance = 'Your-Ninja-Instance'
$NinjaOneClientID = 'Your-Ninja-ClientID'
$NinjaOneClientSecret = 'Your-Ninja-ClientSecret'

### Set Company Name and Doc Template Name
$OrgID = $env:NINJA_ORGANIZATION_ID
$NinjaDocTemplateName = "Srv - IIS Websites"

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

$IISTemplate = [PSCustomObject]@{
    name          = $NinjaDocTemplateName
    allowMultiple = $true
    fields        = @([PSCustomObject]@{
            fieldLabel                = 'Server Name'
            fieldName                 = 'servername'
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
            fieldLabel                = 'Websites'
            fieldName                 = 'websites'
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
            fieldLabel                = 'App Pools'
            fieldName                 = 'apppools'
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
	
Import-Module Webadministration
$Instances = Get-Website
$Websites = @()
$AppPools = @()
	
foreach ($Instance in $Instances) {
  #Set Ninja API Login
  Connect-NinjaOne -NinjaOneInstance $NinjaOneInstance -NinjaOneClientID $NinjaOneClientID -NinjaOneClientSecret $NinjaOneClientSecret
  $IISDocTemplate = Invoke-NinjaOneDocumentTemplate $IISTemplate
  $IISDocs = Invoke-NinjaOneRequest -Method GET -Path 'organization/documents' -QueryParams "templateIds=$($IISDocTemplate.id)"
  [System.Collections.Generic.List[PSCustomObject]]$NinjaDocUpdates = @()
  [System.Collections.Generic.List[PSCustomObject]]$NinjaDocCreation = @()
	$AppPool = Get-IISAppPool -Name $Instance.ApplicationPool
	$AppPoolobj = New-Object -TypeName PSObject
	$AppPoolobj | Add-Member -MemberType NoteProperty -Name "Name" -value $AppPool.Name
	$AppPoolobj | Add-Member -MemberType NoteProperty -Name "Website Name" -value $Instance.Name
	$AppPoolobj | Add-Member -MemberType NoteProperty -Name "State" -value $AppPool.state
	$AppPoolobj | Add-Member -MemberType NoteProperty -Name  "ManagedRuntimeVersion" -value $AppPool.ManagedRuntimeVersion
	$AppPoolobj | Add-Member -MemberType NoteProperty -Name  "ManagedPipelineMode" -value $AppPool.ManagedPipelineMode
	$AppPoolobj | Add-Member -MemberType NoteProperty -Name  "StartMode" -value $AppPool.StartMode
	$AppPools += $AppPoolobj
	foreach ($binding in $Instance.bindings.collection) {
		$Websiteobj = New-Object -TypeName PSObject
		$Websiteobj | Add-Member -MemberType NoteProperty -Name "Name" -value $Instance.Name
		$Websiteobj | Add-Member -MemberType NoteProperty -Name "AppPool Name" -value $AppPool.Name
		$Websiteobj | Add-Member -MemberType NoteProperty -Name "State" -value $Instance.state
		$Websiteobj | Add-Member -MemberType NoteProperty -Name  "PhysicalPath" -value $Instance.physicalPath
		$Websiteobj | Add-Member -MemberType NoteProperty -Name  "Protocol" -value $binding.Protocol
		$Websiteobj | Add-Member -MemberType NoteProperty -Name  "Bindings" -value $binding.BindingInformation
		$Websites += $Websiteobj
	}
	$WebsitesHTML = $Websites | ConvertTo-Html -fragment | Out-String
	$WebsitesHTML = $WebsitesHTML -replace "&lt;th>", "&lt;th style=`"background-color:#4CAF50`">"
	$WebsitesHTML = $WebsitesHTML -replace "&lt;table>", "&lt;table class=`"table table-bordered table-hover`" style=`"width:80%`">"

	$AppPoolsHTML = $AppPools | ConvertTo-Html -fragment | Out-String
	$AppPoolsHTML = $AppPoolsHTML -replace "&lt;th>", "&lt;th style=`"background-color:#4CAF50`">"
	$AppPoolsHTML = $AppPoolsHTML -replace "&lt;table>", "&lt;table class=`"table table-bordered table-hover`" style=`"width:80%`">"
	
	$AssetFields = @{
		"servername"     = "$($ENV:COMPUTERNAME)"
		"websites"         = @{'html' = $WebsitesHTML }
		"apppools"         = @{'html' = $AppPoolsHTML }
	}
}

$DocTitle = "$($ENV:COMPUTERNAME)"
		
try {
  $MatchedDoc = $IISDocs | Where-Object { $_.documentName -eq $DocTitle }
  $MatchCount = ($MatchedDoc | measure-object).count

  # Match to a CloudMonitor
  if ($MatchCount -eq 0) {
	    Write-Host "The Server was not matched to a Document Name in NinjaOne. Please add a IIS Apps and Services document with the name matching $DocTitle"    
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
    documentTemplateId = $IISDocTemplate.id
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
    Write-Host "Creation Error on Doc ID: $IISDocTemplate.id for Org ID: $OrgID, but may have been successful, issue that could have been the cause: $_"
}

try {
    # Update Document
    if (($NinjaDocUpdates | Measure-Object).count -ge 1) {
        Write-Host "Updating Documents"
        $UpdatedDocs = Invoke-NinjaOneRequest -Path "organization/documents" -Method PATCH -InputObject $NinjaDocUpdates -AsArray
        Write-Host "Updated $(($UpdatedDocs | Measure-Object).count) Documents"
    }
} Catch {
    Write-Host "Update Doc Error on Doc ID: $IISDocTemplate.id for Org ID: $OrgID, but may have been successful, issue that could have been the cause: $_"
}
