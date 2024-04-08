### Ensure TLS 1.2 is forced and must happen before connections of any kind ###
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#####################################################################
### Set API Parameters for Ninja
$NinjaOneInstance = 'Your-Ninja-Instance'
$NinjaOneClientID = 'Your-Ninja-ClientID'
$NinjaOneClientSecret = 'Your-Ninja-ClientSecret'

### Set Company Org ID and Doc Template Name
$OrgID = $env:NINJA_ORGANIZATION_ID
$NinjaDocTemplateName = "Net - LAN Nmap"
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

If(Get-Module -ListAvailable -Name "PSnmap") {
	Import-module "PSnmap"
	} Else {
		install-module "PSnmap" -Force
		import-module "PSnmap"
	}

#Set Ninja API Login
Connect-NinjaOne -NinjaOneInstance $NinjaOneInstance -NinjaOneClientID $NinjaOneClientID -NinjaOneClientSecret $NinjaOneClientSecret
    
$SubnetTemplate = [PSCustomObject]@{
    name          = $NinjaDocTemplateName
    allowMultiple = $true
    fields        = @([PSCustomObject]@{
            fieldLabel                = 'Subnet Network'
            fieldName                 = 'subnetNetwork'
            fieldType                 = 'TEXT'
            fieldTechnicianPermission = 'READ_ONLY'
            fieldScriptPermission     = 'NONE'
            fieldApiPermission        = 'READ_WRITE'
        },
        [PSCustomObject]@{
            fieldLabel                = 'Subnet Gateway'
            fieldName                 = 'subnetGateway'
            fieldType                 = 'TEXT'
            fieldTechnicianPermission = 'READ_ONLY'
            fieldScriptPermission     = 'NONE'
            fieldApiPermission        = 'READ_WRITE'
        },
        [PSCustomObject]@{
            fieldLabel                = 'Subnet DNS Servers'
            fieldName                 = 'subnetDNSServers'
            fieldType                 = 'TEXT'
            fieldTechnicianPermission = 'READ_ONLY'
            fieldScriptPermission     = 'NONE'
            fieldApiPermission        = 'READ_WRITE'
        },
        [PSCustomObject]@{
            fieldLabel                = 'Subnet DHCP Servers'
            fieldName                 = 'subnetDHCPServers'
            fieldType                 = 'TEXT'
            fieldTechnicianPermission = 'READ_ONLY'
            fieldScriptPermission     = 'NONE'
            fieldApiPermission        = 'READ_WRITE'
        },
        [PSCustomObject]@{
            fieldLabel                = 'Scan Results'
            fieldName                 = 'scanResults'
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
        }    
    )
}

$SubnetTemplate = Invoke-NinjaOneDocumentTemplate $SubnetTemplate
$SubnetDocs = Invoke-NinjaOneRequest -Method GET -Path 'organization/documents' -QueryParams "templateIds=$($SubnetTemplate.id)"

$currentDate = Get-Date -Format "dddd dd/MM/yyyy HH:mm K"
	
$ConnectedNetworks = Get-NetIPConfiguration -Detailed | Where-Object {$_.Netadapter.status -eq "up"}
    
foreach($Network in $ConnectedNetworks){
	[System.Collections.Generic.List[PSCustomObject]]$NinjaDocUpdates = @()
	[System.Collections.Generic.List[PSCustomObject]]$NinjaDocCreation = @()
	$DHCPServer = (Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object { $_.IPAddress -eq $network.IPv4Address}).DHCPServer
	$Subnet = "$($network.IPv4DefaultGateway.nexthop)/$($network.IPv4Address.PrefixLength)"
	$NetWorkScan = Invoke-PSnmap -ComputerName $subnet -Port 80,443,3389,21,22,25,587,5001,8443,8080,7443 -Dns -NoSummary 
	$HTMLFrag = $NetworkScan | Where-Object {$_.Ping -eq $true} | convertto-html -Fragment -PreContent "<h1> Network scan of $($subnet) <br/><table class=`"table table-bordered table-hover`" >" | out-string

	$AssetFields = @{
		"subnetNetwork" = $Subnet
		"subnetGateway" = $network.IPv4DefaultGateway.nexthop
		"subnetDNSServers" = $network.dnsserver.serveraddresses
		"subnetDHCPServers" = $DHCPServer
		"scanResults" = @{'html' = $HTMLFrag}
	}
	try {
    $MatchedDoc = $SubnetDocs | Where-Object { $_.documentName -eq $Subnet }
    $MatchCount = ($MatchedDoc | measure-object).count

    # Match to a Doc
    if ($MatchCount -eq 0) {
      Write-Host "The subnet was not matched to a Document Name in NinjaOne. Please add a group document with the name matching $Subnet"    
    } elseif ($MatchCount -gt 1) {
      Throw "Multiple NinjaOne Documents ($($MatchedDoc.documentId -join '')) matched to $Subnet"
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
    	documentName = $Subnet
    	fields       = $AssetFields
    }
    $NinjaDocUpdates.Add($UpdateObject)

  } else {
    	$CreateObject = [PSCustomObject]@{
    	documentName = $Subnet
    	documentTemplateId = $SubnetTemplate.id
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
   	Write-Host "Creation Error on Doc ID: $SubnetTemplate.id for Org ID: $OrgID, but may have been successful, issue that could have been the cause: $_"
  }

  try {
    # Update Document
    if (($NinjaDocUpdates | Measure-Object).count -ge 1) {
      Write-Host "Updating Documents"
      $UpdatedDocs = Invoke-NinjaOneRequest -Path "organization/documents" -Method PATCH -InputObject $NinjaDocUpdates -AsArray
      Write-Host "Updated $(($UpdatedDocs | Measure-Object).count) Documents"
    }
  } Catch {
    Write-Host "Update Doc Error on Doc ID: $SubnetDocTemplate.id for Org ID: $OrgID, but may have been successful, issue that could have been the cause: $_"
  }
}
