### ### Ensure TLS 1.2 is forced and must happen before connections of any kind ###
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
#####################################################################
### Set API Parameters for Ninja
$NinjaOneInstance = 'Your-Ninja-Instance'
$NinjaOneClientID = 'Your-Ninja-ClientID'
$NinjaOneClientSecret = 'Your-Ninja-ClientSecret'

### Set Company Org ID and Doc Template Name
$OrgID = $env:NINJA_ORGANIZATION_ID
$NinjaDocTemplateName = "Srv - Server Configs"
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
	
$SrvConfTemplate = [PSCustomObject]@{
    name          = $NinjaDocTemplateName
    allowMultiple = $true
    fields        = @([PSCustomObject]@{
            fieldLabel                = 'Name'
            fieldName                 = 'name'
            fieldType                 = 'TEXT'
            fieldTechnicianPermission = 'READ_ONLY'
            fieldScriptPermission     = 'NONE'
            fieldApiPermission        = 'READ_WRITE'
            fieldContent              = @{
                required         = $False
                advancedSettings = @{
                    expandLargeValueOnRender = $True
                }
            }
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
            fieldLabel                = 'Information'
            fieldName                 = 'information'
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

$SrvConfDocTemplate = Invoke-NinjaOneDocumentTemplate $SrvConfTemplate
$SrvConfDocs = Invoke-NinjaOneRequest -Method GET -Path 'organization/documents' -QueryParams "templateIds=$($SrvConfDocTemplate.id)"

[System.Collections.Generic.List[PSCustomObject]]$NinjaDocUpdates = @()
[System.Collections.Generic.List[PSCustomObject]]$NinjaDocCreation = @()

#This is the object we'll be sending to Ninja. 
$ComputerSystemInfo = Get-CimInstance -ClassName Win32_ComputerSystem
if($ComputerSystemInfo.model -match "Virtual" -or $ComputerSystemInfo.model -match "VMware") { $MachineType = "Virtual"} Else { $MachineType = "Physical"}
$networkName = Get-CimInstance -ClassName Win32_NetworkAdapter | Where-Object {$_.PhysicalAdapter -eq "True"} | Sort Index
$networkIP = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object {$_.MACAddress -gt 0} | Sort Index
$networkSummary = New-Object -TypeName 'System.Collections.ArrayList'

foreach($nic in $networkName) {
	$nic_conf = $networkIP | Where-Object {$_.Index -eq $nic.Index}

	$networkDetails = New-Object PSObject -Property @{
		Index                = [int]$nic.Index;
		AdapterName         = [string]$nic.NetConnectionID;
		Manufacturer         = [string]$nic.Manufacturer;
		Description          = [string]$nic.Description;
		MACAddress           = [string]$nic.MACAddress;
		IPEnabled            = [bool]$nic_conf.IPEnabled;
		IPAddress            = [string]$nic_conf.IPAddress;
		IPSubnet             = [string]$nic_conf.IPSubnet;
		DefaultGateway       = [string]$nic_conf.DefaultIPGateway;
		DHCPEnabled          = [string]$nic_conf.DHCPEnabled;
		DHCPServer           = [string]$nic_conf.DHCPServer;
		DNSServerSearchOrder = [string]$nic_conf.DNSServerSearchOrder;
	}
	$networkSummary += $networkDetails
}
$NicRawConf = $networkSummary | select AdapterName,IPaddress,IPSubnet,DefaultGateway,DNSServerSearchOrder,MACAddress | Convertto-html -Fragment | select -Skip 1
$NicConf = "<br/><table class=`"table table-bordered table-hover`" >" + $NicRawConf
	
$RAM = (systeminfo | Select-String 'Total Physical Memory:').ToString().Split(':')[1].Trim()
	
$ApplicationsFrag = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Convertto-html -Fragment | select -skip 1
$ApplicationsTable = "<br/><table class=`"table table-bordered table-hover`" >" + $ApplicationsFrag
	
$RolesFrag = Get-WindowsFeature | Where-Object {$_.Installed -eq $True} | Select-Object displayname,name  | convertto-html -Fragment | Select-Object -Skip 1
$RolesTable = "<br/><table class=`"table table-bordered table-hover`" >" + $RolesFrag
	
if($machineType -eq "Physical" -and $ComputerSystemInfo.Manufacturer -match "Dell"){
$DiskLayoutRaw = omreport storage pdisk controller=0 -fmt cdv
$DiskLayoutSemi = $DiskLayoutRaw |  select-string -SimpleMatch "ID;Status;" -context 0,($DiskLayoutRaw).Length | convertfrom-csv -Delimiter ";" | select Name,Status,Capacity,State,"Bus Protocol","Product ID","Serial No.","Part Number",Media | convertto-html -Fragment
$DiskLayoutTable = "<br/><table class=`"table table-bordered table-hover`" >" + $DiskLayoutsemi

#Try to get RAID layout
$RAIDLayoutRaw = omreport storage vdisk controller=0 -fmt cdv
$RAIDLayoutSemi = $RAIDLayoutRaw |  select-string -SimpleMatch "ID;Status;" -context 0,($RAIDLayoutRaw).Length | convertfrom-csv -Delimiter ";" | select Name,Status,State,Layout,"Device Name","Read Policy","Write Policy",Media |  convertto-html -Fragment
$RAIDLayoutTable = "<br/><table class=`"table table-bordered table-hover`" >" + $RAIDLayoutsemi
}else {
	$RAIDLayoutTable = "Could not get physical disk info"
	$DiskLayoutTable = "Could not get physical disk info"
}
	
$HTMLFile = "
<b>Servername</b>: $ENV:COMPUTERNAME <br>
<b>Server Type</b>: $machineType <br>
<b>Amount of RAM</b>: $RAM <br>
<br>
<h1>NIC Configuration</h1> <br>
$NicConf
<br>
<h1>Installed Applications</h1> <br>
$ApplicationsTable
<br>
<h1>Installed Roles</h1> <br>
$RolesTable
<br>
<h1>Physical Disk information</h1>
$DiskLayoutTable
<h1>RAID information</h1>
$RAIDLayoutTable
"

$currentDate = Get-Date -Format "dddd dd/MM/yyyy HH:mm K"

$AssetFields = @{
	'name' = $ENV:COMPUTERNAME
	'lastUpdated' = $currentDate
	'information' = @{'html' = $HTMLFile}
}
	
try {
  $MatchedDoc = $SrvConfDocs | Where-Object { $_.documentName -eq $ENV:COMPUTERNAME }
  $MatchCount = ($MatchedDoc | measure-object).count

	# Match to a Doc
  if ($MatchCount -eq 0) {
	  Write-Host "The server was not matched to a Document Name in NinjaOne. Please add a Server document with the name matching $ENV:COMPUTERNAME"    
  } elseif ($MatchCount -gt 1) {
    Throw "Multiple NinjaOne Documents ($($MatchedDoc.documentId -join '')) matched to $($ENV:COMPUTERNAME)"
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
    documentName = $ENV:COMPUTERNAME
    fields       = $AssetFields
	}
	$NinjaDocUpdates.Add($UpdateObject)

} else {
    $CreateObject = [PSCustomObject]@{
    documentName = $ENV:COMPUTERNAME
    documentTemplateId = $SrvConfDocTemplate.id
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
    Write-Host "Creation Error on Doc ID: $SrvConfDocTemplate.id for Org ID: $OrgID, but may have been successful, issue that could have been the cause: $_"
}

try {
    # Update Document
    if (($NinjaDocUpdates | Measure-Object).count -ge 1) {
        Write-Host "Updating Documents"
        $UpdatedDocs = Invoke-NinjaOneRequest -Path "organization/documents" -Method PATCH -InputObject $NinjaDocUpdates -AsArray
        Write-Host "Updated $(($UpdatedDocs | Measure-Object).count) Documents"
    }
} Catch {
    Write-Host "Update Doc Error on Doc ID: $SrvConfDocTemplate.id for Org ID: $OrgID, but may have been successful, issue that could have been the cause: $_"
}
