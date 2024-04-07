### Ensure TLS 1.2 is forced and must happen before connections of any kind ###
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
### Set API Parameters for Ninja
$NinjaOneInstance = 'Your-Ninja-Instance'
$NinjaOneClientID = 'Your-Ninja-ClientID'
$NinjaOneClientSecret = 'Your-Ninja-ClientSecret'

### Set Company Name and Doc Template Name
$OrgID = $env:NINJA_ORGANIZATION_ID
$NinjaDocTemplateName = "Sec - Active Directory"
	
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

$ADDSTemplate = [PSCustomObject]@{
    name          = 'Sec - Active Directory'
    allowMultiple = $true
    fields        = @([PSCustomObject]@{
            fieldLabel                = 'Domain Name'
            fieldName                 = 'domainName'
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
            fieldLabel                = 'toc'
            fieldName                 = 'toc'
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
            fieldLabel                = 'Forest Name'
            fieldName                 = 'forestName'
            fieldType                 = 'TEXT'
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
            fieldLabel                = 'Forest Summary'
            fieldName                 = 'forestSummary'
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
            fieldLabel                = 'Site Summary'
            fieldName                 = 'siteSummary'
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
            fieldLabel                = 'Domains Summary'
            fieldName                 = 'domainsSummary'
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
            fieldLabel                = 'Domain Controllers'
            fieldName                 = 'domainControllers'
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
            fieldLabel                = 'NTP Configuration'
            fieldName                 = 'ntpConfiguration'
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
            fieldLabel                = 'FSMO Roles'
            fieldName                 = 'fsmoRoles'
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
            fieldLabel                = 'Optional Features'
            fieldName                 = 'optionalFeatures'
            fieldType                 = 'WYSIWYG'
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
            fieldLabel                = 'UPN Suffixes'
            fieldName                 = 'upnSuffixes'
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
            fieldLabel                = 'Default Password Policies'
            fieldName                 = 'defaultPasswordPolicies'
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
            fieldLabel                = 'User Count'
            fieldName                 = 'userCount'
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
            fieldLabel                = 'Domain Admins'
            fieldName                 = 'domainAdmins'
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

$ADDSDocTemplate = Invoke-NinjaOneDocumentTemplate $ADDSTemplate
$ADDSDocs = Invoke-NinjaOneRequest -Method GET -Path 'organization/documents' -QueryParams "templateIds=$($ADDSDocTemplate.id)"

[System.Collections.Generic.List[PSCustomObject]]$NinjaDocUpdates = @()
[System.Collections.Generic.List[PSCustomObject]]$NinjaDocCreation = @()
  
Function Get-RegistryValue
{
	# Gets the specified registry value or $Null if it is missing
	[CmdletBinding()]
	Param
	(
		[String] $path, 
		[String] $name, 
		[String] $ComputerName
	)

	If($ComputerName -eq $env:computername -or $ComputerName -eq "LocalHost")
	{
		$key = Get-Item -LiteralPath $path -EA 0
		If($key)
		{
			Return $key.GetValue($name, $Null)
		}
		Else
		{
			Return $Null
		}
	}

	#path needed here is different for remote registry access
	$path1 = $path.SubString( 6 )
	$path2 = $path1.Replace( '\', '\\' )

	$registry = $null
	try
	{
		## use the Remote Registry service
		$registry = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey(
			[Microsoft.Win32.RegistryHive]::LocalMachine,
			$ComputerName ) 
	}
	catch
	{
		#$e = $error[ 0 ]
		#3.06, remove the verbose message as it confised some people
		#wv "Could not open registry on computer $ComputerName ($e)"
	}

	$val = $null
	If( $registry )
	{
		$key = $registry.OpenSubKey( $path2 )
		If( $key )
		{
			$val = $key.GetValue( $name )
			$key.Close()
		}

		$registry.Close()
	}

	Return $val
}

Function GetBasicDCInfo {
	Param
	(
		[Parameter( Mandatory = $true )]
		[String] $dn	## distinguishedName of a DC
	)

	$DCName  = $dn.SubString( 0, $dn.IndexOf( '.' ) )
	$SrvName = $dn.SubString( $dn.IndexOf( '.' ) + 1 )

	$Results = Get-ADDomainController -Identity $DCName -Server $SrvName -EA 0

   	If($? -and $Null -ne $Results)
	{
		$GC       = $Results.IsGlobalCatalog.ToString()
		$ReadOnly = $Results.IsReadOnly.ToString()
		$IPv4Address = $Results.IPv4Address -join ", "
        $IPv6Address = $Results.IPv6Address -join ", "
		$ServerOS = $Results.OperatingSystem
		$tmp = Get-RegistryValue "HKLM:\software\microsoft\windows nt\currentversion" "installationtype" $DCName
		If( $null -eq $tmp ) { $ServerCore = 'Unknown' }
		ElseIf( $tmp -eq 'Server Core') { $ServerCore = 'Yes' }
		Else { $ServerCore = 'No' }
	}
	Else
	{
		$GC          = 'Unable to retrieve status'
		$ReadOnly    = $GC
		$ServerOS    = $GC
		$ServerCore  = $GC
        $IPv4Address  = $GC
        $IPv6Address  = $GC
	}

	$obj = [PSCustomObject] @{ 
		DCName       = $DCName
		GC           = $GC
		ReadOnly     = $ReadOnly
		ServerOS     = $ServerOS
		ServerCore   = $ServerCore
        IPv4Address  = $IPv4Address
        IPv6Address  = $IPv6Address
	}
    
	Return $obj
}

Function GetTimeServerRegistryKeys {
	Param
	(
		[String] $DCName
	)

	$AnnounceFlags = Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config" "AnnounceFlags" $DCName
	If( $null -eq $AnnounceFlags )
	{
		## DCName can't be contacted or DCName is an appliance with no registry
		$AnnounceFlags = 'n/a'
		$MaxNegPhaseCorrection = 'n/a'
		$MaxPosPhaseCorrection = 'n/a'
		$NtpServer = 'n/a'
		$NtpType = 'n/a'
		$SpecialPollInterval = 'n/a'
		$VMICTimeProviderEnabled = 'n/a'
		$NTPSource = 'Cannot retrieve data from registry'
	}
	Else
	{
		$MaxNegPhaseCorrection = Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config" "MaxNegPhaseCorrection" $DCName
		$MaxPosPhaseCorrection = Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config" "MaxPosPhaseCorrection" $DCName
		$NtpServer = Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" "NtpServer" $DCName
		$NtpType = Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" "Type" $DCName
		$SpecialPollInterval = Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient" "SpecialPollInterval" $DCName
		$VMICTimeProviderEnabled = Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\VMICTimeProvider" "Enabled" $DCName
		$NTPSource = Invoke-Command -ComputerName $DCName {w32tm /query /computer:$DCName /source}
	}

	If( $VMICTimeProviderEnabled -eq 'n/a' )
	{
		$VMICEnabled = 'n/a'
	}
	ElseIf( $VMICTimeProviderEnabled -eq 0 )
	{
		$VMICEnabled = 'Disabled'
	}
	Else
	{
		$VMICEnabled = 'Enabled'
	}
	
	$obj = [PSCustomObject] @{
		DCName                = $DCName.Substring(0, $_.IndexOf( '.'))
		TimeSource            = $NTPSource
		AnnounceFlags         = $AnnounceFlags
		MaxNegPhaseCorrection = $MaxNegPhaseCorrection
		MaxPosPhaseCorrection = $MaxPosPhaseCorrection
		NtpServer             = $NtpServer
		NtpType               = $NtpType
		SpecialPollInterval   = $SpecialPollInterval
		VMICTimeProvider      = $VMICEnabled
	}
    Return $obj
}

function Get-WinADForestInformation {
    $Data = @{ }
    $ForestInformation = $(Get-ADForest)
    $Data.Forest = $ForestInformation
    $Data.RootDSE = $(Get-ADRootDSE -Properties *)
    $Data.ForestName = $ForestInformation.Name
    $Data.ForestNameDN = $Data.RootDSE.defaultNamingContext
    $Data.Domains = $ForestInformation.Domains
    $Data.ForestInformation = @{
        'Forest Name'             = $ForestInformation.Name
        'Root Domain'             = $ForestInformation.RootDomain
        'Forest Functional Level' = $ForestInformation.ForestMode
        '# of Domains'            = ($ForestInformation.Domains).Count
        'Sites Count'             = ($ForestInformation.Sites).Count
        'Forest Domains'          = ($ForestInformation.Domains) -join ", "
        'Sites'                   = ($ForestInformation.Sites) -join ", "
    }
      
    $Data.UPNSuffixes = Invoke-Command -ScriptBlock {
        $UPNSuffixList  =  [PSCustomObject] @{ 
                "Primary UPN" = $ForestInformation.RootDomain
                "UPN Suffixes"   = $ForestInformation.UPNSuffixes -join ","
            }  
        return $UPNSuffixList
    }
      
    $Data.GlobalCatalogs = $ForestInformation.GlobalCatalogs
    $Data.SPNSuffixes = $ForestInformation.SPNSuffixes
      
    $Data.Sites = Invoke-Command -ScriptBlock {
      $Sites = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Sites | Sort-Object         
        $SiteData = foreach ($Site in $Sites) {          
          [PSCustomObject] @{ 
                "Site Name" = $site.Name
                "Subnets"   = ($site.Subnets | Sort-Object)  -join ", "
                "Servers" = ($Site.Servers) -join ", "
            }  
        }
        Return $SiteData
    }
      
        
    $Data.FSMO = Invoke-Command -ScriptBlock {
        [PSCustomObject] @{ 
            "Domain" = $ForestInformation.RootDomain
            "Role"   = 'Domain Naming Master'
            "Holder" = $ForestInformation.DomainNamingMaster
        }
 
        [PSCustomObject] @{ 
            "Domain" = $ForestInformation.RootDomain
            "Role"   = 'Schema Master'
            "Holder" = $ForestInformation.SchemaMaster
        }
          
        foreach ($Domain in $ForestInformation.Domains) {
            $DomainFSMO = Get-ADDomain $Domain | Select-Object PDCEmulator, RIDMaster, InfrastructureMaster
 
            [PSCustomObject] @{ 
                "Domain" = $Domain
                "Role"   = 'PDC Emulator'
                "Holder" = $DomainFSMO.PDCEmulator
            } 
 
             
            [PSCustomObject] @{ 
                "Domain" = $Domain
                "Role"   = 'Infrastructure Master'
                "Holder" = $DomainFSMO.InfrastructureMaster
            } 
 
            [PSCustomObject] @{ 
                "Domain" = $Domain
                "Role"   = 'RID Master'
                "Holder" = $DomainFSMO.RIDMaster
            } 
 
        }
          
        Return $FSMO
    }
      
    $Data.OptionalFeatures = Invoke-Command -ScriptBlock {
        $OptionalFeatures = $(Get-ADOptionalFeature -Filter * )
        $Optional = @{
            'Recycle Bin Enabled'                          = ''
            'Privileged Access Management Feature Enabled' = ''
        }
        ### Fix Optional Features
        foreach ($Feature in $OptionalFeatures) {
            if ($Feature.Name -eq 'Recycle Bin Feature') {
                if ("$($Feature.EnabledScopes)" -eq '') {
                    $Optional.'Recycle Bin Enabled' = $False
                }
                else {
                    $Optional.'Recycle Bin Enabled' = $True
                }
            }
            if ($Feature.Name -eq 'Privileged Access Management Feature') {
                if ("$($Feature.EnabledScopes)" -eq '') {
                    $Optional.'Privileged Access Management Feature Enabled' = $False
                }
                else {
                    $Optional.'Privileged Access Management Feature Enabled' = $True
                }
            }
        }
        return $Optional
        ### Fix optional features
    }
    return $Data
}
  
$TableHeader = "<table style=`"width: 100%; border-collapse: collapse; border: 1px solid black;`">"
$Whitespace = "<br/>"
$TableStyling = "<th>", "<th align=`"left`" style=`"background-color:#00adef; border: 1px solid black;`">"
  
$RawAD = Get-WinADForestInformation
  
$ForestRawInfo = new-object PSCustomObject -property $RawAD.ForestInformation | convertto-html -Fragment | Select-Object -Skip 1
$ForestToc = "<div id=`"forest_summary`"></div>"
$ForestNice = $ForestToc + $TableHeader + ($ForestRawInfo -replace $TableStyling) + $Whitespace
  
$SiteRawInfo = $RawAD.Sites | Select-Object 'Site Name', Servers, Subnets | ConvertTo-Html -Fragment | Select-Object -Skip 1
$SiteHeader = "<p id=`"site_summary`"><i>AD Forest Physical Structure.</i></p>"
$SiteNice = $SiteHeader + $TableHeader + ($SiteRawInfo -replace $TableStyling) + $Whitespace

$DomainsRawInfo = $(Get-WinADForestInformation).Domains | ForEach-Object { Get-ADDomain $_  | Select Name, NetBIOSName, DomainMode } | ConvertTo-Html -Fragment | Select-Object -Skip 1
$DomainsHeader = "<p id=`"domains_summary`"><i>AD Forest Logical Structure.</i></p>"
$DomainsNice = $DomainsHeader + $TableHeader + ($DomainsRawInfo -replace $TableStyling) + $Whitespace

$OptionalRawFeatures = new-object PSCustomObject -property $RawAD.OptionalFeatures | convertto-html -Fragment | Select-Object -Skip 1
$OptionalFeaturesToc = "<div id=`"optional_features`"></div>"
$OptionalNice = $OptionalFeaturesToc + $TableHeader + ($OptionalRawFeatures -replace $TableStyling) + $Whitespace
  
$UPNRawFeatures = $RawAD.UPNSuffixes |  convertto-html -Fragment -as list| Select-Object -Skip 1
$UPNToc = "<div id=`"upn_suffixes`"></div>"
$UPNNice = $UPNToc + $TableHeader + ($UPNRawFeatures -replace $TableStyling) + $Whitespace
  
$DCRawFeatures = $RawAD.GlobalCatalogs| Sort-Object | ForEach-Object { GetBasicDCInfo $_ } | convertto-html -Fragment | Select-Object -Skip 1
$DCToc = "<div id=`"domain_controllers`"></div>"
$DCNice = $DCTocStart + $TableHeader + ($DCRawFeatures -replace $TableStyling) + $Whitespace

$DCRawNTPconfig = $RawAD.GlobalCatalogs | Sort-Object | ForEach-Object { (GetTimeServerRegistryKeys $_) } | convertto-html -Fragment  | Select-Object -Skip 1
$NTPToc = "<div id=`"ntp_configuration`"></div>"
$DCNTPconfigNice = $NTPToc + $TableHeader + ($DCRawNTPconfig -replace $TableStyling) + $Whitespace

$FSMORawFeatures = $RawAD.FSMO | convertto-html -Fragment | Select-Object -Skip 1
$FSMOToc = "<div id=`"fsmo_roles`"></div>"
$FSMONice = $FSMOToc + $TableHeader + ($FSMORawFeatures -replace $TableStyling) + $Whitespace
  
$ForestFunctionalLevel = $RawAD.RootDSE.forestFunctionality
$DomainFunctionalLevel = $RawAD.RootDSE.domainFunctionality
$domaincontrollerMaxLevel = $RawAD.RootDSE.domainControllerFunctionality
  
$passwordpolicyraw = Get-ADDefaultDomainPasswordPolicy | Select-Object ComplexityEnabled, PasswordHistoryCount, LockoutDuration, LockoutThreshold, MaxPasswordAge, MinPasswordAge | convertto-html -Fragment -As List | Select-Object -skip 1
$passwordpolicyheader = "<tr><th>Policy</th><th><b>Setting</b></th></tr>"
$passwordToc = "<div id=`"default_password_policies`"></div>"
$passwordpolicyNice = $passwordToc + $TableHeader + ($passwordpolicyheader -replace $TableStyling) + ($passwordpolicyraw -replace $TableStyling) + $Whitespace
  
$adminsraw = Get-ADGroupMember "Domain Admins" | Select-Object SamAccountName, Name | convertto-html -Fragment | Select-Object -Skip 1
$adminsToc = "<div id=`"domain_admins`"></div>"
$adminsnice = $adminsToc + $TableHeader + ($adminsraw -replace $TableStyling) + $Whitespace
  
$TotalUsers = (Get-AdUser -filter *).count
$EnabledUsers = (Get-AdUser -filter * | Where-Object { $_.enabled -eq $true }).count
$DisabledUSers = (Get-AdUser -filter * | Where-Object { $_.enabled -eq $false }).count
$DomainAdminUsers = (Get-ADGroupMember -Identity "Domain Admins").count
$EnterpriseAdminUsers = (Get-ADGroupMember -Identity "Enterprise Admins").count
$SchemaAdminUsers = (Get-ADGroupMember -Identity "Schema Admins").count
$AdminCountUsers = (Get-ADUser -LDAPFilter "(admincount=1)").count
$UsersCountObj = [PSCustomObject] @{ 
    'Total'             = $TotalUsers
    'Enabled'           = $EnabledUsers
    'Disabled'          = $DisabledUSers
    'Domain Admins'     = $DomainAdminUsers
    'Enterprise Admins' = $EnterpriseAdminUsers
    'Schema Admins'     = $SchemaAdminUsers
    'AdminCount users'  = $AdminCountUsers
}

$userTotalsRaw = $UsersCountObj | convertto-html -Fragment | Select-Object -Skip 1
$userTotalsToc = "<div id=`"user_count`"></div>"
$userTotalsNice = $userTotalsToc + $TableHeader + ($userTotalsRaw -replace $TableStyling) + $Whitespace

$currentDate = Get-Date -Format "dddd dd/MM/yyyy HH:mm K"
$toc = '<h2><center>
			<a href="#forestSummary">FOREST SUMMARY</a>|
			<a href="#siteSummary">SITE SUMMARY</a>|
			<a href="#domainsSummary">DOMAIN SUMMARY</a>|
			<a href="#domainControllers">DOMAIN CONTROLLERS</a>|
			<a href="#ntpConfiguration">NTP CONFIGURATION</a>|
			<a href="#fsmoRoles">FSMO ROLES</a>|
			<a href="#optionalFeatures">OPTIONAL FEATURES</a>|
			<a href="#upnSuffixes">UPN SUFFIXES</a>|
			<a href="#defaultPassword_policies">DEFAULT PASSWORD POLICIES</a>|
			<a href="#userCount">USER COUNT</a>|
			<a href="#domainAdmins">DOMAIN ADMINS</a> 
		</center></h2><br />'

# Setup the fields for the Asset 
$AssetFields = @{
    'lastUpdated'               = $currentDate
	'toc'						= @{'html' = $toc }
    'forestName'               = $RawAD.ForestName
    'forestSummary'            = @{'html' = $ForestNice }
    'siteSummary'              = @{'html' = $SiteNice }
    'domainsSummary'           = @{'html' = $DomainsNice }
    'domainControllers'        = @{'html' = $DCNice }
    'ntpConfiguration'         = @{'html' = $DCNTPconfigNice }
    'fsmoRoles'                = @{'html' = $FSMONice }
    'optionalFeatures'         = @{'html' = $OptionalNice }
    'upnSuffixes'              = @{'html' = $UPNNice }
    'defaultPasswordPolicies' = @{'html' = $passwordpolicyNice }
    'domainAdmins'             = @{'html' = $adminsnice }
    'userCount'                = @{'html' = $userTotalsNice }
}

try {
    $MatchedDoc = $ADDSDocs | Where-Object { $_.documentName -eq $RawAD.ForestName }
    $MatchCount = ($MatchedDoc | measure-object).count

    # Match to a CloudMonitor
    if ($MatchCount -eq 0) {
	    Write-Host "The domain was not matched to a Document Name in NinjaOne. Please add a Active Directory Apps and Services document with the name matching $RawAD.ForestName"    
    } elseif ($MatchCount -gt 1) {
        Throw "Multiple NinjaOne Documents ($($MatchedDoc.documentId -join '')) matched to $($RawAD.ForestName)"
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
    documentName = $RawAD.ForestName
    fields       = $AssetFields
	}
	$NinjaDocUpdates.Add($UpdateObject)

} else {
    $CreateObject = [PSCustomObject]@{
    documentName = $RawAD.ForestName
    documentTemplateId = $ADDSDocTemplate.id
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
    Write-Host "Creation Error on Doc ID: $ADDSDocTemplate.id for Org ID: $OrgID, but may have been successful, issue that could have been the cause: $_"
}

try {
    # Update Document
    if (($NinjaDocUpdates | Measure-Object).count -ge 1) {
        Write-Host "Updating Documents"
        $UpdatedDocs = Invoke-NinjaOneRequest -Path "organization/documents" -Method PATCH -InputObject $NinjaDocUpdates -AsArray
        Write-Host "Updated $(($UpdatedDocs | Measure-Object).count) Documents"
    }
} Catch {
    Write-Host "Update Doc Error on Doc ID: $ADDSDocTemplate.id for Org ID: $OrgID, but may have been successful, issue that could have been the cause: $_"
}
