param(
    [string]$DomainName = "LAB.LOCAL",
    [string]$AdminPassword = "Welcome123!",
    [string]$NetbiosName = "LAB",
    [int]$UserCount = 20,
    [int]$GroupCount = 5,
    [int]$ComputerCount = 10
)

$ErrorActionPreference = "Continue"

Import-Module ActiveDirectory

$securePassword = ConvertTo-SecureString -String $AdminPassword -AsPlainText -Force

function New-LabUser {
    param(
        [string]$SamAccountName,
        [string]$DisplayName,
        [string]$Department,
        [bool]$Kerberoastable = $false,
        [bool]$DontRequirePreAuth = $false,
        [string]$SPN = ""
    )

    $ouPath = "OU=Users,DC=$($DomainName.Split('.')[0]),DC=$($DomainName.Split('.')[1])"

    New-ADUser -SamAccountName $SamAccountName `
        -Name $DisplayName `
        -DisplayName $DisplayName `
        -Department $Department `
        -Path $ouPath `
        -AccountPassword $securePassword `
        -Enabled $true `
        -ChangePasswordAtLogon $false

    if ($Kerberoastable -and $SPN) {
        Set-ADUser -Identity $SamAccountName `
            -ServicePrincipalName @{Add=$SPN} `
            -PasswordNeverExpires $true `
            -TrustedForDelegation $false
    }

    if ($DontRequirePreAuth) {
        Set-ADAccountControl -Identity $SamAccountName -DoesNotRequirePreAuth $true
    }
}

function New-LabGroup {
    param(
        [string]$Name,
        [string]$Description,
        [string]$Scope = "DomainLocal",
        [string]$Category = "Security"
    )

    $ouPath = "OU=Groups,DC=$($DomainName.Split('.')[0]),DC=$($DomainName.Split('.')[1])"

    try {
        New-ADGroup -Name $Name `
            -GroupScope $Scope `
            -GroupCategory $Category `
            -Description $Description `
            -Path $ouPath
    } catch {
        Write-Warning "Group $Name may already exist: $_"
    }
}

function Add-LabGroupMember {
    param(
        [string]$GroupName,
        [string]$MemberName
    )

    try {
        Add-ADGroupMember -Identity $GroupName -Members $MemberName -ErrorAction Stop
    } catch {
        Write-Warning "Failed to add $MemberName to $GroupName : $_"
    }
}

function Set-LabACLAbuse {
    param(
        [string]$Principal,
        [string]$TargetDN,
        [string]$Right,
        [string]$InheritanceType = "All"
    )

    try {
        $acl = Get-Acl -Path "AD:\$TargetDN"
        $identity = (Get-ADUser -Identity $Principal).SID

        switch ($Right) {
            "GenericAll" {
                $adRight = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
                $aceType = [System.Security.AccessControl.AccessControlType]::Allow
                $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                    $identity, $adRight, $aceType
                )
            }
            "WriteDacl" {
                $adRight = [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl
                $aceType = [System.Security.AccessControl.AccessControlType]::Allow
                $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                    $identity, $adRight, $aceType
                )
            }
            "WriteOwner" {
                $adRight = [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner
                $aceType = [System.Security.AccessControl.AccessControlType]::Allow
                $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                    $identity, $adRight, $aceType
                )
            }
        }

        $acl.AddAccessRule($ace)
        Set-Acl -Path "AD:\$TargetDN" -AclObject $acl
    } catch {
        Write-Warning "Failed to set ACL for $Principal on $TargetDN : $_"
    }
}

$domainDN = "DC=$($DomainName.Split('.')[0]),DC=$($DomainName.Split('.')[1])"

$ous = @(
    @{Name="Users"; Path=$domainDN},
    @{Name="Computers"; Path=$domainDN},
    @{Name="Servers"; Path=$domainDN},
    @{Name="Groups"; Path=$domainDN},
    @{Name="Service Accounts"; Path=$domainDN}
)

foreach ($ou in $ous) {
    try {
        New-ADOrganizationalUnit -Name $ou.Name -Path $ou.Path
    } catch {
        Write-Warning "OU $($ou.Name) may already exist"
    }
}

$serviceAccounts = @(
    @{Sam="svc_mssql"; Display="MSSQL Service Account"; Dept="IT"; SPN="MSSQLSvc/dc01.$DomainName:1433"; Kerb=$true}
    @{Sam="svc_webapp"; Display="Web Application Account"; Dept="Engineering"; SPN="HTTP/intranet.$DomainName"; Kerb=$true}
    @{Sam="svc_backup"; Display="Backup Service Account"; Dept="IT"; SPN="cifs/fs01.$DomainName"; Kerb=$true}
    @{Sam="svc_reports"; Display="Reporting Service Account"; Dept="Finance"; SPN="HTTP/reports.$DomainName"; Kerb=$true}
)

foreach ($svc in $serviceAccounts) {
    New-LabUser -SamAccountName $svc.Sam `
        -DisplayName $svc.Display `
        -Department $svc.Dept `
        -Kerberoastable $svc.Kerb `
        -SPN $svc.SPN
}

$asrepAccounts = @(
    @{Sam="test_svc01"; Display="Test Service 01"; Dept="IT"; PreAuth=$true}
    @{Sam="legacy_app"; Display="Legacy Application"; Dept="Engineering"; PreAuth=$true}
)

foreach ($acct in $asrepAccounts) {
    New-LabUser -SamAccountName $acct.Sam `
        -DisplayName $acct.Display `
        -Department $acct.Dept `
        -DontRequirePreAuth $true
}

$standardUsers = @(
    @{Sam="jsmith"; Display="John Smith"; Dept="Finance"},
    @{Sam="mjones"; Display="Mary Jones"; Dept="HR"},
    @{Sam="bwilson"; Display="Bob Wilson"; Dept="IT"},
    @{Sam="lgarcia"; Display="Lisa Garcia"; Dept="Engineering"},
    @{Sam="rthompson"; Display="Robert Thompson"; Dept="Marketing"},
    @{Sam="slee"; Display="Sarah Lee"; Dept="Sales"},
    @{Sam="dclark"; Display="David Clark"; Dept="IT"},
    @{Sam="jmiller"; Display="Jennifer Miller"; Dept="Finance"},
    @{Sam="adroberts"; Display="Andrew Roberts"; Dept="Legal"},
    @{Sam="pmartinez"; Display="Patricia Martinez"; Dept="Operations"}
)

foreach ($user in $standardUsers) {
    New-LabUser -SamAccountName $user.Sam `
        -DisplayName $user.Display `
        -Department $user.Dept
}

$groups = @(
    @{Name="IT Administrators"; Desc="IT admin team with elevated rights"},
    @{Name="Server Administrators"; Desc="Server management group"},
    @{Name="Helpdesk Support"; Desc="Tier 1 and 2 support staff"},
    @{Name="Database Administrators"; Desc="Database management team"},
    @{Name="Development Team"; Desc="Application development group"}
)

foreach ($grp in $groups) {
    New-LabGroup -Name $grp.Name -Description $grp.Desc
}

Add-LabGroupMember -GroupName "IT Administrators" -MemberName "dclark"
Add-LabGroupMember -GroupName "IT Administrators" -MemberName "bwilson"
Add-LabGroupMember -GroupName "Server Administrators" -MemberName "bwilson"
Add-LabGroupMember -GroupName "Helpdesk Support" -MemberName "dclark"
Add-LabGroupMember -GroupName "Helpdesk Support" -MemberName "adroberts"
Add-LabGroupMember -GroupName "Database Administrators" -MemberName "jmiller"
Add-LabGroupMember -GroupName "Development Team" -MemberName "lgarcia"

Add-LabGroupMember -GroupName "Server Administrators" -MemberName "IT Administrators"
Add-LabGroupMember -GroupName "Database Administrators" -MemberName "Server Administrators"
Add-LabGroupMember -GroupName "IT Administrators" -MemberName "DOMAIN ADMINS"

Set-LabACLAbuse -Principal "dclark" -TargetDN $domainDN -Right "WriteDacl"
Set-LabACLAbuse -Principal "adroberts" -TargetDN $domainDN -Right "WriteOwner"
Set-LabACLAbuse -Principal "IT Administrators" -TargetDN $domainDN -Right "GenericAll"

Write-Output "AD Lab provisioning complete for domain $DomainName"
Write-Output "Service Accounts (Kerberoastable): $($serviceAccounts.Sam -join ', ')"
Write-Output "AS-REP Roastable: $($asrepAccounts.Sam -join ', ')"
Write-Output "ACL Abuses configured on domain root"
Write-Output "Nested group escalation path: Helpdesk Support -> IT Administrators -> Domain Admins"
