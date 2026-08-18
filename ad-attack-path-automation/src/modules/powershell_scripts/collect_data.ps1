param(
    [string]$DomainName = "LAB.LOCAL",
    [string]$OutputPath = "C:\Collection",
    [string[]]$CollectionMethods = @("All")
)

$ErrorActionPreference = "Continue"

Import-Module ActiveDirectory

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$collection = @{
    Meta = @{
        Type = "SharpHoundCollection"
        Version = "4.3.0"
        CollectionDate = (Get-Date).ToUniversalTime().ToString("o")
        Methods = $CollectionMethods
        Domain = $DomainName
    }
    Nodes = [System.Collections.Generic.List[PSCustomObject]]::new()
    Edges = [System.Collections.Generic.List[PSCustomObject]]::new()
}

function Get-ObjectGraphID {
    param([string]$DistinguishedName)
    try {
        $obj = Get-ADObject -Identity $DistinguishedName -Properties objectGUID -ErrorAction Stop
        return $obj.objectGUID.ToString()
    } catch {
        return [guid]::NewGuid().ToString()
    }
}

Write-Output "[*] Collecting User objects..."

$users = Get-ADUser -Filter * -Properties `
    DisplayName, Description, Department, Title, `
    ServicePrincipalName, `
    DoesNotRequirePreAuth, PasswordNeverExpires, `
    LastLogonDate, Enabled, MemberOf, AdminCount, `
    msDS-AllowedToDelegateTo, TrustedForDelegation, `
    TrustedToAuthForDelegation

foreach ($user in $users) {
    $objectId = $user.objectGUID.ToString()
    $userName = "$($user.SamAccountName)@$DomainName"

    $nodeProps = [ordered]@{
        type = "User"
        name = $userName
        objectid = $objectId
        enabled = if ($user.Enabled) { $true } else { $false }
        displayname = $user.DisplayName
        department = $user.Department
        title = $user.Title
        description = $user.Description
        hasspn = $false
        dont_require_preauth = $false
        password_never_expires = $false
        lastlogondate = $null
        admincount = $false
        unconstrained_delegation = $false
    }

    if ($user.ServicePrincipalName) {
        $nodeProps.hasspn = $true
        $nodeProps.serviceprincipalname = $user.ServicePrincipalName
    }

    if ($user.DoesNotRequirePreAuth) {
        $nodeProps.dont_require_preauth = $true
    }

    if ($user.PasswordNeverExpires) {
        $nodeProps.password_never_expires = $true
    }

    if ($user.LastLogonDate) {
        $nodeProps.lastlogondate = $user.LastLogonDate.ToUniversalTime().ToString("o")
    }

    if ($user.AdminCount -eq 1) {
        $nodeProps.admincount = $true
    }

    if ($user.TrustedForDelegation -eq $true -or $user.TrustedToAuthForDelegation -eq $true) {
        $nodeProps.unconstrained_delegation = $true
    }

    $collection.Nodes.Add([PSCustomObject]$nodeProps)

    foreach ($groupDN in $user.MemberOf) {
        try {
            $group = Get-ADGroup -Identity $groupDN -Properties * -ErrorAction SilentlyContinue
            $groupName = "$($group.Name)@$DomainName"

            $edge = [PSCustomObject][ordered]@{
                source = $userName
                target = $groupName
                type = "MemberOf"
                isACL = $false
            }
            $collection.Edges.Add($edge)
        } catch {
        }
    }
}

Write-Output "[*] Collecting Group objects..."

$groups = Get-ADGroup -Filter * -Properties Description, Member, MemberOf, AdminCount

foreach ($group in $groups) {
    $objectId = $group.objectGUID.ToString()
    $groupName = "$($group.Name)@$DomainName"

    $nodeProps = [ordered]@{
        type = "Group"
        name = $groupName
        objectid = $objectId
        description = $group.Description
        isprivileged = $false
        admincount = $false
    }

    if ($group.AdminCount -eq 1) {
        $nodeProps.admincount = $true
    }

    if ($group.Name -match "DOMAIN ADMINS|ENTERPRISE ADMINS|ADMINISTRATORS") {
        $nodeProps.isprivileged = $true
    }

    $collection.Nodes.Add([PSCustomObject]$nodeProps)

    foreach ($parentDN in $group.MemberOf) {
        try {
            $parent = Get-ADGroup -Identity $parentDN -ErrorAction SilentlyContinue
            $parentName = "$($parent.Name)@$DomainName"
            $edge = [PSCustomObject][ordered]@{
                source = $groupName
                target = $parentName
                type = "MemberOf"
                isACL = $false
            }
            $collection.Edges.Add($edge)
        } catch {
        }
    }
}

Write-Output "[*] Collecting Computer objects..."

$computers = Get-ADComputer -Filter * -Properties `
    DisplayName, Description, OperatingSystem, OperatingSystemVersion, `
    Enabled, LastLogonDate, TrustedForDelegation, `
    msDS-AllowedToDelegateTo, ServicePrincipalName

foreach ($computer in $computers) {
    $objectId = $computer.objectGUID.ToString()
    $compName = "$($computer.Name).$DomainName"

    $nodeProps = [ordered]@{
        type = "Computer"
        name = $compName
        objectid = $objectId
        enabled = if ($computer.Enabled) { $true } else { $false }
        operating_system = $computer.OperatingSystem
        operating_system_version = $computer.OperatingSystemVersion
        description = $computer.Description
        lastlogondate = $null
        unconstrained_delegation = $false
        hasspn = $false
    }

    if ($computer.LastLogonDate) {
        $nodeProps.lastlogondate = $computer.LastLogonDate.ToUniversalTime().ToString("o")
    }

    if ($computer.TrustedForDelegation -eq $true) {
        $nodeProps.unconstrained_delegation = $true
    }

    if ($computer.ServicePrincipalName) {
        $nodeProps.hasspn = $true
    }

    $collection.Nodes.Add([PSCustomObject]$nodeProps)

    $svcUsers = $users | Where-Object { $_.ServicePrincipalName -and $_.Enabled }

    foreach ($svc in $svcUsers) {
        $svcName = "$($svc.SamAccountName)@$DomainName"
        $sessionEdge = [PSCustomObject][ordered]@{
            source = $svcName
            target = $compName
            type = "HasSession"
            isACL = $false
        }
        $collection.Edges.Add($sessionEdge)
    }

    $localAdmins = @("Domain Admins", "Enterprise Admins", "Server Administrators")
    foreach ($adminGroup in $localAdmins) {
        $adminGroupName = "$adminGroup@$DomainName"
        $adminEdge = [PSCustomObject][ordered]@{
            source = $adminGroupName
            target = $compName
            type = "AdminTo"
            isACL = $false
        }
        $collection.Edges.Add($adminEdge)
    }
}

Write-Output "[*] Collecting ACL relationships..."

$domainDN = (Get-ADDomain).DistinguishedName

try {
    $acl = Get-Acl -Path "AD:\$domainDN"

    foreach ($ace in $acl.Access) {
        if ($ace.IdentityReference -match "^S-1-") {
            continue
        }

        $principalName = $ace.IdentityReference.Value
        if ($principalName -match "^$DomainName\\") {
            $account = $principalName -replace "^$DomainName\\", ""
            $principal = "$account@$DomainName"
        } else {
            continue
        }

        $activeDirectoryRights = $ace.ActiveDirectoryRights.ToString()

        switch -Regex ($activeDirectoryRights) {
            "GenericAll" {
                $edgeType = "GenericAll"
                $risk = "Critical"
            }
            "WriteDacl" {
                $edgeType = "WriteDacl"
                $risk = "Critical"
            }
            "WriteOwner" {
                $edgeType = "WriteOwner"
                $risk = "High"
            }
            default {
                continue
            }
        }

        $targetName = $DomainName
        $aclEdge = [PSCustomObject][ordered]@{
            source = $principal
            target = $targetName
            type = $edgeType
            isACL = $true
            risk = $risk
        }
        $collection.Edges.Add($aclEdge)
    }
} catch {
    Write-Warning "Failed to enumerate domain ACLs: $_"
}

Write-Output "[*] Collecting GPO relationships..."

try {
    $gpos = Get-GPO -All -ErrorAction SilentlyContinue

    foreach ($gpo in $gpos) {
        $gpoNode = [PSCustomObject][ordered]@{
            type = "GPO"
            name = $gpo.DisplayName
            objectid = $gpo.Id.ToString()
            gpo_id = $gpo.Id.ToString()
            is_misconfigured = $false
        }
        $collection.Nodes.Add($gpoNode)

        $gpoName = $gpo.DisplayName
        $gpoDomainEdge = [PSCustomObject][ordered]@{
            source = $gpoName
            target = $DomainName
            type = "AppliedGPOs"
            isACL = $false
        }
        $collection.Edges.Add($gpoDomainEdge)
    }
} catch {
    Write-Warning "Failed to enumerate GPOs (GroupPolicy module may not be available)"
}

Write-Output "[*] Collecting OU hierarchy..."

$ous = Get-ADOrganizationalUnit -Filter *

foreach ($ou in $ous) {
    $ouNode = [PSCustomObject][ordered]@{
        type = "OU"
        name = $ou.Name
        objectid = $ou.objectGUID.ToString()
        path = $ou.DistinguishedName
    }
    $collection.Nodes.Add($ouNode)

    if ($ou.DistinguishedName -ne $domainDN) {
        $parentContainer = $ou.DistinguishedName -replace "^.+?,(.+)$", '$1'
        $parent = Get-ADObject -Identity $parentContainer -Properties Name -ErrorAction SilentlyContinue
        if ($parent) {
            $parentName = $parent.Name
            $ouEdge = [PSCustomObject][ordered]@{
                source = $ou.Name
                target = $parentName
                type = "Contains"
                isACL = $false
            }
            $collection.Edges.Add($ouEdge)
        }
    }
}

$domainNode = [PSCustomObject][ordered]@{
    type = "Domain"
    name = $DomainName
    objectid = (Get-ADDomain).objectGUID.ToString()
    fqdn = $DomainName
}
$collection.Nodes.Add($domainNode)

$outputFile = Join-Path $OutputPath "ad_data_$((Get-Date).ToString('yyyyMMdd_HHmmss')).json"
$collection | ConvertTo-Json -Depth 20 | Out-File -FilePath $outputFile -Encoding UTF8

Write-Output "[+] Collection complete"
Write-Output "    Nodes: $($collection.Nodes.Count)"
Write-Output "    Edges: $($collection.Edges.Count)"
Write-Output "    Output: $outputFile"
