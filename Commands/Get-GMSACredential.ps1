Function Get-GMSACredential{
    <#
    .SYNOPSIS
    Returns the GMSA PSCredential based on the identity name of the account
    
    .DESCRIPTION
    Retrieves the password of the GMSA from AD and uses that to create a PSCredential

    .PARAMETER Identity
    Identity of the GMSA account
    
    .PARAMETER Domain
    Domain logon name of the account

    .EXAMPLE
    $Path = 'OU=SERVICE ACCOUNTS,OU=CORP,DC=corp,DC=contoso,DC=com'
    $adGroup = New-ADGroup -Name GMSAAdmin -GroupCategory Security -Path $Path -GroupScope Global -PassThru
    Add-ADGroupMember -Identity GMSAAdmin -Members $env:USERNAME
    klist.exe purge # may refresh ad groups. If it doesnt logout and relogin.
    Try{
        $MyGMSA = New-ADServiceAccount -Name MyGMSA -Path $path -PrincipalsAllowedToRetrieveManagedPassword $adGroup -DNSHostName MyGMSA -Passthru
    }Catch{
        Add-KdsRootKey -EffectiveTime ((get-date).addhours(-10))
        $MyGMSA = New-ADServiceAccount -Name MyGMSA -Path $path -PrincipalsAllowedToRetrieveManagedPassword $adGroup -DNSHostName MyGMSA -Passthru
    }
    $G = Get-GMSACredential -Identity MyGMSA
    Test-Credential $g
    -

    .NOTES
    .Author: Ryan Ephgrave and Jeff Scripter

    #>
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Identity
    )
    $Domain = (Get-CimInstance WIN32_ComputerSystem).Domain
    $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry 
    $searcher = New-Object System.DirectoryServices.DirectorySearcher -ArgumentList $DirectoryEntry
    $searcher.Filter = "(&(name=$($Identity))(ObjectCategory=msDS-GroupManagedServiceAccount))"
    $searcher.SearchRoot.AuthenticationType = 'Sealing'
    $Null = $searcher.PropertiesToLoad.Add('Name')
    $Null = $searcher.PropertiesToLoad.Add('msDS-ManagedPassword')
    $Null = $searcher.PropertiesToLoad.Add('msDS-GroupMSAMembership')
    $Accounts = $searcher.FindAll()

    foreach($a in $accounts){

        #Assuming only one Group with Manage Password Permissions
        $GroupPermissions = $a.Properties.'msds-groupmsamembership'
        [Byte[]]$Groupblob = $GroupPermissions.Foreach({$PSItem})
        $GroupSid = [Security.Principal.SecurityIdentifier]::new($Groupblob,$Groupblob.Length - 28)
        $WindowsIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()

        # Check if user has AD Group to manage password
        if ( -not $WindowsIdentity.Groups.Contains($GroupSid))
        {
            $searcher.Filter = "(objectSid=$($GroupSid.value))"
            $Null = $searcher.PropertiesToLoad.Add('Name')
            $Null = $searcher.PropertiesToLoad.Add('member')
            $searcher.SearchRoot.AuthenticationType = 'Sealing'
            $Group = $searcher.FindAll()
            $SysInfo = New-Object -ComObject ADSystemInfo
            $UserPath = $SysInfo.GetType().InvokeMember("UserName", "GetProperty", $Null, $SysInfo, $Null)
            if ($Group.properties.member -contains $UserPath){
                Write-Warning -Message "$($WindowsIdentity.name) does not Locally contain Group $($Group.path). Try Killing kerberos tickets."                
            }else{
                Write-Warning -Message "$($WindowsIdentity.name) is not in $($Group.path)."
            }
        }

        #Retrieve Password
        if($a.Properties.'msds-managedpassword'){
            $pw = $a.Properties.'msds-managedpassword'
            [Byte[]]$byteBlob = $pw.Foreach({$PSItem})
            $MemoryStream = New-Object System.IO.MemoryStream -ArgumentList (,$byteBlob)
            $Reader = New-Object System.IO.BinaryReader -ArgumentList $MemoryStream
            
            # have to move the reader to the pw offset
            $Version = $Reader.ReadInt16()
            $Reserved = $Reader.ReadInt16()
            $Length = $Reader.ReadInt32()
            $CurrentPWOffset = $Reader.ReadInt16()
            $PreviousPWOffset = $Reader.ReadInt16()
            $QueryPWInterval = $Reader.ReadInt16()
            $UnChangedPWInterval = $Reader.ReadInt16()

            $Length = $byteBlob.Length - $CurrentPWOffset
            $stringBuilder = New-Object System.Text.StringBuilder -ArgumentList $Length
            for($i = $CurrentPWOffset ; $i -le $Length; $i += [System.Text.UnicodeEncoding]::CharSize){
                $currentChar = [System.BitConverter]::ToChar($byteBlob, $i)
                if($currentChar -eq [char]::MinValue) { break; }
                [void]$stringBuilder.Append($currentChar)
                #Write-Verbose -Message "$I - $($byteBlob[$i]) - $currentChar"
            }

            $QueryInterval = [TimeSpan]::FromTicks([System.BitConverter]::ToUInt64($byteBlob,$UnChangedPWInterval))
            Write-Verbose -Message "Password valie for $($QueryInterval.TotalDays)"

            $TimeSpan = [TimeSpan]::FromTicks([System.BitConverter]::ToUInt64($byteBlob,$UnChangedPWInterval))
            Write-Verbose -Message "Password Changes in $($QueryInterval.TotalDays)"

            $Credential =  ( New-Object PSCredential -ArgumentList @(
                                    "corp\MyGMSA$",
                                    (ConvertTo-SecureString $stringBuilder.ToString() -AsPlainText -Force)
                                    ))
            return $Credential
        }
    }
}

