Function Get-MachineCredential { 
<#
.SYNOPSIS
Retrieves the machine password from LSA and makes a PSCredential

.DESCRIPTION
Makes a pscredential object based on the computername and the LSA machine password

.EXAMPLE


PS>     $credential = Get-MachineCredential
        $ADObject = New-Object -ComObject ADSystemInfo
        $DistintishedPath = $ADObject.gettype().InvokeMember("ComputerName","GetProperty",$null,$ADObject,$null)
        $CompDN = "LDAP://$DistintishedPath"
        $ComputerObject = New-Object System.DirectoryServices.DirectoryEntry($CompDN,$Credential.UserName,$Credential.GetNetworkCredential().Password)
        $ComputerObject |Select *


.LINK
http://www.JPScripter.com

#>
    #Check for admin
    if(-not (Test-LocalAdmin)) {
        Throw "Run the Command as an Administrator"
    }

    #Setting LSA Permissions
    Set-ProcessPrivilage -ProcessPrivilege SeDebugPrivilege
    $LSAProcess = (Get-Process -Name lsass)
    $LSAToken = Get-ProcessToken -ProcessID $LSAProcess.ID
    $DupToken = Get-DuplicateToken -Token $LSAToken
    Set-Impersonation -Token $DupToken 

    #Dupliate LSA Key
    $MachineKey = '$MACHINE.ACC'
    $Key = 'LSA1'
    Remove-Item HKLM:\SECURITY\Policy\Secrets\$Key -force -recurse -ErrorAction Ignore
    $Null = New-Item HKLM:\SECURITY\Policy\Secrets\LSA1 -ItemType Directory
    $values = 'CurrVal','OldVal','OupdTime','CupdTime','SecDesc'
    Foreach ($Property in $Values) {
        $copyFrom = "HKLM:\SECURITY\Policy\Secrets\$MachineKey\" + $Property
        $copyTo = "HKLM:\SECURITY\Policy\Secrets\$Key\" + $Property
        $Null = New-Item $copyTo -ItemType Directory
        $item = Get-ItemProperty $copyFrom
        $Null = Set-ItemProperty -Path $copyTo -Name '(default)' -Value $item.'(default)'
    }

    #region Make LSA Objects
    $objectAttributes = New-Object Pinvoke.LSA_OBJECT_ATTRIBUTES
    $objectAttributes.Length = 0
    $objectAttributes.RootDirectory = [IntPtr]::Zero
    $objectAttributes.Attributes = 0
    $objectAttributes.SecurityDescriptor = [IntPtr]::Zero
    $objectAttributes.SecurityQualityOfService = [IntPtr]::Zero

    $localsystem = New-Object Pinvoke.LSA_UNICODE_STRING
    $localsystem.Buffer = [IntPtr]::Zero
    $localsystem.Length = 0
    $localsystem.MaximumLength = 0

    $secretName = New-Object Pinvoke.LSA_UNICODE_STRING
    $secretName.Buffer = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($Key)
    $secretName.Length = [Uint16]($key.Length * [System.Text.UnicodeEncoding]::CharSize)
    $secretName.MaximumLength = [Uint16](($key.Length + 1) * [System.Text.UnicodeEncoding]::CharSize)

    $lsaPolicyHandle = [IntPtr]::Zero
    $access = [Pinvoke.LSA_AccessPolicy]::POLICY_GET_PRIVATE_INFORMATION
    #endregion Make LSA Objects

    #region Open LSA Policy and get Password private Data
    $lsaOpenPolicyHandle = [Pinvoke.advapi32]::LSAOpenPolicy([ref]$localSystem, [ref]$objectAttributes, $access, [ref]$lsaPolicyHandle)
    if ( $lsaPolicyHandle -eq 0){
        throw "Could not open LSA data"
    }
    
    $privateData = [IntPtr]::Zero
    $ntsResult = [Pinvoke.advapi32]::LsaRetrievePrivateData($lsaPolicyHandle, [ref]$secretName, [ref]$privateData)
    $lsaClose = [Pinvoke.advapi32]::LsaClose($lsaPolicyHandle)
    Remove-Item HKLM:\SECURITY\Policy\Secrets\$Key -force -recurse -ErrorAction Ignore
    if ( $privateData -eq [System.IntPtr]::Zero){
        throw "Could not open Private LSA data"
    }
    #endregion 
    
    #region Retrive and convert password
    $Length = [System.Runtime.InteropServices.marshal]::ReadInt16($privateData,0)
    $offset = 16
    $Max = [System.Runtime.InteropServices.marshal]::ReadInt16($privateData,1)
    $stringBuilder = New-Object System.Text.StringBuilder -ArgumentList $Length

    For ($i = $offset; $I -le $Length*2+$offset ; $I+=[System.Text.UnicodeEncoding]::CharSize){
        $b1 =  [System.Runtime.InteropServices.marshal]::ReadByte($privateData,$i) 
        $b2 =  [System.Runtime.InteropServices.marshal]::ReadByte($privateData,$i+1) 
        $currentChar = [System.BitConverter]::ToChar(($b1,$b2),0)
        if($currentChar -eq [char]::MinValue) { break; }
        [void]$stringBuilder.Append($currentChar)
        Write-Verbose -message "$i = $currentChar - $b1 - $b2"
    }

    $Credential = [pscredential]::new("$env:USERDOMAIN\$env:COMPUTERNAME$", (ConvertTo-SecureString -String $stringBuilder.ToString() -AsPlainText -Force))
    $Credential
    #endregion

    #Revert Token Back
    Set-Impersonation  
}