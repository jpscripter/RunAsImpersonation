Function Get-JPSRunAsMachineCredential { 
<#
.SYNOPSIS
Retrieves the machine password from LSA and makes a PSCredential

.DESCRIPTION
Makes a pscredential object based on the computername and the LSA machine password

.EXAMPLE


PS>     $credential = Get-JPSRunAsMachineCredential
        $ADObject = New-Object -ComObject ADSystemInfo
        $DistintishedPath = $ADObject.gettype().InvokeMember("ComputerName","GetProperty",$null,$ADObject,$null)
        $CompDN = "LDAP://$DistintishedPath"
        $ComputerObject = New-Object System.DirectoryServices.DirectoryEntry($CompDN,$Credential.UserName,$Credential.GetNetworkCredential().Password)
        $ComputerObject |Select *


.LINK
http://www.JPScripter.com

#>
    param(  

    )
    Begin{
         #Check for admin
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent())
        if($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -ne $true) {
          Throw "Run the Command as an Administrator"
        }

        [long]$luid = 0

        $tokPriv1Luid = New-Object Pinvoke.TokPriv1Luid
        $tokPriv1Luid.Count = 1
        $tokPriv1Luid.Luid = $luid
        $tokPriv1Luid.Attr = [Pinvoke.ProcessPrivilege]::SE_PRIVILEGE_ENABLED

        $retVal = [Pinvoke.advapi32]::LookupPrivilegeValue($null, "SeDebugPrivilege", [ref]$tokPriv1Luid.Luid)

        [IntPtr]$CurrentToken = 0
        $retVal = [Pinvoke.advapi32]::OpenProcessToken([Pinvoke.advapi32]::GetCurrentProcess(), [Pinvoke.TokenRights]::TOKEN_ALL_ACCESS, [ref]$CurrentToken)
  
  
        $tokenPrivileges = New-Object Pinvoke.TOKEN_PRIVILEGES
        $retVal = [Pinvoke.advapi32]::AdjustTokenPrivileges($CurrentToken, $false, [ref]$tokPriv1Luid, 12, [IntPtr]::Zero, [IntPtr]::Zero)

        if(-not($retVal)) {
        [System.Runtime.InteropServices.marshal]::GetLastWin32Error()
        Throw "Cannot open current process"
        }

        $LSAProcess = (Get-Process -Name lsass)
        [IntPtr]$LSAToken = 0
        $retVal = [Pinvoke.advapi32]::OpenProcessToken($LSAProcess.Handle, ([Pinvoke.TokenRights]::TOKEN_IMPERSONATE -BOR [Pinvoke.TokenRights]::TOKEN_DUPLICATE), [ref]$LSAToken)

        [IntPtr]$DupToken = 0
        $retVal = [Pinvoke.advapi32]::DuplicateToken($LSAToken, 2, [ref]$DupToken)

        $retval = [Pinvoke.advapi32]::SetThreadToken([IntPtr]::Zero, $DupToken)
        if(-not($retVal)) {
            [System.Runtime.InteropServices.marshal]::GetLastWin32Error()
            Throw "Failed adding LSA Permissions"
        }
    }
    Process {
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

        $Credential = [pscredential]::new("$env:USERDNSDOMAIN\$env:COMPUTERNAME", (ConvertTo-SecureString -String $stringBuilder.ToString() -AsPlainText -Force))
        $Credential

			
    }
    End {

    }
}