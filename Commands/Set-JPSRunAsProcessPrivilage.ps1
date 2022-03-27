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
        [Process_Privilege]$ProcessPrivilege
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

        $retVal = [Pinvoke.advapi32]::LookupPrivilegeValue($null, $ProcessPrivilege, [ref]$tokPriv1Luid.Luid)
        $retVal

        [IntPtr]$CurrentToken = 0
        $retVal = [Pinvoke.advapi32]::OpenProcessToken([Pinvoke.advapi32]::GetCurrentProcess(), [Pinvoke.TokenRights]::TOKEN_ALL_ACCESS, [ref]$CurrentToken)
        $retVal
  
        $tokenPrivileges = New-Object Pinvoke.TOKEN_PRIVILEGES
        $retVal = [Pinvoke.advapi32]::AdjustTokenPrivileges($CurrentToken, $false, [ref]$tokPriv1Luid, 12, [IntPtr]::Zero, [IntPtr]::Zero)
        $retVal

        [IntPtr]$DupToken = 0
        $retVal = [Pinvoke.advapi32]::DuplicateToken($CurrentToken, 2, [ref]$DupToken)
        $retVal

        $retval = [Pinvoke.advapi32]::SetThreadToken([IntPtr]::Zero, $DupToken)
        $retVal

        if(-not($retVal)) {
        [System.Runtime.InteropServices.marshal]::GetLastWin32Error()
        Throw "Cannot open current process"
        }

        $LSAProcess = (Get-Process -id 15240)
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
        

			
    }
    End {

    }
}