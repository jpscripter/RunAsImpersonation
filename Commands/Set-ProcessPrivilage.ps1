Function Set-ProcessPrivilage { 
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
    param(  
        [Pinvoke.Process_Privilege]$ProcessPrivilege
    )
    Begin{
         #Check for admin
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent())
        if($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -ne $true) {
          Throw "Run the Command as an Administrator"
        }

    }
    Process {
        
        [long]$luid = 0
        $tokPriv1Luid = New-Object Pinvoke.TokPriv1Luid
        $tokPriv1Luid.Count = 1
        $tokPriv1Luid.Luid = $luid
        $tokPriv1Luid.Attr = 2

        $retVal = [Pinvoke.advapi32]::LookupPrivilegeValue($null, $ProcessPrivilege, [ref]$tokPriv1Luid.Luid)
        Write-Verbose -message "Looking up $ProcessPrivilege - $retVal"

        [IntPtr]$CurrentToken = 0
        $retVal = [Pinvoke.advapi32]::OpenProcessToken([pinvoke.advapi32]::GetCurrentProcess(), [Pinvoke.TokenRights]::TOKEN_ALL_ACCESS, [ref]$CurrentToken)
        Write-Verbose -message "Opening current process - $retVal"
  
        $tokenPrivileges = New-Object Pinvoke.TOKEN_PRIVILEGES
        $retVal = [Pinvoke.advapi32]::AdjustTokenPrivileges($CurrentToken, $false, [ref]$tokPriv1Luid, 12, [IntPtr]::Zero, [IntPtr]::Zero)
        Write-Verbose -message "Adding Privilage $processPrivilege - $retVal"

        [IntPtr]$DupToken = 0
        $retVal = [Pinvoke.advapi32]::DuplicateToken($CurrentToken, 2, [ref]$DupToken)
        Write-Verbose -message "Making adjusted token - $retVal"

        $retval = [Pinvoke.advapi32]::SetThreadToken([IntPtr]::Zero, $DupToken)
        Write-Verbose -message "Impersonating $ProcessPrivilege - $retVal"

        if(-not($retVal)) {
            [System.Runtime.InteropServices.marshal]::GetLastWin32Error()
            Throw "Cannot open current process"
        }
			
    }
    End {

    }
}