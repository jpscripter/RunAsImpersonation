Function Get-TokenInformation { 
<#
.SYNOPSIS
Returns token information using win32API

.DESCRIPTION
Returns selected information from a token api.

.PARAMETER Token
Pointer or Windows Identity to Duplicate

.PARAMETER TokenInformationClass
Token Permissions for Querying, adjusting, creating or impersonating other tokens
https://docs.microsoft.com/en-us/dotnet/api/system.security.principal.tokenaccesslevels?view=net-6.0

.EXAMPLE
PS> 
    Import-Module .\RunAsImpersonation\
    $token = [System.Security.Principal.WindowsIdentity]::GetCurrent().Token
    [Pinvoke.TOKEN_INFORMATION_CLASS] $TokenInformationClass = [Pinvoke.TOKEN_INFORMATION_CLASS]::TokenGroups

    Get-TokenInformation -Token $token

.LINK
http://www.JPScripter.com/extension.html

#>
param(
    [object]$Token,
    [Pinvoke.TOKEN_INFORMATION_CLASS] $TokenInformationClass = [Pinvoke.TOKEN_INFORMATION_CLASS]::TokenGroups

)
        #Convert Token
        if ($Null -eq $token){
            $Token = (Get-TokenInfo).Token
        }Else{
            Switch ($Token.GetType().Name) 
            {
                'IntPtr'{ 
                    Break
                }
                'WindowsIdentity'{
                    $Token = $Token.Token
                    Break
                }
                Default {
                    Throw 'Token must be a WidnowsIdentity or intPtr Object'
                }
            }
        }
        #Get buffer length first
        [int]$TokenInfoLength = 0
        #always fails the first time but the length gets updated.
        $null = [Pinvoke.advapi32]::GetTokenInformation($token,$TokenInformationClass,[System.IntPtr]::Zero, $TokenInfoLength, [ref] $TokenInfoLength)
        if ($TokenInfoLength -ne 0){
            $InfoPointer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenInfoLength)
        }else{
            $Lasterr = ([System.ComponentModel.Win32Exception][System.Runtime.InteropServices.Marshal]::GetHRForLastWin32Error()).message
            Write-Error -Message "Failed Get token information size $lasterr"
        }
        $success = [Pinvoke.advapi32]::GetTokenInformation($token,$TokenInformationClass, $InfoPointer, $TokenInfoLength, [ref] $TokenInfoLength)
        if (-not $Success){
            $Lasterr = ([System.ComponentModel.Win32Exception][System.Runtime.InteropServices.Marshal]::GetHRForLastWin32Error()).message
            Write-Error -Message "Failed to retrieve information pointer $lasterr"
        }
        $InfoPointer
        $userStruc = [System.Runtime.InteropServices.Marshal]::PtrToStructure($InfoPointer,[type][Pinvoke.TOKEN_USER])
        [IntPtr] $userSid = [IntPtr]::Zero
        $Success = [Pinvoke.advapi32]::ConvertSidToStringSid($userStruc.user.Sid,[ref]$userSid)
        if ($userSid -eq [intptr]::Zero){
           $Lasterr = ([System.ComponentModel.Win32Exception][System.Runtime.InteropServices.Marshal]::GetHRForLastWin32Error()).message
            Write-Error -Message "Failed to format sid $lasterr"
        }

        $offset = 0
        $length = 28
        $stringBuilder = New-Object System.Text.StringBuilder -ArgumentList $Length
        $ptr = $userStruc.user.Sid.toint64()
        For ($i = $offset; $I -le $Length*2+$offset ; $I+=[System.Text.UnicodeEncoding]::CharSize){
            $b1 =  [System.Runtime.InteropServices.marshal]::ReadByte($ptr,$i) 
            #$b2 =  [System.Runtime.InteropServices.marshal]::ReadByte($ptr,$i+1) 
            $currentChar = [System.BitConverter]::ToChar(($b1,$b2),0)
        # if($currentChar -eq [char]::MinValue) { break; }
            [void]$stringBuilder.Append($currentChar)
            Write-output  "$i = $currentChar - $b1 - $b2"
            pause
        }

}