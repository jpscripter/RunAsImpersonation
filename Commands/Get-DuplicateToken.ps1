Function Get-DuplicateToken { 
<#
.SYNOPSIS
Creates a copy of the token for use in impersonation or logon

.DESCRIPTION
Uses either a pointer or windows Identity object to make a new duplicate token  for login or impersonation

.PARAMETER Token
Pointer or Windows Identity to Duplicate

.PARAMETER TokenAccess
Token Permissions for Querying, adjusting, creating or impersonating other tokens
https://docs.microsoft.com/en-us/dotnet/api/system.security.principal.tokenaccesslevels?view=net-6.0

.PARAMETER ImpersionationLevel
The new tokens Impersonation level for future impersonations
https://docs.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels

.PARAMETER Token
Pointer or Windows Identity to Duplicate

.EXAMPLE
PS> 
    Get-DuplicateToken -Token $TokenPtr

.LINK
http://www.JPScripter.com/extension.html

#>
param(
    [object]$Token,
    [System.Security.Principal.TokenAccessLevels] $TokenAccess = [System.Security.Principal.TokenAccessLevels]::MaximumAllowed,
    [pinvoke.SECURITY_IMPERSONATION_LEVEL] $ImpersionationLevel = [pinvoke.SECURITY_IMPERSONATION_LEVEL]::SecurityImpersonation,
    [pinvoke.TOKEN_TYPE] $TokenType = [pinvoke.TOKEN_TYPE]::TokenImpersonation,
    [Switch]$returnPointer
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
        #impersonate the token
        [intptr] $ImpersonationToken = 0
        $SecurityAttibutes = New-object pinvoke.SECURITY_ATTRIBUTES
        $SecurityAttibutes.nLength = [System.Runtime.InteropServices.Marshal]::SizeOf($SecurityAttibutes)
        $status = [Pinvoke.advapi32]::DuplicateTokenEx($Token, $Access, [ref] $SecurityAttibutes,$ImpersionationLevel, $TokenType, [ref] $ImpersonationToken)

        #return
        if ($status){
            Write-Verbose -Message "Found Token for system"
            if ($returnPointer.IsPresent){
                $ImpersonationToken
            }Else{
                Get-TokenInfo -Token $ImpersonationToken
            }

        }else{
            Throw "Failed to duplicate token"
        }

}