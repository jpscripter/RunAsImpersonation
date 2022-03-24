Function Invoke-JPSRunasScriptBlock { 
<#
.SYNOPSIS
Uses a PSCredential object to build a token 

.DESCRIPTION
Uses the PSCredential and win32 apis to log the user in and create a local or network only token

.PARAMETER Credential
Credential to execute the scriptblock as

.PARAMETER Token
How this credential will log in (Default is NetOnly but Interactive is also common)


.PARAMETER ScriptBlock
How this credential will log in (Default is NetOnly but Interactive is also common)

.EXAMPLE
PS> 


.LINK
http://www.JPScripter.com

#>
    param(  
        [Parameter(Position = 0, Mandatory = $true, ParameterSetName = "Credential")]
        [PSCredential]$Credential, 
        [Parameter( ParameterSetName = "Credential")]
        [Switch]$NetOnly,
        [Parameter(ParameterSetName = "Token")]
        [intptr]$Token = 0,
        [scriptblock]$ScriptBlock,
        [hashtable]$Parameters
    )
    Begin{
        $LogonType = [Pinvoke.dwLogonType]::Interactive
        if ($NetOnly.IsPresent){[Pinvoke.dwLogonType]::NewCredentials}
        if ($null -NE $Credential){
            $token = Get-JPSRunasCredentialToken -Credential $Credential -LogonType $LogonType
        }
    }
    Process {
        $runspace = [runspacefactory]::CreateRunspace([initialSessionState]::CreateDefault())
        $runspace.open()
        $Powershell = [powershell]::create($runspace)
        $Null = $Powershell.AddScript({param($module)Import-Module $module})
        $Null = $Powershell.AddParameter('module','E:\Repos\Modules\JPSRunAs')
        $Null = $Powershell.AddScript({Param($token)Set-JPSRunAsImpersonation -Token $Token})
        $Null = $Powershell.AddParameter('Token',$token)

        # Running scriptblock
        foreach ($Param in $Parameters.keys){
            $Null = $Powershell.AddParameter($Param,$Parameters[$Param])
        }
        $Null = $Powershell.AddScript($ScriptBlock)
        $Null = $powershell.Invoke()
        $Powershell.Streams
    }
    End {

    }
}