$ModuleInfo = Import-PowerShellDataFile -Path "$PSScriptRoot\RunAsImpersonation.psd1"

if (Test-Path -Path $PSScriptRoot\Classes\){
    $Class = Get-ChildItem -Path $PSScriptRoot\Classes\*.cs -file -Recurse
    $references = @()
    Foreach($CLS in $Class){
	    Write-Verbose -Message "Class File: $CLS"  
	    $Content = Get-Content -raw -path $CLS
        $FilePath = "$env:Tmp\Pinvoke.$($cls.BaseName)-$($ModuleInfo.ModuleVersion).dll"
        Remove-Item -path $FilePath -ErrorAction Ignore
        if (Test-Path -Path $FilePath){
            Add-Type -Path $FilePath -ReferencedAssemblies $references
        }else{
            Write-Verbose -Message "Compliling Class File: $CLS -with Unsafe"  
            if ($PSVersionTable.PSVersion.Major -lt 6){
                $cp = New-Object System.CodeDom.Compiler.CompilerParameters
                $cp.CompilerOptions = '/unsafe'
                $Options = @{CompilerParameters =  $cp}
            }else{
                $Options = @{CompilerOptions =  '/unsafe'}
            }
            $null = Add-Type -TypeDefinition $Content @Options -ReferencedAssemblies $references -OutputAssembly $FilePath -Passthru
        }
        $references += $FilePath
    }
}

if (Test-Path -Path $PSScriptRoot\Commands\){
    $Commands = Get-ChildItem -Path $PSScriptRoot\Commands\*.ps1 -file -Recurse
    Foreach($CMD in $Commands){
	    Write-Verbose -Message "Cmdlet File: $CMD"  
	    . $CMD
    }
}