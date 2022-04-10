if (Test-Path -Path $PSScriptRoot\Classes\){
    $Class = Get-ChildItem -Path $PSScriptRoot\Classes\*.cs -file -Recurse
    Foreach($CLS in $Class){
	    Write-Verbose -Message "Class File: $CLS"  
	    $Content = Get-Content -raw -path $CLS
	    Write-Verbose -Message "Class File: $CLS -with Unsafe"  
        if ($PSVersionTable.PSVersion.Major -lt 6){
            $cp = New-Object System.CodeDom.Compiler.CompilerParameters
            $cp.CompilerOptions = '/unsafe'
            $Options = @{CompilerParameters =  $cp}
        }else{
            $Options = @{CompilerOptions =  '/unsafe'}
        }
        Add-Type -TypeDefinition $Content @Options
    }
}


if (Test-Path -Path $PSScriptRoot\Commands\){
    $Commands = Get-ChildItem -Path $PSScriptRoot\Commands\*.ps1 -file -Recurse
    Foreach($CMD in $Commands){
	    Write-Verbose -Message "Cmdlet File: $CMD"  
	    . $CMD
    }
}