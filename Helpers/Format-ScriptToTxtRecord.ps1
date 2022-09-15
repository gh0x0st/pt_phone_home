function Format-ScriptToTxtRecord() {
    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $True, Position = 0)]
        [System.String]$Path,
        [Parameter(Mandatory = $True, Position = 1)]
        [System.String]$Name
    )
    Begin {
        $Script = [System.IO.File]::ReadLines("$Path")
        $Output = @()
        $Iterations = 1
    }
    Process {
        ForEach ($S in $Script) {
            $Output += 'txt-record={0}.{1},"{2}"' -f $Iterations, $Name, $S
            $Iterations += 1 
        }
        $Output += 'txt-record={0},"{1}"' -f $Name, $($Iterations - 1)
    }
    End {
        return $Output
    }
}
