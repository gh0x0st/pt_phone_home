function Find-LongLines() {
    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $True, Position = 0)]
        [System.String]$Path,
        [Parameter(Mandatory = $False, Position = 1)]
        [System.Int32]$Length = 255
    )
    Begin {
        $Script = [System.IO.File]::ReadLines("$Path")
        $Output = @()
        $Line = 1
    }
    Process {
        ForEach ($S in $Script) {
            If ($S.Length -ge $Length) {
                $Output += "[*] Line $Line >> $S"
            }
            $Line += 1
        }   
    }
    End {
        if ($Output) {
            Write-Output ""
            return $Output
        }
        else {
            Write-Output "[*] This script doesn't contain any lines exceeding $Length characters"
        }
    }
}
