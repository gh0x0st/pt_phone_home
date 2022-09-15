function Format-StringToTxtRecord() {
    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $True, Position = 0)]
        [System.String]$String,
        [Parameter(Mandatory = $True, Position = 1)]
        [System.String]$Name,
        [Parameter(Mandatory = $False, Position = 2)]
        [System.Int32]$Characters = 255
    )
    Begin {
        $CharArray = $String.ToCharArray()
        $Output = @()
        $Line = ''
        $Iterations = 1
    }
    Process {
        for ($Count = 0; $Count -lt $CharArray.Count; $Count++) {
            $line += $CharArray[$Count]           
            if (($Count + 1) % $Characters -eq 0) {
                $Output += 'txt-record={0}.{1},"{2}"' -f $Iterations, $Name, $Line
                $Line = ''
                $Iterations += 1
            }  
        }
        $Output += 'txt-record={0}.{1},"{2}"' -f $Iterations, $Name, $Line
        $Output += 'txt-record={0},"{1}"' -f $Name, $Iterations
    }
    End {
        return $Output
    }
}
