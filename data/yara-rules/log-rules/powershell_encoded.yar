rule Encoded_PowerShell_Command {
    meta:
        description = "Detects base64-encoded PowerShell execution in logs"
        technique_id = "T1059.001"
        severity = "high"

    strings:
        $enc1 = "-EncodedCommand" nocase
        $enc2 = "-enc " nocase
        $enc3 = "FromBase64String" nocase
        $ps = "powershell" nocase

    condition:
        $ps and any of ($enc*)
}

rule PowerShell_Download_Cradle {
    meta:
        description = "Detects PowerShell download cradle patterns"
        technique_id = "T1059.001"
        severity = "high"

    strings:
        $dl1 = "Net.WebClient" nocase
        $dl2 = "DownloadString" nocase
        $dl3 = "DownloadFile" nocase
        $dl4 = "Invoke-WebRequest" nocase
        $dl5 = "iwr " nocase
        $dl6 = "wget " nocase
        $dl7 = "curl " nocase
        $iex1 = "Invoke-Expression" nocase
        $iex2 = "IEX" nocase

    condition:
        any of ($dl*) and any of ($iex*)
}
