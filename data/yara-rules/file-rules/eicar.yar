rule EICAR_Test_File {
    meta:
        description = "Matches the EICAR antivirus test file"
        reference = "https://www.eicar.org/download-anti-malware-testfile/"
        technique_id = "N/A"
        severity = "info"

    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    condition:
        $eicar
}
