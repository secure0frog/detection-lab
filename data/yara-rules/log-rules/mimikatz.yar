rule Mimikatz_CommandLine {
    meta:
        description = "Detects Mimikatz command patterns in logs"
        technique_id = "T1003.001"
        severity = "critical"

    strings:
        $m1 = "sekurlsa::logonpasswords" nocase
        $m2 = "lsadump::dcsync" nocase
        $m3 = "privilege::debug" nocase
        $m4 = "token::elevate" nocase
        $m5 = "lsadump::sam" nocase
        $m6 = "sekurlsa::pth" nocase

    condition:
        any of them
}

rule LSASS_Access_Pattern {
    meta:
        description = "Detects LSASS memory access patterns"
        technique_id = "T1003.001"
        severity = "high"

    strings:
        $lsass = "lsass.exe" nocase
        $access1 = "PROCESS_VM_READ" nocase
        $access2 = "procdump" nocase
        $access3 = "MiniDump" nocase
        $access4 = "comsvcs.dll" nocase

    condition:
        $lsass and any of ($access*)
}
