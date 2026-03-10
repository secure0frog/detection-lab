rule Registry_Run_Key_Persistence {
    meta:
        description = "Detects registry Run key modification for persistence"
        technique_id = "T1547.001"
        severity = "high"

    strings:
        $run1 = "CurrentVersion\\Run" nocase
        $run2 = "CurrentVersion\\RunOnce" nocase
        $run3 = "CurrentVersion\\RunServices" nocase
        $cmd1 = "reg add" nocase
        $cmd2 = "Set-ItemProperty" nocase
        $cmd3 = "New-ItemProperty" nocase

    condition:
        any of ($run*) and any of ($cmd*)
}
