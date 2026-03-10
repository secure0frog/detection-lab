rule PsExec_Lateral_Movement {
    meta:
        description = "Detects PsExec usage for lateral movement"
        technique_id = "T1021.002"
        severity = "high"

    strings:
        $ps1 = "psexec" nocase
        $ps2 = "PSEXESVC" nocase
        $ps3 = "\\\\ADMIN$" nocase
        $ps4 = "\\\\C$" nocase
        $ps5 = "\\\\IPC$" nocase
        $net1 = "net use" nocase

    condition:
        any of ($ps*) or ($net1 and any of ($ps*))
}

rule WMI_Lateral_Movement {
    meta:
        description = "Detects WMI-based lateral movement"
        technique_id = "T1021.002"
        severity = "medium"

    strings:
        $wmi1 = "wmic" nocase
        $wmi2 = "/node:" nocase
        $wmi3 = "Invoke-WmiMethod" nocase
        $wmi4 = "Win32_Process" nocase
        $wmi5 = "process call create" nocase

    condition:
        ($wmi1 and $wmi2) or $wmi3 or ($wmi4 and $wmi5)
}
