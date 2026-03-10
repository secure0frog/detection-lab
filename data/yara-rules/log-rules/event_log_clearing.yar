rule Event_Log_Clearing {
    meta:
        description = "Detects Windows event log clearing commands"
        technique_id = "T1070.001"
        severity = "high"

    strings:
        $cl1 = "Clear-EventLog" nocase
        $cl2 = "wevtutil cl" nocase
        $cl3 = "wevtutil clear-log" nocase
        $cl4 = "Remove-EventLog" nocase

    condition:
        any of them
}
