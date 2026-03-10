rule Suspicious_Scheduled_Task {
    meta:
        description = "Detects suspicious scheduled task creation"
        technique_id = "T1053.005"
        severity = "medium"

    strings:
        $st1 = "schtasks" nocase
        $st2 = "/create" nocase
        $st3 = "Register-ScheduledTask" nocase
        $st4 = "New-ScheduledTask" nocase

    condition:
        ($st1 and $st2) or $st3 or $st4
}
