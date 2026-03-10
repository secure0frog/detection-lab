rule Suspicious_PE_File {
    meta:
        description = "Detects PE executable files (MZ header)"
        technique_id = "T1204.002"
        severity = "medium"

    condition:
        uint16(0) == 0x5A4D
}

rule Suspicious_ELF_File {
    meta:
        description = "Detects ELF executable files"
        technique_id = "T1204.002"
        severity = "medium"

    condition:
        uint32(0) == 0x464C457F
}
