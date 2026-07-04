/*
  IRONYX Process Guard — Sample YARA Rule
  ========================================
  Detects executables in /tmp or /dev/shm that contain
  suspicious patterns commonly found in keylogger binaries.

  NOTE: This rule is for DETECTION ONLY. It does NOT capture
  keystrokes or perform any interception.
*/

rule IRONYX_Suspicious_Tmp_Executable
{
    meta:
        description = "Executable in /tmp with suspicious imports"
        author      = "IRONYX Security"
        date        = "2025-01-01"
        severity    = "high"

    strings:
        $s1 = "/dev/input/event" ascii
        $s2 = "/dev/uinput" ascii
        $s3 = "O_RDONLY" ascii
        $s4 = "EV_KEY" ascii
        $s5 = "read(" ascii
        $s6 = "/tmp/" ascii
        $s7 = "/dev/shm/" ascii

    condition:
        uint16(0) == 0x457f and  // ELF magic
        ($s1 or $s2) and
        ($s3 or $s4) and
        ($s6 or $s7)
}
