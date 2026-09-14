/*
starter rules for the HTTP-object scanner. anything read_http() pulls out
of captured traffic gets checked against every .yar/.yara file in this
folder - add your own, doesn't need to just be these two.
*/

rule EICAR_Test_File
{
    meta:
        description = "the standard antivirus test string - not real malware, just useful for confirming the scan pipeline actually works end to end"
        reference = "https://www.eicar.org/download-anti-malware-testfile/"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule PE_FILE_HEADER
{
    meta:
        description = "flags embedded/extracted Windows executables (PE files)"
        reference = "https://www.nextron-systems.com/2018/01/22/write-yara-rules-detect-embedded-exe-files-ole-objects/"
    strings:
        $dos_stub = "This program cannot be run in DOS mode"
        $kernel32 = "KERNEL32.dll" nocase
        $mz_header = { 4D 5A 40 00 } // MZ@
    condition:
        any of them
}
