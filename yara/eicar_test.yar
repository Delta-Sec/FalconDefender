rule EICAR_Test_File
{
    meta:
        description = "Detects the EICAR standard anti-virus test file"
    strings:
        $eicar_string = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar_string at 0
}
