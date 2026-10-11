rule EICAR_Test_File
{
    meta:
        description = "Fichier de test EICAR (inoffensif)"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"
    condition:
        $eicar
}
