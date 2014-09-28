#helper script for executing pester from visual studio to use
#alternatively, run the pester.bat script from the PesterTesting Directory

$path = "D:\Code\PoSH-Sodium"
cd $path\PesterTesting

import-Module "$path\Pester\Pester.psm1"

Invoke-Pester