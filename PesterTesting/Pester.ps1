$path = "D:\Code\PoSH-Sodium"
cd $path\PesterTesting

import-Module "$path\Pester\Pester.psm1"
import-Module "$path\PoSH-Sodium\bin\Debug\PoSH-Sodium.dll"

Invoke-Pester