if (-not (get-Module PoSH-Sodium))
{
	if (($env:sodiumBuild) -and $env:sodiumBuild -eq "Release")
	{
		import-Module "$pwd\..\PoSH-Sodium\bin\Release\PoSH-Sodium.dll"
	}
	else
	{
		import-Module "$pwd\..\PoSH-Sodium\bin\Debug\PoSH-Sodium.dll"
	}
}

###########################################
#
#        Key Convert Tests
#
###########################################

Describe "ConvertFrom-Key" {
   Context "key is converted" {
	  It "converts key to json string" {
		 $key = New-Key
		 $outKey = $key | ConvertFrom-Key
	     $outKey.GetType().Name | Should Be "String"
	  }
	  It "converts keypair to json string" {
		 $key = New-KeyPair
		 $outKey = $key | ConvertFrom-Key
	     $outKey.GetType().Name | Should Be "String"
	  }
	  It "converts curve keypair to json string" {
		 $key = New-CurveKeyPair
		 $outKey = $key | ConvertFrom-Key
	     $outKey.GetType().Name | Should Be "String"
	  }
   }
}