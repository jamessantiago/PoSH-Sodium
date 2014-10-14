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
#        Encrypt Tests
#
###########################################

Describe "Encrypt-ChaChaMessage" {
   Context "no parameter is provided" {
	  It "fails" {
		 { Encrypt-ChaChaMessage } | Should Throw
	  }
   }
   Context "message and keys are provided" {
	  It "returns encrypted message" {
		 $key = New-Key		 
		 $message = Encrypt-ChaChaMessage -Message "This is a test" -Key $key
		 $message | Should Not BeNullOrEmpty
	  }
   }
   Context "advanced options are provided" {
	  It "returns raw encrypted message" {
		 $key = New-Key
		 $message = Encrypt-ChaChaMessage -Message "This is a test" -Key $key -Raw 
		 $message.Message.GetType().Name | Should Be "Byte[]"
	  }
   }
}

###########################################
#
#        Decrypt Tests
#
###########################################

Describe "Decrypt-ChaChaMessage" {
   Context "no parameter is provided" {
	  It "fails" {
		 { Decrypt-ChaChaMessage } | Should Throw
	  }
   }
   Context "message and keys are provided" {
	  It "returns decrypted message" {
		 $key = New-Key		 
		 $secretMessage = Encrypt-ChaChaMessage -Message "This is a test" -Key $key
		 $message = Decrypt-ChaChaMessage -Message $secretMessage.Message -key $key -Nonce $secretMessage.Nonce
		 $message | Should be "This is a test"
	  }
	  It "returns decrypted message per encoding" {
		 $key = New-Key		 
		 $secretMessage = Encrypt-ChaChaMessage -Message "This is a test" -key $key -Encoding "UTF8"
		 $message = Decrypt-ChaChaMessage -Message $secretMessage.Message -key $key -Nonce $secretMessage.Nonce -Encoding "UTF8"
		 $message | Should be "This is a test"
	  }
   }
}

Describe "Decrypt-RawChaChaMessage" {
   Context "no parameter is provided" {
	  It "fails" {
		 { Decrypt-RawChaChaMessage } | Should Throw
	  }
   }
   Context "message and keys are provided" {
	  It "returns decrypted message" {
		 $key = New-Key		 
		 $secretMessage = Encrypt-ChaChaMessage -Message "This is a test" -Key $key -Raw
		 $message = Decrypt-RawChaChaMessage -Message $secretMessage.Message -key $key -Nonce $secretMessage.Nonce
		 $message | Should be "This is a test"
	  }
	  It "returns decrypted message per encoding" {
		 $key = New-Key		 
		 $secretMessage = Encrypt-ChaChaMessage -Message "This is a test" -key $key -Encoding "UTF8" -Raw
		 $message = Decrypt-RawChaChaMessage -Message $secretMessage.Message -key $key -Nonce $secretMessage.Nonce -Encoding "UTF8"
		 $message | Should be "This is a test"
	  }
   }
}