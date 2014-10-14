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
#        GenerateKey Tests
#
###########################################

Describe "New-Key" {
   Context "no parameter is provided" {
	  It "creates a new key" {
		 $key = New-Key
		 $key.Length | Should Be 32
	  }
   }
}

###########################################
#
#        Encrypt Tests
#
###########################################

Describe "Encrypt-SymmetricMessage" {
   Context "no parameter is provided" {
	  It "fails" {
		 { Encrypt-SymmetricMessage } | Should Throw
	  }
   }
   Context "message and keys are provided" {
	  It "returns encrypted message" {
		 $key = New-Key		 
		 $message = Encrypt-SymmetricMessage -Message "This is a test" -Key $key
		 $message | Should Not BeNullOrEmpty
	  }
   }
   Context "advanced options are provided" {
	  It "returns raw encrypted message" {
		 $key = New-Key
		 $message = Encrypt-SymmetricMessage -Message "This is a test" -Key $key -Raw 
		 $message.Message.GetType().Name | Should Be "Byte[]"
	  }
   }
}


###########################################
#
#        Sign Tests
#
###########################################

Describe "Sign-SymmetricMessage" {
   Context "no parameter is provided" {
	  It "fails" {
		 { Sign-SymmetricMessage } | Should Throw
	  }
   }
   Context "message and key is provided" {
	  It "creates signed message" {
		 $key = New-Key
		 $message = sign-SymmetricMessage -Message "This is a test" -Key $key
		 $message | Should Not BeNullOrEmpty
	  }
   }
   Context "advanced options are provided" {
	  It "creates raw message" {
		 $key = New-Key
		 $message = sign-SymmetricMessage -Message "This is a test" -Key $key -Raw
		 $message | Should Not BeNullOrEmpty
		 $message.Signature.GetType().Name | Should Be "Byte[]"
		 $message.Signature.Length | Should be 32
	  }
	  It "creates signed message with specified encoding" {
		 $key = New-Key
		 $message = sign-SymmetricMessage -Message "This is a test" -Key $key -Encoding "UTF8"
		 $message | Should Not BeNullOrEmpty
	  }
	  It "Creates signed message with HmacSha512" {
		 $key = New-Key
		 $message = sign-SymmetricMessage -Message "This is a test" -Key $key -HashType HmacSha512
		 $message | Should Not BeNullOrEmpty
	  }
	  It "Creates signed message with HmacSha256" {
		 $key = New-Key
		 $message = sign-SymmetricMessage -Message "This is a test" -Key $key -HashType HmacSha256
		 $message | Should Not BeNullOrEmpty
	  }
   }
}

###########################################
#
#        Verify Tests
#
###########################################

Describe "Verify-SymmetricMessage" {
   Context "no parameter is provided" {
	  It "fails" {
		 { Verify-SymmetricMessage } | Should Throw
	  }
   }
   Context "message and key is provided" {
	  It "verifies signed message" {
		 $key = New-Key
		 $message = sign-SymmetricMessage -Message "This is a test" -Key $key
		 Verify-SymmetricMessage -message $message.Message -Key $key -Signature $message.Signature | Should be $true
	  }
   }
   Context "advanced options are provided" {
	  It "verifies signed message with specified encoding" {
		 $key = New-Key
		 $message = sign-SymmetricMessage -Message "This is a test" -Key $key -Encoding "UTF8"
		 Verify-SymmetricMessage -message $message.Message -Key $key -Signature $message.Signature -Encoding "UTF8" | Should be $true
	  }
	  It "verifies signed message with HmacSha512" {
		 $key = New-Key
		 $message = sign-SymmetricMessage -Message "This is a test" -Key $key -HashType HmacSha512
		 Verify-SymmetricMessage -message $message.Message -Key $key -Signature $message.Signature -HashType HmacSha512 | Should be $true
	  }
	  It "verifies signed message with HmacSha256" {
		 $key = New-Key
		 $message = sign-SymmetricMessage -Message "This is a test" -Key $key -HashType HmacSha256
		 Verify-SymmetricMessage -message $message.Message -Key $key -Signature $message.Signature -HashType HmacSha256 | Should be $true
	  }
   }
}

Describe "Verify-RawSymmetricMessage" {
   Context "no parameter is provided" {
	  It "fails" {
		 { Verify-RawSymmetricMessage } | Should Throw
	  }
   }
   Context "message and key is provided" {
	  It "verifies signed message" {
		 $key = New-Key
		 $message = sign-SymmetricMessage -Message "This is a test" -Key $key -Raw
		 Verify-RawSymmetricMessage -message $message.Message -Key $key -Signature $message.Signature | Should be $true
	  }
   }
   Context "advanced options are provided" {
	  It "verifies signed message with specified encoding" {
		 $key = New-Key
		 $message = sign-SymmetricMessage -Message "This is a test" -Key $key -Encoding "UTF8" -Raw
		 Verify-RawSymmetricMessage -message $message.Message -Key $key -Signature $message.Signature -Encoding "UTF8" | Should be $true
	  }
	  It "verifies signed message with HmacSha512" {
		 $key = New-Key
		 $message = sign-SymmetricMessage -Message "This is a test" -Key $key -HashType HmacSha512 -Raw
		 Verify-RawSymmetricMessage -message $message.Message -Key $key -Signature $message.Signature -HashType HmacSha512 | Should be $true
	  }
	  It "verifies signed message with HmacSha256" {
		 $key = New-Key
		 $message = sign-SymmetricMessage -Message "This is a test" -Key $key -HashType HmacSha256 -Raw
		 Verify-RawSymmetricMessage -message $message.Message -Key $key -Signature $message.Signature -HashType HmacSha256 | Should be $true
	  }
   }
}

###########################################
#
#        Decrypt Tests
#
###########################################

Describe "Decrypt-SymmetricMessage" {
   Context "no parameter is provided" {
	  It "fails" {
		 { Decrypt-SymmetricMessage } | Should Throw
	  }
   }
   Context "message and keys are provided" {
	  It "returns decrypted message" {
		 $key = New-Key		 
		 $secretMessage = Encrypt-SymmetricMessage -Message "This is a test" -Key $key
		 $message = Decrypt-SymmetricMessage -Message $secretMessage.Message -key $key -Nonce $secretMessage.Nonce
		 $message | Should be "This is a test"
	  }
	  It "returns decrypted message per encoding" {
		 $key = New-Key		 
		 $secretMessage = Encrypt-SymmetricMessage -Message "This is a test" -key $key -Encoding "UTF8"
		 $message = Decrypt-SymmetricMessage -Message $secretMessage.Message -key $key -Nonce $secretMessage.Nonce -Encoding "UTF8"
		 $message | Should be "This is a test"
	  }
   }
}

Describe "Decrypt-RawSymmetricMessage" {
   Context "no parameter is provided" {
	  It "fails" {
		 { Decrypt-RawSymmetricMessage } | Should Throw
	  }
   }
   Context "message and keys are provided" {
	  It "returns decrypted message" {
		 $key = New-Key		 
		 $secretMessage = Encrypt-SymmetricMessage -Message "This is a test" -Key $key -Raw
		 $message = Decrypt-RawSymmetricMessage -Message $secretMessage.Message -key $key -Nonce $secretMessage.Nonce
		 $message | Should be "This is a test"
	  }
	  It "returns decrypted message per encoding" {
		 $key = New-Key		 
		 $secretMessage = Encrypt-SymmetricMessage -Message "This is a test" -key $key -Encoding "UTF8" -Raw
		 $message = Decrypt-RawSymmetricMessage -Message $secretMessage.Message -key $key -Nonce $secretMessage.Nonce -Encoding "UTF8"
		 $message | Should be "This is a test"
	  }
   }
}