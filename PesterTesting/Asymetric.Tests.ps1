﻿###########################################
#
#        GenerateKeyPair Tests
#
###########################################

Describe "New-KeyPair" {
   Context "no parameter is provided" {
      It "creates a new keypair" {
         $key = New-KeyPair
		 $key.PublicKey.Length | Should Be 32
		 $key.PrivateKey.Length | Should Be 64
      }
   }
   Context "seed is provided" {
      It "fails for bad seed" {
	     [byte[]]$seed = 1..20|%{$_}
         { New-KeyPair -Seed $seed } | Should Throw
      }
      It "creates keypair for good seed" {
	     [byte[]]$seed = 1..32|%{$_}
         { New-KeyPair -Seed $seed } | Should Not Throw
		 $key = New-KeyPair -Seed $seed
		 $key.PublicKey.Length | Should Be 32
		 $key.PrivateKey.Length | Should Be 64
      }
   }
}

Describe "New-CurveKey" {
	Context "no parameter is provided" {
		It "creates a new keypair" {
			$key = New-CurveKeyPair
			$key.PublicKey.Length | Should Be 32
			$key.PrivateKey.Length | Should Be 32
		}
	}
	Context "seed is provided" {
      It "fails for bad seed" {
		 [byte[]]$seed = 1..20|%{$_}
         { New-CurveKeyPair -PrivateKey $seed } | Should Throw
      }
      It "creates keypair for good seed" {
	     [byte[]]$seed = 1..32|%{$_}
         { New-CurveKeyPair -PrivateKey $seed } | Should Not Throw
		 $key = New-CurveKeyPair -PrivateKey $seed
		 $key.PublicKey.Length | Should Be 32
		 $key.PrivateKey.Length | Should Be 32
      }
   }
}


###########################################
#
#        Sign Tests
#
###########################################


Describe "Sign-Message" {
   Context "no parameter is provided" {
      It "fails" {
         { Sign-Message } | Should Throw
      }
   }
   Context "message and key is provided" {
      It "creates signed message" {
		 $key = New-KeyPair
	     $message = sign-Message -Message "This is a test" -Key $key.PrivateKey
		 $message | Should Not BeNullOrEmpty
      }
   }
   Context "advanced options are provided" {
      It "creates raw message" {
	     $key = New-KeyPair
	     $message = sign-Message -Message "This is a test" -Key $key.PrivateKey -Raw
		 $message | Should Not BeNullOrEmpty
		 $message.GetType().Name | Should Be "Byte[]"
      }
	  It "creates signed message with specified encoding" {
	     $key = New-KeyPair
	     $message = sign-Message -Message "This is a test" -Key $key.PrivateKey -Encoding "UTF8"
		 $message | Should Not BeNullOrEmpty
      }
   }
}


###########################################
#
#        Verify Tests
#
###########################################

Describe "Verify-Message" {
   Context "no parameter is provided" {
      It "fails" {
         { Verify-Message } | Should Throw
      }
   }
   Context "signed message and key is provided" {
      It "returns plain text message" {
		 $key = New-KeyPair
	     $message = sign-Message -Message "This is a test" -Key $key.PrivateKey
		 verify-Message -Message $message -Key $key.PublicKey | Should Be "This is a test"
      }
   }
   Context "advanced options are provided" {
      It "returns raw message" {
	     $key = New-KeyPair
	     $message = sign-Message -Message "This is a test" -Key $key.PrivateKey
		 (verify-Message -Message $message -Key $key.PublicKey -Raw).GetType().Name | Should Be "Byte[]"
      }
	  It "verifies signed message with specified encoding" {
	     $key = New-KeyPair
	     $message = sign-Message -Message "This is a test" -Key $key.PrivateKey -Encoding "UTF8"
		 verify-Message -Message $message -Key $key.PublicKey -Encoding "UTF8" | Should Be "This is a test"
      }
   }
}

Describe "Verify-RawMessage" {
   Context "no parameter is provided" {
      It "fails" {
         { Verify-Message } | Should Throw
      }
   }
   Context "signed message and key is provided" {
      It "returns plain text message" {
		 $key = New-KeyPair
	     $message = sign-Message -Message "This is a test" -Key $key.PrivateKey -Raw 
		 verify-RawMessage -Message $message -Key $key.PublicKey | Should Be "This is a test"
      }
   }
   Context "advanced options are provided" {
      It "returns raw message" {
	     $key = New-KeyPair
	     $message = sign-Message -Message "This is a test" -Key $key.PrivateKey -Raw 
		 (verify-RawMessage -Message $message -Key $key.PublicKey -Raw).GetType().Name | Should Be "Byte[]"
      }
	  It "verifies signed message with specified encoding" {
	     $key = New-KeyPair
	     $message = sign-Message -Message "This is a test" -Key $key.PrivateKey -Raw -Encoding "UTF8"
		 verify-RawMessage -Message $message -Key $key.PublicKey -Encoding "UTF8" | Should Be "This is a test"
      }
   }
}