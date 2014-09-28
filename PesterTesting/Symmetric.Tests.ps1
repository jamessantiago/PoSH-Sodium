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