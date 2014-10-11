using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Sodium;
using System.Management.Automation;

namespace PoSH_Sodium
{
        [Cmdlet(VerbsCommon.New, "KeyPair")]
        public class GenerateKeyPair : PSCmdlet
        {
            protected override void ProcessRecord()
            {
                if (Seed != null)
                {
                    var keypair = PublicKeyAuth.GenerateKeyPair(Seed); //throws error if seed is not 32 bytes in length
                    WriteObject(keypair);
                }
                else
                {
                    var keypair = PublicKeyAuth.GenerateKeyPair();
                    WriteObject(keypair);
                }
            }

            [Parameter(
                Mandatory = false,
                ValueFromPipelineByPropertyName = true,
                ValueFromPipeline = true,
                Position = 0,
                HelpMessage = "Seed to allow deterministic key generation")]
            public byte[] Seed;
        }

        [Cmdlet(VerbsCommon.New, "CurveKeyPair")] 
        public class GenerateCurveKeyPair : PSCmdlet
        {
            protected override void ProcessRecord()
            {
                if (PrivateKey != null)
                {
                    var keypair = PublicKeyBox.GenerateKeyPair(PrivateKey);
                    WriteObject(keypair);
                }
                else
                {
                    var keypair = PublicKeyBox.GenerateKeyPair();
                    WriteObject(keypair);
                }
            }

            [Parameter(
                Mandatory = false,
                ValueFromPipelineByPropertyName = true,
                ValueFromPipeline = true,
                Position = 0,
                HelpMessage = "Private key used for key generation")]
            public byte[] PrivateKey;
        }
}
