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
                    var sKey = new SodiumKeyPair()
                    {
                        Info = this.Info,
                        KeyType = "Ed25519",
                        PrivateKey = keypair.PrivateKey.ToBase64String(),
                        PublicKey = keypair.PublicKey.ToBase64String()
                    };
                    WriteObject(sKey);
                }
                else
                {
                    var keypair = PublicKeyAuth.GenerateKeyPair();
                    var sKey = new SodiumKeyPair()
                    {
                        Info = this.Info,
                        KeyType = "Ed25519",
                        PrivateKey = keypair.PrivateKey.ToBase64String(),
                        PublicKey = keypair.PublicKey.ToBase64String()
                    };
                    WriteObject(sKey);
                }
            }

            [Parameter(
                Mandatory = false,
                ValueFromPipelineByPropertyName = true,
                ValueFromPipeline = true,
                Position = 0,
                HelpMessage = "Seed to allow deterministic key generation")]
            public byte[] Seed;

            [Parameter(
                Mandatory = false,
                ValueFromPipelineByPropertyName = true,
                ValueFromPipeline = true,
                Position = 1,
                HelpMessage = "Optional information to describe key")]
            public string Info;
        }

        [Cmdlet(VerbsCommon.New, "CurveKeyPair")] 
        public class GenerateCurveKeyPair : PSCmdlet
        {
            protected override void ProcessRecord()
            {
                if (PrivateKey != null)
                {
                    var keypair = PublicKeyBox.GenerateKeyPair(PrivateKey);
                    var sKey = new SodiumKeyPair()
                    {
                        Info = this.Info,
                        KeyType = "Curve25519",
                        PrivateKey = keypair.PrivateKey.ToBase64String(),
                        PublicKey = keypair.PublicKey.ToBase64String()
                    };
                    WriteObject(sKey);
                }
                else
                {
                    var keypair = PublicKeyBox.GenerateKeyPair();
                    var sKey = new SodiumKeyPair()
                    {
                        Info = this.Info,
                        KeyType = "Curve25519",
                        PrivateKey = keypair.PrivateKey.ToBase64String(),
                        PublicKey = keypair.PublicKey.ToBase64String()
                    };
                    WriteObject(sKey);
                }
            }

            [Parameter(
                Mandatory = false,
                ValueFromPipelineByPropertyName = true,
                ValueFromPipeline = true,
                Position = 0,
                HelpMessage = "Private key used for key generation")]
            public byte[] PrivateKey;

            [Parameter(
                Mandatory = false,
                ValueFromPipelineByPropertyName = true,
                ValueFromPipeline = true,
                Position = 1,
                HelpMessage = "Optional information to describe key")]
            public string Info;
        }
}
