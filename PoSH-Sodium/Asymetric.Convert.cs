using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Management.Automation;
using Sodium;

namespace PoSH_Sodium
{
    [Cmdlet(VerbsData.ConvertTo, "CurveKey")]
    public class ConvertPublic : PSCmdlet
    {
        protected override void ProcessRecord()
        {
            if (ParameterSetName == "KeyPair")
            {
                KeyPair.PublicKey = PublicKeyAuth.ConvertEd25519PublicKeyToCurve25519PublicKey(KeyPair.PublicKey.ToByteArrayFromBase64String()).ToBase64String();
                KeyPair.PrivateKey = PublicKeyAuth.ConvertEd25519SecretKeyToCurve25519SecretKey(KeyPair.PrivateKey.ToByteArrayFromBase64String()).ToBase64String();
                KeyPair.KeyType = "Curve25519";
                WriteObject(KeyPair);
            }
            else if (ParameterSetName == "PublicKey")
            {
                PublicKey.PublicKey = PublicKeyAuth.ConvertEd25519PublicKeyToCurve25519PublicKey(PublicKey.PublicKey.ToByteArrayFromBase64String()).ToBase64String();
                PublicKey.KeyType = "Curve25519";
                WriteObject(PublicKey);
            }
            else if (ParameterSetName == "PrivateKey")
            {
                PrivateKey.PrivateKey = PublicKeyAuth.ConvertEd25519SecretKeyToCurve25519SecretKey(PrivateKey.PrivateKey.ToByteArrayFromBase64String()).ToBase64String();
                PrivateKey.KeyType = "Curve25519";
                WriteObject(PublicKey);
            }
            
        }

        [Parameter(
            ParameterSetName = "KeyPair",
            Mandatory = true,
            ValueFromPipeline = true,
            Position = 0,
            HelpMessage = "Ed25519 public key to convert")]
        public SodiumKeyPair KeyPair;

        [Parameter(
            ParameterSetName = "PublicKey",
            Mandatory = true,
            ValueFromPipeline = true,
            Position = 0,
            HelpMessage = "Ed25519 public key to convert")]
        public SodiumPublicKey PublicKey;

        [Parameter(
            ParameterSetName = "PrivateKey",
            Mandatory = true,
            ValueFromPipeline = true,
            Position = 0,
            HelpMessage = "Ed25519 private key to convert")]
        public SodiumPrivateKey PrivateKey;
    }

}
