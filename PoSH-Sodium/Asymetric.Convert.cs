using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Management.Automation;
using Sodium;

namespace PoSH_Sodium
{
    [Cmdlet(VerbsData.Convert, "PublicKey")]
    public class ConvertPublic : PSCmdlet
    {
        protected override void ProcessRecord()
        {
            var pubKey = PublicKeyAuth.ConvertEd25519PublicKeyToCurve25519PublicKey(PublicKey);
            WriteObject(pubKey);
        }

        [Parameter(
            Mandatory = true,
            ValueFromPipelineByPropertyName = true,
            Position = 0,
            HelpMessage = "Ed25519 public key to convert")]
        public byte[] PublicKey;
    }

    [Cmdlet(VerbsData.Convert, "PrivateKey")]
    public class ConvertPublic : PSCmdlet
    {
        protected override void ProcessRecord()
        {
            var pubKey = PublicKeyAuth.ConvertEd25519SecretKeyToCurve25519SecretKey(PrivateKey);
            WriteObject(pubKey);
        }

        [Parameter(
            Mandatory = true,
            ValueFromPipelineByPropertyName = true,
            Position = 0,
            HelpMessage = "Ed25519 private key to convert")]
        public byte[] PrivateKey;
    }
}
