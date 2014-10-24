using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Management.Automation;
using Sodium;
using Newtonsoft.Json;

namespace PoSH_Sodium
{
    [Cmdlet(VerbsData.ConvertFrom, "Key")]
    public class ConvertKey : PSCmdlet
    {
        protected override void EndProcessing()
        {
            switch (ParameterSetName)
            {
                case "Single":
                    var anonKey = new { 
                        KeyName = KeyName ?? "My Key", 
                        Key = Key.ToBase64String(), 
                        KeyLength = Key.Length };
                    WriteObject(JsonConvert.SerializeObject(anonKey, Formatting.Indented));                    
                    break;
                case "Pair":
                    var anonKeyPair = new {
                        KeyName = KeyName ?? "My Key Pair",
                        PublicKey = KeyPair.PublicKey.ToBase64String(),
                        PublicKeyLength = KeyPair.PublicKey.Length,
                        PrivateKey = KeyPair.PrivateKey.ToBase64String(),
                        PrivateKeyLength = KeyPair.PrivateKey.Length
                    };
                    WriteObject(JsonConvert.SerializeObject(anonKeyPair, Formatting.Indented));
                    break;
                default:
                    break;
            }
        }

        [Parameter(
                ParameterSetName = "Single",
                Mandatory = true,
                ValueFromPipelineByPropertyName = true,
                ValueFromPipeline = true,
                Position = 0,
                HelpMessage = "Key to convert")]
        public byte[] Key;

        [Parameter(
                ParameterSetName = "Pair",
                Mandatory = true,
                ValueFromPipelineByPropertyName = true,
                ValueFromPipeline = true,
                Position = 0,
                HelpMessage = "Key pair to convert")]
        public KeyPair KeyPair;

        [Parameter(
                Mandatory = false,
                ValueFromPipelineByPropertyName = true,
                ValueFromPipeline = true,
                Position = 1,
                HelpMessage = "Name of this key")]
        public string KeyName;
    }

    [Cmdlet(VerbsData.ConvertFrom, "JsonKey")]
    public class ConvertBase64String : PSCmdlet
    {
        protected override void EndProcessing()
        {
            var keyType = new {
                        KeyName = string.Empty,
                        Key = string.Empty,
                        KeyLength = 0,
                        PublicKey = string.Empty,
                        PublicKeyLength = 0,
                        PrivateKey = string.Empty,
                        PrivateKeyLength = 0
                    };
            var keyOut = JsonConvert.DeserializeAnonymousType(Key, keyType);
            if (keyOut.Key.HasValue())
            {
                WriteObject(keyOut.Key.ToByteArrayFromBase64String());
            }
            else
            {
                var keyPair = new KeyPair(
                    keyOut.PublicKey.ToByteArrayFromBase64String(),
                    keyOut.PrivateKey.ToByteArrayFromBase64String());
                WriteObject(keyPair);
            }
        }

        [Parameter(
                Mandatory = true,
                ValueFromPipelineByPropertyName = true,
                ValueFromPipeline = true,
                Position = 0,
                HelpMessage = "Key to convert")]
        public string Key;
    }
}
