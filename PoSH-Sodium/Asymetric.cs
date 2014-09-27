using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Management.Automation;
using Sodium;
using LZ4;

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

    [Cmdlet("Sign", "Message")]
    public class Sign : PSCmdlet
    {
        protected override void BeginProcessing()
        {
            rawMessage = Message.ToByteArray(Encoding);
        }

        protected override void ProcessRecord()
        {
            var signedMessage = PublicKeyAuth.Sign(rawMessage, Key);
            if (Raw.IsPresent && Raw.ToBool())
            {
                WriteObject(signedMessage);
            }
            else
            {
                WriteObject(signedMessage.Compress());
            }
        }

        private byte[] rawMessage;

        [Parameter(
            Mandatory = true,
            ValueFromPipelineByPropertyName = true,
            ValueFromPipeline = true,
            Position = 0,
            HelpMessage = "Message to be signed")]
        public string Message;

        [Parameter(
            Mandatory = true,
            ValueFromPipelineByPropertyName = true,
            Position = 1,
            HelpMessage = "Private key to sign the message with")]
        public byte[] Key;

        [Parameter(
            Mandatory = false,
            ValueFromPipelineByPropertyName = true,
            Position = 2,
            HelpMessage = "Output is returned as a byte array, otherwise an LZ4 compressed base64 encoded string is returned")]
        public SwitchParameter Raw;

        [Parameter(
            Mandatory = false,
            ValueFromPipelineByPropertyName = true,
            Position = 3,
            HelpMessage = "Encoding to use when converting the message to a byte array.  Default is .NET Unicode (UTF16)")]
        [ValidateSet("UTF7", "UTF8", "UTF16", "UTF32", "ASCII", "Unicode", "BigEndianUnicode")]
        public string Encoding;

    }

    [Cmdlet("Verify", "Message")]
    public class Verify : PSCmdlet
    {
        protected override void BeginProcessing()
        {
            rawMessage = Message.Decompress();
        }

        protected override void ProcessRecord()
        {
            byte[] message;
            if (SignatureOnly.IsTrue())
            {
                throw new NotImplementedException("Need new version");
            }
            else
            {
                message = PublicKeyAuth.Verify(rawMessage, Key);

                if (Raw.IsPresent && Raw.ToBool())
                {
                    WriteObject(message);
                }
                else
                {
                    var plainMessage = message.ToString(Encoding);
                    WriteObject(plainMessage);
                }
            }            
        }

        private byte[] rawMessage;

        [Parameter(
            Mandatory = true,
            ValueFromPipelineByPropertyName = true,
            ValueFromPipeline = true,
            Position = 0,
            HelpMessage = "Message to be verified")]
        public string Message;

        [Parameter(
            Mandatory = true,
            ValueFromPipelineByPropertyName = true,
            Position = 1,
            HelpMessage = "Public key to verify the message with")]
        public byte[] Key;

        [Parameter(
            Mandatory = false,
            ValueFromPipelineByPropertyName = true,
            Position = 2,
            HelpMessage = "Verifies a signature without the message")]
        public SwitchParameter SignatureOnly;

        [Parameter(
            Mandatory = false,
            ValueFromPipelineByPropertyName = true,
            Position = 3,
            HelpMessage = "Output is returned as a byte array, otherwise a plain text string is returned")]
        public SwitchParameter Raw;

        [Parameter(
            Mandatory = false,
            ValueFromPipelineByPropertyName = true,
            Position = 4,
            HelpMessage = "Encoding to use when converting the message to a plain text string.  Default is .NET Unicode (UTF16)")]
        [ValidateSet("UTF7", "UTF8", "UTF16", "UTF32", "ASCII", "Unicode", "BigEndianUnicode")]
        public string Encoding;
    }


}
