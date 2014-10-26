using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Management.Automation;
using Sodium;

namespace PoSH_Sodium
{
    [Cmdlet("Sign", "SymmetricMessage")]
    public class SymmetricSign : PSCmdlet
    {
        protected override void BeginProcessing()
        {
            rawMessage = Message.ToByteArray(Encoding);
        }

        protected override void ProcessRecord()
        {
            byte[] signature;
            var key = Key.ToByteArrayFromBase64String();
            switch ((HashType ?? "HmacSha512-256").ToUpper())
            {
                case "HMACSHA512":
                    signature = SecretKeyAuth.SignHmacSha512(rawMessage, key);
                    break;
                case "HMACSHA256":
                    signature = SecretKeyAuth.SignHmacSha256(rawMessage, key);
                    break;
                case "HMACSHA512-256":
                default:
                    signature = SecretKeyAuth.Sign(rawMessage, key);
                    break;
            }
            if (Raw.IsTrue())
            {
                var signedMessave = new RawSignedSymmetricMessage() { Message = Message, Signature = signature };
                WriteObject(signedMessave);
            }
            else
            {
                var signedMessave = new SignedSymmetricMessage() { Message = Message, Signature = signature.Compress() };
                WriteObject(signedMessave);
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
            HelpMessage = "Key to sign the message with")]
        public string Key;

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

        [Parameter(
            Mandatory = false,
            ValueFromPipelineByPropertyName = true,
            Position = 4,
            HelpMessage = "Hash algorithm used to generate signature")]
        [ValidateSet("HmacSha512-256", "HmacSha512", "HmacSha256")]
        public string HashType;
    }
}
