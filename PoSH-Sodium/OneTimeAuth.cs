using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Management.Automation;
using Sodium;

namespace PoSH_Sodium
{

    [Cmdlet(VerbsCommon.New, "OneTimeKey")]
    public class GenerateOneTimeKey : PSCmdlet
    {
        protected override void ProcessRecord()
        {
            var key = new SodiumSymmetricKey()
            {
                KeyType = "OneTime",
                Key = OneTimeAuth.GenerateKey().ToBase64String(),
            };
            WriteObject(key);
        }
    }

    [Cmdlet("Sign", "OneTime")]
    public class OneTimeSign : PSCmdlet
    {
        protected override void BeginProcessing()
        {
            rawMessage = Message.ToByteArray(Encoding);
        }

        protected override void ProcessRecord()
        {
            byte[] signature;
            signature = OneTimeAuth.Sign(rawMessage, Key.ToByteArrayFromBase64String());
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
            HelpMessage = "One time key to sign the message with")]
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
    }

    [Cmdlet("Verify", "OneTime")]
    public class OneTimeVerify : PSCmdlet
    {
        protected override void BeginProcessing()
        {
            rawMessage = Message.ToByteArray(Encoding);
        }

        protected override void ProcessRecord()
        {
            bool isVerified = OneTimeAuth.Verify(rawMessage, Signature.Decompress(), Key.ToByteArrayFromBase64String());            
            WriteObject(isVerified);
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
            HelpMessage = "One time key to verify the message with")]
        public string Key;

        [Parameter(
            Mandatory = true,
            ValueFromPipelineByPropertyName = true,
            Position = 2,
            HelpMessage = "Signature to verify the message with")]
        public string Signature;

        [Parameter(
            Mandatory = false,
            ValueFromPipelineByPropertyName = true,
            Position = 3,
            HelpMessage = "Encoding to use when converting the message to a byte array.  Default is .NET Unicode (UTF16)")]
        [ValidateSet("UTF7", "UTF8", "UTF16", "UTF32", "ASCII", "Unicode", "BigEndianUnicode")]
        public string Encoding;
    }

    [Cmdlet("Verify", "RawOneTime")]
    public class RawOneTime : PSCmdlet
    {
        protected override void BeginProcessing()
        {
            rawMessage = Message.ToByteArray(Encoding);
        }

        protected override void ProcessRecord()
        {
            bool isVerified = OneTimeAuth.Verify(rawMessage, Signature, Key.ToByteArrayFromBase64String());            
            WriteObject(isVerified);
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
            HelpMessage = "Key to verify the message with")]
        public string Key;

        [Parameter(
            Mandatory = true,
            ValueFromPipelineByPropertyName = true,
            Position = 2,
            HelpMessage = "Signature to verify the message with")]
        public byte[] Signature;

        [Parameter(
            Mandatory = false,
            ValueFromPipelineByPropertyName = true,
            Position = 3,
            HelpMessage = "Encoding to use when converting the message to a byte array.  Default is .NET Unicode (UTF16)")]
        [ValidateSet("UTF7", "UTF8", "UTF16", "UTF32", "ASCII", "Unicode", "BigEndianUnicode")]
        public string Encoding;
    }
}
