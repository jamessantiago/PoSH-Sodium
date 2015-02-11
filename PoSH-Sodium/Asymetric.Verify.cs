using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Management.Automation;
using Sodium;

namespace PoSH_Sodium
{
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
                throw new NotImplementedException("Where is verify detached?");
            }
            else
            {
                var key = PublicKey.ToByteArrayFromBase64String();
                message = PublicKeyAuth.Verify(rawMessage, key);

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
            ParameterSetName = "String",
            Mandatory = true,
            ValueFromPipelineByPropertyName = true,
            ValueFromPipeline = true,
            Position = 0,
            HelpMessage = "Message to be verified")]
        public string Message;

        [Parameter(
            ParameterSetName = "Byte",
            Mandatory = true,
            ValueFromPipelineByPropertyName = true,
            ValueFromPipeline = true,
            Position = 0,
            HelpMessage = "Message to be verified")]
        public byte[] RawMessage;

        [Parameter(
            Mandatory = true,
            ValueFromPipelineByPropertyName = true,
            Position = 1,
            HelpMessage = "Public key to verify the message with")]
        public string PublicKey;

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


    [Cmdlet("Verify", "RawMessage")]
    public class VerifyRaw : PSCmdlet
    {
        protected override void ProcessRecord()
        {
            byte[] message;
            if (SignatureOnly.IsTrue())
            {
                throw new NotImplementedException("Where is verify detached?");
            }
            else
            {
                var key = PublicKey.ToByteArrayFromBase64String();
                message = PublicKeyAuth.Verify(Message, key);

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

        [Parameter(
            Mandatory = true,
            ValueFromPipelineByPropertyName = true,
            ValueFromPipeline = true,
            Position = 0,
            HelpMessage = "Message to be verified")]
        public byte[] Message;

        [Parameter(
            Mandatory = true,
            ValueFromPipelineByPropertyName = true,
            Position = 1,
            HelpMessage = "Public key to verify the message with")]
        public string PublicKey;

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
