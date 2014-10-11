using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Management.Automation;
using Sodium;

namespace PoSH_Sodium
{
    [Cmdlet("Decrypt", "SymmetricMessage")]
    public class SymmetricDecrypt : PSCmdlet
    {
        protected override void BeginProcessing()
        {
            rawMessage = Message.Decompress();
        }

        protected override void ProcessRecord()
        {
            byte[] message;
            message = SecretBox.Open(rawMessage, Nonce, Key);
            if (Raw.IsTrue())
            {
                WriteObject(message);
            }
            else
            {
                var plainMessage = message.ToString(Encoding);
                WriteObject(plainMessage);
            }
        }

        private byte[] rawMessage;

        [Parameter(
            Mandatory = true,
            ValueFromPipelineByPropertyName = true,
            ValueFromPipeline = true,
            Position = 0,
            HelpMessage = "Message to be decrypted")]
        public string Message;

        [Parameter(
            Mandatory = true,
            ValueFromPipelineByPropertyName = true,
            Position = 1,
            HelpMessage = "Nonce to decrypt message with")]
        public byte[] Nonce;

        [Parameter(
            Mandatory = true,
            ValueFromPipelineByPropertyName = true,
            Position = 2,
            HelpMessage = "Symmetric key to decrypt the message with")]
        public byte[] Key;

        [Parameter(
            Mandatory = false,
            ValueFromPipelineByPropertyName = true,
            Position = 3,
            HelpMessage = "Output is returned as a byte array, otherwise an LZ4 compressed base64 encoded string is returned")]
        public SwitchParameter Raw;

        [Parameter(
            Mandatory = false,
            ValueFromPipelineByPropertyName = true,
            Position = 4,
            HelpMessage = "Encoding to use when converting the message to a byte array.  Default is .NET Unicode (UTF16)")]
        [ValidateSet("UTF7", "UTF8", "UTF16", "UTF32", "ASCII", "Unicode", "BigEndianUnicode")]
        public string Encoding;
    }

    [Cmdlet("Decrypt", "RawSymmetricMessage")]
    public class RawSymmetricDecrypt : PSCmdlet
    {
        protected override void ProcessRecord()
        {
            byte[] message;
            message = SecretBox.Open(Message, Nonce, Key);
            if (Raw.IsTrue())
            {
                WriteObject(message);
            }
            else
            {
                var plainMessage = message.ToString(Encoding);
                WriteObject(plainMessage);
            }
        }

        [Parameter(
            Mandatory = true,
            ValueFromPipelineByPropertyName = true,
            ValueFromPipeline = true,
            Position = 0,
            HelpMessage = "Message to be decrypted")]
        public byte[] Message;

        [Parameter(
            Mandatory = true,
            ValueFromPipelineByPropertyName = true,
            Position = 1,
            HelpMessage = "Nonce to decrypt message with")]
        public byte[] Nonce;

        [Parameter(
            Mandatory = true,
            ValueFromPipelineByPropertyName = true,
            Position = 2,
            HelpMessage = "Symmetric key to decrypt the message with")]
        public byte[] Key;

        [Parameter(
            Mandatory = false,
            ValueFromPipelineByPropertyName = true,
            Position = 3,
            HelpMessage = "Output is returned as a byte array, otherwise an LZ4 compressed base64 encoded string is returned")]
        public SwitchParameter Raw;

        [Parameter(
            Mandatory = false,
            ValueFromPipelineByPropertyName = true,
            Position = 4,
            HelpMessage = "Encoding to use when converting the message to a byte array.  Default is .NET Unicode (UTF16)")]
        [ValidateSet("UTF7", "UTF8", "UTF16", "UTF32", "ASCII", "Unicode", "BigEndianUnicode")]
        public string Encoding;
    }
}
