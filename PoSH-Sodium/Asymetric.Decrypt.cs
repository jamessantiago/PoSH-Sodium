using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Management.Automation;
using Sodium;

namespace PoSH_Sodium
{
    [Cmdlet("Decrypt", "Message")]
    public class Decrypt : PSCmdlet
    {
        protected override void BeginProcessing()
        {
            rawMessage = Message.Decompress();
        }

        protected override void ProcessRecord()
        {
            byte[] message;
            message = PublicKeyBox.Open(rawMessage, Nonce, PrivateKey, PublicKey);

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

        private byte[] rawMessage;

        [Parameter(
            Mandatory = true,
            ValueFromPipelineByPropertyName = true,
            ValueFromPipeline = true,
            Position = 0,
            HelpMessage = "Message to be verified and decrypted")]
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
            HelpMessage = "Sender's public key to verify the message with")]
        public byte[] PublicKey;

        [Parameter(
            Mandatory = true,
            ValueFromPipelineByPropertyName = true,
            Position = 3,
            HelpMessage = "Recepient's private key to decrypt the message with")]
        public byte[] PrivateKey;

        [Parameter(
            Mandatory = false,
            ValueFromPipelineByPropertyName = true,
            Position = 4,
            HelpMessage = "Output is returned as a byte array, otherwise a plain text string is returned")]
        public SwitchParameter Raw;

        [Parameter(
            Mandatory = false,
            ValueFromPipelineByPropertyName = true,
            Position = 5,
            HelpMessage = "Encoding to use when converting the message to a plain text string.  Default is .NET Unicode (UTF16)")]
        [ValidateSet("UTF7", "UTF8", "UTF16", "UTF32", "ASCII", "Unicode", "BigEndianUnicode")]
        public string Encoding;
    }

    [Cmdlet("Decrypt", "RawMessage")]
    public class RawDecrypt : PSCmdlet
    {

        protected override void ProcessRecord()
        {
            byte[] message;
            message = PublicKeyBox.Open(Message, Nonce, PrivateKey, PublicKey);

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

        private byte[] rawMessage;

        [Parameter(
            Mandatory = true,
            ValueFromPipelineByPropertyName = true,
            ValueFromPipeline = true,
            Position = 0,
            HelpMessage = "Message to be verified and decrypted")]
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
            HelpMessage = "Sender's public key to verify the message with")]
        public byte[] PublicKey;

        [Parameter(
            Mandatory = true,
            ValueFromPipelineByPropertyName = true,
            Position = 3,
            HelpMessage = "Recepient's private key to decrypt the message with")]
        public byte[] PrivateKey;

        [Parameter(
            Mandatory = false,
            ValueFromPipelineByPropertyName = true,
            Position = 4,
            HelpMessage = "Output is returned as a byte array, otherwise a plain text string is returned")]
        public SwitchParameter Raw;

        [Parameter(
            Mandatory = false,
            ValueFromPipelineByPropertyName = true,
            Position = 5,
            HelpMessage = "Encoding to use when converting the message to a plain text string.  Default is .NET Unicode (UTF16)")]
        [ValidateSet("UTF7", "UTF8", "UTF16", "UTF32", "ASCII", "Unicode", "BigEndianUnicode")]
        public string Encoding;
    }
}
