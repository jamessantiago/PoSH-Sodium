using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Management.Automation;
using System.Security.Cryptography;
using System.IO;
using Sodium;

namespace PoSH_Sodium
{
    [Cmdlet("Decrypt", "SymmetricMessage")]
    public class SymmetricDecrypt : PSCmdlet
    {
        protected override void BeginProcessing()
        {
            switch (ParameterSetName)
            {
                case "String":
                    rawMessage = Message.Decompress();
                    break;
                case "Byte":
                    rawMessage = RawMessage;
                    break;
                default:
                    break;
            }  
        }

        protected override void ProcessRecord()
        {
            if (ParameterSetName == "File")
            {
                if (ReplaceFile.IsTrue())
                    OutFile = File;

                byte[] fileEndData = new byte[40];
                long dataEnd = 0;

                using (FileStream source = new FileStream(File, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    source.Seek(-24, SeekOrigin.End);
                    dataEnd = source.Position;
                    source.Read(fileEndData, 0, 24);
                }

                byte[] nonce = new byte[24];
                Array.Copy(fileEndData, 0, nonce, 0, 24);

                using (ICryptoTransform transform = new SodiumCryptoTransform(nonce, Key, SodiumCryptoTransform.Direction.Decrypt))
                using (FileStream destination = new FileStream(OutFile, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                using (CryptoStream cryptoStream = new CryptoStream(destination, transform, CryptoStreamMode.Write))
                using (FileStream source = new FileStream(File, FileMode.Open, FileAccess.Read, FileShare.Read))
                    source.CopyTo(cryptoStream);

            }
            else
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
        }

        private byte[] rawMessage;

        [Parameter(
            ParameterSetName = "String",
            Mandatory = true,
            ValueFromPipelineByPropertyName = true,
            ValueFromPipeline = true,
            Position = 0,
            HelpMessage = "Message to be encrypted")]
        public string Message;

        [Parameter(
            ParameterSetName = "Byte",
            Mandatory = true,
            ValueFromPipelineByPropertyName = true,
            ValueFromPipeline = true,
            Position = 0,
            HelpMessage = "Message to be encrypted")]
        public byte[] RawMessage;

        [Parameter(
            ParameterSetName = "File",
            Mandatory = true,
            ValueFromPipelineByPropertyName = true,
            ValueFromPipeline = true,
            Position = 0,
            HelpMessage = "Message to be encrypted")]
        public string File;

        [Parameter(
            ParameterSetName = "Byte",
            Mandatory = true,
            ValueFromPipelineByPropertyName = true,
            Position = 1,
            HelpMessage = "Nonce to decrypt message with")]
        [Parameter(
            ParameterSetName = "String",
            Mandatory = true,
            ValueFromPipelineByPropertyName = true,
            Position = 1,
            HelpMessage = "Nonce to decrypt message with")]
        public byte[] Nonce;

        [Parameter(
            Mandatory = true,
            ValueFromPipelineByPropertyName = true,
            Position = 2,
            HelpMessage = "key to decrypt the message with")]
        public byte[] Key;

        [Parameter(
            ParameterSetName = "String",
            Mandatory = false,
            ValueFromPipelineByPropertyName = true,
            Position = 3,
            HelpMessage = "Output is returned as a byte array, otherwise an LZ4 compressed base64 encoded string is returned")]
        [Parameter(
            ParameterSetName = "Byte",
            Mandatory = false,
            ValueFromPipelineByPropertyName = true,
            Position = 3,
            HelpMessage = "Output is returned as a byte array, otherwise an LZ4 compressed base64 encoded string is returned")]
        public SwitchParameter Raw;

        [Parameter(
           ParameterSetName = "File",
           Mandatory = false,
           ValueFromPipelineByPropertyName = true,
           ValueFromPipeline = true,
           Position = 3,
           HelpMessage = "Ouput file")]
        public string OutFile;

        [Parameter(
           ParameterSetName = "File",
           Mandatory = false,
           ValueFromPipelineByPropertyName = true,
           ValueFromPipeline = true,
           Position = 4,
           HelpMessage = "Replaces file with encrypted")]
        public SwitchParameter ReplaceFile;

        [Parameter(
            ParameterSetName = "String",
            Mandatory = false,
            ValueFromPipelineByPropertyName = true,
            Position = 4,
            HelpMessage = "Encoding to use when converting the message to a byte array.  Default is .NET Unicode (UTF16)")]
        [ValidateSet("UTF7", "UTF8", "UTF16", "UTF32", "ASCII", "Unicode", "BigEndianUnicode")]
        public string Encoding;
    }

}
