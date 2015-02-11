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
    [Cmdlet(VerbsCommon.New, "GenericHash")]
    public class NewGenericHash : PSCmdlet
    {
        protected override void BeginProcessing()
        {
            switch (ParameterSetName)
            {
                case "String":
                    rawMessage = Message.ToByteArray(Encoding);
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
            byte[] hashedMessage;
            var key = Key.HasValue() ? Key.ToByteArrayFromBase64String() : null;

            if (ParameterSetName == "File")
            {
                using (ICryptoTransform transform = new GenericHash.GenericHashAlgorithm(key, HashLength))
                using (MemoryStream destination = new MemoryStream())
                using (CryptoStream cryptoStream = new CryptoStream(destination, transform, CryptoStreamMode.Write))
                using (FileStream source = new FileStream(File, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    source.CopyTo(cryptoStream);
                    cryptoStream.FlushFinalBlock();
                    hashedMessage = destination.ToArray();
                }
            }
            else
            {
                hashedMessage = GenericHash.Hash(rawMessage, key, HashLength);
            }

            if (Raw.IsTrue())
            {
                WriteObject(hashedMessage);
            }
            else
            {
                WriteObject(hashedMessage.ToBase64String());
            }
        }

        private byte[] rawMessage;

        [Parameter(
            ParameterSetName = "String",
            Mandatory = true,
            ValueFromPipelineByPropertyName = true,
            ValueFromPipeline = true,
            Position = 0,
            HelpMessage = "Message to be hashed")]
        public string Message;

        [Parameter(
        ParameterSetName = "Byte",
        Mandatory = true,
        ValueFromPipelineByPropertyName = true,
        ValueFromPipeline = true,
        Position = 0,
        HelpMessage = "Message to be hashed")]
        public byte[] RawMessage;

        [Parameter(
            ParameterSetName = "File",
            Mandatory = true,
            ValueFromPipelineByPropertyName = true,
            ValueFromPipeline = true,
            Position = 0,
            HelpMessage = "Message to be hashed")]
        public string File;

        [Parameter(
            Mandatory = false,
            ValueFromPipelineByPropertyName = true,
            Position = 1,
            HelpMessage = "Output length of hash")]
        [ValidateRange(16, 64)]
        public int HashLength = 40;

        [Parameter(
            Mandatory = false,
            ValueFromPipelineByPropertyName = true,
            Position = 2,
            HelpMessage = "Optional 16 to 64 byte key to hash the message with")]
        public string Key;

        [Parameter(
            Mandatory = false,
            ValueFromPipelineByPropertyName = true,
            Position = 3,
            HelpMessage = "Output is returned as a byte array, otherwise a base64 encoded string is returned")]
        public SwitchParameter Raw;

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
