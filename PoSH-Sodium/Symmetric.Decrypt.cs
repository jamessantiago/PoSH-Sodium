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
            switch (Type)
            {
                case "ChaCha20":
                    algo = SodiumCryptoTransform.SymmetricAlgorithm.ChaCha20;
                    break;
                case "XSalsa20":
                    algo = SodiumCryptoTransform.SymmetricAlgorithm.XSalsa;
                    break;
                case "Default":
                default:
                    algo = SodiumCryptoTransform.SymmetricAlgorithm.Default;
                    break;
            }
        }

        protected override void ProcessRecord()
        {
            var key = Key.ToByteArrayFromBase64String();
            if (ParameterSetName == "File")
            {
                if (ReplaceFile.IsTrue())
                    OutFile = File;

                byte[] fileEndData = null;
                if (algo == SodiumCryptoTransform.SymmetricAlgorithm.ChaCha20)
                    fileEndData = new byte[8];
                else 
                    fileEndData = new byte[24];
                long dataEnd = 0;

                using (FileStream source = new FileStream(File, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    source.Seek(-fileEndData.Length, SeekOrigin.End);
                    dataEnd = source.Position;
                    source.Read(fileEndData, 0, fileEndData.Length);
                }

                byte[] nonce = new byte[fileEndData.Length];
                Array.Copy(fileEndData, 0, nonce, 0, fileEndData.Length);

                using (ICryptoTransform transform = new SodiumCryptoTransform(nonce, key, SodiumCryptoTransform.Direction.Decrypt, algo))
                using (FileStream destination = new FileStream(OutFile, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                using (CryptoStream cryptoStream = new CryptoStream(destination, transform, CryptoStreamMode.Write))
                using (FileStream source = new FileStream(File, FileMode.Open, FileAccess.Read, FileShare.Read))
                    source.CopyTo(cryptoStream);

            }
            else
            {
                byte[] message;
                byte[] nonce = Nonce.ToByteArrayFromBase64String();
                switch (algo)
                {
                    case SodiumCryptoTransform.SymmetricAlgorithm.ChaCha20:
                        message = StreamEncryption.DecryptChaCha20(rawMessage, nonce, key);
                        break;
                    case SodiumCryptoTransform.SymmetricAlgorithm.XSalsa:
                        message = StreamEncryption.Decrypt(rawMessage, nonce, key);
                        break;
                    case SodiumCryptoTransform.SymmetricAlgorithm.Default:
                    default:
                        message = SecretBox.Open(rawMessage, nonce, key);
                        break;
                }                
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
        private SodiumCryptoTransform.SymmetricAlgorithm algo;

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
        public string Nonce;

        [Parameter(
            Mandatory = true,
            ValueFromPipelineByPropertyName = true,
            Position = 2,
            HelpMessage = "key to decrypt the message with")]
        public string Key;

        [Parameter(
            ParameterSetName = "String",
            Mandatory = false,
            ValueFromPipelineByPropertyName = true,
            Position = 3,
            HelpMessage = "Output is returned as a byte array")]
        [Parameter(
            ParameterSetName = "Byte",
            Mandatory = false,
            ValueFromPipelineByPropertyName = true,
            Position = 3,
            HelpMessage = "Output is returned as a byte array")]
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

        [Parameter(
            Mandatory = false,
            ValueFromPipelineByPropertyName = true,
            Position = 6,
            HelpMessage = "Encryption type to use")]
        [ValidateSet("Default", "ChaCha20", "XSalsa20")]
        public string Type;
    }

}
