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
    [Cmdlet("Encrypt", "SymmetricMessage")]
    public class SymmetricEncrypt : PSCmdlet
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
            switch (Type)
            {
                case "ChaCha20":
                    algo = SodiumCryptoTransform.SymmetricAlgorithm.ChaCha20;
                    nonce = StreamEncryption.GenerateNonceChaCha20();
                    break;
                case "XSalsa20":
                    algo = SodiumCryptoTransform.SymmetricAlgorithm.XSalsa;
                    nonce = StreamEncryption.GenerateNonce();
                    break;                
                case "Default":
                default:
                    algo = SodiumCryptoTransform.SymmetricAlgorithm.Default;
                    nonce = SecretBox.GenerateNonce();
                    break;
            }
        }

        protected override void ProcessRecord()
        {
            if (ParameterSetName == "File")
            {
                if (ReplaceFile.IsTrue())
                    OutFile = File;

                using (ICryptoTransform transform = new SodiumCryptoTransform(nonce, Key, SodiumCryptoTransform.Direction.Encrypt, algo))
                using (FileStream destination = new FileStream(OutFile, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                using (CryptoStream cryptoStream = new CryptoStream(destination, transform, CryptoStreamMode.Write))
                using (FileStream source = new FileStream(File, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    source.CopyTo(cryptoStream);
                    cryptoStream.FlushFinalBlock();
                    destination.Write(nonce, 0, nonce.Length);
                    destination.Flush();
                }
            }
            else
            {
                byte[] encryptedMessage = null;
                switch (algo)
                {
                    case SodiumCryptoTransform.SymmetricAlgorithm.ChaCha20:
                        encryptedMessage = StreamEncryption.EncryptChaCha20(rawMessage, nonce, Key);
                        break;
                    case SodiumCryptoTransform.SymmetricAlgorithm.XSalsa:
                        encryptedMessage = StreamEncryption.Encrypt(rawMessage, nonce, Key);
                        break;
                    case SodiumCryptoTransform.SymmetricAlgorithm.Default:
                    default:
                        encryptedMessage = SecretBox.Create(rawMessage, nonce, Key);
                        break;
                }
                if (Raw.IsTrue())
                {
                    var result = new RawEncryptedMessage() { Message = encryptedMessage, Nonce = nonce };
                    WriteObject(result);
                }
                else
                {
                    var result = new EncryptedMessage() { Message = encryptedMessage.Compress(), Nonce = nonce };
                    WriteObject(result);
                }
            }
        }

        private byte[] rawMessage;
        private SodiumCryptoTransform.SymmetricAlgorithm algo;
        private byte[] nonce;

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
            Mandatory = true,
            ValueFromPipelineByPropertyName = true,
            Position = 1,
            HelpMessage = "Key to encrypt the message with")]
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

        [Parameter(
            Mandatory = false,
            ValueFromPipelineByPropertyName = true,
            Position = 5,
            HelpMessage = "Encryption type to use")]
        [ValidateSet("Default", "ChaCha20", "XSalsa20")]
        public string Type;
    }
}