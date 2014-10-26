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
    [Cmdlet("Encrypt", "Message")]
    public class Encrypt : PSCmdlet
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
            var nonce = SecretBox.GenerateNonce();
            if (ParameterSetName == "File")
            {
                if (ReplaceFile.IsTrue())
                    OutFile = Path.GetTempFileName();

                using (ICryptoTransform transform = new SodiumCryptoTransform(nonce, PrivateKey, PublicKey, SodiumCryptoTransform.Direction.Encrypt))
                using (FileStream destination = new FileStream(OutFile, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                using (CryptoStream cryptoStream = new CryptoStream(destination, transform, CryptoStreamMode.Write))
                using (FileStream source = new FileStream(File, FileMode.Open, FileAccess.Read, FileShare.Read))                
                {
                    source.CopyTo(cryptoStream);
                    cryptoStream.FlushFinalBlock();
                    destination.Write(nonce, 0, nonce.Length);
                    destination.Flush();
                }

                if (ReplaceFile.IsTrue())
                {
                    System.IO.File.Delete(File);
                    System.IO.File.Move(OutFile, File);
                }
            }
            else
            {                
                var encryptedMessage = PublicKeyBox.Create(rawMessage, nonce, PrivateKey, PublicKey);
                var results = new EncryptedMessage()
                {
                    EncryptedType = "Asymetric",
                    Message = NoCompression.IsTrue() ? encryptedMessage.ToBase64String() : encryptedMessage.Compress(),
                    Nonce = nonce.ToBase64String(),
                    Compressed = !NoCompression
                };

                WriteObject(results);
            }
        }

        private byte[] rawMessage;

        
        [Parameter(
            ParameterSetName= "String",
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
            HelpMessage = "Sender's private key to sign the message with")]
        public byte[] PrivateKey;

        [Parameter(
            Mandatory = true,
            ValueFromPipelineByPropertyName = true,
            Position = 2,
            HelpMessage = "Recipient's public key to encrypt the message with")]
        public byte[] PublicKey;

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
            ParameterSetName= "String",
            Mandatory = false,
            ValueFromPipelineByPropertyName = true,
            Position = 4,
            HelpMessage = "Encoding to use when converting the message to a byte array.  Default is .NET Unicode (UTF16)")]
        [ValidateSet("UTF7", "UTF8", "UTF16", "UTF32", "ASCII", "Unicode", "BigEndianUnicode")]
        public string Encoding;

        [Parameter(
            ParameterSetName = "String",
            Mandatory = false,
            ValueFromPipelineByPropertyName = true,
            Position = 5,
            HelpMessage = "No compression is used when returning an encrypted message")]
        public SwitchParameter NoCompression;

    }
}
