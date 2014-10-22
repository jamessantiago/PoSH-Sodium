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
                    OutFile = File;                    

                using (ICryptoTransform transform = new AsymetricCryptoTransform(nonce, PrivateKey, PublicKey, AsymetricCryptoTransform.Direction.Encrypt))
                using (FileStream destination = new FileStream(OutFile, FileMode.Append, FileAccess.Write, FileShare.None))
                using (CryptoStream cryptoStream = new CryptoStream(destination, transform, CryptoStreamMode.Write))
                using (FileStream source = new FileStream(File, FileMode.Open, FileAccess.Read, FileShare.Read))                
                {
                    source.CopyTo(cryptoStream);
                    //int bytesRead = 0;
                    //int chunkSize = 4096;
                    //byte[] chunkData = new byte[chunkSize];

                    //while ((bytesRead = source.Read(chunkData, 0, chunkSize)) > 0)
                    //{
                    //    if (bytesRead != chunkSize)
                    //    {
                    //        byte[] lastData = new byte[bytesRead];
                    //        Array.Copy(chunkData, 0, lastData, 0, bytesRead);
                    //        cryptoStream.Write(lastData, 0, bytesRead);
                    //    }
                    //    else
                    //        cryptoStream.Write(chunkData, 0, bytesRead);
                    //}
                    cryptoStream.FlushFinalBlock();
                    destination.Write(nonce, 0, nonce.Length);
                    destination.Flush();
                }                

                WriteObject(nonce);
            }
            else
            {                
                var encryptedMessage = PublicKeyBox.Create(rawMessage, nonce, PrivateKey, PublicKey);
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

    }
}
