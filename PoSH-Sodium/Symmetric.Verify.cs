using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Management.Automation;
using Sodium;

namespace PoSH_Sodium
{
    [Cmdlet("Verify", "SymmetricMessage")]
    public class SymmetricVerify : PSCmdlet
    {
        protected override void BeginProcessing()
        {
            rawMessage = Message.ToByteArray(Encoding);
        }

        protected override void ProcessRecord()
        {
            bool isVerified;
            switch ((HashType ?? "HmacSha512-256").ToUpper())
            {
                case "HMACSHA512":
                    isVerified = SecretKeyAuth.VerifyHmacSha512(rawMessage, Signature.Decompress(), Key);
                    break;
                case "HMACSHA256":
                    isVerified = SecretKeyAuth.VerifyHmacSha256(rawMessage, Signature.Decompress(), Key);
                    break;
                case "HMACSHA512-256":
                default:
                    isVerified = SecretKeyAuth.Verify(rawMessage, Signature.Decompress(), Key);
                    break;
            }
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
        public byte[] Key;

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

        [Parameter(
            Mandatory = false,
            ValueFromPipelineByPropertyName = true,
            Position = 4,
            HelpMessage = "Hash algorithm used to verify signature")]
        [ValidateSet("HmacSha512-256", "HmacSha512", "HmacSha256")]
        public string HashType;
    }

    [Cmdlet("Verify", "RawSymmetricMessage")]
    public class RawSymmetricVerify : PSCmdlet
    {
        protected override void BeginProcessing()
        {
            rawMessage = Message.ToByteArray(Encoding);
        }

        protected override void ProcessRecord()
        {
            bool isVerified;
            switch ((HashType ?? "HmacSha512-256").ToUpper())
            {
                case "HMACSHA512":
                    isVerified = SecretKeyAuth.VerifyHmacSha512(rawMessage, Signature, Key);
                    break;
                case "HMACSHA256":
                    isVerified = SecretKeyAuth.VerifyHmacSha256(rawMessage, Signature, Key);
                    break;
                case "HMACSHA512-256":
                default:
                    isVerified = SecretKeyAuth.Verify(rawMessage, Signature, Key);
                    break;
            }
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
        public byte[] Key;

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

        [Parameter(
            Mandatory = false,
            ValueFromPipelineByPropertyName = true,
            Position = 4,
            HelpMessage = "Hash algorithm used to verify signature")]
        [ValidateSet("HmacSha512-256", "HmacSha512", "HmacSha256")]
        public string HashType;
    }
}
