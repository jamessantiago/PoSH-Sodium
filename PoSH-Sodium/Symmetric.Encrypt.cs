using Sodium;
using System.Management.Automation;

namespace PoSH_Sodium
{
    [Cmdlet("Encrypt", "SymmetricMessage")]
    public class SymmetricEncrypt : PSCmdlet
    {
        protected override void BeginProcessing()
        {
            rawMessage = Message.ToByteArray(Encoding);
        }

        protected override void ProcessRecord()
        {
            var nonce = SecretBox.GenerateNonce();
            var encryptedMessage = SecretBox.Create(rawMessage, nonce, Key);
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

        private byte[] rawMessage;

        [Parameter(
            Mandatory = true,
            ValueFromPipelineByPropertyName = true,
            ValueFromPipeline = true,
            Position = 0,
            HelpMessage = "Message to be encrypted")]
        public string Message;

        [Parameter(
            Mandatory = true,
            ValueFromPipelineByPropertyName = true,
            Position = 1,
            HelpMessage = "Symmetric key to encrypt the message with")]
        public byte[] Key;

        [Parameter(
            Mandatory = false,
            ValueFromPipelineByPropertyName = true,
            Position = 2,
            HelpMessage = "Output is returned as a byte array, otherwise an LZ4 compressed base64 encoded string is returned")]
        public SwitchParameter Raw;

        [Parameter(
            Mandatory = false,
            ValueFromPipelineByPropertyName = true,
            Position = 3,
            HelpMessage = "Encoding to use when converting the message to a byte array.  Default is .NET Unicode (UTF16)")]
        [ValidateSet("UTF7", "UTF8", "UTF16", "UTF32", "ASCII", "Unicode", "BigEndianUnicode")]
        public string Encoding;
    }
}