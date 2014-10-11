namespace PoSH_Sodium
{
    public class EncryptedMessage
    {
        public string Message;
        public byte[] Nonce;
    }

    public class RawEncryptedMessage
    {
        public byte[] Message;
        public byte[] Nonce;
    }
}