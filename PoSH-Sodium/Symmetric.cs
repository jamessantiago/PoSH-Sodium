namespace PoSH_Sodium
{
    public class SignedSymmetricMessage
    {
        public string Message;
        public string Signature;
    }

    public class RawSignedSymmetricMessage
    {
        public string Message;
        public byte[] Signature;
    }
}