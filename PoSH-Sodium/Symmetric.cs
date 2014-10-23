using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Runtime.ConstrainedExecution;
using System.Runtime.CompilerServices;
using Sodium;

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
