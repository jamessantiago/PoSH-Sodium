using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Runtime.ConstrainedExecution;
using System.Runtime.CompilerServices;
using Sodium;

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