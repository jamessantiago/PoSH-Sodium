using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Runtime.ConstrainedExecution;
using System.Runtime.CompilerServices;
using Newtonsoft.Json;
using Sodium;

namespace PoSH_Sodium
{
    public class EncryptedMessage
    {
        public string Info = "";
        public string EncryptedType;
        public string Message;
        public string Nonce;
        public bool Compressed;
        
        public override string ToString()
        {
            return JsonConvert.SerializeObject(this, Formatting.Indented);
        }
    }
}