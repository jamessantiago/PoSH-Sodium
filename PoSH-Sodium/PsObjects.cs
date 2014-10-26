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

    public class SodiumKeyPair
    {
        public string Info = "";
        public string KeyType;
        public string PublicKey;
        public string PrivateKey;

        public override string ToString()
        {
            return JsonConvert.SerializeObject(this, Formatting.Indented);
        }

        public SodiumPublicKey GetPublicKey()
        {
            return new SodiumPublicKey()
            {
                Info = this.Info,
                KeyType = this.KeyType,
                PublicKey = this.PublicKey
            };
        }

        public SodiumPrivateKey GetPrivateKey()
        {
            return new SodiumPrivateKey()
            {
                Info = this.Info,
                KeyType = this.KeyType,
                PrivateKey = this.PrivateKey
            };
        }
    }

    public class SodiumPrivateKey
    {
        public string Info = "";
        public string KeyType;
        public string PrivateKey;

        public override string ToString()
        {
            return JsonConvert.SerializeObject(this, Formatting.Indented);
        }
    }

    public class SodiumPublicKey
    {
        public string Info = "";
        public string KeyType;
        public string PublicKey;

        public override string ToString()
        {
            return JsonConvert.SerializeObject(this, Formatting.Indented);
        }
    }

    public class SodiumSymmetricKey
    {
        public string Info = "";
        public string Key;

        public override string ToString()
        {
            return JsonConvert.SerializeObject(this, Formatting.Indented);
        }
    }
}
