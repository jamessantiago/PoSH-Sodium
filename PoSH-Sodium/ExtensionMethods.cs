using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Management.Automation;
using LZ4;

namespace PoSH_Sodium
{
    public static class ExtensionMethods
    {
        public static bool HasValue(this string s)
        {
            return !string.IsNullOrEmpty(s);
        }

        public static byte[] ToByteArray(this string s, string encoding)
        {
            switch (encoding.HasValue() ? encoding.ToUpper() : "")
            {
                case "ASCII":
                    return Encoding.ASCII.GetBytes(s);
                case "UTF7":
                    return Encoding.UTF7.GetBytes(s);
                case "UTF8":
                    return Encoding.UTF8.GetBytes(s);                
                case "UTF32":
                    return Encoding.UTF32.GetBytes(s);
                case "BIGENDIANUNICODE":
                    return Encoding.BigEndianUnicode.GetBytes(s);
                case "UNICODE":
                case "UTF16":
                default:
                    return Encoding.Unicode.GetBytes(s);
            }
        }

        public static string ToString(this byte[] b, string encoding)
        {
            switch (encoding.HasValue() ? encoding.ToUpper() : "")
            {
                case "ASCII":
                    return Encoding.ASCII.GetString(b);
                case "UTF7":
                    return Encoding.UTF7.GetString(b);
                case "UTF8":
                    return Encoding.UTF8.GetString(b);
                case "UTF32":
                    return Encoding.UTF32.GetString(b);
                case "BIGENDIANUNICODE":
                    return Encoding.BigEndianUnicode.GetString(b);
                case "UNICODE":
                case "UTF16":
                default:
                    return Encoding.Unicode.GetString(b);
            }
        }

        public static string Compress(this byte[] m)
        {
            var compressed = LZ4Codec.EncodeHC(m, 0, m.Length);
            var compressedBase64 = Convert.ToBase64String(compressed);
            return compressedBase64;
        }

        public static byte[] Decompress(this string m)
        {
            var message = Convert.FromBase64String(m);
            byte[] decoded;
            var buffer = new byte[message.Length * 10];
            int decodedSize = LZ4Codec.Decode(message, 0, message.Length, buffer, 0, buffer.Length, false);
            if (decodedSize > 0)
            {
                decoded = new byte[decodedSize];
                Array.Copy(buffer, decoded, decodedSize);
            }
            else
            {
                throw new InvalidOperationException("Failed to decompress string");
            }
            return decoded;
        }

        public static bool IsTrue(this SwitchParameter s)
        {
            return s.IsPresent && s.ToBool();
        }
    }
}
