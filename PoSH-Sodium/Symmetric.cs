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

    public class SymmetricCryptoTransform : ICryptoTransform
    {
        private byte[] nonce;
        private byte[] key;
        private byte[] mac;
        private bool canReuseTransform;

        private bool canTransformMultipleBlocks;
        private int inputBlockSize;
        private int outputBlockSize;


        public SymmetricCryptoTransform(byte[] Nonce, byte[] Key)
        {
            key = Key;
            nonce = Nonce;
            //block size?

            canReuseTransform = false;
            canTransformMultipleBlocks = true;
        }


        public byte[] Mac { get { return mac; } }

        // Summary:
        //     Gets a value indicating whether the current transform can be reused.
        //
        // Returns:
        //     true if the current transform can be reused; otherwise, false.
        public bool CanReuseTransform { get { return canReuseTransform; } }
        //
        // Summary:
        //     Gets a value indicating whether multiple blocks can be transformed.
        //
        // Returns:
        //     true if multiple blocks can be transformed; otherwise, false.
        public bool CanTransformMultipleBlocks { get { return canTransformMultipleBlocks; } }
        //
        // Summary:
        //     Gets the input block size.
        //
        // Returns:
        //     The size of the input data blocks in bytes.
        public int InputBlockSize { get { return inputBlockSize; } }
 
        public int OutputBlockSize { get { return outputBlockSize; } }


        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            //Global alloc safe handles?
            IncrementNonce(ref nonce, nonce.Length - 1);
            byte[] message = new byte[inputCount];
            Array.Copy(inputBuffer, inputOffset, message, 0, inputCount);
            var detatchedBox = SecretBox.CreateDetached(message, nonce, key);
            mac = detatchedBox.Mac;
            Array.Copy(detatchedBox.CipherText, 0, outputBuffer, outputOffset, detatchedBox.CipherText.Length);            
            return detatchedBox.CipherText.Length;
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            //increment nonce?
            byte[] message = new byte[inputCount];
            Array.Copy(inputBuffer, inputOffset, message, 0, inputCount);
            var detatchedBox = SecretBox.CreateDetached(message, nonce, key);
            mac = detatchedBox.Mac;
            return detatchedBox.CipherText;
        }

        private bool IncrementNonce(ref byte[] nonce, int position)
        {
            if (nonce[position] == 0xFF)
            {
                if (position != 0)
                {
                    if (IncrementNonce(ref nonce, position - 1))
                    {
                        nonce[position] = 0x00;
                        return true;
                    }
                    else return false;
                }
                else return false;
            }
            else
            {
                nonce[position] += 1;
                return true;
            }
        }

        public void Dispose()
        {
            this.Dispose(true);
            GC.SuppressFinalize(this);
        }

        ~SymmetricCryptoTransform()
        {
            Dispose(false);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                //kill things
            }
        }
    }
}
