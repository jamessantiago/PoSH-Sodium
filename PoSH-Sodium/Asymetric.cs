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

    public class AsymetricCryptoTransform : ICryptoTransform
    {
        private byte[] nonce;
        private byte[] privateKey;
        private byte[] publicKey;
        private byte[] mac;
        private bool canReuseTransform;

        private bool canTransformMultipleBlocks;
        private int inputBlockSize;
        private int outputBlockSize;
        private Direction direction;

        public enum Direction
        {
            Encrypt,
            Decrypt
        }

        public AsymetricCryptoTransform(byte[] Nonce, byte[] Mac, byte[] PrivateKey, byte[] PublicKey, Direction Direction)
        {
            privateKey = PrivateKey;
            publicKey = PublicKey;
            nonce = Nonce;

            canReuseTransform = false;
            canTransformMultipleBlocks = true;
            direction = Direction;
            mac = Mac;
            inputBlockSize = 16;
            outputBlockSize = 16;
            //block size?
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
            //IncrementNonce(ref nonce, nonce.Length - 1);
            byte[] message = new byte[inputCount];
            Array.Copy(inputBuffer, inputOffset, message, 0, inputCount);

            if (direction == Direction.Encrypt)
            {
                var detatchedBox = PublicKeyBox.CreateDetached(message, nonce, privateKey, publicKey);
                mac = detatchedBox.Mac;
                Array.Copy(detatchedBox.CipherText, 0, outputBuffer, outputOffset, detatchedBox.CipherText.Length);
                return detatchedBox.CipherText.Length;
            }
            else
            {
                var decryptedData = PublicKeyBox.OpenDetached(message, mac, nonce, privateKey, publicKey);
                Array.Copy(decryptedData, 0, outputBuffer, outputOffset, decryptedData.Length);
                return decryptedData.Length;
            }
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            //increment nonce?
            byte[] message = new byte[inputCount];
            Array.Copy(inputBuffer, inputOffset, message, 0, inputCount);

            if (direction == Direction.Encrypt)
            {
                var detatchedBox = PublicKeyBox.CreateDetached(message, nonce, privateKey, publicKey);
                mac = detatchedBox.Mac;
                return detatchedBox.CipherText;
            }
            else
            {
                var decryptedData = PublicKeyBox.OpenDetached(message, mac, nonce, privateKey, publicKey);
                return decryptedData;
            }
            
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

        ~AsymetricCryptoTransform()
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