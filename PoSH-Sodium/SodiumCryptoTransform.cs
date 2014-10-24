using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Runtime.ConstrainedExecution;
using System.Runtime.CompilerServices;
using Sodium;

namespace PoSH_Sodium
{
    public class SodiumCryptoTransform : ICryptoTransform
    {
        private byte[] nonce;
        private byte[] privateKey;
        private byte[] publicKey;
        private bool canReuseTransform;

        private bool canTransformMultipleBlocks;
        private int inputBlockSize;
        private int outputBlockSize;
        private Direction direction;

        private byte[] key;

        public enum Direction
        {
            Encrypt,
            Decrypt
        }

        public SodiumCryptoTransform(byte[] Nonce, byte[] PrivateKey, byte[] PublicKey, Direction Direction)
        {
            privateKey = PrivateKey;
            publicKey = PublicKey;
            nonce = Nonce;

            canReuseTransform = false;
            canTransformMultipleBlocks = false;
            direction = Direction;
            if (direction == SodiumCryptoTransform.Direction.Encrypt)
            {
                inputBlockSize = 4096; //must be larger than 24, nonce is at end
                outputBlockSize = 4112;
            }
            else
            {
                inputBlockSize = 4112;
                outputBlockSize = 4096;
            }
            //block size?
        }

        public SodiumCryptoTransform(byte[] Nonce, byte[] SymmetricKey, Direction Direction)
        {
            key = SymmetricKey;
            nonce = Nonce;
            canReuseTransform = false;
            canTransformMultipleBlocks = false;
            direction = Direction;
            if (direction == SodiumCryptoTransform.Direction.Encrypt)
            {
                inputBlockSize = 4096; //must be larger than 24, nonce is at end
                outputBlockSize = 4112;
            }
            else
            {
                inputBlockSize = 4112;
                outputBlockSize = 4096;
            }
        }


        public bool CanReuseTransform { get { return canReuseTransform; } }
        public bool CanTransformMultipleBlocks { get { return canTransformMultipleBlocks; } }
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
                DetachedBox detachedBox;
                if (key != null)
                    detachedBox = SecretBox.CreateDetached(message, nonce, key);
                else
                    detachedBox = PublicKeyBox.CreateDetached(message, nonce, privateKey, publicKey);
                Array.Copy(detachedBox.CipherText, 0, outputBuffer, outputOffset, detachedBox.CipherText.Length);
                Array.Copy(detachedBox.Mac, 0, outputBuffer, outputOffset + detachedBox.CipherText.Length, detachedBox.Mac.Length);
                return detachedBox.CipherText.Length + detachedBox.Mac.Length;
            }
            else
            {
                var cipherText = new byte[inputCount - 16];
                var mac = new byte[16];
                Array.Copy(message, 0, cipherText, 0, cipherText.Length);
                Array.Copy(message, cipherText.Length, mac, 0, mac.Length);
                byte[] decryptedData;
                if (key != null)
                    decryptedData = SecretBox.OpenDetached(cipherText, mac, nonce, key);
                else
                    decryptedData = PublicKeyBox.OpenDetached(cipherText, mac, nonce, privateKey, publicKey);
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
                DetachedBox detachedBox;
                if (key != null)
                    detachedBox = SecretBox.CreateDetached(message, nonce, key);
                else
                    detachedBox = PublicKeyBox.CreateDetached(message, nonce, privateKey, publicKey);
                var results = new byte[detachedBox.CipherText.Length + detachedBox.Mac.Length];
                Array.Copy(detachedBox.CipherText, results, detachedBox.CipherText.Length);
                Array.Copy(detachedBox.Mac, 0, results, detachedBox.CipherText.Length, detachedBox.Mac.Length);
                return results;
            }
            else
            {
                //ignore this is mac and nonce?
                if (message.Length > 0)
                {
                    var cipherText = new byte[inputCount - 40];
                    var mac = new byte[16];
                    Array.Copy(message, 0, cipherText, 0, cipherText.Length);
                    Array.Copy(message, cipherText.Length, mac, 0, mac.Length);
                    if (cipherText.Length > 0)
                    {
                        byte[] decryptedData;
                        if (key != null)
                            decryptedData = SecretBox.OpenDetached(cipherText, mac, nonce, key);
                        else
                            decryptedData = PublicKeyBox.OpenDetached(cipherText, mac, nonce, privateKey, publicKey);
                        return decryptedData;
                    }
                }
                return new byte[0];
                //return new byte[0];
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

        ~SodiumCryptoTransform()
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
