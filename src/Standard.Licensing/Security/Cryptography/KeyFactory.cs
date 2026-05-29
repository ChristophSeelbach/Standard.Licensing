//
// Copyright © 2012 - 2013 Nauck IT KG     http://www.nauck-it.de
//
// Author:
//  Daniel Nauck        <d.nauck(at)nauck-it.de>
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
// 
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

using System;
using System.Security.Cryptography;

namespace Standard.Licensing.Security.Cryptography
{
    internal static class KeyFactory
    {
        /// <summary>
        /// Encrypts and encodes the private key bytes.
        /// </summary>
        /// <param name="privateKeyBytes">The private key bytes in DER format.</param>
        /// <param name="passPhrase">The pass phrase to encrypt the private key.</param>
        /// <returns>The encrypted private key.</returns>
        public static string ToEncryptedPrivateKeyStringFromBytes(byte[] privateKeyBytes, string passPhrase)
        {
            byte[] salt = RandomNumberGenerator.GetBytes(16);

#pragma warning disable SYSLIB0060
            using (var pbkdf2 = new Rfc2898DeriveBytes(passPhrase, salt, 10, HashAlgorithmName.SHA256))
            {
                byte[] derivedKey = pbkdf2.GetBytes(32);

                using (var aes = Aes.Create())
                {
                    aes.Key = derivedKey;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;

                    using (var encryptor = aes.CreateEncryptor())
                    {
                        byte[] encryptedData = encryptor.TransformFinalBlock(privateKeyBytes, 0, privateKeyBytes.Length);

                        byte[] result = new byte[salt.Length + aes.IV.Length + encryptedData.Length];
                        Buffer.BlockCopy(salt, 0, result, 0, salt.Length);
                        Buffer.BlockCopy(aes.IV, 0, result, salt.Length, aes.IV.Length);
                        Buffer.BlockCopy(encryptedData, 0, result, salt.Length + aes.IV.Length, encryptedData.Length);

                        return Convert.ToBase64String(result);
                    }
                }
            }
#pragma warning restore SYSLIB0060
        }

        /// <summary>
        /// Encrypts and encodes the private key.
        /// </summary>
        /// <param name="key">The private key.</param>
        /// <param name="passPhrase">The pass phrase to encrypt the private key.</param>
        /// <returns>The encrypted private key.</returns>
        public static string ToEncryptedPrivateKeyString(ECDsa key, string passPhrase)
        {
            return ToEncryptedPrivateKeyStringFromBytes(key.ExportECPrivateKey(), passPhrase);
        }

        /// <summary>
        /// Decrypts the provided private key.
        /// </summary>
        /// <param name="privateKey">The encrypted private key.</param>
        /// <param name="passPhrase">The pass phrase to decrypt the private key.</param>
        /// <returns>The private key.</returns>
        public static ECDsa FromEncryptedPrivateKeyString(string privateKey, string passPhrase)
        {
            byte[] data = Convert.FromBase64String(privateKey);

            byte[] salt = new byte[16];
            byte[] iv = new byte[16];
            byte[] encryptedData = new byte[data.Length - 32];

            Buffer.BlockCopy(data, 0, salt, 0, 16);
            Buffer.BlockCopy(data, 16, iv, 0, 16);
            Buffer.BlockCopy(data, 32, encryptedData, 0, encryptedData.Length);

#pragma warning disable SYSLIB0060
            using (var pbkdf2 = new Rfc2898DeriveBytes(passPhrase, salt, 10, HashAlgorithmName.SHA256))
            {
                byte[] derivedKey = pbkdf2.GetBytes(32);

                using (var aes = Aes.Create())
                {
                    aes.Key = derivedKey;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;

                    using (var decryptor = aes.CreateDecryptor())
                    {
                        byte[] decryptedKeyBytes = decryptor.TransformFinalBlock(encryptedData, 0, encryptedData.Length);

                        ECDsa key = ECDsa.Create();
                        key.ImportECPrivateKey(decryptedKeyBytes, out _);
                        return key;
                    }
                }
            }
#pragma warning restore SYSLIB0060
        }

        /// <summary>
        /// Encodes the public key into DER encoding.
        /// </summary>
        /// <param name="key">The public key.</param>
        /// <returns>The encoded public key.</returns>
        public static string ToPublicKeyString(ECDsa key)
        {
            byte[] publicKeyBytes = key.ExportSubjectPublicKeyInfo();
            return Convert.ToBase64String(publicKeyBytes);
        }

        /// <summary>
        /// Decoded the public key from DER encoding.
        /// </summary>
        /// <param name="publicKey">The encoded public key.</param>
        /// <returns>The public key.</returns>
        public static ECDsa FromPublicKeyString(string publicKey)
        {
            byte[] publicKeyBytes = Convert.FromBase64String(publicKey);
            ECDsa key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);
            return key;
        }
    }
}