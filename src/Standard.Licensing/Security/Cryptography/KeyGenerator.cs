﻿//
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
    /// <summary>
    /// Represents a generator for signature keys of <see cref="License"/>.
    /// </summary>
    public class KeyGenerator
    {
        private readonly string curveName;

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyGenerator"/> class
        /// with a key size of 256 bits.
        /// </summary>
        public KeyGenerator()
            : this(256)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyGenerator"/> class
        /// with the specified key size.
        /// </summary>
        /// <remarks>Following key sizes are supported:
        /// - 192
        /// - 224
        /// - 256 (default)
        /// - 384
        /// - 521</remarks>
        /// <param name="keySize">The key size.</param>
        public KeyGenerator(int keySize)
            : this(keySize, RandomNumberGenerator.GetBytes(32))
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyGenerator"/> class
        /// with the specified key size and seed.
        /// </summary>
        /// <remarks>Following key sizes are supported:
        /// - 192
        /// - 224
        /// - 256 (default)
        /// - 384
        /// - 521</remarks>
        /// <param name="keySize">The key size.</param>
        /// <param name="seed">The seed (unused - kept for API compatibility).</param>
        public KeyGenerator(int keySize, byte[] seed)
        {
            curveName = keySize switch
            {
                192 => "P192",
                224 => "P224",
                256 => "P256",
                384 => "P384",
                521 => "P521",
                _ => throw new ArgumentException($"Unsupported key size: {keySize}. Supported sizes are 192, 224, 256, 384, 521.", nameof(keySize))
            };
        }

        /// <summary>
        /// Creates a new instance of the <see cref="KeyGenerator"/> class.
        /// </summary>
        public static KeyGenerator Create()
        {
            return new KeyGenerator();
        }

        /// <summary>
        /// Generates a private/public key pair for license signing.
        /// </summary>
        /// <returns>A <see cref="KeyPair"/> containing the keys.</returns>
        public KeyPair GenerateKeyPair()
        {
            var curve = curveName switch
            {
                "P192" => ECCurve.CreateFromFriendlyName("secp192r1"),
                "P224" => ECCurve.CreateFromFriendlyName("secp224r1"),
                "P256" => ECCurve.CreateFromFriendlyName("secp256r1"),
                "P384" => ECCurve.CreateFromFriendlyName("secp384r1"),
                "P521" => ECCurve.CreateFromFriendlyName("secp521r1"),
                _ => throw new InvalidOperationException($"Unsupported curve: {curveName}")
            };

            var privateKey = ECDsa.Create(curve);
            return new KeyPair(privateKey);
        }
    }
}