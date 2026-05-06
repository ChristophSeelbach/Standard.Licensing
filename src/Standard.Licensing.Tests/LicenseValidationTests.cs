//
// Copyright (c) 2012 - 2013 Nauck IT KG        http://www.nauck-it.de
// Copyright (c) 2018 - 2024 Junian Triajianto	https://www.junian.dev
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
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NUnit.Framework;
using Standard.Licensing.Validation;

namespace Standard.Licensing.Tests
{
    [TestFixture]
    public class LicenseValidationTests
    {
        private License _expiredLicense;
        private License _notExpiredLicense;

        private static readonly DateTime ExpirationUtc = new DateTime(1899, 12, 31, 0, 0, 0, DateTimeKind.Utc);
        private static readonly DateTime NotExpiredExpirationUtc = new DateTime(2100, 12, 31, 0, 0, 0, DateTimeKind.Utc);

        [SetUp]
        public void SetUp()
        {
            var passPhrase = Guid.NewGuid().ToString();
            var keyGenerator = Security.Cryptography.KeyGenerator.Create();
            var keyPair = keyGenerator.GenerateKeyPair();
            var privateKey = keyPair.ToEncryptedPrivateKeyString(passPhrase);

            _expiredLicense = License.New()
                .WithUniqueIdentifier(new Guid("77d4c193-6088-4c64-9663-ed7398ae8c1a"))
                .As(LicenseType.Trial)
                .ExpiresAt(ExpirationUtc)
                .WithMaximumUtilization(1)
                .LicensedTo("John Doe", "john@doe.tld")
                .CreateAndSignWithPrivateKey(privateKey, passPhrase);

            _notExpiredLicense = License.New()
                .WithUniqueIdentifier(new Guid("77d4c193-6088-4c64-9663-ed7398ae8c1a"))
                .As(LicenseType.Trial)
                .ExpiresAt(NotExpiredExpirationUtc)
                .WithMaximumUtilization(1)
                .LicensedTo("John Doe", "john@doe.tld")
                .CreateAndSignWithPrivateKey(privateKey, passPhrase);
        }

        [Test]
        public void Can_Validate_Valid_Signature()
        {
            var passPhrase = Guid.NewGuid().ToString();
            var keyGenerator = Security.Cryptography.KeyGenerator.Create();
            var keyPair = keyGenerator.GenerateKeyPair();
            var privateKey = keyPair.ToEncryptedPrivateKeyString(passPhrase);
            var publicKey = keyPair.ToPublicKeyString();

			   License license = License.New()
                .WithUniqueIdentifier(new Guid("77d4c193-6088-4c64-9663-ed7398ae8c1a"))
                .As(LicenseType.Trial)
                .ExpiresAt(new DateTime(1899, 12, 31, 0, 0, 0, DateTimeKind.Utc))
                .WithMaximumUtilization(1)
                .LicensedTo("John Doe", "john@doe.tld")
                .CreateAndSignWithPrivateKey(privateKey, passPhrase);

            var validationResults = license
                .Validate()
                .Signature(publicKey)
                .AssertValidLicense();

            Assert.That(validationResults, Is.Not.Null);
            Assert.That(validationResults.Count(), Is.EqualTo(0));
        }

        [Test]
        public void Can_Validate_Invalid_Signature()
        {
            var passPhrase = Guid.NewGuid().ToString();
            var keyGenerator = Security.Cryptography.KeyGenerator.Create();
            var keyPair = keyGenerator.GenerateKeyPair();
            var privateKey = keyPair.ToEncryptedPrivateKeyString(passPhrase);
            var publicKey = keyPair.ToPublicKeyString();

			   License license = License.New()
                .WithUniqueIdentifier(new Guid("77d4c193-6088-4c64-9663-ed7398ae8c1a"))
                .As(LicenseType.Trial)
                .ExpiresAt(new DateTime(1899, 12, 31, 0, 0, 0, DateTimeKind.Utc))
                .WithMaximumUtilization(1)
                .LicensedTo("John Doe", "john@doe.tld")
                .CreateAndSignWithPrivateKey(privateKey, passPhrase);

			   License tamperedLicense = License.Load(license.ToString().Replace("<Quantity>1</Quantity>", "<Quantity>999</Quantity>"));

            var validationResults = tamperedLicense
                .Validate()
                .Signature(publicKey)
                .AssertValidLicense().ToList();

            Assert.That(validationResults, Is.Not.Null);
            Assert.That(validationResults.Count(), Is.EqualTo(1));
            Assert.That(validationResults.FirstOrDefault(), Is.TypeOf<InvalidSignatureValidationFailure>());
        }

        [Test]
        public void Can_Validate_Expired_ExpirationDate()
        {
            Assert.That(_expiredLicense.Expiration.Kind, Is.EqualTo(DateTimeKind.Utc));

            var validationResults = _expiredLicense
                .Validate()
                .ExpirationDate()
                .AssertValidLicense().ToList();

            Assert.That(validationResults, Is.Not.Null);
            Assert.That(validationResults.Count(), Is.EqualTo(1));
            Assert.That(validationResults.FirstOrDefault(), Is.TypeOf<LicenseExpiredValidationFailure>());
        }

        [Test]
        public void Can_Validate_NotExpired_ExpirationDate()
        {
            Assert.That(_notExpiredLicense.Expiration.Kind, Is.EqualTo(DateTimeKind.Utc));

            var validationResults = _notExpiredLicense
                .Validate()
                .ExpirationDate()
                .AssertValidLicense().ToList();

            Assert.That(validationResults, Is.Not.Null);
            Assert.That(validationResults.Count(), Is.EqualTo(0));
        }

        public static IEnumerable<TestCaseData> LocalAndUtcExpired
        {
            get
            {
                var expirationLocalDate = new DateTime(ExpirationUtc.Year, ExpirationUtc.Month, ExpirationUtc.Day, 0, 0, 0, DateTimeKind.Local);
                var expirationLocalDateAtOneMinutePastMidnight = expirationLocalDate.AddMinutes(1);
                var expirationLocalDateAtThirtyMinutesPastMidnight = expirationLocalDate.AddMinutes(30);
                var expirationLocalDateAtNoon = expirationLocalDate.AddHours(12);
                var expirationLocalDateTomorrow = expirationLocalDate.AddDays(1);

                yield return new TestCaseData(expirationLocalDate);
                yield return new TestCaseData(expirationLocalDateAtOneMinutePastMidnight);
                yield return new TestCaseData(expirationLocalDateAtThirtyMinutesPastMidnight);
                yield return new TestCaseData(expirationLocalDateAtNoon);
                yield return new TestCaseData(expirationLocalDateTomorrow);

                yield return new TestCaseData(expirationLocalDate.ToUniversalTime());
                yield return new TestCaseData(expirationLocalDateAtOneMinutePastMidnight.ToUniversalTime());
                yield return new TestCaseData(expirationLocalDateAtThirtyMinutesPastMidnight.ToUniversalTime());
                yield return new TestCaseData(expirationLocalDateAtNoon.ToUniversalTime());
                yield return new TestCaseData(expirationLocalDateTomorrow.ToUniversalTime());
            }
        }

        [Test, TestCaseSource(nameof(LocalAndUtcExpired))]
        public void Can_Validate_Expired_ExpirationDate_CustomDateTime(DateTime currentDate)
        {
            Assert.That(_expiredLicense.Expiration.Kind, Is.EqualTo(DateTimeKind.Utc));

            var validationResults = _expiredLicense
                .Validate()
                .ExpirationDate(systemDateTime: currentDate)
                .AssertValidLicense().ToList();

            Assert.That(validationResults, Is.Not.Null);
            Assert.That(validationResults.Count(), Is.EqualTo(1));
            Assert.That(validationResults.FirstOrDefault(), Is.TypeOf<LicenseExpiredValidationFailure>());
        }

        public static IEnumerable<TestCaseData> LocalAndUtcNotExpired
        {
            get
            {
                var dayBeforeExpirationLocalDate = new DateTime(ExpirationUtc.Year, ExpirationUtc.Month, ExpirationUtc.Day, 0, 0, 0, DateTimeKind.Local).AddDays(-1);
                var dayBeforeExpirationLocalDateAtOneMinutePastMidnight = dayBeforeExpirationLocalDate.AddMinutes(1);
                var dayBeforeExpirationLocalDateAtThirtyMinutesPastMidnight = dayBeforeExpirationLocalDate.AddMinutes(30);
                var dayBeforeExpirationLocalDateAtNoon = dayBeforeExpirationLocalDate.AddHours(12);
                var dayBeforeExpirationLocalDateAtThirtyMinutesBeforeMidnight = dayBeforeExpirationLocalDate.AddHours(23).AddMinutes(30);
                var dayBeforeExpirationLocalDateAtOneMinuteBeforeMidnight = dayBeforeExpirationLocalDate.AddHours(23).AddMinutes(59);

                yield return new TestCaseData(dayBeforeExpirationLocalDate);
                yield return new TestCaseData(dayBeforeExpirationLocalDateAtOneMinutePastMidnight);
                yield return new TestCaseData(dayBeforeExpirationLocalDateAtThirtyMinutesPastMidnight);
                yield return new TestCaseData(dayBeforeExpirationLocalDateAtNoon);
                yield return new TestCaseData(dayBeforeExpirationLocalDateAtThirtyMinutesBeforeMidnight);
                yield return new TestCaseData(dayBeforeExpirationLocalDateAtOneMinuteBeforeMidnight);

                yield return new TestCaseData(dayBeforeExpirationLocalDate.ToUniversalTime());
                yield return new TestCaseData(dayBeforeExpirationLocalDateAtOneMinutePastMidnight.ToUniversalTime());
                yield return new TestCaseData(dayBeforeExpirationLocalDateAtThirtyMinutesPastMidnight.ToUniversalTime());
                yield return new TestCaseData(dayBeforeExpirationLocalDateAtNoon.ToUniversalTime());
                yield return new TestCaseData(dayBeforeExpirationLocalDateAtThirtyMinutesBeforeMidnight.ToUniversalTime());
                yield return new TestCaseData(dayBeforeExpirationLocalDateAtOneMinuteBeforeMidnight.ToUniversalTime());
            }
        }

        [Test, TestCaseSource(nameof(LocalAndUtcNotExpired))]
        public void Can_Validate_NotExpired_ExpirationDate_CustomDateTime(DateTime currentDate)
        {
            Assert.That(_expiredLicense.Expiration.Kind, Is.EqualTo(DateTimeKind.Utc));

            var validationResults = _expiredLicense
                .Validate()
                .ExpirationDate(systemDateTime: currentDate)
                .AssertValidLicense().ToList();

            Assert.That(validationResults, Is.Not.Null);
            Assert.That(validationResults.Count(), Is.EqualTo(0));
        }

        [Test]
        public void Can_Validate_CustomAssertion()
        {
            var passPhrase = Guid.NewGuid().ToString();
            var keyGenerator = Security.Cryptography.KeyGenerator.Create();
            var keyPair = keyGenerator.GenerateKeyPair();
            var privateKey = keyPair.ToEncryptedPrivateKeyString(passPhrase);
            var publicKey = keyPair.ToPublicKeyString();

            var license = License.New()
                .WithUniqueIdentifier(new Guid("77d4c193-6088-4c64-9663-ed7398ae8c1a"))
                .As(LicenseType.Trial)
                .ExpiresAt(new DateTime(2009, 12, 31, 23, 0, 0, DateTimeKind.Utc))
                .WithMaximumUtilization(1)
                .LicensedTo("John Doe", "john@doe.tld")
                .WithAdditionalAttributes(new Dictionary<string, string>
                    {
                        {"Assembly Signature", "123456789"},
                    })
                .WithProductFeatures(new Dictionary<string, string>
                    {
                        {"Sales Module", "yes"},
                        {"Workflow Module", "yes"},
                        {"Maximum Transactions", "10000"},
                    })
                .CreateAndSignWithPrivateKey(privateKey, passPhrase);

            var validationResults = license
                .Validate()
                .AssertThat(lic => lic.ProductFeatures.Contains("Sales Module"),
                            new GeneralValidationFailure {Message = "Sales Module not licensed!"})
                .And()
                .AssertThat(lic => lic.AdditionalAttributes.Get("Assembly Signature") == "123456789",
                            new GeneralValidationFailure {Message = "Assembly Signature does not match!"})
                .And()
                .Signature(publicKey)
                .AssertValidLicense().ToList();

            Assert.That(validationResults, Is.Not.Null);
            Assert.That(validationResults.Count(), Is.EqualTo(0));
        }

        [Test]
        public void Do_Not_Crash_On_Invalid_Data()
        {
            var publicKey = "1234";
            var licenseData =
                @"<license expiration='2013-06-30T00:00:00.0000000' type='Trial'><name>John Doe</name></license>";

            var license = License.Load(licenseData);

            var validationResults = license
                .Validate()
                .ExpirationDate()
                .And()
                .Signature(publicKey)
                .AssertValidLicense().ToList();

            Assert.That(validationResults, Is.Not.Null);
            Assert.That(validationResults.Count(), Is.EqualTo(1));
            Assert.That(validationResults.FirstOrDefault(), Is.TypeOf<InvalidSignatureValidationFailure>());

        }

        [Test]
        public void Test_ValidationChainBuilder_ValidationFailure_List()
        {
            var keyGenerator = Standard.Licensing.Security.Cryptography.KeyGenerator.Create();
            var keyPair = keyGenerator.GenerateKeyPair();
            var publicKey = keyPair.ToPublicKeyString();

            var invalidLicense = @"<License>
  <Signature>WFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFg=</Signature>
</License>";

            var licenseToVerify = License.Load(invalidLicense);

            var validationFailures = licenseToVerify
                .Validate()
                .Signature(publicKey)
                .AssertValidLicense();

            var count = 0;
            foreach (var v in validationFailures)
                count++;

            Assert.That(count, Is.EqualTo(1));
            Assert.That(validationFailures.ToArray().Length, Is.EqualTo(1));
            Assert.That(validationFailures.ToArray().Length, Is.EqualTo(1));
        }

        [Test]
        public void ExpirationDate_IsInvalidStartingAtLocalMidnight_OnStoredExpirationDate()
        {
            var passPhrase = Guid.NewGuid().ToString();
            var keyGenerator = Security.Cryptography.KeyGenerator.Create();
            var keyPair = keyGenerator.GenerateKeyPair();
            var privateKey = keyPair.ToEncryptedPrivateKeyString(passPhrase);

            var expirationUtc = new DateTime(2030, 6, 1, 0, 0, 0, DateTimeKind.Utc);
            var license = License.New()
                .WithUniqueIdentifier(new Guid("77d4c193-6088-4c64-9663-ed7398ae8c1a"))
                .As(LicenseType.Trial)
                .ExpiresAt(expirationUtc)
                .WithMaximumUtilization(1)
                .LicensedTo("John Doe", "john@doe.tld")
                .CreateAndSignWithPrivateKey(privateKey, passPhrase);

            var oneMinuteBeforeLocalMidnight = new DateTime(2030, 5, 31, 23, 59, 0, DateTimeKind.Local);
            var atLocalMidnight = new DateTime(2030, 6, 1, 0, 0, 0, DateTimeKind.Local);

            var validationBeforeMidnight = license
                .Validate()
                .ExpirationDate(systemDateTime: oneMinuteBeforeLocalMidnight)
                .AssertValidLicense().ToList();

            var validationAtMidnight = license
                .Validate()
                .ExpirationDate(systemDateTime: atLocalMidnight)
                .AssertValidLicense().ToList();

            Assert.That(validationBeforeMidnight, Is.Not.Null);
            Assert.That(validationBeforeMidnight.Count(), Is.EqualTo(0));

            Assert.That(validationAtMidnight, Is.Not.Null);
            Assert.That(validationAtMidnight.Count(), Is.EqualTo(1));
            Assert.That(validationAtMidnight.FirstOrDefault(), Is.TypeOf<LicenseExpiredValidationFailure>());
        }
    }
}