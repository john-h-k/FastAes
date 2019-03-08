using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Linq.Expressions;
using System.Runtime.Intrinsics;
using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;
using static FastAes.BaseStaticsX86;

namespace Interactive
{
    public unsafe class Program
    {
        private static unsafe void Main(string[] args)
        {
            BenchmarkRunner.Run<AesBenchmark>();

            // Test();

            Console.ReadKey();
        }

        private static void Test()
        {
            RandomNumberGenerator rng = RandomNumberGenerator.Create();

            byte* truePlainText = stackalloc byte[16];
            byte* key = stackalloc byte[16];

            byte* cipherText = stackalloc byte[16];

            rng.GetBytes(new Span<byte>(truePlainText, 16));
            rng.GetBytes(new Span<byte>(key, 16));

            Aes aes = new AesCryptoServiceProvider
            {
                Key = new Span<byte>(key, 16).ToArray(),
                IV = new byte[16],
                Mode = CipherMode.ECB,
                Padding = PaddingMode.None
            };

            var stream = new MemoryStream();

            using (var cryptoStream = new CryptoStream(stream, aes.CreateEncryptor(), CryptoStreamMode.Write))
            {
                cryptoStream.Write(new ReadOnlySpan<byte>(truePlainText, 16));
            }

            byte[] encryptedBytes = stream.ToArray();

            Span<Vector128<byte>> keySchedule = new Vector128<byte>[20];

            LoadKey(key, keySchedule);
            EncryptBlock(keySchedule, truePlainText, cipherText);

            if (encryptedBytes.SequenceEqual(new Span<byte>(cipherText, 16).ToArray()))
                Console.WriteLine("Good encryption");

            byte* plainText = stackalloc byte[16];
            LoadKey(key, keySchedule);
            DecryptBlock(keySchedule, cipherText, plainText);

            stream = new MemoryStream();
            using (var cryptoStream = new CryptoStream(stream, aes.CreateDecryptor(), CryptoStreamMode.Write))
            {
                cryptoStream.Write(new ReadOnlySpan<byte>(cipherText, 16));
            }

            byte[] decryptedBytes = stream.ToArray();

            if (decryptedBytes.SequenceEqual(new Span<byte>(plainText, 16).ToArray()))
                Console.WriteLine("Good decryption");
        }

        [CoreJob(true)]
        [RPlotExporter]
        [RankColumn]
        public class AesBenchmark
        {
            private readonly byte[] _truePlainText = { 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 };
            private readonly byte[] _key = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };

            public AesBenchmark()
            {
                _aes = new AesCryptoServiceProvider
                {
                    Key = _key,
                    IV = new byte[16],
                    Mode = CipherMode.ECB,
                    Padding = PaddingMode.None
                }.CreateEncryptor();
            }

            private readonly ICryptoTransform _aes;

            [Benchmark]
            public void EncryptIntrinsic()
            {
                byte* truePlainText = stackalloc byte[] { 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 };
                byte* key = stackalloc byte[] { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };

                byte* cipherText = stackalloc byte[16];

                Span<Vector128<byte>> keySchedule = new Vector128<byte>[20];

                LoadKey(key, keySchedule);
                EncryptBlock(keySchedule, truePlainText, cipherText);
            }

            [Benchmark]
            public void EncryptStandardSimple()
            {
                var cipherText = new byte[16];
                _aes.TransformBlock(_truePlainText, 0, 16, cipherText, 0);
            }
        }
    }
}
