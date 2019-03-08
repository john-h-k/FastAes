using System;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

using AesVector = System.Runtime.Intrinsics.Vector128<byte>;

[assembly: InternalsVisibleTo("Interactive")]

namespace FastAes
{
    internal static unsafe class BaseStaticsX86
    {
        private const MethodImplOptions MaxOpt = MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization;

        [MethodImpl(MaxOpt)]
        public static AesVector RawEncryptBlock(AesVector block, Span<AesVector> keySchedule)
        {
            block = Sse2.Xor(block, keySchedule[0]);
            block = Aes.Encrypt(block, keySchedule[1]);
            block = Aes.Encrypt(block, keySchedule[2]);
            block = Aes.Encrypt(block, keySchedule[3]);
            block = Aes.Encrypt(block, keySchedule[4]);
            block = Aes.Encrypt(block, keySchedule[5]);
            block = Aes.Encrypt(block, keySchedule[6]);
            block = Aes.Encrypt(block, keySchedule[7]);
            block = Aes.Encrypt(block, keySchedule[8]);
            block = Aes.Encrypt(block, keySchedule[9]);
            block = Aes.EncryptLast(block, keySchedule[10]);

            return block;
        }

        [MethodImpl(MaxOpt)]
        public static AesVector RawDecryptBlock(AesVector block, Span<AesVector> keySchedule)
        {
            block = Sse2.Xor(block, keySchedule[10 + 0]);
            block = Aes.Decrypt(block, keySchedule[10 + 1]);
            block = Aes.Decrypt(block, keySchedule[10 + 2]);
            block = Aes.Decrypt(block, keySchedule[10 + 3]);
            block = Aes.Decrypt(block, keySchedule[10 + 4]);
            block = Aes.Decrypt(block, keySchedule[10 + 5]);
            block = Aes.Decrypt(block, keySchedule[10 + 6]);
            block = Aes.Decrypt(block, keySchedule[10 + 7]);
            block = Aes.Decrypt(block, keySchedule[10 + 8]);
            block = Aes.Decrypt(block, keySchedule[10 + 9]);
            block = Aes.DecryptLast(block, keySchedule[0]);

            return block;
        }

        [MethodImpl(MaxOpt)]
        public static Vector128<byte> KeyExp128(AesVector key, byte num)
        {
            return InternalKeyExp128(key, Aes.KeygenAssist(key, num));
        }

        [MethodImpl(MaxOpt)]
        public static Vector128<byte> InternalKeyExp128(AesVector key, AesVector keyGenAssisted)
        {
            keyGenAssisted = Sse2.Shuffle(keyGenAssisted.As<uint>(), (((3) << 6) | ((3) << 4) | ((3) << 2) | ((3))))
                .As<byte>();
            
            key = Sse2.Xor(key, Aes.ShiftLeftLogical128BitLane(key, 4));
            key = Sse2.Xor(key, Aes.ShiftLeftLogical128BitLane(key, 4));
            key = Sse2.Xor(key, Aes.ShiftLeftLogical128BitLane(key, 4));

            return Sse2.Xor(key, keyGenAssisted);
        }

        [MethodImpl(MaxOpt)]
        public static void LoadEncryptionKeyOnly(byte* key, Span<AesVector> keySchedule)
        {
            keySchedule[0] = Sse2.LoadVector128(key);
            keySchedule[1] = KeyExp128(keySchedule[0], 0x01);
            keySchedule[2] = KeyExp128(keySchedule[1], 0x02);
            keySchedule[3] = KeyExp128(keySchedule[2], 0x04);
            keySchedule[4] = KeyExp128(keySchedule[3], 0x08);
            keySchedule[5] = KeyExp128(keySchedule[4], 0x10);
            keySchedule[6] = KeyExp128(keySchedule[5], 0x20);
            keySchedule[7] = KeyExp128(keySchedule[6], 0x40);
            keySchedule[8] = KeyExp128(keySchedule[7], 0x80);
            keySchedule[9] = KeyExp128(keySchedule[8], 0x1B);
            keySchedule[10] = KeyExp128(keySchedule[9], 0x36);
        }

        [MethodImpl(MaxOpt)]
        public static void LoadKey(byte* key, Span<AesVector> keySchedule)
        {
            LoadEncryptionKeyOnly(key, keySchedule);

            keySchedule[11] = Aes.InverseMixColumns(keySchedule[9]);
            keySchedule[12] = Aes.InverseMixColumns(keySchedule[8]);
            keySchedule[13] = Aes.InverseMixColumns(keySchedule[7]);
            keySchedule[14] = Aes.InverseMixColumns(keySchedule[6]);
            keySchedule[15] = Aes.InverseMixColumns(keySchedule[5]);
            keySchedule[16] = Aes.InverseMixColumns(keySchedule[4]);
            keySchedule[17] = Aes.InverseMixColumns(keySchedule[3]);
            keySchedule[18] = Aes.InverseMixColumns(keySchedule[2]);
            keySchedule[19] = Aes.InverseMixColumns(keySchedule[1]);
        }

        [MethodImpl(MaxOpt)]
        public static void EncryptBlock(Span<AesVector> keySchedule, byte* plainText, byte* cipherTextBuffer)
        {
            Vector128<byte> msg = Sse2.LoadVector128(plainText);

            msg = RawEncryptBlock(msg, keySchedule);

            Sse2.Store(cipherTextBuffer, msg);
        }

        [MethodImpl(MaxOpt)]
        public static void DecryptBlock(Span<AesVector> keySchedule, byte* cipherText, byte* plainTextBuffer)
        {
            Vector128<byte> msg = Sse2.LoadVector128(cipherText);

            msg = RawDecryptBlock(msg, keySchedule);

            Sse2.Store(plainTextBuffer, msg);
        }
    }
}
