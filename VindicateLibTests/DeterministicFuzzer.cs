using System;

namespace VindicateLibTests
{
    public static class DeterministicFuzzer
    {
        public static Byte[] GenerateByteArray(Int32 seed)
        {
            var random = new Random(seed);
            Int32 len = random.Next(100000);
            var array = new Byte[len];
            random.NextBytes(array);
            return array;
        }
    }
}