/*
    Vindicate - An LLMNR/NBNS/mDNS Spoofing Detection Toolkit
    Copyright (C) 2017 Danny Moules

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/
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