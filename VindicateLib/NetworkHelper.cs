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
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace VindicateLib
{
    internal static class NetworkHelper
    {
        public static UnicastIPAddressInformation GetNetworkAddressInformation(String preferredAddress)
        {
            //Get list of active IPv4 interface addresses
#warning GetAllNetworkInterfaces not supported outside Linux + Windows
            IEnumerable<UnicastIPAddressInformation> eligibleAddresses = NetworkInterface
                .GetAllNetworkInterfaces()
                .Where(i => i.OperationalStatus == OperationalStatus.Up || i.OperationalStatus == OperationalStatus.Unknown)
                .SelectMany(i => i.GetIPProperties().UnicastAddresses)
                .Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork);

            //Get preferred address or first available address iff no preferred address requested
            return preferredAddress == null ? eligibleAddresses.FirstOrDefault() : eligibleAddresses.FirstOrDefault(a => a.Address.ToString() == preferredAddress);
        }

        public static String GetBroadcastAddress(String preferredAddress)
        {
            UnicastIPAddressInformation localAddress = GetNetworkAddressInformation(preferredAddress);
            if (localAddress == null)
                return null;

            //Apply subnet mask to chosen address to get broadcast address
            Byte[] subnetMask = localAddress.IPv4Mask.GetAddressBytes();
            Byte[] address = localAddress.Address.GetAddressBytes();
            for (var i = 0; i < 4; i++)
                address[i] |= (Byte)(subnetMask[i] ^ 255);
            return String.Join(".", address);
        }
    }
}