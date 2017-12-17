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
using System.Net;
using System.Net.Sockets;
using VindicateLib.Enums;

namespace VindicateLib
{
    internal static class SMBTester
    {

        public static SpoofDetectionResult PerformSMBTest(SpoofDetectionResult responseResult, String preferredAddress)
        {
            String error = TryTCPPort(responseResult, preferredAddress, 139);
            if (error == null)
                return DiscoveredSMBResult(responseResult, 139);
            error = TryTCPPort(responseResult, preferredAddress, 445);
            if (error == null)
                return DiscoveredSMBResult(responseResult, 445);

            return new SpoofDetectionResult
            {
                Confidence = ConfidenceLevel.FalsePositive,
                Detected = false,
                Endpoint = new IPEndPoint(responseResult.Endpoint.Address, 445),
                Protocol = Protocol.SMB,
                ErrorMessage = error
            };
        }

        private static SpoofDetectionResult DiscoveredSMBResult(SpoofDetectionResult responseResult, Int32 port)
        {
            return new SpoofDetectionResult
            {
                Confidence = ConfidenceLevel.Medium,
                Detected = true,
                Endpoint = new IPEndPoint(responseResult.Endpoint.Address, port),
                Protocol = Protocol.SMB,
                Response = "Open"
            };
        }

        private static String TryTCPPort(SpoofDetectionResult responseResult, String preferredAddress, Int32 port)
        {
            var tcpClient = new TcpClient(new IPEndPoint(NetworkHelper.GetNetworkAddressInformation(preferredAddress).Address,
                0));
            try
            {
                tcpClient.Connect(responseResult.Endpoint.Address, port);
                return null;
            }
            catch (SocketException ex)
            {
                return ex.Message;
            }
            finally
            {
                tcpClient.Close();
            }
        }
    }
}