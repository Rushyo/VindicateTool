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

        public static SpoofDetectionResult PerformSMBTest(SpoofDetectionResult result, String preferredAddress)
        {
            var tcpClient = new TcpClient(new IPEndPoint(NetworkHelper.GetNetworkAddressInformation(preferredAddress).Address, 0));
            try
            {
                tcpClient.Connect(result.Endpoint.Address, 139);
                return new SpoofDetectionResult
                {
                    Confidence = ConfidenceLevel.Medium,
                    Detected = true,
                    Endpoint = result.Endpoint,
                    Protocol = Protocol.SMB
                };
            }
            catch (Exception ex)
            {
                return new SpoofDetectionResult
                {
                    Confidence = ConfidenceLevel.FalsePositive,
                    Detected = false,
                    Endpoint = result.Endpoint,
                    Protocol = Protocol.SMB,
                    ErrorMessage = ex.Message
                };
            }
            finally
            {
                tcpClient.Close();
            }
        }
    }
}