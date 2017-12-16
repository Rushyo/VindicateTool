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
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using VindicateLib.Enums;
using VindicateLib.Interfaces;

namespace VindicateLib
{
    internal class NameServiceClientImpl
    {
        private const Int32 LLMNROutboundPort = 5355;
        private const Int32 NBNSOutboundPort = 137;
        // ReSharper disable once InconsistentNaming
        private const Int32 mDNSOutboundPort = 5353;
        private readonly Random _random = new Random();

        public Byte[] SendRequest(UdpClient client, Protocol protocol, String lookupName, String subnetBroadcastAddress, IClientActioner clientActioner)
        {
            //Define random transaction ID where relevant
            var transactionId = new Byte[] {0, 0};
            if (protocol != Protocol.mDNS)
                _random.NextBytes(transactionId); //TODO: Replace bad random, not that it matters too much

            //Encode NETBIOS name
            if (protocol == Protocol.NBNS)
                lookupName = EncodeNetBiosName(lookupName, 0x20); //File server service

            //Create datagram
            Byte[] datagram = CreateRequestDatagram(protocol, lookupName, transactionId);

            //Send datagram
            if (protocol == Protocol.LLMNR)
                clientActioner.Send(client, datagram, datagram.Length, "224.0.0.252", LLMNROutboundPort);
            else if (protocol == Protocol.NBNS)
                clientActioner.Send(client, datagram, datagram.Length, subnetBroadcastAddress, NBNSOutboundPort);
            else if (protocol == Protocol.mDNS)
                clientActioner.Send(client, datagram, datagram.Length, "224.0.0.251", mDNSOutboundPort);
            else
                throw new InvalidOperationException("Unknown protocol");
            return transactionId;
        }

        internal SpoofDetectionResult ReceiveAndHandleReply(UdpClient client, Protocol protocol, Byte[] transactionId, IClientActioner clientActioner)
        {
            IPEndPoint sender = null;
            Byte[] replyBuffer;
            try
            {
                replyBuffer = clientActioner.Receive(client, ref sender);
            }
            catch (SocketException ex)
            {
                if(ex.ErrorCode == 10060) //Timeout
                    return null;
                if (ex.ErrorCode == 10004) //Aborted
                    return null;
                throw;
            }

            if (sender != null && replyBuffer.Length > 0)
            {
                var result = new SpoofDetectionResult
                {
                    Confidence = ConfidenceLevel.FalsePositive,
                    Detected = false,
                    Endpoint = null,
                    ErrorMessage = String.Format("Unable to parse packet sent to port {0}",
                        ((IPEndPoint) client.Client.LocalEndPoint).Port)
                };
                try
                {
                    result = HandleReply(replyBuffer, sender, transactionId, protocol);
                }
                catch (Exception)
                {
                    //Omnomnom - There's all sorts of reasons the parser might crash on a packet, we need to handle all of them
                    //until the parser is able to handle those exceptions itself
                }

                return result;
            }
            return null;
        }

        private static Byte[] CreateRequestDatagram(Protocol protocol, String lookupName, Byte[] transactionId)
        {
            var datagram = new List<Byte>();

            //Transaction ID
            datagram.AddRange(transactionId);
            Debug.Assert(datagram.Count == 2);

            //Flags
            if (protocol == Protocol.LLMNR || protocol == Protocol.mDNS)
                datagram.AddRange(new Byte[] { 0x00, 0x00 });
            else if (protocol == Protocol.NBNS)
                datagram.AddRange(new Byte[] { 0x01, 0x10 });
            else
                throw new InvalidOperationException(@"Unknown protocol");
            Debug.Assert(datagram.Count == 4);
            //Questions
            datagram.AddRange(BitConverter.GetBytes((UInt16)1).Reverse());
            Debug.Assert(datagram.Count == 6);
            //Responses
            datagram.AddRange(new Byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
            Debug.Assert(datagram.Count == 12);

            //Query
            Byte[] nameBytes = Encoding.ASCII.GetBytes(lookupName);
            datagram.Add(BitConverter.GetBytes((Byte)nameBytes.Length).Reverse().Last());
            Debug.Assert(datagram.Count == 13);
            datagram.AddRange(nameBytes);
            Int32 totalNameBytes = nameBytes.Length;
            Debug.Assert(datagram.Count == 13 + totalNameBytes);

            //Additional query label(s)
            if (protocol == Protocol.mDNS)
            {
                Byte[] localLabelBytes = Encoding.ASCII.GetBytes(@"local");
                datagram.Add(BitConverter.GetBytes((Byte)localLabelBytes.Length).Reverse().Last());
                totalNameBytes++;
                Debug.Assert(datagram.Count == 13 + totalNameBytes);
                datagram.AddRange(localLabelBytes);
                totalNameBytes += localLabelBytes.Length;
                Debug.Assert(datagram.Count == 13 + totalNameBytes);
            }

            //Final null
            datagram.Add(0x00);
            Debug.Assert(datagram.Count == 14 + totalNameBytes);

            //Additional fields
            if (protocol == Protocol.LLMNR)
                datagram.AddRange(new Byte[] { 0x00, 0x01 }); //Type (A Record IPv4)
            else if (protocol == Protocol.NBNS)
                datagram.AddRange(new Byte[] { 0x00, 0x20 }); //Type (NS)
            //else if (protocol == Protocol.mDNS)
            //    datagram.AddRange(new Byte[] { 0x00, 0x0C }); //Type (PTR)
            else if (protocol == Protocol.mDNS)
                datagram.AddRange(new Byte[] { 0x00, 0x01 }); //Type (A Record IPv4)
            Debug.Assert(datagram.Count == 16 + totalNameBytes);
            datagram.AddRange(new Byte[] { 0x00, 0x01 }); //Class (IN)
            Debug.Assert(datagram.Count == 18 + totalNameBytes);
            return datagram.ToArray();
        }


        //Parses a name service response packet received
        internal static SpoofDetectionResult HandleReply(Byte[] replyBuffer, IPEndPoint remoteEndpoint, Byte[] senderTransactionId, Protocol protocol)
        {
            Byte[] replyTransactionId = replyBuffer.Skip(0).Take(2).ToArray();
            //if(!replyTransactionId.SequenceEqual(senderTransactionId))
            //    return new SpoofDetectionResult() { Detected = false, Endpoint = remoteEndpoint, ErrorMessage = "Incorrect transaction ID or not LLMNR/NBNS"};

            Byte[] flags = replyBuffer.Skip(2).Take(2).ToArray();
            if (protocol == Protocol.LLMNR)
            {
                if (!flags.SequenceEqual(new Byte[] { 0x80, 0x00 }))
                    return new SpoofDetectionResult()
                    {
                        Detected = false,
                        Endpoint = remoteEndpoint,
                        ErrorMessage = "Did not expect LLMNR flags other than 0x8000",
                        Confidence = ConfidenceLevel.FalsePositive,
                        Protocol = Protocol.Unknown
                    };
            }
            else if (protocol == Protocol.NBNS)
            {
                if (flags[0] == 0x00) //Query, not response
                {
                    return new SpoofDetectionResult()
                    {
                        Detected = false,
                        Endpoint = remoteEndpoint,
                        ErrorMessage = "Received NBNS query but expected response",
                        Confidence = ConfidenceLevel.FalsePositive,
                        Protocol = Protocol.Unknown
                    };
                }
                if (flags[1] == 0x03) //Told not on network
                {
                    return new SpoofDetectionResult()
                    {
                        Detected = false,
                        Endpoint = remoteEndpoint,
                        ErrorMessage = "NBNS target not in network",
                        Confidence = ConfidenceLevel.FalsePositive,
                        Protocol = Protocol.Unknown
                    };
                }
                if (flags[0] >> 4 != 0x08)
                {
                    return new SpoofDetectionResult()
                    {
                        Detected = false,
                        Endpoint = remoteEndpoint,
                        ErrorMessage = "Did not expect first 4 bits of NBNS flag to be anything other than 0x1000",
                        Confidence = ConfidenceLevel.FalsePositive,
                        Protocol = Protocol.Unknown
                    };
                }
            }
            else if (protocol == Protocol.mDNS)
            {
                if (flags[0] == 0x00) //Query, not response
                {
                    return new SpoofDetectionResult()
                    {
                        Detected = false,
                        Endpoint = remoteEndpoint,
                        ErrorMessage = "Received mDNS query but expected response",
                        Confidence = ConfidenceLevel.FalsePositive,
                        Protocol = Protocol.Unknown
                    };
                }
                if (flags[0] >> 4 != 0x08)
                {
                    return new SpoofDetectionResult()
                    {
                        Detected = false,
                        Endpoint = remoteEndpoint,
                        ErrorMessage = "Did not expect first 4 bits of mDNS flag to be anything other than 0x1000",
                        Confidence = ConfidenceLevel.FalsePositive,
                        Protocol = Protocol.Unknown
                    };
                }
            }
            else
            {
                throw new InvalidOperationException("Unknown protocol");
            }

            Int32 questions = BitConverter.ToUInt16(replyBuffer.Skip(4).Take(2).Reverse().ToArray(), 0);
            //if(questions != 1 && protocol == Protocol.LLMNR)
            //    return new SpoofDetectionResult() { Detected = false, Endpoint = remoteEndpoint, ErrorMessage = "Response was to questions <> 1" };

            Int32 answerResponses = BitConverter.ToUInt16(replyBuffer.Skip(6).Take(2).Reverse().ToArray(), 0);
            Int32 authorityResponses = BitConverter.ToUInt16(replyBuffer.Skip(8).Take(2).Reverse().ToArray(), 0);
            Int32 additionalResponses = BitConverter.ToUInt16(replyBuffer.Skip(10).Take(2).Reverse().ToArray(), 0);
            Int32 totalResponses = answerResponses + authorityResponses + additionalResponses;
            if (answerResponses == 0)
                return new SpoofDetectionResult() { Detected = false, Endpoint = remoteEndpoint, ErrorMessage = "Received reply with no answers", Confidence = ConfidenceLevel.FalsePositive };

            var queryListBytes = new ArraySegment<Byte>(replyBuffer, 12, replyBuffer.Length - 12);

            Boolean isQuestion = questions > 0;

            Byte[] bytesRemaining = queryListBytes.ToArray();
            while (bytesRemaining.Length > 0)
            {
                Byte nameLength = bytesRemaining.First();
                if (isQuestion)
                {
                    Int32 queryDataLength = nameLength + 6;
                    bytesRemaining = bytesRemaining.Skip(queryDataLength).ToArray();
                    isQuestion = false;
                }
                else
                {
                    Int32 queryDataLength = nameLength + 6;
                    Byte[] nameData = bytesRemaining.Skip(1).Take(nameLength).ToArray();
                    String nameString = Encoding.ASCII.GetString(nameData);
                    if (protocol == Protocol.NBNS)
                        nameString = DecodeNetBiosName(nameString);
                    if (protocol == Protocol.mDNS)
                        nameLength += 6; //Skip .local - This will, of course, fail on lots of things
                    Byte[] typeBytes = bytesRemaining.Skip(1 + nameLength + 1).Take(2).ToArray();
                    Byte[] classBytes = bytesRemaining.Skip(3 + nameLength + 1).Take(2).ToArray();
                    Byte[] ttlBytes = bytesRemaining.Skip(5 + nameLength + 1).Take(4).ToArray();
                    Byte[] dataLengthBytes = bytesRemaining.Skip(9 + nameLength + 1).Take(2).ToArray();
                    UInt16 dataLength = BitConverter.ToUInt16(dataLengthBytes.Reverse().ToArray(), 0);
                    var jumpBytes = 0;
                    if ((protocol == Protocol.LLMNR || protocol == Protocol.mDNS) && dataLength != 4)
                    {
                        return new SpoofDetectionResult()
                        {
                            Detected = false,
                            Endpoint = remoteEndpoint,
                            ErrorMessage = "Expected data length 4, instead received " + dataLength,
                            Confidence = ConfidenceLevel.Low
                        };
                    }
                    else if (protocol == Protocol.NBNS)
                    {
                        if (dataLength != 6)
                        {
                            return new SpoofDetectionResult()
                            {
                                Detected = false,
                                Endpoint = remoteEndpoint,
                                ErrorMessage = "Expected data length 6, instead received " + dataLength,
                                Confidence = ConfidenceLevel.Low
                            };
                        }
                        jumpBytes = 2;
                    }
                    Byte[] dataBytes = bytesRemaining.Skip(11 + nameLength + 1 + jumpBytes).Take(4).ToArray();
                    var dataAddress = new IPAddress(dataBytes);
                    bytesRemaining = bytesRemaining.Skip(11 + nameLength + 1 + dataLength).ToArray();
                    //We only care about the first reply
                    return new SpoofDetectionResult() { Detected = true, Endpoint = remoteEndpoint, Response = dataAddress.ToString(), Protocol = protocol, Confidence = ConfidenceLevel.Low };
                }

            }

            return new SpoofDetectionResult() { Detected = false, Endpoint = remoteEndpoint, ErrorMessage = "Execution error, ran past parsing responses", Confidence = ConfidenceLevel.FalsePositive };
        }

        private static String EncodeNetBiosName(String lookupName, Byte nameSuffix)
        {
            String uppercaseName = lookupName.ToUpper();

            //Encode target name
            var buffer = new List<Byte>();
            foreach (Char chr in uppercaseName)
                buffer.AddRange(EncodeNetBiosChar((Byte)chr));

            //Insert padding
            Int32 bufferCount = buffer.Count;
            for (var i = 0; i < (31 - bufferCount) / 2; i++)
                buffer.AddRange(new Byte[] { 0x43, 0x41 });
            
            //Add name suffix requested (0x00 for workstations, 0x20 for file services)
            buffer.AddRange(EncodeNetBiosChar(nameSuffix));

            return Encoding.ASCII.GetString(buffer.ToArray());
        }

        //Crazy weird encoding scheme
        private static Byte[] EncodeNetBiosChar(Byte c)
        {
            return new Byte[] { (Byte)('A' + (c >> 4)), (Byte)('A' + (c & 0x0F)), };
        }

        //Implement this if you ever need the decoded name for something
        private static String DecodeNetBiosName(String encodedName)
        {
            return encodedName;
        }
    }
}
