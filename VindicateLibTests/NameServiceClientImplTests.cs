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
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using VindicateLib;
using VindicateLib.Enums;

namespace VindicateLibTests
{
    [TestClass]
    public class NameServiceClientImplTests
    {
        private const Int32 LocalLLMNRPort = 49500;
        private const Int32 LocalNBNSPort = 49501;
        private const Int32 LocalmDNSPort = 5353;
        private const Int32 RemoteLLMNRPort = 5355;
        private const Int32 RemoteNBNSPort = 137;
        private const Int32 RemotemDNSPort = 5353;
        private const String LocalAddress = "192.168.1.1";
        private const String RemoteAddress = "192.168.1.24";

        [TestMethod]
        public void SendRequestTest_LLMNR_WPAD()
        {
            var clientActioner = new UdpClientMockActioner();

            using (var client = new UdpClient())
            {
                Byte[] transactionId =
                    new NameServiceClientImpl().SendRequest(client, Protocol.LLMNR, "WPAD", "192.168.1.255", clientActioner);

                Byte[] expectedDatagram = transactionId.Concat(
                        new Byte[] { 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x57, 0x50, 0x41, 0x44, 0x00, 0x00, 0x01, 0x00, 0x01 }
                    ).ToArray();
                //Console.WriteLine(BitConverter.ToString(expectedDatagram));
                //Console.WriteLine(BitConverter.ToString(clientActioner.LastSendDatagram));

                CollectionAssert.AreEqual(expectedDatagram, clientActioner.LastSendDatagram);
                Assert.AreEqual(22, clientActioner.LastSendDatagramLength);
                Assert.AreEqual("224.0.0.252", clientActioner.LastSendHostname);
                Assert.AreEqual(RemoteLLMNRPort, clientActioner.LastSendPort);
                Assert.AreEqual(clientActioner.LastSendDatagram.Length, clientActioner.LastSendDatagramLength);
            }
        }

        [TestMethod]
        public void SendRequestTest_NBNS_WPAD()
        {
            var clientActioner = new UdpClientMockActioner();

            using (var client = new UdpClient())
            {
                Byte[] transactionId =
                    new NameServiceClientImpl().SendRequest(client, Protocol.NBNS, "WPAD", "192.168.1.255", clientActioner);

                Byte[] expectedDatagram = transactionId.Concat(
                    new Byte[] { 0x01, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x46, 0x48, 0x46, 0x41, 0x45
                    , 0x42, 0x45, 0x45, 0x43, 0x41, 0x43, 0x41, 0x43, 0x41, 0x43, 0x41, 0x43, 0x41, 0x43, 0x41, 0x43
                    , 0x41, 0x43, 0x41, 0x43, 0x41, 0x43, 0x41, 0x43, 0x41, 0x43, 0x41, 0x00, 0x00, 0x20, 0x00, 0x01 }
                ).ToArray();

                CollectionAssert.AreEqual(expectedDatagram, clientActioner.LastSendDatagram);
                Assert.AreEqual(50, clientActioner.LastSendDatagramLength);
                Assert.AreEqual("192.168.1.255", clientActioner.LastSendHostname);
                Assert.AreEqual(RemoteNBNSPort, clientActioner.LastSendPort);
                Assert.AreEqual(clientActioner.LastSendDatagram.Length, clientActioner.LastSendDatagramLength);
            }
        }

        [TestMethod]
        public void SendRequestTest_mDNS_appletv()
        {
            var clientActioner = new UdpClientMockActioner();

            using (var client = new UdpClient())
            {
                Byte[] transactionId =
                    new NameServiceClientImpl().SendRequest(client, Protocol.mDNS, "appletv", "192.168.1.255", clientActioner);

                Byte[] expectedDatagram = transactionId.Concat(
                    new Byte[] { 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x61, 0x70, 0x70, 0x6C, 0x65
                    , 0x74, 0x76, 0x05, 0x6C, 0x6F, 0x63, 0x61, 0x6C, 0x00, 0x00, 0x01, 0x00, 0x01 }
                ).ToArray();

                CollectionAssert.AreEqual(new Byte[] { 0x00, 0x00}, transactionId);
                CollectionAssert.AreEqual(expectedDatagram, clientActioner.LastSendDatagram);
                Assert.AreEqual(31, clientActioner.LastSendDatagramLength);
                Assert.AreEqual("224.0.0.251", clientActioner.LastSendHostname);
                Assert.AreEqual(RemotemDNSPort, clientActioner.LastSendPort);
                Assert.AreEqual(clientActioner.LastSendDatagram.Length, clientActioner.LastSendDatagramLength);
            }
        }

        [TestMethod]
        public void ReceiveAndHandleReply_LLMNR_Detected()
        {
            var clientActioner = new UdpClientMockActioner
            {
                //ProxySvc Responder Response
                ReceiveBuffer = new Byte[] {
                    0x8e, 0x32, 0x80, 0x00, 0x00, 0x01, 0x00, 0x01,  0x00, 0x00, 0x00, 0x00, 0x08, 0x50, 0x72, 0x6f,
                    0x78, 0x79, 0x53, 0x76, 0x63, 0x00, 0x00, 0x01,  0x00, 0x01, 0x08, 0x50, 0x72, 0x6f, 0x78, 0x79,
                    0x53, 0x76, 0x63, 0x00, 0x00, 0x01, 0x00, 0x01,  0x00, 0x00, 0x00, 0x1e, 0x00, 0x04, 0xc0, 0xa8,
                    0x01, 0x18
                },
                ReceiveEndPoint = new IPEndPoint(IPAddress.Parse(RemoteAddress), RemoteLLMNRPort)
            };

            using (var client = new UdpClient(LocalAddress, LocalLLMNRPort))
            {
                SpoofDetectionResult result = new NameServiceClientImpl().ReceiveAndHandleReply(client, Protocol.LLMNR, new Byte[] {0x00, 0x00},
                    clientActioner);
                Assert.AreEqual(RemoteAddress, result.Response);
                Assert.AreEqual(ConfidenceLevel.Low, result.Confidence);
                Assert.AreEqual(true, result.Detected);
                Assert.AreEqual(RemoteAddress, result.Endpoint.Address.ToString());
                Assert.AreEqual(RemoteLLMNRPort, result.Endpoint.Port);
                Assert.IsNull(result.ErrorMessage);
                Assert.AreEqual(Protocol.LLMNR, result.Protocol);
            }
        }

        [TestMethod]
        public void ReceiveAndHandleReply_DeterministicFuzz()
        {
            Parallel.For(0, 10000, (i) =>
            {
                using (var client = new UdpClient(LocalAddress, LocalLLMNRPort))
                {
                    var clientActioner = new UdpClientMockActioner
                    {
                        ReceiveBuffer = DeterministicFuzzer.GenerateByteArray(i),
                        ReceiveEndPoint = new IPEndPoint(IPAddress.Parse(RemoteAddress), RemoteLLMNRPort)
                    };


                    SpoofDetectionResult result = new NameServiceClientImpl().ReceiveAndHandleReply(client,
                        Protocol.LLMNR, new Byte[] {0x00, 0x00},
                        clientActioner);
                    if (result == null)
                        return;
                    Assert.IsNull(result.Response);
                    Assert.AreEqual(ConfidenceLevel.FalsePositive, result.Confidence);
                    Assert.AreEqual(false, result.Detected);
                    Assert.AreEqual(RemoteAddress, result.Endpoint.Address.ToString());
                    Assert.AreEqual(RemoteLLMNRPort, result.Endpoint.Port);
                    Assert.IsNotNull(result.ErrorMessage);
                    Assert.AreEqual(Protocol.Unknown, result.Protocol);
                }
            });
        }

        [TestMethod]
        public void ReceiveAndHandleReply_EmptyResponse()
        {

            var clientActioner = new UdpClientMockActioner
            {
                ReceiveBuffer = new Byte[] { },
                ReceiveEndPoint = new IPEndPoint(IPAddress.Parse(RemoteAddress), RemoteLLMNRPort)
            };

            using (var client = new UdpClient(LocalAddress, LocalLLMNRPort))
            {
                SpoofDetectionResult result = new NameServiceClientImpl().ReceiveAndHandleReply(client,
                    Protocol.LLMNR, new Byte[] { 0x00, 0x00 },
                    clientActioner);
                Assert.IsNull(result);
            }
        }

        [TestMethod]
        public void ReceiveAndHandleReply_LLMNR_InvalidFlags()
        {
            var clientActioner = new UdpClientMockActioner
            {
                ReceiveBuffer = new Byte[] {
                    0x8e, 0x32, 0xDE, 0xAD, 0x00, 0x01, 0x00, 0x01,  0x00, 0x00, 0x00, 0x00, 0x08, 0x50, 0x72, 0x6f,
                    0x78, 0x79, 0x53, 0x76, 0x63, 0x00, 0x00, 0x01,  0x00, 0x01, 0x08, 0x50, 0x72, 0x6f, 0x78, 0x79,
                    0x53, 0x76, 0x63, 0x00, 0x00, 0x01, 0x00, 0x01,  0x00, 0x00, 0x00, 0x1e, 0x00, 0x04, 0xc0, 0xa8,
                    0x01, 0x18
                },
                ReceiveEndPoint = new IPEndPoint(IPAddress.Parse(RemoteAddress), RemoteLLMNRPort)
            };

            using (var client = new UdpClient(LocalAddress, LocalLLMNRPort))
            {
                SpoofDetectionResult result = new NameServiceClientImpl().ReceiveAndHandleReply(client, Protocol.LLMNR, new Byte[] { 0x00, 0x00 },
                    clientActioner);
                Assert.AreEqual("Did not expect LLMNR flags other than 0x8000", result.ErrorMessage);
                Assert.AreEqual(ConfidenceLevel.FalsePositive, result.Confidence);
                Assert.AreEqual(false, result.Detected);
                Assert.AreEqual(RemoteAddress, result.Endpoint.Address.ToString());
                Assert.AreEqual(RemoteLLMNRPort, result.Endpoint.Port);
                Assert.IsNull(result.Response);
                Assert.AreEqual(Protocol.Unknown, result.Protocol);
            }
        }


        [TestMethod]
        public void ReceiveAndHandleReply_NBNS_Detected()
        {
            var clientActioner = new UdpClientMockActioner
            {
                //WPAD-PROXY Responder Response
                ReceiveBuffer = new Byte[] {
                    0x81, 0xc6, 0x85, 0x00, 0x00, 0x00, 0x00, 0x01,  0x00, 0x00, 0x00, 0x00, 0x20, 0x46, 0x48, 0x46,
                    0x41, 0x45, 0x42, 0x45, 0x45, 0x43, 0x4e, 0x46,  0x41, 0x46, 0x43, 0x45, 0x50, 0x46, 0x49, 0x46,
                    0x4a, 0x43, 0x41, 0x43, 0x41, 0x43, 0x41, 0x43,  0x41, 0x43, 0x41, 0x43, 0x41, 0x00, 0x00, 0x20,
                    0x00, 0x01, 0x00, 0x00, 0x00, 0xa5, 0x00, 0x06,  0x00, 0x00, 0xc0, 0xa8, 0x01, 0x18
                },
                ReceiveEndPoint = new IPEndPoint(IPAddress.Parse(RemoteAddress), RemoteNBNSPort)
            };

            using (var client = new UdpClient(LocalAddress, LocalNBNSPort))
            {
                SpoofDetectionResult result = new NameServiceClientImpl().ReceiveAndHandleReply(client, Protocol.NBNS, new Byte[] { 0x00, 0x00 },
                    clientActioner);
                Assert.AreEqual(RemoteAddress, result.Response);
                Assert.AreEqual(ConfidenceLevel.Low, result.Confidence);
                Assert.AreEqual(true, result.Detected);
                Assert.AreEqual(RemoteAddress, result.Endpoint.Address.ToString());
                Assert.AreEqual(RemoteNBNSPort, result.Endpoint.Port);
                Assert.IsNull(result.ErrorMessage);
                Assert.AreEqual(Protocol.NBNS, result.Protocol);
            }
        }

        [TestMethod]
        public void ReceiveAndHandleReply_NBNS_InvalidFlags_RequestCase()
        {
            

            var clientActioner = new UdpClientMockActioner
            {
                ReceiveBuffer = new Byte[] {
                    0x81, 0xc6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,  0x00, 0x00, 0x00, 0x00, 0x20, 0x46, 0x48, 0x46,
                    0x41, 0x45, 0x42, 0x45, 0x45, 0x43, 0x4e, 0x46,  0x41, 0x46, 0x43, 0x45, 0x50, 0x46, 0x49, 0x46,
                    0x4a, 0x43, 0x41, 0x43, 0x41, 0x43, 0x41, 0x43,  0x41, 0x43, 0x41, 0x43, 0x41, 0x00, 0x00, 0x20,
                    0x00, 0x01, 0x00, 0x00, 0x00, 0xa5, 0x00, 0x06,  0x00, 0x00, 0xc0, 0xa8, 0x01, 0x18
                },
                ReceiveEndPoint = new IPEndPoint(IPAddress.Parse(RemoteAddress), RemoteNBNSPort)
            };

            using (var client = new UdpClient(LocalAddress, LocalNBNSPort))
            {
                SpoofDetectionResult result = new NameServiceClientImpl().ReceiveAndHandleReply(client, Protocol.NBNS, new Byte[] { 0x00, 0x00 },
                    clientActioner);
                Assert.AreEqual("Received NBNS query but expected response", result.ErrorMessage);
                Assert.AreEqual(ConfidenceLevel.FalsePositive, result.Confidence);
                Assert.AreEqual(false, result.Detected);
                Assert.AreEqual(RemoteAddress, result.Endpoint.Address.ToString());
                Assert.AreEqual(RemoteNBNSPort, result.Endpoint.Port);
                Assert.IsNull(result.Response);
                Assert.AreEqual(Protocol.Unknown, result.Protocol);
            }
        }

        [TestMethod]
        public void ReceiveAndHandleReply_NBNS_InvalidFlags_GenericCase()
        {
            var clientActioner = new UdpClientMockActioner
            {
                ReceiveBuffer = new Byte[] {
                    0x81, 0xc6, 0xDE, 0xAD, 0x00, 0x00, 0x00, 0x01,  0x00, 0x00, 0x00, 0x00, 0x20, 0x46, 0x48, 0x46,
                    0x41, 0x45, 0x42, 0x45, 0x45, 0x43, 0x4e, 0x46,  0x41, 0x46, 0x43, 0x45, 0x50, 0x46, 0x49, 0x46,
                    0x4a, 0x43, 0x41, 0x43, 0x41, 0x43, 0x41, 0x43,  0x41, 0x43, 0x41, 0x43, 0x41, 0x00, 0x00, 0x20,
                    0x00, 0x01, 0x00, 0x00, 0x00, 0xa5, 0x00, 0x06,  0x00, 0x00, 0xc0, 0xa8, 0x01, 0x18
                },
                ReceiveEndPoint = new IPEndPoint(IPAddress.Parse(RemoteAddress), RemoteNBNSPort)
            };

            using (var client = new UdpClient(LocalAddress, LocalNBNSPort))
            {
                SpoofDetectionResult result = new NameServiceClientImpl().ReceiveAndHandleReply(client, Protocol.NBNS, new Byte[] { 0x00, 0x00 },
                    clientActioner);
                Assert.AreEqual("Did not expect first 4 bits of NBNS flag to be anything other than 0x1000", result.ErrorMessage);
                Assert.AreEqual(ConfidenceLevel.FalsePositive, result.Confidence);
                Assert.AreEqual(false, result.Detected);
                Assert.AreEqual(RemoteAddress, result.Endpoint.Address.ToString());
                Assert.AreEqual(RemoteNBNSPort, result.Endpoint.Port);
                Assert.IsNull(result.Response);
                Assert.AreEqual(Protocol.Unknown, result.Protocol);
            }
        }

        [TestMethod]
        public void ReceiveAndHandleReply_NBNS_InvalidFlags_NotInNetwork()
        {
            var clientActioner = new UdpClientMockActioner
            {
                ReceiveBuffer = new Byte[] {
                    0x81, 0xc6, 0x85, 0x03, 0x00, 0x00, 0x00, 0x01,  0x00, 0x00, 0x00, 0x00, 0x20, 0x46, 0x48, 0x46,
                    0x41, 0x45, 0x42, 0x45, 0x45, 0x43, 0x4e, 0x46,  0x41, 0x46, 0x43, 0x45, 0x50, 0x46, 0x49, 0x46,
                    0x4a, 0x43, 0x41, 0x43, 0x41, 0x43, 0x41, 0x43,  0x41, 0x43, 0x41, 0x43, 0x41, 0x00, 0x00, 0x20,
                    0x00, 0x01, 0x00, 0x00, 0x00, 0xa5, 0x00, 0x06,  0x00, 0x00, 0xc0, 0xa8, 0x01, 0x18
                },
                ReceiveEndPoint = new IPEndPoint(IPAddress.Parse(RemoteAddress), RemoteNBNSPort)
            };

            using (var client = new UdpClient(LocalAddress, LocalNBNSPort))
            {
                SpoofDetectionResult result = new NameServiceClientImpl().ReceiveAndHandleReply(client, Protocol.NBNS, new Byte[] { 0x00, 0x00 },
                    clientActioner);
                Assert.AreEqual("NBNS target not in network", result.ErrorMessage);
                Assert.AreEqual(ConfidenceLevel.FalsePositive, result.Confidence);
                Assert.AreEqual(false, result.Detected);
                Assert.AreEqual(RemoteAddress, result.Endpoint.Address.ToString());
                Assert.AreEqual(RemoteNBNSPort, result.Endpoint.Port);
                Assert.IsNull(result.Response);
                Assert.AreEqual(Protocol.Unknown, result.Protocol);
            }
        }

        [TestMethod]
        public void ReceiveAndHandleReply_mDNS_Detected()
        {
            var clientActioner = new UdpClientMockActioner
            {
                //apple-tv.local Responder Response
                ReceiveBuffer = new Byte[] {
                    0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01,  0x00, 0x00, 0x00, 0x00, 0x08, 0x61, 0x70, 0x70,
                    0x6c, 0x65, 0x2d, 0x74, 0x76, 0x05, 0x6c, 0x6f,  0x63, 0x61, 0x6c, 0x00, 0x00, 0x01, 0x00, 0x01,
                    0x00, 0x00, 0x00, 0x78, 0x00, 0x04, 0xc0, 0xa8,  0x01, 0x18
                },
                ReceiveEndPoint = new IPEndPoint(IPAddress.Parse(RemoteAddress), RemotemDNSPort)
            };

            using (var client = new UdpClient(LocalAddress, LocalmDNSPort))
            {
                SpoofDetectionResult result = new NameServiceClientImpl().ReceiveAndHandleReply(client, Protocol.mDNS, new Byte[] { 0x00, 0x00 },
                    clientActioner);
                Assert.AreEqual(RemoteAddress, result.Response);
                Assert.AreEqual(ConfidenceLevel.Low, result.Confidence);
                Assert.AreEqual(true, result.Detected);
                Assert.AreEqual(RemoteAddress, result.Endpoint.Address.ToString());
                Assert.AreEqual(RemotemDNSPort, result.Endpoint.Port);
                Assert.IsNull(result.ErrorMessage);
                Assert.AreEqual(Protocol.mDNS, result.Protocol);
            }
        }

        [TestMethod]
        public void ReceiveAndHandleReply_mDNS_InvalidFlags_GenericCase()
        {
            var clientActioner = new UdpClientMockActioner
            {
                //apple-tv.local Responder Response
                ReceiveBuffer = new Byte[] {
                    0x00, 0x00, 0xDE, 0xAD, 0x00, 0x00, 0x00, 0x01,  0x00, 0x00, 0x00, 0x00, 0x08, 0x61, 0x70, 0x70,
                    0x6c, 0x65, 0x2d, 0x74, 0x76, 0x05, 0x6c, 0x6f,  0x63, 0x61, 0x6c, 0x00, 0x00, 0x01, 0x00, 0x01,
                    0x00, 0x00, 0x00, 0x78, 0x00, 0x04, 0xc0, 0xa8,  0x01, 0x18
                },
                ReceiveEndPoint = new IPEndPoint(IPAddress.Parse(RemoteAddress), RemotemDNSPort)
            };

            using (var client = new UdpClient(LocalAddress, LocalmDNSPort))
            {
                SpoofDetectionResult result = new NameServiceClientImpl().ReceiveAndHandleReply(client, Protocol.mDNS, new Byte[] { 0x00, 0x00 },
                    clientActioner);
                Assert.AreEqual("Did not expect first 4 bits of mDNS flag to be anything other than 0x1000", result.ErrorMessage);
                Assert.AreEqual(ConfidenceLevel.FalsePositive, result.Confidence);
                Assert.AreEqual(false, result.Detected);
                Assert.AreEqual(RemoteAddress, result.Endpoint.Address.ToString());
                Assert.AreEqual(RemotemDNSPort, result.Endpoint.Port);
                Assert.IsNull(result.Response);
                Assert.AreEqual(Protocol.Unknown, result.Protocol);
            }
        }

        [TestMethod]
        public void ReceiveAndHandleReply_mDNS_InvalidFlags_RequestCase()
        {
            var clientActioner = new UdpClientMockActioner
            {
                //apple-tv.local Responder Response
                ReceiveBuffer = new Byte[] {
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,  0x00, 0x00, 0x00, 0x00, 0x08, 0x61, 0x70, 0x70,
                    0x6c, 0x65, 0x2d, 0x74, 0x76, 0x05, 0x6c, 0x6f,  0x63, 0x61, 0x6c, 0x00, 0x00, 0x01, 0x00, 0x01,
                    0x00, 0x00, 0x00, 0x78, 0x00, 0x04, 0xc0, 0xa8,  0x01, 0x18
                },
                ReceiveEndPoint = new IPEndPoint(IPAddress.Parse(RemoteAddress), RemotemDNSPort)
            };

            using (var client = new UdpClient(LocalAddress, LocalmDNSPort))
            {
                SpoofDetectionResult result = new NameServiceClientImpl().ReceiveAndHandleReply(client, Protocol.mDNS, new Byte[] { 0x00, 0x00 },
                    clientActioner);
                Assert.AreEqual("Received mDNS query but expected response", result.ErrorMessage);
                Assert.AreEqual(ConfidenceLevel.FalsePositive, result.Confidence);
                Assert.AreEqual(false, result.Detected);
                Assert.AreEqual(RemoteAddress, result.Endpoint.Address.ToString());
                Assert.AreEqual(RemotemDNSPort, result.Endpoint.Port);
                Assert.IsNull(result.Response);
                Assert.AreEqual(Protocol.Unknown, result.Protocol);
            }
        }
    }
}
