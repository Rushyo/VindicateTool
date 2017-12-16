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
                Assert.AreEqual(5355, clientActioner.LastSendPort);
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
                Assert.AreEqual(137, clientActioner.LastSendPort);
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
                Assert.AreEqual(5353, clientActioner.LastSendPort);
                Assert.AreEqual(clientActioner.LastSendDatagram.Length, clientActioner.LastSendDatagramLength);
            }
        }

        [TestMethod]
        public void ReceiveAndHandleReply_LLMNR_Detected()
        {
            const String localAddress = "192.168.1.1";
            const Int32 localPort = 49500;
            const String remoteAddress = "192.168.1.24";
            const Int32 remotePort = 5355;

            var clientActioner = new UdpClientMockActioner
            {
                //ProxySvc Responder Response
                ReceiveBuffer = new Byte[] {
                    0x8e, 0x32, 0x80, 0x00, 0x00, 0x01, 0x00, 0x01,  0x00, 0x00, 0x00, 0x00, 0x08, 0x50, 0x72, 0x6f,
                    0x78, 0x79, 0x53, 0x76, 0x63, 0x00, 0x00, 0x01,  0x00, 0x01, 0x08, 0x50, 0x72, 0x6f, 0x78, 0x79,
                    0x53, 0x76, 0x63, 0x00, 0x00, 0x01, 0x00, 0x01,  0x00, 0x00, 0x00, 0x1e, 0x00, 0x04, 0xc0, 0xa8,
                    0x01, 0x18
                },
                ReceiveEndPoint = new IPEndPoint(IPAddress.Parse(remoteAddress), remotePort)
            };

            using (var client = new UdpClient(localAddress, localPort))
            {
                SpoofDetectionResult result = new NameServiceClientImpl().ReceiveAndHandleReply(client, Protocol.LLMNR, new Byte[] {0x00, 0x00},
                    clientActioner);
                Assert.AreEqual(remoteAddress, result.Response);
                Assert.AreEqual(ConfidenceLevel.Low, result.Confidence);
                Assert.AreEqual(true, result.Detected);
                Assert.AreEqual(remoteAddress, result.Endpoint.Address.ToString());
                Assert.AreEqual(remotePort, result.Endpoint.Port);
                Assert.IsNull(result.ErrorMessage);
                Assert.AreEqual(Protocol.LLMNR, result.Protocol);
            }
        }

        [TestMethod]
        public void ReceiveAndHandleReply_DeterministicFuzz()
        {
            const String localAddress = "192.168.1.1";
            const Int32 localPort = 49500;
            const String remoteAddress = "192.168.1.24";
            const Int32 remotePort = 5355;

            //TODO: Make async
            for (var i = 0; i < 10000; i++)
            {
                var clientActioner = new UdpClientMockActioner
                {
                    //ProxySvc Responder Response
                    ReceiveBuffer = DeterministicFuzzer.GenerateByteArray(i),
                    ReceiveEndPoint = new IPEndPoint(IPAddress.Parse(remoteAddress), remotePort)
                };

                using (var client = new UdpClient(localAddress, localPort))
                {
                    SpoofDetectionResult result = new NameServiceClientImpl().ReceiveAndHandleReply(client,
                        Protocol.LLMNR, new Byte[] {0x00, 0x00},
                        clientActioner);
                    if (result == null)
                        continue;
                    Assert.IsNull(result.Response);
                    Assert.AreEqual(ConfidenceLevel.FalsePositive, result.Confidence);
                    Assert.AreEqual(false, result.Detected);
                    Assert.AreEqual(remoteAddress, result.Endpoint.Address.ToString());
                    Assert.AreEqual(remotePort, result.Endpoint.Port);
                    Assert.IsNotNull(result.ErrorMessage);
                    Assert.AreEqual(Protocol.Unknown, result.Protocol);
                }
            }
        }

        [TestMethod]
        public void ReceiveAndHandleReply_EmptyResponse()
        {
            const String localAddress = "192.168.1.1";
            const Int32 localPort = 49500;
            const String remoteAddress = "192.168.1.24";
            const Int32 remotePort = 5355;

            var clientActioner = new UdpClientMockActioner
            {
                //ProxySvc Responder Response
                ReceiveBuffer = new Byte[] { 0x00},
                ReceiveEndPoint = new IPEndPoint(IPAddress.Parse(remoteAddress), remotePort)
            };

            using (var client = new UdpClient(localAddress, localPort))
            {
                SpoofDetectionResult result = new NameServiceClientImpl().ReceiveAndHandleReply(client,
                    Protocol.LLMNR, new Byte[] { 0x00, 0x00 },
                    clientActioner);
                Assert.IsNull(result.Response);
                Assert.AreEqual(ConfidenceLevel.FalsePositive, result.Confidence);
                Assert.AreEqual(false, result.Detected);
                Assert.AreEqual(remoteAddress, result.Endpoint.Address.ToString());
                Assert.AreEqual(remotePort, result.Endpoint.Port);
                Assert.IsNotNull(result.ErrorMessage);
                Assert.AreEqual(Protocol.Unknown, result.Protocol);
            }
        }

        [TestMethod]
        public void ReceiveAndHandleReply_LLMNR_InvalidFlags()
        {
            const String localAddress = "192.168.1.1";
            const Int32 localPort = 49500;
            const String remoteAddress = "192.168.1.24";
            const Int32 remotePort = 5355;

            var clientActioner = new UdpClientMockActioner
            {
                ReceiveBuffer = new Byte[] {
                    0x8e, 0x32, 0xDE, 0xAD, 0x00, 0x01, 0x00, 0x01,  0x00, 0x00, 0x00, 0x00, 0x08, 0x50, 0x72, 0x6f,
                    0x78, 0x79, 0x53, 0x76, 0x63, 0x00, 0x00, 0x01,  0x00, 0x01, 0x08, 0x50, 0x72, 0x6f, 0x78, 0x79,
                    0x53, 0x76, 0x63, 0x00, 0x00, 0x01, 0x00, 0x01,  0x00, 0x00, 0x00, 0x1e, 0x00, 0x04, 0xc0, 0xa8,
                    0x01, 0x18
                },
                ReceiveEndPoint = new IPEndPoint(IPAddress.Parse(remoteAddress), remotePort)
            };

            using (var client = new UdpClient(localAddress, localPort))
            {
                SpoofDetectionResult result = new NameServiceClientImpl().ReceiveAndHandleReply(client, Protocol.LLMNR, new Byte[] { 0x00, 0x00 },
                    clientActioner);
                Assert.AreEqual("Did not expect LLMNR flags other than 0x8000", result.ErrorMessage);
                Assert.AreEqual(ConfidenceLevel.FalsePositive, result.Confidence);
                Assert.AreEqual(false, result.Detected);
                Assert.AreEqual(remoteAddress, result.Endpoint.Address.ToString());
                Assert.AreEqual(remotePort, result.Endpoint.Port);
                Assert.IsNull(result.Response);
                Assert.AreEqual(Protocol.Unknown, result.Protocol);
            }
        }


        [TestMethod]
        public void ReceiveAndHandleReply_NBNS_Detected()
        {
            const String localAddress = "192.168.1.1";
            const Int32 localPort = 49501;
            const String remoteAddress = "192.168.1.24";
            const Int32 remotePort = 137;

            var clientActioner = new UdpClientMockActioner
            {
                //WPAD-PROXY Responder Response
                ReceiveBuffer = new Byte[] {
                    0x81, 0xc6, 0x85, 0x00, 0x00, 0x00, 0x00, 0x01,  0x00, 0x00, 0x00, 0x00, 0x20, 0x46, 0x48, 0x46,
                    0x41, 0x45, 0x42, 0x45, 0x45, 0x43, 0x4e, 0x46,  0x41, 0x46, 0x43, 0x45, 0x50, 0x46, 0x49, 0x46,
                    0x4a, 0x43, 0x41, 0x43, 0x41, 0x43, 0x41, 0x43,  0x41, 0x43, 0x41, 0x43, 0x41, 0x00, 0x00, 0x20,
                    0x00, 0x01, 0x00, 0x00, 0x00, 0xa5, 0x00, 0x06,  0x00, 0x00, 0xc0, 0xa8, 0x01, 0x18
                },
                ReceiveEndPoint = new IPEndPoint(IPAddress.Parse(remoteAddress), remotePort)
            };

            using (var client = new UdpClient(localAddress, localPort))
            {
                SpoofDetectionResult result = new NameServiceClientImpl().ReceiveAndHandleReply(client, Protocol.NBNS, new Byte[] { 0x00, 0x00 },
                    clientActioner);
                Assert.AreEqual(remoteAddress, result.Response);
                Assert.AreEqual(ConfidenceLevel.Low, result.Confidence);
                Assert.AreEqual(true, result.Detected);
                Assert.AreEqual(remoteAddress, result.Endpoint.Address.ToString());
                Assert.AreEqual(remotePort, result.Endpoint.Port);
                Assert.IsNull(result.ErrorMessage);
                Assert.AreEqual(Protocol.NBNS, result.Protocol);
            }
        }

        [TestMethod]
        public void ReceiveAndHandleReply_NBNS_InvalidFlags_RequestCase()
        {
            const String localAddress = "192.168.1.1";
            const Int32 localPort = 49501;
            const String remoteAddress = "192.168.1.24";
            const Int32 remotePort = 137;

            var clientActioner = new UdpClientMockActioner
            {
                ReceiveBuffer = new Byte[] {
                    0x81, 0xc6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,  0x00, 0x00, 0x00, 0x00, 0x20, 0x46, 0x48, 0x46,
                    0x41, 0x45, 0x42, 0x45, 0x45, 0x43, 0x4e, 0x46,  0x41, 0x46, 0x43, 0x45, 0x50, 0x46, 0x49, 0x46,
                    0x4a, 0x43, 0x41, 0x43, 0x41, 0x43, 0x41, 0x43,  0x41, 0x43, 0x41, 0x43, 0x41, 0x00, 0x00, 0x20,
                    0x00, 0x01, 0x00, 0x00, 0x00, 0xa5, 0x00, 0x06,  0x00, 0x00, 0xc0, 0xa8, 0x01, 0x18
                },
                ReceiveEndPoint = new IPEndPoint(IPAddress.Parse(remoteAddress), remotePort)
            };

            using (var client = new UdpClient(localAddress, localPort))
            {
                SpoofDetectionResult result = new NameServiceClientImpl().ReceiveAndHandleReply(client, Protocol.NBNS, new Byte[] { 0x00, 0x00 },
                    clientActioner);
                Assert.AreEqual("Received NBNS query but expected response", result.ErrorMessage);
                Assert.AreEqual(ConfidenceLevel.FalsePositive, result.Confidence);
                Assert.AreEqual(false, result.Detected);
                Assert.AreEqual(remoteAddress, result.Endpoint.Address.ToString());
                Assert.AreEqual(remotePort, result.Endpoint.Port);
                Assert.IsNull(result.Response);
                Assert.AreEqual(Protocol.Unknown, result.Protocol);
            }
        }

        [TestMethod]
        public void ReceiveAndHandleReply_NBNS_InvalidFlags_GenericCase()
        {
            const String localAddress = "192.168.1.1";
            const Int32 localPort = 49501;
            const String remoteAddress = "192.168.1.24";
            const Int32 remotePort = 137;

            var clientActioner = new UdpClientMockActioner
            {
                ReceiveBuffer = new Byte[] {
                    0x81, 0xc6, 0xDE, 0xAD, 0x00, 0x00, 0x00, 0x01,  0x00, 0x00, 0x00, 0x00, 0x20, 0x46, 0x48, 0x46,
                    0x41, 0x45, 0x42, 0x45, 0x45, 0x43, 0x4e, 0x46,  0x41, 0x46, 0x43, 0x45, 0x50, 0x46, 0x49, 0x46,
                    0x4a, 0x43, 0x41, 0x43, 0x41, 0x43, 0x41, 0x43,  0x41, 0x43, 0x41, 0x43, 0x41, 0x00, 0x00, 0x20,
                    0x00, 0x01, 0x00, 0x00, 0x00, 0xa5, 0x00, 0x06,  0x00, 0x00, 0xc0, 0xa8, 0x01, 0x18
                },
                ReceiveEndPoint = new IPEndPoint(IPAddress.Parse(remoteAddress), remotePort)
            };

            using (var client = new UdpClient(localAddress, localPort))
            {
                SpoofDetectionResult result = new NameServiceClientImpl().ReceiveAndHandleReply(client, Protocol.NBNS, new Byte[] { 0x00, 0x00 },
                    clientActioner);
                Assert.AreEqual("Did not expect first 4 bits of NBNS flag to be anything other than 0x1000", result.ErrorMessage);
                Assert.AreEqual(ConfidenceLevel.FalsePositive, result.Confidence);
                Assert.AreEqual(false, result.Detected);
                Assert.AreEqual(remoteAddress, result.Endpoint.Address.ToString());
                Assert.AreEqual(remotePort, result.Endpoint.Port);
                Assert.IsNull(result.Response);
                Assert.AreEqual(Protocol.Unknown, result.Protocol);
            }
        }

        [TestMethod]
        public void ReceiveAndHandleReply_NBNS_InvalidFlags_NotInNetwork()
        {
            const String localAddress = "192.168.1.1";
            const Int32 localPort = 49501;
            const String remoteAddress = "192.168.1.24";
            const Int32 remotePort = 137;

            var clientActioner = new UdpClientMockActioner
            {
                ReceiveBuffer = new Byte[] {
                    0x81, 0xc6, 0x85, 0x03, 0x00, 0x00, 0x00, 0x01,  0x00, 0x00, 0x00, 0x00, 0x20, 0x46, 0x48, 0x46,
                    0x41, 0x45, 0x42, 0x45, 0x45, 0x43, 0x4e, 0x46,  0x41, 0x46, 0x43, 0x45, 0x50, 0x46, 0x49, 0x46,
                    0x4a, 0x43, 0x41, 0x43, 0x41, 0x43, 0x41, 0x43,  0x41, 0x43, 0x41, 0x43, 0x41, 0x00, 0x00, 0x20,
                    0x00, 0x01, 0x00, 0x00, 0x00, 0xa5, 0x00, 0x06,  0x00, 0x00, 0xc0, 0xa8, 0x01, 0x18
                },
                ReceiveEndPoint = new IPEndPoint(IPAddress.Parse(remoteAddress), remotePort)
            };

            using (var client = new UdpClient(localAddress, localPort))
            {
                SpoofDetectionResult result = new NameServiceClientImpl().ReceiveAndHandleReply(client, Protocol.NBNS, new Byte[] { 0x00, 0x00 },
                    clientActioner);
                Assert.AreEqual("NBNS target not in network", result.ErrorMessage);
                Assert.AreEqual(ConfidenceLevel.FalsePositive, result.Confidence);
                Assert.AreEqual(false, result.Detected);
                Assert.AreEqual(remoteAddress, result.Endpoint.Address.ToString());
                Assert.AreEqual(remotePort, result.Endpoint.Port);
                Assert.IsNull(result.Response);
                Assert.AreEqual(Protocol.Unknown, result.Protocol);
            }
        }

        [TestMethod]
        public void ReceiveAndHandleReply_mDNS_Detected()
        {
            const String localAddress = "192.168.1.1";
            const Int32 localPort = 5353;
            const String remoteAddress = "192.168.1.24";
            const Int32 remotePort = 5353;

            var clientActioner = new UdpClientMockActioner
            {
                //apple-tv.local Responder Response
                ReceiveBuffer = new Byte[] {
                    0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01,  0x00, 0x00, 0x00, 0x00, 0x08, 0x61, 0x70, 0x70,
                    0x6c, 0x65, 0x2d, 0x74, 0x76, 0x05, 0x6c, 0x6f,  0x63, 0x61, 0x6c, 0x00, 0x00, 0x01, 0x00, 0x01,
                    0x00, 0x00, 0x00, 0x78, 0x00, 0x04, 0xc0, 0xa8,  0x01, 0x18
                },
                ReceiveEndPoint = new IPEndPoint(IPAddress.Parse(remoteAddress), remotePort)
            };

            using (var client = new UdpClient(localAddress, localPort))
            {
                SpoofDetectionResult result = new NameServiceClientImpl().ReceiveAndHandleReply(client, Protocol.mDNS, new Byte[] { 0x00, 0x00 },
                    clientActioner);
                Assert.AreEqual(remoteAddress, result.Response);
                Assert.AreEqual(ConfidenceLevel.Low, result.Confidence);
                Assert.AreEqual(true, result.Detected);
                Assert.AreEqual(remoteAddress, result.Endpoint.Address.ToString());
                Assert.AreEqual(remotePort, result.Endpoint.Port);
                Assert.IsNull(result.ErrorMessage);
                Assert.AreEqual(Protocol.mDNS, result.Protocol);
            }
        }

        [TestMethod]
        public void ReceiveAndHandleReply_mDNS_InvalidFlags_GenericCase()
        {
            const String localAddress = "192.168.1.1";
            const Int32 localPort = 5353;
            const String remoteAddress = "192.168.1.24";
            const Int32 remotePort = 5353;

            var clientActioner = new UdpClientMockActioner
            {
                //apple-tv.local Responder Response
                ReceiveBuffer = new Byte[] {
                    0x00, 0x00, 0xDE, 0xAD, 0x00, 0x00, 0x00, 0x01,  0x00, 0x00, 0x00, 0x00, 0x08, 0x61, 0x70, 0x70,
                    0x6c, 0x65, 0x2d, 0x74, 0x76, 0x05, 0x6c, 0x6f,  0x63, 0x61, 0x6c, 0x00, 0x00, 0x01, 0x00, 0x01,
                    0x00, 0x00, 0x00, 0x78, 0x00, 0x04, 0xc0, 0xa8,  0x01, 0x18
                },
                ReceiveEndPoint = new IPEndPoint(IPAddress.Parse(remoteAddress), remotePort)
            };

            using (var client = new UdpClient(localAddress, localPort))
            {
                SpoofDetectionResult result = new NameServiceClientImpl().ReceiveAndHandleReply(client, Protocol.mDNS, new Byte[] { 0x00, 0x00 },
                    clientActioner);
                Assert.AreEqual("Did not expect first 4 bits of mDNS flag to be anything other than 0x1000", result.ErrorMessage);
                Assert.AreEqual(ConfidenceLevel.FalsePositive, result.Confidence);
                Assert.AreEqual(false, result.Detected);
                Assert.AreEqual(remoteAddress, result.Endpoint.Address.ToString());
                Assert.AreEqual(remotePort, result.Endpoint.Port);
                Assert.IsNull(result.Response);
                Assert.AreEqual(Protocol.Unknown, result.Protocol);
            }
        }

        [TestMethod]
        public void ReceiveAndHandleReply_mDNS_InvalidFlags_RequestCase()
        {
            const String localAddress = "192.168.1.1";
            const Int32 localPort = 5353;
            const String remoteAddress = "192.168.1.24";
            const Int32 remotePort = 5353;

            var clientActioner = new UdpClientMockActioner
            {
                //apple-tv.local Responder Response
                ReceiveBuffer = new Byte[] {
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,  0x00, 0x00, 0x00, 0x00, 0x08, 0x61, 0x70, 0x70,
                    0x6c, 0x65, 0x2d, 0x74, 0x76, 0x05, 0x6c, 0x6f,  0x63, 0x61, 0x6c, 0x00, 0x00, 0x01, 0x00, 0x01,
                    0x00, 0x00, 0x00, 0x78, 0x00, 0x04, 0xc0, 0xa8,  0x01, 0x18
                },
                ReceiveEndPoint = new IPEndPoint(IPAddress.Parse(remoteAddress), remotePort)
            };

            using (var client = new UdpClient(localAddress, localPort))
            {
                SpoofDetectionResult result = new NameServiceClientImpl().ReceiveAndHandleReply(client, Protocol.mDNS, new Byte[] { 0x00, 0x00 },
                    clientActioner);
                Assert.AreEqual("Received mDNS query but expected response", result.ErrorMessage);
                Assert.AreEqual(ConfidenceLevel.FalsePositive, result.Confidence);
                Assert.AreEqual(false, result.Detected);
                Assert.AreEqual(remoteAddress, result.Endpoint.Address.ToString());
                Assert.AreEqual(remotePort, result.Endpoint.Port);
                Assert.IsNull(result.Response);
                Assert.AreEqual(Protocol.Unknown, result.Protocol);
            }
        }
    }
}
