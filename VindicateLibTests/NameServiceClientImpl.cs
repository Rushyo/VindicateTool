using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
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
    }
}
