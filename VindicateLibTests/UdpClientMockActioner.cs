using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using VindicateLib.Interfaces;

namespace VindicateLibTests
{
    public class UdpClientMockActioner : IClientActioner
    {
        public Byte[] LastSendDatagram;
        public Int32 LastSendDatagramLength;
        public String LastSendHostname;
        public Int32 LastSendPort;

        public Byte[] ReceiveBuffer = null;
        public IPEndPoint ReceiveEndPoint = null;

        public void Send(UdpClient client, Byte[] datagram, Int32 datagramLength, String hostname, Int32 port)
        {
            LastSendDatagram = datagram;
            LastSendDatagramLength = datagramLength;
            LastSendHostname = hostname;
            LastSendPort = port;
        }

        public Byte[] Receive(UdpClient client, ref IPEndPoint remoteEndPoint)
        {
            remoteEndPoint = ReceiveEndPoint;
            return ReceiveBuffer;
        }
    }
}
