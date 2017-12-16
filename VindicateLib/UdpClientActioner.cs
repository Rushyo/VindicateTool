using System;
using System.Net;
using System.Net.Sockets;
using VindicateLib.Interfaces;

namespace VindicateLib
{
    public class UdpClientActioner : IClientActioner
    {
        public void Send(UdpClient client, Byte[] datagram, Int32 datagramLength, String hostname, Int32 port)
        {
            client.Send(datagram, datagramLength, hostname, port);
        }

        public Byte[] Receive(UdpClient client, ref IPEndPoint remotEndPoint)
        {
            return client.Receive(ref remotEndPoint);
        }
    }
}