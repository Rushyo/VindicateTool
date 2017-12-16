using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace VindicateLib.Interfaces
{
    internal interface IClientActioner
    {
        void Send(UdpClient client, Byte[] datagram, Int32 datagramLength, String hostname, Int32 port);
        Byte[] Receive(UdpClient client, ref IPEndPoint remotEndPoint);
    }
}
