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
using System.Data.SqlClient;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using VindicateLib.Interfaces;

namespace VindicateLib
{
    public class ClientActioner : IClientActioner
    {
        public void Send(Socket client, Byte[] datagram, String hostname, Int32 port)
        {
            if (client.SocketType == SocketType.Dgram)
            {
                client.SendTo(datagram, SocketFlags.None, new IPEndPoint(IPAddress.Parse(hostname), port));
            }
            else if (client.SocketType == SocketType.Stream)
            {
                client.Connect(hostname, port);
                client.Send(datagram, SocketFlags.None);
                client.Disconnect(true);
            }
        }

        public Byte[] Receive(Socket client, out IPEndPoint remoteEndPoint)
        {
            var buffer = new Byte[4096];
            
            if (client.SocketType == SocketType.Dgram)
            {
                EndPoint socketEndPoint = new IPEndPoint(IPAddress.Any, 0);
                Int32 read = client.ReceiveFrom(buffer, buffer.Length, SocketFlags.None, ref socketEndPoint);
                remoteEndPoint = (IPEndPoint)socketEndPoint;
                return buffer.Take(read).ToArray();
            }
            else if (client.SocketType == SocketType.Stream)
            {
                client.Listen(1);
                using (Socket newSocket = client.Accept())
                {
                    remoteEndPoint = (IPEndPoint) newSocket.RemoteEndPoint;
                    var data = new List<Byte>();
                    while (newSocket.Available != 0)
                    {
                        Int32 read = newSocket.Receive(buffer);
                        data.AddRange(buffer.Take(read));
                    }
                    newSocket.Disconnect(true);
                    return data.ToArray();
                }
            }
            throw new InvalidOperationException("Unknown socket type");
        }
    }
}