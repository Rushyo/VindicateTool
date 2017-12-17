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