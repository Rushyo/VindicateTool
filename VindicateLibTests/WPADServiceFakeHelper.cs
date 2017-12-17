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
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace VindicateLibTests
{
    internal static class WPADServiceFakeHelper
    {
        public static async void PerformSingleWPADServiceListen(HttpListener listener, HttpStatusCode code, String response)
        {
            listener.Start();
            HttpListenerContext contextAsync = await listener.GetContextAsync();
            contextAsync.Response.StatusCode = (Int32)code;
            Byte[] responseBytes = Encoding.UTF8.GetBytes(response);
            contextAsync.Response.OutputStream.Write(responseBytes, 0, responseBytes.Length);
            contextAsync.Response.OutputStream.Close();
            listener.Stop();
        }

        public static HttpListener CreateWPADService(String serviceEndpoint)
        {
            var listener = new HttpListener { UnsafeConnectionNtlmAuthentication = true };
            listener.Prefixes.Add(serviceEndpoint);
            return listener;
        }

        public static Socket CreateConnectionSinkholeTcpSocket(String serverAddress, Int32 serverPort)
        {
            var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
            try
            {
                socket.Bind(new IPEndPoint(IPAddress.Parse(serverAddress), serverPort));
                socket.Listen(1);
                return socket;
            }
            catch
            {
                socket.Close(1);
                throw;
            }
        }

        public static Socket CreateHTTPSinkholeTcpSocket(String serverAddress, Int32 serverPort)
        {
            var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
            try
            {
                socket.Bind(new IPEndPoint(IPAddress.Parse(serverAddress), serverPort));
                socket.Listen(1);
                socket.BeginAccept(HTTPSinkholeTcpSocketCallback, socket);
                return socket;
            }
            catch
            {
                socket.Close(1);
                throw;
            }
        }

        private static void HTTPSinkholeTcpSocketCallback(IAsyncResult result)
        {
            var socketListener = (Socket)result.AsyncState;
            Socket socketHandler = socketListener.EndAccept(result);
            const String partReply = "HTTP/1.1 200 OK\r\nServer: Apache/2.2.14(Win32)\r\nContent-Length: 99999\r\nContent-Type: text/html\r\nKeep-Alive: Connection: keep-alive\r\n\r\nLoading...";
            socketHandler.Send(Encoding.ASCII.GetBytes(partReply));
            //Leave hanging...
        }

        public static Socket CreateJunkTcpSocket(String serverAddress, Int32 serverPort)
        {
            var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
            try
            {
                socket.Bind(new IPEndPoint(IPAddress.Parse(serverAddress), serverPort));
                socket.Listen(1);
                socket.BeginAccept(JunkTcpSocketCallback, socket);
                return socket;
            }
            catch
            {
                socket.Close(1);
                throw;
            }
        }

        private static void JunkTcpSocketCallback(IAsyncResult result)
        {
            var socketListener = (Socket)result.AsyncState;
            using (Socket socketHandler = socketListener.EndAccept(result))
            {
                var junkBytes = new Byte[]
                {
                    0xd0, 0x43, 0x20, 0x00, 0xa1, 0xce, 0xbe, 0x29, 0x39, 0x78, 0xea, 0x9c, 0xff, 0xe7, 0x53, 0xb2,
                    0x3e, 0x59, 0xb1, 0xf0, 0xb1, 0xf4, 0xba, 0xd9, 0x11, 0xc1, 0xb3, 0x1c, 0xaa, 0x49, 0xb5, 0xcc,
                    0x7c, 0xea, 0x5b, 0x1a, 0x05, 0xfc, 0x87, 0xcd, 0x9a, 0x7c, 0x03, 0x88, 0x02, 0xa2, 0x0a, 0xb1,
                    0x90, 0x64, 0x3c, 0xf7, 0x8f, 0x4e, 0x22, 0xfa, 0x71, 0xf5, 0x2c, 0x72, 0xc4, 0x0f, 0x85, 0xd0,
                    0x78, 0x94, 0x44, 0x6c, 0xb8, 0x32, 0x70, 0xf1, 0x8a, 0xa8, 0xc0, 0xb4, 0x6d, 0xf3, 0x81, 0x57,
                    0xc5, 0x06, 0x7c, 0x8e, 0xa0, 0xd2, 0x59, 0x82, 0x08, 0xea, 0xcb, 0x42, 0x74, 0xb0, 0x23, 0xd7,
                    0xc8, 0x61, 0x2c, 0xe9, 0x9b, 0xba, 0x1e, 0x7c, 0xad, 0x20, 0x51, 0xa4, 0xee, 0xfc, 0xe7, 0x0d,
                    0x4b, 0xad, 0xfc, 0x53, 0xa9, 0x09, 0x6d, 0xf9, 0x0a, 0x45, 0x77, 0xd2, 0xb4, 0xaa, 0x16, 0xec,
                    0x3a, 0x22, 0x40, 0x0e, 0x72, 0x6f, 0x63, 0xd0, 0x86, 0x62, 0xf6, 0x93, 0x03, 0x4b, 0x96, 0x17,
                    0x4c, 0xf2, 0xaa, 0xa8, 0x6c, 0x73, 0xe6, 0xf2, 0x23, 0x05, 0xd7, 0xca, 0x98, 0xe2, 0x4d, 0x84,
                    0x7a, 0x74, 0xe3, 0xbc, 0x99, 0x06, 0x0a, 0xc3, 0xa8, 0x41, 0x14, 0xa7, 0xea, 0xb0, 0x08, 0xb7,
                    0x0b, 0xd0, 0xeb, 0x4e, 0x37, 0x08, 0x24, 0x39, 0x2b, 0xd6, 0x20, 0xcd, 0x87, 0x04, 0xda, 0x11,
                    0xdc, 0x78, 0xf7, 0xb0, 0xca, 0x21, 0x38, 0xcf, 0x37, 0x41, 0xc2, 0xf2, 0x3b, 0xf1, 0x4e, 0xd6,
                    0xd8, 0x65, 0xaa, 0x6d, 0x1f, 0xa8, 0xaa, 0x00, 0x22, 0x6a, 0x46, 0xc3, 0x0f, 0xf2, 0x4d, 0x54,
                    0x03, 0xca, 0xf1, 0xb7, 0x61, 0x0f, 0xf7, 0x1a, 0x07, 0x31, 0x2f, 0x0d, 0x0c, 0x9d, 0x15, 0x14,
                    0x49, 0x62, 0x57, 0x99, 0x31, 0x56, 0x35, 0x6a, 0x7f, 0xc8, 0x0c, 0x15, 0x08, 0x56, 0x31, 0x4f
                };
                socketHandler.Send(junkBytes);
                socketHandler.Close(100);
            }
            socketListener.Close(100);
        }
    }
}
