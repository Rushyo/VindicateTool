using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using VindicateLib.Enums;

namespace VindicateLib
{
    internal static class SocketLoader
    {
        public static Socket LoadUDPSocket(Protocol protocol, Int32 port, Boolean verbose, Logger logger)
        {
            Socket socket = null;
            try
            {
                socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp)
                {
                    ReceiveTimeout = 0,
                    DontFragment = true,
                    EnableBroadcast = true,
                    MulticastLoopback = false
                };
                socket.Bind(new IPEndPoint(IPAddress.Any, port));

                //Receive broadcasts
                //socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.Broadcast, 1);

                if (protocol == Protocol.mDNS)
                {
                    socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.AddMembership,
                        new MulticastOption(IPAddress.Parse("224.0.0.251")));
                }

                if (verbose)
                    logger.LogMessage(String.Format("Loaded {0} service on UDP port {1}", protocol, port), EventLogEntryType.Information, (Int32)LogEvents.LoadedUdpClient, (Int16)LogCategories.LoadingInfo);
            }
            catch (SocketException ex)
            {
                logger.LogMessage(String.Format("Unable to load {0} service ({2}). Disabling. UDP Port {1} in use or insufficient privileges?", protocol, port, ex.Message), EventLogEntryType.Error
                    , (Int32)LogEvents.UnableToLoadUdpClient, (Int16)LogCategories.NonFatalError);
                return null;
            }

            return socket;
        }

        public static Socket LoadTCPSocket(Protocol protocol, Int32 port, Boolean verbose, Logger logger)
        {
            Socket socket = null;
            try
            {
                socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                socket.ReceiveTimeout = 0;
                socket.DontFragment = true;
                socket.Bind(new IPEndPoint(IPAddress.Any, port));

                if (protocol == Protocol.mDNS)
                {
                    socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.AddMembership,
                        new MulticastOption(IPAddress.Parse("224.0.0.251")));
                }

                if (verbose)
                    logger.LogMessage(String.Format("Loaded {0} service on TCP port {1}", protocol, port), EventLogEntryType.Information, (Int32)LogEvents.LoadedTcpClient, (Int16)LogCategories.LoadingInfo);
            }
            catch (SocketException ex)
            {
                logger.LogMessage(String.Format("Unable to load {0} service ({2}). Disabling. TCP Port {1} in use or insufficient privileges?", protocol, port, ex.Message), EventLogEntryType.Error
                    , (Int32)LogEvents.UnableToLoadTcpClient, (Int16)LogCategories.NonFatalError);
                return null;
            }

            return socket;
        }
    }
}
