using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace VindicateLibTests
{
    internal static class SMBServiceFakeHelper
    {
        public static void PerformSingleSMBServiceListen(TcpListener listener)
        {
            listener.Start();
            listener.BeginAcceptSocket(AsyncCallback, listener);
        }

        private static void AsyncCallback(IAsyncResult result)
        {
            var listener = (TcpListener) result.AsyncState;
            try
            {
                Socket listenSocket = listener.EndAcceptSocket(result);
                var buffer = new Byte[4096];
                listenSocket.Receive(buffer);
                listenSocket.Close();
            }
            finally
            {
                listener.Stop();
            }

        }

        public static TcpListener CreateSMBService(Int32 port)
        {
            TcpListener tcpListener = TcpListener.Create(port);
            return tcpListener;
        }
    }
}
