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
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using VindicateLib;
using VindicateLib.Enums;

namespace VindicateLibTests
{
    [TestClass]
    public class WPADTesterTests
    {
        private const String ServerAddress = "127.0.0.1";
        private const Int32 ServerPort = 8081;

        [TestMethod]
        public void PerformWPADTest()
        {
            HttpListener httpListener = WPADServiceFakeHelper.CreateWPADService(String.Format("http://{0}:{1}/", ServerAddress, ServerPort));
            try
            {
                WPADServiceFakeHelper.PerformSingleWPADServiceListen(httpListener, HttpStatusCode.OK, "");
                SpoofDetectionResult result =
                    WPADTester.PerformWPADTest(IPAddress.Parse(ServerAddress), ServerPort, "test", "test", "test");
                Assert.IsTrue(result.Detected);
                Assert.AreEqual(ConfidenceLevel.Medium, result.Confidence);
                Assert.AreEqual(Protocol.WPAD, result.Protocol);
                Assert.IsNull(result.ErrorMessage);
                Assert.AreEqual("HTTP Code OK", result.Response);
                Assert.AreEqual(ServerAddress, result.Endpoint.Address.ToString());
                Assert.AreEqual(ServerPort, result.Endpoint.Port);
            }
            finally
            {
                httpListener.Close();
            }
        }

        [TestMethod]
        public void PerformWPADTest_TotalJunk()
        {
            using (Socket socket = WPADServiceFakeHelper.CreateJunkTcpSocket(ServerAddress, ServerPort))
            {
                SpoofDetectionResult result =
                    WPADTester.PerformWPADTest(IPAddress.Parse(ServerAddress), ServerPort, "test", "test", "test");
                Assert.IsFalse(result.Detected);
                Assert.AreEqual(ConfidenceLevel.FalsePositive, result.Confidence);
                Assert.AreEqual(Protocol.WPAD, result.Protocol);
                Assert.IsNull(result.Response);
                Assert.AreEqual(
                    "Unknown HTTP error (The server committed a protocol violation. Section=ResponseStatusLine)",
                    result.ErrorMessage);
                Assert.AreEqual(ServerAddress, result.Endpoint.Address.ToString());
                Assert.AreEqual(ServerPort, result.Endpoint.Port);
            }
        }

        [TestMethod]
        [TestCategory("Slow")]
        public void PerformWPADTest_ConnectionSinkhole()
        {
            using (Socket socket = WPADServiceFakeHelper.CreateConnectionSinkholeTcpSocket(ServerAddress, ServerPort))
            {
                SpoofDetectionResult result =
                    WPADTester.PerformWPADTest(IPAddress.Parse(ServerAddress), ServerPort, "test", "test", "test");
                Assert.IsFalse(result.Detected);
                Assert.AreEqual(ConfidenceLevel.FalsePositive, result.Confidence);
                Assert.AreEqual(Protocol.WPAD, result.Protocol);
                Assert.IsNull(result.Response);
                Assert.AreEqual("Unknown HTTP error (The request was aborted: The operation has timed out.)",
                    result.ErrorMessage);
                Assert.AreEqual(ServerAddress, result.Endpoint.Address.ToString());
                Assert.AreEqual(ServerPort, result.Endpoint.Port);
            }
        }

        [TestMethod]
        [TestCategory("Slow")]
        public void PerformWPADTest_ResponseSinkhole()
        {
            using (Socket socket = WPADServiceFakeHelper.CreateHTTPSinkholeTcpSocket(ServerAddress, ServerPort))
            {
                SpoofDetectionResult result =
                    WPADTester.PerformWPADTest(IPAddress.Parse(ServerAddress), ServerPort, "test", "test", "test");
                Assert.IsFalse(result.Detected);
                Assert.AreEqual(ConfidenceLevel.FalsePositive, result.Confidence);
                Assert.AreEqual(Protocol.WPAD, result.Protocol);
                Assert.IsNull(result.Response);
                Assert.AreEqual("Unknown HTTP error (The operation has timed out.)", result.ErrorMessage);
                Assert.AreEqual(ServerAddress, result.Endpoint.Address.ToString());
                Assert.AreEqual(ServerPort, result.Endpoint.Port);
            }
        }

        [TestMethod]
        public void PerformWPADTest_ResponderLikeReply()
        {
            HttpListener httpListener = WPADServiceFakeHelper.CreateWPADService(String.Format("http://{0}:{1}/", ServerAddress, ServerPort));

            try
            {
                WPADServiceFakeHelper.PerformSingleWPADServiceListen(httpListener, HttpStatusCode.OK, "RespProxySrv");
                SpoofDetectionResult result =
                    WPADTester.PerformWPADTest(IPAddress.Parse(ServerAddress), ServerPort, "test", "test", "test");
                Assert.IsTrue(result.Detected);
                Assert.AreEqual(ConfidenceLevel.Certain, result.Confidence);
                Assert.AreEqual(Protocol.WPAD, result.Protocol);
                Assert.IsNull(result.ErrorMessage);
                Assert.AreEqual("Responder WPAD response", result.Response);
                Assert.AreEqual(ServerAddress, result.Endpoint.Address.ToString());
                Assert.AreEqual(ServerPort, result.Endpoint.Port);
            }
            finally
            {
                httpListener.Close();
            }
           
        }

        [TestMethod]
        public void PerformWPADTest_LegitWPAD()
        {
            HttpListener httpListener = WPADServiceFakeHelper.CreateWPADService(String.Format("http://{0}:{1}/", ServerAddress, ServerPort));
            try
            {
                WPADServiceFakeHelper.PerformSingleWPADServiceListen(httpListener, HttpStatusCode.OK,
                    "Something Something PROXY Something");
                SpoofDetectionResult result =
                    WPADTester.PerformWPADTest(IPAddress.Parse(ServerAddress), ServerPort, "test", "test", "test");
                Assert.IsTrue(result.Detected);
                Assert.AreEqual(ConfidenceLevel.High, result.Confidence);
                Assert.AreEqual(Protocol.WPAD, result.Protocol);
                Assert.IsNull(result.ErrorMessage);
                Assert.AreEqual("WPAD file", result.Response);
                Assert.AreEqual(ServerAddress, result.Endpoint.Address.ToString());
                Assert.AreEqual(ServerPort, result.Endpoint.Port);
            }
            finally
            {
                httpListener.Close();
            }
        }


        [TestMethod]
        public void PerformWPADTest_ForbiddenResponse()
        {
            HttpListener httpListener = WPADServiceFakeHelper.CreateWPADService(String.Format("http://{0}:{1}/", ServerAddress, ServerPort));
            try
            {
                WPADServiceFakeHelper.PerformSingleWPADServiceListen(httpListener, HttpStatusCode.Forbidden,
                    "Forbidden");
                SpoofDetectionResult result =
                    WPADTester.PerformWPADTest(IPAddress.Parse(ServerAddress), ServerPort, "test", "test", "test");
                Assert.IsTrue(result.Detected);
                Assert.AreEqual(ConfidenceLevel.Medium, result.Confidence);
                Assert.AreEqual(Protocol.WPAD, result.Protocol);
                Assert.IsNull(result.ErrorMessage);
                Assert.AreEqual("HTTP Code Forbidden", result.Response);
                Assert.AreEqual(ServerAddress, result.Endpoint.Address.ToString());
                Assert.AreEqual(ServerPort, result.Endpoint.Port);
            }
            finally
            {
                httpListener.Close();
            }
        }

        [TestMethod]
        public void PerformWPADTest_NotFoundResponse()
        {
            HttpListener httpListener = WPADServiceFakeHelper.CreateWPADService(String.Format("http://{0}:{1}/", ServerAddress, ServerPort));
            try
            {
                WPADServiceFakeHelper.PerformSingleWPADServiceListen(httpListener, HttpStatusCode.NotFound,
                    "Not Found");
                SpoofDetectionResult result =
                    WPADTester.PerformWPADTest(IPAddress.Parse(ServerAddress), ServerPort, "test", "test", "test");
                Assert.IsFalse(result.Detected);
                Assert.AreEqual(ConfidenceLevel.Low, result.Confidence);
                Assert.AreEqual(Protocol.WPAD, result.Protocol);
                Assert.IsNull(result.Response);
                Assert.AreEqual("Unexpected HTTP code NotFound", result.ErrorMessage);
                Assert.AreEqual(ServerAddress, result.Endpoint.Address.ToString());
                Assert.AreEqual(ServerPort, result.Endpoint.Port);
            }
            finally
            {
                httpListener.Close();
            }
            
        }

        [TestMethod]
        public void PerformWPADTest_NoServer()
        {
            SpoofDetectionResult result =
                WPADTester.PerformWPADTest(IPAddress.Parse(ServerAddress), ServerPort, "test", "test", "test");
            Assert.IsFalse(result.Detected);
            Assert.AreEqual(ConfidenceLevel.FalsePositive, result.Confidence);
            Assert.AreEqual(Protocol.WPAD, result.Protocol);
            Assert.AreEqual("Unknown HTTP error (Unable to connect to the remote server)", result.ErrorMessage);
            Assert.IsNull(result.Response);
            Assert.AreEqual(ServerAddress, result.Endpoint.Address.ToString());
            Assert.AreEqual(ServerPort, result.Endpoint.Port);
        }




        [TestMethod]
        public void PerformWPADTest_AuthPermutations()
        {
            HttpListener httpListener = WPADServiceFakeHelper.CreateWPADService(String.Format("http://{0}:{1}/", ServerAddress, ServerPort));
            try
            {
                WPADServiceFakeHelper.PerformSingleWPADServiceListen(httpListener, HttpStatusCode.OK, "");
                SpoofDetectionResult result =
                    WPADTester.PerformWPADTest(IPAddress.Parse(ServerAddress), ServerPort, null, null, null);
                Assert.IsTrue(result.Detected);
                Assert.AreEqual(ConfidenceLevel.Medium, result.Confidence);
                Assert.AreEqual("HTTP Code OK", result.Response);

                WPADServiceFakeHelper.PerformSingleWPADServiceListen(httpListener, HttpStatusCode.OK, "");
                result = WPADTester.PerformWPADTest(IPAddress.Parse(ServerAddress), ServerPort, "Guest", null, null);
                Assert.IsTrue(result.Detected);
                Assert.AreEqual(ConfidenceLevel.Medium, result.Confidence);
                Assert.AreEqual("HTTP Code OK", result.Response);

                WPADServiceFakeHelper.PerformSingleWPADServiceListen(httpListener, HttpStatusCode.OK, "");
                result = WPADTester.PerformWPADTest(IPAddress.Parse(ServerAddress), ServerPort, "Guest", "test", null);
                Assert.IsTrue(result.Detected);
                Assert.AreEqual(ConfidenceLevel.Medium, result.Confidence);
                Assert.AreEqual("HTTP Code OK", result.Response);

                WPADServiceFakeHelper.PerformSingleWPADServiceListen(httpListener, HttpStatusCode.OK, "");
                result = WPADTester.PerformWPADTest(IPAddress.Parse(ServerAddress), ServerPort, "Guest", "test",
                    "test");
                Assert.IsTrue(result.Detected);
                Assert.AreEqual(ConfidenceLevel.Medium, result.Confidence);
                Assert.AreEqual("HTTP Code OK", result.Response);

                WPADServiceFakeHelper.PerformSingleWPADServiceListen(httpListener, HttpStatusCode.OK, "");
                result = WPADTester.PerformWPADTest(IPAddress.Parse(ServerAddress), ServerPort, "Guest", null, "test");
                Assert.IsTrue(result.Detected);
                Assert.AreEqual(ConfidenceLevel.Medium, result.Confidence);
                Assert.AreEqual("HTTP Code OK", result.Response);

                WPADServiceFakeHelper.PerformSingleWPADServiceListen(httpListener, HttpStatusCode.OK, "");
                result = WPADTester.PerformWPADTest(IPAddress.Parse(ServerAddress), ServerPort, null, "test", "test");
                Assert.IsTrue(result.Detected);
                Assert.AreEqual(ConfidenceLevel.Medium, result.Confidence);
                Assert.AreEqual("HTTP Code OK", result.Response);

                WPADServiceFakeHelper.PerformSingleWPADServiceListen(httpListener, HttpStatusCode.OK, "");
                result = WPADTester.PerformWPADTest(IPAddress.Parse(ServerAddress), ServerPort, null, null, "test");
                Assert.IsTrue(result.Detected);
                Assert.AreEqual(ConfidenceLevel.Medium, result.Confidence);
                Assert.AreEqual("HTTP Code OK", result.Response);
            }
            finally
            {
                httpListener.Close();
            }
            
        }
    }
}
