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
using System.IO;
using System.Net;
using VindicateLib.Enums;

namespace VindicateLib
{
    internal static class WPADTester
    {
        private const Int32 Timeout = 5000;

        public static SpoofDetectionResult PerformWPADTest(IPAddress targetAddress, Int32 targetPort, String username, String password, String domain)
        {
            var targetEndPoint = new IPEndPoint(targetAddress, targetPort);
            var req = (HttpWebRequest)WebRequest.Create(String.Format("http://{0}:{1}/wpad.dat", targetEndPoint.Address, targetEndPoint.Port));
            req.UnsafeAuthenticatedConnectionSharing = true;
            req.Timeout = Timeout;
            req.KeepAlive = false;
            if (!String.IsNullOrEmpty(username))
            {
                req.AuthenticationLevel = System.Net.Security.AuthenticationLevel.MutualAuthRequested;
                if (domain == null)
                    req.Credentials = new NetworkCredential(username, password ?? "");
                else
                    req.Credentials = new NetworkCredential(username, password ?? "", domain);
            }

            req.UserAgent = "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.10136";

            try
            {
                using (var resp = (HttpWebResponse) req.GetResponse())
                {
                    return HandleWebResponse(resp, targetEndPoint);
                }
            }
            catch (WebException ex)
            {
                if (ex.Status == WebExceptionStatus.ProtocolError)
                {
                    SpoofDetectionResult result = HandleWebResponse((HttpWebResponse)ex.Response, targetEndPoint);
                    ex.Response.Dispose();
                    return result;
                }
                else
                {
                    return new SpoofDetectionResult()
                    {
                        Detected = false,
                        Endpoint = targetEndPoint,
                        ErrorMessage = String.Format("Unknown HTTP error ({0})", ex.Message),
                        Protocol = Protocol.WPAD,
                        Confidence = ConfidenceLevel.FalsePositive
                    };
                }
            }
            catch (Exception ex)
            {
                return new SpoofDetectionResult()
                {
                    Detected = false,
                    Endpoint = targetEndPoint,
                    ErrorMessage = String.Format("Unable to contact WPAD server ({0})", ex.Message),
                    Protocol = Protocol.WPAD,
                    Confidence = ConfidenceLevel.FalsePositive
                };
            }
        }

        private static SpoofDetectionResult HandleWebResponse(HttpWebResponse resp, IPEndPoint targetEndPoint)
        {
            if(resp == null)
                throw new ArgumentNullException("resp");

            if (resp.StatusCode == HttpStatusCode.OK)
            {
                var isResponder = false;
                var isWPAD = false;

                if (resp.GetResponseStream() != null)
                {
                    using (var reader = new StreamReader(resp.GetResponseStream()))
                    {
                        reader.BaseStream.ReadTimeout = Timeout;
                        String content = reader.ReadToEnd();
                        isResponder = content.Contains("RespProxySrv");
                        isWPAD = content.Contains("PROXY");
                    }
                }

                return new SpoofDetectionResult
                {
                    Detected = true,
                    Endpoint = targetEndPoint,
                    Response = isResponder ? "Responder WPAD response" : isWPAD ? "WPAD file" : "HTTP Code OK",
                    Protocol = Protocol.WPAD,
                    Confidence = isResponder ? ConfidenceLevel.Certain : isWPAD ? ConfidenceLevel.High : ConfidenceLevel.Medium
                };
            }

            if (resp.StatusCode == HttpStatusCode.Forbidden ||
                resp.StatusCode == HttpStatusCode.ProxyAuthenticationRequired ||
                resp.StatusCode == HttpStatusCode.Unauthorized)
            {
                return new SpoofDetectionResult()
                {
                    Detected = true,
                    Endpoint = targetEndPoint,
                    Response = "HTTP Code " + resp.StatusCode,
                    Protocol = Protocol.WPAD,
                    Confidence = ConfidenceLevel.Medium
                };
            }

            return new SpoofDetectionResult()
            {
                Detected = false,
                Endpoint = targetEndPoint,
                ErrorMessage = "Unexpected HTTP code " + resp.StatusCode,
                Protocol = Protocol.WPAD,
                Confidence = ConfidenceLevel.Low
            };
        }
    }
}