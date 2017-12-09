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
using VindicateLib.Enums;

namespace VindicateLib
{
    internal static class WPADTester
    {
        public static SpoofDetectionResult PerformWPADTest(IPAddress targetAddress, String username, String password, String domain)
        {
            var targetEndPoint = new IPEndPoint(targetAddress, 80);
            WebRequest req = WebRequest.Create("http://" + targetEndPoint.Address + "/wpad.dat");
            if (!String.IsNullOrEmpty(username))
            {
                req.AuthenticationLevel = System.Net.Security.AuthenticationLevel.MutualAuthRequested;
                if (domain == null)
                    req.Credentials = new NetworkCredential(username, password ?? "");
                else
                    req.Credentials = new NetworkCredential(username, password ?? "", domain);
                
            }

            try
            {
                using (var resp = (HttpWebResponse) req.GetResponse())
                {
                    if (resp.StatusCode == HttpStatusCode.OK || resp.StatusCode == HttpStatusCode.Forbidden ||
                        resp.StatusCode == HttpStatusCode.ProxyAuthenticationRequired ||
                        resp.StatusCode == HttpStatusCode.Unauthorized)
                    {
                        /*using (StreamReader reader = new StreamReader(resp.GetResponseStream()))
                        {
                            var token = reader.ReadToEnd().Trim();
                        }*/
                        return new SpoofDetectionResult()
                        {
                            Detected = true,
                            Endpoint = targetEndPoint,
                            Response = "HTTP Code " + resp.StatusCode,
                            Protocol = Protocol.WPAD,
                            Confidence = (resp.StatusCode == HttpStatusCode.OK) ? ConfidenceLevel.Certain : ConfidenceLevel.High

                        };
                        //TODO: Also check HTTP response for proxy details on HTTP OK - Give medium confidence if not existing
                    }
                    else
                    {
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
            catch (WebException ex)
            {
                if (ex.Status == WebExceptionStatus.ProtocolError)
                {
                    return new SpoofDetectionResult
                    {
                        Detected = true,
                        Endpoint = targetEndPoint,
                        Response = "HTTP Code 401 (Unauthorised)",
                        Protocol = Protocol.WPAD,
                        Confidence = ConfidenceLevel.High

                    };
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
    }
}