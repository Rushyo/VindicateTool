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
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using VindicateLib.Enums;

namespace VindicateLib
{
    public sealed class Detector : IDisposable
    {
        private readonly Logger _logger;
        private readonly DetectorSettings _settings;
        private readonly NameServiceClientImpl _nameServiceClient;
        private ConfidenceLevel _highestConfidenceLevel = ConfidenceLevel.FalsePositive;
        private Random _fastRandom;
        private UdpClient _llmnrClient, _nbnsClient, _mdnsClient;
        private String _localBroadcast;
        private Boolean _performSending = false;
        private Boolean _performListening = false;

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1009:DeclareEventHandlersCorrectly")]
        public event EventHandler<Boolean> MessagesSent;
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1009:DeclareEventHandlersCorrectly")]
        public event EventHandler<ConfidenceLevel> ConfidenceLevelChange;

        private ConfidenceLevel HighestConfidenceLevel
        {
            get { return _highestConfidenceLevel; }
            set
            {
                OnConfidenceLevelChange();
                _highestConfidenceLevel = value;
            }
        }

        /// <summary>
        /// NOTE: Not thread-safe
        /// </summary>
        private Random FastRandom
        {
            get
            {
                //Lazy load non-crypto non-thread safe random
                if (_fastRandom == null)
                {
                    var seed = new Byte[4];
                    using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
                        rng.GetBytes(seed);
                    _fastRandom = new Random(BitConverter.ToInt32(seed, 0));
                }
                return _fastRandom;
            }
        }

        public Detector(Logger logger, DetectorSettings settings)
        {
            if (settings.NTLMUsername != null && settings.NTLMPassword == null)
                settings.NTLMPassword = GenerateRandomPassword();

            _logger = logger;
            _settings = settings;
            _nameServiceClient = new NameServiceClientImpl();

            InitialiseClients();
            InitialiseBroadcastAddress();
        }

        public void BeginSendingAndListening()
        {
            _performSending = true;
            _performListening = true;

            Task.Run(() =>
            {
                var clientActioner = new UdpClientActioner();
                while (_performSending)
                {
                    if (_settings.UseLLMNR)
                        _nameServiceClient.SendRequest(_llmnrClient, Protocol.LLMNR, _settings.LLMNRTarget, null, clientActioner);
                    if (_settings.UseNBNS)
                        _nameServiceClient.SendRequest(_nbnsClient, Protocol.NBNS, _settings.NBNSTarget, _localBroadcast, clientActioner);
                    if (_settings.UsemDNS)
                        _nameServiceClient.SendRequest(_mdnsClient, Protocol.mDNS, _settings.mDNSTarget, null, clientActioner);

                    OnMessagesSent();
                    Thread.Sleep(_settings.SendRequestFrequency);
                }
            });

            if (_settings.UseLLMNR)
            {
                Task.Run(() =>
                {
                    var clientActioner = new UdpClientActioner();
                    var spinWait = new SpinWait();
                    while (_performListening)
                    {
                        //Valid transaction IDs should be acquired from sent requests, but for now we don't validate so send whatever
                        HandleResponseReceivedResult(_nameServiceClient.ReceiveAndHandleReply(_llmnrClient, Protocol.LLMNR, null, clientActioner));
                        spinWait.SpinOnce();
                    }
                });
            }

            if (_settings.UseNBNS)
            {
                Task.Run(() =>
                {
                    var clientActioner = new UdpClientActioner();
                    var spinWait = new SpinWait();
                    while (_performListening)
                    {
                        HandleResponseReceivedResult(_nameServiceClient.ReceiveAndHandleReply(_nbnsClient, Protocol.NBNS, null, clientActioner));
                        spinWait.SpinOnce();
                    }
                });
            }

            if (_settings.UsemDNS)
            {
                Task.Run(() =>
                {
                    var clientActioner = new UdpClientActioner();
                    var spinWait = new SpinWait();
                    while (_performListening)
                    {
                        HandleResponseReceivedResult(_nameServiceClient.ReceiveAndHandleReply(_mdnsClient, Protocol.mDNS, null, clientActioner));
                        spinWait.SpinOnce();
                    }
                });
            }
        }

        public void EndSendingAndListening()
        {
            _performSending = false;
            _performListening = false;
            _llmnrClient?.Close();
            _nbnsClient?.Close();
            _mdnsClient?.Close();
        }


        private void InitialiseBroadcastAddress()
        {
            //Set local broadcast for NBNS
            _localBroadcast = NetworkHelper.GetBroadcastAddress(_settings.PreferredIPv4Address);
            if (_settings.UseNBNS)
            {
                if (_localBroadcast == null)
                {
                    _logger.LogMessage("Unable to find broadcast address for NBNS", EventLogEntryType.Information,
                        (Int32) LogEvents.NoBroadcastAdapterFound, (Int16) LogCategories.NonFatalError);
                    _settings.UseNBNS = false;
                }
                else if (_settings.Verbose)
                {
                    _logger.LogMessage(String.Format("NBNS client will broadcast to address {0}", _localBroadcast),
                        EventLogEntryType.Information, (Int32) LogEvents.SetBroadcastAddress,
                        (Int16) LogCategories.LoadingInfo);
                }
            }
        }

        private void HandleResponseReceivedResult(SpoofDetectionResult result)
        {
            if (result == null)
                return;

            if(result.Protocol == Protocol.WPAD || result.Protocol == Protocol.SMB)
                throw new NotImplementedException(String.Format("Tried to handle an {0} response as an NS response", result.Protocol));

            if (result.Detected)
            {
                _logger.LogMessage(String.Format("Received {0} response from {1} claiming {2}", result.Protocol, result.Endpoint.Address, result.Response)
                    , EventLogEntryType.Information, (Int32)LogEvents.SpoofDetected, (Int16)LogCategories.SpoofNotice, null);
                if (result.Confidence > HighestConfidenceLevel)
                {
                    HighestConfidenceLevel = result.Confidence;
                    _logger.LogMessage(String.Format("Spoofing confidence level adjusted to {0}", HighestConfidenceLevel)
                        , EventLogEntryType.Warning, (Int32)LogEvents.ConfidenceLevelIncreased, (Int16)LogCategories.SpoofNotice, null);
                    //Console.WriteLine("[+] *** Spoofing confidence level adjusted to " + highestConfidenceLevel + " ***");
                }

                if (_settings.UseWPADProbes)
                    TestForWPAD(result);
                if (_settings.UseSMBProbes)
                    TestForSMB(result);
            }
            else
            {
                _logger.LogMessage(String.Format("Received response from {1} with error {2} (Expected {0})", result.Protocol, result.Endpoint.Address, result.ErrorMessage)
                    , EventLogEntryType.Information, (Int32)LogEvents.UnexpectedProtocolResponse, (Int16)LogCategories.DetectedUnexpectedCondition, null);
                if (result.Confidence > HighestConfidenceLevel)
                {
                    HighestConfidenceLevel = result.Confidence;
                    _logger.LogMessage(String.Format("Spoofing confidence level adjusted to {0}", HighestConfidenceLevel)
                        , EventLogEntryType.Warning, (Int32)LogEvents.ConfidenceLevelIncreased, (Int16)LogCategories.SpoofNotice, null);
                }
            }
        }

        private void TestForSMB(SpoofDetectionResult result)
        {
            SpoofDetectionResult smbTestResult = SMBTester.PerformSMBTest(result.Endpoint.Address, _settings.PreferredIPv4Address);
            if (smbTestResult.Detected)
            {
                _logger.LogMessage(String.Format("Detected service on SMB TCP port at {0}",
                        smbTestResult.Endpoint.Address)
                    , EventLogEntryType.Warning, (Int32)LogEvents.SMBTestSucceeded, (Int16)LogCategories.SpoofNotice,
                    null);
            }
            else
            {
                _logger.LogMessage(String.Format("Failed to connect to SMB TCP port at {0} with error {1}",
                        smbTestResult.Endpoint.Address, smbTestResult.ErrorMessage)
                    , EventLogEntryType.Information, (Int32)LogEvents.SMBTestFailed,
                    (Int16)LogCategories.DetectedUnexpectedCondition, null);
            }
            if (smbTestResult.Confidence > HighestConfidenceLevel)
            {
                HighestConfidenceLevel = smbTestResult.Confidence;
                _logger.LogMessage(String.Format("Spoofing confidence level adjusted to {0}", HighestConfidenceLevel)
                    , EventLogEntryType.Warning, (Int32)LogEvents.ConfidenceLevelIncreased, (Int16)LogCategories.SpoofNotice,
                    null);
            }
        }

        private void TestForWPAD(SpoofDetectionResult result)
        {
            SpoofDetectionResult wpadTestResult = WPADTester.PerformWPADTest(IPAddress.Parse(result.Response), 80, _settings.NTLMUsername,
                _settings.NTLMPassword, _settings.NTLMDomain);
            if (wpadTestResult.Detected)
            {
                _logger.LogMessage(String.Format("Detected active WPAD service at {0} claiming {1}",
                        wpadTestResult.Endpoint.Address, wpadTestResult.Response)
                    , EventLogEntryType.Warning, (Int32) LogEvents.WPADProxyFound, (Int16) LogCategories.SpoofNotice,
                    null);
            }
            else
            {
                _logger.LogMessage(String.Format("Received HTTP response from WPAD service {0} with error {1}",
                        wpadTestResult.Endpoint.Address, wpadTestResult.ErrorMessage)
                    , EventLogEntryType.Information, (Int32) LogEvents.WPADProxyError,
                    (Int16) LogCategories.DetectedUnexpectedCondition, null);
            }
            if (wpadTestResult.Confidence > HighestConfidenceLevel)
            {
                HighestConfidenceLevel = wpadTestResult.Confidence;
                _logger.LogMessage(String.Format("Spoofing confidence level adjusted to {0}", HighestConfidenceLevel)
                    , EventLogEntryType.Warning, (Int32) LogEvents.ConfidenceLevelIncreased, (Int16) LogCategories.SpoofNotice,
                    null);
            }
        }

        private void InitialiseClients()
        {
            if (_settings.UseLLMNR)
            {
                _llmnrClient = LoadUDPClient(Protocol.LLMNR, _settings.LLMNRPort);
                if (_llmnrClient == null)
                    _settings.UseLLMNR = false;
            }
            if (_settings.UseNBNS)
            {
                _nbnsClient = LoadUDPClient(Protocol.NBNS, _settings.NBNSPort);
                if (_nbnsClient == null)
                    _settings.UseNBNS = false;
            }
            if (_settings.UsemDNS)
            {
                _mdnsClient = LoadUDPClient(Protocol.mDNS, _settings.mDNSPort);
                if (_mdnsClient == null)
                    _settings.UsemDNS = false;
            }
        }

        private UdpClient LoadUDPClient(Protocol protocol, Int32 port)
        {
            UdpClient client = null;
            try
            {
                client = new UdpClient(port)
                {
                    Client =
                    {
                        ReceiveTimeout = 0,
                    },
                    DontFragment = true,
                    EnableBroadcast = true,
                    MulticastLoopback = false
                };

                if(protocol == Protocol.mDNS)
                    client.JoinMulticastGroup(IPAddress.Parse("224.0.0.251"));

                if (_settings.Verbose)
                    _logger.LogMessage(String.Format("Loaded {0} service on port {1}", protocol, port), EventLogEntryType.Information, (Int32)LogEvents.LoadedUdpClient, (Int16)LogCategories.LoadingInfo);
            }
            catch (SocketException ex)
            {
                _logger.LogMessage(String.Format("Unable to load {0} service ({2}). Disabling. Port {1} in use or insufficient privileges?", protocol, port, ex.Message), EventLogEntryType.Error
                    , (Int32)LogEvents.UnableToLoadUdpClient, (Int16)LogCategories.NonFatalError);
                return null;
            }

            return client;
        }

        private String GenerateRandomPassword()
        {
            const Int32 randomPasswordLength = 40;
            const String valid = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
            var pass = new StringBuilder();
            for(var i = 0; i < randomPasswordLength; i++)
                pass.Append(valid[FastRandom.Next(valid.Length)]);
            return pass.ToString();
        }

        public Boolean IsReady()
        {
            return (_settings.UseLLMNR || _settings.UseNBNS || _settings.UsemDNS) && _settings.SanityCheck();
        }

        private void OnMessagesSent()
        {
            MessagesSent?.Invoke(this, _settings.Verbose);
        }

        private void OnConfidenceLevelChange()
        {
            ConfidenceLevelChange?.Invoke(this, HighestConfidenceLevel);
        }

        [ExcludeFromCodeCoverage()]
        public void Dispose()
        {
            ((IDisposable) _llmnrClient)?.Dispose();
            ((IDisposable) _nbnsClient)?.Dispose();
            ((IDisposable) _mdnsClient)?.Dispose();
        }
    }
}
