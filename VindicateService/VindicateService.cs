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
using System.Reflection;
using System.Security.Principal;
using System.ServiceProcess;
using CommandLine;
using VindicateLib;
using VindicateLib.Enums;

namespace VindicateService
{
    public partial class VindicateService : ServiceBase
    {
        private Detector _detector;

        public VindicateService()
        {
            InitializeComponent();
        }

        //New-EventLog -Source "VindicateService" -LogName "Vindicate"
        protected override void OnStart(String[] args)
        {
            var logger = new Logger(LogMode.EventLog, Assembly.GetExecutingAssembly().GetName().Name, false);

            var parser = new Parser();
            var options = new Options();
            Boolean validArgs = parser.ParseArguments(args, options);
            if (!validArgs)
            {
                logger.LogMessage("Command line arguments failed to validate.", EventLogEntryType.Error, (Int32)LogEvents.InvalidArguments, (Int16)LogCategories.FatalError);
                Stop();
                return;
            }

            var settings = new DetectorSettings
            {
                UseLLMNR = options.UseLLMNR,
                UseNBNS = options.UseNBNS,
                UsemDNS = options.UsemDNS,
                Verbose = options.Verbose,
                LLMNRTarget = options.LLMNRTarget,
                NBNSTarget = options.NBNSTarget,
                mDNSTarget = options.mDNSTarget,
                LLMNRPort = options.LLMNRPort,
                NBNSPort = options.NBNSPort,
                NTLMUsername = options.NTLMUsername,
                NTLMPassword = options.NTLMPassword,
                NTLMDomain = options.NTLMDomain,
                PreferredIPv4Address = options.PreferredIPv4Address,
                UseWPADProbes = options.UseWPADProbes,
                UseSMBProbes = options.UseSMBProbes,
                SendRequestFrequency = options.Frequency

            };
            if (!settings.SanityCheck())
            {
                logger.LogMessage("Invalid arguments (ports out of range or missing critical argument).", EventLogEntryType.Error, (Int32)LogEvents.InvalidArguments, (Int16)LogCategories.FatalError);
                Stop();
                return;
            }

            if (new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))
            {
                logger.LogMessage(
                    "It appears the application is running as an elevated administrator! This is not required and isn't a good idea. Seriously."
                    , EventLogEntryType.Warning, (Int32)LogEvents.RunningAsAdmin,
                    (Int16)LogCategories.SecurityWarning);
            }

            //Create detector
            _detector = new Detector(logger, settings);

            //Check that all services are still enabled after initialisation
            if (!_detector.IsReady())
            {
                logger.LogMessage("No network services could be created", EventLogEntryType.Error, (Int32)LogEvents.NoValidServices, (Int16)LogCategories.FatalError);
                Stop();
                return;
            }
            _detector.BeginSendingAndListening();
            
        }

        protected override void OnStop()
        {
            _detector.EndSendingAndListening();
            RequestAdditionalTime(2000);
        }
    }
}
