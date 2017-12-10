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
using System.Threading;
using CommandLine;
using CommandLine.Text;
using VindicateLib;
using VindicateLib.Enums;

namespace VindicateCLI
{
    internal static class Program
    {
        //New-EventLog -Source "VindicateCLI" -LogName "Vindicate"
        private static Int32 Main(String[] args)
        {
            Console.WriteLine("Vindicate - Copyright (C) 2017 Danny Moules");
            Console.WriteLine("This program comes with ABSOLUTELY NO WARRANTY.");
            Console.WriteLine("This is free software, and you are welcome to redistribute it");
            Console.WriteLine("under certain conditions; see LICENSE for details.");
            Console.WriteLine("");

            var parser = new Parser();
            var options = new Options();
            Boolean validArgs = parser.ParseArguments(args, options);
            if (!validArgs)
            { 
                Console.WriteLine("Command line arguments failed to validate.");
                Console.WriteLine(HelpText.AutoBuild(options));
                Console.WriteLine("Press any key to continue.");
                Console.ReadKey();
                return 0xA0; //ERROR_BAD_ARGUMENTS
            }

            var logger = new Logger(options.Logging ? LogMode.EventLog : LogMode.Silent, Assembly.GetExecutingAssembly().GetName().Name, true);
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
                Console.WriteLine("Invalid arguments (ports out of range or missing critical argument).");
                Console.WriteLine(HelpText.AutoBuild(options));
                Console.WriteLine("Press any key to continue.");
                Console.ReadKey();
                return 0xA0; //ERROR_BAD_ARGUMENTS
            }

            if (new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))
            {
                logger.LogMessage(
                    "It appears the application is running as an elevated administrator! This is not required and isn't a good idea. Seriously."
                    , EventLogEntryType.Warning, (Int32) LogEvents.RunningAsAdmin,
                    (Int16) LogCategories.SecurityWarning);
            }

            //Create detector
            using (var detector = new Detector(logger, settings))
            {

                //Check that all services are still enabled after initialisation
                if (!detector.IsReady())
                {
                    logger.LogMessage("No network services could be created", EventLogEntryType.Error,
                        (Int32) LogEvents.NoValidServices, (Int16) LogCategories.FatalError);
                    return 0x41; //ERROR_NETWORK_ACCESS_DENIED
                }

                detector.MessagesSent += DetectorMessagesSent;
                detector.BeginSendingAndListening();
                while (Console.ReadKey(true).Key != ConsoleKey.Escape)
                    Thread.Yield();
                detector.EndSendingAndListening();
            }

            return 0;
        }

        private static void DetectorMessagesSent(Object sender, Boolean verbose)
        {
            if(verbose)
                Console.WriteLine("Sending round of broadcasts");
        }

        
    }
}
