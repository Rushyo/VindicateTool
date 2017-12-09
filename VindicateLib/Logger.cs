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
using System.Security;
using VindicateLib.Enums;

namespace VindicateLib
{
    public class Logger
    {
        private readonly LogMode _logMode;
        private readonly String _logSource;
        private readonly Boolean _writeToConsole;

        public Logger(LogMode logMode, String logSource, Boolean writeToConsole)
        {
            _logMode = logMode;
            _logSource = logSource;
            _writeToConsole = writeToConsole;

            if(logMode == LogMode.FileLog)
            {
                throw new NotImplementedException("File logging NYI");
            }
        }

        public void LogMessage(String message, EventLogEntryType entryType, Int32 eventId = 0, Int16 category = 0, Byte[] rawData = null)
        {

            if (_writeToConsole)
                Console.WriteLine(message);

            if (_logMode == LogMode.Silent)
                return;

            if (_logMode == LogMode.EventLog)
            {
                try
                {
                    EventLog.WriteEntry(_logSource, message, entryType, eventId, category, rawData);
                }
                catch (SecurityException ex)
                {
                    throw new SecurityException(String.Format("Unable to access event log source {0}. Run 'New-EventLog -Source \"{0}\" -LogName \"Vindicate\"' from an elevated PowerShell prompt.", _logSource), ex);
                }
            }
            else if (_logMode == LogMode.FileLog)
            {
                throw new NotImplementedException("File logging NYI");
            }

        }
    }
}
