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


namespace VindicateLib.Enums
{
    public enum LogEvents
    {
        LoadedUdpClient = 1,
        UnableToLoadUdpClient = 2,
        NoValidServices = 3,
        SetBroadcastAddress = 4,
        NoBroadcastAdapterFound = 5,
        SpoofDetected = 6,
        ConfidenceLevelIncreased = 7,
        WPADProxyFound = 8,
        WPADProxyError = 9,
        UnexpectedProtocolResponse = 10,
        SMBTestSucceeded = 11,
        SMBTestFailed = 12,
        RunningAsAdmin = 13,
        InvalidArguments = 14
    }
}