using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Authentication.ExtendedProtection;
using System.Text;
using System.Threading.Tasks;
using NetFwTypeLib;

namespace VindicateFirewallLib
{
    /// <summary>
    /// Relies on COM and Windows Firewall - Obviously do not reference outside Windows
    /// </summary>
    public static class FirewallManager
    {
        public static void AddRule(String name, FirewallAction action, FirewallProtocol protocol, FirewallDirection direction
            , Int32[] localPorts, Int32[] remotePorts, String serviceName = null)
        {
            //Don't add if it already exists
            var policy = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
            if(policy.Rules.Cast<INetFwRule3>().Any(rule => rule.Name == name))
                return;
            
            //Add new rule
            var newRule = (INetFwRule3)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule"));
            newRule.Enabled = true;
            newRule.Action = (NET_FW_ACTION_)action;
            newRule.Protocol = (Int32)protocol;
            if(localPorts != null)
                newRule.LocalPorts = String.Join(",",localPorts);
            if (remotePorts != null)
                newRule.RemotePorts = String.Join(",",remotePorts);
            newRule.Direction = (NET_FW_RULE_DIRECTION_) direction;
            if (serviceName != null)
                newRule.serviceName = serviceName;
            newRule.Name = name;
            //newRule.Grouping = group;
            newRule.Profiles = (Int32)NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_ALL;

            policy.Rules.Add(newRule);
        }
    }
}
