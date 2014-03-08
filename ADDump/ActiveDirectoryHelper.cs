using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.AccountManagement;
using System.Security.Principal;
using System.Text.RegularExpressions;
using System.Diagnostics;
using CPI.DirectoryServices;
using CommonUtils;

namespace ADDump
{
    public static class ActiveDirectoryHelper
    {
        public class ADUser
        {
            public string UserDN {get; private set;}
            public IDictionary<string,string> Attributes {get;private set;}
            public IList<string> GroupMemberships { get; private set; }

            public ADUser(string userDN)
            {
                this.UserDN = userDN;
                this.Attributes = new Dictionary<string,string>();
                this.GroupMemberships = new List<string>();
            }
        }

        public class ADGroup
        {
            public string GroupDN {get;private set;}
            public IDictionary<string, string> Attributes { get; private set; }
            public List<string> MemberOfGroupDNs { get; private set; }

            public ADGroup(string groupDN)
            {
                this.GroupDN = groupDN;
                this.Attributes = new Dictionary<string,string>();
                this.MemberOfGroupDNs = new List<string>();
            }
        }

        public static IEnumerable<ADUser> GetActiveDirectoryUsers(IEnumerable<string> domainPaths = null, string managerDN = null, int maxCount = 0)
        {
            domainPaths = domainPaths ?? GetDomains().Select(d => DomainNameToPath(d.Name));
            managerDN = managerDN ?? "*";
            return domainPaths.SelectMany(domainPath => GetActiveDirectoryUsers(domainPath, managerDN, maxCount));
        }

        private static string DomainNameToPath(string domainName)
        {
            return string.Concat(@"LDAP://", domainName);
        }

        private static IEnumerable<ADUser> GetActiveDirectoryUsers(string domainPath, string managerDN, int maxCount)
        {
            using (DirectorySearcher searcher = GetDirectorySearcher(domainPath))
            {
                searcher.Filter = "(&(objectCategory=Person)(objectClass=user)(manager={0}))".FormatEx(managerDN);
                searcher.SizeLimit = maxCount;

                using (SearchResultCollection src = searcher.FindAll())
                {
                    foreach (SearchResult sr in src)
                    {
                        string reportDN = (string)sr.Properties["distinguishedName"][0];

                        var user = new ADUser(reportDN);

                        foreach (string propertyName in sr.Properties.PropertyNames)
                        {
                            if ((sr.Properties[propertyName].Count > 0) && (propertyName != "memberof"))
                                user.Attributes[propertyName] = sr.Properties[propertyName][0].ToString();
                        }

                        if (sr.Properties["memberof"].Count > 0)
                        {
                            for (int groupIndex = 0; groupIndex < sr.Properties["memberof"].Count; groupIndex++)
                            {
                                string groupDN = (string)sr.Properties["memberof"][groupIndex];
                                user.GroupMemberships.Add(groupDN);
                            }
                        }

                        yield return user;
                    }
                }
            }
        }

        public static IEnumerable<ADGroup> GetActiveDirectoryGroups(IEnumerable<string> domainPaths = null, int maxCount = int.MaxValue)
        {
            domainPaths = domainPaths ?? GetDomains().Select(d => DomainNameToPath(d.Name));

            foreach (string domainPath in domainPaths)
            {
                using (DirectorySearcher searcher = GetDirectorySearcher(domainPath))
                {
                    searcher.Filter = "(&(objectCategory=group))";
                    searcher.SizeLimit = maxCount;

                    using (SearchResultCollection src = searcher.FindAll())
                    {
                        foreach (SearchResult sr in src)
                        {
                            string groupDN = (string)sr.Properties["distinguishedName"][0];

                            var group = new ADGroup(groupDN);
                            foreach(var propertyName in GroupPropertiesToGet)
                            {
                                if ((sr.Properties[propertyName].Count > 0) && (propertyName != "memberof"))
                                    group.Attributes[propertyName] = sr.Properties[propertyName][0].ToString();
                            }

                            if (sr.Properties["memberof"].Count > 0)
                            {
                                for (int groupIndex = 0; groupIndex < sr.Properties["memberof"].Count; groupIndex++)
                                {
                                    string parentGroupDN = (string)sr.Properties["memberof"][groupIndex];
                                    group.MemberOfGroupDNs.Add(parentGroupDN);
                                }
                            }

                            yield return group;
                        }
                    }
                }
            }
        }

        public static string GetTopLevelUserDN(string domainPath = null, string initialUserDN = null)
        {
            string topLevelDN = null;
            domainPath = domainPath ?? GetCurrentDomainPath();
            using (DirectoryEntry de = GetDirectoryEntry(domainPath))
            {
                using (DirectorySearcher ds = new DirectorySearcher(de))
                {
                    ds.SearchScope = SearchScope.Subtree;
                    ds.PropertiesToLoad.Clear();
                    ds.PropertiesToLoad.Add("manager");
                    ds.PageSize = 1;

                    var managerDN = initialUserDN ?? GetUserDN();
                    do
                    {
                        ds.Filter = string.Format("(&(objectCategory=user)(distinguishedName={0}))", managerDN);
                        topLevelDN = managerDN;
                        SearchResult sr = ds.FindOne();

                        if (sr.Properties["manager"].Count > 0)
                            managerDN = (string)sr.Properties["manager"][0];
                        else
                            managerDN = null;
                    }
                    while (!string.IsNullOrEmpty(managerDN));
                }
            }

            return topLevelDN;
        }

        private static string[] UserPropertiesToGet = 
        {
            "name",
            "company",
            "samaccountname",
            "mobile",
            "extensionattribute4", //employee ID
            "department",
            "logoncount",
            "title",
            "mailnickname",
            "memberof",
            "distinguishedName",
            "physicaldeliveryofficename",
            "legacyexchangedn",
            "countrycode",
            "lastlogon",
            "extensionattribute5", //cost center
            "manager",
            "employeetype",
            "primarygroupid",
            "givenname",
            "sn"

        };

        private static string[] GroupPropertiesToGet = 
        {
            "grouptype"
            ,"whencreated"
            ,"msexchhidefromaddresslists"
            ,"iscriticalsystemobject"
            ,"name"
            ,"description"
            ,"instancetype"
            ,"distinguishedname"
            ,"objectclass"
            ,"memberof"
            ,"mailnickname"
            ,"samaccounttype"
            ,"samaccountname"
            ,"systemflags"
        };


        private static DirectorySearcher GetDirectorySearcher(string domainPath)
        {
            DirectoryEntry directoryEntry = GetDirectoryEntry(domainPath);
            DirectorySearcher ds = new DirectorySearcher(directoryEntry);
            ds.SearchScope = SearchScope.Subtree;
            ds.PropertiesToLoad.Clear();

            Array.ForEach(UserPropertiesToGet, propertyName =>
                {
                    ds.PropertiesToLoad.Add(propertyName);
                });

            ds.PageSize = 1000;
            ds.ServerPageTimeLimit = TimeSpan.FromMinutes(30);

            return ds;
        }

        public static string GetUserDN(string domainUserName = null)
        {
            string[] currentUserAlias = (domainUserName ?? WindowsIdentity.GetCurrent().Name).Split('\\');
            if (currentUserAlias.Length != 2)
                throw new Exception("Current user name is not in domain\alias format");
            using (DirectoryEntry de = GetDirectoryEntry(GetCurrentDomainPath()))
            {
                using (DirectorySearcher ds = new DirectorySearcher(de))
                {
                    ds.SearchScope = SearchScope.Subtree;
                    ds.PropertiesToLoad.Clear();
                    ds.PropertiesToLoad.Add("distinguishedName");
                    ds.PropertiesToLoad.Add("samaccountname");
                    //ds.PageSize = 1;

                    ds.Filter = string.Format("(&(objectCategory=user)(samaccountname={0}))", currentUserAlias[1]);
                    SearchResult rs = ds.FindOne();
                    if (rs != null)
                        return (string)rs.Properties["distinguishedName"][0];
                    else
                        return null;
                }
            }
        }

        private static string GetCurrentDomainPath()
        {
            return DomainNameToPath(Domain.GetCurrentDomain().Name);
        }


        public static string GetDistinguishedName(string netbiosName)
        {
            if (string.IsNullOrEmpty(netbiosName))
            {
                throw new ArgumentNullException("netbiosName");
            }
            if (!Regex.IsMatch(netbiosName, @"^[-\w]{1,15}$"))
            {
                throw new ArgumentException("Invalid NetBIOS domain name format. Domain name should be a maximum of 15 alphanumeric characters (including dashes).", "netbiosName");
            }

            DirectoryEntry globalCatalog = new DirectoryEntry("LDAP://RootDSE");
            string configurationPath = (string)globalCatalog.Properties["configurationNamingContext"].Value;

            DirectoryEntry partitions = new DirectoryEntry("LDAP://CN=Partitions," + configurationPath);

            DirectorySearcher searcher = new DirectorySearcher(partitions,
                String.Format("(&amp;(objectClass=crossRef)(nETBIOSName={0}))", netbiosName),
                new string[] { "nCName" },
                SearchScope.OneLevel);
            SearchResult result = searcher.FindOne();

            string distinguishedName = null;
            if (result != null)
            {
                distinguishedName = result.Properties["nCName"][0] as string;
            }
            return distinguishedName;
        }

        private static DirectoryEntry GetDirectoryEntry(string domainPath)
        {
            //return Domain.GetCurrentDomain().GetDirectoryEntry();
            DirectoryEntry de = new DirectoryEntry(null, null, null, AuthenticationTypes.Secure);
            de.Path = domainPath;
            return de;
        }

        public static string FriendlyDomainToLdapDomain(string friendlyDomainName)
        {
            string ldapPath = null;
            try
            {
                DirectoryContext objContext = new DirectoryContext(
                    DirectoryContextType.Domain, friendlyDomainName);
                Domain objDomain = Domain.GetDomain(objContext);
                ldapPath = objDomain.Name;
            }
            catch (DirectoryServicesCOMException e)
            {
                ldapPath = e.Message.ToString();
            }
            return ldapPath;
        }

        public class ADDomain
        {
            public string Name { get; set; }
            public string Mode { get; set; }
            public string ParentName { get; set; }
        }
        public static IEnumerable<ADDomain> GetDomains()
        {
            using (Forest currentForest = Forest.GetCurrentForest())
            {
                DomainCollection domains = currentForest.Domains;

                foreach (Domain domain in domains)
                    yield return new ADDomain() { Name = domain.Name, Mode = domain.DomainMode.ToString(), ParentName = domain.Parent.IfNotNull(p => p.Name) };
            }
        }

        public class ADCatelog
        {
            public string Name { get; set; }
            public string SiteName { get; set; }
            public string OSVersion { get; set; }
        }
        public static IEnumerable<ADCatelog> GetCatelogs()
        {
            using (Forest currentForest = Forest.GetCurrentForest())
            {
                foreach (GlobalCatalog gc in currentForest.GlobalCatalogs)
                {
                    yield return new ADCatelog() { Name = gc.Name, SiteName = gc.SiteName, OSVersion = gc.OSVersion };
                }
            }
        }
    }
}
