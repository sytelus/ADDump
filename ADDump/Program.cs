using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CommonUtils;
using Newtonsoft.Json;

namespace ADDump
{
    class Program
    {
        const string help = @"
    addump command [arg1 arg2 ...]
    command are not case sensetive.

    Valid commands:
        help                Show help
        UserDN              Show AD distinguished name for user
                            Optional Argument: domain\login
        Domains             Show available domains
        Catelogs            Show available catelogs
        TopUserDN           Walk hierarchy from current user to get top most user
        users               Show users
                            Optional Arguments: domainPath, maxCount
";

        static void Main(string[] args)
        {
            if (args.IsNullOrEmpty())
            {
                Console.Write(help);
                Console.WriteLine();
                Console.Write("Enter arguments: ");
                args = Console.ReadLine().Split();
            }

            var command = args.IsNullOrEmpty() ? "help" : args[0].ToLowerInvariant();
            IEnumerable<string> domainPaths;
            int maxCount = 0;
            switch (command)
            {
                case "help":
                    Console.Write(help);
                    break;
                case "userdn":
                    var userAlias = args.Length > 1 ? args[1] : null;
                    var currentUserDN = ActiveDirectoryHelper.GetUserDN(userAlias);
                    Console.WriteLine(currentUserDN);
                    break;
                case "topuserdn":
                    var topUserDN = ActiveDirectoryHelper.GetTopLevelUserDN();
                    Console.WriteLine(topUserDN);
                    break;
                case "domains":
                    foreach(var domain in ActiveDirectoryHelper.GetDomains())
                        Console.WriteLine("{0}\t{2}\t{2}".FormatEx(domain.Name, domain.ParentName, domain.Mode));
                    break;
                case "catelogs":
                    foreach (var catelog in ActiveDirectoryHelper.GetCatelogs())
                        Console.WriteLine("{0}\t{2}\t{2}".FormatEx(catelog.Name, catelog.SiteName, catelog.OSVersion));
                    break;
                case "users":
                    maxCount = args.Length > 1 ? int.Parse(args[1]) : 0;
                    var managerDN = args.Length > 2 ? ActiveDirectoryHelper.GetUserDN(args[2]) : null;
                    domainPaths = args.Length > 3 ? args.Slice(3) : null;
                    var users = ActiveDirectoryHelper.GetActiveDirectoryUsers(domainPaths, managerDN, maxCount);
                    foreach(var user in users)
                    {
                        var serializedUser = JsonConvert.SerializeObject(user);
                        Console.WriteLine(serializedUser);
                    }
                    break;
                case "groups":
                    maxCount = args.Length > 1 ? int.Parse(args[1]) : 0;
                    domainPaths = args.Length > 2 ? args.Slice(2) : null;
                    var groups = ActiveDirectoryHelper.GetActiveDirectoryGroups(domainPaths, maxCount);
                    foreach (var group in groups)
                    {
                        var serializedGroup = JsonConvert.SerializeObject(group);
                        Console.WriteLine(serializedGroup);
                    }
                    break;
                default:
                    Console.WriteLine("Command {0} is not recognized. Type help.".FormatEx(command));
                    break;
            }
        }
    }
}
