using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace Pinvoke {

    public enum ProcessPrivilegeState : int
    {
        SE_PRIVILEGE_ENABLED = 0x00000002,
        SE_PRIVILEGE_REMOVED = 0x00000004
    }
    public enum TokenPrivilege : int
    {
        TOKEN_QUERY = 0x00000008,
        TOKEN_ADJUST_PRIVILEGES = 0x00000020
    }

    public enum StandardRights : uint
    {
        STANDARD_RIGHTS_REQUIRED = 0x000F0000,
        STANDARD_RIGHTS_READ = 0x00020000
    }

    public enum TokenRights : uint
    {
        TOKEN_ASSIGN_PRIMARY = 0x0001,
        TOKEN_DUPLICATE = 0x0002,
        TOKEN_IMPERSONATE = 0x0004,
        TOKEN_QUERY_SOURCE = 0x0010,
        TOKEN_ADJUST_GROUPS = 0x0040,
        TOKEN_ADJUST_DEFAULT = 0x0080,
        TOKEN_ADJUST_SESSIONID = 0x0100,
        TOKEN_READ = (StandardRights.STANDARD_RIGHTS_READ | TokenPrivilege.TOKEN_QUERY),
        TOKEN_ALL_ACCESS = (StandardRights.STANDARD_RIGHTS_REQUIRED | TokenRights.TOKEN_ASSIGN_PRIMARY |
          TokenRights.TOKEN_DUPLICATE | TokenRights.TOKEN_IMPERSONATE | TokenPrivilege.TOKEN_QUERY | TokenRights.TOKEN_QUERY_SOURCE |
          TokenPrivilege.TOKEN_ADJUST_PRIVILEGES | TokenRights.TOKEN_ADJUST_GROUPS | TokenRights.TOKEN_ADJUST_DEFAULT |
          TokenRights.TOKEN_ADJUST_SESSIONID)
    }

    public enum SePrivilegeRights 
    {
        SeTimeZonePrivilege
    }

    public enum SECURITY_IMPERSONATION_LEVEL {
        SecurityAnonymous,
        SecurityIdentification,
        SecurityImpersonation,
        SecurityDelegation
    }
    public enum Process_Privilege {
      SeAssignPrimaryTokenPrivilege,
      SeAuditPrivilege,
      SeBackupPrivilege,
      SeChangeNotifyPrivilege,
      SeCreateGlobalPrivilege,
      SeCreatePagefilePrivilege,
      SeCreatePermanentPrivilege,
      SeCreateSymbolicLinkPrivilege,
      SeCreateTokenPrivilege,
      SeDebugPrivilege,
      SeEnableDelegationPrivilege,
      SeImpersonatePrivilege,
      SeIncreaseBasePriorityPrivilege,
      SeIncreaseQuotaPrivilege,
      SeIncreaseWorkingSetPrivilege,
      SeLoadDriverPrivilege,
      SeLockMemoryPrivilege,
      SeMachineAccountPrivilege,
      SeManageVolumePrivilege,
      SeProfileSingleProcessPrivilege,
      SeRelabelPrivilege,
      SeRemoteShutdownPrivilege,
      SeRestorePrivilege,
      SeSecurityPrivilege,
      SeShutdownPrivilege,
      SeSyncAgentPrivilege,
      SeSystemEnvironmentPrivilege,
      SeSystemProfilePrivilege,
      SeSystemtimePrivilege,
      SeTakeOwnershipPrivilege,
      SeTcbPrivilege,
      SeTimeZonePrivilege,
      SeTrustedCredManAccessPrivilege,
      SeUndockPrivilege
    }

    public enum LSA_AccessPolicy : long
    {
      POLICY_VIEW_LOCAL_INFORMATION = 0x00000001L,
      POLICY_VIEW_AUDIT_INFORMATION = 0x00000002L,
      POLICY_GET_PRIVATE_INFORMATION = 0x00000004L,
      POLICY_TRUST_ADMIN = 0x00000008L,
      POLICY_CREATE_ACCOUNT = 0x00000010L,
      POLICY_CREATE_SECRET = 0x00000020L,
      POLICY_CREATE_PRIVILEGE = 0x00000040L,
      POLICY_SET_DEFAULT_QUOTA_LIMITS = 0x00000080L,
      POLICY_SET_AUDIT_REQUIREMENTS = 0x00000100L,
      POLICY_AUDIT_LOG_ADMIN = 0x00000200L,
      POLICY_SERVER_ADMIN = 0x00000400L,
      POLICY_LOOKUP_NAMES = 0x00000800L,
      POLICY_NOTIFICATION = 0x00001000L
    }

    public enum CreationFlags : int
    {
      CREATE_SUSPENDED       = 0x00000004,
      CREATE_NEW_CONSOLE     = 0x00000010,
      CREATE_NEW_PROCESS_GROUP   = 0x00000200,
      CREATE_UNICODE_ENVIRONMENT = 0x00000400,
      CREATE_SEPARATE_WOW_VDM    = 0x00000800,
      CREATE_DEFAULT_ERROR_MODE  = 0x04000000,
      CREATE_NO_WINDOW = 0x08000000,
      DETACHED_PROCESS = 0x00000008

    }

    public enum LogonFlags 
    {
      DEFAULT     = 0x00000000,
      LOGON_WITH_PROFILE     = 0x00000001,
      LOGON_NETCREDENTIALS_ONLY  = 0x00000002    
    }

    //https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa
    public enum StartInfoFlags :int
    {
      STARTF_USESHOWWINDOW     = 0x00000001,
      STARTF_FORCEONFEEDBACK     = 0x00000040,
      STARTF_RUNFULLSCREEN      = 0x00000020,
      STARTF_PREVENTPINNING     = 0x00002000
    }
    public enum TOKEN_TYPE 
    {
        TokenPrimary = 1,
        TokenImpersonation
    }

    public enum dwLogonType 
    {
      Interactive = 2,
      Network = 3,
      Batch = 4,
      Service = 5,
      Unlock = 7,
      NetworkClearText = 8,
      NewCredentials = 9,
    }
  
    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_UNICODE_STRING
    {
      public UInt16 Length;
      public UInt16 MaximumLength;
      public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_OBJECT_ATTRIBUTES
    {
      public int Length;
      public IntPtr RootDirectory;
      public LSA_UNICODE_STRING ObjectName;
      public uint Attributes;
      public IntPtr SecurityDescriptor;
      public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct TokPriv1Luid
    {
        public int Count;
        public long Luid;
        public int Attr;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public unsafe byte* lpSecurityDescriptor;
        public int bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Auto)]
    public struct StartupInfo
    {
        public int    cb;
        public String reserved;
        public String desktop;
        public String title;
        public int    x;
        public int    y;
        public int    xSize;
        public int    ySize;
        public int    xCountChars;
        public int    yCountChars;
        public int    fillAttribute;
        public int    flags;
        public UInt16 showWindow;
        public UInt16 reserved2;
        public byte   reserved3;
        public IntPtr stdInput;
        public IntPtr stdOutput;
        public IntPtr stdError;
    } 

    public struct ProcessInformation
    {
        public IntPtr process;
        public IntPtr thread;
        public int    processId;
        public int    threadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID
    {
      public UInt32 LowPart;
      public UInt32 HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID_AND_ATTRIBUTES {
        public LUID Luid;
        public UInt32 Attributes;
    }

    public struct TOKEN_PRIVILEGES {
      public UInt32 PrivilegeCount;
      [MarshalAs(UnmanagedType.ByValArray, SizeConst=1)]
      public LUID_AND_ATTRIBUTES [] Privileges;
    }


    public static class advapi32 {

      [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
      public static extern uint LsaRetrievePrivateData(
        IntPtr PolicyHandle,
        ref LSA_UNICODE_STRING KeyName,
        out IntPtr PrivateData
      );

      [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
      public static extern uint LsaStorePrivateData(
        IntPtr policyHandle,
        ref LSA_UNICODE_STRING KeyName,
        ref LSA_UNICODE_STRING PrivateData
      );

      [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
      public static extern uint LsaOpenPolicy(
        ref LSA_UNICODE_STRING SystemName,
        ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
        uint DesiredAccess,
        out IntPtr PolicyHandle
      );


      [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
      public static extern uint LsaNtStatusToWinError(
        uint status
      );

      [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
      public static extern uint LsaClose(
        IntPtr policyHandle
      );

      [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
      public static extern uint LsaFreeMemory(
        IntPtr buffer
      );

      [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
      public static extern bool AdjustTokenPrivileges(
          IntPtr TokenHandle, 
          bool disall,
          ref TokPriv1Luid newst,
          int len, 
          IntPtr prev, 
          IntPtr relen
      );
      
      [DllImport("advapi32.dll", SetLastError = true)]
      public extern static bool DuplicateToken(
          IntPtr ExistingTokenHandle, int
          SECURITY_IMPERSONATION_LEVEL,
          ref IntPtr DuplicateTokenHandle
      );

      [DllImport("advapi32.dll", CharSet=CharSet.Auto, SetLastError=true)]
      public extern static bool DuplicateTokenEx(
          IntPtr hExistingToken,
          uint dwDesiredAccess,
          ref SECURITY_ATTRIBUTES lpTokenAttributes,
          SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
          TOKEN_TYPE TokenType,
          out IntPtr phNewToken 
      );

      [DllImport("advapi32.dll")]
      [return: MarshalAs(UnmanagedType.Bool)]
      public static extern bool OpenProcessToken(
          IntPtr ProcessHandle, 
          UInt32 DesiredAccess, 
          out IntPtr TokenHandle
          );

      [DllImport("advapi32.dll", SetLastError=true)]
      [return: MarshalAs(UnmanagedType.Bool)]
      public static extern bool SetThreadToken(
          IntPtr PHThread,
          IntPtr Token
      );

      [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
      public static extern bool CreateProcessWithTokenW(
        IntPtr hToken,
        int dwLogonFlags,
        string lpApplicationName,
        string lpCommandLine,
        int dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        [In] ref StartupInfo lpStartupInfo,
        out ProcessInformation lpProcessInformation);

      [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
      public static extern bool CreateProcessWithLogonW(
          String             userName,
          String             domain,
          String             password,
          int                logonFlags,
          String             applicationName,
          String             commandLine,
          int                creationFlags,
          UInt32             environment,
          String             currentDirectory,
          ref  StartupInfo   startupInfo,
          out ProcessInformation     processInformation);

      [DllImport("advapi32.dll", SetLastError=true)]
      public static extern bool LogonUserEx(
          string lpszUsername,
          string lpszDomain,
          string lpszPassword,
          int dwLogonType,
          int dwLogonProvider,
          out IntPtr phToken,
          IntPtr ppLogonSid, // nullable
          IntPtr ppProfileBuffer, // nullable
          IntPtr pdwProfileLength, // nullable
          IntPtr pQuotaLimits // nullable
          );

      [DllImport("advapi32.dll", SetLastError=true)]  
      public static extern bool ImpersonateLoggedOnUser(
        IntPtr hToken
      );
      
      [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
		  public static extern int RevertToSelf();

      [DllImport("advapi32.dll", SetLastError = true)]
      public static extern bool LookupPrivilegeValue(
          string host, 
          string name, 
          ref long pluid
      );

      [DllImport("kernel32.dll", ExactSpelling = true)]
      public static extern IntPtr GetCurrentProcess();
    public static int LaunchProcessAsToken(string binary, string parameters, bool showUI, int logonFlags, int creationFlags, int startInfoFlags, string desktop, IntPtr token, IntPtr envBlock)
    {
      ProcessInformation pi = new ProcessInformation();
      SECURITY_ATTRIBUTES saProcess = new SECURITY_ATTRIBUTES();
      SECURITY_ATTRIBUTES saThread = new SECURITY_ATTRIBUTES();
      saProcess.nLength = (int)Marshal.SizeOf(saProcess);
      saThread.nLength = (int)Marshal.SizeOf(saThread);

      StartupInfo si = new StartupInfo();
      si.cb = (int)Marshal.SizeOf(si);

      si.desktop = desktop;
      si.flags = startInfoFlags ;
      if (showUI){
        si.showWindow = 5;
      }

      CreateProcessWithTokenW(
        token,
        logonFlags,
        binary,
        parameters,
        creationFlags,
        envBlock,
        null,
        ref si,
        out pi);

      return pi.processId;
    }

  }

}
