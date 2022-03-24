using System;
using System.Runtime.InteropServices;

namespace Pinvoke {
    public enum ProcessPrivilege : int
    {
        SE_PRIVILEGE_ENABLED = 0x00000002,
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
        TOKEN_READ = (StandardRights.STANDARD_RIGHTS_READ | ProcessPrivilege.TOKEN_QUERY),
        TOKEN_ALL_ACCESS = (StandardRights.STANDARD_RIGHTS_REQUIRED | TokenRights.TOKEN_ASSIGN_PRIMARY |
          TokenRights.TOKEN_DUPLICATE | TokenRights.TOKEN_IMPERSONATE | ProcessPrivilege.TOKEN_QUERY | TokenRights.TOKEN_QUERY_SOURCE |
          ProcessPrivilege.TOKEN_ADJUST_PRIVILEGES | TokenRights.TOKEN_ADJUST_GROUPS | TokenRights.TOKEN_ADJUST_DEFAULT |
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

    public enum CreationFlags 
    {
      CREATE_SUSPENDED       = 0x00000004,
      CREATE_NEW_CONSOLE     = 0x00000010,
      CREATE_NEW_PROCESS_GROUP   = 0x00000200,
      CREATE_UNICODE_ENVIRONMENT = 0x00000400,
      CREATE_SEPARATE_WOW_VDM    = 0x00000800,
      CREATE_DEFAULT_ERROR_MODE  = 0x04000000,
    }

    public enum LogonFlags 
    {
      DEFAULT     = 0x00000000,
      LOGON_WITH_PROFILE     = 0x00000001,
      LOGON_NETCREDENTIALS_ONLY  = 0x00000002    
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

      [DllImport("advapi32.dll")]
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

      [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
      public static extern bool CreateProcessWithLogonW(
          String             userName,
          String             domain,
          String             password,
          LogonFlags         logonFlags,
          String             applicationName,
          String             commandLine,
          CreationFlags          creationFlags,
          UInt32             environment,
          String             currentDirectory,
          ref  StartupInfo       startupInfo,
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
    }
}
