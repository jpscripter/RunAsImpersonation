using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Diagnostics;
using Pinvoke;

namespace Pinvoke
{

    public static class Logic
    {
      public const uint SE_GROUP_LOGON_ID = 0xC0000000;
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
            si.flags = startInfoFlags;
            if (showUI)
            {
                si.showWindow = 5;
            }

            advapi32.CreateProcessWithTokenW(
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


        public static string GetLogonId(IntPtr token, TOKEN_INFORMATION_CLASS info)
        {
            uint TokenInfLength = 0;
            // first call gets length of TokenInformation
            bool Result = advapi32.GetTokenInformation(token, info, IntPtr.Zero, TokenInfLength, out TokenInfLength);
            IntPtr TokenInformation = Marshal.AllocHGlobal((int)TokenInfLength);
            Result = advapi32.GetTokenInformation(token, info, TokenInformation, TokenInfLength, out TokenInfLength);

            if (!Result)
            {
                Marshal.FreeHGlobal(TokenInformation);
                return string.Empty;
            }

            string retVal = string.Empty;
            TOKEN_GROUPS groups = (TOKEN_GROUPS)Marshal.PtrToStructure(TokenInformation, typeof(TOKEN_GROUPS));
            int sidAndAttrSize = Marshal.SizeOf(new SID_AND_ATTRIBUTES());
            for (int i = 0; i < groups.GroupCount; i++)
            {
                SID_AND_ATTRIBUTES sidAndAttributes = (SID_AND_ATTRIBUTES)Marshal.PtrToStructure(
                    new IntPtr(TokenInformation.ToInt64() + i * sidAndAttrSize + IntPtr.Size), typeof(SID_AND_ATTRIBUTES));
                if ((sidAndAttributes.Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID)
                {
                    IntPtr pstr = IntPtr.Zero;
                    advapi32.ConvertSidToStringSid(sidAndAttributes.Sid, out pstr);
                    retVal = Marshal.PtrToStringAuto(pstr);
                    kernel32.LocalFree(pstr);
                    break;
                }
            }

            Marshal.FreeHGlobal(TokenInformation);
            return retVal;
        }

        
    }
}
