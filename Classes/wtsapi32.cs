using System;
using System.Runtime.InteropServices;

namespace Pinvoke {
    public static class wtsapi32 {
        [DllImport("wtsapi32.dll", SetLastError=true)]
        public static extern bool WTSQueryUserToken(
            uint sessionId,
            out IntPtr Token
        );
    }
}