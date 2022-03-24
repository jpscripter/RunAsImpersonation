using System;
using System.Runtime.InteropServices;

namespace Pinvoke {
    public static class kernel32 {

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint WTSGetActiveConsoleSessionId();
    }
}