using System;
using System.Runtime.InteropServices;

namespace Pinvoke {
    public static class userenv{
	[DllImport("userenv.dll", SetLastError=true)]
	public static extern bool CreateEnvironmentBlock( 
		out IntPtr lpEnvironment, 
		IntPtr hToken, 
		bool bInherit 
		);
    }
}