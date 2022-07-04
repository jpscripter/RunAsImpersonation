# RunAsImpersonation
This module is a mix of credential tools that can help administrators work around the problems of permissions both locally and remotely. This is done by making\getting and using windows credential tokens to manipulate the credentials needed for authenticating.


#About Impersonation
1) If impersonation is set, any sub-processes take the original process token and not the impersonated token. I am writing the process creation cmdlet still.
1) Impersonation is at the thread level and other runspaces will need to be set separately. This is actually a feature because you can make a few threads connecting to different systems at the same time.
1) If you are using impersonation with Azure Automation's hybrid workers, do not impersonate the main thread as it can impact the the worker process and cause instability when sending stream data back to Azure. I recommend using a separate thread and passing back data with a synchronized hashtable. 
1) Once you are done using the impersonation token, you can just run the Set-Impersonation to revert back to the original process token.
1) Some thing like whoami.exe act weird with impersonation. I usually use the .net [System.Security.Principal.WindowsIdentity]::GetCurrent() to see what token I am using. 
1) If you are getting tokens from service accounts or other users on the system, you have to be system first. 
1) Impersonation does get you access to DPAPI keys. So you can impersonate system and decrypt machine variables from wmi.
