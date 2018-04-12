control "xccdf_org.cisecurity.benchmarks_rule_2.2.1_L1_Ensure_Access_Credential_Manager_as_a_trusted_caller_is_set_to_No_One" do
  title "(L1) Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'"
  desc  "
    This security setting is used by Credential Manager during Backup and Restore. No accounts should have this user right, as it is only assigned to Winlogon. Users' saved credentials might be compromised if this user right is assigned to other entities.
    
    The recommended state for this setting is: No One.
    
    Rationale: If an account is given this right the user of the account may create an application that calls into Credential Manager and is returned the credentials for another user.
  "
  impact 1.0
  (users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries).each do |entry|
    describe security_policy do
      its("SeTrustedCredManAccessPrivilege") { should_not include entry }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.2_L1_Configure_Access_this_computer_from_the_network" do
  title "(L1) Configure 'Access this computer from the network'"
  desc  "
    This policy setting allows other users on the network to connect to the computer and is required by various network protocols that include Server Message Block (SMB)based protocols, NetBIOS, Common Internet File System (CIFS), and Component Object Model Plus (COM+).
    
    * **Level 1 - Domain Controller.** The recommended state for this setting is: Administrators, Authenticated Users, ENTERPRISE DOMAIN CONTROLLERS.
    * **Level 1 - Member Server.** The recommended state for this setting is: Administrators, Authenticated Users.
    
    Rationale: Users who can connect from their computer to the network can access resources on target computers for which they have permission. For example, the Access this computer from the network user right is required for users to connect to shared printers and folders. If this user right is assigned to the Everyone group, then anyone in the group will be able to read the files in those shared folders. However, this situation is unlikely for new installations of Windows Server 2003 with Service Pack 1 (SP1), because the default share and NTFS permissions in Windows Server 2003 do not include the Everyone group. This vulnerability may have a higher level of risk for computers that you upgrade from Windows NT 4.0 or Windows 2000, because the default permissions for these operating systems are not as restrictive as the default permissions in Windows Server 2003.
  "
  impact 1.0
  a = (((((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - (users.where { username.casecmp('Administrators') == 0}.uids.entries + groups.where { name.casecmp('Administrators') == 0}.gids.entries)) & ((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - ['S-1-5-11']))) & ((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - ['S-1-5-9'])).uniq
  a.each do |entry|
    describe security_policy do
      its("SeNetworkLogonRight") { should_not include entry }
    end
  end
  a = (((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - (users.where { username.casecmp('Administrators') == 0}.uids.entries + groups.where { name.casecmp('Administrators') == 0}.gids.entries)) & ((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - ['S-1-5-11'])).uniq
  a.each do |entry|
    describe security_policy do
      its("SeNetworkLogonRight") { should_not include entry }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.3_L1_Ensure_Act_as_part_of_the_operating_system_is_set_to_No_One" do
  title "(L1) Ensure 'Act as part of the operating system' is set to 'No One'"
  desc  "
    This policy setting allows a process to assume the identity of any user and thus gain access to the resources that the user is authorized to access.
    
    The recommended state for this setting is: No One.
    
    Rationale: The Act as part of the operating system user right is extremely powerful. Anyone with this user right can take complete control of the computer and erase evidence of their activities.
  "
  impact 1.0
  (users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries).each do |entry|
    describe security_policy do
      its("SeTcbPrivilege") { should_not include entry }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.5_L1_Ensure_Adjust_memory_quotas_for_a_process_is_set_to_Administrators_LOCAL_SERVICE_NETWORK_SERVICE" do
  title "(L1) Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'"
  desc  "
    This policy setting allows a user to adjust the maximum amount of memory that is available to a process. The ability to adjust memory quotas is useful for system tuning, but it can be abused. In the wrong hands, it could be used to launch a denial of service (DoS) attack.
    
    The recommended state for this setting is: Administrators, LOCAL SERVICE, NETWORK SERVICE.
    
    **Note:** A Member Server that holds the **Web Server (IIS)** Role with **Web Server** Role Service will require a special exception to this recommendation, to allow IIS application pool(s) to be granted this user right.
    
    **Note #2:** A Member Server with Microsoft SQL Server installed will require a special exception to this recommendation for additional SQL-generated entries to be granted this user right.
    
    Rationale: A user with the Adjust memory quotas for a process privilege can reduce the amount of memory that is available to any process, which could cause business-critical network applications to become slow or to fail. In the wrong hands, this privilege could be used to start a denial of service (DoS) attack.
  "
  impact 1.0
  a = (((((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - (users.where { username.casecmp('Administrators') == 0}.uids.entries + groups.where { name.casecmp('Administrators') == 0}.gids.entries)) & ((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - ['S-1-5-19']))) & ((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - ['S-1-5-20'])).uniq
  a.each do |entry|
    describe security_policy do
      its("SeIncreaseQuotaPrivilege") { should_not include entry }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.6_L1_Configure_Allow_log_on_locally" do
  title "(L1) Configure 'Allow log on locally'"
  desc  "
    This policy setting determines which users can interactively log on to computers in your environment. Logons that are initiated by pressing the CTRL+ALT+DEL key sequence on the client computer keyboard require this user right. Users who attempt to log on through Terminal Services or IIS also require this user right.
    
    The Guest account is assigned this user right by default. Although this account is disabled by default, it is recommended that you enable this setting through Group Policy. However, this user right should generally be restricted to the Administrators and Users groups. Assign this user right to the Backup Operators group if your organization requires that they have this capability.
    
    * **Level 1 - Domain Controller.** The recommended state for this setting is: Administrators, ENTERPRISE DOMAIN CONTROLLERS.
    * **Level 1 - Member Server.** The recommended state for this setting is: Administrators.
    
    Rationale: Any account with the Allow log on locally user right can log on at the console of the computer. If you do not restrict this user right to legitimate users who need to be able to log on to the console of the computer, unauthorized users could download and run malicious software to elevate their privileges.
  "
  impact 1.0
  a = (users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - (users.where { username.casecmp('Administrators') == 0}.uids.entries + groups.where { name.casecmp('Administrators') == 0}.gids.entries).uniq
  a.each do |entry|
    describe security_policy do
      its("SeInteractiveLogonRight") { should_not include entry }
    end
  end
  a = (((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - (users.where { username.casecmp('Administrators') == 0}.uids.entries + groups.where { name.casecmp('Administrators') == 0}.gids.entries)) & ((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - ['S-1-5-9'])).uniq
  a.each do |entry|
    describe security_policy do
      its("SeInteractiveLogonRight") { should_not include entry }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.7_L1_Configure_Allow_log_on_through_Remote_Desktop_Services" do
  title "(L1) Configure 'Allow log on through Remote Desktop Services'"
  desc  "
    This policy setting determines which users or groups have the right to log on as a Terminal Services client. Remote desktop users require this user right. If your organization uses Remote Assistance as part of its help desk strategy, create a group and assign it this user right through Group Policy. If the help desk in your organization does not use Remote Assistance, assign this user right only to the Administrators group or use the restricted groups feature to ensure that no user accounts are part of the Remote Desktop Users group.
    
    Restrict this user right to the Administrators group, and possibly the Remote Desktop Users group, to prevent unwanted users from gaining access to computers on your network by means of the Remote Assistance feature.
    
    * **Level 1 - Domain Controller.** The recommended state for this setting is: Administrators.
    * **Level 1 - Member Server.** The recommended state for this setting is: Administrators, Remote Desktop Users.
    **Note:** A Member Server that holds the **Remote Desktop Services** Role with **Remote Desktop Connection Broker** Role Service will require a special exception to this recommendation, to allow the Authenticated Users group to be granted this user right.
    
    **Note #2:** The above lists are to be treated as whitelists, which implies that the above principals need not be present for assessment of this recommendation to pass.
    
    Rationale: Any account with the Allow log on through Terminal Services user right can log on to the remote console of the computer. If you do not restrict this user right to legitimate users who need to log on to the console of the computer, unauthorized users could download and run malicious software to elevate their privileges.
  "
  impact 1.0
  a = (((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - (users.where { username.casecmp('Administrators') == 0}.uids.entries + groups.where { name.casecmp('Administrators') == 0}.gids.entries)) & ((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - (users.where { username.casecmp('Remote Desktop Users') == 0}.uids.entries + groups.where { name.casecmp('Remote Desktop Users') == 0}.gids.entries))).uniq
  a.each do |entry|
    describe security_policy do
      its("SeRemoteInteractiveLogonRight") { should_not include entry }
    end
  end
  a = (users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - (users.where { username.casecmp('Administrators') == 0}.uids.entries + groups.where { name.casecmp('Administrators') == 0}.gids.entries).uniq
  a.each do |entry|
    describe security_policy do
      its("SeRemoteInteractiveLogonRight") { should_not include entry }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.8_L1_Ensure_Back_up_files_and_directories_is_set_to_Administrators" do
  title "(L1) Ensure 'Back up files and directories' is set to 'Administrators'"
  desc  "
    This policy setting allows users to circumvent file and directory permissions to back up the system. This user right is enabled only when an application (such as NTBACKUP) attempts to access a file or directory through the NTFS file system backup application programming interface (API). Otherwise, the assigned file and directory permissions apply.
    
    The recommended state for this setting is: Administrators.
    
    Rationale: Users who are able to back up data from a computer could take the backup media to a non-domain computer on which they have administrative privileges and restore the data. They could take ownership of the files and view any unencrypted data that is contained within the backup set.
  "
  impact 1.0
  a = (users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - (users.where { username.casecmp('Administrators') == 0}.uids.entries + groups.where { name.casecmp('Administrators') == 0}.gids.entries).uniq
  a.each do |entry|
    describe security_policy do
      its("SeBackupPrivilege") { should_not include entry }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.9_L1_Ensure_Change_the_system_time_is_set_to_Administrators_LOCAL_SERVICE" do
  title "(L1) Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'"
  desc  "
    This policy setting determines which users and groups can change the time and date on the internal clock of the computers in your environment. Users who are assigned this user right can affect the appearance of event logs. When a computer's time setting is changed, logged events reflect the new time, not the actual time that the events occurred.
    
    When configuring a user right in the SCM enter a comma delimited list of accounts. Accounts can be either local or located in Active Directory, they can be groups, users, or computers.
    
    **Note:** Discrepancies between the time on the local computer and on the domain controllers in your environment may cause problems for the Kerberos authentication protocol, which could make it impossible for users to log on to the domain or obtain authorization to access domain resources after they are logged on. Also, problems will occur when Group Policy is applied to client computers if the system time is not synchronized with the domain controllers.
    
    The recommended state for this setting is: Administrators, LOCAL SERVICE.
    
    Rationale: Users who can change the time on a computer could cause several problems. For example, time stamps on event log entries could be made inaccurate, time stamps on files and folders that are created or modified could be incorrect, and computers that belong to a domain may not be able to authenticate themselves or users who try to log on to the domain from them. Also, because the Kerberos authentication protocol requires that the requestor and authenticator have their clocks synchronized within an administrator-defined skew period, an attacker who changes a computer's time may cause that computer to be unable to obtain or grant Kerberos tickets. The risk from these types of events is mitigated on most domain controllers, member servers, and end-user computers because the Windows Time service automatically synchronizes time with domain controllers in the following ways: &#x2022; All client desktop computers and member servers use the authenticating domain controller as their inbound time partner. &#x2022; All domain controllers in a domain nominate the primary domain controller (PDC) emulator operations master as their inbound time partner. &#x2022; All PDC emulator operations masters follow the hierarchy of domains in the selection of their inbound time partner. &#x2022; The PDC emulator operations master at the root of the domain is authoritative for the organization. Therefore it is recommended that you configure this computer to synchronize with a reliable external time server. This vulnerability becomes much more serious if an attacker is able to change the system time and then stop the Windows Time service or reconfigure it to synchronize with a time server that is not accurate.
  "
  impact 1.0
  a = (((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - (users.where { username.casecmp('Administrators') == 0}.uids.entries + groups.where { name.casecmp('Administrators') == 0}.gids.entries)) & ((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - ['S-1-5-19'])).uniq
  a.each do |entry|
    describe security_policy do
      its("SeSystemtimePrivilege") { should_not include entry }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.10_L1_Ensure_Change_the_time_zone_is_set_to_Administrators_LOCAL_SERVICE" do
  title "(L1) Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE'"
  desc  "
    This setting determines which users can change the time zone of the computer. This ability holds no great danger for the computer and may be useful for mobile workers.
    
    The recommended state for this setting is: Administrators, LOCAL SERVICE.
    
    Rationale: Changing the time zone represents little vulnerability because the system time is not affected. This setting merely enables users to display their preferred time zone while being synchronized with domain controllers in different time zones.
  "
  impact 1.0
  a = (((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - (users.where { username.casecmp('Administrators') == 0}.uids.entries + groups.where { name.casecmp('Administrators') == 0}.gids.entries)) & ((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - ['S-1-5-19'])).uniq
  a.each do |entry|
    describe security_policy do
      its("SeTimeZonePrivilege") { should_not include entry }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.11_L1_Ensure_Create_a_pagefile_is_set_to_Administrators" do
  title "(L1) Ensure 'Create a pagefile' is set to 'Administrators'"
  desc  "
    This policy setting allows users to change the size of the pagefile. By making the pagefile extremely large or extremely small, an attacker could easily affect the performance of a compromised computer.
    
    The recommended state for this setting is: Administrators.
    
    Rationale: Users who can change the page file size could make it extremely small or move the file to a highly fragmented storage volume, which could cause reduced computer performance.
  "
  impact 1.0
  a = (users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - (users.where { username.casecmp('Administrators') == 0}.uids.entries + groups.where { name.casecmp('Administrators') == 0}.gids.entries).uniq
  a.each do |entry|
    describe security_policy do
      its("SeCreatePagefilePrivilege") { should_not include entry }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.12_L1_Ensure_Create_a_token_object_is_set_to_No_One" do
  title "(L1) Ensure 'Create a token object' is set to 'No One'"
  desc  "
    This policy setting allows a process to create an access token, which may provide elevated rights to access sensitive data.
    
    The recommended state for this setting is: No One.
    
    Rationale: A user account that is given this user right has complete control over the system and can lead to the system being compromised. It is highly recommended that you do not assign any user accounts this right.
    
    The operating system examines a user's access token to determine the level of the user's privileges. Access tokens are built when users log on to the local computer or connect to a remote computer over a network. When you revoke a privilege, the change is immediately recorded, but the change is not reflected in the user's access token until the next time the user logs on or connects. Users with the ability to create or modify tokens can change the level of access for any currently logged on account. They could escalate their own privileges or create a DoS condition.
  "
  impact 1.0
  (users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries).each do |entry|
    describe security_policy do
      its("SeCreateTokenPrivilege") { should_not include entry }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.13_L1_Ensure_Create_global_objects_is_set_to_Administrators_LOCAL_SERVICE_NETWORK_SERVICE_SERVICE" do
  title "(L1) Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'"
  desc  "
    This policy setting determines whether users can create global objects that are available to all sessions. Users can still create objects that are specific to their own session if they do not have this user right.
    
    Users who can create global objects could affect processes that run under other users' sessions. This capability could lead to a variety of problems, such as application failure or data corruption.
    
    The recommended state for this setting is: Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE.
    
    Rationale: Users who can create global objects could affect Windows services and processes that run under other user or system accounts. This capability could lead to a variety of problems, such as application failure, data corruption and elevation of privilege.
  "
  impact 1.0
  a = (((((((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - (users.where { username.casecmp('Administrators') == 0}.uids.entries + groups.where { name.casecmp('Administrators') == 0}.gids.entries)) & ((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - ['S-1-5-19']))) & ((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - ['S-1-5-20']))) & ((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - ['S-1-5-6'])).uniq
  a.each do |entry|
    describe security_policy do
      its("SeCreateGlobalPrivilege") { should_not include entry }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.14_L1_Ensure_Create_permanent_shared_objects_is_set_to_No_One" do
  title "(L1) Ensure 'Create permanent shared objects' is set to 'No One'"
  desc  "
    This user right is useful to kernel-mode components that extend the object namespace. However, components that run in kernel mode have this user right inherently. Therefore, it is typically not necessary to specifically assign this user right.
    
    The recommended state for this setting is: No One.
    
    Rationale: Users who have the Create permanent shared objects user right could create new shared objects and expose sensitive data to the network.
  "
  impact 1.0
  (users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries).each do |entry|
    describe security_policy do
      its("SeCreatePermanentPrivilege") { should_not include entry }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.15_L1_Configure_Create_symbolic_links" do
  title "(L1) Configure 'Create symbolic links'"
  desc  "
    This policy setting determines which users can create symbolic links. In Windows Vista, existing NTFS file system objects, such as files and folders, can be accessed by referring to a new kind of file system object called a symbolic link. A symbolic link is a pointer (much like a shortcut or .lnk file) to another file system object, which can be a file, folder, shortcut or another symbolic link. The difference between a shortcut and a symbolic link is that a shortcut only works from within the Windows shell. To other programs and applications, shortcuts are just another file, whereas with symbolic links, the concept of a shortcut is implemented as a feature of the NTFS file system.
    
    Symbolic links can potentially expose security vulnerabilities in applications that are not designed to use them. For this reason, the privilege for creating symbolic links should only be assigned to trusted users. By default, only Administrators can create symbolic links.
    
    * **Level 1 - Domain Controller.** The recommended state for this setting is: Administrators.
    * **Level 1 - Member Server.** The recommended state for this setting is: Administrators and (when the **Hyper-V** Role is installed) NT VIRTUAL MACHINE\\Virtual Machines.
    
    Rationale: Users who have the Create Symbolic Links user right could inadvertently or maliciously expose your system to symbolic link attacks. Symbolic link attacks can be used to change the permissions on a file, to corrupt data, to destroy data, or as a Denial of Service attack.
  "
  impact 1.0
  a = (users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - (users.where { username.casecmp('Administrators') == 0}.uids.entries + groups.where { name.casecmp('Administrators') == 0}.gids.entries).uniq
  a.each do |entry|
    describe security_policy do
      its("SeCreateSymbolicLinkPrivilege") { should_not include entry }
    end
  end
  a = (((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - (users.where { username.casecmp('Administrators') == 0}.uids.entries + groups.where { name.casecmp('Administrators') == 0}.gids.entries)) & ((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - (users.where { username.casecmp('NT VIRTUAL MACHINE\Virtual Machines') == 0}.uids.entries + groups.where { name.casecmp('NT VIRTUAL MACHINE\Virtual Machines') == 0}.gids.entries))).uniq
  a.each do |entry|
    describe security_policy do
      its("SeCreateSymbolicLinkPrivilege") { should_not include entry }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.16_L1_Ensure_Debug_programs_is_set_to_Administrators" do
  title "(L1) Ensure 'Debug programs' is set to 'Administrators'"
  desc  "
    This policy setting determines which user accounts will have the right to attach a debugger to any process or to the kernel, which provides complete access to sensitive and critical operating system components. Developers who are debugging their own applications do not need to be assigned this user right; however, developers who are debugging new system components will need it.
    
    The recommended state for this setting is: Administrators.
    
    Rationale: The Debug programs user right can be exploited to capture sensitive computer information from system memory, or to access and modify kernel or application structures. Some attack tools exploit this user right to extract hashed passwords and other private security information, or to insert rootkit code. By default, the Debug programs user right is assigned only to administrators, which helps to mitigate the risk from this vulnerability.
  "
  impact 1.0
  a = (users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - (users.where { username.casecmp('Administrators') == 0}.uids.entries + groups.where { name.casecmp('Administrators') == 0}.gids.entries).uniq
  a.each do |entry|
    describe security_policy do
      its("SeDebugPrivilege") { should_not include entry }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.17_L1_Configure_Deny_access_to_this_computer_from_the_network" do
  title "(L1) Configure 'Deny access to this computer from the network'"
  desc  "
    This policy setting prohibits users from connecting to a computer from across the network, which would allow users to access and potentially modify data remotely. In high security environments, there should be no need for remote users to access data on a computer. Instead, file sharing should be accomplished through the use of network servers.
    
    * **Level 1 - Domain Controller.** The recommended state for this setting is to include: Guests, Local account.
    * **Level 1 - Member Server.** The recommended state for this setting is to include: Guests, Local account and member of Administrators group.
    **Caution:** Configuring a standalone (non-domain-joined) server as described above may result in an inability to remotely administer the server.
    
    **Note:** Configuring a member server or standalone server as described above may adversely affect applications that create a local service account and place it in the Administrators group - in which case you must either convert the application to use a domain-hosted service account, or remove Local account and member of Administrators group from this User Right Assignment. Using a domain-hosted service account is strongly preferred over making an exception to this rule, where possible.
    
    Rationale: Users who can log on to the computer over the network can enumerate lists of account names, group names, and shared resources. Users with permission to access shared folders and files can connect over the network and possibly view or modify data.
  "
  impact 1.0
  a = (((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - (users.where { username.casecmp('Guests') == 0}.uids.entries + groups.where { name.casecmp('Guests') == 0}.gids.entries)) & ((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - (users.where { username =~ /^([Nn][Tt]\s[Aa][Uu][Tt][Hh][Oo][Rr][Ii][Tt][Yy]\\)?Local account and member of Administrators group$/}.uids.entries + groups.where { name =~ /^([Nn][Tt]\s[Aa][Uu][Tt][Hh][Oo][Rr][Ii][Tt][Yy]\\)?Local account and member of Administrators group$/}.gids.entries))).uniq
  a.each do |entry|
    describe security_policy do
      its("SeDenyNetworkLogonRight") { should_not include entry }
    end
  end
  a = (((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - (users.where { username.casecmp('Guests') == 0}.uids.entries + groups.where { name.casecmp('Guests') == 0}.gids.entries)) & ((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - (users.where { username =~ /^([Nn][Tt]\s[Aa][Uu][Tt][Hh][Oo][Rr][Ii][Tt][Yy]\\)?Local account$/}.uids.entries + groups.where { name =~ /^([Nn][Tt]\s[Aa][Uu][Tt][Hh][Oo][Rr][Ii][Tt][Yy]\\)?Local account$/}.gids.entries))).uniq
  a.each do |entry|
    describe security_policy do
      its("SeDenyNetworkLogonRight") { should_not include entry }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.18_L1_Ensure_Deny_log_on_as_a_batch_job_to_include_Guests" do
  title "(L1) Ensure 'Deny log on as a batch job' to include 'Guests'"
  desc  "
    This policy setting determines which accounts will not be able to log on to the computer as a batch job. A batch job is not a batch (.bat) file, but rather a batch-queue facility. Accounts that use the Task Scheduler to schedule jobs need this user right.
    
    The **Deny log on as a batch job** user right overrides the **Log on as a batch job** user right, which could be used to allow accounts to schedule jobs that consume excessive system resources. Such an occurrence could cause a DoS condition. Failure to assign this user right to the recommended accounts can be a security risk.
    
    The recommended state for this setting is to include: Guests.
    
    Rationale: Accounts that have the Deny log on as a batch job user right could be used to schedule jobs that could consume excessive computer resources and cause a DoS condition.
  "
  impact 1.0
  a = ((users.where { username.casecmp('Guests') == 0}.uids.entries + groups.where { name.casecmp('Guests') == 0}.gids.entries)).uniq
  a.each do |entry|
    describe security_policy do
      its("SeDenyServiceLogonRight") { should include entry }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.19_L1_Ensure_Deny_log_on_as_a_service_to_include_Guests" do
  title "(L1) Ensure 'Deny log on as a service' to include 'Guests'"
  desc  "
    This security setting determines which service accounts are prevented from registering a process as a service. This policy setting supersedes the **Log on as a service** policy setting if an account is subject to both policies.
    
    The recommended state for this setting is to include: Guests.
    
    **Note:** This security setting does not apply to the System, Local Service, or Network Service accounts.
    
    Rationale: Accounts that can log on as a service could be used to configure and start new unauthorized services, such as a keylogger or other malicious software. The benefit of the specified countermeasure is somewhat reduced by the fact that only users with administrative privileges can install and configure services, and an attacker who has already attained that level of access could configure the service to run with the System account.
  "
  impact 1.0
  a = ((users.where { username.casecmp('Guests') == 0}.uids.entries + groups.where { name.casecmp('Guests') == 0}.gids.entries)).uniq
  a.each do |entry|
    describe security_policy do
      its("SeDenyInteractiveLogonRight") { should include entry }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.20_L1_Ensure_Deny_log_on_locally_to_include_Guests" do
  title "(L1) Ensure 'Deny log on locally' to include 'Guests'"
  desc  "
    This security setting determines which users are prevented from logging on at the computer. This policy setting supersedes the **Allow log on locally** policy setting if an account is subject to both policies.
    
    **Important:** If you apply this security policy to the Everyone group, no one will be able to log on locally.
    
    The recommended state for this setting is to include: Guests.
    
    Rationale: Any account with the ability to log on locally could be used to log on at the console of the computer. If this user right is not restricted to legitimate users who need to log on to the console of the computer, unauthorized users might download and run malicious software that elevates their privileges.
  "
  impact 1.0
  a = ((users.where { username.casecmp('Guests') == 0}.uids.entries + groups.where { name.casecmp('Guests') == 0}.gids.entries) + (users.where { username =~ /^([Nn][Tt]\s[Aa][Uu][Tt][Hh][Oo][Rr][Ii][Tt][Yy]\\)?Local account$/}.uids.entries + groups.where { name =~ /^([Nn][Tt]\s[Aa][Uu][Tt][Hh][Oo][Rr][Ii][Tt][Yy]\\)?Local account$/}.gids.entries)).uniq
  a.each do |entry|
    describe security_policy do
      its("SeDenyRemoteInteractiveLogonRight") { should include entry }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.21_L1_Ensure_Deny_log_on_through_Remote_Desktop_Services_to_include_Guests_Local_account" do
  title "(L1) Ensure 'Deny log on through Remote Desktop Services' to include 'Guests, Local account'"
  desc  "
    This policy setting determines whether users can log on as Terminal Services clients. After the baseline member server is joined to a domain environment, there is no need to use local accounts to access the server from the network. Domain accounts can access the server for administration and end-user processing.
    
    The recommended state for this setting is to include: Guests, Local account.
    
    **Caution:** Configuring a standalone (non-domain-joined) server as described above may result in an inability to remotely administer the server.
    
    Rationale: Any account with the right to log on through Terminal Services could be used to log on to the remote console of the computer. If this user right is not restricted to legitimate users who need to log on to the console of the computer, unauthorized users might download and run malicious software that elevates their privileges.
  "
  impact 1.0
  a = ((users.where { username.casecmp('Guests') == 0}.uids.entries + groups.where { name.casecmp('Guests') == 0}.gids.entries) + (users.where { username =~ /^([Nn][Tt]\s[Aa][Uu][Tt][Hh][Oo][Rr][Ii][Tt][Yy]\\)?Local account$/}.uids.entries + groups.where { name =~ /^([Nn][Tt]\s[Aa][Uu][Tt][Hh][Oo][Rr][Ii][Tt][Yy]\\)?Local account$/}.gids.entries)).uniq
  a.each do |entry|
    describe security_policy do
      its("SeDenyRemoteInteractiveLogonRight") { should include entry }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.22_L1_Configure_Enable_computer_and_user_accounts_to_be_trusted_for_delegation" do
  title "(L1) Configure 'Enable computer and user accounts to be trusted for delegation'"
  desc  "
    This policy setting allows users to change the Trusted for Delegation setting on a computer object in Active Directory. Abuse of this privilege could allow unauthorized users to impersonate other users on the network.
    
    * **Level 1 - Domain Controller.** The recommended state for this setting is: Administrators.
    
    * **Level 1 - Member Server.** The recommended state for this setting is: No One.
    
    Rationale: Misuse of the Enable computer and user accounts to be trusted for delegation user right could allow unauthorized users to impersonate other users on the network. An attacker could exploit this privilege to gain access to network resources and make it difficult to determine what has happened after a security incident.
  "
  impact 1.0
  (users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries).each do |entry|
    describe security_policy do
      its("SeEnableDelegationPrivilege") { should_not include entry }
    end
  end
  a = (users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - (users.where { username.casecmp('Administrators') == 0}.uids.entries + groups.where { name.casecmp('Administrators') == 0}.gids.entries).uniq
  a.each do |entry|
    describe security_policy do
      its("SeEnableDelegationPrivilege") { should_not include entry }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.23_L1_Ensure_Force_shutdown_from_a_remote_system_is_set_to_Administrators" do
  title "(L1) Ensure 'Force shutdown from a remote system' is set to 'Administrators'"
  desc  "
    This policy setting allows users to shut down Windows Vista-based computers from remote locations on the network. Anyone who has been assigned this user right can cause a denial of service (DoS) condition, which would make the computer unavailable to service user requests. Therefore, it is recommended that only highly trusted administrators be assigned this user right.
    
    The recommended state for this setting is: Administrators.
    
    Rationale: Any user who can shut down a computer could cause a DoS condition to occur. Therefore, this user right should be tightly restricted.
  "
  impact 1.0
  a = (users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - (users.where { username.casecmp('Administrators') == 0}.uids.entries + groups.where { name.casecmp('Administrators') == 0}.gids.entries).uniq
  a.each do |entry|
    describe security_policy do
      its("SeRemoteShutdownPrivilege") { should_not include entry }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.24_L1_Ensure_Generate_security_audits_is_set_to_LOCAL_SERVICE_NETWORK_SERVICE" do
  title "(L1) Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'"
  desc  "
    This policy setting determines which users or processes can generate audit records in the Security log.
    
    The recommended state for this setting is: LOCAL SERVICE, NETWORK SERVICE.
    
    **Note:** A Member Server that holds the **Web Server (IIS)** Role with **Web Server** Role Service will require a special exception to this recommendation, to allow IIS application pool(s) to be granted this user right.
    
    **Note #2:** A Member Server that holds the **Active Directory Federation Services** Role will require a special exception to this recommendation, to allow the NT SERVICE\\ADFSSrv and NT SERVICE\\DRSservices, as well as the associated Active Directory Federation Services service account, to be granted this user right.
    
    Rationale: An attacker could use this capability to create a large number of audited events, which would make it more difficult for a system administrator to locate any illicit activity. Also, if the event log is configured to overwrite events as needed, any evidence of unauthorized activities could be overwritten by a large number of unrelated events.
  "
  impact 1.0
  a = (((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - ['S-1-5-19']) & ((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - ['S-1-5-20'])).uniq
  a.each do |entry|
    describe security_policy do
      its("SeAuditPrivilege") { should_not include entry }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.25_L1_Configure_Impersonate_a_client_after_authentication" do
  title "(L1) Configure 'Impersonate a client after authentication'"
  desc  "
    The policy setting allows programs that run on behalf of a user to impersonate that user (or another specified account) so that they can act on behalf of the user. If this user right is required for this kind of impersonation, an unauthorized user will not be able to convince a client to connect&#x2014;for example, by remote procedure call (RPC) or named pipes&#x2014;to a service that they have created to impersonate that client, which could elevate the unauthorized user's permissions to administrative or system levels.
    
    Services that are started by the Service Control Manager have the built-in Service group added by default to their access tokens. COM servers that are started by the COM infrastructure and configured to run under a specific account also have the Service group added to their access tokens. As a result, these processes are assigned this user right when they are started.
    
    Also, a user can impersonate an access token if any of the following conditions exist: - The access token that is being impersonated is for this user. - The user, in this logon session, logged on to the network with explicit credentials to create the access token. - The requested level is less than Impersonate, such as Anonymous or Identify.
    
    An attacker with the Impersonate a client after authentication user right could create a service, trick a client to make them connect to the service, and then impersonate that client to elevate the attacker's level of access to that of the client.
    
    * **Level 1 - Domain Controller.** The recommended state for this setting is: Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE.
    * **Level 1 - Member Server.** The recommended state for this setting is: Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE and (when the **Web Server (IIS)** Role with **Web Services** Role Service is installed) IIS_IUSRS.
    **Note:** A Member Server with Microsoft SQL Server installed will require a special exception to this recommendation for additional SQL-generated entries to be granted this user right.
    
    Rationale: An attacker with the Impersonate a client after authentication user right could create a service, trick a client to make them connect to the service, and then impersonate that client to elevate the attacker's level of access to that of the client.
  "
  impact 1.0
  a = (((((((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - (users.where { username.casecmp('Administrators') == 0}.uids.entries + groups.where { name.casecmp('Administrators') == 0}.gids.entries)) & ((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - ['S-1-5-19']))) & ((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - ['S-1-5-20']))) & ((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - ['S-1-5-6'])).uniq
  a.each do |entry|
    describe security_policy do
      its("SeImpersonatePrivilege") { should_not include entry }
    end
  end
  a = (((((((((((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - (users.where { username.casecmp('Administrators') == 0}.uids.entries + groups.where { name.casecmp('Administrators') == 0}.gids.entries)) & ((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - ['S-1-5-19']))) & ((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - ['S-1-5-20']))) & ((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - ['S-1-5-6']))) & ((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - (users.where { username.casecmp('IIS_IUSERS') == 0}.uids.entries + groups.where { name.casecmp('IIS_IUSERS') == 0}.gids.entries)))) & ((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - (users.where { username.casecmp('BUILTIN\IIS_IUSRS') == 0}.uids.entries + groups.where { name.casecmp('BUILTIN\IIS_IUSRS') == 0}.gids.entries))).uniq
  a.each do |entry|
    describe security_policy do
      its("SeImpersonatePrivilege") { should_not include entry }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.26_L1_Ensure_Increase_scheduling_priority_is_set_to_Administrators" do
  title "(L1) Ensure 'Increase scheduling priority' is set to 'Administrators'"
  desc  "
    This policy setting determines whether users can increase the base priority class of a process. (It is not a privileged operation to increase relative priority within a priority class.) This user right is not required by administrative tools that are supplied with the operating system but might be required by software development tools.
    
    The recommended state for this setting is: Administrators.
    
    Rationale: A user who is assigned this user right could increase the scheduling priority of a process to Real-Time, which would leave little processing time for all other processes and could lead to a DoS condition.
  "
  impact 1.0
  a = (users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - (users.where { username.casecmp('Administrators') == 0}.uids.entries + groups.where { name.casecmp('Administrators') == 0}.gids.entries).uniq
  a.each do |entry|
    describe security_policy do
      its("SeIncreaseBasePriorityPrivilege") { should_not include entry }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.27_L1_Ensure_Load_and_unload_device_drivers_is_set_to_Administrators" do
  title "(L1) Ensure 'Load and unload device drivers' is set to 'Administrators'"
  desc  "
    This policy setting allows users to dynamically load a new device driver on a system. An attacker could potentially use this capability to install malicious code that appears to be a device driver. This user right is required for users to add local printers or printer drivers in Windows Vista.
    
    The recommended state for this setting is: Administrators.
    
    Rationale: Device drivers run as highly privileged code. A user who has the Load and unload device drivers user right could unintentionally install malicious code that masquerades as a device driver. Administrators should exercise greater care and install only drivers with verified digital signatures.
  "
  impact 1.0
  a = (users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - (users.where { username.casecmp('Administrators') == 0}.uids.entries + groups.where { name.casecmp('Administrators') == 0}.gids.entries).uniq
  a.each do |entry|
    describe security_policy do
      its("SeLoadDriverPrivilege") { should_not include entry }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.28_L1_Ensure_Lock_pages_in_memory_is_set_to_No_One" do
  title "(L1) Ensure 'Lock pages in memory' is set to 'No One'"
  desc  "
    This policy setting allows a process to keep data in physical memory, which prevents the system from paging the data to virtual memory on disk. If this user right is assigned, significant degradation of system performance can occur.
    
    The recommended state for this setting is: No One.
    
    Rationale: Users with the Lock pages in memory user right could assign physical memory to several processes, which could leave little or no RAM for other processes and result in a DoS condition.
  "
  impact 1.0
  (users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries).each do |entry|
    describe security_policy do
      its("SeLockMemoryPrivilege") { should_not include entry }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.30_L1_Configure_Manage_auditing_and_security_log" do
  title "(L1) Configure 'Manage auditing and security log'"
  desc  "
    This policy setting determines which users can change the auditing options for files and directories and clear the Security log.
    
    For environments running Microsoft Exchange Server, the Exchange Servers group must possess this privilege on Domain Controllers to properly function. Given this, DCs granting the Exchange Servers group this privilege do conform with this benchmark. If the environment does not use Microsoft Exchange Server, then this privilege should be limited to only Administrators on DCs.
    
    * **Level 1 - Domain Controller.** The recommended state for this setting is: Administrators and (when Exchange is running in the environment) Exchange Servers.
    * **Level 1 - Member Server.** The recommended state for this setting is: Administrators.
    
    Rationale: The ability to manage the Security event log is a powerful user right and it should be closely guarded. Anyone with this user right can clear the Security log to erase important evidence of unauthorized activity.
  "
  impact 1.0
  a = (users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - (users.where { username.casecmp('Administrators') == 0}.uids.entries + groups.where { name.casecmp('Administrators') == 0}.gids.entries).uniq
  a.each do |entry|
    describe security_policy do
      its("SeSecurityPrivilege") { should_not include entry }
    end
  end
  a = (((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - (users.where { username.casecmp('Administrators') == 0}.uids.entries + groups.where { name.casecmp('Administrators') == 0}.gids.entries)) & ((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - (users.where { username.casecmp('Exchange Servers') == 0}.uids.entries + groups.where { name.casecmp('Exchange Servers') == 0}.gids.entries))).uniq
  a.each do |entry|
    describe security_policy do
      its("SeSecurityPrivilege") { should_not include entry }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.31_L1_Ensure_Modify_an_object_label_is_set_to_No_One" do
  title "(L1) Ensure 'Modify an object label' is set to 'No One'"
  desc  "
    This privilege determines which user accounts can modify the integrity label of objects, such as files, registry keys, or processes owned by other users. Processes running under a user account can modify the label of an object owned by that user to a lower level without this privilege.
    
    The recommended state for this setting is: No One.
    
    Rationale: By modifying the integrity label of an object owned by another user a malicious user may cause them to execute code at a higher level of privilege than intended.
  "
  impact 1.0
  (users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries).each do |entry|
    describe security_policy do
      its("SeRelabelPrivilege") { should_not include entry }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.32_L1_Ensure_Modify_firmware_environment_values_is_set_to_Administrators" do
  title "(L1) Ensure 'Modify firmware environment values' is set to 'Administrators'"
  desc  "
    This policy setting allows users to configure the system-wide environment variables that affect hardware configuration. This information is typically stored in the Last Known Good Configuration. Modification of these values and could lead to a hardware failure that would result in a denial of service condition.
    
    The recommended state for this setting is: Administrators.
    
    Rationale: Anyone who is assigned the Modify firmware environment values user right could configure the settings of a hardware component to cause it to fail, which could lead to data corruption or a DoS condition.
  "
  impact 1.0
  a = (users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - (users.where { username.casecmp('Administrators') == 0}.uids.entries + groups.where { name.casecmp('Administrators') == 0}.gids.entries).uniq
  a.each do |entry|
    describe security_policy do
      its("SeSystemEnvironmentPrivilege") { should_not include entry }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.33_L1_Ensure_Perform_volume_maintenance_tasks_is_set_to_Administrators" do
  title "(L1) Ensure 'Perform volume maintenance tasks' is set to 'Administrators'"
  desc  "
    This policy setting allows users to manage the system's volume or disk configuration, which could allow a user to delete a volume and cause data loss as well as a denial-of-service condition.
    
    The recommended state for this setting is: Administrators.
    
    Rationale: A user who is assigned the Perform volume maintenance tasks user right could delete a volume, which could result in the loss of data or a DoS condition.
  "
  impact 1.0
  a = (users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - (users.where { username.casecmp('Administrators') == 0}.uids.entries + groups.where { name.casecmp('Administrators') == 0}.gids.entries).uniq
  a.each do |entry|
    describe security_policy do
      its("SeManageVolumePrivilege") { should_not include entry }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.34_L1_Ensure_Profile_single_process_is_set_to_Administrators" do
  title "(L1) Ensure 'Profile single process' is set to 'Administrators'"
  desc  "
    This policy setting determines which users can use tools to monitor the performance of non-system processes. Typically, you do not need to configure this user right to use the Microsoft Management Console (MMC) Performance snap-in. However, you do need this user right if System Monitor is configured to collect data using Windows Management Instrumentation (WMI). Restricting the Profile single process user right prevents intruders from gaining additional information that could be used to mount an attack on the system.
    
    The recommended state for this setting is: Administrators.
    
    Rationale: The Profile single process user right presents a moderate vulnerability. An attacker with this user right could monitor a computer's performance to help identify critical processes that they might wish to attack directly. The attacker may also be able to determine what processes run on the computer so that they could identify countermeasures that they may need to avoid, such as antivirus software, an intrusion-detection system, or which other users are logged on to a computer.
  "
  impact 1.0
  a = (users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - (users.where { username.casecmp('Administrators') == 0}.uids.entries + groups.where { name.casecmp('Administrators') == 0}.gids.entries).uniq
  a.each do |entry|
    describe security_policy do
      its("SeProfileSingleProcessPrivilege") { should_not include entry }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.35_L1_Ensure_Profile_system_performance_is_set_to_Administrators_NT_SERVICEWdiServiceHost" do
  title "(L1) Ensure 'Profile system performance' is set to 'Administrators, NT SERVICE\\WdiServiceHost'"
  desc  "
    This policy setting allows users to use tools to view the performance of different system processes, which could be abused to allow attackers to determine a system's active processes and provide insight into the potential attack surface of the computer.
    
    The recommended state for this setting is: Administrators, NT SERVICE\\WdiServiceHost.
    
    Rationale: The Profile system performance user right poses a moderate vulnerability. Attackers with this user right could monitor a computer's performance to help identify critical processes that they might wish to attack directly. Attackers may also be able to determine what processes are active on the computer so that they could identify countermeasures that they may need to avoid, such as antivirus software or an intrusion detection system.
  "
  impact 1.0
  a = (((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - (users.where { username.casecmp('Administrators') == 0}.uids.entries + groups.where { name.casecmp('Administrators') == 0}.gids.entries)) & ((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - (users.where { username.casecmp('NT SERVICE\WdiServiceHost') == 0}.uids.entries + groups.where { name.casecmp('NT SERVICE\WdiServiceHost') == 0}.gids.entries))).uniq
  a.each do |entry|
    describe security_policy do
      its("SeSystemProfilePrivilege") { should_not include entry }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.36_L1_Ensure_Replace_a_process_level_token_is_set_to_LOCAL_SERVICE_NETWORK_SERVICE" do
  title "(L1) Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'"
  desc  "
    This policy setting allows one process or service to start another service or process with a different security access token, which can be used to modify the security access token of that sub-process and result in the escalation of privileges.
    
    The recommended state for this setting is: LOCAL SERVICE, NETWORK SERVICE.
    
    **Note:** A Member Server that holds the **Web Server (IIS)** Role with **Web Server** Role Service will require a special exception to this recommendation, to allow IIS application pool(s) to be granted this user right.
    
    **Note #2:** A Member Server with Microsoft SQL Server installed will require a special exception to this recommendation for additional SQL-generated entries to be granted this user right.
    
    Rationale: User with the Replace a process level token privilege are able to start processes as other users whose credentials they know. They could use this method to hide their unauthorized actions on the computer. (On Windows 2000-based computers, use of the Replace a process level token user right also requires the user to have the Adjust memory quotas for a process user right that is discussed earlier in this section.)
  "
  impact 1.0
  a = (((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - ['S-1-5-19']) & ((users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - ['S-1-5-20'])).uniq
  a.each do |entry|
    describe security_policy do
      its("SeAssignPrimaryTokenPrivilege") { should_not include entry }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.37_L1_Ensure_Restore_files_and_directories_is_set_to_Administrators" do
  title "(L1) Ensure 'Restore files and directories' is set to 'Administrators'"
  desc  "
    This policy setting determines which users can bypass file, directory, registry, and other persistent object permissions when restoring backed up files and directories on computers that run Windows Vista in your environment. This user right also determines which users can set valid security principals as object owners; it is similar to the Back up files and directories user right.
    
    The recommended state for this setting is: Administrators.
    
    Rationale: An attacker with the Restore files and directories user right could restore sensitive data to a computer and overwrite data that is more recent, which could lead to loss of important data, data corruption, or a denial of service. Attackers could overwrite executable files that are used by legitimate administrators or system services with versions that include malicious software to grant themselves elevated privileges, compromise data, or install backdoors for continued access to the computer.
    
    **Note:** Even if the following countermeasure is configured, an attacker could still restore data to a computer in a domain that is controlled by the attacker. Therefore, it is critical that organizations carefully protect the media that are used to back up data.
  "
  impact 1.0
  a = (users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - (users.where { username.casecmp('Administrators') == 0}.uids.entries + groups.where { name.casecmp('Administrators') == 0}.gids.entries).uniq
  a.each do |entry|
    describe security_policy do
      its("SeRestorePrivilege") { should_not include entry }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.38_L1_Ensure_Shut_down_the_system_is_set_to_Administrators" do
  title "(L1) Ensure 'Shut down the system' is set to 'Administrators'"
  desc  "
    This policy setting determines which users who are logged on locally to the computers in your environment can shut down the operating system with the Shut Down command. Misuse of this user right can result in a denial of service condition.
    
    The recommended state for this setting is: Administrators.
    
    Rationale: The ability to shut down domain controllers and member servers should be limited to a very small number of trusted administrators. Although the **Shut down the system** user right requires the ability to log on to the server, you should be very careful about which accounts and groups you allow to shut down a domain controller or member server.
    
    When a domain controller is shut down, it is no longer available to process logons, serve Group Policy, and answer Lightweight Directory Access Protocol (LDAP) queries. If you shut down domain controllers that possess Flexible Single Master Operations (FSMO) roles, you can disable key domain functionality, such as processing logons for new passwords&#x2014;the Primary Domain Controller (PDC) Emulator role.
  "
  impact 1.0
  a = (users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - (users.where { username.casecmp('Administrators') == 0}.uids.entries + groups.where { name.casecmp('Administrators') == 0}.gids.entries).uniq
  a.each do |entry|
    describe security_policy do
      its("SeShutdownPrivilege") { should_not include entry }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_2.2.40_L1_Ensure_Take_ownership_of_files_or_other_objects_is_set_to_Administrators" do
  title "(L1) Ensure 'Take ownership of files or other objects' is set to 'Administrators'"
  desc  "
    This policy setting allows users to take ownership of files, folders, registry keys, processes, or threads. This user right bypasses any permissions that are in place to protect objects to give ownership to the specified user.
    
    The recommended state for this setting is: Administrators.
    
    Rationale: Any users with the Take ownership of files or other objects user right can take control of any object, regardless of the permissions on that object, and then make any changes they wish to that object. Such changes could result in exposure of data, corruption of data, or a DoS condition.
  "
  impact 1.0
  a = (users.where { username =~ /.*/}.uids.entries + groups.where { name =~ /.*/}.gids.entries) - (users.where { username.casecmp('Administrators') == 0}.uids.entries + groups.where { name.casecmp('Administrators') == 0}.gids.entries).uniq
  a.each do |entry|
    describe security_policy do
      its("SeTakeOwnershipPrivilege") { should_not include entry }
    end
  end
end
