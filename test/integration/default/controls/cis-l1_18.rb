control "xccdf_org.cisecurity.benchmarks_rule_18.1.1.1_L1_Ensure_Prevent_enabling_lock_screen_camera_is_set_to_Enabled" do
  title "(L1) Ensure 'Prevent enabling lock screen camera' is set to 'Enabled'"
  desc  "
    Disables the lock screen camera toggle switch in PC Settings and prevents a camera from being invoked on the lock screen.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Disabling the lock screen camera extends the protection afforded by the lock screen to camera features.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Personalization") do
    it { should have_property "NoLockScreenCamera" }
    its("NoLockScreenCamera") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.1.1.2_L1_Ensure_Prevent_enabling_lock_screen_slide_show_is_set_to_Enabled" do
  title "(L1) Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled'"
  desc  "
    Disables the lock screen slide show settings in PC Settings and prevents a slide show from playing on the lock screen.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Disabling the lock screen slide show extends the protection afforded by the lock screen to slide show contents.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Personalization") do
    it { should have_property "NoLockScreenSlideshow" }
    its("NoLockScreenSlideshow") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.2.1_L1_Ensure_LAPS_AdmPwd_GPO_Extension__CSE_is_installed_MS_only" do
  title "(L1) Ensure LAPS AdmPwd GPO Extension / CSE is installed (MS only)"
  desc  "
    In May 2015, Microsoft released the Local Administrator Password Solution (LAPS) tool, which is free and supported software that allows an organization to automatically set randomized and unique local Administrator account passwords on domain-attached workstations and member servers. The passwords are stored in a confidential attribute of the domain computer account and can be retrieved from Active Directory by approved Sysadmins when needed.
    
    The LAPS tool requires a small Active Directory Schema update in order to implement, as well as installation of a Group Policy Client Side Extension (CSE) on targeted computers. Please see the LAPS documentation for details.
    
    LAPS supports Windows Vista or newer workstation OSes, and Server 2003 or newer server OSes. LAPS does not support standalone computers - they must be joined to a domain.
    
    **Note:** Organizations that utilize 3rd-party commercial software to manage unique  complex local Administrator passwords on domain members may opt to disregard these LAPS recommendations.
    
    Rationale: Due to the difficulty in managing local Administrator passwords, many organizations choose to use the same password on all workstations and/or member servers when deploying them. This poses a serious attack surface security risk because if an attacker manages to compromise one system and learn the password to its local Administrator account, then they can leverage that account to instantly gain access to all other computers that also use that password for their local Administrator account.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\GPExtensions\\{D76B9641-3288-4f75-942D-087DE603E3EA}") do
    it { should have_property "DllName" }
    its("DllName") { should eq "C:\\Program Files\\LAPS\\CSE\\AdmPwd.dll" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.2.2_L1_Ensure_Do_not_allow_password_expiration_time_longer_than_required_by_policy_is_set_to_Enabled_MS_only" do
  title "(L1) Ensure 'Do not allow password expiration time longer than required by policy' is set to 'Enabled' (MS only)"
  desc  "
    In May 2015, Microsoft released the Local Administrator Password Solution (LAPS) tool, which is free and supported software that allows an organization to automatically set randomized and unique local Administrator account passwords on domain-attached workstations and member servers. The passwords are stored in a confidential attribute of the domain computer account and can be retrieved from Active Directory by approved Sysadmins when needed.
    
    The LAPS tool requires a small Active Directory Schema update in order to implement, as well as installation of a Group Policy Client Side Extension (CSE) on targeted computers. Please see the LAPS documentation for details.
    
    LAPS supports Windows Vista or newer workstation OSes, and Server 2003 or newer server OSes. LAPS does not support standalone computers - they must be joined to a domain.
    
    The recommended state for this setting is: Enabled.
    
    **Note:** Organizations that utilize 3rd-party commercial software to manage unique  complex local Administrator passwords on domain members may opt to disregard these LAPS recommendations.
    
    Rationale: Due to the difficulty in managing local Administrator passwords, many organizations choose to use the same password on all workstations and/or member servers when deploying them. This poses a serious attack surface security risk because if an attacker manages to compromise one system and learn the password to its local Administrator account, then they can leverage that account to instantly gain access to all other computers that also use that password for their local Administrator account.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd") do
    it { should have_property "PwdExpirationProtectionEnabled" }
    its("PwdExpirationProtectionEnabled") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.2.3_L1_Ensure_Enable_Local_Admin_Password_Management_is_set_to_Enabled_MS_only" do
  title "(L1) Ensure 'Enable Local Admin Password Management' is set to 'Enabled' (MS only)"
  desc  "
    In May 2015, Microsoft released the Local Administrator Password Solution (LAPS) tool, which is free and supported software that allows an organization to automatically set randomized and unique local Administrator account passwords on domain-attached workstations and member servers. The passwords are stored in a confidential attribute of the domain computer account and can be retrieved from Active Directory by approved Sysadmins when needed.
    
    The LAPS tool requires a small Active Directory Schema update in order to implement, as well as installation of a Group Policy Client Side Extension (CSE) on targeted computers. Please see the LAPS documentation for details.
    
    LAPS supports Windows Vista or newer workstation OSes, and Server 2003 or newer server OSes. LAPS does not support standalone computers - they must be joined to a domain.
    
    The recommended state for this setting is: Enabled.
    
    **Note:** Organizations that utilize 3rd-party commercial software to manage unique  complex local Administrator passwords on domain members may opt to disregard these LAPS recommendations.
    
    Rationale: Due to the difficulty in managing local Administrator passwords, many organizations choose to use the same password on all workstations and/or member servers when deploying them. This poses a serious attack surface security risk because if an attacker manages to compromise one system and learn the password to its local Administrator account, then they can leverage that account to instantly gain access to all other computers that also use that password for their local Administrator account.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft Services\\AdmPwd") do
    it { should have_property "AdmPwdEnabled" }
    its("AdmPwdEnabled") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.2.4_L1_Ensure_Password_Settings_Password_Complexity_is_set_to_Enabled_Large_letters__small_letters__numbers__special_characters_MS_only" do
  title "(L1) Ensure 'Password Settings: Password Complexity' is set to 'Enabled: Large letters + small letters + numbers + special characters' (MS only)"
  desc  "
    In May 2015, Microsoft released the Local Administrator Password Solution (LAPS) tool, which is free and supported software that allows an organization to automatically set randomized and unique local Administrator account passwords on domain-attached workstations and member servers. The passwords are stored in a confidential attribute of the domain computer account and can be retrieved from Active Directory by approved Sysadmins when needed.
    
    The LAPS tool requires a small Active Directory Schema update in order to implement, as well as installation of a Group Policy Client Side Extension (CSE) on targeted computers. Please see the LAPS documentation for details.
    
    LAPS supports Windows Vista or newer workstation OSes, and Server 2003 or newer server OSes. LAPS does not support standalone computers - they must be joined to a domain.
    
    The recommended state for this setting is: Enabled: Large letters + small letters + numbers + special characters.
    
    **Note:** Organizations that utilize 3rd-party commercial software to manage unique  complex local Administrator passwords on domain members may opt to disregard these LAPS recommendations.
    
    Rationale: Due to the difficulty in managing local Administrator passwords, many organizations choose to use the same password on all workstations and/or member servers when deploying them. This poses a serious attack surface security risk because if an attacker manages to compromise one system and learn the password to its local Administrator account, then they can leverage that account to instantly gain access to all other computers that also use that password for their local Administrator account.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd") do
    it { should have_property "PasswordComplexity" }
    its("PasswordComplexity") { should cmp == 4 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.2.5_L1_Ensure_Password_Settings_Password_Length_is_set_to_Enabled_15_or_more_MS_only" do
  title "(L1) Ensure 'Password Settings: Password Length' is set to 'Enabled: 15 or more' (MS only)"
  desc  "
    In May 2015, Microsoft released the Local Administrator Password Solution (LAPS) tool, which is free and supported software that allows an organization to automatically set randomized and unique local Administrator account passwords on domain-attached workstations and member servers. The passwords are stored in a confidential attribute of the domain computer account and can be retrieved from Active Directory by approved Sysadmins when needed.
    
    The LAPS tool requires a small Active Directory Schema update in order to implement, as well as installation of a Group Policy Client Side Extension (CSE) on targeted computers. Please see the LAPS documentation for details.
    
    LAPS supports Windows Vista or newer workstation OSes, and Server 2003 or newer server OSes. LAPS does not support standalone computers - they must be joined to a domain.
    
    The recommended state for this setting is:Enabled: 15 or more.
    
    **Note:** Organizations that utilize 3rd-party commercial software to manage unique  complex local Administrator passwords on domain members may opt to disregard these LAPS recommendations.
    
    Rationale: Due to the difficulty in managing local Administrator passwords, many organizations choose to use the same password on all workstations and/or member servers when deploying them. This poses a serious attack surface security risk because if an attacker manages to compromise one system and learn the password to its local Administrator account, then they can leverage that account to instantly gain access to all other computers that also use that password for their local Administrator account.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd") do
    it { should have_property "PasswordLength" }
    its("PasswordLength") { should cmp >= 15 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.2.6_L1_Ensure_Password_Settings_Password_Age_Days_is_set_to_Enabled_30_or_fewer_MS_only" do
  title "(L1) Ensure 'Password Settings: Password Age (Days)' is set to 'Enabled: 30 or fewer' (MS only)"
  desc  "
    In May 2015, Microsoft released the Local Administrator Password Solution (LAPS) tool, which is free and supported software that allows an organization to automatically set randomized and unique local Administrator account passwords on domain-attached workstations and member servers. The passwords are stored in a confidential attribute of the domain computer account and can be retrieved from Active Directory by approved Sysadmins when needed.
    
    The LAPS tool requires a small Active Directory Schema update in order to implement, as well as installation of a Group Policy Client Side Extension (CSE) on targeted computers. Please see the LAPS documentation for details.
    
    LAPS supports Windows Vista or newer workstation OSes, and Server 2003 or newer server OSes. LAPS does not support standalone computers - they must be joined to a domain.
    
    The recommended state for this setting is:Enabled: 30 or fewer.
    
    **Note:** Organizations that utilize 3rd-party commercial software to manage unique  complex local Administrator passwords on domain members may opt to disregard these LAPS recommendations.
    
    Rationale: Due to the difficulty in managing local Administrator passwords, many organizations choose to use the same password on all workstations and/or member servers when deploying them. This poses a serious attack surface security risk because if an attacker manages to compromise one system and learn the password to its local Administrator account, then they can leverage that account to instantly gain access to all other computers that also use that password for their local Administrator account.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft Services\\AdmPwd") do
    it { should have_property "PasswordAgeDays" }
    its("PasswordAgeDays") { should cmp <= 30 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.3.1_L1_Ensure_MSS_AutoAdminLogon_Enable_Automatic_Logon_not_recommended_is_set_to_Disabled" do
  title "(L1) Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' is set to 'Disabled'"
  desc  "
    This setting is separate from the Welcome screen feature in Windows XP and Windows Vista; if that feature is disabled, this setting is not disabled. If you configure a computer for automatic logon, anyone who can physically gain access to the computer can also gain access to everything that is on the computer, including any network or networks to which the computer is connected. Also, if you enable automatic logon, the password is stored in the registry in plaintext, and the specific registry key that stores this value is remotely readable by the Authenticated Users group.
    
    For additional information, see Microsoft Knowledge Base article 324737: [How to turn on automatic logon in Windows](https://support.microsoft.com/en-us/kb/324737).
    
    The recommended state for this setting is: Disabled.
    
    Rationale: If you configure a computer for automatic logon, anyone who can physically gain access to the computer can also gain access to everything that is on the computer, including any network or networks that the computer is connected to. Also, if you enable automatic logon, the password is stored in the registry in plaintext. The specific registry key that stores this setting is remotely readable by the Authenticated Users group. As a result, this entry is appropriate only if the computer is physically secured and if you ensure that untrusted users cannot remotely see the registry.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon") do
    it { should have_property "AutoAdminLogon" }
    its("AutoAdminLogon") { should eq "0" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.3.2_L1_Ensure_MSS_DisableIPSourceRouting_IPv6_IP_source_routing_protection_level_protects_against_packet_spoofing_is_set_to_Enabled_Highest_protection_source_routing_is_completely_disabled" do
  title "(L1) Ensure 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'"
  desc  "
    IP source routing is a mechanism that allows the sender to determine the IP route that a datagram should follow through the network.
    
    The recommended state for this setting is: Enabled: Highest protection, source routing is completely disabled.
    
    Rationale: An attacker could use source routed packets to obscure their identity and location. Source routing allows a computer that sends a packet to specify the route that the packet takes.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip6\\Parameters") do
    it { should have_property "DisableIPSourceRouting" }
    its("DisableIPSourceRouting") { should cmp == 2 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.3.3_L1_Ensure_MSS_DisableIPSourceRouting_IP_source_routing_protection_level_protects_against_packet_spoofing_is_set_to_Enabled_Highest_protection_source_routing_is_completely_disabled" do
  title "(L1) Ensure 'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'"
  desc  "
    IP source routing is a mechanism that allows the sender to determine the IP route that a datagram should take through the network. It is recommended to configure this setting to Not Defined for enterprise environments and to Highest Protection for high security environments to completely disable source routing.
    
    The recommended state for this setting is: Enabled: Highest protection, source routing is completely disabled.
    
    Rationale: An attacker could use source routed packets to obscure their identity and location. Source routing allows a computer that sends a packet to specify the route that the packet takes.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters") do
    it { should have_property "DisableIPSourceRouting" }
    its("DisableIPSourceRouting") { should cmp == 2 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.3.4_L1_Ensure_MSS_EnableICMPRedirect_Allow_ICMP_redirects_to_override_OSPF_generated_routes_is_set_to_Disabled" do
  title "(L1) Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled'"
  desc  "
    Internet Control Message Protocol (ICMP) redirects cause the IPv4 stack to plumb host routes. These routes override the Open Shortest Path First (OSPF) generated routes.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: This behavior is expected. The problem is that the 10 minute time-out period for the ICMP redirect-plumbed routes temporarily creates a network situation in which traffic will no longer be routed properly for the affected host. Ignoring such ICMP redirects will limit the system's exposure to attacks that will impact its ability to participate on the network.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters") do
    it { should have_property "EnableICMPRedirect" }
    its("EnableICMPRedirect") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.3.6_L1_Ensure_MSS_NoNameReleaseOnDemand_Allow_the_computer_to_ignore_NetBIOS_name_release_requests_except_from_WINS_servers_is_set_to_Enabled" do
  title "(L1) Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled'"
  desc  "
    NetBIOS over TCP/IP is a network protocol that among other things provides a way to easily resolve NetBIOS names that are registered on Windows-based systems to the IP addresses that are configured on those systems. This setting determines whether the computer releases its NetBIOS name when it receives a name-release request.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: The NetBT protocol is designed not to use authentication, and is therefore vulnerable to spoofing. Spoofing makes a transmission appear to come from a user other than the user who performed the action. A malicious user could exploit the unauthenticated nature of the protocol to send a name-conflict datagram to a target computer, which would cause the computer to relinquish its name and not respond to queries.
    
    An attacker could send a request over the network and query a computer to release its NetBIOS name. As with any change that could affect applications, it is recommended that you test this change in a non-production environment before you change the production environment.
    
    The result of such an attack could be to cause intermittent connectivity issues on the target computer, or even to prevent the use of Network Neighborhood, domain logons, the NET SEND command, or additional NetBIOS name resolution.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\NetBT\\Parameters") do
    it { should have_property "nonamereleaseondemand" }
    its("nonamereleaseondemand") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.3.8_L1_Ensure_MSS_SafeDllSearchMode_Enable_Safe_DLL_search_mode_recommended_is_set_to_Enabled" do
  title "(L1) Ensure 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)' is set to 'Enabled'"
  desc  "
    The DLL search order can be configured to search for DLLs that are requested by running processes in one of two ways:
    
    * Search folders specified in the system path first, and then search the current working folder.
    * Search current working folder first, and then search the folders specified in the system path.
    When enabled, the registry value is set to 1. With a setting of 1, the system first searches the folders that are specified in the system path and then searches the current working folder. When disabled the registry value is set to 0 and the system first searches the current working folder and then searches the folders that are specified in the system path.
    
    Applications will be forced to search for DLLs in the system path first. For applications that require unique versions of these DLLs that are included with the application, this entry could cause performance or stability problems.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: If a user unknowingly executes hostile code that was packaged with additional files that include modified versions of system DLLs, the hostile code could load its own versions of those DLLs and potentially increase the type and degree of damage the code can render.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager") do
    it { should have_property "SafeDllSearchMode" }
    its("SafeDllSearchMode") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.3.9_L1_Ensure_MSS_ScreenSaverGracePeriod_The_time_in_seconds_before_the_screen_saver_grace_period_expires_0_recommended_is_set_to_Enabled_5_or_fewer_seconds" do
  title "(L1) Ensure 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)' is set to 'Enabled: 5 or fewer seconds'"
  desc  "
    Windows includes a grace period between when the screen saver is launched and when the console is actually locked automatically when screen saver locking is enabled.
    
    The recommended state for this setting is: Enabled: 5 or fewer seconds.
    
    Rationale: The default grace period that is allowed for user movement before the screen saver lock takes effect is five seconds. If you leave the default grace period configuration, your computer is vulnerable to a potential attack from someone who could approach the console and attempt to log on to the computer before the lock takes effect. An entry to the registry can be made to adjust the length of the grace period.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon") do
    it { should have_property "ScreenSaverGracePeriod" }
    its("ScreenSaverGracePeriod") { should cmp <= 5 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.3.12_L1_Ensure_MSS_WarningLevel_Percentage_threshold_for_the_security_event_log_at_which_the_system_will_generate_a_warning_is_set_to_Enabled_90_or_less" do
  title "(L1) Ensure 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' is set to 'Enabled: 90% or less'"
  desc  "
    This setting can generate a security audit in the Security event log when the log reaches a user-defined threshold.
    
    **Note:** If log settings are configured to Overwrite events as needed or Overwrite events older than x days, this event will not be generated.
    
    The recommended state for this setting is: Enabled: 90% or less.
    
    Rationale: If the Security log reaches 90 percent of its capacity and the computer has not been configured to overwrite events as needed, more recent events will not be written to the log. If the log reaches its capacity and the computer has been configured to shut down when it can no longer record events to the Security log, the computer will shut down and will no longer be available to provide network services.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Eventlog\\Security") do
    it { should have_property "WarningLevel" }
    its("WarningLevel") { should cmp <= 90 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.4.11.2_L1_Ensure_Prohibit_installation_and_configuration_of_Network_Bridge_on_your_DNS_domain_network_is_set_to_Enabled" do
  title "(L1) Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'"
  desc  "
    You can use this procedure to controls user's ability to install and configure a network bridge.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: The Network Bridge setting, if enabled, allows users to create a Layer 2 Media Access Control (MAC) bridge, enabling them to connect two or more physical network segments together. A network bridge thus allows a computer that has connections to two different networks to share data between those networks.
    
    In an enterprise environment, where there is a need to control network traffic to only authorized paths, allowing users to create a network bridge increases the risk and attack surface from the bridged network.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Network Connections") do
    it { should have_property "NC_AllowNetBridge_NLA" }
    its("NC_AllowNetBridge_NLA") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.4.11.3_L1_Ensure_Require_domain_users_to_elevate_when_setting_a_networks_location_is_set_to_Enabled" do
  title "(L1) Ensure 'Require domain users to elevate when setting a network's location' is set to 'Enabled'"
  desc  "
    This policy setting determines whether to require domain users to elevate when setting a network's location.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Allowing regular users to set a network location increases the risk and attack surface.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Network Connections") do
    it { should have_property "NC_StdDomainUserSetLocation" }
    its("NC_StdDomainUserSetLocation") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.4.14.1_L1_Ensure_Hardened_UNC_Paths_is_set_to_Enabled_with_Require_Mutual_Authentication_and_Require_Integrity_set_for_all_NETLOGON_and_SYSVOL_shares" do
  title "(L1) Ensure 'Hardened UNC Paths' is set to 'Enabled, with \"Require Mutual Authentication\" and \"Require Integrity\" set for all NETLOGON and SYSVOL shares'"
  desc  "
    This policy setting configures secure access to UNC paths.
    
    The recommended state for this setting is: Enabled, with \"Require Mutual Authentication\" and \"Require Integrity\" set for all NETLOGON and SYSVOL shares.
    
    **Note:** If the environment exclusively contains Windows 8.0 / Server 2012 or higher systems, then the \"Privacy\" setting may (optionally) also be set to enable SMB encryption. However, using SMB encryption will render the targeted share paths completely inaccessible by older OSes, so only use this additional option with caution and thorough testing.
    
    Rationale: In February 2015, Microsoft released a new control mechanism to mitigate a security risk in Group Policy as part of [MS15-011](https://technet.microsoft.com/library/security/MS15-011) / [MSKB 3000483](https://support.microsoft.com/en-us/kb/3000483). This mechanism requires both the installation of the new security update and also the deployment of specific group policy settings to all computers on the domain from Vista/Server 2008 or higher (the associated security patch to enable this feature was not released for Server 2003). A new group policy template (NetworkProvider.admx/adml) was also provided with the security update.
    
    Once the new GPO template is in place, the following are the minimum requirements to remediate the Group Policy security risk: \\\\*\\NETLOGON RequireMutualAuthentication=1, RequireIntegrity=1 \\\\*\\SYSVOL RequireMutualAuthentication=1, RequireIntegrity=1
    
    **Note:** A reboot may be required after the setting is applied to a client machine to access the above paths.
    
    Additional guidance on the deployment of this security setting is available from the Microsoft Premier Field Engineering (PFE) Platforms TechNet Blog here: [Guidance on Deployment of MS15-011 and MS15-014](http://blogs.technet.com/b/askpfeplat/archive/2015/02/23/guidance-on-deployment-of-ms15-011-and-ms15-014.aspx).
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkProvider\\HardenedPaths") do
    it { should have_property "\\\\*\\NETLOGON" }
    its("\\\\*\\NETLOGON") { should match(//) }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkProvider\\HardenedPaths") do
    it { should have_property "\\\\*\\SYSVOL" }
    its("\\\\*\\SYSVOL") { should match(//) }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.4.21.1_L1_Ensure_Minimize_the_number_of_simultaneous_connections_to_the_Internet_or_a_Windows_Domain_is_set_to_Enabled" do
  title "(L1) Ensure 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled'"
  desc  "
    This policy setting prevents computers from connecting to both a domain based network and a non-domain based network at the same time.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Blocking simultaneous connections can help prevent a user unknowingly allowing network traffic to flow between the Internet and the corporate network.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WcmSvc\\GroupPolicy") do
    it { should have_property "fMinimizeConnections" }
    its("fMinimizeConnections") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.6.1_L1_Ensure_Apply_UAC_restrictions_to_local_accounts_on_network_logons_is_set_to_Enabled_MS_only" do
  title "(L1) Ensure 'Apply UAC restrictions to local accounts on network logons' is set to 'Enabled' (MS only)"
  desc  "
    This setting controls whether local accounts can be used for remote administration via network logon (e.g., NET USE, connecting to C$, etc.). Local accounts are at high risk for credential theft when the same account and password is configured on multiple systems. Enabling this policy significantly reduces that risk.
    
    **Enabled:** Applies UAC token-filtering to local accounts on network logons. Membership in powerful group such as Administrators is disabled and powerful privileges are removed from the resulting access token. This configures the LocalAccountTokenFilterPolicy registry value to 0. This is the default behavior for Windows.
    
    **Disabled:** Allows local accounts to have full administrative rights when authenticating via network logon, by configuring the LocalAccountTokenFilterPolicy registry value to 1.
    
    For more information about local accounts and credential theft, review the \"[Mitigating Pass-the-Hash (PtH) Attacks and Other Credential Theft Techniques](http://www.microsoft.com/en-us/download/details.aspx?id=36036)\" documents.
    
    For more information about LocalAccountTokenFilterPolicy, see Microsoft Knowledge Base article 951016: [Description of User Account Control and remote restrictions in Windows Vista](https://support.microsoft.com/en-us/kb/951016).
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Local accounts are at high risk for credential theft when the same account and password is configured on multiple systems. Ensuring this policy is Enabled significantly reduces that risk.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") do
    it { should have_property "LocalAccountTokenFilterPolicy" }
#    its("LocalAccountTokenFilterPolicy") { should cmp == 0 }
    its("LocalAccountTokenFilterPolicy") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.6.2_L1_Ensure_WDigest_Authentication_is_set_to_Disabled" do
  title "(L1) Ensure 'WDigest Authentication' is set to 'Disabled'"
  desc  "
    When WDigest authentication is enabled, Lsass.exe retains a copy of the user's plaintext password in memory, where it can be at risk of theft. If this setting is not configured, WDigest authentication is disabled in Windows 8.1 and in Windows Server 2012 R2; it is enabled by default in earlier versions of Windows and Windows Server.
    
    For more information about local accounts and credential theft, review the \"[Mitigating Pass-the-Hash (PtH) Attacks and Other Credential Theft Techniques](http://www.microsoft.com/en-us/download/details.aspx?id=36036)\" documents.
    
    For more information about UseLogonCredential, see Microsoft Knowledge Base article 2871997: [Microsoft Security Advisory Update to improve credentials protection and management May 13, 2014](https://support.microsoft.com/en-us/kb/2871997).
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Preventing the plaintext storage of credentials in memory may reduce opportunity for credential theft.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest") do
    it { should have_property "UseLogonCredential" }
    its("UseLogonCredential") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.8.3.1_L1_Ensure_Include_command_line_in_process_creation_events_is_set_to_Disabled" do
  title "(L1) Ensure 'Include command line in process creation events' is set to 'Disabled'"
  desc  "
    This policy setting determines what information is logged in security audit events when a new process has been created.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: When this policy setting is enabled, any user who has read access to the security events can read the command-line arguments for any successfully created process. Command-line arguments may contain sensitive or private information such as passwords or user data.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit") do
    it { should have_property "ProcessCreationIncludeCmdLine_Enabled" }
    its("ProcessCreationIncludeCmdLine_Enabled") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.8.12.1_L1_Ensure_Boot-Start_Driver_Initialization_Policy_is_set_to_Enabled_Good_unknown_and_bad_but_critical" do
  title "(L1) Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'"
  desc  "
    This policy setting allows you to specify which boot-start drivers are initialized based on a classification determined by an Early Launch Antimalware boot-start driver. The Early Launch Antimalware boot-start driver can return the following classifications for each boot-start driver:
    
    * Good: The driver has been signed and has not been tampered with.
    * Bad: The driver has been identified as malware. It is recommended that you do not allow known bad drivers to be initialized.
    * Bad, but required for boot: The driver has been identified as malware, but the computer cannot successfully boot without loading this driver.
    * Unknown: This driver has not been attested to by your malware detection application and has not been classified by the Early Launch Antimalware boot-start driver.
    If you enable this policy setting you will be able to choose which boot-start drivers to initialize the next time the computer is started.
    
    If your malware detection application does not include an Early Launch Antimalware boot-start driver or if your Early Launch Antimalware boot-start driver has been disabled, this setting has no effect and all boot-start drivers are initialized.
    
    The recommended state for this setting is: Enabled: Good, unknown and bad but critical.
    
    Rationale: This policy setting helps reduce the impact of malware that has already infected your system.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Policies\\EarlyLaunch") do
    it { should have_property "DriverLoadPolicy" }
    its("DriverLoadPolicy") { should cmp == 3 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.8.19.2_L1_Ensure_Configure_registry_policy_processing_Do_not_apply_during_periodic_background_processing_is_set_to_Enabled_FALSE" do
  title "(L1) Ensure 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'"
  desc  "
    The \"Do not apply during periodic background processing\" option prevents the system from updating affected policies in the background while the computer is in use. When background updates are disabled, policy changes will not take effect until the next user logon or system restart.
    
    The recommended state for this setting is: Enabled: FALSE (unchecked).
    
    Rationale: Setting this option to false (unchecked) will ensure that domain policy changes take effect more quickly, as compared to waiting until the next user logon or system restart.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Group Policy\\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}") do
    it { should have_property "NoBackgroundPolicy" }
    its("NoBackgroundPolicy") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.8.19.3_L1_Ensure_Configure_registry_policy_processing_Process_even_if_the_Group_Policy_objects_have_not_changed_is_set_to_Enabled_TRUE" do
  title "(L1) Ensure 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'"
  desc  "
    The \"Process even if the Group Policy objects have not changed\" option updates and reapplies policies even if the policies have not changed.
    
    The recommended state for this setting is: Enabled: TRUE (checked).
    
    Rationale: Setting this option to true (checked) will ensure unauthorized changes that might have been configured locally are forced to match the domain-based Group Policy settings again.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Group Policy\\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}") do
    it { should have_property "NoGPOListChanges" }
    its("NoGPOListChanges") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.8.19.4_L1_Ensure_Turn_off_background_refresh_of_Group_Policy_is_set_to_Disabled" do
  title "(L1) Ensure 'Turn off background refresh of Group Policy' is set to 'Disabled'"
  desc  "
    This policy setting prevents Group Policy from being updated while the computer is in use. This policy setting applies to Group Policy for computers, users and domain controllers.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: This setting ensures that group policy changes take effect more quickly, as compared to waiting until the next user logon or system restart.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") do
    it { should_not have_property "DisableBkGndGroupPolicy" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.8.25.1_L1_Ensure_Do_not_display_network_selection_UI_is_set_to_Enabled" do
  title "(L1) Ensure 'Do not display network selection UI' is set to 'Enabled'"
  desc  "
    This policy setting allows you to control whether anyone can interact with available networks UI on the logon screen.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: An unauthorized user could disconnect the PC from the network or can connect the PC to other available networks without signing into Windows.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System") do
    it { should have_property "DontDisplayNetworkSelectionUI" }
    its("DontDisplayNetworkSelectionUI") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.8.25.2_L1_Ensure_Do_not_enumerate_connected_users_on_domain-joined_computers_is_set_to_Enabled" do
  title "(L1) Ensure 'Do not enumerate connected users on domain-joined computers' is set to 'Enabled'"
  desc  "
    This policy setting prevents connected users from being enumerated on domain-joined computers.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: A malicious user could use this feature to gather account names of other users, that information could then be used in conjunction with other types of attacks such as guessing passwords or social engineering. The value of this countermeasure is small because a user with domain credentials could gather the same account information using other methods.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System") do
    it { should have_property "DontEnumerateConnectedUsers" }
    its("DontEnumerateConnectedUsers") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.8.25.3_L1_Ensure_Enumerate_local_users_on_domain-joined_computers_is_set_to_Disabled" do
  title "(L1) Ensure 'Enumerate local users on domain-joined computers' is set to 'Disabled'"
  desc  "
    This policy setting allows local users to be enumerated on domain-joined computers.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: A malicious user could use this feature to gather account names of other users, that information could then be used in conjunction with other types of attacks such as guessing passwords or social engineering. The value of this countermeasure is small because a user with domain credentials could gather the same account information using other methods.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System") do
    it { should have_property "EnumerateLocalUsers" }
    its("EnumerateLocalUsers") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.8.25.4_L1_Ensure_Turn_off_app_notifications_on_the_lock_screen_is_set_to_Enabled" do
  title "(L1) Ensure 'Turn off app notifications on the lock screen' is set to 'Enabled'"
  desc  "
    This policy setting allows you to prevent app notifications from appearing on the lock screen.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: App notifications might display sensitive business or personal data.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System") do
    it { should have_property "DisableLockScreenAppNotifications" }
    its("DisableLockScreenAppNotifications") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.8.25.5_L1_Ensure_Turn_on_convenience_PIN_sign-in_is_set_to_Disabled" do
  title "(L1) Ensure 'Turn on convenience PIN sign-in' is set to 'Disabled'"
  desc  "
    This policy setting allows you to control whether a domain user can sign in using a convenience PIN. In Windows 10, convenience PIN was replaced with Passport, which has stronger security properties. To configure Passport for domain users, use the policies under Computer configuration\\Administrative Templates\\Windows Components\\Microsoft Passport for Work.
    
    **Note:** The user's domain password will be cached in the system vault when using this feature.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: A PIN is created from a much smaller selection of characters than a password, so in most cases a PIN will be much less robust than a password.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System") do
    it { should have_property "AllowDomainPINLogon" }
    its("AllowDomainPINLogon") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.8.31.1_L1_Ensure_Configure_Offer_Remote_Assistance_is_set_to_Disabled" do
  title "(L1) Ensure 'Configure Offer Remote Assistance' is set to 'Disabled'"
  desc  "
    This policy setting allows you to turn on or turn off Offer (Unsolicited) Remote Assistance on this computer.
    
    Help desk and support personnel will not be able to proactively offer assistance, although they can still respond to user assistance requests.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: A user might be tricked and accept an unsolicited Remote Assistance offer from a malicious user.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\policies\\Microsoft\\Windows NT\\Terminal Services") do
    it { should have_property "fAllowUnsolicited" }
    its("fAllowUnsolicited") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.8.31.2_L1_Ensure_Configure_Solicited_Remote_Assistance_is_set_to_Disabled" do
  title "(L1) Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'"
  desc  "
    This policy setting allows you to turn on or turn off Solicited (Ask for) Remote Assistance on this computer.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: There is slight risk that a rogue administrator will gain access to another user's desktop session, however, they cannot connect to a user's computer unannounced or control it without permission from the user. When an expert tries to connect, the user can still choose to deny the connection or give the expert view-only privileges. The user must explicitly click the Yes button to allow the expert to remotely control the workstation.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\policies\\Microsoft\\Windows NT\\Terminal Services") do
    it { should have_property "fAllowToGetHelp" }
    its("fAllowToGetHelp") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.8.32.1_L1_Ensure_Enable_RPC_Endpoint_Mapper_Client_Authentication_is_set_to_Enabled_MS_only" do
  title "(L1) Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled' (MS only)"
  desc  "
    This policy setting controls whether RPC clients authenticate with the Endpoint Mapper Service when the call they are making contains authentication information. The Endpoint Mapper Service on computers running Windows NT4 (all service packs) cannot process authentication information supplied in this manner. This policy setting can cause a specific issue with **1-way** forest trusts if it is applied to the **trusting** domain DCs (see Microsoft [KB3073942](https://support.microsoft.com/en-us/kb/3073942)), so we do not recommend applying it to domain controllers.
    
    **Note:** This policy will not be applied until the system is rebooted.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Anonymous access to RPC services could result in accidental disclosure of information to unauthenticated users.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Rpc") do
    it { should have_property "EnableAuthEpResolution" }
    its("EnableAuthEpResolution") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.6.1_L1_Ensure_Allow_Microsoft_accounts_to_be_optional_is_set_to_Enabled" do
  title "(L1) Ensure 'Allow Microsoft accounts to be optional' is set to 'Enabled'"
  desc  "
    This policy setting lets you control whether Microsoft accounts are optional for Windows Store apps that require an account to sign in. This policy only affects Windows Store apps that support it.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Enabling this setting allows an organization to use their enterprise user accounts instead of using their Microsoft accounts when accessing Windows store apps. This provides the organization with greater control over relevant credentials. Microsoft accounts cannot be centrally managed and as such enterprise credential security policies cannot be applied to them, which could put any information accessed by using Microsoft accounts at risk.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") do
    it { should have_property "MSAOptional" }
    its("MSAOptional") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.8.1_L1_Ensure_Disallow_Autoplay_for_non-volume_devices_is_set_to_Enabled" do
  title "(L1) Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled'"
  desc  "
    This policy setting disallows AutoPlay for MTP devices like cameras or phones.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: An attacker could use this feature to launch a program to damage a client computer or data on the computer.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Explorer") do
    it { should have_property "NoAutoplayfornonVolume" }
    its("NoAutoplayfornonVolume") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.8.2_L1_Ensure_Set_the_default_behavior_for_AutoRun_is_set_to_Enabled_Do_not_execute_any_autorun_commands" do
  title "(L1) Ensure 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands'"
  desc  "
    This policy setting sets the default behavior for Autorun commands. Autorun commands are generally stored in autorun.inf files. They often launch the installation program or other routines.
    
    The recommended state for this setting is: Enabled: Do not execute any autorun commands.
    
    Rationale: Prior to Windows Vista, when media containing an autorun command is inserted, the system will automatically execute the program without user intervention. This creates a major security concern as code may be executed without user's knowledge. The default behavior starting with Windows Vista is to prompt the user whether autorun command is to be run. The autorun command is represented as a handler in the Autoplay dialog.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer") do
    it { should have_property "NoAutorun" }
    its("NoAutorun") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.8.3_L1_Ensure_Turn_off_Autoplay_is_set_to_Enabled_All_drives" do
  title "(L1) Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'"
  desc  "
    Autoplay starts to read from a drive as soon as you insert media in the drive, which causes the setup file for programs or audio media to start immediately. An attacker could use this feature to launch a program to damage the computer or data on the computer. Autoplay is disabled by default on some removable drive types, such as floppy disk and network drives, but not on CD-ROM drives.
    
    **Note:** You cannot use this policy setting to enable Autoplay on computer drives in which it is disabled by default, such as floppy disk and network drives.
    
    The recommended state for this setting is: Enabled: All drives.
    
    Rationale: An attacker could use this feature to launch a program to damage a client computer or data on the computer.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer") do
    it { should have_property "NoDriveTypeAutoRun" }
    its("NoDriveTypeAutoRun") { should cmp == 255 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.15.1_L1_Ensure_Do_not_display_the_password_reveal_button_is_set_to_Enabled" do
  title "(L1) Ensure 'Do not display the password reveal button' is set to 'Enabled'"
  desc  "
    This policy setting allows you to configure the display of the password reveal button in password entry user experiences.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: This is a useful feature when entering a long and complex password, especially when using a touchscreen. The potential risk is that someone else may see your password while surreptitiously observing your screen.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\CredUI") do
    it { should have_property "DisablePasswordReveal" }
    its("DisablePasswordReveal") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.15.2_L1_Ensure_Enumerate_administrator_accounts_on_elevation_is_set_to_Disabled" do
  title "(L1) Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled'"
  desc  "
    This policy setting controls whether administrator accounts are displayed when a user attempts to elevate a running application.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Users could see the list of administrator accounts, making it slightly easier for a malicious user who has logged onto a console session to try to crack the passwords of those accounts.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\CredUI") do
    it { should have_property "EnumerateAdministrators" }
    its("EnumerateAdministrators") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.24.1_L1_Ensure_EMET_5.51_or_higher_is_installed" do
  title "(L1) Ensure 'EMET 5.51' or higher is installed"
  desc  "
    The Enhanced Mitigation Experience Toolkit (EMET) is free, supported, software developed by Microsoft that allows an enterprise to apply exploit mitigations to applications that run on Windows.
    
    **Note:** EMET has been reported to be very problematic on 32-bit OSes - we only recommend using it with 64-bit OSes.
    
    **Note #2:** Microsoft has announced that EMET will be End-Of-Life (EOL) on July 31, 2018.
    
    Rationale: EMET mitigations help reduce the reliability of exploits that target vulnerable software running on Windows
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\services\\EMET_Service") do
    it { should have_property "Start" }
    its("Start") { should cmp == 2 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.24.2_L1_Ensure_Default_Action_and_Mitigation_Settings_is_set_to_Enabled_plus_subsettings" do
  title "(L1) Ensure 'Default Action and Mitigation Settings' is set to 'Enabled' (plus subsettings)"
  desc  "
    This setting configures the default action after detection and advanced ROP mitigation.
    
    The recommended state for this setting is:
    
    Default Action and Mitigation Settings - Enabled Deep Hooks - Enabled Anti Detours - Enabled Banned Functions - Enabled Exploit Action -User Configured
    
    Rationale: These advanced mitigations for ROP mitigations apply to all configured software in EMET. **Deep Hooks** protects critical APIs and the subsequent lower level APIs used by the top level critical API. **Anti Detours** renders ineffective exploits that evade hooks by executing a copy of the hooked function prologue and then jump to the function past the prologue. **Banned Functions** will block calls to **ntdll!LdrHotPatchRoutine** to mitigate potential exploits abusing the API.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\SysSettings") do
    it { should have_property "AntiDetours" }
    its("AntiDetours") { should cmp == 1 }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\SysSettings") do
    it { should have_property "BannedFunctions" }
    its("BannedFunctions") { should cmp == 1 }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\SysSettings") do
    it { should have_property "DeepHooks" }
    its("DeepHooks") { should cmp == 1 }
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\SysSettings") do
    it { should have_property "ExploitAction" }
    its("ExploitAction") { should cmp == 2 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.24.3_L1_Ensure_Default_Protections_for_Internet_Explorer_is_set_to_Enabled" do
  title "(L1) Ensure 'Default Protections for Internet Explorer' is set to 'Enabled'"
  desc  "
    This settings determine if EMET mitigations are applied to Internet Explorer.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Applying EMET mitigations to Internet Explorer will help reduce the reliability of exploits that target it.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "*\\Internet Explorer\\iexplore.exe" }
#    its("*\\Internet Explorer\\iexplore.exe") { should eq "+EAF+ eaf_modules:mshtml.dll;flash*.ocx;jscript*.dll;vbscript.dll;vgx.dll +ASR asr_modules:npjpi*.dll;jp2iexp.dll;vgx.dll;msxml4*.dll;wshom.ocx;scrrun.dll;vbscript.dll asr_zones:1;2" }
    it { should have_property_value('*\Internet Explorer\iexplore.exe', :string, '+EAF+ eaf_modules:mshtml.dll;flash*.ocx;jscript*.dll;vbscript.dll;vgx.dll +ASR asr_modules:npjpi*.dll;jp2iexp.dll;vgx.dll;msxml4*.dll;wshom.ocx;scrrun.dll;vbscript.dll asr_zones:1;2') }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.24.4_L1_Ensure_Default_Protections_for_Popular_Software_is_set_to_Enabled" do
  title "(L1) Ensure 'Default Protections for Popular Software' is set to 'Enabled'"
  desc  "
    This settings determine if EMET mitigations are applied to other popular software.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Applying EMET mitigations to popular software packages will help reduce the reliability of exploits that target them.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "*\\Mozilla Thunderbird\\thunderbird.exe" }
#    its("*\\Mozilla Thunderbird\\thunderbird.exe") { should match(//) }
    it { should have_property_value('*\Mozilla Thunderbird\thunderbird.exe', :string, '') }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.24.5_L1_Ensure_Default_Protections_for_Recommended_Software_is_set_to_Enabled" do
  title "(L1) Ensure 'Default Protections for Recommended Software' is set to 'Enabled'"
  desc  "
    This settings determine if recommended EMET mitigations are applied to WordPad, applications that are part of the Microsoft Office suite, Adobe Acrobat, Adobe Reader, and Oracle Java.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Applying EMET mitigations to recommended software will help reduce the reliability of exploits that target them.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\Defaults") do
    it { should have_property "*\\Java\\jre*\\bin\\javaws.exe" }
#    its("*\\Java\\jre*\\bin\\javaws.exe") { should eq "-HeapSpray" }
    it { should have_property_value('*\Java\jre*\bin\javaws.exe', :string, '-HeapSpray') }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.24.6_L1_Ensure_System_ASLR_is_set_to_Enabled_Application_Opt-In" do
  title "(L1) Ensure 'System ASLR' is set to 'Enabled: Application Opt-In'"
  desc  "
    This setting determines how applications become enrolled in address space layout randomization (ASLR).
    
    The recommended state for this setting is: Enabled: Application Opt-In.
    
    Rationale: ASLR reduces the predictability of process memory, which in-turn helps reduce the reliability of exploits targeting memory corruption vulnerabilities.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\SysSettings") do
    it { should have_property "ASLR" }
    its("ASLR") { should cmp == 3 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.24.7_L1_Ensure_System_DEP_is_set_to_Enabled_Application_Opt-Out" do
  title "(L1) Ensure 'System DEP' is set to 'Enabled: Application Opt-Out'"
  desc  "
    This setting determines how applications become enrolled in data execution protection (DEP).
    
    The recommended state for this setting is: Enabled: Application Opt-Out.
    
    Rationale: DEP marks pages of application memory as non-executable, which reduces a given exploit's ability to run attacker-controlled code.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\SysSettings") do
    it { should have_property "DEP" }
    its("DEP") { should cmp == 2 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.24.8_L1_Ensure_System_SEHOP_is_set_to_Enabled_Application_Opt-Out" do
  title "(L1) Ensure 'System SEHOP' is set to 'Enabled: Application Opt-Out'"
  desc  "
    This setting determines how applications become enrolled in structured exception handler overwrite protection (SEHOP).
    
    The recommended state for this setting is: Enabled: Application Opt-Out.
    
    Rationale: When a software component suffers from a memory corruption vulnerability, an exploit may be able to overwrite memory that contains data structures that control how the software handles exceptions. By corrupting these structures in a controlled manner, an exploit may be able to execute arbitrary code. SEHOP verifies the integrity of those structures before they are used to handle exceptions, which reduces the reliability of exploits that leverage structured exception handler overwrites.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EMET\\SysSettings") do
    it { should have_property "SEHOP" }
    its("SEHOP") { should cmp == 2 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.26.1.1_L1_Ensure_Application_Control_Event_Log_behavior_when_the_log_file_reaches_its_maximum_size_is_set_to_Disabled" do
  title "(L1) Ensure 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
  desc  "
    This policy setting controls Event Log behavior when the log file reaches its maximum size.
    
    The recommended state for this setting is: Disabled.
    
    **Note:** Old events may or may not be retained according to the \"Backup log automatically when full\" policy setting.
    
    Rationale: If new events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Application") do
    it { should have_property "Retention" }
    its("Retention") { should eq "0" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.26.1.2_L1_Ensure_Application_Specify_the_maximum_log_file_size_KB_is_set_to_Enabled_32768_or_greater" do
  title "(L1) Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'"
  desc  "
    This policy setting specifies the maximum size of the log file in kilobytes. The maximum log file size can be configured between 1 megabyte (1,024 kilobytes) and 2 terabytes (2,147,483,647 kilobytes) in kilobyte increments.
    
    The recommended state for this setting is: Enabled: 32,768 or greater.
    
    Rationale: If events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Application") do
    it { should have_property "MaxSize" }
    its("MaxSize") { should cmp >= 32768 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.26.2.1_L1_Ensure_Security_Control_Event_Log_behavior_when_the_log_file_reaches_its_maximum_size_is_set_to_Disabled" do
  title "(L1) Ensure 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
  desc  "
    This policy setting controls Event Log behavior when the log file reaches its maximum size.
    
    The recommended state for this setting is: Disabled.
    
    **Note:** Old events may or may not be retained according to the \"Backup log automatically when full\" policy setting.
    
    Rationale: If new events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Security") do
    it { should have_property "Retention" }
    its("Retention") { should eq "0" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.26.2.2_L1_Ensure_Security_Specify_the_maximum_log_file_size_KB_is_set_to_Enabled_196608_or_greater" do
  title "(L1) Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater'"
  desc  "
    This policy setting specifies the maximum size of the log file in kilobytes. The maximum log file size can be configured between 1 megabyte (1,024 kilobytes) and 2 terabytes (2,147,483,647 kilobytes) in kilobyte increments.
    
    The recommended state for this setting is: Enabled: 196,608 or greater.
    
    Rationale: If events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Security") do
    it { should have_property "MaxSize" }
    its("MaxSize") { should cmp >= 196608 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.26.3.1_L1_Ensure_Setup_Control_Event_Log_behavior_when_the_log_file_reaches_its_maximum_size_is_set_to_Disabled" do
  title "(L1) Ensure 'Setup: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
  desc  "
    This policy setting controls Event Log behavior when the log file reaches its maximum size.
    
    The recommended state for this setting is: Disabled.
    
    **Note:** Old events may or may not be retained according to the \"Backup log automatically when full\" policy setting.
    
    Rationale: If new events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Setup") do
    it { should have_property "Retention" }
    its("Retention") { should eq "0" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.26.3.2_L1_Ensure_Setup_Specify_the_maximum_log_file_size_KB_is_set_to_Enabled_32768_or_greater" do
  title "(L1) Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'"
  desc  "
    This policy setting specifies the maximum size of the log file in kilobytes. The maximum log file size can be configured between 1 megabyte (1,024 kilobytes) and 2 terabytes (2,147,483,647 kilobytes) in kilobyte increments.
    
    The recommended state for this setting is: Enabled: 32,768 or greater.
    
    Rationale: If events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\Setup") do
    it { should have_property "MaxSize" }
    its("MaxSize") { should cmp >= 32768 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.26.4.1_L1_Ensure_System_Control_Event_Log_behavior_when_the_log_file_reaches_its_maximum_size_is_set_to_Disabled" do
  title "(L1) Ensure 'System: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'"
  desc  "
    This policy setting controls Event Log behavior when the log file reaches its maximum size.
    
    The recommended state for this setting is: Disabled.
    
    **Note:** Old events may or may not be retained according to the \"Backup log automatically when full\" policy setting.
    
    Rationale: If new events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\System") do
    it { should have_property "Retention" }
    its("Retention") { should eq "0" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.26.4.2_L1_Ensure_System_Specify_the_maximum_log_file_size_KB_is_set_to_Enabled_32768_or_greater" do
  title "(L1) Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'"
  desc  "
    This policy setting specifies the maximum size of the log file in kilobytes. The maximum log file size can be configured between 1 megabyte (1,024 kilobytes) and 2 terabytes (2,147,483,647 kilobytes) in kilobyte increments.
    
    The recommended state for this setting is: Enabled: 32,768 or greater.
    
    Rationale: If events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\EventLog\\System") do
    it { should have_property "MaxSize" }
    its("MaxSize") { should cmp >= 32768 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.30.2_L1_Ensure_Configure_Windows_SmartScreen_is_set_to_Enabled_Require_approval_from_an_administrator_before_running_downloaded_unknown_software" do
  title "(L1) Ensure 'Configure Windows SmartScreen' is set to 'Enabled: Require approval from an administrator before running downloaded unknown software'"
  desc  "
    This policy setting allows you to manage the behavior of Windows SmartScreen. Windows SmartScreen helps keep PCs safer by warning users before running unrecognized programs downloaded from the Internet. Some information is sent to Microsoft about files and programs run on PCs with this feature enabled.
    
    Windows SmartScreen behavior may be controlled by setting one of the following options:
    
    * Require approval from an administrator before running downloaded unknown software
    * Give user a warning before running downloaded unknown software
    * Turn off SmartScreen
    The recommended state for this setting is: Enabled: Require approval from an administrator before running downloaded unknown software.
    
    Rationale: Windows SmartScreen helps keep PCs safer by warning users before running unrecognized programs downloaded from the Internet. However, due to the fact that some information is sent to Microsoft about files and programs run on PCs some organizations may prefer to disable it.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System") do
    it { should have_property "EnableSmartScreen" }
    its("EnableSmartScreen") { should cmp == 2 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.30.3_L1_Ensure_Turn_off_Data_Execution_Prevention_for_Explorer_is_set_to_Disabled" do
  title "(L1) Ensure 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled'"
  desc  "
    Disabling data execution prevention can allow certain legacy plug-in applications to function without terminating Explorer.
    
    The recommended state for this setting is: Disabled.
    
    **Note:** Some legacy plug-in applications and other software may not function with Data Execution Prevention and will require an exception to be defined for that specific plug-in/software.
    
    Rationale: Data Execution Prevention is an important security feature supported by Explorer that helps to limit the impact of certain types of malware.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Explorer") do
    it { should have_property "NoDataExecutionPrevention" }
    its("NoDataExecutionPrevention") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.30.4_L1_Ensure_Turn_off_heap_termination_on_corruption_is_set_to_Disabled" do
  title "(L1) Ensure 'Turn off heap termination on corruption' is set to 'Disabled'"
  desc  "
    Without heap termination on corruption, legacy plug-in applications may continue to function when a File Explorer session has become corrupt. Ensuring that heap termination on corruption is active will prevent this.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Allowing an application to function after its session has become corrupt increases the risk posture to the system.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Explorer") do
    it { should have_property "NoHeapTerminationOnCorruption" }
    its("NoHeapTerminationOnCorruption") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.30.5_L1_Ensure_Turn_off_shell_protocol_protected_mode_is_set_to_Disabled" do
  title "(L1) Ensure 'Turn off shell protocol protected mode' is set to 'Disabled'"
  desc  "
    This policy setting allows you to configure the amount of functionality that the shell protocol can have. When using the full functionality of this protocol applications can open folders and launch files. The protected mode reduces the functionality of this protocol allowing applications to only open a limited set of folders. Applications are not able to open files with this protocol when it is in the protected mode. It is recommended to leave this protocol in the protected mode to increase the security of Windows.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Limiting the opening of files and folders to a limited set reduces the attack surface of the system.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer") do
    it { should have_property "PreXPSP2ShellProtocolBehavior" }
    its("PreXPSP2ShellProtocolBehavior") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.47.1_L1_Ensure_Prevent_the_usage_of_OneDrive_for_file_storage_is_set_to_Enabled" do
  title "(L1) Ensure 'Prevent the usage of OneDrive for file storage' is set to 'Enabled'"
  desc  "
    This policy setting lets you prevent apps and features from working with files on OneDrive using the Next Generation Sync Client.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Enabling this setting prevents users from accidentally uploading confidential or sensitive corporate information to the OneDrive cloud service using the Next Generation Sync Client.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Skydrive") do
    it { should have_property "DisableFileSync" }
    its("DisableFileSync") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.47.2_L1_Ensure_Prevent_the_usage_of_OneDrive_for_file_storage_on_Windows_8.1_is_set_to_Enabled" do
  title "(L1) Ensure 'Prevent the usage of OneDrive for file storage on Windows 8.1' is set to 'Enabled'"
  desc  "
    This policy setting lets you prevent apps and features from working with files on OneDrive using the legacy OneDrive/SkyDrive client.
    
    The recommended state for this setting is: Enabled.
    
    **Note:** Despite the name of this setting, it is applicable to the legacy OneDrive client on any Windows OS.
    
    Rationale: Enabling this setting prevents users from accidentally uploading confidential or sensitive corporate information to the OneDrive cloud service using the legacy OneDrive/SkyDrive client.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Skydrive") do
    it { should have_property "DisableFileSync" }
    its("DisableFileSync") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.52.2.2_L1_Ensure_Do_not_allow_passwords_to_be_saved_is_set_to_Enabled" do
  title "(L1) Ensure 'Do not allow passwords to be saved' is set to 'Enabled'"
  desc  "
    This policy setting helps prevent Remote Desktop Services / Terminal Services clients from saving passwords on a computer.
    
    The recommended state for this setting is: Enabled.
    
    **Note:** If this policy setting was previously configured as Disabled or Not configured, any previously saved passwords will be deleted the first time a Terminal Services client disconnects from any server.
    
    Rationale: An attacker with physical access to the computer may be able to break the protection guarding saved passwords. An attacker who compromises a user's account and connects to their computer could use saved passwords to gain access to additional hosts.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services") do
    it { should have_property "DisablePasswordSaving" }
    its("DisablePasswordSaving") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.52.3.3.2_L1_Ensure_Do_not_allow_drive_redirection_is_set_to_Enabled" do
  title "(L1) Ensure 'Do not allow drive redirection' is set to 'Enabled'"
  desc  "
    This policy setting prevents users from sharing the local drives on their client computers to Terminal Servers that they access. Mapped drives appear in the session folder tree in Windows Explorer in the following format:
    
    \\\\TSClient\\
    <driveletter>$
    
    If local drives are shared they are left vulnerable to intruders who want to exploit the data that is stored on them.
    
    The recommended state for this setting is: Enabled.</driveletter>
    
    Rationale: Data could be forwarded from the user's Terminal Server session to the user's local computer without any direct user interaction. Malicious software already present on a compromised server would have direct and stealthy disk access to the user's local computer during the Remote Desktop session.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services") do
    it { should have_property "fDisableCdm" }
    its("fDisableCdm") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.52.3.9.1_L1_Ensure_Always_prompt_for_password_upon_connection_is_set_to_Enabled" do
  title "(L1) Ensure 'Always prompt for password upon connection' is set to 'Enabled'"
  desc  "
    This policy setting specifies whether Terminal Services always prompts the client computer for a password upon connection. You can use this policy setting to enforce a password prompt for users who log on to Terminal Services, even if they already provided the password in the Remote Desktop Connection client.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Users have the option to store both their username and password when they create a new Remote Desktop connection shortcut. If the server that runs Terminal Services allows users who have used this feature to log on to the server but not enter their password, then it is possible that an attacker who has gained physical access to the user's computer could connect to a Terminal Server through the Remote Desktop connection shortcut, even though they may not know the user's password.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services") do
    it { should have_property "fPromptForPassword" }
    its("fPromptForPassword") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.52.3.9.2_L1_Ensure_Require_secure_RPC_communication_is_set_to_Enabled" do
  title "(L1) Ensure 'Require secure RPC communication' is set to 'Enabled'"
  desc  "
    This policy setting allows you to specify whether a terminal server requires secure remote procedure call (RPC) communication with all clients or allows unsecured communication.
    
    You can use this policy setting to strengthen the security of RPC communication with clients by allowing only authenticated and encrypted requests.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Allowing unsecure RPC communication can exposes the server to man in the middle attacks and data disclosure attacks.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services") do
    it { should have_property "fEncryptRPCTraffic" }
    its("fEncryptRPCTraffic") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.52.3.9.3_L1_Ensure_Set_client_connection_encryption_level_is_set_to_Enabled_High_Level" do
  title "(L1) Ensure 'Set client connection encryption level' is set to 'Enabled: High Level'"
  desc  "
    This policy setting specifies whether to require the use of a specific encryption level to secure communications between client computers and RD Session Host servers during Remote Desktop Protocol (RDP) connections. This policy only applies when you are using native RDP encryption. However, native RDP encryption (as opposed to SSL encryption) is not recommended. This policy does not apply to SSL encryption.
    
    The recommended state for this setting is: Enabled: High Level.
    
    Rationale: If Terminal Server client connections are allowed that use low level encryption, it is more likely that an attacker will be able to decrypt any captured Terminal Services network traffic.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services") do
    it { should have_property "MinEncryptionLevel" }
    its("MinEncryptionLevel") { should cmp == 3 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.52.3.11.1_L1_Ensure_Do_not_delete_temp_folders_upon_exit_is_set_to_Disabled" do
  title "(L1) Ensure 'Do not delete temp folders upon exit' is set to 'Disabled'"
  desc  "
    This policy setting specifies whether Remote Desktop Services retains a user's per-session temporary folders at logoff.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Sensitive information could be contained inside the temporary folders and shared with other administrators that log into the system.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services") do
    it { should have_property "DeleteTempDirsOnExit" }
    its("DeleteTempDirsOnExit") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.52.3.11.2_L1_Ensure_Do_not_use_temporary_folders_per_session_is_set_to_Disabled" do
  title "(L1) Ensure 'Do not use temporary folders per session' is set to 'Disabled'"
  desc  "
    By default, Remote Desktop Services creates a separate temporary folder on the RD Session Host server for each active session that a user maintains on the RD Session Host server. The temporary folder is created on the RD Session Host server in a Temp folder under the user's profile folder and is named with the \"sessionid.\" This temporary folder is used to store individual temporary files.
    
    To reclaim disk space, the temporary folder is deleted when the user logs off from a session.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: By Disabling this setting you are keeping the cached data independent for each session, both reducing the chance of problems from shared cached data between sessions, and keeping possibly sensitive data separate to each user session.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services") do
    it { should have_property "PerSessionTempDir" }
    its("PerSessionTempDir") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.53.1_L1_Ensure_Prevent_downloading_of_enclosures_is_set_to_Enabled" do
  title "(L1) Ensure 'Prevent downloading of enclosures' is set to 'Enabled'"
  desc  "
    This policy setting prevents the user from having enclosures (file attachments) downloaded from a feed to the user's computer.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Allowing attachments to be downloaded through the RSS feed can introduce files that could have malicious intent.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Feeds") do
    it { should have_property "DisableEnclosureDownload" }
    its("DisableEnclosureDownload") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.54.2_L1_Ensure_Allow_indexing_of_encrypted_files_is_set_to_Disabled" do
  title "(L1) Ensure 'Allow indexing of encrypted files' is set to 'Disabled'"
  desc  "
    This policy setting controls whether encrypted items are allowed to be indexed. When this setting is changed, the index is rebuilt completely. Full volume encryption (such as BitLocker Drive Encryption or a non-Microsoft solution) must be used for the location of the index to maintain security for encrypted files.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Indexing and allowing users to search encrypted files could potentially reveal confidential data stored within the encrypted files.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search") do
    it { should have_property "AllowIndexingEncryptedStoresOrItems" }
    its("AllowIndexingEncryptedStoresOrItems") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.61.1_L1_Ensure_Turn_off_Automatic_Download_and_Install_of_updates_is_set_to_Disabled" do
  title "(L1) Ensure 'Turn off Automatic Download and Install of updates' is set to 'Disabled'"
  desc  "
    This setting enables or disables the automatic download and installation of Windows Store app updates.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Keeping your system properly patched can help protect against 0 day vulnerabilities.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsStore") do
    it { should have_property "AutoDownload" }
    its("AutoDownload") { should cmp == 4 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.61.2_L1_Ensure_Turn_off_the_offer_to_update_to_the_latest_version_of_Windows_is_set_to_Enabled" do
  title "(L1) Ensure 'Turn off the offer to update to the latest version of Windows' is set to 'Enabled'"
  desc  "
    Enables or disables the Windows Store offer to update to the latest version of Windows.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Unplanned OS upgrades can lead to more preventable support calls. The IT department should be managing and approving all updates.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsStore") do
    it { should have_property "DisableOSUpgrade" }
    its("DisableOSUpgrade") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.70.2.1_L1_Ensure_Configure_Default_consent_is_set_to_Enabled_Always_ask_before_sending_data" do
  title "(L1) Ensure 'Configure Default consent' is set to 'Enabled: Always ask before sending data'"
  desc  "
    This setting allows you to set the default consent handling for error reports.
    
    The recommended state for this setting is: Enabled: Always ask before sending data
    
    Rationale: Error reports may contain sensitive information and should not be sent to anyone automatically.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Error Reporting\\Consent") do
    it { should have_property "DefaultConsent" }
    its("DefaultConsent") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.70.3_L1_Ensure_Automatically_send_memory_dumps_for_OS-generated_error_reports_is_set_to_Disabled" do
  title "(L1) Ensure 'Automatically send memory dumps for OS-generated error reports' is set to 'Disabled'"
  desc  "
    This policy setting controls whether memory dumps in support of OS-generated error reports can be sent to Microsoft automatically. This policy does not apply to error reports generated by 3rd-party products, or additional data other than memory dumps.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Memory dumps may contain sensitive information and should not be automatically sent to anyone.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Error Reporting") do
    it { should have_property "AutoApproveOSDumps" }
    its("AutoApproveOSDumps") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.74.1_L1_Ensure_Allow_user_control_over_installs_is_set_to_Disabled" do
  title "(L1) Ensure 'Allow user control over installs' is set to 'Disabled'"
  desc  "
    Permits users to change installation options that typically are available only to system administrators. The security features of Windows Installer prevent users from changing installation options typically reserved for system administrators, such as specifying the directory to which files are installed. If Windows Installer detects that an installation package has permitted the user to change a protected option, it stops the installation and displays a message. These security features operate only when the installation program is running in a privileged security context in which it has access to directories denied to the user.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: In an Enterprise environment, only IT staff with administrative rights should be installing or changing software on a system. Allowing users the ability can risk unapproved software from being installed our removed from a system which could cause the system to become vulnerable.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Installer") do
    it { should have_property "EnableUserControl" }
    its("EnableUserControl") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.74.2_L1_Ensure_Always_install_with_elevated_privileges_is_set_to_Disabled" do
  title "(L1) Ensure 'Always install with elevated privileges' is set to 'Disabled'"
  desc  "
    This setting controls whether or not Windows Installer should use system permissions when it installs any program on the system.
    
    **Note:** This setting appears both in the Computer Configuration and User Configuration folders. To make this setting effective, you must enable the setting in both folders.
    
    **Caution:** If enabled, skilled users can take advantage of the permissions this setting grants to change their privileges and gain permanent access to restricted files and folders. Note that the User Configuration version of this setting is not guaranteed to be secure.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Users with limited privileges can exploit this feature by creating a Windows Installer installation package that creates a new local account that belongs to the local built-in Administrators group, adds their current account to the local built-in Administrators group, installs malicious software, or performs other unauthorized activities.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer") do
    it { should have_property "AlwaysInstallElevated" }
    its("AlwaysInstallElevated") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.75.1_L1_Ensure_Sign-in_last_interactive_user_automatically_after_a_system-initiated_restart_is_set_to_Disabled" do
  title "(L1) Ensure 'Sign-in last interactive user automatically after a system-initiated restart' is set to 'Disabled'"
  desc  "
    This policy setting controls whether a device will automatically sign-in the last interactive user after Windows Update restarts the system.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Disabling this feature will prevent the caching of user's credentials and unauthorized use of the device, and also ensure the user is aware of the restart.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\policies\\system") do
    it { should have_property "DisableAutomaticRestartSignOn" }
    its("DisableAutomaticRestartSignOn") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.84.1_L1_Ensure_Turn_on_PowerShell_Script_Block_Logging_is_set_to_Disabled" do
  title "(L1) Ensure 'Turn on PowerShell Script Block Logging' is set to 'Disabled'"
  desc  "
    This policy setting enables logging of all PowerShell script input to the Microsoft-Windows-PowerShell/Operational event log.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: There are potential risks of capturing passwords in the PowerShell logs. This setting should only be needed for debugging purposes, and not in normal operation, it is important to ensure this is set to Disabled.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging") do
    it { should have_property "EnableScriptBlockLogging" }
    its("EnableScriptBlockLogging") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.84.2_L1_Ensure_Turn_on_PowerShell_Transcription_is_set_to_Disabled" do
  title "(L1) Ensure 'Turn on PowerShell Transcription' is set to 'Disabled'"
  desc  "
    This Policy setting lets you capture the input and output of Windows PowerShell commands into text-based transcripts.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: If this setting is enabled there is a risk that passwords could get stored in plain text in the PowerShell_transcript output file.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription") do
    it { should have_property "EnableTranscripting" }
    its("EnableTranscripting") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.86.1.1_L1_Ensure_Allow_Basic_authentication_is_set_to_Disabled" do
  title "(L1) Ensure 'Allow Basic authentication' is set to 'Disabled'"
  desc  "
    This policy setting allows you to manage whether the Windows Remote Management (WinRM) client uses Basic authentication.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Basic authentication is less robust than other authentication methods available in WinRM because credentials including passwords are transmitted in plain text. An attacker who is able to capture packets on the network where WinRM is running may be able to determine the credentials used for accessing remote hosts via WinRM.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Client") do
    it { should have_property "AllowBasic" }
    its("AllowBasic") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.86.1.2_L1_Ensure_Allow_unencrypted_traffic_is_set_to_Disabled" do
  title "(L1) Ensure 'Allow unencrypted traffic' is set to 'Disabled'"
  desc  "
    This policy setting allows you to manage whether the Windows Remote Management (WinRM) client sends and receives unencrypted messages over the network.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Encrypting WinRM network traffic reduces the risk of an attacker viewing or modifying WinRM messages as they transit the network.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Client") do
    it { should have_property "AllowUnencryptedTraffic" }
    its("AllowUnencryptedTraffic") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.86.1.3_L1_Ensure_Disallow_Digest_authentication_is_set_to_Enabled" do
  title "(L1) Ensure 'Disallow Digest authentication' is set to 'Enabled'"
  desc  "
    This policy setting allows you to manage whether the Windows Remote Management (WinRM) client will not use Digest authentication.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: Digest authentication is less robust than other authentication methods available in WinRM, an attacker who is able to capture packets on the network where WinRM is running may be able to determine the credentials used for accessing remote hosts via WinRM.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Client") do
    it { should have_property "AllowDigest" }
    its("AllowDigest") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.86.2.1_L1_Ensure_Allow_Basic_authentication_is_set_to_Disabled" do
  title "(L1) Ensure 'Allow Basic authentication' is set to 'Disabled'"
  desc  "
    This policy setting allows you to manage whether the Windows Remote Management (WinRM) service accepts Basic authentication from a remote client.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Basic authentication is less robust than other authentication methods available in WinRM because credentials including passwords are transmitted in plain text. An attacker who is able to capture packets on the network where WinRM is running may be able to determine the credentials used for accessing remote hosts via WinRM.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service") do
    it { should have_property "AllowBasic" }
    its("AllowBasic") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.86.2.3_L1_Ensure_Allow_unencrypted_traffic_is_set_to_Disabled" do
  title "(L1) Ensure 'Allow unencrypted traffic' is set to 'Disabled'"
  desc  "
    This policy setting allows you to manage whether the Windows Remote Management (WinRM) service sends and receives unencrypted messages over the network.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Encrypting WinRM network traffic reduces the risk of an attacker viewing or modifying WinRM messages as they transit the network.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service") do
    it { should have_property "AllowUnencryptedTraffic" }
    its("AllowUnencryptedTraffic") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.86.2.4_L1_Ensure_Disallow_WinRM_from_storing_RunAs_credentials_is_set_to_Enabled" do
  title "(L1) Ensure 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled'"
  desc  "
    This policy setting allows you to manage whether the Windows Remote Management (WinRM) service will not allow RunAs credentials to be stored for any plug-ins.
    
    The recommended state for this setting is: Enabled.
    
    **Note:** If you enable and then disable this policy setting, any values that were previously configured for RunAsPassword will need to be reset.
    
    Rationale: Although the ability to store RunAs credentials is a convenient feature it increases the risk of account compromise slightly. For example, if you forget to lock your desktop before leaving it unattended for a few minutes another person could access not only the desktop of your computer but also any hosts you manage via WinRM with cached RunAs credentials.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service") do
    it { should have_property "DisableRunAs" }
    its("DisableRunAs") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.90.2_L1_Ensure_Configure_Automatic_Updates_is_set_to_Enabled" do
  title "(L1) Ensure 'Configure Automatic Updates' is set to 'Enabled'"
  desc  "
    This policy setting specifies whether computers in your environment will receive security updates from Windows Update or WSUS. If you configure this policy setting to Enabled, the operating system will recognize when a network connection is available and then use the network connection to search Windows Update or your designated intranet site for updates that apply to them.
    
    After you configure this policy setting to Enabled, select one of the following three options in the Configure Automatic Updates Properties dialog box to specify how the service will work: - Notify before downloading any updates and notify again before installing them. - Download the updates automatically and notify when they are ready to be installed. (Default setting) - Automatically download updates and install them on the schedule specified below.
    
    The recommended state for this setting is: Enabled.
    
    **Note:** The sub-setting \"**Configure automatic updating:**\" has 4 possible values &#x2013; all of them are valid depending on organizational needs, however if feasible we suggest using a value of 4 - Auto download and schedule the install. This suggestion is not a scored requirement.
    
    Rationale: Although each version of Windows is thoroughly tested before release, it is possible that problems will be discovered after the products are shipped. The Configure Automatic Updates setting can help you ensure that the computers in your environment will always have the most recent critical operating system updates and service packs installed.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU") do
    it { should have_property "NoAutoUpdate" }
    its("NoAutoUpdate") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.90.3_L1_Ensure_Configure_Automatic_Updates_Scheduled_install_day_is_set_to_0_-_Every_day" do
  title "(L1) Ensure 'Configure Automatic Updates: Scheduled install day' is set to '0 - Every day'"
  desc  "
    This policy setting specifies when computers in your environment will receive security updates from Windows Update or WSUS.
    
    The recommended state for this setting is: 0 - Every day.
    
    **Note:** This setting is only applicable if **4 - Auto download and schedule the install** is selected in 18.9.85.1. It will have no impact if any other option is selected.
    
    Rationale: Although each version of Windows is thoroughly tested before release, it is possible that problems will be discovered after the products are shipped. The Configure Automatic Updates setting can help you ensure that the computers in your environment will always have the most recent critical operating system updates and service packs installed.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU") do
    it { should have_property "ScheduledInstallDay" }
    its("ScheduledInstallDay") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_18.9.90.4_L1_Ensure_No_auto-restart_with_logged_on_users_for_scheduled_automatic_updates_installations_is_set_to_Disabled" do
  title "(L1) Ensure 'No auto-restart with logged on users for scheduled automatic updates installations' is set to 'Disabled'"
  desc  "
    This policy setting specifies that Automatic Updates will wait for computers to be restarted by the users who are logged on to them to complete a scheduled installation.
    
    The recommended state for this setting is: Disabled.
    
    **Note:** This setting applies only when you configure Automatic Updates to perform scheduled update installations. If you configure the Configure Automatic Updates setting to Disabled, this setting has no effect.
    
    Rationale: Sometimes updates require updated computers to be restarted to complete an installation. If the computer cannot restart automatically, then the most recent update will not completely install and no new updates will download to the computer until it is restarted.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU") do
    it { should have_property "NoAutoRebootWithLoggedOnUsers" }
    its("NoAutoRebootWithLoggedOnUsers") { should cmp == 0 }
  end
end
