control "xccdf_org.cisecurity.benchmarks_rule_9.1.1_L1_Ensure_Windows_Firewall_Domain_Firewall_state_is_set_to_On_recommended" do
  title "(L1) Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)'"
  desc  "
    Select On (recommended) to have Windows Firewall with Advanced Security use the settings for this profile to filter network traffic. If you select Off, Windows Firewall with Advanced Security will not use any of the firewall rules or connection security rules for this profile.
    
    The recommended state for this setting is: On (recommended).
    
    Rationale: If the firewall is turned off all traffic will be able to access the system and an attacker may be more easily able to remotely exploit a weakness in a network service.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile") do
    it { should have_property "EnableFirewall" }
    its("EnableFirewall") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.1.2_L1_Ensure_Windows_Firewall_Domain_Inbound_connections_is_set_to_Block_default" do
  title "(L1) Ensure 'Windows Firewall: Domain: Inbound connections' is set to 'Block (default)'"
  desc  "
    This setting determines the behavior for inbound connections that do not match an inbound firewall rule.
    
    The recommended state for this setting is: Block (default).
    
    Rationale: If the firewall allows all traffic to access the system then an attacker may be more easily able to remotely exploit a weakness in a network service.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile") do
    it { should have_property "DefaultInboundAction" }
    its("DefaultInboundAction") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.1.3_L1_Ensure_Windows_Firewall_Domain_Outbound_connections_is_set_to_Allow_default" do
  title "(L1) Ensure 'Windows Firewall: Domain: Outbound connections' is set to 'Allow (default)'"
  desc  "
    This setting determines the behavior for outbound connections that do not match an outbound firewall rule.
    
    The recommended state for this setting is: Allow (default).
    
    Rationale: Some people believe that it is prudent to block all outbound connections except those specifically approved by the user or administrator. Microsoft disagrees with this opinion, blocking outbound connections by default will force users to deal with a large number of dialog boxes prompting them to authorize or block applications such as their web browser or instant messaging software. Additionally, blocking outbound traffic has little value because if an attacker has compromised the system they can reconfigure the firewall anyway.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile") do
    it { should have_property "DefaultOutboundAction" }
    its("DefaultOutboundAction") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.1.4_L1_Ensure_Windows_Firewall_Domain_Settings_Display_a_notification_is_set_to_No" do
  title "(L1) Ensure 'Windows Firewall: Domain: Settings: Display a notification' is set to 'No'"
  desc  "
    Select this option to have Windows Firewall with Advanced Security display notifications to the user when a program is blocked from receiving inbound connections.
    
    The recommended state for this setting is: No.
    
    **Note:** When the Apply local firewall rules setting is configured to No, it's recommended to also configure the Display a notification setting to No. Otherwise, users will continue to receive messages that ask if they want to unblock a restricted inbound connection, but the user's response will be ignored.
    
    Rationale: Firewall notifications can be complex and may confuse the end users, who would not be able to address the alert.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile") do
    it { should have_property "DisableNotifications" }
    its("DisableNotifications") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.1.5_L1_Ensure_Windows_Firewall_Domain_Settings_Apply_local_firewall_rules_is_set_to_Yes_default" do
  title "(L1) Ensure 'Windows Firewall: Domain: Settings: Apply local firewall rules' is set to 'Yes (default)'"
  desc  "
    This setting controls whether local administrators are allowed to create local firewall rules that apply together with firewall rules configured by Group Policy.
    
    The recommended state for this setting is: Yes (default).
    
    Rationale: Users with administrative privileges might create firewall rules that expose the system to remote attack.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile") do
    it { should have_property "AllowLocalPolicyMerge" }
    its("AllowLocalPolicyMerge") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.1.6_L1_Ensure_Windows_Firewall_Domain_Settings_Apply_local_connection_security_rules_is_set_to_Yes_default" do
  title "(L1) Ensure 'Windows Firewall: Domain: Settings: Apply local connection security rules' is set to 'Yes (default)'"
  desc  "
    This setting controls whether local administrators are allowed to create connection security rules that apply together with connection security rules configured by Group Policy.
    
    The recommended state for this setting is: Yes (default).
    
    Rationale: Users with administrative privileges might create firewall rules that expose the system to remote attack.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile") do
    it { should have_property "AllowLocalIPsecPolicyMerge" }
    its("AllowLocalIPsecPolicyMerge") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.1.7_L1_Ensure_Windows_Firewall_Domain_Logging_Name_is_set_to_SYSTEMROOTSystem32logfilesfirewalldomainfw.log" do
  title "(L1) Ensure 'Windows Firewall: Domain: Logging: Name' is set to '%SYSTEMROOT%\\System32\\logfiles\\firewall\\domainfw.log'"
  desc  "
    Use this option to specify the path and name of the file in which Windows Firewall will write its log information.
    
    The recommended state for this setting is: %SYSTEMROOT%\\System32\\logfiles\\firewall\\domainfw.log.
    
    Rationale: If events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\Logging") do
    it { should have_property "LogFilePath" }
    its("LogFilePath") { should cmp "%SYSTEMROOT%\\System32\\logfiles\\firewall\\domainfw.log" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.1.8_L1_Ensure_Windows_Firewall_Domain_Logging_Size_limit_KB_is_set_to_16384_KB_or_greater" do
  title "(L1) Ensure 'Windows Firewall: Domain: Logging: Size limit (KB)' is set to '16,384 KB or greater'"
  desc  "
    Use this option to specify the size limit of the file in which Windows Firewall will write its log information.
    
    The recommended state for this setting is: 16,384 KB or greater.
    
    Rationale: If events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\Logging") do
    it { should have_property "LogFileSize" }
    its("LogFileSize") { should cmp >= 16384 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.1.9_L1_Ensure_Windows_Firewall_Domain_Logging_Log_dropped_packets_is_set_to_Yes" do
  title "(L1) Ensure 'Windows Firewall: Domain: Logging: Log dropped packets' is set to 'Yes'"
  desc  "
    Use this option to log when Windows Firewall with Advanced Security discards an inbound packet for any reason. The log records why and when the packet was dropped. Look for entries with the word DROP in the action column of the log.
    
    The recommended state for this setting is: Yes.
    
    Rationale: If events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\Logging") do
    it { should have_property "LogDroppedPackets" }
    its("LogDroppedPackets") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.1.10_L1_Ensure_Windows_Firewall_Domain_Logging_Log_successful_connections_is_set_to_Yes" do
  title "(L1) Ensure 'Windows Firewall: Domain: Logging: Log successful connections' is set to 'Yes'"
  desc  "
    Use this option to log when Windows Firewall with Advanced Security allows an inbound connection. The log records why and when the connection was formed. Look for entries with the word ALLOW in the action column of the log.
    
    The recommended state for this setting is: Yes.
    
    Rationale: If events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\Logging") do
    it { should have_property "LogSuccessfulConnections" }
    its("LogSuccessfulConnections") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.1_L1_Ensure_Windows_Firewall_Private_Firewall_state_is_set_to_On_recommended" do
  title "(L1) Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)'"
  desc  "
    Select On (recommended) to have Windows Firewall with Advanced Security use the settings for this profile to filter network traffic. If you select Off, Windows Firewall with Advanced Security will not use any of the firewall rules or connection security rules for this profile.
    
    The recommended state for this setting is: On (recommended).
    
    Rationale: If the firewall is turned off all traffic will be able to access the system and an attacker may be more easily able to remotely exploit a weakness in a network service.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile") do
    it { should have_property "EnableFirewall" }
    its("EnableFirewall") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.2_L1_Ensure_Windows_Firewall_Private_Inbound_connections_is_set_to_Block_default" do
  title "(L1) Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block (default)'"
  desc  "
    This setting determines the behavior for inbound connections that do not match an inbound firewall rule.
    
    The recommended state for this setting is: Block (default).
    
    Rationale: If the firewall allows all traffic to access the system then an attacker may be more easily able to remotely exploit a weakness in a network service.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile") do
    it { should have_property "DefaultInboundAction" }
    its("DefaultInboundAction") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.3_L1_Ensure_Windows_Firewall_Private_Outbound_connections_is_set_to_Allow_default" do
  title "(L1) Ensure 'Windows Firewall: Private: Outbound connections' is set to 'Allow (default)'"
  desc  "
    This setting determines the behavior for outbound connections that do not match an outbound firewall rule.
    
    The recommended state for this setting is: Allow (default).
    
    **Note:** If you set Outbound connections to Block and then deploy the firewall policy by using a GPO, computers that receive the GPO settings cannot receive subsequent Group Policy updates unless you create and deploy an outbound rule that enables Group Policy to work. Predefined rules for Core Networking include outbound rules that enable Group Policy to work. Ensure that these outbound rules are active, and thoroughly test firewall profiles before deploying.
    
    Rationale: Some people believe that it is prudent to block all outbound connections except those specifically approved by the user or administrator. Microsoft disagrees with this opinion, blocking outbound connections by default will force users to deal with a large number of dialog boxes prompting them to authorize or block applications such as their web browser or instant messaging software. Additionally, blocking outbound traffic has little value because if an attacker has compromised the system they can reconfigure the firewall anyway.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile") do
    it { should have_property "DefaultOutboundAction" }
    its("DefaultOutboundAction") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.4_L1_Ensure_Windows_Firewall_Private_Settings_Display_a_notification_is_set_to_No" do
  title "(L1) Ensure 'Windows Firewall: Private: Settings: Display a notification' is set to 'No'"
  desc  "
    Select this option to have Windows Firewall with Advanced Security display notifications to the user when a program is blocked from receiving inbound connections.
    
    The recommended state for this setting is: No.
    
    **Note:** When the Apply local firewall rules setting is configured to No, it's recommended to also configure the Display a notification setting to No. Otherwise, users will continue to receive messages that ask if they want to unblock a restricted inbound connection, but the user's response will be ignored.
    
    Rationale: Firewall notifications can be complex and may confuse the end users, who would not be able to address the alert.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile") do
    it { should have_property "DisableNotifications" }
    its("DisableNotifications") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.5_L1_Ensure_Windows_Firewall_Private_Settings_Apply_local_firewall_rules_is_set_to_Yes_default" do
  title "(L1) Ensure 'Windows Firewall: Private: Settings: Apply local firewall rules' is set to 'Yes (default)'"
  desc  "
    This setting controls whether local administrators are allowed to create local firewall rules that apply together with firewall rules configured by Group Policy.
    
    The recommended state for this setting is: Yes (default).
    
    Rationale: Users with administrative privileges might create firewall rules that expose the system to remote attack.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile") do
    it { should have_property "AllowLocalPolicyMerge" }
    its("AllowLocalPolicyMerge") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.6_L1_Ensure_Windows_Firewall_Private_Settings_Apply_local_connection_security_rules_is_set_to_Yes_default" do
  title "(L1) Ensure 'Windows Firewall: Private: Settings: Apply local connection security rules' is set to 'Yes (default)'"
  desc  "
    This setting controls whether local administrators are allowed to create connection security rules that apply together with connection security rules configured by Group Policy.
    
    The recommended state for this setting is: Yes (default).
    
    Rationale: Users with administrative privileges might create firewall rules that expose the system to remote attack.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile") do
    it { should have_property "AllowLocalIPsecPolicyMerge" }
    its("AllowLocalIPsecPolicyMerge") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.7_L1_Ensure_Windows_Firewall_Private_Logging_Name_is_set_to_SYSTEMROOTSystem32logfilesfirewallprivatefw.log" do
  title "(L1) Ensure 'Windows Firewall: Private: Logging: Name' is set to '%SYSTEMROOT%\\System32\\logfiles\\firewall\\privatefw.log'"
  desc  "
    Use this option to specify the path and name of the file in which Windows Firewall will write its log information.
    
    The recommended state for this setting is: %SYSTEMROOT%\\System32\\logfiles\\firewall\\privatefw.log.
    
    Rationale: If events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile\\Logging") do
    it { should have_property "LogFilePath" }
    its("LogFilePath") { should cmp "%SYSTEMROOT%\\System32\\logfiles\\firewall\\privatefw.log" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.8_L1_Ensure_Windows_Firewall_Private_Logging_Size_limit_KB_is_set_to_16384_KB_or_greater" do
  title "(L1) Ensure 'Windows Firewall: Private: Logging: Size limit (KB)' is set to '16,384 KB or greater'"
  desc  "
    Use this option to specify the size limit of the file in which Windows Firewall will write its log information.
    
    The recommended state for this setting is: 16,384 KB or greater.
    
    Rationale: If events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile\\Logging") do
    it { should have_property "LogFileSize" }
    its("LogFileSize") { should cmp >= 16384 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.9_L1_Ensure_Windows_Firewall_Private_Logging_Log_dropped_packets_is_set_to_Yes" do
  title "(L1) Ensure 'Windows Firewall: Private: Logging: Log dropped packets' is set to 'Yes'"
  desc  "
    Use this option to log when Windows Firewall with Advanced Security discards an inbound packet for any reason. The log records why and when the packet was dropped. Look for entries with the word DROP in the action column of the log.
    
    The recommended state for this setting is: Yes.
    
    Rationale: If events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile\\Logging") do
    it { should have_property "LogDroppedPackets" }
    its("LogDroppedPackets") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.2.10_L1_Ensure_Windows_Firewall_Private_Logging_Log_successful_connections_is_set_to_Yes" do
  title "(L1) Ensure 'Windows Firewall: Private: Logging: Log successful connections' is set to 'Yes'"
  desc  "
    Use this option to log when Windows Firewall with Advanced Security allows an inbound connection. The log records why and when the connection was formed. Look for entries with the word ALLOW in the action column of the log.
    
    The recommended state for this setting is: Yes.
    
    Rationale: If events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile\\Logging") do
    it { should have_property "LogSuccessfulConnections" }
    its("LogSuccessfulConnections") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.3.1_L1_Ensure_Windows_Firewall_Public_Firewall_state_is_set_to_On_recommended" do
  title "(L1) Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'"
  desc  "
    Select On (recommended) to have Windows Firewall with Advanced Security use the settings for this profile to filter network traffic. If you select Off, Windows Firewall with Advanced Security will not use any of the firewall rules or connection security rules for this profile.
    
    The recommended state for this setting is: On (recommended).
    
    Rationale: If the firewall is turned off all traffic will be able to access the system and an attacker may be more easily able to remotely exploit a weakness in a network service.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile") do
    it { should have_property "EnableFirewall" }
    its("EnableFirewall") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.3.2_L1_Ensure_Windows_Firewall_Public_Inbound_connections_is_set_to_Block_default" do
  title "(L1) Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block (default)'"
  desc  "
    This setting determines the behavior for inbound connections that do not match an inbound firewall rule.
    
    The recommended state for this setting is: Block (default).
    
    Rationale: If the firewall allows all traffic to access the system then an attacker may be more easily able to remotely exploit a weakness in a network service.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile") do
    it { should have_property "DefaultInboundAction" }
    its("DefaultInboundAction") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.3.3_L1_Ensure_Windows_Firewall_Public_Outbound_connections_is_set_to_Allow_default" do
  title "(L1) Ensure 'Windows Firewall: Public: Outbound connections' is set to 'Allow (default)'"
  desc  "
    This setting determines the behavior for outbound connections that do not match an outbound firewall rule.
    
    The recommended state for this setting is: Allow (default).
    
    **Note:** If you set Outbound connections to Block and then deploy the firewall policy by using a GPO, computers that receive the GPO settings cannot receive subsequent Group Policy updates unless you create and deploy an outbound rule that enables Group Policy to work. Predefined rules for Core Networking include outbound rules that enable Group Policy to work. Ensure that these outbound rules are active, and thoroughly test firewall profiles before deploying.
    
    Rationale: Some people believe that it is prudent to block all outbound connections except those specifically approved by the user or administrator. Microsoft disagrees with this opinion, blocking outbound connections by default will force users to deal with a large number of dialog boxes prompting them to authorize or block applications such as their web browser or instant messaging software. Additionally, blocking outbound traffic has little value because if an attacker has compromised the system they can reconfigure the firewall anyway.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile") do
    it { should have_property "DefaultOutboundAction" }
    its("DefaultOutboundAction") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.3.4_L1_Ensure_Windows_Firewall_Public_Settings_Display_a_notification_is_set_to_Yes" do
  title "(L1) Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'Yes'"
  desc  "
    Select this option to have Windows Firewall with Advanced Security display notifications to the user when a program is blocked from receiving inbound connections.
    
    The recommended state for this setting is: Yes.
    
    **Note:** When the Apply local firewall rules setting is configured to Yes, it is also recommended to also configure the Display a notification setting to Yes. Otherwise, users will not receive messages that ask if they want to unblock a restricted inbound connection.
    
    Rationale: Some organizations may prefer to avoid alarming users when firewall rules block certain types of network activity. However, notifications can be helpful when troubleshooting network issues involving the firewall.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile") do
    it { should have_property "DisableNotifications" }
    its("DisableNotifications") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.3.5_L1_Ensure_Windows_Firewall_Public_Settings_Apply_local_firewall_rules_is_set_to_No" do
  title "(L1) Ensure 'Windows Firewall: Public: Settings: Apply local firewall rules' is set to 'No'"
  desc  "
    This setting controls whether local administrators are allowed to create local firewall rules that apply together with firewall rules configured by Group Policy.
    
    The recommended state for this setting is: No.
    
    Rationale: When in the Public profile, there should be no special local firewall exceptions per computer. These settings should be managed by a centralized policy.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile") do
    it { should have_property "AllowLocalPolicyMerge" }
    its("AllowLocalPolicyMerge") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.3.6_L1_Ensure_Windows_Firewall_Public_Settings_Apply_local_connection_security_rules_is_set_to_No" do
  title "(L1) Ensure 'Windows Firewall: Public: Settings: Apply local connection security rules' is set to 'No'"
  desc  "
    This setting controls whether local administrators are allowed to create connection security rules that apply together with connection security rules configured by Group Policy.
    
    The recommended state for this setting is: No.
    
    Rationale: Users with administrative privileges might create firewall rules that expose the system to remote attack.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile") do
    it { should have_property "AllowLocalIPsecPolicyMerge" }
    its("AllowLocalIPsecPolicyMerge") { should cmp == 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.3.7_L1_Ensure_Windows_Firewall_Public_Logging_Name_is_set_to_SYSTEMROOTSystem32logfilesfirewallpublicfw.log" do
  title "(L1) Ensure 'Windows Firewall: Public: Logging: Name' is set to '%SYSTEMROOT%\\System32\\logfiles\\firewall\\publicfw.log'"
  desc  "
    Use this option to specify the path and name of the file in which Windows Firewall will write its log information.
    
    The recommended state for this setting is: %SYSTEMROOT%\\System32\\logfiles\\firewall\\publicfw.log.
    
    Rationale: If events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile\\Logging") do
    it { should have_property "LogFilePath" }
    its("LogFilePath") { should cmp "%systemroot%\\system32\\logfiles\\firewall\\publicfw.log" }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.3.8_L1_Ensure_Windows_Firewall_Public_Logging_Size_limit_KB_is_set_to_16384_KB_or_greater" do
  title "(L1) Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' is set to '16,384 KB or greater'"
  desc  "
    Use this option to specify the size limit of the file in which Windows Firewall will write its log information.
    
    The recommended state for this setting is: 16,384 KB or greater.
    
    Rationale: If events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile\\Logging") do
    it { should have_property "LogFileSize" }
    its("LogFileSize") { should cmp >= 16384 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.3.9_L1_Ensure_Windows_Firewall_Public_Logging_Log_dropped_packets_is_set_to_Yes" do
  title "(L1) Ensure 'Windows Firewall: Public: Logging: Log dropped packets' is set to 'Yes'"
  desc  "
    Use this option to log when Windows Firewall with Advanced Security discards an inbound packet for any reason. The log records why and when the packet was dropped. Look for entries with the word DROP in the action column of the log.
    
    The recommended state for this setting is: Yes.
    
    Rationale: If events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile\\Logging") do
    it { should have_property "LogDroppedPackets" }
    its("LogDroppedPackets") { should cmp == 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_9.3.10_L1_Ensure_Windows_Firewall_Public_Logging_Log_successful_connections_is_set_to_Yes" do
  title "(L1) Ensure 'Windows Firewall: Public: Logging: Log successful connections' is set to 'Yes'"
  desc  "
    Use this option to log when Windows Firewall with Advanced Security allows an inbound connection. The log records why and when the connection was formed. Look for entries with the word ALLOW in the action column of the log.
    
    The recommended state for this setting is: Yes.
    
    Rationale: If events are not recorded it may be difficult or impossible to determine the root cause of system problems or the unauthorized activities of malicious users.
  "
  impact 1.0
  describe registry_key("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile\\Logging") do
    it { should have_property "LogSuccessfulConnections" }
    its("LogSuccessfulConnections") { should cmp == 1 }
  end
end
