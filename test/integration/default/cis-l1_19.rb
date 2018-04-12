control "xccdf_org.cisecurity.benchmarks_rule_19.1.3.1_L1_Ensure_Enable_screen_saver_is_set_to_Enabled" do
  title "(L1) Ensure 'Enable screen saver' is set to 'Enabled'"
  desc  "
    This policy setting enables/disables the use of desktop screen savers.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: If a user forgets to lock their computer when they walk away it's possible that a passerby will hijack it.
  "
  impact 1.0
  registry_key({hive: 'HKEY_USERS'}).children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}$/).map { |x| x.to_s + "\\Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop" }.each do |entry|
    describe registry_key(entry) do
      it { should have_property "ScreenSaveActive" }
      its("ScreenSaveActive") { should eq "1" }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_19.1.3.2_L1_Ensure_Force_specific_screen_saver_Screen_saver_executable_name_is_set_to_Enabled_scrnsave.scr" do
  title "(L1) Ensure 'Force specific screen saver: Screen saver executable name' is set to 'Enabled: scrnsave.scr'"
  desc  "
    This policy setting specifies the screen saver for the user's desktop.
    
    The recommended state for this setting is: Enabled: scrnsave.scr.
    
    **Note:** If the specified screen saver is not installed on a computer to which this setting applies, the setting is ignored.
    
    Rationale: If a user forgets to lock their computer when they walk away it's possible that a passerby will hijack it.
  "
  impact 1.0
  registry_key({hive: 'HKEY_USERS'}).children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}$/).map { |x| x.to_s + "\\Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop" }.each do |entry|
    describe registry_key(entry) do
      it { should have_property "SCRNSAVE.EXE" }
#      its("SCRNSAVE.EXE") { should eq "scrnsave.scr" }
      it { should have_property_value('SCRNSAVE.EXE', :string, 'scrnsave.scr') }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_19.1.3.3_L1_Ensure_Password_protect_the_screen_saver_is_set_to_Enabled" do
  title "(L1) Ensure 'Password protect the screen saver' is set to 'Enabled'"
  desc  "
    This setting determines whether screen savers used on the computer are password protected.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: If a user forgets to lock their computer when they walk away it is possible that a passerby will hijack it.
  "
  impact 1.0
  registry_key({hive: 'HKEY_USERS'}).children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}$/).map { |x| x.to_s + "\\Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop" }.each do |entry|
    describe registry_key(entry) do
      it { should have_property "ScreenSaverIsSecure" }
      its("ScreenSaverIsSecure") { should eq "1" }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_19.1.3.4_L1_Ensure_Screen_saver_timeout_is_set_to_Enabled_900_seconds_or_fewer_but_not_0" do
  title "(L1) Ensure 'Screen saver timeout' is set to 'Enabled: 900 seconds or fewer, but not 0'"
  desc  "
    This setting specifies how much user idle time must elapse before the screen saver is launched.
    
    The recommended state for this setting is: Enabled: 900 seconds or fewer, but not 0.
    
    **Note:** This setting has no effect under the following circumstances: - The wait time is set to zero - The \"Enable Screen Saver\" setting is disabled - A valid screen saver is not selected manually or via the \"Screen saver executable name\" setting
    
    Rationale: If a user forgets to lock their computer when they walk away it is possible that a passerby will hijack it.
  "
  impact 1.0
  registry_key({hive: 'HKEY_USERS'}).children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}$/).map { |x| x.to_s + "\\Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop" }.each do |entry|
    describe registry_key(entry) do
      it { should have_property "ScreenSaveTimeOut" }
      its("ScreenSaveTimeOut") { should cmp <= 900 }
    end
  end
  registry_key({hive: 'HKEY_USERS'}).children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}$/).map { |x| x.to_s + "\\Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop" }.each do |entry|
    describe registry_key(entry) do
      it { should have_property "ScreenSaveTimeOut" }
      its("ScreenSaveTimeOut") { should cmp =! 0 }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_19.5.1.1_L1_Ensure_Turn_off_toast_notifications_on_the_lock_screen_is_set_to_Enabled" do
  title "(L1) Ensure 'Turn off toast notifications on the lock screen' is set to 'Enabled'"
  desc  "
    This policy setting turns off toast notifications on the lock screen.
    
    The recommended state for this setting is Enabled.
    
    Rationale: While this feature can be handy for users applications that provide toast notifications might display sensitive personal or business data while the device is unattended.
  "
  impact 1.0
  registry_key({hive: 'HKEY_USERS'}).children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}$/).map { |x| x.to_s + "\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\PushNotifications" }.each do |entry|
    describe registry_key(entry) do
      it { should have_property "NoToastApplicationNotificationOnLockScreen" }
      its("NoToastApplicationNotificationOnLockScreen") { should cmp == 1 }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_19.7.4.1_L1_Ensure_Do_not_preserve_zone_information_in_file_attachments_is_set_to_Disabled" do
  title "(L1) Ensure 'Do not preserve zone information in file attachments' is set to 'Disabled'"
  desc  "
    This policy setting allows you to manage whether Windows marks file attachments with information about their zone of origin (such as restricted, Internet, intranet, local). This requires NTFS in order to function correctly, and will fail without notice on FAT32. By not preserving the zone information, Windows cannot make proper risk assessments.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: A file that is downloaded from a computer in the Internet or Restricted Sites zone may be moved to a location that makes it appear safe, like an intranet file share, and executed by an unsuspecting user.
  "
  impact 1.0
  registry_key({hive: 'HKEY_USERS'}).children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}$/).map { |x| x.to_s + "\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments" }.each do |entry|
    describe registry_key(entry) do
      it { should have_property "SaveZoneInformation" }
      its("SaveZoneInformation") { should cmp == 2 }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_19.7.4.2_L1_Ensure_Notify_antivirus_programs_when_opening_attachments_is_set_to_Enabled" do
  title "(L1) Ensure 'Notify antivirus programs when opening attachments' is set to 'Enabled'"
  desc  "
    This policy setting allows you to manage the behavior for notifying registered antivirus programs. If multiple programs are registered, they will all be notified.
    
    The recommended state for this setting is: Enabled.
    
    **Note:** An updated antivirus program must be installed for this policy setting to function properly.
    
    Rationale: Antivirus programs that do not perform on-access checks may not be able to scan downloaded files.
  "
  impact 1.0
  registry_key({hive: 'HKEY_USERS'}).children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}$/).map { |x| x.to_s + "\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments" }.each do |entry|
    describe registry_key(entry) do
      it { should have_property "ScanWithAntiVirus" }
      its("ScanWithAntiVirus") { should cmp == 3 }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_19.7.26.1_L1_Ensure_Prevent_users_from_sharing_files_within_their_profile._is_set_to_Enabled" do
  title "(L1) Ensure 'Prevent users from sharing files within their profile.' is set to 'Enabled'"
  desc  "
    This policy setting specifies whether users can share files within their profile. By default users are allowed to share files within their profile to other users on their network after an administrator opts in the computer. An administrator can opt in the computer by using the sharing wizard to share a file within their profile.
    
    The recommended state for this setting is: Enabled.
    
    Rationale: If not properly controlled a user could accidentally share sensitive data with unauthorized users. In a corporate environment, the company should provide a managed location for file sharing, such as a file server or SharePoint.
  "
  impact 1.0
  registry_key({hive: 'HKEY_USERS'}).children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}$/).map { |x| x.to_s + "\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" }.each do |entry|
    describe registry_key(entry) do
      it { should have_property "NoInplaceSharing" }
      its("NoInplaceSharing") { should cmp == 1 }
    end
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_19.7.39.1_L1_Ensure_Always_install_with_elevated_privileges_is_set_to_Disabled" do
  title "(L1) Ensure 'Always install with elevated privileges' is set to 'Disabled'"
  desc  "
    This setting controls whether or not Windows Installer should use system permissions when it installs any program on the system.
    
    **Note:** This setting appears both in the Computer Configuration and User Configuration folders. To make this setting effective, you must enable the setting in both folders.
    
    **Caution:** If enabled, skilled users can take advantage of the permissions this setting grants to change their privileges and gain permanent access to restricted files and folders. Note that the User Configuration version of this setting is not guaranteed to be secure.
    
    The recommended state for this setting is: Disabled.
    
    Rationale: Users with limited privileges can exploit this feature by creating a Windows Installer installation package that creates a new local account that belongs to the local built-in Administrators group, adds their current account to the local built-in Administrators group, installs malicious software, or performs other unauthorized activities.
  "
  impact 1.0
  registry_key({hive: 'HKEY_USERS'}).children(/^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]{3,}$/).map { |x| x.to_s + "\\Software\\Policies\\Microsoft\\Windows\\Installer" }.each do |entry|
    describe registry_key(entry) do
      it { should have_property "AlwaysInstallElevated" }
      its("AlwaysInstallElevated") { should cmp == 0 }
    end
  end
end
