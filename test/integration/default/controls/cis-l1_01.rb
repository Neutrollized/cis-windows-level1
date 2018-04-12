title 'CIS-WIN2012R2-L1_ANSIBLE_ROLE'

control "xccdf_org.cisecurity.benchmarks_rule_1.1.1_L1_Ensure_Enforce_password_history_is_set_to_24_or_more_passwords" do
  title "(L1) Ensure 'Enforce password history' is set to '24 or more password(s)'"
  desc  "
    This policy setting determines the number of renewed, unique passwords that have to be associated with a user account before you can reuse an old password. The value for this policy setting must be betw
een 0 and 24 passwords. The default value for Windows Vista is 0 passwords, but the default setting in a domain is 24 passwords. To maintain the effectiveness of this policy setting, use the Minimum passwor
d age setting to prevent users from repeatedly changing their password.

    The recommended state for this setting is: 24 or more password(s).

    Rationale: The longer a user uses the same password, the greater the chance that an attacker can determine the password through brute force attacks. Also, any accounts that may have been compromised wil
l remain exploitable for as long as the password is left unchanged. If password changes are required but password reuse is not prevented, or if users continually reuse a small number of passwords, the effec
tiveness of a good password policy is greatly reduced.

    If you specify a low number for this policy setting, users will be able to use the same small number of passwords repeatedly. If you do not also configure the Minimum password age setting, users might r
epeatedly change their passwords until they can reuse their original password.
  "
  impact 1.0
  describe security_policy do
    its("PasswordHistorySize") { should be >= 24 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.2_L1_Ensure_Maximum_password_age_is_set_to_60_or_fewer_days_but_not_0" do
  title "(L1) Ensure 'Maximum password age' is set to '60 or fewer days, but not 0'"
  desc  "
    This policy setting defines how long a user can use their password before it expires.

    Values for this policy setting range from 0 to 999 days. If you set the value to 0, the password will never expire.

    Because attackers can crack passwords, the more frequently you change the password the less opportunity an attacker has to use a cracked password. However, the lower this value is set, the higher the potential for an increase in calls to help desk support due to users having to change their password or forgetting which password is current.

    The recommended state for this setting is 60 or fewer days, but not 0.

    Rationale: The longer a password exists the higher the likelihood that it will be compromised by a brute force attack, by an attacker gaining general knowledge about the user, or by the user sharing the password. Configuring the Maximum password age setting to 0 so that users are never required to change their passwords is a major security risk because that allows a compromised password to be used by the malicious user for as long as the valid user is authorized access.
  "
  impact 1.0
  describe security_policy do
    its("MaximumPasswordAge") { should be <= 60 }
  end
  describe security_policy do
    its("MaximumPasswordAge") { should be > 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.3_L1_Ensure_Minimum_password_age_is_set_to_1_or_more_days" do
  title "(L1) Ensure 'Minimum password age' is set to '1 or more day(s)'"
  desc  "
    This policy setting determines the number of days that you must use a password before you can change it. The range of values for this policy setting is between 1 and 999 days. (You may also set the value to 0 to allow immediate password changes.) The default value for this setting is 0 days.

    The recommended state for this setting is: 1 or more day(s).

    Rationale: Users may have favorite passwords that they like to use because they are easy to remember and they believe that their password choice is secure from compromise. Unfortunately, passwords are compromised and if an attacker is targeting a specific individual user account, with foreknowledge of data about that user, reuse of old passwords can cause a security breach. To address password reuse a combination of security settings is required. Using this policy setting with the Enforce password history setting prevents the easy reuse of old passwords. For example, if you configure the Enforce password history setting to ensure that users cannot reuse any of their last 12 passwords, they could change their password 13 times in a few minutes and reuse the password they started with, unless you also configure the Minimum password age setting to a number that is greater than 0. You must configure this policy setting to a number that is greater than 0 for the Enforce password history setting to be effective.
  "
  impact 1.0
  describe security_policy do
    its("MinimumPasswordAge") { should be >= 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.4_L1_Ensure_Minimum_password_length_is_set_to_14_or_more_characters" do
  title "(L1) Ensure 'Minimum password length' is set to '14 or more character(s)'"
  desc  "
    This policy setting determines the least number of characters that make up a password for a user account. There are many different theories about how to determine the best password length for an organization, but perhaps \"pass phrase\" is a better term than \"password.\" In Microsoft Windows 2000 or later, pass phrases can be quite long and can include spaces. Therefore, a phrase such as \"I want to drink a $5 milkshake\" is a valid pass phrase; it is a considerably stronger password than an 8 or 10 character string of random numbers and letters, and yet is easier to remember. Users must be educated about the proper selection and maintenance of passwords, especially with regard to password length. In enterprise environments, the ideal value for the Minimum password length setting is 14 characters, however you should adjust this value to meet your organization's business requirements.

    The recommended state for this setting is: 14 or more character(s).

    Rationale: Types of password attacks include dictionary attacks (which attempt to use common words and phrases) and brute force attacks (which try every possible combination of characters). Also, attackers sometimes try to obtain the account database so they can use tools to discover the accounts and passwords.
  "
  impact 1.0
  describe security_policy do
    its("MinimumPasswordLength") { should be >= 14 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.5_L1_Ensure_Password_must_meet_complexity_requirements_is_set_to_Enabled" do
  title "(L1) Ensure 'Password must meet complexity requirements' is set to 'Enabled'"
  desc  "
    This policy setting checks all new passwords to ensure that they meet basic requirements for strong passwords.

    When this policy is enabled, passwords must meet the following minimum requirements: - Not contain the user's account name or parts of the user's full name that exceed two consecutive characters - Be at least six characters in length - Contain characters from three of the following four categories: - English uppercase characters (A through Z) - English lowercase characters (a through z) - Base 10 digits (0 through 9) - Non-alphabetic characters (for example, !, $, #, %) - A catch-all category of any Unicode character that does not fall under the previous four categories. This fifth category can be regionally specific.

    Each additional character in a password increases its complexity exponentially. For instance, a seven-character, all lower-case alphabetic password would have 267 (approximately 8 x 109 or 8 billion) possible combinations. At 1,000,000 attempts per second (a capability of many password-cracking utilities), it would only take 133 minutes to crack. A seven-character alphabetic password with case sensitivity has 527 combinations. A seven-character case-sensitive alphanumeric password without punctuation has 627 combinations. An eight-character password has 268 (or 2 x 1011) possible combinations. Although this might seem to be a large number, at 1,000,000 attempts per second it would take only 59 hours to try all possible passwords. Remember, these times will significantly increase for passwords that use ALT characters and other special keyboard characters such as \"!\" or \"@\". Proper use of the password settings can help make it difficult to mount a brute force attack.

    The recommended state for this setting is: Enabled.

    Rationale: Passwords that contain only alphanumeric characters are extremely easy to discover with several publicly available tools.
  "
  impact 1.0
  describe security_policy do
    its("PasswordComplexity") { should eq 1 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.1.6_L1_Ensure_Store_passwords_using_reversible_encryption_is_set_to_Disabled" do
  title "(L1) Ensure 'Store passwords using reversible encryption' is set to 'Disabled'"
  desc  "
    This policy setting determines whether the operating system stores passwords in a way that uses reversible encryption, which provides support for application protocols that require knowledge of the user's password for authentication purposes. Passwords that are stored with reversible encryption are essentially the same as plaintext versions of the passwords.

    The recommended state for this setting is: Disabled.

    Rationale: Enabling this policy setting allows the operating system to store passwords in a weaker format that is much more susceptible to compromise and weakens your system security.
  "
  impact 1.0
  describe security_policy do
    its("ClearTextPassword") { should eq 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.2.1_L1_Ensure_Account_lockout_duration_is_set_to_15_or_more_minutes" do
  title "(L1) Ensure 'Account lockout duration' is set to '15 or more minute(s)'"
  desc  "
    This policy setting determines the length of time that must pass before a locked account is unlocked and a user can try to log on again. The setting does this by specifying the number of minutes a locked out account will remain unavailable. If the value for this policy setting is configured to 0, locked out accounts will remain locked out until an administrator manually unlocks them.

    Although it might seem like a good idea to configure the value for this policy setting to a high value, such a configuration will likely increase the number of calls that the help desk receives to unlock accounts locked by mistake. Users should be aware of the length of time a lock remains in place, so that they realize they only need to call the help desk if they have an extremely urgent need to regain access to their computer.

    The recommended state for this setting is: 15 or more minute(s).

    Rationale: A denial of service (DoS) condition can be created if an attacker abuses the Account lockout threshold and repeatedly attempts to log on with a specific account. Once you configure the Account lockout threshold setting, the account will be locked out after the specified number of failed attempts. If you configure the Account lockout duration setting to 0, then the account will remain locked out until an administrator unlocks it manually.
  "
  impact 1.0
  describe security_policy do
    its("LockoutDuration") { should be >= 900 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.2.2_L1_Ensure_Account_lockout_threshold_is_set_to_10_or_fewer_invalid_logon_attempts_but_not_0" do
  title "(L1) Ensure 'Account lockout threshold' is set to '10 or fewer invalid logon attempt(s), but not 0'"
  desc  "
    This policy setting determines the number of failed logon attempts before the account is locked. Setting this policy to 0 does not conform with the benchmark as doing so disables the account lockout threshold.

    The recommended state for this setting is: 10 or fewer invalid logon attempt(s), but not 0.

    Rationale: Setting an account lockout threshold reduces the likelihood that an online password brute force attack will be successful. Setting the account lockout threshold too low introduces risk of increased accidental lockouts and/or a malicious actor intentionally locking out accounts.
  "
  impact 1.0
  describe security_policy do
    its("LockoutBadCount") { should be <= 10 }
  end
  describe security_policy do
    its("LockoutBadCount") { should be > 0 }
  end
end

control "xccdf_org.cisecurity.benchmarks_rule_1.2.3_L1_Ensure_Reset_account_lockout_counter_after_is_set_to_15_or_more_minutes" do
  title "(L1) Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'"
  desc  "
    This policy setting determines the length of time before the Account lockout threshold resets to zero. The default value for this policy setting is Not Defined. If the Account lockout threshold is defined, this reset time must be less than or equal to the value for the Account lockout duration setting.

    If you leave this policy setting at its default value or configure the value to an interval that is too long, your environment could be vulnerable to a DoS attack. An attacker could maliciously perform a number of failed logon attempts on all users in the organization, which will lock out their accounts. If no policy were determined to reset the account lockout, it would be a manual task for administrators. Conversely, if a reasonable time value is configured for this policy setting, users would be locked out for a set period until all of the accounts are unlocked automatically.

    The recommended state for this setting is: 15 or more minute(s).

    Rationale: Users can accidentally lock themselves out of their accounts if they mistype their password multiple times. To reduce the chance of such accidental lockouts, the Reset account lockout counter after setting determines the number of minutes that must elapse before the counter that tracks failed logon attempts and triggers lockouts is reset to 0.
  "
  impact 1.0
  describe security_policy do
    its("ResetLockoutCount") { should be >= 0 }
  end
end
