# cis-windows-level1

This role sets up Cis-windows-level1

Created for and tested on Windows 2012R2 

Should work for Windows 2016 (untested)


## Requirements

Requires Ansible 2.5+ as the `win_audit_policy_system` module is required and it's new in 2.5


## Notes & Rule Omittance

My testing was done on a Windows 2012R2 Vagrant box I built using [this](https://github.com/Neutrollized/packer-windows)

Inspec controls taken from Chef Automate's CIS Windows Level 1 profile.
- some of inspec 'describe' statements were modified (read as: fixed).  I've left the original rule in the control commented out (and my modified/corrected one underneath it)

- 2.3.1.5 Administrator account was not renamed; changed to disabled

- 2.3.1.6 Guest account was not renamed; changed disabled

- 18.6.1: LocalAccountTokenFilterPolicy was not set to 0 as I use a local user to WinRM into run the ansible role so if that gets set to 1 then the role breaks

- 2.2.x: User Rights rules moved to the end as setting them early will prevent some of the other changes in the "later" rules sets from being applied due to stripped rights

Rules for 19.x.x aren't run as they modify HKEY_USERS and that's apparently not allowed :( And as such, the Inspec controls are in the test/integration/default/ folder rather than in controls/ (easier than commenting out the rules)


# Maintainer

Glen Yu

# E-mail

glen.yu@gmail.com

# License

MIT
