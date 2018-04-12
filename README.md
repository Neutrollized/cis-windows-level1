# cis-windows-level1

This role sets up Cis-windows-level1

## TODOs

still have a few things I need to fix but it's 95%+ done


## Notes

Inspec controls taken from Chef Automate's CIS Windows Level 1 profile.
- some of inspec 'describe' statements were modified (read as: fixed).  I've left the original rule in the control commented out (and my modified/corrected one underneath it)

Administrator and Guest account weren't renamed.

LocalAccountTokenFilterPolicy was not set to 0 as I use a local user to WinRM into run the ansible role so if that gets set to 1 then the role breaks

Rules for 19.x.x aren't run as they modify HKEY_USERS and that's apparently not allowed :(


# Maintainer

Glen Yu

# E-mail

glen.yu@gmail.com

# License

MIT
