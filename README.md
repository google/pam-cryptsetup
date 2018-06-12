
**Disclamer:** This is not an official Google product.

# Overview

pam-cryptsetup provides a PAM module that allows LUKS-based disk encryption passwords to be
kept in sync with account passwords automatically based on factors like if the user has
decypted the disk successfully previously.

# Module Configuration
When adding this module to an authentication stack, it is recommended to use either the auth [default=ignore] or auth optional flags and to place its entry at the very end of the auth module sequence, as one probably doesn't want authentication of a user hinging on a module that doesn't actually provide any.

## Arguments:
* `crypt_name=<container>` (Required): Name of encrypted /dev/mapper based container to probe.
* `debug=<state>`: If set to 'true', provide additional execution details via pam_syslog. Otherwise behavior is not modified.

## Examples:
For an encrypted device at /dev/mapper/rootdev_crypt:
```
auth [default=ignore] pam_cryptsetup.so crypt_name=rootdev_crypt
```
Square brackets ([ and ]) can be used for device names with spaces:
```
auth [default=ignore] pam_cryptsetup.so [crypt_name=my special device]
```
# Crypt Slot Cache
All user information, such as which (if any) slot was most recently unlocked with their login password, is recoded in /var/cache/libpam-cryptsetup as a GLib string array.
The default format, before any unlocking has happened, is as follows:
```
['', '', '', '', '', '', '', '']
```
where each string associates with one of the 8 LUKS slots (numbered 0-7) available. Once a user's password has sucessfully unlocked a slot on the disk, their username is added to the string associated with the number slot unlocked.

For example, if we had a user 'kathy' unlock slot 3, the cache would be updated as follows:
```
['', '', '', 'kathy', '', '', '', '']
```
Next time kathy authenticates, this info will be used to determine the appropriate action for the module to take.

# Operation
During authentication, the module takes the following information into account:
* Username
* Password
* Cache entries
* Crypt slots

Once all available information is gathered, the action taken is decided by the following logic:
* No action if:
  * User is not recorded in-cache, and password does not unlock any slot
  * User is recorded in-cache, and password unlocks the associated slot
* Update disk slot if:
  * User is recorded in-cache, and password does not unlock recorded slot
* Update cache if:
  * User is recorded in-cache, and password unlocks different slot than the one recorded
  * User is not recorded in-cache, and password unlocks a slot

# Building

Built with autotools and includes an autogen.sh script:

1.  ./autogen.sh (not needed when using source tarball)
2.  ./configure
3.  make
4.  make check
5.  sudo make install

Dependencies:

*   GLib
*   Linux-PAM
*   libcryptsetup
*   libdevicemapper
*   Autoconf, Automake, Libtool
