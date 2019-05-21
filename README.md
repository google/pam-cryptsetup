
**Disclamer:** This is not an official Google product.

# Overview

pam-cryptsetup provides a PAM module that allows LUKS-based disk encryption
passwords to be kept in sync with account passwords automatically based on
factors like if the user has decrypted the disk successfully previously.

The project as a whole consists of two parts: a PAM module pam_cryptsetup.so for
triggering on user authentication, and a helper program pam_cryptsetup_helper
to perform the actual encryption checks and modifications required.

# Building and Installing

Built with GNU Autotools and includes an autogen.sh script:

1.  ./autogen.sh
2.  ./configure
3.  make [prefix={path}]
4.  make check # (optional)
5.  sudo make install [prefix={path}]

Depends on:

*   GLib
*   Linux-PAM
*   libcryptsetup
*   libdevicemapper
*   Autoconf, Automake, Libtool

## The Autotools Prefix
Due to this project's use of GNU Autotools, all the components are built and
installed relative to a user-definable prefix via `make prefix={path}`. Any time
this documentation references `{prefix}`, substitute the value given to make,
or `/usr/local` if none was given.

Additionally, when using `make install`, it is required to manually link
pam_cryptsetup.so to the proper PAM modules directory (usually `/lib/security`)
from the build default `{prefix}/lib/security`. This can be avoided by defining
the prefix to be empty via `make install prefix=`.

# Components

## pam_cryptsetup.so
The pam_cryptsetup.so module attaches to a PAM authentication or credential
stack, and passes information provided to the pam_cryptsetup_helper executable
to enact any changes that might be necessary.

### Module Configuration
When adding this module to a PAM stack, it is recommended to use either the
`[default=ignore]` or `optional` flags and to place the entry for the
module at the very end of the PAM config file sequence.

### Module Arguments:
| Declaration | Default | Description|
|-------------|---------|------------|
| `crypt_name=<container>` | _(none)_ | Name of encrypted /dev/mapper based container to probe. Required for operation. |
| `debug=<state>` | false | If set to 'true', provide additional module execution details via pam_syslog. |
| `background=<state>` | true | If set to 'false', authentication module will wait for helper process to complete |

### Module Examples:
#### Authentication mode
Authentication mode is most useful when a user's login password can be changed
by external factors, such as in an LDAP authentication environment.

The following example changes would be placed in `/etc/pam/common.auth`

For an encrypted device at /dev/mapper/rootdev_crypt:
```
<snip>
auth [default=ignore] pam_cryptsetup.so crypt_name=rootdev_crypt
```
Square brackets ([ and ]) can be used for device names with spaces:
```
<snip>
auth [default=ignore] pam_cryptsetup.so [crypt_name=my special device]
```
And if your device has a really weird name, closing square brackets must be
escaped by using `\]`:
```
<snip>
auth [default=ignore] pam_cryptsetup.so [crypt_name=my [extra\] special device]
```

#### Credential mode
As an alternative authentication mode, the module can instead be used in
credential mode, and will run only when a user account password is set via the
passwd command. This is recommended for setups where the password is never
expected to change outside of the passwd command being run.

For credential mode, changes should be made in `/etc/pam/passwd`

For an encrypted device at /dev/mapper/rootdev_crypt:
```
<snip>
password [default=ignore] pam_cryptsetup.so crypt_name=rootdev_crypt
```

## pam_cryptsetup_helper
The pam_cryptsetup_helper executable receives data via unnamed piping and
command line arguments when invoked by the pam_cryptsetup.so module, and uses
the data passed to decide if updates to the encrypted disk are necessary.

### A Note on Security
Because this helper module handles sensitive information (notably password and
volume keys) outside the secure PAM context, the following steps are taken to
prevent leaking data:

* memlockall() is called at the start of the process to prevent it or any
  libraries' memory from being paged to disk during runtime.
* Variables that held sensitive information are zeroed before being freed via
  either a native implementation of explicit_bzero or an included equivalent.
* While non-sensitive data like username or crypt name are passed via argument,
  password tokens are read via inter-process anonymous pipes.

Additionally, while this executable can be called manually if one knows the
proper invocation, it is not setuid, and requires the caller have root
permissions in order for changes to be made to the encrypted disk.

### Helper Crypt Slot Cache
All user information, such as which (if any) slot was most recently unlocked with their login password, is recoded in `{prefix}/var/pam-cryptsetup/slots` as a GLib string array.
The default format, before any unlocking has happened, is as follows:
```
['', '', '', '', '', '', '', '']
```
where each string associates with one of the 8 LUKS slots (numbered 0-7) available. Once a user's password has successfully unlocked a slot on the disk, their username is added to the string associated with the number slot unlocked.

For example, if we had a user 'kathy' unlock slot 3, the cache would be updated as follows:
```
['', '', '', 'kathy', '', '', '', '']
```
Next time kathy authenticates, this info will be used to determine the appropriate action for the helper to take.

### Helper Operation
During a run, the module takes the following information into account:
* Username
* Password
* Old Password (cred mode only)
* Cache entries
* Crypt slots unlock-able using
    * password (auth mode)
    * old password (cred mode)

Once all available information is gathered, the action taken is decided by the following logic:

Authentication mode:

* No action if:
  * User is not recorded in-cache, and password does not unlock any slot
  * User is recorded in-cache, and password unlocks the associated slot
* Update disk and cache slot if:
  * User is recorded in-cache, and password does not unlock recorded slot
* Update cache if:
  * User is recorded in-cache, and password unlocks different slot than the one recorded
  * User is not recorded in-cache, and password unlocks a slot

Password mode:

* No action if:
  * Old password does not unlock a slot
* Update disk if:
  * Old password unlocks a slot
* ADDITIONALLY update cache if:
  * User entry exists in a different cache slot compared to new crypt slot

Note: While credential mode will interact with the cache in some cases, it is
not meant to be used in addition to authentication mode; using it as such is
untested and considered unsupported at this time!

# Potential Future Improvements

* Save cache to drive encryption header using LUKS2 unbound slots
  * Would allow easier drive transfer to new systems while keeping existing
    pam-cryptsetup info intact.
  * Security-conscious might appreciate a less-easily-accessible record of users
    who can unlock the drive with their passwords.
    
* Reintroduce multi-threading in helper application (unlikely)
  * Code was messy
  * Performance benefits don't matter when helper
    runs in the background.
    
* Utilize kernel keychain for retrieving active volume key
  * Would allow dropping the direct libdevmapper usage
  * Would require that user's kernel is set to store the volume key in an
    accessible keychain.
