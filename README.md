# Disclamer

This is not an official Google product.

# Overview

pam-cryptsetup provides a PAM module that allows LUKS-based disk encryption passwords to be
kept in sync with account passwords automatically based on factors like if the user has
decypted the disk successfully previously.

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
