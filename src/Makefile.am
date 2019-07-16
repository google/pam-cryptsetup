# Copyright 2017 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# GLib TAP test harness.
include $(top_srcdir)/glib-tap.mk

AM_CFLAGS = $(GLIB_CFLAGS) -Wall -Werror -DG_LOG_DOMAIN="\"pamcryptsetup\"" \
		-D_GNU_SOURCE=1 -fstack-protector-all -D_FORTIFY_SOURCE=2 \
		-Wl,-z,relro,-z,now, -Wformat -Wformat-security
AM_LDFLAGS = $(GLIB_LIBS) -Wa,--noexecstack

securelibdir = $(libdir)/security
securelib_LTLIBRARIES = pam_cryptsetup.la

MODULE_SOURCES = module.c module.h
HELPER_SOURCES = helper.c helper.h

pam_cryptsetup_la_SOURCES = $(MODULE_SOURCES)
pam_cryptsetup_la_CFLAGS = -fPIC $(AM_CFLAGS)
pam_cryptsetup_la_CPPFLAGS = -DHELPER_EXEC='"$(pkglibexecdir)/pam_cryptsetup_helper"'
pam_cryptsetup_la_LDFLAGS = -shared -module -avoid-version \
		-export-symbols-regex 'pam_sm_*' -lpam $(AM_LDFLAGS)

pkglibexec_PROGRAMS = pam_cryptsetup_helper
pam_cryptsetup_helper_SOURCES = $(HELPER_SOURCES)
pam_cryptsetup_helper_CFLAGS = $(AM_CFLAGS)
pam_cryptsetup_helper_CPPFLAGS = -DCACHE_DIR='"$(prefix)/var/pam_cryptsetup"'
pam_cryptsetup_helper_LDFLAGS = -avoid-version -lcryptsetup -ldevmapper \
 		-Wa,--noexecstack $(AM_LDFLAGS)

# GLib unit test programs for helper.

helper_test_sources = helper_test.c $(HELPER_SOURCES)
helper_test_LDFLAGS = -no-install $(AM_LDFLAGS)
helper_test_CFLAGS = $(AM_CFLAGS)

test_programs = helper_test
