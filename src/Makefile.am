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

AM_CFLAGS = $(GLIB_CFLAGS) -Wall -Werror \
	    -DG_LOG_DOMAIN="\"pamcryptsetup\"" \
	    -D_GNU_SOURCE=1 \
	    -fPIC -fstack-protector-all -D_FORTIFY_SOURCE=2 \
	    -Wl,-z,relro,-z,now, -Wformat -Wformat-security
AM_LDFLAGS = $(GLIB_LIBS) -lpam -lcryptsetup -ldevmapper -Wa,--noexecstack

securelibdir = $(libdir)/security
securelib_LTLIBRARIES = pam_cryptsetup.la

MODULE_SOURCES = module.c module.h

EXTRA_DIST = run_root_tests.test run_nonroot_tests.test

pam_cryptsetup_la_SOURCES = $(MODULE_SOURCES)
pam_cryptsetup_la_LDFLAGS = -shared -module -avoid-version \
			     -export-symbols-regex 'pam_sm_*' \
			     $(AM_LDFLAGS)

# Unit-tests with one executable per test-suite.
module_test_SOURCES = module_test.c $(MODULE_SOURCES)
module_test_LDFLAGS = -no-install $(AM_LDFLAGS)
module_test_CFLAGS = $(AM_CFLAGS)

check_PROGRAMS = module_test
TESTS = run_nonroot_tests.test run_root_tests.test
