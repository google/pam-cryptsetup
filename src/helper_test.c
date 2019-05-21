// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "helper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <libcryptsetup.h>

#define kFirstUser "userone"
#define kFirstUserPassphrase "somepass"
#define kMissingUser "missing"
#define kMissingUserPassphrase "alsomissing"
#define kMissingUserNewPassphrase "stillmissing"
#define kCryptName "test_crypt"
#define kCacheContents_Default "['userone', '', '', '', '', '', '', '']"
#define kCacheContents_Empty "['', '', '', '', '', '', '', '']"
#define kCacheContents_MovedUser "['', 'userone', '', '', '', '', '', '']"
#define kCacheContents_AdditionalUser "['userone', 'missing', '', '', '', '', '', '']"

#define kHelperExec "pam_cryptsetup_helper"

typedef struct {
        char tempdir_path[1024];
        struct crypt_device *cd;
} testFixture;

// Test helper functions.

void _CompareCacheToString(char *buffer, int buffer_len, char *temp_path, char *test_string) {
        gchar *path;
        FILE *cachefile;

        path = g_strconcat(temp_path, "/", kCryptsetupHelperSlotsCacheFile, NULL);
        cachefile = fopen(path, "r");
        if (NULL == cachefile) {
                g_test_fail();
                g_test_message("Verify: Unexpected error: Failed to open cache file %s", path);
                return;
        }
        g_free(path);
        if (0 != strcmp(fgets(buffer, buffer_len, cachefile), test_string)) {
            g_test_fail();
            g_test_message("Cache was unexpectedly modified. Expected:\n%s\nActual:\n%s", test_string, buffer);
        } else {
            g_test_message("Cache contents match expected value of %s", test_string);
        }
}

void _CheckCryptHeaderSlots(char **passphrases, int *expected) {
        int r;
        struct crypt_device *cd;
        
        // Re-init header to ensure changes are discovered
        r = crypt_init_by_name(&cd, kCryptName);
        if (r < 0) {
                g_test_fail();
                g_test_message("Slot check: Unexpected error: Failed to init crypt device: %s (%d)", strerror(-r), -r);
                return;
        }

        for (int i = 0; i < LUKS_NUM_SLOTS; i++) {
                r = crypt_activate_by_passphrase(cd, NULL, i, passphrases[i], strlen(passphrases[i]), 0);
                if (expected[i] != r) {
                        g_test_fail();
                        g_test_message("Slot check: Bad result checking keyslot %d with passphrase '%s'. Expected: %d, Actual: %d", i, passphrases[i], expected[i], r);
                        g_test_message("Slot check: Keyslot status is %d", crypt_keyslot_status(cd, i));
                        //crypt_dump(cd);
                        // TODO(warrenpw): Copy failed file for investigation purposes.
                }
        }
        
        crypt_free(cd);
        
        if (!g_test_failed()) {
            g_test_message("Slots check returned expected values for all slots.");
        }

        return;
}

void _CryptLog(int level, const char *msg, void *usrptr) {
        g_test_message("libcryptsetup: %s", msg);
}

// End test helper functions.

static void SetUpTemp(testFixture *fixture, gconstpointer userdata) {
        char dir_template[] = "pamEncTestXXXXXX";
        char *tempdir;
        GError *error = NULL;

        tempdir = mkdtemp(dir_template);
        if (NULL == tempdir) {
                g_test_fail();
                g_test_message("Setup: Unexpected error: Failed to allocate temporary directory.");
                return;
        }
        strcpy(fixture->tempdir_path, tempdir);
        g_test_message("Setup: Created temp directory %s.", tempdir);
        
        if (userdata) {
            char *path = g_strconcat(fixture->tempdir_path, "/slots", NULL);
            g_file_set_contents(path, userdata, -1, &error);
            g_free(path);
            if (error) {
                g_test_fail();
                g_test_message("Setup: Unexpected error: Unable to create initial cache file");
                return;
            }
            g_test_message("Setup: Created initial cache file in %s with contents %s", fixture->tempdir_path, (char*)userdata);
        } else {
            g_test_message("Setup: Not creating an initial cache file");
        }
}

static void SetUpTempAndCrypt(testFixture *fixture, gconstpointer userdata) {
        char buffer[2048];
        char *imgfilepath;
        int r;

        // Attempt to use cryptsetup to mount an encrypted image via loopback device.
        SetUpTemp(fixture, userdata);

        if (g_test_failed()) {
                return;
        }

        snprintf(buffer, sizeof buffer, "/bin/cp ../testdata/testimage.img %s", fixture->tempdir_path);
        if (0 != system(buffer)) {
                g_test_fail();
                g_test_message("Setup: Unexpected error: Failed to copy test image.");
                return;
        }
        g_test_message("Setup: Created testimage.img file under %s", fixture->tempdir_path);
        //crypt_set_log_callback(fixture->cd, _CryptLog, NULL);
        //crypt_set_debug_level(CRYPT_DEBUG_ALL);
        imgfilepath = g_strconcat(fixture->tempdir_path, "/testimage.img", NULL);
        r = crypt_init(&fixture->cd, imgfilepath);
        g_free(imgfilepath);
        if (r < 0) {
                g_test_fail();
                g_test_message("Setup: Unexpected error: Failed to init crypt device: %s (%d)", strerror(-r), -r);
                return;
        }
        r = crypt_load(fixture->cd, CRYPT_LUKS, NULL);
        if (r < 0) {
                g_test_fail();
                g_test_message("Setup: Unexpected error: Failed to load device settings: %s (%d)", strerror(-r), -r);
                return;
        }
        r = crypt_activate_by_passphrase(fixture->cd, kCryptName, CRYPT_ANY_SLOT, kFirstUserPassphrase, strlen(kFirstUserPassphrase), 0);
        if (r < 0) {
                g_test_fail();
                g_test_message("Setup: Unexpected error: Failed to activate crypt device: %s (%d)", strerror(-r), -r);
                return;
        }
}

static void TearDownTemp(testFixture *fixture, gconstpointer userdata) {
        char buffer[2048];
        int r = 0;

        snprintf(buffer, sizeof buffer, "/bin/rm -r %s", fixture->tempdir_path);
        r = system(buffer);
        if (r != 0) {
                g_test_message("Tear down encountered errors; this is expected if set up failed.");
        }
}

static void TearDownTempAndCrypt(testFixture *fixture, gconstpointer userdata) {
        int r = 0;

        r = crypt_deactivate_by_name(fixture->cd, kCryptName, 0);
        if (r != 0) {
                g_test_message("Failed to tear down crypt device %s; this is expected if set up failed.", kCryptName);
        }

        crypt_free(fixture->cd);

        TearDownTemp(fixture, userdata);
}

static void TestEncryptionHelper_CreateCacheFile(testFixture *fixture, gconstpointer userdata) {
    char buffer[2048];
    int r = 0;

    snprintf(buffer, sizeof buffer, "printf '%s\n' | ./%s %s %s %s 3>/dev/null", kMissingUserPassphrase, kHelperExec, kCryptName, kMissingUser, fixture->tempdir_path);
    r = system(buffer);
    if (0 != r) {
            g_test_fail();
            g_test_message("Encryption helper exited with unexpected code %d", r);
            return;
    }

    _CompareCacheToString(buffer, sizeof buffer, fixture->tempdir_path, kCacheContents_Empty);
}

static void TestEncryptionHelperAuthMode_NoChangesPasswordExists(testFixture *fixture, gconstpointer userdata) {
        char buffer[2048];
        int r = 0;

        snprintf(buffer, sizeof buffer, "printf '%s\n' | ./%s %s %s %s 3>/dev/null", kFirstUserPassphrase, kHelperExec, kCryptName, kFirstUser, fixture->tempdir_path);
        r = system(buffer);
        if (0 != r) {
                g_test_fail();
                g_test_message("Encryption helper exited with unexpected code %d", r);
                return;
        }

        _CompareCacheToString(buffer, sizeof buffer, fixture->tempdir_path, kCacheContents_Default);

        int e[] = {0, -2, -2, -2, -2, -2, -2, -2};
        char* p[8] = {kFirstUserPassphrase, "", "", "", "", "", "", ""};
        _CheckCryptHeaderSlots(p, e);
}

static void TestEncryptionHelperAuthMode_NoChangesPasswordNotInHeader(testFixture *fixture, gconstpointer userdata) {
        char buffer[2048];
        int r = 0;

        snprintf(buffer, sizeof buffer, "printf '%s\n' | ./%s %s %s %s 3>/dev/null", kMissingUserPassphrase, kHelperExec, kCryptName, kMissingUser, fixture->tempdir_path);
        r = system(buffer);
        if (0 != r) {
                g_test_fail();
                g_test_message("Encryption helper exited with unexpected code %d", r);
                return;
        }

        _CompareCacheToString(buffer, sizeof buffer, fixture->tempdir_path, kCacheContents_Default);

        int e[] = {0, -2, -2, -2, -2, -2, -2, -2};
        char* p[8] = {kFirstUserPassphrase, "", "", "", "", "", "", ""};
        _CheckCryptHeaderSlots(p, e);
}

static void TestEncryptionHelperAuthMode_CacheChangePasswordMoved(testFixture *fixture, gconstpointer userdata) {
        char buffer[2048];
        int r = 0;
        
        //TODO(warrenpw) Move this encryption stuff to a setup function?
        r = crypt_keyslot_change_by_passphrase(fixture->cd, 0, 1, kFirstUserPassphrase, strlen(kFirstUserPassphrase), kFirstUserPassphrase, strlen(kFirstUserPassphrase));
        if (r < 0) {
                g_test_fail();
                g_test_message("Failed to rekey encrypted image: %s (%d)", strerror(-r), -r);
                return;
        }

        snprintf(buffer, sizeof buffer, "printf '%s\n' | ./%s %s %s %s 3>/dev/null", kFirstUserPassphrase, kHelperExec, kCryptName, kFirstUser, fixture->tempdir_path);
        r = system(buffer);
        if (0 != r) {
                g_test_fail();
                g_test_message("Encryption helper exited with unexpected code %d", r);
                return;
        }

        _CompareCacheToString(buffer, sizeof buffer, fixture->tempdir_path, kCacheContents_MovedUser);

        int e[] = {-2, 1, -2, -2, -2, -2, -2, -2};
        char* p[8] = {"", kFirstUserPassphrase, "", "", "", "", "", ""};
        _CheckCryptHeaderSlots(p, e);
}

static void TestEncryptionHelperAuthMode_CacheChangeFixUsername(testFixture *fixture, gconstpointer userdata) {
        char buffer[2048];
        int r = 0;

        snprintf(buffer, sizeof buffer, "printf '%s\n' | ./%s %s %s %s 3>/dev/null", kFirstUserPassphrase, kHelperExec, kCryptName, kFirstUser, fixture->tempdir_path);
        r = system(buffer);
        if (0 != r) {
                g_test_fail();
                g_test_message("Encryption helper exited with unexpected code %d", r);
                return;
        }

        _CompareCacheToString(buffer, sizeof buffer, fixture->tempdir_path, kCacheContents_Default);

        int e[] = {0, -2, -2, -2, -2, -2, -2, -2};
        char* p[8] = {kFirstUserPassphrase, "", "", "", "", "", "", ""};
        _CheckCryptHeaderSlots(p, e);
}

static void TestEncryptionHelperAuthMode_CacheChangeAddUser(testFixture *fixture, gconstpointer userdata) {
        char buffer[2048];
        int r = 0;
        
        //TODO(warrenpw) Move this encryption stuff to a setup function?
        r = crypt_keyslot_add_by_passphrase(fixture->cd, 1, kFirstUserPassphrase, strlen(kFirstUserPassphrase), kMissingUserPassphrase, strlen(kMissingUserPassphrase));
        if (r < 0) {
                g_test_fail();
                g_test_message("Failed to rekey encrypted image: %s (%d)", strerror(-r), -r);
                return;
        }

        snprintf(buffer, sizeof buffer, "printf '%s\n' | ./%s %s %s %s 3>/dev/null", kMissingUserPassphrase, kHelperExec, kCryptName, kMissingUser, fixture->tempdir_path);
        r = system(buffer);
        if (0 != r) {
                g_test_fail();
                g_test_message("Encryption helper exited with unexpected code %d", r);
                return;
        }

        _CompareCacheToString(buffer, sizeof buffer, fixture->tempdir_path, kCacheContents_AdditionalUser);

        int e[] = {0, 1, -2, -2, -2, -2, -2, -2};
        char* p[8] = {kFirstUserPassphrase, kMissingUserPassphrase, "", "", "", "", "", ""};
        _CheckCryptHeaderSlots(p, e);
}

static void TestEncryptionHelperAuthMode_DiskChangeUpdatePassword(testFixture *fixture, gconstpointer userdata) {
        char buffer[2048];
        int r = 0;

        sleep(5);

        snprintf(buffer, sizeof buffer, "printf '%s\n' | ./%s %s %s %s 3>/dev/null", kMissingUserPassphrase, kHelperExec, kCryptName, kFirstUser, fixture->tempdir_path);
        r = system(buffer);
        if (0 != r) {
                g_test_fail();
                g_test_message("Encryption helper exited with unexpected code %d", r);
                return;
        }

        _CompareCacheToString(buffer, sizeof buffer, fixture->tempdir_path, kCacheContents_MovedUser);

        int e[] = {-2, 1, -2, -2, -2, -2, -2, -2};
        char* p[8] = {"", kMissingUserPassphrase, "", "", "", "", "", ""};
        _CheckCryptHeaderSlots(p, e);
}

static void TestEncryptionHelperCredMode_RekeyWithoutCacheUpdate(testFixture *fixture, gconstpointer userdata) {
        char buffer[2048];
        int r = 0;
        
        //TODO(warrenpw) Move this encryption stuff to a setup function?
        r = crypt_keyslot_add_by_passphrase(fixture->cd, 1, kFirstUserPassphrase, strlen(kFirstUserPassphrase), kMissingUserPassphrase, strlen(kMissingUserPassphrase));
        if (r < 0) {
                g_test_fail();
                g_test_message("Failed to rekey encrypted image: %s (%d)", strerror(-r), -r);
                return;
        }

        //NOTE: For cred mode, order of passwords in pipe is new, then current.
        snprintf(buffer, sizeof buffer, "printf '%s\n%s\n' | ./%s %s %s %s 3>/dev/null", kMissingUserNewPassphrase, kMissingUserPassphrase, kHelperExec, kCryptName, kMissingUser, fixture->tempdir_path);
        r = system(buffer);
        if (0 != r) {
                g_test_fail();
                g_test_message("Encryption helper exited with unexpected code %d", r);
                return;
        }

        _CompareCacheToString(buffer, sizeof buffer, fixture->tempdir_path, kCacheContents_Default);

        int e[] = {0, -2, 2, -2, -2, -2, -2, -2};
        char* p[8] = {kFirstUserPassphrase, "", kMissingUserNewPassphrase, "", "", "", "", ""};
        _CheckCryptHeaderSlots(p, e);
}

static void TestEncryptionHelperCredMode_RekeyUpdateCache(testFixture *fixture, gconstpointer userdata) {
        char buffer[2048];
        int r = 0;

        snprintf(buffer, sizeof buffer, "printf '%s\n%s\n' | ./%s %s %s %s 3>/dev/null", kMissingUserPassphrase, kFirstUserPassphrase, kHelperExec, kCryptName, kFirstUser, fixture->tempdir_path);
        r = system(buffer);
        if (0 != r) {
                g_test_fail();
                g_test_message("Encryption helper exited with unexpected code %d", r);
                return;
        }

        _CompareCacheToString(buffer, sizeof buffer, fixture->tempdir_path, kCacheContents_MovedUser);

        int e[] = {-2, 1, -2, -2, -2, -2, -2, -2};
        char* p[8] = {"", kMissingUserPassphrase, "", "", "", "", "", ""};
        _CheckCryptHeaderSlots(p, e);
}

int main(int argc, char **argv) {
        g_test_init(&argc, &argv, NULL);
        // g_test_add("/module_root_tests/TestDMSetupGetDeviceParams", testFixture, NULL,
        //            SetUpTempAndCrypt, TestDMSetupGetDeviceParams,
        //            TearDownTempAndCrypt);
        // g_test_add_func("/module_tests/TestHexStringToByteArray",
        //                 TestHexStringToByteArray);
        g_test_add("/helper/CreateCacheFile", testFixture, NULL, SetUpTempAndCrypt, TestEncryptionHelper_CreateCacheFile, TearDownTempAndCrypt);
        g_test_add("/helper/AuthMode/NoChange_PasswordExists", testFixture, kCacheContents_Default, SetUpTempAndCrypt, TestEncryptionHelperAuthMode_NoChangesPasswordExists, TearDownTempAndCrypt);
        g_test_add("/helper/AuthMode/NoChange_PasswordNotInHeader", testFixture, kCacheContents_Default, SetUpTempAndCrypt, TestEncryptionHelperAuthMode_NoChangesPasswordNotInHeader, TearDownTempAndCrypt);
        g_test_add("/helper/AuthMode/Cache_ChangeUsernameSlot", testFixture, kCacheContents_Default, SetUpTempAndCrypt, TestEncryptionHelperAuthMode_CacheChangePasswordMoved, TearDownTempAndCrypt);
        g_test_add("/helper/AuthMode/Cache_FixUsernameSlot", testFixture, kCacheContents_MovedUser, SetUpTempAndCrypt, TestEncryptionHelperAuthMode_CacheChangeFixUsername, TearDownTempAndCrypt);
        g_test_add("/helper/AuthMode/Cache_AddUsername", testFixture, kCacheContents_Default, SetUpTempAndCrypt, TestEncryptionHelperAuthMode_CacheChangeAddUser, TearDownTempAndCrypt);
        g_test_add("/helper/AuthMode/Disk_UpdateLUKSPassphrase", testFixture, kCacheContents_Default, SetUpTempAndCrypt, TestEncryptionHelperAuthMode_DiskChangeUpdatePassword, TearDownTempAndCrypt);
        g_test_add("/helper/CredMode/Rekey_NoCacheChange", testFixture, kCacheContents_Default, SetUpTempAndCrypt, TestEncryptionHelperCredMode_RekeyWithoutCacheUpdate, TearDownTempAndCrypt);
        g_test_add("/helper/CredMode/Rekey_UpdateCache", testFixture, kCacheContents_Default, SetUpTempAndCrypt, TestEncryptionHelperCredMode_RekeyUpdateCache, TearDownTempAndCrypt);
        return g_test_run();
}
