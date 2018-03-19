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

#include "module.h"

#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define kFirstUser "userone"
#define kPassphrase "somepass"
#define kCryptName "test_crypt"
#define kCryptNameArg "crypt_name=test_crypt"
#define kCacheContents "['userone', '', '', '', '', '', '', '']"

typedef struct {
  char tempdir_path[1024];
  CryptsetupModule *module;
} testFixture;

static void SetUpTemp(testFixture *fixture, gconstpointer userdata) {
  char dir_template[] = "pamEncTestXXXXXX";
  char *tempdir;

  tempdir = mkdtemp(dir_template);
  strcpy(fixture->tempdir_path, tempdir);

  fixture->module = CryptsetupModuleNew();

  if (!fixture->module) {
    g_test_fail();
    g_test_message("failed to allocate module");
    return;
  }
}

static void SetUpTempAndCrypt(testFixture *fixture, gconstpointer userdata) {
  char buffer[2048];
  char *tempfile;
  FILE *keyfile;

  // Attempt to use /dev/loop0 to mount test image.
  SetUpTemp(fixture, userdata);

  if (g_test_failed()) {
    return;
  }

  snprintf(buffer, sizeof buffer, "/bin/cp ../testdata/testimage.img %s",
           fixture->tempdir_path);
  if (0 != system(buffer)) {
    g_test_fail();
    g_test_message("Failed to copy test image.");
    return;
  }
  tempfile = g_strconcat(fixture->tempdir_path, "/", "testimage.img", NULL);
  snprintf(buffer, sizeof buffer, "/sbin/losetup /dev/loop0 %s", tempfile);
  if (0 != system(buffer)) {
    g_test_fail();
    g_test_message("Failed to set up /dev/loop0.");
    return;
  }
  g_free(tempfile);
  tempfile = g_strconcat(fixture->tempdir_path, "/", "keyfile.key", NULL);
  keyfile = fopen(tempfile, "w");
  fputs(kPassphrase, keyfile);
  fclose(keyfile);
  snprintf(buffer, sizeof buffer,
           "/sbin/cryptsetup luksOpen /dev/loop0 %s --key-file %s", kCryptName,
           tempfile);
  if (0 != system(buffer)) {
    g_test_fail();
    g_test_message("Failed to set up crypt container %s.", kCryptName);
    return;
  }
  g_free(tempfile);
}

static void TearDownTemp(testFixture *fixture, gconstpointer userdata) {
  char buffer[2048];
  int r = 0;

  CryptsetupModuleFree(fixture->module);

  snprintf(buffer, sizeof buffer, "/bin/rm -r %s", fixture->tempdir_path);
  r |= system(buffer);
  if (r != 0) {
    g_test_message(
        "Tear down encountered errors. This is expected if set up failed.");
  }
}

static void TearDownTempAndCrypt(testFixture *fixture, gconstpointer userdata) {
  char buffer[2048];
  int r = 0;

  snprintf(buffer, sizeof buffer, "/sbin/cryptsetup luksClose %s", kCryptName);
  r |= system(buffer);
  r |= system("/sbin/losetup -d /dev/loop0");
  if (r != 0) {
    g_test_message(
        "Tear down encountered errors. This is expected if set up failed.");
  }
  TearDownTemp(fixture, userdata);
}

static void TestHexStringToByteArray() {
  char hexstring1[] = "ABCD1234";
  char bytearray1[] = {0xAB, 0xCD, 0x12, 0x34};
  char hexstring2[] = "FEB026";
  char bytearray2[] = {0xFE, 0xB0, 0x26};
  char buffer[10];

  _StringToByteArr(buffer, hexstring1);
  for (int i = 0; i < (strlen(hexstring1) / 2); i++) {
    if (bytearray1[i] != buffer[i]) {
      g_test_fail();
      g_test_message("byte conversion error: 0x%c%c:\n%X !=\n%X",
                     hexstring1[i * 2], hexstring1[i * 2 + 1], bytearray1[i],
                     buffer[i]);
    }
  }
  _StringToByteArr(buffer, hexstring2);
  for (int i = 0; i < (strlen(hexstring2) / 2); i++) {
    if (bytearray2[i] != buffer[i]) {
      g_test_fail();
      g_test_message("byte conversion error: 0x%c%c:\n%X !=\n%X",
                     hexstring2[i * 2], hexstring2[i * 2 + 1], bytearray2[i],
                     buffer[i]);
    }
  }
}

static void TestCryptSetupModuleAllocate() {
  CryptsetupModule *module = NULL;

  module = CryptsetupModuleNew();

  if (!module) {
    g_test_fail();
    g_test_message("failed to allocate module");
    return;
  }

  CryptsetupModuleFree(module);
}

static void TestCryptsetupModuleRetrieveCacheSlot() {
  CryptsetupModule *module = NULL;
  int r;

  module = CryptsetupModuleNew();

  if (!module) {
    g_test_fail();
    g_test_message("failed to allocate module");
    return;
  }

  module->userslots[0] = g_malloc(strlen(kFirstUser) + 1);
  strcpy(module->userslots[0], kFirstUser);

  r = CryptsetupModuleRetrieveCacheSlot(module, kFirstUser);

  if (r != 0) {
    g_test_fail();
    g_test_message(
        "did not find recorded user in proper slot: expected 0, got %i", r);
    CryptsetupModuleFree(module);
    return;
  }

  r = CryptsetupModuleRetrieveCacheSlot(module, "notauser");

  if (r != -1) {
    g_test_fail();
    g_test_message("found nonexistant user in slot %i", r);
    CryptsetupModuleFree(module);
    return;
  }

  CryptsetupModuleFree(module);
}

static void TestCryptsetupModuleStoreCache(testFixture *fixture,
                                           gconstpointer userdata) {
  GError *error = NULL;
  gboolean r;

  if (g_test_failed()) {
    return;
  }

  fixture->module->userslots[0] = g_malloc(strlen(kFirstUser) + 1);
  strcpy(fixture->module->userslots[0], kFirstUser);

  r = CryptsetupModuleStoreCache(fixture->module, fixture->tempdir_path,
                                 &error);
  if (error) {
    g_test_fail();
    g_test_message("CryptsetupModuleStoreCache failed with error: %s",
                   error->message);
    g_error_free(error);
    return;
  }
  if (!r) {
    g_test_fail();
    g_test_message("CryptsetupModuleStoreCache failed without error");
    return;
  }

  char *tempcachefile = g_strconcat(fixture->tempdir_path, "/", "slots", NULL);
  char *cachecontents;
  g_file_get_contents(tempcachefile, &cachecontents, NULL, &error);
  g_free(tempcachefile);
  if (error) {
    g_test_fail();
    g_test_message("failed to read temp cache file: %s", error->message);
    g_error_free(error);
    return;
  }

  if (strcmp(kCacheContents, cachecontents) != 0) {
    g_test_fail();
    g_test_message("Cache contents malformed: Expected:\n%s\nGot:\n%s\n",
                   kCacheContents, cachecontents);
    g_free(cachecontents);
    return;
  }

  g_free(cachecontents);
}

static void TestCryptsetupModuleReadCache(testFixture *fixture,
                                          gconstpointer userdata) {
  GError *error = NULL;
  gboolean r;

  if (g_test_failed()) {
    return;
  }

  char *tempcachefile = g_strconcat(fixture->tempdir_path, "/", "slots", NULL);

  g_file_set_contents(tempcachefile, kCacheContents, -1, &error);
  g_free(tempcachefile);
  if (error) {
    g_test_fail();
    g_test_message("failed to write test data to temp cache file: %s",
                   error->message);
    g_error_free(error);
    g_free(tempcachefile);
    return;
  }

  r = CryptsetupModuleReadCache(fixture->module, fixture->tempdir_path, &error);
  if (error) {
    g_test_fail();
    g_test_message("CryptsetupModuleReadCache failed with error: %s",
                   error->message);
    g_error_free(error);
    return;
  }
  if (!r) {
    g_test_fail();
    g_test_message("CryptsetupModuleReadCache failed without error");
    return;
  }

  if (strcmp(fixture->module->userslots[0], kFirstUser) != 0) {
    g_test_fail();
    g_test_message(
        "User slot 0 was not set properly: Expected:\n%s\nGot:\n%s\n",
        kFirstUser, fixture->module->userslots[0]);
    return;
  }
}

// **** Tests below require root ****

static void TestCryptsetupModuleCryptNameArg(testFixture *fixture,
                                             gconstpointer userdata) {
  GError *error = NULL;
  gboolean result;

  if (g_test_failed()) {
    return;
  }

  result = CryptsetupModuleAddArg(fixture->module, kCryptNameArg, &error);
  if (error) {
    g_test_fail();
    g_test_message("function CryptsetupModuleAddArg failed with error: %s",
                   error->message);
    g_error_free(error);
    return;
  }
  if (!result) {
    g_test_fail();
    g_test_message("function CryptsetupModuleAddArg failed without error");
    return;
  }

  if (0 != strcmp(kCryptName, fixture->module->crypt_mapper_name)) {
    g_test_fail();
    g_test_message("Crypt name was not properly stored:\n%s !=\n%s", kCryptName,
                   fixture->module->crypt_mapper_name);
    return;
  }

  if (!CryptsetupModuleVerifyCryptName(fixture->module, &error)) {
    g_test_fail();
    g_test_message("function CryptsetupModuleVerifyCryptName failed with error: %s",
                   error->message);
    g_error_free(error);
    return;
  }
}

static void TestCryptsetupModuleInitEncryption(testFixture *fixture,
                                               gconstpointer userdata) {
  GError *error = NULL;
  gboolean result;

  if (g_test_failed()) {
    return;
  }

  g_test_message("CryptsetupModuleAddArg");
  result = CryptsetupModuleAddArg(fixture->module, kCryptNameArg, &error);
  if (error) {
    g_test_fail();
    g_test_message("function CryptsetupModuleAddArg failed with error: %s",
                   error->message);
    g_error_free(error);
    return;
  }
  if (!result) {
    g_test_fail();
    g_test_message("function CryptsetupModuleAddArg failed without error");
    return;
  }

  g_test_message("CryptsetupModuleInit");
  result = CryptsetupModuleInitEncryption(fixture->module, &error);
  if (error) {
    g_test_fail();
    g_test_message("function CryptsetupModuleInit failed with error: %s",
                   error->message);
    g_error_free(error);
    return;
  }
  if (!result) {
    g_test_fail();
    g_test_message("function CryptsetupModuleInit failed without error");
    return;
  }
}

static void TestCryptsetupModuleRetrieveHeaderSlot(testFixture *fixture,
                                                   gconstpointer userdata) {
  GError *error = NULL;
  gboolean result;

  if (g_test_failed()) {
    return;
  }

  g_test_message("CryptsetupModuleAddArg");
  result = CryptsetupModuleAddArg(fixture->module, kCryptNameArg, &error);
  if (error) {
    g_test_fail();
    g_test_message("function CryptsetupModuleAddArg failed with error: %s",
                   error->message);
    g_error_free(error);
    return;
  }
  if (!result) {
    g_test_fail();
    g_test_message("function CryptsetupModuleAddArg failed without error");
    return;
  }

  g_test_message("CryptsetupModuleInit");
  result = CryptsetupModuleInitEncryption(fixture->module, &error);
  if (error) {
    g_test_fail();
    g_test_message("function CryptsetupModuleInit failed with error: %s",
                   error->message);
    g_error_free(error);
    return;
  }
  if (!result) {
    g_test_fail();
    g_test_message("function CryptsetupModuleInit failed without error");
    return;
  }

  result =
      CryptsetupModuleRetrieveHeaderSlot(fixture->module, kPassphrase, &error);
  if (error) {
    g_test_fail();
    g_test_message("function CryptsetupModuleRecord failed with error: %s",
                   error->message);
    g_error_free(error);
    return;
  }
  if (result == -1) {
    g_test_fail();
    g_test_message("function CryptsetupModuleRecord failed without error");
    return;
  }

  if (result != 0) {
    g_test_fail();
    g_test_message(
        "Header slot was not properly read: Expected slot 0, got slot %d",
        result);
    return;
  }
}

static void TestCryptsetupModuleRekey(testFixture *fixture,
                                      gconstpointer userdata) {
  GError *error = NULL;
  gboolean result;

  if (g_test_failed()) {
    return;
  }

  g_test_message("CryptsetupModuleAddArg");
  result = CryptsetupModuleAddArg(fixture->module, kCryptNameArg, &error);
  if (error) {
    g_test_fail();
    g_test_message("function CryptsetupModuleAddArg failed with error: %s",
                   error->message);
    g_error_free(error);
    return;
  }
  if (!result) {
    g_test_fail();
    g_test_message("function CryptsetupModuleAddArg failed without error");
    return;
  }

  g_test_message("CryptsetupModuleInit");
  result = CryptsetupModuleInitEncryption(fixture->module, &error);
  if (error) {
    g_test_fail();
    g_test_message("function CryptsetupModuleInit failed with error: %s",
                   error->message);
    g_error_free(error);
    return;
  }
  if (!result) {
    g_test_fail();
    g_test_message("function CryptsetupModuleInit failed without error");
    return;
  }

  g_test_message("CryptsetupModuleRekey");
  result = CryptsetupModuleRekey(fixture->module, "someuser", "somepass2", 0,
                                 &error);
  if (error) {
    g_test_fail();
    g_test_message("function CryptsetupModuleRekey failed with error: %s",
                   error->message);
    g_error_free(error);
    return;
  }
  if (!result) {
    g_test_fail();
    g_test_message("function CryptsetupModuleInit failed without error");
    return;
  }
}

static void TestDMSetupGetDeviceParams(testFixture *fixture,
                                       gconstpointer userdata) {
  GError *error = NULL;
  gboolean result;
  char **split_params_array;
  char expected_key[] =
      "5d9f64afb7be43713e0ca8e0fb0e26bbf67d26b6bc42f8e2ce96e8bf07fdba58";

  if (g_test_failed()) {
    return;
  }

  result = _DeviceMapperGetParams(kCryptName, &split_params_array, &error);
  if (!result && error) {
    g_test_fail();
    g_test_message("parameter get failed with the following error: %s",
                   error->message);
    g_error_free(error);
    return;
  } else if (!result) {
    g_test_fail();
    g_test_message("parameter get failed without error.");
    return;
  }

  if (0 != strcmp(expected_key, split_params_array[1])) {
    g_test_fail();
    g_test_message("did not get expected value:\n%s !=\n%s", expected_key,
                   split_params_array[1]);
    g_strfreev(split_params_array);
    return;
  }
  g_strfreev(split_params_array);
}

int main(int argc, char **argv) {
  g_test_init(&argc, &argv, NULL);
  g_test_add("/module_root_tests/TestDMSetupGetDeviceParams", testFixture, NULL,
             SetUpTempAndCrypt, TestDMSetupGetDeviceParams,
             TearDownTempAndCrypt);
  g_test_add("/module_root_tests/TestCryptsetupModuleCryptNameArg", testFixture,
             NULL, SetUpTempAndCrypt, TestCryptsetupModuleCryptNameArg,
             TearDownTempAndCrypt);
  g_test_add("/module_root_tests/TestCryptsetupModuleInitEncryption",
             testFixture, NULL, SetUpTempAndCrypt,
             TestCryptsetupModuleInitEncryption, TearDownTempAndCrypt);
  g_test_add("/module_root_tests/TestCryptsetupModuleRetrieveHeaderSlot",
             testFixture, NULL, SetUpTempAndCrypt,
             TestCryptsetupModuleRetrieveHeaderSlot, TearDownTempAndCrypt);
  g_test_add("/module_root_tests/TestCryptsetupModuleRekey", testFixture, NULL,
             SetUpTempAndCrypt, TestCryptsetupModuleRekey,
             TearDownTempAndCrypt);
  g_test_add_func("/module_tests/TestHexStringToByteArray",
                  TestHexStringToByteArray);
  g_test_add_func("/module_tests/TestCryptSetupModuleAllocate",
                  TestCryptSetupModuleAllocate);
  g_test_add_func("/module_tests/TestCryptsetupModuleRetrieveCacheSlot",
                  TestCryptsetupModuleRetrieveCacheSlot);
  g_test_add("/module_tests/TestCryptsetupModuleStoreCache", testFixture, NULL,
             SetUpTemp, TestCryptsetupModuleStoreCache, TearDownTemp);
  g_test_add("/module_tests/TestCryptsetupModuleReadCache", testFixture, NULL,
             SetUpTemp, TestCryptsetupModuleReadCache, TearDownTemp);
  return g_test_run();
}
