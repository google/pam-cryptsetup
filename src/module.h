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

#include <glib.h>
#include <libcryptsetup.h>

#define kCryptsetupModuleError _CryptsetupModuleErrorQuark()

typedef enum {
  kCryptsetupModuleGetItemError,
  kCryptsetupModuleArgumentError,
  kCryptsetupModuleCacheError,
  kCryptsetupModuleCryptInitError,
  kCryptsetupModuleCryptLoadError,
  kCryptsetupModuleCryptKeyslotError,
  kCryptsetupModuleCryptVolkeyError,
  kCryptsetupModuleDeviceMapperTaskError,
  kCryptsetupModuleThreadError,
} CryptsetupModuleError;

typedef struct {
  char *userslots[8];
  struct crypt_device *crypt_device;
  char *crypt_mapper_name;
  gboolean debug;
} CryptsetupModule;

CryptsetupModule *CryptsetupModuleNew();
void CryptsetupModuleFree(CryptsetupModule *self);

gboolean CryptsetupModuleAddArg(CryptsetupModule *self, const char *arg,
                                GError **error);
gboolean CryptsetupModuleStoreCache(CryptsetupModule *self,
                                    const char *cachepath, GError **error);
gboolean CryptsetupModuleReadCache(CryptsetupModule *self,
                                   const char *cachepath, GError **error);
gboolean CryptsetupModuleVerifyCryptName(CryptsetupModule *self,
                                         GError **error);
gboolean CryptsetupModuleInitEncryption(CryptsetupModule *self, GError **error);
int CryptsetupModuleRetrieveCacheSlot(CryptsetupModule *self,
                                      const char *username);
int CryptsetupModuleRetrieveHeaderSlot(CryptsetupModule *self,
                                       const char *password, GError **error);
int CryptsetupModuleRekey(CryptsetupModule *self, const char *username,
                          const char *password, int slot, GError **error);
gboolean _DeviceMapperGetParams(const char *root_name, char ***params_array,
                                GError **error);
void _StringToByteArr(char *byte_buffer, char *string);


GQuark _CryptsetupModuleErrorQuark();
