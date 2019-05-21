// Copyright 2019 Google Inc.
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

#ifndef PAMCRYPTSETUP_HELPER_H
#define PAMCRYPTSETUP_HELPER_H

#include <glib.h>
#include <libcryptsetup.h>
#include <sys/stat.h>
#include <sys/types.h>

#define LUKS_NUM_SLOTS 8

#define STRING_BUFFER_SIZE 100
#define PASSWORD_BUFFER_SIZE 512  // 512 is LUKS's max passphrase size.

#define DEVICEMAPPER_INDEX_KEY 1

#define kCryptsetupHelperSlotsCacheFile "slots"

#define kCryptsetupHelperError _CryptsetupHelperErrorQuark()

typedef enum {
        kCryptsetupHelperCacheError,
        kCryptsetupHelperCryptInitError,
        kCryptsetupHelperCryptKeyslotError,
        kCryptsetupHelperCryptVolkeyError,
        kCryptsetupHelperDeviceMapperTaskError,
        kCryptsetupHelperInputError,
} CryptsetupHelperError;

typedef struct {
        char *userslots[LUKS_NUM_SLOTS];
        char username[STRING_BUFFER_SIZE];
        char password[PASSWORD_BUFFER_SIZE];
        char old_password[PASSWORD_BUFFER_SIZE];
        char cache_path[STRING_BUFFER_SIZE];
        struct crypt_device *crypt_device;
        char crypt_mapper_name[STRING_BUFFER_SIZE];
} HelperState;

HelperState* HelperStateNew();
void CryptsetupHelperStateFree(HelperState*);

gboolean _TrimFgetsInput(char[], int, GError**);
gboolean CryptsetupHelperStoreCache(HelperState*, const char*, GError**);
gboolean CryptsetupHelperReadCache(HelperState*, const char *, GError**);
int CryptsetupHelperRetrieveCacheSlot(HelperState*);
gboolean CryptsetupHelperInitEncryption(HelperState*, GError**);
int CryptsetupHelperRetrieveHeaderSlot(HelperState*, GError**);
int CryptsetupHelperRekey(HelperState*, int, GError**);
void _HelperAuthMode(HelperState*);
void _HelperPassMode(HelperState*);

GQuark _CryptsetupHelperErrorQuark();

#endif //PAMCRYPTSETUP_HELPER_H
