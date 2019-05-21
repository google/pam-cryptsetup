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

#include "helper.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sysexits.h>
#include <syslog.h>
#include <unistd.h>

#include <glib.h>
#include <libcryptsetup.h>
#include <libdevmapper.h>

#ifndef HAVE_EXPLICIT_BZERO
    #if __clang__
        __attribute__ (( optnone )) __attribute__ (( noinline )) \
    #elif __GNUC__
        __attribute__ (( optimize( 0 ) )) __attribute__ (( noinline )) \
    #else
        #error "Can't determine compiler attributes for inline and no optimization"
        explode
    #endif
    void explicit_bzero( void * const buf, const size_t n ) {
    	size_t i;
    	unsigned char * p = buf;

    	for( i = 0; i < n; i++ ) {
    		p[ i ] = 0;
    	}
    }
#endif // HAVE_EXPLICIT_BZERO

GQuark _CryptsetupHelperErrorQuark() {
        return g_quark_from_string("pam-cryptsetup-helper-error-quark");
}

gboolean _TrimFgetsInput(char *s, int buf_size, GError **error) {
        char *pos;
        if ((pos=strchr(s, '\n')) != NULL) {
                *pos = '\0';
        }
        else {
                g_set_error(error, kCryptsetupHelperError,
                            kCryptsetupHelperInputError,
                            "Fgets buffer reached max size of %d bytes; input may have been truncated",
                            buf_size);
                return FALSE;
        }
        return TRUE;
}

gboolean _DeviceMapperGetParams(HelperState *self, char ***params_array,GError **error) {
        struct dm_task *task;
        uint64_t start, length;
        char *target_type;
        char *params;

        task = dm_task_create(DM_DEVICE_TABLE);
        if (!task) {
                g_set_error(error, kCryptsetupHelperError, kCryptsetupHelperDeviceMapperTaskError, "Failed to create devicemapper task");
                return FALSE;
        }

        if (!dm_task_set_name(task, self->crypt_mapper_name)) {
                g_set_error(error, kCryptsetupHelperError, kCryptsetupHelperDeviceMapperTaskError, "Failed to set devicemapper task to device name %s", self->crypt_mapper_name);
                return FALSE;
        }

        if (!dm_task_run(task)) {
                g_set_error(error, kCryptsetupHelperError, kCryptsetupHelperDeviceMapperTaskError, "Failed to run devicemapper task");
                return FALSE;
        }

        dm_get_next_target(task, NULL, &start, &length, &target_type, &params);

        *params_array = g_strsplit(params, " ", 0);
        dm_task_destroy(task);
        return TRUE;
}

void _StringToByteArr(char *byte_buffer, char *string) {
        size_t str_len;
        char char_buffer[3] = {'\0', '\0', '\0'};
        char byte;

        str_len = strlen(string);

        for (int i = 0; i < str_len; i += 2) {
                strncpy(char_buffer, string, 2);
                byte = (char)strtol(char_buffer, NULL, 16);
                byte_buffer[i / 2] = byte;
                string += 2;
        }
}

HelperState* HelperStateNew() {
        HelperState *self = g_new0(HelperState, 1);
        for (int i = 0; i < 8; i++) {
                self->userslots[i] = NULL;
        }
        return self;
}

void CryptsetupHelperStateFree(HelperState *self) {
        for (int i = 0; i < 8; i++) {
                g_free(self->userslots[i]);
        }
        if (self->crypt_device) {
                crypt_free(self->crypt_device);
        }
        g_free(self);
}

gboolean CryptsetupHelperStoreCache(HelperState *self, const char *cachepath, GError **error) {
        char *cachefile;

        int r = g_mkdir_with_parents(cachepath, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
        if ((r == -1) && (errno != EEXIST)) {
                g_set_error(error, kCryptsetupHelperError, kCryptsetupHelperCacheError,
                            "Failed to create cache directory %s: %s", cachepath,
                            strerror(errno));
                return FALSE;
        }

        GVariantBuilder builder;
        GVariant *variant;

        g_variant_builder_init(&builder, G_VARIANT_TYPE_STRING_ARRAY);
        for (int i = 0; i < 8; i++) {
                if (self->userslots[i]) {
                        g_variant_builder_add(&builder, "s", self->userslots[i]);
                        syslog(LOG_DEBUG, "Set cache slot %d to '%s'", i, self->userslots[i]);
                } else {
                        g_variant_builder_add(&builder, "s", "");
                        syslog(LOG_DEBUG, "Set cache slot %d to empty", i);
                }
        }
        variant = g_variant_builder_end(&builder);

        gchar *cachedata = g_variant_print(variant, FALSE);
        g_variant_unref(variant);

        if (self->cache_path[0] != 0) {
                cachefile = g_strconcat(self->cache_path, "/", kCryptsetupHelperSlotsCacheFile, NULL);
        } else {
                cachefile = g_strconcat(cachepath, "/", kCryptsetupHelperSlotsCacheFile, NULL);
        }
        
        syslog(LOG_INFO, "Storing cache into %s", cachefile);

        GError *suberror = NULL;
        gboolean result;

        result = g_file_set_contents(cachefile, cachedata, -1, &suberror);
        g_free(cachefile);
        g_free(cachedata);

        if (!result) {
                g_propagate_error(error, suberror);
                return FALSE;
        }

        return TRUE;
}

gboolean CryptsetupHelperReadCache(HelperState *self, const char *cachepath, GError **error) {
        gchar *contents = NULL;
        GError *suberror = NULL;
        char *cachefile;
        gboolean r;

        if (strlen(self->cache_path) > 0) {
                cachefile = g_strconcat(self->cache_path, "/", kCryptsetupHelperSlotsCacheFile, NULL);
        } else {
                cachefile = g_strconcat(cachepath, "/", kCryptsetupHelperSlotsCacheFile, NULL);
        }
        
        syslog(LOG_INFO, "Reading cache from %s", cachefile);

        r = g_file_get_contents(cachefile, &contents, NULL, &suberror);
        g_free(cachefile);

        if (!r) {
                if (suberror->code != G_FILE_ERROR_NOENT) {
                        g_propagate_error(error, suberror);
                        return FALSE;
                } else {
                        // File does not yet exist; not a fail condition.
                        syslog(LOG_INFO, "Cache file does not exist, assuming first run.");
                        return TRUE;
                }
        }

        GVariant *variant = g_variant_parse(G_VARIANT_TYPE_STRING_ARRAY, contents,
                                            NULL, NULL, &suberror);
        g_free(contents);
        if (suberror) {
                g_propagate_error(error, suberror);
                return FALSE;
        }

        gchar *username;
        GVariantIter *iter = g_variant_iter_new(variant);
        for (int i = 0; i < LUKS_NUM_SLOTS; i++) {
                if (!g_variant_iter_next(iter, "s", &username)) {
                        g_set_error(
                                error, kCryptsetupHelperError, kCryptsetupHelperCacheError,
                                "Failed to read slots cache file: not enough values returned (expected %d, got %d)", LUKS_NUM_SLOTS, i);
                        g_variant_iter_free(iter);
                        g_variant_unref(variant);
                        return FALSE;
                }
                self->userslots[i] = username;
                syslog(LOG_DEBUG, "Retreived value '%s' from cache slot %d", username, i);
        }
        g_variant_iter_free(iter);
        g_variant_unref(variant);
        return TRUE;
}

int CryptsetupHelperRetrieveCacheSlot(HelperState *self) {
        int cache_slot = -1;

        for (int i = 0; i < LUKS_NUM_SLOTS; i++) {
                if (g_strcmp0(self->username, self->userslots[i]) == 0) {
                        cache_slot = i;
                        break;
                }
        }
        return cache_slot;
}

void _CryptLog(int level, const char *msg, void *usrptr) {
    syslog(LOG_DEBUG, "libcryptsetup: %s", msg);
}

gboolean CryptsetupHelperInitEncryption(HelperState *self, GError **error) {
        int r;
        r = crypt_init_by_name(&self->crypt_device, self->crypt_mapper_name);
        if (r != 0) {
                g_set_error(error, kCryptsetupHelperError, kCryptsetupHelperCryptInitError,
                            "Failed to initialize crypt device %s: %s (%d)", self->crypt_mapper_name, strerror(-r), -r);
                return FALSE;
        }
        //crypt_set_log_callback(self->crypt_device, _CryptLog, NULL);
        //crypt_set_debug_level(CRYPT_DEBUG_ALL);
        return TRUE;
}

int CryptsetupHelperRetrieveHeaderSlot(HelperState *self, GError **error) {
        // Returns slot number for password in LUKS header, or -1 for none.
        int crypt_slot = -1;

        if (self->old_password[0] != 0) {
                syslog(LOG_INFO, "Checking if old password exists in crypt header");
                crypt_slot = crypt_activate_by_passphrase(self->crypt_device, NULL, CRYPT_ANY_SLOT, self->old_password, strlen(self->old_password), 0);
        } else {
                syslog(LOG_INFO, "Checking if current password exists in crypt header");
                crypt_slot = crypt_activate_by_passphrase(self->crypt_device, NULL, CRYPT_ANY_SLOT, self->password, strlen(self->password), 0);
        }

        if (crypt_slot < 0) {
                g_set_error(error, kCryptsetupHelperError,
                            kCryptsetupHelperCryptKeyslotError,
                            "Failed to find keyslot holding password: %s (%d)",
                            strerror(-crypt_slot), -crypt_slot);
                return -1;
        }

        return crypt_slot;
}

int CryptsetupHelperRekey(HelperState *self, int crypt_slot, GError **error) {
        int r;
        int new_slot;
        char **split_array;
        char *volkey_str;
        size_t volkey_strlen;
        char *volkey_bytearr;
        size_t volkey_arrlen;
        GError *suberror = NULL;

        if (!_DeviceMapperGetParams(self, &split_array, &suberror)) {
                g_propagate_error(error, suberror);
                return -1;
        }

        volkey_str = split_array[DEVICEMAPPER_INDEX_KEY];

        volkey_strlen = strlen(volkey_str);
        volkey_arrlen = volkey_strlen / 2 + volkey_strlen % 2;
        volkey_bytearr = g_malloc(volkey_arrlen);
        _StringToByteArr(volkey_bytearr, volkey_str);
        // Zero sensitive volkey string before free to prevent leaking.
        explicit_bzero(volkey_str, volkey_strlen);
        g_strfreev(split_array);
        
        r = crypt_volume_key_verify(self->crypt_device, volkey_bytearr, volkey_arrlen);
        if (r < 0) {
                g_set_error(error, kCryptsetupHelperError,
                            kCryptsetupHelperCryptVolkeyError,
                            "Failed to retreive valid crypt volume key: %s (%d)",
                            strerror(-r), -r);
                return r;
        }

        // Slot marked in cache is in use, need to do full move.
        r = crypt_keyslot_add_by_volume_key(self->crypt_device, CRYPT_ANY_SLOT, volkey_bytearr, volkey_arrlen, self->password, strlen(self->password));
        if (r < 0) {
                g_set_error(error, kCryptsetupHelperError,
                            kCryptsetupHelperCryptKeyslotError,
                            "Failed to add passphrase to new keyslot: %s (%d)",
                            strerror(-r), -r);
                return r;
        }
        syslog(LOG_NOTICE, "Added new passphrase to slot %d", r);
        new_slot = r;

        r = crypt_keyslot_destroy(self->crypt_device, crypt_slot);
        if (r < 0) {
                g_set_error(error, kCryptsetupHelperError,
                            kCryptsetupHelperCryptKeyslotError,
                            "Failed to destroy old keyslot: %s (%d)",
                            strerror(-r), -r);
                return r;
        }
        syslog(LOG_NOTICE, "Removed old passphrase from slot %d", crypt_slot);
        
        // Zero sensitive volkey byte array before free to prevent leaking.
        explicit_bzero(volkey_bytearr, volkey_arrlen);
        free(volkey_bytearr);
        
        return new_slot;
}

int main(int argc, char *argv[]) {
        GError *error = NULL;

        openlog("PamCryptsetup_Helper", LOG_PERROR | LOG_PID, LOG_USER);
        syslog(LOG_INFO, "Starting");

        if ( -1 == setuid(0)) {
            syslog(LOG_ERR, "Failed to set UID to root.");
            exit(EX_NOPERM);
        }

        syslog(LOG_DEBUG, "uid: %d; euid: %d", getuid(), geteuid());

        HelperState *state = HelperStateNew();

        mlockall(MCL_CURRENT | MCL_FUTURE);
        syslog(LOG_DEBUG, "Process memory locked");

        if (argc < 3) {
                syslog(LOG_ERR, "Too few arguments. Expected: volume_name username [cache_path].");
                exit(EX_USAGE);
        }

        if (argc > 4) {
                syslog(LOG_ERR, "Too many arguments; expected volume_name username [cache_path].");
                exit(EX_USAGE);
        }

        syslog(LOG_DEBUG, "Reading argument 1");
        strncpy(state->crypt_mapper_name, argv[1], STRING_BUFFER_SIZE);
        if (state->crypt_mapper_name[STRING_BUFFER_SIZE - 1] != 0) {
                syslog(LOG_ERR, "Crypt device name overran buffer size of %d bytes.", STRING_BUFFER_SIZE);
                exit(EX_SOFTWARE);
        }
        if (!CryptsetupHelperInitEncryption(state, &error)) {
                syslog(LOG_ERR, "Encryption setup failed: %s", error->message);
                exit(EX_UNAVAILABLE);
        }

        // Indicate encryption setup success to parent process.
        int status = write(3, "1", 1);
        if (status < 1) {
                syslog(LOG_WARNING, "Failed to write success status to login module.");
        }
        close(3);

        syslog(LOG_DEBUG, "Reading argument 2");
        strncpy(state->username, argv[2], STRING_BUFFER_SIZE);
        if (state->username[STRING_BUFFER_SIZE - 1] != 0) {
                syslog(LOG_ERR, "Username overran buffer size of %d bytes.", STRING_BUFFER_SIZE);
                exit(EX_SOFTWARE);
        }
        if (argc == 4) {
                syslog(LOG_DEBUG, "Reading argument 3");
                strncpy(state->cache_path, argv[3], STRING_BUFFER_SIZE);
                if (state->cache_path[STRING_BUFFER_SIZE - 1] != 0) {
                        syslog(LOG_ERR, "Cache path overran buffer size of %d bytes.", STRING_BUFFER_SIZE);
                        exit(EX_SOFTWARE);
                }
                syslog(LOG_INFO, "Setting cache path to %s", state->cache_path);
        }

        syslog(LOG_DEBUG, "Reading password from login module.");
        if (fgets(state->password, PASSWORD_BUFFER_SIZE, stdin) == NULL) {
                syslog(LOG_ERR, "Did not receive password token from login module.");
                exit(EX_SOFTWARE);
        }
        if (!_TrimFgetsInput(state->password, PASSWORD_BUFFER_SIZE, &error)) {
                syslog(LOG_ERR, "Parsing password token failed: %s", error->message);
                exit(EX_SOFTWARE);
        }
        syslog(LOG_DEBUG, "Reading old_password from login module.");
        if (fgets(state->old_password, PASSWORD_BUFFER_SIZE, stdin) == NULL) {
                syslog(LOG_INFO, "Did not receive old_password token from login module");
        }
        close(STDIN_FILENO);
        // Value is optional, so check for existance before trim
        if (state->old_password[0] != 0) {
                if (!_TrimFgetsInput(state->old_password, PASSWORD_BUFFER_SIZE, &error)) {
                        syslog(LOG_ERR, "Parsing old_password token failed: %s", error->message);
                        exit(EX_SOFTWARE);
                }
                _HelperPassMode(state);
        }
        _HelperAuthMode(state);
}

void _HelperAuthMode(HelperState *self) {
        GError *error = NULL;
        int cache_slot;
        int crypt_slot;

        if (!CryptsetupHelperReadCache(self, CACHE_DIR, &error)) {
                syslog(LOG_ERR, "Cache read failed with error: %s", error->message);
                exit(EX_IOERR);
        }

        cache_slot = CryptsetupHelperRetrieveCacheSlot(self);
        syslog(LOG_INFO, "Cache slot check for username '%s' returned %d", self->username, cache_slot);
        crypt_slot = CryptsetupHelperRetrieveHeaderSlot(self, &error);
        // Ignore possible errors since password may not match current
        // LUKS passphrase.
        syslog(LOG_INFO, "Crypt slot check returned %d", crypt_slot);
        g_clear_error(&error);

        if (cache_slot != -1) {
                if (crypt_slot != -1) {
                        if (cache_slot != crypt_slot) {
                                syslog(LOG_NOTICE, "Moving '%s' from cache slot %d to cache slot %d", self->username, cache_slot, crypt_slot);
                                g_free(self->userslots[cache_slot]);
                                self->userslots[cache_slot] = g_malloc0(1);
                                g_free(self->userslots[crypt_slot]);
                                self->userslots[crypt_slot] = g_malloc(strlen(self->username) + 1);
                                strcpy(self->userslots[crypt_slot], self->username);
                        }
                } else {
                        syslog(LOG_NOTICE, "Updating crypt header");
                        crypt_slot = CryptsetupHelperRekey(self, cache_slot, &error);
                        if (error) {
                                syslog(LOG_ERR, "Failed to perform rekey: %s", error->message);
                                exit(EX_UNAVAILABLE);
                        }
                        syslog(LOG_NOTICE, "Moving user '%s' from cache slot %d to cache slot %d", self->username, cache_slot, crypt_slot);
                        g_free(self->userslots[cache_slot]);
                        self->userslots[cache_slot] = NULL;
                        g_free(self->userslots[crypt_slot]);
                        self->userslots[crypt_slot] = g_malloc(strlen(self->username) + 1);
                        strcpy(self->userslots[crypt_slot], self->username);
                }
        } else if ((cache_slot == -1) && (crypt_slot != -1)) {
                syslog(LOG_NOTICE, "Recording user %s in cache slot %d", self->username, crypt_slot);
                g_free(self->userslots[crypt_slot]);
                self->userslots[crypt_slot] = g_malloc(strlen(self->username) + 1);
                strcpy(self->userslots[crypt_slot], self->username);
        } else if ((cache_slot == -1) && (crypt_slot == -1)) {
            // User is not recognized, don't touch disk or cache.
            syslog(LOG_NOTICE, "Unable to identify user '%s', not making changes.", self->username);
        };

        if (!CryptsetupHelperStoreCache(self, CACHE_DIR, &error)) {
                syslog(LOG_ERR, "Failed to store new cache: %s", error->message);
                exit(EX_IOERR);
        }

        exit(EX_OK);
}

void _HelperPassMode(HelperState *self) {
        GError *error = NULL;
        int crypt_slot;
        int cache_slot;

        crypt_slot = CryptsetupHelperRetrieveHeaderSlot(self, &error);
        if (error) {
                syslog(LOG_ERR, "Failed to retrieve current crypt slot: %s", error->message);
                exit(EX_UNAVAILABLE);
        }
        syslog(LOG_INFO, "Crypt slot check returned %d", crypt_slot);

        if (crypt_slot != -1) {
                syslog(LOG_NOTICE, "Updating passphrase in slot %d", crypt_slot);
                crypt_slot = CryptsetupHelperRekey(self, crypt_slot, &error);
                if (error) {
                        syslog(LOG_ERR, "Failed to update passphrase: %s", error->message);
                        exit(EX_UNAVAILABLE);
                }
        } else {
                syslog(LOG_WARNING, "Failed to find old passphrase, not replacing");
                return;
        }

        // Update cache if entry exists for user
        if (!CryptsetupHelperReadCache(self, CACHE_DIR, &error)) {
                syslog(LOG_NOTICE, "Unable to retrieve cache info: %s", error->message);
                syslog(LOG_NOTICE, "Skipping cache update");
                exit(EX_OK);
        }
        cache_slot = CryptsetupHelperRetrieveCacheSlot(self);
        syslog(LOG_INFO, "Cache slot check for username '%s' returned %d", self->username, cache_slot);

        if (cache_slot != -1) {
                if (cache_slot != crypt_slot) {
                        syslog(LOG_NOTICE, "Moving user '%s' from cache slot %d to cache slot %d", self->username, cache_slot, crypt_slot);
                        g_free(self->userslots[cache_slot]);
                        self->userslots[cache_slot] = g_malloc0(1);
                        g_free(self->userslots[crypt_slot]);
                        self->userslots[crypt_slot] = g_malloc(strlen(self->username) + 1);
                        strcpy(self->userslots[crypt_slot], self->username);
                } else {
                        syslog(LOG_NOTICE, "Recording user '%s' in cache slot %d", self->username, crypt_slot);
                        g_free(self->userslots[crypt_slot]);
                        self->userslots[crypt_slot] = g_malloc(strlen(self->username) + 1);
                        strcpy(self->userslots[crypt_slot], self->username);
                }
        }

        if (!CryptsetupHelperStoreCache(self, CACHE_DIR, &error)) {
                syslog(LOG_ERR, "Failed to store new cache: %s", error->message);
                exit(EX_IOERR);
        }

        exit(EX_OK);
}
