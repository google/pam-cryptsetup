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

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>

#include <glib.h>
#include <libcryptsetup.h>
#include <libdevmapper.h>

#define PAM_SM_AUTH
#include <security/pam_ext.h>
#include <security/pam_modules.h>

#define kCryptsetupModuleCacheDir "/var/cache/libpam-cryptsetup"
#define kCryptsetupModuleSlotsCacheFile "slots"

#define kStackSize 16 * 1024

typedef struct {
  CryptsetupModule *module;
  pam_handle_t *pamh;
  const char *username;
  const char *password;
} CloneStruct;

GQuark _CryptsetupModuleErrorQuark() {
  return g_quark_from_string("cryptsetup-module-error-quark");
}

gboolean _DeviceMapperGetParams(const char *root_name, char ***params_array,
                                GError **error) {
  struct dm_task *task;
  uint64_t start, length;
  char *target_type;
  char *params;

  task = dm_task_create(DM_DEVICE_TABLE);
  if (!task) {
    g_set_error(error, kCryptsetupModuleError,
                kCryptsetupModuleDeviceMapperTaskError,
                "failed to create devicemapper task");
    return FALSE;
  }

  if (!dm_task_set_name(task, root_name)) {
    g_set_error(error, kCryptsetupModuleError,
                kCryptsetupModuleDeviceMapperTaskError,
                "failed to set devicemapper task to device name %s", root_name);
    return FALSE;
  }

  if (!dm_task_run(task)) {
    g_set_error(error, kCryptsetupModuleError,
                kCryptsetupModuleDeviceMapperTaskError,
                "failed to run devicemapper task");
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

CryptsetupModule *CryptsetupModuleNew() {
  CryptsetupModule *self = g_new0(CryptsetupModule, 1);
  for (int i = 0; i < 8; i++) {
    self->userslots[i] = NULL;
  }
  self->debug = FALSE;
  return self;
}

void CryptsetupModuleFree(CryptsetupModule *self) {
  for (int i = 0; i < 8; i++) {
    g_free(self->userslots[i]);
  }
  if (self->crypt_device) {
    crypt_free(self->crypt_device);
  }
  g_free(self->crypt_mapper_name);
  g_free(self);
}

gboolean CryptsetupModuleAddArg(CryptsetupModule *self, const char *arg,
                                GError **error) {
  char **split_arg;

  split_arg = g_strsplit(arg, "=", 0);

  if (split_arg[1] == NULL) {
    g_set_error(error, kCryptsetupModuleError, kCryptsetupModuleArgumentError,
                "invalid argument '%s': args must be 'key=value' pairs", arg);
    g_strfreev(split_arg);
    return FALSE;
  }

  if (0 == strcmp(split_arg[0], "crypt_name")) {
    self->crypt_mapper_name = g_malloc(strlen(split_arg[1]) + 1);
    strcpy(self->crypt_mapper_name, split_arg[1]);
  } else if (0 == strcmp(split_arg[0], "debug")) {
    if (0 == strcmp(split_arg[1], "true")) {
      self->debug = TRUE;
    } else {
      self->debug = FALSE;
    }
  } else {
    g_set_error(error, kCryptsetupModuleError, kCryptsetupModuleArgumentError,
                "invalid argument '%s'", arg);
    return FALSE;
  }

  g_strfreev(split_arg);
  return TRUE;
}

gboolean CryptsetupModuleInitEncryption(CryptsetupModule *self,
                                        GError **error) {
  int r;
  char *devno_str;
  char *devno_path;
  char *device_name;
  char *device_path;
  char *real_path;
  char **split_array;
  GError *suberror;

  if (!_DeviceMapperGetParams(self->crypt_mapper_name, &split_array,
                              &suberror)) {
    if (suberror) {
      g_propagate_error(error, suberror);
    }
    return FALSE;
  }

  devno_str = split_array[3];
  devno_path = g_strconcat("/sys/dev/block/", devno_str, NULL);
  g_strfreev(split_array);
  real_path = realpath(devno_path, NULL);
  device_name = g_path_get_basename(real_path);
  g_free(real_path);
  device_path = g_strconcat("/dev/", device_name, NULL);
  g_free(device_name);
  g_free(devno_path);

  r = crypt_init(&(self->crypt_device), device_path);
  if (r < 0) {
    g_set_error(error, kCryptsetupModuleError, kCryptsetupModuleCryptInitError,
                "failed to init crypt container %s: %s (%d)", device_path,
                strerror(-r), -r);
    g_free(device_path);
    return FALSE;
  }

  r = crypt_load(self->crypt_device, CRYPT_LUKS1, NULL);
  if (r < 0) {
    g_set_error(error, kCryptsetupModuleError, kCryptsetupModuleCryptLoadError,
                "failed to load crypt container %s: %s (%d)", device_path,
                strerror(-r), -r);
    g_free(device_path);
    return FALSE;
  }

  g_free(device_path);
  return TRUE;
}

gboolean CryptsetupModuleStoreCache(CryptsetupModule *self,
                                    const char *cachepath, GError **error) {
  int r = mkdir(cachepath, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
  if ((r == -1) && (errno != EEXIST)) {
    g_set_error(error, kCryptsetupModuleError, kCryptsetupModuleCacheError,
                "failed to create cache directory %s: %s", cachepath,
                strerror(errno));
    return FALSE;
  }

  GVariantBuilder builder;
  GVariant *variant;

  g_variant_builder_init(&builder, G_VARIANT_TYPE_STRING_ARRAY);
  for (int i = 0; i < 8; i++) {
    if (self->userslots[i]) {
      g_variant_builder_add(&builder, "s", self->userslots[i]);
    } else {
      g_variant_builder_add(&builder, "s", "");
    }
  }
  variant = g_variant_builder_end(&builder);

  gchar *cachedata = g_variant_print(variant, FALSE);
  g_variant_unref(variant);

  char *cachefile =
      g_strconcat(cachepath, "/", kCryptsetupModuleSlotsCacheFile, NULL);

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

gboolean CryptsetupModuleReadCache(CryptsetupModule *self,
                                   const char *cachepath, GError **error) {
  gchar *contents = NULL;
  GError *suberror = NULL;
  gboolean r;

  char *cachefile =
      g_strconcat(cachepath, "/", kCryptsetupModuleSlotsCacheFile, NULL);

  r = g_file_get_contents(cachefile, &contents, NULL, &suberror);
  g_free(cachefile);

  if (!r) {
    if (suberror->code != G_FILE_ERROR_NOENT) {
      g_propagate_error(error, suberror);
      return FALSE;
    } else {
      // File does not yet exist; not a fail condition.
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
  for (int i = 0; i < 8; i++) {
    if (!g_variant_iter_next(iter, "s", &username)) {
      g_set_error(
          error, kCryptsetupModuleError, kCryptsetupModuleCacheError,
          "failed to read slots cache file: not enough values returned");
      g_variant_iter_free(iter);
      g_variant_unref(variant);
      return FALSE;
    }
    self->userslots[i] = username;
  }
  g_variant_iter_free(iter);
  g_variant_unref(variant);
  return TRUE;
}

gboolean CryptsetupModuleVerifyCryptName(CryptsetupModule *self,
                                         GError **error) {
  char *crypt_path;
  int result;
  struct stat st;

  if (!self->crypt_mapper_name) {
    g_set_error(error, kCryptsetupModuleError, kCryptsetupModuleArgumentError,
                "required argument crypt_name was not given");
    return FALSE;
  }

  crypt_path = g_strconcat("/dev/mapper/", self->crypt_mapper_name, NULL);
  result = stat(crypt_path, &st);
  g_free(crypt_path);
  if (result != 0) {
    g_set_error(error, kCryptsetupModuleError, kCryptsetupModuleArgumentError,
                "failed to verify crypt device '%s': stat: %s (%d)",
                self->crypt_mapper_name, strerror(errno), errno);
    return FALSE;
  }
  if (!S_ISBLK(st.st_mode)) {
    g_set_error(error, kCryptsetupModuleError, kCryptsetupModuleArgumentError,
                "failed to verify crypt device '%s': %s is not block device in "
                "/dev/mapper",
                self->crypt_mapper_name, self->crypt_mapper_name);
    return FALSE;
  }
  return TRUE;
}

int CryptsetupModuleRetrieveCacheSlot(CryptsetupModule *self,
                                      const char *username) {
  int cache_slot = -1;

  for (int i = 0; i < 8; i++) {
    if (g_strcmp0(username, self->userslots[i]) == 0) {
      cache_slot = i;
      break;
    }
  }
  return cache_slot;
}

int CryptsetupModuleRetrieveHeaderSlot(CryptsetupModule *self,
                                       const char *password, GError **error) {
  // Returns slot number for password in LUKS header, or -1 for none.
  int crypt_slot = -1;
  int crypt_slots[8] = {-1};

  for(int i = 0; i < 8; i++) {
    crypt_slots[i] = crypt_activate_by_passphrase(
        self->crypt_device, NULL, i, password, strlen(password), 0);
  }

  for(int i = 0; i < 8; i++) {
    if (crypt_slots[i] == -1) {
      // Password didn't match slot (Operation not permitted).
      continue;
    } else if (crypt_slots[i] == -2) {
      // Specified slot is empty (No such file or directory).
      continue;
    } else if (crypt_slots[i] < 0) {
      g_set_error(error, kCryptsetupModuleError,
                  kCryptsetupModuleCryptKeyslotError,
                  "failed to find keyslot holding password: %s (%d)",
                  strerror(-crypt_slots[i]), -crypt_slots[i]);
      return -1;
    } else {
      crypt_slot = crypt_slots[i];
    }
  }
  return crypt_slot;
}

int CryptsetupModuleRekey(CryptsetupModule *self, const char *username,
                          const char *password, int slot, GError **error) {
  int r;
  int new_slot;
  char **split_array;
  char *volkey_str;
  size_t volkey_strlen;
  char *volkey_bytearr;
  size_t volkey_arrlen;
  GError *suberror = NULL;

  if (!_DeviceMapperGetParams(self->crypt_mapper_name, &split_array,
                              &suberror)) {
    g_propagate_error(error, suberror);
    return -1;
  }

  volkey_str = split_array[1];

  volkey_strlen = strlen(volkey_str);
  volkey_arrlen = volkey_strlen / 2 + volkey_strlen % 2;
  volkey_bytearr = g_malloc(volkey_arrlen);
  _StringToByteArr(volkey_bytearr, volkey_str);
  g_strfreev(split_array);
  r = crypt_volume_key_verify(self->crypt_device, volkey_bytearr,
                              volkey_arrlen);
  if (r < 0) {
    g_set_error(error, kCryptsetupModuleError,
                kCryptsetupModuleCryptKeyslotError,
                "volume key not valid: %s (%d)", strerror(-r), -r);
    return -1;
  }

  // Add new key before removing old one, to prevent leaving disk without
  // a passphrase set.
  new_slot = crypt_keyslot_add_by_volume_key(self->crypt_device, CRYPT_ANY_SLOT,
                                             volkey_bytearr, volkey_arrlen,
                                             password, strlen(password));
  g_free(volkey_bytearr);
  if (new_slot < 0) {
    g_set_error(error, kCryptsetupModuleError,
                kCryptsetupModuleCryptKeyslotError,
                "failed to write new passphrase: %s (%d)", strerror(-r), -r);
    return -1;
  }
  r = crypt_keyslot_destroy(self->crypt_device, slot);
  if (r < 0) {
    g_set_error(
        error, kCryptsetupModuleError, kCryptsetupModuleCryptKeyslotError,
        "failed to destroy keyslot %d: %s (%d)", slot, strerror(-r), -r);
    return -1;
  }

  return new_slot;
}

static const char *PamGetItemString(pam_handle_t *pamh, int type,
                                    const char *name, GError **error) {
  const char *value = NULL;
  int result = pam_get_item(pamh, type, (const void **)&value);
  if (result != PAM_SUCCESS) {
    g_set_error(error, kCryptsetupModuleError, kCryptsetupModuleGetItemError,
                "failed to get %s: %s", name, pam_strerror(pamh, result));
    return NULL;
  }
  if (value == NULL || strlen(value) == 0) {
    g_set_error(error, kCryptsetupModuleError, kCryptsetupModuleGetItemError,
                "no %s available", name);
    return NULL;
  }
  return value;
}

static int clone_function(void *arg) {
  CloneStruct *clonestruct = (CloneStruct *)arg;
  CryptsetupModule *module = clonestruct->module;
  pam_handle_t *pamh = clonestruct->pamh;
  const char *username = clonestruct->username;
  const char *password = clonestruct->password;
  int cache_slot;
  int crypt_slot;
  GError *error = NULL;

  // Set our UID to root to match our EUID
  // Prevent privilage de-escalation by libgcrypt memory protection
  if (module->debug) {
    uid_t olduid = getuid();
    pam_syslog(pamh, LOG_INFO, "Crypt thread: thread started");
    pam_syslog(pamh, LOG_INFO, "Crypt thread: dropping uid %d for uid 0",
               olduid);
  }
  if (setuid(0) != 0) {
    g_set_error(&error, kCryptsetupModuleError, kCryptsetupModuleGetItemError,
                "Crypt thread: failed to setuid to 0: %s (%d)", strerror(errno),
                errno);
    goto done;
  }

  if (!CryptsetupModuleInitEncryption(module, &error)) {
    goto done;
  }

  cache_slot = CryptsetupModuleRetrieveCacheSlot(module, username);
  crypt_slot = CryptsetupModuleRetrieveHeaderSlot(module, password, &error);
  if (error) {
    goto done;
  }
  if (module->debug) {
    pam_syslog(pamh, LOG_INFO, "Crypt thread: cache slot: %d", cache_slot);
    pam_syslog(pamh, LOG_INFO, "Crypt thread: crypt slot: %d", crypt_slot);
  }
  if (cache_slot != -1) {
    if (crypt_slot != -1) {
      if (cache_slot != crypt_slot) {
        if (module->debug) {
          pam_syslog(
              pamh, LOG_INFO,
              "Crypt thread: moving %s from cache slot %d to cache slot %d",
              username, cache_slot, crypt_slot);
        }
        g_free(module->userslots[cache_slot]);
        module->userslots[cache_slot] = g_malloc0(1);
        g_free(module->userslots[crypt_slot]);
        module->userslots[crypt_slot] = g_malloc(strlen(username) + 1);
        strcpy(module->userslots[crypt_slot], username);
      }
    } else {
      if (module->debug) {
        pam_syslog(pamh, LOG_INFO,
                   "Crypt thread: removing key from crypt slot %d and adding "
                   "new key to crypt header",
                   cache_slot);
      }
      crypt_slot =
          CryptsetupModuleRekey(module, username, password, cache_slot, &error);
      if (error) {
        goto done;
      }
      if (module->debug) {
        pam_syslog(
            pamh, LOG_INFO,
            "Crypt thread: moving %s from cache slot %d to cache slot %d",
            username, cache_slot, crypt_slot);
      }
      g_free(module->userslots[cache_slot]);
      module->userslots[cache_slot] = NULL;
      g_free(module->userslots[crypt_slot]);
      module->userslots[crypt_slot] = g_malloc(strlen(username) + 1);
      strcpy(module->userslots[crypt_slot], username);
    }
  } else if ((cache_slot == -1) && (crypt_slot != -1)) {
    if (module->debug) {
      pam_syslog(pamh, LOG_INFO, "Crypt thread: recording %s in cache slot %d",
                 username, crypt_slot);
    }
    g_free(module->userslots[crypt_slot]);
    module->userslots[crypt_slot] = g_malloc(strlen(username) + 1);
    strcpy(module->userslots[crypt_slot], username);
  }

  if (!CryptsetupModuleStoreCache(module, kCryptsetupModuleCacheDir, &error)) {
    goto done;
  }

done:

  if (module->debug) {
    pam_syslog(pamh, LOG_INFO, "Crypt thread: cleaning up");
  }
  if (error) {
    pam_syslog(pamh, LOG_WARNING, "Crypt thread: Error: %s", error->message);
    g_error_free(error);
    return -1;
  }

  return 0;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                                   const char **argv) {
  void *stack = NULL;
  GError *error = NULL;

  CryptsetupModule *module = CryptsetupModuleNew();
  for (guint i = 0; i < argc; i++) {
    if (!CryptsetupModuleAddArg(module, argv[i], &error)) {
      goto done;
    }
  }
  if (module->debug) {
    pam_syslog(pamh, LOG_INFO, "Debugging enabled");
    pam_syslog(pamh, LOG_INFO, "Raw flag variable: 0x%X", flags);
    if (PAM_SILENT & flags) {
      pam_syslog(pamh, LOG_INFO, "PAM_SILENT flag enabled");
    }
    if (PAM_DISALLOW_NULL_AUTHTOK & flags) {
      pam_syslog(pamh, LOG_INFO, "PAM_DISALLOW_NULL_AUTHTOK flag enabled");
    }
    pam_syslog(pamh, LOG_INFO, "Start: UID Real: %d Effective: %d", getuid(),
               geteuid());
  }

  if (!CryptsetupModuleVerifyCryptName(module, &error)) {
    goto done;
  }

  const gchar *username = PamGetItemString(pamh, PAM_USER, "username", &error);
  if (!username) {
    goto done;
  }

  const gchar *password = PamGetItemString(pamh, PAM_AUTHTOK, "password", &error);
  if (!password && (PAM_DISALLOW_NULL_AUTHTOK & flags)) {
    CryptsetupModuleFree(module);
    return PAM_AUTH_ERR;
  } else if (!password) {
    goto done;
  }

  if (!CryptsetupModuleReadCache(module, kCryptsetupModuleCacheDir, &error)) {
    goto done;
  }

  stack = g_malloc(kStackSize);
  CloneStruct clonestruct = {module, pamh, username, password};
  pid_t pid = clone(clone_function, stack + kStackSize, 0, &clonestruct);
  if (pid == -1) {
    g_set_error(&error, kCryptsetupModuleError, kCryptsetupModuleThreadError,
                "failed to start crypt thread: %s (%d)", strerror(errno),
                errno);
    goto done;
  }
  int status = 0;
  if (waitpid(pid, &status, __WCLONE) == -1) {
    g_set_error(&error, kCryptsetupModuleError, kCryptsetupModuleThreadError,
                "failed to block on crypt thread: %s (%d)", strerror(errno),
                errno);
    goto done;
  }

done:
  g_free(stack);

  if (error) {
    pam_syslog(pamh, LOG_WARNING, "Error: %s", error->message);
    g_error_free(error);
  }

  if (module->debug) {
    pam_syslog(pamh, LOG_INFO, "End: UID Real: %d Effective: %d", getuid(),
               geteuid());
  }

  CryptsetupModuleFree(module);

  return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
                              const char **argv) {
  return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc,
                                const char **argv) {
  return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
                                   const char **argv) {
  return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc,
                                    const char **argv) {
  return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc,
                                const char **argv) {
  return PAM_IGNORE;
}
