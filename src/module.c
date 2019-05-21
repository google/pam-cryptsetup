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
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sysexits.h>
#include <syslog.h>
#include <unistd.h>

#include <glib.h>

#define PAM_SM_AUTH
#include <security/pam_ext.h>
#include <security/pam_modules.h>

GQuark _CryptsetupModuleErrorQuark() {
        return g_quark_from_string("pam-cryptsetup-module-error-quark");
}

CryptsetupModule* CryptsetupModuleNew() {
        CryptsetupModule *self = g_new0(CryptsetupModule, 1);
        self->debug = FALSE;
        self->background = TRUE;
        return self;
}

void CryptsetupModuleFree(CryptsetupModule *self) {
        g_free(self->crypt_mapper_name);
        g_free(self);
}

gboolean CryptsetupModuleAddArg(CryptsetupModule *self, const char *arg, GError **error) {
        char **split_arg;

        split_arg = g_strsplit(arg, "=", 2);

        if (split_arg[1] == NULL) {
                g_set_error(error, kCryptsetupModuleError, kCryptsetupModuleArgumentError, "invalid argument '%s': args must be 'key=value' pairs", arg);
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
        } else if (0 == strcmp(split_arg[0], "background")) {
                if (0 == strcmp(split_arg[1], "false")) {
                        self->background = FALSE;
                } else {
                        self->background = TRUE;
                }
        }else {
                g_set_error(error, kCryptsetupModuleError, kCryptsetupModuleArgumentError, "invalid argument '%s'", arg);
                return FALSE;
        }

        g_strfreev(split_arg);
        return TRUE;
}

static const char *PamGetItemString(pam_handle_t *pamh, int type, const char *name, GError **error) {
        const char *value = NULL;
        int result = pam_get_item(pamh, type, (const void **)&value);
        if (result != PAM_SUCCESS) {
                g_set_error(error, kCryptsetupModuleError, kCryptsetupModuleGetItemError, "failed to get %s: %s", name, pam_strerror(pamh, result));
                return NULL;
        }
        if (value == NULL || strlen(value) == 0) {
                g_set_error(error, kCryptsetupModuleError, kCryptsetupModuleGetItemError, "no %s available", name);
                return NULL;
        }
        return value;
}

int _StartModuleProcess(pam_handle_t *pamh, int flags, int argc, const char **argv, int mode) {
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
        }

        const gchar *username = PamGetItemString(pamh, PAM_USER, "username", &error);
        if (!username) {
                goto done;
        }

        const gchar *password = PamGetItemString(pamh, PAM_AUTHTOK, "password", &error);
        if(error != NULL) {
            goto done;
        }
        if (!password) {
                g_set_error(&error, kCryptsetupModuleError, kCryptsetupModuleGetItemError, "Disallowing null auth token");
                goto done;
        }

        const gchar *old_password =
                PamGetItemString(pamh, PAM_OLDAUTHTOK, "old_password", &error);
        if (mode == CRED && !old_password) {
                goto done;
        }
        // Prevent overwriting an ignored error
        g_clear_error(&error);

        pid_t child_pid;
        int status = 0;
        int pfd[2];
        int opfd[2];
        if ((pipe2(pfd, O_CLOEXEC) | pipe2(opfd, O_CLOEXEC)) == -1) {
            g_set_error(&error, kCryptsetupModuleError, kCryptSetupModuleProcessError, "Failed to create comminucation pipes.");
            if (!(flags & PAM_SILENT)) {
                pam_error(pamh, "Failed to create communication pipes.");
            }
            goto done;
        }
        close(pfd[0]);
        close(opfd[1]);
        child_pid = fork();
        if (child_pid == 0) {
                // Start child process
                dup2(pfd[0], STDIN_FILENO);
                dup2(opfd[1], 3);
                close(pfd[0]);
                close(pfd[1]);
                close(opfd[0]);
                close(opfd[1]);
                execl(HELPER_EXEC, module->crypt_mapper_name, username, (char *)NULL);
                // If we get here, execute failed.
                exit(EX_OSERR);
                // End child process
        }

        if (module->debug) {
                pam_syslog(pamh, LOG_INFO, "Spawned encryption process under PID %d", child_pid);
        }
        
        int result = 0;
        
        result |= write(pfd[1], password, strlen(password));
        result |= write(pfd[1], "\n", 1);
        if (old_password) {
            result |= write(pfd[1], old_password, strlen(old_password));
            result |= write(pfd[1], "\n", 1);
        }
        close(pfd[1]);
        
        if (result < 0) {
            g_set_error(&error, kCryptsetupModuleError, kCryptSetupModuleProcessError, "Failed to write to helper process.");
            goto done;
        }

        char* output[2];
        status = read(opfd[0], output, 1);
        
        if (status == 1) {
            pam_syslog(pamh, LOG_INFO, "Encryption helper sucessfully opened crypt volume %s.", module->crypt_mapper_name);
            if (!(flags & PAM_SILENT)) {
                pam_info(pamh, "Crypt update process started.");
            }
        } else {
            g_set_error(&error, kCryptsetupModuleError, kCryptSetupModuleProcessError, "Encryption helper failed to open crypt volume %s.", module->crypt_mapper_name);
            goto done;
        }

        if (!module->background) {
                pam_syslog(pamh, LOG_INFO, "Waiting for encryption process to finish.");
                waitpid(child_pid, &status, 0);

                if (WIFEXITED(status)) {
                        int exit_status = WEXITSTATUS(status);
                        if (exit_status == 0) {
                                pam_syslog(pamh, LOG_NOTICE, "Encryption helper ran successfully.");
                                if (!(flags & PAM_SILENT)) {
                                    pam_info(pamh, "Crypt update process completed successfully.");
                                }
                        } else {
                                g_set_error(&error, kCryptsetupModuleError, kCryptSetupModuleProcessError, "Encryption helper failed with exit code %d; see syslog for details.", exit_status);
                                goto done;
                        }
                } else {
                        g_set_error(&error, kCryptsetupModuleError, kCryptSetupModuleProcessError, "Encryption helper died unexpectedly; see syslog for details.");
                        goto done;
                }
        }

done:
        if (error) {
                pam_syslog(pamh, LOG_ERR, "Module run failed: %s", error->message);
                if (!(flags & PAM_SILENT)) {
                    pam_error(pamh, "%s", error->message);
                }
                g_error_free(error);
        }

        CryptsetupModuleFree(module);
        return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
        return _StartModuleProcess(pamh, flags, argc, argv, AUTH);
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {

        return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
        return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
        return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
        return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
        return _StartModuleProcess(pamh, flags, argc, argv, CRED);
}
