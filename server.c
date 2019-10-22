//#include "config.h"
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static int auth_password(char *user, char *password) {
	if (strcmp(user, "atarget")) return 0;
	if (strcmp(password, "atarget")) return 0;
	return 1;
}

int main() {
	ssh_bind sshbind = ssh_bind_new();
	ssh_session session = ssh_new();
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT_STR, "900");
	//ssh_disconnect(session);
	//ssh_bind_free(sshbind);
	ssh_finalize();
	return 0;
}
