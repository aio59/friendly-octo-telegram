#include <libssh/libssh.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int ssh_tunnel(ssh_session session) {
	int rc;
	int startpoint = 29000;
	int endpoint = 22;

	rc = ssh_channel_listen_forward(session, NULL, startpoint, NULL);
	if (rc != SSH_OK) {
		printf("Error opening remote port: %s\n", ssh_get_error(session));
		exit(-1);
	}

	ssh_channel channel = ssh_channel_accept_forward(session, 60000, &endpoint);
	if (channel == NULL) {
		printf("Error waiting for incoming connection: %s\n", ssh_get_error(session));
		exit(-1);
	}
}

int main() {
	int rc;
	char *host = "192.168.254.122";
	int ssh_port = 22;
	char *user = "a";
	char *password = "cerberus";

	ssh_session session = ssh_new();
	if (session == NULL) {
		exit(-1);
	}

	ssh_options_set(session, SSH_OPTIONS_HOST, host);
    	ssh_options_set(session, SSH_OPTIONS_PORT, &ssh_port);
    	ssh_options_set(session, SSH_OPTIONS_USER, user);

    	rc = ssh_connect(session);
    	if (rc != SSH_OK) {
    		printf("Error connecting to localhost: %s\n", ssh_get_error(session));
    		exit(-1);
    	}

    	rc = ssh_userauth_password(session, NULL, password);
    	if (rc != SSH_AUTH_SUCCESS) {
    		printf("Error authenticating with password: %s\n", ssh_get_error(session));
    		exit(-1);
	}

    	ssh_tunnel(session);
    	ssh_disconnect(session);
    	ssh_free(session);
}
