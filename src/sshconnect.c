#include <libssh/libssh.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int sshlisten(ssh_session session) {
	int rc;
	char buffer[256];
	int nbytes;
	int newport = 1080;
	int forwardport = 0;

	// Port Forwarding
	rc = ssh_channel_listen_forward(session, NULL, newport, NULL);
	if (rc != SSH_OK) {
		printf("Error opening remote port: %s\n", ssh_get_error(session));
		exit(-1);
	}

	ssh_channel channel = ssh_channel_accept_forward(session, 60000, &forwardport);
	if (channel == NULL) {
		printf("Error waiting for incoming connection: %s\n", ssh_get_error(session));
		exit(-1);
	}

	nbytes = strlen("helloworld");
	ssh_channel_write(channel, "helloworld", nbytes);
}

int sshreqexec(ssh_session session, char *command) {
	int rc;
	char buffer[256];
	int nbytes;

	ssh_channel channel = ssh_channel_new(session);
    if (channel == NULL) {
    	exit(-1);
    }

    rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK) {
    	printf("Error opening channel: %s\n", ssh_get_error(session));
  		ssh_channel_free(channel);
    	exit(-1);
    }

    rc = ssh_channel_request_exec(channel, command);
    if (rc != SSH_OK) {
    	printf("Error executing: %s\n", ssh_get_error(session));
    	ssh_channel_close(channel);
  		ssh_channel_free(channel);
    	exit(-1);
    }

    nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
	while (nbytes > 0) {
  		if (fwrite(buffer, 1, nbytes, stdout) != nbytes) {
    		ssh_channel_close(channel);
    		ssh_channel_free(channel);
    	}
  		nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
	}
	if (nbytes < 0) {
    	ssh_channel_close(channel);
    	ssh_channel_free(channel);
  	}

  	ssh_channel_send_eof(channel);
	ssh_channel_close(channel);
	ssh_channel_free(channel);
}

int main() {
	int rc;

	char *host = "192.168.254.200";
	int port = 22;
	char *user = "debian666";
	char *password = "11c6iEva~!";

	ssh_session session = ssh_new();
	if (session == NULL) {
		exit(-1);
	}

	ssh_options_set(session, SSH_OPTIONS_HOST, host);
    ssh_options_set(session, SSH_OPTIONS_PORT, &port);
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

    sshlisten(session);

    //ssh_disconnect(session);
    //ssh_free(session);
}