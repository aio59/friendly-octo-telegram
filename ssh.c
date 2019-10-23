#include <libssh/libssh.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int ssh_tunnel(ssh_session session) {
	int startpoint = 29000;
	int endpoint = 0;

	int rc;
	rc = ssh_channel_listen_forward(session, NULL, startpoint, NULL); // wait till request
	if (rc != SSH_OK) {
		printf("Error opening remote port: %s\n", ssh_get_error(session));
		exit(-1);
	}

	ssh_channel channel;
	channel = ssh_channel_accept_forward(session, 60000, &endpoint);
	if (channel == NULL) {
		printf("Error waiting for incoming connection: %s\n", ssh_get_error(session));
		exit(-1);
	}

	int buffer[256];
	int buffer_length;
	buffer_length = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
	if (buffer_length < 0) {
		ssh_channel_send_eof(channel);
		ssh_channel_free(channel);
	}

	fwrite(buffer, 1, buffer_length, stdout);

	//char *test = "Hello, World!";
	//ssh_channel_write(channel, test, strlen(test));

	ssh_channel_send_eof(channel);
	ssh_channel_free(channel);
}

int ssh_exec(ssh_session session, char *command) {
	ssh_channel channel;
	channel = ssh_channel_new(session);
	if (channel == NULL) {
		printf("%s\n", ssh_get_error(session));
		exit(-1);
	}

	int rc;
	rc = ssh_channel_open_session(channel);
	if (rc != SSH_OK) {
		ssh_channel_free(channel);
		exit(-1);
	}
	rc = ssh_channel_request_exec(channel, command);
	if (rc != SSH_OK) {
		ssh_channel_close(channel); // close channel session
		ssh_channel_free(channel);
		exit(-1);
	}

	int buffer[256];
	int buffer_length;
	buffer_length = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
	while (buffer_length > 0) {
		fwrite(buffer, 1, buffer_length, stdout);
		buffer_length = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
	}
	if (buffer_length < 0) {
		ssh_channel_close(channel);
		ssh_channel_free(channel);
	}

	ssh_channel_send_eof(channel); // send end-of-file
	ssh_channel_close(channel);
	ssh_channel_free(channel);
}

int main() {
	char *host = "192.168.254.122";
	int ssh_port = 22;
	char *user = "a";
	char *password = "cerberus";

	ssh_session session;
	session = ssh_new();
	if (session == NULL) {
		exit(-1);
	}

	ssh_options_set(session, SSH_OPTIONS_HOST, host);
   	ssh_options_set(session, SSH_OPTIONS_PORT, &ssh_port);
   	ssh_options_set(session, SSH_OPTIONS_USER, user);

	int rc;
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
