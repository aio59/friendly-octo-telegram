#include <libssh/libssh.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define HOST "192.168.254.122"
#define PORT 22
#define USER "a"
#define PASSWORD "cerberus"

#define REMOTE_LISTEN_PORT 2222
#define REMOTE_DESTINATION_PORT 0

#define LOCAL_ADDRESS "127.0.0.1"
#define LOCAL_PORT 8083

int forwardtcp(ssh_channel channel) {
	int local_sock;
	local_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (local_sock == -1) {
		exit(-1);
	}

	struct sockaddr_in sin;
	char *host = LOCAL_ADDRESS;
	int port = LOCAL_PORT;

	sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr(host);
    sin.sin_port = htons(port);

    int iretval;
    iretval = connect(local_sock, (struct sockaddr *)&sin, sizeof(struct sockaddr_in));
    if (iretval == -1) {
		fprintf(stderr, "Error connecting to local sock\n");
    	goto close;
    }

	fd_set fds;
	struct timeval tv;
	int rc;
	int buffer[16384];
	ssize_t buffer_len;
	int bl;
	ssize_t i;
	while (1) {
		FD_ZERO(&fds);
		FD_SET(local_sock, &fds);
		tv.tv_sec = 0;
		tv.tv_usec = 100000;

		rc = select(local_sock + 1, &fds, NULL, NULL, &tv);
		if (rc == -1) {
			fprintf(stderr, "select\n");
			goto close;
		}
		if (rc && FD_ISSET(local_sock, &fds)) { fprintf(stderr, "asdasdasdasda");
			buffer_len = recv(local_sock, buffer, sizeof(buffer), 0); // receive buffer from local sock
			fwrite(buffer, 1, buffer_len, stdout);
			if (buffer_len < 0) {
				fprintf(stderr, "Error reading on local sock\n");
				goto close;
			}
			else if(buffer_len == 0) {
                fprintf(stderr, "Error local sock disconnected\n");
                goto close;
            }

			i = 0;
			do {
				bl = ssh_channel_write(channel, buffer, buffer_len); 
				if (bl < 0) {
					fprintf(stderr, "Error writing to channel\n");
					goto close;
				}
				i += bl;
			} while(bl > 0 && i < buffer_len);
		}
		while (1) {
			buffer_len = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
			if (buffer_len < 0) {
				fprintf(stderr, "Error reading on channel\n");
				goto close;
			}

			i = 0;
			while (i < buffer_len) {
				bl = send(local_sock, buffer + i, buffer_len - i, 0); 
				if (bl <= 0) {
					fprintf(stderr, "Error writing to local sock\n");
					goto close;
				}
				i += bl;
			}
			if (ssh_channel_is_eof(channel)) {
				goto close;
			}
		}
	}

	close:
	close(local_sock);
}

int sshportforward(ssh_session session) {
	int listen_port = REMOTE_LISTEN_PORT;
	int destination_port = REMOTE_DESTINATION_PORT;
	int rc;
	rc = ssh_channel_listen_forward(session, NULL, listen_port, NULL); // wait till request
	if (rc != SSH_OK) {
		fprintf(stderr, "Error opening remote port: %s\n", ssh_get_error(session));
		exit(-1);
	}
	ssh_channel channel;
	while (1) {
		channel = ssh_channel_accept_forward(session, 60000, &destination_port);
		if (channel == NULL) {
			fprintf(stderr, "Error waiting for incoming connection: %s\n", ssh_get_error(session));
			exit(-1);
		}
		
		/*
		int buffer[256];
		int buffer_len;
		buffer_len = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
		if (buffer_len < 0) {
			ssh_channel_send_eof(channel);
			ssh_channel_free(channel);
		}

		fwrite(buffer, 1, buffer_len, stdout);
		*/
		ssh_set_blocking(session, 0);
		forwardtcp(channel);
		ssh_set_blocking(session, 1);
		ssh_channel_free(channel);
	}
}

ssh_session sshconnect(ssh_session session) {
	char *host = HOST;
	int port = PORT;
	char *user = USER;
	char *password = PASSWORD;

	ssh_options_set(session, SSH_OPTIONS_HOST, host);
   	ssh_options_set(session, SSH_OPTIONS_PORT, &port);
   	ssh_options_set(session, SSH_OPTIONS_USER, user);

	int rc;
    rc = ssh_connect(session);
    if (rc != SSH_OK) {
    	fprintf(stderr, "Error connecting to localhost: %s\n", ssh_get_error(session));
    	exit(-1);
    }
    rc = ssh_userauth_password(session, NULL, password);
    if (rc != SSH_AUTH_SUCCESS) {
    	fprintf(stderr, "Error authenticating with password: %s\n", ssh_get_error(session));
    	exit(-1);
	}
	return session;
}

int main() {
	ssh_session session;
	session = ssh_new();
	if (session == NULL) exit(-1);

	session = sshconnect(session);
    sshportforward(session);
   	ssh_disconnect(session);
   	ssh_free(session);
}
