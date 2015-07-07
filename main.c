/*
 *	This program acts as server
 *	It uses MINIMSG_RECV_ONLY socket type
 *	socket of type MINIMSG_RECV_ONLY only recevies data represented in msg_t
 *	The program can be terminated normally by sending SIGINT ( ctrl+c ). 
 *	Date: 2015/06/28
 */
#include <minimsg/minimsg.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <signal.h>
#include "nfc_event.h"
#include <event2/event.h>

#define MAX_EVENTS 8
static void signal_handler(int fd, short event, void *arg)
{
	void* base = arg;
	if(event_base_loopbreak(base) == -1) nfc_handle_error("event_base_loopbreak fails\n");	
}


int main()
{
	minimsg_context_t* ctx;
	minimsg_socket_t* socket;
	msg_t * m;
	int efd,n,i;
	struct epoll_event event;
	struct epoll_event* events;
	sigset_t mask;
        int sfd;
        struct signalfd_siginfo fdsi;
        ssize_t s;
	void* base;
	nfc_t* center;
	struct event* data_event;
	struct event* signal_event;
        base = event_base_new();
        if(!base) nfc_handle_error("event_base_new()");
        if(data_efd == -1 || control_efd == -1) goto error;
        data_event=event_new(base, data_efd, EV_READ|EV_PERSIST, data_handler, (void*)ctx );
        signal_event = event_new(base,SIGINT, EV_SIGNAL,signal_handler,base);

        if(!signal_event || !data_event) nfc_handle_error("event_new");
	event_add(signal_event,NULL);
	event_add(data_event,NULL);

	
	/* create network function center */
	center = nfc_create();

	ctx = minimsg_create_context();
	if(!ctx){
		fprintf(stderr,"fail to create minimsg context\n");
		return 0;
	}
	
	socket = minimsg_create_socket(ctx,MINIMSG_RECV_ONLY);
	fprintf(stderr,"socket is created\n");
	if(minimsg_bind(socket,"remote://127.0.0.1:12345") == MINIMSG_FAIL){
//	if(minimsg_bind(socket,"local:///home/bendog/git/minimsg/template/local") == MINIMSG_FAIL){
		fprintf(stderr,"bind fails\n");
		return 0;
	}
	else
		fprintf(stderr,"bind is OK\n");
/* add event */
	/* socket */
	event.data.fd = minimsg_socket_recv_fd(socket);
	event.events = EPOLLIN;
	s = epoll_ctl(efd,EPOLL_CTL_ADD,event.data.fd,&event);
        if(s == -1){
        	perror("epoll_ctl");
                return 0;
        }
	/* signal */
	event.data.fd = sfd;
	event.events = EPOLLIN;
	s = epoll_ctl(efd,EPOLL_CTL_ADD,event.data.fd,&event);
        if(s == -1){
        	perror("epoll_ctl");
                return 0;
        }
	events = calloc(MAX_EVENTS,sizeof( event ));
        if(!events)handle_error("calloc fails\n");
/* start */		
	while(1){
		n = epoll_wait(efd,events,MAX_EVENTS,-1);
		if(n == -1){
			printf("epoll_wait error\n");
			goto end;
		}
		printf("got new events: %d\n",n);
		for(i = 0 ;i<n; i++){
                        if( minimsg_socket_recv_fd(socket) == events[i].data.fd){
				m = minimsg_recv(socket);
				printf("server receives message\n");
				msg_print(m);
				nfc_msg_process(center,m);
				msg_free(m);
			}
			else if(sfd == events[i].data.fd){
				s = read(sfd,&fdsi,sizeof(struct signalfd_siginfo));
				//TODO , signal occurs again
				if( s != sizeof( struct signalfd_siginfo)) handle_error("read");
				if(fdsi.ssi_signo == SIGINT){
					printf("got signal SIGINT\n");
					goto end;
				}
			}
		}
	}
end:
	free(events);
	close(sfd);	
	close(efd);
	nfc_free(center);
	minimsg_free_context(ctx);
	return 0;
}
