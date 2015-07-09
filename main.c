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

/* a struct for passing argument to data_handler */
struct data{
	nfc_t* center;
	minimsg_socket_t* socket;
};
/* 
 * data_handler
 * handle network data
 */
static void data_handler(int fd, short event, void *arg)
{
	struct data * d = (struct data*) arg;
	msg_t* m;
	m = minimsg_recv(d->socket);
	printf("server receives message\n");
	msg_print(m);
	nfc_msg_process(d->center,m);
	msg_free(m);
}
static void signal_handler(int fd, short event, void *arg)
{
	void* base = arg;
	nfc_dbg("catch signal SIGINT\n");
	if(event_base_loopbreak(base) == -1) nfc_handle_error("event_base_loopbreak fails\n");	
}


int main()
{
	minimsg_context_t* ctx;
	minimsg_socket_t* socket;
	msg_t * m;
	int n,i;
	nfc_t* center;
	struct event* data_event;
	struct event* signal_event;
	struct data* d;

	/* create minimsg context */
	ctx = minimsg_create_context();
	if(!ctx){
		fprintf(stderr,"fail to create minimsg context\n");
		return 0;
	}
	/* create socket */	
	socket = minimsg_create_socket(ctx,MINIMSG_RECV_ONLY);
	fprintf(stderr,"socket is created\n");
	if(minimsg_bind(socket,"remote://127.0.0.1:12345") == MINIMSG_FAIL){
		fprintf(stderr,"bind fails\n");
		return 0;
	}
	else
		fprintf(stderr,"bind is OK\n");

	d = (struct data*)malloc( sizeof(struct data));
	if(!d){
		fprintf(stderr,"malloc fails\n");
		goto end;
	}
	/* create network function center */

	center = nfc_create();
	if(!center) nfc_handle_error("nfc_create");
	d->center =center;
	d->socket = socket;
        data_event=event_new(center->base, minimsg_socket_recv_fd(socket), EV_READ|EV_PERSIST, data_handler, (void*)d );
        signal_event = event_new(center->base,SIGINT, EV_SIGNAL,signal_handler,center->base);

        if(!signal_event || !data_event) nfc_handle_error("event_new");
	event_add(signal_event,NULL);
	event_add(data_event,NULL);

	nfc_dbg("start dispatching ...\n");	
	event_base_dispatch(center->base);		
end:
	nfc_dbg("program is shut down\n");
	nfc_free(center);
	minimsg_free_context(ctx);
	return 0;
}
