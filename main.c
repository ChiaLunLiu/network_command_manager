#include "event.h"
#include "linkedlist.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
void addPermanentRule();

void event_test_sys(void* arg)
{
	printf("%s\n",__func__);
}
void event_test_user(void* arg)
{
	printf("%s\n",__func__);
}

int main()
{
	eventfactory_t *ef;
	ef = malloc( sizeof( eventfactory_t));
	eventfactory_init(ef);
	
	event_sys_register(ef,"test", event_test_sys);
	event_user_register(ef,"test",event_test_user);
	event_script_register(ef,"./test.sh");
	
	event_process(ef,"test",EVENTUSER,1);
	fprintf(stderr,"hhhh\n");
	event_process(ef,"./test.sh",EVENTSCRIPT,1);
	free(ef);
	
	
	return 0;
}
