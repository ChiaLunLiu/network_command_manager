#include "event.h"
#include "linkedlist.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void update_permanent_rule(int ty)
{
	int r;
	if(ty == 0)
		r=system("sh script/permanent.sh start");
	else
		r=system("sh script/permanent.sh stop");
}

void event_test_sys(event_t* arg)
{
	printf("%s\n",__func__);
}
void event_test_user(event_t* arg)
{
	printf("%s\n",__func__);
}

int main()
{
	eventfactory_t *ef;
	ef = malloc( sizeof( eventfactory_t));
	eventfactory_init(ef);
	
	update_permanent_rule(0);
	
	/* sys event */
	event_sys_register(ef,"test", event_test_sys,"test_enable");
	event_sys_register(ef,"dhcp", app_dhcp,""); //TODO cmskey
	event_sys_register(ef,"dmz", dmz,"ui_dmz_enable");
//	event_sys_register(ef,"icmp redirect to host",);
	
	
//	event_user_register(ef,"test",event_test_user);
//	event_script_register(ef,"./test.sh");
	
//	event_process(ef,"test",EVENTUSER,1);
//	fprintf(stderr,"hhhh\n");
//	event_process(ef,"./test.sh",EVENTSCRIPT,1);

	free(ef);
	
	
	return 0;
}
