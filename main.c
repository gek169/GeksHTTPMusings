#define HTTPSERVER_IMPL
#define C_SAFEMEM_IMPL
#include "httpserver.h"
#include "stringutil.h"
#include <pthread.h>

pthread_mutex_t safemem_mtx;	//(pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
#define SAFEPTR_RESOURCE_LOCK() {pthread_mutex_lock(&safemem_mtx);}
#define SAFEPTR_RESOURCE_UNLOCK() {pthread_mutex_unlock(&safemem_mtx);}
//#define C_SAFEMEM_DEBUG
#include "safemem.h"
#include <string.h>
#include <time.h>



#define MAX_USER_SESSIONS 10

typedef struct {
	pthread_mutex_t mtx;
	safepointer data1;	//This safepointer will always resolve to a pointer successfully if the session is active.
	safepointer data2;	//This is data used by the user_session
	unsigned int type;	//Identifies current session.
} user_session;

//pthread_mutex_t sessions_mtx;
#define SESSIONS_RESOURCE_LOCK() /**/
#define SESSIONS_RESOURCE_UNLOCK() /**/
user_session sessions[MAX_USER_SESSIONS];


void deliver_404(struct http_request_s* request){
	const char* text_404 = "ERROR 404\nSTOP TRYING TO BREAK INTO MY HOUSE!\n";
	struct http_response_s* response = http_response_init();
	http_response_status(response, 404);
  	http_response_header(response, "Content-Type", "text/plain");
  	http_response_body(response, text_404, strlen(text_404));
  	http_respond(request, response);
  	puts("User was delivered 404\n");
}

void deliver_string_contenttype(struct http_request_s* request, const char* str, const char* contenttype){
		struct http_response_s* response = http_response_init();
		http_response_status(response, 200);
	  	http_response_header(response, "Content-Type", contenttype);
	  	http_response_body(response, str, strlen(str));
	  	http_respond(request, response);
}

void deliver_string(struct http_request_s* request, const char* str){
		struct http_response_s* response = http_response_init();
		http_response_status(response, 200);
	  	http_response_header(response, "Content-Type", "text/plain");
	  	http_response_body(response, str, strlen(str));
	  	http_respond(request, response);
}

void deliver_data(struct http_request_s* request, const void* data, unsigned int len){
		struct http_response_s* response = http_response_init();
		http_response_status(response, 200);
	  	http_response_header(response, "Content-Type", "application/octet-stream");
	  	http_response_body(response, data, len);
	  	http_respond(request, response);
}

void deliver_data_contenttype(struct http_request_s* request, const void* data, unsigned int len, const char* contenttype){
		struct http_response_s* response = http_response_init();
		http_response_status(response, 200);
	  	http_response_header(response, "Content-Type", contenttype);
	  	http_response_body(response, data, len);
	  	http_respond(request, response);
}

void deliver_text(struct http_request_s* request, const char* fname){
	if(!fname)	{deliver_404(request);return;}
	if(fname[0] == '/') {deliver_404(request);return;}
	for(size_t i = 1; i < strlen(fname);i++)
			if(fname[i] == '.' && fname[i-1] == '.')
				{deliver_404(request);return;}
	FILE* f = fopen(fname, "r");
	if(!f) {deliver_404(request);return;}
	unsigned long len;
	char* p = read_file_into_alloced_buffer(f, &len);
	if(!p)	{fclose(f);deliver_404(request);return;}
	{
		struct http_response_s* response = http_response_init();
		http_response_status(response, 200);
  		http_response_header(response, "Content-Type", "text/plain");
  		http_response_body(response, p, len);
  		http_respond(request, response);
		free(p);
	}
	fclose(f);
}

void deliver_redirect(struct http_request_s* request, const char* location){
	const char* docp1 = "<!DOCTYPE html>"
											"<html>"
					  							"<head>"
					    					"<meta http-equiv=\"refresh\" content=\"1; url=\'";
			
	const char* docp2 =		   "\'\" />"
			  "</head>"
			  "<body>"
			   "<p>Redirecting!</p>"
			  "</body>"
			"</html>";
	char* b = strcatallocf2(docp1, strcatalloc(location, docp2));
	deliver_string_contenttype(request, b, "text/html");
	free(b);
	return;
}

void deliver_html(struct http_request_s* request, const char* fname){
	if(!fname)	{deliver_404(request);return;}
	if(fname[0] == '/') {deliver_404(request);return;}
	for(size_t i = 1; i < strlen(fname);i++)
			if(fname[i] == '.' && fname[i-1] == '.')
				{deliver_404(request);return;}
	FILE* f = fopen(fname, "r");
	if(!f) {deliver_404(request);return;}
	unsigned long len;
	char* p = read_file_into_alloced_buffer(f, &len);
	if(!p)	{fclose(f);deliver_404(request);return;}
	{
		struct http_response_s* response = http_response_init();
		http_response_status(response, 200);
  		http_response_header(response, "Content-Type", "text/html");
  		http_response_body(response, p, len);
  		http_respond(request, response);
		free(p);
	}
	fclose(f);
}


void handle_user_session_req(struct http_request_s* request, const char* sess_url_text){
	if(strlen(sess_url_text) < 3) {deliver_404(request);return;}
	if(strprefix("new_text",sess_url_text)){
		unsigned int s_mine = MAX_USER_SESSIONS;
		void* p = NULL;
		char string_sessionid[32];
		string_sessionid[31] = '\0';
		
		SAFEPTR_RESOURCE_LOCK();
		for(unsigned int i = 0; i < MAX_USER_SESSIONS; i++){
			p = safepointer_deref(sessions[i].data1);
			if(!p) {s_mine = i; break;}
		}
		SAFEPTR_RESOURCE_UNLOCK();
		
		if(!(s_mine < MAX_USER_SESSIONS)){deliver_string(request, "No free sessions! Refresh a few times and see if one comes up!");return;}
		sessions[s_mine].data1 = SAFEPTR_MALLOC(char, 512, (60 * 60)); //one hour.
		sessions[s_mine].type = 1; //Text entry session- The user enters text and it is spat back at them.
		sprintf(string_sessionid,"%u",s_mine);
		const char* docp1 = "<!DOCTYPE html>"
										"<html>"
				  							"<head>"
				    					"<meta http-equiv=\"refresh\" content=\"1; url=\'/session/active/";
		
		const char* docp2 =		   "\'\" />"
				  "</head>"
				  "<body>"
				   "<p>Redirecting you to your session....</p>"
				  "</body>"
				"</html>";
		char* b = strcatallocf1(	strcatalloc(docp1, string_sessionid),	docp2);
		if(!b)	{deliver_string(request, "Internal server error :(");return;}
		deliver_string_contenttype(request, b, "text/html");
		free(b);
	} else if(strprefix("active/",sess_url_text)){

		sess_url_text += 7;
		unsigned int id = 0; id = strtoull(sess_url_text, 0, 10 );
		if(id >= MAX_USER_SESSIONS) {deliver_404(request);return;}
		
		{
			const char* docp1 = "<!DOCTYPE html>"
													"<html>"
							  						"<head>"
							  						"</head>"
							  						"<body>"
							   "<a href=\"/session/end_session/";

			const char* docp2 = "\">click here to end your session.</a>"
							  "</body>"
							"</html> <plaintext>";
			char string_sessionid[50];
			string_sessionid[49] = '\0';
			void* p = NULL;

			p = safepointer_deref(sessions[id].data1);
			if(p == NULL) 
				{deliver_string(request, "Session expired.");}
			else{
				//Valid request.
				while(*sess_url_text != '\0' && *sess_url_text != '/')
					sess_url_text++;
				{
					sess_url_text++;//Skip the slash.
					sprintf(string_sessionid,"%u",id);

					if(strlen(sess_url_text) > 0){//Something to add.
						char* bum = strcatalloc(p, sess_url_text);
						puts("adding text to session...\n");
						//SAFEPTR_RESOURCE_UNLOCK();
						sessions[id].data1 = SAFEPTR_MALLOC(char, strlen(bum) + 1, (60 * 60));
						SAFEPTR_RESOURCE_LOCK();
						p = safepointer_deref(sessions[id].data1);
						strcpy(p,bum);
						free(bum);
					} else {

						p = safepointer_deref(sessions[id].data1);

					}
					//Prepare a webpage.
					char* web = strcatafb(
							strcata(docp1, string_sessionid), 
							strcata(docp2, p)
						);

					deliver_string_contenttype(request, web, "text/html");
					free(web);
				}
			}
		}
		SAFEPTR_RESOURCE_UNLOCK();
		
		return;
	} else if(strprefix("end_session/",sess_url_text)){
		sess_url_text += 12;
		unsigned int id = 0; id = strtoull(sess_url_text, 0, 10 );
		if(id > MAX_USER_SESSIONS) {deliver_404(request);return;}
		
		SAFEPTR_RESOURCE_LOCK();
		void* p = NULL;
		p = safepointer_deref(sessions[id].data1);
		if(p){
			SAFEPTR_RESOURCE_UNLOCK();
			safepointer_free(sessions[id].data1);
			SAFEPTR_RESOURCE_LOCK();
			deliver_redirect(request, "/");
		}
		else{deliver_string(request, "Cannot end session, it is not active.");}
		
		SAFEPTR_RESOURCE_UNLOCK();
	} else deliver_string(request,"Invalid session request.");
}

void handle_request(struct http_request_s* request) {
	struct http_string_s preurl = http_request_target(request);
	char* alloced_url = str_null_terminated_alloc(preurl.buf, preurl.len);
	puts("~~ BEGINNING NEW REQUEST ~~\n");
	if(!alloced_url) {deliver_404(request);return;}
	if(strprefix("/echo/", alloced_url))			{deliver_string(request, alloced_url+6);goto handled;}
	else if (strprefix("/text/", alloced_url)){
			if(alloced_url[9] == '/') {deliver_404(request);goto handled;}
					for(size_t i = 1; i < strlen(alloced_url);i++)
							if(alloced_url[i] == '.' && alloced_url[i-1] == '.')
								{deliver_404(request);goto handled;}
			deliver_text(request, alloced_url + 6);
			goto handled;
	}else if (strprefix("/html/", alloced_url)){
		if(alloced_url[9] == '/') {deliver_404(request);goto handled;}
				for(size_t i = 1; i < strlen(alloced_url);i++)
						if(alloced_url[i] == '.' && alloced_url[i-1] == '.')
							{deliver_404(request);goto handled;}
		deliver_html(request, alloced_url + 6);
		goto handled;
	}else if(strprefix("/command/", alloced_url)){
		if(strprefix("kill", alloced_url + 9)) 
			{
				deliver_string(request, "Dying in two seconds!");
				sleep(2);
				exit(0);
			}
		else if(strprefix("uname", alloced_url + 9)) {
			FILE* fp = NULL; 
			fp = popen("uname -a", "r");
			if(fp == NULL)	{deliver_string(request,"Error running uname command, cannot popen");goto handled;}
			char contents[5000]; contents[4999] = '\0';
			fgets(contents, 5000, fp);
			contents[4999] = '\0';
			deliver_string(request,contents);
			fclose(fp);
			goto handled;
		}
	} else if(strprefix("/rawfile/", alloced_url)){
		//USER_IS_NAUGHTY!
		if(alloced_url[9] == '/') {deliver_404(request);goto handled;}
		for(size_t i = 1; i < strlen(alloced_url);i++)
				if(alloced_url[i] == '.' && alloced_url[i-1] == '.')
					{deliver_404(request);goto handled;}
		FILE* fp = fopen(alloced_url + 9, "rb");
		if(!fp)	{deliver_404(request);goto handled;}
		unsigned long len;
		void* p = read_file_into_alloced_buffer(fp, &len);
		deliver_data(request,p,len);
		fclose(fp);
		goto handled;
	} else if (strprefix("/session/", alloced_url)){
		handle_user_session_req(request, alloced_url + 9);
		goto handled;
	}
	deliver_html(request, "index.html");
	//the jump point for all those else-ifs
	handled:
	
	free(alloced_url);
	puts("Handled request.\n");
}

struct http_server_s* server;

int msleep(long msec)
{
    struct timespec ts;
    int res;

    if (msec < 0)
    {
        errno = EINVAL;
        return -1;
    }

    ts.tv_sec = msec / 1000;
    ts.tv_nsec = (msec % 1000) * 1000000;

    do {
        res = nanosleep(&ts, &ts);
    } while (res && errno == EINTR);

    return res;
}

void http_gc(){
	puts("Going to collect garbage.\n");
	msleep(10);
	safepointer_collect_garbage();
}

struct {
	void (*handler)();
} b;

int main() {
	b.handler = http_gc;
	safemem_mtx = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
	for(int i = 0; i < MAX_USER_SESSIONS; i++){
		sessions[i].mtx = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
		sessions[i].data1 = SAFEPTR_INIT;
		sessions[i].data2 = SAFEPTR_INIT;
	}
	//sessions_mtx = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
	server = http_server_init(8080, handle_request);
	//http_server_set_userdata(server, &b);
	//Blocking version
	//http_server_listen(server);
	http_server_listen_poll(server);
	while(1){
		while(http_server_poll(server));
		
		http_gc();	
	}
}
