#define HTTPSERVER_IMPL
#include "httpserver.h"
#include "stringutil.h"
#include <string.h>
char* myresponse = "Tested.";

void deliver_404(struct http_request_s* request){
	const char* text_404 = "ERROR 404\nSTOP TRYING TO BREAK INTO MY HOUSE!\n";
	struct http_response_s* response = http_response_init();
	http_response_status(response, 404);
  	http_response_header(response, "Content-Type", "text/plain");
  	http_response_body(response, text_404, strlen(text_404));
  	http_respond(request, response);
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
	unsigned int len;
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

void deliver_html(struct http_request_s* request, const char* fname){
	if(!fname)	{deliver_404(request);return;}
	if(fname[0] == '/') {deliver_404(request);return;}
	for(size_t i = 1; i < strlen(fname);i++)
			if(fname[i] == '.' && fname[i-1] == '.')
				{deliver_404(request);return;}
	FILE* f = fopen(fname, "r");
	if(!f) {deliver_404(request);return;}
	unsigned int len;
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

void handle_request(struct http_request_s* request) {
	struct http_string_s preurl = http_request_target(request);
	char* alloced_url = str_null_terminated_alloc(preurl.buf, preurl.len);
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
		FILE* fp = fopen(alloced_url + 9, "r");
		if(!fp)	{deliver_404(request);goto handled;}
		unsigned int len;
		void* p = read_file_into_alloced_buffer(fp, &len);
		deliver_data(request,p,len);
		fclose(fp);
		goto handled;
	}
	deliver_html(request, "index.html");
	handled:
	free(alloced_url);
}

int main(int argc, char **argv) {
  struct http_server_s* server = http_server_init(8080, handle_request);
  if(argc > 1)
  	myresponse = strcatalloc(argv[1],"");
  http_server_listen(server);
}
