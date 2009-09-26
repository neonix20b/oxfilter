#include "httpd.h"
#include "http_config.h"
#include "apr_buckets.h"
#include "apr_general.h"
#include "apr_lib.h"
#include "util_filter.h"
#include "http_request.h"
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <oxdigest.h>
#include "bstrstr.h"


#define DEBUG(str) fprintf(stderr, "DEBUG: %s\n", str); fflush(stderr);

static const char s_szOxFilterName[]="OxFilter";

static apr_bucket* header = NULL;
static apr_bucket* footer = NULL;
static apr_bucket* small = NULL;
static apr_pool_t* pool;
static apr_bucket_alloc_t* allocator;
static struct sockaddr_in addr;
static char* digest_placeholder;

module AP_MODULE_DECLARE_DATA oxfilter_module;

typedef struct _OxExcludeByUrl {
	const char* str;
	struct _OxExcludeByUrl* next;
} OxExcludeByUrl;

static OxExcludeByUrl* excludes_by_url = NULL;

typedef struct {
	int bEnabled;
} OxFilterConfig;



static const char* txt_file_bucket(const char* fname, apr_bucket** bucket) {
	apr_file_t* file = NULL ;
	apr_finfo_t finfo ;
	if ( apr_stat(&finfo, fname, APR_FINFO_SIZE, pool) != APR_SUCCESS ) {
		return "failed to retrieve size of a file" ;
	}
	if ( apr_file_open(&file, fname, APR_READ|APR_SHARELOCK|APR_SENDFILE_ENABLED,
		APR_OS_DEFAULT, pool ) != APR_SUCCESS ) {
		return "apr_file_open failed" ;
	}
		if ( ! file ) {
			return "file is NULL" ;
	}
	*bucket = apr_bucket_file_create(file, 0, finfo.size, pool, allocator) ;
	return NULL;
}


static void *OxFilterCreateServerConfig(apr_pool_t *p,server_rec *s) {
    pool = s->process->pconf;
    allocator = apr_bucket_alloc_create(pool);

    addr.sin_family = AF_INET;
    addr.sin_port = htons(2905);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    OxFilterConfig *pConfig=apr_pcalloc(p,sizeof *pConfig);
    pConfig->bEnabled=0;
    return pConfig;
    //return NULL;
}

static int check_header(const char* domain) {
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	char buf;
	if(connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		DEBUG("connect failed");
		return 0;
	}
	send(sock, domain, strlen(domain), 0);
	if(recv(sock, &buf, sizeof(buf), 0) < 0) {
		DEBUG("recv failed");
		return 0;
	}
	close(sock);
	//fprintf(stderr, "Got response from oxserviced - '%s'=%c\n", domain,buf);
	//fflush(stderr);
	return buf != 't';
}

static int insert_with_ad(apr_bucket_brigade *pbbIn) {
            apr_bucket *pbktIn;
	    for (pbktIn = APR_BRIGADE_FIRST(pbbIn); pbktIn != APR_BRIGADE_SENTINEL(pbbIn); pbktIn = APR_BUCKET_NEXT(pbktIn)) {
    		apr_bucket* first;
		int firstn;
		int n;
		if(bstrstr(pbktIn, "<body", 0, &first, &firstn, &n)) {
			if(bstrstr(pbktIn, ">", n, &first, &firstn, &n)) {
				apr_bucket_split(pbktIn,n+1);
				apr_bucket* copy;
				apr_bucket_copy(header, &copy);
				APR_BUCKET_INSERT_BEFORE(APR_BUCKET_NEXT(pbktIn),copy);
				break;
			} else
				return -1;
		}
	    }
	    for (pbktIn = APR_BRIGADE_FIRST(pbbIn); pbktIn != APR_BRIGADE_SENTINEL(pbbIn); pbktIn = APR_BUCKET_NEXT(pbktIn)) {
	    	apr_bucket* first;
		int firstn;
		int n;
		if(bstrstr(pbktIn, "</body>", 0, &first, &firstn, &n)) {
				apr_bucket_split(first,firstn);
				apr_bucket* copy;
				apr_bucket_copy(footer, &copy);
				APR_BUCKET_INSERT_BEFORE(APR_BUCKET_NEXT(first),copy);
				break;
		}
	    }
	    return 0;
}

static void insert_without_ad(apr_bucket_brigade *pbbIn) {
	    apr_bucket *pbktIn;
	    for (pbktIn = APR_BRIGADE_FIRST(pbbIn); pbktIn != APR_BRIGADE_SENTINEL(pbbIn); pbktIn = APR_BUCKET_NEXT(pbktIn)) {
	    	apr_bucket* first;
		int firstn;
		int n;
		if(bstrstr(pbktIn, "</body>", 0, &first, &firstn, &n)) {
				
				apr_bucket_split(first,firstn);
				apr_bucket* copy;
				apr_bucket_copy(small, &copy);
				APR_BUCKET_INSERT_BEFORE(APR_BUCKET_NEXT(first),copy);
				break;
		}
	    }
}

static apr_status_t OxFilterOutFilter(ap_filter_t *f, apr_bucket_brigade *pbbIn) {
    OxExcludeByUrl* last = excludes_by_url;
    char* buf;
    char* ptr;
    apr_off_t len, len_full;
    apr_bucket *pbktOut;
    int left;

    request_rec *r = f->r;
    conn_rec *c = r->connection;
    apr_bucket *pbktIn;
    apr_bucket_brigade *pbbOut;
  
    if (APR_BRIGADE_EMPTY(pbbIn))
        goto pass_filter;
    
    /*if (!ap_is_initial_req(r)) {
	ap_remove_output_filter(f);
	goto pass_filter;
    }*/

    if(!strstr(r->content_type,"text/html"))
    	goto pass_filter;
    while(last != NULL) {
	if(strcasestr(r->uri, last->str)) {
	    goto pass_filter;
	}
    	last = last->next;
    }
    if(!header || !footer || !small)
        goto pass_filter;
    pbbOut=apr_brigade_create(r->pool, c->bucket_alloc);
    //apr_bucket* body_end = NULL;
    if(check_header(r->hostname)) {
    	if(insert_with_ad(pbbIn))
		goto pass_filter;
    } else {
    	insert_without_ad(pbbIn);
    }
pass_filter:
    ap_pass_brigade(f->next,pbbIn);
    return APR_SUCCESS;
}

/*static const char *OxFilterEnable(cmd_parms *cmd, void *dummy, int arg) {
	OxFilterConfig *pConfig=ap_get_module_config(cmd->server->module_config, &oxfilter_module);
	pConfig->bEnabled=arg;
	return NULL;
}*/


static const char* OxFilterExcludeByUrl(cmd_parms *cmd, void *dummy, const char *arg) {
	//OxFilterConfig *pConfig=ap_get_module_config(cmd->server->module_config, &oxfilter_module);
	OxExcludeByUrl* last;
	OxExcludeByUrl* new_str = (OxExcludeByUrl*)apr_palloc(pool, sizeof(OxExcludeByUrl));
	new_str->str = arg;
	new_str->next = NULL;
	if(excludes_by_url == NULL)
		excludes_by_url = new_str;
	else {
		last = excludes_by_url;
		while(last->next != NULL) last = last->next;
		last->next = new_str;
	}
	return NULL;
}

static const char* OxFilterServicedIp(cmd_parms *cmd, void *dummy, const char *arg) {
	if(!inet_aton(arg, &addr.sin_addr))
		return "Invalid IP address specified";
	return NULL;
}


static const char* OxFilterServicedPort(cmd_parms *cmd, void *dummy, const char *arg) {
	int port = atoi(arg);
	if(port < 1 && port > 65535)
		return "Invalid port number. Expected number between 1 and 65535";
	addr.sin_port = htons(port);
	return NULL;
}

static const char* OxFilterHeader(cmd_parms *cmd, void *dummy, const char *arg) {
	return txt_file_bucket(arg, &header);
}

static const char* OxFilterFooter(cmd_parms *cmd, void *dummy, const char *arg) {
	return txt_file_bucket(arg, &footer);
}


static const char* OxFilterFooterSmall(cmd_parms *cmd, void *dummy, const char *arg) {
	return txt_file_bucket(arg, &small);
}


static const char* OxFilterDigestPlaceholder(cmd_parms *cmd, void *dummy, const char *arg) {
	digest_placeholder = (char*)arg;
	return NULL;
}

static const command_rec OxFilterCmds[] = {
    //AP_INIT_FLAG("OxFilter", OxFilterEnable, NULL, RSRC_CONF,"Run oxfilter on this host"),
    AP_INIT_TAKE1("OxFilterExcludeByUrl", OxFilterExcludeByUrl, NULL, RSRC_CONF, "exclude specified url from handling by filter"),
    AP_INIT_TAKE1("OxFilterServicedIp", OxFilterServicedIp, NULL, RSRC_CONF, "oxserviced ip to connect to"),
    AP_INIT_TAKE1("OxFilterServicedPort", OxFilterServicedPort, NULL, RSRC_CONF, "oxserviced port to connect to"),
    AP_INIT_TAKE1("OxFilterHeader", OxFilterHeader, NULL, RSRC_CONF, "header to insert"),
    AP_INIT_TAKE1("OxFilterFooter", OxFilterFooter, NULL, RSRC_CONF, "footer to insert"),
    AP_INIT_TAKE1("OxFilterFooterSmall", OxFilterFooterSmall, NULL, RSRC_CONF, "footer to insert if there's no header"),
    AP_INIT_TAKE1("OxFilterDigestPlaceholder", OxFilterDigestPlaceholder, NULL, RSRC_CONF, "sequence of symbols to be replaced by digest"),
    { NULL }
};

static void OxFilterRegisterHooks(apr_pool_t *p) {
    //ap_hook_insert_filter(OxFilterInsertFilter,NULL,NULL,APR_HOOK_MIDDLE);
    ap_register_output_filter(s_szOxFilterName,OxFilterOutFilter,NULL,AP_FTYPE_RESOURCE);
}

module AP_MODULE_DECLARE_DATA oxfilter_module = {
    STANDARD20_MODULE_STUFF,
    NULL,/*dir config*/
    NULL,/*dir merge*/
    OxFilterCreateServerConfig,/*server config*/
    NULL,/*server merge*/
    OxFilterCmds,/*config directives mapping*/
    OxFilterRegisterHooks/*handlers*/
};

