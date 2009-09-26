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

static const char s_szOxDigestName[]="OxDigest";

static char* digest_placeholder;

module AP_MODULE_DECLARE_DATA oxdigest_module;

static apr_status_t OxDigestOutFilter(ap_filter_t *f, apr_bucket_brigade *pbbIn) {
    char* buf;
    char* ptr;
    apr_off_t len, len_full;
    apr_bucket *pbktOut;
    int left;

    request_rec *r = f->r;
    conn_rec *c = r->connection;
    apr_bucket *pbktIn;
  
    if (APR_BRIGADE_EMPTY(pbbIn))
        goto pass_filter2;
    
    /*if (!ap_is_initial_req(r)) {
	ap_remove_output_filter(f);
	goto pass_filter;
    }*/

    if(!strstr(r->content_type,"text/html")) {
    	goto pass_filter2;
    }
    apr_size_t abc;
    char* xxx;
    apr_brigade_pflatten(pbbIn,&xxx,&abc,r->pool);
    int h;
    for(h = 0; h < abc; h++) fprintf(stderr, "%c", xxx[h]);
    fprintf(stderr, "\n\n***********************************************************************************************************\n\n");
    fflush(stderr);
    if(digest_placeholder) {
    	    apr_bucket *pbktIn;
	    for (pbktIn = APR_BRIGADE_FIRST(pbbIn); pbktIn != APR_BRIGADE_SENTINEL(pbbIn); pbktIn = APR_BUCKET_NEXT(pbktIn)) {
	    	apr_bucket* first;
		int firstn;
		int n;
		if(bstrstr(pbktIn, digest_placeholder, 0, &first, &firstn, &n)) {
				char digest[DIGEST_SIZE];
				get_digest(digest);
				apr_bucket* digest_bucket = apr_bucket_transient_create(digest,DIGEST_SIZE-1,c->bucket_alloc);
				apr_bucket_split(first,firstn);
				//apr_bucket* before_first = APR_BUCKET_PREV(first);
				//APR_BUCKET_REMOVE(first);
				//apr_bucket_copy(first, &first);
				//APR_BUCKET_INSERT_AFTER(before_first, first);
				apr_bucket_split(APR_BUCKET_NEXT(first),strlen(digest_placeholder));
				APR_BUCKET_REMOVE(APR_BUCKET_NEXT(first));
				APR_BUCKET_INSERT_AFTER(first,digest_bucket);
				break;
		}
	    }
    }
pass_filter2:
    ap_pass_brigade(f->next,pbbIn);
    return APR_SUCCESS;
}

static const char* OxDigestPlaceholder(cmd_parms *cmd, void *dummy, const char *arg) {
	digest_placeholder = (char*)arg;
	return NULL;
}

static const command_rec OxDigestCmds[] = {
    //AP_INIT_FLAG("OxDigest", OxDigestEnable, NULL, RSRC_CONF,"Run oxfilter on this host"),
    AP_INIT_TAKE1("OxDigestPlaceholder", OxDigestPlaceholder, NULL, RSRC_CONF, "sequence of symbols to be replaced by digest"),
    { NULL }
};

static void OxDigestRegisterHooks(apr_pool_t *p) {
    //ap_hook_insert_filter(OxDigestInsertFilter,NULL,NULL,APR_HOOK_MIDDLE);
    ap_register_output_filter(s_szOxDigestName,OxDigestOutFilter,NULL,AP_FTYPE_RESOURCE);
}

module AP_MODULE_DECLARE_DATA oxdigest_module = {
    STANDARD20_MODULE_STUFF,
    NULL,/*dir config*/
    NULL,/*dir merge*/
    NULL,/*server config*/
    NULL,/*server merge*/
    OxDigestCmds,/*config directives mapping*/
    OxDigestRegisterHooks/*handlers*/
};

