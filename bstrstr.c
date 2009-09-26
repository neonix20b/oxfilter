#include "bstrstr.h"

#define DEBUG(str) fprintf(stderr, "DEBUG: %s\n", str); fflush(stderr);

int bstrstr(apr_bucket* bucket, char* str, int start, apr_bucket** first, int* firstn, int* n) {
	static int symbols_matched = 0;
	static apr_bucket* prev_bucket = NULL;
	static int prev_len = 0;
	int match = 0;
	int len;
	int str_len = strlen(str);
	char* data;
	int i;
	//fprintf(stderr,"%s ", str);
	//DEBUG("searching...")
	apr_bucket_read(bucket, (void*)&data, &len, APR_BLOCK_READ);
	for(i = start; i < len; i++) {
		while(i + match < len && match < str_len) {
			if(data[i+match] == str[symbols_matched]) {
				//fprintf(stderr, " = %d, match = %d, %c = %c\n", i, match, data[i+match], str[symbols_matched]);
				//fflush(stderr);
				match++;
				symbols_matched++;
			} else
				goto search_fail;
			if(str[symbols_matched] == '\0') {
				*n = i;
				if(symbols_matched >= len) {
					//DEBUG("previous bucket");
					*first = prev_bucket;
					*firstn = prev_len - (symbols_matched - len);
				} else {
					//DEBUG("this bucket");
					*first = bucket;
					*firstn = *n;
				}
				//fprintf(stderr, "n=%d\n", i);
				char buf[20] = {0};
				memcpy(buf, data+i-10, 19);
				//fprintf(stderr, "%s\n", buf);
				//DEBUG(str);
				//DEBUG("found");
				symbols_matched = 0;
				return 1;
			}
		}
search_fail:
		match = 0;
		symbols_matched = 0;
	}
	prev_bucket = bucket;
	prev_len = len;
	//fprintf(stderr,"%s ", str);
	//DEBUG("not found");
	return 0;
}

