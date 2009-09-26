#include "apr_buckets.h"
#include "apr_general.h"
#include "apr_lib.h"
#include <stdio.h>

int bstrstr(apr_bucket* bucket, char* str, int start, apr_bucket** first, int* firstn, int* n);

