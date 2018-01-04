#define _GNU_SOURCE
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <limits.h>
#include <time.h>
#include <signal.h>
#include <sys/stat.h>
#ifdef __APPLE__
#define strdupa strdup
#include <libgen.h>
#else
#include <stdio_ext.h>
#endif
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#define CL_USE_DEPRECATED_OPENCL_1_2_APIS
#ifdef __APPLE__
#include <OpenCL/cl.h>
#else
#include <CL/cl.h>
#endif
#include "common.h"
#include "common.c"


#define MAX_SOURCE_SIZE (0x1000000)
typedef struct
{
 uint32_t h0,h1,h2,h3,h4;
} SHA_DEV_CTX;

typedef struct
{
 SHA_DEV_CTX ctx_ipad;
 SHA_DEV_CTX ctx_opad;
 SHA_DEV_CTX e1;
 SHA_DEV_CTX e2;
} gpu_inbuffer;

typedef struct
{
 SHA_DEV_CTX pmk1;
 SHA_DEV_CTX pmk2;
} gpu_outbuffer;


#define COWPATTY_SIGNATURE 0x43575041L
struct cow_head
{
 uint32_t magic;
 uint8_t reserved1[3];
 uint8_t essidlen;
 uint8_t essid[32];
};
typedef struct cow_head cow_head_t;
#define	COWHEAD_SIZE (sizeof(cow_head_t))

#define MAX_WORKSIZE (1024*1024)  /* Max. figure */
static size_t gws = 16;           /* Start figure; will auto-tune */
static cl_ulong max_gpu_alloc;    /* Memory limit */

/*===========================================================================*/
/* globale Variablen */

bool pipeflag = false;
cl_uint platformCount;
cl_platform_id *platforms = NULL;
cl_uint deviceCount;
cl_device_id *devices = NULL;

cl_int ret;
cl_context context;
cl_command_queue command_queue;
cl_kernel kernel;

uint8_t progende = false;

uint8_t essidlen = 0;
char *essidname = NULL;

FILE *fhascii = NULL;
FILE *fhasciipw = NULL;
FILE *fhcow = NULL;

gpu_inbuffer inbuffer[MAX_WORKSIZE];
char password[MAX_WORKSIZE][64];

#define HANDLE_CLERROR(command)         \
        do { cl_int __err = (command); \
                if (__err != CL_SUCCESS) { \
                        fprintf(stderr, "OpenCL %s error in %s:%d\n", \
                            getCLresultMsg(__err), __FILE__, __LINE__); \
                } \
        } while (0)


static const char *kerneldata = "\n" \
"#ifndef uint32_t    \n"  \
"#define uint32_t unsigned int    \n"  \
"#endif    \n"  \
"    \n"  \
"typedef struct    \n"  \
"{    \n"  \
"    uint32_t h0,h1,h2,h3,h4;    \n"  \
"} SHA_DEV_CTX;    \n"  \
"    \n"  \
"#define CPY_DEVCTX(src, dst) { dst.h0 = src.h0; dst.h1 = src.h1; dst.h2 = src.h2; dst.h3 = src.h3; dst.h4 = src.h4; }    \n"  \
"    \n"  \
"typedef struct    \n"  \
"{    \n"  \
"    SHA_DEV_CTX ctx_ipad;    \n"  \
"    SHA_DEV_CTX ctx_opad;    \n"  \
"    SHA_DEV_CTX e1;    \n"  \
"    SHA_DEV_CTX e2;    \n"  \
"} gpu_inbuffer;    \n"  \
"    \n"  \
"typedef struct    \n"  \
"{    \n"  \
"    SHA_DEV_CTX pmk1;    \n"  \
"    SHA_DEV_CTX pmk2;    \n"  \
"} gpu_outbuffer;    \n"  \
"    \n"  \
"    \n"  \
"    \n"  \
"void sha1_process(__private const SHA_DEV_CTX ctx, __private SHA_DEV_CTX *data)    \n"  \
"{    \n"  \
"  uint32_t temp, W[16], A, B, C, D, E;    \n"  \
"    \n"  \
"  W[ 0] = data->h0; W[ 1] = data->h1;    \n"  \
"  W[ 2] = data->h2; W[ 3] = data->h3;    \n"  \
"  W[ 4] = data->h4; W[ 5] = 0x80000000;    \n"  \
"  W[ 6] = 0; W[ 7] = 0;    \n"  \
"  W[ 8] = 0; W[ 9] = 0;    \n"  \
"  W[10] = 0; W[11] = 0;    \n"  \
"  W[12] = 0; W[13] = 0;    \n"  \
"  W[14] = 0; W[15] = (64+20)*8;    \n"  \
"    \n"  \
"  A = ctx.h0;    \n"  \
"  B = ctx.h1;    \n"  \
"  C = ctx.h2;    \n"  \
"  D = ctx.h3;    \n"  \
"  E = ctx.h4;    \n"  \
"    \n"  \
"#undef R    \n"  \
"#define R(t) (temp = W[(t -  3) & 0x0F] ^ W[(t - 8) & 0x0F] ^ W[(t - 14) & 0x0F] ^ W[t & 0x0F], ( W[t & 0x0F] = rotate((int)temp,1)))    \n"  \
"    \n"  \
"#undef P    \n"  \
"#define P(a,b,c,d,e,x) { e += rotate((int)a,5) + F(b,c,d) + K + x; b = rotate((int)b,30); }    \n"  \
"    \n"  \
"#define F(x,y,z) (z ^ (x & (y ^ z)))    \n"  \
"#define K 0x5A827999    \n"  \
"      \n"  \
"  P( A, B, C, D, E, W[0]  );    \n"  \
"  P( E, A, B, C, D, W[1]  );    \n"  \
"  P( D, E, A, B, C, W[2]  );    \n"  \
"  P( C, D, E, A, B, W[3]  );    \n"  \
"  P( B, C, D, E, A, W[4]  );    \n"  \
"  P( A, B, C, D, E, W[5]  );    \n"  \
"  P( E, A, B, C, D, W[6]  );    \n"  \
"  P( D, E, A, B, C, W[7]  );    \n"  \
"  P( C, D, E, A, B, W[8]  );    \n"  \
"  P( B, C, D, E, A, W[9]  );    \n"  \
"  P( A, B, C, D, E, W[10] );    \n"  \
"  P( E, A, B, C, D, W[11] );    \n"  \
"  P( D, E, A, B, C, W[12] );    \n"  \
"  P( C, D, E, A, B, W[13] );    \n"  \
"  P( B, C, D, E, A, W[14] );    \n"  \
"  P( A, B, C, D, E, W[15] );    \n"  \
"  P( E, A, B, C, D, R(16) );    \n"  \
"  P( D, E, A, B, C, R(17) );    \n"  \
"  P( C, D, E, A, B, R(18) );    \n"  \
"  P( B, C, D, E, A, R(19) );    \n"  \
"    \n"  \
"#undef K    \n"  \
"#undef F    \n"  \
"    \n"  \
"#define F(x,y,z) (x ^ y ^ z)    \n"  \
"#define K 0x6ED9EBA1    \n"  \
"      \n"  \
"  P( A, B, C, D, E, R(20) );    \n"  \
"  P( E, A, B, C, D, R(21) );    \n"  \
"  P( D, E, A, B, C, R(22) );    \n"  \
"  P( C, D, E, A, B, R(23) );    \n"  \
"  P( B, C, D, E, A, R(24) );    \n"  \
"  P( A, B, C, D, E, R(25) );    \n"  \
"  P( E, A, B, C, D, R(26) );    \n"  \
"  P( D, E, A, B, C, R(27) );    \n"  \
"  P( C, D, E, A, B, R(28) );    \n"  \
"  P( B, C, D, E, A, R(29) );    \n"  \
"  P( A, B, C, D, E, R(30) );    \n"  \
"  P( E, A, B, C, D, R(31) );    \n"  \
"  P( D, E, A, B, C, R(32) );    \n"  \
"  P( C, D, E, A, B, R(33) );    \n"  \
"  P( B, C, D, E, A, R(34) );    \n"  \
"  P( A, B, C, D, E, R(35) );    \n"  \
"  P( E, A, B, C, D, R(36) );    \n"  \
"  P( D, E, A, B, C, R(37) );    \n"  \
"  P( C, D, E, A, B, R(38) );    \n"  \
"  P( B, C, D, E, A, R(39) );    \n"  \
"      \n"  \
"#undef K    \n"  \
"#undef F    \n"  \
"      \n"  \
"#define F(x,y,z) ((x & y) | (z & (x | y)))    \n"  \
"#define K 0x8F1BBCDC    \n"  \
"      \n"  \
"  P( A, B, C, D, E, R(40) );    \n"  \
"  P( E, A, B, C, D, R(41) );    \n"  \
"  P( D, E, A, B, C, R(42) );    \n"  \
"  P( C, D, E, A, B, R(43) );    \n"  \
"  P( B, C, D, E, A, R(44) );    \n"  \
"  P( A, B, C, D, E, R(45) );    \n"  \
"  P( E, A, B, C, D, R(46) );    \n"  \
"  P( D, E, A, B, C, R(47) );    \n"  \
"  P( C, D, E, A, B, R(48) );    \n"  \
"  P( B, C, D, E, A, R(49) );    \n"  \
"  P( A, B, C, D, E, R(50) );    \n"  \
"  P( E, A, B, C, D, R(51) );    \n"  \
"  P( D, E, A, B, C, R(52) );    \n"  \
"  P( C, D, E, A, B, R(53) );    \n"  \
"  P( B, C, D, E, A, R(54) );    \n"  \
"  P( A, B, C, D, E, R(55) );    \n"  \
"  P( E, A, B, C, D, R(56) );    \n"  \
"  P( D, E, A, B, C, R(57) );    \n"  \
"  P( C, D, E, A, B, R(58) );    \n"  \
"  P( B, C, D, E, A, R(59) );    \n"  \
"      \n"  \
"#undef K    \n"  \
"#undef F    \n"  \
"    \n"  \
"#define F(x,y,z) (x ^ y ^ z)    \n"  \
"#define K 0xCA62C1D6    \n"  \
"      \n"  \
"  P( A, B, C, D, E, R(60) );    \n"  \
"  P( E, A, B, C, D, R(61) );    \n"  \
"  P( D, E, A, B, C, R(62) );    \n"  \
"  P( C, D, E, A, B, R(63) );    \n"  \
"  P( B, C, D, E, A, R(64) );    \n"  \
"  P( A, B, C, D, E, R(65) );    \n"  \
"  P( E, A, B, C, D, R(66) );    \n"  \
"  P( D, E, A, B, C, R(67) );    \n"  \
"  P( C, D, E, A, B, R(68) );    \n"  \
"  P( B, C, D, E, A, R(69) );    \n"  \
"  P( A, B, C, D, E, R(70) );    \n"  \
"  P( E, A, B, C, D, R(71) );    \n"  \
"  P( D, E, A, B, C, R(72) );    \n"  \
"  P( C, D, E, A, B, R(73) );    \n"  \
"  P( B, C, D, E, A, R(74) );    \n"  \
"  P( A, B, C, D, E, R(75) );    \n"  \
"  P( E, A, B, C, D, R(76) );    \n"  \
"  P( D, E, A, B, C, R(77) );    \n"  \
"  P( C, D, E, A, B, R(78) );    \n"  \
"  P( B, C, D, E, A, R(79) );    \n"  \
"    \n"  \
"#undef K    \n"  \
"#undef F    \n"  \
"    \n"  \
"  data->h0 = ctx.h0 + A;    \n"  \
"  data->h1 = ctx.h1 + B;    \n"  \
"  data->h2 = ctx.h2 + C;    \n"  \
"  data->h3 = ctx.h3 + D;    \n"  \
"  data->h4 = ctx.h4 + E;    \n"  \
"    \n"  \
"}    \n"  \
"    \n"  \
"__kernel    \n"  \
"void opencl_pmk_kernel(__global gpu_inbuffer *inbuffer, __global gpu_outbuffer *outbuffer)    \n"  \
"{    \n"  \
"    int i;    \n"  \
"    const int idx = get_global_id(0);    \n"  \
"    SHA_DEV_CTX temp_ctx;    \n"  \
"    SHA_DEV_CTX pmk_ctx;    \n"  \
"    SHA_DEV_CTX ipad;    \n"  \
"    SHA_DEV_CTX opad;    \n"  \
"        \n"  \
"    CPY_DEVCTX(inbuffer[idx].ctx_ipad, ipad);    \n"  \
"    CPY_DEVCTX(inbuffer[idx].ctx_opad, opad);    \n"  \
"        \n"  \
"    CPY_DEVCTX(inbuffer[idx].e1, temp_ctx);    \n"  \
"    CPY_DEVCTX(temp_ctx, pmk_ctx);    \n"  \
"    for( i = 0; i < 4096-1; i++ )    \n"  \
"    {    \n"  \
"        sha1_process(ipad, &temp_ctx);    \n"  \
"        sha1_process(opad, &temp_ctx);    \n"  \
"        pmk_ctx.h0 ^= temp_ctx.h0; pmk_ctx.h1 ^= temp_ctx.h1;    \n"  \
"        pmk_ctx.h2 ^= temp_ctx.h2; pmk_ctx.h3 ^= temp_ctx.h3;    \n"  \
"        pmk_ctx.h4 ^= temp_ctx.h4;    \n"  \
"    }    \n"  \
"    CPY_DEVCTX(pmk_ctx, outbuffer[idx].pmk1);    \n"  \
"        \n"  \
"        \n"  \
"    CPY_DEVCTX(inbuffer[idx].e2, temp_ctx);    \n"  \
"    CPY_DEVCTX(temp_ctx, pmk_ctx);    \n"  \
"    for( i = 0; i < 4096-1; i++ )    \n"  \
"    {    \n"  \
"      sha1_process(ipad, &temp_ctx);    \n"  \
"      sha1_process(opad, &temp_ctx);    \n"  \
"        pmk_ctx.h0 ^= temp_ctx.h0; pmk_ctx.h1 ^= temp_ctx.h1;    \n"  \
"        pmk_ctx.h2 ^= temp_ctx.h2; pmk_ctx.h3 ^= temp_ctx.h3;    \n"  \
"        pmk_ctx.h4 ^= temp_ctx.h4;    \n"  \
"    }    \n"  \
"    CPY_DEVCTX(pmk_ctx, outbuffer[idx].pmk2);    \n"  \
"}    \n";

/*===========================================================================*/
static char* getCLresultMsg(cl_int error)
{
switch (error)
	{
	case CL_SUCCESS: return "CL_SUCCESS";
	case CL_DEVICE_NOT_FOUND: return "CL_DEVICE_NOT_FOUND";
	case CL_DEVICE_NOT_AVAILABLE: return "CL_DEVICE_NOT_AVAILABLE";
	case CL_COMPILER_NOT_AVAILABLE: return "CL_COMPILER_NOT_AVAILABLE";
	case CL_MEM_OBJECT_ALLOCATION_FAILURE: return "CL_MEM_OBJECT_ALLOCATION_FAILURE";
	case CL_OUT_OF_RESOURCES: return "CL_OUT_OF_RESOURCES";
	case CL_OUT_OF_HOST_MEMORY: return "CL_OUT_OF_HOST_MEMORY";
	case CL_PROFILING_INFO_NOT_AVAILABLE: return "CL_PROFILING_INFO_NOT_AVAILABLE";
	case CL_MEM_COPY_OVERLAP: return "CL_MEM_COPY_OVERLAP";
	case CL_IMAGE_FORMAT_MISMATCH: return "CL_IMAGE_FORMAT_MISMATCH";
	case CL_IMAGE_FORMAT_NOT_SUPPORTED: return "CL_IMAGE_FORMAT_NOT_SUPPORTED";
	case CL_BUILD_PROGRAM_FAILURE: return "CL_BUILD_PROGRAM_FAILURE";
	case CL_MAP_FAILURE: return "CL_MAP_FAILURE";
	case CL_INVALID_VALUE: return "CL_INVALID_VALUE";
	case CL_INVALID_DEVICE_TYPE: return "CL_INVALID_DEVICE_TYPE";
	case CL_INVALID_PLATFORM: return "CL_INVALID_PLATFORM";
	case CL_INVALID_DEVICE: return "CL_INVALID_DEVICE";
	case CL_INVALID_CONTEXT: return "CL_INVALID_CONTEXT";
	case CL_INVALID_QUEUE_PROPERTIES: return "CL_INVALID_QUEUE_PROPERTIES";
	case CL_INVALID_COMMAND_QUEUE: return "CL_INVALID_COMMAND_QUEUE";
	case CL_INVALID_HOST_PTR: return "CL_INVALID_HOST_PTR";
	case CL_INVALID_MEM_OBJECT: return "CL_INVALID_MEM_OBJECT";
	case CL_INVALID_IMAGE_FORMAT_DESCRIPTOR: return "CL_INVALID_IMAGE_FORMAT_DESCRIPTOR";
	case CL_INVALID_IMAGE_SIZE: return "CL_INVALID_IMAGE_SIZE";
	case CL_INVALID_SAMPLER: return "CL_INVALID_SAMPLER";
	case CL_INVALID_BINARY: return "CL_INVALID_BINARY";
	case CL_INVALID_BUILD_OPTIONS: return "CL_INVALID_BUILD_OPTIONS";
	case CL_INVALID_PROGRAM: return "CL_INVALID_PROGRAM";
	case CL_INVALID_PROGRAM_EXECUTABLE: return "CL_INVALID_PROGRAM_EXECUTABLE";
	case CL_INVALID_KERNEL_NAME: return "CL_INVALID_KERNEL_NAME";
	case CL_INVALID_KERNEL_DEFINITION: return "CL_INVALID_KERNEL_DEFINITION";
	case CL_INVALID_KERNEL: return "CL_INVALID_KERNEL";
	case CL_INVALID_ARG_INDEX: return "CL_INVALID_ARG_INDEX";
	case CL_INVALID_ARG_VALUE: return "CL_INVALID_ARG_VALUE";
	case CL_INVALID_ARG_SIZE: return "CL_INVALID_ARG_SIZE";
	case CL_INVALID_KERNEL_ARGS: return "CL_INVALID_KERNEL_ARGS";
	case CL_INVALID_WORK_DIMENSION: return "CL_INVALID_WORK_DIMENSION";
	case CL_INVALID_WORK_GROUP_SIZE: return "CL_INVALID_WORK_GROUP_SIZE";
	case CL_INVALID_WORK_ITEM_SIZE: return "CL_INVALID_WORK_ITEM_SIZE";
	case CL_INVALID_GLOBAL_OFFSET: return "CL_INVALID_GLOBAL_OFFSET";
	case CL_INVALID_EVENT_WAIT_LIST: return "CL_INVALID_EVENT_WAIT_LIST";
	case CL_INVALID_EVENT: return "CL_INVALID_EVENT";
	case CL_INVALID_OPERATION: return "CL_INVALID_OPERATION";
	case CL_INVALID_GL_OBJECT: return "CL_INVALID_GL_OBJECT";
	case CL_INVALID_BUFFER_SIZE: return "CL_INVALID_BUFFER_SIZE";
	case CL_INVALID_MIP_LEVEL: return "CL_INVALID_MIP_LEVEL";
	default : return "Unknown CLresult";
	}
return "Unknown CLresult";
}
/*===========================================================================*/
uint32_t finalcalc(size_t listsize)
{
size_t c;
int cr;
cl_mem g_inbuffer, g_outbuffer;
gpu_outbuffer *outbuffer;
gpu_outbuffer zeigerout;
g_inbuffer = NULL;
g_outbuffer = NULL;
cl_event clEvents[3];
uint8_t cowreclen;
cl_ulong start_ts, end_ts;
uint32_t ms_dur;
uint32_t cowpmk[8];

outbuffer = malloc(listsize *sizeof(gpu_outbuffer));
g_inbuffer = clCreateBuffer(context, CL_MEM_READ_ONLY, listsize *sizeof(gpu_inbuffer), NULL, &ret);
HANDLE_CLERROR(clEnqueueWriteBuffer(command_queue, g_inbuffer, CL_FALSE, 0, listsize *sizeof(gpu_inbuffer), &inbuffer, 0, NULL, &clEvents[0]));
g_outbuffer = clCreateBuffer(context, CL_MEM_WRITE_ONLY, listsize *sizeof(gpu_outbuffer), NULL, &ret);

HANDLE_CLERROR(clSetKernelArg(kernel, 0, sizeof(cl_mem), &g_inbuffer));
HANDLE_CLERROR(clSetKernelArg(kernel, 1, sizeof(cl_mem), &g_outbuffer));

HANDLE_CLERROR(clEnqueueNDRangeKernel(command_queue, kernel, 1, NULL, &listsize, NULL, 1, clEvents, &clEvents[1]));
HANDLE_CLERROR(clEnqueueReadBuffer(command_queue, g_outbuffer, CL_FALSE, 0, listsize *sizeof(gpu_outbuffer), outbuffer, 2, clEvents, &clEvents[2]));

HANDLE_CLERROR(clFinish(command_queue));

HANDLE_CLERROR(clWaitForEvents(3, clEvents));

HANDLE_CLERROR(clGetEventProfilingInfo(clEvents[1], CL_PROFILING_COMMAND_START, sizeof(cl_ulong), &start_ts, NULL));
HANDLE_CLERROR(clGetEventProfilingInfo(clEvents[2], CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &end_ts, NULL));

ms_dur = (uint32_t)((end_ts - start_ts) / 1000000);
//fprintf(stderr, "GWS %zu Time: %u ms\n", gws, ms_dur);
if (ms_dur <= 100 &&
    2 * gws < MAX_WORKSIZE &&
    2 * gws * sizeof(gpu_inbuffer) < max_gpu_alloc)
	{
	gws *= 2;
	}

for(c = 0; c < listsize; c++)
	{
	zeigerout = outbuffer[c];
	if(fhascii != NULL)
		fprintf(fhascii, "%08x%08x%08x%08x%08x%08x%08x%08x\n",zeigerout.pmk1.h0, zeigerout.pmk1.h1, zeigerout.pmk1.h2, zeigerout.pmk1.h3, zeigerout.pmk1.h4, zeigerout.pmk2.h0, zeigerout.pmk2.h1, zeigerout.pmk2.h2);
	if(fhasciipw != NULL)
		fprintf(fhasciipw, "%08x%08x%08x%08x%08x%08x%08x%08x:%s\n",zeigerout.pmk1.h0, zeigerout.pmk1.h1, zeigerout.pmk1.h2, zeigerout.pmk1.h3, zeigerout.pmk1.h4, zeigerout.pmk2.h0, zeigerout.pmk2.h1, zeigerout.pmk2.h2, &password[c][0]);

	if(fhcow != NULL)
		{
		cowreclen = sizeof(cowreclen) + strlen(&password[c][0]) + 32;
		cr = fwrite(&cowreclen, sizeof(cowreclen), 1, fhcow);
		if(cr != 1)
			{
			fprintf(stderr, "error writing cowpatty file\n");
			exit(EXIT_FAILURE);
			}
		fprintf(fhcow, "%s", &password[c][0]);
		cowpmk[0] = byte_swap_32(zeigerout.pmk1.h0);
		cowpmk[1] = byte_swap_32(zeigerout.pmk1.h1);
		cowpmk[2] = byte_swap_32(zeigerout.pmk1.h2);
		cowpmk[3] = byte_swap_32(zeigerout.pmk1.h3);
		cowpmk[4] = byte_swap_32(zeigerout.pmk1.h4);
		cowpmk[5] = byte_swap_32(zeigerout.pmk2.h0);
		cowpmk[6] = byte_swap_32(zeigerout.pmk2.h1);
		cowpmk[7] = byte_swap_32(zeigerout.pmk2.h2);

		cr = fwrite(&cowpmk[0], sizeof(uint32_t), 8, fhcow);
		if(cr != 8)
			{
			fprintf(stderr, "error writing cowpatty file\n");
			exit(EXIT_FAILURE);
			}
		}


	}

for (c = 0; c < 3; c++)
	{
	if(clEvents[c] != 0)
	clReleaseEvent(clEvents[c]);
	}

if (g_inbuffer != NULL)
	clReleaseMemObject(g_inbuffer);
if (g_outbuffer != NULL)
	clReleaseMemObject(g_outbuffer);
free(outbuffer);

return listsize * 1000 / ms_dur;
}
/*===========================================================================*/
void precalc(gpu_inbuffer *zeigerinbuffer, uint8_t passwdlen, char *password)
{

int i;
SHA_CTX ctx_pad;

unsigned char essid[32 +4];
unsigned char pad[64];
unsigned char hmacout[32];

memcpy(essid, essidname, essidlen);
memset(essid + essidlen, 0, sizeof(essid) - essidlen);

memcpy(pad, password, passwdlen);
memset(pad + passwdlen, 0, sizeof(pad) - passwdlen);
for (i = 0; i < 16; i++)
	((unsigned int*)pad)[i] ^= 0x36363636;
SHA1_Init(&ctx_pad);
SHA1_Update(&ctx_pad, pad, sizeof(pad));
zeigerinbuffer->ctx_ipad.h0 = ctx_pad.h0;
zeigerinbuffer->ctx_ipad.h1 = ctx_pad.h1;
zeigerinbuffer->ctx_ipad.h2 = ctx_pad.h2;
zeigerinbuffer->ctx_ipad.h3 = ctx_pad.h3;
zeigerinbuffer->ctx_ipad.h4 = ctx_pad.h4;

for (i = 0; i < 16; i++)
	((unsigned int*)pad)[i] ^= 0x6A6A6A6A;
SHA1_Init(&ctx_pad);
SHA1_Update(&ctx_pad, pad, sizeof(pad));
zeigerinbuffer->ctx_opad.h0 = ctx_pad.h0;
zeigerinbuffer->ctx_opad.h1 = ctx_pad.h1;
zeigerinbuffer->ctx_opad.h2 = ctx_pad.h2;
zeigerinbuffer->ctx_opad.h3 = ctx_pad.h3;
zeigerinbuffer->ctx_opad.h4 = ctx_pad.h4;

essid[essidlen + 4 - 1] = '\1';
HMAC(EVP_sha1(), password, passwdlen, essid, essidlen + 4, hmacout, NULL);
zeigerinbuffer->e1.h0 = (hmacout[0] << 24) | (hmacout[0 +1] << 16) | (hmacout[0 +2] << 8) | (hmacout[0 +3]);
zeigerinbuffer->e1.h1 = (hmacout[4] << 24) | (hmacout[4 +1] << 16) | (hmacout[4 +2] << 8) | (hmacout[4 +3]);
zeigerinbuffer->e1.h2 = (hmacout[8] << 24) | (hmacout[8 +1] << 16) | (hmacout[8 +2] << 8) | (hmacout[8 +3]);
zeigerinbuffer->e1.h3 = (hmacout[12] << 24) | (hmacout[12 +1] << 16) | (hmacout[12 +2] << 8) | (hmacout[12 +3]);
zeigerinbuffer->e1.h4 = (hmacout[16] << 24) | (hmacout[16 +1] << 16) | (hmacout[16 +2] << 8) | (hmacout[16 +3]);

essid[essidlen + 4 - 1] = '\2';
HMAC(EVP_sha1(), password, passwdlen, essid, essidlen + 4, hmacout, NULL);
zeigerinbuffer->e2.h0 = (hmacout[0] << 24) | (hmacout[0 +1] << 16) | (hmacout[0 +2] << 8) | (hmacout[0 +3]);
zeigerinbuffer->e2.h1 = (hmacout[4] << 24) | (hmacout[4 +1] << 16) | (hmacout[4 +2] << 8) | (hmacout[4 +3]);
zeigerinbuffer->e2.h2 = (hmacout[8] << 24) | (hmacout[8 +1] << 16) | (hmacout[8 +2] << 8) | (hmacout[8 +3]);
zeigerinbuffer->e2.h3 = (hmacout[12] << 24) | (hmacout[12 +1] << 16) | (hmacout[12 +2] << 8) | (hmacout[12 +3]);
zeigerinbuffer->e2.h4 = (hmacout[16] << 24) | (hmacout[16 +1] << 16) | (hmacout[16 +2] << 8) | (hmacout[16 +3]);

return;
}


/*===========================================================================*/
void programmende(int signum)
{
if((signum == SIGINT) || (signum == SIGTERM) || (signum == SIGKILL))
	{
	progende = true;
	}
return;
}
/*===========================================================================*/
size_t chop(char *buffer, size_t len)
{
char *ptr = buffer +len -1;

while(len)
	{
	if (*ptr != '\n')
		break;
	*ptr-- = 0;
	len--;
	}

while(len)
	{
	if (*ptr != '\r')
		break;
	*ptr-- = 0;
	len--;
	}
return len;
}
/*---------------------------------------------------------------------------*/
int fgetline(FILE *inputstream, size_t size, char *buffer)
{
if(feof(inputstream))
	return -1;
char *buffptr = fgets (buffer, size, inputstream);

if(buffptr == NULL)
	return -1;

size_t len = strlen(buffptr);
len = chop(buffptr, len);
return len;
}
/*===========================================================================*/
void filecombiout(FILE *fhcombi)
{
size_t c;
char *ptr1 = NULL;
int combilen;
int pwlen;
int cr;
int hr;
cow_head_t cow;
long int pmkcount = 0;
long int skippedcount = 0;
uint32_t speed = 0;
char combiline[256];
uint8_t buffhex[128];

signal(SIGINT, programmende);
if(fhcow != NULL)
	{
	memset(&cow, 0, COWHEAD_SIZE);
	cow.magic = COWPATTY_SIGNATURE;
	memset(&cow.essid, 0,32);
	cow.essidlen = 0;
	cow.reserved1[2] = 1;
	cr = fwrite(&cow, COWHEAD_SIZE, 1, fhcow);
	if(cr != 1)
		{
		fprintf(stderr, "error writing cowpatty file\n");
		exit(EXIT_FAILURE);
		}
	}

c = 0;
while((progende != true) && ((combilen = fgetline(fhcombi, 256, combiline)) != -1))
	{
	if(combilen < 10)
		{
		skippedcount++;
		continue;
		}

	essidname = combiline;
	ptr1 = strchr(combiline, ':');
	if(ptr1 == NULL)
		{
		skippedcount++;
		continue;
		}

	ptr1[0] = 0;
	ptr1++;
	essidlen = strlen(essidname);
	if(is_hexify((uint8_t*)essidname, essidlen))
		{
		hr = do_unhexify((uint8_t*)essidname, essidlen, buffhex, 128);
		memcpy(essidname, buffhex, hr);
		essidlen = hr;
		}
	if((essidlen < 1) || (essidlen > 32))
		{
		skippedcount++;
		continue;
		}

	pwlen = strlen(ptr1);
	if(is_hexify((uint8_t*)ptr1, pwlen))
		{
		hr = do_unhexify((uint8_t*)ptr1, pwlen, buffhex, 128);
		memcpy(ptr1, buffhex, hr);
		pwlen = hr;
		}

	if((pwlen < 8) || (pwlen > 63))
		{
		skippedcount++;
		continue;
		}

	memset(&password[c][0], 0, 64);
	memcpy(&password[c][0], ptr1, pwlen);

	precalc(&inbuffer[c], pwlen, &password[c][0]);
	c++;
	pmkcount++;
	if(c >= gws)
		{
		speed = finalcalc(c);
		c = 0;
		}
	if((pipeflag == false) && ((pmkcount % 1000) == 0))
		{
		printf("\r%ld plainmasterkeys generated (%u/s)", pmkcount, speed);
		}
	}

if(c != 0)
	speed = finalcalc(c);

if(pipeflag == false)
	{
	printf("\r%ld plainmasterkeys generated, %ld password(s) skipped\n", pmkcount, skippedcount);
	}
return;
}
/*===========================================================================*/
void processpasswords(FILE *fhpwlist)
{
int pwlen;
size_t c;
int cr;
long int pmkcount = 0;
long int skippedcount = 0;
cow_head_t cow;
uint32_t speed = 0;

signal(SIGINT, programmende);
if((fhcow != NULL) && (essidname != NULL))
	{
	memset(&cow, 0, COWHEAD_SIZE);
	cow.magic = COWPATTY_SIGNATURE;
	memcpy(cow.essid, essidname, essidlen);
	cow.essidlen = essidlen;
	cr = fwrite(&cow, COWHEAD_SIZE, 1, fhcow);
	if(cr != 1)
		{
		fprintf(stderr, "error writing cowpatty file\n");
		exit(EXIT_FAILURE);
		}
	}

c = 0;
while((progende != true) && ((pwlen = fgetline(fhpwlist, 64, &password[c][0])) != -1))
	{
	if((pwlen < 8) || pwlen > 63)
		{
		skippedcount++;
		continue;
		}

	precalc(&inbuffer[c], pwlen, &password[c][0]);
	c++;
	pmkcount++;
	if(c >= gws)
		{
		speed = finalcalc(c);
		c = 0;
		}
	if((pipeflag == false) && ((pmkcount % 1000) == 0))
		printf("\r%ld plainmasterkeys generated (%u/s)", pmkcount, speed);
	}

if(c != 0)
	speed = finalcalc(c);
if(pipeflag == false)
	{
	printf("\r%ld plainmasterkeys generated, %ld password(s) skipped\n", pmkcount, skippedcount);
	}
return;
}
/*===========================================================================*/
bool initopencl(unsigned int gplfc, unsigned int gdevc)
{
cl_program program;

char *devicename;
size_t devicenamesize;

HANDLE_CLERROR(clGetPlatformIDs(0, NULL, &platformCount));

platforms = (cl_platform_id*) malloc(sizeof(cl_platform_id) * platformCount);

HANDLE_CLERROR(clGetPlatformIDs(platformCount, platforms, NULL));

if(gplfc >= platformCount)
	return false;

HANDLE_CLERROR(clGetDeviceIDs(platforms[gplfc], CL_DEVICE_TYPE_ALL, 0, NULL, &deviceCount));

devices = (cl_device_id*) malloc(sizeof(cl_device_id) * deviceCount);
HANDLE_CLERROR(clGetDeviceIDs(platforms[gplfc], CL_DEVICE_TYPE_ALL, deviceCount, devices, NULL));

if(gdevc >= deviceCount)
	return false;

HANDLE_CLERROR(clGetDeviceInfo(devices[gdevc], CL_DEVICE_MAX_MEM_ALLOC_SIZE, sizeof(max_gpu_alloc), &max_gpu_alloc, NULL));

HANDLE_CLERROR(clGetDeviceInfo(devices[gdevc], CL_DEVICE_NAME, 0, NULL, &devicenamesize));

devicename = (char*) malloc(devicenamesize);
HANDLE_CLERROR(clGetDeviceInfo(devices[gdevc], CL_DEVICE_NAME, devicenamesize, devicename, NULL));
if(pipeflag == false)
	{
	printf("using: %s\n", devicename);
	}
free(devicename);

context = clCreateContext( NULL, 1, &devices[gdevc], NULL, NULL, &ret);

command_queue = clCreateCommandQueue(context, devices[gdevc], CL_QUEUE_PROFILING_ENABLE, &ret);
program = clCreateProgramWithSource(context, 1, (const char **) &kerneldata, NULL, &ret);

ret = clBuildProgram(program, 1, &devices[gdevc], NULL, NULL, NULL);
if (ret != CL_SUCCESS)
	{
	printf("OpenCL Error %s\n", getCLresultMsg(ret));
    size_t len;
    char buffer[62048];
    printf("Error: Failed to build program executable!\n");
    clGetProgramBuildInfo(program, devices[gdevc], CL_PROGRAM_BUILD_LOG, sizeof(buffer), buffer, &len);
    printf("%s\n", buffer);
    exit(1);
	return false;
	}

kernel = clCreateKernel(program, "opencl_pmk_kernel", &ret);
if (ret != CL_SUCCESS)
	{
	printf("OpenCL Error %s\n", getCLresultMsg(ret));
	return false;
	}
return true;
}
/*===========================================================================*/
bool listdevices()
{
unsigned int p, d;
char* value1;
char* value2;
size_t valueSize;


HANDLE_CLERROR(clGetPlatformIDs(0, NULL, &platformCount));

platforms = (cl_platform_id*) malloc(sizeof(cl_platform_id) * platformCount);

HANDLE_CLERROR(clGetPlatformIDs(platformCount, platforms, NULL));

for (p = 0; p < platformCount; p++)
	{
		HANDLE_CLERROR(clGetDeviceIDs(platforms[p], CL_DEVICE_TYPE_ALL, 0, NULL, &deviceCount));

	devices = (cl_device_id*) malloc(sizeof(cl_device_id) * deviceCount);
	HANDLE_CLERROR(clGetDeviceIDs(platforms[p], CL_DEVICE_TYPE_ALL, deviceCount, devices, NULL));
	for (d = 0; d < deviceCount; d++)
		{
		clGetDeviceInfo(devices[d], CL_DEVICE_NAME, 0, NULL, &valueSize);
		value1 = (char*) malloc(valueSize);
		clGetDeviceInfo(devices[d], CL_DEVICE_NAME, valueSize, value1, NULL);

		clGetDeviceInfo(devices[d], CL_DEVICE_OPENCL_C_VERSION, 0, NULL, &valueSize);
		value2 = (char*) malloc(valueSize);
		clGetDeviceInfo(devices[d], CL_DEVICE_OPENCL_C_VERSION, valueSize, value2, NULL);
		printf("%s, %s  for this device use options -P %d -D %d\n", value1, value2, p, d);
		free(value2);
		free(value1);
		}
	free(devices);
	}
free(platforms);
return true;
}
/*===========================================================================*/
void singlepmkout(char *pwname, int pwlen)
{
int c;

unsigned char essid[32];
unsigned char pmk1[64];
unsigned char pmk256[64];

memset(&essid, 0, 32);
memcpy(&essid, essidname, essidlen);

fprintf(stdout, "\n"
		"essid (networkname)....: %s\n"
		"password...............: %s\n"
		, essidname, pwname);


if(PKCS5_PBKDF2_HMAC(pwname, pwlen, essid, essidlen, 4096, EVP_sha1(), 32, pmk1) != 0)
	{
	printf("plainmasterkey (SHA1)..: ");
	for(c = 0; c< 32; c++)
		{
		printf("%02x", pmk1[c]);
		}
	printf("\n");
	}
if(PKCS5_PBKDF2_HMAC(pwname, pwlen, essid, essidlen, 4096, EVP_sha256(), 32, pmk256) != 0)
	{
	printf("plainmasterkey (SHA256): ");
	for(c = 0; c< 32; c++)
		{
		printf("%02x", pmk256[c]);
		}
	printf("\n\n");
	}

return;
}
/*===========================================================================*/
static void usage(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n"
	"usage: %s <options>\n"
	"\n"
	"options:\n"
	"-e <essid>    : input single essid (networkname: 1 .. 32 characters) requires -p\n"
	"-p <password> : input single password (8 .. 63 characters) requires -e\n"
	"-i <file>     : input passwordlist\n"
	"-I <file>     : input combilist (essid:password)\n"
	"-a <file>     : output plainmasterkeys as ASCII file (hashcat -m 2501)\n"
	"-A <file>     : output plainmasterkeys:password as ASCII file\n"
	"-c <file>     : output cowpatty hashfile (existing file will be replaced)\n"
	"-P <platform> : input platform, default 0 (first platform)\n"
	"-D <device>   : input device, default 0 (first device)\n"
	"-l            : list device info\n"
	"-h            : this help\n"
	"\n", eigenname, VERSION, VERSION_JAHR, eigenname);
exit(EXIT_FAILURE);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
FILE *fhpwlist = NULL;
FILE *fhcombi = NULL;
int auswahl;
unsigned int gplfc = 0;
unsigned int gdevc= 0;

int pwlen = 0;
int listdeviceinfo = false;

char *eigenname = NULL;
char *eigenpfadname = NULL;
char *pwname = NULL;

eigenpfadname = strdupa(argv[0]);
eigenname = basename(eigenpfadname);

setbuf(stdout, NULL);
while ((auswahl = getopt(argc, argv, "p:e:i:I:a:A:c:P:D:lh")) != -1)
	{
	switch (auswahl)
		{
		case 'e':
		essidname = optarg;
		essidlen = strlen(essidname);
		if((essidlen < 1) || (essidlen > 32))
			{
			fprintf(stderr, "error wrong essid len\n");
			exit(EXIT_FAILURE);
			}
		break;

		case 'p':
		pwname = optarg;
		pwlen = strlen(pwname);
		if((pwlen < 8) || (pwlen > 63))
			{
			fprintf(stderr, "error wrong password len\n");
			exit(EXIT_FAILURE);
			}
		break;

		case 'i':
		if((fhpwlist = fopen(optarg, "r")) == NULL)
			{
			fprintf(stderr, "error opening %s\n", optarg);
			exit(EXIT_FAILURE);
			}
		break;

		case 'I':
		if((fhcombi = fopen(optarg, "r")) == NULL)
			{
			fprintf(stderr, "error opening %s\n", optarg);
			exit(EXIT_FAILURE);
			}
		break;

		case 'a':
		if((fhascii = fopen(optarg, "a")) == NULL)
			{
			fprintf(stderr, "error opening %s\n", optarg);
			exit(EXIT_FAILURE);
			}
		break;

		case 'A':
		if((fhasciipw = fopen(optarg, "a")) == NULL)
			{
			fprintf(stderr, "error opening %s\n", optarg);
			exit(EXIT_FAILURE);
			}
		break;

		case 'c':
		if((fhcow = fopen(optarg, "w")) == NULL)
			{
			fprintf(stderr, "error opening %s\n", optarg);
			exit(EXIT_FAILURE);
			}
		break;

		case 'P':
		gplfc = atoi(optarg);
		break;

		case 'D':
		gdevc = atoi(optarg);
		break;

		case 'l':
		listdeviceinfo = true;
		break;

		case 'h':
		usage(eigenname);
		break;

		default:
		usage(eigenname);
		break;
		}
	}

if((essidname != NULL) && (pwname == NULL) && (fhpwlist == NULL) && (fhcombi == NULL) && (fhascii == NULL))
	{
	pipeflag = true;
	}

if(listdeviceinfo == true)
	{
	if(listdevices() != true)
		exit(EXIT_FAILURE);
	return EXIT_SUCCESS;
	}

if(initopencl(gplfc, gdevc) != true)
	{
	fprintf(stderr, "couldn't initialize devices\n");
	exit(EXIT_FAILURE);
	}


if((essidname != NULL) && (pwname != NULL))
	{
	singlepmkout(pwname, pwlen);
	return EXIT_SUCCESS;
	}

else if((essidname != NULL) && (fhpwlist != NULL))
	{
	processpasswords(fhpwlist);
	}

else if(fhcombi != NULL)
	{
	filecombiout(fhcombi);
	}

else if((essidname != NULL) && (pwname == NULL) && (fhpwlist == NULL) && (fhcombi == NULL) && (fhascii == NULL))
	{
	fhascii = stdout;
	fhpwlist = stdin;
	processpasswords(fhpwlist);
	}

if(devices != NULL)
	free(devices);

if(platforms != NULL)
free(platforms);

if(fhcombi != NULL)
	fclose(fhcombi);

if(fhpwlist != NULL)
	fclose(fhpwlist);

if(fhascii != NULL)
	fclose(fhascii);

return EXIT_SUCCESS;
}
