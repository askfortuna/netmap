#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <net/netmap_user.h>
#include "libnetmap.h"

static void
nmctx_error_stderr(struct nmctx *ctx, const char *errmsg)
{
	if (ctx->verbose > 0)
		fprintf(stderr, "%s\n", errmsg);
}

void
nmctx_init(struct nmctx *ctx)
{
	ctx->netmap_fd = -1;
	ctx->nopen = 0;
	ctx->error = nmctx_error_stderr;
	ctx->get = NULL;
	ctx->put = NULL;
}

static struct nmctx nmctx_global = {
	.netmap_fd = -1,
	.nopen = 0,
	.verbose = 1,
	.error = nmctx_error_stderr,
};

struct nmctx *
nmctx_get(void)
{
	struct nmctx *ctx = &nmctx_global;
	if (ctx->get != NULL)
		ctx->get(ctx);
	return ctx;
}

void
nmctx_put(struct nmctx *ctx)
{
	if (ctx != NULL && ctx->put != NULL)
		ctx->put(ctx);
}

int
nmctx_getfd(struct nmctx *ctx)
{
	int fd;

	if (!ctx->nopen) {
		ctx->netmap_fd = open("/dev/netmap", O_RDONLY);
	}
	fd = ctx->netmap_fd;
	if (fd >= 0)
		ctx->nopen++;

	return fd;
}

void
nmctx_putfd(struct nmctx *ctx)
{
	ctx->nopen--;
	if (ctx->nopen == 0) {
		close(ctx->netmap_fd);
		ctx->netmap_fd = -1;
	}
}

#define MAXERRMSG 1000
void
nmctx_ferror(struct nmctx *ctx, const char *fmt, ...)
{
	char errmsg[MAXERRMSG];
	va_list ap;
	int rv;

	va_start(ap, fmt);
	rv = vsnprintf(errmsg, MAXERRMSG, fmt, ap);
	va_end(ap);

	if (rv > 0) {
		if (rv < MAXERRMSG) {
			ctx->error(ctx, errmsg);
		} else {
			ctx->error(ctx, "error message too long");
		}
	} else {
		ctx->error(ctx, "internal error");
	}
}
