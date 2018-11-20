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

struct nmport_d *
nmport_new(struct nmctx *ctx)
{
	struct nmport_d *d = NULL;

	/* allocate a descriptor */
	d = malloc(sizeof(*d));
	if (d == NULL) {
		nmctx_ferror(ctx, "cannot allocate nmreq descriptor");
		goto out;
	}
	memset(d, 0, sizeof(*d));

out:
	return d;
}

void
nmport_delete(struct nmport_d *d, struct nmctx *ctx)
{
	free(d);
}

int
nmport_parse(struct nmport_d *d, const char *ifname, struct nmctx *ctx)
{
	const char *scan = ifname;

	if (nmreq_header_decode(&scan, &d->hdr, ctx) < 0) {
		goto err;
	}

	/* specialize the header */
	d->hdr.nr_reqtype = NETMAP_REQ_REGISTER;
	d->hdr.nr_body = (uintptr_t)&d->reg;

	/* parse the register request */
	if (nmreq_register_decode(&scan, &d->reg, ctx) < 0) {
		goto err;
	}

	/* parse the options, if any */
	while (*scan) {
		const char optc = *scan++;
		switch (optc) {
		case '@': {
			struct nmreq_opt_extmem *e;
			/* we only understand the extmem option for now */
			e = malloc(sizeof(*e));
			if (e == NULL) {
				nmctx_ferror(ctx, "cannot allocate extmem option");
				goto err;
			}
			memset(e, 0, sizeof(*e));
			nmreq_push_option(&d->hdr, &e->nro_opt);
			if (nmreq_opt_extmem_decode(&scan, e, ctx) < 0) {
				goto err_free_opts;
			}
			break;
		}

		default:
			nmctx_ferror(ctx, "unexpected characters: '%c%s'", optc, scan);
			goto err_free_opts;
		}
	}

	return 0;

err_free_opts:
	nmreq_free_options(&d->hdr);
err:
	return -1;
}

int
nmport_register(struct nmport_d *d, struct nmctx *ctx)
{
	if (d->register_done) {
		errno = EINVAL;
		nmctx_ferror(ctx, "%s: already registered", d->hdr.nr_name);
		goto err;
	}

	d->netmap_fd = open("/dev/netmap", O_RDWR);
	if (d->netmap_fd < 0) {
		nmctx_ferror(ctx, "/dev/netmap: %s", strerror(errno));
		goto err;
	}

	if (ioctl(d->netmap_fd, NIOCCTRL, &d->hdr) < 0) {
		nmctx_ferror(ctx, "%s: %s", d->hdr.nr_name, strerror(errno));
		goto err_close;
	}

	d->extmem =(struct nmreq_opt_extmem *)nmreq_find_option(&d->hdr,
			NETMAP_REQ_OPT_EXTMEM);
	if (d->extmem != NULL && d->extmem->nro_opt.nro_status)
		d->extmem = NULL;
	d->register_done = 1;

	return 0;

err_close:
	close(d->netmap_fd);
err:
	return -1;
}

int
nmport_mmap(struct nmport_d *d, struct nmctx *ctx)
{
	struct nmem_d *m = NULL;
	u_int num_tx, num_rx;
	int i;

	if (d->mmap_done) {
		errno = EINVAL;
		nmctx_ferror(ctx, "%s: already mapped", d->hdr.nr_name);
		goto err;
	}

	if (!d->register_done) {
		errno = EINVAL;
		nmctx_ferror(ctx, "cannot map unregistered port");
		goto err;
	}

	// lock

	for (m = ctx->mem_descs; m != NULL; m = m->next)
		if (m->mem_id == d->reg.nr_mem_id)
			break;

	if (m == NULL) {
		m = malloc(sizeof(*m));
		if (m == NULL) {
			nmctx_ferror(ctx, "cannot allocate memory descriptor");
			goto err;
		}
		memset(m, 0, sizeof(*m));
		if (d->extmem != NULL) {
			m->mem = (void *)d->extmem->nro_usrptr;
			m->size = d->extmem->nro_info.nr_memsize;
			m->is_extmem = 1;
		} else {
			m->mem = mmap(NULL, d->reg.nr_memsize, PROT_READ|PROT_WRITE,
					MAP_SHARED, d->netmap_fd, 0);
			if (m->mem == MAP_FAILED) {
				nmctx_ferror(ctx, "mmap: %s", strerror(errno));
				goto err_free;
			}
			m->size = d->reg.nr_memsize;
		}
		m->mem_id = d->reg.nr_mem_id;
		m->next = ctx->mem_descs;
		if (ctx->mem_descs != NULL)
			ctx->mem_descs->prev = m;
		ctx->mem_descs = m;
	}
	m->refcount++;

	// unlock

	d->mem = m;

	d->nifp = NETMAP_IF(m->mem, d->reg.nr_offset);

	num_tx = d->reg.nr_tx_rings + 1; /* XXX fix for multiple host rings */
	for (i = 0; i < num_tx && !d->nifp->ring_ofs[i]; i++)
		;
	d->first_tx_ring = i;
	for ( ; i < num_tx && d->nifp->ring_ofs[i]; i++)
		;
	d->last_tx_ring = i - 1;
	for (i = 0; i < num_tx && !d->nifp->ring_ofs[i + num_tx]; i++)
		;
	d->first_rx_ring = i;
	num_rx = d->reg.nr_rx_rings + 1; /* XXX fix for multiple host rings */
	for ( ; i < num_rx && d->nifp->ring_ofs[i + num_tx]; i++)
		;
	d->last_rx_ring = i - 1;

	d->mmap_done = 1;

	return 0;

err_free:
	// unlock
	free(m);
err:
	return -1;
}


struct nmport_d *
nmport_open(const char *ifname)
{
	struct nmport_d *d = NULL;
	struct nmctx *ctx;

	ctx = nmctx_get();

	/* allocate a descriptor */
	d = nmport_new(ctx);
	if (d == NULL)
		goto err;

	/* parse the header */
	if (nmport_parse(d, ifname, ctx) < 0)
		goto err;

	/* open netmap and register */
	if (nmport_register(d, ctx) < 0)
		goto err;

	/* lookup the mem_id in the mem-list: do a new mmap() if
	 * not found, reuse existing otherwise
	 */
	if (nmport_mmap(d, ctx) < 0)
		goto err;

	nmctx_put(ctx);
	return d;

err:
	nmctx_put(ctx);
	if (d != NULL)
		nmport_close(d);
	return NULL;
}

void
nmport_close(struct nmport_d *d)
{
	struct nmem_d *m;
	struct nmctx *ctx;

	ctx = nmctx_get();

	if (d->mmap_done) {
		m = d->mem;
		// lock
		m->refcount--;
		if (m->refcount <= 0) {
			if (!m->is_extmem)
				munmap(m->mem, m->size);
			/* extract from the list and free */
			if (m->next != NULL)
				m->next->prev = m->prev;
			if (m->prev != NULL)
				m->prev->next = m->next;
			else
				ctx->mem_descs = m->next;
			free(m);
		}
		// unlock
	}

	if (d->register_done)
		close(d->netmap_fd);
	nmreq_free_options(&d->hdr);
	free(d);

	nmctx_put(ctx);
}
