#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <net/netmap_user.h>
#define LIBNETMAP_NOTHREADSAFE
#include "libnetmap.h"

static struct nmport_d *
nmport_new_with_ctx(struct nmctx *ctx)
{
	struct nmport_d *d;

	/* allocate a descriptor */
	d = nmctx_malloc(ctx, sizeof(*d));
	if (d == NULL) {
		nmctx_ferror(ctx, "cannot allocate nmport descriptor");
		goto out;
	}
	memset(d, 0, sizeof(*d));
	d->ctx = ctx;
	d->fd = -1;

out:
	return d;
}

struct nmport_d *
nmport_new(void)
{
	struct nmctx *ctx = nmctx_get();
	return nmport_new_with_ctx(ctx);
}


void
nmport_delete(struct nmport_d *d)
{
	nmctx_free(d->ctx, d);
}

int
nmport_extmem_from_file(struct nmport_d *d, const char *fname)
{
	struct nmctx *ctx = d->ctx;
	int fd = -1;
	off_t mapsize;
	void *p;

	fd = open(fname, O_RDWR);
	if (fd < 0) {
		nmctx_ferror(ctx, "cannot open '%s': %s", fname, strerror(errno));
		goto fail;
	}
	mapsize = lseek(fd, 0, SEEK_END);
	if (mapsize < 0) {
		nmctx_ferror(ctx, "failed to obtain filesize of '%s': %s", fname, strerror(errno));
		goto fail;
	}
	p = mmap(0, mapsize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED) {
		nmctx_ferror(ctx, "cannot mmap '%s': %s", fname, strerror(errno));
		goto fail;
	}
	d->extmem = nmctx_malloc(ctx, sizeof(*d->extmem));
	if (d->extmem == NULL) {
		nmctx_ferror(ctx, "cannot allocate extmem option");
		errno = ENOMEM;
		goto fail;
	}
	memset(d->extmem, 0, sizeof(*d->extmem));
	d->extmem->nro_usrptr = (uintptr_t)p;
	d->extmem->nro_opt.nro_reqtype = NETMAP_REQ_OPT_EXTMEM;
	d->extmem->nro_info.nr_memsize = mapsize;
	nmreq_push_option(&d->hdr, &d->extmem->nro_opt);

	close(fd);

	return 0;

fail:
	if (fd >= 0)
		close(fd);
	nmport_undo_extmem(d);
	return -1;
}

void
nmport_undo_extmem(struct nmport_d *d)
{
	void *p;

	if (d->extmem == NULL)
		return;

	p = (void *)d->extmem->nro_usrptr;
	if (p != MAP_FAILED)
		munmap(p, d->extmem->nro_info.nr_memsize);
	nmreq_remove_option(&d->hdr, &d->extmem->nro_opt);
	nmctx_free(d->ctx, d->extmem);
	d->extmem = NULL;
}

static int
nmport_share_parser(struct nmreq_parse_ctx *pctx)
{
	struct nmctx *ctx = pctx->ctx;
	struct nmport_d *d = pctx->token;
	int32_t mem_id;
	const char *v = pctx->keys[0];

	mem_id = nmreq_get_mem_id(&v, ctx);
	if (mem_id < 0)
		return -1;
	if (d->reg.nr_mem_id && d->reg.nr_mem_id != mem_id) {
		nmctx_ferror(ctx, "cannot set mem_id to %"PRId32", already set to %"PRIu16"",
				mem_id, d->reg.nr_mem_id);
		errno = EINVAL;
		return -1;
	}
	d->reg.nr_mem_id = mem_id;
	return 0;
}

static int
nmport_extmem_parser(struct nmreq_parse_ctx *pctx)
{
	struct nmport_d *d;
	struct nmreq_pools_info *pi;
	int i;

	d = pctx->token;

	if (nmport_extmem_from_file(d, pctx->keys[0]) < 0)
		return -1;

	pi = &d->extmem->nro_info;

	for  (i = 1; i < 7; i++) {
		const char *k = pctx->keys[i];
		uint32_t v;

		if (k == NULL)
			continue;

		v = atoi(k);
		switch (i) {
		case 1:
			pi->nr_if_pool_objtotal = v;
			break;
		case 2:
			pi->nr_if_pool_objsize = v;
			break;
		case 3:
			pi->nr_ring_pool_objtotal = v;
			break;
		case 4:
			pi->nr_ring_pool_objsize = v;
			break;
		case 5:
			pi->nr_buf_pool_objtotal = v;
			break;
		case 6:
			pi->nr_buf_pool_objsize = v;
			break;
		}
	}
	return 0;
}

static int
nmport_conf_parser(struct nmreq_parse_ctx *pctx)
{
	struct nmport_d *d;
	struct nmctx *ctx;

	d = pctx->token;
	ctx = d->ctx;

	if (pctx->keys[0] != NULL) {
		uint16_t nr_rings = atoi(pctx->keys[0]);
		d->reg.nr_tx_rings = nr_rings;
		d->reg.nr_rx_rings = nr_rings;
	}
	if (pctx->keys[1] != NULL) {
		uint32_t nr_slots = atoi(pctx->keys[1]);
		d->reg.nr_tx_slots = nr_slots;
		d->reg.nr_rx_slots = nr_slots;
	}
	if (pctx->keys[2] != NULL) {
		d->reg.nr_tx_rings = atoi(pctx->keys[2]);
	}
	if (pctx->keys[3] != NULL) {
		d->reg.nr_tx_rings = atoi(pctx->keys[3]);
	}
	if (pctx->keys[4] != NULL) {
		d->reg.nr_tx_slots = atoi(pctx->keys[4]);
	}
	if (pctx->keys[5] != NULL) {
		d->reg.nr_tx_slots = atoi(pctx->keys[5]);
	}
}

static struct nmreq_opt_parser nmport_opt_parsers[] = {
	{
		.prefix = "share",
		.parse  = nmport_share_parser,
	},
	{
		.prefix = "extmem",
		.parse = nmport_extmem_parser,
		.default_key = 0, /* the "file" key */
		.flags = 0,
		.keys = {
			{ "file",	0, 	NMREQ_OPTK_NODEFAULT },
			{ "if-num",	1 },
			{ "if-size",	2 },
			{ "ring-num",   3 },
			{ "ring-size",  4 },
			{ "buf-num",    5 },
			{ "buf-size",   6 }
		}
	},
	{
		.prefix = "conf",
		.parse = nmport_conf_parser,
		.default_key = -1,
		.flags = 0,
		.keys = {
			{ "rings",    0 }, /* both tx and rx */
			{ "slots",    1 }, /*      ""        */
			{ "tx-rings", 2 },
			{ "rx-rings", 3 },
			{ "tx-slots", 4 },
			{ "rx-slots", 5 }
		}
	}
};

static int nmport_opt_parsers_n =
	sizeof(nmport_opt_parsers) / sizeof(nmport_opt_parsers[0]);

int
nmport_parse(struct nmport_d *d, const char *ifname)
{
	const char *scan = ifname;

	if (nmreq_header_decode(&scan, &d->hdr, d->ctx) < 0) {
		goto err;
	}

	/* specialize the header */
	d->hdr.nr_reqtype = NETMAP_REQ_REGISTER;
	d->hdr.nr_body = (uintptr_t)&d->reg;

	/* parse the register request */
	if (nmreq_register_decode(&scan, &d->reg, d->ctx) < 0) {
		goto err;
	}

	/* parse the options, if any */
	if (nmreq_options_decode(scan, nmport_opt_parsers,
				nmport_opt_parsers_n, d, d->ctx) < 0) {
		goto err;
	}
	return 0;

err:
	nmport_undo_parse(d);
	return -1;
}

void
nmport_undo_parse(struct nmport_d *d)
{
	nmport_undo_extmem(d);
	memset(&d->reg, 0, sizeof(d->reg));
	memset(&d->hdr, 0, sizeof(d->hdr));
}

struct nmport_d *
nmport_prepare(const char *ifname)
{
	struct nmport_d *d;

	/* allocate a descriptor */
	d = nmport_new();
	if (d == NULL)
		goto err;

	/* parse the header */
	if (nmport_parse(d, ifname) < 0)
		goto err;

	return d;

err:
	nmport_undo_prepare(d);
	return NULL;
}

void
nmport_undo_prepare(struct nmport_d *d)
{
	if (d == NULL)
		return;
	nmport_undo_parse(d);
	nmport_delete(d);
}

int
nmport_register(struct nmport_d *d)
{
	struct nmctx *ctx = d->ctx;

	if (d->register_done) {
		errno = EINVAL;
		nmctx_ferror(ctx, "%s: already registered", d->hdr.nr_name);
		goto err;
	}

	d->fd = open("/dev/netmap", O_RDWR);
	if (d->fd < 0) {
		nmctx_ferror(ctx, "/dev/netmap: %s", strerror(errno));
		goto err;
	}

	if (ioctl(d->fd, NIOCCTRL, &d->hdr) < 0) {
		nmctx_ferror(ctx, "%s: %s", d->hdr.nr_name, strerror(errno));
		if (d->extmem != NULL && d->extmem->nro_opt.nro_status) {
			nmctx_ferror(ctx, "failed to allocate extmem: %s",
					strerror(d->extmem->nro_opt.nro_status));
		}
		goto err;
	}

	d->register_done = 1;

	return 0;

err:
	nmport_undo_register(d);
	return -1;
}

void
nmport_undo_register(struct nmport_d *d)
{
	if (d->fd >= 0)
		close(d->fd);
	d->fd = -1;
	d->register_done = 0;
}

/* lookup the mem_id in the mem-list: do a new mmap() if
 * not found, reuse existing otherwise
 */
int
nmport_mmap(struct nmport_d *d)
{
	struct nmctx *ctx = d->ctx;
	struct nmem_d *m = NULL;
	u_int num_tx, num_rx;
	int i;

	if (d->mmap_done) {
		errno = EINVAL;
		nmctx_ferror(ctx, "%s: already mapped", d->hdr.nr_name);
		return -1;
	}

	if (!d->register_done) {
		errno = EINVAL;
		nmctx_ferror(ctx, "cannot map unregistered port");
		return -1;
	}

	nmctx_lock(ctx);

	for (m = ctx->mem_descs; m != NULL; m = m->next)
		if (m->mem_id == d->reg.nr_mem_id)
			break;

	if (m == NULL) {
		m = nmctx_malloc(ctx, sizeof(*m));
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
					MAP_SHARED, d->fd, 0);
			if (m->mem == MAP_FAILED) {
				nmctx_ferror(ctx, "mmap: %s", strerror(errno));
				goto err;
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

	nmctx_unlock(ctx);

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

err:
	nmctx_unlock(ctx);
	nmport_undo_mmap(d);
	return -1;
}

void
nmport_undo_mmap(struct nmport_d *d)
{
	struct nmem_d *m;
	struct nmctx *ctx = d->ctx;

	m = d->mem;
	if (m == NULL)
		return;
	nmctx_lock(ctx);
	m->refcount--;
	if (m->refcount <= 0) {
		if (!m->is_extmem && m->mem != MAP_FAILED)
			munmap(m->mem, m->size);
		/* extract from the list and free */
		if (m->next != NULL)
			m->next->prev = m->prev;
		if (m->prev != NULL)
			m->prev->next = m->next;
		else
			ctx->mem_descs = m->next;
		nmctx_free(ctx, m);
		d->mem = NULL;
	}
	nmctx_unlock(ctx);
	d->mmap_done = 0;
	d->mem == NULL;
	d->nifp = NULL;
	d->first_tx_ring = 0;
	d->last_tx_ring = 0;
	d->first_rx_ring = 0;
	d->last_rx_ring = 0;
	d->cur_tx_ring = 0;
	d->cur_rx_ring = 0;
}

int
nmport_open_desc(struct nmport_d *d)
{
	if (nmport_register(d) < 0)
		goto err;

	if (nmport_mmap(d) < 0)
		goto err;

	return 0;
err:
	nmport_undo_open_desc(d);
	return -1;
}

void
nmport_undo_open_desc(struct nmport_d *d)
{
	nmport_undo_mmap(d);
	nmport_undo_register(d);
}


struct nmport_d *
nmport_open(const char *ifname)
{
	struct nmport_d *d;

	/* prepare the descriptor */
	d = nmport_prepare(ifname);
	if (d == NULL)
		goto err;

	/* open netmap and register */
	if (nmport_open_desc(d) < 0)
		goto err;

	return d;

err:
	nmport_close(d);
	return NULL;
}

void
nmport_close(struct nmport_d *d)
{
	if (d == NULL)
		return;
	nmport_undo_open_desc(d);
	nmport_undo_prepare(d);
}

struct nmport_d *
nmport_clone(struct nmport_d *d)
{
	struct nmport_d *c;
	struct nmctx *ctx;

	ctx = d->ctx;

	if (d->extmem != NULL && !d->register_done) {
		errno = EINVAL;
		nmctx_ferror(ctx, "cannot clone unregistered port that is using extmem");
		return NULL;
	}

	c = nmport_new_with_ctx(ctx);
	if (c == NULL)
		return NULL;
	/* copy the output of parse */
	c->hdr = d->hdr;
	/* redirect the pointer to the body */
	c->hdr.nr_body = (uintptr_t)&c->reg;
	/* options are not cloned */
	c->hdr.nr_options = 0;
	c->reg = d->reg; /* this also copies the mem_id */
	/* put the new port in an un-registered, unmapped state */
	c->fd = -1;
	c->nifp = NULL;
	c->register_done = 0;
	c->mem = NULL;
	c->extmem = NULL;
	c->mmap_done = 0;
	c->first_tx_ring = 0;
	c->last_tx_ring = 0;
	c->first_rx_ring = 0;
	c->last_rx_ring = 0;
	c->cur_tx_ring = 0;
	c->cur_rx_ring = 0;

	return c;
}

int
nmport_inject(struct nmport_d *d, const void *buf, size_t size)
{
	u_int c, n = d->last_tx_ring - d->first_tx_ring + 1,
		ri = d->cur_tx_ring;

	for (c = 0; c < n ; c++, ri++) {
		/* compute current ring to use */
		struct netmap_ring *ring;
		uint32_t i, j, idx;
		size_t rem;

		if (ri > d->last_tx_ring)
			ri = d->first_tx_ring;
		ring = NETMAP_TXRING(d->nifp, ri);
		rem = size;
		j = ring->cur;
		while (rem > ring->nr_buf_size && j != ring->tail) {
			rem -= ring->nr_buf_size;
			j = nm_ring_next(ring, j);
		}
		if (j == ring->tail && rem > 0)
			continue;
		i = ring->cur;
		while (i != j) {
			idx = ring->slot[i].buf_idx;
			ring->slot[i].len = ring->nr_buf_size;
			ring->slot[i].flags = NS_MOREFRAG;
			nm_pkt_copy(buf, NETMAP_BUF(ring, idx), ring->nr_buf_size);
			i = nm_ring_next(ring, i);
			buf = (char *)buf + ring->nr_buf_size;
		}
		idx = ring->slot[i].buf_idx;
		ring->slot[i].len = rem;
		ring->slot[i].flags = 0;
		nm_pkt_copy(buf, NETMAP_BUF(ring, idx), rem);
		ring->head = ring->cur = nm_ring_next(ring, i);
		d->cur_tx_ring = ri;
		return size;
	}
	return 0; /* fail */
}
