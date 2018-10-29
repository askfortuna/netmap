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

#ifdef NMREQ_DEBUG
#define ED(...)	D(__VA_ARGS__)
#else
#define ED(...)
#endif /* NMREQ_DEBUG */

struct nmreq_ctx;
struct nmreq_open_d;
struct nmreq_mem_d;

typedef void (*nmreq_ctx_error_cb)(struct nmreq_ctx *, const char *);

struct nmreq_ctx {
	int netmap_fd;
	int nopen;

	int verbose;
	nmreq_ctx_error_cb error;

	void (*get)(struct nmreq_ctx *);
	void (*put)(struct nmreq_ctx *);

	struct nmreq_mem_d  *mem_descs;
};

struct nmreq_mem_d {
	uint16_t mem_id;
	int refcount;
	void *mem;
	size_t size;

	struct nmreq_mem_d *next;
	struct nmreq_mem_d *prev;
};

struct nmreq_open_d {
	struct nmreq_ctx *ctx;
	struct nmreq_header hdr;
	struct nmreq_register reg;
	struct nmreq_option *opts;

	struct nmreq_open_d *next;
	struct nmreq_open_d *prev;

	int netmap_fd;
	struct nmreq_mem_d *mem;
};

static void
nmreq_ctx_error_stderr(struct nmreq_ctx *ctx, const char *errmsg)
{
	if (ctx->verbose > 0)
		fprintf(stderr, "%s\n", errmsg);
}

void
nmreq_ctx_init(struct nmreq_ctx *ctx)
{
	ctx->netmap_fd = -1;
	ctx->nopen = 0;
	ctx->error = nmreq_ctx_error_stderr;
	ctx->get = NULL;
	ctx->put = NULL;
}

static struct nmreq_ctx nmreq_ctx_global = {
	.netmap_fd = -1,
	.nopen = 0,
	.verbose = 1,
	.error = nmreq_ctx_error_stderr,
};

struct nmreq_ctx *
nmreq_ctx_get(struct nmreq_ctx *ctx)
{
	ctx = (ctx == NULL ? &nmreq_ctx_global : ctx);
	if (ctx->get != NULL)
		ctx->get(ctx);
	return ctx;
}

void
nmreq_ctx_put(struct nmreq_ctx *ctx)
{
	if (ctx != NULL && ctx->put != NULL)
		ctx->put(ctx);
}

int
nmreq_ctx_getfd(struct nmreq_ctx *ctx)
{
	int fd;

	ctx = nmreq_ctx_get(ctx);

	if (!ctx->nopen) {
		ctx->netmap_fd = open("/dev/netmap", O_RDONLY);
	}
	fd = ctx->netmap_fd;
	if (fd >= 0)
		ctx->nopen++;

	nmreq_ctx_put(ctx);

	return fd;
}

void
nmreq_ctx_putfd(struct nmreq_ctx *ctx)
{
	ctx = nmreq_ctx_get(ctx);

	ctx->nopen--;
	if (ctx->nopen == 0) {
		close(ctx->netmap_fd);
		ctx->netmap_fd = -1;
	}

	nmreq_ctx_put(ctx);
}

/* an identifier is a possibly empty sequence of alphanum characters and
 * underscores
 */
static int
nm_is_identifier(const char *s, const char *e)
{
	for (; s != e; s++) {
		if (!isalnum(*s) && *s != '_') {
			return 0;
		}
	}

	return 1;
}

#define MAXERRMSG 1000
static void
nmreq_ferror(struct nmreq_ctx *ctx, const char *fmt, ...)
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

void
nmreq_push_option(struct nmreq_header *h, struct nmreq_option *o)
{
	o->nro_next = h->nr_options;
	h->nr_options = (uintptr_t)o;
}

int
nmreq_header_decode(const char **pifname, struct nmreq_header *h, struct nmreq_ctx *ctx)
{
	int is_vale;
	const char *scan = NULL;
	const char *vpname = NULL;
	const char *pipesep = NULL;
	u_int namelen;
	static size_t NM_BDG_NAMSZ = strlen(NM_BDG_NAME);
	const char *ifname = *pifname;

	ctx = nmreq_ctx_get(ctx);

	if (strncmp(ifname, "netmap:", 7) &&
			strncmp(ifname, NM_BDG_NAME, NM_BDG_NAMSZ)) {
		nmreq_ferror(ctx, "invalid request '%s' (must begin with 'netmap:' or '" NM_BDG_NAME "')", ifname);
		goto fail;
	}

	is_vale = (ifname[0] == 'v');
	if (is_vale) {
		scan = index(ifname, ':');
		if (scan == NULL) {
			nmreq_ferror(ctx, "missing ':' in VALE name '%s'", ifname);
			goto fail;
		}

		if (!nm_is_identifier(ifname + NM_BDG_NAMSZ, scan)) {
			nmreq_ferror(ctx, "invalid VALE bridge name '%.*s'",
					(scan - ifname - NM_BDG_NAMSZ), ifname + NM_BDG_NAMSZ);
			goto fail;
		}

		vpname = ++scan;
	} else {
		ifname += 7;
		scan = ifname;
		vpname = ifname;
	}

	/* scan for a separator */
	for (; *scan && !index("-*^/@", *scan); scan++)
		;

	/* search for possible pipe indicators */
	for (pipesep = vpname; pipesep != scan && !index("{}", *pipesep); pipesep++)
		;

	if (!nm_is_identifier(vpname, pipesep)) {
		nmreq_ferror(ctx, "invalid %sport name '%.*s'", (is_vale ? "VALE " : ""),
				pipesep - vpname, vpname);
		goto fail;
	}
	if (pipesep != scan) {
		pipesep++;
		if (!nm_is_identifier(pipesep, scan)) {
			nmreq_ferror(ctx, "invalid pipe name '%.*s'", scan - pipesep, pipesep);
			goto fail;
		}
	}

	namelen = scan - ifname;
	if (namelen >= sizeof(h->nr_name)) {
		nmreq_ferror(ctx, "name '%.*s' too long", namelen, ifname);
		goto fail;
	}

	/* fill the header */
	memset(h, 0, sizeof(*h));
	h->nr_version = NETMAP_API;
	memcpy(h->nr_name, ifname, namelen);
	h->nr_name[namelen] = '\0';
	ED("name %s", h->nr_name);

	*pifname = scan;

	nmreq_ctx_put(ctx);

	return 0;
fail:
	errno = EINVAL;
	nmreq_ctx_put(ctx);
	return -1;
}


/*
 * 0 not recognized
 * -1 error
 *  >= 0 mem_id
 */
int
nmreq_get_mem_id(const char **pifname, struct nmreq_ctx *ctx)
{
	int fd = -1;
	struct nmreq_header gh;
	struct nmreq_port_info_get gb;
	const char *ifname;
	int error = -1;
	int old_verbose;

	errno = 0;
	ifname = *pifname;

	ctx = nmreq_ctx_get(ctx);

	if (ifname == NULL)
		goto fail;

	/* try to look for a netmap port with this name */
	fd = nmreq_ctx_getfd(ctx);
	if (fd < 0) {
		nmreq_ferror(ctx, "cannot open /dev/netmap: %s", strerror(errno));
		goto fail;
	}
	old_verbose = ctx->verbose;
	ctx->verbose = 0; /* silence errors */
	if (nmreq_header_decode(&ifname, &gh, ctx) < 0) {
		error = 0; /* not recognized */
		goto fail;
	}
	ctx->verbose = old_verbose;
	gh.nr_reqtype = NETMAP_REQ_PORT_INFO_GET;
	memset(&gb, 0, sizeof(gb));
	gh.nr_body = (uintptr_t)&gb;
	if (ioctl(fd, NIOCCTRL, &gh) < 0) {
		if (errno == ENOENT || errno == ENXIO) {
			error = 0;
			goto fail;
		}
		nmreq_ferror(ctx, "cannot get info for '%s': %s", ifname, strerror(errno));
		goto fail;
	}
	*pifname = ifname;
	nmreq_ctx_putfd(ctx);
	nmreq_ctx_put(ctx);
	return gb.nr_mem_id;

fail:
	if (fd >= 0)
		nmreq_ctx_putfd(ctx);
	if (!errno)
		errno = EINVAL;
	ctx->verbose = old_verbose;
	nmreq_ctx_put(ctx);
	return error;
}


int
nmreq_opt_extmem_decode(const char **spec, struct nmreq_opt_extmem *e, struct nmreq_ctx *ctx)
{
	int fd;
	off_t mapsize;
	void *p;
	const char *mem_id = *spec;

	ctx = nmreq_ctx_get(ctx);

	ED("trying with external memory");
	fd = open(mem_id, O_RDWR);
	if (fd < 0) {
		nmreq_ferror(ctx, "cannot open '%s': %s", mem_id, strerror(errno));
		goto fail;
	}
	mapsize = lseek(fd, 0, SEEK_END);
	if (mapsize < 0) {
		nmreq_ferror(ctx, "failed to obtain filesize of '%s': %s", mem_id, strerror(errno));
		goto fail;
	}
	p = mmap(0, mapsize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED) {
		nmreq_ferror(ctx, "cannot mmap '%s': %s", mem_id, strerror(errno));
		goto fail;
	}
	memset(e, 0, sizeof(*e));
	e->nro_opt.nro_reqtype = NETMAP_REQ_OPT_EXTMEM;
	e->nro_usrptr = (uintptr_t)p;
	e->nro_info.nr_memsize = mapsize;
	ED("mapped %zu bytes at %p from file %s", mapsize, pi, mem_id);
	*spec = mem_id + strlen(mem_id);
	nmreq_ctx_put(ctx);
	return 0;
fail:
	if (fd > 0)
		close(fd);
	nmreq_ctx_put(ctx);
	return -1;
}

int
nmreq_register_decode(const char **pifname, struct nmreq_register *r, struct nmreq_ctx *ctx)
{
	enum { P_START, P_RNGSFXOK, P_GETNUM, P_FLAGS, P_FLAGSOK, P_MEMID } p_state;
	long num;
	const char *scan = *pifname;
	int memid_allowed = 1;

	ctx = nmreq_ctx_get(ctx);

	/* fill the request */
	memset(r, 0, sizeof(*r));

	p_state = P_START;
	r->nr_mode = NR_REG_ALL_NIC; /* default for no suffix */
	while (*scan) {
		switch (p_state) {
		case P_START:
			switch (*scan) {
			case '^': /* only SW ring */
				r->nr_mode = NR_REG_SW;
				p_state = P_RNGSFXOK;
				break;
			case '*': /* NIC and SW */
				r->nr_mode = NR_REG_NIC_SW;
				p_state = P_RNGSFXOK;
				break;
			case '-': /* one NIC ring pair */
				r->nr_mode = NR_REG_ONE_NIC;
				p_state = P_GETNUM;
				break;
			case '/': /* start of flags */
				p_state = P_FLAGS;
				break;
			case '@': /* start of memid */
				p_state = P_MEMID;
				break;
			default:
				nmreq_ferror(ctx, "unknown modifier: '%c'", *scan);
				goto fail;
			}
			scan++;
			break;
		case P_RNGSFXOK:
			switch (*scan) {
			case '/':
				p_state = P_FLAGS;
				break;
			case '@':
				p_state = P_MEMID;
				break;
			default:
				nmreq_ferror(ctx, "unexpected character: '%c'", *scan);
				goto fail;
			}
			scan++;
			break;
		case P_GETNUM:
			if (!isdigit(*scan)) {
				nmreq_ferror(ctx, "got '%s' while expecting a number", scan);
				goto fail;
			}
			num = strtol(scan, (char **)&scan, 10);
			if (num < 0 || num >= NETMAP_RING_MASK) {
				nmreq_ferror(ctx, "'%ld' out of range [0, %d)",
						num, NETMAP_RING_MASK);
				goto fail;
			}
			r->nr_ringid = num & NETMAP_RING_MASK;
			p_state = P_RNGSFXOK;
			break;
		case P_FLAGS:
		case P_FLAGSOK:
			if (*scan == '@') {
				scan++;
				p_state = P_MEMID;
				break;
			}
			switch (*scan) {
			case 'x':
				r->nr_flags |= NR_EXCLUSIVE;
				break;
			case 'z':
				r->nr_flags |= NR_ZCOPY_MON;
				break;
			case 't':
				r->nr_flags |= NR_MONITOR_TX;
				break;
			case 'r':
				r->nr_flags |= NR_MONITOR_RX;
				break;
			case 'R':
				r->nr_flags |= NR_RX_RINGS_ONLY;
				break;
			case 'T':
				r->nr_flags |= NR_TX_RINGS_ONLY;
				break;
			default:
				nmreq_ferror(ctx, "unrecognized flag: '%c'", *scan);
				goto fail;
			}
			scan++;
			p_state = P_FLAGSOK;
			break;
		case P_MEMID:
			if (!memid_allowed) {
				nmreq_ferror(ctx, "double setting of mem_id");
				goto fail;
			}
			if (isdigit(*scan)) {
				num = strtol(scan, (char **)&scan, 10);
				r->nr_mem_id = num;
				memid_allowed = 0;
				p_state = P_RNGSFXOK;
			} else {
				ED("non-numeric mem_id '%s'", scan);
				num = nmreq_get_mem_id(&scan, ctx);
				switch (num) {
				case -1:
					goto fail;
				case 0:
					scan--;
					goto out;
				default:
					break;
				}
				if (*scan != '\0') {
					nmreq_ferror(ctx, "unexpected characters '%s' in mem_id spec", scan);
					goto fail;
				}
				r->nr_mem_id = num;
				goto out;
			}
			break;
		}
	}
	if (p_state != P_START && p_state != P_RNGSFXOK &&
	    p_state != P_FLAGSOK && p_state != P_MEMID) {
		nmreq_ferror(ctx, "unexpected end of request");
		goto fail;
	}
out:
	ED("flags: %s %s %s %s %s %s",
			(r->nr_flags & NR_EXCLUSIVE) ? "EXCLUSIVE" : "",
			(r->nr_flags & NR_ZCOPY_MON) ? "ZCOPY_MON" : "",
			(r->nr_flags & NR_MONITOR_TX) ? "MONITOR_TX" : "",
			(r->nr_flags & NR_MONITOR_RX) ? "MONITOR_RX" : "",
			(r->nr_flags & NR_RX_RINGS_ONLY) ? "RX_RINGS_ONLY" : "",
			(r->nr_flags & NR_TX_RINGS_ONLY) ? "TX_RINGS_ONLY" : "");
	*pifname = scan;
	nmreq_ctx_put(ctx);
	return 0;

fail:
	if (!errno)
		errno = EINVAL;
	nmreq_ctx_put(ctx);
	return -1;
}

static void
nmreq_free_options(struct nmreq_header *h)
{
	struct nmreq_option *o, *next;

	for (o = (struct nmreq_option *)h->nr_options; o != NULL; o = next)
	{
		next = (struct nmreq_option *)o->nro_next;
		free(o);
	}
}

struct nmreq_open_d *
nmreq_open(const char *ifname, struct nmreq_ctx *ctx)
{
	struct nmreq_open_d *d = NULL;
	const char *scan = ifname;
	struct nmreq_mem_d *m;

	ctx = nmreq_ctx_get(ctx);

	/* allocate a descriptor */
	d = malloc(sizeof(*d));
	if (d == NULL) {
		nmreq_ferror(ctx, "cannot allocate nmreq descriptor");
		goto err_put;
	}
	memset(d, 0, sizeof(*d));

	/* parse the header */
	if (nmreq_header_decode(&scan, &d->hdr, ctx) < 0) {
		goto err_free;
	}

	/* specialize the header */
	d->hdr.nr_reqtype = NETMAP_REQ_REGISTER;
	d->hdr.nr_body = (uintptr_t)&d->reg;

	/* parse the register request */
	if (nmreq_register_decode(&scan, &d->reg, ctx) < 0) {
		goto err_free;
	}

	/* parse the options, if any */
	while (*scan) {
		const char optc = *scan++;
		switch (optc) {
		case '@': {
			/* we only understand the extmem option for now */
			struct nmreq_opt_extmem *e;

			e = malloc(sizeof(*e));
			if (e == NULL) {
				nmreq_ferror(ctx, "cannot allocate extmem option");
				goto err_free;
			}
			memset(e, 0, sizeof(*e));
			nmreq_push_option(&d->hdr, &e->nro_opt);
			if (nmreq_opt_extmem_decode(&scan, e, NULL) < 0) {
				goto err_free_opts;
			}
			break;
		}

		default:
			nmreq_ferror(ctx, "unexpected characters: '%c%s'", optc, scan);
			goto err_free_opts;
		}
	}

	/* open netmap and register */
	d->netmap_fd = open("/dev/netmap", O_RDWR);
	if (d->netmap_fd < 0) {
		nmreq_ferror(ctx, "/dev/netmap: %s", strerror(errno));
		goto err_free_opts;
	}

	if (ioctl(d->netmap_fd, NIOCCTRL, &d->hdr) < 0) {
		nmreq_ferror(ctx, "%s: %s", ifname, strerror(errno));
		goto err_close;
	}

	/* lookup the mem_id in the mem-list: do a new mmap() if
	 * not found, reuse existing otherwise
	 */

	for (m = ctx->mem_descs; m != NULL; m = m->next)
		if (m->mem_id == d->reg.nr_mem_id)
			break;
	if (m == NULL) {
		m = malloc(sizeof(*m));
		if (m == NULL) {
			nmreq_ferror(ctx, "cannot allocate memory descriptor");
			goto err_close;
		}
		memset(m, 0, sizeof(*m));
		m->mem = mmap(NULL, d->reg.nr_memsize, PROT_READ|PROT_WRITE,
				MAP_SHARED, d->netmap_fd, 0);
		if (m->mem == MAP_FAILED) {
			nmreq_ferror(ctx, "mmap: %s", strerror(errno));
			goto err_free_mem;
		}
		m->mem_id = d->reg.nr_mem_id;
		m->size = d->reg.nr_memsize;
		m->next = ctx->mem_descs;
		if (ctx->mem_descs != NULL)
			ctx->mem_descs->prev = m;
		ctx->mem_descs = m;
	}
	m->refcount++;
	d->mem = m;

	nmreq_ctx_put(ctx);
	return d;

err_free_mem:
	free(m);
err_close:
	close(d->netmap_fd);
err_free_opts:
	nmreq_free_options(&d->hdr);
err_free:
	free(d);
err_put:
	nmreq_ctx_put(ctx);
	return NULL;
}

void
nmreq_close(struct nmreq_open_d *d, struct nmreq_ctx *ctx)
{
	struct nmreq_mem_d *m;

	ctx = nmreq_ctx_get(ctx);

	m = d->mem;
	m->refcount--;
	if (m->refcount <= 0) {
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

	close(d->netmap_fd);
	free(d);

	nmreq_ctx_put(ctx);
}

#if 1
#include <inttypes.h>
static void
nmreq_dump(struct nmreq_open_d *d)
{
	printf("header:\n");
	printf("   nr_version:  %"PRIu16"\n", d->hdr.nr_version);
	printf("   nr_reqtype:  %"PRIu16"\n", d->hdr.nr_reqtype);
	printf("   nr_reserved: %"PRIu32"\n", d->hdr.nr_reserved);
	printf("   nr_name:     %s\n", d->hdr.nr_name);
	printf("   nr_options:  %lx\n", (unsigned long)d->hdr.nr_options);
	printf("   nr_body:     %lx\n", (unsigned long)d->hdr.nr_body);
	printf("\n");
	printf("register (%p):\n", (void *)d->hdr.nr_body);
	printf("   nr_mem_id:   %"PRIu16"\n", d->reg.nr_mem_id);
	printf("   nr_ringid:   %"PRIu16"\n", d->reg.nr_ringid);
	printf("   nr_mode:     %lx\n", (unsigned long)d->reg.nr_mode);
	printf("   nr_flags:    %lx\n", (unsigned long)d->reg.nr_flags);
	printf("\n");
	if (d->hdr.nr_options) {
		struct nmreq_opt_extmem *e = (struct nmreq_opt_extmem *)d->hdr.nr_options;
		printf("opt_extmem (%p):\n", e);
		printf("   nro_opt.nro_next:    %lx\n", (unsigned long)e->nro_opt.nro_next);
		printf("   nro_opt.nro_reqtype: %"PRIu32"\n", e->nro_opt.nro_reqtype);
		printf("   nro_usrptr:          %lx\n", (unsigned long)e->nro_usrptr);
		printf("   nro_info.nr_memsize  %"PRIu64"\n", e->nro_info.nr_memsize);
	}
	printf("mem (%p):\n", d->mem);
	printf("   refcount:   %d\n", d->mem->refcount);
	printf("   mem:        %p\n", d->mem->mem);
	printf("   size:       %zu\n", d->mem->size);
}
int
main(int argc, char *argv[])
{
	struct nmreq_open_d *d;

	if (argc < 2) {
		fprintf(stderr, "usage: %s netmap-expr\n", argv[0]);
		return 1;
	}

	d = nmreq_open(argv[1], NULL);
	if (d != NULL) {
		nmreq_dump(d);
	}

	return 0;
}
#endif
