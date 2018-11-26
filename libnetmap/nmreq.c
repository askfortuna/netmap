#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

//#define NMREQ_DEBUG
#ifdef NMREQ_DEBUG
#define NETMAP_WITH_LIBS
#define ED(...)	D(__VA_ARGS__)
#else
#define ED(...)
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
#endif /* NMREQ_DEBUG */

#include <net/netmap_user.h>
#include "libnetmap.h"

void
nmreq_push_option(struct nmreq_header *h, struct nmreq_option *o)
{
	o->nro_next = h->nr_options;
	h->nr_options = (uintptr_t)o;
}

int
nmreq_header_decode(const char **pifname, struct nmreq_header *h, struct nmctx *ctx)
{
	int is_vale;
	const char *scan = NULL;
	const char *vpname = NULL;
	const char *pipesep = NULL;
	u_int namelen;
	static size_t NM_BDG_NAMSZ = strlen(NM_BDG_NAME);
	const char *ifname = *pifname;

	if (strncmp(ifname, "netmap:", 7) &&
			strncmp(ifname, NM_BDG_NAME, NM_BDG_NAMSZ)) {
		nmctx_ferror(ctx, "invalid request '%s' (must begin with 'netmap:' or '" NM_BDG_NAME "')", ifname);
		goto fail;
	}

	is_vale = (ifname[0] == 'v');
	if (is_vale) {
		scan = index(ifname, ':');
		if (scan == NULL) {
			nmctx_ferror(ctx, "missing ':' in VALE name '%s'", ifname);
			goto fail;
		}

		if (!nm_is_identifier(ifname + NM_BDG_NAMSZ, scan)) {
			nmctx_ferror(ctx, "invalid VALE bridge name '%.*s'",
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
		nmctx_ferror(ctx, "invalid %sport name '%.*s'", (is_vale ? "VALE " : ""),
				pipesep - vpname, vpname);
		goto fail;
	}
	if (pipesep != scan) {
		pipesep++;
		if (!nm_is_identifier(pipesep, scan)) {
			nmctx_ferror(ctx, "invalid pipe name '%.*s'", scan - pipesep, pipesep);
			goto fail;
		}
	}

	namelen = scan - ifname;
	if (namelen >= sizeof(h->nr_name)) {
		nmctx_ferror(ctx, "name '%.*s' too long", namelen, ifname);
		goto fail;
	}
	if (namelen == 0) {
		nmctx_ferror(ctx, "invalid empty port name");
		goto fail;
	}

	/* fill the header */
	memset(h, 0, sizeof(*h));
	h->nr_version = NETMAP_API;
	memcpy(h->nr_name, ifname, namelen);
	h->nr_name[namelen] = '\0';
	ED("name %s", h->nr_name);

	*pifname = scan;

	return 0;
fail:
	errno = EINVAL;
	return -1;
}


/*
 * 0 not recognized
 * -1 error
 *  >= 0 mem_id
 */
int
nmreq_get_mem_id(const char **pifname, struct nmctx *ctx)
{
	int fd = -1;
	struct nmreq_header gh;
	struct nmreq_port_info_get gb;
	const char *ifname;
	int error = -1;
	int old_verbose;

	errno = 0;
	ifname = *pifname;

	if (ifname == NULL)
		goto fail;

	/* try to look for a netmap port with this name */
	fd = open("/dev/netmap", O_RDWR);
	if (fd < 0) {
		nmctx_ferror(ctx, "cannot open /dev/netmap: %s", strerror(errno));
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
		nmctx_ferror(ctx, "cannot get info for '%s': %s", ifname, strerror(errno));
		goto fail;
	}
	*pifname = ifname;
	close(fd);
	return gb.nr_mem_id;

fail:
	if (fd >= 0)
		close(fd);
	if (!errno)
		errno = EINVAL;
	ctx->verbose = old_verbose;
	return error;
}


int
nmreq_opt_extmem_decode(const char **spec, struct nmreq_opt_extmem *e, struct nmctx *ctx)
{
	int fd;
	off_t mapsize;
	void *p;
	const char *mem_id = *spec;

	ED("trying with external memory");
	fd = open(mem_id, O_RDWR);
	if (fd < 0) {
		nmctx_ferror(ctx, "cannot open '%s': %s", mem_id, strerror(errno));
		goto fail;
	}
	mapsize = lseek(fd, 0, SEEK_END);
	if (mapsize < 0) {
		nmctx_ferror(ctx, "failed to obtain filesize of '%s': %s", mem_id, strerror(errno));
		goto fail;
	}
	memset(e, 0, sizeof(*e));
	p = mmap(0, mapsize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	e->nro_usrptr = (uintptr_t)p;
	if (p == MAP_FAILED) {
		nmctx_ferror(ctx, "cannot mmap '%s': %s", mem_id, strerror(errno));
		goto fail;
	}
	e->nro_opt.nro_reqtype = NETMAP_REQ_OPT_EXTMEM;
	e->nro_info.nr_memsize = mapsize;
	ED("mapped %zu bytes at %p from file %s", mapsize, p, mem_id);
	*spec = mem_id + strlen(mem_id);
	return 0;
fail:
	if (fd > 0)
		close(fd);
	return -1;
}

int
nmreq_register_decode(const char **pifname, struct nmreq_register *r, struct nmctx *ctx)
{
	enum { P_START, P_RNGSFXOK, P_GETNUM, P_FLAGS, P_FLAGSOK, P_MEMID } p_state;
	long num;
	const char *scan = *pifname;
	int memid_allowed = 1;

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
				nmctx_ferror(ctx, "unknown modifier: '%c'", *scan);
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
				nmctx_ferror(ctx, "unexpected character: '%c'", *scan);
				goto fail;
			}
			scan++;
			break;
		case P_GETNUM:
			if (!isdigit(*scan)) {
				nmctx_ferror(ctx, "got '%s' while expecting a number", scan);
				goto fail;
			}
			num = strtol(scan, (char **)&scan, 10);
			if (num < 0 || num >= NETMAP_RING_MASK) {
				nmctx_ferror(ctx, "'%ld' out of range [0, %d)",
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
				nmctx_ferror(ctx, "unrecognized flag: '%c'", *scan);
				goto fail;
			}
			scan++;
			p_state = P_FLAGSOK;
			break;
		case P_MEMID:
			if (!memid_allowed) {
				nmctx_ferror(ctx, "double setting of mem_id");
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
					nmctx_ferror(ctx, "unexpected characters '%s' in mem_id spec", scan);
					goto fail;
				}
				r->nr_mem_id = num;
				goto out;
			}
			break;
		}
	}
	if (p_state == P_MEMID && !*scan) {
		nmctx_ferror(ctx, "invalid empty mem_id");
		goto fail;
	}
	if (p_state != P_START && p_state != P_RNGSFXOK &&
	    p_state != P_FLAGSOK && p_state != P_MEMID) {
		nmctx_ferror(ctx, "unexpected end of request");
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
	return 0;

fail:
	if (!errno)
		errno = EINVAL;
	return -1;
}

struct nmreq_option *
nmreq_find_option(struct nmreq_header *h, uint32_t t)
{
	struct nmreq_option *o;

	for (o = (struct nmreq_option *)h->nr_options; o != NULL;
			o = (struct nmreq_option *)o->nro_next) {
		if (o->nro_reqtype == t)
			break;
	}
	return o;
}

void
nmreq_remove_option(struct nmreq_header *h, struct nmreq_option *o)
{
	uintptr_t *scan;

	for (scan = &h->nr_options; *scan;
			scan = &((struct nmreq_option *)*scan)->nro_next) {
		if (*scan == (uintptr_t)o) {
			*scan = o->nro_next;
			o->nro_next = 0;
			break;
		}
	}
}

void
nmreq_free_options(struct nmreq_header *h)
{
	struct nmreq_option *o, *next;

	for (o = (struct nmreq_option *)h->nr_options; o != NULL; o = next) {
		next = (struct nmreq_option *)o->nro_next;
		free(o);
	}
}

#if 0
#include <inttypes.h>
static void
nmreq_dump(struct nmport_d *d)
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
	printf("\n");
	printf("mem (%p):\n", d->mem);
	printf("   refcount:   %d\n", d->mem->refcount);
	printf("   mem:        %p\n", d->mem->mem);
	printf("   size:       %zu\n", d->mem->size);
	printf("\n");
	printf("rings:\n");
	printf("   tx:   [%d, %d]\n", d->first_tx_ring, d->last_tx_ring);
	printf("   rx:   [%d, %d]\n", d->first_rx_ring, d->last_rx_ring);
}
int
main(int argc, char *argv[])
{
	struct nmport_d *d;

	if (argc < 2) {
		fprintf(stderr, "usage: %s netmap-expr\n", argv[0]);
		return 1;
	}

	d = nmport_open(argv[1]);
	if (d != NULL) {
		nmreq_dump(d);
		nmport_close(d);
	}

	return 0;
}
#endif
