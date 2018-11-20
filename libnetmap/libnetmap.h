#ifndef LIBNETMAP_H_
#define LIBNETMAP_H_

struct nmctx;
struct nmport_d;
struct nmem_d;

typedef void (*nmctx_error_cb)(struct nmctx *, const char *);

struct nmctx {
	int netmap_fd;
	int nopen;

	int verbose;
	nmctx_error_cb error;

	void (*get)(struct nmctx *);
	void (*put)(struct nmctx *);

	struct nmem_d  *mem_descs;
};

struct nmem_d {
	uint16_t mem_id;
	int refcount;
	void *mem;
	size_t size;
	int is_extmem;

	struct nmem_d *next;
	struct nmem_d *prev;
};

struct nmport_d {
	struct nmctx *ctx;
	struct nmreq_header hdr;
	struct nmreq_register reg;

	struct nmport_d *next;
	struct nmport_d *prev;

	int netmap_fd;
	struct nmem_d *mem;

	/* status */
	int register_done;
	int mmap_done;
	struct nmreq_opt_extmem *extmem;

	struct netmap_if *nifp;
	u_int first_tx_ring;
	u_int last_tx_ring;
	u_int first_rx_ring;
	u_int last_rx_ring;
};

/* nmctx manipulation */
void nmctx_init(struct nmctx *);
struct nmctx * nmctx_get(void);
void nmctx_put(struct nmctx *);
int nmctx_getfd(struct nmctx *);
void nmctx_putfd(struct nmctx *);

/* nmreq manipulation */
void nmreq_push_option(struct nmreq_header *, struct nmreq_option *);
struct nmreq_option *nmreq_find_option(struct nmreq_header *, uint32_t);
int nmreq_header_decode(const char **, struct nmreq_header *, struct nmctx *);
int nmreq_get_mem_id(const char **, struct nmctx *);
int nmreq_opt_extmem_decode(const char **, struct nmreq_opt_extmem *, struct nmctx *);
int nmreq_register_decode(const char **, struct nmreq_register *, struct nmctx *);

/* nmport manipulation */
struct nmport_d * nmport_open(const char *);
void nmport_close(struct nmport_d *);


/* internal functions */
void nmctx_ferror(struct nmctx *, const char *, ...);
void nmreq_free_options(struct nmreq_header *);

#endif /* LIBNETMAP_H_ */
