#ifndef LIBNETMAP_H_
#define LIBNETMAP_H_

struct nmctx;
struct nmport_d;
struct nmem_d;

typedef void  (*nmctx_error_cb)(struct nmctx *, const char *);
typedef void *(*nmctx_malloc_cb)(struct nmctx *,size_t);
typedef void  (*nmctx_free_cb)(struct nmctx *,void *);
typedef void  (*nmctx_lock_cb)(struct nmctx *, int);

struct nmctx {
	int verbose;
	nmctx_error_cb 	error;
	nmctx_malloc_cb	malloc;
	nmctx_free_cb	free;
	nmctx_lock_cb	lock;

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

	struct nmem_d *mem;

	/* status */
	int register_done;
	int mmap_done;
	struct nmreq_opt_extmem *extmem;

	/* public fields */
	struct nmreq_header hdr;
	struct nmreq_register reg;
	/* public fields (compatible with nm_open()) */
	int fd;
	struct netmap_if *nifp;
	uint16_t first_tx_ring;
	uint16_t last_tx_ring;
	uint16_t first_rx_ring;
	uint16_t last_rx_ring;
	uint16_t cur_tx_ring;
	uint16_t cur_rx_ring;
};

/* nmctx manipulation */
struct nmctx * nmctx_get(void);
void nmctx_ferror(struct nmctx *, const char *, ...);
void *nmctx_malloc(struct nmctx *, size_t);
void nmctx_free(struct nmctx *, void *);
void nmctx_lock(struct nmctx *);
void nmctx_unlock(struct nmctx *);


/* nmreq manipulation */
void nmreq_push_option(struct nmreq_header *, struct nmreq_option *);
void nmreq_remove_option(struct nmreq_header *, struct nmreq_option *);
struct nmreq_option *nmreq_find_option(struct nmreq_header *, uint32_t);
int nmmreq_clone_options(struct nmreq_header *, struct nmreq_header *);
int nmreq_header_decode(const char **, struct nmreq_header *, struct nmctx *);
int nmreq_get_mem_id(const char **, struct nmctx *);
int nmreq_opt_extmem_decode(const char **, struct nmreq_opt_extmem *, struct nmctx *);
int nmreq_register_decode(const char **, struct nmreq_register *, struct nmctx *);

/* nmport manipulation */

/* highest level */
struct nmport_d * nmport_open(const char *);
void nmport_close(struct nmport_d *);
struct nmport_d *nmport_clone(struct nmport_d *);

/* middle level */
struct nmport_d *nmport_prepare(const char *);
int nmport_complete(struct nmport_d *d);
void nmport_undo_prepare(struct nmport_d *);
void nmport_undo_complete(struct nmport_d *);

int nmport_extmem_from_file(struct nmport_d *, const char **);
int nmport_extmem_from_mem(struct nmport_d *, void *, size_t);
void nmport_undo_extmem(struct nmport_d *);

/* lowest level */
struct nmport_d *nmport_new(void);
struct nmport_d *nmport_new_with_ctx(struct nmctx *);
int nmport_parse(struct nmport_d *, const char *);
int nmport_register(struct nmport_d *);
int nmport_mmap(struct nmport_d *);
void nmport_delete(struct nmport_d *);
void nmport_delete(struct nmport_d *);
void nmport_undo_parse(struct nmport_d *);
void nmport_undo_register(struct nmport_d *);
void nmport_undo_mmap(struct nmport_d *);


/* internal functions */
void nmreq_free_options(struct nmreq_header *);

#endif /* LIBNETMAP_H_ */
