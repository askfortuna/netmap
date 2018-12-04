/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (C) 2018 Universita` di Pisa
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef LIBNETMAP_H_
#define LIBNETMAP_H_
#include <net/netmap_user.h>

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
	/* public fields compatible with nm_open() */
	int fd;
	struct netmap_if *nifp;
	uint16_t first_tx_ring;
	uint16_t last_tx_ring;
	uint16_t first_rx_ring;
	uint16_t last_rx_ring;
	uint16_t cur_tx_ring;
	uint16_t cur_rx_ring;
};

/*
 * A port open specification (portspec for brevity) has the following syntax
 * (square brackets delimit optional parts):
 *
 *     subsystem:vpname[mode][options]
 *
 *  The subsystem is denoted by a prefix, possibly followed by an identifier.
 *  There can be several kinds of subsystems, each one selected by a unique
 *  prefix.  Currently defined subsystems are:
 *
 *  netmap	(no id allowed)
 *  	the standard subsystem
 *  vale	(followed by a possibily empty id)
 *  	the vpname is connected to a VALE switch identified by the id
 *  	(an empty id selects the default switch)
 *
 *  The "port name" is given by the subsystem:vpname part of the portspec.
 *
 *  The vpname has the following syntax:
 *
 *     identifier			or
 *     identifier{identifier		or
 *     identifier}identifier
 *
 *  Identifiers are sequences of alphanumeric characters. The part that begins
 *  with either '{' or '}', when present, denotes a netmap pipe opened in the
 *  same memory region of the port named by the first identifier.
 *
 */


/* nmport manipulation */

/* highest level */
struct nmport_d * nmport_open(const char *);
void nmport_close(struct nmport_d *);
struct nmport_d *nmport_clone(struct nmport_d *);
int nmport_inject(struct nmport_d *d, const void *buf, size_t size);

/* middle level */
struct nmport_d *nmport_prepare(const char *);
int nmport_open_desc(struct nmport_d *d);
void nmport_undo_prepare(struct nmport_d *);
void nmport_undo_open_desc(struct nmport_d *);

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
void nmport_undo_parse(struct nmport_d *);
void nmport_undo_register(struct nmport_d *);
void nmport_undo_mmap(struct nmport_d *);

/* nmreq manipulation */

/* nmreq_header_decode - initialize an nmreq_header
 * @ppspec:	(in/out) pointer to a pointer to the portspec
 * @hdr:	pointer to the nmreq_header to be initialized
 * @ctx:	pointer to the nmctx to use (for errors)
 *
 * This function fills the @hdr nr_version field with NETMAP_API and the
 * nr_name field with the port name extracted from *@pifname.  The other fields
 * of *@hdr are set to zero. The @pifname is updated to point at the first char
 * past the port name.
 *
 * Returns 0 on success.  In case of error, -1 is returned with errno set to
 * EINVAL, @pifname is unchanged, *@hdr is also unchanged, and an error message
 * is sent through @ctx->error().
 */
int nmreq_header_decode(const char **ppspec, struct nmreq_header *hdr, struct nmctx *ctx);

/* nmreq_regiter_decode - inizialize an nmreq_register
 * @pmode:	(in/out) pointer to a pointer to an opening mode
 * @reg:	pointer to the nmreq_register to be initialized
 * @ctx:	pointer to the nmctx to use (for errors)
 *
 * This function fills the nr_mode, nr_ringid, nr_flags and nr_mem_id fields of
 * the structure pointed by @reg, according to the opening mode specified by
 * *@pmode. The other fields of *@reg are set to zero.  The @pmode is updatet
 * to point at the first char past the opening mode.
 *
 * If a '@' is encountered followed by something which is not a number, parsing
 * stops (without error) and @pmode is left pointing at the '@' char. The
 * nr_mode, nr_ringid and nr_flags fields are still updated, but nr_mem_id is
 * not touched and the interpretation of the '@' field is left to the caller.
 *
 * Returns 0 on success.  In case of error, -1 is returned with errno set to
 * EINVAL, @pmode is unchanged, *@reg is also unchanged, and an error message
 * is sent through @ctx->error().
 */
int nmreq_register_decode(const char **pmode, struct nmreq_register *reg, struct nmctx *ctx);

int nmreq_get_mem_id(const char **, struct nmctx *);

struct nmreq_parse_ctx {
	struct nmctx *ctx;
	void *token;
#define NMREQ_OPT_MAXKEYS 16
	const char *keys[NMREQ_OPT_MAXKEYS];
};

typedef int (*nmreq_opt_parser_cb)(struct nmreq_parse_ctx *);

struct nmreq_opt_key {
	const char *key;
	int id;
	unsigned int flags;
#define NMREQ_OPTK_ALLOWEMPTY 	(1U << 0)
};
struct nmreq_opt_parser {
	const char *prefix;
	nmreq_opt_parser_cb parse;
	int default_key;
	unsigned int flags;
#define NMREQ_OPTF_ALLOWEMPTY	(1U << 0)
	struct nmreq_opt_key keys[NMREQ_OPT_MAXKEYS];
};
int nmreq_options_decode(const char *opt, struct nmreq_opt_parser[], int, void *, struct nmctx *);

int nmreq_opt_extmem_decode(const char **, struct nmreq_opt_extmem *, struct nmctx *);
void nmreq_push_option(struct nmreq_header *, struct nmreq_option *);
void nmreq_remove_option(struct nmreq_header *, struct nmreq_option *);
struct nmreq_option *nmreq_find_option(struct nmreq_header *, uint32_t);

/* nmctx manipulation */
struct nmctx *nmctx_get(void);
struct nmctx *nmctx_set_default(struct nmctx *ctx);
void nmctx_set_threadsafe(void);
void nmctx_ferror(struct nmctx *, const char *, ...);
void *nmctx_malloc(struct nmctx *, size_t);
void nmctx_free(struct nmctx *, void *);
void nmctx_lock(struct nmctx *);
void nmctx_unlock(struct nmctx *);

/* internal functions */
void nmreq_free_options(struct nmreq_header *);

static  __attribute__((used)) void libnetmap_init(void)
{
#ifndef LIBNETMAP_NOTHREADSAFE
	extern int nmctx_threadsafe;
	nmctx_threadsafe = 1;
#endif /* LIBNETMAP_NOTHREADSAFE */
}

#endif /* LIBNETMAP_H_ */
