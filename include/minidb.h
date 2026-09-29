#ifndef MINIDB_H
#define MINIDB_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

/* Return codes for the byte-oriented API. */
#define MINIDB_OK 0
#define MINIDB_ERR_ARGUMENT -1
#define MINIDB_ERR_DATABASE -2
#define MINIDB_ERR_BUFFER_TOO_SMALL -3

void *minidb_open(const char *dir);
void  minidb_close(void *db);
/* Checked close reports checkpoint/close failures; consumes the handle. */
int   minidb_close_checked(void *db);
int   minidb_put(void *db, const char *key, const char *value);
/* String-form functions use NUL-terminated byte strings and cannot carry embedded NUL.
	minidb_get copies raw value bytes; it does not validate or transcode UTF-8. */
int   minidb_get(void *db, const char *key, char *out, int out_len);
int   minidb_delete(void *db, const char *key);

/* Byte-form functions accept arbitrary bytes; keys must be non-empty.
	For an empty value, value may be NULL when value_len is 0. */
int     minidb_put_bytes(void *db, const uint8_t *key, size_t key_len,
						 const uint8_t *value, size_t value_len);
/* Size is 0 for absent or empty values; use minidb_exists to distinguish them. */
intptr_t minidb_get_size(void *db, const uint8_t *key, size_t key_len);
/* Returns 1 if present, 0 if absent, and a negative error code otherwise. */
int     minidb_exists(void *db, const uint8_t *key, size_t key_len);
/* Returns copied bytes; 0 means absent or empty. Check existence separately. */
intptr_t minidb_get_bytes(void *db, const uint8_t *key, size_t key_len,
						  uint8_t *out, size_t out_len);
/* Like minidb_put_bytes, expiring after ttl_ms milliseconds (must be > 0). */
int     minidb_put_ttl_bytes(void *db, const uint8_t *key, size_t key_len,
							 const uint8_t *value, size_t value_len, uint64_t ttl_ms);
/* Counts visible keys in [start, end); end may be NULL for no upper bound.
   Returns the count, or MINIDB_ERR_ARGUMENT / MINIDB_ERR_DATABASE. */
int64_t minidb_count(void *db, const uint8_t *start, size_t start_len,
					 const uint8_t *end, size_t end_len);
#ifdef __cplusplus
}
#endif
#endif
