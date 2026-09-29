#include "minidb.h"

int main(void) {
    void *db = minidb_open("./data");
    if (db == NULL) {
        return 1;
    }
    const uint8_t key[] = {0x00, 0xff};
    const uint8_t value[] = {0x01, 0x00, 0xfe};
    uint8_t output[sizeof(value)];
    if (minidb_put_bytes(db, key, sizeof(key), value, sizeof(value)) != MINIDB_OK) {
        minidb_close(db);
        return 2;
    }
    if (minidb_exists(db, key, sizeof(key)) != 1) {
        minidb_close(db);
        return 3;
    }
    if (minidb_get_size(db, key, sizeof(key)) != (intptr_t)sizeof(value)) {
        minidb_close(db);
        return 4;
    }
    if (minidb_get_bytes(db, key, sizeof(key), output, sizeof(output)) !=
        (intptr_t)sizeof(value)) {
        minidb_close(db);
        return 5;
    }
    if (minidb_put_ttl_bytes(db, key, sizeof(key), value, sizeof(value), 60000) != MINIDB_OK) {
        minidb_close(db);
        return 6;
    }
    if (minidb_count(db, key, sizeof(key), NULL, 0) != 1) {
        minidb_close(db);
        return 7;
    }
    return minidb_close_checked(db) == MINIDB_OK ? 0 : 8;
}
