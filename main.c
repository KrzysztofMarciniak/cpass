#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <termios.h>
#include "openssl.h"

#define DB_FILE ".pass.db"
#define MAX_LEN 1024

typedef struct Entry {
    char *name;
    char *username;
    char *password;
} Entry;

typedef struct DB {
    Entry *entries;
    size_t count;
} DB;

// Each entry: [uint32 name_len][uint32 user_len][uint32 pass_len][name][username][password]
static unsigned char *serialize_db(DB *db, size_t *outlen) {
    size_t total = 0;
    for (size_t i = 0; i < db->count; i++) {
        total += 12 + strlen(db->entries[i].name) + strlen(db->entries[i].username) + strlen(db->entries[i].password);
    }
    unsigned char *buf = malloc(total);
    if (!buf) return NULL;

    unsigned char *p = buf;
    for (size_t i = 0; i < db->count; i++) {
        uint32_t nl = (uint32_t)strlen(db->entries[i].name);
        uint32_t ul = (uint32_t)strlen(db->entries[i].username);
        uint32_t pl = (uint32_t)strlen(db->entries[i].password);

        memcpy(p, &nl, 4); p += 4;
        memcpy(p, &ul, 4); p += 4;
        memcpy(p, &pl, 4); p += 4;

        memcpy(p, db->entries[i].name, nl); p += nl;
        memcpy(p, db->entries[i].username, ul); p += ul;
        memcpy(p, db->entries[i].password, pl); p += pl;
    }
    *outlen = total;
    return buf;
}

static DB *deserialize_db(unsigned char *buf, size_t len) {
    DB *db = malloc(sizeof(DB));
    if (!db) return NULL;
    db->entries = NULL;
    db->count = 0;

    unsigned char *p = buf;
    unsigned char *end = buf + len;

    while (p + 12 <= end) {
        uint32_t nl, ul, pl;
        memcpy(&nl, p, 4); p += 4;
        memcpy(&ul, p, 4); p += 4;
        memcpy(&pl, p, 4); p += 4;

        if (p + nl + ul + pl > end) break;

        db->entries = realloc(db->entries, sizeof(Entry)*(db->count+1));
        db->entries[db->count].name = strndup((char*)p, nl); p += nl;
        db->entries[db->count].username = strndup((char*)p, ul); p += ul;
        db->entries[db->count].password = strndup((char*)p, pl); p += pl;

        db->count++;
    }

    return db;
}

static void free_db(DB *db) {
    if (!db) return;
    for (size_t i = 0; i < db->count; i++) {
        free(db->entries[i].name);
        free(db->entries[i].username);
        free(db->entries[i].password);
    }
    free(db->entries);
    free(db);
}



static char *get_pass() {
    static char buf[MAX_LEN];

    struct termios oldt, newt;
    printf("Master password: ");
    fflush(stdout);

    if (tcgetattr(STDIN_FILENO, &oldt) != 0) {
        perror("tcgetattr");
        return NULL;
    }

    newt = oldt;
    newt.c_lflag &= ~ECHO;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &newt) != 0) {
        perror("tcsetattr");
        return NULL;
    }

    if (!fgets(buf, sizeof(buf), stdin)) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &oldt);
        return NULL;
    }

    buf[strcspn(buf, "\n")] = 0;

    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &oldt) != 0) {
        perror("tcsetattr");
        return NULL;
    }

    printf("\n");
    return buf;
}

static char *db_path() {
    const char *home = getenv("HOME");
    static char path[512];
    snprintf(path, sizeof(path), "%s/%s", home, DB_FILE);
    return path;
}

static DB *load_db(const char *password) {
    FILE *f = fopen(db_path(), "rb");
    if (!f) return calloc(1,sizeof(DB));
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    unsigned char *buf = malloc(sz);
    fread(buf, 1, sz, f);
    fclose(f);

    size_t outlen;
    unsigned char *plaintext = decrypt_file(db_path(), &outlen, password);
    free(buf);
    if (!plaintext) {
        fprintf(stderr,"Decryption failed. Wrong password or corrupt DB.\n");
        return NULL;
    }
    DB *db = deserialize_db(plaintext, outlen);
    explicit_bzero(plaintext, outlen);
    free(plaintext);
    return db;
}

static int save_db(DB *db, const char *password) {
    size_t len;
    unsigned char *buf = serialize_db(db, &len);
    if (!buf) return 0;
    int r = encrypt_file(db_path(), buf, len, password);
    explicit_bzero(buf, len);
    free(buf);
    return r;
}

static void cmd_init() {
    char *pass = get_pass();
    if (!pass) return;
    FILE *f = fopen(db_path(), "rb");
    if (f) {
        fclose(f);
        fprintf(stderr,"DB already exists: %s\n", db_path());
        return;
    }
    DB db = {0};
    if (!save_db(&db, pass)) fprintf(stderr,"Failed to create DB\n");
    else printf("DB created at %s\n", db_path());
}

static void cmd_ls(char *arg) {
    char *pass = get_pass();
    DB *db = load_db(pass);
    if (!db) return;
    if (!arg) {
        for (size_t i = 0; i < db->count; i++)
            printf("%s\n", db->entries[i].name);
    } else {
        for (size_t i = 0; i < db->count; i++)
            if (strcmp(db->entries[i].name, arg) == 0)
                printf("Username: %s\nPassword: %s\n", db->entries[i].username, db->entries[i].password);
    }
    free_db(db);
}

static void cmd_add(char *name, char *user, char *passw) {
    char *pass = get_pass();
    DB *db = load_db(pass);
    if (!db) return;
    db->entries = realloc(db->entries, sizeof(Entry)*(db->count+1));
    db->entries[db->count].name = strdup(name);
    db->entries[db->count].username = strdup(user);
    db->entries[db->count].password = strdup(passw);
    db->count++;
    if (!save_db(db, pass)) fprintf(stderr,"Failed to save DB\n");
    free_db(db);
    printf("Added entry '%s'\n", name);
}

static void cmd_delete(char *name) {
    char *pass = get_pass();
    DB *db = load_db(pass);
    if (!db) return;
    size_t new_count = 0;
    for (size_t i = 0; i < db->count; i++) {
        if (strcmp(db->entries[i].name, name) != 0) {
            db->entries[new_count++] = db->entries[i];
        } else {
            free(db->entries[i].name);
            free(db->entries[i].username);
            free(db->entries[i].password);
        }
    }
    db->count = new_count;
    if (!save_db(db, pass)) fprintf(stderr,"Failed to save DB\n");
    free_db(db);
    printf("Deleted entry '%s'\n", name);
}

static void cmd_edit(char *name) {
    char *pass = get_pass();
    DB *db = load_db(pass);
    if (!db) return;
    for (size_t i = 0; i < db->count; i++) {
        if (strcmp(db->entries[i].name, name) == 0) {
            char user[MAX_LEN], passw[MAX_LEN];
            printf("New username [%s]: ", db->entries[i].username);
            if (!fgets(user, sizeof(user), stdin)) return;
            user[strcspn(user,"\n")]=0;
            printf("New password [%s]: ", db->entries[i].password);
            if (!fgets(passw, sizeof(passw), stdin)) return;
            passw[strcspn(passw,"\n")]=0;
            if (strlen(user)>0) { free(db->entries[i].username); db->entries[i].username=strdup(user); }
            if (strlen(passw)>0){ free(db->entries[i].password); db->entries[i].password=strdup(passw);}
            if (!save_db(db, pass)) fprintf(stderr,"Failed to save DB\n");
            free_db(db);
            printf("Updated '%s'\n", name);
            return;
        }
    }
    free_db(db);
    printf("Entry '%s' not found\n", name);
}

static void print_help() {
    printf("Usage:\n");
    printf("  cpass init\n");
    printf("  cpass a <name> <username> <password>\n");
    printf("  cpass d <name>\n");
    printf("  cpass e <name>\n");
    printf("  cpass ls [<name>]\n");
}

int main(int argc, char **argv) {
    if (argc < 2) { print_help(); return 0; }
    if (strcmp(argv[1],"init")==0) cmd_init();
    else if (strcmp(argv[1],"ls")==0) cmd_ls(argc>2?argv[2]:NULL);
    else if (strcmp(argv[1],"a")==0 && argc==5) cmd_add(argv[2],argv[3],argv[4]);
    else if (strcmp(argv[1],"d")==0 && argc==3) cmd_delete(argv[2]);
    else if (strcmp(argv[1],"e")==0 && argc==3) cmd_edit(argv[2]);
    else print_help();
    return 0;
}
