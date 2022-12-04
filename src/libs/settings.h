/********************************** MUNI - Milter ***********************************
 *
 * FILENAME:	settings.h
 * DESCRIPTION:	Header file for the config parser for milter.
 * NOTES:		This lib is part of the MUNI-Milter, and will not work on its own.
 * AUTHOR:		Patrik Čelko
 *
 *************************************************************************************/

#ifndef SETTINGS_H
#define SETTINGS_H

/* Settings structure */
struct settings {
    bool dry_run; // DEFAULT: false
    bool save_database; // DEFAULT: true
    bool allow_statistics; // DEFAULt: true
    int forward_counter_limit; // DEFAULT: 50
    int super_spam_limit; // DEFAULT: 15
    int basic_spam_limit; // DEFAULT: 10
    int milter_debug_level; // DEFAULT: 0 | MAX: 6
    int hash_table_size; // DEFAULT: 2000000
    int clean_interval; // DEFAULT: 600 | 5 min.
    int soft_score_limit; // DEFAULT: 5000
    int hard_score_limit; // DEFAULT: 7000
    char* database_path; // DEFAULT: ./db.data
    char* socket_path; // DEFAULT: local:/tmp/f1.sock
    char** blacklist; // DEFAULT: [] | PRIVATE
    char** whitelist; // DEFAULT: [] | PRIVATE
    int blacklist_len; // PRIVATE
    int whitelist_len; // PRIVATE
};

typedef struct settings settings_t;

/* [Thread-Unsafe] Initialise settings structure */
settings_t* settings_init(char* config_path);

/* [Thread-Safe] Destroy settings structure */
void settings_destroy(settings_t* settings);

/* [Thread-Safe] Check if IP is in the whitelist */
bool is_whitelisted(char* address, settings_t* settings);

/* [Thread-Safe] Check if IP is in the blacklist */
bool is_blacklisted(char* address, settings_t* settings);

#endif
