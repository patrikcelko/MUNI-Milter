/********************************** MUNI - Milter ***********************************
 *
 * FILENAME:    database.h
 * DESCRIPTION: Header file for the database for milter.
 * NOTES:       This lib is part of the MUNI-Milter, and will not work on its own.
 * AUTHOR:      Patrik Čelko
 *
 *************************************************************************************/

#ifndef DATABASE_H
#define DATABASE_H

#include "settings.h"

/* Database entry/bucket structure */
struct entry {
    char* key;
    time_t last_email;
    int score;
    struct entry* next;
};

/* Database structure */
struct database {
    struct entry** data;
    pthread_mutex_t mutex_value;
    time_t last_clean;
    settings_t* settings_instance;
    int entry_counter;
};

/* Additional email info structure for function 'db_new_score' */
struct email_info {
    int assassin_score;
    time_t last_email;
    bool is_auth;
    bool is_forward;
    bool is_local;
};

typedef struct entry entry_t;
typedef struct database database_t;
typedef struct email_info email_info_t;

/* [Thread-Unsafe] Construct database structure */
database_t* db_construct(pthread_mutex_t mutex_value, settings_t* settings);

/* [Thread-Unsafe] Destroy database structure */
void db_destroy(database_t* db_instance);

/* [Thread-Safe] Set entry in database */
void db_set(database_t* db_instance, char* key, time_t last_email, int score);

/* [Thread-Safe] Get entry from database */
entry_t* db_get(database_t* db_instance, char* ip_to_search);

/* [Thread-Unsafe] Save whole database to file */
void db_save(database_t* db_instance);

/* [Thread-Unsafe] Load database from local path */
void db_load(database_t* db_instance);

/* [Thread-Safe] Remove old records from database and update score */
void db_cleanup(database_t* db_instance);

/* [Thread-Safe] Calculate new score for database */
int db_new_score(int old_score, email_info_t* email_info, settings_t* settings);

#endif
