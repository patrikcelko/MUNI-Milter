/********************************** MUNI - Milter ***********************************
 *
 * FILENAME:	database.c
 * DESCRIPTION:	Implementation of the database for milter.
 * NOTES:		This lib is part of the MUNI-Milter, and will not work on its own.
 * AUTHOR:		Patrik Čelko
 *
 *************************************************************************************/

#define _GNU_SOURCE

#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#include "database.h"

/* Score multipliers */
static double AUTH_MULTIPLIER = 1.6;
static double LOCAL_MULTIPLIER = 1.4;
static double FORWARD_MULTIPLIER = 1.5;

/* Constants */
static char DATABASE_DELIMITER[] = ",";

/* [Thread-Safe] This function (djb2) was inspired by http://www.cse.yorku.ca/~oz/hash.html */
unsigned int djb2_hash(const char* ip_string, int table_size)
{
    unsigned int hash_value = 5381;
    int c;

    while ((c = *ip_string++)) {
        hash_value = (hash_value << 5) + hash_value;
        hash_value += !isupper(c) ? c : c + 32;
    }
    return hash_value % table_size;
}

/* [Thread-Safe] Calculate new scores for the database */
int db_new_score(int old_score, email_info_t* email_info, settings_t* settings)
{
    if (email_info->assassin_score < 0 || old_score < 0) {
        syslog(LOG_WARNING, "Invalid spam assassin score (%d) or old score value (%d).", email_info->assassin_score, old_score);
        return 0;
    }

    int return_score = old_score;
    double multiplier = 1; // Default

    if (email_info->is_auth) {
        syslog(LOG_DEBUG, "[db_new_score] User is logged in, we can be more strict (Multiplier: %fx).", AUTH_MULTIPLIER);
        multiplier *= AUTH_MULTIPLIER;
    }

    if (email_info->is_forward) {
        syslog(LOG_DEBUG, "[db_new_score] The mail is forwarded from the MUNI network (Multiplier: %fx).", FORWARD_MULTIPLIER);
        multiplier *= LOCAL_MULTIPLIER;
    }

    if (email_info->is_local) {
        syslog(LOG_DEBUG, "[db_new_score] The email end address is in the MUNI network (Multiplier: %fx).", LOCAL_MULTIPLIER);
        multiplier *= FORWARD_MULTIPLIER;
    }

    syslog(LOG_DEBUG, "[db_new_score] Spam assassin score is %d.", email_info->assassin_score);

    if (email_info->assassin_score != 0) {
        if (email_info->assassin_score <= 5) {
            return_score += (email_info->assassin_score ^ 2) * multiplier;
        } else if (email_info->assassin_score <= 10) {
            return_score += (email_info->assassin_score ^ 2) * 3 * multiplier;
        } else if (email_info->assassin_score <= 15) {
            return return_score + (email_info->assassin_score ^ 2) * 7 * multiplier;
        } else {
            return return_score + (email_info->assassin_score ^ 2) * 11 * multiplier;
        }
    }

    double subtract_value = (100 / settings->clean_interval) * difftime(time(0), email_info->last_email);
    if (return_score >= settings->soft_score_limit) {
        subtract_value /= 2;
    }

    return_score -= subtract_value;
    return return_score < 0 ? 0 : return_score;
}

/* [Thread-Unsafe] Construct database structure */
database_t* db_construct(pthread_mutex_t mutex_value, settings_t* settings)
{
    if (!settings) {
        syslog(LOG_ERR, "Was not able to construct a database without settings an instance.");
        return NULL;
    }

    syslog(LOG_DEBUG, "[db_construct] Database initialisation started. Hash table size: %d", settings->hash_table_size);

    database_t* db_instance = malloc(sizeof(database_t));
    db_instance->data = malloc(sizeof(entry_t*) * settings->hash_table_size);

    for (int i = 0; i < settings->hash_table_size; i++) {
        db_instance->data[i] = NULL;
    }

    db_instance->mutex_value = mutex_value;
    db_instance->settings_instance = settings;
    db_instance->last_clean = time(0);
    db_instance->entry_counter = 0;

    syslog(LOG_DEBUG, "[db_construct] The database was successfully constructed.");
    return db_instance;
}

/* [Thread-Unsafe] Recursion function for 'db_destroy' */
void destroy_entry_recursion(entry_t* entry, int* destroy_counter)
{
    if (!entry) {
        return;
    }

    if (entry->next) {
        destroy_entry_recursion(entry->next, destroy_counter);
    }

    (*destroy_counter)++;

    free(entry->key);
    free(entry);
}

/* [Thread-Unsafe] Destroy database structure */
void db_destroy(database_t* db_instance)
{
    if (!db_instance) {
        syslog(LOG_WARNING, "Destroy function received empty database instance. Skipping.");
        return;
    }

    syslog(LOG_DEBUG, "[db_destroy] Destroying database structure and freeing resources. Entries: %d.", db_instance->entry_counter);

    int destroy_counter = 0;
    for (int i = 0; i < db_instance->settings_instance->hash_table_size; i++) {
        destroy_entry_recursion(db_instance->data[i], &destroy_counter);

        if (destroy_counter >= db_instance->entry_counter) {
            break; // The database is now empty
        }
    }

    free(db_instance->data);
    free(db_instance);

    syslog(LOG_DEBUG, "[db_destroy] The database was successfully removed from memory.");
}

/* [Thread-Safe] Recursion function for 'db_set' */
entry_t* set_entry_recursion(entry_t* entry, char* key, time_t last_email, int score, database_t* db_instance, bool allow_print)
{
    if (!entry) {
        if (allow_print) {
            syslog(LOG_DEBUG, "[set_entry_recursion] Space was found, creating a record. Key: %s.", key);
        }

        pthread_mutex_lock(&db_instance->mutex_value);
        entry_t* temp_entry = malloc(sizeof(entry_t));
        temp_entry->key = malloc(strlen(key) + 1);

        strcpy(temp_entry->key, key);

        temp_entry->last_email = last_email;
        temp_entry->score = score;

        db_instance->entry_counter++;
        pthread_mutex_unlock(&db_instance->mutex_value);

        if (allow_print) {
            syslog(LOG_DEBUG, "[set_entry_recursion] The record was successfully created. Key: %s.", key);
        }
        return temp_entry;
    }

    if (entry->key && !strcmp(entry->key, key)) {
        if (allow_print) {
            syslog(LOG_DEBUG, "[set_entry_recursion] The record already exists, updating values. Key: %s.", key);
        }

        pthread_mutex_lock(&db_instance->mutex_value);
        entry->last_email = last_email;
        entry->score = score;
        pthread_mutex_unlock(&db_instance->mutex_value);

        if (allow_print) {
            syslog(LOG_DEBUG, "[set_entry_recursion] The record was successfully updated. Key: %s.", key);
        }
        return entry;
    }

    entry_t* new_entry = set_entry_recursion(entry->next, key, last_email, score, db_instance, allow_print);

    if (new_entry != entry->next) {
        pthread_mutex_lock(&db_instance->mutex_value);
        entry->next = new_entry;
        pthread_mutex_unlock(&db_instance->mutex_value);
    }

    return entry;
}

/* [Thread-Safe] Set entry in the database but with the option to disable print outputs */
void db_set_with_print(database_t* db_instance, char* key, time_t last_email, int score, bool allow_print)
{
    if (!key || !db_instance) {
        syslog(LOG_WARNING, "Database setter received invalid key or database instance.");
        return;
    }

    unsigned int record_index = djb2_hash(key, db_instance->settings_instance->hash_table_size);
    if (allow_print) {
        syslog(LOG_DEBUG, "[db_set] Trying to update or set value for key %s with hash %u.", key, record_index);
    }
    entry_t* entry = db_instance->data[record_index];

    if (!entry) {
        if (allow_print) {
            syslog(LOG_DEBUG, "[db_set] The Hash bucket was empty creating a new record. Key: %s.", key);
        }
        pthread_mutex_lock(&db_instance->mutex_value);
        db_instance->data[record_index] = malloc(sizeof(entry_t));

        db_instance->data[record_index]->key = malloc(strlen(key) + 1);
        strcpy(db_instance->data[record_index]->key, key);

        db_instance->data[record_index]->last_email = last_email;
        db_instance->data[record_index]->score = score;
        db_instance->data[record_index]->next = NULL;

        db_instance->entry_counter++;
        pthread_mutex_unlock(&db_instance->mutex_value);

        if (allow_print) {
            syslog(LOG_DEBUG, "[db_set] The record was successfully created. Key: %s.", key);
        }
        return;
    }

    if (allow_print) {
        syslog(LOG_DEBUG, "[db_set] The first hash bucket already exists searching for space. Key: %s.", key);
    }

    entry_t* new_entry = set_entry_recursion(entry, key, last_email, score, db_instance, allow_print);
    if (new_entry != entry) {
        pthread_mutex_lock(&db_instance->mutex_value);
        db_instance->data[record_index] = new_entry;
        pthread_mutex_unlock(&db_instance->mutex_value);
    }
}

/* [Thread-Safe] Set database entry */
void db_set(database_t* db_instance, char* key, time_t last_email, int score)
{
    db_set_with_print(db_instance, key, last_email, score, true); // Allow print
}

/* [Thread-Safe] Recursion function for 'db_get' */
entry_t* get_entry_recursion(entry_t* entry, char* ip_to_search)
{
    if (!strcmp(entry->key, ip_to_search)) {
        syslog(LOG_DEBUG, "[get_entry_recursion] Record for key %s was successfully found.", ip_to_search);
        return entry;
    }

    if (entry->next) {
        return get_entry_recursion(entry->next, ip_to_search);
    }

    syslog(LOG_DEBUG, "[get_entry_recursion] Was not able to find key %s (out of buckets).", ip_to_search);
    return NULL;
}

/* [Thread-Safe] Get entry from database */
entry_t* db_get(database_t* db_instance, char* ip_to_search)
{
    if (!ip_to_search || !db_instance) {
        syslog(LOG_WARNING, "Database getter received invalid key or database instance.");
        return NULL;
    }

    unsigned int record_index = djb2_hash(ip_to_search, db_instance->settings_instance->hash_table_size);
    syslog(LOG_DEBUG, "[db_get] Starting to search for key %s with hash %u.", ip_to_search, record_index);

    entry_t* entry = db_instance->data[record_index];
    if (!entry) {
        syslog(LOG_DEBUG, "[db_get] Record for key %s does not exist (first bucket does not exist).", ip_to_search);
        return NULL;
    }
    return get_entry_recursion(entry, ip_to_search);
}

/* [Thread-Unsafe] Recursion function for 'db_save_recusrion' */
void db_save_recusrion(entry_t* entry, int* saved_lines, FILE* db_save_fd, settings_t* settings)
{
    if (!entry) {
        return;
    }

    email_info_t temp_email_info = {
        0,
        entry->last_email,
        false,
        false,
        false
    };

    int new_score = db_new_score(entry->score, &temp_email_info, settings);

    if (new_score > 0) {
        fprintf(db_save_fd, "%s%s%d\n", entry->key, DATABASE_DELIMITER, new_score);
        (*saved_lines)++;
    }
    db_save_recusrion(entry->next, saved_lines, db_save_fd, settings);
}

/* [Thread-Unsafe] Save the whole database to file */
void db_save(database_t* db_instance)
{
    if (!db_instance || !db_instance->settings_instance) {
        syslog(LOG_WARNING, "Was not able to start saving because the database or settings instance is invalid.");
        return;
    }

    if (db_instance->entry_counter <= 0) {
        syslog(LOG_DEBUG, "[db_save] There is nothing to save (empty database). Skipping.");
        return;
    }

    char* path = db_instance->settings_instance->database_path;

    syslog(LOG_DEBUG, "[db_save] Starting to save generated database to file: %s.", path);
    FILE* db_save_fd = fopen(path, "w+");
    if (!db_save_fd) {
        syslog(LOG_ERR, "Was not able to open the file descriptor for database save after saving. Path: %s.", path);
        return;
    }

    int saved_lines = 0;
    for (int i = 0; i < db_instance->settings_instance->hash_table_size; i++) {
        db_save_recusrion(db_instance->data[i], &saved_lines, db_save_fd, db_instance->settings_instance);

        if (saved_lines >= db_instance->entry_counter) {
            break; // Everything was already saved
        }
    }

    errno = 0;
    if (fclose(db_save_fd) == EBADF || errno) {
        syslog(LOG_ERR, "Was not able to close the database save file descriptor. Path: %s.", path);
    }

    syslog(LOG_INFO, "The database was successfully saved to: %s. Saved lines: %d.", path, saved_lines);
    if (db_instance->entry_counter != saved_lines) {
        syslog(LOG_WARNING, "There was a problem during saving the database to file. Saved: %d/%d.", saved_lines, db_instance->entry_counter);
    }
}

/* [Thread-Unsafe] Load database from local path */
void db_load(database_t* db_instance)
{
    if (!db_instance || !db_instance->settings_instance) {
        syslog(LOG_WARNING, "Was not able to load the database file because the database or settings instance is invalid.");
        return;
    }

    char* path = db_instance->settings_instance->database_path;
    FILE* db_load_fd = fopen(path, "r");
    if (!db_load_fd) {
        syslog(LOG_ERR, "Was not able to open the file descriptor for the saved database. Path: %s.", path);
        return;
    }

    syslog(LOG_DEBUG, "[db_load] Starting to load saved database from the path: %s.", path);

    char* line_content = NULL;
    int loaded_counter = 0;
    size_t data_length;

    while (getline(&line_content, &data_length, db_load_fd) != EOF) {
        char* key = strtok(line_content, DATABASE_DELIMITER);
        char* raw_score = strtok(NULL, DATABASE_DELIMITER);

        if (!key || !raw_score) {
            continue; // Invalid line in saved database, skipping (missing part)
        }

        if (is_whitelisted(key, db_instance->settings_instance)) {
            syslog(LOG_DEBUG, "[db_load] IP %s was removed from records because is whitelisted.", key);
            continue;
        }

        loaded_counter++;

        errno = 0;
        char* end_ptr;
        int score = strtol(raw_score, &end_ptr, 10);

        if (errno != 0 || end_ptr == raw_score) {
            syslog(LOG_WARNING, "Was not able to load the score from the saved database key: %s. Skipping.", key);
            continue; // Invalid line in database, skipping (parse int problem)
        }
        db_set_with_print(db_instance, key, time(0), score, false);
    }

    if (line_content) {
        free(line_content);
    }

    errno = 0;
    if (fclose(db_load_fd) == EBADF || errno) {
        syslog(LOG_ERR, "Was not able to close the database save file descriptor after loading. Path: %s.", path);
    }

    syslog(LOG_DEBUG, "[db_load] The database was successfully loaded. Loaded: %d.", loaded_counter);
    db_instance->entry_counter = loaded_counter;

    syslog(LOG_DEBUG, "[db_load] Removing old database file.");
    if (remove(path) == -1) {
        syslog(LOG_WARNING, "Was not able to remove the old database file. Path: %s.", path);
    }
}

/* [Thread-Safe] Recursion function for 'db_cleanup_thread' */
void db_cleanup_recursion(entry_t* entry, entry_t* prev_entry, database_t* db_instance, int record_index, int* actual_counter)
{
    if (!entry) {
        return;
    }

    pthread_mutex_lock(&db_instance->mutex_value);
    (*actual_counter)++;
    pthread_mutex_unlock(&db_instance->mutex_value);

    if (difftime(entry->last_email, time(0)) <= db_instance->settings_instance->clean_interval) {
        db_cleanup_recursion(entry->next, entry, db_instance, record_index, actual_counter);
        return;
    }

    email_info_t temp_email_info = {
        0,
        entry->last_email,
        false,
        false,
        false
    };

    int new_score = db_new_score(entry->score, &temp_email_info, db_instance->settings_instance);
    if (new_score <= 0) {
        if (entry->next) {
            db_cleanup_recursion(entry->next, entry, db_instance, record_index, actual_counter);
        }

        pthread_mutex_lock(&db_instance->mutex_value);
        db_instance->entry_counter--;
        pthread_mutex_unlock(&db_instance->mutex_value);

        free(entry->key);

        pthread_mutex_lock(&db_instance->mutex_value);
        if (!prev_entry) {
            db_instance->data[record_index] = entry->next;
        } else {
            prev_entry->next = entry->next;
        }
        pthread_mutex_unlock(&db_instance->mutex_value);

        free(entry);
    } else {
        pthread_mutex_lock(&db_instance->mutex_value);
        entry->last_email = time(0);
        entry->score = new_score;
        pthread_mutex_unlock(&db_instance->mutex_value);

        db_cleanup_recursion(entry->next, entry, db_instance, record_index, actual_counter);
    }
}

/* [Thread-Safe] Cleanup thread */
void* db_cleanup_thread(void* void_database)
{
    syslog(LOG_DEBUG, "[db_cleanup_thread] The cleanup thread was successfully created. Starting cleanup.");
    database_t* db_instance = (database_t*)void_database;
    int actual_counter = 0;

    if (!db_instance) {
        syslog(LOG_WARNING, "Was not able to load the database pointer. Ending cleanup.");
        return NULL;
    }

    int original_counter = db_instance->entry_counter;
    for (int i = 0; i < db_instance->settings_instance->hash_table_size; i++) {
        if (!db_instance->data[i]) {
            continue; // The entry bucket is empty
        }

        if (original_counter <= actual_counter) {
            break; // No more entries in the database
        }

        db_cleanup_recursion(db_instance->data[i], NULL, db_instance, i, &actual_counter);
    }

    syslog(LOG_DEBUG, "[db_cleanup_thread] Cleanup was successful.");
    return NULL;
}

/* [Thread-Safe] Remove old records from the database and update the score */
void db_cleanup(database_t* db_instance)
{
    if (!db_instance || !db_instance->settings_instance) {
        syslog(LOG_WARNING, "Was not able to start cleanup because the database or settings instance is invalid.");
        return;
    }

    int time_diff = difftime(time(0), db_instance->last_clean);
    syslog(LOG_DEBUG, "Time after the last cleanup: %d (seconds).", time_diff);

    if (time_diff <= db_instance->settings_instance->clean_interval) {
        return; // The time difference for cleanup is still under the limit
    }

    pthread_mutex_lock(&db_instance->mutex_value);
    db_instance->last_clean = time(0);
    pthread_mutex_unlock(&db_instance->mutex_value);

    if (db_instance->entry_counter <= 0) {
        syslog(LOG_DEBUG, "[db_cleanup] The database is empty, skipping cleanup.");
        return; // Database is empty
    }

    pthread_t thread_id;
    if (pthread_create(&thread_id, NULL, db_cleanup_thread, db_instance)) {
        syslog(LOG_ERR, "Was not able to create a database cleanup thread.");
        return;
    }

    if (pthread_detach(thread_id)) {
        syslog(LOG_ERR, "Was not able to detach the database cleanup thread.");
        return;
    }
}
