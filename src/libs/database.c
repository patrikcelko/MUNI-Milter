/*****************************************************************************************
 * Copyright [2022] [Patrik Čelko]
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under
 * the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 *
 *****************************************************************************************/

/********************************** MUNI - Milter ****************************************
 *
 * FILENAME:	database.c
 * DESCRIPTION:	Implementation of the database for Milter.
 * NOTES:		This lib is part of the MUNI-Milter, and will not work on its own.
 * AUTHOR:		Patrik Čelko
 *
 *****************************************************************************************/

#define _GNU_SOURCE
#define _POSIX_C_SOURCE

#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#include "database.h"

/* Constants */
static char DATABASE_DELIMITER[] = ",";

/* [Thread-Safe] This function (djb2) was inspired by http://www.cse.yorku.ca/~oz/hash.html */
unsigned int djb2_hash(const char* key, int table_size)
{
    unsigned int hash_value = 5381;
    int c;

    while ((c = *key++)) {
        hash_value = (hash_value << 5) + hash_value;
        hash_value += !isupper(c) ? c : c + 32;
    }
    return hash_value % table_size;
}

/* [Thread-Unsafe] Construct database structure */
database_t* db_construct(pthread_mutex_t mutex_value, settings_t* settings)
{
    if (!settings) {
        syslog(LOG_ERR, "Was not able to construct a database without settings an instance.");
        return NULL;
    }

    syslog(LOG_DEBUG, "[db_construct] Database initialization started. Hash table size: %d", settings->hash_table_size);

    database_t* db_instance = malloc(sizeof(database_t));
    if (!db_instance) {
        syslog(LOG_ERR, "Was not able to allocate memory for the database instance.");
        return NULL;
    }

    db_instance->data = malloc(sizeof(entry_t*) * settings->hash_table_size);
    if (!db_instance->data) {
        syslog(LOG_ERR, "Was not able to allocate memory for the database hash table.");
        free(db_instance); // Reclaim struct memory
        return NULL;
    }

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
            break; // The database should be now empty
        }
    }

    free(db_instance->data);
    free(db_instance);

    syslog(LOG_DEBUG, "[db_destroy] The database was successfully removed from memory.");
}

/* [Thread-Safe] Create a new entry in the database */
entry_t* create_new_entry(char* key, database_t* db_instance)
{
    syslog(LOG_DEBUG, "[create_new_entry] Space was found, creating a record. Key: %s.", key);

    pthread_mutex_lock(&db_instance->mutex_value);
    entry_t* entry = malloc(sizeof(entry_t));
    if (!entry) {
        syslog(LOG_ERR, "Was not able to allocate memory for entry. Key: %s.", key);
        return NULL;
    }

    entry->key = malloc(strlen(key) + 1);
    if (!entry->key) {
        syslog(LOG_ERR, "Was not able to allocate memory for the key value. Key: %s.", key);
        free(entry);
        return NULL;
    }

    strcpy(entry->key, key); // Save the key (address) to our struct

    entry->last_email = 0;
    entry->email_count = 0;
    entry->average_time = 0;
    entry->average_score = 0;
    entry->next = NULL;

    db_instance->entry_counter++;
    pthread_mutex_unlock(&db_instance->mutex_value);

    syslog(LOG_DEBUG, "[create_new_entry] The record was successfully created. Key: %s.", key);
    return entry;
}

/* [Thread-Safe] Recursion function for 'db_get' */
entry_t* get_entry_recursion(entry_t* entry, char* addr_to_search, database_t* db_instance)
{
    if (!strcmp(entry->key, addr_to_search)) {
        syslog(LOG_DEBUG, "[get_entry_recursion] The record for key %s was successfully found.", addr_to_search);
        return entry;
    }

    if (entry->next) {
        return get_entry_recursion(entry->next, addr_to_search, db_instance);
    }

    syslog(LOG_DEBUG, "[get_entry_recursion] Was not able to find key %s (out of buckets).", addr_to_search);

    entry->next = create_new_entry(addr_to_search, db_instance);
    return entry->next;
}

/* [Thread-Safe] Get an entry from the database (if does not exist create a new one) */
entry_t* db_get(database_t* db_instance, char* addr_to_search)
{
    if (!addr_to_search || !db_instance) {
        syslog(LOG_WARNING, "Database getter received invalid key or database instance.");
        return NULL;
    }

    unsigned int record_index = djb2_hash(addr_to_search, db_instance->settings_instance->hash_table_size);
    syslog(LOG_DEBUG, "[db_get] Starting to search for key %s with hash %u.", addr_to_search, record_index);

    entry_t* entry = db_instance->data[record_index];
    if (!entry) {
        syslog(LOG_DEBUG, "[db_get] The record for key %s does not exist (the first bucket does not exist).", addr_to_search);
        entry = create_new_entry(addr_to_search, db_instance);
        db_instance->data[record_index] = entry;
        return entry;
    }
    return get_entry_recursion(entry, addr_to_search, db_instance);
}

/* [Thread-Unsafe] Recursion function for 'db_save_recusrion' */
void db_save_recusrion(entry_t* entry, int* saved_lines, FILE* db_save_fd, settings_t* settings)
{
    if (!entry) {
        return;
    }

    // Save only records that are not too old
    if (fabs((float)difftime(time(0), entry->last_email)) < settings->max_save_time) {
        fprintf(db_save_fd, "%s%s%d%s%.4f%s%.2f\n", entry->key, DATABASE_DELIMITER, entry->email_count,
            DATABASE_DELIMITER, entry->average_time, DATABASE_DELIMITER, entry->average_score);
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
        syslog(LOG_WARNING, "There was a problem during saving the database to the file. Saved: %d/%d.", saved_lines, db_instance->entry_counter);
    }
}

/* [Thread-Unsafe] Save one line from the file to the database if valid */
bool save_entry_line(char *line_content, database_t *db_instance) 
{
    char* key = strtok(line_content, DATABASE_DELIMITER);
    char* raw_email_count = strtok(NULL, DATABASE_DELIMITER);
    char* raw_average_time = strtok(NULL, DATABASE_DELIMITER);
    char* raw_average_score = strtok(NULL, DATABASE_DELIMITER);

    if (!key || !raw_email_count || !raw_average_time || !raw_average_score) {
        return false; // Invalid line in saved database
    }

    if (is_whitelisted(key, db_instance->settings_instance)) {
        syslog(LOG_DEBUG, "[db_load] IP %s was removed from records because is whitelisted.", key);
        return false;
    }
    errno = 0;

    // Parse email_count as integer
    char* email_count_end;
    int email_count = strtol(raw_email_count, &email_count_end, 10);

    // Parse average_time as float
    char* average_time_end;
    int average_time = strtof(raw_average_time, &average_time_end);

    // Parse average_score as float
    char* average_score_end;
    int average_score = strtof(raw_average_score, &average_score_end);

    if (errno != 0 || email_count_end == raw_email_count || average_time_end == raw_average_time || average_score_end == raw_average_score) {
        syslog(LOG_WARNING, "Was not able to load the email_conut, average_time, or average_score from the saved database key: %s. Skipping.", key);
        return false; // Invalid line in database, skipping (parsing error)
    }

    entry_t* entry = db_get(db_instance, key);
    if (!entry) {
        syslog(LOG_WARNING, "Was not able to get an entry for %s, during loading from file.", key);
        return false;
    }

    entry->last_email = time(0);
    entry->email_count = email_count;
    entry->average_time = average_time;
    entry->average_score = average_score;

    return true;
}

/* [Thread-Unsafe] Load database from local path/file */
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
        if(save_entry_line(line_content, db_instance)) {
            loaded_counter++;
        }
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

    syslog(LOG_DEBUG, "[db_load] Removing old database files.");
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

    if (fabs((float)difftime(entry->last_email, time(0))) < db_instance->settings_instance->max_save_time) {
        db_cleanup_recursion(entry->next, entry, db_instance, record_index, actual_counter);
        return;
    }

    pthread_mutex_lock(&db_instance->mutex_value);
    
    free(entry->key);
    db_instance->entry_counter--;
    
    if (!prev_entry) {
        db_instance->data[record_index] = entry->next;
    } else {
        prev_entry->next = entry->next;
    }
    pthread_mutex_unlock(&db_instance->mutex_value);

    db_cleanup_recursion(entry->next, !prev_entry ? db_instance->data[record_index] : prev_entry, db_instance, record_index, actual_counter);

    pthread_mutex_lock(&db_instance->mutex_value);
    free(entry);
    pthread_mutex_unlock(&db_instance->mutex_value);
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

    float time_diff = fabs((float)difftime(time(0), db_instance->last_clean));
    syslog(LOG_DEBUG, "[db_cleanup] Time after the last cleanup: %.0f (seconds).", time_diff);

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
