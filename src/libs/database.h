/*************************************************************************************
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
***************************************************************************************/

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
    char* key; // The hash value of the sender
    time_t last_email; // The time when the last email was sent
    int email_count; // The total amount of emails for the selected sender
    float average_time; // The average time between sending emails for the selected sender
    float average_score; // Average spam score for the selected sender
    struct entry* next; // Next entry if the hash match
};

/* Database structure */
struct database {
    struct entry** data;
    pthread_mutex_t mutex_value;
    time_t last_clean;
    settings_t* settings_instance;
    int entry_counter;
};

typedef struct entry entry_t;
typedef struct database database_t;

/* [Thread-Unsafe] Construct database structure */
database_t* db_construct(pthread_mutex_t mutex_value, settings_t* settings);

/* [Thread-Unsafe] Destroy database structure */
void db_destroy(database_t* db_instance);

/* [Thread-Safe] Get an entry from the database (if does not exist create a new one) */
entry_t* db_get(database_t* db_instance, char* ip_to_search);

/* [Thread-Unsafe] Save the whole database to file */
void db_save(database_t* db_instance);

/* [Thread-Unsafe] Load database from local path/file */
void db_load(database_t* db_instance);

/* [Thread-Safe] Remove old records from the database and update the score */
void db_cleanup(database_t* db_instance);

#endif
