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
 * FILENAME:	settings.h
 * DESCRIPTION:	Header file for the config parser for Milter.
 * NOTES:		This lib is part of the MUNI-Milter, and will not work on its own.
 * AUTHOR:		Patrik Čelko
 *
 *****************************************************************************************/

#ifndef SETTINGS_H
#define SETTINGS_H

/* Settings structure */
struct settings {
    bool dry_run; // DEFAULT: false
    bool save_data; // DEFAULT: true
    char* database_path; // DEFAULT: ./db.data
    char* statistics_path; // DEFAULT: ./stat.data
    int super_spam_limit; // DEFAULT: 20
    int spam_limit; // DEFAULT: 12
    int milter_debug_level; // DEFAULT: 0 | MAX: 6
    int hash_table_size; // DEFAULT: 2000000
    int clean_interval; // DEFAULT: 2400 | 20 min.
    int max_save_time; // DEFAULT: 600 | 5 min.
    float time_percentage_spam; // DEFAULT: 50 (%)
    float time_percentage_super_spam; // DEFAULT: 75 (%)
    float score_percentage_spam; // DEFAULT: 15 (%)
    float score_percentage_super_spam; // DEFAULT: 35 (%)
    int forward_counter_limit; // DEFAULT: 20
    float forward_percentage_limit; // DEFAULT: 15 (%)
    char* socket_path; // DEFAULT: local:/tmp/f1.sock
    char** blacklist; // DEFAULT: [] | PRIVATE
    char** whitelist; // DEFAULT: [] | PRIVATE
    int blacklist_len; // PRIVATE
    int whitelist_len; // PRIVATE
};

typedef struct settings settings_t;

/* [Thread-Unsafe] Initialize settings structure */
settings_t* settings_init(char* config_path);

/* [Thread-Safe] Destroy settings structure */
void settings_destroy(settings_t* settings);

/* [Thread-Safe] Check if the address is on the whitelist */
bool is_whitelisted(char* address, settings_t* settings);

/* [Thread-Safe] Check if the address is on the blacklist */
bool is_blacklisted(char* address, settings_t* settings);

#endif
