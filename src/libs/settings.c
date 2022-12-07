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
 * FILENAME:	settings.c
 * DESCRIPTION:	Implementation of the config parser for Milter.
 * NOTES:		This lib is part of the MUNI-Milter, and will not work on its own.
 * AUTHOR:		Patrik Čelko
 * REPOSITORY:  https://github.com/patrikcelko/MUNI-Milter
 *
 *****************************************************************************************/

#define _GNU_SOURCE
#define _POSIX_C_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

#include "settings.h"

/* Constants */
static char DEFAULT_PATH[] = "./config.cfg";
static char CONFIG_DELIMITER[] = "=";
static char LIST_DELIMITER = ';';
static int AMOUNT_OF_CONFIG_LINES = 19;

/* [Thread-Safe] Fill the newly created config file with default values */
void fill_empty_config(FILE* config_fd)
{
    fprintf(config_fd, "\
## Run Milter, but do not make any changes during a run. DEFAULT: false\n\
dry_run=false\n\
## Save the whole database and statistics to an external file after the exit call. DEFAULT: true\n\
save_data=true\n\
## The path where should be stored database. Used when 'save_data' is allowed. DEFAULT: ./db.data\n\
database_path=./db.data\n\
## The path where should be stored statistics. Used when 'save_data' is allowed. DEFAULT: ./stat.data\n\
statistics_path=./stat.data\n\
## Limit after which will email possible to mark as super-spam. DEFAULT: 6\n\
super_spam_limit=6\n\
## Limit after which will email possible to mark as spam. DEFAULT: 2\n\
spam_limit=2\n\
## How much info should milter print? DEFAULT: 0 | MAX: 6\n\
milter_debug_level=0\n\
## Size of the hash table where will be stored data about emails. DEFAULT: 2000000\n\
hash_table_size=200000\n\
## Interval after which will be automatically removed the record from the database. DEFAULT: 2400 | 20 min.\n\
clean_interval=2400\n\
## The time after which the record in the database expires. DEFAULT: 600 | 5 min.\n\
max_save_time=600\n\
# How much percent can the difference between the faculty average time and the sender's average which will be categorized as spam? DEFAULT: 50\n\
time_percentage_spam=50\n\
# How much percent can the difference between the faculty average time and the sender's average which will be categorized as super-spam? DEFAULT: 75\n\
time_percentage_super_spam=75\n\
## After how much percent above faculty average should be sender marked to the category spam? DEFAULT: 15\n\
score_percentage_spam=15\n\
## After how much percent above faculty average should be sender marked to the category super-spam? DEFAULT: 30\n\
score_percentage_super_spam=30\n\
## Limit how many times can email pass relay. DEFAULT: 20\n\
forward_counter_limit=20\n\
## After how much percent above the relay average should forward blocked? DEFAULT: 15\n\
forward_percentage_limit=15\n\
## The path where should be stored socket for communication with Sendmail (Do not use the default one). DEFAULT: local:/tmp/f1.sock\n\
socket_path=local:/tmp/f1.sock\n\
## List of blacklisted IP/DNS/emails separated by semicolumn. EXAMPLE: localhost;192.168.0.1;muni.cz;patrik@celko.cz\n\
blacklist=\n\
## List of whitelisted IP/DNS/emails separated by semicolumn. EXAMPLE: localhost;192.168.0.1;muni.cz;patrik@celko.cz\n\
whitelist=\n");
}

/* [Thread-Safe] Get config file descriptor, if the file does not exist create a new one with default values */
FILE* get_config_fd(char* config_path)
{
    syslog(LOG_DEBUG, "[get_config_fd] Trying to open the config file descriptor.");
    char* temp_path = !config_path ? DEFAULT_PATH : config_path;
    struct stat temp_buffer;

    if (stat(temp_path, &temp_buffer) == -1) {
        syslog(LOG_DEBUG, "[get_config_fd] Config file was not found, generating the default one in %s.", temp_path);
        FILE* temp_write_fd = fopen(temp_path, "w+");

        if (!temp_write_fd) {
            syslog(LOG_ERR, "Was not able to create an empty config file. Path: %s.", temp_path);
            return NULL;
        }
        fill_empty_config(temp_write_fd);

        errno = 0;
        if (fflush(temp_write_fd) == EBADF || errno) {
            if (fclose(temp_write_fd) == EBADF || errno) {
                syslog(LOG_ERR, "Was not able to close the temp config file descriptor (from fflush error). Path: %s.", temp_path);
            }
            return NULL;
        }

        errno = 0;
        if (fclose(temp_write_fd) == EBADF || errno) {
            syslog(LOG_ERR, "Was not able to close the temp config file descriptor. Path: %s", temp_path);
            return NULL;
        }
    }
    return fopen(temp_path, "r");
}

/* [Thread-Safe] Verify that the loaded config has the correct values */
bool verify_settings_integrity(settings_t* settings, int assign_counter)
{
    syslog(LOG_DEBUG, "[verify_settings_integrity] Starting to verify settings integrity. (Loaded: %d/%d)", assign_counter, AMOUNT_OF_CONFIG_LINES);

    if (assign_counter != AMOUNT_OF_CONFIG_LINES) {
        syslog(LOG_ERR, "Some values from the config were not loaded properly or were skipped. (Not loaded: %d)", AMOUNT_OF_CONFIG_LINES - assign_counter);
        return false;
    }

    if (settings->save_data && (!settings->database_path || settings->database_path[0] == '\0')) {
        syslog(LOG_ERR, "Database saving is turned on, but the database path is invalid.");
        return false;
    }

    if (settings->save_data && (!settings->statistics_path || settings->statistics_path[0] == '\0')) {
        syslog(LOG_ERR, "Statistics saving is turned on, but the database path is invalid.");
        return false;
    }

    if (settings->time_percentage_spam <= 0 || settings->time_percentage_super_spam <= 0 || settings->score_percentage_spam <= 0 || settings->score_percentage_super_spam <= 0) {
        syslog(LOG_ERR, "Percentage limits must be a positive integer. Now: Time -> (%.0f | %.0f) & Spam -> (%.0f | %.0f)",
            settings->time_percentage_spam * 100, settings->time_percentage_super_spam * 100, settings->score_percentage_spam * 100,
            settings->score_percentage_super_spam * 100);
        return false;
    }

    if (settings->time_percentage_spam >= settings->time_percentage_super_spam || settings->score_percentage_spam >= settings->score_percentage_super_spam) {
        syslog(LOG_ERR, "The percentage for super-spam must be bigger than spam. Now: Time -> (%.0f | %.0f) & Spam -> (%.0f | %.0f)",
            settings->time_percentage_spam * 100, settings->time_percentage_super_spam * 100, settings->score_percentage_spam * 100,
            settings->score_percentage_super_spam * 100);
        return false;
    }

    if (settings->forward_percentage_limit <= 0) {
        syslog(LOG_ERR, "The forward percentage limit must be a positive integer. Now: %.0f.", settings->forward_percentage_limit * 100);
        return false;
    }

    if (settings->forward_counter_limit <= 0) {
        syslog(LOG_ERR, "The forward counter limit must be a positive integer. Now: %d.", settings->forward_counter_limit);
        return false;
    }

    if (settings->super_spam_limit <= 0 || settings->spam_limit <= 0) {
        syslog(LOG_ERR, "The super-spam limit and the spam limit should be positive integers. Now: %d & %d.", settings->super_spam_limit, settings->spam_limit);
        return false;
    }

    if (settings->super_spam_limit <= settings->spam_limit) {
        syslog(LOG_ERR, "The super-spam limit must be bigger than the spam limit. Now: %d & %d.", settings->super_spam_limit, settings->spam_limit);
        return false;
    }

    if (settings->milter_debug_level > 6 || settings->milter_debug_level < 0) {
        syslog(LOG_ERR, "Milter debug level should be in intervals between 0 and 6. Now: %d.", settings->milter_debug_level);
        return false;
    }

    if (!settings->socket_path || settings->socket_path[0] == '\0') {
        syslog(LOG_ERR, "The path to the socket is not correctly defined.");
        return false;
    }

    if (settings->forward_counter_limit <= 1) {
        syslog(LOG_ERR, "The forward counter limit must be a positive integer bigger than 1. Now: %d.", settings->forward_counter_limit);
        return false;
    }

    if (settings->max_save_time <= 0) {
        syslog(LOG_ERR, "The maximally save time for records in DB must be a positive integer. Now: %d.", settings->max_save_time);
        return false;
    }

    if (settings->clean_interval <= 0) {
        syslog(LOG_ERR, "Database clean interval must be a positive integer. Now: %d.", settings->clean_interval);
        return false;
    }

    if (settings->hash_table_size <= 0) {
        syslog(LOG_ERR, "The hash table size should be a positive integer. Now: %d.", settings->hash_table_size);
        return false;
    }

    if (settings->hash_table_size <= 1000) {
        syslog(LOG_WARNING, "The size of the hash table is %d, this makes the database slow (linear access). Higher is better.", settings->hash_table_size);
    }

    if (settings->whitelist_len > 0 && settings->blacklist_len > 0) {
        for (int i_white = 0; i_white < settings->whitelist_len; i_white++) {
            for (int i_black = 0; i_black < settings->blacklist_len; i_black++) {
                if (!strcmp(settings->whitelist[i_white], settings->blacklist[i_black])) {
                    syslog(LOG_ERR, "Address %s was found in the whitelist, but also the blacklist. This is unwanted behavior.", settings->blacklist[i_black]);
                    return false;
                }
            }
        }
    }

    syslog(LOG_DEBUG, "[verify_settings_integrity] Config integrity was successfully verified.");
    return true;
}

/* [Thread-Unsafe] Remove all unwanted white space chars from the config lines */
void remove_white_space(char* string_value)
{
    if (!string_value) {
        return; // Empty string
    }

    char* temp_string_pointer = string_value;
    while (*temp_string_pointer == ' ') {
        temp_string_pointer++;
        if (temp_string_pointer != string_value) {
            memmove(string_value, temp_string_pointer, strlen(temp_string_pointer) + 1);
        }
    }

    size_t str_length = strlen(string_value);
    if (string_value[str_length - 1] == '\n') {
        string_value[str_length - 1] = '\0';
    }
}

/* [Thread-Unsafe] Parse IP/DNS/email lists to more suitable representation */
char** parse_list_value(char* value, char* list_name, int* list_len)
{
    *list_len = 0;

    if (!value) {
        syslog(LOG_DEBUG, "[parse_list_value] There is no IP/DNS/email in %s. Skipping.", list_name);
        return NULL;
    }

    int to_allocate_blocks = 1;
    for (int i = 0; value[i] != '\0'; i++) {
        if (value[i] == LIST_DELIMITER && value[i + 1] != '\0') {
            to_allocate_blocks++;
        }
    }

    if (to_allocate_blocks <= 0) {
        return NULL;
    }

    syslog(LOG_DEBUG, "[parse_list_value] Found %d IP/DNS/email in %s, allocating memory blocks.", to_allocate_blocks, list_name);

    char** list = malloc(sizeof(char*) * to_allocate_blocks);
    if (!list) {
        syslog(LOG_ERR, "Was not abel to allocate memory for %s.", list_name);
        return NULL;
    }

    char delimiter_as_string[2] = "\0";
    delimiter_as_string[0] = LIST_DELIMITER;
    char* pointer = strtok(value, delimiter_as_string);
    int counter = 0;

    while (pointer) {
        list[counter] = strdup(pointer);
        syslog(LOG_DEBUG, "[parse_list_value] Address %s was saved to %s.", list[counter], list_name);
        counter++;
        pointer = strtok(NULL, delimiter_as_string);
    }

    *list_len = to_allocate_blocks;
    return list;
}

/* [Thread-Safe] Get float value from string, if invalid returns -1.0 */
float parse_float_value(char* value, char* key)
{
    errno = 0;
    char* end_ptr;
    float temp_number = (float)strtof(value, &end_ptr);

    if (errno || end_ptr == value) {
        syslog(LOG_ERR, "Was not able to parse float value for the key %s.", key);
        return -1;
    }
    return temp_number;
}

/* [Thread-Safe] Get integer value from string, if invalid returns -1 */
int parse_number_value(char* value, char* key)
{
    errno = 0;
    char* end_ptr;
    int temp_number = (int)strtol(value, &end_ptr, 10);

    if (errno || end_ptr == value) {
        syslog(LOG_ERR, "Was not able to parse integer value for the key %s.", key);
        return -1;
    }
    return temp_number;
}

/* [Thread-Safe] Simple boolean parser from a string */
bool parse_bool_value(char* value)
{
    return !strcmp(value, "true");
}

/* [Thread-Unsafe] Initialize settings structure */
settings_t* settings_init(char* config_path)
{
    FILE* config_fd = get_config_fd(config_path);
    if (!config_fd) {
        syslog(LOG_ERR, "Was not able to open the config file descriptor.");
        return NULL;
    }

    settings_t* settings = malloc(sizeof(settings_t));
    if (!settings) {
        syslog(LOG_ERR, "Was not able to allocate memory for settings structure.");
        return NULL;
    }

    char* line_content = NULL;
    size_t data_length;

    syslog(LOG_DEBUG, "[settings_init] The file descriptor for the config was successfully created.");

    settings->dry_run = false;
    settings->save_data = false;
    settings->database_path = NULL;
    settings->super_spam_limit = 0;
    settings->spam_limit = 0;
    settings->milter_debug_level = 0;
    settings->hash_table_size = 0;
    settings->clean_interval = 0;
    settings->max_save_time = 0;
    settings->time_percentage_spam = 0;
    settings->time_percentage_super_spam = 0;
    settings->score_percentage_spam = 0;
    settings->score_percentage_super_spam = 0;
    settings->forward_counter_limit = 0;
    settings->forward_percentage_limit = 0;
    settings->socket_path = NULL;
    settings->statistics_path = NULL;
    settings->blacklist = NULL;
    settings->whitelist = NULL;
    settings->blacklist_len = 0;
    settings->whitelist_len = 0;

    syslog(LOG_DEBUG, "[settings_init] Starting to parse the config file.");
    int assign_counter = 0;
    while (getline(&line_content, &data_length, config_fd) != EOF) {
        remove_white_space(line_content);

        if (line_content[0] == '#') {
            free(line_content);
            data_length = 0;
            continue; // Comment was found, skipping line
        }

        char* key = strtok(line_content, CONFIG_DELIMITER);
        char* value = strtok(NULL, CONFIG_DELIMITER);

        syslog(LOG_DEBUG, "[settings_init] Key %s was found in the config with value %s.", key, value);

        if (!strcmp(key, "score_percentage_super_spam")) {
            settings->score_percentage_super_spam = parse_float_value(value, key) / 100;
        } else if (!strcmp(key, "score_percentage_spam")) {
            settings->score_percentage_spam = parse_float_value(value, key) / 100;
        } else if (!strcmp(key, "time_percentage_super_spam")) {
            settings->time_percentage_super_spam = parse_float_value(value, key) / 100;
        } else if (!strcmp(key, "time_percentage_spam")) {
            settings->time_percentage_spam = parse_float_value(value, key) / 100;
        } else if (!strcmp(key, "max_save_time")) {
            settings->max_save_time = parse_number_value(value, key);
        } else if (!strcmp(key, "forward_percentage_limit")) {
            settings->forward_percentage_limit = parse_float_value(value, key) / 100;
        } else if (!strcmp(key, "clean_interval")) {
            settings->clean_interval = parse_number_value(value, key);
        } else if (!strcmp(key, "forward_counter_limit")) {
            settings->forward_counter_limit = parse_number_value(value, key);
        } else if (!strcmp(key, "dry_run")) {
            settings->dry_run = parse_bool_value(value);
        } else if (!strcmp(key, "save_data")) {
            settings->save_data = parse_bool_value(value);
        } else if (!strcmp(key, "super_spam_limit")) {
            settings->super_spam_limit = parse_number_value(value, key);
        } else if (!strcmp(key, "spam_limit")) {
            settings->spam_limit = parse_number_value(value, key);
        } else if (!strcmp(key, "milter_debug_level")) {
            settings->milter_debug_level = parse_number_value(value, key);
        } else if (!strcmp(key, "hash_table_size")) {
            settings->hash_table_size = parse_number_value(value, key);
        } else if (!strcmp(key, "database_path")) {
            settings->database_path = strdup(value);
        } else if (!strcmp(key, "statistics_path")) {
            settings->statistics_path = strdup(value);
        } else if (!strcmp(key, "socket_path")) {
            settings->socket_path = strdup(value);
        } else if (!strcmp(key, "blacklist")) {
            settings->blacklist = parse_list_value(value, "blacklist", &(settings->blacklist_len));
        } else if (!strcmp(key, "whitelist")) {
            settings->whitelist = parse_list_value(value, "whitelist", &(settings->whitelist_len));
        } else {
            syslog(LOG_WARNING, "Found an unknown key in the config file: %s. Skipping.", key);
            continue;
        }
        assign_counter++;
    }

    if (line_content) {
        free(line_content);
    }

    errno = 0;
    if (fclose(config_fd) == EBADF || errno) {
        syslog(LOG_WARNING, "Was not able to close the file descriptor after settings initialization. Skipping.");
    }

    syslog(LOG_DEBUG, "[settings_init] Config parsing was successful.");
    if (verify_settings_integrity(settings, assign_counter)) {
        return settings;
    }

    syslog(LOG_DEBUG, "[settings_init] Settings initialization failed, cleaning resources.");
    settings_destroy(settings);
    return NULL;
}

/* [Thread-Safe] Destroy settings structure */
void settings_destroy(settings_t* settings)
{
    syslog(LOG_DEBUG, "[settings_destroy] Destroying setting structure and freeing resources.");
    if (settings) {
        free(settings->database_path);
        free(settings->statistics_path);
        free(settings->socket_path);

        if(!settings->blacklist) {
            for (int i = 0; i < settings->blacklist_len; i++) {
                free(settings->blacklist[i]);
            }
            free(settings->blacklist);
        }

        if(!settings->whitelist) {
            for (int i = 0; i < settings->whitelist_len; i++) {
                free(settings->whitelist[i]);
            }
            free(settings->whitelist);
        }
    }

    free(settings);
    syslog(LOG_DEBUG, "[settings_destroy] The setting structure was successfully destroyed.");
}

/* [Thread-Safe] Get IP from DNS (Alternative: gethostbyname) */
char* IP_from_DNS(char* dns_name)
{
    if (!dns_name) {
        return NULL;
    }

    struct addrinfo* server_info;
    char* return_value = NULL;
    struct addrinfo* pointer;

    struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_RAW
    };

    if (getaddrinfo(dns_name, NULL, &hints, &server_info) != 0) {
        syslog(LOG_DEBUG, "[IP_from_DNS] Was not able to get the address info. DNS: %s.", dns_name);
        return NULL;
    }

    for (pointer = server_info; pointer != NULL; pointer = pointer->ai_next) {
        return_value = strdup(inet_ntoa(((struct sockaddr_in*)pointer->ai_addr)->sin_addr));
        break;
    }

    freeaddrinfo(server_info);
    if (return_value) {
        syslog(LOG_DEBUG, "[IP_from_DNS] Was able to get IP %s for DNS %s.", return_value, dns_name);
    }
    return return_value;
}

/* [Thread-Safe] Check if the string is IP (true) or DNS name (false) */
bool is_IP(char* address)
{
    struct sockaddr_in socket_address;
    return inet_pton(AF_INET, address, &(socket_address.sin_addr)) || inet_pton(AF_INET6, address, &(socket_address.sin_addr));
}

/* [Thread-Safe] Check if two IPs / DNS names are the same or similar (subdomain) */
bool contains_subaddress(char* address_A, char* address_B)
{
    if (!address_A || !address_B) {
        return false;
    }

    bool is_IP_address_B = is_IP(address_B);
    bool is_IP_address_A = is_IP(address_A);

    if (is_IP_address_B && is_IP_address_A) {
        return !strcmp(address_A, address_B);
    } else if (!is_IP_address_B && is_IP_address_A) {
        char* temp_DNS_pointer = IP_from_DNS(address_B);
        bool return_value = temp_DNS_pointer && !strcmp(temp_DNS_pointer, address_A);
        free(temp_DNS_pointer);
        return return_value;
    } else if (is_IP_address_B && !is_IP_address_A) {
        char* temp_DNS_pointer = IP_from_DNS(address_A);
        bool return_value = temp_DNS_pointer && !strcmp(temp_DNS_pointer, address_B);
        free(temp_DNS_pointer);
        return return_value;
    }

    if (strlen(address_B) >= strlen(address_A)) {
        return false;
    }

    char* end_pointer = address_A + (strlen(address_A) - strlen(address_B));
    if (end_pointer - 1 >= address_A && *(end_pointer - 1) != '.') {
        return false;
    }
    return !strcmp(address_B, end_pointer);
}

/* [Thread-Safe] Compare the email DNS part if matches with the domain in the whitelist/blacklist */
bool cmp_email_dns(char* address, char* domain)
{
    strtok(address, "@"); // User part, which can we just ignore
    char* email_domain_part = strtok(NULL, "@");
    char* other = strtok(NULL, "@");

    if (other || !email_domain_part) {
        return false; // Invalid email
    }

    return contains_subaddress(email_domain_part, domain);
}

/* [Thread-Safe] Abstraction for functions 'is_whitelisted' and 'is_blacklisted' */
bool contains_address(char* address, int array_length, char** array, char* array_name)
{
    syslog(LOG_DEBUG, "[check_if_array_contains] Checking if IP/DNS/email %s is in %s (%d)", 
        address, array_name, array_length);
    for (int i = 0; i < array_length; i++) {
        syslog(LOG_DEBUG, "Validating %s with our %s in %s.", address, array[i], array_name);
        if (!strcmp(address, array[i]) || contains_subaddress(address, array[i]) || cmp_email_dns(address, array[i])) {
            syslog(LOG_DEBUG, "[check_if_array_contains] IP/DNS/email %s was found in %s.", address, array_name);
            return true;
        }
    }
    return false;
}

/* [Thread-Safe] Check if the address is on the whitelist */
bool is_whitelisted(char* address, settings_t* settings)
{
    return contains_address(address, settings->whitelist_len, settings->whitelist, "whitelist");
}

/* [Thread-Safe] Check if the address is on the blacklist */
bool is_blacklisted(char* address, settings_t* settings)
{
    return contains_address(address, settings->blacklist_len, settings->blacklist, "blacklist");
}
