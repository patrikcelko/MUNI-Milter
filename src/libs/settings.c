/********************************** MUNI - Milter ***********************************
 *
 * FILENAME:	settings.c
 * DESCRIPTION:	Implementation of the config parser for milter.
 * NOTES:		This lib is part of the MUNI-Milter, and will not work on its own.
 * AUTHOR:		Patrik Čelko
 *
 *************************************************************************************/

#define _GNU_SOURCE

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
static int AMOUNT_OF_CONFIG_LINES = 15;

/* [Thread-Safe] Fill the newly created config file with default values */
void fill_empty_config(FILE* config_fd)
{
    fprintf(config_fd, "\
## Limit how many times an email pass relay. DEFAULT: 50\n\
forward_counter_limit=50\n\
## During milter exit print milter statistics (how many emails was parsed/banned). DEFAULT: true\n\
allow_statistics=true\n\
## Run milter, but do not make any change during a run. DEFAULT: false\n\
dry_run=false\n\
## Save database to external file after exit. DEFAULT: true\n\
save_database=true\n\
## Interval after which will be automatically removed the record from the database. DEFAULT: 600 | 5 min.\n\
clean_interval=600\n\
## Limit for marking email as super-spam. DEFAULT: 15\n\
super_spam_limit=15\n\
## Limit for marking email as basic spam. DEFAULT: 10\n\
basic_spam_limit=10\n\
## How much info should milter print? DEFAULT: 0 | MAX: 6\n\
milter_debug_level=0\n\
## Size of the hash table where will be stored statistics about emails. DEFAULT: 2000000\n\
hash_table_size=200000\n\
## The path where should be stored statistic database. Used when 'save_database' is allowed. DEFAULT: ./db.data\n\
database_path=./db.data\n\
## The path where should be stored socket for communication with sendmail. DEFAULT: local:/tmp/f1.sock\n\
socket_path=local:/tmp/f1.sock\n\
## Limit after which will email always be rejected (send to quarantine). DEFAULT: 420\n\
hard_score_limit=420\n\
## Limit after which will record in the database be saved for two times longer. DEFAULT: 250\n\
soft_score_limit=250\n\
## List of blacklisted IP/DNS separated by semicolumn. EXAMPLE: localhost;192.168.0.1;muni.cz\n\
blacklist=\n\
## List of whitelisted IP/DNS separated by semicolumn. EXAMPLE: localhost;192.168.0.1;muni.cz\n\
whitelist=\n");
}

/* [Thread-Safe] Get config file descriptor, if does not exist create a new one with default values */
FILE* get_config_fd(char* config_path)
{
    syslog(LOG_DEBUG, "[get_config_fd] Trying to open config file descriptor.");
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

/* [Thread-Safe] Verify that the loaded config has correct values */
bool verify_settings_integrity(settings_t* settings, int assign_counter)
{
    syslog(LOG_DEBUG, "[verify_settings_integrity] Starting to verify settings integrity. (Loaded: %d/%d)", assign_counter, AMOUNT_OF_CONFIG_LINES);

    if (assign_counter != AMOUNT_OF_CONFIG_LINES) {
        syslog(LOG_ERR, "Some values from the config were not loaded properly or were skipped. (Not loaded: %d)", AMOUNT_OF_CONFIG_LINES - assign_counter);
        return false;
    }

    if (settings->save_database && (!settings->database_path || settings->database_path[0] == '\0')) {
        syslog(LOG_ERR, "Database saving is turned on, but the database path is invalid.");
        return false;
    }

    if (settings->forward_counter_limit <= 0) {
        syslog(LOG_ERR, "The forward counter limit must be a positive integer. Now: %d.", settings->forward_counter_limit);
        return false;
    }

    if (settings->super_spam_limit <= 0 || settings->basic_spam_limit <= 0) {
        syslog(LOG_ERR, "The super-spam limit and basic spam limit should be a positive integer. Now: %d & %d.", settings->super_spam_limit, settings->basic_spam_limit);
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

    if (settings->soft_score_limit <= 0 || settings->hard_score_limit <= 0) {
        syslog(LOG_ERR, "The soft and hard score limits must be a positive integer. Now: %d - %d.", settings->soft_score_limit, settings->hard_score_limit);
        return false;
    }

    if (settings->soft_score_limit >= settings->hard_score_limit) {
        syslog(LOG_ERR, "The hard score limit must be greater than the soft score limit. Now: %d !> %d.", settings->soft_score_limit, settings->hard_score_limit);
        return false;
    }

    if (settings->clean_interval <= 0) {
        syslog(LOG_ERR, "Database clean interval must be a positive integer. Now: %d.", settings->clean_interval);
        return false;
    }

    if (settings->hash_table_size <= 0) {
        syslog(LOG_ERR, "Hash table size should be a positive integer. Now: %d.", settings->hash_table_size);
        return false;
    }

    if (settings->hash_table_size <= 1000) {
        syslog(LOG_WARNING, "The size of the hash table is %d, this makes the database slow (linear access). Higher is better.", settings->hash_table_size);
    }

    if (settings->whitelist && settings->blacklist) {
        for (int i_white = 0; i_white <= settings->whitelist_len; i_white++) {
            for (int i_black = 0; i_black <= settings->blacklist_len; i_black++) {
                if (!strcmp(settings->whitelist[i_white], settings->blacklist[i_black])) {
                    syslog(LOG_ERR, "IP %s was found in the white-list, but also in the black-list. This is unwanted behaviour.", settings->blacklist[i_black]);
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

/* [Thread-Unsafe] Parse IP/DNS lists to more suitable representation */
char** parse_list_value(char* value, char* list_name, int* list_len)
{
    *list_len = 0; // Default/Empty value

    if (!value) {
        syslog(LOG_DEBUG, "[parse_list_value] There is no IP/DNS in %s. Skipping.", list_name);
        return NULL;
    }

    int to_allocate_blocks = 0;
    for (int i = 0; value[i] != '\0'; i++) {
        if (value[i] == LIST_DELIMITER && value[i + 1] != '\0') {
            to_allocate_blocks++;
        }
    }

    if (to_allocate_blocks <= 0) {
        return NULL;
    }

    syslog(LOG_DEBUG, "[parse_list_value] Found %d IP/DNS in %s, allocating memory blocks.", to_allocate_blocks, list_name);

    char** list = malloc(sizeof(char*) * to_allocate_blocks);
    char delimiter_as_string[2] = "\0";
    delimiter_as_string[0] = LIST_DELIMITER;
    char* pointer = strtok(value, delimiter_as_string);
    int counter = 0;

    while (pointer) {
        list[counter] = strdup(pointer);
        syslog(LOG_DEBUG, "[parse_list_value] IP %s was saved to %s.", list[counter], list_name);
        counter++;
        pointer = strtok(NULL, delimiter_as_string);
    }

    *list_len = to_allocate_blocks;
    return list;
}

/* [Thread-Safe] Get int value from string, if invalid returns -1 */
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

/* [Thread-Unsafe] Initialise settings structure */
settings_t* settings_init(char* config_path)
{
    FILE* config_fd = get_config_fd(config_path);
    if (!config_fd) {
        syslog(LOG_ERR, "Was not able to open the config file descriptor.");
        return NULL;
    }

    settings_t* settings = malloc(sizeof(settings_t));
    char* line_content = NULL;
    size_t data_length;

    syslog(LOG_DEBUG, "[settings_init] The file descriptor for config was successfully created.");

    // Setting as "empty" values
    settings->forward_counter_limit = 0;
    settings->dry_run = false;
    settings->allow_statistics = false;
    settings->save_database = false;
    settings->super_spam_limit = 0;
    settings->basic_spam_limit = 0;
    settings->milter_debug_level = 0;
    settings->hash_table_size = 0;
    settings->database_path = NULL;
    settings->socket_path = NULL;
    settings->blacklist = NULL;
    settings->whitelist = NULL;
    settings->clean_interval = 0;
    settings->soft_score_limit = 0;
    settings->hard_score_limit = 0;
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

        if (!strcmp(key, "allow_statistics")) {
            settings->allow_statistics = parse_bool_value(value);
        } else if (!strcmp(key, "hard_score_limit")) {
            settings->hard_score_limit = parse_number_value(value, key);
        } else if (!strcmp(key, "soft_score_limit")) {
            settings->soft_score_limit = parse_number_value(value, key);
        } else if (!strcmp(key, "clean_interval")) {
            settings->clean_interval = parse_number_value(value, key);
        } else if (!strcmp(key, "forward_counter_limit")) {
            settings->forward_counter_limit = parse_number_value(value, key);
        } else if (!strcmp(key, "dry_run")) {
            settings->dry_run = parse_bool_value(value);
        } else if (!strcmp(key, "save_database")) {
            settings->save_database = parse_bool_value(value);
        } else if (!strcmp(key, "super_spam_limit")) {
            settings->super_spam_limit = parse_number_value(value, key);
        } else if (!strcmp(key, "basic_spam_limit")) {
            settings->basic_spam_limit = parse_number_value(value, key);
        } else if (!strcmp(key, "milter_debug_level")) {
            settings->milter_debug_level = parse_number_value(value, key);
        } else if (!strcmp(key, "hash_table_size")) {
            settings->hash_table_size = parse_number_value(value, key);
        } else if (!strcmp(key, "database_path")) {
            settings->database_path = strdup(value);
        } else if (!strcmp(key, "socket_path")) {
            settings->socket_path = strdup(value);
        } else if (!strcmp(key, "blacklist")) {
            settings->blacklist = parse_list_value(value, "blacklist", &(settings->blacklist_len));
        } else if (!strcmp(key, "whitelist")) {
            settings->whitelist = parse_list_value(value, "whitelist", &(settings->whitelist_len));
        } else {
            syslog(LOG_WARNING, "Found unknown key in the config file: %s. Skipping.", key);
            continue;
        }
        assign_counter++;
    }

    if (line_content) {
        free(line_content);
    }

    errno = 0;
    if (fclose(config_fd) == EBADF || errno) {
        syslog(LOG_WARNING, "Was not able to close the file descriptor after settings initialisation. Skipping.");
    }

    syslog(LOG_DEBUG, "[settings_init] Config parsing was successful.");
    if (verify_settings_integrity(settings, assign_counter)) {
        return settings;
    }

    syslog(LOG_DEBUG, "[settings_init] Settings initialisation failed cleaning resources.");
    settings_destroy(settings);
    return NULL;
}

/* [Thread-Safe] Destroy settings structure */
void settings_destroy(settings_t* settings)
{
    syslog(LOG_DEBUG, "[settings_destroy] Destroying setting structure and freeing resources.");
    if (settings) {
        free(settings->database_path);
        free(settings->socket_path);

        for (int i = 0; i < settings->blacklist_len; i++) {
            free(settings->blacklist[i]);
        }
        free(settings->blacklist);

        for (int i = 0; i < settings->whitelist_len; i++) {
            free(settings->whitelist[i]);
        }
        free(settings->whitelist);
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
        syslog(LOG_DEBUG, "[IP_from_DNS] Was not able to get address info. DNS: %s.", dns_name);
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

/* [Thread-Safe] Abstraction for functions 'is_whitelisted' and 'is_blacklisted' */
bool contains_address(char* address, int array_length, char** array, char* array_name)
{
    syslog(LOG_DEBUG, "[check_if_array_contains] Checking if IP or DNS %s is in %s", address, array_name);
    for (int i = 0; i < array_length; i++) {
        if (!strcmp(address, array[i]) || contains_subaddress(address, array[i])) {
            syslog(LOG_DEBUG, "[check_if_array_contains] IP/DNS %s was found in %s.", address, array_name);
            return true;
        }
    }
    return false;
}

/* [Thread-Safe] Check if IP is in the whitelist */
bool is_whitelisted(char* address, settings_t* settings)
{
    return contains_address(address, settings->whitelist_len, settings->whitelist, "whitelist");
}

/* [Thread-Safe] Check if IP is in the blacklist */
bool is_blacklisted(char* address, settings_t* settings)
{
    return contains_address(address, settings->blacklist_len, settings->blacklist, "blacklist");
}
