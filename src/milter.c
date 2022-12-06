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

/*****************************************************************************************
 *
 * FILENAME:    milter.c
 * DESCRIPTION: Implementation of the Milter.
 * NOTES:       This Milter will need additional libs (settings, database) to run.
 * AUTHOR:      Patrik Čelko
 *
*****************************************************************************************/

#define _GNU_SOURCE
#define _POSIX_C_SOURCE

#include <errno.h>
#include <getopt.h>
#include <libmilter/mfapi.h>
#include <libmilter/mfdef.h>
#include <math.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sysexits.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <regex.h>

#include "libs/database.h"
#include "libs/settings.h"
#include "milter.h"

/* Constants */
static char VERSION[] = "1.2.0";
static char AUTHOR[] = "Patrik Celko"; // Email headers do not like 'Č'
static char MILTER_NAME[] = "MUNI-Milter";
static char OPTSTRING[] = "hVvdc:";
static bool ALLOW_REPLY = true; // This can be set to false to not send reply messages about quarantine
static char STATISTICS_DELIMITER[] = ";";

/* Headers names */
static char HEADER_FORWARD_COUNTER[] = "X-MUNI-Forward-Counter"; // HEADER: Trip counter
static char HEADER_FROM[] = "X-MUNI-From"; // HEADER: Sender email
static char HEADER_TO[] = "X-MUNI-To"; // HEADER: Recipient email
static char HEADER_QUARANTINE[] = "X-MUNI-Quarantine"; // HEADER: Should email go to quarantine?
static char HEADER_INFO[] = "X-MUNI-Info"; // HEADER: Information about milter
static char HEADER_IS_AUTH[] = "X-MUNI-Auth"; // HEADER: Is the user authenticated?
static char HEADER_IS_FORWARD[] = "X-MUNI-Forward"; // HEADER: Is it forward?
static char HEADER_SPAM[] = "X-Spam-Status"; // HEADER: X-Spam-Flag will be yes if > 5
static char HEADER_IS_LOCAL[] = "X-MUNI-Local"; // HEADER: Is it in the MUNI network?
static char HEADER_SUBJECT[] = "Subject"; // HEADER: Email subject
static char HEADER_ID[] = "Message-Id"; // HEADER: Email ID
static char HEADER_SPECIAL[] = "X-MUNI-Special"; // HEADER: BLACKLISTED / WHITELISTED

/* Thread MUTEX used throughout the whole implementation */
static pthread_mutex_t DATA_MUTEX = PTHREAD_MUTEX_INITIALIZER;

/* Global structures */
static settings_t* SETTINGS;
static database_t* DATABASE;
static statistics_t* STATISTICS;

/* Other global variables */
static sigset_t SIGNALS_SET;
static options_t OPTIONS = { 0 };

/* Regex to match any MUNI email: .+\@(.+\.{1})*muni\.cz */
static regex_t MUNI_MAIL_REGEX = { 0 }; 

/* Available options */
static struct option longopts[] = {
    { .val = 'h', .name = "help" },
    { .val = 'V', .name = "version" },
    { .val = 'v', .name = "verbose" },
    { .val = 'c', .name = "config" },
    { .val = 'd', .name = "daemon" },
    { 0 },
};

/* Milter structure */
struct smfiDesc milter_struct = {
    MILTER_NAME,
    SMFI_VERSION,
    SMFIF_ADDHDRS | SMFIF_QUARANTINE | SMFIF_CHGBODY | SMFIF_CHGHDRS,
    mlfi_connect,
    NULL, // Not-Used: HELO command, not reliable
    mlfi_envfrom,
    mlfi_envrcpt,
    mlfi_header,
    mlfi_eoh,
    mlfi_body,
    mlfi_eom,
    mlfi_abort,
    mlfi_close,
    mlfi_unknown,
    mlfi_data,
    NULL, // Replaced by function 'mlfi_connect'
};

/*********************************************************************/
/************************* HANDLING SIGNALS **************************/
/*********************************************************************/

/* [Thread-Safe] Signals handler */
void signal_handler(int recieved_signal)
{
    if (recieved_signal == SIGUSR1) {
        syslog(LOG_DEBUG, "[signal_handler] The SIGUSR1 signal was received. Printing statistics.");
        print_statistics();
        return;
    }

    if (recieved_signal == SIGINT) {
        syslog(LOG_DEBUG, "[signal_handler] The SIGINT signal was received. Exiting Milter.");
        if(!OPTIONS.daemon && OPTIONS.verbose) {
            fprintf(stdout, "[%s] Turning off MUNI-Milter. Please wait... \n", MILTER_NAME);
        }

        exit_milter(false);
    }
    syslog(LOG_ERR, "Milter received an unknown signal. Skipping.");
}

/* [Thread-Safe] Thread for catching signals from the users */
void* signals_thread()
{
    struct sigaction signal_action = { 0 };
    signal_action.sa_handler = signal_handler;
    signal_action.sa_flags = 0; // Make it none-blocking

    if (sigemptyset(&(signal_action.sa_mask)) || sigemptyset(&SIGNALS_SET)) {
        syslog(LOG_ERR, "Was not able to create empty sets for signal handling.");
        exit_milter(true);
    }

    if (sigaddset(&SIGNALS_SET, SIGINT) || sigaddset(&SIGNALS_SET, SIGUSR1)) {
        syslog(LOG_ERR, "Was not able to add SIGINT or SIGUSR1 to the signal set.");
        exit_milter(true);
    }

    if (sigaction(SIGUSR1, &signal_action, 0) || sigaction(SIGINT, &signal_action, 0)) {
        syslog(LOG_ERR, "Was not able to register a handler for signals (SIGINT, SIGUSR1).");
        exit_milter(true);
    }

    syslog(LOG_DEBUG, "[signals_thread] The signal thread started. Waiting for signal.");

    while (true) {
        if (sigprocmask(SIG_BLOCK, &SIGNALS_SET, NULL)) {
            syslog(LOG_ERR, "Was not able to mask signals. Exiting milter.");
            exit_milter(true);
        }

        // This always returns -1, so we do not need to worry about it
        sigsuspend(&(signal_action.sa_mask));
    }
}

/*********************************************************************/
/*************************** MISC FUNCTIONS **************************/
/*********************************************************************/

/* [Thread-Safe] Simple help print */
void print_help(char* argv[])
{
    printf("%s [OPTIONS]\n\n \
OPTIONS:\n \
    -h,--help - Show help\n \
    -V,--version - Display milter version\n \
    -v,--verbose - Show debug and additional messages\n \
    -c,--config [path] - Load config file from the specific path\n \
    -d,--daemon - Run milter as a daemon\n",
        argv[0]);
}

/* [Thread-Safe] Validate the email and get the domain part (faculty/server representation) */
char* get_faculty_name(char* original_from, char* original_to)
{
    // Something (even MUNI email) -> MUNI
    if(regexec(&MUNI_MAIL_REGEX, original_to, 0, NULL, 0) != REG_NOMATCH) {
        strtok(original_to, "@"); // This is the beginning of the email address (user part)
        return strtok(NULL, "@");
    }

    // MUNI -> Something (not MUNI email)
    if(regexec(&MUNI_MAIL_REGEX, original_from, 0, NULL, 0) != REG_NOMATCH) {
        strtok(original_from, "@"); // User part let's skip it again
        return strtok(NULL, "@");
    }

    return NULL;
}

/* [Thread-Unsafe] Remove specific char (usually brackets) from the start and end of the string */
char* remove_brackets(char* str, char start, char end)
{
    if (str && *str == start) {
        char* last_occ = strrchr(str, end);
        if (last_occ) {
            return strndup(str + 1, last_occ - str - 1);
        }
    }
    return NULL;
}

/* [Thread-Safe] Validate if the email address is in the MUNI network */
bool check_is_local(char* address)
{
    return regexec(&MUNI_MAIL_REGEX, address, 0, NULL, 0) != REG_NOMATCH;
}

/* [Thread-Safe] Set and validate (with logs) the header */
void set_header(SMFICTX* ctx, char* headerf, char* headerv)
{
    if (smfi_chgheader(ctx, headerf, 1, headerv) == MI_FAILURE) {
        syslog(LOG_ERR, "Was not able to set the header with key: %s to the value %s.", headerf, headerv);
    }
    syslog(LOG_DEBUG, "[set_header] The header with key %s was successfully set.", headerf);
}

/* [Thread-Safe] Mark selected email as spam */
void mark_as_spam(SMFICTX* ctx, private_data_t* data)
{
    if (SETTINGS->dry_run) {
        syslog(LOG_DEBUG, "[mark_as_spam] The email was marked as spam in dry-run mode. ID: %s.", data->email_id);
        return; // In dry-run mode, we do not want to affect emails
    }
    
    if (smfi_quarantine(ctx, "Spammer access rejected") == MI_FAILURE) {
        syslog(LOG_ERR, "Was not able to mark email %s as spam. This is an urgent problem (Hostname: %s).", 
            data->email_id, data->sender_hostname);
    }
        
    if (ALLOW_REPLY) {
        if (smfi_setmlreply(ctx, "550", "5.7.0", "Spammer access rejected", NULL) == MI_FAILURE) {
            syslog(LOG_ERR, "Was not able to send multi-line messages for email %s (Hostname: %s).", 
                data->email_id, data->sender_hostname);
        }
    }
}

/*********************************************************************/
/**************************** MILTER INITS ***************************/
/*********************************************************************/

/* [Thread-Unsafe] Options parsing and initialization */
void init_options(int argc, char* argv[], options_t* options)
{
    int opt;
    while ((opt = getopt_long(argc, argv, OPTSTRING, longopts, NULL)) != -1) {
        switch (opt) {
        case 'h':
            print_help(argv);
            exit(EXIT_SUCCESS);
        case 'V':
            fprintf(stdout, "[%s] version: %s, author: %s\n", MILTER_NAME, VERSION, AUTHOR);
            exit(EXIT_SUCCESS);
        case 'v':
            options->verbose = true;
            break;
        case 'c':
            options->config_path = optarg;
            break;
        case 'd':
            options->daemon = true;
            break;
        default:
            fprintf(stderr, "Option -%c is invalid.", opt);
            print_help(argv);
            exit(EXIT_FAILURE);
        }
    }
}

/* [Thread-Unsafe] Init regex for MUNI emails */
bool init_mail_regex() {
    syslog(LOG_DEBUG, "[init_mail_regex] Starting mail regex initialization.");

    if (!regcomp(&MUNI_MAIL_REGEX, ".+\\@(.+\\.{1})*celko\\.cz", REG_EXTENDED)) {
        syslog(LOG_DEBUG, "[init_mail_regex] The regex for matching the MUNI email was parsed successfully.");
        return true;
    }
    syslog(LOG_ERR, "Was not able to parse regex for matching MUNI emails.");
    return false;
}

/* [Thread-Safe] Init logging */
void init_loging()
{
    openlog(MILTER_NAME, LOG_PID | LOG_NDELAY, LOG_DAEMON);
    setlogmask(LOG_UPTO(OPTIONS.verbose ? LOG_DEBUG : LOG_INFO));
    syslog(LOG_DEBUG, "[init_loging] Syslog was initialized (verbose %s).", OPTIONS.verbose ? "on" : "off");
}

/* [Thread-Unsafe] The initialization for private data */
bool init_private_data(SMFICTX* ctx, private_data_t* data)
{
    data->is_forward = false;
    data->is_local = false;
    data->is_auth = false;
    data->header_quarantine = false;
    data->forward_counter = 0;
    data->spam_score = -1;
    data->sender_hostname = NULL;
    data->email_id = NULL;
    data->from = NULL;
    data->to = NULL;
    data->subject = NULL;
    data->header_from = NULL;
    data->header_to = NULL;

    return smfi_setpriv(ctx, data) == MI_SUCCESS;
}

/*********************************************************************/
/***************************** STATISTICS ****************************/
/*********************************************************************/

/* [Thread-Safe] Create a new empty record in the statistics */
statistics_record_t* create_new_stat_record(char* name)
{
    statistics_record_t* record = malloc(sizeof(statistics_record_t));
    if (!record) {
        syslog(LOG_ERR, "Was not able to create a statistics record for %s.", name);
        return NULL;
    }

    pthread_mutex_lock(&DATA_MUTEX);

    record->name = strdup(name);
    record->forwarded_emails_counter = 0;
    record->parsed_email_counter = 0;
    record->super_spam_counter = 0;
    record->spam_counter = 0;
    record->average_score = 0;
    record->average_time = 0;

    STATISTICS->array_size++;

    // We will save it at the end of the array
    STATISTICS->data[STATISTICS->array_size - 1] = record;

    pthread_mutex_unlock(&DATA_MUTEX);

    syslog(LOG_DEBUG, "[create_new_stat_record] Created a new record with the name %s.", name);
    return record;
}

/* [Thread-Safe] Retrieve statistics record by faculty server name */
statistics_record_t* retrieve_statistics_record(char* server_name)
{
    syslog(LOG_DEBUG, "[retrieve_statistics_record] Retrieving statistic record for: %s", server_name);

    for (size_t i = 0; i < STATISTICS->array_size; ++i) {
        if (!strcmp((STATISTICS->data)[i]->name, server_name)) {
            syslog(LOG_DEBUG, "[retrieve_statistics_record] Successfully retrieved record for %s", 
                (STATISTICS->data)[i]->name);
            return (STATISTICS->data)[i];
        }
    }

    // This means we do not have a selected faculty server in our statistics and we need to add him.
    if (STATISTICS->array_size >= 255) {
        syslog(LOG_ERR, "We reached the limit for the statistics record (this should not happen). Exiting milter.");
        exit_milter(true);
    }

    statistics_record_t *ret_record = create_new_stat_record(server_name);

    if (!ret_record) {
        exit_milter(true);
    }
    return ret_record;
}

/* [Thread-Safe] Print actual statistics of the MUNI Milter */
void print_statistics()
{
    syslog(LOG_DEBUG, "[print_statistics] Printing statistics data. Entries: %ld", STATISTICS->array_size);

    if (!STATISTICS) {
        syslog(LOG_ERR, "Can not print scores for invalid statistics.");
        return;
    }

    syslog(LOG_INFO, "[STATISTICS] Email statistics:");
    for (size_t i = 0; i < STATISTICS->array_size; ++i) {
        syslog(LOG_INFO, "     <%s>: Total: %llu | Forwarded: %llu | Super-spam: %llu | Spam: %llu", 
            (STATISTICS->data)[i]->name, (STATISTICS->data)[i]->parsed_email_counter, 
            (STATISTICS->data)[i]->forwarded_emails_counter, (STATISTICS->data)[i]->super_spam_counter,
            (STATISTICS->data)[i]->spam_counter);
    }

    syslog(LOG_INFO, "[STATISTICS] Average values:");
    for (size_t i = 0; i < STATISTICS->array_size; ++i) {
        syslog(LOG_INFO, "     <%s>: Spam score: %.2f | Time: %.2f", 
            (STATISTICS->data)[i]->name, (STATISTICS->data)[i]->average_score, 
            (STATISTICS->data)[i]->average_time);
    }

    syslog(LOG_DEBUG, "[print_statistics] Statistics data were successfully printed.");
}

/* [Thread-Unsafe] The function that will parse the line loaded from the saved statistics file  */
bool load_statistic_line(char *line_content) 
{
    char* name = strtok(line_content, STATISTICS_DELIMITER);
    char* raw_forwarded_emails_counter = strtok(NULL, STATISTICS_DELIMITER);
    char* raw_parsed_email_counter = strtok(NULL, STATISTICS_DELIMITER);
    char* raw_super_spam_counter = strtok(NULL, STATISTICS_DELIMITER);
    char* raw_spam_counter = strtok(NULL, STATISTICS_DELIMITER);
    char* raw_average_score = strtok(NULL, STATISTICS_DELIMITER);
    char* raw_average_time = strtok(NULL, STATISTICS_DELIMITER);

    errno = 0;
    if (!name || !raw_forwarded_emails_counter || !raw_parsed_email_counter || !raw_super_spam_counter ||
      !raw_spam_counter || !raw_average_score || !raw_average_time) {
        return false; // Invalid line in statistics file, skipping (missing part)
    }

    char *end_forwarded_emails_counter; // Parse raw_forwarded_emails_counter as integer
    int forwarded_emails_counter = strtol(raw_forwarded_emails_counter, &end_forwarded_emails_counter, 10);

    char *end_parsed_email_counter; // Parse raw_parsed_email_counter as integer
    int parsed_email_counter = strtol(raw_parsed_email_counter, &end_parsed_email_counter, 10);

    char *end_super_spam_counter; // Parse raw_super_spam_counter as integer
    int super_spam_counter = strtol(raw_super_spam_counter, &end_super_spam_counter, 10);

    char *end_spam_counter; // Parse raw_spam_counter as integer
    int spam_counter = strtol(raw_spam_counter, &end_spam_counter, 10);

    char *end_average_score; // Parse raw_average_score as float
    int average_score = strtof(raw_average_score, &end_average_score);

    char *end_average_time; // Parse raw_average_time as float
    int average_time = strtof(raw_average_time, &end_average_time);

    if (errno != 0 || end_forwarded_emails_counter == raw_forwarded_emails_counter || 
      end_parsed_email_counter == raw_parsed_email_counter || end_super_spam_counter == raw_super_spam_counter ||
      end_spam_counter == raw_spam_counter || end_average_score == raw_average_score ||
      end_average_time == raw_average_time) {
        syslog(LOG_WARNING, "Was not able to load the line from the statistic file: %s. Skipping.", name);
        return false; // Invalid line in statistics, skipping...
    }

    statistics_record_t *record = retrieve_statistics_record(name);
    record->name = strdup(name);
    record->forwarded_emails_counter = forwarded_emails_counter;
    record->parsed_email_counter = parsed_email_counter;
    record->super_spam_counter = super_spam_counter;
    record->spam_counter = spam_counter;
    record->average_score = average_score;
    record->average_time = average_time;

    return true;
}

/* [Thread-Unsafe] The function that will load previously saved statistics data from the file */
void statistics_load(statistics_t* statistics)
{
    if (!statistics || !SETTINGS || !SETTINGS->statistics_path) {
        syslog(LOG_WARNING, "Was not able to load the statistics file (invalid settings or statistics).");
        return;
    }

    char *path = SETTINGS->statistics_path;
    FILE* stat_load_fd = fopen(path, "r");

    if (!stat_load_fd) {
        syslog(LOG_ERR, "Was not able to open the file descriptor for the saved statistics. Path: %s.", path);
        return;
    }

    syslog(LOG_DEBUG, "[statistics_load] Starting to load saved statistics from the path: %s.", path);

    char* line_content = NULL;
    int loaded_counter = 0;
    size_t data_length;

    while (getline(&line_content, &data_length, stat_load_fd) != EOF) {
        if(load_statistic_line(line_content)) {
            loaded_counter++;    
        }
    }

    if (line_content) {
        free(line_content);
    }

    errno = 0;
    if (fclose(stat_load_fd) == EBADF || errno) {
        syslog(LOG_ERR, "Was not able to close the statistic file descriptor after loading. Path: %s.", path);
    }

    syslog(LOG_DEBUG, "[statistics_load] Statistics were successfully loaded. Loaded (lines): %d.", loaded_counter);
    syslog(LOG_DEBUG, "[statistics_load] Removing old statistics file.");
    if (remove(path) == -1) {
        syslog(LOG_WARNING, "Was not able to remove the old statistics file. Path: %s.", path);
    }

    if(OPTIONS.verbose) {
        print_statistics();
    }
}

/* [Thread-Unsafe] Save the whole statistics to file */
void statistics_save(statistics_t* statistics)
{
    if (!statistics || !SETTINGS || !SETTINGS->statistics_path) {
        syslog(LOG_WARNING, "Was not able to save the statistics file (invalid settings or statistics).");
        return;
    }

    char *path = SETTINGS->statistics_path;
    FILE* stat_save_fd = fopen(path, "w+");

    if (!stat_save_fd) {
        syslog(LOG_ERR, "Was not able to open the file descriptor for statistics saving. Path: %s.", path);
        return;
    }

    syslog(LOG_DEBUG, "[statistics_save] Starting to save statistics to file: %s.", path);
    for (size_t i = 0; i < statistics->array_size; ++i) {
        statistics_record_t *record = (statistics->data)[i];
        fprintf(stat_save_fd, "%s%s%llu%s%llu%s%llu%s%llu%s%.4f%s%.4f\n", record->name, STATISTICS_DELIMITER, 
            record->forwarded_emails_counter, STATISTICS_DELIMITER, record->parsed_email_counter, STATISTICS_DELIMITER,
            record->super_spam_counter, STATISTICS_DELIMITER, record->spam_counter, STATISTICS_DELIMITER, 
            record->average_score, STATISTICS_DELIMITER, record->average_time);
    }

    errno = 0;
    if (fclose(stat_save_fd) == EBADF || errno) {
        syslog(LOG_ERR, "Was not able to close the statistic file descriptor. Path: %s.", path);
    }
    syslog(LOG_INFO, "The statistics were successfully saved to: %s. Saved lines: %ld.", path, statistics->array_size);
}

/* [Thread-Unsafe] Init statistic structure */
bool init_statistics()
{
    syslog(LOG_DEBUG, "[init_statistics] Trying to initialize statistics structure.");
    STATISTICS = malloc(sizeof(statistics_t));

    if (!STATISTICS) {
        syslog(LOG_ERR, "Was not able to allocate an array for statistics structure.");
        return false;
    }

    // Initial record for the relay (index 0 will be included in create_new_stat_record)
    STATISTICS->array_size = 0;

    // This will represent all traffic on the MUNI relay (it will be always on index 0)
    create_new_stat_record("Relay");
    return (bool) (STATISTICS->data)[0];
}

/* [Thread-Unsafe] Destroy statistic structure */
void destroy_statistics()
{
    syslog(LOG_DEBUG, "[destroy_statistics] Removing statistics from memory.");

    if (!STATISTICS) {
        syslog(LOG_ERR, "Failed to remove statistics from memory. Probably was not allocated at all.");
        return;
    }

    for (size_t i = 0; i < STATISTICS->array_size; ++i) {
        free((STATISTICS->data)[i]->name);
        free((STATISTICS->data)[i]);
    }

    free(STATISTICS);
    syslog(LOG_DEBUG, "[destroy_statistics] The statistics were successfully removed from memory. Removed: %ld.", 
        STATISTICS->array_size);
}

/* [Thread-Safe] Evaluate spam category for the sender and update statistics data */
void update_statistics(statistics_record_t* faculty_record, float time_score, float spam_score, 
    bool is_forward, spam_type_t evaluated_type)
{
    statistics_record_t* relay_record = (STATISTICS->data)[0];

    pthread_mutex_lock(&DATA_MUTEX);
    
    if (is_forward) {
        relay_record->forwarded_emails_counter++;
        faculty_record->forwarded_emails_counter++;
    }

    int r_count = relay_record->parsed_email_counter;
    int f_count = faculty_record->parsed_email_counter;

    // Update average score for relay and faculty server
    relay_record->average_score = (relay_record->average_score * r_count + spam_score) / (r_count + 1);
    faculty_record->average_score = (faculty_record->average_score * f_count + spam_score) / (f_count + 1);

    // Update average time for relay and faculty server
    relay_record->average_time = (relay_record->average_time * r_count + time_score) / (r_count + 1);
    faculty_record->average_time = (faculty_record->average_time * f_count + time_score) / (f_count + 1);

    if (evaluated_type == SPAM) {
        relay_record->spam_counter++;
        faculty_record->spam_counter++;
    }

    if (evaluated_type == SUPERSPAM) {
        relay_record->super_spam_counter++;
        faculty_record->super_spam_counter++;
    }

    relay_record->parsed_email_counter++;
    faculty_record->parsed_email_counter++;

    pthread_mutex_unlock(&DATA_MUTEX);

    syslog(LOG_DEBUG, "[update_statistics] Successfully updated statistic record for: %s", faculty_record->name);
}

/*********************************************************************/
/******************************** MAIN *******************************/
/*********************************************************************/

/* [Thread-Safe] Safe milter exit */
void exit_milter(bool is_fail)
{
    syslog(LOG_DEBUG, "[exit_milter] Freeing milter resources.");
    free(OPTIONS.config_path);

    if (SETTINGS && SETTINGS->save_data) {
        pthread_mutex_lock(&DATA_MUTEX);
        
        db_save(DATABASE);
        statistics_save(STATISTICS);
        
        pthread_mutex_unlock(&DATA_MUTEX);
    }

    print_statistics();

    pthread_mutex_lock(&DATA_MUTEX);

    destroy_statistics();
    db_destroy(DATABASE);
    settings_destroy(SETTINGS);

    pthread_mutex_unlock(&DATA_MUTEX);

    syslog(LOG_INFO, "Exiting milter. Goodbye.");

    closelog();
    smfi_stop();
    exit(is_fail ? EXIT_FAILURE : EXIT_SUCCESS);
}

/* Main function */
int main(int argc, char* argv[])
{
    init_options(argc, argv, &OPTIONS);
    init_loging();

    if (!(SETTINGS = settings_init(OPTIONS.config_path))) {
        syslog(LOG_ERR, "Was not able to load settings. Please remove the config file to generate the default one.");
        exit_milter(true);
    }

    if (OPTIONS.verbose && smfi_setdbg(SETTINGS->milter_debug_level) != MI_SUCCESS) {
        syslog(LOG_ERR, "Was not able to turn on debug for milter.");
        exit_milter(true);
    }

    if (!(DATABASE = db_construct(DATA_MUTEX, SETTINGS))) {
        syslog(LOG_ERR, "Was not able to construct a database.");
        exit_milter(true);
    }

    if (!init_statistics() || !init_mail_regex()) {
        exit_milter(true);
    }

    if (SETTINGS->save_data) {
        db_load(DATABASE);
        statistics_load(STATISTICS);
    }

    if (!SETTINGS->socket_path || *SETTINGS->socket_path == '\0') {
        syslog(LOG_ERR, "Invalid socket path.");
        exit_milter(true);
    }

    syslog(LOG_INFO, "Starting %s. Socket %s.", MILTER_NAME, SETTINGS->socket_path);

    if (OPTIONS.daemon) {
        if (daemon(true, true)) {
            syslog(LOG_ERR, "Deamon function failed.");
            exit_milter(true);
        }
        syslog(LOG_DEBUG, "[main] Daemon successfully started. PID: %u", getpid());
    }

    syslog(LOG_DEBUG, "[main] Starting working with threads.");

    if (smfi_setconn(SETTINGS->socket_path) != MI_SUCCESS) {
        syslog(LOG_ERR, "Connection with socket failed (lack of memory).");
        exit_milter(true);
    }

    if (smfi_register(milter_struct) == MI_FAILURE) {
        syslog(LOG_ERR, "Was not able to establish a connection with the socket.");
        exit_milter(true);
    }

    pthread_t thread_id;
    if (pthread_create(&thread_id, NULL, signals_thread, NULL)) {
        syslog(LOG_ERR, "Was not able to create a signals handler thread.");
        exit_milter(true);
    }

    if (pthread_detach(thread_id)) {
        syslog(LOG_ERR, "Was not able to detach signals thread.");
        exit_milter(true);
    }

    if (smfi_opensocket(true) == MI_FAILURE) {
        syslog(LOG_ERR, "Was not able to create a socket (probably is being still used).");
        exit_milter(true);
    }

    int return_value = smfi_main();
    if (return_value != MI_SUCCESS) {
        syslog(LOG_ERR, "Was not able to run the milter main function.");
        exit_milter(true);
    }
    return return_value;
}

/*********************************************************************/
/******************************* MILTER ******************************/
/*********************************************************************/

/* Unknown or unimplemented SMTP command */
sfsistat mlfi_unknown(SMFICTX* ctx, const char* cmd)
{
    (void)ctx;
    syslog(LOG_WARNING, "Found an unknown command %s (ending connection).", cmd);
    syslog(LOG_DEBUG, "[mlfi_unknown] An unknown command, rejecting.");

    // This will call the function 'mlfi_abort'
    return SETTINGS->dry_run ? SMFIS_CONTINUE : SMFIS_REJECT;
}

/* The connection was canceled. */
sfsistat mlfi_close(SMFICTX* ctx)
{
    syslog(LOG_DEBUG, "[mlfi_close] The connection was closed.");
    return mlfi_cleanup(ctx, SMFIS_CONTINUE);
}

/* The message was aborted. */
sfsistat mlfi_abort(SMFICTX* ctx)
{
    syslog(LOG_DEBUG, "[mlfi_abort] The message was aborted.");
    return mlfi_cleanup(ctx, SMFIS_CONTINUE);
}

/* Data manipulation */
sfsistat mlfi_data(SMFICTX* ctx)
{
    (void)ctx;
    return SMFIS_CONTINUE;
}

/* Try to make a milter connection */
sfsistat mlfi_connect(SMFICTX* ctx, char* hostname, _SOCK_ADDR* hostaddr)
{
    syslog(LOG_DEBUG, "[mlfi_connect] Entering function 'mlfi_connect'. Trying to establish a connection.");
    syslog(LOG_DEBUG, "[mlfi_connect] Passing relay: %s.", smfi_getsymval(ctx, "{_}"));

    if (SETTINGS->dry_run) {
        syslog(LOG_INFO, "Dry-run was activated!");
    }

    if (!hostaddr) {
        syslog(LOG_WARNING, "Host using old version of the SMTP protocol or message was sent from stdin.");
    }

    syslog(LOG_DEBUG, "[mlfi_connect] Empty data structure. Starting initialization.");
    
    pthread_mutex_lock(&DATA_MUTEX);
    
    private_data_t* data = malloc(sizeof(private_data_t));
    
    pthread_mutex_unlock(&DATA_MUTEX);

    if (!data) {
        syslog(LOG_ERR, "Was not able to init private data structure (malloc).");
        return SMFIS_TEMPFAIL;
    }

    pthread_mutex_lock(&DATA_MUTEX);

    if (!init_private_data(ctx, data)) {
        return SMFIS_TEMPFAIL;
    }
    
    pthread_mutex_unlock(&DATA_MUTEX);

    syslog(LOG_DEBUG, "[mlfi_connect] Milter successfully established a connection. Hostname: %s", hostname);
    return SMFIS_CONTINUE;
}

/* Envelope sender */
sfsistat mlfi_envfrom(SMFICTX* ctx, char** envfrom)
{
    syslog(LOG_DEBUG, "[mlfi_envfrom] Entering function mlfi_envfrom. Parsing sender data.");

    private_data_t* data = smfi_getpriv(ctx);
    if (!data) {
        syslog(LOG_ERR, "Was not able to load private data. Rejecting connection from 'mlfi_envfrom'.");
        return SMFIS_TEMPFAIL;
    }

    char* retrieved_hostname = smfi_getsymval(ctx, "{client_addr}");
    if (!retrieved_hostname) {
        syslog(LOG_ERR, "Was not able to retrieve the client's address. Rejecting connection.");
        return SMFIS_TEMPFAIL;
    }

    syslog(LOG_DEBUG, "[mlfi_envfrom] The client address was successfully parsed: %s.", retrieved_hostname);

    pthread_mutex_lock(&DATA_MUTEX);

    data->from = remove_brackets(envfrom[0], '<', '>');
    data->sender_hostname = strdup(retrieved_hostname);

    pthread_mutex_unlock(&DATA_MUTEX);

    if (!data->from) {
        syslog(LOG_ERR, "Can not find the sender. Rejecting connection."); // Ensured by SMTP
        return SMFIS_TEMPFAIL;
    }

    char* auth_result = smfi_getsymval(ctx, "{auth_authen}");

    pthread_mutex_lock(&DATA_MUTEX);

    data->is_auth = auth_result != NULL;

    pthread_mutex_unlock(&DATA_MUTEX);

    if (data->is_auth) {
        syslog(LOG_DEBUG, "[mlfi_envfrom] Auth data for sender %s were found.", data->from);
    }

    syslog(LOG_DEBUG, "[mlfi_envfrom] Sender found: %s", data->from);
    return SMFIS_CONTINUE;
}

/* Envelope recipient */
sfsistat mlfi_envrcpt(SMFICTX* ctx, char** envrcpt)
{
    syslog(LOG_DEBUG, "[mlfi_envrcpt] Entering function mlfi_envrcpt. Parsing recipient data.");
    private_data_t* data = smfi_getpriv(ctx);

    if (!data) {
        syslog(LOG_ERR, "Was not able to load private data. Rejecting connection from 'mlfi_envrcpt'.");
        return SMFIS_TEMPFAIL;
    }

    pthread_mutex_lock(&DATA_MUTEX);

    data->to = remove_brackets(envrcpt[0], '<', '>');

    pthread_mutex_unlock(&DATA_MUTEX);

    if (!data->to) {
        syslog(LOG_ERR, "Can not find the recipient. Rejecting connection."); // Ensured by SMTP
        return SMFIS_TEMPFAIL;
    }

    syslog(LOG_DEBUG, "[mlfi_envrcpt] Recipient found: %s", data->to);
    return SMFIS_CONTINUE;
}

/* Header parser | NOTE: I do not advise decompose this function */
sfsistat mlfi_header(SMFICTX* ctx, char* headerf, char* headerv)
{
    syslog(LOG_DEBUG, "[mlfi_header] Starting to parse %s : %s", headerf, headerv);
    
    private_data_t* data = smfi_getpriv(ctx);
    if (!data) {
        syslog(LOG_ERR, "Was not able to load private data. Rejecting connection from 'mlfi_header'.");
        return SMFIS_TEMPFAIL;
    }

    if (!strcmp(headerf, HEADER_SPAM)) { // SpamAssassin score
        char* score_string = strstr(headerv, "score=");
        if (score_string) {
            char* end_ptr;
            errno = 0;
            float temp_spam_score = strtof(score_string + 6, &end_ptr);

            if (errno != 0 || end_ptr == headerv) {
                syslog(LOG_WARNING, "[mlfi_header] Was not able to parse the SpamAssassin score. Skipping.");
                return SMFIS_CONTINUE;
            }

            pthread_mutex_lock(&DATA_MUTEX);
            data->spam_score = temp_spam_score;
            pthread_mutex_unlock(&DATA_MUTEX);
        }
        return SMFIS_CONTINUE;
    }

    if (!strcmp(headerf, HEADER_SUBJECT)) { // Subject
        pthread_mutex_lock(&DATA_MUTEX);
        data->subject = strdup(headerv);
        pthread_mutex_unlock(&DATA_MUTEX);
        return SMFIS_CONTINUE;
    }

    if (!strcmp(headerf, HEADER_FORWARD_COUNTER)) { // Forward counter
        char* end_ptr;
        errno = 0;
        int temp_counter = (int)strtol(headerv, &end_ptr, 10);

        if (errno != 0 || *end_ptr != '\0' || end_ptr == headerv) {
            syslog(LOG_DEBUG, "[mlfi_header] Was not able to parse the forward counter. Skipping.");
            return SMFIS_CONTINUE;
        }

        pthread_mutex_lock(&DATA_MUTEX);
        data->forward_counter = temp_counter;
        data->is_forward = data->forward_counter > 0;
        pthread_mutex_unlock(&DATA_MUTEX);
        return SMFIS_CONTINUE;
    }
    
    if (!strcmp(headerf, HEADER_INFO)) { // Debug print informing about repeated pass through our Milter
        syslog(LOG_DEBUG, "[mlfi_header] The email was already seen by the MUNI relay. Info: %s", headerv);
        return SMFIS_CONTINUE;
    }

    if (!strcmp(headerf, HEADER_ID)) { // Emial ID
        pthread_mutex_lock(&DATA_MUTEX);
        data->email_id = remove_brackets(headerv, '<', '>');
        pthread_mutex_unlock(&DATA_MUTEX);
        return SMFIS_CONTINUE;
    }
    
    if (!strcmp(headerf, HEADER_FROM)) { // Header FROM
        pthread_mutex_lock(&DATA_MUTEX);
        data->header_from = strdup(headerv);
        pthread_mutex_unlock(&DATA_MUTEX);
        syslog(LOG_DEBUG, "[mlfi_header] The email originated from: %s.", data->header_from);
        return SMFIS_CONTINUE;
    }

    if (!strcmp(headerf, HEADER_TO)) { // Header TO
        pthread_mutex_lock(&DATA_MUTEX);
        data->header_to = strdup(headerv);
        pthread_mutex_unlock(&DATA_MUTEX);
        return SMFIS_CONTINUE;
    }

    if (!strcmp(headerf, HEADER_QUARANTINE)) { // Quarantine flag
        pthread_mutex_lock(&DATA_MUTEX);
        data->header_quarantine = strcmp(headerv, "Yes");
        pthread_mutex_unlock(&DATA_MUTEX);
        return SMFIS_CONTINUE;
    }

    return SMFIS_CONTINUE; // Unknown header... continue
}

/* End of the header */
sfsistat mlfi_eoh(SMFICTX* ctx)
{
    syslog(LOG_DEBUG, "[mlfi_eoh] Entering function 'mlfi_eoh'. The header was successfully parsed.");
    
    private_data_t* data = smfi_getpriv(ctx);
    if (!data) {
        syslog(LOG_ERR, "Was not able to load private data. Rejecting connection from 'mlfi_eoh'.");
        return SMFIS_TEMPFAIL;
    }

    if (!data->email_id) {
        syslog(LOG_ERR, "Invalid email ID.");
        return SMFIS_TEMPFAIL;
    }

    if (data->header_quarantine) {
        syslog(LOG_DEBUG, "[mlfi_eoh] The email was already marked as super-spam (forward). Email ID: %s", 
            data->email_id);
    }

    if (data->spam_score == -1) {
        syslog(LOG_WARNING, "Was not able to find the spam assassin score in the header of the email.");
        
        pthread_mutex_lock(&DATA_MUTEX);
        data->spam_score = SETTINGS->dry_run ? 0 : 15;
        pthread_mutex_unlock(&DATA_MUTEX);
    }

    if (data->forward_counter != 0) {
        syslog(LOG_DEBUG, "[mlfi_eoh] Forward through MUNI relay was detected. Forward counter: %d.", data->forward_counter);
        
        pthread_mutex_lock(&DATA_MUTEX);
        data->is_forward = true;
        pthread_mutex_unlock(&DATA_MUTEX);
    }

    if (!data->subject) {
        syslog(LOG_DEBUG, "[mlfi_eoh] The header does not contain a subject. Email ID: %s.", data->email_id);
    }

    syslog(LOG_DEBUG, "Email header with ID: %s was successfully parsed.", data->email_id);
    return SMFIS_CONTINUE;
}

/* The body part of the message */
sfsistat mlfi_body(SMFICTX* ctx, u_char* bodyp, size_t bodylen)
{
    syslog(LOG_DEBUG, "[mlfi_body] Entering function 'mlfi_body'. Starting parsing message body.");
    private_data_t* data = smfi_getpriv(ctx);

    if (!data) {
        syslog(LOG_ERR, "Was not able to load private data. Rejecting connection from 'mlfi_body'.");
        return SMFIS_TEMPFAIL;
    }

    (void)bodyp;
    (void)bodylen;
    // Here can be added some kind of parser in the future (for now will be empty)

    syslog(LOG_DEBUG, "[mlfi_body] The message body was successfully parsed.");
    return SMFIS_CONTINUE;
}

/* Cleanup after connection is closed */
sfsistat mlfi_cleanup(SMFICTX* ctx, sfsistat return_value)
{
    private_data_t* data = smfi_getpriv(ctx);
    syslog(LOG_DEBUG, "[mlfi_cleanup] Entering function 'mlfi_cleanup'. Starting cleanup.");
    
    pthread_mutex_lock(&DATA_MUTEX);
    if (data) {
        free(data->sender_hostname);
        free(data->email_id);
        free(data->from);
        free(data->to);
        free(data->subject);
        free(data->header_from);
        free(data->header_to);
    }
    free(data);

    if (smfi_setpriv(ctx, NULL) != MI_SUCCESS) {
        syslog(LOG_ERR, "Was not able to set private data to NULL.");
        return SMFIS_TEMPFAIL;
    }
    pthread_mutex_unlock(&DATA_MUTEX);

    db_cleanup(DATABASE);

    syslog(LOG_DEBUG, "[mlfi_cleanup] Successfully cleared all private data.");
    return return_value;
}




//TODO refactor




































/* End of the message */
sfsistat mlfi_eom(SMFICTX* ctx)
{
    syslog(LOG_DEBUG, "[mlfi_eom] Entering function 'mlfi_eom'.");
    private_data_t* data = smfi_getpriv(ctx);

    if (!data) {
        syslog(LOG_ERR, "Was not able to load private data. Rejecting connection from 'mlfi_eom'.");
        return SMFIS_TEMPFAIL;
    }

    char* original_addr_from = data->header_from ? data->header_from : data->from;
    char* original_addr_to = data->header_to ? data->header_to : data->to;
    spam_type_t result_type = data->header_quarantine ? SUPERSPAM : NORMAL;

    pthread_mutex_lock(&DATA_MUTEX);
    data->is_local = check_is_local(original_addr_from) && check_is_local(original_addr_to);
    pthread_mutex_unlock(&DATA_MUTEX);

    if (data->is_forward && data->is_local) {
        syslog(LOG_WARNING, "Local forward. This should not happened. From (original): %s. To: %s.", original_addr_from, original_addr_to);
        return SMFIS_TEMPFAIL;
    }

    if (is_blacklisted(data->sender_hostname, SETTINGS) || is_blacklisted(original_addr_from, SETTINGS)) {
        set_header(ctx, HEADER_SPECIAL, "BLACKLISTED");
        syslog(LOG_DEBUG, "[mlfi_eom] Email is in the blacklist, blocking. Email ID: %s.", data->email_id);
        if (!SETTINGS->dry_run) {
            if (smfi_quarantine(ctx, "Blacklisted email") == MI_FAILURE) {
                syslog(LOG_ERR, "Was not able to mark email %s as blacklisted. Hostname: %s.", data->email_id, data->sender_hostname);
            }
            if (ALLOW_REPLY) {
                if (smfi_setmlreply(ctx, "403", "5.7.0", "Blacklisted email", NULL) == MI_FAILURE) {
                    syslog(LOG_ERR, "Was not able to send multi-line messages for email %s (Hostname: %s).", data->email_id, data->sender_hostname);
                }
            }
        }
        goto eom_finish; // We need to set headers for blacklisted email
    }

    if (is_whitelisted(data->sender_hostname, SETTINGS) || is_whitelisted(original_addr_from, SETTINGS)) {
        syslog(LOG_DEBUG, "[mlfi_eom] Sender hostname was found in the whitelist, skipping check. Email ID: %s.", data->email_id);
        set_header(ctx, HEADER_SPECIAL, "WHITELISTED");
        goto eom_finish; // We need to set headers for whitelisted email
    }

    char* temp_email_id = remove_brackets(smfi_getsymval(ctx, "{msg_id}"), '<', '>');
    if (!temp_email_id || strcmp(temp_email_id, data->email_id)) {
        syslog(LOG_ERR, "Was not able to validate the email ID. Email data were damaged.");
        free(temp_email_id);
        return SMFIS_TEMPFAIL;
    }

    syslog(LOG_DEBUG, "[mlfi_eom] Unique ID was matched with: %s", data->email_id);
    free(temp_email_id);

    int amount_of_trips = data->forward_counter + 1;
    if (amount_of_trips >= SETTINGS->forward_counter_limit) {
        syslog(LOG_ERR, "Something is probably wrong with the email path. Forward counter: %d", amount_of_trips);
        return SMFIS_TEMPFAIL;
    }

    char temp_trip_value[16];
    sprintf(temp_trip_value, "%d", amount_of_trips);
    set_header(ctx, HEADER_FORWARD_COUNTER, temp_trip_value);

    // It does not exist a new record will be created in DB
    entry_t* entry = db_get(DATABASE, data->sender_hostname);

    char* faculty_server_name = get_faculty_name(original_addr_from, original_addr_to);
    statistics_record_t* faculty_record = retrieve_statistics_record(faculty_server_name);
    time_t time_now = time(0);
    float email_time_score = fabs((float)difftime(entry->last_email, time_now));

    pthread_mutex_lock(&(DATABASE->mutex_value));
    entry->average_time = (entry->average_time * entry->email_count + email_time_score) / (entry->email_count + 1);
    entry->average_score = (entry->average_score * entry->email_count + data->spam_score) / (entry->email_count + 1);
    entry->last_email = time_now;
    entry->email_count++;
    pthread_mutex_unlock(&(DATABASE->mutex_value));

    if (entry->average_score > SETTINGS->spam_limit || entry->average_score * (1 + SETTINGS->score_percentage_spam) > faculty_record->average_score || entry->average_time * (1 + SETTINGS->time_percentage_spam) > faculty_record->average_time) {
        syslog(LOG_WARNING, "Spam level was reached for email: %s.", data->email_id);
        result_type = SPAM;
    }

    if (entry->average_score > SETTINGS->super_spam_limit || entry->average_score * (1 + SETTINGS->score_percentage_super_spam) > faculty_record->average_score || entry->average_time * (1 + SETTINGS->time_percentage_super_spam) > faculty_record->average_time) {
        syslog(LOG_WARNING, "Super-spam level was reached for email: %s.", data->email_id);
        result_type = SUPERSPAM;
    }

    // We do not want to include whitelisted or blacklisted emails in our statistics
    update_statistics(faculty_record, email_time_score, data->spam_score, data->is_forward, result_type);

    // Forwarded email
    if (result_type > SPAM && entry->average_score * (1 + SETTINGS->forward_percentage_limit) > (STATISTICS->data)[0]->average_score) {
        syslog(LOG_WARNING, "Forwarded email from %s reached spam limit. ID: %s.", original_addr_from, data->email_id);
        mark_as_spam(ctx, data);
        goto eom_finish;
    }

    // Authenticated user
    if (data->is_auth && result_type > SPAM) {
        syslog(LOG_WARNING, "Auth user from %s reached spam level (%s).", original_addr_from, data->email_id);
        mark_as_spam(ctx, data);
        goto eom_finish;
    }

    // If it is a local email probably it is some kind of newsletter
    if (result_type == SUPERSPAM && !data->is_local) {
        syslog(LOG_WARNING, "The sender that send email %s was marked as a super-spammer.", data->email_id);
        mark_as_spam(ctx, data);
    }

eom_finish:;

    set_header(ctx, HEADER_QUARANTINE, result_type == SUPERSPAM ? "Yes" : "No");
    set_header(ctx, HEADER_IS_AUTH, data->is_auth ? "Yes" : "No");
    set_header(ctx, HEADER_IS_FORWARD, data->is_forward ? "Yes" : "No");
    set_header(ctx, HEADER_IS_LOCAL, data->is_local ? "Yes" : "No");
    set_header(ctx, HEADER_TO, original_addr_to);
    set_header(ctx, HEADER_FROM, original_addr_from);

    char temp_info_value[512];
    sprintf(temp_info_value, "%s version: %s made by %s", MILTER_NAME, VERSION, AUTHOR);
    set_header(ctx, HEADER_INFO, temp_info_value);

    syslog(LOG_INFO, "Message from %s to %s passed milter.", original_addr_from, data->to);
    syslog(LOG_DEBUG, "[mlfi_eom] All changes at the end of the message were made. Email ID: %s", data->email_id);

    return mlfi_cleanup(ctx, SMFIS_CONTINUE);
}


