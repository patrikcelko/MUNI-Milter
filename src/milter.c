/********************************** MUNI - Milter ***********************************
 *
 * FILENAME:    milter.c
 * DESCRIPTION: Implementation of the milter.
 * NOTES:       This milter will need additional libs (settings, database) to run.
 * AUTHOR:      Patrik Čelko
 *
 *************************************************************************************/

#define _GNU_SOURCE

#include <errno.h>
#include <getopt.h>
#include <libmilter/mfapi.h>
#include <libmilter/mfdef.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sysexits.h>
#include <syslog.h>
#include <unistd.h>

#include "libs/database.h"
#include "libs/settings.h"
#include "milter.h"

/* Constants */
static char VERSION[] = "1.2.0";
static char AUTHOR[] = "Patrik Celko";
static char MILTER_NAME[] = "MUNI-Milter";
static char OPTSTRING[] = "hVvdc:";
static char LOCAL_DNS[] = "muni.cz";
static bool ALLOW_REPLY = false;

/* Headers names */
static char HEADER_FORWARD_COUNTER[] = "X-MUNI-Forward-Counter"; // HEADER: Trip counter
static char HEADER_FROM[] = "X-MUNI-From"; // HEADER: Sender email
static char HEADER_TO[] = "X-MUNI-To"; // HEADER: Recipient email
static char HEADER_SCORE[] = "X-MUNI-Score"; // HEADER: Score from previous runs through milter
static char HEADER_QUARANTINE[] = "X-MUNI-Quarantine"; // HEADER: Should email go to quarantine?
static char HEADER_INFO[] = "X-MUNI-Info"; // HEADER: Information about milter
static char HEADER_IS_AUTH[] = "X-MUNI-Auth"; // HEADER: Is the user authenticated?
static char HEADER_IS_FORWARD[] = "X-MUNI-Forward"; // HEADER: Is it forward?
static char HEADER_SPAM[] = "X-Spam-Status"; // HEADER: X-Spam-Flag will be yes if > 5
static char HEADER_IS_LOCAL[] = "X-MUNI-Local"; // HEADER: Is it in the MUNI network?
static char HEADER_SUBJECT[] = "Subject"; // HEADER: Email subject
static char HEADER_ID[] = "Message-Id"; // HEADER: Email ID

/* Global variables */
static pthread_mutex_t DATA_MUTEX = PTHREAD_MUTEX_INITIALIZER;
static settings_t* SETTINGS;
static database_t* DATABASE;
static statistics_t* STATTISTICS;

/* Avalible options */
struct option longopts[] = {
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

/* [Thread-Unsafe] The initialisation for private data */
bool init_private_data(SMFICTX* ctx, private_data_t* data)
{
    data->is_forward = false;
    data->is_local = false;
    data->is_auth = false;
    data->header_quarantine = false;
    data->forward_counter = 0;
    data->header_score = 0;
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

/* [Thread-Safe] Safe milter exit */
void exit_milter(options_t* options, bool is_fail)
{
    syslog(LOG_DEBUG, "[exit_milter] Freeing milter resources.");
    if (options) {
        free(options->config_path);
    }

    if (SETTINGS && SETTINGS->save_database) {
        pthread_mutex_lock(&DATA_MUTEX);
        db_save(DATABASE);
        pthread_mutex_unlock(&DATA_MUTEX);
    }

    if (SETTINGS && STATTISTICS && SETTINGS->allow_statistics) {
        syslog(LOG_INFO, "[STATTISTICS] Hit hard score limit: %llu", STATTISTICS->hard_limit_counter);
        syslog(LOG_INFO, "[STATTISTICS] Hit soft score limit: %llu", STATTISTICS->soft_limit_counter);
        syslog(LOG_INFO, "[STATTISTICS] Marked as spam: %llu", STATTISTICS->marked_as_spam_counter);
        syslog(LOG_INFO, "[STATTISTICS] Parsed emails: %llu", STATTISTICS->parsed_email_counter);
    }

    free(STATTISTICS);

    pthread_mutex_lock(&DATA_MUTEX);
    db_destroy(DATABASE);
    settings_destroy(SETTINGS);
    pthread_mutex_unlock(&DATA_MUTEX);

    syslog(LOG_INFO, "Exiting milter. Goodbye.");

    closelog();
    smfi_stop();
    exit(is_fail ? EXIT_FAILURE : EXIT_SUCCESS);
}

/* [Thread-Safe] Remove specific char from start and end of the string */
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
bool validate_local(char* address)
{
    if (strlen(address) <= strlen(LOCAL_DNS) + 2) {
        return false;
    }

    char* end_pointer = address + (strlen(address) - strlen(LOCAL_DNS)) - 1;
    if (*(end_pointer - 1) != '.' && *(end_pointer - 1) != '@') {
        return false;
    }
    return !strcmp(LOCAL_DNS, end_pointer);
}

/* [Thread-Safe] Set and validate (with logs) header */
void set_header(SMFICTX* ctx, char* headerf, char* headerv)
{
    if (smfi_chgheader(ctx, headerf, 1, headerv) == MI_FAILURE) {
        syslog(LOG_ERR, "Was not able to set the header with key: %s to value %s.", headerf, headerv);
    }
    syslog(LOG_DEBUG, "[set_header] Header with key %s was successfully set.", headerf);
}

/* [Thread-Safe] Mark selected email as spam */
void mark_as_spam(SMFICTX* ctx, private_data_t* data)
{
    syslog(LOG_WARNING, "Spam was detected. Email ID: %s.", data->email_id);

    pthread_mutex_lock(&DATA_MUTEX);
    STATTISTICS->marked_as_spam_counter++;
    pthread_mutex_unlock(&DATA_MUTEX);

    if (!SETTINGS->dry_run) {
        if (smfi_quarantine(ctx, "Spammer access rejected") == MI_FAILURE) {
            syslog(LOG_ERR, "Was not able to mark email %s as spam. This is an urgent problem (Hostname: %s).", data->email_id, data->sender_hostname);
        }
        if (ALLOW_REPLY) {
            if (smfi_setmlreply(ctx, "550", "5.7.0", "Spammer access rejected", NULL) == MI_FAILURE) {
                syslog(LOG_ERR, "Was not able to send multi-line messages for email %s (Hostname: %s).", data->email_id, data->sender_hostname);
            }
        }
    }
}

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

/* [Thread-Safe] Init statistic structure */
bool init_statistics()
{
    syslog(LOG_DEBUG, "[init_statistics] Trying to init statistics structure.");
    STATTISTICS = malloc(sizeof(statistics_t));

    if (!STATTISTICS) {
        syslog(LOG_ERR, "Was not able to allocate statistics structure.");
        return false;
    }

    STATTISTICS->hard_limit_counter = 0;
    STATTISTICS->soft_limit_counter = 0;
    STATTISTICS->marked_as_spam_counter = 0;
    STATTISTICS->parsed_email_counter = 0;
    return true;
}

/* [Thread-Unsafe] Parse options */
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

/* [Thread-Safe] Init logging */
void init_loging(options_t* options)
{
    openlog(MILTER_NAME, LOG_PID | LOG_NDELAY, LOG_DAEMON);
    setlogmask(LOG_UPTO(options->verbose ? LOG_DEBUG : LOG_INFO));
    syslog(LOG_DEBUG, "[init_loging] Syslog was initialised (verbose %s).", options->verbose ? "on" : "off");
}

/* [Thread-Safe] Simple signals handler */
void signal_handler(int recieved_signal, options_t* options)
{
    if (recieved_signal == SIGINT) {
        syslog(LOG_DEBUG, "[signal_handler] The SIGINT signal was received. Starting cleanup.");
        exit_milter(options, false);
    }
    syslog(LOG_WARNING, "Milter received an unknown signal. Skipping.");
}

/* [Thread-Safe] Thread for catching signals from the user */
void* signals_thread(void* void_options)
{
    sigset_t sig_set;
    if (sigemptyset(&sig_set)) {
        syslog(LOG_ERR, "Was not able to create an empty set.");
        exit_milter((options_t*)void_options, true);
    }

    if (sigaddset(&sig_set, SIGINT)) {
        syslog(LOG_ERR, "Was not able to add SIGINT to the signal set.");
        exit_milter((options_t*)void_options, true);
    }

    syslog(LOG_DEBUG, "[signals_thread] The signal thread started. Waiting for signal.");

    if (sigprocmask(SIG_BLOCK, &sig_set, NULL)) {
        syslog(LOG_ERR, "Was not able to mask signals.");
        exit_milter((options_t*)void_options, true);
    }

    int recieved_signal;
    while (true) {
        if (sigwait(&sig_set, &recieved_signal)) {
            syslog(LOG_ERR, "Sigwait failed, ending the program.");
            exit_milter((options_t*)void_options, true);
        }
        signal_handler(recieved_signal, (options_t*)void_options);
    }
}

/* Main function */
int main(int argc, char* argv[])
{
    options_t options = { 0 };
    init_options(argc, argv, &options);
    init_loging(&options);

    if (!(SETTINGS = settings_init(options.config_path))) {
        syslog(LOG_ERR, "Was not able to load settings. Please remove the config file to generate the default one.");
        exit_milter(&options, true);
    }

    if (options.verbose && smfi_setdbg(SETTINGS->milter_debug_level) != MI_SUCCESS) {
        syslog(LOG_ERR, "Was not able to turn on debug for milter.");
        exit_milter(&options, true);
    }

    if (!(DATABASE = db_construct(DATA_MUTEX, SETTINGS))) {
        syslog(LOG_ERR, "Was not able to construct a database.");
        exit_milter(&options, true);
    }

    if (!init_statistics()) {
        exit_milter(&options, true);
    }

    if (SETTINGS->save_database) {
        db_load(DATABASE);
    }

    if (!SETTINGS->socket_path || *SETTINGS->socket_path == '\0') {
        syslog(LOG_ERR, "Invalid socket path.");
        exit_milter(&options, true);
    }

    syslog(LOG_INFO, "Starting %s. Socket %s.", MILTER_NAME, SETTINGS->socket_path);

    if (options.daemon) {
        if (daemon(true, true)) {
            syslog(LOG_ERR, "Deamon function failed.");
            exit_milter(&options, true);
        }
        syslog(LOG_DEBUG, "[main] Daemon successfully started. PID: %u", getpid());
    }

    syslog(LOG_DEBUG, "[main] Starting working with threads.");

    if (smfi_setconn(SETTINGS->socket_path) != MI_SUCCESS) {
        syslog(LOG_ERR, "Connection with socket failed (lack of memory).");
        exit_milter(&options, true);
    }

    if (smfi_register(milter_struct) == MI_FAILURE) {
        syslog(LOG_ERR, "Was not able to establish a connection with the socket.");
        exit_milter(&options, true);
    }

    pthread_t thread_id;
    if (pthread_create(&thread_id, NULL, signals_thread, &options)) {
        syslog(LOG_ERR, "Was not able to create a signals handler thread.");
        exit_milter(&options, true);
    }

    if (pthread_detach(thread_id)) {
        syslog(LOG_ERR, "Was not able to detach signals thread.");
        exit_milter(&options, true);
    }

    if (smfi_opensocket(true) == MI_FAILURE) {
        syslog(LOG_ERR, "Was not able to create a socket (probably is being still used).");
        exit_milter(&options, true);
    }

    int return_value = smfi_main();
    if (return_value != MI_SUCCESS) {
        syslog(LOG_ERR, "Was not able to run the milter main function.");
        exit_milter(&options, true);
    }
    return return_value;
}

/*********************************************************************/
/**************************** MILTER PART ****************************/
/*********************************************************************/

/* Unknown or unimplemented SMTP command */
sfsistat mlfi_unknown(SMFICTX* ctx, const char* cmd)
{
    (void)ctx;
    syslog(LOG_WARNING, "Found an unknown command %s (ending connection).", cmd);
    syslog(LOG_DEBUG, "[mlfi_unknown] An unknown command, rejecting.");

    return SETTINGS->dry_run ? SMFIS_CONTINUE : SMFIS_REJECT; // This will call function 'mlfi_abort'
}

/* The connection was cancelled. */
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
        syslog(LOG_INFO, "Dry-run was activated.");
    }

    if (!hostaddr) {
        syslog(LOG_WARNING, "Host using old version of the SMTP protocol or message was send from stdin.");
    }

    syslog(LOG_DEBUG, "[mlfi_connect] Empty data structure. Starting initialisation.");
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

    if (hostname && hostname[0] == '[') {
        syslog(LOG_WARNING, "Reverse lookup failed, using original IP address.");
        data->sender_hostname = remove_brackets(hostname, '[', ']');
    } else {
        if (hostname) {
            data->sender_hostname = strdup(hostname);
        }
    }
    pthread_mutex_unlock(&DATA_MUTEX);

    if (!data->sender_hostname) {
        syslog(LOG_ERR, "Was not able to validate the sender IP address. Rejecting connection.");
        return SMFIS_TEMPFAIL;
    }

    syslog(LOG_DEBUG, "[mlfi_connect] Milter successfully established a connection. Hostname: %s", data->sender_hostname);
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

    pthread_mutex_lock(&DATA_MUTEX);
    data->from = remove_brackets(envfrom[0], '<', '>');
    pthread_mutex_unlock(&DATA_MUTEX);

    if (!data->from) {
        syslog(LOG_ERR, "Can not find the sender. Rejecting connection.");
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
        syslog(LOG_ERR, "Can not find the recipient. Rejecting connection.");
        return SMFIS_TEMPFAIL;
    }

    syslog(LOG_DEBUG, "[mlfi_envrcpt] Recipient found: %s", data->to);
    return SMFIS_CONTINUE;
}

/* Header parser */
sfsistat mlfi_header(SMFICTX* ctx, char* headerf, char* headerv)
{
    syslog(LOG_DEBUG, "[mlfi_header] Starting to parse %s : %s", headerf, headerv);
    private_data_t* data = smfi_getpriv(ctx);

    if (!data) {
        syslog(LOG_ERR, "Was not able to load private data. Rejecting connection from 'mlfi_header'.");
        return SMFIS_TEMPFAIL;
    }

    if (!strcmp(headerf, HEADER_SPAM)) {
        char* score_string = strstr(headerv, "score=");
        if (score_string) {
            char* end_ptr;
            errno = 0;
            float temp_spam_score = strtof(score_string + 6, &end_ptr);
            if (errno != 0 || end_ptr == headerv) {
                syslog(LOG_WARNING, "[mlfi_header] Was not able to parse the spam score. Skipping.");
                return SMFIS_CONTINUE;
            }

            pthread_mutex_lock(&DATA_MUTEX);
            data->spam_score = temp_spam_score;
            pthread_mutex_unlock(&DATA_MUTEX);
        }
    } else if (!strcmp(headerf, HEADER_SUBJECT)) {
        pthread_mutex_lock(&DATA_MUTEX);
        data->subject = strdup(headerv);
        pthread_mutex_unlock(&DATA_MUTEX);
    } else if (!strcmp(headerf, HEADER_FORWARD_COUNTER)) {
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
    } else if (!strcmp(headerf, HEADER_ID)) {
        pthread_mutex_lock(&DATA_MUTEX);
        data->email_id = remove_brackets(headerv, '<', '>');
        pthread_mutex_unlock(&DATA_MUTEX);
    } else if (!strcmp(headerf, HEADER_FROM)) {
        pthread_mutex_lock(&DATA_MUTEX);
        data->header_from = strdup(headerv);
        pthread_mutex_unlock(&DATA_MUTEX);
        syslog(LOG_DEBUG, "[mlfi_header] The email was originated from: %s.", data->header_from);
    } else if (!strcmp(headerf, HEADER_TO)) {
        pthread_mutex_lock(&DATA_MUTEX);
        data->header_to = strdup(headerv);
        pthread_mutex_unlock(&DATA_MUTEX);
    } else if (!strcmp(headerf, HEADER_QUARANTINE)) {
        pthread_mutex_lock(&DATA_MUTEX);
        data->header_quarantine = strcmp(headerv, "Yes");
        pthread_mutex_unlock(&DATA_MUTEX);
    } else if (!strcmp(headerf, HEADER_SCORE)) {
        char* end_ptr;
        errno = 0;
        int temp_score = (int)strtol(headerv, &end_ptr, 10);

        if (errno != 0 || *end_ptr != '\0' || end_ptr == headerv) {
            syslog(LOG_DEBUG, "[mlfi_header] Was not able to parse the score. Skipping.");
            return SMFIS_CONTINUE;
        }

        pthread_mutex_lock(&DATA_MUTEX);
        data->header_score = temp_score;
        pthread_mutex_unlock(&DATA_MUTEX);
    } else if (!strcmp(headerf, HEADER_INFO)) {
        syslog(LOG_DEBUG, "[mlfi_header] The email was already seen by the MUNI relay. Info: %s", headerv);
    }
    return SMFIS_CONTINUE;
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

    if (data->header_quarantine) {
        syslog(LOG_WARNING, "The email was already marked as spam (forward) with score: %d.", data->header_score);
    }

    if (!data->email_id) {
        syslog(LOG_ERR, "Invalid email ID.");
        return SMFIS_TEMPFAIL;
    }

    if (data->spam_score == -1) {
        syslog(LOG_WARNING, "Was not able to find the spam assassin score in the header of the email. This could be a potential problem.");
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
        syslog(LOG_WARNING, "The header does not contain a subject. Email ID: %s.", data->email_id);
    }

    if (validate_local(data->from) && validate_local(data->to)) {
        pthread_mutex_lock(&DATA_MUTEX);
        data->is_local = true;
        pthread_mutex_unlock(&DATA_MUTEX);
    }

    if (data->is_forward && data->is_local) {
        syslog(LOG_WARNING, "Local forward. This should not happened. From (original): %s. To: %s.", data->header_from, data->to);
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
    // Here can be added some kind of parser in future (for now will be empty)

    syslog(LOG_DEBUG, "[mlfi_body] The message body was successfully parsed.");
    return SMFIS_CONTINUE;
}

/* End of the message */
sfsistat mlfi_eom(SMFICTX* ctx)
{
    syslog(LOG_DEBUG, "[mlfi_eom] Entering function 'mlfi_eom'.");
    private_data_t* data = smfi_getpriv(ctx);

    if (is_blacklisted(data->sender_hostname, SETTINGS)) {
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

    if (!data) {
        syslog(LOG_ERR, "Was not able to load private data. Rejecting connection from 'mlfi_eom'.");
        return SMFIS_TEMPFAIL;
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
        syslog(LOG_WARNING, "Something is probably wrong with the email path. Forward counter: %d", amount_of_trips);
    }

    char temp_trip_value[16];
    sprintf(temp_trip_value, "%d", amount_of_trips);
    set_header(ctx, HEADER_FORWARD_COUNTER, temp_trip_value);

    int old_score = 0;
    time_t last_email_temp = time(0);

    entry_t* entry = db_get(DATABASE, data->sender_hostname);
    if (entry) {
        old_score = entry->score;
        last_email_temp = entry->last_email;
        syslog(LOG_DEBUG, "[mlfi_eom] The old entry was found taking the old score: %d.", old_score);
    }

    bool is_spam = data->header_quarantine;
    email_info_t email_info = {
        (int)data->spam_score,
        last_email_temp,
        data->is_auth,
        data->is_forward,
        data->is_local
    };

    int new_score = db_new_score(old_score, &email_info, SETTINGS);
    syslog(LOG_DEBUG, "[mlfi_eom] New score for email %s is: %d.", data->email_id, new_score);
    db_set(DATABASE, data->sender_hostname, time(0), new_score);

    if (!is_whitelisted(data->sender_hostname, SETTINGS)) {
        if (new_score >= SETTINGS->hard_score_limit) {
            pthread_mutex_lock(&DATA_MUTEX);
            STATTISTICS->hard_limit_counter++;
            pthread_mutex_unlock(&DATA_MUTEX);

            syslog(LOG_WARNING, "Email %s score reached hard spam limit and will be marked as spam.", data->email_id);
            is_spam = true;
            mark_as_spam(ctx, data);
        } else if (new_score >= SETTINGS->soft_score_limit) {
            pthread_mutex_lock(&DATA_MUTEX);
            STATTISTICS->soft_limit_counter++;
            pthread_mutex_unlock(&DATA_MUTEX);

            syslog(LOG_WARNING, "Email %s score reached soft spam limit. Forward: %s.", data->email_id, data->is_forward ? "Yes" : "No");
            if (data->is_auth) {
                syslog(LOG_DEBUG, "[mlfi_eom] User is logged in, we will be more strict.");
                mark_as_spam(ctx, data);
                is_spam = true;
            }

            if (!data->is_local && validate_local(data->from)) {
                syslog(LOG_WARNING, "Local email %s is probably used to send spam (password leak).", data->from);
            }
        } else {
            syslog(LOG_DEBUG, "[mlfi_eom] Email %s passed score check.", data->email_id);
        }
    } else {
        syslog(LOG_DEBUG, "[mlfi_eom] Sender hostname was found in the whitelist, skipping check. Email ID: %s.", data->email_id);
    }

    char temp_score_value[16];
    sprintf(temp_score_value, "%d", new_score);
    set_header(ctx, HEADER_SCORE, temp_score_value);

    set_header(ctx, HEADER_QUARANTINE, is_spam ? "Yes" : "No");
    set_header(ctx, HEADER_IS_AUTH, data->is_auth ? "Yes" : "No");
    set_header(ctx, HEADER_IS_FORWARD, data->is_forward ? "Yes" : "No");
    set_header(ctx, HEADER_IS_LOCAL, data->is_local ? "Yes" : "No");
    set_header(ctx, HEADER_FROM, data->header_from ? data->header_from : data->from);
    set_header(ctx, HEADER_TO, data->to);

eom_finish:;

    char temp_info_value[512];
    sprintf(temp_info_value, "%s version: %s made by %s", MILTER_NAME, VERSION, AUTHOR);
    set_header(ctx, HEADER_INFO, temp_info_value);

    syslog(LOG_INFO, "Message from %s to %s passed milter.", data->from, data->to);
    syslog(LOG_DEBUG, "[mlfi_eom] All changes at the end of the message were made. Email ID: %s", data->email_id);

    pthread_mutex_lock(&DATA_MUTEX);
    STATTISTICS->parsed_email_counter++;
    pthread_mutex_unlock(&DATA_MUTEX);

    return mlfi_cleanup(ctx, SMFIS_CONTINUE);
}

/* Cleanup after connection is closed */
sfsistat mlfi_cleanup(SMFICTX* ctx, sfsistat return_value)
{
    private_data_t* data = smfi_getpriv(ctx);
    syslog(LOG_DEBUG, "[mlfi_cleanup] Entering function 'mlfi_cleanup'. Starting cleanup.");

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

    pthread_mutex_lock(&DATA_MUTEX);
    if (smfi_setpriv(ctx, NULL) != MI_SUCCESS) {
        syslog(LOG_ERR, "Was not able to set private data to NULL.");
        return SMFIS_TEMPFAIL;
    }
    pthread_mutex_unlock(&DATA_MUTEX);

    db_cleanup(DATABASE);

    syslog(LOG_DEBUG, "[mlfi_cleanup] Successfully cleared all private data.");
    return return_value;
}
