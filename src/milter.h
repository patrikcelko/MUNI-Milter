/********************************** MUNI - Milter ***********************************
 *
 * FILENAME:    milter.h
 * DESCRIPTION: Header file for the milter.
 * NOTES:       This milter will need additional libs (settings, database) to run.
 * AUTHOR:      Patrik Čelko
 *
 *************************************************************************************/

#ifndef MILTER_H
#define MILTER_H

/* Options structure */
struct options {
    bool daemon;
    bool verbose;
    char* config_path;
};

/* Milter statistics structure */
struct statistics {
    unsigned long long int hard_limit_counter;
    unsigned long long int soft_limit_counter;
    unsigned long long int marked_as_spam_counter;
    unsigned long long int parsed_email_counter;
};

/* Email information structure */
struct private_data {
    bool is_forward; // [mlfi_eoh] Is email forward
    bool is_local; // [mlfi_eoh] True if email travel only in the local network
    bool is_auth; // [mlfi_envfrom] True if a user is authenticated
    bool header_quarantine; // [mlfi_header] Value from header - Was marked as dangerous email
    int forward_counter; // [mlfi_header] How many times was email seen?
    int header_score; // [mlfi_header] Value from header - Score from previews runs through milter
    float spam_score; // [mlfi_header] Spam assassin score
    char* sender_hostname; // [mlfi_connect] Sender IP or DNS
    char* email_id; // [mlfi_header] Email ID
    char* from; // [mlfi_envfrom] Email sender
    char* to; // [mlfi_envrcpt] Email recipient
    char* subject; // [mlfi_header] Email subject
    char* header_from; // [mlfi_header] Value from header - Email sender
    char* header_to; // [mlfi_header] Value from header - Email recipient
};

typedef struct options options_t;
typedef struct private_data private_data_t;
typedef struct statistics statistics_t;

/* Cleanup after the connection is closed */
sfsistat mlfi_cleanup(SMFICTX* ctx, sfsistat return_value);

/* Try to make a milter connection */
sfsistat mlfi_connect(SMFICTX* ctx, char* hostname, _SOCK_ADDR* hostaddr);

/* Envelope sender */
sfsistat mlfi_envfrom(SMFICTX* ctx, char** envfrom);

/* Envelope recipient */
sfsistat mlfi_envrcpt(SMFICTX* ctx, char** envrcpt);

/* Header parser */
sfsistat mlfi_header(SMFICTX* ctx, char* headerf, char* headerv);

/* The body part of the message */
sfsistat mlfi_body(SMFICTX* ctx, u_char* bodyp, size_t bodylen);

/* End of the header */
sfsistat mlfi_eoh(SMFICTX* ctx);

/* End of the message */
sfsistat mlfi_eom(SMFICTX* ctx);

/* Data manipulation */
sfsistat mlfi_data(SMFICTX* ctx);

/* Unknown or unimplemented SMTP command */
sfsistat mlfi_unknown(SMFICTX* ctx, const char* cmd);

/* The message was aborted */
sfsistat mlfi_abort(SMFICTX* ctx);

/* The connection was cancelled. */
sfsistat mlfi_close(SMFICTX* ctx);

#endif