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
 * FILENAME:    milter.h
 * DESCRIPTION: Header file for the Milter.
 * NOTES:       This Milter will need additional libs (settings, database) to run.
 * AUTHOR:      Patrik Čelko
 * REPOSITORY:  https://github.com/patrikcelko/MUNI-Milter
 *
 *****************************************************************************************/

#ifndef MILTER_H
#define MILTER_H

/* Senders category */
enum spam_type {
    NORMAL,
    SPAM,
    SUPERSPAM
};

/* Options structure */
struct options {
    bool daemon;
    bool verbose;
    char* config_path;
};

/* Representation of the statistics record */
struct statistic_record {
    char* name; // Name of the record (relay or faculty server name)
    unsigned long long int forwarded_emails_counter;
    unsigned long long int parsed_email_counter;
    unsigned long long int super_spam_counter;
    unsigned long long int spam_counter;
    float average_score;
    float average_time;
};

typedef struct statistic_record statistics_record_t;

/* Milter statistics structure */
struct statistics {
    size_t array_size;
    // An array containing all statistics records.
    // We can assume that we would not have more than 256 records.
    statistics_record_t* data[256];
};

/* Email information structure */
struct private_data {
    bool is_forward; // [mlfi_eoh] Is email forward
    bool is_local; // [mlfi_eoh] True if email travel only in the local network
    bool is_auth; // [mlfi_envfrom] True if a user is authenticated
    bool header_quarantine; // [mlfi_header] Value from header - Was marked as a dangerous email
    int forward_counter; // [mlfi_header] How many times was the email seen?
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
typedef enum spam_type spam_type_t;

/* Misc functions */
void exit_milter(bool is_fail);
void print_statistics();

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