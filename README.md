# MUNI-Milter

This code is a part of the bachelor thesis named Mail filtering of spam with Milter extensions made by Patrik Čelko.

In this implementation, we are primarily dealing with the logic of selective spam separation, for which we are using our chosen algorithm working with the already existing score obtained from SpamAssassin and the intensity of incoming emails. Of course, the implementation also includes the detection of forwarded emails and different policies for authenticated users, internal Masaryk University devices, and possible behavioral differentiation based on target IP addresses. The implementation itself could not have been done without add-ons such as a simple database system and a settings parser, which are also included.

## Running Milter and the related tools

Before compilation, we would need to install the lib used by Milter. To install it we can use:

> ```sudo apt install libmilter-dev```

In the source folder, we included a Makefile that helps with compilation, formatting and even detecting bugs with hellgrind and valgrind. Usage:

>  ```make``` - Compile files related to our Milter that were changed \
>  ```make format``` - Format all *.h and *.c files included in this project \
>  ```make tidy``` - Call clang-tidy on all parts of the milter \
>  ```make valgrind``` - Run Milter with valgrind enabled \
>  ```make helgrind``` - Run Milter with helgrind enabled \
>  ```make rebuild``` - Clean the config file, remove the test socket and rebuild all binaries

Now we can start milter using the command: ```./milter [OPTIONS]```.

With possible options:
>  ```-h,--help``` - Show help \
>  ```-V,--version``` - Display Milter version \
>  ```-v,--verbose``` - Show debug and additional messages \
>  ```-c,--config [path]``` - Load config file from the specific path \
>  ```-d,--daemon``` - Run Milter as a daemon

## Setting up Sendmail

After successfully compiling the binaries, we would need to set up the Sendmail to correctly work with our Milter. We would do that by simply adding these two lines to the Sendmail's config file (it will register our Milter for the Sendmail):

```
INPUT_MAIL_FILTER(`MUNI-Milter', `S=unix:<socket-path>, F=R')
define(`confINPUT_MAIL_FILTERS', `MUNI-Milter')
```

Note: Using the default path for a socket is not recommended and might cause security problems.

Also if you do not already have an enabled macro named ```client_addr``` you need to add the following lines:
```
LOCAL_RULESETS
SLocal_check_mail
R $*                    $: $&{client_addr}
R ${ourdomain} . $-     $@ OK our domain
R $*                    $#error $@ 5.7.1 $: "550 cannot send out from the outside"
```
