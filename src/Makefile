#****************************************************************************************
# Copyright [2022] [Patrik Čelko]
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
# file except in compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the License for the specific language governing
# permissions and limitations under the License.
#
#****************************************************************************************

#********************************* MUNI - Milter ****************************************
#
# FILENAME:    Makefile
# DESCRIPTION: Makefile manager
# AUTHOR:      Patrik Čelko
# REPOSITORY:  https://github.com/patrikcelko/MUNI-Milter
#
#****************************************************************************************

MILTER_TARGET = milter

INCLUDE_PATH = ./include
LIB_DATABASE_PATH = ./libs/database
LIB_SETTINGS_PATH = ./libs/settings
SOCKET_PATH = /tmp/f1.sock

FORMAT-STYLE = WebKit

CFLAGS = -std=c99 -Wall -pedantic -Wextra

all: $(MILTER_TARGET)

rebuild: clean all fix-socket

$(MILTER_TARGET): LDLIBS += -pthread

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

%: %.o
	$(CC) -I$(INCLUDE_PATH) -o $@ $^ -lmilter $(LDLIBS) $(LOADLIBES)

$(MILTER_TARGET) : $(LIB_DATABASE_PATH).o
$(MILTER_TARGET).o : $(LIB_DATABASE_PATH).h
$(LIB_DATABASE_PATH).o : $(LIB_DATABASE_PATH).h

$(MILTER_TARGET) : $(LIB_SETTINGS_PATH).o
$(MILTER_TARGET).o : $(LIB_SETTINGS_PATH).h
$(LIB_SETTINGS_PATH).o : $(LIB_SETTINGS_PATH).h

$(MILTER_TARGET).o : $(MILTER_TARGET).h
$(MILTER_TARGET).o : $(MILTER_TARGET).c

clean:
	$(RM) *.o $(MILTER_TARGET) $(LIB_DATABASE_PATH).o $(LIB_SETTINGS_PATH).o *.cfg *.data

fix-socket:
	$(RM) $(SOCKET_PATH)

valgrind: rebuild
	valgrind --verbose --leak-check=full --track-origins=yes --show-leak-kinds=all ./$(MILTER_TARGET) -v

helgrind: rebuild
	valgrind --tool=helgrind --verbose ./$(MILTER_TARGET) -v

tidy:
	clang-tidy --use-color -checks=-clang-analyzer-security.* $(LIB_SETTINGS_PATH).c
	clang-tidy --use-color -checks=-clang-analyzer-security.* $(LIB_DATABASE_PATH).c
	clang-tidy --use-color -checks=-clang-analyzer-security.* ./$(MILTER_TARGET).c

format:
	clang-format -style=$(FORMAT-STYLE) -i $(LIB_SETTINGS_PATH).h
	clang-format -style=$(FORMAT-STYLE) -i $(LIB_SETTINGS_PATH).c
	clang-format -style=$(FORMAT-STYLE) -i $(LIB_DATABASE_PATH).h
	clang-format -style=$(FORMAT-STYLE) -i $(LIB_DATABASE_PATH).c
	clang-format -style=$(FORMAT-STYLE) -i ./$(MILTER_TARGET).c
	clang-format -style=$(FORMAT-STYLE) -i ./$(MILTER_TARGET).h


.PHONY: all clean rebuild fix-socket valgrind format tidy helgrind
