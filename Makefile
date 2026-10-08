#   Copyright (C) 2023 John Törnblom
#
# This file is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING. If not see
# <http://www.gnu.org/licenses/>.
PS5_HOST ?= ps5
PS5_PORT ?= 9021
PS5_PAYLOAD_SDK ?= /opt/ps5-payload-sdk
ifdef PS5_PAYLOAD_SDK
    include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
else
    $(error PS5_PAYLOAD_SDK is undefined)
endif
ELF := entitlements.elf
SERVICE_LABEL ?= 0
CFLAGS := -Wall -Werror -g -DSERVICE_LABEL=$(SERVICE_LABEL)
LDFLAGS := -lSceSysmodule
# $(ELF) is phony so changing SERVICE_LABEL on the command line always rebuilds.
.PHONY: all clean test test-host debug $(ELF)
all: $(ELF)
$(ELF): main.c
	$(CC) $(CFLAGS) -o $@ main.c $(LDFLAGS)
test-host:
	gcc -Wall -Werror -o tests/test_parse_pid tests/test_parse_pid.c && tests/test_parse_pid
	gcc -Wall -Werror -o tests/test_find_game_pid_filter tests/test_find_game_pid_filter.c && tests/test_find_game_pid_filter
	gcc -Wall -Werror -o tests/test_output_format tests/test_output_format.c && tests/test_output_format
clean:
	rm -f $(ELF) tests/test_parse_pid tests/test_find_game_pid_filter tests/test_output_format
test: $(ELF)
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $^
debug: $(ELF)
	gdb-multiarch \
	-ex "set architecture i386:x86-64" \
	-ex "target extended-remote $(PS5_HOST):2159" \
	-ex "file $(ELF)" \
	-ex "remote put $(ELF) /data/$(ELF)" \
	-ex "set remote exec-file /data/$(ELF)" \
	-ex "start"
