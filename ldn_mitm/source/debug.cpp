/*
 * Copyright (c) 2018 Atmosphère-NX
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
 
#include <switch.h>
#include <stratosphere.hpp>
#include <cstring>
#include "debug.hpp"

void Reboot() {
    /* ... */
}

void Log(const void *data, int size) {
    (void)(data);
    (void)(size);
    /* ... */
}

void LogStr(const char *str) {
    FILE *file = fopen("sdmc:/space.log", "a+");
    fwrite(str, 1, strlen(str), file);
    fclose(file);
}