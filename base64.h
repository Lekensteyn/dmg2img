/*
 * DMG2ISO base64.h
 * 
 * Copyright (c) 2004 vu1tur <to@vu1tur.eu.org> This program is free software; you
 * can redistribute it and/or modify it under the terms of the GNU General
 * Public License as published by the Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#define bool short
#define true 1
#define false 0

void decode_base64(const char *inp, unsigned int isize,
		        char *out, unsigned int *osize);

unsigned char decode_base64_char(const char c);
void cleanup_base64(char *inp, const unsigned int size);
bool is_base64(const char c);
