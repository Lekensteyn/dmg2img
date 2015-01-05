/*
 * DMG2ISO base64.cc
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

#include "base64.h"
#include <stdlib.h>

bool is_base64(const char c)
{
	if ((c >= 'A' && c <= 'Z') ||
	    (c >= 'a' && c <= 'z') ||
	    (c >= '0' && c <= '9') ||
	    c == '+' ||
	    c == '/' ||
	    c == '=')
		return true;
	return false;
}

void cleanup_base64(char *inp, const unsigned int size)
{
	char *tinp1, *tinp2;
	unsigned int i;
	tinp1 = inp;
	tinp2 = inp;
	for (i = 0; i < size; i++) {
		if (is_base64(*tinp2)) {
			*tinp1++ = *tinp2++;
		} else {
			*tinp1 = *tinp2++;
		}
	}
	*(tinp1) = 0;
}

unsigned char decode_base64_char(const char c)
{
	if (c >= 'A' && c <= 'Z')
		return c - 'A';
	if (c >= 'a' && c <= 'z')
		return c - 'a' + 26;
	if (c >= '0' && c <= '9')
		return c - '0' + 52;
	if (c == '+')
		return 62;
	if (c == '=')
		return 0;
	return 63;
}

void decode_base64(const char *inp, unsigned int isize,
		        char *out, unsigned int *osize)
{
	char *tinp = (char *)inp;
	char *tout;
	unsigned int i;

	*osize = isize / 4 * 3;
	if (inp != out) {
		tout = (char *)malloc(*osize);
		out = tout;
	} else {
		tout = tinp;
	}
	for (i = 0; i < (isize >> 2); i++) {
		*tout = decode_base64_char(*tinp++) << 2;
		*tout++ |= decode_base64_char(*tinp) >> 4;
		*tout = decode_base64_char(*tinp++) << 4;
		*tout++ |= decode_base64_char(*tinp) >> 2;
		*tout = decode_base64_char(*tinp++) << 6;
		*tout++ |= decode_base64_char(*tinp++);
	}
	if (*(tinp - 1) == '=')
		(*osize)--;
	if (*(tinp - 2) == '=')
		(*osize)--;
}
