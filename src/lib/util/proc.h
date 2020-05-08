#pragma once
/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 *
 * @brief Platform independent process functions
 * @file lib/util/proc.h
 *
 * @copyright 2020 Jorge Pereira (jpereira@freeradius.org)
 */
RCSIDH(proc_h, "$Id$")

#include <freeradius-devel/missing.h>
#include <freeradius-devel/util/debug.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Hold the status of memory usage (in bytes).
 */
typedef struct {
	size_t size;		//!< The current memory size.
	size_t shared;		//!< Entire memory that this process has shared.
	size_t resident;	//!< The current size, in bytes, of memory that this process has
				// allocated that cannot be shared with other processes
	size_t text;		//!< The amount of physical memory devoted to executable code.
	size_t data;		//!< physical memory devoted to other than executable code
} fr_proc_memory_t;

bool fr_proc_get_memory_usage(fr_proc_memory_t *proc_memory);

#ifdef __cplusplus
}
#endif
