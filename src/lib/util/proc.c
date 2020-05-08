/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 *
 * @brief Platform independent process functions
 * @file lib/util/proc.c
 *
 * @copyright 2020 Jorge Pereira (jpereira@freeradius.org)
 */
RCSID("$Id$")

#include <freeradius-devel/autoconf.h>
#include <freeradius-devel/util/proc.h>
#include <freeradius-devel/util/strerror.h>

#ifdef __APPLE__
#	include <sys/sysctl.h>
#	include <mach/mach.h>
#	include <mach/mach_vm.h>
#	include <mach/shared_region.h>
#endif

/** Get the current memory usage.
 *
 * all memory related values are returned in bytes.
 *
 * @return
 *	- true on success.
 *	- false on failure.
 */
#if defined(__APPLE__)
bool _fr_proc_addr_is_shared_region(mach_vm_address_t addr, cpu_type_t type);
bool _fr_proc_get_cpu_type(cpu_type_t *cpu_type);
bool fr_proc_get_memory_usage(fr_proc_memory_t *proc_memory)
{
	size_t private_pages_count = 0;
	size_t shared_pages_count = 0;
	cpu_type_t cpu_type;
	mach_vm_address_t address;
	mach_vm_size_t size = 0;
	mach_port_t task;

	fr_assert(proc_memory != NULL);

	task = mach_task_self();
	if (task == MACH_PORT_NULL) {
		fr_strerror_printf("Invalid process returned by mach_task_self()");
		return false;
	}

	if (!_fr_proc_get_cpu_type(&cpu_type)) return false;

	/**
	* The same region can be referenced multiple times. To avoid double counting
	* we need to keep track of which regions we've already counted.
	* int seen_objects[1024];
	* int seen_objects_len = 0;
	*
	* We iterate through each VM region in the task's address map. For shared
	* memory we add up all the pages that are marked as shared. Like libtop we
	* try to avoid counting pages that are also referenced by other tasks. Since
	* we don't have access to the VM regions of other tasks the only hint we have
	* is if the address is in the shared region area.
	*
	* Private memory is much simpler. We simply count the pages that are marked
	* as private or copy on write (COW).
	*
	* See libtop_update_vm_regions in
	* http:*www.opensource.apple.com/source/top/top-67/libtop.c
	*/
	for (address = MACH_VM_MIN_ADDRESS; ; address += size) {
		vm_region_top_info_data_t info;
		mach_msg_type_number_t info_count = VM_REGION_TOP_INFO_COUNT;
		mach_port_t object_name;
		kern_return_t kr;

		kr = mach_vm_region(task, &address, &size, VM_REGION_TOP_INFO, (vm_region_info_t)&info, &info_count, &object_name);
		if (kr == KERN_INVALID_ADDRESS) {
			/* We're at the end of the address space. */
			break;
		} else if (kr != KERN_SUCCESS) {
			fr_strerror_printf("mach_vm_region() is failed");
			return false;
		}

		/**
		 * The kernel always returns a null object for VM_REGION_TOP_INFO, but
		 * balance it with a deallocate in case this ever changes. See 10.9.2
		 * xnu-2422.90.20/osfmk/vm/vm_map.c vm_map_region.
		 */
		mach_port_deallocate(mach_task_self(), object_name);

		if (_fr_proc_addr_is_shared_region(address, cpu_type) && info.share_mode != SM_PRIVATE) continue;

		if (info.share_mode == SM_COW && info.ref_count == 1) info.share_mode = SM_PRIVATE;

		switch (info.share_mode) {
			case SM_PRIVATE:
				private_pages_count += info.private_pages_resident;
				private_pages_count += info.shared_pages_resident;
				break;
			case SM_COW:
				private_pages_count += info.private_pages_resident;

			/* Fall through */
			case SM_SHARED:
				shared_pages_count += info.shared_pages_resident;
				break;

			default:
				break;
		}
	}

	proc_memory->resident = (private_pages_count * PAGE_SIZE);
	proc_memory->shared   = (shared_pages_count  * PAGE_SIZE);

	return true;
}

bool _fr_proc_addr_is_shared_region(mach_vm_address_t addr, cpu_type_t type) {
	mach_vm_address_t base;
	mach_vm_address_t size;

	switch (type) {
		case CPU_TYPE_ARM:
			base = SHARED_REGION_BASE_ARM;
			size = SHARED_REGION_SIZE_ARM;
			break;
		case CPU_TYPE_I386:
			base = SHARED_REGION_BASE_I386;
			size = SHARED_REGION_SIZE_I386;
			break;
		case CPU_TYPE_X86_64:
			base = SHARED_REGION_BASE_X86_64;
			size = SHARED_REGION_SIZE_X86_64;
			break;
		default:
			return false;
	}

	return (base <= addr && addr < (base + size));
}

bool _fr_proc_get_cpu_type(cpu_type_t *cpu_type) {
	size_t len = sizeof(*cpu_type);

	if (sysctlbyname("sysctl.proc_cputype", cpu_type, &len, NULL, 0) != 0) {
		fr_strerror_printf("Problems to call sysctlbyname(\"sysctl.proc_cputype\")");
		return false;
	}

	return true;
}
#elif defined(__linux__)
bool fr_proc_get_memory_usage(fr_proc_memory_t *proc_memory) {
	int ret;
	const char *proc_statm = "/proc/self/statm";
	FILE *f;

	fr_assert (proc_memory != NULL);

	f = fopen(proc_statm, "r");
	if (!f) {
		fr_strerror_printf("Problems with fopen(%s)", proc_statm);
		return false;
	}

	/**
	 * The 7 fields as described in https://github.com/torvalds/linux/blob/master/fs/proc/array.c#L635
	 */
	ret = fscanf(f, "%lu %lu %lu %lu 0 %lu 0", &proc_memory->size,
						   &proc_memory->resident,
						   &proc_memory->shared,
						   &proc_memory->text,
						   &proc_memory->data);
	if (ret != 5) {
		fr_strerror_printf("Unexpected content of %s", proc_statm);
		fclose(f);
		return false;
	}

	fclose(f);

	return true;
}
#else
bool fr_proc_get_memory_usage(UNUSED fr_proc_memory_t *proc_memory) {
	fr_strerror_printf("fr_proc_get_memory_usage not implemented");
	return false;
}
#endif