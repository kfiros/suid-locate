/*******************************************************************
* Project:	SUID-Locate
*		SUID-Locate searches for files with the SUID/SGID
*		bit on.
*
* Author:	Kfiros (Kfir Shtober)
* Year:		2015	
*
* File:		suid_locate.c
* Description:	Easily finds files with the SUID or SGID bit on.
*		Setuid/gid can be very handy when properly used,
*		however, it can expose your system to many security
*		risks.
*******************************************************************/

/*******************************************************************
* Includes
*******************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <dirent.h>
#include "suid_locate.h"

/*******************************************************************
* Name: 	exclude_path
* Description:	This function decides whether a specific path
*		should be excluded.
*******************************************************************/
static bool exclude_path(const char * path) {
	bool ret = false;

	if (NULL == path) {
		ret = true;
		goto cleanup;
	}

	/* Avoid /proc directory */
	if (0 == strncmp(path, PROC_DIR, PROC_DIR_LENGTH)) {
		ret = true;
		goto cleanup;
	}

cleanup:	
	return ret;
}

/*******************************************************************
* Name: 	check_suid
* Description:	Tests for SUID/GUID bit turned on a given path.
*******************************************************************/
static int check_suid(const char * path, OUT bool * is_suid) {
	int ret = SUCCESS;
	int call_rv;
	struct stat path_stat;
		
	/* Get file status */
	call_rv = stat(path, &path_stat);
	if (ERROR == call_rv) {
		ret = ERROR;
		goto cleanup;
	}

	/* Check if SUID/SGID bit is turned on */
	if ((ISUID_ON(path_stat)) || (ISGID_ON(path_stat))) {
		*is_suid = true;
		goto cleanup;
	} else {
		*is_suid = false;
	}
cleanup:
	return ret;
}

/*******************************************************************
* Name: 	invalid_dir
* Description:	Examines if a given directory name is invalid.
*******************************************************************/
static bool invalid_dir_name(const char * name) {
	bool ret = false;
	
	if (NULL == name) {
		ret = true;
		goto cleanup;
	}

	if ((THIS_FOLDER_LENGTH == strlen(name)) && 
				(0 == strncmp(name, THIS_FOLDER_STRING, THIS_FOLDER_LENGTH))) {
		ret = true;
		goto cleanup;
	}

	if ((UPPER_FOLDER_LENGTH == strlen(name)) &&
				(0 == strncmp(name, UPPER_FOLDER_STRING, UPPER_FOLDER_LENGTH))) {
		ret = true;
		goto cleanup;
	}

cleanup:
	return ret;
}

/*******************************************************************
* Name: 	analyze_entry
* Description:	This function analyzes a given direntry. In case it's a
*		directory it lists it, and in case of file it checks
*		it for suid/sgid.
*******************************************************************/
inline static void analyze_entry(const char * path, struct dirent * entry) {
		int call_rv;
		char full_entry_path[MAX_PATH_LENGTH];
		bool is_suid = false;

		if (DT_DIR == entry->d_type) { /* DIRECTORY */
			if (true == invalid_dir_name(entry->d_name)) {
				return;
			}
			/* Create updated full path */			
			snprintf(full_entry_path, MAX_PATH_LENGTH, "%s/%s", path, entry->d_name);	

			if (true == exclude_path(full_entry_path)) {
				return;
			}

			/* Recursively walk over the directory contents */
			scan_suid_by_dir(full_entry_path);

		} else { /* FILE */
			/* Create updated full path */			
			snprintf(full_entry_path, MAX_PATH_LENGTH, "%s/%s", path, entry->d_name);	

			/* Check for suid/sgid */
			call_rv = check_suid(full_entry_path, &is_suid);
			if (SUCCESS != call_rv) {
				return;
			} else if(true == is_suid){
				fprintf(stdout, "[+] %s\n", full_entry_path + 1); /* + 1 to avoid the first slash */
			}
		}
}

/*******************************************************************
* Name: 	scan_suid_by_dir
* Description:	Recursively scans the given path for suid/sgid files.
*******************************************************************/
static void scan_suid_by_dir(const char * path) {
	DIR * dir_stream;
	struct dirent * entry;

	dir_stream = opendir(path);
	if (NULL == dir_stream) {
		return;
	}

	entry = readdir(dir_stream);	
	if (NULL == entry) {
		goto cleanup;
	}
	
	do {
		analyze_entry(path, entry);

	} while ((entry = readdir(dir_stream)));
cleanup:
	if (NULL != dir_stream) {
		closedir(dir_stream);
	}	
}

/*******************************************************************
* Name: 	main
* Description:	Main function of the program
*******************************************************************/
int main() {
	fprintf(stdout, "[*] suid-locate (Kfiros 2015) \n");
	fprintf(stdout, "[*] Searching for SUID/SGID files in your system... \n");

	/* Start main logic */
	scan_suid_by_dir(DIR_PATH);

	fprintf(stdout, "[*] DONE \n");

	return SUCCESS;
}

