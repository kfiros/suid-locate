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

#ifndef __SUID_LOCATE_H__
#define __SUID_LOCATE_H__

/*******************************************************************
* Constants & Macros
*******************************************************************/

typedef enum {
	false = 0,
	true,
} bool;

#define SUCCESS (0)
#define ERROR (-1)
#define OUT

#define DIR_PATH ("/")
#define MAX_PATH_LENGTH (255)

#define PROC_DIR ("//proc\0")
#define PROC_DIR_LENGTH (5)

#define ISUID_ON(stat) ((S_ISUID == (S_ISUID & stat.st_mode)) && (S_IXUSR == (S_IXUSR & stat.st_mode)))
#define ISGID_ON(stat) ((S_ISGID == (S_ISGID & stat.st_mode)) && (S_IXGRP == (S_IXGRP & stat.st_mode)))


/* '.' and '..' are two known invalid directories,
*  we need to handle it properly */
#define THIS_FOLDER_STRING (".")
#define THIS_FOLDER_LENGTH (1)
#define UPPER_FOLDER_STRING ("..")
#define UPPER_FOLDER_LENGTH (2)

#define UNUSED(expr) do { (void)(expr); } while (false)

/*******************************************************************
* Prototypes 
*******************************************************************/
static void scan_suid_by_dir(const char * path);

#endif /* __SUID_LOCATE_H__*/
