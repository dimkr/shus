#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>
#include <stdlib.h>
#include <libgen.h>
#include <assert.h>
#include <string.h>
#include <limits.h>

#include "common.h"

/* the usage messge */
#define USAGE "Usage: shus-index DIRCTORY\n"

/* the index page header */
#define HEADER \
	"<!DOCTYPE HTML>\n" \
	"<html>\n" \
	"	<head>\n" \
	"		<title>Index of %s</title>\n" \
	"		<meta http-equiv=\"Content-Type\" content=\"text/html; " \
	"charset=UTF-8\">\n" \
	"		<meta charset=\"UTF-8\">\n" \
	"	</head>\n" \
	"	<body>\n" \
	"		<h1>Index of %s</h1>\n" \
	"		<ul>\n"

/* the index page footer */
#define FOOTER \
	"		</ul>\n" \
	"	</body>\n" \
	"</html>"

int main(int argc, char *argv[]) {
	/* the index path */
	char path[PATH_MAX] = {'\0'};

	/* a file under the directory */
	struct dirent entry = {0};

	/* the path length */
	int length = 0;

	/* the exit code */
	int exit_code = EXIT_FAILURE;

	/* the directory */
	DIR *directory = NULL;

	/* the output file */
	FILE *index = NULL;

	/* the return value of readdir_r() */
	struct dirent *result = NULL;

	/* the directory base name */
	const char *base_name = NULL;

	/* parse the command-line */
	if (2 != argc) {
		PRINT(USAGE);
		goto end;
	}

	/* format the output file path */
	length = snprintf(path, sizeof(path), "%s/"INDEX_PAGE, argv[1]);
	if ((sizeof(path) <= length) || (0 > length)) {
		goto end;
	}

	/* open the directory */
	directory = opendir(argv[1]);
	if (NULL == directory) {
		goto end;
	}

	/* open the output file */
	index = fopen(path, "w");
	if (NULL == index) {
		goto close_directory;
	}

	/* write the header */
	base_name = basename(argv[1]);
	assert(NULL != base_name);
	if (0 > fprintf(index, HEADER, base_name, base_name)) {
		goto close_index;
	}

	do {
		/* read the name and type of one file under the directory */
		if (0 != readdir_r(directory, &entry, &result)) {
			goto close_index;
		}
		if (NULL == result) {
			break;
		}

		/* skip hidden files or relative paths */
		if ('.' == result->d_name[0]) {
			continue;
		}

		/* skip the index page */
		if (0 == strcmp(INDEX_PAGE, result->d_name)) {
			continue;
		}

		/* add a link to the index */
		if (0 > fprintf(index, "\t\t\t<li>%s</li>\n", result->d_name)) {
			goto close_index;
		}
	} while (1);

	/* write the footer */
	if (STRLEN(FOOTER) != fwrite(FOOTER, sizeof(char), STRLEN(FOOTER), index)) {
		goto close_index;
	}

	/* report success */
	exit_code = EXIT_SUCCESS;

close_index:
	/* close the output file */
	(void) fclose(index);

close_directory:
	/* close the directory */
	(void) closedir(directory);

end:
	return exit_code;
}
