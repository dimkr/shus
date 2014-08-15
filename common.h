#ifndef _COMMON_H_INCLUDED
#	define _COMMON_H_INCLUDED

#	include <unistd.h>

/* constant string length */
#	define STRLEN(x) (sizeof(x) - sizeof(char))

/* the index page extension */
#	define INDEX_EXTENSION "html"

/* the index page name / */
#	define INDEX_PAGE "index."INDEX_EXTENSION

/* output of a constant string */
#	define PRINT(x) (void) write(STDOUT_FILENO, x, STRLEN(x))

#endif
