#ifndef DBG_H
#define DBG_H

#ifdef DEBUG
#define dprintf(...) fprintf(stderr, __VA_ARGS__)
#else
#define dprintf(...)
#endif

#endif	/* DBG_H */
