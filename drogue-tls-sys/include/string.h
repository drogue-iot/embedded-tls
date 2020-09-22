#define NULL ((void*)0)

extern void* memset(void*, int, unsigned int);
extern void* memcpy(void*, const void*, unsigned int);
extern int memcmp(const void*, const void*, unsigned int);
extern void* memmove(void*, const void*, unsigned int);

extern int strcmp(const char *, const char*);
extern unsigned int strlen(const char *);
extern char* strstr(const char *, const char *);
extern char* strncpy(char *, const char *, unsigned int);
extern int strncmp(const char*, const char *, unsigned int);
