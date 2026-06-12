/*
 * payload.c — Position-independent payload for GapMap.
 *
 * All strings on the stack. No .rdata, no imports, no relocations.
 * Resolves kernel32 via PEB, finds APIs by export table parsing.
 *
 * Build: gcc -O2 -nostdlib -fno-asynchronous-unwind-tables -fno-ident
 *            -e payload_entry -Wl,--section-alignment,4096
 *            -Wl,--file-alignment,512 -Wl,-s -Wl,--no-seh
 *            -o payload.exe payload.c
 */

#include <stdint.h>

typedef void          *HANDLE;
typedef unsigned long  DWORD;
typedef int            BOOL;
typedef unsigned short WORD;
typedef unsigned char  BYTE;

/* PEB/LDR — opaque reserved blocks to the fields we actually read.
 * Avoids faking per-field layouts that only work by luck with padding. */

typedef struct { WORD Length; WORD MaxLen; wchar_t *Buffer; } USTR;

typedef struct {
    void *InLoadOrderLinks[2];   /* +0x00 */
    void *InMemoryOrderLinks[2]; /* +0x10 */
    void *InInitOrderLinks[2];   /* +0x20 */
    void *DllBase;               /* +0x30 */
    void *EntryPoint;            /* +0x38 */
    BYTE  pad_40[8];             /* +0x40  SizeOfImage + alignment */
    USTR  FullDllName;           /* +0x48 */
    USTR  BaseDllName;           /* +0x58 */
} LDR_ENTRY;

typedef struct {
    BYTE  reserved[0x10]; /* Length, Initialized, SsHandle */
    void *InLoadOrder[2]; /* +0x10 */
} LDR_DATA;

typedef struct {
    BYTE      reserved[0x18]; /* misc fields before Ldr */
    LDR_DATA *Ldr;            /* +0x18 */
} PEB;

/* PE export directory */

typedef struct {
    DWORD Characteristics, TimeDateStamp;
    WORD  MajorVersion, MinorVersion;
    DWORD Name, Base, NumberOfFunctions, NumberOfNames;
    DWORD AddressOfFunctions, AddressOfNames, AddressOfNameOrdinals;
} EXPORT_DIR;

/* ASCII-only case-insensitive compare for DLL name matching */
static int wicmp(const wchar_t *w, const char *a)
{
    for (;;) {
        wchar_t wc = *w++;
        char    ac = *a++;
        if (wc >= 'A' && wc <= 'Z') wc += 32;
        if (ac >= 'A' && ac <= 'Z') ac += 32;
        if (wc != (wchar_t)ac) return 1;
        if (ac == 0) return 0;
    }
}

static int streq(const char *a, const char *b)
{
    while (*a && *a == *b) { a++; b++; }
    return *a == *b;
}

static void *find_module(const char *name)
{
    PEB *peb;
    __asm__ volatile ("movq %%gs:0x60, %0" : "=r"(peb));
    LDR_DATA *ldr = peb->Ldr;
    uint8_t *head = (uint8_t *)ldr->InLoadOrder[0];
    uint8_t *cur  = head;
    do {
        LDR_ENTRY *e = (LDR_ENTRY *)cur;
        if (e->BaseDllName.Buffer && e->DllBase)
            if (wicmp(e->BaseDllName.Buffer, name) == 0)
                return e->DllBase;
        cur = *(uint8_t **)cur;
    } while (cur != head);
    return 0;
}

#define DOS_E_LFANEW     0x3C
#define PE_EXPORT_DD_OFF (4 + 20 + 112) /* PE sig + COFF header + opt header to export dir */

static void *get_proc(void *base, const char *name)
{
    uint8_t *b = (uint8_t *)base;
    if (*(WORD *)b != 0x5A4D) return 0;

    int e_lfanew = *(int *)(b + DOS_E_LFANEW);
    DWORD export_rva = *(DWORD *)(b + e_lfanew + PE_EXPORT_DD_OFF);
    if (!export_rva) return 0;

    EXPORT_DIR *exp = (EXPORT_DIR *)(b + export_rva);
    DWORD *funcs = (DWORD *)(b + exp->AddressOfFunctions);
    DWORD *names = (DWORD *)(b + exp->AddressOfNames);
    WORD  *ords  = (WORD  *)(b + exp->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exp->NumberOfNames; i++)
        if (streq((const char *)(b + names[i]), name))
            return (void *)(b + funcs[ords[i]]);
    return 0;
}

typedef HANDLE (__attribute__((ms_abi)) *fnCreateEventA)(void *, BOOL, BOOL, const char *);
typedef BOOL   (__attribute__((ms_abi)) *fnSetEvent)(HANDLE);
typedef void   (__attribute__((ms_abi)) *fnSleep)(DWORD);

__attribute__((section(".text"), ms_abi))
unsigned long payload_entry(void *param)
{
    (void)param;

    char k32[]  = {'k','e','r','n','e','l','3','2','.','d','l','l',0};
    char sCA[]  = {'C','r','e','a','t','e','E','v','e','n','t','A',0};
    char sSE[]  = {'S','e','t','E','v','e','n','t',0};
    char sSl[]  = {'S','l','e','e','p',0};
    char sEvt[] = {'G','a','p','M','a','p','A','l','i','v','e',0};

    void *k = find_module(k32);
    if (!k) return 1;

    fnCreateEventA pCreateEvent = (fnCreateEventA)get_proc(k, sCA);
    fnSetEvent     pSetEvent    = (fnSetEvent)get_proc(k, sSE);
    fnSleep        pSleep       = (fnSleep)get_proc(k, sSl);
    if (!pCreateEvent || !pSetEvent || !pSleep) return 1;

    HANDLE evt = pCreateEvent(0, 1, 0, sEvt);
    if (evt) pSetEvent(evt);

    for (;;) pSleep(1000);
}
