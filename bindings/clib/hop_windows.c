// Exported functions run on threads this file owns while the caller waits on its own stack.
// A host runtime may send the calling thread a special user APC at any moment. Windows will
// not resume a thread whose stack pointer is outside the TEB's stack bounds, which is where
// a goroutine stack is: NtContinueEx answers 0xC000000D and the process dies.
// Linked with -Wl,--wrap=crosscall2, the one door every cgo export goes through.

#include <windows.h>
#include <stdlib.h>

void __real_crosscall2(void (*fn)(void*), void* frame, int size, size_t ctxt);

typedef struct hop_worker {
    void (*fn)(void*);
    void* frame;
    int size;
    size_t ctxt;
    HANDLE wake;
    HANDLE done;
    struct hop_worker* next;
} hop_worker;

static SRWLOCK hop_lock = SRWLOCK_INIT;
static hop_worker* hop_idle = NULL;

static DWORD WINAPI hop_run(LPVOID arg) {
    hop_worker* w = (hop_worker*)arg;
    for (;;) {
        WaitForSingleObject(w->wake, INFINITE);
        __real_crosscall2(w->fn, w->frame, w->size, w->ctxt);
        SetEvent(w->done);
    }
    return 0;
}

static hop_worker* hop_start(void) {
    HANDLE t;
    hop_worker* w = (hop_worker*)calloc(1, sizeof(hop_worker));
    if (w == NULL) {
        abort();
    }

    w->wake = CreateEventW(NULL, FALSE, FALSE, NULL);
    w->done = CreateEventW(NULL, FALSE, FALSE, NULL);
    t = CreateThread(NULL, 0, hop_run, w, 0, NULL);
    if (w->wake == NULL || w->done == NULL || t == NULL) {
        abort();
    }

    CloseHandle(t);
    return w;
}

void __wrap_crosscall2(void (*fn)(void*), void* frame, int size, size_t ctxt) {
    hop_worker* w;

    AcquireSRWLockExclusive(&hop_lock);
    w = hop_idle;
    if (w != NULL) {
        hop_idle = w->next;
    }
    ReleaseSRWLockExclusive(&hop_lock);

    if (w == NULL) {
        w = hop_start();
    }

    w->fn = fn;
    w->frame = frame;
    w->size = size;
    w->ctxt = ctxt;
    SetEvent(w->wake);
    WaitForSingleObject(w->done, INFINITE);

    AcquireSRWLockExclusive(&hop_lock);
    w->next = hop_idle;
    hop_idle = w;
    ReleaseSRWLockExclusive(&hop_lock);
}
