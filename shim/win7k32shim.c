/*
 * win7k32shim.dll —— 给 Windows 7 补上 python313.dll 需要的 6 个
 * 仅 Windows 8 / 8.1 才提供的 KERNEL32 导出。
 *
 * 设计要点：**先探测、再转发**。
 *   - 若系统（Win8+）本身就有该 API，直接转发给系统实现，行为 100% 一致；
 *   - 若没有（Win7），用等价手段模拟，或退化为「明确失败」而不是崩溃。
 * 这样这个包在 Win7 上能用，在 Win8/10/11 上也不会因为本 shim 而变差。
 *
 * 被替代的 7 个函数：
 *   CopyFile2          (Win8)    -> CopyFileW + 错误码转 HRESULT
 *   AddDllDirectory    (Win8)    -> SetDllDirectoryW 模拟
 *   RemoveDllDirectory (Win8)    -> SetDllDirectoryW(NULL)
 *   PssCaptureSnapshot (Win8.1)  -> 返回 ERROR_CALL_NOT_IMPLEMENTED
 *   PssQuerySnapshot   (Win8.1)  -> 同上
 *   PssFreeSnapshot    (Win8.1)  -> 返回 ERROR_SUCCESS（空实现）
 */
#include <windows.h>

#ifndef ERROR_CALL_NOT_IMPLEMENTED
#define ERROR_CALL_NOT_IMPLEMENTED 120L
#endif

typedef HRESULT(WINAPI *PFN_CopyFile2)(PCWSTR, PCWSTR, COPYFILE2_EXTENDED_PARAMETERS *);
typedef DWORD(WINAPI *PFN_PssCaptureSnapshot)(HANDLE, DWORD, DWORD, void **);
typedef DWORD(WINAPI *PFN_PssQuerySnapshot)(void *, int, void *, DWORD, DWORD *);
typedef DWORD(WINAPI *PFN_PssFreeSnapshot)(HANDLE, void *);
typedef PVOID(WINAPI *PFN_AddDllDirectory)(PCWSTR);
typedef BOOL(WINAPI *PFN_RemoveDllDirectory)(PVOID);
typedef void(WINAPI *PFN_GetCurrentThreadStackLimits)(PULONG_PTR, PULONG_PTR);

static PFN_CopyFile2          pCopyFile2;
static PFN_PssCaptureSnapshot pPssCaptureSnapshot;
static PFN_PssQuerySnapshot   pPssQuerySnapshot;
static PFN_PssFreeSnapshot    pPssFreeSnapshot;
static PFN_AddDllDirectory    pAddDllDirectory;
static PFN_RemoveDllDirectory pRemoveDllDirectory;
static PFN_GetCurrentThreadStackLimits pGetCurrentThreadStackLimits;

static void resolve_real(void)
{
    HMODULE k = GetModuleHandleA("kernel32.dll");
    if (!k) {
        k = LoadLibraryA("kernel32.dll");
        if (!k) {
            return;
        }
    }
    pCopyFile2          = (PFN_CopyFile2)GetProcAddress(k, "CopyFile2");
    pPssCaptureSnapshot = (PFN_PssCaptureSnapshot)GetProcAddress(k, "PssCaptureSnapshot");
    pPssQuerySnapshot   = (PFN_PssQuerySnapshot)GetProcAddress(k, "PssQuerySnapshot");
    pPssFreeSnapshot    = (PFN_PssFreeSnapshot)GetProcAddress(k, "PssFreeSnapshot");
    pAddDllDirectory    = (PFN_AddDllDirectory)GetProcAddress(k, "AddDllDirectory");
    pRemoveDllDirectory = (PFN_RemoveDllDirectory)GetProcAddress(k, "RemoveDllDirectory");
    pGetCurrentThreadStackLimits =
        (PFN_GetCurrentThreadStackLimits)GetProcAddress(k, "GetCurrentThreadStackLimits");
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(inst);
        resolve_real();
    }
    return TRUE;
}

/* ---------------- CopyFile2 ---------------- */
HRESULT WINAPI CopyFile2(PCWSTR existing, PCWSTR newname,
                         COPYFILE2_EXTENDED_PARAMETERS *params)
{
    DWORD flags = 0;
    if (pCopyFile2) {
        return pCopyFile2(existing, newname, params);
    }
    if (params) {
        flags = params->dwCopyFlags;
    }
    /* COPY_FILE_FAIL_IF_EXISTS == 1 */
    if (CopyFileW(existing, newname, (flags & 1) ? TRUE : FALSE)) {
        return S_OK;
    }
    return HRESULT_FROM_WIN32(GetLastError());
}

/* ---------------- PSS 进程快照：Win7 无此能力 ---------------- */
DWORD WINAPI PssCaptureSnapshot(HANDLE process, DWORD flags, DWORD threadid, void **snapshot)
{
    if (pPssCaptureSnapshot) {
        return pPssCaptureSnapshot(process, flags, threadid, snapshot);
    }
    if (snapshot) {
        *snapshot = NULL;
    }
    return (DWORD)ERROR_CALL_NOT_IMPLEMENTED;
}

DWORD WINAPI PssQuerySnapshot(void *snapshot, int info, void *buf, DWORD buflen, DWORD *retlen)
{
    if (pPssQuerySnapshot) {
        return pPssQuerySnapshot(snapshot, info, buf, buflen, retlen);
    }
    if (retlen) {
        *retlen = 0;
    }
    return (DWORD)ERROR_CALL_NOT_IMPLEMENTED;
}

DWORD WINAPI PssFreeSnapshot(HANDLE process, void *snapshot)
{
    if (pPssFreeSnapshot) {
        return pPssFreeSnapshot(process, snapshot);
    }
    (void)process;
    (void)snapshot;
    return ERROR_SUCCESS;
}

/* ---------------- DLL 目录 API ---------------- */
#define FAKE_COOKIE ((PVOID)(ULONG_PTR)1)

PVOID WINAPI AddDllDirectory(PCWSTR path)
{
    if (pAddDllDirectory) {
        return pAddDllDirectory(path);
    }
    /* Win7 退化：用 SetDllDirectoryW，效果最接近“把该目录加入搜索路径” */
    if (path && SetDllDirectoryW(path)) {
        return FAKE_COOKIE;
    }
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return NULL;
}

BOOL WINAPI RemoveDllDirectory(PVOID cookie)
{
    if (pRemoveDllDirectory) {
        return pRemoveDllDirectory(cookie);
    }
    if (cookie == FAKE_COOKIE) {
        SetDllDirectoryW(NULL);
    }
    return TRUE;
}

/* ---------------- 线程栈边界（Python 3.14+ 用到） ---------------- */
/*
 * Win7 没有 GetCurrentThreadStackLimits，但 TEB 里一直有 StackBase / StackLimit
 * （Win8 的实现本身就是读这两个字段再加一点对齐处理），所以这里直接读 TEB，
 * 结果与 Win8+ 基本等价，不是估算值。
 */
void WINAPI GetCurrentThreadStackLimits(PULONG_PTR low, PULONG_PTR high)
{
    NT_TIB *tib;
    if (pGetCurrentThreadStackLimits) {
        pGetCurrentThreadStackLimits(low, high);
        return;
    }
    tib = (NT_TIB *)NtCurrentTeb();
    if (low) {
        *low = (ULONG_PTR)tib->StackLimit;
    }
    if (high) {
        *high = (ULONG_PTR)tib->StackBase;
    }
}
