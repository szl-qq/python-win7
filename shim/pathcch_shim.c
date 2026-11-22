/* api-ms-win-core-path-l1-1-0.dll 替身（Win7 用）
 * 提供 PathCchSkipRoot / PathCchCombineEx，实现基于 shlwapi（Win7 已有）。
 * 仅导出 CPython 3.13 python313.dll 实际导入的两个符号，调用约定 stdcall。
 */
#include <windows.h>
#include <shlwapi.h>

HRESULT WINAPI PathCchSkipRoot(PCWSTR pszPath, PCWSTR *ppszRootEnd)
{
    if (!pszPath || !ppszRootEnd) {
        return E_INVALIDARG;
    }
    LPCWSTR end = PathSkipRootW(pszPath);
    if (!end) {
        return E_INVALIDARG;
    }
    *ppszRootEnd = end;
    return S_OK;
}

HRESULT WINAPI PathCchCombineEx(PWSTR pszPathOut, size_t cchPathOut,
                                PCWSTR pszPathIn, PCWSTR pszMore,
                                ULONG dwFlags)
{
    (void)dwFlags;   /* PATHCCH_ALLOW_LONG_PATHS 等标志在 Win7 上无意义 */
    if (!pszPathOut || cchPathOut == 0) {
        return E_INVALIDARG;
    }
    WCHAR tmp[MAX_PATH];
    LPWSTR r = PathCombineW(tmp, pszPathIn, pszMore);
    if (!r) {
        return E_INVALIDARG;
    }
    size_t len = wcslen(r);
    if (len + 1 > cchPathOut) {
        return HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
    }
    wcscpy(pszPathOut, r);
    return S_OK;
}
