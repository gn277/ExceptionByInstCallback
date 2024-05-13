#include "Exception/Exception.h"


void InitializeException(HMODULE self_module)
{
    try
    {
        exception = std::make_shared<Exception>();
    }
    catch (const std::shared_ptr<ExceptionError>& e)
    {
        ::MessageBoxA(::GetActiveWindow(), e->what(), "Error", MB_OK);
    }
    catch (const std::exception& e)
    {
        ::MessageBoxA(::GetActiveWindow(), e.what(), "Error", MB_OK);
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        CloseHandle(CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)InitializeException, (LPVOID)hModule, NULL, NULL));
        break;
    }
    case DLL_THREAD_ATTACH: break;
    case DLL_PROCESS_DETACH: break;
    case DLL_THREAD_DETACH: break;
    }
    return TRUE;
}

