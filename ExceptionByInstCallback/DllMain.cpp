#include "Exception/Exception.h"


LONG WINAPI ExceptionHandler(PEXCEPTION_RECORD exception_record, PCONTEXT context)
{
	//hardware breakpoint
	if (exception_record->ExceptionCode == EXCEPTION_SINGLE_STEP)
	{
		if (exception_record->ExceptionAddress == (PVOID64)exception->_dr0)
		{
			//ACE-Base64.dll + 815844 - 48 89 47 08 -	mov[rdi + 08], rax			//Hook点
			//ACE-Base64.dll + 815848 - FF 53 20 -		call qword ptr[rbx + 20]	//跳过执行
			//ACE-Base64.dll + 81584B - 48 8B 1B -		mov rbx, [rbx]

			std::cout << "caller address: " << std::hex << *(DWORD64*)context->Rsi << std::endl;
			std::cout << "callee address: " << std::hex << *(DWORD64*)(context->Rbx + 0x20) << std::endl;

			context->Rip = exception->_dr0 + 0x07;
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		else if (exception_record->ExceptionAddress == (PVOID64)exception->_dr1)
		{
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		else if (exception_record->ExceptionAddress == (PVOID64)exception->_dr2)
		{
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		else if (exception_record->ExceptionAddress == (PVOID64)exception->_dr3)
		{
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		else
		{
			context->Dr0 = exception->_dr0;
			context->Dr1 = exception->_dr1;
			context->Dr2 = exception->_dr2;
			context->Dr3 = exception->_dr3;
			return EXCEPTION_CONTINUE_SEARCH;
		}
	}
	//software breakpoint
	else if (exception_record->ExceptionCode == EXCEPTION_BREAKPOINT)
	{
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

void InitializeException(HMODULE self_module)
{
	//打开控制台
	AllocConsole();
	freopen("CONOUT$", "w", stdout);

    try
    {
        exception = std::make_shared<Exception>();
		exception->InstallException(ExceptionHandler);

		DWORD64 ace_base_module = 0;
		while (true)
		{
			ace_base_module = (DWORD64)::GetModuleHandleA("ACE-Base64.dll");
			if (ace_base_module > 0x1000)
				break;
		}
		auto value = exception->SetHardWareBreakPoint(L"crossfire.exe", 0x455, ace_base_module + 0x815844, 0x0, 0x0, 0x0);
		printf("value:%d\n", value);
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

