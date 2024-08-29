#include "Exception.h"

#define ThreadQuerySetWin32StartAddress 0x09

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
{
	ULONG Version;
	ULONG Reserved;
	PVOID Callback;
} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION, * PPROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;

using  pfnNtSetContextThread = LONG(WINAPI*)(IN HANDLE ThreadHandle, IN PCONTEXT Context);
using pfnNtGetContextThread = LONG(__stdcall*)(IN HANDLE ThreadHandle, OUT PCONTEXT Context);
using pfnNtSuspendThread = LONG(WINAPI*)(IN HANDLE ThreadHandle, OUT PULONG PreviousSuspendCount OPTIONAL);
using pfnNtResumeThread = LONG(WINAPI*)(IN HANDLE ThreadHandle, OUT PULONG PreviousSuspendCount OPTIONAL);
using pfnNtContinue = LONG(WINAPI*)(IN PCONTEXT Context, IN BOOLEAN TestAlert);

extern "C" LONG(__stdcall * ZwQueryInformationThread)(IN HANDLE ThreadHandle, IN THREADINFOCLASS ThreadInformationClass, OUT PVOID ThreadInformation, IN ULONG ThreadInformationLength, OUT PULONG ReturnLength OPTIONAL) = NULL;
extern "C" NTSTATUS NTAPI NtSetInformationProcess(HANDLE ProcessHandle, ULONG ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength);
extern "C" void MyCallbackEntry();
extern "C" void MyCallbackRoutine(CONTEXT * context);

extern "C" void NtContinueProc();
extern "C" void NtResumeThreadProc();
extern "C" void NtSuspendThreadProc();
extern "C" void NtSetContextThreadProc();
extern "C" void NtGetContextThreadProc();

pfnNtContinue NtContinue = nullptr;
pfnNtResumeThread NtResumeThread = nullptr;
pfnNtSuspendThread NtSuspendThread = nullptr;
pfnNtSetContextThread NtSetContextThread = nullptr;
pfnNtGetContextThread NtGetContextThread = nullptr;
DWORD64 sysret_address = 0, rtl_restore_context_offset = 0;


ExceptionError::ExceptionError(std::string error) :_error_str(error)
{
}

ExceptionError::~ExceptionError()
{
}

char const* ExceptionError::what() const throw()
{
	return this->_error_str.c_str();
}


Exception::Exception()
{
}

Exception::~Exception()
{
}

ULONG Exception::GetSSDTIndexByName(const char* function_name)
{
	DWORD dwBytesRead = NULL;

	HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return 0;
	DWORD dwLength = GetFileSize(hFile, NULL);
	if (dwLength == INVALID_FILE_SIZE || dwLength == 0)
		return 0;
	PVOID lpBuffer = HeapAlloc(GetProcessHeap(), 0, dwLength);
	if (!lpBuffer)
		return 0;
	if (ReadFile(hFile, lpBuffer, dwLength, &dwBytesRead, NULL) == FALSE)
		return 0;

	//ȡ��������
	PIMAGE_DOS_HEADER  pDosHeader;
	PIMAGE_NT_HEADERS  pNtHeaders;
	PIMAGE_SECTION_HEADER pSectionHeader;
	ULONGLONG     FileOffset;//������64λ���ģ��������ﲻ��32���ֽ�
	PIMAGE_EXPORT_DIRECTORY pExportDirectory;
	//DLL�ڴ�����ת��DOSͷ�ṹ
	pDosHeader = (PIMAGE_DOS_HEADER)lpBuffer;
	//ȡ��PEͷ�ṹ
	pNtHeaders = (PIMAGE_NT_HEADERS)((ULONGLONG)lpBuffer + pDosHeader->e_lfanew);
	//�ж�PEͷ��������Ƿ�Ϊ��

	if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
		return 0;

	//ȡ��������ƫ��
	FileOffset = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	//ȡ����ͷ�ṹ
	pSectionHeader = (PIMAGE_SECTION_HEADER)((ULONGLONG)pNtHeaders + sizeof(IMAGE_NT_HEADERS));
	PIMAGE_SECTION_HEADER pOldSectionHeader = pSectionHeader;
	//�����ڽṹ���е�ַ����
	for (UINT16 Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++)
	{
		if (pSectionHeader->VirtualAddress <= FileOffset && FileOffset <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
			FileOffset = FileOffset - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
	}

	//�������ַ
	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONGLONG)lpBuffer + FileOffset);
	//ȡ������������ַ
	PLONG AddressOfFunctions;
	FileOffset = pExportDirectory->AddressOfFunctions;
	//�����ڽṹ���е�ַ����
	pSectionHeader = pOldSectionHeader;
	for (UINT16 Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++)
	{
		if (pSectionHeader->VirtualAddress <= FileOffset && FileOffset <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
			FileOffset = FileOffset - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
	}
	AddressOfFunctions = (PLONG)((ULONGLONG)lpBuffer + FileOffset);//����ע��һ��foa��rva

	//ȡ��������������
	PUSHORT AddressOfNameOrdinals;
	FileOffset = pExportDirectory->AddressOfNameOrdinals;

	//�����ڽṹ���е�ַ����
	pSectionHeader = pOldSectionHeader;
	for (UINT16 Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++)
	{
		if (pSectionHeader->VirtualAddress <= FileOffset && FileOffset <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
			FileOffset = FileOffset - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
	}
	AddressOfNameOrdinals = (PUSHORT)((ULONGLONG)lpBuffer + FileOffset);//ע��һ��foa��rva

	//ȡ�������������
	PULONG AddressOfNames;
	FileOffset = pExportDirectory->AddressOfNames;

	//�����ڽṹ���е�ַ����
	pSectionHeader = pOldSectionHeader;
	for (UINT16 Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++)
	{
		if (pSectionHeader->VirtualAddress <= FileOffset && FileOffset <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
			FileOffset = FileOffset - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
	}
	AddressOfNames = (PULONG)((ULONGLONG)lpBuffer + FileOffset);//ע��һ��foa��rva
	//DbgPrint("\n AddressOfFunctions %llX AddressOfNameOrdinals %llX AddressOfNames %llX  \n", (ULONGLONG)AddressOfFunctions- (ULONGLONG)pBuffer, (ULONGLONG)AddressOfNameOrdinals- (ULONGLONG)pBuffer, (ULONGLONG)AddressOfNames- (ULONGLONG)pBuffer);
	//DbgPrint("\n AddressOfFunctions %llX AddressOfNameOrdinals %llX AddressOfNames %llX  \n", pExportDirectory->AddressOfFunctions, pExportDirectory->AddressOfNameOrdinals, pExportDirectory->AddressOfNames);

	//����������
	ULONG uNameOffset;
	ULONG uOffset;
	LPSTR FunName;
	PVOID pFuncAddr;
	ULONG uServerIndex;
	ULONG uAddressOfNames;
	for (ULONG uIndex = 0; uIndex < pExportDirectory->NumberOfNames; uIndex++, AddressOfNames++, AddressOfNameOrdinals++)
	{
		uAddressOfNames = *AddressOfNames;
		pSectionHeader = pOldSectionHeader;
		for (UINT32 Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++)
		{
			if (pSectionHeader->VirtualAddress <= uAddressOfNames && uAddressOfNames <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
				uOffset = uAddressOfNames - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
		}
		FunName = (LPSTR)((ULONGLONG)lpBuffer + uOffset);
		if (FunName[0] == 'Z' && FunName[1] == 'w')
		{
			pSectionHeader = pOldSectionHeader;
			uOffset = (ULONG)AddressOfFunctions[*AddressOfNameOrdinals];
			for (UINT32 Index = 0; Index < pNtHeaders->FileHeader.NumberOfSections; Index++, pSectionHeader++)
			{
				if (pSectionHeader->VirtualAddress <= uOffset && uOffset <= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
					uNameOffset = uOffset - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
			}
			pFuncAddr = (PVOID)((ULONGLONG)lpBuffer + uNameOffset);
			uServerIndex = *(PULONG)((ULONGLONG)pFuncAddr + 4);
			FunName[0] = 'N';
			FunName[1] = 't';
			//���ָ���ı��
			if (!_stricmp(FunName, (const char*)function_name))
			{
				if (lpBuffer)
					HeapFree(GetProcessHeap(), 0, lpBuffer);
				CloseHandle(hFile);
				return uServerIndex;
			}
			//DbgPrint("Name: %s index:%d\n ", FunName, uServerIndex);//index��%d\n, uServerIndex
		}
	}

	if (lpBuffer)
		HeapFree(GetProcessHeap(), 0, lpBuffer);
	CloseHandle(hFile);
	return 0;
}

DWORD64 Exception::GetOffset(DWORD64 start_address, SIZE_T end_offset, SIZE_T weight)
{
	DWORD64 ret_address = 0;
	BYTE temp_address[5] = { NULL };
	BYTE judgment[5] = { 0x48,0x8B,0xCC,0x33,0xD2 };
	//������
	// mov	rcx, rsp
	// xor	edx, edx
	// call	RtlRestoreContext

	start_address += weight;

	for (size_t i = 0; i < end_offset; i++)
	{
		memcpy((PVOID)temp_address, (PVOID)start_address, sizeof(judgment));
		if (_memicmp(temp_address, judgment, sizeof(judgment)) == 0)
		{
			ret_address = start_address;
			return ret_address;
		}
		else
			start_address++;
	}

	return ret_address;
}

bool Exception::InstallException(pfnExceptionHandlerApi p_exception_api)
{
	DWORD old;

	//��ȡsyscall������ַ
	NtSetContextThread = (pfnNtSetContextThread)NtSetContextThreadProc;
	::VirtualProtect((PVOID)((DWORD64)&NtSetContextThreadProc + 0x04), 4, PAGE_EXECUTE_READWRITE, &old);
	*(DWORD*)((DWORD64)&NtSetContextThreadProc + 0x04) = (DWORD)GetSSDTIndexByName("NtSetContextThread");
	::VirtualProtect((PVOID)((DWORD64)&NtSetContextThreadProc + 0x04), 4, old, NULL);

	NtGetContextThread = (pfnNtGetContextThread)NtGetContextThreadProc;
	::VirtualProtect((PVOID)((DWORD64)&NtGetContextThreadProc + 0x04), 4, PAGE_EXECUTE_READWRITE, &old);
	*(DWORD*)((DWORD64)&NtGetContextThreadProc + 0x04) = (DWORD)GetSSDTIndexByName("NtGetContextThread");
	::VirtualProtect((PVOID)((DWORD64)&NtGetContextThreadProc + 0x04), 4, old, NULL);

	NtSuspendThread = (pfnNtSuspendThread)NtSuspendThreadProc;
	::VirtualProtect((PVOID)((DWORD64)&NtSuspendThreadProc + 0x04), 4, PAGE_EXECUTE_READWRITE, &old);
	*(DWORD*)((DWORD64)&NtSuspendThreadProc + 0x04) = (DWORD)GetSSDTIndexByName("NtSuspendThread");
	::VirtualProtect((PVOID)((DWORD64)&NtSuspendThreadProc + 0x04), 4, old, NULL);

	NtResumeThread = (pfnNtResumeThread)NtResumeThreadProc;
	::VirtualProtect((PVOID)((DWORD64)&NtResumeThreadProc + 0x04), 4, PAGE_EXECUTE_READWRITE, &old);
	*(DWORD*)((DWORD64)&NtResumeThreadProc + 0x04) = (DWORD)GetSSDTIndexByName("NtResumeThread");
	::VirtualProtect((PVOID)((DWORD64)&NtResumeThreadProc + 0x04), 4, old, NULL);

	NtContinue = (pfnNtContinue)NtContinueProc;
	::VirtualProtect((PVOID)((DWORD64)&NtContinueProc + 0x04), 4, PAGE_EXECUTE_READWRITE, &old);
	*(DWORD*)((DWORD64)&NtContinueProc + 0x04) = (DWORD)GetSSDTIndexByName("NtContinue");
	::VirtualProtect((PVOID)((DWORD64)&NtContinueProc + 0x04), 4, old, NULL);


	//���溯��ָ��
	this->_self_exception_api = p_exception_api;

	HMODULE ntdll = ::GetModuleHandleA("ntdll.dll");
	if (ntdll == NULL)
		ntdll = ::LoadLibraryA("ntdll.dll");
	//��ȡhook�ķ��ص�ַ
	sysret_address = (DWORD64)::GetProcAddress(ntdll, "KiUserExceptionDispatcher");
	if (sysret_address == NULL)
		sysret_address = (DWORD64)::GetProcAddress(ntdll, "KiUserExceptionDispatcher");
	rtl_restore_context_offset = this->GetOffset(sysret_address, 0x70, 0x10);
	if (rtl_restore_context_offset <= 0)
		::MessageBoxA(::GetActiveWindow(), "δ�ҵ�����ƫ��", "Error", MB_OK);

	PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION info;
	info.Version = 0;
	info.Reserved = 0;
	info.Callback = MyCallbackEntry;
	ULONG status = NtSetInformationProcess(GetCurrentProcess(), 0x28, &info, sizeof(info));
	if (status)
		return false;

	return true;
}

int Exception::SetHardWareBreakPoint(const wchar_t* main_modulename, DWORD64 dr7_statu, DWORD64 dr0, DWORD64 dr1, DWORD64 dr2, DWORD64 dr3)
{
	this->_dr0 = dr0;
	this->_dr1 = dr1;
	this->_dr2 = dr2;
	this->_dr3 = dr3;

	//�����߳� ͨ��openthread��ȡ���̻߳���������Ӳ���ϵ�
	HANDLE hTool32 = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hTool32 != INVALID_HANDLE_VALUE)
	{
		THREADENTRY32 thread_entry32;						//�̻߳����ṹ��
		thread_entry32.dwSize = sizeof(THREADENTRY32);
		HANDLE h_hook_thread = NULL;
		MODULEINFO module_info = { 0 };						//ģ����Ϣ

		HANDLE target_modulehandle = GetModuleHandleW(main_modulename);

		//�� ntdll.dll ��ȡ�� ZwQueryInformationThread
		(FARPROC&)ZwQueryInformationThread = ::GetProcAddress(GetModuleHandleA("ntdll"), "ZwQueryInformationThread");

		if (target_modulehandle != 0)
		{
			//��ȡģ�������ַ
			GetModuleInformation(GetCurrentProcess(), (HMODULE)target_modulehandle, &module_info, sizeof(MODULEINFO));
			__int64 target_modulehandle_endaddress = ((__int64)module_info.lpBaseOfDll + module_info.SizeOfImage);
			//�����߳�
			if (Thread32First(hTool32, &thread_entry32))
			{
				do
				{
					//����̸߳�����IDΪ��ǰ����ID
					if (thread_entry32.th32OwnerProcessID == GetCurrentProcessId())
					{
						h_hook_thread = OpenThread(THREAD_ALL_ACCESS, FALSE, thread_entry32.th32ThreadID);
						// ��ȡ�߳���ڵ�ַ
						PVOID startaddr;//���������߳���ڵ�ַ
						ZwQueryInformationThread(h_hook_thread, (THREADINFOCLASS)ThreadQuerySetWin32StartAddress, &startaddr, sizeof(startaddr), NULL);
						if (((__int64)startaddr >= (__int64)target_modulehandle) && ((__int64)startaddr <= target_modulehandle_endaddress))
						{
							//��ͣ�߳�
							ULONG previous_count = NULL;
							NtSuspendThread(h_hook_thread, &previous_count);

							//����Ӳ���ϵ�
							CONTEXT thread_context = { CONTEXT_DEBUG_REGISTERS };
							thread_context.ContextFlags = CONTEXT_ALL;

							//�õ�ָ���̵߳Ļ�����������
							if (!NT_SUCCESS(NtGetContextThread(h_hook_thread, &thread_context)))
								return 3;

							//����Ӳ���ϵ��ַ
							thread_context.Dr0 = dr0;
							thread_context.Dr1 = dr1;
							thread_context.Dr2 = dr2;
							thread_context.Dr3 = dr3;
							//ÿ��Ӳ�Ͽ���״̬
							thread_context.Dr7 = dr7_statu;
							if (!NT_SUCCESS(NtSetContextThread(h_hook_thread, &thread_context)))
								return 4;

							//�ָ��߳�
							NtResumeThread(h_hook_thread, &previous_count);
						}
						CloseHandle(h_hook_thread);
					}
				} while (Thread32Next(hTool32, &thread_entry32));
			}
			CloseHandle(hTool32);
			return true;
		}
		else
			return 2;//ģ������ȡʧ��
	}
	return 0;
}

void MyCallbackRoutine(CONTEXT* context)
{
	context->Rip = __readgsqword(0x02D8);//syscall �ķ��ص�ַ
	context->Rsp = __readgsqword(0x02E0);//context = rsp, ExceptionRecord = rsp + 0x4F0
	context->Rcx = context->R10;

	if (context->Rip == sysret_address)
		if (Exception::GetInstance()->_self_exception_api((PEXCEPTION_RECORD)(context->Rsp + 0x4F0), (PCONTEXT)context->Rsp) == EXCEPTION_CONTINUE_EXECUTION)
			context->Rip = rtl_restore_context_offset;

	NtContinue(context, 0);
}

