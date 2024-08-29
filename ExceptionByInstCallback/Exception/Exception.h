#pragma once
#include <Windows.h>
#include <iostream>
#include <string>
#include <psapi.h>
#include <DbgHelp.h>
#include <tlhelp32.h>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "imagehlp.lib")


class ExceptionError :public std::exception
{
private:
	std::string _error_str;

public:
	ExceptionError(std::string error);
	~ExceptionError();

public:
	virtual char const* what() const throw();

};


class Exception
{
public:
	static std::shared_ptr<Exception> GetInstance()
	{
		static std::shared_ptr<Exception> instance(new Exception());
		return instance;
	}
	~Exception();
private:
	Exception();

	typedef LONG(__stdcall* pfnExceptionHandlerApi)(PEXCEPTION_RECORD ExceptionRecord, PCONTEXT context);

public:
	DWORD64 _dr0 = 0;
	DWORD64 _dr1 = 0;
	DWORD64 _dr2 = 0;
	DWORD64 _dr3 = 0;

	pfnExceptionHandlerApi _self_exception_api = nullptr;

private:
	ULONG GetSSDTIndexByName(const char* function_name);
	DWORD64 GetOffset(DWORD64 start_address, SIZE_T end_offset, SIZE_T weight);

public:
	bool InstallException(pfnExceptionHandlerApi p_exception_api);
	//0 ��������ʧ�ܣ�1 �ɹ���2 ģ������ȡʧ�ܣ�3 ����߳�������ʧ�ܣ�4 �����߳�������ʧ��
	int SetHardWareBreakPoint(const wchar_t* main_modulename, DWORD64 dr7_statu, DWORD64 dr0, DWORD64 dr1, DWORD64 dr2, DWORD64 dr3);

};
