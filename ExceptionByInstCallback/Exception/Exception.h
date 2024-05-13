#pragma once
#include <Windows.h>
#include <iostream>
#include <string>


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
private:

public:
	Exception();
	~Exception();

public:

};


extern "C" std::shared_ptr<Exception> exception;

