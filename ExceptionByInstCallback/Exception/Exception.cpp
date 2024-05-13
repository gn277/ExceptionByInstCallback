#include "Exception.h"

std::shared_ptr<Exception> exception = nullptr;


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
