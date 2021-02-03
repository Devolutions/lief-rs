#include <iostream>
#include <memory>
#include <string>
#include "LIEF/PE.hpp"


#ifdef _MSC_VER
    #define LIEF_SYS_EXPORT __declspec(dllexport)
#else
    #define LIEF_SYS_EXPORT __attribute__((dllexport))
#endif

typedef struct Binary Binary;

extern "C"
{
    LIEF_SYS_EXPORT Binary* Binary_New(const char * path)
    {
        std::unique_ptr<LIEF::PE::Binary> unique_ptr = LIEF::PE::Parser::parse(std::string(path));
        LIEF::PE::Binary* ptr = unique_ptr.release();
        return reinterpret_cast<Binary*>(ptr);
    }

    LIEF_SYS_EXPORT void Binary_Free(Binary* _this)
    {
        LIEF::PE::Binary* binary = reinterpret_cast<LIEF::PE::Binary*>(_this);
        delete binary;
    }

    LIEF_SYS_EXPORT  void Binary_Print(Binary* _this)
    {
        LIEF::PE::Binary* binary = reinterpret_cast<LIEF::PE::Binary*>(_this);
        std::cout << *binary << std::endl;
    }

}

