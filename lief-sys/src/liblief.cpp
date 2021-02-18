#include <iostream>
#include <memory>
#include <exception>
#include "LIEF/PE.hpp"

#ifdef _MSC_VER
    #define LIEF_SYS_EXPORT __declspec(dllexport)
#else
    #define LIEF_SYS_EXPORT __attribute__((dllexport))
#endif

#define LIEF_SYS_OK 0
#define LIEF_SYS_BUILD_ERROR 1
#define LIEF_SYS_SET_ICON_ERROR 2
#define LIEF_SYS_SET_RCDATA_ERROR 3
#define LIEF_SYS_SET_STRING_ERROR 4

using namespace LIEF;

typedef struct Binary Binary;
typedef struct ResourceManager ResourceManager;

extern "C"
{
    LIEF_SYS_EXPORT Binary* Binary_New(const char* path)
    {
        std::unique_ptr<PE::Binary> binary;
        try {
            binary = PE::Parser::parse(path);
        } catch (const std::exception& ex) {
            return nullptr;
        }

        return reinterpret_cast<Binary*>(binary.release());
    }

    LIEF_SYS_EXPORT void Binary_Free(Binary* _this)
    {
        PE::Binary* binary = reinterpret_cast<PE::Binary*>(_this);
        delete binary;
    }

    LIEF_SYS_EXPORT unsigned int Binary_Build(Binary* _this, const char* path)
    {
        PE::Binary* binary = reinterpret_cast<PE::Binary*>(_this);
        PE::Builder builder = PE::Builder::Builder(binary);

        builder.build_resources(true);

        try {
            builder.build();
            builder.write(path);
        } catch (const std::exception& ex) {
            return LIEF_SYS_BUILD_ERROR;
        }

        return LIEF_SYS_OK;
    }

    LIEF_SYS_EXPORT ResourceManager* Binary_GetResourceManager(Binary* _this)
    {
        PE::Binary* binary = reinterpret_cast<PE::Binary*>(_this);

        PE::ResourcesManager tmp(nullptr);
        try {
            tmp = binary->resources_manager();
        } catch (std::exception& ex) {
            return nullptr;
        }

        PE::ResourcesManager* resourceManager = new PE::ResourcesManager(nullptr);
        *resourceManager = tmp;

        return reinterpret_cast<ResourceManager*>(resourceManager);
    }

    LIEF_SYS_EXPORT void ResourceManager_Free(ResourceManager* _this) {
        PE::ResourcesManager* resourceManager = reinterpret_cast<PE::ResourcesManager*>(_this);
        delete resourceManager;
    }
}

