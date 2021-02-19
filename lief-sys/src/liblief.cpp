#include <iostream>
#include <memory>
#include <exception>
#include <vector>
#include "LIEF/PE.hpp"

#ifdef _MSC_VER
    #define LIEF_SYS_EXPORT __declspec(dllexport)
#else
    #define LIEF_SYS_EXPORT __attribute__((dllexport))
#endif

#define LIEF_SYS_OK                 0
#define LIEF_SYS_BUILD_ERROR        1
#define LIEF_SYS_SET_ICON_ERROR     2
#define LIEF_SYS_SET_RCDATA_ERROR   3
#define LIEF_SYS_SET_STRING_ERROR   4

using namespace LIEF;

typedef struct Binary Binary;
typedef struct ResourceManager ResourceManager;

extern "C"
{
    LIEF_SYS_EXPORT Binary* Binary_New(const char* path)
    {
        std::unique_ptr<PE::Binary> binary;
        try
        {
            binary = PE::Parser::parse(path);
        }
        catch (const std::exception& ex)
        {
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

        try
        {
            builder.build();
            builder.write(path);
        }
        catch (const std::exception& ex)
        {
            return LIEF_SYS_BUILD_ERROR;
        }

        return LIEF_SYS_OK;
    }

    LIEF_SYS_EXPORT ResourceManager* Binary_GetResourceManager(Binary* _this)
    {
        PE::Binary* binary = reinterpret_cast<PE::Binary*>(_this);

        PE::ResourcesManager* resourceManager = nullptr;
        try
        {
            tmp = binary->resources_manager();
        }
        catch (const std::exception& ex)
        {
            return nullptr;
        }

        PE::ResourcesManager tmp(nullptr);
        try
        {
            resourceManager = new PE::ResourcesManager(nullptr);
        }
        catch (const std::exception& ex)
        {
            return nullptr;
        }

        *resourceManager = tmp;

        return reinterpret_cast<ResourceManager*>(resourceManager);
    }

    LIEF_SYS_EXPORT void ResourceManager_Free(ResourceManager* _this) {
        PE::ResourcesManager* resourceManager = reinterpret_cast<PE::ResourcesManager*>(_this);
        delete resourceManager;
    }

    LIEF_SYS_EXPORT int SetRcData(ResourceManager* _this, const uint8_t* data, uint32_t data_size, uint32_t resource_id) {
        PE::ResourcesManager* resources_manager = reinterpret_cast<PE::ResourcesManager*>(_this);

        PE::ResourceData rcdata_data_node;
        PE::ResourceDirectory rcdata_dir_node;

        std::vector<uint8_t> content(data_size);
        try
        {
            std::copy(data, data + data_size * sizeof(uint8_t), content.begin());
        }
        catch (const std::exception &ex)
        {
            return LIEF_SYS_SET_RCDATA_ERROR;
        }

        rcdata_data_node.id(static_cast<uint32_t>(PE::RESOURCE_LANGS::LANG_ENGLISH));
        rcdata_data_node.content(content);

        try
        {
            rcdata_dir_node.add_child(rcdata_data_node);
        }
        catch (const std::exception& ex)
        {
            return LIEF_SYS_SET_RCDATA_ERROR;
        }

        rcdata_dir_node.id(resource_id);
        rcdata_dir_node.numberof_id_entries(1);

        try
        {
            PE::ResourceNode& rc_data_root = resources_manager->get_node_type(PE::RESOURCE_TYPES::RCDATA);
            rc_data_root.add_child(rcdata_dir_node);
        }
        catch(const std::exception& ex)
        {
            return LIEF_SYS_SET_RCDATA_ERROR;
        }

        return LIEF_SYS_OK;
    }
}

