#include <memory>
#include <exception>
#include <vector>
#include "LIEF/PE.hpp"

#ifdef _MSC_VER
    #define LIEF_SYS_EXPORT __declspec(dllexport)
#else
    #define LIEF_SYS_EXPORT __attribute__((dllexport))
#endif

enum class LIEF_SYS_STATUS: unsigned  int {
    OK = 0,
    BUILD_ERROR,
    SET_ICON_ERROR,
    SET_RCDATA_ERROR,
    SET_STRING_ERROR,
    DELETE_NODE_ERROR
};

using namespace LIEF;

typedef struct Binary Binary;
typedef struct ResourceManager ResourceManager;

LIEF_SYS_STATUS DeleteRootNodeChilds(PE::ResourceNode& root, uint32_t dir_node_id);

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
            return static_cast<unsigned int>(LIEF_SYS_STATUS::BUILD_ERROR);
        }

        return static_cast<unsigned int>(LIEF_SYS_STATUS::OK);
    }

    LIEF_SYS_EXPORT ResourceManager* Binary_GetResourceManager(Binary* _this)
    {
        PE::Binary* binary = reinterpret_cast<PE::Binary*>(_this);

        PE::ResourcesManager* resourceManager = nullptr;
        PE::ResourcesManager tmp(nullptr);

        try
        {
            tmp = binary->resources_manager();
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

    LIEF_SYS_EXPORT unsigned int SetRcData(ResourceManager* _this, const uint8_t* data, uint32_t data_size, uint32_t resource_id) {
        PE::ResourcesManager* resources_manager = reinterpret_cast<PE::ResourcesManager*>(_this);

        try
        {
            PE::ResourceNode &rc_data_root = resources_manager->get_node_type(PE::RESOURCE_TYPES::RCDATA);

            if(DeleteRootNodeChilds(rc_data_root, resource_id) != LIEF_SYS_STATUS::OK)
                return static_cast<unsigned int>(LIEF_SYS_STATUS::SET_RCDATA_ERROR);

            PE::ResourceData rcdata_data_node;
            PE::ResourceDirectory rcdata_dir_node;

            std::vector <uint8_t> content(data_size, 0);

            std::copy(data, data + data_size * sizeof(uint8_t), content.begin());

            rcdata_data_node.id(static_cast<uint32_t>(PE::RESOURCE_LANGS::LANG_ENGLISH));
            rcdata_data_node.content(content);

            rcdata_dir_node.add_child(rcdata_data_node);

            rcdata_dir_node.id(resource_id);
            rcdata_dir_node.numberof_id_entries(1);

            rc_data_root.add_child(rcdata_dir_node);
        }
        catch (const std::exception& ex)
        {
            return static_cast<unsigned int>(LIEF_SYS_STATUS::SET_RCDATA_ERROR);
        }

        return static_cast<unsigned int>(LIEF_SYS_STATUS::OK);
    }

    LIEF_SYS_EXPORT unsigned int SetString(ResourceManager* _this, const uint16_t* string_data, const uint32_t resource_id) {
        const uint32_t max_strings_count = 16;

        PE::ResourcesManager* resources_manager = reinterpret_cast<PE::ResourcesManager*>(_this);
        try
        {
            PE::ResourceNode& string_table_root  = resources_manager->get_node_type(PE::RESOURCE_TYPES::STRING);

            std::u16string string = std::u16string(reinterpret_cast<char16_t const*>(string_data));

            if(DeleteRootNodeChilds(string_table_root, resource_id % max_strings_count) !=  LIEF_SYS_STATUS::OK)
                return static_cast<unsigned int>(LIEF_SYS_STATUS::SET_STRING_ERROR);

            PE::ResourceData string_table_data_node;
            PE::ResourceDirectory string_table_dir_node;

            std::vector<uint8_t> content(max_strings_count * 2, 0);

            size_t blockId = 2 * (static_cast<size_t>(resource_id) % max_strings_count);
            content[blockId] = string.size();

            const uint8_t* begin = reinterpret_cast<uint8_t const*>(string.c_str());
            const uint8_t* end = reinterpret_cast<uint8_t const*>(string.c_str() + string.size());

            const size_t offset = std::distance(content.data(), content.data() + blockId + 2);
            std::vector<uint8_t>::const_iterator pos = content.cbegin() + offset;

            content.insert(pos, begin, end);

            string_table_data_node.id(static_cast<uint32_t>(PE::RESOURCE_LANGS::LANG_ENGLISH));
            string_table_data_node.content(content);

            string_table_dir_node.id(resource_id % max_strings_count);
            string_table_dir_node.add_child(string_table_data_node);
            string_table_dir_node.numberof_id_entries(1);

            string_table_root.add_child(string_table_dir_node);
        }
        catch(const std::exception& ex)
        {
            return static_cast<unsigned int>(LIEF_SYS_STATUS::SET_STRING_ERROR);
        }

        return static_cast<unsigned int>(LIEF_SYS_STATUS::OK);
    }
}

LIEF_SYS_STATUS DeleteRootNodeChilds(PE::ResourceNode& root, uint32_t dir_node_id) {
    auto childs = root.childs();

    auto&& dir_node = std::find_if(
            std::begin(childs),
            std::end(childs),
            [&](const PE::ResourceNode& node) {
                return node.id() == dir_node_id;
            });

    if(dir_node == std::end(childs)) 
        return LIEF_SYS_STATUS::OK;


    try
    {
        auto data_nodes = dir_node->childs();
        std::for_each(
            std::begin(data_nodes),
            std::end(data_nodes),
            [&](const PE::ResourceNode& data_node)
            {
                dir_node->delete_child(data_node);
            });

        root.delete_child(*dir_node);
    }
    catch(const std::exception& ex)
    {
        return LIEF_SYS_STATUS::DELETE_NODE_ERROR;
    }

    return LIEF_SYS_STATUS::OK;
}
