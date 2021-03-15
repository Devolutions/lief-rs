#include <cmath>
#include <memory>
#include <exception>
#include <stdexcept>
#include <vector>
#include <string>
#include "LIEF/PE.hpp"

#ifdef _MSC_VER
    #define LIEF_SYS_EXPORT __declspec(dllexport)
#else
    #define LIEF_SYS_EXPORT __attribute__((dllexport))
#endif

#define Result(type, name) typedef struct { type value; const char* message; } name

enum class LIEF_SYS_STATUS: unsigned  int {
    OK = 0,
    ERROR,
};

const uint32_t gMaxStringsCount = 16;

using namespace LIEF;

typedef struct Binary Binary;
typedef struct ResourceManager ResourceManager;

Result(Binary*, BinaryResult);
Result(unsigned int, StatusResult);
Result(ResourceManager*, ResourceManagerResult);
Result(uint8_t*, GetRcDataResult);
Result(uint16_t*, GetStringResult);
Result(uint8_t*, GetIconResult);

PE::ResourceIcon CreateIconFromRawData(const uint8_t* data, size_t data_size);
void DeleteRootNodeChilds(PE::ResourceNode& root, uint32_t dir_node_id);
const char* CopyCStringToHeap(const char* string);

extern "C"
{
    LIEF_SYS_EXPORT BinaryResult Binary_New(const char* path) {
        std::unique_ptr<PE::Binary> binary;

        try
        {
            binary = PE::Parser::parse(path);
        }
        catch(const std::exception& ex)
        {
            const char* message = CopyCStringToHeap(ex.what());
            return BinaryResult{ nullptr, message };
        }

        auto ptr = reinterpret_cast<Binary*>(binary.release());

        return BinaryResult{ ptr, nullptr };
    }

    LIEF_SYS_EXPORT void Binary_Free(Binary* _this) {
        auto* binary = reinterpret_cast<PE::Binary*>(_this);
        delete binary;
    }

    LIEF_SYS_EXPORT StatusResult Binary_Build(Binary* _this, const char* path) {
        auto* binary = reinterpret_cast<PE::Binary*>(_this);
        PE::Builder builder = PE::Builder(binary);

        builder.build_resources(true);

        try
        {
            builder.build();
            builder.write(path);
        }
        catch(const std::exception& ex)
        {
            const char* message = CopyCStringToHeap(ex.what());
            return StatusResult { static_cast<unsigned int>(LIEF_SYS_STATUS::ERROR), message };
        }

        return StatusResult { static_cast<unsigned int>(LIEF_SYS_STATUS::OK), nullptr };
    }

    LIEF_SYS_EXPORT ResourceManagerResult Binary_GetResourceManager(Binary* _this) {
        auto* binary = reinterpret_cast<PE::Binary*>(_this);

        PE::ResourcesManager* resourceManager = nullptr;
        PE::ResourcesManager tmp(nullptr);

        try
        {
            tmp = binary->resources_manager();
            resourceManager = new PE::ResourcesManager(nullptr);
        }
        catch(const std::exception& ex)
        {
            const char* message = CopyCStringToHeap(ex.what());
            return ResourceManagerResult{ nullptr, message };
        }

        *resourceManager = tmp;
        auto ptr = reinterpret_cast<ResourceManager*>(resourceManager);

        return ResourceManagerResult{ ptr, nullptr };
    }

    LIEF_SYS_EXPORT void ResourceManager_Free(ResourceManager* _this) {
        auto* resources_manager = reinterpret_cast<PE::ResourcesManager*>(_this);
        delete resources_manager;
    }

    LIEF_SYS_EXPORT StatusResult SetRcData(ResourceManager* _this, const uint8_t* data, size_t data_size, uint32_t resource_id) {
        auto* resources_manager = reinterpret_cast<PE::ResourcesManager*>(_this);

        try
        {
            PE::ResourceNode& rcdata_root = resources_manager->get_node_type(PE::RESOURCE_TYPES::RCDATA);

            DeleteRootNodeChilds(rcdata_root, resource_id);

            PE::ResourceData rcdata_data_node;
            PE::ResourceDirectory rcdata_dir_node;

            std::vector <uint8_t> content(data_size, 0);

            std::copy(data, data + data_size * sizeof(uint8_t), content.begin());

            rcdata_data_node.id(static_cast<uint32_t>(PE::RESOURCE_LANGS::LANG_ENGLISH));
            rcdata_data_node.content(content);

            rcdata_dir_node.add_child(rcdata_data_node);

            rcdata_dir_node.id(resource_id);
            rcdata_dir_node.numberof_id_entries(1);

            rcdata_root.add_child(rcdata_dir_node);
        }
        catch(const std::exception& ex)
        {
            const char* message = CopyCStringToHeap(ex.what());
            return StatusResult{ static_cast<unsigned int>(LIEF_SYS_STATUS::ERROR), message };
        }

        return StatusResult { static_cast<unsigned int>(LIEF_SYS_STATUS::OK), nullptr };
    }

    LIEF_SYS_EXPORT GetRcDataResult GetRcData(ResourceManager* _this, uint32_t resource_id, size_t* rcdata_size) {
        auto* resources_manager = reinterpret_cast<PE::ResourcesManager*>(_this);

        uint8_t* rcdata = nullptr;
        try
        {
            PE::ResourceNode& rcdata_root = resources_manager->get_node_type(PE::RESOURCE_TYPES::RCDATA);
            auto childs = rcdata_root.childs();

            auto&& rcdata_dir_node = std::find_if(
                    std::cbegin(childs),
                    std::cend(childs),
                    [&] (const auto& node) {
                        return node.id() == resource_id;
                    });

            if(rcdata_dir_node == std::cend(childs)) {
                const char* message = CopyCStringToHeap("Failed to find rcdata dir node in rcdata root node");
                return GetRcDataResult { rcdata, message };
            }

            auto dir_childs = rcdata_dir_node->childs();
            if(dir_childs.size() == 0) {
                const char* message = CopyCStringToHeap("There is no children in rcdata dir node");
                return GetRcDataResult { rcdata, message };
            }

            const auto* rcdata_data_node = static_cast<PE::ResourceData*>(&dir_childs[0]);

            if(rcdata_data_node == nullptr) {
                const char* message = CopyCStringToHeap("There is no children in rcdata dir node");
                return GetRcDataResult { rcdata, message };
            }

            const auto& content = rcdata_data_node->content();
            if(content.size() == 0) {
                const char* message = CopyCStringToHeap("Rcdata content is empty");
                return GetRcDataResult { rcdata, message };
            }

            rcdata = new uint8_t[content.size()];

            std::copy(std::cbegin(content), std::cend(content), rcdata);
            *rcdata_size = content.size();
        }
        catch(const std::exception& ex)
        {
            delete[] rcdata;
            const char* message = CopyCStringToHeap(ex.what());
            return GetRcDataResult {nullptr, message };
        }

        return GetRcDataResult { rcdata, nullptr };
    }

    LIEF_SYS_EXPORT void DeallocateRcData(const uint8_t* rcdata){
        delete[] rcdata;
    }

    LIEF_SYS_EXPORT StatusResult SetString(ResourceManager* _this, const uint16_t* string_data, const uint32_t resource_id) {
        auto* resources_manager = reinterpret_cast<PE::ResourcesManager*>(_this);

        try
        {
            PE::ResourceNode& string_table_root  = resources_manager->get_node_type(PE::RESOURCE_TYPES::STRING);

            std::u16string string = std::u16string(reinterpret_cast<char16_t const*>(string_data));

            DeleteRootNodeChilds(string_table_root, resource_id % gMaxStringsCount);

            PE::ResourceData string_table_data_node;
            PE::ResourceDirectory string_table_dir_node;

            std::vector<uint8_t> content(gMaxStringsCount * 2, 0);

            size_t blockId = 2 * (static_cast<size_t>(resource_id) % gMaxStringsCount);
            content[blockId] = string.size();

            const auto* begin = reinterpret_cast<uint8_t const*>(string.c_str());
            const auto* end = reinterpret_cast<uint8_t const*>(string.c_str() + string.size());

            const size_t offset = std::distance(content.data(), content.data() + blockId + 2);
            auto pos = content.cbegin() + offset;

            content.insert(pos, begin, end);

            string_table_data_node.id(static_cast<uint32_t>(PE::RESOURCE_LANGS::LANG_ENGLISH));
            string_table_data_node.content(content);

            string_table_dir_node.id(static_cast<uint32_t>(std::ceil(float(resource_id) / gMaxStringsCount)));
            string_table_dir_node.add_child(string_table_data_node);
            string_table_dir_node.numberof_id_entries(1);

            string_table_root.add_child(string_table_dir_node);
        }
        catch(const std::exception& ex)
        {
            const char* message = CopyCStringToHeap(ex.what());
            return StatusResult{ static_cast<unsigned int>(LIEF_SYS_STATUS::ERROR), message };
        }

        return StatusResult { static_cast<unsigned int>(LIEF_SYS_STATUS::OK), nullptr };
    }

    LIEF_SYS_EXPORT GetStringResult GetString(ResourceManager* _this, const uint32_t resource_id,  size_t* const string_size) {
        auto* resources_manager = reinterpret_cast<PE::ResourcesManager*>(_this);

        uint16_t* string = nullptr;

        try
        {
            PE::ResourceNode& string_table_root  = resources_manager->get_node_type(PE::RESOURCE_TYPES::STRING);
            auto root_childs = string_table_root.childs();

            auto string_dir_id = static_cast<uint32_t>(std::ceil(float(resource_id) / gMaxStringsCount));

            auto&& string_table_dir_node = std::find_if(
                    std::cbegin(root_childs),
                    std::cend(root_childs),
                    [&](const auto& node) {
                        return node.id() == string_dir_id;
                    });

            if(string_table_dir_node == std::cend(root_childs)) {
                const char* message = CopyCStringToHeap("Failed to find string table dir node in string table root node");
                return GetStringResult{ nullptr, message};
            }

            auto dir_childs = string_table_dir_node->childs();
            if(dir_childs.size() == 0) {
                const char* message = CopyCStringToHeap("There is no children in dir string table node");
                return GetStringResult{ nullptr, message };
            }


            const auto* string_table_data_node = static_cast<PE::ResourceData*>(&dir_childs[0]);
            if(string_table_data_node == nullptr) {
                const char* message = CopyCStringToHeap("String table first children is not ResourceData type");
                return GetStringResult{ nullptr, message };
            }


            const auto& content = string_table_data_node->content();
            if(content.size() < 2 * gMaxStringsCount) {
                const char* message = CopyCStringToHeap("String table resource data size is less that 32 bytes");
                return GetStringResult{ nullptr, message };
            }


            size_t blockId = 2 * (static_cast<uint32_t>(resource_id) % gMaxStringsCount);

            *string_size = content[blockId];

            const size_t offset = std::distance(content.data(), content.data() + blockId + 2);
            std::u16string u16string(reinterpret_cast<const uint16_t*>(content.data() + offset),
                                        reinterpret_cast<const uint16_t*>(content.data() + offset +  2 * *string_size));

            string = new uint16_t[*string_size];

            std::copy(std::cbegin(u16string), std::cend(u16string), string);
        }
        catch(const std::exception& ex)
        {
            delete[] string;
            const char* message = CopyCStringToHeap(ex.what());
            return GetStringResult{ nullptr, message };
        }

        return GetStringResult{ string, nullptr };
    }

    LIEF_SYS_EXPORT void DeallocateString(const uint16_t* string) {
        delete[] string;
    }

    LIEF_SYS_EXPORT StatusResult ReplaceIcon(ResourceManager* _this, const uint8_t* data, size_t data_size) {
        PE::ResourcesManager* resources_manager = reinterpret_cast<PE::ResourcesManager*>(_this);

        try
        {
            if(!resources_manager->has_icons()) {
                const char* message = CopyCStringToHeap("The executable have no icons");
                return StatusResult { static_cast<unsigned int>(LIEF_SYS_STATUS::ERROR), message };
            }

            PE::ResourceIcon icon = CreateIconFromRawData(data, data_size);

            PE::ResourceNode& icon_group_root = resources_manager->get_node_type(PE::RESOURCE_TYPES::GROUP_ICON);
            PE::ResourceNode& icon_root = resources_manager->get_node_type(PE::RESOURCE_TYPES::ICON);

            icon_group_root.sort_by_id();
            for(auto& grp_icon_dir_node: icon_group_root.childs()) {
                grp_icon_dir_node.sort_by_id();

                for(auto& grp_icon_data_node: grp_icon_dir_node.childs()) {
                    auto* icon_group_res_data = static_cast<PE::ResourceData*>(&grp_icon_data_node);

                    auto icon_group_content = icon_group_res_data->content();
                    auto* icon_group_header = reinterpret_cast<PE::pe_resource_icon_dir*>(icon_group_content.data());

                    for(size_t i = 0; i < icon_group_header->count; i++) {
                        auto* icon_header = reinterpret_cast<PE::pe_resource_icon_group*>(
                                    icon_group_content.data() +
                                    sizeof(PE::pe_resource_icon_dir) +
                                    i * sizeof(PE::pe_resource_icon_group));

                        if(icon_header != nullptr
                            && (icon_header->width == icon.width())
                            && (icon_header->height == icon.height()))
                        {
                            icon_header->color_count = icon.color_count();
                            icon_header->reserved = icon.reserved();
                            icon_header->planes = icon.planes();
                            icon_header->bit_count = icon.bit_count();
                            icon_header->size = icon.size();

                            icon.id(icon_header->ID);

                            DeleteRootNodeChilds(icon_root, icon_header->ID);

                            PE::ResourceData icon_res_data{ icon.pixels(), 0 };
                            icon_res_data.id(static_cast<int>(icon.sublang()) << 10 | static_cast<int>(icon.lang()));

                            PE::ResourceDirectory icon_res_dir;
                            icon_res_dir.id(icon.id());
                            icon_res_dir.add_child(icon_res_data);

                            icon_root.add_child(icon_res_dir);
                        }
                    }
                }
            }
        }
        catch(const std::exception& ex)
        {
            const char* message = CopyCStringToHeap(ex.what());
            return StatusResult { static_cast<unsigned int>(LIEF_SYS_STATUS::ERROR), message };
        }

        return  StatusResult { static_cast<unsigned int>(LIEF_SYS_STATUS::OK), nullptr };
    }

    LIEF_SYS_EXPORT GetIconResult GetIcon(ResourceManager* _this, uint32_t width, uint32_t height, size_t* pixels_data_size) {
        auto* resources_manager = reinterpret_cast<PE::ResourcesManager*>(_this);

        uint8_t* icon_pixels = nullptr;
        try
        {
            if(!resources_manager->has_icons()) {
                const char* message = CopyCStringToHeap("The executable have no icons");
                return GetIconResult{ nullptr, message };
            }

            auto icons = resources_manager->icons();

            auto icon_width = static_cast<uint8_t>(width);
            auto icon_height = static_cast<uint8_t>(height);

            auto&& icon = std::find_if(
                    std::cbegin(icons),
                    std::cend(icons),
                    [&](const auto& icon) {
                        return icon.width() == icon_width && icon.height() ==  icon_height;
                    });

            if(icon == std::cend(icons)) {
                const char* message = CopyCStringToHeap("There is not an icons with specified width and height");
                return GetIconResult{ nullptr, message };
            }

            auto pixels = icon->pixels();
            if(pixels.size() == 0) {
                const char* message = CopyCStringToHeap("The Icon with specified width and height don't have pixels");
                return GetIconResult{ nullptr, message };
            }

            icon_pixels = new uint8_t[pixels.size()];

            std::copy(std::cbegin(pixels), std::cend(pixels), icon_pixels);
            *pixels_data_size = pixels.size();
        }
        catch(const std::exception& ex)
        {
            delete[] icon_pixels;
            const char* message = CopyCStringToHeap(ex.what());
            return GetIconResult { nullptr, message };
        }

        return GetIconResult { icon_pixels, nullptr };
    }

    LIEF_SYS_EXPORT void DeallocateIcon(const uint8_t* icon_data) {
        delete[] icon_data;
    }

    LIEF_SYS_EXPORT void DeallocateMessage(const char* message) {
        delete[] message;
    }
}

PE::ResourceIcon CreateIconFromRawData(const uint8_t* data, size_t data_size) {
    if(data_size < sizeof(PE::pe_resource_icon_dir))
        throw std::out_of_range("Icon data size is less than pe_resource_icon_dir size");


    const auto* icon_header = reinterpret_cast<const PE::pe_icon_header*>(data + sizeof(PE::pe_resource_icon_dir));
    PE::ResourceIcon icon{icon_header};

    if(data_size < icon_header->offset + icon_header->size)
        throw std::out_of_range("Icon data size is less than icon_header offset + icon_header size");

    std::vector<uint8_t> pixels = { data + icon_header->offset, data + icon_header->offset + icon_header->size };
    icon.pixels(pixels);

    return icon;
}

void DeleteRootNodeChilds(PE::ResourceNode& root, uint32_t dir_node_id) {
    auto childs = root.childs();

    auto&& dir_node = std::find_if(
            std::cbegin(childs),
            std::cend(childs),
            [&](const auto& node) {
                return node.id() == dir_node_id;
            });

    if(dir_node == std::cend(childs))
        return;

    auto data_nodes = dir_node->childs();
    std::for_each(
            std::begin(data_nodes),
            std::end(data_nodes),
            [&](const auto& data_node)
            {
                dir_node->delete_child(data_node);
            });

    root.delete_child(*dir_node);
}

const char* CopyCStringToHeap(const char* string) {
    auto len = std::strlen(string);
    char* new_string = nullptr;

    try
    {
        new_string = new char[len + 1];
        std::strncpy(new_string, string, len);
        new_string[len] = '\0';
    }
    catch(const std::exception& ex)
    {
        delete[] new_string;
        return nullptr;
    }

    return new_string;
}