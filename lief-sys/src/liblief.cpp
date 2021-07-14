#include <cmath>
#include <memory>
#include <exception>
#include <stdexcept>
#include <numeric>
#include <vector>

#include "LIEF/PE.hpp"
#include "LIEF/logging.hpp"
#undef LANG_ENGLISH

#ifdef _MSC_VER
    #define LIEF_SYS_EXPORT __declspec(dllexport)
#else
    #define LIEF_SYS_EXPORT __attribute__((dllexport))
#endif

#define Result(type, name) typedef struct { type value; const char* message; } name

enum class LIEF_SYS_STATUS: unsigned int {
    Ok = 0,
    Err,
};

const uint32_t gMaxStringsCount = 16;

using namespace LIEF;

typedef struct Binary Binary;
typedef struct ResourceManager ResourceManager;

Result(Binary*, BinaryResult);
Result(uint8_t*, GetFileHashResult);
Result(unsigned int, StatusResult);
Result(int, SignatureVeryficationResult);
Result(ResourceManager*, ResourceManagerResult);
Result(uint8_t*, GetRcDataResult);
Result(uint16_t*, GetStringResult);
Result(uint8_t*, GetIconResult);
Result(uint8_t*, GetAuthenticodeDataResult);

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

    LIEF_SYS_EXPORT StatusResult Binary_Build(Binary* _this, const char* path, bool with_resources) {
        auto* binary = reinterpret_cast<PE::Binary*>(_this);
        PE::Builder builder = PE::Builder(binary);

        builder.build_resources(with_resources);
        try
        {
            builder.build();
            builder.write(path);
        }
        catch(const std::exception& ex)
        {
            return StatusResult { static_cast<unsigned int>(LIEF_SYS_STATUS::Err), CopyCStringToHeap(ex.what()) };
        }

        return StatusResult { static_cast<unsigned int>(LIEF_SYS_STATUS::Ok), nullptr };
    }

    LIEF_SYS_EXPORT GetFileHashResult GetFileHash(Binary* _this, size_t* hash_len)  {
        auto* binary = reinterpret_cast<PE::Binary*>(_this);
        std::unique_ptr<uint8_t []> file_hash = nullptr;

        try
        {
            std::vector<uint8_t> hash = binary->authentihash(PE::ALGORITHMS::SHA_256);
            if (hash.size() == 0)
                return GetFileHashResult{ nullptr, CopyCStringToHeap("Authentihash size is zero") };

            file_hash.reset(new uint8_t[hash.size()]);

            std::copy(std::cbegin(hash), std::cend(hash), file_hash.get());

            if (hash_len == nullptr)
                return GetFileHashResult{ nullptr, CopyCStringToHeap("Out variable hash_len is a null pointer") };

            *hash_len = hash.size();
        }
        catch(const std::exception &ex)
        {
            return GetFileHashResult{ nullptr, CopyCStringToHeap(ex.what()) };
        }

        return GetFileHashResult{ file_hash.release(), nullptr };
    }

    LIEF_SYS_EXPORT void DeallocateFileHash(const uint8_t* file_hash) {
        delete[] file_hash;
    }

    LIEF_SYS_EXPORT StatusResult SetAuthenticode(Binary* _this, const uint8_t* cert_data, size_t cert_data_len) {
        auto* binary = reinterpret_cast<PE::Binary*>(_this);

        try
        {
            auto it_sections = binary->sections();

            std::vector<uint8_t> data(cert_data_len, 0);
            std::copy(cert_data, cert_data + cert_data_len * sizeof(uint8_t), data.begin());

            uint32_t certificate_table_offset = 0;
            const uint64_t last_section_offset = std::accumulate(
                    std::cbegin(it_sections),
                    std::cend(it_sections), 0,
                    [] (uint64_t offset, const PE::Section& section) {
                        return std::max<uint64_t>(section.offset() + section.size(), offset);
                    });

            certificate_table_offset += last_section_offset;
            std::vector<uint8_t>& overlay = binary->overlay();
            certificate_table_offset += overlay.size();

            overlay.reserve(data.size());
            std::copy(data.cbegin(), data.cend(), std::back_inserter(overlay));

            PE::DataDirectory& certificate_table = binary->data_directory(PE::DATA_DIRECTORY::CERTIFICATE_TABLE);

            certificate_table.RVA(certificate_table_offset);
            certificate_table.size(cert_data_len);
        }
        catch(const std::exception& ex)
        {
            return StatusResult { static_cast<unsigned int>(LIEF_SYS_STATUS::Err), CopyCStringToHeap(ex.what()) };
        }

        return StatusResult { static_cast<unsigned int>(LIEF_SYS_STATUS::Ok), nullptr };
    }

    LIEF_SYS_EXPORT GetAuthenticodeDataResult GetAuthenticodeData(Binary* _this, size_t* data_size) {
        auto* binary = reinterpret_cast<PE::Binary*>(_this);

        std::unique_ptr<uint8_t []> data = nullptr;
        try
        {
            PE::DataDirectory& certificate_table = binary->data_directory(PE::DATA_DIRECTORY::CERTIFICATE_TABLE);

            auto it_sections = binary->sections();
            const uint64_t overlay_offset = std::accumulate(
                    std::cbegin(it_sections),
                    std::cend(it_sections), 0,
                    [] (uint64_t offset, const PE::Section& section) {
                        return std::max<uint64_t>(section.offset() + section.size(), offset);
                    });

            if (certificate_table.RVA() > 0 && certificate_table.size() > 0 && certificate_table.RVA() >= overlay_offset)
            {
                const uint64_t start_cert_offset = certificate_table.RVA() - overlay_offset;
                const uint64_t end_cert_offset   = start_cert_offset + certificate_table.size();

                const auto& overlay = binary->overlay();
                if (end_cert_offset <= overlay.size()) {
                    data.reset(new uint8_t[certificate_table.size()]);

                    std::copy(overlay.data() + start_cert_offset, overlay.data() + end_cert_offset, data.get());
                } else {
                    data.reset(new uint8_t[certificate_table.size()]);

                    std::copy(std::cbegin(overlay), std::cend(overlay), data.get());
                }

                if(data_size == nullptr)
                    return GetAuthenticodeDataResult{ nullptr, CopyCStringToHeap("Out variable data_size is a null pointer") };

                *data_size = certificate_table.size();
            }
            else
                return GetAuthenticodeDataResult{ nullptr, CopyCStringToHeap("File is not digital signed") };
        }
        catch(const std::exception& ex)
        {
            return GetAuthenticodeDataResult{ nullptr,  CopyCStringToHeap(ex.what()) };
        }


        return GetAuthenticodeDataResult{ data.release() , nullptr };
    }

    LIEF_SYS_EXPORT SignatureVeryficationResult CheckSignature(Binary* _this, int checks) {
        auto* binary = reinterpret_cast<PE::Binary* const>(_this);

        auto verification_checks = static_cast<PE::Signature::VERIFICATION_CHECKS>(checks);
        auto verification_flags = PE::Signature::VERIFICATION_FLAGS::OK;
        try
        {
            verification_flags = binary->verify_signature(verification_checks);
        }
        catch(const std::exception& ex)
        {
            return SignatureVeryficationResult {static_cast<uint16_t>(-1), CopyCStringToHeap(ex.what())};
        }

        return SignatureVeryficationResult { static_cast<int>(verification_flags), nullptr };
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
            return ResourceManagerResult{ nullptr, CopyCStringToHeap(ex.what()) };
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
            return StatusResult{ static_cast<unsigned int>(LIEF_SYS_STATUS::Err), CopyCStringToHeap(ex.what()) };
        }

        return StatusResult { static_cast<unsigned int>(LIEF_SYS_STATUS::Ok), nullptr };
    }

    LIEF_SYS_EXPORT GetRcDataResult GetRcData(ResourceManager* _this, uint32_t resource_id, size_t* rcdata_size) {
        auto* resources_manager = reinterpret_cast<PE::ResourcesManager*>(_this);

        std::unique_ptr<uint8_t[]> rcdata = nullptr;
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

            if(rcdata_dir_node == std::cend(childs))
                return GetRcDataResult { nullptr, CopyCStringToHeap("Failed to find rcdata dir node in rcdata root node") };

            auto dir_childs = rcdata_dir_node->childs();
            if(dir_childs.size() == 0)
                return GetRcDataResult { nullptr, CopyCStringToHeap("There is no children in rcdata dir node") };

            const auto* rcdata_data_node = static_cast<PE::ResourceData*>(&dir_childs[0]);

            if(rcdata_data_node == nullptr)
                return GetRcDataResult { nullptr, CopyCStringToHeap("There is no children in rcdata dir node") };

            const auto& content = rcdata_data_node->content();
            if(content.size() == 0)
                return GetRcDataResult { nullptr, CopyCStringToHeap("Rcdata content is empty") };

            rcdata.reset(new uint8_t[content.size()]);

            std::copy(std::cbegin(content), std::cend(content), rcdata.get());

            if(rcdata_size == nullptr)
                return GetRcDataResult{ nullptr, CopyCStringToHeap("Out variable rcdata_size is a null pointer") };

            *rcdata_size = content.size();
        }
        catch(const std::exception& ex)
        {
            return GetRcDataResult { nullptr, CopyCStringToHeap(ex.what()) };
        }

        return GetRcDataResult { rcdata.release(), nullptr };
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
            return StatusResult{ static_cast<unsigned int>(LIEF_SYS_STATUS::Err), CopyCStringToHeap(ex.what()) };
        }

        return StatusResult { static_cast<unsigned int>(LIEF_SYS_STATUS::Ok), nullptr };
    }

    LIEF_SYS_EXPORT GetStringResult GetString(ResourceManager* _this, const uint32_t resource_id,  size_t* const string_size) {
        auto* resources_manager = reinterpret_cast<PE::ResourcesManager*>(_this);

        std::unique_ptr<uint16_t[]> string = nullptr;

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

            if(string_table_dir_node == std::cend(root_childs))
                return GetStringResult{ nullptr, CopyCStringToHeap("Failed to find string table dir node in string table root node") };

            auto dir_childs = string_table_dir_node->childs();
            if(dir_childs.size() == 0)
                return GetStringResult{ nullptr, CopyCStringToHeap("There is no children in dir string table node") };

            const auto* string_table_data_node = static_cast<PE::ResourceData*>(&dir_childs[0]);
            if(string_table_data_node == nullptr)
                return GetStringResult{ nullptr, CopyCStringToHeap("String table first children is not ResourceData type") };

            const auto& content = string_table_data_node->content();
            if(content.size() < 2 * gMaxStringsCount)
                return GetStringResult{ nullptr, CopyCStringToHeap("String table resource data size is less that 32 bytes") };

            size_t blockId = 2 * (static_cast<uint32_t>(resource_id) % gMaxStringsCount);

            if (string_size == nullptr)
                return GetStringResult{ nullptr, CopyCStringToHeap("Out variable string_size is a null pointer") };

            *string_size = content[blockId];

            const size_t offset = std::distance(content.data(), content.data() + blockId + 2);
            std::u16string u16string(reinterpret_cast<const uint16_t*>(content.data() + offset),
                                        reinterpret_cast<const uint16_t*>(content.data() + offset +  2 * *string_size));

            string.reset(new uint16_t[*string_size]);

            std::copy(std::cbegin(u16string), std::cend(u16string), string.get());
        }
        catch(const std::exception& ex)
        {
            return GetStringResult{ nullptr, CopyCStringToHeap(ex.what()) };
        }

        return GetStringResult{ string.release(), nullptr };
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
                return StatusResult {static_cast<unsigned int>(LIEF_SYS_STATUS::Err), message };
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
            return StatusResult {static_cast<unsigned int>(LIEF_SYS_STATUS::Err), CopyCStringToHeap(ex.what()) };
        }

        return  StatusResult {static_cast<unsigned int>(LIEF_SYS_STATUS::Ok), nullptr };
    }

    LIEF_SYS_EXPORT GetIconResult GetIcon(ResourceManager* _this, uint32_t width, uint32_t height, size_t* pixels_data_size) {
        auto* resources_manager = reinterpret_cast<PE::ResourcesManager*>(_this);

        std::unique_ptr<uint8_t[]> icon_pixels = nullptr;
        try
        {
            if(!resources_manager->has_icons()) {
                return GetIconResult{ nullptr, CopyCStringToHeap("The executable have no icons") };
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

            if(icon == std::cend(icons))
                return GetIconResult{ nullptr, CopyCStringToHeap("There is not an icons with specified width and height") };


            auto pixels = icon->pixels();
            if(pixels.size() == 0)
                return GetIconResult{ nullptr, CopyCStringToHeap("The Icon with specified width and height don't have pixels") };

            icon_pixels.reset(new uint8_t[pixels.size()]);

            std::copy(std::cbegin(pixels), std::cend(pixels), icon_pixels.get());

            if(pixels_data_size == nullptr)
                return GetIconResult{ nullptr, CopyCStringToHeap("Out variable pixels_data_size is a null pointer") };

            *pixels_data_size = pixels.size();
        }
        catch(const std::exception& ex)
        {
            return GetIconResult { nullptr, CopyCStringToHeap(ex.what()) };
        }

        return GetIconResult { icon_pixels.release(), nullptr };
    }

    LIEF_SYS_EXPORT void DeallocateIcon(const uint8_t* icon_data) {
        delete[] icon_data;
    }

    LIEF_SYS_EXPORT void DeallocateMessage(const char* message) {
        delete[] message;
    }

    LIEF_SYS_EXPORT void DeallocateAuthenticode(uint8_t* data) {
        delete[] data;
    }

    LIEF_SYS_EXPORT void EnableLogging(int log_level) {
        logging::enable();
        logging::set_level(static_cast<logging::LOGGING_LEVEL>(log_level));
    }

    LIEF_SYS_EXPORT void DisableLogging() {
        logging::disable();
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

    while (dir_node->childs().size() != 0) {
        auto child = dir_node->childs();
        dir_node->delete_child(*child);
    }

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
