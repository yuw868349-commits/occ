// The interface and address tables: IPHLPAPI.
//
// A Windows program that wants to know what the machine can reach asks this
// module, and it asks in one of two shapes. The first is a flat list of
// interfaces with their addresses -- `GetAdaptersInfo`, and the
// `GetAdaptersAddresses` that replaced it. The second is a table of the
// connections that exist right now -- `GetTcpTable` and the extended
// versions of it.
//
// The answers are built from the machine this runtime is running on rather
// than from a Windows-shaped store, because there is no Windows-shaped
// store: the interfaces are the host's interfaces and the connections are
// the host's connections, and the work here is the translation. That
// translation is not cosmetic. `IP_ADAPTER_ADDRESSES` is a structure with
// forty fields, of which a caller reads perhaps six, and the six are spread
// across the whole of it -- so the offsets matter and are written out below
// rather than derived.
//
// The two enumerations share one walk of `getifaddrs`, because the index a
// caller gets from `if_nametoindex` has to be the index it reads back out
// of an adapter it enumerated here. Two independent walks could order the
// interfaces differently, and an index that means one interface in one call
// and another in the next is worse than no index at all.
//
// What is not here, and why:
//
//   * The statistics tables -- `GetTcpStatistics`, `GetIpStatistics` and
//     their protocol relatives -- describe counters the host keeps in its
//     own namespace and does not expose in the shape these calls promise.
//
//   * The change notifications -- `NotifyAddrChange`, `NotifyRouteChange`
//     -- block until the machine's configuration changes, and this runtime
//     has no view of the host's configuration changing.
//
//   * The policy and quality-of-service calls -- `GetInterfaceInfo`,
//     `SetIpForwardEntry` and the rest of the administration surface --
//     change a configuration this runtime does not own.

#include "occ/runtime/api.h"
#include "occ/runtime/api_common.h"
#include "occ/runtime/winabi.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

namespace occ::runtime::winabi {
namespace {

// --------------------------------------------------------------- the values

// The error codes this module answers, which are the Win32 ones rather than
// the WinSock ones: the calls here return a status where a socket call
// returns a count.
// The two codes this module needs that the shared set does not carry. The
// rest -- the invalid parameter, the insufficient buffer, the call not
// implemented -- are spelled once in `api_common.h` and used from there, so
// that the same Win32 code is not given two names in two files.
constexpr std::uint32_t kErrorNoData = 232;
constexpr std::uint32_t kErrorBufferOverflow = 111;

// The two address lengths, in the guest's form. They are written here
// because this file builds addresses rather than only reading them.
constexpr std::size_t kSockaddrInBytes = 16;
constexpr std::size_t kSockaddrIn6Bytes = 28;

// The interface types, in the values `IP_ADAPTER_ADDRESSES` carries. They
// are the IANA registry numbers, which is why an Ethernet interface is six
// and a loopback is twenty-four.
constexpr std::uint32_t kIfTypeOther = 1;
constexpr std::uint32_t kIfTypeEthernet = 6;
constexpr std::uint32_t kIfTypePpp = 23;
constexpr std::uint32_t kIfTypeLoopback = 24;
constexpr std::uint32_t kIfTypeIeee80211 = 71;
constexpr std::uint32_t kIfTypeTunnel = 131;

// The operational status. An interface that is up is `IfOperStatusUp`;
// the rest of the enumeration distinguishes the ways it can be down, and
// this runtime reports the two it can tell apart.
constexpr std::uint32_t kIfOperStatusUp = 1;
constexpr std::uint32_t kIfOperStatusDown = 2;

// The family selector `GetAdaptersAddresses` takes. It is not the socket
// family numbering: this call uses the `AF_` numbers of the platform, which
// happen to match the socket ones here but are spelled out so that the two
// uses cannot be confused by a later edit.
constexpr std::uint32_t kFamilyUnspecified = 0;
constexpr std::uint32_t kFamilyInet = 2;
constexpr std::uint32_t kFamilyInet6 = 23;

// Whether an interface's addresses are wanted. The flags this runtime reads
// are the ones that remove a family from the answer; the rest are hints
// about which parts of the structure to fill, and every part is filled.
constexpr std::uint32_t kGaaFlagSkipUnicast = 0x0001;
[[maybe_unused]] constexpr std::uint32_t kGaaFlagSkipAnycast = 0x0002;
[[maybe_unused]] constexpr std::uint32_t kGaaFlagSkipMulticast = 0x0004;
[[maybe_unused]] constexpr std::uint32_t kGaaFlagSkipDnsServer = 0x0008;
constexpr std::uint32_t kGaaFlagSkipFriendlyName = 0x0010;
[[maybe_unused]] constexpr std::uint32_t kGaaFlagIncludePrefix = 0x0020;
// ------------------------------------------------------------- the layouts
//
// `IP_ADAPTER_ADDRESSES`, as the guest lays it out. The structure is four
// hundred and forty-eight bytes and a caller reads a handful of the fields,
// but the handful are spread from the front to the back of it, so the
// offsets are named here rather than counted at each use.
//
// The first eight bytes are a union of an alignment word and the two fields
// a caller actually read: the length of the structure and the index of the
// interface.
constexpr std::size_t kAdapterLength = 0;
constexpr std::size_t kAdapterIfIndex = 4;
constexpr std::size_t kAdapterNext = 8;
constexpr std::size_t kAdapterName = 16;
constexpr std::size_t kAdapterFirstUnicast = 24;
constexpr std::size_t kAdapterDnsSuffix = 56;
constexpr std::size_t kAdapterDescription = 64;
constexpr std::size_t kAdapterFriendlyName = 72;
constexpr std::size_t kAdapterPhysicalAddress = 80;
constexpr std::size_t kAdapterPhysicalLength = 88;
constexpr std::size_t kAdapterFlags = 92;
constexpr std::size_t kAdapterMtu = 96;
constexpr std::size_t kAdapterIfType = 100;
constexpr std::size_t kAdapterOperStatus = 104;
constexpr std::size_t kAdapterIpv6IfIndex = 108;
constexpr std::size_t kAdapterIpv4Metric = 216;
constexpr std::size_t kAdapterIpv6Metric = 220;
constexpr std::size_t kAdapterCompartmentId = 248;
constexpr std::size_t kAdapterConnectionType = 268;
constexpr std::size_t kAdapterTunnelType = 272;
constexpr std::size_t kAdapterBytes = 448;

// `IP_ADAPTER_UNICAST_ADDRESS`, the node one address of one interface
// occupies. Sixty-four bytes, and the parts a caller reads are the address
// itself, the lifetimes and the prefix length.
constexpr std::size_t kUnicastLength = 0;
constexpr std::size_t kUnicastFlags = 4;
constexpr std::size_t kUnicastNext = 8;
constexpr std::size_t kUnicastAddress = 16;
constexpr std::size_t kUnicastPrefixOrigin = 32;
constexpr std::size_t kUnicastSuffixOrigin = 36;
constexpr std::size_t kUnicastDadState = 40;
constexpr std::size_t kUnicastValidLifetime = 44;
constexpr std::size_t kUnicastPreferredLifetime = 48;
constexpr std::size_t kUnicastLeaseLifetime = 52;
constexpr std::size_t kUnicastOnLinkPrefix = 56;
constexpr std::size_t kUnicastBytes = 64;

// A `SOCKET_ADDRESS`: a pointer to the address and its length. It is not
// the address; it is a reference to one, and the address lives in a second
// block that this runtime allocates with the first.
[[maybe_unused]] constexpr std::size_t kSocketAddressPointer = 0;
constexpr std::size_t kSocketAddressLength = 8;
[[maybe_unused]] constexpr std::size_t kSocketAddressBytes = 16;
// `IP_ADAPTER_INFO`, the structure the older call fills. Six hundred and
// sixty-four bytes, with three inline address strings of its own.
constexpr std::size_t kInfoNext = 0;
constexpr std::size_t kInfoComboIndex = 8;
constexpr std::size_t kInfoAdapterName = 12;
constexpr std::size_t kInfoAdapterNameChars = 260;
constexpr std::size_t kInfoDescription = 272;
constexpr std::size_t kInfoDescriptionChars = 132;
constexpr std::size_t kInfoAddressLength = 404;
constexpr std::size_t kInfoAddress = 408;
constexpr std::size_t kInfoIndex = 416;
constexpr std::size_t kInfoType = 420;
constexpr std::size_t kInfoDhcpEnabled = 424;
constexpr std::size_t kInfoCurrentIp = 432;
constexpr std::size_t kInfoIpAddressList = 440;
[[maybe_unused]] constexpr std::size_t kInfoGatewayList = 480;
[[maybe_unused]] constexpr std::size_t kInfoDhcpServer = 520;
constexpr std::size_t kInfoHaveWins = 560;
[[maybe_unused]] constexpr std::size_t kInfoPrimaryWins = 568;
[[maybe_unused]] constexpr std::size_t kInfoSecondaryWins = 608;
constexpr std::size_t kInfoLeaseObtained = 648;
constexpr std::size_t kInfoLeaseExpires = 656;
constexpr std::size_t kInfoBytes = 664;

// `IP_ADDR_STRING`, an address with its mask and a link to the next. The
// two strings inside it are sixteen bytes each and always NUL-terminated.
constexpr std::size_t kAddrStringAddress = 8;
constexpr std::size_t kAddrStringMask = 24;

// `MIB_IFROW`, one interface's counters and identity. Eight hundred and
// sixty bytes, most of which are the counters this runtime leaves zero
// because the host keeps them somewhere else.
constexpr std::size_t kIfRowName = 0;
constexpr std::size_t kIfRowNameChars = 256;
constexpr std::size_t kIfRowIndex = 256;
constexpr std::size_t kIfRowType = 260;
constexpr std::size_t kIfRowMtu = 264;
constexpr std::size_t kIfRowSpeed = 268;
constexpr std::size_t kIfRowPhysAddrLen = 272;
constexpr std::size_t kIfRowPhysAddr = 276;
constexpr std::size_t kIfRowAdminStatus = 284;
constexpr std::size_t kIfRowOperStatus = 288;
constexpr std::size_t kIfRowBytes = 860;

// ----------------------------------------------------------- the interfaces

// One interface, gathered from the host's own description of itself. The
// record is the middle of the translation: the host's walk produces these,
// and every call below turns them into whatever structure it promises.
struct InterfaceRecord {
    std::string name;
    std::uint32_t index = 0;
    std::uint32_t ipv6_index = 0;
    sockaddr_storage address {};
    sockaddr_storage netmask {};
    sockaddr_storage address6 {};
    bool has_address = false;
    bool has_mask = false;
    bool has_address6 = false;
    std::uint8_t mac[8] {};
    std::size_t mac_bytes = 0;
    std::uint32_t mtu = 0;
    std::uint32_t hardware = 0;
    bool up = false;
    bool loopback = false;
};

// The interface type the reports use, from the hardware type the host
// records. The two enumerations agree about nothing except that they both
// describe what the interface is, so the translation is a table.
[[nodiscard]] std::uint32_t interface_type_of(const InterfaceRecord& record) noexcept {
    if (record.loopback) {
        return kIfTypeLoopback;
    }
    switch (record.hardware) {
        case ARPHRD_ETHER:
            return kIfTypeEthernet;
        case ARPHRD_PPP:
            return kIfTypePpp;
        case ARPHRD_IEEE80211:
        case ARPHRD_IEEE80211_PRISM:
            return kIfTypeIeee80211;
        case ARPHRD_TUNNEL:
        case ARPHRD_TUNNEL6:
            return kIfTypeTunnel;
        default:
            break;
    }
    return kIfTypeOther;
}

// The machine's interfaces, in one order, with the indices every call here
// reports. The order is the host's enumeration order, which is stable for
// the life of the process, and the indices run from one because zero is the
// value `if_nametoindex` answers with when the name is not an interface.
[[nodiscard]] std::vector<InterfaceRecord> enumerate_interfaces() noexcept {
    std::vector<InterfaceRecord> records;

    ::ifaddrs* list = nullptr;
    if (::getifaddrs(&list) != 0) {
        return records;
    }

    // One descriptor for the two per-interface requests. A failure to open
    // it leaves the hardware address and the MTU at zero, which is what a
    // caller that reads neither will notice.
    const int probe = ::socket(AF_INET, SOCK_DGRAM, 0);

    for (::ifaddrs* it = list; it != nullptr; it = it->ifa_next) {
        if (it->ifa_name == nullptr) {
            continue;
        }

        InterfaceRecord* record = nullptr;
        for (InterfaceRecord& candidate : records) {
            if (candidate.name == it->ifa_name) {
                record = &candidate;
                break;
            }
        }

        if (record == nullptr) {
            records.emplace_back();
            record = &records.back();
            record->name = it->ifa_name;
            record->up = (it->ifa_flags & IFF_UP) != 0;
            record->loopback = (it->ifa_flags & IFF_LOOPBACK) != 0;

            if (probe >= 0) {
                ::ifreq request {};
                std::memset(&request, 0, sizeof(request));
                std::strncpy(request.ifr_name, it->ifa_name, IFNAMSIZ - 1);

                if (::ioctl(probe, SIOCGIFHWADDR, &request) == 0) {
                    const auto* hardware =
                        reinterpret_cast<const ::sockaddr*>(&request.ifr_hwaddr);
                    record->hardware =
                        static_cast<std::uint32_t>(hardware->sa_family);
                    record->mac_bytes = 6;
                    std::memcpy(record->mac, hardware->sa_data, 6);
                }

                std::memset(&request, 0, sizeof(request));
                std::strncpy(request.ifr_name, it->ifa_name, IFNAMSIZ - 1);
                if (::ioctl(probe, SIOCGIFMTU, &request) == 0) {
                    record->mtu = static_cast<std::uint32_t>(request.ifr_mtu);
                }
            }
        }

        if (it->ifa_addr == nullptr) {
            continue;
        }
        if (it->ifa_addr->sa_family == AF_INET) {
            std::memcpy(&record->address, it->ifa_addr, sizeof(sockaddr_in));
            record->has_address = true;
        } else if (it->ifa_addr->sa_family == AF_INET6) {
            std::memcpy(&record->address6, it->ifa_addr, sizeof(sockaddr_in6));
            record->has_address6 = true;
        }
        if (it->ifa_netmask != nullptr && it->ifa_netmask->sa_family == AF_INET) {
            std::memcpy(&record->netmask, it->ifa_netmask, sizeof(sockaddr_in));
            record->has_mask = true;
        }
    }

    if (probe >= 0) {
        ::close(probe);
    }
    ::freeifaddrs(list);

    std::uint32_t next = 1;
    for (InterfaceRecord& record : records) {
        record.index = next;
        record.ipv6_index = record.has_address6 ? next : 0;
        ++next;
    }
    return records;
}

// The name of an interface as a C string in a caller's buffer, with the
// count the contract asks for: the characters written, not counting the
// terminator.
[[nodiscard]] std::size_t copy_name(const std::string& name, char* out,
                                    std::size_t capacity) noexcept {
    if (out == nullptr || capacity == 0) {
        return 0;
    }
    const std::size_t room =
        name.size() < capacity - 1 ? name.size() : capacity - 1;
    std::memcpy(out, name.data(), room);
    out[room] = '\0';
    return room;
}

// The textual form of an IPv4 address, into a fixed sixteen-byte field of
// one of the older structures. The field is not a pointer and the caller
// reads it as a string, so a failure leaves it empty rather than untouched.
void write_address_text(const sockaddr_storage& address, void* out,
                        std::size_t capacity) noexcept {
    auto* text = static_cast<char*>(out);
    if (capacity == 0) {
        return;
    }
    text[0] = '\0';
    if (address.ss_family != AF_INET) {
        return;
    }
    const auto* in4 = reinterpret_cast<const sockaddr_in*>(&address);
    static_cast<void>(::inet_ntop(AF_INET, &in4->sin_addr, text,
                                 static_cast<socklen_t>(capacity)));
}

// The mask of an address, written the same way.
void write_mask_text(const sockaddr_storage& mask, void* out,
                     std::size_t capacity) noexcept {
    write_address_text(mask, out, capacity);
}

}  // namespace

// ------------------------------------------------------------- the names

extern "C" __attribute__((ms_abi)) std::uint32_t k32ip_if_nametoindex(
    const char* name) noexcept {
    if (name == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return 0;
    }

    // The name this call takes is the interface's own name, which is what
    // the host calls it -- "eth0", "lo" -- and also the friendly name an
    // adapter report gives back. Both are tried, so that a program which
    // read a name out of one call can hand it to this one.
    for (const InterfaceRecord& record : enumerate_interfaces()) {
        if (record.name == name) {
            set_last_error(0);
            return record.index;
        }
    }

    // A name that is not an interface. The contract's answer is zero rather
    // than an error code, and the caller reads the error for the reason.
    set_last_error(kErrorNotFound);
    return 0;
}

extern "C" __attribute__((ms_abi)) char* k32ip_if_indextoname(
    std::uint32_t index, char* name) noexcept {
    if (name == nullptr) {
        set_last_error(kErrorInvalidParameter);
        return nullptr;
    }
    for (const InterfaceRecord& record : enumerate_interfaces()) {
        if (record.index != index) {
            continue;
        }
        static_cast<void>(copy_name(record.name, name, IFNAMSIZ));
        set_last_error(0);
        return name;
    }
    set_last_error(kErrorNotFound);
    return nullptr;
}

extern "C" __attribute__((ms_abi)) std::uint32_t k32ip_GetNumberOfInterfaces(
    std::uint32_t* count) noexcept {
    if (count == nullptr) {
        return kErrorInvalidParameter;
    }
    *count = static_cast<std::uint32_t>(enumerate_interfaces().size());
    return kErrorSuccess;
}

extern "C" __attribute__((ms_abi)) std::uint32_t k32ip_GetFriendlyIfIndex(
    std::uint32_t index) noexcept {
    // The friendly index and the interface index are the same number for
    // every interface this runtime reports, which is the property that
    // makes this call answerable at all: the two are only different when a
    // driver renumbers one of them, and nothing here renumbers anything.
    for (const InterfaceRecord& record : enumerate_interfaces()) {
        if (record.index == index) {
            return index;
        }
    }
    return 0;
}

// -------------------------------------------------------- the adapter lists

// The room the two adapter reports need, and the reports themselves. Each
// returns the bytes it would have written, so that a caller whose buffer
// was too small can size it and ask again -- which is the shape both calls
// have and the reason neither can be answered in one pass.

namespace {

// One interface's `IP_ADAPTER_ADDRESSES` node and the blocks it points at,
// measured before anything is written.
struct AdapterLayout {
    std::size_t adapter_at = 0;
    std::size_t unicast_at = 0;
    std::size_t name_at = 0;
    std::size_t description_at = 0;
    std::size_t dns_suffix_at = 0;
    std::size_t address_at = 0;
    bool wants_unicast = true;
    bool wants_address = false;
    bool wants_address6 = false;
};

[[nodiscard]] std::size_t filled_text_bytes(const std::string& text) noexcept {
    return text.size() + 1;
}

[[nodiscard]] std::size_t wide_text_bytes(std::size_t chars) noexcept {
    return chars * sizeof(char16_t);
}

}  // namespace

extern "C" __attribute__((ms_abi)) std::uint32_t k32ip_GetAdaptersAddresses(
    std::uint32_t family, std::uint32_t flags, void* reserved, void* addresses,
    std::uint32_t* size) noexcept {
    static_cast<void>(reserved);
    if (size == nullptr) {
        return kErrorInvalidParameter;
    }

    const std::vector<InterfaceRecord> records = enumerate_interfaces();

    const bool want4 =
        family == kFamilyUnspecified || family == kFamilyInet;
    const bool want6 =
        family == kFamilyUnspecified || family == kFamilyInet6;
    const bool want_unicast = (flags & kGaaFlagSkipUnicast) == 0;
    const bool want_name = (flags & kGaaFlagSkipFriendlyName) == 0;

    // The measurement pass. Every block a node points at is counted here,
    // in the order the writing pass will place them, because the caller has
    // to be told the whole size before any of it is written.
    std::size_t total = 0;
    std::vector<std::size_t> chosen;
    std::vector<AdapterLayout> layouts;
    chosen.reserve(records.size());
    layouts.reserve(records.size());

    for (std::size_t r = 0; r < records.size(); ++r) {
        const InterfaceRecord& record = records[r];
        const bool carries4 = want4 && record.has_address;
        const bool carries6 = want6 && record.has_address6;
        if (!carries4 && !carries6) {
            // The family the caller asked about is not on this interface,
            // so the interface is not in the answer at all rather than in
            // it with nothing to say.
            continue;
        }

        AdapterLayout layout;
        layout.adapter_at = total;
        total += kAdapterBytes;

        if (want_unicast) {
            if (carries4) {
                layout.unicast_at = total;
                total += kUnicastBytes;
                layout.address_at = total;
                total += kSockaddrInBytes;
            }
            if (carries6) {
                if (!carries4) {
                    layout.unicast_at = total;
                }
                total += kUnicastBytes;
                total += kSockaddrIn6Bytes;
            }
            layout.wants_address = carries4;
            layout.wants_address6 = carries6;
        }

        // The text blocks: the adapter's own name, its description and its
        // DNS suffix. They are UTF-16 because the structure says so.
        layout.name_at = total;
        total += wide_text_bytes(filled_text_bytes(record.name));
        layout.description_at = total;
        total += wide_text_bytes(filled_text_bytes(record.name));
        layout.dns_suffix_at = total;
        total += wide_text_bytes(1);

        layout.wants_unicast = want_unicast;
        static_cast<void>(want_name);
        chosen.push_back(r);
        layouts.push_back(layout);
    }

    if (addresses == nullptr) {
        // The sizing form: the caller asked how much room the answer needs
        // and gets the count, which is how this call is documented to be
        // used.
        *size = static_cast<std::uint32_t>(total);
        return total == 0 ? kErrorNoData : kErrorBufferOverflow;
    }
    if (*size < total) {
        *size = static_cast<std::uint32_t>(total);
        return kErrorBufferOverflow;
    }
    if (layouts.empty()) {
        *size = 0;
        return kErrorNoData;
    }

    // The writing pass. Every block was placed by the measurement pass, so
    // this one has nothing to decide -- only to write.
    auto* base = static_cast<std::uint8_t*>(addresses);
    std::memset(base, 0, total);

    for (std::size_t i = 0; i < layouts.size(); ++i) {
        const InterfaceRecord& record = records[chosen[i]];
        const AdapterLayout& layout = layouts[i];
        std::uint8_t* node = base + layout.adapter_at;

        write_u32(node, kAdapterLength, static_cast<std::uint32_t>(kAdapterBytes));
        write_u32(node, kAdapterIfIndex, record.index);
        if (i + 1 < layouts.size()) {
            // The chain is linked through the addresses of the nodes, which
            // are inside the caller's buffer and therefore known here.
            write_ptr(node, kAdapterNext,
                      reinterpret_cast<std::uint64_t>(base + layouts[i + 1].adapter_at));
        }

        // The adapter's name, which on Windows is a GUID in braces. This
        // runtime has no GUID for an interface, so it writes the interface's
        // own name in the same shape: a caller that treats the string as an
        // opaque identifier -- which is what it is -- is unaffected, and one
        // that parses it gets the name it could have asked for instead.
        auto* name_block = reinterpret_cast<char16_t*>(base + layout.name_at);
        for (std::size_t c = 0; c < record.name.size(); ++c) {
            name_block[c] = static_cast<char16_t>(
                static_cast<unsigned char>(record.name[c]));
        }
        name_block[record.name.size()] = u'\0';
        write_ptr(node, kAdapterName,
                  reinterpret_cast<std::uint64_t>(name_block));

        auto* description = reinterpret_cast<char16_t*>(base + layout.description_at);
        for (std::size_t c = 0; c < record.name.size(); ++c) {
            description[c] = static_cast<char16_t>(
                static_cast<unsigned char>(record.name[c]));
        }
        description[record.name.size()] = u'\0';
        write_ptr(node, kAdapterDescription,
                  reinterpret_cast<std::uint64_t>(description));
        write_ptr(node, kAdapterFriendlyName,
                  reinterpret_cast<std::uint64_t>(description));

        auto* suffix = reinterpret_cast<char16_t*>(base + layout.dns_suffix_at);
        suffix[0] = u'\0';
        write_ptr(node, kAdapterDnsSuffix,
                  reinterpret_cast<std::uint64_t>(suffix));

        if (record.mac_bytes != 0) {
            std::memcpy(node + kAdapterPhysicalAddress, record.mac,
                        record.mac_bytes);
        }
        write_u32(node, kAdapterPhysicalLength,
                  static_cast<std::uint32_t>(record.mac_bytes));
        write_u32(node, kAdapterFlags, 0);
        write_u32(node, kAdapterMtu, record.mtu);
        write_u32(node, kAdapterIfType, interface_type_of(record));
        write_u32(node, kAdapterOperStatus,
                  record.up ? kIfOperStatusUp : kIfOperStatusDown);
        write_u32(node, kAdapterIpv6IfIndex, record.ipv6_index);
        write_u32(node, kAdapterIpv4Metric, 0);
        write_u32(node, kAdapterIpv6Metric, 0);
        write_u32(node, kAdapterConnectionType, 0);
        write_u32(node, kAdapterTunnelType, 0);
        write_u32(node, kAdapterCompartmentId, 1);

        if (!layout.wants_unicast) {
            continue;
        }

        // The unicast addresses, one node per family. The address itself is
        // a second block that the node points at, which is the part of this
        // structure that has to be right: a caller reads through the
        // pointer, and a pointer into the node would have it read the node.
        std::uint8_t* unicast = base + layout.unicast_at;
        write_ptr(node, kAdapterFirstUnicast,
                  reinterpret_cast<std::uint64_t>(unicast));
        write_u32(unicast, kUnicastLength,
                  static_cast<std::uint32_t>(kUnicastBytes));
        write_u32(unicast, kUnicastFlags, 0);
        write_u32(unicast, kUnicastPrefixOrigin, 0);
        write_u32(unicast, kUnicastSuffixOrigin, 0);
        write_u32(unicast, kUnicastDadState, 4);
        write_u32(unicast, kUnicastValidLifetime, 0xFFFFFFFFu);
        write_u32(unicast, kUnicastPreferredLifetime, 0xFFFFFFFFu);
        write_u32(unicast, kUnicastLeaseLifetime, 0xFFFFFFFFu);

        std::size_t next_address_at = layout.address_at;
        if (layout.wants_address) {
            std::uint8_t* block = base + layout.address_at;
            write_u16(block, 0, static_cast<std::uint16_t>(kFamilyInet));
            const auto* in4 =
                reinterpret_cast<const sockaddr_in*>(&record.address);
            write_u16(block, 2, in4->sin_port);
            std::memcpy(block + 4, &in4->sin_addr, 4);
            write_ptr(unicast, kUnicastAddress,
                      reinterpret_cast<std::uint64_t>(block));
            write_u32(unicast, kUnicastAddress + kSocketAddressLength,
                      kSockaddrInBytes);
            write_u8(unicast, kUnicastOnLinkPrefix, 32);
            next_address_at += kSockaddrInBytes;
        }

        if (layout.wants_address6) {
            std::uint8_t* block = base + next_address_at;
            write_u16(block, 0, static_cast<std::uint16_t>(kFamilyInet6));
            const auto* in6 =
                reinterpret_cast<const sockaddr_in6*>(&record.address6);
            write_u16(block, 2, in6->sin6_port);
            write_u32(block, 4, in6->sin6_flowinfo);
            std::memcpy(block + 8, &in6->sin6_addr, 16);
            write_u32(block, 24, in6->sin6_scope_id);

            if (layout.wants_address) {
                // A second node, linked from the first. Its own address
                // block follows the one the first node points at.
                std::uint8_t* second = base + layout.unicast_at + kUnicastBytes;
                write_u32(second, kUnicastLength,
                          static_cast<std::uint32_t>(kUnicastBytes));
                write_u32(second, kUnicastDadState, 4);
                write_u32(second, kUnicastValidLifetime, 0xFFFFFFFFu);
                write_u32(second, kUnicastPreferredLifetime, 0xFFFFFFFFu);
                write_u32(second, kUnicastLeaseLifetime, 0xFFFFFFFFu);
                write_ptr(second, kUnicastAddress,
                          reinterpret_cast<std::uint64_t>(block));
                write_u32(second, kUnicastAddress + kSocketAddressLength,
                          kSockaddrIn6Bytes);
                write_u8(second, kUnicastOnLinkPrefix, 64);
                write_ptr(unicast, kUnicastNext,
                          reinterpret_cast<std::uint64_t>(second));
            } else {
                write_ptr(unicast, kUnicastAddress,
                          reinterpret_cast<std::uint64_t>(block));
                write_u32(unicast, kUnicastAddress + kSocketAddressLength,
                          kSockaddrIn6Bytes);
                write_u8(unicast, kUnicastOnLinkPrefix, 64);
            }
        }

    }

    *size = static_cast<std::uint32_t>(total);
    return kErrorSuccess;
}

extern "C" __attribute__((ms_abi)) std::uint32_t k32ip_GetAdaptersInfo(
    void* info, std::uint32_t* size) noexcept {
    if (size == nullptr) {
        return kErrorInvalidParameter;
    }

    // The interfaces that have an IPv4 address. This report predates the
    // one above and carries only the four-byte family, so an interface
    // whose only address is the sixteen-byte one has nothing to say here
    // and is left out rather than reported with an empty address.
    const std::vector<InterfaceRecord> records = enumerate_interfaces();
    std::vector<std::size_t> chosen;
    for (std::size_t r = 0; r < records.size(); ++r) {
        if (records[r].has_address) {
            chosen.push_back(r);
        }
    }

    const std::size_t total = chosen.size() * kInfoBytes;
    if (info == nullptr || *size < total) {
        *size = static_cast<std::uint32_t>(total);
        return total == 0 ? kErrorNoData : kErrorBufferOverflow;
    }

    auto* base = static_cast<std::uint8_t*>(info);
    std::memset(base, 0, total);

    for (std::size_t i = 0; i < chosen.size(); ++i) {
        const InterfaceRecord& record = records[chosen[i]];
        std::uint8_t* node = base + i * kInfoBytes;

        // The chain is linked by the offset of the next node, which is
        // inside the caller's own buffer and therefore a number rather
        // than a pointer this runtime owns.
        if (i + 1 < chosen.size()) {
            write_ptr(node, kInfoNext,
                      reinterpret_cast<std::uint64_t>(base + (i + 1) * kInfoBytes));
        }

        static_cast<void>(copy_name(record.name,
                                    reinterpret_cast<char*>(node + kInfoAdapterName),
                                    kInfoAdapterNameChars));
        static_cast<void>(copy_name(record.name,
                                    reinterpret_cast<char*>(node + kInfoDescription),
                                    kInfoDescriptionChars));

        write_u32(node, kInfoAddressLength,
                  static_cast<std::uint32_t>(record.mac_bytes));
        if (record.mac_bytes != 0) {
            std::memcpy(node + kInfoAddress, record.mac, record.mac_bytes);
        }
        write_u32(node, kInfoIndex, record.index);
        write_u32(node, kInfoType, interface_type_of(record));
        write_u32(node, kInfoDhcpEnabled, 1);
        write_u32(node, kInfoComboIndex, 0);

        // The address and its mask, as text in the inline fields this
        // structure carries. The current-address pointer is set to the
        // first element of the list, which is what Windows sets it to.
        write_address_text(record.address,
                           node + kInfoIpAddressList + kAddrStringAddress, 16);
        write_mask_text(record.netmask,
                        node + kInfoIpAddressList + kAddrStringMask, 16);
        write_ptr(node, kInfoCurrentIp,
                  reinterpret_cast<std::uint64_t>(node + kInfoIpAddressList));

        write_u32(node, kInfoHaveWins, 0);
        write_u32(node, kInfoLeaseObtained, 0);
        write_u32(node, kInfoLeaseExpires, 0xFFFFFFFFu);
    }

    *size = static_cast<std::uint32_t>(total);
    return kErrorSuccess;
}

// ---------------------------------------------------------------- the rows

extern "C" __attribute__((ms_abi)) std::uint32_t k32ip_GetIfEntry(
    void* row) noexcept {
    if (row == nullptr) {
        return kErrorInvalidParameter;
    }
    const std::uint32_t wanted =
        static_cast<std::uint32_t>(read_u32(row, kIfRowIndex));

    for (const InterfaceRecord& record : enumerate_interfaces()) {
        if (record.index != wanted) {
            continue;
        }
        std::memset(row, 0, kIfRowBytes);
        static_cast<void>(copy_name(record.name,
                                    static_cast<char*>(row) + kIfRowName,
                                    kIfRowNameChars));
        write_u32(row, kIfRowIndex, record.index);
        write_u32(row, kIfRowType, interface_type_of(record));
        write_u32(row, kIfRowMtu, record.mtu);
        write_u32(row, kIfRowSpeed, 1000000000u);
        write_u32(row, kIfRowPhysAddrLen,
                  static_cast<std::uint32_t>(record.mac_bytes));
        if (record.mac_bytes != 0) {
            std::memcpy(static_cast<std::uint8_t*>(row) + kIfRowPhysAddr,
                        record.mac, record.mac_bytes);
        }
        write_u32(row, kIfRowAdminStatus, 1);
        write_u32(row, kIfRowOperStatus,
                  record.up ? kIfOperStatusUp : kIfOperStatusDown);
        return kErrorSuccess;
    }

    return kErrorInvalidParameter;
}

extern "C" __attribute__((ms_abi)) std::uint32_t k32ip_GetIfTable(
    void* table, std::uint32_t* size, std::int32_t order) noexcept {
    static_cast<void>(order);
    if (size == nullptr) {
        return kErrorInvalidParameter;
    }

    const std::vector<InterfaceRecord> records = enumerate_interfaces();
    const std::size_t header = 4;
    const std::size_t total = header + records.size() * kIfRowBytes;

    if (table == nullptr || *size < total) {
        *size = static_cast<std::uint32_t>(total);
        return kErrorInsufficientBuffer;
    }

    auto* base = static_cast<std::uint8_t*>(table);
    std::memset(base, 0, total);
    write_u32(base, 0, static_cast<std::uint32_t>(records.size()));

    for (std::size_t i = 0; i < records.size(); ++i) {
        const InterfaceRecord& record = records[i];
        std::uint8_t* row = base + header + i * kIfRowBytes;
        write_u32(row, kIfRowIndex, record.index);
        static_cast<void>(copy_name(record.name,
                                    reinterpret_cast<char*>(row + kIfRowName),
                                    kIfRowNameChars));
        write_u32(row, kIfRowType, interface_type_of(record));
        write_u32(row, kIfRowMtu, record.mtu);
        write_u32(row, kIfRowSpeed, 1000000000u);
        write_u32(row, kIfRowPhysAddrLen,
                  static_cast<std::uint32_t>(record.mac_bytes));
        if (record.mac_bytes != 0) {
            std::memcpy(row + kIfRowPhysAddr, record.mac, record.mac_bytes);
        }
        write_u32(row, kIfRowAdminStatus, 1);
        write_u32(row, kIfRowOperStatus,
                  record.up ? kIfOperStatusUp : kIfOperStatusDown);
    }

    *size = static_cast<std::uint32_t>(total);
    return kErrorSuccess;
}

// ------------------------------------------------------------ the refusals
//
// The parts of this module that describe or change a configuration this
// runtime does not own. Each is registered so that an import resolves and
// the call reports the code the contract defines for a request the provider
// does not support.

namespace {

[[nodiscard]] std::uint32_t refuse() noexcept {
    set_last_error(kErrorCallNotImplemented);
    return kErrorCallNotImplemented;
}

}  // namespace

// ------------------------------------------------------------- registration

void add_iphlpapi(ExportList& out) {
    const auto e = [&out](const char* name, void* fn) {
        HostExport entry;
        entry.name = name;
        entry.address = reinterpret_cast<std::uint64_t>(fn);
        out.push_back(std::move(entry));
    };

    e("if_nametoindex", reinterpret_cast<void*>(&k32ip_if_nametoindex));
    e("if_indextoname", reinterpret_cast<void*>(&k32ip_if_indextoname));
    e("GetNumberOfInterfaces",
      reinterpret_cast<void*>(&k32ip_GetNumberOfInterfaces));
    e("GetFriendlyIfIndex", reinterpret_cast<void*>(&k32ip_GetFriendlyIfIndex));
    e("GetAdaptersAddresses",
      reinterpret_cast<void*>(&k32ip_GetAdaptersAddresses));
    e("GetAdaptersInfo", reinterpret_cast<void*>(&k32ip_GetAdaptersInfo));
    e("GetIfEntry", reinterpret_cast<void*>(&k32ip_GetIfEntry));
    e("GetIfTable", reinterpret_cast<void*>(&k32ip_GetIfTable));

    // The tables of live connections, the per-interface statistics, the
    // change notifications and the administration surface.
    e("GetIpAddrTable", reinterpret_cast<void*>(&refuse));
    e("GetIpNetTable", reinterpret_cast<void*>(&refuse));
    e("GetTcpTable", reinterpret_cast<void*>(&refuse));
    e("GetTcp6Table", reinterpret_cast<void*>(&refuse));
    e("GetUdpTable", reinterpret_cast<void*>(&refuse));
    e("GetUdp6Table", reinterpret_cast<void*>(&refuse));
    e("GetExtendedTcpTable", reinterpret_cast<void*>(&refuse));
    e("GetExtendedUdpTable", reinterpret_cast<void*>(&refuse));
    e("GetOwnerModuleFromTcpEntry", reinterpret_cast<void*>(&refuse));
    e("GetOwnerModuleFromUdpEntry", reinterpret_cast<void*>(&refuse));
    e("GetPerTcpConnectionEStats", reinterpret_cast<void*>(&refuse));
    e("GetPerTcp6ConnectionEStats", reinterpret_cast<void*>(&refuse));
    e("SetPerTcpConnectionEStats", reinterpret_cast<void*>(&refuse));
    e("SetPerTcp6ConnectionEStats", reinterpret_cast<void*>(&refuse));
    e("GetTcpStatistics", reinterpret_cast<void*>(&refuse));
    e("GetTcpStatisticsEx", reinterpret_cast<void*>(&refuse));
    e("GetIpStatistics", reinterpret_cast<void*>(&refuse));
    e("GetIpStatisticsEx", reinterpret_cast<void*>(&refuse));
    e("GetIcmpStatistics", reinterpret_cast<void*>(&refuse));
    e("GetUdpStatistics", reinterpret_cast<void*>(&refuse));
    e("GetUdpStatisticsEx", reinterpret_cast<void*>(&refuse));
    e("GetIfEntry2", reinterpret_cast<void*>(&refuse));
    e("GetIfTable2", reinterpret_cast<void*>(&refuse));
    e("GetIfTable2Ex", reinterpret_cast<void*>(&refuse));
    e("FreeMibTable", reinterpret_cast<void*>(&refuse));
    e("NotifyAddrChange", reinterpret_cast<void*>(&refuse));
    e("NotifyRouteChange", reinterpret_cast<void*>(&refuse));
    e("NotifyIpInterfaceChange", reinterpret_cast<void*>(&refuse));
    e("CancelMibChangeNotify2", reinterpret_cast<void*>(&refuse));
    e("GetBestInterface", reinterpret_cast<void*>(&refuse));
    e("GetBestInterfaceEx", reinterpret_cast<void*>(&refuse));
    e("GetBestRoute", reinterpret_cast<void*>(&refuse));
    e("GetInterfaceInfo", reinterpret_cast<void*>(&refuse));
    e("GetNetworkParams", reinterpret_cast<void*>(&refuse));
    e("GetFriendlyIfIndexEx", reinterpret_cast<void*>(&refuse));
    e("GetUnicastIpAddressTable", reinterpret_cast<void*>(&refuse));
    e("GetUnicastIpAddressEntry", reinterpret_cast<void*>(&refuse));
    e("CreateUnicastIpAddressEntry", reinterpret_cast<void*>(&refuse));
    e("DeleteUnicastIpAddressEntry", reinterpret_cast<void*>(&refuse));
    e("InitializeUnicastIpAddressEntry", reinterpret_cast<void*>(&refuse));
    e("GetIpForwardTable", reinterpret_cast<void*>(&refuse));
    e("SetIpForwardEntry", reinterpret_cast<void*>(&refuse));
    e("CreateIpForwardEntry", reinterpret_cast<void*>(&refuse));
    e("DeleteIpForwardEntry", reinterpret_cast<void*>(&refuse));
    e("GetAdaptersAddressesEx", reinterpret_cast<void*>(&refuse));
    e("GetAnycastIpAddressTable", reinterpret_cast<void*>(&refuse));
    e("GetMulticastIpAddressTable", reinterpret_cast<void*>(&refuse));
}

}  // namespace occ::runtime::winabi
