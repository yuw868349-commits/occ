// The RPCRT4 surface, as the tests see it.
//
// The UUIDs are checked the way the standards allow them to be checked:
// the version and variant bits are where the rules put them, two draws
// differ, a draw survives a trip through its text form, and the nil form
// is recognised. The marshalling primitives are checked by packing a
// conformant array and reading it back with the same runtime's
// unmarshaller -- a round trip that a wrong alignment or a wrong count
// would break.

#include "occ/runtime/api.h"
#include "occ/runtime/exports.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

using namespace occ::runtime;
using namespace occ::runtime::winabi;

namespace {

int failures = 0;
int checks = 0;

void check(bool ok, const char* what) {
    ++checks;
    if (!ok) {
        ++failures;
        std::fprintf(stderr, "FAIL %s\n", what);
    }
}

struct Uuid {
    std::uint32_t data1;
    std::uint16_t data2;
    std::uint16_t data3;
    std::uint8_t data4[8];
};

extern "C" __attribute__((ms_abi)) std::int32_t cr32_UuidCreate(
    Uuid*) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr32_UuidCreateSequential(
    Uuid*) noexcept;
extern "C" __attribute__((ms_abi)) void cr32_UuidCreateNil(Uuid*) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr32_UuidIsNil(
    const Uuid*) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr32_UuidEqual(
    const Uuid*, const Uuid*) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr32_UuidCompare(
    const Uuid*, const Uuid*) noexcept;
extern "C" __attribute__((ms_abi)) std::uint16_t cr32_UuidHash(
    const Uuid*, std::uint16_t*) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr32_UuidToStringA(
    const Uuid*, std::uint8_t**) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr32_UuidFromStringA(
    const std::uint8_t*, Uuid*) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr32_RpcStringFreeA(
    std::uint8_t**) noexcept;
extern "C" __attribute__((ms_abi)) std::uint32_t cr32_NdrConformantArraySize(
    std::uint32_t, std::uint32_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr32_NdrMarshalByteArray(
    std::uint8_t*, std::uint32_t, const std::uint8_t*, std::uint32_t,
    std::uint32_t*) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr32_NdrUnmarshalByteArray(
    const std::uint8_t*, std::uint32_t, std::uint8_t*, std::uint32_t,
    std::uint32_t*) noexcept;
extern "C" __attribute__((ms_abi)) std::uint8_t* cr32_NdrAlignPointer(
    std::uint8_t*, std::size_t) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr32_RpcStringBindingComposeA(
    std::uint8_t*, std::uint8_t*, std::uint8_t*, std::uint8_t*, std::uint8_t*,
    std::uint8_t**) noexcept;
extern "C" __attribute__((ms_abi)) std::int32_t cr32_RpcStringBindingParseA(
    const std::uint8_t*, std::uint8_t**, std::uint8_t**, std::uint8_t**,
    std::uint8_t**, std::uint8_t**) noexcept;

void test_uuid_rules() {
    // The random form: the version nibble is where the standard puts it,
    // and the variant bits are the two most significant of the fourth
    // field's first byte.
    Uuid a = {};
    check(cr32_UuidCreate(&a) == 0, "rpcrt4: the uuid is created");
    check((a.data3 & 0xF000) == 0x4000,
          "rpcrt4: the random form carries version 4");
    check((a.data4[0] & 0xC0) == 0x80,
          "rpcrt4: the variant bits are the standard's");

    // A second draw differs from the first, which is what a generator is
    // for.
    Uuid b = {};
    cr32_UuidCreate(&b);
    check(cr32_UuidEqual(&a, &b) == 0, "rpcrt4: two draws differ");

    // The sequential form: version 1, with its own variant bits.
    Uuid c = {};
    check(cr32_UuidCreateSequential(&c) == 0,
          "rpcrt4: the sequential uuid is created");
    check((c.data3 & 0xF000) == 0x1000,
          "rpcrt4: the sequential form carries version 1");

    // The nil form, and the recognition of it.
    Uuid nil = {};
    cr32_UuidCreateNil(&nil);
    check(cr32_UuidIsNil(&nil) == 1, "rpcrt4: the nil uuid is recognised");
    check(cr32_UuidIsNil(&a) == 0, "rpcrt4: a real uuid is not nil");

    // The comparison and the hash: equal uuids compare equal and hash
    // equally, which is the contract the hash is used under.
    Uuid copy = a;
    check(cr32_UuidCompare(&a, &copy) == 0,
          "rpcrt4: equal uuids compare equal");
    check(cr32_UuidCompare(&a, &b) != 0, "rpcrt4: different uuids differ");
    std::uint16_t status_a = 1;
    std::uint16_t status_b = 1;
    const std::uint16_t hash_a = cr32_UuidHash(&a, &status_a);
    const std::uint16_t hash_copy = cr32_UuidHash(&copy, &status_b);
    check(hash_a == hash_copy, "rpcrt4: equal uuids hash equally");
    check(status_a == 0 && status_b == 0, "rpcrt4: the hash reports success");
}

void test_uuid_text() {
    // The text form, and the parse back to the same uuid.
    const Uuid known{0x12345678, 0x9ABC, 0x4DEF,
                     {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}};
    std::uint8_t* text = nullptr;
    check(cr32_UuidToStringA(&known, &text) == 0,
          "rpcrt4: the uuid renders as text");
    check(text != nullptr, "rpcrt4: the text is handed back");
    if (text != nullptr) {
        check(std::strcmp(reinterpret_cast<const char*>(text),
                          "12345678-9ABC-4DEF-0123-456789ABCDEF") == 0,
              "rpcrt4: the text is the standard's form");
        Uuid parsed = {};
        check(cr32_UuidFromStringA(text, &parsed) == 0,
              "rpcrt4: the text parses back");
        check(cr32_UuidEqual(&known, &parsed) == 1,
              "rpcrt4: the uuid round-trips through text");
        cr32_RpcStringFreeA(&text);
    }

    // The braced spelling parses as well, which is the form the shell
    // and the registry use.
    const char* braced = "{12345678-9ABC-4DEF-0123-456789ABCDEF}";
    Uuid from_braced = {};
    check(cr32_UuidFromStringA(reinterpret_cast<const std::uint8_t*>(braced),
                               &from_braced) == 0,
          "rpcrt4: a braced uuid parses");
    check(cr32_UuidEqual(&known, &from_braced) == 1,
          "rpcrt4: the braces name the same uuid");

    // A malformed string is refused.
    const char* broken = "not-a-uuid";
    Uuid rejected = {};
    check(cr32_UuidFromStringA(reinterpret_cast<const std::uint8_t*>(broken),
                               &rejected) != 0,
          "rpcrt4: a malformed uuid is refused");
}

void test_ndr_primitives() {
    // The conformant array's size: the count word, its padding, then the
    // elements at their own alignment.
    check(cr32_NdrConformantArraySize(10, 1) == 14,
          "rpcrt4: a byte array is its count plus its bytes");
    check(cr32_NdrConformantArraySize(10, 4) == 44,
          "rpcrt4: a word array is aligned at four");

    // The alignment rule: a pointer moves up to its boundary.
    auto* raw = reinterpret_cast<std::uint8_t*>(0x1001);
    check(cr32_NdrAlignPointer(raw, 4) ==
              reinterpret_cast<std::uint8_t*>(0x1004),
          "rpcrt4: the alignment moves up to the boundary");
    check(cr32_NdrAlignPointer(reinterpret_cast<std::uint8_t*>(0x1004), 4) ==
              reinterpret_cast<std::uint8_t*>(0x1004),
          "rpcrt4: an aligned pointer does not move");

    // The marshal and unmarshal round trip: the count is written and read
    // back, and the elements follow it.
    const std::uint8_t payload[5] = {1, 2, 3, 4, 5};
    std::uint8_t buffer[64] = {};
    std::uint32_t written = 0;
    check(cr32_NdrMarshalByteArray(buffer, sizeof(buffer), payload, 5,
                                   &written) == 0,
          "rpcrt4: the array marshals");
    check(written == 9, "rpcrt4: the marshalled size is the count plus bytes");
    std::uint32_t count = 0;
    std::uint8_t back[8] = {};
    check(cr32_NdrUnmarshalByteArray(buffer, written, back, sizeof(back),
                                     &count) == 0,
          "rpcrt4: the array unmarshals");
    check(count == 5, "rpcrt4: the count round-trips");
    check(std::memcmp(back, payload, 5) == 0,
          "rpcrt4: the elements round-trip");

    // A buffer too small for the array is refused rather than overrun.
    std::uint8_t small[4] = {};
    check(cr32_NdrMarshalByteArray(small, sizeof(small), payload, 5,
                                   &written) != 0,
          "rpcrt4: a buffer too small is refused");
}

void test_bindings() {
    // The compose and the parse are inverses.
    std::uint8_t* binding = nullptr;
    check(cr32_RpcStringBindingComposeA(
              nullptr,
              reinterpret_cast<std::uint8_t*>(const_cast<char*>("ncacn_ip_tcp")),
              reinterpret_cast<std::uint8_t*>(const_cast<char*>("127.0.0.1")),
              reinterpret_cast<std::uint8_t*>(const_cast<char*>("135")),
              nullptr, &binding) == 0,
          "rpcrt4: the binding composes");
    check(binding != nullptr, "rpcrt4: the binding string is handed back");
    if (binding != nullptr) {
        const std::string text(reinterpret_cast<const char*>(binding));
        check(text.find("ncacn_ip_tcp") == 0,
              "rpcrt4: the binding carries its protocol");
        check(text.find("127.0.0.1") != std::string::npos,
              "rpcrt4: the binding carries its address");
        check(text.find("[135]") != std::string::npos,
              "rpcrt4: the binding carries its endpoint");

        std::uint8_t* protocol = nullptr;
        std::uint8_t* address = nullptr;
        std::uint8_t* endpoint = nullptr;
        std::uint8_t* options = nullptr;
        std::uint8_t* object = nullptr;
        check(cr32_RpcStringBindingParseA(binding, &object, &protocol,
                                          &address, &endpoint,
                                          &options) == 0,
              "rpcrt4: the binding parses");
        check(protocol != nullptr &&
                  std::strcmp(reinterpret_cast<const char*>(protocol),
                              "ncacn_ip_tcp") == 0,
              "rpcrt4: the parsed protocol is the composed one");
        check(address != nullptr &&
                  std::strcmp(reinterpret_cast<const char*>(address),
                              "127.0.0.1") == 0,
              "rpcrt4: the parsed address is the composed one");
        check(endpoint != nullptr &&
                  std::strcmp(reinterpret_cast<const char*>(endpoint),
                              "135") == 0,
              "rpcrt4: the parsed endpoint is the composed one");
        cr32_RpcStringFreeA(&binding);
        if (protocol != nullptr) cr32_RpcStringFreeA(&protocol);
        if (address != nullptr) cr32_RpcStringFreeA(&address);
        if (endpoint != nullptr) cr32_RpcStringFreeA(&endpoint);
        if (options != nullptr) cr32_RpcStringFreeA(&options);
        if (object != nullptr) cr32_RpcStringFreeA(&object);
    }
}

void test_registry() {
    ExportList list;
    add_rpcrt4(list);
    bool ok = true;
    int count = 0;
    for (const HostExport& e : list) {
        if (e.name.empty() || e.address == 0) {
            ok = false;
        }
        ++count;
    }
    check(ok, "rpcrt4: every entry has a name and an address");
    check(count >= 40, "rpcrt4: the surface registers in full");
}

}  // namespace

int main() {
    test_registry();
    test_uuid_rules();
    test_uuid_text();
    test_ndr_primitives();
    test_bindings();
    std::fprintf(stderr, "%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
