// The modules this runtime presents, and the domains each is built from.
//
// `winabi.cpp` holds the machinery and the modules that predate this split;
// this file holds the ones that were added after it, so that a module whose
// whole surface is domains has a home that is only a list. A module named
// here is reachable through the export registry and through `LoadLibrary`
// at once, because both are built from this same table.

#include "occ/runtime/api.h"
#include "occ/runtime/winabi.h"

namespace occ::runtime::winabi {
void add_module_ntdll(ExportModule& module) {
    module.name = "NTDLL.dll";
    add_ntdll_rtl(module.host_exports);
    add_ntdll_rtl_str(module.host_exports);
    add_ntdll_rtl_mem1(module.host_exports);
    add_ntdll_nt(module.host_exports);
}

void add_module_gdi32(ExportModule& module) {
    module.name = "GDI32.dll";
    add_gdi32(module.host_exports);
}

void add_module_advapi32(ExportModule& module) {
    module.name = "ADVAPI32.dll";
    add_advapi32(module.host_exports);
    add_advapi32_reg(module.host_exports);
    add_advapi32_sec(module.host_exports);
}

void add_module_rpcrt4(ExportModule& module) {
    module.name = "RPCRT4.dll";
    add_rpcrt4(module.host_exports);
}

void add_module_setupapi(ExportModule& module) {
    module.name = "SETUPAPI.dll";
    add_setupapi(module.host_exports);
}

void add_module_shell32(ExportModule& module) {
    module.name = "SHELL32.dll";
    add_shell32(module.host_exports);
}

void add_module_crypt32(ExportModule& module) {
    module.name = "CRYPT32.dll";
    add_crypt32(module.host_exports);
}

void add_module_ole32(ExportModule& module) {
    module.name = "OLE32.dll";
    add_ole32(module.host_exports);
}

void add_module_ucrtbase(ExportModule& module) {
    module.name = "UCRTBASE.dll";
    add_crt(module.host_exports, "ucrtbase.dll");
}

void add_module_msvcr70(ExportModule& module) {
    module.name = "MSVCR70.dll";
    add_crt(module.host_exports, "msvcr70.dll");
}

void add_module_msvcr71(ExportModule& module) {
    module.name = "MSVCR71.dll";
    add_crt(module.host_exports, "msvcr71.dll");
}

void add_module_msvcr80(ExportModule& module) {
    module.name = "MSVCR80.dll";
    add_crt(module.host_exports, "msvcr80.dll");
}

void add_module_msvcr90(ExportModule& module) {
    module.name = "MSVCR90.dll";
    add_crt(module.host_exports, "msvcr90.dll");
}

void add_module_msvcr100(ExportModule& module) {
    module.name = "MSVCR100.dll";
    add_crt(module.host_exports, "msvcr100.dll");
}

void add_module_msvcr110(ExportModule& module) {
    module.name = "MSVCR110.dll";
    add_crt(module.host_exports, "msvcr110.dll");
}

void add_module_msvcr120(ExportModule& module) {
    module.name = "MSVCR120.dll";
    add_crt(module.host_exports, "msvcr120.dll");
}

void add_module_msvcr120_app(ExportModule& module) {
    module.name = "MSVCR120_APP.dll";
    add_crt(module.host_exports, "msvcr120_app.dll");
}

void add_module_msvcrtd(ExportModule& module) {
    module.name = "MSVCRTD.dll";
    add_crt(module.host_exports, "msvcrtd.dll");
}

void add_module_msvcrt20(ExportModule& module) {
    module.name = "MSVCRT20.dll";
    add_crt(module.host_exports, "msvcrt20.dll");
}

void add_module_msvcrt40(ExportModule& module) {
    module.name = "MSVCRT40.dll";
    add_crt(module.host_exports, "msvcrt40.dll");
}

void add_module_msvcirt(ExportModule& module) {
    module.name = "MSVCIRT.dll";
    add_crt(module.host_exports, "msvcirt.dll");
}

}  // namespace occ::runtime::winabi
