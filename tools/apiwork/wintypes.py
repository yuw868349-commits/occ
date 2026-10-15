"""The Windows types, as the C++ types this runtime's thunks are declared in.

The runtime includes no Windows header. Every type a guest's declaration
mentions therefore has to be spelled here as the type it actually is, and
the spelling has to be right in the one respect a wrong answer is not
recoverable from: the class the call's arguments are passed in.

On the 64-bit Microsoft ABI an argument goes in a general-purpose register
or in an XMM register according to its *type*, not according to how many of
its kind came before it. A `float` is not an integer that happens to be
small; put it in RCX and the callee reads a bit pattern out of XMM1 that was
never written. So the table below is not a cosmetic mapping from `DWORD` to
`std::uint32_t`. It is the statement of which arguments travel in which
register file, and the float-like names -- `FLOAT`, `DOUBLE`, `DATE` and the
OpenGL spellings of the same sizes -- are the ones that matter.

Everything else is a compromise that costs nothing at the call site: an
unknown non-floating type of at most eight bytes is passed in a
general-purpose register whatever it is, so an unknown name maps to a
64-bit integer and the call is still correct. That is deliberately the last
resort rather than the first, and `unresolved()` counts how often it is
taken so that the answer is visible rather than assumed.
"""

import re

# Types that travel in an XMM register. Anything here must not appear in
# the integer table below, and anything in the integer table must not be one
# of these: the two lists together are the register assignment.
FLOAT_TYPES = {
    'float': 'float',
    'FLOAT': 'float',
    'GLfloat': 'float',
    'GLclampf': 'float',
    'GLdouble': 'double',
    'GLclampd': 'double',
    'double': 'double',
    'DOUBLE': 'double',
    # DATE is an OLE Automation date: a double counting days from 1899.
    'DATE': 'double',
    'long double': 'long double',
}

# The scalar and pointer-width types, with the width that decides how much
# of the register the callee will read.
SCALAR_TYPES = {
    # --- the C spellings the headers also use
    'void': 'void',
    'char': 'char',
    'signed char': 'std::int8_t',
    'unsigned char': 'std::uint8_t',
    'short': 'std::int16_t',
    'unsigned short': 'std::uint16_t',
    'int': 'std::int32_t',
    'unsigned int': 'std::uint32_t',
    'long': 'std::int32_t',
    'unsigned long': 'std::uint32_t',
    'long long': 'std::int64_t',
    'unsigned long long': 'std::uint64_t',
    'long long int': 'std::int64_t',
    'unsigned long long int': 'std::uint64_t',
    '__int8': 'std::int8_t',
    '__int16': 'std::int16_t',
    '__int32': 'std::int32_t',
    '__int64': 'std::int64_t',
    'bool': 'std::uint8_t',
    # --- the Windows spellings of the same widths
    'BOOL': 'std::int32_t',
    'WINBOOL': 'std::int32_t',
    'BOOLEAN': 'std::uint8_t',
    'BYTE': 'std::uint8_t',
    'CHAR': 'char',
    'CCHAR': 'char',
    'UCHAR': 'std::uint8_t',
    'WCHAR': 'char16_t',
    'SHORT': 'std::int16_t',
    'USHORT': 'std::uint16_t',
    'WORD': 'std::uint16_t',
    'ATOM': 'std::uint16_t',
    'LANGID': 'std::uint16_t',
    'LCID': 'std::uint32_t',
    'INT': 'std::int32_t',
    'INT8': 'std::int8_t',
    'INT16': 'std::int16_t',
    'INT32': 'std::int32_t',
    'LONG': 'std::int32_t',
    'LONG32': 'std::int32_t',
    'UINT': 'std::uint32_t',
    'UINT8': 'std::uint8_t',
    'UINT16': 'std::uint16_t',
    'UINT32': 'std::uint32_t',
    'DWORD': 'std::uint32_t',
    'DWORD32': 'std::uint32_t',
    'ULONG': 'std::uint32_t',
    'ULONG32': 'std::uint32_t',
    'COLORREF': 'std::uint32_t',
    'HRESULT': 'std::int32_t',
    'NTSTATUS': 'std::int32_t',
    'LSTATUS': 'std::int32_t',
    'SECURITY_INFORMATION': 'std::uint32_t',
    'ACCESS_MASK': 'std::uint32_t',
    'REGSAM': 'std::uint32_t',
    'MASK': 'std::uint32_t',
    'EXCEPTION_DISPOSITION': 'std::int32_t',
    'VARTYPE': 'std::uint16_t',
    'VARIANT_BOOL': 'std::int16_t',
    'GLenum': 'std::uint32_t',
    'GLbitfield': 'std::uint32_t',
    'GLsizei': 'std::int32_t',
    'GLint': 'std::int32_t',
    'GLuint': 'std::uint32_t',
    'GLboolean': 'std::uint8_t',
    'GLbyte': 'std::int8_t',
    'GLubyte': 'std::uint8_t',
    'GLshort': 'std::int16_t',
    'GLushort': 'std::uint16_t',
    'GLvoid': 'void',
    # --- the 64-bit spellings
    'LONGLONG': 'std::int64_t',
    'INT64': 'std::int64_t',
    'LONG64': 'std::int64_t',
    'ULONGLONG': 'std::uint64_t',
    'DWORDLONG': 'std::uint64_t',
    'ULONG64': 'std::uint64_t',
    'UINT64': 'std::uint64_t',
    'DWORD64': 'std::uint64_t',
    'SIZE_T': 'std::uint64_t',
    'ULONG_PTR': 'std::uint64_t',
    'DWORD_PTR': 'std::uint64_t',
    'UINT_PTR': 'std::uint64_t',
    'SSIZE_T': 'std::int64_t',
    'LONG_PTR': 'std::int64_t',
    'INT_PTR': 'std::int64_t',
    'LRESULT': 'std::int64_t',
    'WPARAM': 'std::uint64_t',
    'LPARAM': 'std::int64_t',
    'CY': 'std::int64_t',
    'ULONGLONG_': 'std::uint64_t',
    'FILE_SEGMENT_ELEMENT': 'std::uint64_t',
    'DWORDLONG_': 'std::uint64_t',
    'PALETTEENTRY': 'std::uint32_t',
    'MCIDEVICEID': 'std::uint32_t',
    'HMMIO': 'std::uint64_t',
    'MMRESULT': 'std::uint32_t',
    'TIMECAPS': 'std::uint32_t',
    'DEVINST': 'std::uint32_t',
    'RESOURCEID': 'std::uint32_t',
    'HEVENT': 'std::uint64_t',
    'DISPID': 'std::int32_t',
    'MEMBERID': 'std::int32_t',
    'SE_OBJECT_TYPE': 'std::int32_t',
    'SID_NAME_USE': 'std::int32_t',
    'WELL_KNOWN_SID_TYPE': 'std::int32_t',
    'ACL_INFORMATION_CLASS': 'std::int32_t',
    'SECURITY_IMPERSONATION_LEVEL': 'std::int32_t',
    'TOKEN_INFORMATION_CLASS': 'std::int32_t',
    'TOKEN_TYPE': 'std::int32_t',
    'PROCESSOR_NUMBER': 'std::uint32_t',
    'TRUSTEE_FORM': 'std::int32_t',
    'TRUSTEE_TYPE': 'std::int32_t',
    'MULTIPLE_TRUSTEE_OPERATION': 'std::int32_t',
    'AUDIT_EVENT_TYPE': 'std::int32_t',
    'POLICY_AUDIT_EVENT_TYPE': 'std::int32_t',
    'AUDIT_PARAM_TYPE': 'std::uint32_t',
    'MEDIA_TYPE': 'std::int32_t',
    'STORAGE_PROPERTY_ID': 'std::int32_t',
    'STORAGE_QUERY_TYPE': 'std::int32_t',
    'HDSKSPC': 'std::uint64_t',
    'HSPFILEQ': 'std::uint64_t',
    'HSPSETUPFILE': 'std::uint64_t',
    'HDEVINFO': 'std::uint64_t',
    'HINF': 'std::uint64_t',
    'HRGN': 'std::uint64_t',
    'SOCKET_': 'std::uint64_t',
    'INT64_': 'std::int64_t',
    'PRPC_MESSAGE': 'std::uint64_t',
    'RPC_BINDING_HANDLE_': 'std::uint64_t',
    'GUID_': 'std::uint64_t',
    'size_t': 'std::uint64_t',
    'ptrdiff_t': 'std::int64_t',
    'ssize_t': 'std::int64_t',
    'wint_t': 'std::uint16_t',
    'time_t': 'std::int64_t',
    'off_t': 'std::int64_t',
    # The status words: each is a 32-bit code whose sign says failure, and
    # each is spelled differently by the subsystem that issues it.
    'RPC_STATUS': 'std::int32_t',
    'CONFIGRET': 'std::uint32_t',
    'DNS_STATUS': 'std::int32_t',
    'SECURITY_STATUS': 'std::int32_t',
    'CALID': 'std::uint32_t',
    'CALTYPE': 'std::uint32_t',
    'GROUPID': 'std::uint32_t',
    'WORD_': 'std::uint16_t',
    'HWINSTA': 'std::uint64_t',
    'HDESK': 'std::uint64_t',
    'HCOLORSPACE': 'std::uint64_t',
    'HCRYPTPROV_LEGACY': 'std::uint64_t',
    'NDR_SCONTEXT': 'std::uint64_t',
    'ULONG64_': 'std::uint64_t',
    'ULARGE_INTEGER': 'std::uint64_t',
    'LARGE_INTEGER_': 'std::int64_t',
    'HSPFILELOG': 'std::uint64_t',
    'RES_DES': 'std::uint64_t',
    'LOG_CONF': 'std::uint64_t',
    'IP4_ARRAY': 'std::uint64_t',
    'GENERIC_READ_': 'std::uint32_t',
}

# The pointer spellings. A name here is a pointer of a stated pointee, and
# the pointee is what the implementation reads, so these are spelled out
# rather than left to the fallback.
POINTER_TYPES = {
    'LPSTR': 'char*',
    'PSTR': 'char*',
    'LPCH': 'char*',
    'PCHAR': 'char*',
    'LPCSTR': 'const char*',
    'PCSTR': 'const char*',
    'PCCH': 'const char*',
    'LPWSTR': 'char16_t*',
    'PWSTR': 'char16_t*',
    'PWCHAR': 'char16_t*',
    'LPCWSTR': 'const char16_t*',
    'PCWSTR': 'const char16_t*',
    'PCWCHAR': 'const char16_t*',
    'LPOLESTR': 'char16_t*',
    'LPCOLESTR': 'const char16_t*',
    # A BSTR is a wide string with a length prefix; the prefix sits before
    # the pointer the caller holds, which is why it is the plain wide type
    # here and the length is written by the allocator that makes one.
    'BSTR': 'char16_t*',
    'LPTSTR': 'char*',
    'LPCVTSTR': 'const char*',
    'LPBYTE': 'std::uint8_t*',
    'PBYTE': 'std::uint8_t*',
    'LPWORD': 'std::uint16_t*',
    'PWORD': 'std::uint16_t*',
    'LPDWORD': 'std::uint32_t*',
    'PDWORD': 'std::uint32_t*',
    'PUINT': 'std::uint32_t*',
    'LPUINT': 'std::uint32_t*',
    'PLONG': 'std::int32_t*',
    'LPLONG': 'std::int32_t*',
    'PBOOL': 'std::int32_t*',
    'LPBOOL': 'std::int32_t*',
    'LPINT': 'std::int32_t*',
    'PINT': 'std::int32_t*',
    'PSIZE_T': 'std::uint64_t*',
    'PULONG_PTR': 'std::uint64_t*',
    'PLONGLONG': 'std::int64_t*',
    'PULONGLONG': 'std::uint64_t*',
    'PULONG': 'std::uint32_t*',
    'PUSHORT': 'std::uint16_t*',
    'PLCID': 'std::uint32_t*',
    'PHANDLE': 'void**',
    'PVOID': 'void*',
    'LPVOID': 'void*',
    'PCEVENT': 'std::uint64_t*',
    'PFLT_FILTER': 'void*',
    'PLDAPControlA': 'void*',
    'PLDAPControlW': 'void*',
    'PLDAPControl': 'void*',
    'LDAPControlA': 'void',
    'LDAPControlW': 'void',
    'LDAPControl': 'void',
    'LDAPModA': 'void',
    'LDAPModW': 'void',
    'LDAPMod': 'void',
    'BerElement': 'void',
    'BerValue': 'void',
    'RPC_BINDING_HANDLE': 'void*',
    'RPC_IF_HANDLE': 'void*',
    'RPC_BINDING_VECTOR': 'void',
    'RPC_ERROR_ENUM_HANDLE': 'void',
    'RPC_ASYNC_STATE': 'void',
    'RPC_POLICY': 'void',
    'RPC_CLIENT_ALLOC': 'void*',
    'RPC_CLIENT_FREE': 'void*',
    'MIDL_STUB_DESC': 'void',
    'PMIDL_STUB_DESC': 'void*',
    'RANGE_LIST': 'void',
    'PCVOID': 'const void*',
    'LPCVOID': 'const void*',
    'CLPCVOID': 'const void*',
    'PUMS_CONTEXT': 'void*',
    'SLIST_ENTRY': 'void',
    'PSLIST_ENTRY': 'void*',
    'NET_LUID': 'std::uint64_t',
    'CLIPFORMAT': 'std::uint16_t',
    'MCIERROR': 'std::uint32_t',
    'INTERNET_STATUS_CALLBACK': 'void*',
    'FULL_PTR_XLAT_TABLES': 'void',
    'PFULL_PTR_XLAT_TABLES': 'void*',
    '__LONG32': 'std::int32_t',
    'SHREGENUM_FLAGS': 'std::uint32_t',
    'ASSOCF': 'std::uint32_t',
    'REGDISPOSITION': 'std::uint32_t',
    'HDRVR': 'std::uint64_t',
    'HPAINTBUFFER': 'std::uint64_t',
    'HMIDISTRM': 'std::uint64_t',
    'PLDAPSearch': 'void*',
    'PPNP_VETO_TYPE': 'void*',
    'PNP_VETO_TYPE': 'std::int32_t',
    'SP_ALTPLATFORM_INFO': 'void',
    'PSP_ALTPLATFORM_INFO': 'void*',
    'PSP_INF_INFORMATION': 'void*',
    'SP_INF_INFORMATION': 'void',
    'OOBJECT_TYPE_LIST': 'void',
    'POBJECT_TYPE_LIST': 'void*',
    'OBJECT_TYPE_LIST': 'void',
    'PPRIVILEGE_SET': 'void*',
    'PRIVILEGE_SET': 'void',
    'DEVINSTID_A': 'const char*',
    'DEVINSTID_W': 'const char16_t*',
    'PCERT_PUBLIC_KEY_INFO': 'const void*',
    'CERT_PUBLIC_KEY_INFO': 'void',
    'INTERNET_CACHE_ENTRY_INFOA': 'void',
    'INTERNET_CACHE_ENTRY_INFOW': 'void',
    'LPINTERNET_CACHE_ENTRY_INFOA': 'void*',
    'LPINTERNET_CACHE_ENTRY_INFOW': 'void*',
    'l_timeval': 'void',
    'LPMIDIHDR': 'void*',
    'PSYMBOL_INFO': 'void*',
    'PSYMBOL_INFOW': 'void*',
    'LPNETRESOURCEA': 'void*',
    'LPNETRESOURCEW': 'void*',
    'LPPROGRESS_ROUTINE': 'void*',
    'PSP_FILE_CALLBACK_A': 'void*',
    'PSP_FILE_CALLBACK_W': 'void*',
    'LPMONIKER': 'void*',
    'LPDATAOBJECT': 'void*',
    'VARIANTARG': 'void',
    'LPDESC': 'void*',
    'PDNS_SERVICE_CANCEL': 'void*',
    'NETRESOURCEA': 'void',
    'NETRESOURCEW': 'void',
    'POINT': 'std::uint64_t',
    'SYNCHRONIZATION_BARRIER': 'void',
    'SRWLOCK': 'void',
    'INIT_ONCE': 'void',
    'CRITICAL_SECTION': 'void',
    'CONDITION_VARIABLE': 'void',
    'SLIST_HEADER': 'void',
    'SLIST_ENTRY': 'void',
    'MEMORY_RESOURCE_NOTIFICATION_TYPE': 'std::int32_t',
    'OFFER_PRIORITY': 'std::int32_t',
    'FIRMWARE_TYPE': 'std::int32_t',
    'EXECUTION_STATE': 'std::uint32_t',
    'GEOCLASS': 'std::int32_t',
    'MEMORYSTATUS': 'void',
    'OSVERSIONINFOEXA': 'void',
    'OSVERSIONINFOEXW': 'void',
    'WIN32_MEMORY_RANGE_ENTRY': 'void',
    'DLL_DIRECTORY_COOKIE': 'std::uint64_t',
    'HEAP_SUMMARY': 'void',
    'SECURITY_ATTRIBUTES': 'void',
    'DWORDLONG': 'std::uint64_t',
    'FILETIME': 'std::uint64_t',
    'HDROP': 'std::uint64_t',
    'HPSXA': 'std::uint64_t',
    'FOURCC': 'std::uint32_t',
    'INTERNET_PORT': 'std::uint16_t',
    'ASSOCSTR': 'std::uint32_t',
    'SHREGDEL_FLAGS': 'std::uint32_t',
    'SHREGENUM_FLAGS': 'std::uint32_t',
    'SHREGSET_FLAGS': 'std::uint32_t',
    'DNS_CHARSET': 'std::uint32_t',
    'MCIERROR_': 'std::uint32_t',
    'LPSTR_': 'char*',
    'MICROSOFT_JSON_': 'void',

    'SOCKET': 'std::uint64_t',
    'GEOID': 'std::int32_t',
    'CONTEXT': 'void',
    'PCONTEXT': 'void*',
    'CredHandle': 'void',
    'CtxtHandle': 'void',
    'PCredHandle': 'void*',
    'PCtxtHandle': 'void*',
    'va_list': 'void*',
    'LPACCEL': 'void*',
    'ACCEL': 'void',
    'HPOWERNOTIFY': 'std::uint64_t',
    'DEVNODE': 'std::uint64_t',
    'FN_PROGRESS': 'void*',
    'PROG_INVOKE_SETTING': 'std::uint32_t',
    'MULTI_QI': 'void',
    'LPOLESTREAM': 'void*',
    'LPWAVEHDR': 'void*',
    'WAVEHDR': 'void',
    'PTP_POOL': 'void*',
    'PTP_CALLBACK_INSTANCE': 'void*',
    'PSLIST_HEADER': 'void*',
    'RPC_AUTH_IDENTITY_HANDLE': 'void*',
    'RPC_AUTHZ_HANDLE': 'void*',
    'UUID_VECTOR': 'void',
    'RPC_IF_ID': 'void',
    'SYSKIND': 'std::uint32_t',
    'KNOWNFOLDERID': 'void',
    'STRRET': 'void',
    'NET_IF_COMPARTMENT_ID': 'std::uint32_t',
    'HCRYPTPROV_OR_NCRYPT_KEY_HANDLE': 'std::uint64_t',
    'PLDAPSortKeyA': 'void*',
    'PLDAPSortKeyW': 'void*',
    'PSYM_ENUMERATESYMBOLS_CALLBACK': 'void*',
    'NLS_FUNCTION': 'std::uint32_t',
    'PZZWSTR': 'char16_t*',
    'PZWSTR': 'char16_t*',
    'CONFLICT_LIST': 'std::uint64_t',
    'PSP_CLASSINSTALL_HEADER': 'void*',
    'PSP_DRVINSTALL_PARAMS': 'void*',
    'PAUDIT_POLICY_INFORMATION': 'void*',
    'AUDIT_POLICY_INFORMATION': 'void',
    'ACCESS_MODE': 'std::int32_t',
    'PLSA_REFERENCED_DOMAIN_LIST': 'void*',
    'TRUSTED_INFORMATION_CLASS': 'std::int32_t',
    'NDR_RUNDOWN': 'void*',
    'DWORD64_': 'std::uint64_t',
    'ULONG32_': 'std::uint32_t',
    '__LONG32': 'std::int32_t',
    'PFLT_CONTEXT': 'void*',
    'LSA_UNICODE_STRING': 'void',
    'LDAP_TIMEVAL': 'void',
    'PLDAP_TIMEVAL': 'void*',
    'PLDAP_BERVAL': 'void*',
    'LDAP_BERVAL': 'void',
    'LDAPMessage_': 'void',
    'SF_TYPE': 'std::uint32_t',
    'DVD_STRUCT': 'void',
    'IDiskQuotaUser': 'void*',
    'AM_MEDIA_TYPE': 'void',
    'ISampleGrabberCB_': 'void*',
    'MONITORINFOEXA': 'void',
    'MONITORINFOEXW': 'void',
    'CANDIDATELIST_': 'void',

    'RPC_CSTR': 'char*',
    'RPC_WSTR': 'char16_t*',
    'RPC_CWSTR': 'const char16_t*',
    'PUCHAR': 'std::uint8_t*',
    'PCHAR_': 'char*',
    'PUINT8': 'std::uint8_t*',
    'OLECHAR': 'char16_t',
    'OLECHAR_': 'char16_t',
    'LPWCH': 'char16_t*',
    'LPCWCH': 'const char16_t*',
    'NPSTR': 'char*',
    'NWPSTR': 'char16_t*',
    'PHKEY': 'void**',
    'PHANDLE_': 'void**',
    # The callback types are addresses the guest passed. The runtime never
    # calls one of these from a host thread it invented, so the type is the
    # address and nothing more.
    'WNDPROC': 'void*',
    'FARPROC': 'void*',
    'PROC': 'void*',
    'HOOKPROC': 'void*',
    'DLGPROC': 'void*',
    'TIMERPROC': 'void*',
    'ENHMFENUMPROC': 'void*',
    'LPTHREAD_START_ROUTINE': 'void*',
    'LPOVERLAPPED_COMPLETION_ROUTINE': 'void*',
    'PAPCFUNC': 'void*',
    'WAITORTIMERCALLBACK': 'void*',
    'PTP_WIN32_IO_CALLBACK_': 'void*',
    'APPLICATION_RECOVERY_CALLBACK': 'void*',
    'PFIBER_START_ROUTINE': 'void*',
    'WNDENUMPROC': 'void*',
    'PENUMPROCEXPROC': 'void*',
    'PFNLVCOMPARE': 'void*',
    'SUBLCASS_PROC_POINTERS': 'void*',
}

# The handle names, and the names of structures that only ever appear
# behind a pointer. A handle is a pointer-width value in a general-purpose
# register, so it is a `void*` here; a structure behind a pointer is the
# same thing from the call site's point of view.
HANDLE_NAMES = (
    'HANDLE', 'HWND', 'HMODULE', 'HINSTANCE', 'HKEY', 'HKL', 'HDC', 'HBITMAP',
    'HBRUSH', 'HPEN', 'HFONT', 'HPALETTE', 'HICON', 'HCURSOR', 'HMENU',
    'HACCEL', 'HDWP', 'HHOOK', 'HMONITOR', 'HGDIOBJ', 'HGLOBAL', 'HLOCAL',
    'HRSRC', 'HGLRC', 'HPROPSHEETPAGE', 'HENHMETAFILE', 'HMETAFILE', 'HSTR',
    'HTHEME', 'SC_HANDLE', 'SERVICE_STATUS_HANDLE', 'PSID', 'PACL',
    'PSECURITY_DESCRIPTOR', 'HFILE', 'HINTERNET', 'HMACHINE', 'HIMAGELIST',
    'HIMC', 'HWAVEOUT', 'HWAVEIN', 'HMIDIOUT', 'HMIDIIN', 'HMIXER',
    'HMIXEROBJ', 'HACMDRIVER', 'HACMDRIVERID', 'HACMSTREAM', 'HAVIStream',
    'PAVISTREAM', 'PAVIFILE', 'HIC', 'HDSA', 'HDPA', 'HUSKEY',
    'LSA_HANDLE', 'HCERTSTORE', 'LPSTORAGE', 'LPSTREAM', 'PSP_DEVINFO_DATA',
    'PSP_DEVICE_INTERFACE_DATA', 'PSP_DEVICE_INTERFACE_DETAIL_DATA_A',
    'PSP_DEVICE_INTERFACE_DETAIL_DATA_W', 'PDEVINST', 'LPGUID',
    'PGENERIC_MAPPING', 'PTOKEN_GROUPS', 'PTOKEN_PRIVILEGES', 'PINFCONTEXT',
    'PLDAP', 'PLDAPMessage', 'PCCERT_CONTEXT', 'PCCTL_CONTEXT',
    'PCCRL_CONTEXT', 'LPDECIMAL', 'LPVARIANT', 'LPVOID', 'PVOID',
    'LPSECURITY_ATTRIBUTES', 'LPOVERLAPPED', 'LPRECT', 'LPPOINT',
    'LPFORMATETC', 'LPITEMIDLIST', 'LPCITEMIDLIST', 'LPUNKNOWN',
    'LPOLECLIENTSITE', 'LPSAFEARRAY', 'LPMENUINFO', 'LPCMENUINFO',
    'LPMSG', 'LPARAM_', 'LPDISPATCH', 'LPTRUSTEE_A', 'LPTRUSTEE_W',
    'PTRUSTEE_A', 'PTRUSTEE_W', 'PSEC_WINNT_AUTH_IDENTITY_OPAQUE',
    'PDNS_RECORD', 'BCRYPT_KEY_HANDLE', 'BCRYPT_ALG_HANDLE',
    'BCRYPT_HASH_HANDLE', 'BCRYPT_SECRET_HANDLE', 'HCRYPTPROV',
    'HCRYPTKEY', 'HCRYPTHASH', 'HCRYPTMSG', 'PKCS7_', 'PCERT_',
    'HCERTCHAINENGINE', 'HCRYPTMSG_', 'PLSA_UNICODE_STRING',
    'PIO_APC_ROUTINE', 'PIO_STATUS_BLOCK', 'PAIO_', 'HPALETTE_',
)

# Structures that reach the runtime only through a pointer. Naming them
# here means the pointer is a `void*` rather than the 64-bit integer the
# last-resort rule would answer, which is the same at the call site and
# more honest in the signature.
OPAQUE_NAMES = (
    'IID', 'GUID', 'CLSID', 'FMTID', 'UUID', 'RECT', 'POINT', 'SIZE',
    'SAFEARRAY', 'DECIMAL', 'VARIANT', 'PROPVARIANT', 'in6_addr', 'in_addr',
    'sockaddr', 'sockaddr_in', 'sockaddr_in6', 'berval', 'ldapmodA',
    'ldapmodW', 'LDAPMessage', 'LDAP', 'ldapmsg', 'SID', 'ACL',
    'SECURITY_DESCRIPTOR', 'SECURITY_ATTRIBUTES', 'OVERLAPPED', 'MENUINFO',
    'MENUINFO_', 'RANGE_LIST', 'DEVINSTID_A', 'DEVINSTID_W', 'DEVPROPKEY',
    'DEVPROPCOMPKEY', 'SETUPAPI_DEVPROPERTY', 'SP_DEVINFO_DATA',
    'SP_DEVICE_INTERFACE_DATA', 'SP_DEVICE_INTERFACE_DETAIL_DATA_A',
    'SP_DEVICE_INTERFACE_DETAIL_DATA_W', 'SP_CLASSIMAGELIST_DATA',
    'SP_DRVINFO_DATA_A', 'SP_DRVINFO_DATA_W', 'SP_DRVINFO_DETAIL_DATA_A',
    'SP_DRVINFO_DETAIL_DATA_W', 'SP_DEVINSTALL_PARAMS_A',
    'SP_DEVINSTALL_PARAMS_W', 'SP_ORIGINAL_FILE_INFO_A',
    'SP_ORIGINAL_FILE_INFO_W', 'SP_DETECTDEVICE_PARAMS',
    'CERT_CONTEXT', 'CERT_CHAIN_CONTEXT', 'CERT_CHAIN_PARA', 'CTL_CONTEXT',
    'CRL_CONTEXT', 'CTL_USAGE', 'CRYPT_ALGORITHM_IDENTIFIER',
    'CRYPT_SIGN_MESSAGE_PARA', 'CRYPT_ENCRYPT_MESSAGE_PARA',
    'CRYPT_DECRYPT_MESSAGE_PARA', 'CRYPT_VERIFY_MESSAGE_PARA',
    'CRYPT_DATA_BLOB', 'CMSG_', 'CERT_', 'CRYPT_', 'VOID_', 'WCHAR_',
    'DCB', 'COMMTIMEOUTS', 'COMMCONFIG', 'COMMPROP', 'BY_HANDLE_FILE_INFORMATION',
    'FILE_SEGMENT_ELEMENT_', 'MEMORY_BASIC_INFORMATION', 'MEMORYSTATUSEX',
    'SYSTEM_INFO', 'SYSTEM_INFO_', 'SYSTEMTIME', 'FILETIME', 'LARGE_INTEGER',
    'TIME_ZONE_INFORMATION', 'DYNAMIC_TIME_ZONE_INFORMATION', 'OSVERSIONINFOA',
    'OSVERSIONINFOW', 'PROCESS_INFORMATION', 'STARTUPINFOA', 'STARTUPINFOW',
    'WIN32_FIND_DATAA', 'WIN32_FIND_DATAW', 'THREADENTRY32', 'MODULEENTRY32',
    'HEAPENTRY32', 'PROCESSENTRY32', 'WSADATA', 'hostent', 'servent',
    'protoent', 'addrinfo', 'addrInfoExA', 'addrInfoExW', 'timeval',
    'FD_SET', 'fd_set', 'WSABUF', 'WSAPOLLFD', 'TRANSMIT_FILE_BUFFERS',
    'MIB_', 'IP_ADAPTER_', 'FIXED_INFO', 'IP_ADDR_STRING', 'DNS_',
    'NETBIOS_', 'UUID_', 'RPC_', 'NDR_', 'MIDL_STUB_MESSAGE',
    'FORMAT_STRING', 'RPC_MESSAGE', 'RPC_BINDING_HANDLE', 'RPC_IF_HANDLE',
    'PFORMAT_STRING', 'PMIDL_STUB_MESSAGE', 'TAPE_', 'WIN32_STREAM_ID',
    'BINIT_', 'DORESTORE_', 'PROC_THREAD_ATTRIBUTE_LIST', 'STARTUPINFOEXA',
    'STARTUPINFOEXW', 'UMS_', 'JOBOBJECT_', 'JOB_', 'TOKEN_', 'GENERIC_MAPPING',
    'TRUSTEE_A', 'TRUSTEE_W', 'EXPLICIT_ACCESS_A', 'EXPLICIT_ACCESS_W',
    'ACL_SIZE_INFORMATION', 'ACL_REVISION_INFORMATION', 'SID_IDENTIFIER_AUTHORITY',
    'SECURITY_DESCRIPTOR_RELATIVE', 'SE_OBJECT_TYPE_', 'AUDIT_', 'POLICY_',
    'LSA_', 'LSA_UNICODE_STRING', 'SERVICE_', 'SC_', 'QUERY_SERVICE_',
    'ENUM_SERVICE_', 'EVENTLOGRECORD', 'ENUM_LOG_', 'MENUITEMINFO',
    'WINDOWPLACEMENT', 'WINDOWINFO', 'GUITHREADINFO', 'CURSORINFO', 'ICONINFO',
    'PAINTSTRUCT', 'LOGFONTA', 'LOGFONTW', 'BITMAPINFO', 'BITMAPINFOHEADER',
    'TEXTMETRICA', 'TEXTMETRICW', 'DEVMODEA', 'DEVMODEW', 'PIXELFORMATDESCRIPTOR',
    'RGNDATA', 'XFORM', 'COLORADJUSTMENT', 'EXTLOGFONTA', 'EXTLOGFONTW',
    'ENUMLOGFONTEXA', 'ENUMLOGFONTEXW', 'PANOSE', 'OUTLINETEXTMETRICA',
    'STUBMESSAGE', 'MSG', 'WNDCLASSA', 'WNDCLASSW', 'WNDCLASSEXA', 'WNDCLASSEXW',
    'CREATESTRUCTA', 'CREATESTRUCTW', 'MINMAXINFO', 'NCCALCSIZE_PARAMS',
    'COMPAREITEMSTRUCT', 'DRAWITEMSTRUCT', 'MEASUREITEMSTRUCT', 'DELETEITEMSTRUCT',
    'INPUT', 'KEYBDINPUT', 'MOUSEINPUT', 'HARDWAREINPUT', 'TPMPARAMS',
    'SCROLLINFO', 'TRACKMOUSEEVENT', 'DWM_', 'UPDATELAYEREDWINDOWINFO',
    'NMHDR', 'NMTTDISPINFOA', 'LITEM', 'LVITEM', 'LVCOLUMN', 'TCITEM',
    'TBBUTTON', 'HDITEM', 'TLITEM', 'MCHITTESTINFO', 'SYSTEMTIME_',
    'IMECHARPOSITION', 'COMPOSITIONFORM', 'CANDIDATEFORM', 'CANDIDATELIST',
    'IMC_', 'IMM_', 'GL_', 'AVISTREAMINFOA', 'AVISTREAMINFOW', 'AVIFILEINFOA',
    'AVIFILEINFOW', 'AVICOMPRESSOPTIONS', 'BITMAPINFOHEADER_', 'ICINFO',
    'WAVEFORMATEX', 'WAVEOUTCAPSA', 'WAVEINCAPSA', 'MIDIOUTCAPSA',
    'MIDIINCAPSA', 'TIMECAPS_', 'JOYCAPSA', 'JOYINFOEX', 'JOYINFO',
    'MIXERCAPSA', 'MIXERLINEA', 'MIXERCONTROLA', 'MIXERCONTROLDETAILS',
    'ACM_', 'MMTIME', 'PRINTER_INFO_', 'PRINTER_DEFAULTSA', 'PRINTER_DEFAULTSW',
    'DOC_INFO_1A', 'DOC_INFO_1W', 'JOB_INFO_', 'PORT_INFO_', 'DRIVER_INFO_',
    'MONITOR_INFO_', 'PROVIDER_INFO_', 'FIND_DATA_', 'PRINTPROVIDOR',
    'WTS_', 'WTSINFO', 'SESSION_INFO', 'USER_INFO_', 'LOCALGROUP_',
    'GROUP_USERS_INFO_', 'TIME_OF_DAY_INFO', 'USE_INFO_', 'CONNECTION_INFO_',
    'SHARE_INFO_', 'SERVER_INFO_', 'DISPLAY_', 'STAT_', 'CONFIG_INFO_',
    'FILE_INFO_', 'MESSAGE_INFO_', 'ACCESS_INFO_', 'Wksta', 'WKSTA_',
    'LPUSER_INFO_', 'DHCP_', 'DHCPAPI_', 'IP_ADDR_', 'IP_', 'ICMP_',
    'JOB_INFO', 'MSGBOXPARAMSA', 'MSGBOXPARAMSW', 'OPENFILENAMEA',
    'OPENFILENAMEW', 'CHOOSECOLORA', 'CHOOSECOLORW', 'FINDREPLACEA',
    'FINDREPLACEW', 'CHOOSEFONTA', 'CHOOSEFONTW', 'PRINTDLGA', 'PRINTDLGW',
    'PAGESETUPDLGA', 'PAGESETUPDLGW', 'DRAWITEMSTRUCT_', 'TOOLINFOA',
    'TOOLINFOW', 'INITCOMMONCONTROLSEX', 'NM_', 'PBRANGE', 'UDACCEL',
    'SYSTEM_POWER_STATUS', 'MEMORYSTATUS', 'PROCESSOR_NUMBER_', 'GROUP_AFFINITY',
    'NUMA_', 'PERFORMANCE_INFORMATION', 'PROCESS_MEMORY_COUNTERS',
    'MODULEINFO', 'PSAPI_WORKING_SET_INFORMATION', 'MEMORY_BASIC_INFORMATION64',
    'VS_FIXEDFILEINFO', 'FILE_VERSIONINFO', 'LDR_', 'PEB', 'TEB',
    'UNICODE_STRING', 'ANSI_STRING', 'STRING', 'OBJECT_ATTRIBUTES',
    'IO_STATUS_BLOCK', 'LARGE_STRING', 'CURDIR', 'RTL_USER_PROCESS_PARAMETERS',
    'ACTIVATION_CONTEXT_', 'WINTRUST_', 'CRYPT_PROVIDER_', 'CATALOG_INFO',
    'SPC_', 'SIP_', 'WIN_CERTIFICATE', 'MS_', 'GENERIC_MAPPING_',
    'TOOLTIPTEXT', 'CRYPTPROV_', 'PROPSPEC', 'CA_', 'CLUSTER_', 'CLUS_',
)



QUALIFIERS = ('const', 'CONST', 'volatile', 'restrict', '__restrict', 'struct',
              'enum', 'union', 'register', '_restrict', '__ptr64', '__ptr32',
              'class', 'typename', 'signed_', 'volatile_')

# The calling conventions and storage classes the headers decorate a
# declaration with. They belong to the declaration and not to the type, and
# a signature that kept one of them would be a signature whose return type
# is a macro name.
CONVENTIONS = ('WINAPI', 'WINAPIV', 'APIENTRY', 'CALLBACK', 'PASCAL', 'NTAPI',
               'NTSYSAPI', 'RPC_ENTRY', 'RPC_USER', 'RPC_STUB', 'RPCRTAPI',
               'RPCAPI', 'RPC_VAR_ENTRY', 'STDAPICALLTYPE', 'STDAPI',
               'STDMETHODCALLTYPE', 'STDMETHODIMP', 'DECLSPEC_IMPORT',
               'DECLSPEC_EXPORT', 'DECLSPEC_DEPRECATED', 'EXTERN_C',
               '__cdecl', '__stdcall', '__fastcall', '__RPC_USER',
               '__RPC_FAR', '__RPC_STUB', '__RPC_API', 'WINBASEAPI',
               'WINGDIAPI', 'WINUSERAPI', 'WINADVAPI', 'WINWLDAPAPI',
               'WINSCARDAPI', 'WINOLEAPI', 'WINOLEAUTAPI', 'WINMSID',
               'static', 'inline', '__inline__', '__inline', 'extern',
               '__extension__', '__forceinline', '__CRT_INLINE', '__CRTIMP',
               '_CRTIMP', '__declspec', 'dllimport', 'dllexport', 'noreturn',
               '__MINGW_NOTHROW', '__MINGW_ATTRIB_NORETURN', 'SAL_',
               '_In_', '_Out_', '_Inout_', '_Reserved_')

# Names a header spells in capitals that mean the same as the type beside
# them. `VOID` is a parameter list that takes nothing when it stands alone
# and an alias for `void` when it is a return type.
VOID_NAMES = ('VOID', 'GLvoid_', 'WINVOID')

_KNOWN = None


def _known_bases():
    """Every base name the tables can answer for."""
    global _KNOWN
    if _KNOWN is None:
        _KNOWN = set(FLOAT_TYPES) | set(SCALAR_TYPES) | set(POINTER_TYPES) | \
                 set(HANDLE_NAMES) | set(OPAQUE_NAMES)
    return _KNOWN


def _normalise(text):
    """A type expression, as its base name and its pointer depth.

    The stars are counted and removed rather than kept as tokens, because a
    qualifier may be glued to one -- `*const` is a qualifier on the pointer
    -- and a scan that removed the word `const` alone would leave the star
    attached to nothing. Counting them also keeps `**` a depth of two,
    which a token scan that collapsed adjacent stars would read as one.
    """
    spaced = text.replace('[', ' ').replace(']', ' ')
    # An array bound is a number standing alone; a digit inside a name is
    # not, and cannot be reached by this pattern because a word boundary
    # does not fall inside one.
    spaced = re.sub(r'\b\d+\b', ' ', spaced)
    levels = spaced.count('*')
    spaced = spaced.replace('*', ' ')
    kept = []
    for token in re.split(r'\s+', spaced.strip()):
        if not token:
            continue
        if token in QUALIFIERS or token in CONVENTIONS:
            continue
        if token.startswith('__attribute__') or token.startswith('__declspec'):
            continue
        kept.append(token)
    return ' '.join(kept), levels


def _not_void(mapped, base, fallback='std::uint64_t'):
    """A named type that the tables spell as `void`.

    Several names in the opaque list are structures, and a structure is
    spelled `void` so that a pointer to it is a `void*`. One reached by
    value -- which happens for the few that are small enough to be passed in
    a register -- would be a parameter of type `void`, which is not a
    parameter at all. A 64-bit integer carries it, and keeping the pointer
    spelling for the pointed-to case is what the caller of this wants.
    """
    if base in ('void', 'VOID', 'GLvoid', 'GLvoid_'):
        return 'void'
    return fallback if mapped == 'void' else mapped


def _pointer_of(base, levels, is_const):
    """Builds a pointer type, placing the const on the pointee.

    A base that already spells a pointer -- `LPCSTR` is `const char*` --
    keeps its own const and gains one only from the level above it.
    """
    text = base + '*' * levels
    if is_const and levels and not base.startswith('const '):
        return 'const ' + text
    return text


class TypeMap:
    """The mapping, with the record of what it could not name."""

    def __init__(self):
        self.unknown = {}

    def _derived(self, base):
        """The types a header spells by prefixing a name it already has.

        `PHKEY` is a pointer to an `HKEY`, `LPCVOID` is a const pointer to
        what `PVOID` points at, and the table does not list every one of
        them because the rule that makes them is the rule, and a list of two
        hundred derived names is a list that will be missing one.
        """
        if len(base) < 3:
            return None
        for prefix in ('LPC', 'PC', 'LP', 'P'):
            if not base.startswith(prefix):
                continue
            rest = base[len(prefix):]
            if rest not in _known_bases():
                continue
            if rest in FLOAT_TYPES:
                return FLOAT_TYPES[rest] + '*'
            if rest in SCALAR_TYPES:
                return SCALAR_TYPES[rest] + '*'
            if rest in POINTER_TYPES:
                return POINTER_TYPES[rest] + '*'
            return 'void*'
        return None

    def type_of(self, text):
        """The C++ type for one Windows type name."""
        raw = text.strip()
        if not raw:
            return 'void'

        # A function pointer or a function type: the address, and nothing
        # about the signature is needed to pass it.
        if '(' in raw:
            return 'void*'

        is_const = bool(re.match(r'^\s*(const|CONST)\b', raw))
        base, levels = _normalise(raw)
        base = re.sub(r'\s+', ' ', base).strip()

        if not base:
            return 'void*' if levels else 'void'
        if base in VOID_NAMES:
            base = 'void'

        if levels == 0:
            if base in FLOAT_TYPES:
                return FLOAT_TYPES[base]
            if base in SCALAR_TYPES:
                return _not_void(SCALAR_TYPES[base], base)
            if base in POINTER_TYPES:
                return _not_void(POINTER_TYPES[base], base)
            if base in HANDLE_NAMES:
                return 'void*'
            derived = self._derived(base)
            if derived is not None:
                return derived
            if self._is_interface(base):
                return 'void*'
            return self._fallback(base)

        if base in FLOAT_TYPES:
            return _pointer_of(FLOAT_TYPES[base], levels, is_const)
        if base in SCALAR_TYPES:
            return _pointer_of(SCALAR_TYPES[base], levels, is_const)
        if base in POINTER_TYPES:
            return _pointer_of(POINTER_TYPES[base], levels, is_const)
        if base in OPAQUE_NAMES or base in HANDLE_NAMES:
            return _pointer_of('void', levels, is_const)
        if self._is_interface(base):
            return _pointer_of('void', levels, is_const)
        return self._fallback_pointer(base, levels, is_const)

    @staticmethod
    def _is_interface(base):
        """A COM interface name: `I` and then a word.

        Every one of them is a vtable pointer, and a function that takes one
        has no layout to read -- which is what makes the name pattern safe
        to rely on rather than a list of the several hundred that exist.
        """
        return bool(re.fullmatch(r'I[A-Z][A-Za-z0-9]*', base))

    def _fallback(self, base):
        """A value type this table does not name.

        Windows passes structures of this size by value in a register, or
        not at all; the names that reach here are the enumerations and the
        small handles, and a 64-bit integer carries every one of them
        exactly. What it would not carry is a floating-point type, which is
        why those are all named above rather than left to this.
        """
        self.unknown[base] = self.unknown.get(base, 0) + 1
        return 'std::uint64_t'

    def _fallback_pointer(self, base, levels, is_const):
        """A pointer to something this table does not name."""
        self.unknown[base + '*'] = self.unknown.get(base + '*', 0) + 1
        text = 'void*' + '*' * (levels - 1)
        return ('const ' + text) if is_const else text

    def unresolved(self):
        return sorted(self.unknown.items(), key=lambda kv: -kv[1])


TYPES = TypeMap()


def map_type(text):
    return TYPES.type_of(text)


def split_args(args_text):
    """One parameter per entry, as `(type, name)`.

    The header text has been normalised to `Type a,Type b`, so the split is
    on commas outside any parentheses -- a callback parameter's own
    parameter list contains commas that are not separators.

    An array parameter is the case that has to be handled before the name is
    looked for: in `char buf[260]` the name is not the last identifier, it
    is the one before the bracket, and reading the text the other way round
    leaves the name inside the type. An array parameter is a pointer, so
    that is what it becomes.
    """
    text = args_text.strip()
    if text in ('', 'void', 'VOID'):
        return []
    parts = []
    depth = 0
    current = ''
    for ch in text:
        if ch in '([':
            depth += 1
        elif ch in ')]':
            depth -= 1
        if ch == ',' and depth == 0:
            parts.append(current)
            current = ''
        else:
            current += ch
    if current.strip():
        parts.append(current)

    out = []
    for index, part in enumerate(parts):
        part = part.strip()
        if part == '...':
            out.append(('...', 'variadic'))
            continue
        type_text, name = _split_one(part, index)
        out.append((map_type(type_text), name))
    return out


def _split_one(part, index):
    """The declared type and the declared name of one parameter."""
    # An array parameter: the name sits before the bracket, and the
    # brackets with their bound are not part of the type.
    array = re.match(r'^(.*?)\b([A-Za-z_][A-Za-z0-9_]*)\s*\[[^\]]*\]\s*$', part)
    if array and array.group(1).strip():
        return array.group(1).strip() + ' *', array.group(2)
    # The name is the last identifier, and everything before it is the type.
    match = re.match(r'^(.*?)\b([A-Za-z_][A-Za-z0-9_]*)\s*$', part)
    if match and match.group(1).strip():
        return match.group(1).strip(), match.group(2)
    return part, 'arg%d' % index


def map_return(text):
    """The C++ return type. A float return comes back in XMM0."""
    body = text.strip()
    body = re.sub(r'^(const|CONST)\s+', '', body)
    return map_type(body)
