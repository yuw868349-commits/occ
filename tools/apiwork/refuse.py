"""Why an entry point this runtime does not implement is refused.

A refusal is not a stub and not a placeholder. It is the answer Windows
gives for an entry point whose subsystem is not present in the process --
`ERROR_CALL_NOT_IMPLEMENTED` through `SetLastError` -- and it is written
alongside a line naming the subsystem that would have to exist for the call
to be answered.

The alternative, a function that answers success for work it did not do, is
worse than the refusal in a way worth stating. A guest told that a window
was created holds a handle it will pass to four more calls and free; a guest
told that a call is unavailable takes the branch it already has for that
answer. The first failure surfaces somewhere else entirely, in code that
has no reason to suspect what went wrong, and that is the failure mode this
project treats as the worst one because it cannot be diagnosed from where
it lands.

The reasons are grouped by subsystem rather than by function, because the
grouping is the honest part: it says what would have to be built. Two
hundred window calls are refused for one reason, and writing that reason
two hundred times would not make it two hundred reasons.
"""

import re


def _any(*keys):
    """A predicate: the name contains one of these substrings."""
    return lambda name, dll, keys=keys: any(k in name for k in keys)


def _match(pattern):
    """A predicate: the name matches this pattern."""
    return lambda name, dll, pattern=pattern: re.search(pattern, name) is not None


def _dll_is(*names):
    return lambda name, dll, names=names: dll in names


def _both(predicate, dlls):
    return lambda name, dll: dll in dlls and predicate(name, dll)


# --------------------------------------------------------------- the table
#
# Each entry is (predicate, subsystem, note). The first match wins, so the
# narrower families come first and the module-wide reasons come last.

REASONS = [
    # ---------------------------------------------------- the window manager
    (_both(_any('Window', 'Wnd', 'hwnd', 'Hwnd'), ('user32',)),
     'the window manager',
     'no window is ever created in this process, so there is no window to '
     'name, no message queue to post to and no window procedure to call'),
    (_both(_any('Menu', 'MenuItem'), ('user32',)),
     'the window manager',
     'menus are objects of a window manager, and there is none here'),
    (_both(_any('Dialog', 'Dlg', 'DlgItem', 'MessageBox', 'MsgBox'),
           ('user32', 'comdlg32', 'shlwapi')),
     'the window manager',
     'a dialog is a window with a message loop behind it; there is no '
     'window manager in this runtime and therefore no dialog'),
    (_both(_any('Message', 'Msg', 'PostMessage', 'SendMessage',
                'GetMessage', 'PeekMessage', 'DispatchMessage',
                'TranslateMessage', 'Broadcast'),
           ('user32', 'shlwapi')),
     'the window manager',
     'a message is addressed to a window and delivered through the '
     'window manager\'s queue; neither exists here'),
    (_both(_any('Clipboard', 'Caret', 'ScrollBar', 'ScrollInfo', 'Hook',
                'Cursor', 'Icon', 'Class', 'WinEvent', 'Input', 'Keyboard',
                'Keybd', 'Mouse', 'Touch', 'Raw', 'Cascade', 'Tile',
                'Minimize', 'Maximize', 'ShowWindow', 'SetWindow',
                'GetWindow', 'SetFocus', 'GetFocus', 'SetForeground',
                'GetForeground', 'SystemMetrics', 'SystemParameter',
                'MonitorFrom', 'EnumDisplay', 'DisplayConfig', 'ChangeDisplay',
                'Paint', 'BeginPaint', 'EndPaint', 'Invalidate', 'UpdateWindow',
                'Screen', 'Desktop', 'Foreground'),
           ('user32',)),
     'the window manager',
     'this runtime presents no desktop: there is no window station, no '
     'input queue and no display to describe'),
    (_both(_any('String', 'Char', 'Oem', 'Tabbed') , ('user32',)),
     'the window manager',
     'the call is part of the window manager\'s text handling and has no '
     'meaning without a window or a device context to draw into'),
    (_dll_is('comctl32'),
     'the common controls',
     'the common controls are windows; every one of these calls names a '
     'window handle, and there is no window manager here'),
    (_dll_is('comdlg32'),
     'the common dialogs',
     'the common dialogs are modal windows over a shell namespace; neither '
     'the window manager nor the shell namespace exists here'),
    (_dll_is('uxtheme'),
     'the theming subsystem',
     'a theme describes how a window is drawn; there is no window and no '
     'surface to draw on'),
    (_dll_is('imm32'),
     'the input method editor',
     'an input context belongs to a window and to the input queue of the '
     'window manager, neither of which this runtime has'),

    # ------------------------------------------------------- the graphics
    (_dll_is('opengl32'),
     'the OpenGL client library',
     'an OpenGL context is a driver object attached to a device context, '
     'and both the driver and the device context would have to exist'),
    (_both(_any('DC', 'Bitmap', 'Brush', 'Pen', 'Font', 'Palette', 'Region',
                'Rgn', 'MetaFile', 'DIB', 'PixelFormat', 'Clipping',
                'Path', 'Color', 'Glyph', 'Text'),
           ('gdi32',)),
     'the graphics device layer',
     'there is no device context in this runtime: drawing needs a surface '
     'and a rasterizer, and neither is present -- the rasterizing this '
     'runtime does is the ASCII report its own commands print'),
    (_dll_is('gdi32'),
     'the graphics device layer',
     'the call names a GDI object or a device context; this runtime has '
     'neither, because it has no surface to draw on'),

    # ---------------------------------------------------------- the devices
    (_dll_is('setupapi'),
     'the device installation API',
     'the device tree belongs to the kernel and is presented through the '
     'Plug and Play manager; this runtime has no device tree to walk and '
     'no driver store to install from'),
    (_dll_is('winspool'),
     'the print spooler',
     'printing needs a spooler service, a printer port and a driver, and '
     'the call reaches all three through the spooler\'s named pipe'),
    (_dll_is('msacm32'),
     'the audio compression manager',
     'an audio codec is a driver; there is no audio device in this runtime '
     'for one to attach to'),
    (_dll_is('avifil32'),
     'the video-for-windows layer',
     'the AVIFile layer reads through device streams and installed codecs, '
     'and this runtime has neither'),
    (_both(_any('midi', 'Midi', 'wave', 'Wave', 'mci', 'MCI', 'joy', 'Joy',
                'Mixer', 'mixer', 'Aux', 'aux', 'PlaySound', 'Snd',
                'Sound', 'Audio', 'Driver', 'Device', 'timeSetEvent',
                'TimeSetEvent'),
           ('winmm',)),
     'the multimedia device layer',
     'audio, MIDI and joystick access is device access, and this runtime '
     'has no audio device to open'),
    (_dll_is('winmm'),
     'the multimedia device layer',
     'the call reaches an installed multimedia driver; there are none here'),

    # ------------------------------------------------- the system services
    (_any('Service', 'SCManager', 'Svc', 'QueryService') ,
     'the service control manager',
     'services are processes the kernel starts on behalf of a service '
     'database this runtime does not have'),
    (_any('EventLog', 'EventSource', 'ReportEvent', 'Audit', 'Syslog'),
     'the event log and audit subsystem',
     'the event log is a service\'s file, and auditing is a policy the '
     'kernel applies; this runtime does not stand in as either'),
    (_any('Net', 'WNet', 'LAN', 'Wksta', 'Netbios', 'NetBIOS', 'NetShare',
          'NetUser', 'NetGroup', 'NetServer', 'NetFile', 'NetMessage',
          'NetSession', 'NetStatistics', 'NetConnection', 'NetUse'),
     'the network redirector and the directory service',
     'these calls reach a network provider -- a share, a domain controller '
     'or a directory -- over a protocol this runtime does not carry; the '
     'socket and name-resolution surface is answered instead'),
    (_any('Ldap', 'LDAP', 'Cldap'),
     'the LDAP client',
     'this is a protocol client with its own encoding and its own session '
     'state; the socket surface is answered instead'),
    (_any('Dhcp', 'DHCP'),
     'the DHCP client',
     'the call reaches the DHCP client service through its RPC interface'),
    (_any('Lsa', 'LSA', 'Sspi', 'SSPI', 'Schannel', 'AcquireCredentials',
          'SecBuffer', 'SecPkgInfo', 'InitializeSecurityContext',
          'AcceptSecurityContext', 'QuerySecurityContextToken'),
     'the security packages',
     'an authentication package is loaded into the process by the local '
     'security authority; there is no such authority here'),
    (_any('WTS', 'Wts', 'TerminalServer', 'SessionId', 'RemoteDesktop'),
     'the terminal services API',
     'the sessions this describes are sessions of a station manager that '
     'this runtime does not run under'),
    (_any('WinHttp', 'Internet', 'HttpQuery', 'HttpSend', 'HttpOpen',
          'InternetOpen', 'InternetConnect', 'Ftp'),
     'the WinINet and WinHTTP stacks',
     'these are protocol clients with their own caches, cookie stores and '
     'proxy configuration; the socket surface is answered instead'),
    (_any('WinVerify', 'Wintrust', 'CryptVerify', 'CertVerify', 'Catalog',
          'WTHelper', 'Softpub'),
     'the trust verification provider',
     'verifying a signature needs a trust provider and a certificate store '
     'that the system services maintain'),
    (_any('Cert', 'Crypt', 'Crypto', 'BCrypt', 'Protect', 'Ncrypt',
          'Encrypt', 'Decrypt', 'Hash', 'Ssl', 'Tls'),
     'the cryptography providers',
     'a provider selected by the platform is a kernel and service '
     'arrangement; the primitives this runtime implements are its own and '
     'are reached through their own entry points'),
    (_any('UserEnv', 'Profile', 'GroupPolicy', 'Policy', 'EnvironmentBlock'),
     'the user environment and policy',
     'a user profile and the policy that shapes it are built by the logon '
     'process, which this runtime is not'),
    (_any('Token', 'Sid', 'Acl', 'Sddl', 'SecurityDescriptor', 'AccessCheck',
          'Privilege', 'Impersonate', 'LogonUser', 'BoundaryDescriptor',
          'PrivateNamespace', 'Trustee', 'ExplicitAccess', 'Mandatory',
          'AccessAllowed', 'AccessDenied', 'SecurityInfo', 'SecurityAccess',
          'IsTextUnicode'),
     'the security subsystem',
     'tokens, descriptors and access checks are kernel objects backed by a '
     'security database; this runtime answers the registry and file surface '
     'without a security model behind it'),

    # ------------------------------------------------------- the kernel
    (_any('Transacted', 'Transaction', 'KTM'),
     'the transactional NTFS and kernel transaction manager',
     'a transaction needs the kernel transaction manager to enlist the '
     'file system in it, and there is none here'),
    (_any('ActCtx', 'ActivationContext', 'Sxs', 'Fusion'),
     'the side-by-side activation context',
     'an activation context is built from a manifest and a catalog store by '
     'the loader\'s own subsystem; this runtime resolves modules by name'),
    (_any('Job', 'Ums', 'UMS', 'Threadpool', 'ThreadPool', 'Fiber',
          'WaitForTimer', 'BoundaryDescriptor'),
     'the kernel scheduling objects',
     'a job, a thread-pool and a user-mode scheduler are kernel scheduling '
     'objects with completion ports behind them, and this runtime is a '
     'single-threaded host for the guest it runs'),
    (_any('Tape', 'EraseTape', 'WriteTapemark'),
     'the tape device layer',
     'a tape is a device reached through the device I/O control surface'),
    (_any('Comm', 'DCB', 'Modem', 'Serial'),
     'the serial device layer',
     'a serial port is a device; there is no device node to open, no '
     'buffer to flush and no modem to report on'),
    (_any('Power', 'Firmware', 'Wakeup', 'Hiberboot', 'Apm'),
     'the power management interface',
     'power requests are made to the platform firmware through the kernel, '
     'and this runtime is a process on a host that has its own'),
    (_any('Volume', 'MountPoint', 'Disk', 'Partition', 'FileSystem',
          'Drive', 'DeviceIoControl', 'FsControl', 'DosDevice'),
     'the storage subsystem',
     'volumes, partitions and mount points belong to the storage stack '
     'underneath the file system this runtime answers'),
    (_any('Atom', 'GlobalAddAtom', 'LocalAddAtom'),
     'the atom table',
     'the atom table the call addresses is the window manager\'s, and this '
     'runtime has no window manager to own one'),
    (_any('Atom'), 'the atom table',
     'the atom table is owned by the window manager, which this runtime '
     'does not have'),
    (_any('NLS', 'Locale', 'Calendar', 'GeoId', 'GeoInfo', 'LanguageGroup',
          'LocaleName', 'CodePage', 'IdnTo', 'Normalize', 'Script',
          'DurationFormat', 'TimeFormat', 'DateFormat', 'CurrencyFormat',
          'NumberFormat', 'EnumCalendar', 'EnumDate', 'EnumTime',
          'EnumSystem', 'GetStringType', 'UILanguage', 'SortKey',
          'CompareString', 'LCMapString', 'FoldString'),
     'the national language support data',
     'the locale, calendar and collation tables are data files of a '
     'system installation; this runtime would be inventing them, and a '
     'guest that formats a date through invented tables is told a wrong '
     'answer rather than an unavailable one'),
    (_any('Console', 'Conio', 'CtrlHandler'),
     'the console subsystem',
     'a console is a window manager window with a screen buffer behind it; '
     'this runtime\'s standard streams are the host\'s, which is what the '
     'stream API answers'),
    (_any('Mailslot', 'NamedPipe', 'Pipe'),
     'the inter-process transport',
     'the call names a peer process through a transport this runtime does '
     'not connect: a guest here is the only process in its address space'),
    (_any('Debug', 'DebugActive', 'DebugProcess', 'WaitForDebugEvent',
          'ContinueDebugEvent', 'Sym', 'MiniDump', 'StackWalk'),
     'the debugging interface',
     'a debugger needs the kernel to stop a process and report its events; '
     'this runtime runs its guest in-process and answers the queries that '
     'read its own state'),
    (_any('Nt', 'Zw'),
     'the NT system call surface',
     'this runtime answers the Win32 API directly rather than through a '
     'syscall layer, so the native entry point has no implementation to '
     'reach -- a guest that calls it is asking for the kernel interface '
     'underneath the one it was given'),
    (_any('Rtl', 'Rtlp', 'Rtlx', 'Ndr', 'Ldr', 'Csr', 'Alpc', 'Port'),
     'the loader and runtime library internals',
     'this call is part of the native runtime library, whose state this '
     'runtime keeps in its own structures rather than in the kernel\'s'),

    # -------------------------------------------------- the shell and COM
    (_any('IStream', 'IStorage', 'ISequential', 'IClass', 'IEnum', 'IPersist',
          'IMalloc', 'IBindCtx', 'IMoniker', 'IDataObject', 'IShell',
          'IObject', 'IDispatch', 'IUnknown', 'IDropTarget', 'IQuery',
          'IContext', 'IView'),
     'the COM marshalling and storage layer',
     'this call reaches a COM interface by vtable, and the vtable that '
     'would answer it belongs to an object nobody here created: COM needs '
     'a class registry, an apartment and a marshaller'),
    (_any('Dde', 'DDE'),
     'dynamic data exchange',
     'DDE is a protocol of the window manager\'s message queue'),
    (_any('SHGet', 'SHSet', 'SHCreate', 'SHEnum', 'SHBrowse', 'SHFile',
          'Shell', 'Pidl', 'PIDL', 'ItemIdList', 'KnownFolder',
          'SHChangeNotify', 'Drag', 'Drop'),
     'the shell namespace',
     'the shell namespace is a tree of folders each of which is a COM '
     'object, and there is no shell here for one to belong to'),
    (_any('Assoc', 'IsOS', 'WhichPlatform', 'SHLoadIndirectString',
          'SHFormatDateTime', 'SHMessageBox', 'SHSendMessageBroadcast',
          'SHAutoComplete', 'SHCreateShellPalette', 'SHGetInverseCMAP',
          'QISearch', 'ConnectToConnectionPoint', 'HashData'),
     'the shell\'s own services',
     'the call is answered by the shell -- the file-type database, the '
     'desktop, the display -- and this runtime is not the shell'),

    # --------------------------------------------------------- the modules
    (_dll_is('rpcrt4'),
     'the RPC runtime',
     'an RPC call is marshalled through a stub the MIDL compiler generated '
     'and a format string it emitted; a runtime that answered one without '
     'a transport and a binding would be answering from nowhere'),
    (_dll_is('wldap32'),
     'the LDAP client',
     'this is a protocol client with its own encoding and session state, '
     'reached over a socket this runtime does provide but does not build '
     'an LDAP session on'),
    (_dll_is('netapi32'),
     'the network redirector',
     'these calls reach a share or a domain over a protocol served by '
     'another machine'),
    (_dll_is('dnsapi'),
     'the DNS client',
     'the call reaches a resolver whose configuration is a service\'s '
     'state; this runtime answers the host resolver through WinSock'),
    (_dll_is('iphlpapi'),
     'the interface and routing tables',
     'the call describes the machine\'s own network configuration, which '
     'belongs to the host\'s network stack and not to this process'),
    (_dll_is('dhcpcsvc'),
     'the DHCP client',
     'the call reaches the DHCP service through its RPC interface'),
    (_dll_is('mpr'),
     'the network redirector',
     'the call names a network resource to connect or enumerate, and the '
     'provider that would answer it is not here'),
    (_dll_is('dbghelp'),
     'the symbol handler',
     'symbols come from a symbol store reached over the network or from '
     'debug information this runtime does not parse; a symbol handler '
     'that answered with invented names is worse than one that declines'),
    (_dll_is('wintrust'),
     'the trust provider',
     'verification needs a trust provider and a certificate store that '
     'the system services maintain'),
    (_dll_is('mswsock'),
     'the Winsock service provider extensions',
     'these entry points are the layered-provider interface: they hand a '
     'provider a request structure and the provider answers. The base '
     'socket surface is answered instead'),
]

GENERIC = (
    'a subsystem this runtime does not provide',
    'the entry point belongs to a part of the platform this runtime does '
    'not stand in for; the call refuses rather than pretending, so that a '
    'guest which checks its return values sees a coherent machine')

# The per-module reason, for a name no family above matches. A module whose
# whole subject is absent says so once.
MODULE_REASONS = {
    'avifil32': ('the video-for-windows layer',
                 'the AVIFile layer reads through device streams and '
                 'installed codecs, and this runtime has neither'),
    'comctl32': ('the common controls',
                 'the common controls are windows, and there is no window '
                 'manager here'),
    'dnsapi': ('the DNS client',
               'the call reaches a resolver configured by a service; this '
               'runtime answers the host resolver through WinSock'),
    'imm32': ('the input method editor',
              'an input context belongs to a window and to the window '
              'manager\'s input queue'),
    'msacm32': ('the audio compression manager',
                'a codec is a driver, and there is no audio device here'),
    'mswsock': ('the Winsock service provider extensions',
                'these hand a request structure to a layered provider; '
                'the base socket surface is answered instead'),
    'netapi32': ('the network redirector',
                 'these calls reach a share or a domain over a protocol '
                 'served by another machine'),
    'opengl32': ('the OpenGL client library',
                 'an OpenGL context is a driver object attached to a device '
                 'context, and neither exists here'),
    'rpcrt4': ('the RPC runtime',
               'an RPC call is marshalled through a generated stub and a '
               'format string, over a transport and a binding this runtime '
               'does not establish'),
    'setupapi': ('the device installation API',
                 'the device tree belongs to the kernel; there are no '
                 'devices to enumerate and no driver store to install from'),
    'uxtheme': ('the theming subsystem',
                'a theme describes how a window is drawn, and there is '
                'nothing to draw on'),
    'userenv': ('the user environment and policy',
                'a user profile and the policy shaping it are built by the '
                'logon process'),
    'wintrust': ('the trust provider',
                 'verification needs a trust provider and a certificate '
                 'store maintained by the system services'),
    'winhttp': ('the WinHTTP stack',
                'a protocol client with its own caches and proxy '
                'configuration; the socket surface is answered instead'),
    'wininet': ('the WinINet stack',
                'a protocol client with its own cache and cookie store; '
                'the socket surface is answered instead'),
    'wldap32': ('the LDAP client',
                'a protocol client with its own encoding and session state'),
    'winspool': ('the print spooler',
                 'printing needs a spooler service, a port and a driver'),
    'wtsapi32': ('the terminal services API',
                 'the sessions this describes belong to a station manager '
                 'this runtime does not run under'),
    'gdi32': ('the graphics device layer',
              'the call names a GDI object or a device context, and this '
              'runtime has neither'),
    'user32': ('the window manager',
               'this runtime presents no desktop: there is no window '
               'station, no input queue and no display'),
    'comdlg32': ('the common dialogs',
                 'the common dialogs are modal windows over a shell '
                 'namespace, and neither exists here'),
    'shell32': ('the shell namespace',
                'the shell namespace is a tree of COM folders, and there '
                'is no shell here'),
    'crypt32': ('the cryptography providers',
                'a provider selected by the platform is a kernel and '
                'service arrangement'),
    'secur32': ('the security packages',
                'an authentication package is loaded by the local security '
                'authority, which is not present here'),
    'bcrypt': ('the platform cryptography providers',
               'the algorithm providers are image files loaded by the '
               'system; this runtime implements its own primitives'),
    'dbghelp': ('the symbol handler',
                'symbols come from a symbol store or from debug information '
                'this runtime does not parse'),
    'iphlpapi': ('the interface and routing tables',
                 'this describes the host\'s network stack, not the '
                 'guest\'s'),
    'advapi32': ('a subsystem of the security and service layer',
                 'the call reaches the service database, the audit policy '
                 'or the security database, none of which is here'),
    'kernel32': ('a kernel subsystem this runtime does not provide',
                 'the call reaches a device, a service or a kernel object '
                 'this runtime has no counterpart for'),
    'ntdll': ('the native runtime library',
              'the call is part of the interface underneath the Win32 one, '
              'whose state this runtime keeps in its own structures'),
    'ole32': ('the COM runtime',
              'the call needs an apartment, a class registry or a '
              'marshaller, none of which this runtime establishes'),
    'oleaut32': ('the OLE automation library',
                 'the call belongs to the automation type library support '
                 'this runtime does not carry'),
    'shlwapi': ('the shell\'s own services',
                'the call is answered by the shell or by a COM object of '
                'it, and this runtime is not the shell'),
    'winmm': ('the multimedia device layer',
              'the call reaches an installed multimedia driver, and there '
              'are none here'),
    'ws2_32': ('the Winsock name space providers',
               'the call enumerates the installed name-space providers, '
               'which this runtime does not install'),
}


def reason_for(name, dll):
    """The subsystem and the note for one refused name."""
    for predicate, subsystem, note in REASONS:
        try:
            if predicate(name, dll):
                return subsystem, note
        except Exception:
            continue
    if dll in MODULE_REASONS:
        return MODULE_REASONS[dll]
    return GENERIC
