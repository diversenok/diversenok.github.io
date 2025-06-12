---
layout: post
title: "Improving AFD Socket Visibility for Windows Forensics & Troubleshooting"
date: 2025-05-15 10:00:00 +0200
---

> This is a copy of an article I wrote for [Hunt & Hackett](https://www.huntandhackett.com/blog/improving_afd_socket_visibility)

Windows includes a kernel component called **Ancillary Function Driver** (AFD) that provides a backbone for Microsoft's [Winsock library](https://learn.microsoft.com/en-us/windows/win32/winsock/windows-sockets-start-page-2) and exposes **networking sockets** to user-mode applications. And while Winsock has extensive documentation, the underlying driver API is not so lucky. Our research into this topic culminated in publishing definitions in the [PHNT header collection](https://github.com/winsiderss/systeminformer/tree/master/phnt) describing most of the available I/O control codes and structures for interacting with AFD and developing a feature in [System Informer](https://github.com/winsiderss/systeminformer) that substantially increases **socket handle visibility**. This blog post provides essential background knowledge for understanding Ancillary Function Driver API and describes its forensic and troubleshooting potential.

## Prior Research & Prior Confusion

It wouldn't be fair to say there is no information on the subject. To start with, *Steven Vittitoe* from *Google Project Zero* held a conference talk in 2015 called [Reverse Engineering Windows AFD.sys](https://recon.cx/2015/schedule/events/17.html), in which he explained the driver's role and explored it as an **attack surface**. Notably, the closing [slides](https://recon.cx/2015/slides/recon2015-20-steven-vittitoe-Reverse-Engineering-Windows-AFD-sys.pdf) of that presentation mentioned creating a native socket library on top of AFD as potential future work. We have not gone as far as creating a full-featured library that can replace Winsock, but the definitions we publish can provide a formidable base for doing so in the future.

Another helpful material in understanding AFD's architecture is the [Blackswan technical write-up](https://hello.fieldeffect.com/hubfs/Blackswan/Blackswan_Technical_Write%20Up_Field_Effect.pdf) by *Field Effect*. The paper explains a chain of **vulnerabilities** and, while jumping between several Windows subsystems, shares valuable details about post-Windows XP socket implementation.

Finally, it's also possible to find occasional pieces of API definitions. One well-explored area of AFD is related to socket event polling, with several blog posts ([1](https://2023.notgull.net/device-afd/), [2](https://lenholgate.com/blog/2023/04/adventures-with-afd.html)) and libraries covering the subject ([1](https://github.com/piscisaureus/wepoll), [2](https://github.com/libuv/libuv/blob/bcc799a16ebb171b9be60a9ac69312ef020e7358/src/win/winsock.h)). As for other publicly available types, these are a source of great confusion. So far, most known definitions target **pre-Vista** versions of Windows, be it [ReactOS](https://github.com/reactos/reactos/blob/3b8cfa42c102852913956df6fc8eace5802d842e/sdk/include/reactos/drivers/afd/shared.h) that aims for XP compatibility or portions of headers from even older Windows source code leaks. Windows Vista, however, introduced several **breaking changes** to the interface and its design. Some people picked up on these changes and adjusted the types accordingly (see [this issue in DrMemory](https://github.com/DynamoRIO/drmemory/issues/376), for instance), yet the overall level of adoption for them remains low. Two notable projects that provide working non-polling-related **demos** for modern Windows are [lib-nosa](https://github.com/ViperXSecurity/lib-nosa) by *ViperX Security* and [NTSockets](https://www.x86matthew.com/view_post?id=ntsockets) by *x86matthew*.

## Sockets & I/O Control

To answer the question of what is so different between XP and newer interface versions, we first need to understand how the Ancillary Function Driver makes its functionality accessible to the user-mode callers. The core primitive in this discussion is a **socket**, which is (and always has been) merely a **file** under a dedicated device - `\Device\Afd`. This design makes sockets compatible with [`ReadFile`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile) and [`WriteFile`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile) and otherwise allows them to benefit from integration with the I/O subsystem features like [completion ports](https://learn.microsoft.com/en-us/windows/win32/fileio/i-o-completion-ports). Socket-specific functionality relies on ~70 **I/O control code** (IOCTL) handlers that applications can reach via [`DeviceIoControl`](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-deviceiocontrol). The structure of input and output buffers is request-specific and what defines the primary portion of the exposed interface.

<figure>
  <img alt="Figure: Ancillary Function Driver I/O control code function numbers per OS version." src="/images/AFD-sockets/01-ioctls.png"/>
  <figcaption><i>Figure:</i> Ancillary Function Driver I/O control code function numbers per OS version.</figcaption>
</figure>

The diagram above lists function numbers for socket I/O control requests. If you have ever programmed networking, many names should sound familiar and remind you of the standard socket library functions: [`accept`](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-accept), [`bind`](bind), [`connect`](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-connect), etc. Winsock puts more logic in their user-mode implementation than a single `DeviceIoControl` call, though the mapping remains comparatively direct. As for how the list evolved over two decades, you can see that most AFD IOCTLs already existed in XP. Then, occasional new Windows releases appended entries in the end. Microsoft also **inserted** one entry (52) into the middle between XP and Vista and, as a result, **broke the layout** for the values below. Luckily, this change is old enough not to be a headache for header file maintenance anymore. Microsoft has not made a similar compatibility mistake since. So it's merely an ancient oddity nowadays.

Speaking of oddities, there is one more. IOCTL values almost always follow the same bit layout (see the [`CTL_CODE` macro](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/defining-i-o-control-codes)), which packs the targeted device type, the function number, the required handle access, and the buffering method into a single 32-bit value. Well, not with AFD. While preserving the concept, Ancillary Function Driver uses a **custom macro** that allocates fewer bits per field. It is not a big deal, though; just an annoying deviation from the standard that some might prefer to follow.

<figure>
  <img alt="Figure: AFD IOCTL structure by example." src="/images/AFD-sockets/02-ctl_code.png"/>
  <figcaption><i>Figure:</i> AFD IOCTL structure by example.</figcaption>
</figure>

## Transport Modes

Before we can dive into specific IOCTLs, we must cover one essential concept: **socket transport modes**. On the Native API level, creating a socket object requires calling [`NtCreateFile`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntcreatefile) on `\Device\Afd` with a specially crafted *extended attribute*. This attribute allows the caller to select an address family, protocol, and flags for the new socket, plus explicitly choose the underlying transport device. Transport selection was subject to **substantial changes in Vista** and is the primary source of confusion for those who attempt to apply XP-targeting definitions on later OS versions. Here is an example for creating a TCP socket without specifying a transport device:

```c
HANDLE fileHandle;
UNICODE_STRING deviceName = RTL_CONSTANT_STRING(AFD_DEVICE_NAME);
OBJECT_ATTRIBUTES objAttr = RTL_CONSTANT_OBJECT_ATTRIBUTES(&deviceName, OBJ_CASE_INSENSITIVE);
IO_STATUS_BLOCK ioStatusBlock;
AFD_OPEN_PACKET_FULL_EA extendedAttribute = { 0 };

extendedAttribute.EaValueLength = sizeof(AFD_OPEN_PACKET);
extendedAttribute.EaNameLength = sizeof(AfdOpenPacket) - sizeof(ANSI_NULL);
RtlCopyMemory(extendedAttribute.EaName, AfdOpenPacket, sizeof(AfdOpenPacket));

extendedAttribute.OpenPacket.AddressFamily = AF_INET;
extendedAttribute.OpenPacket.SocketType = SOCK_STREAM;
extendedAttribute.OpenPacket.Protocol = IPPROTO_TCP;

NTSTATUS status = NtCreateFile(
	&fileHandle,
	GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
	&objAttr,
	&ioStatusBlock,
	NULL,
	0,
	FILE_SHARE_READ | FILE_SHARE_WRITE,
	FILE_CREATE,
	FILE_SYNCHRONOUS_IO_NONALERT,
	&extendedAttribute,
	sizeof(extendedAttribute)
    );
```

When the system dispatches a `NtCreateFile` call to AFD, the driver eventually ends up in `Afd!AfdAllocateEndpoint`, which selects one of the three **modes** for the socket:
- **TLI**. This mode is the default and the most common option, applicable when the extended attribute doesn't specify a transport device. Internally, sockets of this type have the `TransportIsTLI` flag set in their kernel `AFD_ENDPOINT` structure. TLI here presumably stands for *Transport Layer Interface*.
- **Hybrid**. If the caller specifies one of the pre-defined transport devices (`\Device\Tcp`, `\Device\Tcp6`, `\Device\Udp`, `\Device\Udp6`, `\Device\RawIp`, `\Device\RawIp6`) and a compatible pair of address family and protocol, the socket becomes hybrid type, as denoted by the `TDITLHybrid` flag.
- **TDI**. This option corresponds to remaining cases that don't satisfy the criteria for the other two modes and, thus, have neither of the two flags set in `AFD_ENDPOINT`. You can find examples of such sockets in Bluetooth Audio Gateway Service (BTAGService), which uses this transport mode over `\Device\BTHMS_RFCOMM` when connecting to wireless headsets. TDI here stands for *Transport Driver Interface*.

So why not consider the transport mode merely a hidden implementation detail? The reason is simple: it **defines** which set of structures and which **format** for addresses AFD IOCTLs will use on a given socket. TDI and hybrid modes use legacy types and `TDI_ADDRESS_INFO`/`TRANSPORT_ADDRESS` for addresses, while TLI sockets replace them with newer `*_TL`-suffixed structures and `SOCKADDR`. Since a fair portion of control codes pass addresses back and forth, this adjustment of defaults introduced breaking **layout changes** and, therefore, confusion among those who write tools that parse these types (like the previously mentioned *DrMemory*).

Luckily, the difference between `TDI_ADDRESS_INFO` and `SOCKADDR` is not that dramatic. `SOCKADDR` is, effectively, already embedded into `TDI_ADDRESS_INFO` (albeit at an odd offset), so converting between the two is a matter of inserting or removing a simple header. Likewise, the incompatibility between `*_TL` and non-TL types comes primarily from the different formats of embedded addresses.

<figure>
  <img alt="Figure: Embedding of SOCKADDR in TDI_ADDRESS_INFO." src="/images/AFD-sockets/03-sockaddr.png"/>
  <figcaption><i>Figure:</i> Embedding of SOCKADDR in TDI_ADDRESS_INFO.</figcaption>
</figure>

These are all the prerequisites. The new [`ntafd.h`](https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntafd.h) header in PHNT includes types for all transport modes and has comments on how to choose them.

## Forensics on Duplicated Sockets

Now, we could entertain potential **offensive security** applications of this knowledge, such as maintaining C2 communication without ever loading Winsock DLLs. However, at *Hunt & Hackett*, we focus on **defensive** cybersecurity, so we'll prioritize exploring the forensic and troubleshooting potential of having the latest Ancillary Function Driver definitions instead.

Looking back at the list of I/O control codes, we highlighted several entries that allow **querying** potentially valuable information. The following sections will discuss the purpose and types associated with these IOCTLs. Furthermore, we want to identify their **reliability** as data sources, i.e., whether an attacker can easily tamper with the result. The plan is to display all details as-is while explicitly marking where they come from so that people concerned with forensic quality can judge which fields to trust based on the documentation presented here. But, of course, all sources are welcome when it comes to debugging and troubleshooting, especially in a research context.

Here is a rough outline of what a system tool needs to do to collect socket details:
1. **Enumerate** handles of all/specific processes on the system.
2. **Find** file handles that belong to `\Device\Afd`.
3. **Duplicate** each handle and **query** information from it.

If we wanted to use **Winsock API**, there would be potential concerns regarding attempts to interact with sockets created by other processes. Winsock [supports socket sharing](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsaduplicatesocketw), but the documented procedure expects the creator to actively participate by filling in and delivering a specific [data structure](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/ns-winsock2-wsaprotocol_infoa) to the target. Merely duplicating the underlying handle is not guaranteed to work, and MSDN [advises against it](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle#remarks). At the same time, we can see that [`WSASocket`](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasocketw) defaults to creating inheritable sockets, which implies support for direct duplication. *Yarden Shafir* and *Alex Ionescu* addressed this conundrum in [one of their blog posts](https://windows-internals.com/faxing-your-way-to-system/):

> That’s not to say those warnings or documentation are wrong. Yes, in certain cases, if you have various Layered Service Providers (LSPs) installed, or use esoteric non TCP/IP sockets that are mostly implemented in user-space, the duplicated socket will be completely unusable. Ultimately, for sockets owned by `Afd.sys`, which is the kernel IFS (Installable File System) implementation of Windows Sockets, the operation works just fine, and the resulting socket is perfectly usable – and has certain perks.

Internally, `mswsock.dll` maintains an in-memory state associated with each socket and relies on it during operation. However, it also has a **fallback path** for recreating this state by querying necessary details from the driver (see `mswsock!SockImportHandle`). This feature makes the duplicate-and-use approach safe, at least in the AFD case. Either way, we plan to **skip the Winsock layer altogether** (as an unnecessary abstraction). All we need is to issue IOCTLs against the copied handle.

## Source One: Shared Context

The **richest** amount of valuable information about a socket is accessible via [`IOCTL_AFD_GET_CONTEXT`](https://ntdoc.m417z.com/ioctl_afd_get_context). Just look at the data structure that corresponds to this control code:

```c
typedef struct _SOCK_SHARED_INFO
{
    SOCKET_STATE State;
    LONG AddressFamily; // AF_*
    LONG SocketType; // SOCK_*
    LONG Protocol; // IPPROTO_*, BTHPROTO_*, HV_PROTOCOL_*, etc.
    LONG LocalAddressLength;
    LONG RemoteAddressLength;
    LINGER LingerInfo;
    ULONG SendTimeout; // in milliseconds
    ULONG ReceiveTimeout; // in milliseconds
    ULONG ReceiveBufferSize;
    ULONG SendBufferSize;
    union
    {
        USHORT Flags;
        struct
        {
            USHORT Listening : 1;
            USHORT Broadcast : 1;
            USHORT Debug : 1;
            USHORT OobInline : 1;
            USHORT ReuseAddresses : 1;
            USHORT ExclusiveAddressUse : 1;
            USHORT NonBlocking : 1;
            USHORT DontUseWildcard : 1;
            USHORT ReceiveShutdown : 1;
            USHORT SendShutdown : 1;
            USHORT ConditionalAccept : 1;
            USHORT IsSANSocket : 1;
            USHORT fIsTLI : 1;
            USHORT Rio : 1;
            USHORT ReceiveBufferSizeSet : 1;
            USHORT SendBufferSizeSet : 1;
        };
    };
    ULONG CreationFlags; // WSA_FLAG_*
    ULONG CatalogEntryId;
    ULONG ServiceFlags1; // XP1_*
    ULONG ProviderFlags; // PFL_*
    GROUP GroupID;
    AFD_GROUP_TYPE GroupType;
    LONG GroupPriority;
    LONG LastError;
    union
    {
        HWND AsyncSelecthWnd;
        ULONGLONG AsyncSelectWnd64;
    };
    ULONG AsyncSelectSerialNumber;
    ULONG AsyncSelectwMsg;
    LONG AsyncSelectlEvent;
    LONG DisabledAsyncSelectEvents;
    GUID ProviderId;
} SOCK_SHARED_INFO, *PSOCK_SHARED_INFO;
```

Most fields are self-explanatory. Out of the interesting things, we have **socket state**, type, address family, **protocol**, timeout values, buffer size settings, and an extensive collection of **bit flags**. One of these flags - `fIsTLI` - indicates the socket transport mode (as covered earlier). There are also portions related to quality-of-service features (group, priority) which are less usable. Finally, several other fields, namely `CatalogEntryId`, `ProviderID`, `ProviderFlags`, and `ServiceFlags1`, describe the socket protocol provider and its features and duplicate the information available via the [`WSCEnumProtocols`](https://learn.microsoft.com/en-us/windows/win32/api/ws2spi/nf-ws2spi-wscenumprotocols) function.

The structure also contains a variable part (appended in the end) that stores the **local** and **remote addresses** associated with the socket, with their sizes denoted in the corresponding fields.

Doesn't it sound wonderful? The unfortunate price for all these juicy details is that maintaining their correctness is Winsock's job. In other words, **everything** in the shared context **comes from the Win32 layer** (user mode), and details are undoubtedly the easiest to spoof. AFD offers a matching [`IOCTL_AFD_SET_CONTEXT`](https://ntdoc.m417z.com/ioctl_afd_set_context) control code that Winsock frequently uses to update the buffer. The driver performs no validation checks against the content; frankly, it's not even aware of `SOCK_SHARED_INFO`'s definition, as it belongs to a different level of abstraction. The moral of the story - you can look at the shared context, but you shouldn't make critical decisions based on what you see if you don't trust the socket's origin.

Aside from accepting `SOCK_SHARED_INFO` on input, `IOCTL_AFD_SET_CONTEXT` has a peculiar output parameter that selects a portion of the shared context for storing the **remote address**. AFD ensures that the input buffer completely encloses the output range. This design doesn't mean the IOCTLs will write anything there, though. AFD stores a copy of the context in kernel memory, and when the remote address becomes available, the driver writes it into the specified region so the next `IOCTL_AFD_GET_CONTEXT` can read it.

## Source Two: Info Classes

The second interesting control code is [`IOCTL_AFD_GET_INFORMATION`](https://ntdoc.m417z.com/ioctl_afd_get_information). Together with its counterpart [`IOCTL_AFD_SET_INFORMATION`](https://ntdoc.m417z.com/ioctl_afd_set_information), it follows a more granular approach in retrieving and adjusting information that should sound familiar to anybody who has experience with Native API. Effectively, it offers an **info-class-based** interface, where the caller selects the type of information from an enumeration and provides an accordingly sized buffer on input or output. Here is the list of known information classes:

```c
#define AFD_INLINE_MODE                1 // s: BOOLEAN
#define AFD_NONBLOCKING_MODE           2 // s: BOOLEAN
#define AFD_MAX_SEND_SIZE              3 // q: ULONG
#define AFD_SENDS_PENDING              4 // q: ULONG
#define AFD_MAX_PATH_SEND_SIZE         5 // q: ULONG
#define AFD_RECEIVE_WINDOW_SIZE        6 // q; s: ULONG
#define AFD_SEND_WINDOW_SIZE           7 // q; s: ULONG
#define AFD_CONNECT_TIME               8 // q: ULONG (in seconds)
#define AFD_CIRCULAR_QUEUEING          9 // s: BOOLEAN
#define AFD_GROUP_ID_AND_TYPE          10 // q: AFD_GROUP_INFO
#define AFD_REPORT_PORT_UNREACHABLE    11 // s: BOOLEAN
#define AFD_REPORT_NETWORK_UNREACHABLE 12 // s: BOOLEAN
#define AFD_DELIVERY_STATUS            14 // q: SIO_DELIVERY_STATUS
#define AFD_CANCEL_TL                  15 // s: void
```

As you can see, only a few entries support querying, plus the properties they return partially overlap with the fields we saw in the shared context. However, this time, the data comes straight from the object's kernel representation and is much more **trustworthy**. One info class that is especially valuable from the forensic perspective is `AFD_CONNECT_TIME`, which returns the **number of seconds** since the socket established a **connection**.

## Source Three: Addresses

Two dedicated control codes provide access to local and remote addresses associated with a socket. These are [`IOCTL_AFD_GET_ADDRESS`](https://ntdoc.m417z.com/ioctl_afd_get_address) and [`IOCTL_AFD_GET_REMOTE_ADDRESS`](https://ntdoc.m417z.com/ioctl_afd_get_remote_address), respectively. What can be simpler than that? Well, here we run into a **pitfall** foreshadowed in the section about transport modes. The output format depends on whether the socket we interrogate is **TLI** or **TDI/hybrid**. Remember, the first one yields a shortened `SOCKADDR` representation, while the other two produce a lengthy legacy `TDI_ADDRESS_INFO`.

Fortunately, the layout of these types is rather distinctive and includes a magic field with the **address family**. Since it only makes sense to interpret addresses of known families (otherwise, we wouldn't know what structure they follow, to begin with), it's possible to write a decently robust detection logic for telling the two structures apart. Our implementation performs careful range checks and accounts for the fact that **TLI** sockets are the most prevalent. It might be possible to trick it into misinterpreting an address of one type as another, but that would require carefully preparing a legacy socket and will still have limited impact (if any at all) due to merely partial control of the structure for most common address families.

> The current implementation recognizes *IPv4*, *IPv6*, *Bluetooth*, and *Hyper-V* socket address families. *Update:* Johnny Shaw, one of the maintainters of System Informer, also recently expanded it with Unix socket support.

There is, however, a more concerning reliability issue with one of these IOCTLs. While local address querying consults with the transport layer (and should always return correct information), the **remote address** comes from a cached value recorded in the **shared context**. As previously discussed, `IOCTL_AFD_SET_CONTEXT` dedicates a portion of the context for storing the address. The same IOCTL **allows overwriting** the entire buffer with arbitrary data, including the part read by `IOCTL_AFD_GET_REMOTE_ADDRESS`. Recording a socket's remote address in a user-controlled region is a questionable design choice from the forensics perspective. Unfortunately, we haven't identified alternatives for retrieving equivalent information via other Ancillary Function Driver APIs.

On a side note, it would be interesting to see **EDR** vendors try monitoring `IOCTL_AFD_SET_CONTEXT` requests to detect tampering with the stored remote address data.

If these were not enough problems, another caveat with remote address querying related to a **bug** in `Afd!AfdGetRemoteAddress`. For sockets in a suitable state but with no recorded remote address (a legitimate case), the IOCTL can **succeed without returning** any data. Yet, it will claim to have written a non-zero number of bytes via [`IO_STATUS_BLOCK`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_io_status_block)'s `Information` field. Internally, the function uses the correct size in `memcpy` but sets the `Information` field to an unrelated value of the overall shared context size. What looks like a copy-paste typo (with the line copied from `Afd!AfdGetContext`) prevents callers from knowing how many bytes the IOCTL has returned or requires to succeed. The bug has no security implications and merely presents an inconvenience. It is possible to **work around** the problem by issuing a zero-sized query to tell if there is no remote address. Maybe if somebody from Microsoft reads this, they can fix it.

## Source Four: Socket Options

Another valuable entry is [`IOCTL_AFD_TRANSPORT_IOCTL`](https://ntdoc.m417z.com/ioctl_afd_transport_ioctl). It is an I/O control code for... (checks the notes) issuing more I/O control codes. Admittedly, it's a funny concept, but I guess it's known as a *networking stack* for a reason. This request is an entry point for interrogating **transport layers** below TLI and hybrid sockets. From the usage perspective, this feature is analogous to info-class-based querying we saw earlier, except, this time, it identifies the action via multiple enumerations. The input structure looks like the following:

```c
typedef enum TL_IO_CONTROL_TYPE
{
    TlEndpointIoControlType,   // not supported
    TlSetSockOptIoControlType, // setsockopt
    TlGetSockOptIoControlType, // getsockopt
    TlSocketIoControlType,     // ioctlsocket
} TL_IO_CONTROL_TYPE, *PTL_IO_CONTROL_TYPE;

typedef struct _AFD_TL_IO_CONTROL_INFO
{
    TL_IO_CONTROL_TYPE Type;
    ULONG Level;
    ULONG IoControlCode;
    BOOLEAN EndpointIoctl;
    _Field_size_bytes_(InputBufferLength) PVOID InputBuffer;
    SIZE_T InputBufferLength;
} AFD_TL_IO_CONTROL_INFO, *PAFD_TL_IO_CONTROL_INFO;
```

The `Type` field selects the operation, the `Level` field identifies the stack layer to interact with, and `IoControlCode` specifies the option within the level. Given the validation enforced by AFD, the following rules apply:
- `EndpointIoctl` boolean must be set to TRUE.
- `TlGetSockOptIoControlType` and `TlSetSockOptIoControlType` operations allow any level except for `0xFFFC` and `0xFFFD`.
- `TlSocketIoControlType` operations must have their level set to `0`.
- `TlEndpointIoControlType` is not supported.

People familiar with the networking API should recognize that the three supported types correspond to calling [`getsockopt`](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-getsockopt), [`setsockopt`](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-setsockopt), and [`ioctlsocket`](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-ioctlsocket). Microsoft offers comprehensive documentation on available get- and set- options per level/protocol (see links for [`SOL_SOCKET`](https://learn.microsoft.com/en-us/windows/win32/winsock/sol-socket-socket-options), [`IPPROTO_IP`](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options), [`IPPROTO_IPV6`](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ipv6-socket-options), [`IPPROTO_TCP`](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-tcp-socket-options) and [`IPPROTO_UDP`](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-udp-socket-options)) plus a list of known [socket control codes](https://learn.microsoft.com/en-us/windows/win32/winsock/winsock-ioctls) for `TlSocketIoControlType` requests. Not all of them work with the driver, though, as Winsock handles some of these operations without leaving user mode.

Nonetheless, the list of available information is rather impressive, although **heavily dependent** on the socket type, **protocol**, and state. Here is a table with options that we identified via a combination of reversing and experimentation as available for querying:

| Level | Option | Type | TCP | UDP | Raw IP | Hyper-V |
| ------|--------|------|:---:|:---:|:-----:|:-------:|
| SOL_SOCKET | SO_REUSEADDR | BOOLEAN | ➕ | ➕ | ➕ | ➖ |
| SOL_SOCKET | SO_KEEPALIVE | BOOLEAN | ➕ | ➖ | ➖ | ➖ |
| SOL_SOCKET | SO_DONTROUTE | BOOLEAN | ➕ | ➕ | ➕ | ➖ |
| SOL_SOCKET | SO_BROADCAST | BOOLEAN | ➖ | ➕ | ➕ | ➖ |
| SOL_SOCKET | SO_OOBINLINE | BOOLEAN | ➕ | ➖ | ➖ | ➖ |
| SOL_SOCKET | SO_RCVBUF | ULONG | ➕ | ➖ | ➖ | ➖ |
| SOL_SOCKET | SO_MAX_MSG_SIZE | ULONG | ➕ | ➕ | ➕ | ➖ |
| SOL_SOCKET | SO_CONDITIONAL_ACCEPT | BOOLEAN | ➕ | ➖ | ➖ | ➖ |
| SOL_SOCKET | SO_PAUSE_ACCEPT | BOOLEAN | ➕ | ➖ | ➖ | ➕ |
| SOL_SOCKET | SO_COMPARTMENT_ID | ULONG | ➕ | ➕ | ➕ | ➕ |
| SOL_SOCKET | SO_RANDOMIZE_PORT | BOOL | ➕ | ➕ | ➖ | ➖ |
| SOL_SOCKET | SO_PORT_SCALABILITY | BOOLEAN | ➕ | ➖ | ➖ | ➖ |
| SOL_SOCKET | SO_REUSE_UNICASTPORT | BOOLEAN | ➕ | ➖ | ➖ | ➖ |
| SOL_SOCKET | SO_EXCLUSIVEADDRUSE | BOOLEAN | ➕ | ➕ | ➕ | ➖ |
| IPPROTO_IP[V6] | IP_OPTIONS, IPV6_HOPOPTS | Variable | ➕ | ➕ | ➕ | ➖ |
| IPPROTO_IP[V6] | IP_HDRINCL, IPV6_HDRINCL | BOOL | ➖ | ➖ | ➕ | ➖ |
| IPPROTO_IP | IP_TOS | BYTE | ➕ | ➕ | ➕ | ➖ |
| IPPROTO_IP[V6] | IP_TTL, IPV6_UNICAST_HOPS | BYTE | ➕ | ➕ | ➕ | ➖ |
| IPPROTO_IP[V6] | IP_MULTICAST_IF, IPV6_MULTICAST_IF | ULONG, IN_ADDR | ➖ | ➕ | ➕ | ➖ |
| IPPROTO_IP[V6] | IP_MULTICAST_TTL, IPV6_MULTICAST_HOPS | BYTE | ➖ | ➕ | ➕ | ➖ |
| IPPROTO_IP[V6] | IP_MULTICAST_LOOP, IPV6_MULTICAST_LOOP | BOOLEAN | ➖ | ➕ | ➕ | ➖ |
| IPPROTO_IP[V6] | IP_DONTFRAGMENT, IPV6_DONTFRAG | BOOLEAN | ➕ | ➕ | ➕ | ➖ |
| IPPROTO_IP[V6] | IP_PKTINFO, IPV6_PKTINFO | BOOL | ➖ | ➕ | ➕ | ➖ |
| IPPROTO_IP[V6] | IP_HOPLIMIT, IP_RECVTTL, IPV6_HOPLIMIT | BOOL | ➖ | ➕ | ➕ | ➖ |
| IPPROTO_IP | IP_RECEIVE_BROADCAST | BOOL | ➖ | ➕ | ➕ | ➖ |
| IPPROTO_IPV6 | IPV6_PROTECTION_LEVEL | ULONG | ➕ | ➕ | ➕ | ➖ |
| IPPROTO_IP[V6] | IP_RECVIF, IPV6_RECVIF | BOOL | ➖ | ➕ | ➕ | ➖ |
| IPPROTO_IP[V6] | IP_RECVDSTADDR, IPV6_RECVDSTADDR | BOOL | ➖ | ➕ | ➕ | ➖ |
| IPPROTO_IPV6 | IPV6_V6ONLY | BOOL | ➕ | ➕ | ➕ | ➖ |
| IPPROTO_IP[V6] | IP_IFLIST, IPV6_IFLIST | BOOL | ➕ | ➕ | ➕ | ➖ |
| IPPROTO_IP[V6] | IP_UNICAST_IF, IPV6_UNICAST_IF | ULONG, IN_ADDR | ➕ | ➕ | ➕ | ➖ |
| IPPROTO_IP[V6] | IP_RTHDR, IPV6_RTHDR | Variable | ➕ | ➕ | ➕ | ➖ |
| IPPROTO_IP[V6] | IP_GET_IFLIST, IPV6_GET_IFLIST | ULONG[] | ➕ | ➕ | ➕ | ➖ |
| IPPROTO_IP[V6] | IP_RECVRTHDR, IPV6_RECVRTHDR | BOOL | ➖ | ➕ | ➕ | ➖ |
| IPPROTO_IP[V6] | IP_RECVTCLASS, IP_RECVTOS, IPV6_RECVTCLASS | BOOL | ➖ | ➕ | ➕ | ➖ |
| IPPROTO_IP | IP_ORIGINAL_ARRIVAL_IF | BOOL | ➖ | ➕ | ➕ | ➖ |
| IPPROTO_IP[V6] | IP_ECN, IP_RECVECN, IPV6_ECN, IPV6_RECVECN | BOOL | ➖ | ➕ | ➕ | ➖ |
| IPPROTO_IP[V6] | IP_PKTINFO_EX, IPV6_PKTINFO_EX | BOOL | ➖ | ➕ | ➕ | ➖ |
| IPPROTO_IP[V6] | IP_WFP_REDIRECT_RECORDS, IPV6_WFP_REDIRECT_RECORDS | BOOL | ➖ | ➕ | ➕ | ➖ |
| IPPROTO_IP[V6] | IP_WFP_REDIRECT_CONTEXT, IPV6_WFP_REDIRECT_CONTEXT | BOOL | ➖ | ➕ | ➕ | ➖ |
| IPPROTO_IP[V6] | IP_MTU_DISCOVER, IPV6_MTU_DISCOVER | ULONG | ➕ | ➕ | ➕ | ➖ |
| IPPROTO_IPV6 | IPV6_MTU | ULONG | ➕ | ➖ | ➖ | ➖ |
| IPPROTO_IP | IP_MTU | ULONG | ➕ | ➖ | ➖ | ➖ |
| IPPROTO_IP[V6] | IP_RECVERR, IPV6_RECVERR | BOOL | ➖ | ➕ | ➖ | ➖ |
| IPPROTO_IP[V6] | IP_USER_MTU, IPV6_USER_MTU | ULONG | ➕ | ➕ | ➕ | ➖ |
| IPPROTO_TCP | TCP_NODELAY | BOOLEAN | ➕ | ➖ | ➖ | ➖ |
| IPPROTO_TCP | TCP_EXPEDITED_1122 | BOOLEAN | ➕ | ➖ | ➖ | ➖ |
| IPPROTO_TCP | TCP_KEEPALIVE | ULONG | ➕ | ➖ | ➖ | ➖ |
| IPPROTO_TCP | TCP_MAXSEG | ULONG | ➕ | ➖ | ➖ | ➖ |
| IPPROTO_TCP | TCP_MAXRT | ULONG | ➕ | ➖ | ➖ | ➖ |
| IPPROTO_TCP | TCP_STDURG | BOOLEAN | ➕ | ➖ | ➖ | ➖ |
| IPPROTO_TCP | TCP_NOURG | BOOLEAN | ➕ | ➖ | ➖ | ➖ |
| IPPROTO_TCP | TCP_ATMARK | BOOLEAN | ➕ | ➖ | ➖ | ➖ |
| IPPROTO_TCP | TCP_NOSYNRETRIES | BOOLEAN | ➕ | ➖ | ➖ | ➖ |
| IPPROTO_TCP | TCP_TIMESTAMPS | BOOLEAN | ➕ | ➖ | ➖ | ➖ |
| IPPROTO_TCP | TCP_CONGESTION_ALGORITHM | ULONG | ➕ | ➖ | ➖ | ➖ |
| IPPROTO_TCP | TCP_DELAY_FIN_ACK | BOOLEAN | ➕ | ➖ | ➖ | ➖ |
| IPPROTO_TCP | TCP_MAXRTMS | ULONG | ➕ | ➖ | ➖ | ➖ |
| IPPROTO_TCP | TCP_FASTOPEN | BOOLEAN | ➕ | ➖ | ➖ | ➖ |
| IPPROTO_TCP | TCP_KEEPCNT | ULONG | ➕ | ➖ | ➖ | ➖ |
| IPPROTO_TCP | TCP_KEEPINTVL | ULONG | ➕ | ➖ | ➖ | ➖ |
| IPPROTO_TCP | TCP_FAIL_CONNECT_ON_ICMP_ERROR | BOOLEAN | ➕ | ➖ | ➖ | ➖ |
| IPPROTO_TCP | TCP_ICMP_ERROR_INFO | ICMP_ERROR_INFO | ➕ | ➖ | ➖ | ➖ |
| N/A | SIO_TCP_INFO | TCP_INFO_v* | ➕ | ➖ | ➖ | ➖ |
| IPPROTO_UDP | UDP_NOCHECKSUM | BOOLEAN | ➖ | ➕ | ➖ | ➖ |
| IPPROTO_UDP | UDP_SEND_MSG_SIZE | ULONG | ➖ | ➕ | ➖ | ➖ |
| IPPROTO_UDP | UDP_RECV_MAX_COALESCED_SIZE | ULONG | ➖ | ➕ | ➖ | ➖ |
| HV_PROTOCOL_RAW | HVSOCKET_CONNECT_TIMEOUT | ULONG | ➖ | ➖ | ➖ | ➕ |
| HV_PROTOCOL_RAW | HVSOCKET_CONTAINER_PASSTHRU | BOOL | ➖ | ➖ | ➖ | ➕ |
| HV_PROTOCOL_RAW | HVSOCKET_CONNECTED_SUSPEND | BOOL | ➖ | ➖ | ➖ | ➕ |
| HV_PROTOCOL_RAW | HVSOCKET_HIGH_VTL | BOOL | ➖ | ➖ | ➖ | ➕ |

The table also includes [`SIO_TCP_INFO`](https://learn.microsoft.com/en-us/windows/win32/winsock/sio-tcp-info), which is technically not an option but a socket control code. It fills in a [decently-sized structure](https://learn.microsoft.com/en-us/windows/win32/api/mstcpip/ns-mstcpip-tcp_info_v1) - a treasure bag of valuable TCP-related properties, so we put it into the same category.

Instead of trying to choose the most interesting entries, we decided to go ahead and display virtually all of them in a **dedicated tab** in the handle properties dialog in System Informer. Somebody will undoubtedly find them helpful.

<figure class="shadow">
  <img alt="Figure: Socket options displayed in System Informer." src="/images/AFD-sockets/04-options.png"/>
</figure>

While implementing support for this feature, we discovered an annoying **bug** in the Hyper-V socket driver. As you can see from the table, we marked Hyper-V sockets as supporting six options: two on the `SOL_SOCKET` level and four on the `HV_PROTOCOL_RAW` level. However, it only applies to bound sockets. Open sockets don't support any options, which is sad but perhaps fair. And finally, there are connected sockets that break everything. For whatever reason, instead of failing unsupported requests, `HvSocket!VmbusTlConnectionIoControlEndpoint` **returns `STATUS_SUCCES` for every combination** of level-option-output size for both get- and set- operations. As a workaround, we added an extra check that attempts to retrieve a deliberately invalid option. If the operation succeeds (when it clearly shouldn't), we assume we hit the bug and stop interrogating the given Hyper-V socket to prevent displaying bogus information.

As for reliability outside of this unfortunate accident, we can report that AFD forwards requests to the appropriate transport driver (most frequently, `tcpip.sys`), which reads options from the corresponding kernel-mode structures and validates modification requests before applying them. In other words, what we see via this IOCTL should reflect the current state.

## Source Five: TDI Handles

Another peculiar control code called [`IOCTL_AFD_QUERY_HANDLES`](https://ntdoc.m417z.com/ioctl_afd_query_handles) allows us to request handles to the underlying **TDI devices** for a socket. The input identifies which handles we want to open (address device, connection device, or both), and each output handle receives one of the three values:
- **`INVALID_HANDLE_VALUE`**, meaning the operation **does not apply** to the specified socket due to its **transport mode** (TLI or hybrid).
- **`NULL`**, when the socket has the correct mode of transport (TDI) but **no associated** address/connection **device** yet.
- A **valid file handle** that the caller becomes responsible for closing. We could use it to interact with the corresponding device, for example, by issuing [TDI IOCTLs](https://learn.microsoft.com/en-us/previous-versions/windows/hardware/network/ff565106%28v=vs.85%29) to it. We haven't explored this functionality much due to TDI's legacy nature, and instead, we limited ourselves to merely displaying the **device name** for informational purposes.

Interestingly, the `tdiinfo.h` header from the SDK includes definitions for what looks like a **TDI counterpart** for AFD's transport-interrogating control code from the previous section (which only operates on TLI and hybrid sockets). The TDI version is called `IOCTL_TDI_TL_IO_CONTROL_ENDPOINT` and has the underlying types almost identical to its TLI doppelganger. We suspect it might be possible to issue this IOCTL against the queried TDI handles, but we had no luck making it work.

## Conclusion

<figure class="shadow">
  <img alt="Figure: The handle search dialog in System Informer displaying details about AFD sockets." src="/images/AFD-sockets/05-preview.png"/>
  <figcaption><i>Figure:</i> The handle search dialog in System Informer displaying details about AFD sockets.</figcaption>
</figure>

Windows supports various means of collecting information about networking activity and connections on the system. However, what we demonstrated in this blog post provides a **fresh perspective** on the subject, as it allows detailed introspection of the state on a **per-socket basis**. What once was a collection of identical-looking `\Device\Afd` handles now brings valuable insight into the activity of a process. **Ancillary Function Driver**'s API is lightweight yet powerful, and now its definitions [reside in PHNT](https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntafd.h) and power the corresponding features in the [Canary builds](https://systeminformer.sourceforge.io/canary) of [System Informer](https://github.com/winsiderss/systeminformer). And if you need command-line support, our [AfdSocketViewer](https://github.com/huntandhackett/AfdSocketViewer) tool is available on GitHub.
