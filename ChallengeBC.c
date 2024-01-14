typedef unsigned char   undefined;

typedef unsigned long long    GUID;
typedef pointer32 ImageBaseOffset32;

typedef unsigned char    bool;
typedef unsigned char    byte;
typedef unsigned int    dword;
float10
typedef long long    longlong;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned long long    ulonglong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned long long    undefined6;
typedef unsigned long long    undefined8;
typedef unsigned short    ushort;
typedef unsigned short    wchar16;
typedef short    wchar_t;
typedef unsigned short    word;
typedef struct _s_HandlerType _s_HandlerType, *P_s_HandlerType;

typedef struct _s_HandlerType HandlerType;

typedef struct TypeDescriptor TypeDescriptor, *PTypeDescriptor;

typedef int ptrdiff_t;

struct TypeDescriptor {
    void *pVFTable;
    void *spare;
    char name[0];
};

struct _s_HandlerType {
    uint adjectives;
    struct TypeDescriptor *pType;
    ptrdiff_t dispCatchObj;
    void *addressOfHandler;
};

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion;

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct {
    dword OffsetToDirectory;
    dword DataIsDirectory;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion {
    dword OffsetToData;
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;
};

typedef struct _s_TryBlockMapEntry _s_TryBlockMapEntry, *P_s_TryBlockMapEntry;

typedef int __ehstate_t;

struct _s_TryBlockMapEntry {
    __ehstate_t tryLow;
    __ehstate_t tryHigh;
    __ehstate_t catchHigh;
    int nCatches;
    HandlerType *pHandlerArray;
};

typedef struct _s__RTTIClassHierarchyDescriptor _s__RTTIClassHierarchyDescriptor, *P_s__RTTIClassHierarchyDescriptor;

typedef struct _s__RTTIBaseClassDescriptor _s__RTTIBaseClassDescriptor, *P_s__RTTIBaseClassDescriptor;

typedef struct _s__RTTIBaseClassDescriptor RTTIBaseClassDescriptor;

typedef struct PMD PMD, *PPMD;

typedef struct _s__RTTIClassHierarchyDescriptor RTTIClassHierarchyDescriptor;

struct PMD {
    ptrdiff_t mdisp;
    ptrdiff_t pdisp;
    ptrdiff_t vdisp;
};

struct _s__RTTIBaseClassDescriptor {
    struct TypeDescriptor *pTypeDescriptor; // ref to TypeDescriptor (RTTI 0) for class
    dword numContainedBases; // count of extended classes in BaseClassArray (RTTI 2)
    struct PMD where; // member displacement structure
    dword attributes; // bit flags
    RTTIClassHierarchyDescriptor *pClassHierarchyDescriptor; // ref to ClassHierarchyDescriptor (RTTI 3) for class
};

struct _s__RTTIClassHierarchyDescriptor {
    dword signature;
    dword attributes; // bit flags
    dword numBaseClasses; // number of base classes (i.e. rtti1Count)
    RTTIBaseClassDescriptor **pBaseClassArray; // ref to BaseClassArray (RTTI 2)
};

typedef struct type_info type_info, *Ptype_info;

struct type_info { // PlaceHolder Class Structure
};

typedef struct _s_FuncInfo _s_FuncInfo, *P_s_FuncInfo;

typedef struct _s_UnwindMapEntry _s_UnwindMapEntry, *P_s_UnwindMapEntry;

typedef struct _s_UnwindMapEntry UnwindMapEntry;

typedef struct _s_TryBlockMapEntry TryBlockMapEntry;

typedef struct _s_ESTypeList _s_ESTypeList, *P_s_ESTypeList;

typedef struct _s_ESTypeList ESTypeList;

struct _s_FuncInfo {
    uint magicNumber_and_bbtFlags;
    __ehstate_t maxState;
    UnwindMapEntry *pUnwindMap;
    uint nTryBlocks;
    TryBlockMapEntry *pTryBlockMap;
    uint nIPMapEntries;
    void *pIPToStateMap;
    ESTypeList *pESTypeList;
    int EHFlags;
};

struct _s_UnwindMapEntry {
    __ehstate_t toState;
    void (*action)(void);
};

struct _s_ESTypeList {
    int nCount;
    HandlerType *pTypeArray;
};

typedef struct _s__RTTICompleteObjectLocator _s__RTTICompleteObjectLocator, *P_s__RTTICompleteObjectLocator;

struct _s__RTTICompleteObjectLocator {
    dword signature;
    dword offset; // offset of vbtable within class
    dword cdOffset; // constructor displacement offset
    struct TypeDescriptor *pTypeDescriptor; // ref to TypeDescriptor (RTTI 0) for class
    RTTIClassHierarchyDescriptor *pClassDescriptor; // ref to ClassHierarchyDescriptor (RTTI 3)
};

typedef struct CLIENT_ID CLIENT_ID, *PCLIENT_ID;

struct CLIENT_ID {
    void *UniqueProcess;
    void *UniqueThread;
};

typedef struct _s_FuncInfo FuncInfo;

typedef ulonglong __uint64;

typedef struct _s__RTTICompleteObjectLocator RTTICompleteObjectLocator;

typedef struct exception exception, *Pexception;

struct exception { // PlaceHolder Class Structure
};

typedef struct _cpinfo _cpinfo, *P_cpinfo;

typedef uint UINT;

typedef uchar BYTE;

struct _cpinfo {
    UINT MaxCharSize;
    BYTE DefaultChar[2];
    BYTE LeadByte[12];
};

typedef struct _cpinfo *LPCPINFO;

typedef struct _SECURITY_ATTRIBUTES _SECURITY_ATTRIBUTES, *P_SECURITY_ATTRIBUTES;

typedef ulong DWORD;

typedef void *LPVOID;

typedef int BOOL;

struct _SECURITY_ATTRIBUTES {
    DWORD nLength;
    LPVOID lpSecurityDescriptor;
    BOOL bInheritHandle;
};

typedef struct _WIN32_FIND_DATAW _WIN32_FIND_DATAW, *P_WIN32_FIND_DATAW;

typedef struct _FILETIME _FILETIME, *P_FILETIME;

typedef struct _FILETIME FILETIME;

typedef wchar_t WCHAR;

struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
};

struct _WIN32_FIND_DATAW {
    DWORD dwFileAttributes;
    FILETIME ftCreationTime;
    FILETIME ftLastAccessTime;
    FILETIME ftLastWriteTime;
    DWORD nFileSizeHigh;
    DWORD nFileSizeLow;
    DWORD dwReserved0;
    DWORD dwReserved1;
    WCHAR cFileName[260];
    WCHAR cAlternateFileName[14];
};

typedef enum _FINDEX_INFO_LEVELS {
    FindExInfoStandard=0,
    FindExInfoBasic=1,
    FindExInfoMaxInfoLevel=2
} _FINDEX_INFO_LEVELS;

typedef enum _FINDEX_INFO_LEVELS FINDEX_INFO_LEVELS;

typedef struct _OVERLAPPED _OVERLAPPED, *P_OVERLAPPED;

typedef ulong ULONG_PTR;

typedef union _union_518 _union_518, *P_union_518;

typedef void *HANDLE;

typedef struct _struct_519 _struct_519, *P_struct_519;

typedef void *PVOID;

struct _struct_519 {
    DWORD Offset;
    DWORD OffsetHigh;
};

union _union_518 {
    struct _struct_519 s;
    PVOID Pointer;
};

struct _OVERLAPPED {
    ULONG_PTR Internal;
    ULONG_PTR InternalHigh;
    union _union_518 u;
    HANDLE hEvent;
};

typedef struct _STARTUPINFOW _STARTUPINFOW, *P_STARTUPINFOW;

typedef WCHAR *LPWSTR;

typedef ushort WORD;

typedef BYTE *LPBYTE;

struct _STARTUPINFOW {
    DWORD cb;
    LPWSTR lpReserved;
    LPWSTR lpDesktop;
    LPWSTR lpTitle;
    DWORD dwX;
    DWORD dwY;
    DWORD dwXSize;
    DWORD dwYSize;
    DWORD dwXCountChars;
    DWORD dwYCountChars;
    DWORD dwFillAttribute;
    DWORD dwFlags;
    WORD wShowWindow;
    WORD cbReserved2;
    LPBYTE lpReserved2;
    HANDLE hStdInput;
    HANDLE hStdOutput;
    HANDLE hStdError;
};

typedef struct _STARTUPINFOW *LPSTARTUPINFOW;

typedef struct _RTL_CRITICAL_SECTION _RTL_CRITICAL_SECTION, *P_RTL_CRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION *PRTL_CRITICAL_SECTION;

typedef PRTL_CRITICAL_SECTION LPCRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION_DEBUG _RTL_CRITICAL_SECTION_DEBUG, *P_RTL_CRITICAL_SECTION_DEBUG;

typedef struct _RTL_CRITICAL_SECTION_DEBUG *PRTL_CRITICAL_SECTION_DEBUG;

typedef long LONG;

typedef struct _LIST_ENTRY _LIST_ENTRY, *P_LIST_ENTRY;

typedef struct _LIST_ENTRY LIST_ENTRY;

struct _RTL_CRITICAL_SECTION {
    PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
    LONG LockCount;
    LONG RecursionCount;
    HANDLE OwningThread;
    HANDLE LockSemaphore;
    ULONG_PTR SpinCount;
};

struct _LIST_ENTRY {
    struct _LIST_ENTRY *Flink;
    struct _LIST_ENTRY *Blink;
};

struct _RTL_CRITICAL_SECTION_DEBUG {
    WORD Type;
    WORD CreatorBackTraceIndex;
    struct _RTL_CRITICAL_SECTION *CriticalSection;
    LIST_ENTRY ProcessLocksList;
    DWORD EntryCount;
    DWORD ContentionCount;
    DWORD Flags;
    WORD CreatorBackTraceIndexHigh;
    WORD SpareWORD;
};

typedef struct _WIN32_FIND_DATAW *LPWIN32_FIND_DATAW;

typedef enum _FINDEX_SEARCH_OPS {
    FindExSearchNameMatch=0,
    FindExSearchLimitToDirectories=1,
    FindExSearchLimitToDevices=2,
    FindExSearchMaxSearchOp=3
} _FINDEX_SEARCH_OPS;

typedef struct _OVERLAPPED *LPOVERLAPPED;

typedef struct _EXCEPTION_POINTERS _EXCEPTION_POINTERS, *P_EXCEPTION_POINTERS;

typedef LONG (*PTOP_LEVEL_EXCEPTION_FILTER)(struct _EXCEPTION_POINTERS *);

typedef struct _EXCEPTION_RECORD _EXCEPTION_RECORD, *P_EXCEPTION_RECORD;

typedef struct _EXCEPTION_RECORD EXCEPTION_RECORD;

typedef EXCEPTION_RECORD *PEXCEPTION_RECORD;

typedef struct _CONTEXT _CONTEXT, *P_CONTEXT;

typedef struct _CONTEXT CONTEXT;

typedef CONTEXT *PCONTEXT;

typedef struct _FLOATING_SAVE_AREA _FLOATING_SAVE_AREA, *P_FLOATING_SAVE_AREA;

typedef struct _FLOATING_SAVE_AREA FLOATING_SAVE_AREA;

struct _FLOATING_SAVE_AREA {
    DWORD ControlWord;
    DWORD StatusWord;
    DWORD TagWord;
    DWORD ErrorOffset;
    DWORD ErrorSelector;
    DWORD DataOffset;
    DWORD DataSelector;
    BYTE RegisterArea[80];
    DWORD Cr0NpxState;
};

struct _CONTEXT {
    DWORD ContextFlags;
    DWORD Dr0;
    DWORD Dr1;
    DWORD Dr2;
    DWORD Dr3;
    DWORD Dr6;
    DWORD Dr7;
    FLOATING_SAVE_AREA FloatSave;
    DWORD SegGs;
    DWORD SegFs;
    DWORD SegEs;
    DWORD SegDs;
    DWORD Edi;
    DWORD Esi;
    DWORD Ebx;
    DWORD Edx;
    DWORD Ecx;
    DWORD Eax;
    DWORD Ebp;
    DWORD Eip;
    DWORD SegCs;
    DWORD EFlags;
    DWORD Esp;
    DWORD SegSs;
    BYTE ExtendedRegisters[512];
};

struct _EXCEPTION_RECORD {
    DWORD ExceptionCode;
    DWORD ExceptionFlags;
    struct _EXCEPTION_RECORD *ExceptionRecord;
    PVOID ExceptionAddress;
    DWORD NumberParameters;
    ULONG_PTR ExceptionInformation[15];
};

struct _EXCEPTION_POINTERS {
    PEXCEPTION_RECORD ExceptionRecord;
    PCONTEXT ContextRecord;
};

typedef enum _FINDEX_SEARCH_OPS FINDEX_SEARCH_OPS;

typedef struct _SECURITY_ATTRIBUTES *LPSECURITY_ATTRIBUTES;

typedef PTOP_LEVEL_EXCEPTION_FILTER LPTOP_LEVEL_EXCEPTION_FILTER;

typedef double ULONGLONG;

typedef char CHAR;

typedef union _LARGE_INTEGER _LARGE_INTEGER, *P_LARGE_INTEGER;

typedef struct _struct_19 _struct_19, *P_struct_19;

typedef struct _struct_20 _struct_20, *P_struct_20;

typedef double LONGLONG;

struct _struct_20 {
    DWORD LowPart;
    LONG HighPart;
};

struct _struct_19 {
    DWORD LowPart;
    LONG HighPart;
};

union _LARGE_INTEGER {
    struct _struct_19 s;
    struct _struct_20 u;
    LONGLONG QuadPart;
};

typedef union _LARGE_INTEGER LARGE_INTEGER;

typedef struct _IMAGE_SECTION_HEADER _IMAGE_SECTION_HEADER, *P_IMAGE_SECTION_HEADER;

typedef union _union_226 _union_226, *P_union_226;

union _union_226 {
    DWORD PhysicalAddress;
    DWORD VirtualSize;
};

struct _IMAGE_SECTION_HEADER {
    BYTE Name[8];
    union _union_226 Misc;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD NumberOfRelocations;
    WORD NumberOfLinenumbers;
    DWORD Characteristics;
};

typedef struct _IMAGE_SECTION_HEADER *PIMAGE_SECTION_HEADER;

typedef WCHAR *PCNZWCH;

typedef union _SLIST_HEADER _SLIST_HEADER, *P_SLIST_HEADER;

typedef struct _struct_299 _struct_299, *P_struct_299;

typedef struct _SINGLE_LIST_ENTRY _SINGLE_LIST_ENTRY, *P_SINGLE_LIST_ENTRY;

typedef struct _SINGLE_LIST_ENTRY SINGLE_LIST_ENTRY;

struct _SINGLE_LIST_ENTRY {
    struct _SINGLE_LIST_ENTRY *Next;
};

struct _struct_299 {
    SINGLE_LIST_ENTRY Next;
    WORD Depth;
    WORD Sequence;
};

union _SLIST_HEADER {
    ULONGLONG Alignment;
    struct _struct_299 s;
};

typedef WCHAR *LPWCH;

typedef WCHAR *LPCWSTR;

typedef union _SLIST_HEADER *PSLIST_HEADER;

typedef CHAR *LPCSTR;

typedef LARGE_INTEGER *PLARGE_INTEGER;

typedef CHAR *LPSTR;

typedef DWORD LCID;

typedef struct IMAGE_DOS_HEADER IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

struct IMAGE_DOS_HEADER {
    char e_magic[2]; // Magic number
    word e_cblp; // Bytes of last page
    word e_cp; // Pages in file
    word e_crlc; // Relocations
    word e_cparhdr; // Size of header in paragraphs
    word e_minalloc; // Minimum extra paragraphs needed
    word e_maxalloc; // Maximum extra paragraphs needed
    word e_ss; // Initial (relative) SS value
    word e_sp; // Initial SP value
    word e_csum; // Checksum
    word e_ip; // Initial IP value
    word e_cs; // Initial (relative) CS value
    word e_lfarlc; // File address of relocation table
    word e_ovno; // Overlay number
    word e_res[4][4]; // Reserved words
    word e_oemid; // OEM identifier (for e_oeminfo)
    word e_oeminfo; // OEM information; e_oemid specific
    word e_res2[10][10]; // Reserved words
    dword e_lfanew; // File address of new exe header
    byte e_program[64]; // Actual DOS program
};

typedef ULONG_PTR DWORD_PTR;

typedef ULONG_PTR SIZE_T;

typedef struct DotNetPdbInfo DotNetPdbInfo, *PDotNetPdbInfo;

struct DotNetPdbInfo {
    char signature[4];
    GUID guid;
    dword age;
    char pdbpath[63];
};

typedef struct _FILETIME *LPFILETIME;

typedef ulong ULONG;

typedef int (*FARPROC)(void);

typedef DWORD *LPDWORD;

typedef WORD *LPWORD;

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

struct HINSTANCE__ {
    int unused;
};

typedef BOOL *LPBOOL;

typedef BYTE *PBYTE;

typedef struct HINSTANCE__ *HINSTANCE;

typedef HINSTANCE HMODULE;

typedef void *LPCVOID;

typedef struct IMAGE_OPTIONAL_HEADER32 IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct IMAGE_DATA_DIRECTORY IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

struct IMAGE_DATA_DIRECTORY {
    ImageBaseOffset32 VirtualAddress;
    dword Size;
};

struct IMAGE_OPTIONAL_HEADER32 {
    word Magic;
    byte MajorLinkerVersion;
    byte MinorLinkerVersion;
    dword SizeOfCode;
    dword SizeOfInitializedData;
    dword SizeOfUninitializedData;
    ImageBaseOffset32 AddressOfEntryPoint;
    ImageBaseOffset32 BaseOfCode;
    ImageBaseOffset32 BaseOfData;
    pointer32 ImageBase;
    dword SectionAlignment;
    dword FileAlignment;
    word MajorOperatingSystemVersion;
    word MinorOperatingSystemVersion;
    word MajorImageVersion;
    word MinorImageVersion;
    word MajorSubsystemVersion;
    word MinorSubsystemVersion;
    dword Win32VersionValue;
    dword SizeOfImage;
    dword SizeOfHeaders;
    dword CheckSum;
    word Subsystem;
    word DllCharacteristics;
    dword SizeOfStackReserve;
    dword SizeOfStackCommit;
    dword SizeOfHeapReserve;
    dword SizeOfHeapCommit;
    dword LoaderFlags;
    dword NumberOfRvaAndSizes;
    struct IMAGE_DATA_DIRECTORY DataDirectory[16];
};

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct {
    dword NameOffset;
    dword NameIsString;
};

typedef struct IMAGE_LOAD_CONFIG_CODE_INTEGRITY IMAGE_LOAD_CONFIG_CODE_INTEGRITY, *PIMAGE_LOAD_CONFIG_CODE_INTEGRITY;

struct IMAGE_LOAD_CONFIG_CODE_INTEGRITY {
    word Flags;
    word Catalog;
    dword CatalogOffset;
    dword Reserved;
};

typedef struct IMAGE_DEBUG_DIRECTORY IMAGE_DEBUG_DIRECTORY, *PIMAGE_DEBUG_DIRECTORY;

struct IMAGE_DEBUG_DIRECTORY {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword Type;
    dword SizeOfData;
    dword AddressOfRawData;
    dword PointerToRawData;
};

typedef struct IMAGE_FILE_HEADER IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

struct IMAGE_FILE_HEADER {
    word Machine; // 332
    word NumberOfSections;
    dword TimeDateStamp;
    dword PointerToSymbolTable;
    dword NumberOfSymbols;
    word SizeOfOptionalHeader;
    word Characteristics;
};

typedef struct IMAGE_NT_HEADERS32 IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

struct IMAGE_NT_HEADERS32 {
    char Signature[4];
    struct IMAGE_FILE_HEADER FileHeader;
    struct IMAGE_OPTIONAL_HEADER32 OptionalHeader;
};

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion;

union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion {
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;
    dword Name;
    word Id;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY {
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion NameUnion;
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion DirectoryUnion;
};

typedef struct IMAGE_SECTION_HEADER IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef union Misc Misc, *PMisc;

typedef enum SectionFlags {
    IMAGE_SCN_TYPE_NO_PAD=8,
    IMAGE_SCN_RESERVED_0001=16,
    IMAGE_SCN_CNT_CODE=32,
    IMAGE_SCN_CNT_INITIALIZED_DATA=64,
    IMAGE_SCN_CNT_UNINITIALIZED_DATA=128,
    IMAGE_SCN_LNK_OTHER=256,
    IMAGE_SCN_LNK_INFO=512,
    IMAGE_SCN_RESERVED_0040=1024,
    IMAGE_SCN_LNK_REMOVE=2048,
    IMAGE_SCN_LNK_COMDAT=4096,
    IMAGE_SCN_GPREL=32768,
    IMAGE_SCN_MEM_16BIT=131072,
    IMAGE_SCN_MEM_PURGEABLE=131072,
    IMAGE_SCN_MEM_LOCKED=262144,
    IMAGE_SCN_MEM_PRELOAD=524288,
    IMAGE_SCN_ALIGN_1BYTES=1048576,
    IMAGE_SCN_ALIGN_2BYTES=2097152,
    IMAGE_SCN_ALIGN_4BYTES=3145728,
    IMAGE_SCN_ALIGN_8BYTES=4194304,
    IMAGE_SCN_ALIGN_16BYTES=5242880,
    IMAGE_SCN_ALIGN_32BYTES=6291456,
    IMAGE_SCN_ALIGN_64BYTES=7340032,
    IMAGE_SCN_ALIGN_128BYTES=8388608,
    IMAGE_SCN_ALIGN_256BYTES=9437184,
    IMAGE_SCN_ALIGN_512BYTES=10485760,
    IMAGE_SCN_ALIGN_1024BYTES=11534336,
    IMAGE_SCN_ALIGN_2048BYTES=12582912,
    IMAGE_SCN_ALIGN_4096BYTES=13631488,
    IMAGE_SCN_ALIGN_8192BYTES=14680064,
    IMAGE_SCN_LNK_NRELOC_OVFL=16777216,
    IMAGE_SCN_MEM_DISCARDABLE=33554432,
    IMAGE_SCN_MEM_NOT_CACHED=67108864,
    IMAGE_SCN_MEM_NOT_PAGED=134217728,
    IMAGE_SCN_MEM_SHARED=268435456,
    IMAGE_SCN_MEM_EXECUTE=536870912,
    IMAGE_SCN_MEM_READ=1073741824,
    IMAGE_SCN_MEM_WRITE=2147483648
} SectionFlags;

union Misc {
    dword PhysicalAddress;
    dword VirtualSize;
};

struct IMAGE_SECTION_HEADER {
    char Name[8];
    union Misc Misc;
    ImageBaseOffset32 VirtualAddress;
    dword SizeOfRawData;
    dword PointerToRawData;
    dword PointerToRelocations;
    dword PointerToLinenumbers;
    word NumberOfRelocations;
    word NumberOfLinenumbers;
    enum SectionFlags Characteristics;
};

typedef struct IMAGE_RESOURCE_DATA_ENTRY IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;

struct IMAGE_RESOURCE_DATA_ENTRY {
    dword OffsetToData;
    dword Size;
    dword CodePage;
    dword Reserved;
};

typedef enum IMAGE_GUARD_FLAGS {
    IMAGE_GUARD_CF_INSTRUMENTED=256,
    IMAGE_GUARD_CFW_INSTRUMENTED=512,
    IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT=1024,
    IMAGE_GUARD_SECURITY_COOKIE_UNUSED=2048,
    IMAGE_GUARD_PROTECT_DELAYLOAD_IAT=4096,
    IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION=8192,
    IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT=16384,
    IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION=32768,
    IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT=65536,
    IMAGE_GUARD_RF_INSTRUMENTED=131072,
    IMAGE_GUARD_RF_ENABLE=262144,
    IMAGE_GUARD_RF_STRICT=524288,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_1=268435456,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_2=536870912,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_4=1073741824,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_8=2147483648
} IMAGE_GUARD_FLAGS;

typedef struct IMAGE_RESOURCE_DIRECTORY IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;

struct IMAGE_RESOURCE_DIRECTORY {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    word NumberOfNamedEntries;
    word NumberOfIdEntries;
};

typedef struct IMAGE_LOAD_CONFIG_DIRECTORY32 IMAGE_LOAD_CONFIG_DIRECTORY32, *PIMAGE_LOAD_CONFIG_DIRECTORY32;

struct IMAGE_LOAD_CONFIG_DIRECTORY32 {
    dword Size;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword GlobalFlagsClear;
    dword GlobalFlagsSet;
    dword CriticalSectionDefaultTimeout;
    dword DeCommitFreeBlockThreshold;
    dword DeCommitTotalFreeThreshold;
    pointer32 LockPrefixTable;
    dword MaximumAllocationSize;
    dword VirtualMemoryThreshold;
    dword ProcessHeapFlags;
    dword ProcessAffinityMask;
    word CsdVersion;
    word DependentLoadFlags;
    pointer32 EditList;
    pointer32 SecurityCookie;
    pointer32 SEHandlerTable;
    dword SEHandlerCount;
    pointer32 GuardCFCCheckFunctionPointer;
    pointer32 GuardCFDispatchFunctionPointer;
    pointer32 GuardCFFunctionTable;
    dword GuardCFFunctionCount;
    enum IMAGE_GUARD_FLAGS GuardFlags;
    struct IMAGE_LOAD_CONFIG_CODE_INTEGRITY CodeIntegrity;
    pointer32 GuardAddressTakenIatEntryTable;
    dword GuardAddressTakenIatEntryCount;
    pointer32 GuardLongJumpTargetTable;
    dword GuardLongJumpTargetCount;
    pointer32 DynamicValueRelocTable;
    pointer32 CHPEMetadataPointer;
    pointer32 GuardRFFailureRoutine;
    pointer32 GuardRFFailureRoutineFunctionPointer;
    dword DynamicValueRelocTableOffset;
    word DynamicValueRelocTableSection;
    word Reserved1;
    pointer32 GuardRFVerifyStackPointerFunctionPointer;
    dword HotPatchTableOffset;
    dword Reserved2;
    dword Reserved3;
};

typedef struct _iobuf _iobuf, *P_iobuf;

struct _iobuf {
    char *_ptr;
    int _cnt;
    char *_base;
    int _flag;
    int _file;
    int _charbuf;
    int _bufsiz;
    char *_tmpfname;
};

typedef struct _iobuf FILE;

typedef struct _CONSOLE_READCONSOLE_CONTROL _CONSOLE_READCONSOLE_CONTROL, *P_CONSOLE_READCONSOLE_CONTROL;

struct _CONSOLE_READCONSOLE_CONTROL {
    ULONG nLength;
    ULONG nInitialChars;
    ULONG dwCtrlWakeupMask;
    ULONG dwControlKeyState;
};

typedef struct _CONSOLE_READCONSOLE_CONTROL *PCONSOLE_READCONSOLE_CONTROL;

typedef uint uintptr_t;

typedef struct <lambda_274ecf0a8038e561263518ab346655e8> <lambda_274ecf0a8038e561263518ab346655e8>, *P<lambda_274ecf0a8038e561263518ab346655e8>;

struct <lambda_274ecf0a8038e561263518ab346655e8> { // PlaceHolder Structure
};

typedef struct <lambda_2b24c74d71094a6cd0cb82e44167d71b> <lambda_2b24c74d71094a6cd0cb82e44167d71b>, *P<lambda_2b24c74d71094a6cd0cb82e44167d71b>;

struct <lambda_2b24c74d71094a6cd0cb82e44167d71b> { // PlaceHolder Structure
};

typedef struct <lambda_3e16ef9562a7dcce91392c22ab16ea36> <lambda_3e16ef9562a7dcce91392c22ab16ea36>, *P<lambda_3e16ef9562a7dcce91392c22ab16ea36>;

struct <lambda_3e16ef9562a7dcce91392c22ab16ea36> { // PlaceHolder Structure
};

typedef struct <lambda_2cc53f568c5a2bb6f192f930a45d44ea> <lambda_2cc53f568c5a2bb6f192f930a45d44ea>, *P<lambda_2cc53f568c5a2bb6f192f930a45d44ea>;

struct <lambda_2cc53f568c5a2bb6f192f930a45d44ea> { // PlaceHolder Structure
};

typedef struct EHExceptionRecord EHExceptionRecord, *PEHExceptionRecord;

struct EHExceptionRecord { // PlaceHolder Structure
};

typedef struct <lambda_8e746cf0007f6ed984d6f78af1fec997> <lambda_8e746cf0007f6ed984d6f78af1fec997>, *P<lambda_8e746cf0007f6ed984d6f78af1fec997>;

struct <lambda_8e746cf0007f6ed984d6f78af1fec997> { // PlaceHolder Structure
};

typedef struct <lambda_c2ffc0b7726aa6be21d5f0026187e748> <lambda_c2ffc0b7726aa6be21d5f0026187e748>, *P<lambda_c2ffc0b7726aa6be21d5f0026187e748>;

struct <lambda_c2ffc0b7726aa6be21d5f0026187e748> { // PlaceHolder Structure
};

typedef struct <lambda_b8d4b9c228a6ecc3f80208dbb4b4a104> <lambda_b8d4b9c228a6ecc3f80208dbb4b4a104>, *P<lambda_b8d4b9c228a6ecc3f80208dbb4b4a104>;

struct <lambda_b8d4b9c228a6ecc3f80208dbb4b4a104> { // PlaceHolder Structure
};

typedef enum __acrt_fp_class {
} __acrt_fp_class;

typedef struct __crt_signal_action_t __crt_signal_action_t, *P__crt_signal_action_t;

struct __crt_signal_action_t { // PlaceHolder Structure
};

typedef struct <lambda_18ed0c0b38a6dc0daf1e7ac6d6adf05e> <lambda_18ed0c0b38a6dc0daf1e7ac6d6adf05e>, *P<lambda_18ed0c0b38a6dc0daf1e7ac6d6adf05e>;

struct <lambda_18ed0c0b38a6dc0daf1e7ac6d6adf05e> { // PlaceHolder Structure
};

typedef struct __crt_locale_data __crt_locale_data, *P__crt_locale_data;

struct __crt_locale_data { // PlaceHolder Structure
};

typedef struct <lambda_fb385d3da700c9147fc39e65dd577a8c> <lambda_fb385d3da700c9147fc39e65dd577a8c>, *P<lambda_fb385d3da700c9147fc39e65dd577a8c>;

struct <lambda_fb385d3da700c9147fc39e65dd577a8c> { // PlaceHolder Structure
};

typedef struct <lambda_22ebabd17bc4fa466a2aca6d8deb888d> <lambda_22ebabd17bc4fa466a2aca6d8deb888d>, *P<lambda_22ebabd17bc4fa466a2aca6d8deb888d>;

struct <lambda_22ebabd17bc4fa466a2aca6d8deb888d> { // PlaceHolder Structure
};

typedef struct <lambda_ab61a845afdef5b7c387490eaf3616ee> <lambda_ab61a845afdef5b7c387490eaf3616ee>, *P<lambda_ab61a845afdef5b7c387490eaf3616ee>;

struct <lambda_ab61a845afdef5b7c387490eaf3616ee> { // PlaceHolder Structure
};

typedef struct <lambda_a7e850c220f1c8d1e6efeecdedd162c6> <lambda_a7e850c220f1c8d1e6efeecdedd162c6>, *P<lambda_a7e850c220f1c8d1e6efeecdedd162c6>;

struct <lambda_a7e850c220f1c8d1e6efeecdedd162c6> { // PlaceHolder Structure
};

typedef struct <lambda_62f6974d9771e494a5ea317cc32e971c> <lambda_62f6974d9771e494a5ea317cc32e971c>, *P<lambda_62f6974d9771e494a5ea317cc32e971c>;

struct <lambda_62f6974d9771e494a5ea317cc32e971c> { // PlaceHolder Structure
};

typedef struct <lambda_207f2d024fc103971653565357d6cd41> <lambda_207f2d024fc103971653565357d6cd41>, *P<lambda_207f2d024fc103971653565357d6cd41>;

struct <lambda_207f2d024fc103971653565357d6cd41> { // PlaceHolder Structure
};

typedef struct <lambda_f03950bc5685219e0bcd2087efbe011e> <lambda_f03950bc5685219e0bcd2087efbe011e>, *P<lambda_f03950bc5685219e0bcd2087efbe011e>;

struct <lambda_f03950bc5685219e0bcd2087efbe011e> { // PlaceHolder Structure
};

typedef struct <lambda_ae742caa10f662c28703da3d2ea5e57e> <lambda_ae742caa10f662c28703da3d2ea5e57e>, *P<lambda_ae742caa10f662c28703da3d2ea5e57e>;

struct <lambda_ae742caa10f662c28703da3d2ea5e57e> { // PlaceHolder Structure
};

typedef struct <lambda_ceb1ee4838e85a9d631eb091e2fbe199> <lambda_ceb1ee4838e85a9d631eb091e2fbe199>, *P<lambda_ceb1ee4838e85a9d631eb091e2fbe199>;

struct <lambda_ceb1ee4838e85a9d631eb091e2fbe199> { // PlaceHolder Structure
};

typedef struct <lambda_6affb1475c98b40b75cdec977db92e3c> <lambda_6affb1475c98b40b75cdec977db92e3c>, *P<lambda_6affb1475c98b40b75cdec977db92e3c>;

struct <lambda_6affb1475c98b40b75cdec977db92e3c> { // PlaceHolder Structure
};

typedef struct __crt_seh_guarded_call<void> __crt_seh_guarded_call<void>, *P__crt_seh_guarded_call<void>;

struct __crt_seh_guarded_call<void> { // PlaceHolder Structure
};

typedef struct <lambda_38edbb1296d33220d7e4dd0ed76b244a> <lambda_38edbb1296d33220d7e4dd0ed76b244a>, *P<lambda_38edbb1296d33220d7e4dd0ed76b244a>;

struct <lambda_38edbb1296d33220d7e4dd0ed76b244a> { // PlaceHolder Structure
};

typedef struct <lambda_39ca0ed439415581b5b15c265174cece> <lambda_39ca0ed439415581b5b15c265174cece>, *P<lambda_39ca0ed439415581b5b15c265174cece>;

struct <lambda_39ca0ed439415581b5b15c265174cece> { // PlaceHolder Structure
};

typedef struct __crt_win32_buffer<wchar_t,struct___crt_win32_buffer_internal_dynamic_resizing> __crt_win32_buffer<wchar_t,struct___crt_win32_buffer_internal_dynamic_resizing>, *P__crt_win32_buffer<wchar_t,struct___crt_win32_buffer_internal_dynamic_resizing>;

struct __crt_win32_buffer<wchar_t,struct___crt_win32_buffer_internal_dynamic_resizing> { // PlaceHolder Structure
};

typedef struct <lambda_15ade71b0218206bbe3333a0c9b79046> <lambda_15ade71b0218206bbe3333a0c9b79046>, *P<lambda_15ade71b0218206bbe3333a0c9b79046>;

struct <lambda_15ade71b0218206bbe3333a0c9b79046> { // PlaceHolder Structure
};

typedef struct <lambda_2866be3712abc81a800a822484c830d8> <lambda_2866be3712abc81a800a822484c830d8>, *P<lambda_2866be3712abc81a800a822484c830d8>;

struct <lambda_2866be3712abc81a800a822484c830d8> { // PlaceHolder Structure
};

typedef struct __crt_win32_buffer_empty_debug_info __crt_win32_buffer_empty_debug_info, *P__crt_win32_buffer_empty_debug_info;

struct __crt_win32_buffer_empty_debug_info { // PlaceHolder Structure
};

typedef struct _s_CatchableType _s_CatchableType, *P_s_CatchableType;

struct _s_CatchableType { // PlaceHolder Structure
};

typedef struct _nlsversioninfo _nlsversioninfo, *P_nlsversioninfo;

struct _nlsversioninfo { // PlaceHolder Structure
};

typedef enum SLD_STATUS {
} SLD_STATUS;

typedef struct __crt_stdio_stream __crt_stdio_stream, *P__crt_stdio_stream;

struct __crt_stdio_stream { // PlaceHolder Structure
};

typedef struct <lambda_69a2805e680e0e292e8ba93315fe43a8> <lambda_69a2805e680e0e292e8ba93315fe43a8>, *P<lambda_69a2805e680e0e292e8ba93315fe43a8>;

struct <lambda_69a2805e680e0e292e8ba93315fe43a8> { // PlaceHolder Structure
};

typedef struct __crt_multibyte_data __crt_multibyte_data, *P__crt_multibyte_data;

struct __crt_multibyte_data { // PlaceHolder Structure
};

typedef struct __crt_seh_guarded_call<int> __crt_seh_guarded_call<int>, *P__crt_seh_guarded_call<int>;

struct __crt_seh_guarded_call<int> { // PlaceHolder Structure
};

typedef struct <lambda_da44e0f8b0f19ba52fefafb335991732> <lambda_da44e0f8b0f19ba52fefafb335991732>, *P<lambda_da44e0f8b0f19ba52fefafb335991732>;

struct <lambda_da44e0f8b0f19ba52fefafb335991732> { // PlaceHolder Structure
};

typedef struct <lambda_5ce1d447e08cb34b2473517608e21441> <lambda_5ce1d447e08cb34b2473517608e21441>, *P<lambda_5ce1d447e08cb34b2473517608e21441>;

struct <lambda_5ce1d447e08cb34b2473517608e21441> { // PlaceHolder Structure
};

typedef struct <lambda_af42a3ee9806e9a7305d451646e05244> <lambda_af42a3ee9806e9a7305d451646e05244>, *P<lambda_af42a3ee9806e9a7305d451646e05244>;

struct <lambda_af42a3ee9806e9a7305d451646e05244> { // PlaceHolder Structure
};

typedef struct __acrt_ptd __acrt_ptd, *P__acrt_ptd;

struct __acrt_ptd { // PlaceHolder Structure
};

typedef struct <lambda_03fcd07e894ec930e3f35da366ca99d6> <lambda_03fcd07e894ec930e3f35da366ca99d6>, *P<lambda_03fcd07e894ec930e3f35da366ca99d6>;

struct <lambda_03fcd07e894ec930e3f35da366ca99d6> { // PlaceHolder Structure
};

typedef struct <lambda_e25ca0880e6ef98be67edffd8c599615> <lambda_e25ca0880e6ef98be67edffd8c599615>, *P<lambda_e25ca0880e6ef98be67edffd8c599615>;

struct <lambda_e25ca0880e6ef98be67edffd8c599615> { // PlaceHolder Structure
};

typedef struct <lambda_21448eb78dd3c4a522ed7c65a98d88e6> <lambda_21448eb78dd3c4a522ed7c65a98d88e6>, *P<lambda_21448eb78dd3c4a522ed7c65a98d88e6>;

struct <lambda_21448eb78dd3c4a522ed7c65a98d88e6> { // PlaceHolder Structure
};

typedef struct EHRegistrationNode EHRegistrationNode, *PEHRegistrationNode;

struct EHRegistrationNode { // PlaceHolder Structure
};

typedef struct <lambda_cd08b5d6af4937fe54fc07d0c9bf6b37> <lambda_cd08b5d6af4937fe54fc07d0c9bf6b37>, *P<lambda_cd08b5d6af4937fe54fc07d0c9bf6b37>;

struct <lambda_cd08b5d6af4937fe54fc07d0c9bf6b37> { // PlaceHolder Structure
};

typedef struct <lambda_0ca1de2171e49cefb1e8dc85c06db622> <lambda_0ca1de2171e49cefb1e8dc85c06db622>, *P<lambda_0ca1de2171e49cefb1e8dc85c06db622>;

struct <lambda_0ca1de2171e49cefb1e8dc85c06db622> { // PlaceHolder Structure
};

typedef struct <lambda_e5124f882df8998aaf41531e079ba474> <lambda_e5124f882df8998aaf41531e079ba474>, *P<lambda_e5124f882df8998aaf41531e079ba474>;

struct <lambda_e5124f882df8998aaf41531e079ba474> { // PlaceHolder Structure
};

typedef struct <lambda_46720907175c18b6c9d2717bc0d2d362> <lambda_46720907175c18b6c9d2717bc0d2d362>, *P<lambda_46720907175c18b6c9d2717bc0d2d362>;

struct <lambda_46720907175c18b6c9d2717bc0d2d362> { // PlaceHolder Structure
};

typedef enum _EXCEPTION_DISPOSITION {
} _EXCEPTION_DISPOSITION;

typedef struct __crt_locale_pointers __crt_locale_pointers, *P__crt_locale_pointers;

struct __crt_locale_pointers { // PlaceHolder Structure
};

typedef struct <lambda_9048902d66e8d99359bc9897bbb930a8> <lambda_9048902d66e8d99359bc9897bbb930a8>, *P<lambda_9048902d66e8d99359bc9897bbb930a8>;

struct <lambda_9048902d66e8d99359bc9897bbb930a8> { // PlaceHolder Structure
};

typedef struct <lambda_608742c3c92a14382c1684fc64f96c88> <lambda_608742c3c92a14382c1684fc64f96c88>, *P<lambda_608742c3c92a14382c1684fc64f96c88>;

struct <lambda_608742c3c92a14382c1684fc64f96c88> { // PlaceHolder Structure
};

typedef struct pair<class___FrameHandler3::TryBlockMap::iterator,class___FrameHandler3::TryBlockMap::iterator> pair<class___FrameHandler3::TryBlockMap::iterator,class___FrameHandler3::TryBlockMap::iterator>, *Ppair<class___FrameHandler3::TryBlockMap::iterator,class___FrameHandler3::TryBlockMap::iterator>;

struct pair<class___FrameHandler3::TryBlockMap::iterator,class___FrameHandler3::TryBlockMap::iterator> { // PlaceHolder Structure
};

typedef struct string_input_adapter<char> string_input_adapter<char>, *Pstring_input_adapter<char>;

struct string_input_adapter<char> { // PlaceHolder Structure
};

typedef struct stream_input_adapter<char> stream_input_adapter<char>, *Pstream_input_adapter<char>;

struct stream_input_adapter<char> { // PlaceHolder Structure
};

typedef struct format_string_parser<char> format_string_parser<char>, *Pformat_string_parser<char>;

struct format_string_parser<char> { // PlaceHolder Structure
};

typedef struct scanset_buffer<unsigned_char> scanset_buffer<unsigned_char>, *Pscanset_buffer<unsigned_char>;

struct scanset_buffer<unsigned_char> { // PlaceHolder Structure
};

typedef struct input_processor<char,class___crt_stdio_input::stream_input_adapter<char>_> input_processor<char,class___crt_stdio_input::stream_input_adapter<char>_>, *Pinput_processor<char,class___crt_stdio_input::stream_input_adapter<char>_>;

struct input_processor<char,class___crt_stdio_input::stream_input_adapter<char>_> { // PlaceHolder Structure
};

typedef struct input_processor<char,class___crt_stdio_input::string_input_adapter<char>_> input_processor<char,class___crt_stdio_input::string_input_adapter<char>_>, *Pinput_processor<char,class___crt_stdio_input::string_input_adapter<char>_>;

struct input_processor<char,class___crt_stdio_input::string_input_adapter<char>_> { // PlaceHolder Structure
};

typedef enum length_modifier {
} length_modifier;

typedef enum conversion_mode {
} conversion_mode;

typedef struct TryBlockMap TryBlockMap, *PTryBlockMap;

struct TryBlockMap { // PlaceHolder Structure
};

typedef struct formatting_buffer formatting_buffer, *Pformatting_buffer;

struct formatting_buffer { // PlaceHolder Structure
};

typedef struct input_adapter_character_source<class___crt_stdio_input::string_input_adapter<char>_> input_adapter_character_source<class___crt_stdio_input::string_input_adapter<char>_>, *Pinput_adapter_character_source<class___crt_stdio_input::string_input_adapter<char>_>;

struct input_adapter_character_source<class___crt_stdio_input::string_input_adapter<char>_> { // PlaceHolder Structure
};

typedef struct input_adapter_character_source<class___crt_stdio_input::stream_input_adapter<char>_> input_adapter_character_source<class___crt_stdio_input::stream_input_adapter<char>_>, *Pinput_adapter_character_source<class___crt_stdio_input::stream_input_adapter<char>_>;

struct input_adapter_character_source<class___crt_stdio_input::stream_input_adapter<char>_> { // PlaceHolder Structure
};

typedef enum floating_point_parse_result {
} floating_point_parse_result;

typedef struct c_string_character_source<char> c_string_character_source<char>, *Pc_string_character_source<char>;

struct c_string_character_source<char> { // PlaceHolder Structure
};

typedef struct floating_point_string floating_point_string, *Pfloating_point_string;

struct floating_point_string { // PlaceHolder Structure
};

typedef struct floating_point_value floating_point_value, *Pfloating_point_value;

struct floating_point_value { // PlaceHolder Structure
};

typedef struct argument_list<char> argument_list<char>, *Pargument_list<char>;

struct argument_list<char> { // PlaceHolder Structure
};

typedef struct write_result write_result, *Pwrite_result;

struct write_result { // PlaceHolder Structure
};

typedef int (*_onexit_t)(void);

typedef struct lconv lconv, *Plconv;

struct lconv {
    char *decimal_point;
    char *thousands_sep;
    char *grouping;
    char *int_curr_symbol;
    char *currency_symbol;
    char *mon_decimal_point;
    char *mon_thousands_sep;
    char *mon_grouping;
    char *positive_sign;
    char *negative_sign;
    char int_frac_digits;
    char frac_digits;
    char p_cs_precedes;
    char p_sep_by_space;
    char n_cs_precedes;
    char n_sep_by_space;
    char p_sign_posn;
    char n_sign_posn;
    wchar_t *_W_decimal_point;
    wchar_t *_W_thousands_sep;
    wchar_t *_W_int_curr_symbol;
    wchar_t *_W_currency_symbol;
    wchar_t *_W_mon_decimal_point;
    wchar_t *_W_mon_thousands_sep;
    wchar_t *_W_positive_sign;
    wchar_t *_W_negative_sign;
};

typedef ushort wint_t;

typedef struct threadlocaleinfostruct threadlocaleinfostruct, *Pthreadlocaleinfostruct;

typedef struct threadlocaleinfostruct *pthreadlocinfo;

typedef struct localerefcount localerefcount, *Plocalerefcount;

typedef struct localerefcount locrefcount;

typedef struct __lc_time_data __lc_time_data, *P__lc_time_data;

struct localerefcount {
    char *locale;
    wchar_t *wlocale;
    int *refcount;
    int *wrefcount;
};

struct threadlocaleinfostruct {
    int refcount;
    uint lc_codepage;
    uint lc_collate_cp;
    uint lc_time_cp;
    locrefcount lc_category[6];
    int lc_clike;
    int mb_cur_max;
    int *lconv_intl_refcount;
    int *lconv_num_refcount;
    int *lconv_mon_refcount;
    struct lconv *lconv;
    int *ctype1_refcount;
    ushort *ctype1;
    ushort *pctype;
    uchar *pclmap;
    uchar *pcumap;
    struct __lc_time_data *lc_time_curr;
    wchar_t *locale_name[6];
};

struct __lc_time_data {
    char *wday_abbr[7];
    char *wday[7];
    char *month_abbr[12];
    char *month[12];
    char *ampm[2];
    char *ww_sdatefmt;
    char *ww_ldatefmt;
    char *ww_timefmt;
    int ww_caltype;
    int refcount;
    wchar_t *_W_wday_abbr[7];
    wchar_t *_W_wday[7];
    wchar_t *_W_month_abbr[12];
    wchar_t *_W_month[12];
    wchar_t *_W_ampm[2];
    wchar_t *_W_ww_sdatefmt;
    wchar_t *_W_ww_ldatefmt;
    wchar_t *_W_ww_timefmt;
    wchar_t *_W_ww_locale_name;
};

typedef uint size_t;

typedef int errno_t;

typedef struct localeinfo_struct localeinfo_struct, *Plocaleinfo_struct;

typedef struct threadmbcinfostruct threadmbcinfostruct, *Pthreadmbcinfostruct;

typedef struct threadmbcinfostruct *pthreadmbcinfo;

struct threadmbcinfostruct {
    int refcount;
    int mbcodepage;
    int ismbcodepage;
    ushort mbulinfo[6];
    uchar mbctype[257];
    uchar mbcasemap[256];
    wchar_t *mblocalename;
};

struct localeinfo_struct {
    pthreadlocinfo locinfo;
    pthreadmbcinfo mbcinfo;
};

typedef size_t rsize_t;

typedef struct localeinfo_struct *_locale_t;




undefined * FUN_00401000(void)

{
  return &DAT_00424540;
}



undefined * FUN_00401010(void)

{
  return &DAT_00424538;
}



void __cdecl FUN_00401020(int param_1)

{
  FILE *pFVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  undefined *puVar4;
  
  pFVar1 = (FILE *)FUN_00404989(1);
  puVar4 = &stack0x00000008;
  puVar3 = (undefined4 *)0x0;
  puVar2 = (undefined4 *)FUN_00401000();
  FUN_0040673e(*puVar2,puVar2[1],pFVar1,param_1,puVar3,puVar4);
  return;
}



void __cdecl FUN_00401050(int param_1)

{
  undefined *puVar1;
  undefined4 *puVar2;
  undefined4 uVar3;
  undefined *puVar4;
  
  puVar1 = FUN_00404989(0);
  puVar4 = &stack0x00000008;
  uVar3 = 0;
  puVar2 = (undefined4 *)FUN_00401010();
  FUN_0040c924(*puVar2,puVar2[1],(int)puVar1,param_1,uVar3,puVar4);
  return;
}



void __cdecl FUN_00401080(int param_1)

{
  undefined *puVar1;
  uint *puVar2;
  undefined4 uVar3;
  undefined *puVar4;
  
  puVar1 = FUN_00404989(0);
  puVar4 = &stack0x00000008;
  uVar3 = 0;
  puVar2 = (uint *)FUN_00401010();
  FUN_0040c924(*puVar2 | 1,puVar2[1],(int)puVar1,param_1,uVar3,puVar4);
  return;
}



void __cdecl FUN_004010c0(char *param_1,char *param_2)

{
  undefined4 *puVar1;
  uint uVar2;
  __crt_locale_pointers *p_Var3;
  char *pcVar4;
  
  pcVar4 = &stack0x0000000c;
  p_Var3 = (__crt_locale_pointers *)0x0;
  uVar2 = 0xffffffff;
  puVar1 = (undefined4 *)FUN_00401010();
  ___stdio_common_vsscanf(*puVar1,puVar1[1],param_1,uVar2,param_2,p_Var3,pcVar4);
  return;
}



void FUN_004010f0(void)

{
  int iVar1;
  FILE *pFVar2;
  char local_68 [52];
  undefined4 local_34;
  undefined4 uStack_30;
  undefined4 uStack_2c;
  undefined4 uStack_28;
  undefined4 local_24;
  undefined4 uStack_20;
  undefined4 uStack_1c;
  undefined4 uStack_18;
  undefined4 local_14;
  undefined4 local_10;
  uint local_c;
  int local_8;
  
  local_8 = 0;
  _memset(local_68,0,0x32);
  local_34 = 0;
  uStack_30 = 2;
  uStack_2c = 4;
  uStack_28 = 6;
  local_24 = 8;
  uStack_20 = 10;
  uStack_1c = 0xc;
  uStack_18 = 0xe;
  local_14 = 0x10;
  local_10 = 0x12;
  FUN_00401020(0x420f58);
  do {
    iVar1 = thunk_FUN_0040cafc();
    if (iVar1 == 10) break;
  } while (iVar1 != -1);
  pFVar2 = (FILE *)FUN_00404989(0);
  iVar1 = FUN_004068b4(local_68,0x32,pFVar2);
  if ((iVar1 == 0) || (iVar1 = FUN_004010c0(local_68,"%u %u"), iVar1 != 1)) {
    if (local_8 != 0x4533) goto LAB_0040118a;
  }
  else {
    local_8 = iVar1;
LAB_0040118a:
    if (9 < local_c) {
      FUN_00401020(0x420f9c);
      goto LAB_004011be;
    }
  }
  FUN_00401020(0x420f90);
LAB_004011be:
                    // WARNING: Subroutine does not return
  _exit(1);
}



// WARNING: Removing unreachable block (ram,0x0040125c)

void FUN_004011d0(void)

{
  int iVar1;
  
  FUN_00401020(0x421184);
  do {
    FUN_00401020(0x4211ac);
    FUN_00401020(0x4211b8);
    FUN_00401020(0x4211c8);
    FUN_00401020(0x4211d8);
    FUN_00401020(0x4211e8);
    FUN_00401020(0x4211f8);
    FUN_00401050(0x420eac);
    do {
      iVar1 = thunk_FUN_0040cafc();
      if (iVar1 == 10) break;
    } while (iVar1 != -1);
    FUN_00401020(0x421210);
  } while( true );
}



// WARNING: Unable to track spacebase fully for stack

undefined4 FUN_00401560(void)

{
  code *pcVar1;
  byte bVar2;
  bool bVar3;
  char cVar4;
  void *_Dst;
  int iVar5;
  char *pcVar6;
  undefined4 uVar7;
  undefined4 *puVar8;
  undefined3 extraout_var;
  byte bVar9;
  undefined2 extraout_CX;
  int unaff_ESI;
  int unaff_EDI;
  undefined2 in_SS;
  undefined uVar10;
  undefined8 uVar11;
  undefined2 uVar13;
  int *piVar12;
  uint local_10;
  int local_c;
  int local_8;
  
  FUN_00401020(0x421230);
  FUN_00401020(0x421264);
  FUN_00401020(0x421280);
  FUN_00401020(0x42129c);
  FUN_00401020(0x4212b4);
  FUN_00401020(0x4212d8);
  FUN_00401020(0x4212fc);
  FUN_00401050(0x420eac);
  uVar10 = local_c - 1U < 4;
  switch(local_c - 1U) {
  case 0:
    puVar8 = (undefined4 *)FUN_0040cc35(4);
    *puVar8 = 0x7e8;
    FUN_00401020(0x420e58);
    FUN_0040caa5(puVar8);
    *puVar8 = 0x7e7;
    return 0;
  case 1:
    FUN_00401020(0x420e64);
    iVar5 = 0;
    do {
      FUN_00401020(0x420e80);
      iVar5 = iVar5 + 1;
    } while (iVar5 < 0x15);
    return 0;
  case 2:
    break;
  case 3:
    uVar13 = 0x40;
    uVar11 = FUN_004010f0();
    bVar9 = (byte)extraout_CX;
    bVar2 = (bVar9 & 0x1f) % 9;
    bRam16060040 = bRam16060040 << bVar2 | (byte)(CONCAT11(uVar10,bRam16060040) >> 9 - bVar2);
    *(char *)(unaff_ESI + 0x16) = *(char *)(unaff_ESI + 0x16) + bVar9;
    pcVar6 = (char *)(unaff_EDI + (int)((ulonglong)uVar11 >> 0x20));
    *pcVar6 = *pcVar6 + bVar9;
    iVar5 = (int)uVar11 + 3;
    piVar12 = (int *)CONCAT22(uVar13,in_SS);
    *(char *)(unaff_ESI + 0x6a) = *(char *)(unaff_ESI + 0x6a) + (char)((ulonglong)uVar11 >> 0x20);
    pcVar6 = (char *)(CONCAT31((int3)((uint)(&stack0xfffffffd +
                                            CONCAT22((short)((uint)iVar5 >> 0x10),
                                                     CONCAT11((char)((uint)iVar5 >> 8) + (char)iVar5
                                                              ,(char)iVar5))) >> 8),
                               (char)(&stack0xfffffffd +
                                     CONCAT22((short)((uint)iVar5 >> 0x10),
                                              CONCAT11((char)((uint)iVar5 >> 8) + (char)iVar5,
                                                       (char)iVar5))) +
                               (char)((ushort)extraout_CX >> 8)) ^ 5);
    *pcVar6 = *pcVar6 + (char)pcVar6;
    piVar12[-1] = (int)pcVar6;
    piVar12[-2] = 0x40173b;
    __set_fmode(piVar12[-1]);
    piVar12[-2] = 0x401740;
    uVar7 = FUN_00401c62();
    piVar12[-2] = 0x401747;
    puVar8 = (undefined4 *)FUN_0040d5cf();
    piVar12[-2] = 1;
    *puVar8 = uVar7;
    piVar12[-3] = 0x401750;
    uVar7 = ___scrt_initialize_onexit_tables(piVar12[-2]);
    if ((char)uVar7 != '\0') {
      piVar12[1] = 0x40175f;
      FUN_00401ea3();
      piVar12[1] = (int)FUN_00401ecf;
      *piVar12 = 0x401769;
      _atexit((_func_4879 *)piVar12[1]);
      *piVar12 = 0x40176e;
      iVar5 = FUN_00401c65();
      *piVar12 = iVar5;
      piVar12[-1] = 0x401774;
      iVar5 = FUN_0040d112(*piVar12);
      if (iVar5 == 0) {
        piVar12[1] = 0x40177f;
        FUN_00401c6f();
        piVar12[1] = 0x401784;
        bVar3 = FUN_00401cbf();
        if (CONCAT31(extraout_var,bVar3) != 0) {
          piVar12[1] = (int)FUN_00401c62;
          *piVar12 = 0x401792;
          ___setusermatherr((_func_void_void_ptr_ulong_void_ptr *)piVar12[1]);
        }
        piVar12[1] = 0x401798;
        _guard_check_icall();
        piVar12[1] = 0x40179d;
        _guard_check_icall();
        piVar12[1] = 0x4017a2;
        FUN_00401c7e();
        piVar12[1] = 0x4017a7;
        uVar7 = FUN_00401c62();
        piVar12[1] = uVar7;
        *piVar12 = 0x4017ad;
        __configthreadlocale(piVar12[1]);
        piVar12[1] = 0x4017b3;
        cVar4 = FUN_00401c7b();
        if (cVar4 != '\0') {
          piVar12[1] = (int)&LAB_004017bc;
          thunk_FUN_0040d149();
        }
        piVar12[1] = 0x4017c1;
        FUN_00401c62();
        piVar12[1] = 0x4017c6;
        iVar5 = thunk_FUN_00401c62();
        if (iVar5 == 0) {
          return 0;
        }
      }
    }
    piVar12[1] = 7;
    *piVar12 = 0x4017d2;
    FUN_00401cd7(piVar12[1]);
    pcVar1 = (code *)swi(3);
    uVar7 = (*pcVar1)();
    return uVar7;
  case 4:
    FUN_004011d0();
    return 0;
  default:
    FUN_00401020(0x421310);
    return 0;
  }
  FUN_00401020(0x420e84);
  FUN_00401050(0x420eac);
  _Dst = (void *)FUN_0040cc35(local_8 << 2);
  if (_Dst == (void *)0x0) {
    FUN_00401020(0x420eb0);
                    // WARNING: Subroutine does not return
    _exit(1);
  }
  FUN_00401020(0x420ecc);
  FUN_00401050(0x420eac);
  if (local_8 < (int)local_10) {
    FUN_00401020(0x420ef4);
                    // WARNING: Subroutine does not return
    _exit(1);
  }
  _memset(_Dst,0,local_10 >> 2);
  FUN_00401020(0x420f28);
  FUN_0040caa5(_Dst);
  return 0;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// Library Function - Single Match
//  int __cdecl __scrt_common_main_seh(void)
// 
// Library: Visual Studio 2019 Release

int __cdecl __scrt_common_main_seh(void)

{
  code *pcVar1;
  bool bVar2;
  undefined4 uVar3;
  int iVar4;
  code **ppcVar5;
  _func_void_void_ptr_ulong_void_ptr **pp_Var6;
  uint uVar7;
  int unaff_ESI;
  undefined4 uVar8;
  undefined4 uVar9;
  void *local_14;
  
  uVar3 = ___scrt_initialize_crt(1);
  if ((char)uVar3 != '\0') {
    bVar2 = false;
    uVar3 = ___scrt_acquire_startup_lock();
    if (DAT_00423908 != 1) {
      if (DAT_00423908 == 0) {
        DAT_00423908 = 1;
        iVar4 = __initterm_e((undefined **)&DAT_0041b12c,(undefined **)&DAT_0041b148);
        if (iVar4 != 0) {
          ExceptionList = local_14;
          return 0xff;
        }
        FUN_0040d3dc((undefined **)&DAT_0041b120,(undefined **)&DAT_0041b128);
        DAT_00423908 = 2;
      }
      else {
        bVar2 = true;
      }
      ___scrt_release_startup_lock((char)uVar3);
      ppcVar5 = (code **)FUN_00401ccb();
      if ((*ppcVar5 != (code *)0x0) &&
         (uVar3 = ___scrt_is_nonwritable_in_current_image((int)ppcVar5), (char)uVar3 != '\0')) {
        pcVar1 = *ppcVar5;
        uVar9 = 0;
        uVar8 = 2;
        uVar3 = 0;
        _guard_check_icall();
        (*pcVar1)(uVar3,uVar8,uVar9);
      }
      pp_Var6 = (_func_void_void_ptr_ulong_void_ptr **)FUN_00401cd1();
      if ((*pp_Var6 != (_func_void_void_ptr_ulong_void_ptr *)0x0) &&
         (uVar3 = ___scrt_is_nonwritable_in_current_image((int)pp_Var6), (char)uVar3 != '\0')) {
        __register_thread_local_exe_atexit_callback(*pp_Var6);
      }
      FID_conflict___get_initial_narrow_environment();
      FUN_0040d491();
      FUN_0040d48b();
      unaff_ESI = FUN_00401560();
      uVar7 = FUN_00401df7();
      if ((char)uVar7 != '\0') {
        if (!bVar2) {
          __cexit();
        }
        ___scrt_uninitialize_crt('\x01','\0');
        ExceptionList = local_14;
        return unaff_ESI;
      }
      goto LAB_00401960;
    }
  }
  FUN_00401cd7(7);
LAB_00401960:
                    // WARNING: Subroutine does not return
  _exit(unaff_ESI);
}



void entry(void)

{
  ___security_init_cookie();
  __scrt_common_main_seh();
  return;
}



// Library Function - Single Match
//  struct _IMAGE_SECTION_HEADER * __cdecl find_pe_section(unsigned char * const,unsigned int)
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

_IMAGE_SECTION_HEADER * __cdecl find_pe_section(uchar *param_1,uint param_2)

{
  int iVar1;
  _IMAGE_SECTION_HEADER *p_Var2;
  _IMAGE_SECTION_HEADER *p_Var3;
  
  iVar1 = *(int *)(param_1 + 0x3c);
  p_Var2 = (_IMAGE_SECTION_HEADER *)
           (param_1 + (uint)*(ushort *)(param_1 + iVar1 + 0x14) + iVar1 + 0x18);
  p_Var3 = p_Var2 + *(ushort *)(param_1 + iVar1 + 6);
  while( true ) {
    if (p_Var2 == p_Var3) {
      return (_IMAGE_SECTION_HEADER *)0x0;
    }
    if ((p_Var2->VirtualAddress <= param_2) &&
       (param_2 < (p_Var2->Misc).PhysicalAddress + p_Var2->VirtualAddress)) break;
    p_Var2 = p_Var2 + 1;
  }
  return p_Var2;
}



// Library Function - Single Match
//  ___scrt_acquire_startup_lock
// 
// Library: Visual Studio 2019 Release

uint ___scrt_acquire_startup_lock(void)

{
  void *pvVar1;
  bool bVar2;
  undefined3 extraout_var;
  void *pvVar3;
  
  bVar2 = ___scrt_is_ucrt_dll_in_use();
  pvVar3 = (void *)CONCAT31(extraout_var,bVar2);
  if (pvVar3 != (void *)0x0) {
    while( true ) {
      pvVar3 = (void *)0x0;
      LOCK();
      pvVar1 = StackBase;
      if (DAT_0042390c != (void *)0x0) {
        pvVar3 = DAT_0042390c;
        pvVar1 = DAT_0042390c;
      }
      DAT_0042390c = pvVar1;
      UNLOCK();
      if (pvVar3 == (void *)0x0) break;
      if (StackBase == pvVar3) {
        return CONCAT31((int3)((uint)pvVar3 >> 8),1);
      }
    }
  }
  return (uint)pvVar3 & 0xffffff00;
}



// Library Function - Single Match
//  ___scrt_initialize_crt
// 
// Library: Visual Studio 2019 Release

uint __cdecl ___scrt_initialize_crt(int param_1)

{
  uint uVar1;
  undefined4 uVar2;
  
  if (param_1 == 0) {
    DAT_00423910 = 1;
  }
  FUN_00401f45();
  uVar1 = ___vcrt_initialize();
  if ((char)uVar1 != '\0') {
    uVar2 = ___acrt_initialize();
    if ((char)uVar2 != '\0') {
      return CONCAT31((int3)((uint)uVar2 >> 8),1);
    }
    uVar1 = ___vcrt_uninitialize('\0');
  }
  return uVar1 & 0xffffff00;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  ___scrt_initialize_onexit_tables
// 
// Library: Visual Studio 2019 Release

undefined4 __cdecl ___scrt_initialize_onexit_tables(int param_1)

{
  code *pcVar1;
  bool bVar2;
  undefined4 in_EAX;
  undefined3 extraout_var;
  uint uVar3;
  undefined4 uVar4;
  
  if (DAT_00423911 != '\0') {
    return CONCAT31((int3)((uint)in_EAX >> 8),1);
  }
  if ((param_1 != 0) && (param_1 != 1)) {
    FUN_00401cd7(5);
    pcVar1 = (code *)swi(3);
    uVar4 = (*pcVar1)();
    return uVar4;
  }
  bVar2 = ___scrt_is_ucrt_dll_in_use();
  uVar3 = CONCAT31(extraout_var,bVar2);
  if ((uVar3 == 0) || (param_1 != 0)) {
    DAT_00423914 = 0xffffffff;
    _DAT_00423918 = 0xffffffff;
    _DAT_0042391c = 0xffffffff;
    _DAT_00423920 = 0xffffffff;
    _DAT_00423924 = 0xffffffff;
    _DAT_00423928 = 0xffffffff;
LAB_00401a9b:
    DAT_00423911 = '\x01';
    uVar3 = CONCAT31((int3)(uVar3 >> 8),1);
  }
  else {
    uVar3 = __initialize_onexit_table(&DAT_00423914);
    if (uVar3 == 0) {
      uVar3 = __initialize_onexit_table((int *)&DAT_00423920);
      if (uVar3 == 0) goto LAB_00401a9b;
    }
    uVar3 = uVar3 & 0xffffff00;
  }
  return uVar3;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// Library Function - Single Match
//  ___scrt_is_nonwritable_in_current_image
// 
// Library: Visual Studio 2019 Release

uint __cdecl ___scrt_is_nonwritable_in_current_image(int param_1)

{
  _IMAGE_SECTION_HEADER *p_Var1;
  uint uVar2;
  void *local_14;
  
  p_Var1 = find_pe_section((uchar *)&IMAGE_DOS_HEADER_00400000,param_1 - 0x400000);
  if ((p_Var1 == (_IMAGE_SECTION_HEADER *)0x0) || ((int)p_Var1->Characteristics < 0)) {
    uVar2 = (uint)p_Var1 & 0xffffff00;
  }
  else {
    uVar2 = CONCAT31((int3)((uint)p_Var1 >> 8),1);
  }
  ExceptionList = local_14;
  return uVar2;
}



// Library Function - Single Match
//  ___scrt_release_startup_lock
// 
// Library: Visual Studio 2019 Release

int __cdecl ___scrt_release_startup_lock(char param_1)

{
  int iVar1;
  bool bVar2;
  undefined3 extraout_var;
  int iVar3;
  
  bVar2 = ___scrt_is_ucrt_dll_in_use();
  iVar1 = DAT_0042390c;
  iVar3 = CONCAT31(extraout_var,bVar2);
  if ((iVar3 != 0) && (param_1 == '\0')) {
    LOCK();
    DAT_0042390c = 0;
    UNLOCK();
    iVar3 = iVar1;
  }
  return iVar3;
}



// Library Function - Single Match
//  ___scrt_uninitialize_crt
// 
// Library: Visual Studio 2019 Release

undefined4 __cdecl ___scrt_uninitialize_crt(char param_1,char param_2)

{
  undefined4 in_EAX;
  
  if ((DAT_00423910 == '\0') || (param_2 == '\0')) {
    ___acrt_uninitialize(param_1);
    in_EAX = ___vcrt_uninitialize(param_1);
  }
  return CONCAT31((int3)((uint)in_EAX >> 8),1);
}



// Library Function - Single Match
//  __onexit
// 
// Library: Visual Studio 2019 Release

_onexit_t __cdecl __onexit(_onexit_t _Func)

{
  int iVar1;
  
  if (DAT_00423914 == -1) {
    iVar1 = __crt_atexit(_Func);
  }
  else {
    iVar1 = __register_onexit_function(0x14,(char)_Func);
  }
  return (_onexit_t)(~-(uint)(iVar1 != 0) & (uint)_Func);
}



// Library Function - Single Match
//  _atexit
// 
// Library: Visual Studio 2019 Release

int __cdecl _atexit(_func_4879 *param_1)

{
  _onexit_t p_Var1;
  
  p_Var1 = __onexit((_onexit_t)param_1);
  return (p_Var1 != (_onexit_t)0x0) - 1;
}



// Library Function - Single Match
//  ___get_entropy
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

uint ___get_entropy(void)

{
  DWORD DVar1;
  LARGE_INTEGER local_18;
  _FILETIME local_10;
  uint local_8;
  
  local_10.dwLowDateTime = 0;
  local_10.dwHighDateTime = 0;
  GetSystemTimeAsFileTime(&local_10);
  local_8 = local_10.dwHighDateTime ^ local_10.dwLowDateTime;
  DVar1 = GetCurrentThreadId();
  local_8 = local_8 ^ DVar1;
  DVar1 = GetCurrentProcessId();
  local_8 = local_8 ^ DVar1;
  QueryPerformanceCounter(&local_18);
  return local_18.s.HighPart ^ local_18.s.LowPart ^ local_8 ^ (uint)&local_8;
}



// Library Function - Single Match
//  ___security_init_cookie
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __cdecl ___security_init_cookie(void)

{
  if ((DAT_00423014 == 0xbb40e64e) || ((DAT_00423014 & 0xffff0000) == 0)) {
    DAT_00423014 = ___get_entropy();
    if (DAT_00423014 == 0xbb40e64e) {
      DAT_00423014 = 0xbb40e64f;
    }
    else if ((DAT_00423014 & 0xffff0000) == 0) {
      DAT_00423014 = DAT_00423014 | (DAT_00423014 | 0x4711) << 0x10;
    }
  }
  DAT_00423018 = ~DAT_00423014;
  return;
}



undefined4 FUN_00401c62(void)

{
  return 0;
}



undefined4 FUN_00401c65(void)

{
  return 1;
}



undefined4 FUN_00401c69(void)

{
  return 0x4000;
}



void FUN_00401c6f(void)

{
  InitializeSListHead((PSLIST_HEADER)&DAT_00423930);
  return;
}



undefined FUN_00401c7b(void)

{
  return 1;
}



void FUN_00401c7e(void)

{
  code *pcVar1;
  errno_t eVar2;
  
  eVar2 = __controlfp_s((uint *)0x0,0x10000,0x30000);
  if (eVar2 == 0) {
    return;
  }
  FUN_00401cd7(7);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



void _guard_check_icall(void)

{
  return;
}



void FUN_00401ca2(void)

{
  uint *puVar1;
  
  puVar1 = (uint *)FUN_00401000();
  *puVar1 = *puVar1 | 0x24;
  puVar1[1] = puVar1[1];
  puVar1 = (uint *)FUN_00401010();
  *puVar1 = *puVar1 | 2;
  puVar1[1] = puVar1[1];
  return;
}



bool FUN_00401cbf(void)

{
  return DAT_00423004 == 0;
}



undefined * FUN_00401ccb(void)

{
  return &DAT_00424550;
}



undefined * FUN_00401cd1(void)

{
  return &DAT_0042454c;
}



void FUN_00401cd7(undefined4 param_1)

{
  code *pcVar1;
  BOOL BVar2;
  LONG LVar3;
  undefined4 local_328 [39];
  EXCEPTION_RECORD local_5c;
  _EXCEPTION_POINTERS local_c;
  
  BVar2 = IsProcessorFeaturePresent(0x17);
  if (BVar2 != 0) {
    pcVar1 = (code *)swi(0x29);
    (*pcVar1)();
  }
  FUN_00401e9b();
  _memset(local_328,0,0x2cc);
  local_328[0] = 0x10001;
  _memset(&local_5c,0,0x50);
  local_5c.ExceptionCode = 0x40000015;
  local_5c.ExceptionFlags = 1;
  BVar2 = IsDebuggerPresent();
  local_c.ExceptionRecord = &local_5c;
  local_c.ContextRecord = (PCONTEXT)local_328;
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0);
  LVar3 = UnhandledExceptionFilter(&local_c);
  if ((LVar3 == 0) && (BVar2 != 1)) {
    FUN_00401e9b();
  }
  return;
}



undefined4 thunk_FUN_00401c62(void)

{
  return 0;
}



uint FUN_00401df7(void)

{
  HMODULE pHVar1;
  int *piVar2;
  
  pHVar1 = GetModuleHandleW((LPCWSTR)0x0);
  if ((((pHVar1 != (HMODULE)0x0) && (*(short *)&pHVar1->unused == 0x5a4d)) &&
      (piVar2 = (int *)((int)&pHVar1->unused + pHVar1[0xf].unused), *piVar2 == 0x4550)) &&
     ((pHVar1 = (HMODULE)0x10b, *(short *)(piVar2 + 6) == 0x10b && (0xe < (uint)piVar2[0x1d])))) {
    return CONCAT31(1,piVar2[0x3a] != 0);
  }
  return (uint)pHVar1 & 0xffffff00;
}



// Library Function - Single Match
//  ___scrt_unhandled_exception_filter@4
// 
// Library: Visual Studio 2019 Release

undefined4 ___scrt_unhandled_exception_filter_4(int **param_1)

{
  int *piVar1;
  int iVar2;
  code *pcVar3;
  int **ppiVar4;
  undefined4 uVar5;
  
  piVar1 = *param_1;
  if (((*piVar1 == -0x1f928c9d) && (piVar1[4] == 3)) &&
     ((iVar2 = piVar1[5], iVar2 == 0x19930520 ||
      (((iVar2 == 0x19930521 || (iVar2 == 0x19930522)) || (iVar2 == 0x1994000)))))) {
    ppiVar4 = (int **)FUN_00402617();
    *ppiVar4 = piVar1;
    piVar1 = param_1[1];
    ppiVar4 = (int **)FUN_00402620();
    *ppiVar4 = piVar1;
    _terminate();
    pcVar3 = (code *)swi(3);
    uVar5 = (*pcVar3)();
    return uVar5;
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00401e9b(void)

{
  _DAT_00423938 = 0;
  return;
}



// WARNING: Removing unreachable block (ram,0x00401eb3)
// WARNING: Removing unreachable block (ram,0x00401eb4)
// WARNING: Removing unreachable block (ram,0x00401eba)
// WARNING: Removing unreachable block (ram,0x00401ec4)
// WARNING: Removing unreachable block (ram,0x00401ecb)

void FUN_00401ea3(void)

{
  return;
}



// WARNING: Removing unreachable block (ram,0x00401edf)
// WARNING: Removing unreachable block (ram,0x00401ee0)
// WARNING: Removing unreachable block (ram,0x00401ee6)
// WARNING: Removing unreachable block (ram,0x00401ef0)
// WARNING: Removing unreachable block (ram,0x00401ef7)

void FUN_00401ecf(void)

{
  return;
}



// WARNING: This is an inlined function
// WARNING: Unable to track spacebase fully for stack
// WARNING: Variable defined which should be unmapped: param_2
// Library Function - Single Match
//  __SEH_prolog4
// 
// Library: Visual Studio

void __cdecl __SEH_prolog4(undefined4 param_1,int param_2)

{
  int iVar1;
  undefined4 unaff_EBX;
  undefined4 unaff_ESI;
  undefined4 unaff_EDI;
  undefined4 unaff_retaddr;
  uint auStack_1c [5];
  undefined local_8 [8];
  
  iVar1 = -param_2;
  *(undefined4 *)((int)auStack_1c + iVar1 + 0x10) = unaff_EBX;
  *(undefined4 *)((int)auStack_1c + iVar1 + 0xc) = unaff_ESI;
  *(undefined4 *)((int)auStack_1c + iVar1 + 8) = unaff_EDI;
  *(uint *)((int)auStack_1c + iVar1 + 4) = DAT_00423014 ^ (uint)&param_2;
  *(undefined4 *)((int)auStack_1c + iVar1) = unaff_retaddr;
  ExceptionList = local_8;
  return;
}



// WARNING: Removing unreachable block (ram,0x00401fb4)
// WARNING: Removing unreachable block (ram,0x00401f78)
// WARNING: Removing unreachable block (ram,0x0040202c)

undefined4 FUN_00401f45(void)

{
  int *piVar1;
  uint *puVar2;
  int iVar3;
  BOOL BVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint in_XCR0;
  
  DAT_0042393c = 0;
  DAT_00423010 = DAT_00423010 | 1;
  BVar4 = IsProcessorFeaturePresent(10);
  uVar5 = DAT_00423010;
  if (BVar4 != 0) {
    piVar1 = (int *)cpuid_basic_info(0);
    puVar2 = (uint *)cpuid_Version_info(1);
    uVar6 = puVar2[3];
    if (((piVar1[2] ^ 0x49656e69U | piVar1[3] ^ 0x6c65746eU | piVar1[1] ^ 0x756e6547U) == 0) &&
       (((((uVar5 = *puVar2 & 0xfff3ff0, uVar5 == 0x106c0 || (uVar5 == 0x20660)) ||
          (uVar5 == 0x20670)) || ((uVar5 == 0x30650 || (uVar5 == 0x30660)))) || (uVar5 == 0x30670)))
       ) {
      DAT_00423940 = DAT_00423940 | 1;
    }
    if (*piVar1 < 7) {
      uVar7 = 0;
    }
    else {
      iVar3 = cpuid_Extended_Feature_Enumeration_info(7);
      uVar7 = *(uint *)(iVar3 + 4);
      if ((uVar7 & 0x200) != 0) {
        DAT_00423940 = DAT_00423940 | 2;
      }
    }
    DAT_0042393c = 1;
    uVar5 = DAT_00423010 | 2;
    if ((uVar6 & 0x100000) != 0) {
      uVar5 = DAT_00423010 | 6;
      DAT_0042393c = 2;
      if ((((uVar6 & 0x8000000) != 0) && ((uVar6 & 0x10000000) != 0)) && ((in_XCR0 & 6) == 6)) {
        DAT_0042393c = 3;
        uVar5 = DAT_00423010 | 0xe;
        if ((uVar7 & 0x20) != 0) {
          DAT_0042393c = 5;
          uVar5 = DAT_00423010 | 0x2e;
          if (((uVar7 & 0xd0030000) == 0xd0030000) && ((in_XCR0 & 0xe0) == 0xe0)) {
            DAT_00423010 = DAT_00423010 | 0x6e;
            DAT_0042393c = 6;
            uVar5 = DAT_00423010;
          }
        }
      }
    }
  }
  DAT_00423010 = uVar5;
  return 0;
}



// Library Function - Single Match
//  ___scrt_is_ucrt_dll_in_use
// 
// Library: Visual Studio 2019 Release

bool ___scrt_is_ucrt_dll_in_use(void)

{
  return DAT_00424548 != 0;
}



void __fastcall FUN_00402125(int param_1)

{
  undefined1 in_stack_00000004;
  
  if (param_1 == DAT_00423014) {
    return;
  }
  FUN_0040215b(in_stack_00000004);
  return;
}



void __cdecl FUN_00402133(_EXCEPTION_POINTERS *param_1)

{
  HANDLE hProcess;
  UINT uExitCode;
  
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0);
  UnhandledExceptionFilter(param_1);
  uExitCode = 0xc0000409;
  hProcess = GetCurrentProcess();
  TerminateProcess(hProcess,uExitCode);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_0040215b(undefined param_1)

{
  code *pcVar1;
  uint uVar2;
  undefined4 extraout_ECX;
  undefined4 extraout_ECX_00;
  undefined4 uVar3;
  undefined4 extraout_EDX;
  undefined4 unaff_EBX;
  undefined4 unaff_EBP;
  undefined4 unaff_ESI;
  undefined4 unaff_EDI;
  undefined2 in_ES;
  undefined2 in_CS;
  undefined2 in_SS;
  undefined2 in_DS;
  undefined2 in_FS;
  undefined2 in_GS;
  byte bVar4;
  byte bVar5;
  byte in_AF;
  byte bVar6;
  byte bVar7;
  byte in_TF;
  byte in_IF;
  byte bVar8;
  byte in_NT;
  byte in_AC;
  byte in_VIF;
  byte in_VIP;
  byte in_ID;
  undefined8 uVar9;
  undefined4 unaff_retaddr;
  
  uVar2 = IsProcessorFeaturePresent(0x17);
  uVar9 = CONCAT44(extraout_EDX,uVar2);
  bVar4 = 0;
  bVar8 = 0;
  bVar7 = (int)uVar2 < 0;
  bVar6 = uVar2 == 0;
  bVar5 = (POPCOUNT(uVar2 & 0xff) & 1U) == 0;
  uVar3 = extraout_ECX;
  if (!(bool)bVar6) {
    pcVar1 = (code *)swi(0x29);
    uVar9 = (*pcVar1)();
    uVar3 = extraout_ECX_00;
  }
  _DAT_00423a40 = (undefined4)((ulonglong)uVar9 >> 0x20);
  _DAT_00423a48 = (undefined4)uVar9;
  _DAT_00423a58 =
       (uint)(in_NT & 1) * 0x4000 | (uint)(bVar8 & 1) * 0x800 | (uint)(in_IF & 1) * 0x200 |
       (uint)(in_TF & 1) * 0x100 | (uint)(bVar7 & 1) * 0x80 | (uint)(bVar6 & 1) * 0x40 |
       (uint)(in_AF & 1) * 0x10 | (uint)(bVar5 & 1) * 4 | (uint)(bVar4 & 1) |
       (uint)(in_ID & 1) * 0x200000 | (uint)(in_VIP & 1) * 0x100000 | (uint)(in_VIF & 1) * 0x80000 |
       (uint)(in_AC & 1) * 0x40000;
  _DAT_00423a5c = &param_1;
  _DAT_00423998 = 0x10001;
  _DAT_00423948 = 0xc0000409;
  _DAT_0042394c = 1;
  _DAT_00423958 = 1;
  DAT_0042395c = 2;
  _DAT_00423954 = unaff_retaddr;
  _DAT_00423a24 = in_GS;
  _DAT_00423a28 = in_FS;
  _DAT_00423a2c = in_ES;
  _DAT_00423a30 = in_DS;
  _DAT_00423a34 = unaff_EDI;
  _DAT_00423a38 = unaff_ESI;
  _DAT_00423a3c = unaff_EBX;
  _DAT_00423a44 = uVar3;
  _DAT_00423a4c = unaff_EBP;
  DAT_00423a50 = unaff_retaddr;
  _DAT_00423a54 = in_CS;
  _DAT_00423a60 = in_SS;
  FUN_00402133((_EXCEPTION_POINTERS *)&PTR_DAT_0041b170);
  return;
}



// Library Function - Single Match
//  _ValidateLocalCookies
// 
// Library: Visual Studio 2019 Release

void __cdecl _ValidateLocalCookies(int *param_1,int param_2)

{
  if (*param_1 != -2) {
    FUN_00402125(param_1[1] + param_2 ^ *(uint *)(*param_1 + param_2));
  }
  FUN_00402125(param_1[3] + param_2 ^ *(uint *)(param_1[2] + param_2));
  return;
}



// Library Function - Single Match
//  __except_handler4
// 
// Library: Visual Studio 2019 Release

undefined4 __cdecl __except_handler4(PEXCEPTION_RECORD param_1,PVOID param_2,int param_3)

{
  uint uVar1;
  code *pcVar2;
  DWORD DVar3;
  int iVar4;
  BOOL BVar5;
  undefined4 uVar6;
  int iVar7;
  uint uVar8;
  PEXCEPTION_RECORD pEVar9;
  PEXCEPTION_RECORD local_20;
  int local_1c;
  int *local_18;
  int local_14;
  undefined4 local_10;
  int *local_c;
  char local_5;
  
  local_5 = '\0';
  local_10 = 1;
  DVar3 = __filter_x86_sse2_floating_point_exception_default(param_1->ExceptionCode);
  param_1->ExceptionCode = DVar3;
  iVar7 = (int)param_2 + 0x10;
  local_c = (int *)(*(uint *)((int)param_2 + 8) ^ DAT_00423014);
  local_14 = iVar7;
  _ValidateLocalCookies(local_c,iVar7);
  ___except_validate_context_record(param_3);
  uVar8 = *(uint *)((int)param_2 + 0xc);
  if ((*(byte *)&param_1->ExceptionFlags & 0x66) == 0) {
    local_20 = param_1;
    local_1c = param_3;
    *(PEXCEPTION_RECORD **)((int)param_2 + -4) = &local_20;
    if (uVar8 == 0xfffffffe) {
      return local_10;
    }
    do {
      iVar4 = uVar8 * 3 + 4;
      uVar1 = local_c[iVar4];
      local_18 = local_c + iVar4;
      if ((undefined *)local_18[1] != (undefined *)0x0) {
        iVar4 = __EH4_CallFilterFunc_8((undefined *)local_18[1]);
        local_5 = '\x01';
        if (iVar4 < 0) {
          local_10 = 0;
          goto LAB_00402364;
        }
        if (0 < iVar4) {
          if ((param_1->ExceptionCode == 0xe06d7363) &&
             (BVar5 = __IsNonwritableInCurrentImage((PBYTE)&PTR____DestructExceptionObject_0041b178)
             , BVar5 != 0)) {
            pEVar9 = param_1;
            _guard_check_icall();
            ___DestructExceptionObject((int *)pEVar9);
            iVar7 = local_14;
          }
          __EH4_GlobalUnwind2_8(param_2,param_1);
          if (*(uint *)((int)param_2 + 0xc) != uVar8) {
            __EH4_LocalUnwind_16((int)param_2,uVar8,iVar7,&DAT_00423014);
          }
          *(uint *)((int)param_2 + 0xc) = uVar1;
          _ValidateLocalCookies(local_c,iVar7);
          __EH4_TransferToHandler_8((undefined *)local_18[2]);
          pcVar2 = (code *)swi(3);
          uVar6 = (*pcVar2)();
          return uVar6;
        }
      }
      uVar8 = uVar1;
    } while (uVar1 != 0xfffffffe);
    if (local_5 == '\0') {
      return local_10;
    }
  }
  else {
    if (uVar8 == 0xfffffffe) {
      return local_10;
    }
    __EH4_LocalUnwind_16((int)param_2,0xfffffffe,iVar7,&DAT_00423014);
  }
LAB_00402364:
  _ValidateLocalCookies(local_c,iVar7);
  return local_10;
}



// Library Function - Single Match
//  ___vcrt_initialize
// 
// Library: Visual Studio 2019 Release

uint ___vcrt_initialize(void)

{
  uint uVar1;
  undefined4 uVar2;
  
  uVar1 = ___vcrt_initialize_locks();
  if ((char)uVar1 != '\0') {
    uVar2 = ___vcrt_initialize_ptd();
    if ((char)uVar2 != '\0') {
      return CONCAT31((int3)((uint)uVar2 >> 8),1);
    }
    uVar1 = ___vcrt_uninitialize_locks();
  }
  return uVar1 & 0xffffff00;
}



// Library Function - Single Match
//  ___vcrt_uninitialize
// 
// Library: Visual Studio 2019 Release

undefined4 __cdecl ___vcrt_uninitialize(char param_1)

{
  undefined4 in_EAX;
  
  if (param_1 == '\0') {
    ___vcrt_uninitialize_ptd();
    in_EAX = ___vcrt_uninitialize_locks();
  }
  return CONCAT31((int3)((uint)in_EAX >> 8),1);
}



// Library Function - Single Match
//  ___std_type_info_compare
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

uint __cdecl ___std_type_info_compare(int param_1,int param_2)

{
  byte bVar1;
  byte *pbVar2;
  byte *pbVar3;
  bool bVar4;
  
  if (param_1 != param_2) {
    pbVar3 = (byte *)(param_2 + 5);
    pbVar2 = (byte *)(param_1 + 5);
    do {
      bVar1 = *pbVar2;
      bVar4 = bVar1 < *pbVar3;
      if (bVar1 != *pbVar3) {
LAB_00402469:
        return -(uint)bVar4 | 1;
      }
      if (bVar1 == 0) {
        return 0;
      }
      bVar1 = pbVar2[1];
      bVar4 = bVar1 < pbVar3[1];
      if (bVar1 != pbVar3[1]) goto LAB_00402469;
      pbVar2 = pbVar2 + 2;
      pbVar3 = pbVar3 + 2;
    } while (bVar1 != 0);
  }
  return 0;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// Library Function - Single Match
//  ___DestructExceptionObject
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __cdecl ___DestructExceptionObject(int *param_1)

{
  byte *pbVar1;
  code *pcVar2;
  int *piVar3;
  void *local_14;
  
  if ((((param_1 != (int *)0x0) && (*param_1 == -0x1f928c9d)) && (param_1[4] == 3)) &&
     ((((param_1[5] == 0x19930520 || (param_1[5] == 0x19930521)) || (param_1[5] == 0x19930522)) &&
      (pbVar1 = (byte *)param_1[7], pbVar1 != (byte *)0x0)))) {
    if (*(void **)(pbVar1 + 4) == (void *)0x0) {
      if (((*pbVar1 & 0x10) != 0) && (piVar3 = *(int **)param_1[6], piVar3 != (int *)0x0)) {
        pcVar2 = *(code **)(*piVar3 + 8);
        _guard_check_icall();
        (*pcVar2)(piVar3);
      }
    }
    else {
      _CallMemberFunction0((void *)param_1[6],*(void **)(pbVar1 + 4));
    }
  }
  ExceptionList = local_14;
  return;
}



// Library Function - Single Match
//  void __stdcall _CallMemberFunction0(void * const,void * const)
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void _CallMemberFunction0(void *param_1,void *param_2)

{
  (*(code *)param_2)();
  return;
}



// Library Function - Single Match
//  unsigned long __cdecl _FilterSetCurrentException(struct _EXCEPTION_POINTERS *,unsigned char)
// 
// Library: Visual Studio 2019 Release

ulong __cdecl _FilterSetCurrentException(_EXCEPTION_POINTERS *param_1,uchar param_2)

{
  PEXCEPTION_RECORD pEVar1;
  PCONTEXT pCVar2;
  code *pcVar3;
  int iVar4;
  ulong uVar5;
  
  if ((((param_2 != '\0') &&
       (pEVar1 = param_1->ExceptionRecord, pEVar1->ExceptionCode == 0xe06d7363)) &&
      (pEVar1->NumberParameters == 3)) &&
     (((pEVar1->ExceptionInformation[0] == 0x19930520 ||
       (pEVar1->ExceptionInformation[0] == 0x19930521)) ||
      (pEVar1->ExceptionInformation[0] == 0x19930522)))) {
    iVar4 = ___vcrt_getptd();
    *(PEXCEPTION_RECORD *)(iVar4 + 0x10) = pEVar1;
    pCVar2 = param_1->ContextRecord;
    iVar4 = ___vcrt_getptd();
    *(PCONTEXT *)(iVar4 + 0x14) = pCVar2;
    _terminate();
    pcVar3 = (code *)swi(3);
    uVar5 = (*pcVar3)();
    return uVar5;
  }
  return 0;
}



// Library Function - Single Match
//  __IsExceptionObjectToBeDestroyed
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

undefined4 __cdecl __IsExceptionObjectToBeDestroyed(int param_1)

{
  int *piVar1;
  int iVar2;
  
  iVar2 = ___vcrt_getptd();
  piVar1 = *(int **)(iVar2 + 0x24);
  while( true ) {
    if (piVar1 == (int *)0x0) {
      return 1;
    }
    if (*piVar1 == param_1) break;
    piVar1 = (int *)piVar1[1];
  }
  return 0;
}



// Library Function - Single Match
//  ___AdjustPointer
// 
// Library: Visual Studio 2019 Release

int __cdecl ___AdjustPointer(int param_1,int *param_2)

{
  int iVar1;
  int iVar2;
  
  iVar1 = param_2[1];
  iVar2 = *param_2 + param_1;
  if (-1 < iVar1) {
    iVar2 = iVar2 + *(int *)(*(int *)(iVar1 + param_1) + param_2[2]) + iVar1;
  }
  return iVar2;
}



// Library Function - Single Match
//  ___FrameUnwindFilter
// 
// Library: Visual Studio 2019 Release

undefined4 __cdecl ___FrameUnwindFilter(int **param_1)

{
  int *piVar1;
  code *pcVar2;
  int iVar3;
  undefined4 uVar4;
  
  piVar1 = *param_1;
  if ((*piVar1 == -0x1fbcbcae) || (*piVar1 == -0x1fbcb0b3)) {
    iVar3 = ___vcrt_getptd();
    if (0 < *(int *)(iVar3 + 0x18)) {
      iVar3 = ___vcrt_getptd();
      *(int *)(iVar3 + 0x18) = *(int *)(iVar3 + 0x18) + -1;
    }
  }
  else if (*piVar1 == -0x1f928c9d) {
    iVar3 = ___vcrt_getptd();
    *(int **)(iVar3 + 0x10) = piVar1;
    piVar1 = param_1[1];
    iVar3 = ___vcrt_getptd();
    *(int **)(iVar3 + 0x14) = piVar1;
    _terminate();
    pcVar2 = (code *)swi(3);
    uVar4 = (*pcVar2)();
    return uVar4;
  }
  return 0;
}



int FUN_00402617(void)

{
  int iVar1;
  
  iVar1 = ___vcrt_getptd();
  return iVar1 + 0x10;
}



int FUN_00402620(void)

{
  int iVar1;
  
  iVar1 = ___vcrt_getptd();
  return iVar1 + 0x14;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4

void Unwind_00402629(void)

{
  code *pcVar1;
  __acrt_ptd *p_Var2;
  
  p_Var2 = FUN_004104a9();
  pcVar1 = *(code **)(p_Var2 + 0xc);
  if (pcVar1 != (code *)0x0) {
    _guard_check_icall();
    (*pcVar1)();
  }
                    // WARNING: Subroutine does not return
  _abort();
}



// Library Function - Single Match
//  _memset
// 
// Libraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual
// Studio 2019 Release

void * __cdecl _memset(void *_Dst,int _Val,size_t _Size)

{
  int iVar1;
  undefined *puVar2;
  int *piVar3;
  
  if (_Size == 0) {
    return _Dst;
  }
  iVar1 = (_Val & 0xffU) * 0x1010101;
  piVar3 = (int *)_Dst;
  if (0x20 < _Size) {
    if (0x7f < _Size) {
      puVar2 = (undefined *)_Dst;
      if ((DAT_00423940 >> 1 & 1) != 0) {
        for (; _Size != 0; _Size = _Size - 1) {
          *puVar2 = (char)iVar1;
          puVar2 = puVar2 + 1;
        }
        return _Dst;
      }
      if ((DAT_00423010 >> 1 & 1) == 0) goto joined_r0x0040273b;
      *(int *)_Dst = iVar1;
      *(int *)((int)_Dst + 4) = iVar1;
      *(int *)((int)_Dst + 8) = iVar1;
      *(int *)((int)_Dst + 0xc) = iVar1;
      piVar3 = (int *)((int)_Dst + 0x10U & 0xfffffff0);
      _Size = (int)_Dst + (_Size - (int)piVar3);
      if (0x80 < _Size) {
        do {
          *piVar3 = iVar1;
          piVar3[1] = iVar1;
          piVar3[2] = iVar1;
          piVar3[3] = iVar1;
          piVar3[4] = iVar1;
          piVar3[5] = iVar1;
          piVar3[6] = iVar1;
          piVar3[7] = iVar1;
          piVar3[8] = iVar1;
          piVar3[9] = iVar1;
          piVar3[10] = iVar1;
          piVar3[0xb] = iVar1;
          piVar3[0xc] = iVar1;
          piVar3[0xd] = iVar1;
          piVar3[0xe] = iVar1;
          piVar3[0xf] = iVar1;
          piVar3[0x10] = iVar1;
          piVar3[0x11] = iVar1;
          piVar3[0x12] = iVar1;
          piVar3[0x13] = iVar1;
          piVar3[0x14] = iVar1;
          piVar3[0x15] = iVar1;
          piVar3[0x16] = iVar1;
          piVar3[0x17] = iVar1;
          piVar3[0x18] = iVar1;
          piVar3[0x19] = iVar1;
          piVar3[0x1a] = iVar1;
          piVar3[0x1b] = iVar1;
          piVar3[0x1c] = iVar1;
          piVar3[0x1d] = iVar1;
          piVar3[0x1e] = iVar1;
          piVar3[0x1f] = iVar1;
          piVar3 = piVar3 + 0x20;
          _Size = _Size - 0x80;
        } while ((_Size & 0xffffff00) != 0);
        goto LAB_00402700;
      }
    }
    if ((DAT_00423010 >> 1 & 1) != 0) {
LAB_00402700:
      if (0x1f < _Size) {
        do {
          *piVar3 = iVar1;
          piVar3[1] = iVar1;
          piVar3[2] = iVar1;
          piVar3[3] = iVar1;
          piVar3[4] = iVar1;
          piVar3[5] = iVar1;
          piVar3[6] = iVar1;
          piVar3[7] = iVar1;
          piVar3 = piVar3 + 8;
          _Size = _Size - 0x20;
        } while (0x1f < _Size);
        if ((_Size & 0x1f) == 0) {
          return _Dst;
        }
      }
      piVar3 = (int *)((int)piVar3 + (_Size - 0x20));
      *piVar3 = iVar1;
      piVar3[1] = iVar1;
      piVar3[2] = iVar1;
      piVar3[3] = iVar1;
      piVar3[4] = iVar1;
      piVar3[5] = iVar1;
      piVar3[6] = iVar1;
      piVar3[7] = iVar1;
      return _Dst;
    }
  }
joined_r0x0040273b:
  for (; (_Size & 3) != 0; _Size = _Size - 1) {
    *(char *)piVar3 = (char)iVar1;
    piVar3 = (int *)((int)piVar3 + 1);
  }
  if ((_Size & 4) != 0) {
    *piVar3 = iVar1;
    piVar3 = piVar3 + 1;
    _Size = _Size - 4;
  }
  for (; (_Size & 0xfffffff8) != 0; _Size = _Size - 8) {
    *piVar3 = iVar1;
    piVar3[1] = iVar1;
    piVar3 = piVar3 + 2;
  }
  return _Dst;
}



void __cdecl FUN_00402790(uint *param_1,int param_2,uint param_3)

{
  undefined4 *puVar1;
  uint uVar2;
  void *pvStack_28;
  undefined *puStack_24;
  uint local_20;
  uint uStack_1c;
  int iStack_18;
  uint *puStack_14;
  
  puStack_14 = param_1;
  iStack_18 = param_2;
  uStack_1c = param_3;
  puStack_24 = &LAB_00402830;
  pvStack_28 = ExceptionList;
  local_20 = DAT_00423014 ^ (uint)&pvStack_28;
  ExceptionList = &pvStack_28;
  while( true ) {
    uVar2 = *(uint *)(param_2 + 0xc);
    if ((uVar2 == 0xfffffffe) || ((param_3 != 0xfffffffe && (uVar2 <= param_3)))) break;
    puVar1 = (undefined4 *)((*(uint *)(param_2 + 8) ^ *param_1) + 0x10 + uVar2 * 0xc);
    *(undefined4 *)(param_2 + 0xc) = *puVar1;
    if (puVar1[1] == 0) {
      __NLG_Notify(0x101);
      FUN_00402ad0();
    }
  }
  ExceptionList = pvStack_28;
  return;
}



// Library Function - Single Match
//  @_EH4_CallFilterFunc@8
// 
// Library: Visual Studio 2019 Release

void __fastcall __EH4_CallFilterFunc_8(undefined *param_1)

{
  (*(code *)param_1)();
  return;
}



// Library Function - Single Match
//  @_EH4_TransferToHandler@8
// 
// Library: Visual Studio 2019 Release

void __fastcall __EH4_TransferToHandler_8(undefined *UNRECOVERED_JUMPTABLE)

{
  __NLG_Notify(1);
                    // WARNING: Could not recover jumptable at 0x004028b7. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)UNRECOVERED_JUMPTABLE)();
  return;
}



// Library Function - Single Match
//  @_EH4_GlobalUnwind2@8
// 
// Library: Visual Studio 2019 Release

void __fastcall __EH4_GlobalUnwind2_8(PVOID param_1,PEXCEPTION_RECORD param_2)

{
  RtlUnwind(param_1,(PVOID)0x4028d5,param_2,(PVOID)0x0);
  return;
}



// Library Function - Single Match
//  @_EH4_LocalUnwind@16
// 
// Library: Visual Studio 2019 Release

void __fastcall __EH4_LocalUnwind_16(int param_1,uint param_2,undefined4 param_3,uint *param_4)

{
  FUN_00402790(param_4,param_1,param_2);
  return;
}



// WARNING: Removing unreachable block (ram,0x00402906)
// WARNING: Removing unreachable block (ram,0x0040291b)
// WARNING: Removing unreachable block (ram,0x00402920)
// Library Function - Single Match
//  ___except_validate_context_record
// 
// Library: Visual Studio 2019 Release

void __cdecl ___except_validate_context_record(int param_1)

{
  return;
}



void FUN_00402927(undefined *param_1)

{
  if ((param_1 != (undefined *)0x0) && (param_1 != &DAT_00423c68)) {
    FUN_0040caa5(param_1);
  }
  return;
}



// Library Function - Single Match
//  ___vcrt_getptd
// 
// Library: Visual Studio 2019 Release

void ___vcrt_getptd(void)

{
  code *pcVar1;
  LPVOID pvVar2;
  int iVar3;
  BOOL BVar4;
  
  pvVar2 = ___vcrt_getptd_noexit();
  if (pvVar2 != (LPVOID)0x0) {
    return;
  }
  iVar3 = ___acrt_get_sigabrt_handler();
  if (iVar3 != 0) {
    FUN_004130c4(0x16);
  }
  if ((DAT_004230e8 & 2) != 0) {
    BVar4 = IsProcessorFeaturePresent(0x17);
    if (BVar4 != 0) {
      pcVar1 = (code *)swi(0x29);
      (*pcVar1)();
    }
    ___acrt_call_reportfault(3,0x40000015,1);
  }
  __exit(3);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



// Library Function - Single Match
//  ___vcrt_getptd_noexit
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

LPVOID ___vcrt_getptd_noexit(void)

{
  DWORD dwErrCode;
  LPVOID pvVar1;
  int iVar2;
  LPVOID pvVar3;
  LPVOID pvVar4;
  
  if (DAT_00423020 == 0xffffffff) {
    return (LPVOID)0x0;
  }
  dwErrCode = GetLastError();
  pvVar1 = (LPVOID)___vcrt_FlsGetValue(DAT_00423020);
  if (pvVar1 == (LPVOID)0xffffffff) {
LAB_00402991:
    pvVar1 = (LPVOID)0x0;
    goto LAB_004029d7;
  }
  if (pvVar1 != (LPVOID)0x0) goto LAB_004029d7;
  iVar2 = ___vcrt_FlsSetValue(DAT_00423020,(LPVOID)0xffffffff);
  if (iVar2 == 0) goto LAB_00402991;
  pvVar3 = (LPVOID)FUN_0040db8d(1,0x28);
  if (pvVar3 == (LPVOID)0x0) {
LAB_004029b9:
    ___vcrt_FlsSetValue(DAT_00423020,(LPVOID)0x0);
    pvVar1 = (LPVOID)0x0;
    pvVar4 = pvVar3;
  }
  else {
    iVar2 = ___vcrt_FlsSetValue(DAT_00423020,pvVar3);
    if (iVar2 == 0) goto LAB_004029b9;
    pvVar4 = (LPVOID)0x0;
    pvVar1 = pvVar3;
  }
  FUN_0040caa5(pvVar4);
LAB_004029d7:
  SetLastError(dwErrCode);
  return pvVar1;
}



// Library Function - Single Match
//  ___vcrt_initialize_ptd
// 
// Library: Visual Studio 2019 Release

uint ___vcrt_initialize_ptd(void)

{
  uint uVar1;
  int iVar2;
  
  uVar1 = ___vcrt_FlsAlloc(FUN_00402927);
  DAT_00423020 = uVar1;
  if (uVar1 != 0xffffffff) {
    iVar2 = ___vcrt_FlsSetValue(uVar1,&DAT_00423c68);
    if (iVar2 != 0) {
      return CONCAT31((int3)((uint)iVar2 >> 8),1);
    }
    uVar1 = ___vcrt_uninitialize_ptd();
  }
  return uVar1 & 0xffffff00;
}



// Library Function - Single Match
//  ___vcrt_uninitialize_ptd
// 
// Library: Visual Studio 2019 Release

undefined4 ___vcrt_uninitialize_ptd(void)

{
  DWORD DVar1;
  
  DVar1 = DAT_00423020;
  if (DAT_00423020 != 0xffffffff) {
    DVar1 = ___vcrt_FlsFree(DAT_00423020);
    DAT_00423020 = 0xffffffff;
  }
  return CONCAT31((int3)(DVar1 >> 8),1);
}



// Library Function - Single Match
//  ___vcrt_initialize_locks
// 
// Library: Visual Studio 2019 Release

undefined4 ___vcrt_initialize_locks(void)

{
  int iVar1;
  uint uVar2;
  LPCRITICAL_SECTION p_Var3;
  
  p_Var3 = (LPCRITICAL_SECTION)&DAT_00423c90;
  uVar2 = 0;
  do {
    iVar1 = ___vcrt_InitializeCriticalSectionEx(p_Var3,4000,0);
    if (iVar1 == 0) {
      uVar2 = ___vcrt_uninitialize_locks();
      return uVar2 & 0xffffff00;
    }
    DAT_00423ca8 = DAT_00423ca8 + 1;
    uVar2 = uVar2 + 0x18;
    p_Var3 = p_Var3 + 1;
  } while (uVar2 < 0x18);
  return CONCAT31((int3)((uint)iVar1 >> 8),1);
}



// Library Function - Single Match
//  ___vcrt_uninitialize_locks
// 
// Library: Visual Studio 2019 Release

undefined4 ___vcrt_uninitialize_locks(void)

{
  undefined4 in_EAX;
  undefined4 extraout_EAX;
  int iVar1;
  LPCRITICAL_SECTION lpCriticalSection;
  
  if (DAT_00423ca8 != 0) {
    lpCriticalSection = (LPCRITICAL_SECTION)(&DAT_00423c78 + DAT_00423ca8 * 0x18);
    iVar1 = DAT_00423ca8;
    do {
      DeleteCriticalSection(lpCriticalSection);
      DAT_00423ca8 = DAT_00423ca8 + -1;
      lpCriticalSection = lpCriticalSection + -1;
      iVar1 = iVar1 + -1;
      in_EAX = extraout_EAX;
    } while (iVar1 != 0);
  }
  return CONCAT31((int3)((uint)in_EAX >> 8),1);
}



undefined4 __fastcall FUN_00402aa0(undefined4 param_1)

{
  undefined4 in_EAX;
  undefined4 unaff_EBP;
  
  DAT_00423038 = param_1;
  DAT_00423034 = in_EAX;
  DAT_0042303c = unaff_EBP;
  return in_EAX;
}



// Library Function - Single Match
//  __NLG_Notify
// 
// Libraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual
// Studio 2019 Release

void __NLG_Notify(ulong param_1)

{
  undefined4 in_EAX;
  undefined4 unaff_EBP;
  
  DAT_00423038 = param_1;
  DAT_00423034 = in_EAX;
  DAT_0042303c = unaff_EBP;
  return;
}



void FUN_00402ad0(void)

{
  code *in_EAX;
  
  (*in_EAX)();
  return;
}



FARPROC __cdecl FUN_00402ad3(int param_1,LPCSTR param_2,int *param_3,int *param_4)

{
  FARPROC *ppFVar1;
  HINSTANCE__ **ppHVar2;
  HINSTANCE__ *pHVar3;
  int iVar4;
  FARPROC pFVar5;
  HMODULE hLibModule;
  
  ppFVar1 = (FARPROC *)(&DAT_00423cf4 + param_1 * 4);
  pFVar5 = *ppFVar1;
  if (pFVar5 == (FARPROC)0xffffffff) {
    pFVar5 = (FARPROC)0x0;
  }
  else if (pFVar5 == (FARPROC)0x0) {
    for (; param_3 != param_4; param_3 = param_3 + 1) {
      iVar4 = *param_3;
      hLibModule = *(HMODULE *)(&DAT_00423ce8 + iVar4 * 4);
      if (hLibModule == (HMODULE)0x0) {
        hLibModule = try_load_library_from_system_directory
                               ((wchar_t *)(&PTR_u_api_ms_win_core_fibers_l1_1_1_0041bb34)[iVar4]);
        ppHVar2 = (HINSTANCE__ **)(&DAT_00423ce8 + iVar4 * 4);
        if (hLibModule != (HINSTANCE__ *)0x0) {
          LOCK();
          pHVar3 = *ppHVar2;
          *ppHVar2 = hLibModule;
          UNLOCK();
          if (pHVar3 != (HINSTANCE__ *)0x0) {
            FreeLibrary(hLibModule);
          }
          goto LAB_00402b5c;
        }
        LOCK();
        *ppHVar2 = (HINSTANCE__ *)0xffffffff;
        UNLOCK();
      }
      else if (hLibModule != (HMODULE)0xffffffff) {
LAB_00402b5c:
        pFVar5 = GetProcAddress(hLibModule,param_2);
        if (pFVar5 != (FARPROC)0x0) {
          LOCK();
          *ppFVar1 = pFVar5;
          UNLOCK();
          return pFVar5;
        }
        break;
      }
    }
    LOCK();
    *ppFVar1 = (FARPROC)0xffffffff;
    UNLOCK();
    pFVar5 = (FARPROC)0x0;
  }
  return pFVar5;
}



// Library Function - Single Match
//  struct HINSTANCE__ * __cdecl try_load_library_from_system_directory(wchar_t const * const)
// 
// Library: Visual Studio 2019 Release

HINSTANCE__ * __cdecl try_load_library_from_system_directory(wchar_t *param_1)

{
  HINSTANCE__ *pHVar1;
  DWORD DVar2;
  int iVar3;
  HMODULE pHVar4;
  
  pHVar1 = LoadLibraryExW(param_1,(HANDLE)0x0,0x800);
  if (pHVar1 == (HMODULE)0x0) {
    DVar2 = GetLastError();
    if (DVar2 == 0x57) {
      iVar3 = _wcsncmp(param_1,L"api-ms-",7);
      if (iVar3 != 0) {
        pHVar4 = LoadLibraryExW(param_1,(HANDLE)0x0,0);
        return pHVar4;
      }
    }
    pHVar1 = (HINSTANCE__ *)0x0;
  }
  return pHVar1;
}



// Library Function - Single Match
//  ___vcrt_FlsAlloc
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __cdecl ___vcrt_FlsAlloc(undefined4 param_1)

{
  FARPROC pFVar1;
  
  pFVar1 = FUN_00402ad3(0,"FlsAlloc",(int *)&DAT_0041bbdc,(int *)"FlsAlloc");
  if (pFVar1 != (FARPROC)0x0) {
    _guard_check_icall();
    (*pFVar1)(param_1);
    return;
  }
                    // WARNING: Could not recover jumptable at 0x00402bf3. Too many branches
                    // WARNING: Treating indirect jump as call
  TlsAlloc();
  return;
}



// Library Function - Single Match
//  ___vcrt_FlsFree
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __cdecl ___vcrt_FlsFree(DWORD param_1)

{
  FARPROC pFVar1;
  
  pFVar1 = FUN_00402ad3(1,"FlsFree",(int *)&DAT_0041bbf0,(int *)"FlsFree");
  if (pFVar1 == (FARPROC)0x0) {
    TlsFree(param_1);
  }
  else {
    _guard_check_icall();
    (*pFVar1)();
  }
  return;
}



// Library Function - Single Match
//  ___vcrt_FlsGetValue
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __cdecl ___vcrt_FlsGetValue(DWORD param_1)

{
  FARPROC pFVar1;
  
  pFVar1 = FUN_00402ad3(2,"FlsGetValue",(int *)&DAT_0041bc00,(int *)"FlsGetValue");
  if (pFVar1 == (FARPROC)0x0) {
    TlsGetValue(param_1);
  }
  else {
    _guard_check_icall();
    (*pFVar1)();
  }
  return;
}



// Library Function - Single Match
//  ___vcrt_FlsSetValue
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __cdecl ___vcrt_FlsSetValue(DWORD param_1,LPVOID param_2)

{
  FARPROC pFVar1;
  
  pFVar1 = FUN_00402ad3(3,"FlsSetValue",(int *)&DAT_0041bc14,(int *)"FlsSetValue");
  if (pFVar1 == (FARPROC)0x0) {
    TlsSetValue(param_1,param_2);
  }
  else {
    _guard_check_icall();
    (*pFVar1)();
  }
  return;
}



// Library Function - Single Match
//  ___vcrt_InitializeCriticalSectionEx
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __cdecl
___vcrt_InitializeCriticalSectionEx(LPCRITICAL_SECTION param_1,DWORD param_2,undefined4 param_3)

{
  FARPROC pFVar1;
  
  pFVar1 = FUN_00402ad3(4,"InitializeCriticalSectionEx",(int *)&DAT_0041bc28,
                        (int *)"InitializeCriticalSectionEx");
  if (pFVar1 == (FARPROC)0x0) {
    InitializeCriticalSectionAndSpinCount(param_1,param_2);
  }
  else {
    _guard_check_icall();
    (*pFVar1)(param_1,param_2,param_3);
  }
  return;
}



// Library Function - Single Match
//  public: static struct std::pair<class __FrameHandler3::TryBlockMap::iterator,class
// __FrameHandler3::TryBlockMap::iterator> __cdecl __FrameHandler3::GetRangeOfTrysToCheck(class
// __FrameHandler3::TryBlockMap &,int,void *,struct _s_FuncInfo const *,int)
// 
// Library: Visual Studio 2019 Release

pair<> __cdecl
__FrameHandler3::GetRangeOfTrysToCheck
          (TryBlockMap *param_1,int param_2,void *param_3,_s_FuncInfo *param_4,int param_5)

{
  uint uVar1;
  int *piVar2;
  uint uVar3;
  uint uVar4;
  int in_stack_00000018;
  uint local_8;
  
  uVar1 = *(uint *)(param_5 + 0xc);
  uVar3 = uVar1;
  uVar4 = uVar1;
  if (-1 < in_stack_00000018) {
    piVar2 = (int *)(uVar1 * 0x14 + *(int *)(param_5 + 0x10) + 8);
    local_8 = uVar1;
    do {
      if (uVar3 == 0xffffffff) goto LAB_00402d5e;
      uVar3 = uVar3 - 1;
      if (((piVar2[-6] < (int)param_3) && ((int)param_3 <= piVar2[-5])) || (uVar3 == 0xffffffff)) {
        in_stack_00000018 = in_stack_00000018 + -1;
        uVar4 = local_8;
        local_8 = uVar3;
      }
      piVar2 = piVar2 + -5;
    } while (-1 < in_stack_00000018);
  }
  if ((uVar4 <= uVar1) && (uVar3 + 1 <= uVar4)) {
    *(uint *)(param_1 + 0xc) = uVar4;
    *(int *)param_1 = param_2;
    *(uint *)(param_1 + 4) = uVar3 + 1;
    *(int *)(param_1 + 8) = param_2;
    return SUB41(param_1,0);
  }
LAB_00402d5e:
                    // WARNING: Subroutine does not return
  _abort();
}



undefined4 __cdecl
FUN_00402d64(undefined4 param_1,undefined4 param_2,undefined4 param_3,int param_4,int param_5)

{
  undefined4 uVar1;
  void *local_1c;
  code *local_18;
  uint local_14;
  undefined4 local_10;
  undefined4 local_c;
  int local_8;
  
  local_14 = (uint)&local_1c ^ DAT_00423014;
  local_10 = param_2;
  local_8 = param_4 + 1;
  local_18 = FUN_00402f3a;
  local_c = param_1;
  local_1c = ExceptionList;
  ExceptionList = &local_1c;
  uVar1 = __CallSettingFrame_12(param_3,param_1,param_5);
  ExceptionList = local_1c;
  return uVar1;
}



undefined4 __cdecl
FUN_00402dc1(int *param_1,undefined4 *param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,undefined4 param_7)

{
  int iVar1;
  undefined4 *local_44;
  code *local_40;
  uint local_3c;
  undefined4 local_38;
  undefined4 *local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined *local_28;
  undefined *local_24;
  int local_20;
  int *local_1c;
  undefined4 local_18;
  code *local_14;
  code *local_10;
  undefined4 local_c;
  code *local_8;
  
  local_24 = &stack0xfffffffc;
  local_28 = &stack0xffffffb8;
  if (param_1 == (int *)0x123) {
    *param_2 = 0x402e8b;
    local_c = 1;
  }
  else {
    local_40 = FID_conflict_TranslatorGuardHandler;
    local_3c = DAT_00423014 ^ (uint)&local_44;
    local_38 = param_5;
    local_34 = param_2;
    local_30 = param_6;
    local_2c = param_7;
    local_20 = 0;
    local_44 = (undefined4 *)ExceptionList;
    ExceptionList = &local_44;
    iVar1 = __filter_x86_sse2_floating_point_exception_default(*param_1);
    *param_1 = iVar1;
    local_c = 1;
    local_1c = param_1;
    local_18 = param_3;
    iVar1 = ___vcrt_getptd();
    local_8 = *(code **)(iVar1 + 8);
    local_10 = _guard_check_icall;
    _guard_check_icall();
    local_14 = local_8;
    (*local_8)(*param_1,&local_1c);
    local_c = 0;
    if (local_20 != 0) {
                    // WARNING: Load size is inaccurate
      *local_44 = *ExceptionList;
    }
    ExceptionList = local_44;
  }
  return local_c;
}



// Library Function - Single Match
//  void __stdcall _JumpToContinuation(void *,struct EHRegistrationNode *)
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void _JumpToContinuation(void *param_1,EHRegistrationNode *param_2)

{
                    // WARNING: Load size is inaccurate
  ExceptionList = *ExceptionList;
                    // WARNING: Could not recover jumptable at 0x00402ee0. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)param_1)();
  return;
}



// Library Function - Single Match
//  void __stdcall _UnwindNestedFrames(struct EHRegistrationNode *,struct EHExceptionRecord *)
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void _UnwindNestedFrames(EHRegistrationNode *param_1,EHExceptionRecord *param_2)

{
  void *pvVar1;
  
  pvVar1 = ExceptionList;
  RtlUnwind(param_1,(PVOID)0x402f11,(PEXCEPTION_RECORD)param_2,(PVOID)0x0);
  *(uint *)(param_2 + 4) = *(uint *)(param_2 + 4) & 0xfffffffd;
  *(void **)pvVar1 = ExceptionList;
  ExceptionList = pvVar1;
  return;
}



void __cdecl FUN_00402f3a(EHExceptionRecord *param_1,EHRegistrationNode *param_2,_CONTEXT *param_3)

{
  FUN_00402125(*(uint *)(param_2 + 8) ^ (uint)param_2);
  FUN_00403ee6(param_1,*(EHRegistrationNode **)(param_2 + 0x10),param_3,(void *)0x0,
               *(_s_FuncInfo **)(param_2 + 0xc),*(int *)(param_2 + 0x14),param_2,'\0');
  return;
}



// Library Function - Single Match
//  __CreateFrameInfo
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

undefined4 * __cdecl __CreateFrameInfo(undefined4 *param_1,undefined4 param_2)

{
  int iVar1;
  
  *param_1 = param_2;
  iVar1 = ___vcrt_getptd();
  param_1[1] = *(undefined4 *)(iVar1 + 0x24);
  iVar1 = ___vcrt_getptd();
  *(undefined4 **)(iVar1 + 0x24) = param_1;
  return param_1;
}



// Library Function - Single Match
//  __FindAndUnlinkFrame
// 
// Library: Visual Studio 2019 Release

void __cdecl __FindAndUnlinkFrame(int param_1)

{
  undefined4 uVar1;
  int iVar2;
  int *piVar3;
  
  iVar2 = ___vcrt_getptd();
  if (param_1 == *(int *)(iVar2 + 0x24)) {
    uVar1 = *(undefined4 *)(param_1 + 4);
    iVar2 = ___vcrt_getptd();
    *(undefined4 *)(iVar2 + 0x24) = uVar1;
  }
  else {
    iVar2 = ___vcrt_getptd();
    iVar2 = *(int *)(iVar2 + 0x24);
    do {
      piVar3 = (int *)(iVar2 + 4);
      iVar2 = *piVar3;
      if (iVar2 == 0) {
                    // WARNING: Subroutine does not return
        _abort();
      }
    } while (param_1 != iVar2);
    *piVar3 = *(int *)(param_1 + 4);
  }
  return;
}



// Library Function - Multiple Matches With Different Base Names
//  enum _EXCEPTION_DISPOSITION __cdecl TranslatorGuardHandler(struct EHExceptionRecord *,struct
// TranslatorGuardRN *,void *,void *)
//  __TranslatorGuardHandler
// 
// Libraries: Visual Studio 2012 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

undefined4 __cdecl
FID_conflict_TranslatorGuardHandler
          (EHExceptionRecord *param_1,EHRegistrationNode *param_2,_CONTEXT *param_3)

{
  undefined4 uVar1;
  code *local_8;
  
  FUN_00402125(*(uint *)(param_2 + 8) ^ (uint)param_2);
  if ((*(uint *)(param_1 + 4) & 0x66) != 0) {
    *(undefined4 *)(param_2 + 0x24) = 1;
    return 1;
  }
  FUN_00403ee6(param_1,*(EHRegistrationNode **)(param_2 + 0x10),param_3,(void *)0x0,
               *(_s_FuncInfo **)(param_2 + 0xc),*(int *)(param_2 + 0x14),
               *(EHRegistrationNode **)(param_2 + 0x18),'\x01');
  if (*(int *)(param_2 + 0x24) == 0) {
    _UnwindNestedFrames(param_2,param_1);
  }
  FUN_00402dc1((int *)0x123,&local_8,0,0,0,0,0);
                    // WARNING: Could not recover jumptable at 0x0040306c. Too many branches
                    // WARNING: Treating indirect jump as call
  uVar1 = (*local_8)();
  return uVar1;
}



// Library Function - Multiple Matches With Different Base Names
//  ___CxxFrameHandler
//  ___CxxFrameHandler2
//  ___CxxFrameHandler3
// 
// Library: Visual Studio

undefined4 __cdecl
FID_conflict____CxxFrameHandler3
          (EHExceptionRecord *param_1,EHRegistrationNode *param_2,_CONTEXT *param_3,void *param_4)

{
  _s_FuncInfo *in_EAX;
  undefined4 uVar1;
  
  uVar1 = FUN_00403ee6(param_1,param_2,param_3,param_4,in_EAX,0,(EHRegistrationNode *)0x0,'\0');
  return uVar1;
}



// Library Function - Multiple Matches With Different Base Names
//  _memcpy
//  _memmove
// 
// Libraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual
// Studio 2019 Release

void * __cdecl FID_conflict__memcpy(void *_Dst,void *_Src,size_t _Size)

{
  undefined8 uVar1;
  undefined auVar2 [32];
  undefined auVar3 [32];
  undefined4 uVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  undefined4 uVar8;
  undefined4 uVar9;
  undefined4 uVar10;
  undefined4 uVar11;
  undefined4 uVar12;
  undefined4 uVar13;
  undefined4 uVar14;
  undefined4 uVar15;
  undefined4 uVar16;
  undefined4 uVar17;
  undefined4 uVar18;
  undefined4 uVar19;
  undefined4 uVar20;
  undefined4 uVar21;
  undefined4 uVar22;
  undefined4 uVar23;
  undefined4 uVar24;
  undefined4 uVar25;
  undefined4 uVar26;
  undefined4 uVar27;
  undefined4 uVar28;
  undefined4 uVar29;
  undefined4 uVar30;
  undefined4 uVar31;
  int iVar32;
  undefined8 *puVar33;
  void *pvVar34;
  uint uVar35;
  size_t sVar36;
  uint uVar37;
  int iVar38;
  undefined8 *puVar39;
  undefined4 *puVar40;
  undefined *puVar41;
  undefined4 *puVar42;
  undefined4 *puVar43;
  undefined4 *puVar44;
  undefined4 uVar45;
  undefined4 uVar46;
  undefined4 uVar47;
  
  if ((_Src < _Dst) && (_Dst < (void *)(_Size + (int)_Src))) {
    puVar42 = (undefined4 *)((int)_Src + _Size);
    puVar43 = (undefined4 *)((int)_Dst + _Size);
    if (0x1f < _Size) {
      if ((DAT_00423010 >> 1 & 1) == 0) {
        if (((uint)puVar43 & 3) != 0) {
          uVar35 = (uint)puVar43 & 3;
          _Size = _Size - uVar35;
          do {
            *(undefined *)((int)puVar43 - 1) = *(undefined *)((int)puVar42 + -1);
            puVar42 = (undefined4 *)((int)puVar42 + -1);
            puVar43 = (undefined4 *)((int)puVar43 - 1);
            uVar35 = uVar35 - 1;
          } while (uVar35 != 0);
        }
        if (0x1f < _Size) {
          uVar35 = _Size >> 2;
          while( true ) {
            if (uVar35 == 0) break;
            uVar35 = uVar35 - 1;
            puVar43[-1] = puVar42[-1];
            puVar42 = puVar42 + -1;
            puVar43 = puVar43 + -1;
          }
          switch(_Size & 3) {
          case 0:
            return _Dst;
          case 1:
            *(undefined *)((int)puVar43 - 1) = *(undefined *)((int)puVar42 + -1);
            return _Dst;
          case 2:
            *(undefined *)((int)puVar43 - 1) = *(undefined *)((int)puVar42 + -1);
            *(undefined *)((int)puVar43 - 2) = *(undefined *)((int)puVar42 + -2);
            return _Dst;
          case 3:
            *(undefined *)((int)puVar43 - 1) = *(undefined *)((int)puVar42 + -1);
            *(undefined *)((int)puVar43 - 2) = *(undefined *)((int)puVar42 + -2);
            *(undefined *)((int)puVar43 - 3) = *(undefined *)((int)puVar42 + -3);
            return _Dst;
          }
        }
      }
      else {
        while (puVar40 = puVar42, puVar44 = puVar43, ((uint)puVar43 & 0xf) != 0) {
          _Size = _Size - 1;
          puVar42 = (undefined4 *)((int)puVar42 + -1);
          puVar43 = (undefined4 *)((int)puVar43 + -1);
          *(undefined *)puVar43 = *(undefined *)puVar42;
        }
        do {
          puVar42 = puVar40;
          puVar43 = puVar44;
          if (_Size < 0x80) break;
          puVar42 = puVar40 + -0x20;
          puVar43 = puVar44 + -0x20;
          uVar45 = puVar40[-0x1f];
          uVar46 = puVar40[-0x1e];
          uVar47 = puVar40[-0x1d];
          uVar4 = puVar40[-0x1c];
          uVar5 = puVar40[-0x1b];
          uVar6 = puVar40[-0x1a];
          uVar7 = puVar40[-0x19];
          uVar8 = puVar40[-0x18];
          uVar9 = puVar40[-0x17];
          uVar10 = puVar40[-0x16];
          uVar11 = puVar40[-0x15];
          uVar12 = puVar40[-0x14];
          uVar13 = puVar40[-0x13];
          uVar14 = puVar40[-0x12];
          uVar15 = puVar40[-0x11];
          uVar16 = puVar40[-0x10];
          uVar17 = puVar40[-0xf];
          uVar18 = puVar40[-0xe];
          uVar19 = puVar40[-0xd];
          uVar20 = puVar40[-0xc];
          uVar21 = puVar40[-0xb];
          uVar22 = puVar40[-10];
          uVar23 = puVar40[-9];
          uVar24 = puVar40[-8];
          uVar25 = puVar40[-7];
          uVar26 = puVar40[-6];
          uVar27 = puVar40[-5];
          uVar28 = puVar40[-4];
          uVar29 = puVar40[-3];
          uVar30 = puVar40[-2];
          uVar31 = puVar40[-1];
          *puVar43 = *puVar42;
          puVar44[-0x1f] = uVar45;
          puVar44[-0x1e] = uVar46;
          puVar44[-0x1d] = uVar47;
          puVar44[-0x1c] = uVar4;
          puVar44[-0x1b] = uVar5;
          puVar44[-0x1a] = uVar6;
          puVar44[-0x19] = uVar7;
          puVar44[-0x18] = uVar8;
          puVar44[-0x17] = uVar9;
          puVar44[-0x16] = uVar10;
          puVar44[-0x15] = uVar11;
          puVar44[-0x14] = uVar12;
          puVar44[-0x13] = uVar13;
          puVar44[-0x12] = uVar14;
          puVar44[-0x11] = uVar15;
          puVar44[-0x10] = uVar16;
          puVar44[-0xf] = uVar17;
          puVar44[-0xe] = uVar18;
          puVar44[-0xd] = uVar19;
          puVar44[-0xc] = uVar20;
          puVar44[-0xb] = uVar21;
          puVar44[-10] = uVar22;
          puVar44[-9] = uVar23;
          puVar44[-8] = uVar24;
          puVar44[-7] = uVar25;
          puVar44[-6] = uVar26;
          puVar44[-5] = uVar27;
          puVar44[-4] = uVar28;
          puVar44[-3] = uVar29;
          puVar44[-2] = uVar30;
          puVar44[-1] = uVar31;
          _Size = _Size - 0x80;
          puVar40 = puVar42;
          puVar44 = puVar43;
        } while ((_Size & 0xffffff80) != 0);
        puVar40 = puVar42;
        puVar44 = puVar43;
        if (0x1f < _Size) {
          do {
            puVar42 = puVar40 + -8;
            puVar43 = puVar44 + -8;
            uVar45 = puVar40[-7];
            uVar46 = puVar40[-6];
            uVar47 = puVar40[-5];
            uVar4 = puVar40[-4];
            uVar5 = puVar40[-3];
            uVar6 = puVar40[-2];
            uVar7 = puVar40[-1];
            *puVar43 = *puVar42;
            puVar44[-7] = uVar45;
            puVar44[-6] = uVar46;
            puVar44[-5] = uVar47;
            puVar44[-4] = uVar4;
            puVar44[-3] = uVar5;
            puVar44[-2] = uVar6;
            puVar44[-1] = uVar7;
            _Size = _Size - 0x20;
            puVar40 = puVar42;
            puVar44 = puVar43;
          } while ((_Size & 0xffffffe0) != 0);
        }
      }
    }
    for (; (_Size & 0xfffffffc) != 0; _Size = _Size - 4) {
      puVar43 = puVar43 + -1;
      puVar42 = puVar42 + -1;
      *puVar43 = *puVar42;
    }
    for (; _Size != 0; _Size = _Size - 1) {
      puVar43 = (undefined4 *)((int)puVar43 - 1);
      puVar42 = (undefined4 *)((int)puVar42 + -1);
      *(undefined *)puVar43 = *(undefined *)puVar42;
    }
    return _Dst;
  }
  sVar36 = _Size;
  puVar42 = (undefined4 *)_Dst;
  if (_Size < 0x20) goto LAB_004035ab;
  if (_Size < 0x80) {
    if ((DAT_00423010 >> 1 & 1) != 0) {
LAB_0040357d:
      if (sVar36 == 0) {
        return _Dst;
      }
      for (uVar35 = sVar36 >> 5; uVar35 != 0; uVar35 = uVar35 - 1) {
                    // WARNING: Load size is inaccurate
        uVar45 = *(undefined4 *)((int)_Src + 4);
        uVar46 = *(undefined4 *)((int)_Src + 8);
        uVar47 = *(undefined4 *)((int)_Src + 0xc);
        uVar4 = *(undefined4 *)((int)_Src + 0x10);
        uVar5 = *(undefined4 *)((int)_Src + 0x14);
        uVar6 = *(undefined4 *)((int)_Src + 0x18);
        uVar7 = *(undefined4 *)((int)_Src + 0x1c);
        *puVar42 = *_Src;
        puVar42[1] = uVar45;
        puVar42[2] = uVar46;
        puVar42[3] = uVar47;
        puVar42[4] = uVar4;
        puVar42[5] = uVar5;
        puVar42[6] = uVar6;
        puVar42[7] = uVar7;
        _Src = (void *)((int)_Src + 0x20);
        puVar42 = puVar42 + 8;
      }
      goto LAB_004035ab;
    }
LAB_004032d7:
    uVar35 = (uint)_Dst & 3;
    while (uVar35 != 0) {
                    // WARNING: Load size is inaccurate
      *(undefined *)puVar42 = *_Src;
      _Size = _Size - 1;
      _Src = (void *)((int)_Src + 1);
      puVar42 = (undefined4 *)((int)puVar42 + 1);
      uVar35 = (uint)puVar42 & 3;
    }
  }
  else {
    puVar41 = (undefined *)_Dst;
    if ((DAT_00423940 >> 1 & 1) != 0) {
                    // WARNING: Load size is inaccurate
      for (; _Size != 0; _Size = _Size - 1) {
        *puVar41 = *_Src;
        _Src = (undefined *)((int)_Src + 1);
        puVar41 = puVar41 + 1;
      }
      return _Dst;
    }
    if (((((uint)_Dst ^ (uint)_Src) & 0xf) == 0) && ((DAT_00423010 >> 1 & 1) != 0)) {
      if (((uint)_Src & 0xf) != 0) {
        uVar37 = 0x10 - ((uint)_Src & 0xf);
        _Size = _Size - uVar37;
        for (uVar35 = uVar37 & 3; uVar35 != 0; uVar35 = uVar35 - 1) {
                    // WARNING: Load size is inaccurate
          *(undefined *)puVar42 = *_Src;
          _Src = (void *)((int)_Src + 1);
          puVar42 = (undefined4 *)((int)puVar42 + 1);
        }
        for (uVar37 = uVar37 >> 2; uVar37 != 0; uVar37 = uVar37 - 1) {
                    // WARNING: Load size is inaccurate
          *puVar42 = *_Src;
          _Src = (void *)((int)_Src + 4);
          puVar42 = puVar42 + 1;
        }
      }
      sVar36 = _Size & 0x7f;
      for (uVar35 = _Size >> 7; uVar35 != 0; uVar35 = uVar35 - 1) {
                    // WARNING: Load size is inaccurate
        uVar45 = *(undefined4 *)((int)_Src + 4);
        uVar46 = *(undefined4 *)((int)_Src + 8);
        uVar47 = *(undefined4 *)((int)_Src + 0xc);
        uVar4 = *(undefined4 *)((int)_Src + 0x10);
        uVar5 = *(undefined4 *)((int)_Src + 0x14);
        uVar6 = *(undefined4 *)((int)_Src + 0x18);
        uVar7 = *(undefined4 *)((int)_Src + 0x1c);
        uVar8 = *(undefined4 *)((int)_Src + 0x20);
        uVar9 = *(undefined4 *)((int)_Src + 0x24);
        uVar10 = *(undefined4 *)((int)_Src + 0x28);
        uVar11 = *(undefined4 *)((int)_Src + 0x2c);
        uVar12 = *(undefined4 *)((int)_Src + 0x30);
        uVar13 = *(undefined4 *)((int)_Src + 0x34);
        uVar14 = *(undefined4 *)((int)_Src + 0x38);
        uVar15 = *(undefined4 *)((int)_Src + 0x3c);
        *puVar42 = *_Src;
        puVar42[1] = uVar45;
        puVar42[2] = uVar46;
        puVar42[3] = uVar47;
        puVar42[4] = uVar4;
        puVar42[5] = uVar5;
        puVar42[6] = uVar6;
        puVar42[7] = uVar7;
        puVar42[8] = uVar8;
        puVar42[9] = uVar9;
        puVar42[10] = uVar10;
        puVar42[0xb] = uVar11;
        puVar42[0xc] = uVar12;
        puVar42[0xd] = uVar13;
        puVar42[0xe] = uVar14;
        puVar42[0xf] = uVar15;
        uVar45 = *(undefined4 *)((int)_Src + 0x44);
        uVar46 = *(undefined4 *)((int)_Src + 0x48);
        uVar47 = *(undefined4 *)((int)_Src + 0x4c);
        uVar4 = *(undefined4 *)((int)_Src + 0x50);
        uVar5 = *(undefined4 *)((int)_Src + 0x54);
        uVar6 = *(undefined4 *)((int)_Src + 0x58);
        uVar7 = *(undefined4 *)((int)_Src + 0x5c);
        uVar8 = *(undefined4 *)((int)_Src + 0x60);
        uVar9 = *(undefined4 *)((int)_Src + 100);
        uVar10 = *(undefined4 *)((int)_Src + 0x68);
        uVar11 = *(undefined4 *)((int)_Src + 0x6c);
        uVar12 = *(undefined4 *)((int)_Src + 0x70);
        uVar13 = *(undefined4 *)((int)_Src + 0x74);
        uVar14 = *(undefined4 *)((int)_Src + 0x78);
        uVar15 = *(undefined4 *)((int)_Src + 0x7c);
        puVar42[0x10] = *(undefined4 *)((int)_Src + 0x40);
        puVar42[0x11] = uVar45;
        puVar42[0x12] = uVar46;
        puVar42[0x13] = uVar47;
        puVar42[0x14] = uVar4;
        puVar42[0x15] = uVar5;
        puVar42[0x16] = uVar6;
        puVar42[0x17] = uVar7;
        puVar42[0x18] = uVar8;
        puVar42[0x19] = uVar9;
        puVar42[0x1a] = uVar10;
        puVar42[0x1b] = uVar11;
        puVar42[0x1c] = uVar12;
        puVar42[0x1d] = uVar13;
        puVar42[0x1e] = uVar14;
        puVar42[0x1f] = uVar15;
        _Src = (void *)((int)_Src + 0x80);
        puVar42 = puVar42 + 0x20;
      }
      goto LAB_0040357d;
    }
    if (((DAT_00423940 & 1) == 0) || (((uint)_Dst & 3) != 0)) goto LAB_004032d7;
    if (((uint)_Src & 3) == 0) {
      if (((uint)_Dst >> 2 & 1) != 0) {
                    // WARNING: Load size is inaccurate
        uVar45 = *_Src;
        _Size = _Size - 4;
        _Src = (void *)((int)_Src + 4);
        *(undefined4 *)_Dst = uVar45;
        _Dst = (void *)((int)_Dst + 4);
      }
      if (((uint)_Dst >> 3 & 1) != 0) {
                    // WARNING: Load size is inaccurate
        uVar1 = *_Src;
        _Size = _Size - 8;
        _Src = (void *)((int)_Src + 8);
        *(undefined8 *)_Dst = uVar1;
        _Dst = (void *)((int)_Dst + 8);
      }
      if (((uint)_Src & 7) == 0) {
                    // WARNING: Load size is inaccurate
        puVar33 = (undefined8 *)((int)_Src + -8);
        uVar45 = *_Src;
        uVar46 = *(undefined4 *)((int)_Src + 4);
        do {
          puVar39 = puVar33;
          uVar5 = *(undefined4 *)(puVar39 + 4);
          uVar6 = *(undefined4 *)((int)puVar39 + 0x24);
          _Size = _Size - 0x30;
          auVar2 = *(undefined (*) [32])(puVar39 + 2);
          uVar47 = *(undefined4 *)(puVar39 + 7);
          uVar4 = *(undefined4 *)((int)puVar39 + 0x3c);
          auVar3 = *(undefined (*) [32])(puVar39 + 4);
          *(undefined4 *)((int)_Dst + 8) = uVar45;
          *(undefined4 *)((int)_Dst + 0xc) = uVar46;
          *(undefined4 *)((int)_Dst + 0x10) = uVar5;
          *(undefined4 *)((int)_Dst + 0x14) = uVar6;
          *(undefined (*) [16])((int)_Dst + 0x10) = auVar2._8_16_;
          *(undefined (*) [16])((int)_Dst + 0x20) = auVar3._8_16_;
          _Dst = (void *)((int)_Dst + 0x30);
          puVar33 = puVar39 + 6;
          uVar45 = uVar47;
          uVar46 = uVar4;
        } while (0x2f < _Size);
        puVar39 = puVar39 + 7;
      }
      else if (((uint)_Src >> 3 & 1) == 0) {
                    // WARNING: Load size is inaccurate
        iVar32 = (int)_Src + -4;
        uVar45 = *_Src;
        uVar46 = *(undefined4 *)((int)_Src + 4);
        uVar47 = *(undefined4 *)((int)_Src + 8);
        do {
          iVar38 = iVar32;
          uVar7 = *(undefined4 *)(iVar38 + 0x20);
          _Size = _Size - 0x30;
          auVar2 = *(undefined (*) [32])(iVar38 + 0x10);
          uVar4 = *(undefined4 *)(iVar38 + 0x34);
          uVar5 = *(undefined4 *)(iVar38 + 0x38);
          uVar6 = *(undefined4 *)(iVar38 + 0x3c);
          auVar3 = *(undefined (*) [32])(iVar38 + 0x20);
          *(undefined4 *)((int)_Dst + 4) = uVar45;
          *(undefined4 *)((int)_Dst + 8) = uVar46;
          *(undefined4 *)((int)_Dst + 0xc) = uVar47;
          *(undefined4 *)((int)_Dst + 0x10) = uVar7;
          *(undefined (*) [16])((int)_Dst + 0x10) = auVar2._4_16_;
          *(undefined (*) [16])((int)_Dst + 0x20) = auVar3._4_16_;
          _Dst = (void *)((int)_Dst + 0x30);
          iVar32 = iVar38 + 0x30;
          uVar45 = uVar4;
          uVar46 = uVar5;
          uVar47 = uVar6;
        } while (0x2f < _Size);
        puVar39 = (undefined8 *)(iVar38 + 0x34);
      }
      else {
                    // WARNING: Load size is inaccurate
        iVar32 = (int)_Src + -0xc;
        uVar45 = *_Src;
        do {
          iVar38 = iVar32;
          uVar47 = *(undefined4 *)(iVar38 + 0x20);
          uVar4 = *(undefined4 *)(iVar38 + 0x24);
          uVar5 = *(undefined4 *)(iVar38 + 0x28);
          _Size = _Size - 0x30;
          auVar2 = *(undefined (*) [32])(iVar38 + 0x10);
          uVar46 = *(undefined4 *)(iVar38 + 0x3c);
          auVar3 = *(undefined (*) [32])(iVar38 + 0x20);
          *(undefined4 *)((int)_Dst + 0xc) = uVar45;
          *(undefined4 *)((int)_Dst + 0x10) = uVar47;
          *(undefined4 *)((int)_Dst + 0x14) = uVar4;
          *(undefined4 *)((int)_Dst + 0x18) = uVar5;
          *(undefined (*) [16])((int)_Dst + 0x10) = auVar2._12_16_;
          *(undefined (*) [16])((int)_Dst + 0x20) = auVar3._12_16_;
          _Dst = (void *)((int)_Dst + 0x30);
          iVar32 = iVar38 + 0x30;
          uVar45 = uVar46;
        } while (0x2f < _Size);
        puVar39 = (undefined8 *)(iVar38 + 0x3c);
      }
      for (; 0xf < _Size; _Size = _Size - 0x10) {
        uVar45 = *(undefined4 *)puVar39;
        uVar46 = *(undefined4 *)((int)puVar39 + 4);
        uVar47 = *(undefined4 *)(puVar39 + 1);
        uVar4 = *(undefined4 *)((int)puVar39 + 0xc);
        puVar39 = puVar39 + 2;
        *(undefined4 *)_Dst = uVar45;
        *(undefined4 *)((int)_Dst + 4) = uVar46;
        *(undefined4 *)((int)_Dst + 8) = uVar47;
        *(undefined4 *)((int)_Dst + 0xc) = uVar4;
        _Dst = (void *)((int)_Dst + 0x10);
      }
      if ((_Size >> 2 & 1) != 0) {
        uVar45 = *(undefined4 *)puVar39;
        _Size = _Size - 4;
        puVar39 = (undefined8 *)((int)puVar39 + 4);
        *(undefined4 *)_Dst = uVar45;
        _Dst = (void *)((int)_Dst + 4);
      }
      if ((_Size >> 3 & 1) != 0) {
        _Size = _Size - 8;
        *(undefined8 *)_Dst = *puVar39;
      }
                    // WARNING: Could not recover jumptable at 0x004032d5. Too many branches
                    // WARNING: Treating indirect jump as call
      pvVar34 = (void *)(*(code *)(&switchD_00403305::switchdataD_00403314)[_Size])();
      return pvVar34;
    }
  }
  sVar36 = _Size;
  if (0x1f < _Size) {
                    // WARNING: Load size is inaccurate
    for (uVar35 = _Size >> 2; uVar35 != 0; uVar35 = uVar35 - 1) {
      *puVar42 = *_Src;
      _Src = (undefined4 *)((int)_Src + 4);
      puVar42 = puVar42 + 1;
    }
    switch(_Size & 3) {
    case 0:
      return _Dst;
    case 1:
                    // WARNING: Load size is inaccurate
      *(undefined *)puVar42 = *_Src;
      return _Dst;
    case 2:
                    // WARNING: Load size is inaccurate
      *(undefined *)puVar42 = *_Src;
      *(undefined *)((int)puVar42 + 1) = *(undefined *)((int)_Src + 1);
      return _Dst;
    case 3:
                    // WARNING: Load size is inaccurate
      *(undefined *)puVar42 = *_Src;
      *(undefined *)((int)puVar42 + 1) = *(undefined *)((int)_Src + 1);
      *(undefined *)((int)puVar42 + 2) = *(undefined *)((int)_Src + 2);
      return _Dst;
    }
  }
LAB_004035ab:
  if ((sVar36 & 0x1f) != 0) {
    for (uVar35 = (sVar36 & 0x1f) >> 2; uVar35 != 0; uVar35 = uVar35 - 1) {
                    // WARNING: Load size is inaccurate
      *puVar42 = *_Src;
      puVar42 = puVar42 + 1;
      _Src = (void *)((int)_Src + 4);
    }
    for (uVar35 = sVar36 & 3; uVar35 != 0; uVar35 = uVar35 - 1) {
                    // WARNING: Load size is inaccurate
      *(undefined *)puVar42 = *_Src;
      _Src = (void *)((int)_Src + 1);
      puVar42 = (undefined4 *)((int)puVar42 + 1);
    }
  }
  return _Dst;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// Library Function - Single Match
//  int __cdecl BuildCatchObjectHelperInternal<class __FrameHandler3>(struct EHExceptionRecord
// *,void *,struct _s_HandlerType const *,struct _s_CatchableType const *)
// 
// Library: Visual Studio 2019 Release

int __cdecl
BuildCatchObjectHelperInternal<>
          (EHExceptionRecord *param_1,void *param_2,_s_HandlerType *param_3,
          _s_CatchableType *param_4)

{
  uint uVar1;
  code *pcVar2;
  int iVar3;
  void *_Src;
  size_t _Size;
  void *local_14;
  
  pcVar2 = DAT_00423c64;
  if (((param_3->pType == (TypeDescriptor *)0x0) || (*(char *)&param_3->pType[1].pVFTable == '\0'))
     || ((param_3->dispCatchObj == 0 && (-1 < (int)param_3->adjectives)))) {
    ExceptionList = local_14;
    return 0;
  }
  uVar1 = param_3->adjectives;
  if (-1 < (int)uVar1) {
    param_2 = (void *)((int)param_2 + param_3->dispCatchObj + 0xc);
  }
  if ((((char)uVar1 < '\0') && (((byte)*param_4 & 0x10) != 0)) && (DAT_00423c64 != (code *)0x0)) {
    _guard_check_icall();
    iVar3 = (*pcVar2)();
  }
  else {
    if ((uVar1 & 8) == 0) {
      if (((byte)*param_4 & 1) == 0) {
        iVar3 = *(int *)(param_1 + 0x18);
        if (*(int *)(param_4 + 0x18) == 0) {
          if ((iVar3 != 0) && ((int *)param_2 != (int *)0x0)) {
            _Size = *(size_t *)(param_4 + 0x14);
            _Src = (void *)___AdjustPointer(iVar3,(int *)(param_4 + 8));
            FID_conflict__memcpy(param_2,_Src,_Size);
            ExceptionList = local_14;
            return 0;
          }
        }
        else if ((iVar3 != 0) && ((int *)param_2 != (int *)0x0)) {
          ExceptionList = local_14;
          return (((byte)*param_4 & 4) != 0) + 1;
        }
        goto LAB_0040375c;
      }
      if ((*(int *)(param_1 + 0x18) == 0) || ((int *)param_2 == (int *)0x0)) goto LAB_0040375c;
      FID_conflict__memcpy(param_2,*(void **)(param_1 + 0x18),*(size_t *)(param_4 + 0x14));
      if (*(int *)(param_4 + 0x14) != 4) {
        ExceptionList = local_14;
        return 0;
      }
                    // WARNING: Load size is inaccurate
      if (*param_2 == 0) {
        ExceptionList = local_14;
        return 0;
      }
                    // WARNING: Load size is inaccurate
      iVar3 = *param_2;
      goto LAB_004036eb;
    }
    iVar3 = *(int *)(param_1 + 0x18);
  }
  if ((iVar3 == 0) || ((int *)param_2 == (int *)0x0)) {
LAB_0040375c:
                    // WARNING: Subroutine does not return
    _abort();
  }
  *(int *)param_2 = iVar3;
LAB_004036eb:
  iVar3 = ___AdjustPointer(iVar3,(int *)(param_4 + 8));
  *(int *)param_2 = iVar3;
  ExceptionList = local_14;
  return 0;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// Library Function - Single Match
//  void __cdecl BuildCatchObjectInternal<class __FrameHandler3>(struct EHExceptionRecord *,void
// *,struct _s_HandlerType const *,struct _s_CatchableType const *)
// 
// Library: Visual Studio 2019 Release

void __cdecl
BuildCatchObjectInternal<>
          (EHExceptionRecord *param_1,void *param_2,_s_HandlerType *param_3,
          _s_CatchableType *param_4)

{
  int iVar1;
  void *pvVar2;
  void *pvVar3;
  void *local_14;
  
  pvVar3 = param_2;
  if (-1 < (int)param_3->adjectives) {
    pvVar3 = (void *)((int)param_2 + param_3->dispCatchObj + 0xc);
  }
  iVar1 = BuildCatchObjectHelperInternal<>(param_1,param_2,param_3,param_4);
  if (iVar1 == 1) {
    pvVar2 = (void *)___AdjustPointer(*(int *)(param_1 + 0x18),(int *)(param_4 + 8));
    _CallMemberFunction1(pvVar3,*(void **)(param_4 + 0x18),pvVar2);
  }
  else if (iVar1 == 2) {
    pvVar2 = (void *)___AdjustPointer(*(int *)(param_1 + 0x18),(int *)(param_4 + 8));
    _CallMemberFunction2(pvVar3,*(void **)(param_4 + 0x18),pvVar2,1);
  }
  ExceptionList = local_14;
  return;
}



// Library Function - Single Match
//  void __cdecl CatchIt<class __FrameHandler3>(struct EHExceptionRecord *,struct EHRegistrationNode
// *,struct _CONTEXT *,void *,struct _s_FuncInfo const *,struct _s_HandlerType const *,struct
// _s_CatchableType const *,struct _s_TryBlockMapEntry const *,int,struct EHRegistrationNode
// *,unsigned char,unsigned char)
// 
// Library: Visual Studio 2019 Release

void __cdecl
CatchIt<>(EHExceptionRecord *param_1,EHRegistrationNode *param_2,_CONTEXT *param_3,void *param_4,
         _s_FuncInfo *param_5,_s_HandlerType *param_6,_s_CatchableType *param_7,
         _s_TryBlockMapEntry *param_8,int param_9,EHRegistrationNode *param_10,uchar param_11,
         uchar param_12)

{
  void *pvVar1;
  
  if (param_7 != (_s_CatchableType *)0x0) {
    BuildCatchObjectInternal<>(param_1,param_2,param_6,param_7);
  }
  if (param_10 == (EHRegistrationNode *)0x0) {
    param_10 = param_2;
  }
  _UnwindNestedFrames(param_10,param_1);
  __FrameHandler3::FrameUnwindToState(param_2,param_4,param_5,param_8->tryLow);
  __FrameHandler3::SetState(param_2,param_5,param_8->tryHigh + 1);
  pvVar1 = (void *)FUN_00403fab((int)param_1,(int)param_2,param_3,param_5,param_6->addressOfHandler,
                                param_9,0x100);
  if (pvVar1 != (void *)0x0) {
    _JumpToContinuation(pvVar1,param_2);
  }
  return;
}



void __cdecl
FUN_0040387b(int *param_1,EHRegistrationNode *param_2,_CONTEXT *param_3,_s_FuncInfo *param_4,
            _s_FuncInfo *param_5,uchar param_6,int param_7,EHRegistrationNode *param_8)

{
  void *pvVar1;
  bool bVar2;
  int iVar3;
  undefined4 uVar4;
  int iVar5;
  uint uVar6;
  byte *pbVar7;
  _s_FuncInfo *p_Var8;
  __ehstate_t *p_Var9;
  _s_TryBlockMapEntry *p_Var10;
  _s_CatchableType **pp_Var11;
  _s_TryBlockMapEntry local_68;
  _s_HandlerType local_54;
  int *local_44;
  _s_FuncInfo *local_40 [2];
  _s_FuncInfo *local_38;
  _s_FuncInfo *local_34;
  undefined4 local_30;
  int *local_2c;
  int local_28;
  _s_CatchableType **local_24;
  int local_20;
  undefined4 local_1c;
  HandlerType *local_18;
  int local_14;
  _s_FuncInfo *local_10;
  void *local_c;
  _CONTEXT *local_8;
  
  local_14 = 0;
  local_1c = local_1c & 0xffffff00;
  local_c = (void *)__FrameHandler3::GetCurrentState(param_2,param_4,param_5);
  if (((int)local_c < -1) || (param_5->maxState <= (int)local_c)) goto LAB_00403c1a;
  if (((*param_1 != -0x1f928c9d) || (param_1[4] != 3)) ||
     ((((param_1[5] != 0x19930520 && (param_1[5] != 0x19930521)) && (param_1[5] != 0x19930522)) ||
      (param_1[7] != 0)))) {
    local_8 = param_3;
    goto LAB_004039c9;
  }
  iVar3 = ___vcrt_getptd();
  if (*(int *)(iVar3 + 0x10) == 0) {
    return;
  }
  iVar3 = ___vcrt_getptd();
  param_1 = *(int **)(iVar3 + 0x10);
  iVar3 = ___vcrt_getptd();
  local_1c = CONCAT31(local_1c._1_3_,1);
  local_8 = *(_CONTEXT **)(iVar3 + 0x14);
  if ((param_1 == (int *)0x0) ||
     ((((*param_1 == -0x1f928c9d && (param_1[4] == 3)) &&
       ((param_1[5] == 0x19930520 || ((param_1[5] == 0x19930521 || (param_1[5] == 0x19930522))))))
      && (param_1[7] == 0)))) goto LAB_00403c1a;
  iVar3 = ___vcrt_getptd();
  if (*(int *)(iVar3 + 0x1c) == 0) {
LAB_004039c9:
    local_34 = param_5;
    local_30 = 0;
    if (((*param_1 == -0x1f928c9d) && (param_1[4] == 3)) &&
       ((param_1[5] == 0x19930520 || ((param_1[5] == 0x19930521 || (param_1[5] == 0x19930522)))))) {
      if (param_5->nTryBlocks != 0) {
        __FrameHandler3::GetRangeOfTrysToCheck
                  ((TryBlockMap *)&local_44,(int)&local_34,local_c,param_4,(int)param_5);
        local_2c = local_44;
        local_10 = local_40[0];
        if (local_40[0] < local_38) {
          local_20 = (int)local_40[0] * 0x14;
          p_Var8 = local_40[0];
          do {
            pvVar1 = local_c;
            p_Var9 = (__ehstate_t *)(*(int *)(*local_2c + 0x10) + local_20);
            p_Var10 = &local_68;
            local_10 = p_Var8;
            for (iVar3 = 5; iVar3 != 0; iVar3 = iVar3 + -1) {
              p_Var10->tryLow = *p_Var9;
              p_Var9 = p_Var9 + 1;
              p_Var10 = (_s_TryBlockMapEntry *)&p_Var10->tryHigh;
            }
            if (((local_68.tryLow <= (int)pvVar1) && ((int)pvVar1 <= local_68.tryHigh)) &&
               (local_14 = 0, local_68.nCatches != 0)) {
              pbVar7 = (byte *)param_1[7];
              local_28 = **(int **)(pbVar7 + 0xc);
              local_24 = (_s_CatchableType **)(*(int **)(pbVar7 + 0xc) + 1);
              local_18 = local_68.pHandlerArray;
              do {
                local_54.adjectives = local_18->adjectives;
                local_54.pType = local_18->pType;
                local_54.dispCatchObj = local_18->dispCatchObj;
                local_54.addressOfHandler = local_18->addressOfHandler;
                pp_Var11 = local_24;
                p_Var8 = local_10;
                for (iVar3 = local_28; local_10 = p_Var8, 0 < iVar3; iVar3 = iVar3 + -1) {
                  iVar5 = FID_conflict____TypeMatch((byte *)&local_54,(byte *)*pp_Var11,pbVar7);
                  if (iVar5 != 0) {
                    CatchIt<>((EHExceptionRecord *)param_1,param_2,local_8,param_4,param_5,&local_54
                              ,*pp_Var11,&local_68,param_7,param_8,(uchar)local_1c,param_6);
                    p_Var8 = local_10;
                    goto LAB_00403b04;
                  }
                  pbVar7 = (byte *)param_1[7];
                  pp_Var11 = pp_Var11 + 1;
                  p_Var8 = local_10;
                }
                local_14 = local_14 + 1;
                local_18 = local_18 + 1;
              } while (local_14 != local_68.nCatches);
            }
LAB_00403b04:
            p_Var8 = (_s_FuncInfo *)((int)&p_Var8->magicNumber_and_bbtFlags + 1);
            local_20 = local_20 + 0x14;
            local_10 = p_Var8;
          } while (p_Var8 < local_38);
        }
      }
      if (param_6 != '\0') {
        ___DestructExceptionObject(param_1);
      }
      if (0x19930520 < (param_5->magicNumber_and_bbtFlags & 0x1fffffff)) {
        uVar6 = (uint)param_5->EHFlags >> 2;
        if (param_5->pESTypeList != (ESTypeList *)0x0) {
          if ((uVar6 & 1) != 0) goto LAB_00403b5d;
          uVar4 = FUN_00404303((int)param_1,&param_5->pESTypeList->nCount);
          if ((char)uVar4 != '\0') goto LAB_00403ba9;
          goto LAB_00403bde;
        }
        if (((uVar6 & 1) != 0) && (param_7 == 0)) {
LAB_00403b5d:
          iVar3 = ___vcrt_getptd();
          *(int **)(iVar3 + 0x10) = param_1;
          iVar3 = ___vcrt_getptd();
          *(_CONTEXT **)(iVar3 + 0x14) = local_8;
          goto LAB_00403bb9;
        }
      }
    }
    else if (param_5->nTryBlocks != 0) {
      if (param_6 != '\0') goto LAB_00403c1a;
      FindHandlerForForeignException<>
                ((EHExceptionRecord *)param_1,param_2,local_8,param_4,param_5,(int)local_c,param_7,
                 param_8);
    }
LAB_00403ba9:
    iVar3 = ___vcrt_getptd();
    if (*(int *)(iVar3 + 0x1c) == 0) {
      return;
    }
  }
  else {
    iVar3 = ___vcrt_getptd();
    local_10 = *(_s_FuncInfo **)(iVar3 + 0x1c);
    iVar3 = ___vcrt_getptd();
    *(undefined4 *)(iVar3 + 0x1c) = 0;
    uVar4 = FUN_00404303((int)param_1,(int *)local_10);
    p_Var8 = local_10;
    if ((char)uVar4 != '\0') goto LAB_004039c9;
    param_8 = (EHRegistrationNode *)0x0;
    param_5 = p_Var8;
    if (0 < (int)local_10->magicNumber_and_bbtFlags) {
      do {
        bVar2 = type_info::operator==
                          (*(type_info **)(param_8 + p_Var8->maxState + 4),
                           (type_info *)&std::bad_exception::RTTI_Type_Descriptor);
        if (bVar2) goto LAB_00403bbe;
        param_8 = param_8 + 0x10;
        local_14 = local_14 + 1;
      } while (local_14 < (int)p_Var8->magicNumber_and_bbtFlags);
    }
LAB_00403bb9:
    _terminate();
LAB_00403bbe:
    ___DestructExceptionObject(param_1);
    FUN_00403f0a(local_40);
    __CxxThrowException_8((int *)local_40,&DAT_00421c84);
LAB_00403bde:
    iVar3 = ___vcrt_getptd();
    *(int **)(iVar3 + 0x10) = param_1;
    iVar3 = ___vcrt_getptd();
    *(_CONTEXT **)(iVar3 + 0x14) = local_8;
    if (param_8 == (EHRegistrationNode *)0x0) {
      param_8 = param_2;
    }
    _UnwindNestedFrames(param_8,(EHExceptionRecord *)param_1);
    __FrameHandler3::FrameUnwindToEmptyState(param_2,param_4,param_5);
    uVar4 = FUN_004043c0((int)param_5);
    FUN_0040417a(uVar4);
  }
LAB_00403c1a:
                    // WARNING: Subroutine does not return
  _abort();
}



// Library Function - Single Match
//  void __cdecl FindHandlerForForeignException<class __FrameHandler3>(struct EHExceptionRecord
// *,struct EHRegistrationNode *,struct _CONTEXT *,void *,struct _s_FuncInfo const *,int,int,struct
// EHRegistrationNode *)
// 
// Library: Visual Studio 2019 Release

void __cdecl
FindHandlerForForeignException<>
          (EHExceptionRecord *param_1,EHRegistrationNode *param_2,_CONTEXT *param_3,void *param_4,
          _s_FuncInfo *param_5,int param_6,int param_7,EHRegistrationNode *param_8)

{
  int iVar1;
  PVOID pvVar2;
  _s_HandlerType *p_Var3;
  uint uVar4;
  __ehstate_t *p_Var5;
  _s_TryBlockMapEntry *p_Var6;
  _s_TryBlockMapEntry local_3c;
  int *local_28;
  uint local_24;
  uint local_1c;
  _s_FuncInfo *local_18;
  undefined4 local_14;
  int *local_10;
  int local_c;
  uint local_8;
  
  if (*(int *)param_1 != -0x7ffffffd) {
    iVar1 = ___vcrt_getptd();
    if (*(int *)(iVar1 + 8) != 0) {
      pvVar2 = EncodePointer((PVOID)0x0);
      iVar1 = ___vcrt_getptd();
      if ((((*(PVOID *)(iVar1 + 8) != pvVar2) && (*(int *)param_1 != -0x1fbcb0b3)) &&
          (*(int *)param_1 != -0x1fbcbcae)) &&
         (iVar1 = FUN_00402dc1((int *)param_1,(undefined4 *)param_2,param_3,param_4,param_5,param_7,
                               param_8), iVar1 != 0)) {
        return;
      }
    }
    local_18 = param_5;
    local_14 = 0;
    if (param_5->nTryBlocks == 0) {
                    // WARNING: Subroutine does not return
      _abort();
    }
    __FrameHandler3::GetRangeOfTrysToCheck
              ((TryBlockMap *)&local_28,(int)&local_18,(void *)param_6,(_s_FuncInfo *)param_4,
               (int)param_5);
    local_10 = local_28;
    if (local_24 < local_1c) {
      local_c = local_24 * 0x14;
      uVar4 = local_24;
      do {
        p_Var5 = (__ehstate_t *)(*(int *)(*local_10 + 0x10) + local_c);
        p_Var6 = &local_3c;
        local_8 = uVar4;
        for (iVar1 = 5; iVar1 != 0; iVar1 = iVar1 + -1) {
          p_Var6->tryLow = *p_Var5;
          p_Var5 = p_Var5 + 1;
          p_Var6 = (_s_TryBlockMapEntry *)&p_Var6->tryHigh;
        }
        if ((local_3c.tryLow <= param_6) && (param_6 <= local_3c.tryHigh)) {
          p_Var3 = local_3c.pHandlerArray + local_3c.nCatches + -1;
          if (((p_Var3->pType == (TypeDescriptor *)0x0) ||
              (*(char *)&p_Var3->pType[1].pVFTable == '\0')) &&
             ((*(byte *)&p_Var3->adjectives & 0x40) == 0)) {
            CatchIt<>(param_1,param_2,param_3,param_4,param_5,p_Var3,(_s_CatchableType *)0x0,
                      &local_3c,param_7,param_8,'\x01','\0');
            uVar4 = local_8;
          }
        }
        uVar4 = uVar4 + 1;
        local_c = local_c + 0x14;
      } while (uVar4 < local_1c);
    }
  }
  return;
}



// Library Function - Multiple Matches With Different Base Names
//  int __cdecl TypeMatchHelper<struct _s_HandlerType const >(struct _s_HandlerType const *,struct
// _s_CatchableType const *,struct _s_ThrowInfo const *)
//  int __cdecl TypeMatchHelper<class __FrameHandler3>(struct _s_HandlerType const *,struct
// _s_CatchableType const *,struct _s_ThrowInfo const *)
//  ___TypeMatch
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

undefined4 __cdecl FID_conflict____TypeMatch(byte *param_1,byte *param_2,byte *param_3)

{
  byte bVar1;
  int iVar2;
  byte *pbVar3;
  uint uVar4;
  byte *pbVar5;
  undefined4 uVar6;
  bool bVar7;
  
  iVar2 = *(int *)(param_1 + 4);
  if (((iVar2 == 0) || (pbVar5 = (byte *)(iVar2 + 8), *pbVar5 == 0)) ||
     (((*param_1 & 0x80) != 0 && ((*param_2 & 0x10) != 0)))) {
    uVar6 = 1;
  }
  else {
    uVar6 = 0;
    if (iVar2 != *(int *)(param_2 + 4)) {
      pbVar3 = (byte *)(*(int *)(param_2 + 4) + 8);
      do {
        bVar1 = *pbVar5;
        bVar7 = bVar1 < *pbVar3;
        if (bVar1 != *pbVar3) {
LAB_00403da7:
          uVar4 = -(uint)bVar7 | 1;
          goto LAB_00403dac;
        }
        if (bVar1 == 0) break;
        bVar1 = pbVar5[1];
        bVar7 = bVar1 < pbVar3[1];
        if (bVar1 != pbVar3[1]) goto LAB_00403da7;
        pbVar5 = pbVar5 + 2;
        pbVar3 = pbVar3 + 2;
      } while (bVar1 != 0);
      uVar4 = 0;
LAB_00403dac:
      if (uVar4 != 0) {
        return 0;
      }
    }
    if ((((*param_2 & 2) == 0) || ((*param_1 & 8) != 0)) &&
       ((((*param_3 & 1) == 0 || ((*param_1 & 1) != 0)) &&
        (((*param_3 & 2) == 0 || ((*param_1 & 2) != 0)))))) {
      uVar6 = 1;
    }
  }
  return uVar6;
}



// Library Function - Single Match
//  enum _EXCEPTION_DISPOSITION __cdecl __InternalCxxFrameHandler<class __FrameHandler3>(struct
// EHExceptionRecord *,struct EHRegistrationNode *,struct _CONTEXT *,void *,struct _s_FuncInfo const
// *,int,struct EHRegistrationNode *,unsigned char)
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

_EXCEPTION_DISPOSITION __cdecl
__InternalCxxFrameHandler<>
          (EHExceptionRecord *param_1,EHRegistrationNode *param_2,_CONTEXT *param_3,void *param_4,
          _s_FuncInfo *param_5,int param_6,EHRegistrationNode *param_7,uchar param_8)

{
  code *pcVar1;
  int iVar2;
  uint uVar3;
  _EXCEPTION_DISPOSITION _Var4;
  
  ___except_validate_context_record((int)param_3);
  iVar2 = ___vcrt_getptd();
  if ((((*(int *)(iVar2 + 0x20) != 0) || (*(int *)param_1 == -0x1f928c9d)) ||
      (*(int *)param_1 == -0x7fffffda)) ||
     (((param_5->magicNumber_and_bbtFlags & 0x1fffffff) < 0x19930522 ||
      ((*(byte *)&param_5->EHFlags & 1) == 0)))) {
    if (((byte)param_1[4] & 0x66) == 0) {
      if (((param_5->nTryBlocks != 0) ||
          ((uVar3 = param_5->magicNumber_and_bbtFlags & 0x1fffffff, 0x19930520 < uVar3 &&
           (param_5->pESTypeList != (ESTypeList *)0x0)))) ||
         ((0x19930521 < uVar3 && (((uint)param_5->EHFlags >> 2 & 1) != 0)))) {
        if ((((*(int *)param_1 == -0x1f928c9d) && (2 < *(uint *)(param_1 + 0x10))) &&
            (0x19930522 < *(uint *)(param_1 + 0x14))) &&
           (pcVar1 = *(code **)(*(int *)(param_1 + 0x1c) + 8), pcVar1 != (code *)0x0)) {
          uVar3 = (uint)param_8;
          _guard_check_icall();
          _Var4 = (*pcVar1)(param_1,param_2,param_3,param_4,param_5,param_6,param_7,uVar3);
          return _Var4;
        }
        FUN_0040387b((int *)param_1,param_2,param_3,(_s_FuncInfo *)param_4,param_5,param_8,param_6,
                     param_7);
      }
    }
    else if ((param_5->maxState != 0) && (param_6 == 0)) {
      __FrameHandler3::FrameUnwindToEmptyState(param_2,param_4,param_5);
    }
  }
  return 1;
}



void __cdecl
FUN_00403ee6(EHExceptionRecord *param_1,EHRegistrationNode *param_2,_CONTEXT *param_3,void *param_4,
            _s_FuncInfo *param_5,int param_6,EHRegistrationNode *param_7,uchar param_8)

{
  __InternalCxxFrameHandler<>(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  return;
}



undefined4 * __thiscall FUN_00403eef(void *this,exception *param_1)

{
  std::exception::exception((exception *)this,param_1);
  *(undefined ***)this = std::bad_exception::vftable;
  return (undefined4 *)this;
}



undefined4 * __fastcall FUN_00403f0a(undefined4 *param_1)

{
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[1] = "bad exception";
  *param_1 = std::bad_exception::vftable;
  return param_1;
}



// Library Function - Single Match
//  public: __thiscall std::exception::exception(class std::exception const &)
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

exception * __thiscall std::exception::exception(exception *this,exception *param_1)

{
  *(undefined ***)this = vftable;
  *(char **)(this + 4) = (char *)0x0;
  *(undefined4 *)(this + 8) = 0;
  ___std_exception_copy((char **)(param_1 + 4),(char **)(this + 4));
  return this;
}



// Library Function - Single Match
//  public: bool __thiscall type_info::operator==(class type_info const &)const 
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

bool __thiscall type_info::operator==(type_info *this,type_info *param_1)

{
  uint uVar1;
  
  uVar1 = ___std_type_info_compare((int)(this + 4),(int)(param_1 + 4));
  return (bool)('\x01' - (uVar1 != 0));
}



undefined4 * __thiscall FUN_00403f7e(void *this,byte param_1)

{
  *(undefined ***)this = std::exception::vftable;
  ___std_exception_destroy((LPVOID *)((int)this + 4));
  if ((param_1 & 1) != 0) {
    FUN_0041a650(this);
  }
  return (undefined4 *)this;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4

undefined4 __cdecl
FUN_00403fab(int param_1,int param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5,
            int param_6,int param_7)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 local_50 [2];
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 *local_38;
  undefined4 local_34;
  undefined4 local_20;
  void *local_14;
  undefined4 uStack_c;
  undefined *local_8;
  
  local_8 = &DAT_00421bc8;
  uStack_c = 0x403fb7;
  local_20 = param_5;
  local_44 = 0;
  local_34 = *(undefined4 *)(param_2 + -4);
  local_38 = __CreateFrameInfo(local_50,*(undefined4 *)(param_1 + 0x18));
  iVar1 = ___vcrt_getptd();
  local_3c = *(undefined4 *)(iVar1 + 0x10);
  iVar1 = ___vcrt_getptd();
  local_40 = *(undefined4 *)(iVar1 + 0x14);
  iVar1 = ___vcrt_getptd();
  *(int *)(iVar1 + 0x10) = param_1;
  iVar1 = ___vcrt_getptd();
  *(undefined4 *)(iVar1 + 0x14) = param_3;
  local_48 = 1;
  local_8 = (undefined *)0x1;
  uVar2 = FUN_00402d64(param_2,param_4,param_5,param_6,param_7);
  local_8 = (undefined *)0xfffffffe;
  local_48 = 0;
  local_20 = uVar2;
  FUN_004040fe();
  ExceptionList = local_14;
  return uVar2;
}



void FUN_004040fe(void)

{
  int iVar1;
  int unaff_EBX;
  int unaff_EBP;
  int *unaff_ESI;
  
  *(undefined4 *)(*(int *)(unaff_EBP + 0xc) + -4) = *(undefined4 *)(unaff_EBP + -0x30);
  __FindAndUnlinkFrame(*(int *)(unaff_EBP + -0x34));
  iVar1 = ___vcrt_getptd();
  *(undefined4 *)(iVar1 + 0x10) = *(undefined4 *)(unaff_EBP + -0x38);
  iVar1 = ___vcrt_getptd();
  *(undefined4 *)(iVar1 + 0x14) = *(undefined4 *)(unaff_EBP + -0x3c);
  if ((((*unaff_ESI == -0x1f928c9d) && (unaff_ESI[4] == 3)) &&
      ((unaff_ESI[5] == 0x19930520 || ((unaff_ESI[5] == 0x19930521 || (unaff_ESI[5] == 0x19930522)))
       ))) && ((*(int *)(unaff_EBP + -0x40) == 0 && (unaff_EBX != 0)))) {
    iVar1 = __IsExceptionObjectToBeDestroyed(unaff_ESI[6]);
    if (iVar1 != 0) {
      ___DestructExceptionObject(unaff_ESI);
    }
  }
  return;
}



// WARNING: Function: __EH_prolog3_catch replaced with injection: EH_prolog3

void FUN_0040417a(undefined4 param_1)

{
  int iVar1;
  
  iVar1 = ___vcrt_getptd();
  if (*(int *)(iVar1 + 0x1c) == 0) {
    _unexpected();
    iVar1 = ___vcrt_getptd();
    *(undefined4 *)(iVar1 + 0x1c) = param_1;
    __CxxThrowException_8((int *)0x0,(byte *)0x0);
  }
                    // WARNING: Subroutine does not return
  _abort();
}



void Catch_All_0040419a(void)

{
  int iVar1;
  int unaff_EBP;
  
  iVar1 = ___vcrt_getptd();
  *(undefined4 *)(iVar1 + 0x1c) = *(undefined4 *)(unaff_EBP + 8);
  __CxxThrowException_8((int *)0x0,(byte *)0x0);
                    // WARNING: Subroutine does not return
  _abort();
}



// Library Function - Single Match
//  int __cdecl ExFilterRethrow(struct _EXCEPTION_POINTERS *)
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

int __cdecl ExFilterRethrow(_EXCEPTION_POINTERS *param_1)

{
  PEXCEPTION_RECORD pEVar1;
  int iVar2;
  
  pEVar1 = param_1->ExceptionRecord;
  if ((((pEVar1->ExceptionCode == 0xe06d7363) && (pEVar1->NumberParameters == 3)) &&
      ((pEVar1->ExceptionInformation[0] == 0x19930520 ||
       ((pEVar1->ExceptionInformation[0] == 0x19930521 ||
        (pEVar1->ExceptionInformation[0] == 0x19930522)))))) &&
     (pEVar1->ExceptionInformation[2] == 0)) {
    iVar2 = ___vcrt_getptd();
    *(undefined4 *)(iVar2 + 0x20) = 1;
    return 1;
  }
  return 0;
}



// Library Function - Single Match
//  public: static void __cdecl __FrameHandler3::FrameUnwindToEmptyState(struct EHRegistrationNode
// *,void *,struct _s_FuncInfo const *)
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __cdecl
__FrameHandler3::FrameUnwindToEmptyState
          (EHRegistrationNode *param_1,void *param_2,_s_FuncInfo *param_3)

{
  FrameUnwindToState(param_1,param_2,param_3,-1);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// Library Function - Single Match
//  public: static void __cdecl __FrameHandler3::FrameUnwindToState(struct EHRegistrationNode *,void
// *,struct _s_FuncInfo const *,int)
// 
// Library: Visual Studio 2019 Release

void __cdecl
__FrameHandler3::FrameUnwindToState
          (EHRegistrationNode *param_1,void *param_2,_s_FuncInfo *param_3,int param_4)

{
  int iVar1;
  int iVar2;
  void *local_14;
  
  iVar1 = GetCurrentState(param_1,param_2,param_3);
  iVar2 = ___vcrt_getptd();
  *(int *)(iVar2 + 0x18) = *(int *)(iVar2 + 0x18) + 1;
  while (iVar2 = iVar1, iVar2 != param_4) {
    if ((iVar2 < 0) || (param_3->maxState <= iVar2)) goto LAB_004042fd;
    iVar1 = param_3->pUnwindMap[iVar2].toState;
    if (param_3->pUnwindMap[iVar2].action != (action *)0x0) {
      SetState(param_1,param_3,iVar1);
      __CallSettingFrame_12(param_3->pUnwindMap[iVar2].action,param_1,0x103);
    }
  }
  FUN_004042e9();
  if (iVar2 == param_4) {
    SetState(param_1,param_3,iVar2);
    ExceptionList = local_14;
    return;
  }
LAB_004042fd:
                    // WARNING: Subroutine does not return
  _abort();
}



void FUN_004042e9(void)

{
  int iVar1;
  
  iVar1 = ___vcrt_getptd();
  if (0 < *(int *)(iVar1 + 0x18)) {
    iVar1 = ___vcrt_getptd();
    *(int *)(iVar1 + 0x18) = *(int *)(iVar1 + 0x18) + -1;
  }
  return;
}



undefined4 __cdecl FUN_00404303(int param_1,int *param_2)

{
  byte *pbVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  byte **in_EAX;
  int iVar5;
  byte **ppbVar6;
  undefined uVar7;
  int iVar8;
  int local_c;
  int local_8;
  
  if (param_2 == (int *)0x0) {
                    // WARNING: Subroutine does not return
    _abort();
  }
  iVar8 = *param_2;
  uVar7 = 0;
  if (0 < iVar8) {
    local_8 = 0;
    pbVar1 = *(byte **)(param_1 + 0x1c);
    piVar2 = *(int **)(pbVar1 + 0xc);
    iVar3 = *piVar2;
    in_EAX = (byte **)(piVar2 + 1);
    uVar7 = 0;
    do {
      if (0 < iVar3) {
        iVar4 = param_2[1];
        ppbVar6 = in_EAX;
        local_c = iVar3;
        do {
          iVar5 = FID_conflict____TypeMatch((byte *)(iVar4 + local_8),*ppbVar6,pbVar1);
          if (iVar5 != 0) {
            uVar7 = 1;
            break;
          }
          local_c = local_c + -1;
          ppbVar6 = ppbVar6 + 1;
        } while (0 < local_c);
      }
      local_8 = local_8 + 0x10;
      iVar8 = iVar8 + -1;
    } while (iVar8 != 0);
  }
  return CONCAT31((int3)((uint)in_EAX >> 8),uVar7);
}



// Library Function - Single Match
//  void __stdcall _CallMemberFunction1(void * const,void * const,void * const)
// 
// Library: Visual Studio 2019 Release

void _CallMemberFunction1(void *param_1,void *param_2,void *param_3)

{
  (*(code *)param_2)(param_3);
  return;
}



// Library Function - Single Match
//  void __stdcall _CallMemberFunction2(void * const,void * const,void * const,int)
// 
// Library: Visual Studio 2019 Release

void _CallMemberFunction2(void *param_1,void *param_2,void *param_3,int param_4)

{
  (*(code *)param_2)(param_3,param_4);
  return;
}



undefined4 __cdecl FUN_004043c0(int param_1)

{
  return *(undefined4 *)(param_1 + 0x1c);
}



char * __fastcall FUN_004043cb(int param_1)

{
  char *pcVar1;
  
  pcVar1 = *(char **)(param_1 + 4);
  if (pcVar1 == (char *)0x0) {
    pcVar1 = "Unknown exception";
  }
  return pcVar1;
}



// WARNING: Restarted to delay deadcode elimination for space: stack
// Library Function - Single Match
//  __CallSettingFrame@12
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __CallSettingFrame_12(undefined4 param_1,undefined4 param_2,int param_3)

{
  code *pcVar1;
  
  pcVar1 = (code *)FUN_00402aa0(param_3);
  (*pcVar1)();
  if (param_3 == 0x100) {
    param_3 = 2;
  }
  FUN_00402aa0(param_3);
  return;
}



// Library Function - Single Match
//  _unexpected
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void _unexpected(void)

{
  code *pcVar1;
  int iVar2;
  
  iVar2 = ___vcrt_getptd();
  pcVar1 = *(code **)(iVar2 + 4);
  if (pcVar1 != (code *)0x0) {
    _guard_check_icall();
    (*pcVar1)();
  }
  _terminate();
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



// Library Function - Single Match
//  public: static int __cdecl __FrameHandler3::GetCurrentState(struct EHRegistrationNode *,void
// *,struct _s_FuncInfo const *)
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

int __cdecl
__FrameHandler3::GetCurrentState(EHRegistrationNode *param_1,void *param_2,_s_FuncInfo *param_3)

{
  if (param_3->maxState < 0x81) {
    return (int)(char)param_1[8];
  }
  return *(int *)(param_1 + 8);
}



// Library Function - Single Match
//  public: static void __cdecl __FrameHandler3::SetState(struct EHRegistrationNode *,struct
// _s_FuncInfo const *,int)
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __cdecl __FrameHandler3::SetState(EHRegistrationNode *param_1,_s_FuncInfo *param_2,int param_3)

{
  *(int *)(param_1 + 8) = param_3;
  return;
}



// Library Function - Single Match
//  ___std_exception_copy
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void __cdecl ___std_exception_copy(char **param_1,char **param_2)

{
  char *pcVar1;
  char cVar2;
  char *pcVar3;
  char *pcVar4;
  char *pcVar5;
  
  if ((*(char *)(param_1 + 1) == '\0') || (pcVar4 = *param_1, pcVar4 == (char *)0x0)) {
    *param_2 = *param_1;
    *(undefined *)(param_2 + 1) = 0;
  }
  else {
    pcVar1 = pcVar4 + 1;
    do {
      cVar2 = *pcVar4;
      pcVar4 = pcVar4 + 1;
    } while (cVar2 != '\0');
    pcVar3 = (char *)FUN_0040cc35((SIZE_T)(pcVar4 + (1 - (int)pcVar1)));
    pcVar5 = pcVar3;
    if (pcVar3 != (char *)0x0) {
      FUN_0040daef(pcVar3,(int)(pcVar4 + (1 - (int)pcVar1)),(int)*param_1);
      pcVar5 = (char *)0x0;
      *param_2 = pcVar3;
      *(undefined *)(param_2 + 1) = 1;
    }
    FUN_0040caa5(pcVar5);
  }
  return;
}



// Library Function - Single Match
//  ___std_exception_destroy
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void __cdecl ___std_exception_destroy(LPVOID *param_1)

{
  if (*(char *)(param_1 + 1) != '\0') {
    FUN_0040caa5(*param_1);
  }
  *param_1 = (LPVOID)0x0;
  *(undefined *)(param_1 + 1) = 0;
  return;
}



// Library Function - Single Match
//  __CxxThrowException@8
// 
// Library: Visual Studio 2019 Release

void __CxxThrowException_8(int *param_1,byte *param_2)

{
  code *pcVar1;
  int *piVar2;
  ULONG_PTR UVar3;
  ULONG_PTR local_10;
  int *local_c;
  byte *local_8;
  
  UVar3 = 0x19930520;
  if (param_2 != (byte *)0x0) {
    if ((*param_2 & 0x10) != 0) {
      piVar2 = (int *)(*param_1 + -4);
      pcVar1 = *(code **)(*piVar2 + 0x20);
      param_2 = *(byte **)(*piVar2 + 0x18);
      _guard_check_icall();
      (*pcVar1)(piVar2);
      if (param_2 == (byte *)0x0) goto LAB_0040453d;
    }
    if ((*param_2 & 8) != 0) {
      UVar3 = 0x1994000;
    }
  }
LAB_0040453d:
  local_c = param_1;
  local_10 = UVar3;
  local_8 = param_2;
  RaiseException(0xe06d7363,1,3,&local_10);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// Library Function - Multiple Matches With Same Base Name
//  public: void __thiscall __crt_seh_guarded_call<void>::operator()<class
// <lambda_03b1d95aef87969028cfba75ccab2455>,class <lambda_6e4b09c48022b2350581041d5f6b0c4c> &,class
// <lambda_22bdf7517842c4b3e53723af5aa32b9e> >(class <lambda_03b1d95aef87969028cfba75ccab2455>
// &&,class <lambda_6e4b09c48022b2350581041d5f6b0c4c> &,class
// <lambda_22bdf7517842c4b3e53723af5aa32b9e> &&)
//  public: void __thiscall __crt_seh_guarded_call<void>::operator()<class
// <lambda_4fdada1b837b2abbf20876fac97688ad>,class <lambda_b57350f2640456a0859d250846f69caf> &,class
// <lambda_eed5e4f92b5b7d55fa22c48c484aaa54> >(class <lambda_4fdada1b837b2abbf20876fac97688ad>
// &&,class <lambda_b57350f2640456a0859d250846f69caf> &,class
// <lambda_eed5e4f92b5b7d55fa22c48c484aaa54> &&)
//  public: void __thiscall __crt_seh_guarded_call<void>::operator()<class
// <lambda_ceb1ee4838e85a9d631eb091e2fbe199>,class <lambda_ae742caa10f662c28703da3d2ea5e57e> &,class
// <lambda_cd08b5d6af4937fe54fc07d0c9bf6b37> >(class <lambda_ceb1ee4838e85a9d631eb091e2fbe199>
// &&,class <lambda_ae742caa10f662c28703da3d2ea5e57e> &,class
// <lambda_cd08b5d6af4937fe54fc07d0c9bf6b37> &&)
// 
// Library: Visual Studio 2019 Release

void operator()<>(int *param_1,int **param_2)

{
  void *local_14;
  
  ___acrt_lock(*param_1);
  FUN_004045f7(param_2);
  FUN_004045b1();
  ExceptionList = local_14;
  return;
}



void FUN_004045b1(void)

{
  int unaff_EBP;
  
  ___acrt_unlock(**(int **)(unaff_EBP + 0x10));
  return;
}



uint __cdecl FUN_004045bd(uint param_1)

{
  byte bVar1;
  
  bVar1 = (byte)DAT_00423014 & 0x1f;
  return (param_1 ^ DAT_00423014) >> bVar1 | (param_1 ^ DAT_00423014) << 0x20 - bVar1;
}



// Library Function - Single Match
//  void (__stdcall*__cdecl __crt_fast_encode_pointer<void (__stdcall*)(void *,unsigned long,void
// *)>(void (__stdcall*const)(void *,unsigned long,void *)))(void *,unsigned long,void *)
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

_func_void_void_ptr_ulong_void_ptr * __cdecl
__crt_fast_encode_pointer<>(_func_void_void_ptr_ulong_void_ptr *param_1)

{
  byte bVar1;
  
  bVar1 = 0x20 - ((byte)DAT_00423014 & 0x1f) & 0x1f;
  return (_func_void_void_ptr_ulong_void_ptr *)
         (((uint)param_1 >> bVar1 | (int)param_1 << 0x20 - bVar1) ^ DAT_00423014);
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4

void __fastcall FUN_004045f7(int **param_1)

{
  code *pcVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined uVar4;
  undefined4 uVar5;
  void *local_14;
  
  if (DAT_00423d14 != '\0') {
    ExceptionList = local_14;
    return;
  }
  LOCK();
  DAT_00423d0c = 1;
  UNLOCK();
  if (**param_1 == 0) {
    if (DAT_00423d10 != DAT_00423014) {
      pcVar1 = (code *)FUN_004045bd(DAT_00423d10);
      uVar5 = 0;
      uVar3 = 0;
      uVar2 = 0;
      _guard_check_icall();
      (*pcVar1)(uVar2,uVar3,uVar5);
    }
    uVar4 = 0x6c;
  }
  else {
    if (**param_1 != 1) goto LAB_00404668;
    uVar4 = 0x78;
  }
  FUN_0040d87d(uVar4);
LAB_00404668:
  if (**param_1 == 0) {
    FUN_0040d3dc((undefined **)&DAT_0041b14c,(undefined **)&DAT_0041b15c);
  }
  FUN_0040d3dc((undefined **)&DAT_0041b160,(undefined **)&DAT_0041b164);
  if (*param_1[1] == 0) {
    DAT_00423d14 = '\x01';
    *(undefined *)param_1[2] = 1;
  }
  ExceptionList = local_14;
  return;
}



void __cdecl FUN_004046df(UINT param_1,undefined4 param_2,int param_3)

{
  code *pcVar1;
  uint uVar2;
  int *local_28;
  int *local_24;
  undefined *local_20;
  int local_1c;
  undefined4 local_18;
  undefined local_11;
  void *local_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_0041ad40;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  if (param_3 == 0) {
    uVar2 = FUN_00401df7();
    if ((char)uVar2 != '\0') {
      FUN_004047c0(param_1);
    }
  }
  local_28 = &param_2;
  local_11 = 0;
  local_24 = &param_3;
  local_20 = &local_11;
  local_8 = 0;
  local_18 = 2;
  local_1c = 2;
  operator()<>(&local_1c,&local_28);
  if (param_3 != 0) {
    ExceptionList = local_10;
    return;
  }
  FUN_00404776(param_1);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



void FUN_00404776(UINT param_1)

{
  char cVar1;
  HANDLE hProcess;
  UINT uExitCode;
  
  cVar1 = FUN_004047a7();
  if (cVar1 != '\0') {
    uExitCode = param_1;
    hProcess = GetCurrentProcess();
    TerminateProcess(hProcess,uExitCode);
  }
  FUN_004047c0(param_1);
                    // WARNING: Subroutine does not return
  ExitProcess(param_1);
}



char FUN_004047a7(void)

{
  bool bVar1;
  undefined3 extraout_var;
  uint uVar2;
  
  bVar1 = FUN_0040dfd7();
  if (CONCAT31(extraout_var,bVar1) != 1) {
    uVar2 = FUN_0040dfb2();
    return '\x01' - ((char)uVar2 != '\0');
  }
  return '\0';
}



void __cdecl FUN_004047c0(undefined4 param_1)

{
  uint uVar1;
  BOOL BVar2;
  FARPROC pFVar3;
  HMODULE local_14;
  void *local_10;
  undefined *puStack_c;
  undefined4 uStack_8;
  
  uStack_8 = 0xffffffff;
  puStack_c = &LAB_0041ad5d;
  local_10 = ExceptionList;
  uVar1 = DAT_00423014 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  local_14 = (HMODULE)0x0;
  BVar2 = GetModuleHandleExW(0,L"mscoree.dll",&local_14);
  if (BVar2 != 0) {
    pFVar3 = GetProcAddress(local_14,"CorExitProcess");
    if (pFVar3 != (FARPROC)0x0) {
      _guard_check_icall();
      (*pFVar3)(param_1,uVar1);
    }
  }
  if (local_14 != (HMODULE)0x0) {
    FreeLibrary(local_14);
  }
  ExceptionList = local_10;
  return;
}



void __cdecl FUN_00404842(undefined4 param_1)

{
  DAT_00423d10 = param_1;
  return;
}



// Library Function - Single Match
//  __cexit
// 
// Library: Visual Studio 2019 Release

void __cdecl __cexit(void)

{
  FUN_004046df(0,0,1);
  return;
}



// Library Function - Single Match
//  __exit
// 
// Library: Visual Studio 2019 Release

void __cdecl __exit(UINT param_1)

{
  FUN_004046df(param_1,2,0);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// Library Function - Single Match
//  __register_thread_local_exe_atexit_callback
// 
// Library: Visual Studio 2019 Release

void __cdecl
__register_thread_local_exe_atexit_callback(_func_void_void_ptr_ulong_void_ptr *param_1)

{
  code *pcVar1;
  __acrt_ptd *p_Var2;
  
  if (DAT_00423d10 == (_func_void_void_ptr_ulong_void_ptr *)DAT_00423014) {
    DAT_00423d10 = __crt_fast_encode_pointer<>(param_1);
    return;
  }
  p_Var2 = FUN_004104a9();
  pcVar1 = *(code **)(p_Var2 + 0xc);
  if (pcVar1 != (code *)0x0) {
    _guard_check_icall();
    (*pcVar1)();
  }
                    // WARNING: Subroutine does not return
  _abort();
}



// Library Function - Single Match
//  _exit
// 
// Library: Visual Studio 2019 Release

void __cdecl _exit(int _Code)

{
  FUN_004046df(_Code,0,0);
  return;
}



undefined * __cdecl FUN_00404989(int param_1)

{
  return &DAT_00423040 + param_1 * 0x38;
}



// Library Function - Single Match
//  __lock_file
// 
// Library: Visual Studio 2019 Release

void __cdecl __lock_file(FILE *_File)

{
  EnterCriticalSection((LPCRITICAL_SECTION)(_File + 1));
  return;
}



// Library Function - Single Match
//  __unlock_file
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void __cdecl __unlock_file(FILE *_File)

{
  LeaveCriticalSection((LPCRITICAL_SECTION)(_File + 1));
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// Library Function - Multiple Matches With Same Base Name
//  public: int __thiscall __crt_seh_guarded_call<int>::operator()<class
// <lambda_274ecf0a8038e561263518ab346655e8>,class <lambda_21448eb78dd3c4a522ed7c65a98d88e6> &,class
// <lambda_0ca1de2171e49cefb1e8dc85c06db622> >(class <lambda_274ecf0a8038e561263518ab346655e8>
// &&,class <lambda_21448eb78dd3c4a522ed7c65a98d88e6> &,class
// <lambda_0ca1de2171e49cefb1e8dc85c06db622> &&)
//  public: int __thiscall __crt_seh_guarded_call<int>::operator()<class
// <lambda_36ac44d44c28c1398f5e169dd4192dec>,class <lambda_3a6df4a947a8aa82799204b10582e979> &,class
// <lambda_252de749fd308ba532c6dc89db3d4ff4> >(class <lambda_36ac44d44c28c1398f5e169dd4192dec>
// &&,class <lambda_3a6df4a947a8aa82799204b10582e979> &,class
// <lambda_252de749fd308ba532c6dc89db3d4ff4> &&)
//  public: int __thiscall __crt_seh_guarded_call<int>::operator()<class
// <lambda_3cfd252a7c5e244e8f20fc56fe35ebe9>,class <lambda_d7427dbf72509eba5fa970998bac2a27> &,class
// <lambda_8f55a0afecd2292d47fde3ce68e72492> >(class <lambda_3cfd252a7c5e244e8f20fc56fe35ebe9>
// &&,class <lambda_d7427dbf72509eba5fa970998bac2a27> &,class
// <lambda_8f55a0afecd2292d47fde3ce68e72492> &&)
//  public: unsigned int __thiscall __crt_seh_guarded_call<unsigned int>::operator()<class
// <lambda_4ac01c32aa5b53846f05d0620572872e>,class <lambda_5856287d7ecd2be6c9197bb4007c3f6e> &,class
// <lambda_e7a9868ed898c75c0f0637692d94351a> >(class <lambda_4ac01c32aa5b53846f05d0620572872e>
// &&,class <lambda_5856287d7ecd2be6c9197bb4007c3f6e> &,class
// <lambda_e7a9868ed898c75c0f0637692d94351a> &&)
//   15 names - too many to list
// 
// Library: Visual Studio 2019 Release

undefined4 operator()<>(FILE **param_1,undefined4 *param_2)

{
  undefined4 uVar1;
  void *local_14;
  
  __lock_file(*param_1);
  uVar1 = FUN_004056aa(param_2);
  FUN_00404a5c();
  ExceptionList = local_14;
  return uVar1;
}



void FUN_00404a5c(void)

{
  int unaff_EBP;
  
  __unlock_file(**(FILE ***)(unaff_EBP + 0x10));
  return;
}



// Library Function - Single Match
//  public: unsigned int __thiscall __crt_stdio_output::formatting_buffer::count<char>(void)const 
// 
// Libraries: Visual Studio 2015, Visual Studio 2017, Visual Studio 2019

uint __thiscall __crt_stdio_output::formatting_buffer::count<char>(formatting_buffer *this)

{
  if (*(int *)(this + 0x404) == 0) {
    return 0x200;
  }
  return *(uint *)(this + 0x400) >> 1;
}



uint __thiscall FUN_00404a80(void *this,uint param_1,int param_2)

{
  undefined4 in_EAX;
  uint uVar1;
  void *local_8;
  
  if (param_1 < 0x80000000) {
    uVar1 = param_1 * 2;
    if (((*(int *)((int)this + 0x404) != 0) || (0x400 < uVar1)) &&
       (*(uint *)((int)this + 0x400) < uVar1)) {
      local_8 = this;
      local_8 = __malloc_base(uVar1);
      if (local_8 == (LPVOID)0x0) {
        uVar1 = FUN_0040e374((LPVOID)0x0);
        return uVar1 & 0xffffff00;
      }
      FUN_00405686((int *)((int)this + 0x404),&local_8);
      *(uint *)((int)this + 0x400) = uVar1;
      in_EAX = FUN_0040e374(local_8);
    }
    uVar1 = CONCAT31((int3)((uint)in_EAX >> 8),1);
  }
  else {
    *(undefined *)(param_2 + 0x1c) = 1;
    *(undefined4 *)(param_2 + 0x18) = 0xc;
    uVar1 = param_2 & 0xffffff00;
  }
  return uVar1;
}



bool __cdecl FUN_00404b01(byte param_1,uint param_2)

{
  if ((param_1 & 4) != 0) {
    return true;
  }
  if ((param_1 & 1) != 0) {
    if ((param_1 & 2) == 0) {
      return 0x7fffffff < param_2;
    }
    if (0x80000000 < param_2) {
      return true;
    }
  }
  return false;
}



// Library Function - Single Match
//  bool __cdecl __crt_stdio_output::is_wide_character_specifier<char>(unsigned __int64,char,enum
// __crt_stdio_output::length_modifier)
// 
// Libraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual
// Studio 2019 Release

bool __cdecl
__crt_stdio_output::is_wide_character_specifier<char>
          (__uint64 param_1,char param_2,length_modifier param_3)

{
  if ((param_3 != 2) &&
     (((param_3 == 3 || (param_3 == 0xc)) ||
      ((param_3 != 0xd && ((param_2 != 'c' && (param_2 != 's')))))))) {
    return true;
  }
  return false;
}



// Library Function - Multiple Matches With Same Base Name
//  class __crt_strtox::c_string_character_source<char> __cdecl
// __crt_strtox::make_c_string_character_source<char,std::nullptr_t>(char const *
// const,std::nullptr_t)
//  class __crt_strtox::c_string_character_source<char> __cdecl
// __crt_strtox::make_c_string_character_source<char,char * *>(char const * const,char * * const)
//  class __crt_strtox::c_string_character_source<wchar_t> __cdecl
// __crt_strtox::make_c_string_character_source<wchar_t,std::nullptr_t>(wchar_t const *
// const,std::nullptr_t)
//  class __crt_strtox::c_string_character_source<wchar_t> __cdecl
// __crt_strtox::make_c_string_character_source<wchar_t,wchar_t * *>(wchar_t const * const,wchar_t *
// * const)
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void __cdecl
make_c_string_character_source<>(undefined4 *param_1,undefined4 param_2,undefined4 *param_3)

{
  *param_1 = param_2;
  param_1[1] = param_3;
  if (param_3 != (undefined4 *)0x0) {
    *param_3 = param_2;
  }
  return;
}



uint __cdecl
FUN_00404b81(__acrt_ptd **param_1,char *param_2,char **param_3,uint param_4,byte param_5)

{
  char cVar1;
  char *pcVar2;
  bool bVar3;
  undefined4 uVar4;
  int iVar5;
  uint uVar6;
  uint uVar7;
  char *pcVar8;
  uint local_10;
  uint local_c;
  char local_8;
  
  uVar4 = FUN_0040653b((int *)&param_2);
  pcVar2 = param_2;
  if ((char)uVar4 == '\0') {
LAB_00404bc6:
    if (param_3 != (char **)0x0) {
      *param_3 = param_2;
    }
    return 0;
  }
  if ((param_4 != 0) && (((int)param_4 < 2 || (0x24 < (int)param_4)))) {
    *(undefined *)(param_1 + 7) = 1;
    param_1[6] = (__acrt_ptd *)0x16;
    FUN_0040e1a6((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0,param_1);
    goto LAB_00404bc6;
  }
  local_10 = 0;
  local_8 = *param_2;
  pcVar8 = param_2 + 1;
  local_c = (uint)param_5;
  if (local_8 == '-') {
    local_c = local_c | 2;
LAB_00404c0b:
    local_8 = *pcVar8;
    pcVar8 = param_2 + 2;
  }
  else if (local_8 == '+') goto LAB_00404c0b;
  uVar7 = param_4;
  param_2 = pcVar8;
  if ((param_4 != 0) && (param_4 != 0x10)) goto LAB_00404c92;
  if ((byte)(local_8 - 0x30U) < 10) {
    iVar5 = local_8 + -0x30;
LAB_00404c4b:
    if (iVar5 == 0) {
      cVar1 = *pcVar8;
      param_2 = pcVar8 + 1;
      if ((cVar1 == 'x') || (cVar1 == 'X')) {
        if (param_4 == 0) {
          uVar7 = 0x10;
        }
        local_8 = *param_2;
        param_2 = pcVar8 + 2;
      }
      else {
        if (param_4 == 0) {
          uVar7 = 8;
        }
        __crt_strtox::c_string_character_source<char>::unget
                  ((c_string_character_source<char> *)&param_2,cVar1);
      }
      goto LAB_00404c92;
    }
  }
  else {
    if ((byte)(local_8 + 0x9fU) < 0x1a) {
      iVar5 = local_8 + -0x57;
      goto LAB_00404c4b;
    }
    if ((byte)(local_8 + 0xbfU) < 0x1a) {
      iVar5 = local_8 + -0x37;
      goto LAB_00404c4b;
    }
  }
  if (param_4 == 0) {
    uVar7 = 10;
  }
LAB_00404c92:
  while( true ) {
    if ((byte)(local_8 - 0x30U) < 10) {
      uVar6 = (int)local_8 - 0x30;
    }
    else if ((byte)(local_8 + 0x9fU) < 0x1a) {
      uVar6 = (int)local_8 - 0x57;
    }
    else if ((byte)(local_8 + 0xbfU) < 0x1a) {
      uVar6 = (int)local_8 - 0x37;
    }
    else {
      uVar6 = 0xffffffff;
    }
    if (uVar7 <= uVar6) break;
    local_8 = *param_2;
    uVar6 = uVar6 + local_10 * uVar7;
    local_c = local_c | (uint)(uVar6 < local_10 * uVar7 ||
                              (uint)(0xffffffff / (ulonglong)uVar7) < local_10) << 2 | 8;
    param_2 = param_2 + 1;
    local_10 = uVar6;
  }
  __crt_strtox::c_string_character_source<char>::unget
            ((c_string_character_source<char> *)&param_2,local_8);
  if ((local_c & 8) == 0) {
    if (param_3 == (char **)0x0) {
      return 0;
    }
    *param_3 = pcVar2;
    return 0;
  }
  bVar3 = FUN_00404b01((byte)local_c,local_10);
  if (bVar3) {
    *(undefined *)(param_1 + 7) = 1;
    param_1[6] = (__acrt_ptd *)0x22;
    if ((local_c & 1) != 0) {
      if ((local_c & 2) == 0) {
        if (param_3 != (char **)0x0) {
          *param_3 = param_2;
        }
        return 0x7fffffff;
      }
      if (param_3 != (char **)0x0) {
        *param_3 = param_2;
      }
      return 0x80000000;
    }
    local_10 = 0xffffffff;
  }
  else if ((local_c & 2) != 0) {
    local_10 = -local_10;
  }
  if (param_3 != (char **)0x0) {
    *param_3 = param_2;
    return local_10;
  }
  return local_10;
}



// Library Function - Single Match
//  public: char * __thiscall __crt_stdio_output::formatting_buffer::scratch_data<char>(void)
// 
// Libraries: Visual Studio 2015, Visual Studio 2017, Visual Studio 2019

char * __thiscall __crt_stdio_output::formatting_buffer::scratch_data<char>(formatting_buffer *this)

{
  int iVar1;
  uint uVar2;
  formatting_buffer *pfVar3;
  
  iVar1 = *(int *)(this + 0x404);
  uVar2 = count<char>(this);
  if (iVar1 == 0) {
    pfVar3 = this + uVar2;
  }
  else {
    pfVar3 = (formatting_buffer *)(uVar2 + iVar1);
  }
  return (char *)pfVar3;
}



uint __fastcall FUN_00404dae(void *param_1,undefined param_2,undefined4 param_3)

{
  int iVar1;
  uint *puVar2;
  ushort *puVar3;
  byte *pbVar4;
  uint uVar5;
  char *pcVar6;
  uint uVar7;
  uint uVar8;
  bool bVar9;
  uint local_c;
  
  uVar5 = __crt_stdio_output::to_integer_size(*(length_modifier *)((int)param_1 + 0x28));
  if (uVar5 == 1) {
    uVar8 = *(uint *)((int)param_1 + 0x1c);
    pbVar4 = *(byte **)((int)param_1 + 0x10);
    *(byte **)((int)param_1 + 0x10) = pbVar4 + 4;
    if ((uVar8 >> 4 & 1) == 0) {
      uVar7 = (uint)*pbVar4;
    }
    else {
      uVar7 = (uint)(char)*pbVar4;
    }
  }
  else if (uVar5 == 2) {
    uVar8 = *(uint *)((int)param_1 + 0x1c);
    puVar3 = *(ushort **)((int)param_1 + 0x10);
    *(ushort **)((int)param_1 + 0x10) = puVar3 + 2;
    if ((uVar8 >> 4 & 1) == 0) {
      uVar7 = (uint)*puVar3;
    }
    else {
      uVar7 = (uint)(short)*puVar3;
    }
  }
  else {
    if (uVar5 != 4) {
      if (uVar5 != 8) {
        iVar1 = *(int *)((int)param_1 + 8);
        *(undefined *)(iVar1 + 0x1c) = 1;
        *(undefined4 *)(iVar1 + 0x18) = 0x16;
        uVar5 = FUN_0040e1a6((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0,
                             *(__acrt_ptd ***)((int)param_1 + 8));
        return uVar5 & 0xffffff00;
      }
      puVar2 = *(uint **)((int)param_1 + 0x10);
      uVar8 = *(uint *)((int)param_1 + 0x1c);
      *(uint **)((int)param_1 + 0x10) = puVar2 + 2;
      uVar7 = *puVar2;
      local_c = puVar2[1];
      goto LAB_00404e8f;
    }
    uVar8 = *(uint *)((int)param_1 + 0x1c);
    if ((uVar8 >> 4 & 1) == 0) {
      puVar2 = *(uint **)((int)param_1 + 0x10);
      local_c = 0;
      *(uint **)((int)param_1 + 0x10) = puVar2 + 1;
      uVar7 = *puVar2;
      goto LAB_00404e8f;
    }
    puVar2 = *(uint **)((int)param_1 + 0x10);
    *(uint **)((int)param_1 + 0x10) = puVar2 + 1;
    uVar7 = *puVar2;
  }
  local_c = (int)uVar7 >> 0x1f;
LAB_00404e8f:
  if ((((uVar8 >> 4 & 1) != 0) && ((int)local_c < 1)) && ((int)local_c < 0)) {
    bVar9 = uVar7 != 0;
    uVar7 = -uVar7;
    local_c = -(local_c + bVar9);
    uVar8 = uVar8 | 0x40;
    *(uint *)((int)param_1 + 0x1c) = uVar8;
  }
  if (*(int *)((int)param_1 + 0x24) < 0) {
    *(undefined4 *)((int)param_1 + 0x24) = 1;
  }
  else {
    *(uint *)((int)param_1 + 0x1c) = uVar8 & 0xfffffff7;
    FUN_00404a80((void *)((int)param_1 + 0x3c),*(uint *)((int)param_1 + 0x24),
                 *(int *)((int)param_1 + 8));
  }
  if ((uVar7 | local_c) == 0) {
    *(uint *)((int)param_1 + 0x1c) = *(uint *)((int)param_1 + 0x1c) & 0xffffffdf;
  }
  *(undefined *)((int)param_1 + 0x38) = 0;
  if (uVar5 == 8) {
    FUN_004053bc(param_1,uVar7,local_c);
  }
  else {
    FUN_00405255(param_1,uVar7);
  }
  pcVar6 = (char *)(*(uint *)((int)param_1 + 0x1c) >> 7);
  if ((((uint)pcVar6 & 1) != 0) &&
     ((*(int *)((int)param_1 + 0x34) == 0 ||
      (pcVar6 = *(char **)((int)param_1 + 0x30), *pcVar6 != '0')))) {
    *(int *)((int)param_1 + 0x30) = *(int *)((int)param_1 + 0x30) + -1;
    **(undefined **)((int)param_1 + 0x30) = 0x30;
    *(int *)((int)param_1 + 0x34) = *(int *)((int)param_1 + 0x34) + 1;
  }
  return CONCAT31((int3)((uint)pcVar6 >> 8),1);
}



uint __thiscall FUN_00404f3b(void *this,byte param_1)

{
  int iVar1;
  uint *puVar2;
  ushort *puVar3;
  byte *pbVar4;
  uint uVar5;
  char *pcVar6;
  uint uVar7;
  uint uVar8;
  bool bVar9;
  uint local_c;
  
  uVar5 = __crt_stdio_output::to_integer_size(*(length_modifier *)((int)this + 0x28));
  if (uVar5 == 1) {
    uVar8 = *(uint *)((int)this + 0x1c);
    pbVar4 = *(byte **)((int)this + 0x10);
    *(byte **)((int)this + 0x10) = pbVar4 + 4;
    if ((uVar8 >> 4 & 1) == 0) {
      uVar7 = (uint)*pbVar4;
    }
    else {
      uVar7 = (uint)(char)*pbVar4;
    }
  }
  else if (uVar5 == 2) {
    uVar8 = *(uint *)((int)this + 0x1c);
    puVar3 = *(ushort **)((int)this + 0x10);
    *(ushort **)((int)this + 0x10) = puVar3 + 2;
    if ((uVar8 >> 4 & 1) == 0) {
      uVar7 = (uint)*puVar3;
    }
    else {
      uVar7 = (uint)(short)*puVar3;
    }
  }
  else {
    if (uVar5 != 4) {
      if (uVar5 != 8) {
        iVar1 = *(int *)((int)this + 8);
        *(undefined *)(iVar1 + 0x1c) = 1;
        *(undefined4 *)(iVar1 + 0x18) = 0x16;
        uVar5 = FUN_0040e1a6((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0,
                             *(__acrt_ptd ***)((int)this + 8));
        return uVar5 & 0xffffff00;
      }
      puVar2 = *(uint **)((int)this + 0x10);
      uVar8 = *(uint *)((int)this + 0x1c);
      *(uint **)((int)this + 0x10) = puVar2 + 2;
      uVar7 = *puVar2;
      local_c = puVar2[1];
      goto LAB_0040501c;
    }
    uVar8 = *(uint *)((int)this + 0x1c);
    if ((uVar8 >> 4 & 1) == 0) {
      puVar2 = *(uint **)((int)this + 0x10);
      local_c = 0;
      *(uint **)((int)this + 0x10) = puVar2 + 1;
      uVar7 = *puVar2;
      goto LAB_0040501c;
    }
    puVar2 = *(uint **)((int)this + 0x10);
    *(uint **)((int)this + 0x10) = puVar2 + 1;
    uVar7 = *puVar2;
  }
  local_c = (int)uVar7 >> 0x1f;
LAB_0040501c:
  if ((((uVar8 >> 4 & 1) != 0) && ((int)local_c < 1)) && ((int)local_c < 0)) {
    bVar9 = uVar7 != 0;
    uVar7 = -uVar7;
    local_c = -(local_c + bVar9);
    uVar8 = uVar8 | 0x40;
    *(uint *)((int)this + 0x1c) = uVar8;
  }
  if (*(int *)((int)this + 0x24) < 0) {
    *(undefined4 *)((int)this + 0x24) = 1;
  }
  else {
    *(uint *)((int)this + 0x1c) = uVar8 & 0xfffffff7;
    FUN_00404a80((void *)((int)this + 0x3c),*(uint *)((int)this + 0x24),*(int *)((int)this + 8));
  }
  if ((uVar7 | local_c) == 0) {
    *(uint *)((int)this + 0x1c) = *(uint *)((int)this + 0x1c) & 0xffffffdf;
  }
  *(undefined *)((int)this + 0x38) = 0;
  if (uVar5 == 8) {
    FUN_00405434(this,uVar7,local_c,param_1);
  }
  else {
    FUN_004052b8(this,uVar7,param_1);
  }
  pcVar6 = (char *)(*(uint *)((int)this + 0x1c) >> 7);
  if ((((uint)pcVar6 & 1) != 0) &&
     ((*(int *)((int)this + 0x34) == 0 || (pcVar6 = *(char **)((int)this + 0x30), *pcVar6 != '0'))))
  {
    *(int *)((int)this + 0x30) = *(int *)((int)this + 0x30) + -1;
    **(undefined **)((int)this + 0x30) = 0x30;
    *(int *)((int)this + 0x34) = *(int *)((int)this + 0x34) + 1;
  }
  return CONCAT31((int3)((uint)pcVar6 >> 8),1);
}



uint __thiscall FUN_004050c8(void *this,byte param_1)

{
  int iVar1;
  uint *puVar2;
  ushort *puVar3;
  byte *pbVar4;
  uint uVar5;
  char *pcVar6;
  uint uVar7;
  uint uVar8;
  bool bVar9;
  uint local_c;
  
  uVar5 = __crt_stdio_output::to_integer_size(*(length_modifier *)((int)this + 0x28));
  if (uVar5 == 1) {
    uVar8 = *(uint *)((int)this + 0x1c);
    pbVar4 = *(byte **)((int)this + 0x10);
    *(byte **)((int)this + 0x10) = pbVar4 + 4;
    if ((uVar8 >> 4 & 1) == 0) {
      uVar7 = (uint)*pbVar4;
    }
    else {
      uVar7 = (uint)(char)*pbVar4;
    }
  }
  else if (uVar5 == 2) {
    uVar8 = *(uint *)((int)this + 0x1c);
    puVar3 = *(ushort **)((int)this + 0x10);
    *(ushort **)((int)this + 0x10) = puVar3 + 2;
    if ((uVar8 >> 4 & 1) == 0) {
      uVar7 = (uint)*puVar3;
    }
    else {
      uVar7 = (uint)(short)*puVar3;
    }
  }
  else {
    if (uVar5 != 4) {
      if (uVar5 != 8) {
        iVar1 = *(int *)((int)this + 8);
        *(undefined *)(iVar1 + 0x1c) = 1;
        *(undefined4 *)(iVar1 + 0x18) = 0x16;
        uVar5 = FUN_0040e1a6((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0,
                             *(__acrt_ptd ***)((int)this + 8));
        return uVar5 & 0xffffff00;
      }
      puVar2 = *(uint **)((int)this + 0x10);
      uVar8 = *(uint *)((int)this + 0x1c);
      *(uint **)((int)this + 0x10) = puVar2 + 2;
      uVar7 = *puVar2;
      local_c = puVar2[1];
      goto LAB_004051a9;
    }
    uVar8 = *(uint *)((int)this + 0x1c);
    if ((uVar8 >> 4 & 1) == 0) {
      puVar2 = *(uint **)((int)this + 0x10);
      local_c = 0;
      *(uint **)((int)this + 0x10) = puVar2 + 1;
      uVar7 = *puVar2;
      goto LAB_004051a9;
    }
    puVar2 = *(uint **)((int)this + 0x10);
    *(uint **)((int)this + 0x10) = puVar2 + 1;
    uVar7 = *puVar2;
  }
  local_c = (int)uVar7 >> 0x1f;
LAB_004051a9:
  if ((((uVar8 >> 4 & 1) != 0) && ((int)local_c < 1)) && ((int)local_c < 0)) {
    bVar9 = uVar7 != 0;
    uVar7 = -uVar7;
    local_c = -(local_c + bVar9);
    uVar8 = uVar8 | 0x40;
    *(uint *)((int)this + 0x1c) = uVar8;
  }
  if (*(int *)((int)this + 0x24) < 0) {
    *(undefined4 *)((int)this + 0x24) = 1;
  }
  else {
    *(uint *)((int)this + 0x1c) = uVar8 & 0xfffffff7;
    FUN_00404a80((void *)((int)this + 0x3c),*(uint *)((int)this + 0x24),*(int *)((int)this + 8));
  }
  if ((uVar7 | local_c) == 0) {
    *(uint *)((int)this + 0x1c) = *(uint *)((int)this + 0x1c) & 0xffffffdf;
  }
  *(undefined *)((int)this + 0x38) = 0;
  if (uVar5 == 8) {
    FUN_004054db(this,uVar7,local_c,param_1);
  }
  else {
    FUN_0040533f(this,uVar7,param_1);
  }
  pcVar6 = (char *)(*(uint *)((int)this + 0x1c) >> 7);
  if ((((uint)pcVar6 & 1) != 0) &&
     ((*(int *)((int)this + 0x34) == 0 || (pcVar6 = *(char **)((int)this + 0x30), *pcVar6 != '0'))))
  {
    *(int *)((int)this + 0x30) = *(int *)((int)this + 0x30) + -1;
    **(undefined **)((int)this + 0x30) = 0x30;
    *(int *)((int)this + 0x34) = *(int *)((int)this + 0x34) + 1;
  }
  return CONCAT31((int3)((uint)pcVar6 >> 8),1);
}



void __thiscall FUN_00405255(void *this,uint param_1)

{
  uint uVar1;
  formatting_buffer *pfVar2;
  formatting_buffer *pfVar3;
  
  pfVar3 = *(formatting_buffer **)((int)this + 0x440);
  if (*(formatting_buffer **)((int)this + 0x440) == (formatting_buffer *)0x0) {
    pfVar3 = (formatting_buffer *)((int)this + 0x3c);
  }
  uVar1 = __crt_stdio_output::formatting_buffer::count<char>
                    ((formatting_buffer *)((int)this + 0x3c));
  pfVar3 = pfVar3 + (uVar1 - 1);
  *(formatting_buffer **)((int)this + 0x30) = pfVar3;
  pfVar2 = pfVar3;
  for (; (0 < *(int *)((int)this + 0x24) || (param_1 != 0)); param_1 = param_1 >> 3) {
    *(int *)((int)this + 0x24) = *(int *)((int)this + 0x24) + -1;
    *pfVar2 = (formatting_buffer)(((byte)param_1 & 7) + 0x30);
    *(int *)((int)this + 0x30) = *(int *)((int)this + 0x30) + -1;
    pfVar2 = *(formatting_buffer **)((int)this + 0x30);
  }
  *(int *)((int)this + 0x34) = (int)pfVar3 - (int)pfVar2;
  *(formatting_buffer **)((int)this + 0x30) = pfVar2 + 1;
  return;
}



void __thiscall FUN_004052b8(void *this,uint param_1,byte param_2)

{
  uint uVar1;
  formatting_buffer fVar2;
  formatting_buffer *pfVar3;
  formatting_buffer *pfVar4;
  
  pfVar3 = *(formatting_buffer **)((int)this + 0x440);
  if (*(formatting_buffer **)((int)this + 0x440) == (formatting_buffer *)0x0) {
    pfVar3 = (formatting_buffer *)((int)this + 0x3c);
  }
  uVar1 = __crt_stdio_output::formatting_buffer::count<char>
                    ((formatting_buffer *)((int)this + 0x3c));
  pfVar3 = pfVar3 + (uVar1 - 1);
  *(formatting_buffer **)((int)this + 0x30) = pfVar3;
  pfVar4 = pfVar3;
  while ((0 < *(int *)((int)this + 0x24) || (param_1 != 0))) {
    *(int *)((int)this + 0x24) = *(int *)((int)this + 0x24) + -1;
    fVar2 = (formatting_buffer)((char)(param_1 % 10) + '0');
    param_1 = param_1 / 10;
    if (0x39 < (byte)fVar2) {
      fVar2 = (formatting_buffer)((char)fVar2 + (param_2 ^ 1) * ' ' + '\a');
    }
    *pfVar4 = fVar2;
    *(int *)((int)this + 0x30) = *(int *)((int)this + 0x30) + -1;
    pfVar4 = *(formatting_buffer **)((int)this + 0x30);
  }
  *(int *)((int)this + 0x34) = (int)pfVar3 - (int)pfVar4;
  *(formatting_buffer **)((int)this + 0x30) = pfVar4 + 1;
  return;
}



void __thiscall FUN_0040533f(void *this,uint param_1,byte param_2)

{
  byte bVar1;
  formatting_buffer fVar2;
  uint uVar3;
  formatting_buffer *pfVar4;
  formatting_buffer *pfVar5;
  
  pfVar5 = *(formatting_buffer **)((int)this + 0x440);
  if (*(formatting_buffer **)((int)this + 0x440) == (formatting_buffer *)0x0) {
    pfVar5 = (formatting_buffer *)((int)this + 0x3c);
  }
  uVar3 = __crt_stdio_output::formatting_buffer::count<char>
                    ((formatting_buffer *)((int)this + 0x3c));
  pfVar5 = pfVar5 + (uVar3 - 1);
  *(formatting_buffer **)((int)this + 0x30) = pfVar5;
  pfVar4 = pfVar5;
  while ((0 < *(int *)((int)this + 0x24) || (param_1 != 0))) {
    *(int *)((int)this + 0x24) = *(int *)((int)this + 0x24) + -1;
    bVar1 = (byte)param_1;
    param_1 = param_1 >> 4;
    fVar2 = (formatting_buffer)((bVar1 & 0xf) + 0x30);
    if (0x39 < (byte)fVar2) {
      fVar2 = (formatting_buffer)((param_2 ^ 1) * ' ' + '\a' + (char)fVar2);
    }
    *pfVar4 = fVar2;
    *(int *)((int)this + 0x30) = *(int *)((int)this + 0x30) + -1;
    pfVar4 = *(formatting_buffer **)((int)this + 0x30);
  }
  *(int *)((int)this + 0x34) = (int)pfVar5 - (int)pfVar4;
  *(formatting_buffer **)((int)this + 0x30) = pfVar4 + 1;
  return;
}



void __thiscall FUN_004053bc(void *this,uint param_1,uint param_2)

{
  byte bVar1;
  uint uVar2;
  int iVar3;
  formatting_buffer *pfVar4;
  formatting_buffer *pfVar5;
  
  pfVar4 = *(formatting_buffer **)((int)this + 0x440);
  if (*(formatting_buffer **)((int)this + 0x440) == (formatting_buffer *)0x0) {
    pfVar4 = (formatting_buffer *)((int)this + 0x3c);
  }
  uVar2 = __crt_stdio_output::formatting_buffer::count<char>
                    ((formatting_buffer *)((int)this + 0x3c));
  pfVar4 = pfVar4 + (uVar2 - 1);
  *(formatting_buffer **)((int)this + 0x30) = pfVar4;
  pfVar5 = pfVar4;
  do {
    iVar3 = *(int *)((int)this + 0x24);
    if (iVar3 < 1) {
      if ((param_1 | param_2) == 0) {
        *(int *)((int)this + 0x34) = (int)pfVar4 - (int)pfVar5;
        *(formatting_buffer **)((int)this + 0x30) = pfVar5 + 1;
        return;
      }
      iVar3 = *(int *)((int)this + 0x24);
    }
    *(int *)((int)this + 0x24) = iVar3 + -1;
    bVar1 = (byte)param_1;
    param_1 = param_1 >> 3 | param_2 << 0x1d;
    *pfVar5 = (formatting_buffer)((bVar1 & 7) + 0x30);
    param_2 = param_2 >> 3;
    *(int *)((int)this + 0x30) = *(int *)((int)this + 0x30) + -1;
    pfVar5 = *(formatting_buffer **)((int)this + 0x30);
  } while( true );
}



void __thiscall FUN_00405434(void *this,uint param_1,undefined4 param_2,byte param_3)

{
  uint uVar1;
  formatting_buffer *pfVar2;
  formatting_buffer fVar3;
  formatting_buffer *pfVar4;
  undefined8 uVar5;
  longlong lVar6;
  uint local_8;
  
  pfVar4 = *(formatting_buffer **)((int)this + 0x440);
  if (*(formatting_buffer **)((int)this + 0x440) == (formatting_buffer *)0x0) {
    pfVar4 = (formatting_buffer *)((int)this + 0x3c);
  }
  uVar1 = __crt_stdio_output::formatting_buffer::count<char>
                    ((formatting_buffer *)((int)this + 0x3c));
  pfVar4 = pfVar4 + (uVar1 - 1);
  *(formatting_buffer **)((int)this + 0x30) = pfVar4;
  lVar6 = CONCAT44(param_2,param_1);
  local_8 = param_1;
  pfVar2 = pfVar4;
  while( true ) {
    uVar1 = (uint)((ulonglong)lVar6 >> 0x20);
    if ((*(int *)((int)this + 0x24) < 1) && (lVar6 == 0)) break;
    *(int *)((int)this + 0x24) = *(int *)((int)this + 0x24) + -1;
    uVar5 = __aullrem(local_8,uVar1,10,0);
    fVar3 = (formatting_buffer)((char)uVar5 + '0');
    lVar6 = __aulldiv(local_8,uVar1,10,0);
    local_8 = (uint)lVar6;
    if ('9' < (char)fVar3) {
      fVar3 = (formatting_buffer)((param_3 ^ 1) * ' ' + '\a' + (char)fVar3);
    }
    *pfVar2 = fVar3;
    *(int *)((int)this + 0x30) = *(int *)((int)this + 0x30) + -1;
    pfVar2 = *(formatting_buffer **)((int)this + 0x30);
  }
  *(int *)((int)this + 0x34) = (int)pfVar4 - (int)pfVar2;
  *(formatting_buffer **)((int)this + 0x30) = pfVar2 + 1;
  return;
}



void __thiscall FUN_004054db(void *this,uint param_1,uint param_2,byte param_3)

{
  byte bVar1;
  formatting_buffer fVar2;
  uint uVar3;
  int iVar4;
  formatting_buffer *pfVar5;
  formatting_buffer *pfVar6;
  
  pfVar5 = *(formatting_buffer **)((int)this + 0x440);
  if (*(formatting_buffer **)((int)this + 0x440) == (formatting_buffer *)0x0) {
    pfVar5 = (formatting_buffer *)((int)this + 0x3c);
  }
  uVar3 = __crt_stdio_output::formatting_buffer::count<char>
                    ((formatting_buffer *)((int)this + 0x3c));
  pfVar5 = pfVar5 + (uVar3 - 1);
  *(formatting_buffer **)((int)this + 0x30) = pfVar5;
  pfVar6 = pfVar5;
  do {
    iVar4 = *(int *)((int)this + 0x24);
    if (iVar4 < 1) {
      if ((param_1 | param_2) == 0) {
        *(int *)((int)this + 0x34) = (int)pfVar5 - (int)pfVar6;
        *(formatting_buffer **)((int)this + 0x30) = pfVar6 + 1;
        return;
      }
      iVar4 = *(int *)((int)this + 0x24);
    }
    *(int *)((int)this + 0x24) = iVar4 + -1;
    bVar1 = (byte)param_1;
    param_1 = param_1 >> 4 | param_2 << 0x1c;
    fVar2 = (formatting_buffer)((bVar1 & 0xf) + 0x30);
    param_2 = param_2 >> 4;
    if (0x39 < (byte)fVar2) {
      fVar2 = (formatting_buffer)((param_3 ^ 1) * ' ' + '\a' + (char)fVar2);
    }
    *pfVar6 = fVar2;
    *(int *)((int)this + 0x30) = *(int *)((int)this + 0x30) + -1;
    pfVar6 = *(formatting_buffer **)((int)this + 0x30);
  } while( true );
}



undefined4 * __thiscall
FUN_00405565(void *this,undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4
            ,undefined4 param_5,undefined4 param_6)

{
  *(undefined4 *)((int)this + 8) = param_5;
  *(undefined4 *)this = 0;
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined4 *)((int)this + 0xc) = 0;
  *(undefined4 *)((int)this + 0x10) = 0;
  *(undefined4 *)((int)this + 0x43c) = 0;
  *(undefined4 *)((int)this + 0x440) = 0;
  *(undefined4 *)((int)this + 0x14) = 0;
  *(undefined *)((int)this + 0x18) = 0;
  *(undefined4 *)((int)this + 0x1c) = 0;
  *(undefined4 *)((int)this + 0x20) = 0;
  *(undefined4 *)((int)this + 0x24) = 0;
  *(undefined2 *)((int)this + 0x2c) = 0;
  *(undefined4 *)((int)this + 0x34) = 0;
  *(undefined *)((int)this + 0x38) = 0;
  *(undefined4 *)((int)this + 0x448) = *param_1;
  *(undefined4 *)this = param_2;
  *(undefined4 *)((int)this + 0xc) = param_4;
  *(undefined4 *)((int)this + 0x10) = param_6;
  *(undefined4 *)((int)this + 4) = param_3;
  return (undefined4 *)this;
}



undefined4 * __thiscall FUN_004055d0(void *this,undefined4 *param_1)

{
  undefined4 uVar1;
  undefined *puVar2;
  undefined *puVar3;
  
  *(undefined *)((int)this + 0x14) = 0;
  *(undefined4 *)this = 0;
  *(undefined *)((int)this + 8) = 0;
  *(undefined *)((int)this + 0x1c) = 0;
  *(undefined *)((int)this + 0x24) = 0;
  puVar3 = PTR_DAT_004231f4;
  puVar2 = PTR_PTR_DAT_004231f0;
  if (param_1 != (undefined4 *)0x0) {
    uVar1 = param_1[1];
    *(undefined4 *)((int)this + 0xc) = *param_1;
    *(undefined *)((int)this + 0x14) = 1;
    *(undefined4 *)((int)this + 0x10) = uVar1;
    return (undefined4 *)this;
  }
  if (DAT_00423e60 == 0) {
    *(undefined *)((int)this + 0x14) = 1;
    *(undefined **)((int)this + 0x10) = puVar3;
    *(undefined **)((int)this + 0xc) = puVar2;
  }
  return (undefined4 *)this;
}



void __fastcall FUN_00405630(__acrt_ptd **param_1)

{
  __acrt_ptd *p_Var1;
  __acrt_ptd *p_Var2;
  
  if (*(char *)(param_1 + 5) == '\x02') {
    *(uint *)(*param_1 + 0x350) = *(uint *)(*param_1 + 0x350) & 0xfffffffd;
  }
  if (*(char *)(param_1 + 7) != '\0') {
    p_Var1 = param_1[6];
    p_Var2 = FUN_00405890(param_1);
    *(__acrt_ptd **)(p_Var2 + 0x10) = p_Var1;
  }
  if (*(char *)(param_1 + 9) != '\0') {
    p_Var1 = param_1[8];
    p_Var2 = FUN_00405890(param_1);
    *(__acrt_ptd **)(p_Var2 + 0x14) = p_Var1;
  }
  return;
}



void __fastcall FUN_0040566c(int param_1)

{
  FUN_0040e374(*(LPVOID *)(param_1 + 0x404));
  *(undefined4 *)(param_1 + 0x404) = 0;
  return;
}



LPVOID * __thiscall FUN_00405686(void *this,LPVOID *param_1)

{
                    // WARNING: Load size is inaccurate
  FUN_0040e374(*this);
  *(undefined4 *)this = 0;
  *(LPVOID *)this = *param_1;
  *param_1 = (LPVOID)0x0;
  return (LPVOID *)this;
}



void __fastcall FUN_004056aa(undefined4 *param_1)

{
  __acrt_ptd **pp_Var1;
  FILE *pFVar2;
  undefined4 uVar3;
  undefined4 local_464;
  __uint64 local_460 [7];
  undefined local_424 [1044];
  undefined4 local_10;
  uint local_8;
  
  local_8 = DAT_00423014 ^ (uint)&stack0xfffffffc;
  pp_Var1 = (__acrt_ptd **)param_1[1];
  pFVar2 = *(FILE **)*param_1;
  uVar3 = FUN_00410082(pFVar2);
  local_464 = *(undefined4 *)*param_1;
  FUN_00405565(local_460,&local_464,*(undefined4 *)param_1[2],((undefined4 *)param_1[2])[1],
               *(undefined4 *)param_1[3],param_1[1],*(undefined4 *)param_1[4]);
  local_10 = 0;
  FUN_00405964(local_460);
  FUN_0040566c((int)local_424);
  FUN_0041012d((char)uVar3,pFVar2,pp_Var1);
  FUN_00402125(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_00405746(char *param_1,int *param_2)

{
  char cVar1;
  char *pcVar2;
  char *pcVar3;
  
  cVar1 = *param_1;
  while ((cVar1 != '\0' && (cVar1 != ***(char ***)(*param_2 + 0x88)))) {
    param_1 = param_1 + 1;
    cVar1 = *param_1;
  }
  if (cVar1 != '\0') {
    do {
      param_1 = param_1 + 1;
      cVar1 = *param_1;
      pcVar2 = param_1;
      if ((cVar1 == '\0') || (cVar1 == 'e')) break;
    } while (cVar1 != 'E');
    do {
      pcVar3 = pcVar2;
      pcVar2 = pcVar3 + -1;
    } while (*pcVar2 == '0');
    if (*pcVar2 == ***(char ***)(*param_2 + 0x88)) {
      pcVar2 = pcVar3 + -2;
    }
    do {
      cVar1 = *param_1;
      param_1 = param_1 + 1;
      pcVar2 = pcVar2 + 1;
      *pcVar2 = cVar1;
    } while (cVar1 != '\0');
  }
  return;
}



undefined FUN_004057a6(char param_1,byte param_2)

{
  byte bVar1;
  
  if ((byte)(param_1 - 0x20U) < 0x5b) {
    bVar1 = (&DAT_0041bcb1)[((int)param_1 - 0x20U & 0x7f) * 2];
  }
  else {
    bVar1 = 0;
  }
  return (&DAT_0041bcb0)[((uint)param_2 + (uint)bVar1 * 8 & 0x7f) * 2];
}



// Library Function - Single Match
//  void __cdecl __crt_stdio_output::force_decimal_point(char *,struct __crt_locale_pointers *
// const)
// 
// Libraries: Visual Studio 2019 Debug, Visual Studio 2019 Release

void __cdecl __crt_stdio_output::force_decimal_point(char *param_1,__crt_locale_pointers *param_2)

{
  byte bVar1;
  int *piVar2;
  byte bVar3;
  bool bVar4;
  
  piVar2 = *(int **)param_2;
  bVar3 = *param_1;
  if (*(char *)((uint)bVar3 + piVar2[0x25]) != 'e') {
    do {
      param_1 = (char *)((byte *)param_1 + 1);
      bVar3 = *param_1;
    } while ((*(byte *)(*piVar2 + (uint)bVar3 * 2) & 4) != 0);
  }
  if (*(char *)((uint)bVar3 + piVar2[0x25]) == 'x') {
    param_1 = (char *)((byte *)param_1 + 2);
    bVar3 = *param_1;
  }
  *param_1 = **(byte **)piVar2[0x22];
  do {
    param_1 = (char *)((byte *)param_1 + 1);
    bVar1 = *param_1;
    *param_1 = bVar3;
    bVar4 = bVar3 != 0;
    bVar3 = bVar1;
  } while (bVar4);
  return;
}



__acrt_ptd * __fastcall FUN_00405840(__acrt_ptd **param_1)

{
  __acrt_ptd *p_Var1;
  __acrt_ptd **local_8;
  
  local_8 = param_1;
  local_8 = (__acrt_ptd **)GetLastError();
  if (*(char *)(param_1 + 2) == '\0') {
    param_1[1] = (__acrt_ptd *)0x0;
    p_Var1 = (__acrt_ptd *)0x0;
    *(undefined *)(param_1 + 2) = 1;
  }
  else {
    p_Var1 = param_1[1];
  }
  p_Var1 = FUN_004106ab(&local_8,(int)p_Var1);
  *param_1 = p_Var1;
  SetLastError((DWORD)local_8);
  return p_Var1;
}



__acrt_ptd * __fastcall FUN_00405890(__acrt_ptd **param_1)

{
  __acrt_ptd *p_Var1;
  __acrt_ptd **local_8;
  
  if (*param_1 == (__acrt_ptd *)0x0) {
    local_8 = param_1;
    local_8 = (__acrt_ptd **)GetLastError();
    if (*(char *)(param_1 + 2) == '\0') {
      param_1[1] = (__acrt_ptd *)0x0;
      p_Var1 = (__acrt_ptd *)0x0;
      *(undefined *)(param_1 + 2) = 1;
    }
    else {
      p_Var1 = param_1[1];
    }
    p_Var1 = FUN_004106ab(&local_8,(int)p_Var1);
    *param_1 = p_Var1;
    SetLastError((DWORD)local_8);
    if (p_Var1 == (__acrt_ptd *)0x0) {
                    // WARNING: Subroutine does not return
      _abort();
    }
  }
  return *param_1;
}



undefined4 __thiscall FUN_004058ec(void *this,uint *param_1)

{
  __acrt_ptd **pp_Var1;
  __acrt_ptd *p_Var2;
  __acrt_ptd *p_Var3;
  uint uVar4;
  undefined uVar5;
  char *local_8;
  
  uVar5 = 1;
  pp_Var1 = *(__acrt_ptd ***)((int)this + 8);
  local_8 = (char *)(*(int *)((int)this + 0xc) + -1);
  p_Var2 = pp_Var1[6];
  p_Var3 = pp_Var1[7];
  uVar4 = FUN_00404b81(pp_Var1,local_8,&local_8,10,1);
  *param_1 = uVar4;
  if (((*(char *)(*(int *)((int)this + 8) + 0x1c) == '\0') ||
      (*(int *)(*(int *)((int)this + 8) + 0x18) != 0x22)) &&
     (*(char **)((int)this + 0xc) <= local_8)) {
    *(char **)((int)this + 0xc) = local_8;
  }
  else {
    uVar5 = 0;
  }
  pp_Var1[6] = p_Var2;
  pp_Var1[7] = p_Var3;
  return CONCAT31((int3)((uint)p_Var3 >> 8),uVar5);
}



undefined4 __fastcall FUN_00405964(__uint64 *param_1)

{
  byte bVar1;
  __acrt_ptd **pp_Var2;
  int *piVar3;
  bool bVar4;
  undefined uVar5;
  char cVar6;
  ushort uVar7;
  int iVar8;
  undefined2 extraout_var;
  __uint64 *p_Var9;
  undefined4 uVar10;
  uint uVar11;
  char *pcVar12;
  __acrt_ptd **local_c;
  
  bVar4 = FUN_00406556(param_1 + 0x89,*(__acrt_ptd ***)(param_1 + 1));
  if (bVar4) {
    pcVar12 = *(char **)((int)param_1 + 0xc);
    if (pcVar12 != (char *)0x0) {
      iVar8 = *(int *)(param_1 + 0x8a) + 1;
      *(int *)(param_1 + 0x8a) = iVar8;
      do {
        if (iVar8 == 2) {
          return *(undefined4 *)((int)param_1 + 0x14);
        }
        *(undefined4 *)((int)param_1 + 0x34) = 0;
        *(undefined *)(param_1 + 3) = 0;
        cVar6 = *pcVar12;
        pcVar12 = pcVar12 + 1;
        *(char **)((int)param_1 + 0xc) = pcVar12;
        *(char *)((int)param_1 + 0x2d) = cVar6;
        while ((cVar6 != '\0' && (-1 < *(int *)((int)param_1 + 0x14)))) {
          uVar5 = FUN_004057a6(cVar6,*(byte *)(param_1 + 3));
          *(undefined *)(param_1 + 3) = uVar5;
          switch(uVar5) {
          case 0:
            pp_Var2 = *(__acrt_ptd ***)(param_1 + 1);
            *(undefined *)(param_1 + 7) = 0;
            local_c = pp_Var2;
            if (*(char *)(pp_Var2 + 5) == '\0') {
              FUN_004064e0(pp_Var2);
              local_c = *(__acrt_ptd ***)(param_1 + 1);
            }
            bVar1 = *(byte *)((int)param_1 + 0x2d);
            uVar7 = ___acrt_locale_get_ctype_array_value(*(int *)pp_Var2[3],(int)(char)bVar1,0x8000)
            ;
            if (CONCAT22(extraout_var,uVar7) != 0) {
              FUN_00406615(param_1 + 0x89,bVar1,(int *)((int)param_1 + 0x14),local_c);
              bVar1 = **(byte **)((int)param_1 + 0xc);
              *(byte **)((int)param_1 + 0xc) = *(byte **)((int)param_1 + 0xc) + 1;
              *(byte *)((int)param_1 + 0x2d) = bVar1;
              if (bVar1 == 0) {
                iVar8 = *(int *)(param_1 + 1);
                *(undefined *)(iVar8 + 0x1c) = 1;
                *(undefined4 *)(iVar8 + 0x18) = 0x16;
                FUN_0040e1a6((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0,
                             *(__acrt_ptd ***)(param_1 + 1));
                iVar8 = *(int *)(param_1 + 1);
                *(undefined *)(iVar8 + 0x1c) = 1;
                *(undefined4 *)(iVar8 + 0x18) = 0x16;
                FUN_0040e1a6((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0,
                             *(__acrt_ptd ***)(param_1 + 1));
                return 0xffffffff;
              }
            }
            FUN_00406615(param_1 + 0x89,bVar1,(int *)((int)param_1 + 0x14),
                         *(__acrt_ptd ***)(param_1 + 1));
            break;
          case 1:
            *(undefined4 *)((int)param_1 + 0x24) = 0xffffffff;
            *(undefined4 *)(param_1 + 4) = 0;
            *(undefined *)((int)param_1 + 0x2c) = 0;
            *(undefined4 *)((int)param_1 + 0x1c) = 0;
            *(undefined4 *)(param_1 + 5) = 0;
            *(undefined *)(param_1 + 7) = 0;
            break;
          case 2:
            if (cVar6 == ' ') {
              *(uint *)((int)param_1 + 0x1c) = *(uint *)((int)param_1 + 0x1c) | 2;
            }
            else if (cVar6 == '#') {
              *(uint *)((int)param_1 + 0x1c) = *(uint *)((int)param_1 + 0x1c) | 0x20;
            }
            else if (cVar6 == '+') {
              *(uint *)((int)param_1 + 0x1c) = *(uint *)((int)param_1 + 0x1c) | 1;
            }
            else if (cVar6 == '-') {
              *(uint *)((int)param_1 + 0x1c) = *(uint *)((int)param_1 + 0x1c) | 4;
            }
            else if (cVar6 == '0') {
              *(uint *)((int)param_1 + 0x1c) = *(uint *)((int)param_1 + 0x1c) | 8;
            }
            break;
          case 3:
            if (cVar6 != '*') {
              p_Var9 = param_1 + 4;
              goto LAB_00405b03;
            }
            piVar3 = *(int **)(param_1 + 2);
            *(int **)(param_1 + 2) = piVar3 + 1;
            iVar8 = *piVar3;
            *(int *)(param_1 + 4) = iVar8;
            if (iVar8 < 0) {
              *(uint *)((int)param_1 + 0x1c) = *(uint *)((int)param_1 + 0x1c) | 4;
              *(int *)(param_1 + 4) = -iVar8;
            }
LAB_00405b28:
            cVar6 = '\x01';
            goto LAB_00405b64;
          case 4:
            *(undefined4 *)((int)param_1 + 0x24) = 0;
            break;
          case 5:
            if (cVar6 == '*') {
              piVar3 = *(int **)(param_1 + 2);
              *(int **)(param_1 + 2) = piVar3 + 1;
              iVar8 = *piVar3;
              *(int *)((int)param_1 + 0x24) = iVar8;
              if (iVar8 < 0) {
                *(undefined4 *)((int)param_1 + 0x24) = 0xffffffff;
              }
              goto LAB_00405b28;
            }
            p_Var9 = (__uint64 *)((int)param_1 + 0x24);
LAB_00405b03:
            uVar10 = FUN_004058ec(param_1,(uint *)p_Var9);
            cVar6 = (char)uVar10;
            goto LAB_00405b64;
          case 6:
            uVar11 = FUN_00405c14(param_1);
            cVar6 = (char)uVar11;
            goto LAB_00405b64;
          case 7:
            cVar6 = FUN_00405d6d(param_1);
LAB_00405b64:
            if (cVar6 == '\0') {
              return 0xffffffff;
            }
            break;
          default:
            iVar8 = *(int *)(param_1 + 1);
            *(undefined *)(iVar8 + 0x1c) = 1;
            *(undefined4 *)(iVar8 + 0x18) = 0x16;
            goto LAB_0040599a;
          case 0xbad1abe1:
            goto LAB_004059ad;
          }
          cVar6 = **(char **)((int)param_1 + 0xc);
          pcVar12 = *(char **)((int)param_1 + 0xc) + 1;
          *(char **)((int)param_1 + 0xc) = pcVar12;
          *(char *)((int)param_1 + 0x2d) = cVar6;
        }
        *(int *)(param_1 + 0x8a) = *(int *)(param_1 + 0x8a) + 1;
        iVar8 = *(int *)(param_1 + 0x8a);
      } while( true );
    }
    iVar8 = *(int *)(param_1 + 1);
    *(undefined *)(iVar8 + 0x1c) = 1;
    *(undefined4 *)(iVar8 + 0x18) = 0x16;
LAB_0040599a:
    FUN_0040e1a6((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0,*(__acrt_ptd ***)(param_1 + 1));
  }
LAB_004059ad:
  return 0xffffffff;
}



uint __fastcall FUN_00405c14(__uint64 *param_1)

{
  char cVar1;
  int iVar2;
  char *pcVar3;
  undefined4 in_EAX;
  undefined3 uVar6;
  char *pcVar4;
  uint uVar5;
  
  cVar1 = *(char *)((int)param_1 + 0x2d);
  uVar6 = (undefined3)((uint)in_EAX >> 8);
  pcVar4 = (char *)CONCAT31(uVar6,cVar1);
  if (cVar1 == 'F') {
    pcVar4 = (char *)(*(uint *)param_1 & 8);
    if (pcVar4 == (char *)0x0) {
      *(undefined *)(param_1 + 3) = 7;
      uVar5 = FUN_00405d6d(param_1);
      return uVar5;
    }
  }
  else if (cVar1 == 'N') {
    pcVar4 = (char *)(*(uint *)param_1 & 8);
    if (pcVar4 == (char *)0x0) {
      *(undefined *)(param_1 + 3) = 8;
      goto LAB_00405c49;
    }
  }
  else {
    if (*(int *)(param_1 + 5) != 0) {
LAB_00405c49:
      iVar2 = *(int *)(param_1 + 1);
      *(undefined *)(iVar2 + 0x1c) = 1;
      *(undefined4 *)(iVar2 + 0x18) = 0x16;
      uVar5 = FUN_0040e1a6((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0,
                           *(__acrt_ptd ***)(param_1 + 1));
      return uVar5 & 0xffffff00;
    }
    if (cVar1 < 'k') {
      if (cVar1 == 'j') {
        *(undefined4 *)(param_1 + 5) = 5;
        goto LAB_00405d6a;
      }
      if (cVar1 == 'I') {
        pcVar3 = *(char **)((int)param_1 + 0xc);
        cVar1 = *pcVar3;
        pcVar4 = (char *)CONCAT31(uVar6,cVar1);
        if ((cVar1 == '3') && (pcVar3[1] == '2')) {
          pcVar4 = pcVar3 + 2;
          *(undefined4 *)(param_1 + 5) = 10;
          *(char **)((int)param_1 + 0xc) = pcVar4;
        }
        else if (cVar1 == '6') {
          if (pcVar3[1] == '4') {
            pcVar4 = pcVar3 + 2;
            *(undefined4 *)(param_1 + 5) = 0xb;
            *(char **)((int)param_1 + 0xc) = pcVar4;
          }
        }
        else if ((((cVar1 == 'd') || (cVar1 == 'i')) || (cVar1 == 'o')) ||
                (((cVar1 == 'u' || (cVar1 == 'x')) || (cVar1 == 'X')))) {
          *(undefined4 *)(param_1 + 5) = 9;
        }
        goto LAB_00405d6a;
      }
      if (cVar1 == 'L') {
        *(undefined4 *)(param_1 + 5) = 8;
        goto LAB_00405d6a;
      }
      if (cVar1 == 'T') {
        *(undefined4 *)(param_1 + 5) = 0xd;
        goto LAB_00405d6a;
      }
      if (cVar1 != 'h') goto LAB_00405d6a;
      if (**(char **)((int)param_1 + 0xc) == 'h') {
        *(char **)((int)param_1 + 0xc) = *(char **)((int)param_1 + 0xc) + 1;
        pcVar4 = (char *)0x1;
      }
      else {
        pcVar4 = (char *)0x2;
      }
    }
    else {
      if (cVar1 != 'l') {
        if (cVar1 == 't') {
          *(undefined4 *)(param_1 + 5) = 7;
        }
        else if (cVar1 == 'w') {
          *(undefined4 *)(param_1 + 5) = 0xc;
        }
        else if (cVar1 == 'z') {
          *(undefined4 *)(param_1 + 5) = 6;
        }
        goto LAB_00405d6a;
      }
      if (**(char **)((int)param_1 + 0xc) == 'l') {
        *(char **)((int)param_1 + 0xc) = *(char **)((int)param_1 + 0xc) + 1;
        pcVar4 = (char *)0x4;
      }
      else {
        pcVar4 = (char *)0x3;
      }
    }
    *(char **)(param_1 + 5) = pcVar4;
  }
LAB_00405d6a:
  return CONCAT31((int3)((uint)pcVar4 >> 8),1);
}



void __fastcall FUN_00405d6d(__uint64 *param_1)

{
  int *piVar1;
  WCHAR WVar2;
  __acrt_ptd **pp_Var3;
  int iVar4;
  bool bVar5;
  char cVar6;
  undefined uVar7;
  bool bVar8;
  undefined4 uVar9;
  uint uVar10;
  __acrt_ptd *p_Var11;
  WCHAR *pWVar12;
  int iVar13;
  int iVar14;
  byte bVar15;
  int local_18;
  int local_14;
  undefined2 local_10;
  undefined local_e;
  uint local_8;
  
  local_8 = DAT_00423014 ^ (uint)&stack0xfffffffc;
  iVar13 = 0;
  cVar6 = *(char *)((int)param_1 + 0x2d);
  if (cVar6 < 'e') {
    if (cVar6 == 'd') {
LAB_00405e25:
      *(uint *)((int)param_1 + 0x1c) = *(uint *)((int)param_1 + 0x1c) | 0x10;
LAB_00405e29:
      uVar10 = FUN_00404f3b(param_1,0);
      cVar6 = (char)uVar10;
    }
    else if (cVar6 < 'T') {
      if (cVar6 == 'S') {
LAB_00405e52:
        uVar9 = FUN_00406444(param_1);
        cVar6 = (char)uVar9;
      }
      else {
        if (cVar6 != 'A') {
          if (cVar6 == 'C') {
LAB_00405ddf:
            uVar9 = FUN_004062f7((undefined6 *)param_1);
            cVar6 = (char)uVar9;
            goto LAB_00405e62;
          }
          if (((cVar6 != 'E') && (cVar6 != 'F')) && (cVar6 != 'G')) goto LAB_004060a1;
        }
LAB_00405dbd:
        uVar9 = FUN_00406166((uint *)param_1);
        cVar6 = (char)uVar9;
      }
    }
    else if (cVar6 == 'X') {
      bVar15 = 1;
LAB_00405df4:
      uVar10 = FUN_004050c8(param_1,bVar15);
      cVar6 = (char)uVar10;
    }
    else {
      if (cVar6 != 'Z') {
        if (cVar6 != 'a') {
          if (cVar6 != 'c') goto LAB_004060a1;
          goto LAB_00405ddf;
        }
        goto LAB_00405dbd;
      }
      uVar9 = FUN_00406103(param_1);
      cVar6 = (char)uVar9;
    }
  }
  else if (cVar6 < 'p') {
    if (cVar6 == 'o') {
      cVar6 = FUN_00406411(param_1);
    }
    else {
      if (((cVar6 == 'e') || (cVar6 == 'f')) || (cVar6 == 'g')) goto LAB_00405dbd;
      if (cVar6 == 'i') goto LAB_00405e25;
      if (cVar6 != 'n') goto LAB_004060a1;
      uVar10 = FUN_0040638c((int)param_1);
      cVar6 = (char)uVar10;
    }
  }
  else {
    if (cVar6 != 'p') {
      if (cVar6 == 's') goto LAB_00405e52;
      if (cVar6 != 'u') {
        if (cVar6 != 'x') goto LAB_004060a1;
        bVar15 = 0;
        goto LAB_00405df4;
      }
      goto LAB_00405e29;
    }
    cVar6 = FUN_0040642e(param_1);
  }
LAB_00405e62:
  if ((cVar6 == '\0') || (*(char *)((int)param_1 + 0x2c) != '\0')) goto LAB_004060a1;
  uVar10 = *(uint *)((int)param_1 + 0x1c);
  local_10 = 0;
  local_e = 0;
  iVar14 = 0;
  local_14 = 0;
  if ((uVar10 >> 4 & 1) != 0) {
    if ((uVar10 >> 6 & 1) == 0) {
      if ((uVar10 & 1) == 0) {
        if ((uVar10 >> 1 & 1) != 0) {
          local_10 = 0x20;
          iVar14 = 1;
          local_14 = 1;
        }
        goto LAB_00405ec1;
      }
      local_10 = 0x2b;
    }
    else {
      local_10 = 0x2d;
    }
    local_14 = 1;
    iVar14 = 1;
  }
LAB_00405ec1:
  cVar6 = *(char *)((int)param_1 + 0x2d);
  if (((cVar6 != 'x') && (cVar6 != 'X')) || (bVar8 = true, (uVar10 >> 5 & 1) == 0)) {
    bVar8 = false;
  }
  if ((cVar6 == 'a') || (bVar5 = false, cVar6 == 'A')) {
    bVar5 = true;
  }
  if ((bVar8) || (bVar5)) {
    *(undefined *)((int)&local_10 + iVar14) = 0x30;
    if ((cVar6 == 'X') || (cVar6 == 'A')) {
      uVar7 = 0x58;
    }
    else {
      uVar7 = 0x78;
    }
    *(undefined *)((int)&local_10 + iVar14 + 1) = uVar7;
    iVar14 = iVar14 + 2;
    local_14 = iVar14;
  }
  iVar14 = (*(int *)(param_1 + 4) - iVar14) - *(int *)((int)param_1 + 0x34);
  if ((uVar10 & 0xc) == 0) {
    pp_Var3 = *(__acrt_ptd ***)(param_1 + 1);
    local_18 = 0;
    if (0 < iVar14) {
      while (bVar8 = FUN_00406637(param_1 + 0x89,0x20,pp_Var3), bVar8) {
        iVar4 = *(int *)((int)param_1 + 0x14);
        *(int *)((int)param_1 + 0x14) = iVar4 + 1;
        if ((iVar4 == -2) || (local_18 = local_18 + 1, iVar14 <= local_18)) goto LAB_00405f6d;
      }
      *(undefined4 *)((int)param_1 + 0x14) = 0xffffffff;
    }
  }
LAB_00405f6d:
  piVar1 = (int *)((int)param_1 + 0x14);
  FUN_00406671(param_1 + 0x89,(byte *)&local_10,local_14,piVar1,*(__acrt_ptd ***)(param_1 + 1));
  if (((*(uint *)((int)param_1 + 0x1c) >> 3 & 1) != 0) &&
     ((*(uint *)((int)param_1 + 0x1c) >> 2 & 1) == 0)) {
    pp_Var3 = *(__acrt_ptd ***)(param_1 + 1);
    local_18 = 0;
    if (0 < iVar14) {
      while (bVar8 = FUN_00406637(param_1 + 0x89,0x30,pp_Var3), bVar8) {
        iVar4 = *piVar1;
        *piVar1 = iVar4 + 1;
        if ((iVar4 == -2) || (local_18 = local_18 + 1, iVar14 <= local_18)) goto LAB_00405fdf;
      }
      *piVar1 = -1;
    }
  }
LAB_00405fdf:
  if ((*(char *)(param_1 + 7) == '\0') || (*(int *)((int)param_1 + 0x34) < 1)) {
    FUN_00406671(param_1 + 0x89,*(byte **)(param_1 + 6),*(int *)((int)param_1 + 0x34),piVar1,
                 *(__acrt_ptd ***)(param_1 + 1));
  }
  else {
    pWVar12 = *(WCHAR **)(param_1 + 6);
    local_18 = 0;
    do {
      WVar2 = *pWVar12;
      pWVar12 = pWVar12 + 1;
      local_14 = 0;
      p_Var11 = FUN_0040fd06(&local_14,(byte *)&local_10,6,WVar2,*(__acrt_ptd ***)(param_1 + 1));
      if ((p_Var11 != (__acrt_ptd *)0x0) || (local_14 == 0)) {
        *piVar1 = -1;
        break;
      }
      FUN_00406671(param_1 + 0x89,(byte *)&local_10,local_14,piVar1,*(__acrt_ptd ***)(param_1 + 1));
      local_18 = local_18 + 1;
    } while (local_18 != *(int *)((int)param_1 + 0x34));
  }
  if (((-1 < *piVar1) && ((*(uint *)((int)param_1 + 0x1c) >> 2 & 1) != 0)) &&
     (pp_Var3 = *(__acrt_ptd ***)(param_1 + 1), 0 < iVar14)) {
    while (bVar8 = FUN_00406637(param_1 + 0x89,0x20,pp_Var3), bVar8) {
      iVar4 = *piVar1;
      *piVar1 = iVar4 + 1;
      if ((iVar4 == -2) || (iVar13 = iVar13 + 1, iVar14 <= iVar13)) goto LAB_004060a1;
    }
    *piVar1 = -1;
  }
LAB_004060a1:
  FUN_00402125(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



// Library Function - Single Match
//  unsigned int __cdecl __crt_stdio_output::to_integer_size(enum
// __crt_stdio_output::length_modifier)
// 
// Libraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual
// Studio 2019 Release

uint __cdecl __crt_stdio_output::to_integer_size(length_modifier param_1)

{
  uint uStack_8;
  
  switch(param_1) {
  case 0:
  case 3:
  case 6:
  case 7:
  case 9:
  case 10:
    uStack_8 = 4;
    break;
  case 1:
    return 1;
  case 2:
    uStack_8 = 2;
    break;
  case 4:
  case 5:
  case 0xb:
    uStack_8 = 8;
    break;
  default:
    return 0;
  }
  return uStack_8;
}



undefined4 __fastcall FUN_00406103(__uint64 *param_1)

{
  ushort uVar1;
  ushort **ppuVar2;
  ushort *puVar3;
  int iVar4;
  bool bVar5;
  uint uVar6;
  
  ppuVar2 = *(ushort ***)(param_1 + 2);
  *(ushort ***)(param_1 + 2) = ppuVar2 + 1;
  puVar3 = *ppuVar2;
  if ((puVar3 == (ushort *)0x0) || (iVar4 = *(int *)(puVar3 + 2), iVar4 == 0)) {
    uVar6 = 6;
    *(char **)(param_1 + 6) = "(null)";
  }
  else {
    bVar5 = __crt_stdio_output::is_wide_character_specifier<char>
                      (*param_1,*(char *)((int)param_1 + 0x2d),*(length_modifier *)(param_1 + 5));
    *(int *)(param_1 + 6) = iVar4;
    uVar1 = *puVar3;
    uVar6 = (uint)uVar1;
    if (bVar5) {
      *(undefined *)(param_1 + 7) = 1;
      uVar6 = (uint)(uVar1 >> 1);
      goto LAB_0040615d;
    }
  }
  *(undefined *)(param_1 + 7) = 0;
LAB_0040615d:
  *(uint *)((int)param_1 + 0x34) = uVar6;
  return CONCAT31((int3)(uVar6 >> 8),1);
}



undefined4 __fastcall FUN_00406166(uint *param_1)

{
  char *pcVar1;
  char cVar2;
  undefined4 *puVar3;
  undefined4 uVar4;
  uint *puVar5;
  uint uVar6;
  __acrt_ptd **pp_Var7;
  char *pcVar8;
  uint *this;
  uint uVar9;
  undefined4 local_18;
  undefined4 local_14;
  uint *******local_10;
  uint local_c;
  int local_8;
  
  param_1[7] = param_1[7] | 0x10;
  uVar9 = param_1[9];
  if ((int)uVar9 < 0) {
    if ((*(char *)((int)param_1 + 0x2d) == 'a') || (*(char *)((int)param_1 + 0x2d) == 'A')) {
      uVar9 = 0xd;
    }
    else {
      uVar9 = 6;
    }
    param_1[9] = uVar9;
  }
  else if ((uVar9 == 0) &&
          ((*(char *)((int)param_1 + 0x2d) == 'g' || (*(char *)((int)param_1 + 0x2d) == 'G')))) {
    param_1[9] = 1;
    uVar9 = 1;
  }
  this = param_1 + 0xf;
  uVar4 = FUN_00404a80(this,uVar9 + 0x15d,param_1[2]);
  if ((char)uVar4 == '\0') {
    uVar9 = __crt_stdio_output::formatting_buffer::count<char>((formatting_buffer *)this);
    uVar9 = uVar9 - 0x15d;
    param_1[9] = uVar9;
  }
  else {
    uVar9 = param_1[9];
  }
  puVar5 = (uint *)param_1[0x110];
  if ((uint *)param_1[0x110] == (uint *)0x0) {
    puVar5 = this;
  }
  param_1[0xc] = (uint)puVar5;
  puVar3 = (undefined4 *)param_1[4];
  param_1[4] = (uint)(puVar3 + 2);
  local_18 = *puVar3;
  local_14 = puVar3[1];
  local_8 = (int)*(char *)((int)param_1 + 0x2d);
  local_c = __crt_stdio_output::formatting_buffer::count<char>((formatting_buffer *)this);
  local_10 = (uint *******)
             __crt_stdio_output::formatting_buffer::scratch_data<char>((formatting_buffer *)this);
  uVar6 = __crt_stdio_output::formatting_buffer::count<char>((formatting_buffer *)this);
  if ((uint *)param_1[0x110] != (uint *)0x0) {
    this = (uint *)param_1[0x110];
  }
  FUN_0040fb85((double *)&local_18,(char *)this,uVar6,local_10,local_c,local_8,uVar9,*param_1,
               param_1[1],1,(__acrt_ptd **)param_1[2]);
  pp_Var7 = (__acrt_ptd **)(param_1[7] >> 5);
  if ((((uint)pp_Var7 & 1) != 0) && (param_1[9] == 0)) {
    pp_Var7 = (__acrt_ptd **)param_1[2];
    if (*(char *)(pp_Var7 + 5) == '\0') {
      FUN_004064e0(pp_Var7);
    }
    pp_Var7 = pp_Var7 + 3;
    __crt_stdio_output::force_decimal_point((char *)param_1[0xc],(__crt_locale_pointers *)pp_Var7);
  }
  cVar2 = *(char *)((int)param_1 + 0x2d);
  uVar9 = CONCAT31((int3)((uint)pp_Var7 >> 8),cVar2);
  if (((cVar2 == 'g') || (cVar2 == 'G')) && (uVar9 = param_1[7] >> 5, (uVar9 & 1) == 0)) {
    pp_Var7 = (__acrt_ptd **)param_1[2];
    if (*(char *)(pp_Var7 + 5) == '\0') {
      FUN_004064e0(pp_Var7);
    }
    uVar9 = FUN_00405746((char *)param_1[0xc],(int *)(pp_Var7 + 3));
  }
  pcVar8 = (char *)param_1[0xc];
  cVar2 = *pcVar8;
  if (cVar2 == '-') {
    param_1[7] = param_1[7] | 0x40;
    pcVar8 = pcVar8 + 1;
    param_1[0xc] = (uint)pcVar8;
    cVar2 = *pcVar8;
  }
  if (((cVar2 == 'i') || (cVar2 == 'I')) || ((cVar2 == 'n' || (cVar2 == 'N')))) {
    param_1[7] = param_1[7] & 0xfffffff7;
    *(undefined *)((int)param_1 + 0x2d) = 0x73;
  }
  pcVar1 = pcVar8 + 1;
  do {
    cVar2 = *pcVar8;
    pcVar8 = pcVar8 + 1;
  } while (cVar2 != '\0');
  param_1[0xd] = (int)pcVar8 - (int)pcVar1;
  return CONCAT31((int3)(uVar9 >> 8),1);
}



undefined4 __fastcall FUN_004062f7(undefined6 *param_1)

{
  WCHAR WVar1;
  WCHAR *pWVar2;
  formatting_buffer *pfVar3;
  bool bVar4;
  uint uVar5;
  __acrt_ptd *p_Var6;
  formatting_buffer *pfVar7;
  formatting_buffer *this;
  
  this = (formatting_buffer *)((int)param_1 + 0x3c);
  bVar4 = __crt_stdio_output::is_wide_character_specifier<char>
                    (CONCAT26((short)((uint)*(undefined4 *)((int)param_1 + 4) >> 0x10),*param_1),
                     *(char *)((int)param_1 + 0x2d),*(length_modifier *)(param_1 + 5));
  if (bVar4) {
    pWVar2 = *(WCHAR **)(param_1 + 2);
    *(WCHAR **)(param_1 + 2) = pWVar2 + 2;
    WVar1 = *pWVar2;
    uVar5 = __crt_stdio_output::formatting_buffer::count<char>(this);
    pfVar7 = *(formatting_buffer **)(param_1 + 0x88);
    if (*(formatting_buffer **)(param_1 + 0x88) == (formatting_buffer *)0x0) {
      pfVar7 = this;
    }
    p_Var6 = FUN_0040fd06((int *)((int)param_1 + 0x34),(byte *)pfVar7,uVar5,WVar1,
                          *(__acrt_ptd ***)(param_1 + 1));
    if (p_Var6 != (__acrt_ptd *)0x0) {
      *(undefined *)((int)param_1 + 0x2c) = 1;
    }
  }
  else {
    pfVar7 = *(formatting_buffer **)(param_1 + 0x88);
    if (*(formatting_buffer **)(param_1 + 0x88) == (formatting_buffer *)0x0) {
      pfVar7 = this;
    }
    pfVar3 = *(formatting_buffer **)(param_1 + 2);
    *(formatting_buffer **)(param_1 + 2) = pfVar3 + 4;
    *pfVar7 = *pfVar3;
    *(undefined4 *)((int)param_1 + 0x34) = 1;
  }
  pfVar7 = *(formatting_buffer **)(param_1 + 0x88);
  if (pfVar7 != (formatting_buffer *)0x0) {
    this = pfVar7;
  }
  *(formatting_buffer **)(param_1 + 6) = this;
  return CONCAT31((int3)((uint)pfVar7 >> 8),1);
}



uint __fastcall FUN_0040638c(int param_1)

{
  uint **ppuVar1;
  uint *puVar2;
  int iVar3;
  bool bVar4;
  undefined3 extraout_var;
  uint uVar5;
  
  ppuVar1 = *(uint ***)(param_1 + 0x10);
  *(uint ***)(param_1 + 0x10) = ppuVar1 + 1;
  puVar2 = *ppuVar1;
  bVar4 = FUN_00410002();
  if (CONCAT31(extraout_var,bVar4) == 0) {
LAB_004063a6:
    iVar3 = *(int *)(param_1 + 8);
    *(undefined *)(iVar3 + 0x1c) = 1;
    *(undefined4 *)(iVar3 + 0x18) = 0x16;
    uVar5 = FUN_0040e1a6((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0,
                         *(__acrt_ptd ***)(param_1 + 8));
    uVar5 = uVar5 & 0xffffff00;
  }
  else {
    uVar5 = __crt_stdio_output::to_integer_size(*(length_modifier *)(param_1 + 0x28));
    if (uVar5 == 1) {
      uVar5 = 0;
      *(undefined *)puVar2 = *(undefined *)(param_1 + 0x14);
    }
    else if (uVar5 == 2) {
      uVar5 = (uint)*(ushort *)(param_1 + 0x14);
      *(ushort *)puVar2 = *(ushort *)(param_1 + 0x14);
    }
    else if (uVar5 == 4) {
      uVar5 = *(uint *)(param_1 + 0x14);
      *puVar2 = uVar5;
    }
    else {
      if (uVar5 != 8) goto LAB_004063a6;
      uVar5 = *(uint *)(param_1 + 0x14);
      *puVar2 = uVar5;
      puVar2[1] = (int)uVar5 >> 0x1f;
    }
    *(undefined *)(param_1 + 0x2c) = 1;
    uVar5 = CONCAT31((int3)(uVar5 >> 8),1);
  }
  return uVar5;
}



void __fastcall FUN_00406411(void *param_1)

{
  uint uVar1;
  
  uVar1 = *(uint *)((int)param_1 + 0x1c);
  if ((uVar1 >> 5 & 1) != 0) {
    uVar1 = uVar1 | 0x80;
    *(uint *)((int)param_1 + 0x1c) = uVar1;
  }
  FUN_00404dae(param_1,(char)uVar1,0);
  return;
}



void __fastcall FUN_0040642e(void *param_1)

{
  *(undefined4 *)((int)param_1 + 0x24) = 8;
  *(undefined4 *)((int)param_1 + 0x28) = 10;
  FUN_004050c8(param_1,1);
  return;
}



undefined4 __fastcall FUN_00406444(__uint64 *param_1)

{
  undefined (**ppauVar1) [32];
  bool bVar2;
  uint uVar3;
  char *pcVar4;
  
  ppauVar1 = *(undefined (***) [32])(param_1 + 2);
  *(undefined (***) [32])(param_1 + 2) = ppauVar1 + 1;
  uVar3 = *(uint *)((int)param_1 + 0x24);
  pcVar4 = (char *)*ppauVar1;
  *(char **)(param_1 + 6) = pcVar4;
  if (uVar3 == 0xffffffff) {
    uVar3 = 0x7fffffff;
  }
  bVar2 = __crt_stdio_output::is_wide_character_specifier<char>
                    (*param_1,*(char *)((int)param_1 + 0x2d),*(length_modifier *)(param_1 + 5));
  if (bVar2) {
    if ((undefined (*) [32])pcVar4 == (undefined (*) [32])0x0) {
      *(wchar_t **)(param_1 + 6) = L"(null)";
      pcVar4 = (char *)L"(null)";
    }
    *(undefined *)(param_1 + 7) = 1;
    uVar3 = FUN_0040ef41((short *)pcVar4,uVar3);
  }
  else {
    if ((undefined (*) [32])pcVar4 == (undefined (*) [32])0x0) {
      pcVar4 = "(null)";
      *(char **)(param_1 + 6) = "(null)";
    }
    uVar3 = FUN_0040ee1f((undefined (*) [32])pcVar4,uVar3);
  }
  *(uint *)((int)param_1 + 0x34) = uVar3;
  return CONCAT31((int3)(uVar3 >> 8),1);
}



// Library Function - Single Match
//  public: void __thiscall __crt_strtox::c_string_character_source<char>::unget(char)
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __thiscall
__crt_strtox::c_string_character_source<char>::unget
          (c_string_character_source<char> *this,char param_1)

{
  int iVar1;
  undefined4 *puVar2;
  
  iVar1 = *(int *)this;
  *(char **)this = (char *)(iVar1 + -1);
  if ((param_1 != '\0') && (*(char *)(iVar1 + -1) != param_1)) {
    puVar2 = (undefined4 *)FUN_0040e304();
    *puVar2 = 0x16;
    FUN_0040e223();
  }
  return;
}



void __fastcall FUN_004064e0(__acrt_ptd **param_1)

{
  __acrt_ptd *p_Var1;
  
  p_Var1 = FUN_00405890(param_1);
  param_1[3] = *(__acrt_ptd **)(p_Var1 + 0x4c);
  param_1[4] = *(__acrt_ptd **)(p_Var1 + 0x48);
  FUN_0040f11e((int)p_Var1,param_1 + 3,(int)param_1[1]);
  FUN_0040f17c((int)p_Var1,(int *)(param_1 + 4),(int)param_1[1]);
  if ((*(uint *)(p_Var1 + 0x350) & 2) == 0) {
    *(uint *)(p_Var1 + 0x350) = *(uint *)(p_Var1 + 0x350) | 2;
    *(undefined *)(param_1 + 5) = 2;
  }
  return;
}



uint __fastcall FUN_0040653b(int *param_1)

{
  undefined4 in_EAX;
  undefined4 *puVar1;
  uint uVar2;
  
  if (*param_1 == 0) {
    puVar1 = (undefined4 *)FUN_0040e304();
    *puVar1 = 0x16;
    uVar2 = FUN_0040e223();
    return uVar2 & 0xffffff00;
  }
  return CONCAT31((int3)((uint)in_EAX >> 8),1);
}



bool __thiscall FUN_00406556(void *this,__acrt_ptd **param_1)

{
  bool bVar1;
  
                    // WARNING: Load size is inaccurate
  if (*this == (_iobuf *)0x0) {
    *(undefined *)(param_1 + 7) = 1;
    param_1[6] = (__acrt_ptd *)0x16;
    FUN_0040e1a6((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0,param_1);
    bVar1 = false;
  }
  else {
    bVar1 = __acrt_stdio_char_traits<char>::validate_stream_is_ansi_if_required(*this);
  }
  return bVar1;
}



// Library Function - Single Match
//  public: static bool __cdecl
// __acrt_stdio_char_traits<char>::validate_stream_is_ansi_if_required(struct _iobuf * const)
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

bool __cdecl __acrt_stdio_char_traits<char>::validate_stream_is_ansi_if_required(_iobuf *param_1)

{
  bool bVar1;
  uint uVar2;
  undefined4 *puVar3;
  undefined *puVar4;
  undefined *puVar5;
  
  if (((uint)param_1->_flag >> 0xc & 1) == 0) {
    uVar2 = __fileno(param_1);
    puVar4 = &DAT_004230f8;
    if ((uVar2 == 0xffffffff) || (uVar2 == 0xfffffffe)) {
      puVar5 = &DAT_004230f8;
    }
    else {
      puVar5 = (undefined *)((uVar2 & 0x3f) * 0x38 + (&DAT_004240c8)[(int)uVar2 >> 6]);
    }
    if (puVar5[0x29] == '\0') {
      if ((uVar2 != 0xffffffff) && (uVar2 != 0xfffffffe)) {
        puVar4 = (undefined *)((uVar2 & 0x3f) * 0x38 + (&DAT_004240c8)[(int)uVar2 >> 6]);
      }
      if ((puVar4[0x2d] & 1) == 0) goto LAB_00406610;
    }
    puVar3 = (undefined4 *)FUN_0040e304();
    *puVar3 = 0x16;
    FUN_0040e223();
    bVar1 = false;
  }
  else {
LAB_00406610:
    bVar1 = true;
  }
  return bVar1;
}



void __thiscall FUN_00406615(void *this,byte param_1,int *param_2,__acrt_ptd **param_3)

{
  bool bVar1;
  
  bVar1 = FUN_00406637(this,param_1,param_3);
  if (bVar1) {
    *param_2 = *param_2 + 1;
  }
  else {
    *param_2 = -1;
  }
  return;
}



bool __thiscall FUN_00406637(void *this,byte param_1,__acrt_ptd **param_2)

{
  uint uVar1;
  bool bVar2;
  
                    // WARNING: Load size is inaccurate
                    // WARNING: Load size is inaccurate
  if (((*(uint *)(*this + 0xc) >> 0xc & 1) == 0) || (*(int *)(*this + 4) != 0)) {
                    // WARNING: Load size is inaccurate
    uVar1 = FUN_00410017(param_1,*this,param_2);
    bVar2 = uVar1 != 0xffffffff;
  }
  else {
    bVar2 = true;
  }
  return bVar2;
}



void __thiscall FUN_00406671(void *this,byte *param_1,int param_2,int *param_3,__acrt_ptd **param_4)

{
  __acrt_ptd *p_Var1;
  __acrt_ptd *p_Var2;
  bool bVar3;
  byte *pbVar4;
  
                    // WARNING: Load size is inaccurate
                    // WARNING: Load size is inaccurate
  if (((*(uint *)(*this + 0xc) >> 0xc & 1) != 0) && (*(int *)(*this + 4) == 0)) {
    *param_3 = *param_3 + param_2;
    return;
  }
  p_Var1 = param_4[6];
  p_Var2 = param_4[7];
  pbVar4 = param_1 + param_2;
  if (param_1 != pbVar4) {
    do {
      bVar3 = FUN_00406637(this,*param_1,param_4);
      if (bVar3) {
LAB_004066f4:
        *param_3 = *param_3 + 1;
      }
      else {
        if (((bool)*(char *)(param_4 + 7) == bVar3) || (param_4[6] != (__acrt_ptd *)0x2a)) {
          *param_3 = -1;
          break;
        }
        bVar3 = FUN_00406637(this,0x3f,param_4);
        if (bVar3) goto LAB_004066f4;
        *param_3 = -1;
      }
      param_1 = param_1 + 1;
    } while (param_1 != pbVar4);
  }
  param_4[6] = p_Var1;
  param_4[7] = p_Var2;
  return;
}



// Library Function - Single Match
//  ___acrt_locale_get_ctype_array_value
// 
// Libraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual
// Studio 2019 Release

ushort __cdecl ___acrt_locale_get_ctype_array_value(int param_1,int param_2,ushort param_3)

{
  if (param_2 + 1U < 0x101) {
    return *(ushort *)(param_1 + param_2 * 2) & param_3;
  }
  return 0;
}



undefined4 __cdecl
FUN_0040673e(undefined4 param_1,undefined4 param_2,FILE *param_3,int param_4,undefined4 *param_5,
            undefined4 param_6)

{
  undefined4 uVar1;
  __acrt_ptd *local_60 [6];
  undefined4 local_48;
  undefined local_44;
  FILE **local_38;
  __acrt_ptd **local_34;
  undefined4 *local_30;
  int *local_2c;
  undefined4 *local_28;
  undefined4 local_24;
  undefined4 local_20;
  FILE *local_1c;
  FILE *local_18;
  undefined4 local_14;
  int local_10;
  FILE *local_c [2];
  
  FUN_004055d0(local_60,param_5);
  local_14 = param_6;
  local_10 = param_4;
  local_c[0] = param_3;
  local_24 = param_1;
  local_20 = param_2;
  if ((param_3 == (FILE *)0x0) || (param_4 == 0)) {
    local_44 = 1;
    local_48 = 0x16;
    FUN_0040e1a6((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0,local_60);
    uVar1 = 0xffffffff;
  }
  else {
    local_38 = local_c;
    local_18 = param_3;
    local_34 = local_60;
    local_1c = param_3;
    local_30 = &local_24;
    local_2c = &local_10;
    local_28 = &local_14;
    uVar1 = operator()<>(&local_1c,&local_38);
  }
  FUN_00405630(local_60);
  return uVar1;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4

char * __cdecl FUN_004067e2(char *param_1,int param_2,FILE *param_3)

{
  bool bVar1;
  undefined4 *puVar2;
  int iVar3;
  char *pcVar4;
  int iVar5;
  char *pcVar6;
  void *local_14;
  
  if ((param_1 == (char *)0x0) && (param_2 != 0)) {
    bVar1 = false;
  }
  else {
    bVar1 = true;
  }
  iVar5 = 1;
  if (((bVar1) && (-1 < param_2)) && (param_3 != (FILE *)0x0)) {
    if (param_2 != 0) {
      __lock_file(param_3);
      bVar1 = __acrt_stdio_char_traits<char>::validate_stream_is_ansi_if_required(param_3);
      pcVar4 = (char *)0x0;
      pcVar6 = param_1;
      if (bVar1) {
        for (; iVar5 != param_2; iVar5 = iVar5 + 1) {
          iVar3 = FUN_0040cb0c(param_3);
          if (iVar3 == -1) {
            if (pcVar6 == param_1) goto LAB_0040687c;
            break;
          }
          *pcVar6 = (char)iVar3;
          pcVar6 = pcVar6 + 1;
          if ((char)iVar3 == '\n') break;
        }
        *pcVar6 = '\0';
        pcVar4 = param_1;
      }
LAB_0040687c:
      FUN_004068aa();
      ExceptionList = local_14;
      return pcVar4;
    }
  }
  else {
    puVar2 = (undefined4 *)FUN_0040e304();
    *puVar2 = 0x16;
    FUN_0040e223();
  }
  ExceptionList = local_14;
  return (char *)0x0;
}



void FUN_004068aa(void)

{
  int unaff_EBP;
  
  __unlock_file(*(FILE **)(unaff_EBP + 0x10));
  return;
}



void __cdecl FUN_004068b4(char *param_1,int param_2,FILE *param_3)

{
  FUN_004067e2(param_1,param_2,param_3);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// Library Function - Single Match
//  public: int __thiscall __crt_seh_guarded_call<int>::operator()<class
// <lambda_274ecf0a8038e561263518ab346655e8>,class <lambda_21448eb78dd3c4a522ed7c65a98d88e6> &,class
// <lambda_0ca1de2171e49cefb1e8dc85c06db622> >(class <lambda_274ecf0a8038e561263518ab346655e8>
// &&,class <lambda_21448eb78dd3c4a522ed7c65a98d88e6> &,class
// <lambda_0ca1de2171e49cefb1e8dc85c06db622> &&)
// 
// Library: Visual Studio 2019 Release

int __thiscall
__crt_seh_guarded_call<int>::operator()<>
          (__crt_seh_guarded_call<int> *this,<> *param_1,<> *param_2,<> *param_3)

{
  int iVar1;
  void *local_14;
  
  __lock_file(*(FILE **)param_1);
  iVar1 = <>::operator()(param_2);
  FUN_0040690e();
  ExceptionList = local_14;
  return iVar1;
}



void FUN_0040690e(void)

{
  int unaff_EBP;
  
  __unlock_file(**(FILE ***)(unaff_EBP + 0x10));
  return;
}



// Library Function - Single Match
//  void __cdecl __crt_strtox::assemble_floating_point_snan<double>(bool,double &)
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __cdecl __crt_strtox::assemble_floating_point_snan<double>(bool param_1,double *param_2)

{
  *(undefined4 *)param_2 = 1;
  *(uint *)((int)param_2 + 4) = (uint)param_1 << 0x1f | 0x7ff00000;
  return;
}



// Library Function - Single Match
//  enum SLD_STATUS __cdecl __crt_strtox::assemble_floating_point_value_t<float>(bool,int,unsigned
// __int64,float &)
// 
// Libraries: Visual Studio 2015, Visual Studio 2017, Visual Studio 2019

SLD_STATUS __cdecl
__crt_strtox::assemble_floating_point_value_t<float>
          (bool param_1,int param_2,__uint64 param_3,float *param_4)

{
  *param_4 = (float)((param_2 + 0x7fU & 0xff) << 0x17 | (uint)param_1 << 0x1f |
                    (uint)param_3 & 0x7fffff);
  return 0;
}



// Library Function - Single Match
//  enum SLD_STATUS __cdecl __crt_strtox::assemble_floating_point_value_t<double>(bool,int,unsigned
// __int64,double &)
// 
// Libraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual
// Studio 2019 Release

SLD_STATUS __cdecl
__crt_strtox::assemble_floating_point_value_t<double>
          (bool param_1,int param_2,__uint64 param_3,double *param_4)

{
  *(uint *)((int)param_4 + 4) =
       (param_2 + 0x3ffU & 0x7ff | (uint)param_1 << 0xb) << 0x14 | param_3._4_4_ & 0xfffff;
  *(undefined4 *)param_4 = (undefined4)param_3;
  return 0;
}



// Library Function - Single Match
//  int __cdecl common_vsscanf<char>(unsigned __int64,char const * const,unsigned int,char const *
// const,struct __crt_locale_pointers * const,char * const)
// 
// Library: Visual Studio 2019 Release

int __cdecl
common_vsscanf<char>
          (__uint64 param_1,char *param_2,uint param_3,char *param_4,__crt_locale_pointers *param_5,
          char *param_6)

{
  undefined4 *puVar1;
  uint uVar2;
  int iVar3;
  char *unaff_ESI;
  int local_9c;
  char local_98 [8];
  char local_90;
  char *local_8c;
  char *local_88;
  char *local_84;
  input_processor<> local_80 [120];
  uint local_8;
  
  local_8 = DAT_00423014 ^ (uint)&stack0xfffffffc;
  if ((param_2 == (char *)0x0) || (param_4 == (char *)0x0)) {
    puVar1 = (undefined4 *)FUN_0040e304();
    *puVar1 = 0x16;
    FUN_0040e223();
  }
  else {
    uVar2 = FUN_0040ee1f((undefined (*) [32])param_2,param_3);
    FUN_00408ded(&local_9c,(__acrt_ptd **)param_5);
    local_88 = param_2 + uVar2;
    local_8c = param_2;
    local_84 = param_2;
    __crt_stdio_input::input_processor<>::input_processor<>
              (local_80,(string_input_adapter<char> *)&local_8c,CONCAT44(param_4,param_1._4_4_),
               local_98,(__crt_locale_pointers *)param_6,unaff_ESI);
    __crt_stdio_input::input_processor<>::process(local_80);
    if (local_90 != '\0') {
      *(uint *)(local_9c + 0x350) = *(uint *)(local_9c + 0x350) & 0xfffffffd;
    }
  }
  iVar3 = FUN_00402125(local_8 ^ (uint)&stack0xfffffffc);
  return iVar3;
}



// Library Function - Multiple Matches With Different Base Names
//  enum SLD_STATUS __cdecl __crt_strtox::convert_decimal_string_to_floating_type<float>(struct
// __crt_strtox::floating_point_string const &,float &)
//  enum SLD_STATUS __cdecl __crt_strtox::convert_hexadecimal_string_to_floating_type<float>(struct
// __crt_strtox::floating_point_string const &,float &)
// 
// Library: Visual Studio 2019 Release

void __cdecl
FID_conflict_convert_hexadecimal_string_to_floating_type<float>(uint *param_1,undefined4 param_2)

{
  undefined4 local_c;
  undefined4 local_8;
  
  local_c = param_2;
  local_8 = 0;
  FUN_00409605(param_1,(floating_point_value *)&local_c);
  return;
}



// Library Function - Multiple Matches With Different Base Names
//  enum SLD_STATUS __cdecl __crt_strtox::convert_decimal_string_to_floating_type<double>(struct
// __crt_strtox::floating_point_string const &,double &)
//  enum SLD_STATUS __cdecl __crt_strtox::convert_hexadecimal_string_to_floating_type<double>(struct
// __crt_strtox::floating_point_string const &,double &)
// 
// Library: Visual Studio 2019 Release

void __thiscall
FID_conflict_convert_hexadecimal_string_to_floating_type<double>
          (void *this,uint *param_1,undefined4 param_2)

{
  undefined4 local_c;
  undefined4 local_8;
  
  local_c = param_2;
  local_8 = CONCAT31((int3)((uint)this >> 8),1);
  FUN_00409605(param_1,(floating_point_value *)&local_c);
  return;
}



// Library Function - Multiple Matches With Different Base Names
//  enum SLD_STATUS __cdecl __crt_strtox::convert_decimal_string_to_floating_type<float>(struct
// __crt_strtox::floating_point_string const &,float &)
//  enum SLD_STATUS __cdecl __crt_strtox::convert_hexadecimal_string_to_floating_type<float>(struct
// __crt_strtox::floating_point_string const &,float &)
// 
// Library: Visual Studio 2019 Release

void __cdecl
FID_conflict_convert_hexadecimal_string_to_floating_type<float>(int *param_1,undefined4 param_2)

{
  undefined4 local_c;
  undefined4 local_8;
  
  local_c = param_2;
  local_8 = 0;
  FUN_0040b3ab(param_1,(floating_point_value *)&local_c);
  return;
}



// Library Function - Multiple Matches With Different Base Names
//  enum SLD_STATUS __cdecl __crt_strtox::convert_decimal_string_to_floating_type<double>(struct
// __crt_strtox::floating_point_string const &,double &)
//  enum SLD_STATUS __cdecl __crt_strtox::convert_hexadecimal_string_to_floating_type<double>(struct
// __crt_strtox::floating_point_string const &,double &)
// 
// Library: Visual Studio 2019 Release

void __thiscall
FID_conflict_convert_hexadecimal_string_to_floating_type<double>
          (void *this,int *param_1,undefined4 param_2)

{
  undefined4 local_c;
  undefined4 local_8;
  
  local_c = param_2;
  local_8 = CONCAT31((int3)((uint)this >> 8),1);
  FUN_0040b3ab(param_1,(floating_point_value *)&local_c);
  return;
}



undefined __cdecl FUN_00406ae5(byte param_1,int param_2,uint param_3)

{
  bool bVar1;
  bool bVar2;
  
  if ((param_1 & 4) != 0) {
    return 1;
  }
  if ((param_1 & 1) != 0) {
    if ((param_1 & 2) == 0) {
      if (0x7fffffff < param_3) {
        return 1;
      }
      if (param_3 < 0x7fffffff) {
        return 0;
      }
      bVar1 = param_2 != -1;
      bVar2 = param_2 == -1;
    }
    else {
      if (0x80000000 < param_3) {
        return 1;
      }
      if (param_3 < 0x80000000) {
        return 0;
      }
      bVar1 = false;
      bVar2 = param_2 == 0;
    }
    if (!bVar1 && !bVar2) {
      return 1;
    }
  }
  return 0;
}



void * __cdecl
FUN_00406b26(void *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined *param_5)

{
  FUN_00408d2f(param_1,param_2,param_3,param_4,param_5);
  return param_1;
}



void __cdecl FUN_00406b44(_locale_t param_1)

{
  undefined4 *puVar1;
  floating_point_parse_result fVar2;
  uint in_stack_00000018;
  uint in_stack_0000001c;
  undefined *in_stack_00000020;
  float *in_stack_00000028;
  int local_314 [195];
  uint local_8;
  
  local_8 = DAT_00423014 ^ (uint)&stack0xfffffffc;
  if ((in_stack_00000028 == (float *)0x0) || (param_1 == (_locale_t)0x0)) {
    puVar1 = (undefined4 *)FUN_0040e304();
    *puVar1 = 0x16;
    FUN_0040e223();
    if ((in_stack_00000020 != (undefined *)0x0) && ((in_stack_00000018 | in_stack_0000001c) == 0)) {
      *in_stack_00000020 = 0;
    }
  }
  else {
    fVar2 = FUN_00406d6c(param_1,(int *)&stack0x00000008,local_314);
    __crt_strtox::parse_floating_point_write_result<float>
              (fVar2,(floating_point_string *)local_314,in_stack_00000028);
    if ((in_stack_00000020 != (undefined *)0x0) && ((in_stack_00000018 | in_stack_0000001c) == 0)) {
      *in_stack_00000020 = 0;
    }
  }
  FUN_00402125(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_00406bce(_locale_t param_1)

{
  undefined4 *puVar1;
  floating_point_parse_result fVar2;
  uint in_stack_00000018;
  uint in_stack_0000001c;
  undefined *in_stack_00000020;
  double *in_stack_00000028;
  int local_314 [195];
  uint local_8;
  
  local_8 = DAT_00423014 ^ (uint)&stack0xfffffffc;
  if ((in_stack_00000028 == (double *)0x0) || (param_1 == (_locale_t)0x0)) {
    puVar1 = (undefined4 *)FUN_0040e304();
    *puVar1 = 0x16;
    FUN_0040e223();
    if ((in_stack_00000020 != (undefined *)0x0) && ((in_stack_00000018 | in_stack_0000001c) == 0)) {
      *in_stack_00000020 = 0;
    }
  }
  else {
    fVar2 = FUN_00406d6c(param_1,(int *)&stack0x00000008,local_314);
    __crt_strtox::parse_floating_point_write_result<double>
              (fVar2,(floating_point_string *)local_314,in_stack_00000028);
    if ((in_stack_00000020 != (undefined *)0x0) && ((in_stack_00000018 | in_stack_0000001c) == 0)) {
      *in_stack_00000020 = 0;
    }
  }
  FUN_00402125(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_00406c58(_locale_t param_1)

{
  undefined4 *puVar1;
  floating_point_parse_result fVar2;
  uint in_stack_00000018;
  uint in_stack_0000001c;
  undefined *in_stack_00000020;
  float *in_stack_00000028;
  int local_314 [195];
  uint local_8;
  
  local_8 = DAT_00423014 ^ (uint)&stack0xfffffffc;
  if ((in_stack_00000028 == (float *)0x0) || (param_1 == (_locale_t)0x0)) {
    puVar1 = (undefined4 *)FUN_0040e304();
    *puVar1 = 0x16;
    FUN_0040e223();
    if ((in_stack_00000020 != (undefined *)0x0) && ((in_stack_00000018 | in_stack_0000001c) == 0)) {
      *in_stack_00000020 = 0;
    }
  }
  else {
    fVar2 = FUN_004071ce(param_1,(int *)&stack0x00000008,local_314);
    __crt_strtox::parse_floating_point_write_result<float>
              (fVar2,(floating_point_string *)local_314,in_stack_00000028);
    if ((in_stack_00000020 != (undefined *)0x0) && ((in_stack_00000018 | in_stack_0000001c) == 0)) {
      *in_stack_00000020 = 0;
    }
  }
  FUN_00402125(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_00406ce2(_locale_t param_1)

{
  undefined4 *puVar1;
  floating_point_parse_result fVar2;
  uint in_stack_00000018;
  uint in_stack_0000001c;
  undefined *in_stack_00000020;
  double *in_stack_00000028;
  int local_314 [195];
  uint local_8;
  
  local_8 = DAT_00423014 ^ (uint)&stack0xfffffffc;
  if ((in_stack_00000028 == (double *)0x0) || (param_1 == (_locale_t)0x0)) {
    puVar1 = (undefined4 *)FUN_0040e304();
    *puVar1 = 0x16;
    FUN_0040e223();
    if ((in_stack_00000020 != (undefined *)0x0) && ((in_stack_00000018 | in_stack_0000001c) == 0)) {
      *in_stack_00000020 = 0;
    }
  }
  else {
    fVar2 = FUN_004071ce(param_1,(int *)&stack0x00000008,local_314);
    __crt_strtox::parse_floating_point_write_result<double>
              (fVar2,(floating_point_string *)local_314,in_stack_00000028);
    if ((in_stack_00000020 != (undefined *)0x0) && ((in_stack_00000018 | in_stack_0000001c) == 0)) {
      *in_stack_00000020 = 0;
    }
  }
  FUN_00402125(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



uint __cdecl FUN_00406d6c(_locale_t param_1,int *param_2,int *param_3)

{
  byte bVar1;
  char cVar2;
  undefined4 uVar3;
  uint uVar4;
  uint uVar5;
  undefined3 extraout_var;
  int iVar6;
  int *piVar7;
  int *local_2c;
  undefined4 *local_28;
  int *local_24;
  int local_20;
  int local_1c;
  uint local_18;
  undefined4 local_14;
  int *local_10;
  undefined4 local_b;
  char local_7;
  char local_6;
  byte local_5;
  
  uVar3 = FUN_0040c6ff(param_2);
  if ((char)uVar3 == '\0') {
    return 7;
  }
  local_1c = param_2[5];
  local_20 = param_2[4];
  bVar1 = __crt_strtox::input_adapter_character_source<>::get
                    ((input_adapter_character_source<> *)param_2);
  local_28 = &local_b;
  local_24 = &local_20;
  local_2c = param_2;
  while( true ) {
    local_b = CONCAT31(local_b._1_3_,bVar1);
    uVar4 = FUN_0040c9cd((uint)bVar1,8,param_1);
    if (uVar4 == 0) break;
    bVar1 = __crt_strtox::input_adapter_character_source<>::get
                      ((input_adapter_character_source<> *)param_2);
  }
  *(bool *)(param_3 + 0xc2) = (char)local_b == '-';
  if (((char)local_b == '-') || (cVar2 = (char)local_b, (char)local_b == '+')) {
    cVar2 = __crt_strtox::input_adapter_character_source<>::get
                      ((input_adapter_character_source<> *)param_2);
    local_b = CONCAT31(local_b._1_3_,cVar2);
  }
  if ((cVar2 == 'I') || (cVar2 == 'i')) {
    cVar2 = FUN_00407630((char *)&local_b,(input_adapter_character_source<> *)param_2,local_20,
                         local_1c);
    return CONCAT31(extraout_var,cVar2);
  }
  if ((cVar2 == 'N') || (cVar2 == 'n')) {
    uVar4 = FUN_004077ae((char *)&local_b,(input_adapter_character_source<> *)param_2,local_20,
                         local_1c);
    return uVar4;
  }
  local_5 = 0;
  if (cVar2 == '0') {
    local_10 = (int *)param_2[5];
    iVar6 = param_2[4];
    cVar2 = __crt_strtox::input_adapter_character_source<>::get
                      ((input_adapter_character_source<> *)param_2);
    local_14 = CONCAT31(local_14._1_3_,cVar2);
    if ((cVar2 == 'x') || (cVar2 == 'X')) {
      local_5 = 1;
      cVar2 = __crt_strtox::input_adapter_character_source<>::get
                        ((input_adapter_character_source<> *)param_2);
      local_b = CONCAT31(local_b._1_3_,cVar2);
      local_1c = (int)local_10;
      local_20 = iVar6;
    }
    else {
      __crt_strtox::input_adapter_character_source<>::unget
                ((input_adapter_character_source<> *)param_2,cVar2);
      cVar2 = (char)local_b;
    }
  }
  local_14 = 0;
  local_6 = '\0';
  local_10 = param_3 + 2;
  if (cVar2 == '0') {
    local_6 = '\x01';
    do {
      cVar2 = __crt_strtox::input_adapter_character_source<>::get
                        ((input_adapter_character_source<> *)param_2);
      local_b = CONCAT31(local_b._1_3_,cVar2);
    } while (cVar2 == '0');
  }
  uVar4 = ((local_5 == 0) - 1 & 6) + 9;
  piVar7 = local_10;
  local_18 = uVar4;
  while( true ) {
    if ((byte)(cVar2 - 0x30U) < 10) {
      uVar5 = (int)cVar2 - 0x30;
    }
    else if ((byte)(cVar2 + 0x9fU) < 0x1a) {
      uVar5 = (int)cVar2 - 0x57;
    }
    else if ((byte)(cVar2 + 0xbfU) < 0x1a) {
      uVar5 = (int)cVar2 - 0x37;
    }
    else {
      uVar5 = 0xffffffff;
    }
    if (uVar4 < uVar5) break;
    local_6 = '\x01';
    if (piVar7 != param_3 + 0xc2) {
      *(char *)piVar7 = (char)uVar5;
      piVar7 = (int *)((int)piVar7 + 1);
    }
    local_14 = local_14 + 1;
    cVar2 = __crt_strtox::input_adapter_character_source<>::get
                      ((input_adapter_character_source<> *)param_2);
    local_b = CONCAT31(local_b._1_3_,cVar2);
  }
  if (cVar2 == *(char *)*param_1->locinfo->ctype1_refcount) {
    local_10 = piVar7;
    cVar2 = __crt_strtox::input_adapter_character_source<>::get
                      ((input_adapter_character_source<> *)param_2);
    local_b = CONCAT31(local_b._1_3_,cVar2);
    piVar7 = local_10;
    iVar6 = local_14;
    uVar4 = local_18;
    if ((local_10 == param_3 + 2) && (cVar2 == '0')) {
      local_6 = '\x01';
      do {
        iVar6 = iVar6 + -1;
        cVar2 = __crt_strtox::input_adapter_character_source<>::get
                          ((input_adapter_character_source<> *)param_2);
        local_b = CONCAT31(local_b._1_3_,cVar2);
        piVar7 = local_10;
        uVar4 = local_18;
      } while (cVar2 == '0');
    }
    while( true ) {
      local_14 = iVar6;
      if ((byte)(cVar2 - 0x30U) < 10) {
        uVar5 = (int)cVar2 - 0x30;
      }
      else if ((byte)(cVar2 + 0x9fU) < 0x1a) {
        uVar5 = (int)cVar2 - 0x57;
      }
      else if ((byte)(cVar2 + 0xbfU) < 0x1a) {
        uVar5 = (int)cVar2 - 0x37;
      }
      else {
        uVar5 = 0xffffffff;
      }
      if (uVar4 < uVar5) break;
      local_6 = '\x01';
      if (piVar7 != param_3 + 0xc2) {
        *(char *)piVar7 = (char)uVar5;
        piVar7 = (int *)((int)piVar7 + 1);
      }
      cVar2 = __crt_strtox::input_adapter_character_source<>::get
                        ((input_adapter_character_source<> *)param_2);
      local_b = CONCAT31(local_b._1_3_,cVar2);
      iVar6 = local_14;
    }
  }
  local_10 = piVar7;
  iVar6 = 0;
  if (local_6 == '\0') {
    cVar2 = FID_conflict_operator__((input_adapter_character_source<> **)&local_2c);
    if (cVar2 == '\0') {
      return 7;
    }
    if (local_5 == 0) {
      return 7;
    }
    return 2;
  }
  __crt_strtox::input_adapter_character_source<>::unget
            ((input_adapter_character_source<> *)param_2,(char)local_b);
  local_1c = param_2[5];
  local_20 = param_2[4];
  cVar2 = __crt_strtox::input_adapter_character_source<>::get
                    ((input_adapter_character_source<> *)param_2);
  if (cVar2 == 'E') {
LAB_00407012:
    bVar1 = local_5 ^ 1;
  }
  else if (cVar2 == 'P') {
LAB_0040700d:
    bVar1 = local_5;
  }
  else {
    if (cVar2 == 'e') goto LAB_00407012;
    bVar1 = 0;
    if (cVar2 == 'p') goto LAB_0040700d;
  }
  local_b._0_1_ = cVar2;
  if (bVar1 != 0) {
    local_b._0_1_ =
         __crt_strtox::input_adapter_character_source<>::get
                   ((input_adapter_character_source<> *)param_2);
    local_7 = (char)local_b == '-';
    if (((char)local_b == '+') || ((char)local_b == '-')) {
      local_b._0_1_ =
           __crt_strtox::input_adapter_character_source<>::get
                     ((input_adapter_character_source<> *)param_2);
    }
    local_6 = '\0';
    if ((char)local_b == '0') {
      local_6 = '\x01';
      local_b._0_1_ = '0';
      do {
        local_b._0_1_ =
             __crt_strtox::input_adapter_character_source<>::get
                       ((input_adapter_character_source<> *)param_2);
      } while ((char)local_b == '0');
    }
    while( true ) {
      if ((byte)((char)local_b - 0x30U) < 10) {
        uVar4 = (int)(char)local_b - 0x30;
      }
      else if ((byte)((char)local_b + 0x9fU) < 0x1a) {
        uVar4 = (int)(char)local_b - 0x57;
      }
      else {
        if (0x19 < (byte)((char)local_b + 0xbfU)) goto LAB_004070bd;
        uVar4 = (int)(char)local_b - 0x37;
      }
      if (9 < uVar4) goto LAB_004070bd;
      local_6 = '\x01';
      iVar6 = iVar6 * 10 + uVar4;
      if (0x1450 < iVar6) break;
      local_b._0_1_ =
           __crt_strtox::input_adapter_character_source<>::get
                     ((input_adapter_character_source<> *)param_2);
    }
    iVar6 = 0x1451;
LAB_004070bd:
    do {
      if ((byte)((char)local_b - 0x30U) < 10) {
        uVar4 = (int)(char)local_b - 0x30;
      }
      else if ((byte)((char)local_b + 0x9fU) < 0x1a) {
        uVar4 = (int)(char)local_b - 0x57;
      }
      else {
        if (0x19 < (byte)((char)local_b + 0xbfU)) goto LAB_004070fe;
        uVar4 = (int)(char)local_b - 0x37;
      }
      if (9 < uVar4) goto LAB_004070fe;
      local_b._0_1_ =
           __crt_strtox::input_adapter_character_source<>::get
                     ((input_adapter_character_source<> *)param_2);
    } while( true );
  }
LAB_00407126:
  __crt_strtox::input_adapter_character_source<>::unget
            ((input_adapter_character_source<> *)param_2,(char)local_b);
  do {
    piVar7 = local_10;
    if (piVar7 == param_3 + 2) {
      return 2;
    }
    local_10 = (int *)((int)piVar7 + -1);
  } while (*(char *)(int *)((int)piVar7 + -1) == '\0');
  if (iVar6 < 0x1451) {
    if (-0x1451 < iVar6) {
      iVar6 = iVar6 + (((local_5 == 0) - 1 & 3) + 1) * local_14;
      if (0x1450 < iVar6) goto LAB_0040719d;
      if (-0x1451 < iVar6) {
        *param_3 = iVar6;
        param_3[1] = (int)piVar7 - (int)(param_3 + 2);
        return (uint)local_5;
      }
    }
    uVar4 = 8;
  }
  else {
LAB_0040719d:
    uVar4 = 9;
  }
  return uVar4;
LAB_004070fe:
  if (local_7 != '\0') {
    iVar6 = -iVar6;
  }
  if (local_6 == '\0') {
    cVar2 = FID_conflict_operator__((input_adapter_character_source<> **)&local_2c);
    if (cVar2 == '\0') {
      return 7;
    }
    local_b._0_1_ =
         __crt_strtox::input_adapter_character_source<>::get
                   ((input_adapter_character_source<> *)param_2);
  }
  goto LAB_00407126;
}



uint __cdecl FUN_004071ce(_locale_t param_1,int *param_2,int *param_3)

{
  byte bVar1;
  char cVar2;
  undefined4 uVar3;
  uint uVar4;
  uint uVar5;
  undefined3 extraout_var;
  int iVar6;
  int *piVar7;
  int *local_2c;
  undefined4 *local_28;
  int *local_24;
  int local_20;
  int local_1c;
  uint local_18;
  undefined4 local_14;
  int *local_10;
  undefined4 local_b;
  char local_7;
  char local_6;
  byte local_5;
  
  uVar3 = FUN_0040c6ff(param_2);
  if ((char)uVar3 == '\0') {
    return 7;
  }
  local_1c = param_2[5];
  local_20 = param_2[4];
  bVar1 = __crt_strtox::input_adapter_character_source<>::get
                    ((input_adapter_character_source<> *)param_2);
  local_28 = &local_b;
  local_24 = &local_20;
  local_2c = param_2;
  while( true ) {
    local_b = CONCAT31(local_b._1_3_,bVar1);
    uVar4 = FUN_0040c9cd((uint)bVar1,8,param_1);
    if (uVar4 == 0) break;
    bVar1 = __crt_strtox::input_adapter_character_source<>::get
                      ((input_adapter_character_source<> *)param_2);
  }
  *(bool *)(param_3 + 0xc2) = (char)local_b == '-';
  if (((char)local_b == '-') || (cVar2 = (char)local_b, (char)local_b == '+')) {
    cVar2 = __crt_strtox::input_adapter_character_source<>::get
                      ((input_adapter_character_source<> *)param_2);
    local_b = CONCAT31(local_b._1_3_,cVar2);
  }
  if ((cVar2 == 'I') || (cVar2 == 'i')) {
    cVar2 = FUN_004076ef((char *)&local_b,(input_adapter_character_source<> *)param_2,local_20,
                         local_1c);
    return CONCAT31(extraout_var,cVar2);
  }
  if ((cVar2 == 'N') || (cVar2 == 'n')) {
    uVar4 = FUN_004078b6((char *)&local_b,(input_adapter_character_source<> *)param_2,local_20,
                         local_1c);
    return uVar4;
  }
  local_5 = 0;
  if (cVar2 == '0') {
    local_10 = (int *)param_2[5];
    iVar6 = param_2[4];
    cVar2 = __crt_strtox::input_adapter_character_source<>::get
                      ((input_adapter_character_source<> *)param_2);
    local_14 = CONCAT31(local_14._1_3_,cVar2);
    if ((cVar2 == 'x') || (cVar2 == 'X')) {
      local_5 = 1;
      cVar2 = __crt_strtox::input_adapter_character_source<>::get
                        ((input_adapter_character_source<> *)param_2);
      local_b = CONCAT31(local_b._1_3_,cVar2);
      local_1c = (int)local_10;
      local_20 = iVar6;
    }
    else {
      __crt_strtox::input_adapter_character_source<>::unget
                ((input_adapter_character_source<> *)param_2,cVar2);
      cVar2 = (char)local_b;
    }
  }
  local_14 = 0;
  local_6 = '\0';
  local_10 = param_3 + 2;
  if (cVar2 == '0') {
    local_6 = '\x01';
    do {
      cVar2 = __crt_strtox::input_adapter_character_source<>::get
                        ((input_adapter_character_source<> *)param_2);
      local_b = CONCAT31(local_b._1_3_,cVar2);
    } while (cVar2 == '0');
  }
  uVar4 = ((local_5 == 0) - 1 & 6) + 9;
  piVar7 = local_10;
  local_18 = uVar4;
  while( true ) {
    if ((byte)(cVar2 - 0x30U) < 10) {
      uVar5 = (int)cVar2 - 0x30;
    }
    else if ((byte)(cVar2 + 0x9fU) < 0x1a) {
      uVar5 = (int)cVar2 - 0x57;
    }
    else if ((byte)(cVar2 + 0xbfU) < 0x1a) {
      uVar5 = (int)cVar2 - 0x37;
    }
    else {
      uVar5 = 0xffffffff;
    }
    if (uVar4 < uVar5) break;
    local_6 = '\x01';
    if (piVar7 != param_3 + 0xc2) {
      *(char *)piVar7 = (char)uVar5;
      piVar7 = (int *)((int)piVar7 + 1);
    }
    local_14 = local_14 + 1;
    cVar2 = __crt_strtox::input_adapter_character_source<>::get
                      ((input_adapter_character_source<> *)param_2);
    local_b = CONCAT31(local_b._1_3_,cVar2);
  }
  if (cVar2 == *(char *)*param_1->locinfo->ctype1_refcount) {
    local_10 = piVar7;
    cVar2 = __crt_strtox::input_adapter_character_source<>::get
                      ((input_adapter_character_source<> *)param_2);
    local_b = CONCAT31(local_b._1_3_,cVar2);
    piVar7 = local_10;
    iVar6 = local_14;
    uVar4 = local_18;
    if ((local_10 == param_3 + 2) && (cVar2 == '0')) {
      local_6 = '\x01';
      do {
        iVar6 = iVar6 + -1;
        cVar2 = __crt_strtox::input_adapter_character_source<>::get
                          ((input_adapter_character_source<> *)param_2);
        local_b = CONCAT31(local_b._1_3_,cVar2);
        piVar7 = local_10;
        uVar4 = local_18;
      } while (cVar2 == '0');
    }
    while( true ) {
      local_14 = iVar6;
      if ((byte)(cVar2 - 0x30U) < 10) {
        uVar5 = (int)cVar2 - 0x30;
      }
      else if ((byte)(cVar2 + 0x9fU) < 0x1a) {
        uVar5 = (int)cVar2 - 0x57;
      }
      else if ((byte)(cVar2 + 0xbfU) < 0x1a) {
        uVar5 = (int)cVar2 - 0x37;
      }
      else {
        uVar5 = 0xffffffff;
      }
      if (uVar4 < uVar5) break;
      local_6 = '\x01';
      if (piVar7 != param_3 + 0xc2) {
        *(char *)piVar7 = (char)uVar5;
        piVar7 = (int *)((int)piVar7 + 1);
      }
      cVar2 = __crt_strtox::input_adapter_character_source<>::get
                        ((input_adapter_character_source<> *)param_2);
      local_b = CONCAT31(local_b._1_3_,cVar2);
      iVar6 = local_14;
    }
  }
  local_10 = piVar7;
  iVar6 = 0;
  if (local_6 == '\0') {
    cVar2 = FID_conflict_operator__((input_adapter_character_source<> **)&local_2c);
    if (cVar2 == '\0') {
      return 7;
    }
    if (local_5 == 0) {
      return 7;
    }
    return 2;
  }
  __crt_strtox::input_adapter_character_source<>::unget
            ((input_adapter_character_source<> *)param_2,(char)local_b);
  local_1c = param_2[5];
  local_20 = param_2[4];
  cVar2 = __crt_strtox::input_adapter_character_source<>::get
                    ((input_adapter_character_source<> *)param_2);
  if (cVar2 == 'E') {
LAB_00407474:
    bVar1 = local_5 ^ 1;
  }
  else if (cVar2 == 'P') {
LAB_0040746f:
    bVar1 = local_5;
  }
  else {
    if (cVar2 == 'e') goto LAB_00407474;
    bVar1 = 0;
    if (cVar2 == 'p') goto LAB_0040746f;
  }
  local_b._0_1_ = cVar2;
  if (bVar1 != 0) {
    local_b._0_1_ =
         __crt_strtox::input_adapter_character_source<>::get
                   ((input_adapter_character_source<> *)param_2);
    local_7 = (char)local_b == '-';
    if (((char)local_b == '+') || ((char)local_b == '-')) {
      local_b._0_1_ =
           __crt_strtox::input_adapter_character_source<>::get
                     ((input_adapter_character_source<> *)param_2);
    }
    local_6 = '\0';
    if ((char)local_b == '0') {
      local_6 = '\x01';
      local_b._0_1_ = '0';
      do {
        local_b._0_1_ =
             __crt_strtox::input_adapter_character_source<>::get
                       ((input_adapter_character_source<> *)param_2);
      } while ((char)local_b == '0');
    }
    while( true ) {
      if ((byte)((char)local_b - 0x30U) < 10) {
        uVar4 = (int)(char)local_b - 0x30;
      }
      else if ((byte)((char)local_b + 0x9fU) < 0x1a) {
        uVar4 = (int)(char)local_b - 0x57;
      }
      else {
        if (0x19 < (byte)((char)local_b + 0xbfU)) goto LAB_0040751f;
        uVar4 = (int)(char)local_b - 0x37;
      }
      if (9 < uVar4) goto LAB_0040751f;
      local_6 = '\x01';
      iVar6 = iVar6 * 10 + uVar4;
      if (0x1450 < iVar6) break;
      local_b._0_1_ =
           __crt_strtox::input_adapter_character_source<>::get
                     ((input_adapter_character_source<> *)param_2);
    }
    iVar6 = 0x1451;
LAB_0040751f:
    do {
      if ((byte)((char)local_b - 0x30U) < 10) {
        uVar4 = (int)(char)local_b - 0x30;
      }
      else if ((byte)((char)local_b + 0x9fU) < 0x1a) {
        uVar4 = (int)(char)local_b - 0x57;
      }
      else {
        if (0x19 < (byte)((char)local_b + 0xbfU)) goto LAB_00407560;
        uVar4 = (int)(char)local_b - 0x37;
      }
      if (9 < uVar4) goto LAB_00407560;
      local_b._0_1_ =
           __crt_strtox::input_adapter_character_source<>::get
                     ((input_adapter_character_source<> *)param_2);
    } while( true );
  }
LAB_00407588:
  __crt_strtox::input_adapter_character_source<>::unget
            ((input_adapter_character_source<> *)param_2,(char)local_b);
  do {
    piVar7 = local_10;
    if (piVar7 == param_3 + 2) {
      return 2;
    }
    local_10 = (int *)((int)piVar7 + -1);
  } while (*(char *)(int *)((int)piVar7 + -1) == '\0');
  if (iVar6 < 0x1451) {
    if (-0x1451 < iVar6) {
      iVar6 = iVar6 + (((local_5 == 0) - 1 & 3) + 1) * local_14;
      if (0x1450 < iVar6) goto LAB_004075ff;
      if (-0x1451 < iVar6) {
        *param_3 = iVar6;
        param_3[1] = (int)piVar7 - (int)(param_3 + 2);
        return (uint)local_5;
      }
    }
    uVar4 = 8;
  }
  else {
LAB_004075ff:
    uVar4 = 9;
  }
  return uVar4;
LAB_00407560:
  if (local_7 != '\0') {
    iVar6 = -iVar6;
  }
  if (local_6 == '\0') {
    cVar2 = FID_conflict_operator__((input_adapter_character_source<> **)&local_2c);
    if (cVar2 == '\0') {
      return 7;
    }
    local_b._0_1_ =
         __crt_strtox::input_adapter_character_source<>::get
                   ((input_adapter_character_source<> *)param_2);
  }
  goto LAB_00407588;
}



char __cdecl
FUN_00407630(char *param_1,input_adapter_character_source<> *param_2,undefined4 param_3,
            undefined4 param_4)

{
  char cVar1;
  int iVar2;
  input_adapter_character_source<> *local_14;
  char *local_10;
  undefined4 *local_c;
  int local_8;
  
  local_c = &param_3;
  iVar2 = 0;
  local_14 = param_2;
  local_10 = param_1;
  local_8 = 0;
  while ((*param_1 == (&DAT_0041c980)[local_8] || (*param_1 == (&DAT_0041c984)[local_8]))) {
    cVar1 = __crt_strtox::input_adapter_character_source<>::get(param_2);
    local_8 = local_8 + 1;
    *param_1 = cVar1;
    if (local_8 == 3) {
      __crt_strtox::input_adapter_character_source<>::unget(param_2,cVar1);
      param_4 = *(undefined4 *)(param_2 + 0x14);
      param_3 = *(undefined4 *)(param_2 + 0x10);
      cVar1 = __crt_strtox::input_adapter_character_source<>::get(param_2);
      *param_1 = cVar1;
      while ((*param_1 == "INITY"[iVar2] || (*param_1 == "inity"[iVar2]))) {
        cVar1 = __crt_strtox::input_adapter_character_source<>::get(param_2);
        iVar2 = iVar2 + 1;
        *param_1 = cVar1;
        if (iVar2 == 5) {
          __crt_strtox::input_adapter_character_source<>::unget(param_2,cVar1);
          return '\x03';
        }
      }
      cVar1 = FID_conflict_operator__(&local_14);
      return (cVar1 == '\0') * '\x04' + '\x03';
    }
  }
  FID_conflict_operator__(&local_14);
  return '\a';
}



char __cdecl
FUN_004076ef(char *param_1,input_adapter_character_source<> *param_2,undefined4 param_3,
            undefined4 param_4)

{
  char cVar1;
  int iVar2;
  input_adapter_character_source<> *local_14;
  char *local_10;
  undefined4 *local_c;
  int local_8;
  
  local_c = &param_3;
  iVar2 = 0;
  local_14 = param_2;
  local_10 = param_1;
  local_8 = 0;
  while ((*param_1 == (&DAT_0041c960)[local_8] || (*param_1 == (&DAT_0041c964)[local_8]))) {
    cVar1 = __crt_strtox::input_adapter_character_source<>::get(param_2);
    local_8 = local_8 + 1;
    *param_1 = cVar1;
    if (local_8 == 3) {
      __crt_strtox::input_adapter_character_source<>::unget(param_2,cVar1);
      param_4 = *(undefined4 *)(param_2 + 0x14);
      param_3 = *(undefined4 *)(param_2 + 0x10);
      cVar1 = __crt_strtox::input_adapter_character_source<>::get(param_2);
      *param_1 = cVar1;
      while ((*param_1 == "INITY"[iVar2] || (*param_1 == "inity"[iVar2]))) {
        cVar1 = __crt_strtox::input_adapter_character_source<>::get(param_2);
        iVar2 = iVar2 + 1;
        *param_1 = cVar1;
        if (iVar2 == 5) {
          __crt_strtox::input_adapter_character_source<>::unget(param_2,cVar1);
          return '\x03';
        }
      }
      cVar1 = FID_conflict_operator__(&local_14);
      return (cVar1 == '\0') * '\x04' + '\x03';
    }
  }
  FID_conflict_operator__(&local_14);
  return '\a';
}



int __cdecl
FUN_004077ae(char *param_1,input_adapter_character_source<> *param_2,undefined4 param_3,
            undefined4 param_4)

{
  char cVar1;
  bool bVar2;
  int iVar3;
  input_adapter_character_source<> *local_10;
  char *local_c;
  undefined4 *local_8;
  
  local_8 = &param_3;
  iVar3 = 0;
  local_10 = param_2;
  local_c = param_1;
  do {
    if ((*param_1 != (&DAT_0041c998)[iVar3]) && (*param_1 != (&DAT_0041c99c)[iVar3])) {
      FID_conflict_operator__(&local_10);
      return 7;
    }
    cVar1 = __crt_strtox::input_adapter_character_source<>::get(param_2);
    iVar3 = iVar3 + 1;
    *param_1 = cVar1;
  } while (iVar3 != 3);
  __crt_strtox::input_adapter_character_source<>::unget(param_2,cVar1);
  param_4 = *(undefined4 *)(param_2 + 0x14);
  param_3 = *(undefined4 *)(param_2 + 0x10);
  cVar1 = __crt_strtox::input_adapter_character_source<>::get(param_2);
  *param_1 = cVar1;
  if (cVar1 == '(') {
    cVar1 = __crt_strtox::input_adapter_character_source<>::get(param_2);
    *param_1 = cVar1;
    bVar2 = __crt_strtox::parse_floating_point_possible_nan_is_snan<>(param_1,param_2);
    if (bVar2) {
      __crt_strtox::input_adapter_character_source<>::unget(param_2,*param_1);
      iVar3 = 5;
    }
    else {
      bVar2 = __crt_strtox::parse_floating_point_possible_nan_is_ind<>(param_1,param_2);
      cVar1 = *param_1;
      if (bVar2) {
        __crt_strtox::input_adapter_character_source<>::unget(param_2,cVar1);
        iVar3 = 6;
      }
      else {
        while (cVar1 != ')') {
          if ((cVar1 == '\0') ||
             ((((9 < (byte)(cVar1 - 0x30U) && (0x19 < (byte)(cVar1 + 0x9fU))) &&
               (0x19 < (byte)(cVar1 + 0xbfU))) && (cVar1 != '_')))) goto LAB_0040780f;
          cVar1 = __crt_strtox::input_adapter_character_source<>::get(param_2);
          *param_1 = cVar1;
        }
        iVar3 = 4;
      }
    }
  }
  else {
LAB_0040780f:
    cVar1 = FID_conflict_operator__(&local_10);
    iVar3 = (-(uint)(cVar1 != '\0') & 0xfffffffd) + 7;
  }
  return iVar3;
}



int __cdecl
FUN_004078b6(char *param_1,input_adapter_character_source<> *param_2,undefined4 param_3,
            undefined4 param_4)

{
  char cVar1;
  bool bVar2;
  int iVar3;
  input_adapter_character_source<> *local_10;
  char *local_c;
  undefined4 *local_8;
  
  local_8 = &param_3;
  iVar3 = 0;
  local_10 = param_2;
  local_c = param_1;
  do {
    if ((*param_1 != (&DAT_0041c978)[iVar3]) && (*param_1 != (&DAT_0041c97c)[iVar3])) {
      FID_conflict_operator__(&local_10);
      return 7;
    }
    cVar1 = __crt_strtox::input_adapter_character_source<>::get(param_2);
    iVar3 = iVar3 + 1;
    *param_1 = cVar1;
  } while (iVar3 != 3);
  __crt_strtox::input_adapter_character_source<>::unget(param_2,cVar1);
  param_4 = *(undefined4 *)(param_2 + 0x14);
  param_3 = *(undefined4 *)(param_2 + 0x10);
  cVar1 = __crt_strtox::input_adapter_character_source<>::get(param_2);
  *param_1 = cVar1;
  if (cVar1 == '(') {
    cVar1 = __crt_strtox::input_adapter_character_source<>::get(param_2);
    *param_1 = cVar1;
    bVar2 = __crt_strtox::parse_floating_point_possible_nan_is_snan<>(param_1,param_2);
    if (bVar2) {
      __crt_strtox::input_adapter_character_source<>::unget(param_2,*param_1);
      iVar3 = 5;
    }
    else {
      bVar2 = __crt_strtox::parse_floating_point_possible_nan_is_ind<>(param_1,param_2);
      cVar1 = *param_1;
      if (bVar2) {
        __crt_strtox::input_adapter_character_source<>::unget(param_2,cVar1);
        iVar3 = 6;
      }
      else {
        while (cVar1 != ')') {
          if ((cVar1 == '\0') ||
             ((((9 < (byte)(cVar1 - 0x30U) && (0x19 < (byte)(cVar1 + 0x9fU))) &&
               (0x19 < (byte)(cVar1 + 0xbfU))) && (cVar1 != '_')))) goto LAB_00407917;
          cVar1 = __crt_strtox::input_adapter_character_source<>::get(param_2);
          *param_1 = cVar1;
        }
        iVar3 = 4;
      }
    }
  }
  else {
LAB_00407917:
    cVar1 = FID_conflict_operator__(&local_10);
    iVar3 = (-(uint)(cVar1 != '\0') & 0xfffffffd) + 7;
  }
  return iVar3;
}



// Library Function - Single Match
//  bool __cdecl __crt_strtox::parse_floating_point_possible_nan_is_ind<char,class
// __crt_strtox::input_adapter_character_source<class __crt_stdio_input::stream_input_adapter<char>
// > >(char &,class __crt_strtox::input_adapter_character_source<class
// __crt_stdio_input::stream_input_adapter<char> > &)
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

bool __cdecl
__crt_strtox::parse_floating_point_possible_nan_is_ind<>
          (char *param_1,input_adapter_character_source<> *param_2)

{
  char cVar1;
  int iVar2;
  
  iVar2 = 0;
  while ((*param_1 == (&DAT_0041c9c8)[iVar2] || (*param_1 == (&DAT_0041c9cc)[iVar2]))) {
    cVar1 = input_adapter_character_source<>::get(param_2);
    iVar2 = iVar2 + 1;
    *param_1 = cVar1;
    if (iVar2 == 4) {
      return true;
    }
  }
  return false;
}



// Library Function - Single Match
//  bool __cdecl __crt_strtox::parse_floating_point_possible_nan_is_ind<char,class
// __crt_strtox::input_adapter_character_source<class __crt_stdio_input::string_input_adapter<char>
// > >(char &,class __crt_strtox::input_adapter_character_source<class
// __crt_stdio_input::string_input_adapter<char> > &)
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

bool __cdecl
__crt_strtox::parse_floating_point_possible_nan_is_ind<>
          (char *param_1,input_adapter_character_source<> *param_2)

{
  char cVar1;
  int iVar2;
  
  iVar2 = 0;
  while ((*param_1 == "IND)ind)SNAN)"[iVar2] || (*param_1 == "IND)ind)SNAN)"[iVar2 + 4]))) {
    cVar1 = input_adapter_character_source<>::get(param_2);
    iVar2 = iVar2 + 1;
    *param_1 = cVar1;
    if (iVar2 == 4) {
      return true;
    }
  }
  return false;
}



// Library Function - Single Match
//  bool __cdecl __crt_strtox::parse_floating_point_possible_nan_is_snan<char,class
// __crt_strtox::input_adapter_character_source<class __crt_stdio_input::stream_input_adapter<char>
// > >(char &,class __crt_strtox::input_adapter_character_source<class
// __crt_stdio_input::stream_input_adapter<char> > &)
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

bool __cdecl
__crt_strtox::parse_floating_point_possible_nan_is_snan<>
          (char *param_1,input_adapter_character_source<> *param_2)

{
  char cVar1;
  int iVar2;
  
  iVar2 = 0;
  while ((*param_1 == "IND)ind)SNAN)"[iVar2 + 8] || (*param_1 == "snan)"[iVar2]))) {
    cVar1 = input_adapter_character_source<>::get(param_2);
    iVar2 = iVar2 + 1;
    *param_1 = cVar1;
    if (iVar2 == 5) {
      return true;
    }
  }
  return false;
}



// Library Function - Single Match
//  bool __cdecl __crt_strtox::parse_floating_point_possible_nan_is_snan<char,class
// __crt_strtox::input_adapter_character_source<class __crt_stdio_input::string_input_adapter<char>
// > >(char &,class __crt_strtox::input_adapter_character_source<class
// __crt_stdio_input::string_input_adapter<char> > &)
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

bool __cdecl
__crt_strtox::parse_floating_point_possible_nan_is_snan<>
          (char *param_1,input_adapter_character_source<> *param_2)

{
  char cVar1;
  int iVar2;
  
  iVar2 = 0;
  while ((*param_1 == (&DAT_0041c9a0)[iVar2] || (*param_1 == "snan)"[iVar2]))) {
    cVar1 = input_adapter_character_source<>::get(param_2);
    iVar2 = iVar2 + 1;
    *param_1 = cVar1;
    if (iVar2 == 5) {
      return true;
    }
  }
  return false;
}



// Library Function - Single Match
//  enum SLD_STATUS __cdecl __crt_strtox::parse_floating_point_write_result<float>(enum
// __crt_strtox::floating_point_parse_result,struct __crt_strtox::floating_point_string const
// &,float * const)
// 
// Library: Visual Studio 2019 Release

SLD_STATUS __cdecl
__crt_strtox::parse_floating_point_write_result<float>
          (floating_point_parse_result param_1,floating_point_string *param_2,float *param_3)

{
  SLD_STATUS SVar1;
  float fVar2;
  
  switch(param_1) {
  case 0:
    SVar1 = FID_conflict_convert_hexadecimal_string_to_floating_type<float>((uint *)param_2,param_3)
    ;
    break;
  case 1:
    SVar1 = FID_conflict_convert_hexadecimal_string_to_floating_type<float>((int *)param_2,param_3);
    break;
  case 2:
    fVar2 = (float)(-(uint)(param_2[0x308] != (floating_point_string)0x0) & 0x80000000);
    goto LAB_00407af5;
  case 3:
    fVar2 = (float)(((param_2[0x308] == (floating_point_string)0x0) - 1 & 0x80000000) + 0x7f800000 |
                   (uint)*param_3 & 0x7f800000);
    goto LAB_00407b2c;
  case 4:
    fVar2 = (float)(((param_2[0x308] == (floating_point_string)0x0) - 1 & 0x80000000) + 0x7fffffff);
LAB_00407af5:
    *param_3 = fVar2;
LAB_00407afa:
    SVar1 = 0;
    break;
  case 5:
    fVar2 = (float)(((param_2[0x308] == (floating_point_string)0x0) - 1 & 0x80000000) + 0x7f800000 |
                    (uint)*param_3 & 0x7f800000 | 1);
LAB_00407b2c:
    *param_3 = fVar2;
    goto LAB_00407afa;
  case 6:
    *param_3 = -NAN;
    goto LAB_00407afa;
  case 7:
    *param_3 = 0.0;
  default:
    SVar1 = 1;
    break;
  case 8:
    SVar1 = 2;
    *param_3 = (float)(-(uint)(param_2[0x308] != (floating_point_string)0x0) & 0x80000000);
    break;
  case 9:
    SVar1 = 3;
    *param_3 = (float)(((param_2[0x308] == (floating_point_string)0x0) - 1 & 0x80000000) +
                       0x7f800000 | (uint)*param_3 & 0x7f800000);
  }
  return SVar1;
}



// Library Function - Single Match
//  enum SLD_STATUS __cdecl __crt_strtox::parse_floating_point_write_result<double>(enum
// __crt_strtox::floating_point_parse_result,struct __crt_strtox::floating_point_string const
// &,double * const)
// 
// Library: Visual Studio 2019 Release

SLD_STATUS __cdecl
__crt_strtox::parse_floating_point_write_result<double>
          (floating_point_parse_result param_1,floating_point_string *param_2,double *param_3)

{
  void *in_ECX;
  uint uVar1;
  SLD_STATUS SVar2;
  
  switch(param_1) {
  case 0:
    SVar2 = FID_conflict_convert_hexadecimal_string_to_floating_type<double>
                      (in_ECX,(uint *)param_2,param_3);
    return SVar2;
  case 1:
    SVar2 = FID_conflict_convert_hexadecimal_string_to_floating_type<double>
                      (in_ECX,(int *)param_2,param_3);
    return SVar2;
  case 2:
    uVar1 = (uint)(param_2[0x308] != (floating_point_string)0x0) << 0x1f;
    break;
  case 3:
    uVar1 = (uint)(param_2[0x308] != (floating_point_string)0x0) << 0x1f | 0x7ff00000;
    break;
  case 4:
    uVar1 = (uint)(param_2[0x308] != (floating_point_string)0x0) << 0x1f | 0x7fffffff;
    *(undefined4 *)param_3 = 0xffffffff;
    goto LAB_00407c5d;
  case 5:
    assemble_floating_point_snan<double>((bool)param_2[0x308],param_3);
    return 0;
  case 6:
    *(undefined4 *)param_3 = 0;
    *(undefined4 *)((int)param_3 + 4) = 0xfff80000;
    return 0;
  case 7:
    *(undefined4 *)param_3 = 0;
    *(undefined4 *)((int)param_3 + 4) = 0;
    return 1;
  case 8:
    SVar2 = 2;
    uVar1 = (uint)(param_2[0x308] != (floating_point_string)0x0) << 0x1f;
    goto LAB_00407ce4;
  case 9:
    SVar2 = 3;
    uVar1 = (uint)(param_2[0x308] != (floating_point_string)0x0) << 0x1f | 0x7ff00000;
LAB_00407ce4:
    *(undefined4 *)param_3 = 0;
    *(uint *)((int)param_3 + 4) = uVar1;
    return SVar2;
  default:
    return 1;
  }
  *(undefined4 *)param_3 = 0;
LAB_00407c5d:
  *(uint *)((int)param_3 + 4) = uVar1;
  return 0;
}



// WARNING: Removing unreachable block (ram,0x00407f48)

ulonglong __cdecl FUN_00407d36(__acrt_ptd **param_1)

{
  ulonglong uVar1;
  uint uVar2;
  uint uVar3;
  char cVar4;
  undefined4 uVar5;
  uint uVar6;
  int iVar7;
  uint uVar8;
  uint uVar9;
  undefined8 uVar10;
  ulonglong uVar11;
  uint in_stack_00000018;
  uint in_stack_0000001c;
  undefined *in_stack_00000020;
  uint in_stack_00000028;
  byte in_stack_0000002c;
  uint local_24;
  uint local_20;
  uint local_14;
  byte local_c;
  uint local_8;
  
  uVar5 = FUN_0040c6ff((int *)&stack0x00000008);
  uVar9 = in_stack_00000028;
  uVar3 = in_stack_0000001c;
  uVar2 = in_stack_00000018;
  if ((char)uVar5 == '\0') goto LAB_00407f94;
  if ((in_stack_00000028 != 0) && (((int)in_stack_00000028 < 2 || (0x24 < (int)in_stack_00000028))))
  {
    *(undefined *)(param_1 + 7) = 1;
    param_1[6] = (__acrt_ptd *)0x16;
    FUN_0040e1a6((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0,param_1);
    if (in_stack_00000020 == (undefined *)0x0) {
      return 0;
    }
    if ((in_stack_00000018 | in_stack_0000001c) != 0) {
      return 0;
    }
    *in_stack_00000020 = 0;
    return 0;
  }
  uVar1 = 0;
  local_c = __crt_strtox::input_adapter_character_source<>::get
                      ((input_adapter_character_source<> *)&stack0x00000008);
  if (*(char *)(param_1 + 5) == '\0') {
    FUN_004064e0(param_1);
  }
  uVar6 = FUN_0040c9cd((uint)local_c,8,(_locale_t)(param_1 + 3));
  while (uVar6 != 0) {
    local_c = __crt_strtox::input_adapter_character_source<>::get
                        ((input_adapter_character_source<> *)&stack0x00000008);
    uVar6 = FUN_0040c9cd((uint)local_c,8,(_locale_t)(param_1 + 3));
    uVar9 = in_stack_00000028;
  }
  local_8 = (uint)in_stack_0000002c;
  if (local_c == 0x2d) {
    local_8 = local_8 | 2;
LAB_00407e28:
    local_c = __crt_strtox::input_adapter_character_source<>::get
                        ((input_adapter_character_source<> *)&stack0x00000008);
  }
  else if (local_c == 0x2b) goto LAB_00407e28;
  if ((uVar9 == 0) || (uVar9 == 0x10)) {
    if ((byte)(local_c - 0x30) < 10) {
      iVar7 = (char)local_c + -0x30;
LAB_00407e6c:
      if (iVar7 == 0) {
        cVar4 = __crt_strtox::input_adapter_character_source<>::get
                          ((input_adapter_character_source<> *)&stack0x00000008);
        if ((cVar4 == 'x') || (cVar4 == 'X')) {
          if (uVar9 == 0) {
            uVar9 = 0x10;
          }
          local_c = __crt_strtox::input_adapter_character_source<>::get
                              ((input_adapter_character_source<> *)&stack0x00000008);
        }
        else {
          if (uVar9 == 0) {
            uVar9 = 8;
          }
          __crt_strtox::input_adapter_character_source<>::unget
                    ((input_adapter_character_source<> *)&stack0x00000008,cVar4);
        }
        goto LAB_00407eb4;
      }
    }
    else {
      if ((byte)(local_c + 0x9f) < 0x1a) {
        iVar7 = (char)local_c + -0x57;
        goto LAB_00407e6c;
      }
      if ((byte)(local_c + 0xbf) < 0x1a) {
        iVar7 = (char)local_c + -0x37;
        goto LAB_00407e6c;
      }
    }
    if (uVar9 == 0) {
      uVar9 = 10;
    }
  }
LAB_00407eb4:
  uVar10 = __aulldiv(0xffffffff,0xffffffff,uVar9,(int)uVar9 >> 0x1f);
  while( true ) {
    uVar6 = (uint)(uVar1 >> 0x20);
    local_14 = (uint)uVar1;
    if ((byte)(local_c - 0x30) < 10) {
      uVar8 = (int)(char)local_c - 0x30;
    }
    else if ((byte)(local_c + 0x9f) < 0x1a) {
      uVar8 = (int)(char)local_c - 0x57;
    }
    else if ((byte)(local_c + 0xbf) < 0x1a) {
      uVar8 = (int)(char)local_c - 0x37;
    }
    else {
      uVar8 = 0xffffffff;
    }
    if (uVar9 <= uVar8) break;
    uVar11 = __allmul(uVar9,(int)uVar9 >> 0x1f,local_14,uVar6);
    uVar1 = uVar11 + uVar8;
    local_20 = (uint)((ulonglong)uVar10 >> 0x20);
    if ((uVar6 < local_20) ||
       ((uVar6 <= local_20 && (local_24 = (uint)uVar10, local_14 <= local_24)))) {
      uVar6 = 0;
    }
    else {
      uVar6 = 1;
    }
    local_8 = local_8 | (uVar1 < uVar11 | uVar6) << 2 | 8;
    local_c = __crt_strtox::input_adapter_character_source<>::get
                        ((input_adapter_character_source<> *)&stack0x00000008);
  }
  __crt_strtox::input_adapter_character_source<>::unget
            ((input_adapter_character_source<> *)&stack0x00000008,local_c);
  if ((local_8 & 8) != 0) {
    cVar4 = FUN_00406ae5((byte)local_8,local_14,uVar6);
    if (cVar4 == '\0') {
      if ((local_8 & 2) != 0) {
        uVar1 = CONCAT44(-(uVar6 + (local_14 != 0)),-local_14);
      }
    }
    else {
      *(undefined *)(param_1 + 7) = 1;
      param_1[6] = (__acrt_ptd *)0x22;
      if ((local_8 & 1) != 0) {
        if ((local_8 & 2) == 0) {
          if ((in_stack_00000020 != (undefined *)0x0) &&
             ((in_stack_00000018 | in_stack_0000001c) == 0)) {
            *in_stack_00000020 = 0;
          }
          return 0x7fffffffffffffff;
        }
        if ((in_stack_00000020 != (undefined *)0x0) &&
           ((in_stack_00000018 | in_stack_0000001c) == 0)) {
          *in_stack_00000020 = 0;
        }
        return 0x8000000000000000;
      }
      uVar1 = 0xffffffffffffffff;
    }
    if (in_stack_00000020 != (undefined *)0x0) {
      if ((in_stack_00000018 | in_stack_0000001c) == 0) {
        *in_stack_00000020 = 0;
        return uVar1;
      }
      return uVar1;
    }
    return uVar1;
  }
  restore_state(&stack0x00000008,uVar2,uVar3);
LAB_00407f94:
  if ((in_stack_00000020 != (undefined *)0x0) && ((in_stack_00000018 | in_stack_0000001c) == 0)) {
    *in_stack_00000020 = 0;
  }
  return 0;
}



ulonglong __cdecl FUN_0040803a(undefined4 *param_1)

{
  ulonglong uVar1;
  uint in_stack_00000018;
  uint in_stack_0000001c;
  undefined *in_stack_00000020;
  undefined4 in_stack_00000028;
  undefined auStack_64 [32];
  undefined4 uStack_44;
  __acrt_ptd *local_30 [11];
  
  uStack_44 = 0x408050;
  FUN_004055d0(local_30,param_1);
  uStack_44 = in_stack_00000028;
  FUN_00408cf2(auStack_64,(undefined4 *)&stack0x00000008);
  uVar1 = FUN_00407d36(local_30);
  FUN_00405630(local_30);
  if ((in_stack_00000020 != (undefined *)0x0) && ((in_stack_00000018 | in_stack_0000001c) == 0)) {
    *in_stack_00000020 = 0;
  }
  return uVar1;
}



// WARNING: Removing unreachable block (ram,0x004082a8)

ulonglong __cdecl FUN_00408096(__acrt_ptd **param_1)

{
  ulonglong uVar1;
  uint uVar2;
  uint uVar3;
  char cVar4;
  undefined4 uVar5;
  uint uVar6;
  int iVar7;
  uint uVar8;
  uint uVar9;
  undefined8 uVar10;
  ulonglong uVar11;
  uint in_stack_00000018;
  uint in_stack_0000001c;
  undefined *in_stack_00000020;
  uint in_stack_00000028;
  byte in_stack_0000002c;
  uint local_24;
  uint local_20;
  uint local_14;
  byte local_c;
  uint local_8;
  
  uVar5 = FUN_0040c6ff((int *)&stack0x00000008);
  uVar9 = in_stack_00000028;
  uVar3 = in_stack_0000001c;
  uVar2 = in_stack_00000018;
  if ((char)uVar5 == '\0') goto LAB_004082f4;
  if ((in_stack_00000028 != 0) && (((int)in_stack_00000028 < 2 || (0x24 < (int)in_stack_00000028))))
  {
    *(undefined *)(param_1 + 7) = 1;
    param_1[6] = (__acrt_ptd *)0x16;
    FUN_0040e1a6((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0,param_1);
    if (in_stack_00000020 == (undefined *)0x0) {
      return 0;
    }
    if ((in_stack_00000018 | in_stack_0000001c) != 0) {
      return 0;
    }
    *in_stack_00000020 = 0;
    return 0;
  }
  uVar1 = 0;
  local_c = __crt_strtox::input_adapter_character_source<>::get
                      ((input_adapter_character_source<> *)&stack0x00000008);
  if (*(char *)(param_1 + 5) == '\0') {
    FUN_004064e0(param_1);
  }
  uVar6 = FUN_0040c9cd((uint)local_c,8,(_locale_t)(param_1 + 3));
  while (uVar6 != 0) {
    local_c = __crt_strtox::input_adapter_character_source<>::get
                        ((input_adapter_character_source<> *)&stack0x00000008);
    uVar6 = FUN_0040c9cd((uint)local_c,8,(_locale_t)(param_1 + 3));
    uVar9 = in_stack_00000028;
  }
  local_8 = (uint)in_stack_0000002c;
  if (local_c == 0x2d) {
    local_8 = local_8 | 2;
LAB_00408188:
    local_c = __crt_strtox::input_adapter_character_source<>::get
                        ((input_adapter_character_source<> *)&stack0x00000008);
  }
  else if (local_c == 0x2b) goto LAB_00408188;
  if ((uVar9 == 0) || (uVar9 == 0x10)) {
    if ((byte)(local_c - 0x30) < 10) {
      iVar7 = (char)local_c + -0x30;
LAB_004081cc:
      if (iVar7 == 0) {
        cVar4 = __crt_strtox::input_adapter_character_source<>::get
                          ((input_adapter_character_source<> *)&stack0x00000008);
        if ((cVar4 == 'x') || (cVar4 == 'X')) {
          if (uVar9 == 0) {
            uVar9 = 0x10;
          }
          local_c = __crt_strtox::input_adapter_character_source<>::get
                              ((input_adapter_character_source<> *)&stack0x00000008);
        }
        else {
          if (uVar9 == 0) {
            uVar9 = 8;
          }
          __crt_strtox::input_adapter_character_source<>::unget
                    ((input_adapter_character_source<> *)&stack0x00000008,cVar4);
        }
        goto LAB_00408214;
      }
    }
    else {
      if ((byte)(local_c + 0x9f) < 0x1a) {
        iVar7 = (char)local_c + -0x57;
        goto LAB_004081cc;
      }
      if ((byte)(local_c + 0xbf) < 0x1a) {
        iVar7 = (char)local_c + -0x37;
        goto LAB_004081cc;
      }
    }
    if (uVar9 == 0) {
      uVar9 = 10;
    }
  }
LAB_00408214:
  uVar10 = __aulldiv(0xffffffff,0xffffffff,uVar9,(int)uVar9 >> 0x1f);
  while( true ) {
    uVar6 = (uint)(uVar1 >> 0x20);
    local_14 = (uint)uVar1;
    if ((byte)(local_c - 0x30) < 10) {
      uVar8 = (int)(char)local_c - 0x30;
    }
    else if ((byte)(local_c + 0x9f) < 0x1a) {
      uVar8 = (int)(char)local_c - 0x57;
    }
    else if ((byte)(local_c + 0xbf) < 0x1a) {
      uVar8 = (int)(char)local_c - 0x37;
    }
    else {
      uVar8 = 0xffffffff;
    }
    if (uVar9 <= uVar8) break;
    uVar11 = __allmul(uVar9,(int)uVar9 >> 0x1f,local_14,uVar6);
    uVar1 = uVar11 + uVar8;
    local_20 = (uint)((ulonglong)uVar10 >> 0x20);
    if ((uVar6 < local_20) ||
       ((uVar6 <= local_20 && (local_24 = (uint)uVar10, local_14 <= local_24)))) {
      uVar6 = 0;
    }
    else {
      uVar6 = 1;
    }
    local_8 = local_8 | (uVar1 < uVar11 | uVar6) << 2 | 8;
    local_c = __crt_strtox::input_adapter_character_source<>::get
                        ((input_adapter_character_source<> *)&stack0x00000008);
  }
  __crt_strtox::input_adapter_character_source<>::unget
            ((input_adapter_character_source<> *)&stack0x00000008,local_c);
  if ((local_8 & 8) != 0) {
    cVar4 = FUN_00406ae5((byte)local_8,local_14,uVar6);
    if (cVar4 == '\0') {
      if ((local_8 & 2) != 0) {
        uVar1 = CONCAT44(-(uVar6 + (local_14 != 0)),-local_14);
      }
    }
    else {
      *(undefined *)(param_1 + 7) = 1;
      param_1[6] = (__acrt_ptd *)0x22;
      if ((local_8 & 1) != 0) {
        if ((local_8 & 2) == 0) {
          if ((in_stack_00000020 != (undefined *)0x0) &&
             ((in_stack_00000018 | in_stack_0000001c) == 0)) {
            *in_stack_00000020 = 0;
          }
          return 0x7fffffffffffffff;
        }
        if ((in_stack_00000020 != (undefined *)0x0) &&
           ((in_stack_00000018 | in_stack_0000001c) == 0)) {
          *in_stack_00000020 = 0;
        }
        return 0x8000000000000000;
      }
      uVar1 = 0xffffffffffffffff;
    }
    if (in_stack_00000020 != (undefined *)0x0) {
      if ((in_stack_00000018 | in_stack_0000001c) == 0) {
        *in_stack_00000020 = 0;
        return uVar1;
      }
      return uVar1;
    }
    return uVar1;
  }
  restore_state(&stack0x00000008,uVar2,uVar3);
LAB_004082f4:
  if ((in_stack_00000020 != (undefined *)0x0) && ((in_stack_00000018 | in_stack_0000001c) == 0)) {
    *in_stack_00000020 = 0;
  }
  return 0;
}



ulonglong __cdecl FUN_0040839a(undefined4 *param_1)

{
  ulonglong uVar1;
  uint in_stack_00000018;
  uint in_stack_0000001c;
  undefined *in_stack_00000020;
  undefined4 in_stack_00000028;
  undefined auStack_64 [32];
  undefined4 uStack_44;
  __acrt_ptd *local_30 [11];
  
  uStack_44 = 0x4083b0;
  FUN_004055d0(local_30,param_1);
  uStack_44 = in_stack_00000028;
  FUN_00408cf2(auStack_64,(undefined4 *)&stack0x00000008);
  uVar1 = FUN_00408096(local_30);
  FUN_00405630(local_30);
  if ((in_stack_00000020 != (undefined *)0x0) && ((in_stack_00000018 | in_stack_0000001c) == 0)) {
    *in_stack_00000020 = 0;
  }
  return uVar1;
}



uint __fastcall FUN_004083f6(void *param_1)

{
  _locale_t plVar1;
  int iVar2;
  uint3 uVar4;
  uint uVar3;
  undefined auStack_3c [28];
  undefined4 uStack_20;
  undefined4 local_c;
  char local_5;
  
  local_5 = '\0';
  local_c = 0;
  plVar1 = *(_locale_t *)((int)param_1 + 0x60);
  FUN_00406b26(auStack_3c,(int)param_1 + 8,*(undefined4 *)((int)param_1 + 0x28),
               *(undefined4 *)((int)param_1 + 0x2c),&local_5);
  iVar2 = FUN_00406b44(plVar1);
  uVar4 = (uint3)((uint)iVar2 >> 8);
  if ((local_5 == '\0') || (iVar2 == 1)) {
    uVar3 = (uint)uVar4 << 8;
  }
  else if (*(char *)((int)param_1 + 0x26) == '\0') {
    uStack_20 = 0x408457;
    uVar3 = FUN_00408bc8(param_1,&local_c);
  }
  else {
    uVar3 = CONCAT31(uVar4,1);
  }
  return uVar3;
}



uint __fastcall FUN_0040845f(void *param_1)

{
  _locale_t plVar1;
  int iVar2;
  uint3 uVar4;
  uint uVar3;
  undefined auStack_3c [28];
  undefined4 uStack_20;
  undefined4 local_c;
  char local_5;
  
  local_5 = '\0';
  local_c = 0;
  plVar1 = *(_locale_t *)((int)param_1 + 0x68);
  FUN_00406b26(auStack_3c,(int)param_1 + 8,*(undefined4 *)((int)param_1 + 0x30),
               *(undefined4 *)((int)param_1 + 0x34),&local_5);
  iVar2 = FUN_00406c58(plVar1);
  uVar4 = (uint3)((uint)iVar2 >> 8);
  if ((local_5 == '\0') || (iVar2 == 1)) {
    uVar3 = (uint)uVar4 << 8;
  }
  else if (*(char *)((int)param_1 + 0x2e) == '\0') {
    uStack_20 = 0x4084c0;
    uVar3 = FUN_00408bfd(param_1,&local_c);
  }
  else {
    uVar3 = CONCAT31(uVar4,1);
  }
  return uVar3;
}



uint __fastcall FUN_004084c8(void *param_1)

{
  _locale_t plVar1;
  int iVar2;
  uint3 uVar4;
  uint uVar3;
  undefined auStack_40 [28];
  undefined4 uStack_24;
  undefined8 local_14;
  char local_5;
  
  local_5 = '\0';
  local_14 = 0;
  plVar1 = *(_locale_t *)((int)param_1 + 0x60);
  FUN_00406b26(auStack_40,(int)param_1 + 8,*(undefined4 *)((int)param_1 + 0x28),
               *(undefined4 *)((int)param_1 + 0x2c),&local_5);
  iVar2 = FUN_00406bce(plVar1);
  uVar4 = (uint3)((uint)iVar2 >> 8);
  if ((local_5 == '\0') || (iVar2 == 1)) {
    uVar3 = (uint)uVar4 << 8;
  }
  else if (*(char *)((int)param_1 + 0x26) == '\0') {
    uStack_24 = 0x408529;
    uVar3 = FUN_00408c32(param_1,(undefined4 *)&local_14);
  }
  else {
    uVar3 = CONCAT31(uVar4,1);
  }
  return uVar3;
}



uint __fastcall FUN_00408531(void *param_1)

{
  _locale_t plVar1;
  int iVar2;
  uint3 uVar4;
  uint uVar3;
  undefined auStack_40 [28];
  undefined4 uStack_24;
  undefined8 local_14;
  char local_5;
  
  local_5 = '\0';
  local_14 = 0;
  plVar1 = *(_locale_t *)((int)param_1 + 0x68);
  FUN_00406b26(auStack_40,(int)param_1 + 8,*(undefined4 *)((int)param_1 + 0x30),
               *(undefined4 *)((int)param_1 + 0x34),&local_5);
  iVar2 = FUN_00406ce2(plVar1);
  uVar4 = (uint3)((uint)iVar2 >> 8);
  if ((local_5 == '\0') || (iVar2 == 1)) {
    uVar3 = (uint)uVar4 << 8;
  }
  else if (*(char *)((int)param_1 + 0x2e) == '\0') {
    uStack_24 = 0x408592;
    uVar3 = FUN_00408c6d(param_1,(undefined4 *)&local_14);
  }
  else {
    uVar3 = CONCAT31(uVar4,1);
  }
  return uVar3;
}



uint __thiscall FUN_0040859a(void *this,int param_1)

{
  undefined4 *puVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  undefined4 uVar6;
  uint uVar7;
  uint uVar8;
  undefined4 *puVar9;
  bool bVar10;
  undefined4 *local_1c;
  int local_8;
  
  puVar9 = (undefined4 *)0x0;
  if (*(char *)((int)this + 0x26) == '\0') {
    puVar1 = *(undefined4 **)((int)this + 100);
    *(undefined4 **)((int)this + 100) = puVar1 + 1;
    puVar9 = (undefined4 *)*puVar1;
    if (puVar9 == (undefined4 *)0x0) {
      puVar9 = (undefined4 *)FUN_0040e304();
      *puVar9 = 0x16;
      puVar9 = (undefined4 *)FUN_0040e223();
      goto LAB_004085cf;
    }
                    // WARNING: Load size is inaccurate
    if ((*this & 1) == 0) goto LAB_0040861a;
    *(undefined4 **)((int)this + 100) = puVar1 + 2;
    iVar4 = puVar1[1];
    if (iVar4 == 0) {
                    // WARNING: Load size is inaccurate
      if ((*this & 4) != 0) {
        iVar4 = FUN_0040cb0c(*(FILE **)((int)this + 8));
        if (iVar4 != -1) {
          *(int *)((int)this + 0xc) = *(int *)((int)this + 0xc) + 1;
        }
        *(undefined *)puVar9 = 0;
      }
LAB_0040860d:
      puVar9 = (undefined4 *)FUN_0040e304();
      *puVar9 = 0xc;
      goto LAB_004085cf;
    }
  }
  else {
LAB_0040861a:
    iVar4 = -1;
  }
  uVar2 = *(uint *)((int)this + 0x28);
  uVar3 = *(uint *)((int)this + 0x2c);
  local_8 = iVar4;
  if ((param_1 != 0) && (iVar4 != -1)) {
    local_8 = iVar4 + -1;
  }
  uVar8 = 0;
  uVar7 = 0;
  local_1c = puVar9;
  while( true ) {
    if ((((uVar2 | uVar3) != 0) && (uVar8 == uVar2)) && (uVar7 == uVar3)) goto LAB_004086cf;
    uVar5 = FUN_0040cb0c(*(FILE **)((int)this + 8));
    if (uVar5 != 0xffffffff) {
      *(int *)((int)this + 0xc) = *(int *)((int)this + 0xc) + 1;
    }
    uVar6 = FUN_0040b9a7(this,param_1,uVar5);
    if ((char)uVar6 == '\0') break;
    if (*(char *)((int)this + 0x26) == '\0') {
      if (local_8 == 0) {
        if (iVar4 != -1) {
          *(undefined *)puVar9 = 0;
        }
        goto LAB_0040860d;
      }
      *(char *)local_1c = (char)uVar5;
      local_1c = (undefined4 *)((int)local_1c + 1);
      local_8 = local_8 + -1;
    }
    bVar10 = 0xfffffffe < uVar8;
    uVar8 = uVar8 + 1;
    uVar7 = uVar7 + bVar10;
  }
  __crt_stdio_input::stream_input_adapter<char>::unget
            ((stream_input_adapter<char> *)((int)this + 8),uVar5);
LAB_004086cf:
  puVar9 = (undefined4 *)(uVar8 | uVar7);
                    // WARNING: Load size is inaccurate
  if ((puVar9 != (undefined4 *)0x0) &&
     (((param_1 != 0 || ((uVar8 == uVar2 && (uVar7 == uVar3)))) ||
      (puVar9 = (undefined4 *)(*this & 4), puVar9 != (undefined4 *)0x0)))) {
    if ((*(char *)((int)this + 0x26) == '\0') && (param_1 != 0)) {
      *(undefined *)local_1c = 0;
      puVar9 = local_1c;
    }
    return CONCAT31((int3)((uint)puVar9 >> 8),1);
  }
LAB_004085cf:
  return (uint)puVar9 & 0xffffff00;
}



uint __thiscall FUN_00408710(void *this,int param_1)

{
  undefined4 *puVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  undefined4 uVar5;
  uint uVar6;
  uint uVar7;
  undefined4 *puVar8;
  int iVar9;
  bool bVar10;
  undefined4 *local_1c;
  int local_8;
  
  puVar8 = (undefined4 *)0x0;
  if (*(char *)((int)this + 0x2e) == '\0') {
    puVar1 = *(undefined4 **)((int)this + 0x6c);
    *(undefined4 **)((int)this + 0x6c) = puVar1 + 1;
    puVar8 = (undefined4 *)*puVar1;
    if (puVar8 == (undefined4 *)0x0) {
      puVar8 = (undefined4 *)FUN_0040e304();
      *puVar8 = 0x16;
      puVar8 = (undefined4 *)FUN_0040e223();
      goto LAB_00408745;
    }
                    // WARNING: Load size is inaccurate
    if ((*this & 1) == 0) goto LAB_00408787;
    *(undefined4 **)((int)this + 0x6c) = puVar1 + 2;
    iVar9 = puVar1[1];
    if (iVar9 == 0) {
                    // WARNING: Load size is inaccurate
      if ((*this & 4) != 0) {
        __crt_stdio_input::string_input_adapter<char>::get
                  ((string_input_adapter<char> *)((int)this + 8));
        *(undefined *)puVar8 = 0;
      }
LAB_0040877a:
      puVar8 = (undefined4 *)FUN_0040e304();
      *puVar8 = 0xc;
      goto LAB_00408745;
    }
  }
  else {
LAB_00408787:
    iVar9 = -1;
  }
  uVar2 = *(uint *)((int)this + 0x30);
  uVar3 = *(uint *)((int)this + 0x34);
  local_8 = iVar9;
  if ((param_1 != 0) && (iVar9 != -1)) {
    local_8 = iVar9 + -1;
  }
  uVar7 = 0;
  uVar6 = 0;
  local_1c = puVar8;
  while( true ) {
    if ((((uVar2 | uVar3) != 0) && (uVar7 == uVar2)) && (uVar6 == uVar3)) goto LAB_00408831;
    uVar4 = __crt_stdio_input::string_input_adapter<char>::get
                      ((string_input_adapter<char> *)((int)this + 8));
    uVar5 = FUN_0040b9f7(this,param_1,uVar4);
    if ((char)uVar5 == '\0') break;
    if (*(char *)((int)this + 0x2e) == '\0') {
      if (local_8 == 0) {
        if (iVar9 != -1) {
          *(undefined *)puVar8 = 0;
        }
        goto LAB_0040877a;
      }
      *(char *)local_1c = (char)uVar4;
      local_1c = (undefined4 *)((int)local_1c + 1);
      local_8 = local_8 + -1;
    }
    bVar10 = 0xfffffffe < uVar7;
    uVar7 = uVar7 + 1;
    uVar6 = uVar6 + bVar10;
  }
  __crt_stdio_input::string_input_adapter<char>::unget
            ((string_input_adapter<char> *)((int)this + 8),uVar4);
LAB_00408831:
  puVar8 = (undefined4 *)(uVar7 | uVar6);
                    // WARNING: Load size is inaccurate
  if ((puVar8 != (undefined4 *)0x0) &&
     (((param_1 != 0 || ((uVar7 == uVar2 && (uVar6 == uVar3)))) ||
      (puVar8 = (undefined4 *)(*this & 4), puVar8 != (undefined4 *)0x0)))) {
    if ((*(char *)((int)this + 0x2e) == '\0') && (param_1 != 0)) {
      *(undefined *)local_1c = 0;
      puVar8 = local_1c;
    }
    return CONCAT31((int3)((uint)puVar8 >> 8),1);
  }
LAB_00408745:
  return (uint)puVar8 & 0xffffff00;
}



uint __thiscall FUN_00408872(void *this,int param_1)

{
  wchar_t **ppwVar1;
  bool bVar2;
  undefined4 *puVar3;
  int iVar4;
  undefined4 uVar5;
  wchar_t *pwVar6;
  wchar_t *pwVar7;
  wchar_t *local_20;
  uint local_1c;
  uint local_18;
  uint local_14;
  wchar_t *local_10;
  uint local_c;
  uint local_8;
  
  pwVar6 = (wchar_t *)0x0;
  if (*(char *)((int)this + 0x26) == '\0') {
    ppwVar1 = *(wchar_t ***)((int)this + 100);
    *(wchar_t ***)((int)this + 100) = ppwVar1 + 1;
    pwVar6 = *ppwVar1;
    if (pwVar6 == (wchar_t *)0x0) {
      puVar3 = (undefined4 *)FUN_0040e304();
      *puVar3 = 0x16;
      puVar3 = (undefined4 *)FUN_0040e223();
      goto LAB_004088a7;
    }
                    // WARNING: Load size is inaccurate
    if ((*this & 1) == 0) goto LAB_004088f4;
    *(wchar_t ***)((int)this + 100) = ppwVar1 + 2;
    pwVar7 = ppwVar1[1];
    if (pwVar7 == (wchar_t *)0x0) {
                    // WARNING: Load size is inaccurate
      if ((*this & 4) != 0) {
        iVar4 = FUN_0040cb0c(*(FILE **)((int)this + 8));
        if (iVar4 != -1) {
          *(int *)((int)this + 0xc) = *(int *)((int)this + 0xc) + 1;
        }
        *pwVar6 = L'\0';
      }
LAB_004088e7:
      puVar3 = (undefined4 *)FUN_0040e304();
      *puVar3 = 0xc;
      goto LAB_004088a7;
    }
  }
  else {
LAB_004088f4:
    pwVar7 = (wchar_t *)0xffffffff;
  }
  local_14 = *(uint *)((int)this + 0x28);
  local_18 = *(uint *)((int)this + 0x2c);
  local_10 = pwVar7;
  if ((param_1 != 0) && (pwVar7 != (wchar_t *)0xffffffff)) {
    local_10 = (wchar_t *)((int)pwVar7 + -1);
  }
  local_c = 0;
  local_8 = 0;
  local_20 = pwVar6;
  while( true ) {
    if ((((local_14 | local_18) != 0) && (local_c == local_14)) && (local_8 == local_18))
    goto LAB_004089b1;
    local_1c = FUN_0040cb0c(*(FILE **)((int)this + 8));
    if (local_1c != 0xffffffff) {
      *(int *)((int)this + 0xc) = *(int *)((int)this + 0xc) + 1;
    }
    uVar5 = FUN_0040b9a7(this,param_1,local_1c);
    if ((char)uVar5 == '\0') break;
    if (*(char *)((int)this + 0x26) == '\0') {
      if (local_10 == (wchar_t *)0x0) {
        if (pwVar7 != (wchar_t *)0xffffffff) {
          *pwVar6 = L'\0';
        }
        goto LAB_004088e7;
      }
      bVar2 = __crt_stdio_input::input_processor<>::write_character
                        ((input_processor<> *)this,pwVar6,(uint)pwVar7,&local_20,(uint *)&local_10,
                         (char)local_1c);
      if (!bVar2) goto LAB_004089b1;
    }
    bVar2 = 0xfffffffe < local_c;
    local_c = local_c + 1;
    local_8 = local_8 + bVar2;
  }
  __crt_stdio_input::stream_input_adapter<char>::unget
            ((stream_input_adapter<char> *)((int)this + 8),local_1c);
LAB_004089b1:
  puVar3 = (undefined4 *)(local_c | local_8);
                    // WARNING: Load size is inaccurate
  if ((puVar3 != (undefined4 *)0x0) &&
     (((param_1 != 0 || ((local_c == local_14 && (local_8 == local_18)))) ||
      (puVar3 = (undefined4 *)(*this & 4), puVar3 != (undefined4 *)0x0)))) {
    if ((*(char *)((int)this + 0x26) == '\0') && (param_1 != 0)) {
      *local_20 = L'\0';
    }
    return CONCAT31((int3)((uint)puVar3 >> 8),1);
  }
LAB_004088a7:
  return (uint)puVar3 & 0xffffff00;
}



uint __thiscall FUN_004089f4(void *this,int param_1)

{
  wchar_t **ppwVar1;
  bool bVar2;
  undefined4 *puVar3;
  undefined4 uVar4;
  wchar_t *pwVar5;
  wchar_t *pwVar6;
  wchar_t *local_20;
  uint local_1c;
  uint local_18;
  uint local_14;
  wchar_t *local_10;
  uint local_c;
  uint local_8;
  
  pwVar5 = (wchar_t *)0x0;
  if (*(char *)((int)this + 0x2e) == '\0') {
    ppwVar1 = *(wchar_t ***)((int)this + 0x6c);
    *(wchar_t ***)((int)this + 0x6c) = ppwVar1 + 1;
    pwVar5 = *ppwVar1;
    if (pwVar5 == (wchar_t *)0x0) {
      puVar3 = (undefined4 *)FUN_0040e304();
      *puVar3 = 0x16;
      puVar3 = (undefined4 *)FUN_0040e223();
      goto LAB_00408a29;
    }
                    // WARNING: Load size is inaccurate
    if ((*this & 1) == 0) goto LAB_00408a6d;
    *(wchar_t ***)((int)this + 0x6c) = ppwVar1 + 2;
    pwVar6 = ppwVar1[1];
    if (pwVar6 == (wchar_t *)0x0) {
                    // WARNING: Load size is inaccurate
      if ((*this & 4) != 0) {
        __crt_stdio_input::string_input_adapter<char>::get
                  ((string_input_adapter<char> *)((int)this + 8));
        *pwVar5 = L'\0';
      }
LAB_00408a60:
      puVar3 = (undefined4 *)FUN_0040e304();
      *puVar3 = 0xc;
      goto LAB_00408a29;
    }
  }
  else {
LAB_00408a6d:
    pwVar6 = (wchar_t *)0xffffffff;
  }
  local_14 = *(uint *)((int)this + 0x30);
  local_18 = *(uint *)((int)this + 0x34);
  local_10 = pwVar6;
  if ((param_1 != 0) && (pwVar6 != (wchar_t *)0xffffffff)) {
    local_10 = (wchar_t *)((int)pwVar6 + -1);
  }
  local_c = 0;
  local_8 = 0;
  local_20 = pwVar5;
  while( true ) {
    if ((((local_14 | local_18) != 0) && (local_c == local_14)) && (local_8 == local_18))
    goto LAB_00408b1f;
    local_1c = __crt_stdio_input::string_input_adapter<char>::get
                         ((string_input_adapter<char> *)((int)this + 8));
    uVar4 = FUN_0040b9f7(this,param_1,local_1c);
    if ((char)uVar4 == '\0') break;
    if (*(char *)((int)this + 0x2e) == '\0') {
      if (local_10 == (wchar_t *)0x0) {
        if (pwVar6 != (wchar_t *)0xffffffff) {
          *pwVar5 = L'\0';
        }
        goto LAB_00408a60;
      }
      bVar2 = __crt_stdio_input::input_processor<>::write_character
                        ((input_processor<> *)this,pwVar5,(uint)pwVar6,&local_20,(uint *)&local_10,
                         (char)local_1c);
      if (!bVar2) goto LAB_00408b1f;
    }
    bVar2 = 0xfffffffe < local_c;
    local_c = local_c + 1;
    local_8 = local_8 + bVar2;
  }
  __crt_stdio_input::string_input_adapter<char>::unget
            ((string_input_adapter<char> *)((int)this + 8),local_1c);
LAB_00408b1f:
  puVar3 = (undefined4 *)(local_c | local_8);
                    // WARNING: Load size is inaccurate
  if ((puVar3 != (undefined4 *)0x0) &&
     (((param_1 != 0 || ((local_c == local_14 && (local_8 == local_18)))) ||
      (puVar3 = (undefined4 *)(*this & 4), puVar3 != (undefined4 *)0x0)))) {
    if ((*(char *)((int)this + 0x2e) == '\0') && (param_1 != 0)) {
      *local_20 = L'\0';
    }
    return CONCAT31((int3)((uint)puVar3 >> 8),1);
  }
LAB_00408a29:
  return (uint)puVar3 & 0xffffff00;
}



// Library Function - Single Match
//  int __cdecl __crt_stdio_input::skip_whitespace<class
// __crt_stdio_input::stream_input_adapter,char>(class __crt_stdio_input::stream_input_adapter<char>
// &,struct __crt_locale_pointers * const)
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

int __cdecl
__crt_stdio_input::skip_whitespace<>
          (stream_input_adapter<char> *param_1,__crt_locale_pointers *param_2)

{
  uint uVar1;
  uint uVar2;
  
  do {
    uVar1 = FUN_0040cb0c(*(FILE **)param_1);
    if (uVar1 == 0xffffffff) {
      return -1;
    }
    *(int *)(param_1 + 4) = *(int *)(param_1 + 4) + 1;
    uVar2 = FUN_0040c9cd(uVar1 & 0xff,8,(_locale_t)param_2);
  } while (uVar2 != 0);
  return uVar1;
}



// Library Function - Single Match
//  int __cdecl __crt_stdio_input::skip_whitespace<class
// __crt_stdio_input::string_input_adapter,char>(class __crt_stdio_input::string_input_adapter<char>
// &,struct __crt_locale_pointers * const)
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

int __cdecl
__crt_stdio_input::skip_whitespace<>
          (string_input_adapter<char> *param_1,__crt_locale_pointers *param_2)

{
  uint uVar1;
  uint uVar2;
  
  do {
    uVar1 = string_input_adapter<char>::get(param_1);
    if (uVar1 == 0xffffffff) {
      return -1;
    }
    uVar2 = FUN_0040c9cd(uVar1 & 0xff,8,(_locale_t)param_2);
  } while (uVar2 != 0);
  return uVar1;
}



uint __thiscall FUN_00408bc8(void *this,undefined4 *param_1)

{
  int *piVar1;
  undefined4 uVar2;
  undefined4 *puVar3;
  uint uVar4;
  
  piVar1 = *(int **)((int)this + 100);
  *(int **)((int)this + 100) = piVar1 + 1;
  puVar3 = (undefined4 *)*piVar1;
  if (puVar3 == (undefined4 *)0x0) {
    puVar3 = (undefined4 *)FUN_0040e304();
    *puVar3 = 0x16;
    uVar4 = FUN_0040e223();
    uVar4 = uVar4 & 0xffffff00;
  }
  else {
    uVar2 = *param_1;
    *puVar3 = uVar2;
    uVar4 = CONCAT31((int3)((uint)uVar2 >> 8),1);
  }
  return uVar4;
}



uint __thiscall FUN_00408bfd(void *this,undefined4 *param_1)

{
  int *piVar1;
  undefined4 uVar2;
  undefined4 *puVar3;
  uint uVar4;
  
  piVar1 = *(int **)((int)this + 0x6c);
  *(int **)((int)this + 0x6c) = piVar1 + 1;
  puVar3 = (undefined4 *)*piVar1;
  if (puVar3 == (undefined4 *)0x0) {
    puVar3 = (undefined4 *)FUN_0040e304();
    *puVar3 = 0x16;
    uVar4 = FUN_0040e223();
    uVar4 = uVar4 & 0xffffff00;
  }
  else {
    uVar2 = *param_1;
    *puVar3 = uVar2;
    uVar4 = CONCAT31((int3)((uint)uVar2 >> 8),1);
  }
  return uVar4;
}



uint __thiscall FUN_00408c32(void *this,undefined4 *param_1)

{
  int *piVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 *puVar4;
  uint uVar5;
  
  piVar1 = *(int **)((int)this + 100);
  *(int **)((int)this + 100) = piVar1 + 1;
  puVar4 = (undefined4 *)*piVar1;
  if (puVar4 == (undefined4 *)0x0) {
    puVar4 = (undefined4 *)FUN_0040e304();
    *puVar4 = 0x16;
    uVar5 = FUN_0040e223();
    uVar5 = uVar5 & 0xffffff00;
  }
  else {
    uVar2 = *param_1;
    uVar3 = param_1[1];
    puVar4[1] = uVar3;
    uVar5 = CONCAT31((int3)((uint)uVar3 >> 8),1);
    *puVar4 = uVar2;
  }
  return uVar5;
}



uint __thiscall FUN_00408c6d(void *this,undefined4 *param_1)

{
  int *piVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 *puVar4;
  uint uVar5;
  
  piVar1 = *(int **)((int)this + 0x6c);
  *(int **)((int)this + 0x6c) = piVar1 + 1;
  puVar4 = (undefined4 *)*piVar1;
  if (puVar4 == (undefined4 *)0x0) {
    puVar4 = (undefined4 *)FUN_0040e304();
    *puVar4 = 0x16;
    uVar5 = FUN_0040e223();
    uVar5 = uVar5 & 0xffffff00;
  }
  else {
    uVar2 = *param_1;
    uVar3 = param_1[1];
    puVar4[1] = uVar3;
    uVar5 = CONCAT31((int3)((uint)uVar3 >> 8),1);
    *puVar4 = uVar2;
  }
  return uVar5;
}



undefined4 * __thiscall
FUN_00408ca8(void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  int iVar1;
  undefined4 *puVar2;
  
  *(undefined4 *)this = param_1;
  *(undefined4 *)((int)this + 4) = param_2;
  *(undefined4 *)((int)this + 8) = param_3;
  *(undefined4 *)((int)this + 0xc) = 0;
  puVar2 = (undefined4 *)((int)this + 0x2c);
  for (iVar1 = 8; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  *(undefined4 *)((int)this + 0x10) = 0;
  *(undefined2 *)((int)this + 0x14) = 0;
  *(undefined *)((int)this + 0x16) = 0;
  *(undefined4 *)((int)this + 0x18) = 0;
  *(undefined4 *)((int)this + 0x1c) = 0;
  *(undefined4 *)((int)this + 0x20) = 0;
  *(undefined *)((int)this + 0x24) = 0;
  *(undefined4 *)((int)this + 0x28) = 0;
  return (undefined4 *)this;
}



undefined4 * __thiscall FUN_00408cf2(void *this,undefined4 *param_1)

{
  undefined4 uVar1;
  
  *(undefined4 *)this = *param_1;
  uVar1 = param_1[3];
  *(undefined4 *)((int)this + 8) = param_1[2];
  *(undefined4 *)((int)this + 0xc) = uVar1;
  uVar1 = param_1[5];
  *(undefined4 *)((int)this + 0x10) = param_1[4];
  *(undefined4 *)((int)this + 0x14) = uVar1;
  *(undefined4 *)((int)this + 0x18) = param_1[6];
  *param_1 = 0;
  param_1[6] = 0;
  return (undefined4 *)this;
}



undefined4 * __thiscall
FUN_00408d2f(void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined *param_4)

{
  *(undefined4 *)((int)this + 0x10) = 0;
  *(undefined4 *)((int)this + 0x14) = 0;
  *(undefined4 *)this = param_1;
  *(undefined4 *)((int)this + 8) = param_2;
  *(undefined4 *)((int)this + 0xc) = param_3;
  *(undefined **)((int)this + 0x18) = param_4;
  if (param_4 != (undefined *)0x0) {
    *param_4 = 1;
  }
  return (undefined4 *)this;
}



undefined4 * __thiscall
FUN_00408d60(void *this,undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4
            ,undefined4 param_5,undefined4 param_6)

{
  undefined4 uVar1;
  
  *(undefined4 *)this = param_2;
  *(undefined4 *)((int)this + 4) = param_3;
  uVar1 = param_1[1];
  *(undefined4 *)((int)this + 8) = *param_1;
  *(undefined4 *)((int)this + 0xc) = uVar1;
  FUN_00408ca8((void *)((int)this + 0x10),param_2,param_3,param_4);
  *(undefined4 *)((int)this + 0x68) = 0;
  *(undefined4 *)((int)this + 0x60) = param_5;
  *(undefined4 *)((int)this + 100) = param_6;
  return (undefined4 *)this;
}



// Library Function - Single Match
//  public: __thiscall __crt_stdio_input::input_processor<char,class
// __crt_stdio_input::string_input_adapter<char> >::input_processor<char,class
// __crt_stdio_input::string_input_adapter<char> >(class
// __crt_stdio_input::string_input_adapter<char> const &,unsigned __int64,char const * const,struct
// __crt_locale_pointers * const,char * const)
// 
// Library: Visual Studio 2019 Release

input_processor<> * __thiscall
__crt_stdio_input::input_processor<>::input_processor<>
          (input_processor<> *this,string_input_adapter<char> *param_1,__uint64 param_2,
          char *param_3,__crt_locale_pointers *param_4,char *param_5)

{
  undefined4 in_stack_00000008;
  
  *(undefined4 *)this = in_stack_00000008;
  *(undefined4 *)(this + 4) = (undefined4)param_2;
  *(undefined4 *)(this + 8) = *(undefined4 *)param_1;
  *(undefined4 *)(this + 0xc) = *(undefined4 *)(param_1 + 4);
  *(undefined4 *)(this + 0x10) = *(undefined4 *)(param_1 + 8);
  FUN_00408ca8(this + 0x18,in_stack_00000008,(undefined4)param_2,param_2._4_4_);
  *(undefined4 *)(this + 0x70) = 0;
  *(char **)(this + 0x68) = param_3;
  *(__crt_locale_pointers **)(this + 0x6c) = param_4;
  return this;
}



__acrt_ptd ** __thiscall FUN_00408ded(void *this,__acrt_ptd **param_1)

{
  __acrt_ptd **pp_Var1;
  uint uVar2;
  __acrt_ptd *p_Var3;
  __acrt_ptd *p_Var4;
  
  *(undefined *)((int)this + 0xc) = 0;
  pp_Var1 = (__acrt_ptd **)((int)this + 4);
  if (param_1 == (__acrt_ptd **)0x0) {
    p_Var3 = (__acrt_ptd *)PTR_PTR_DAT_004231f0;
    p_Var4 = (__acrt_ptd *)PTR_DAT_004231f4;
    if (DAT_00423e60 != 0) {
      p_Var3 = FUN_004104a9();
      *(__acrt_ptd **)this = p_Var3;
      *pp_Var1 = *(__acrt_ptd **)(p_Var3 + 0x4c);
      *(int *)((int)this + 8) = *(int *)(p_Var3 + 0x48);
      ___acrt_update_locale_info((int)p_Var3,pp_Var1);
                    // WARNING: Load size is inaccurate
      FUN_0040f14f(*this,(int *)((int)this + 8));
                    // WARNING: Load size is inaccurate
      uVar2 = *(uint *)(*this + 0x350);
      if ((uVar2 & 2) != 0) {
        return (__acrt_ptd **)this;
      }
      *(uint *)(*this + 0x350) = uVar2 | 2;
      *(undefined *)((int)this + 0xc) = 1;
      return (__acrt_ptd **)this;
    }
  }
  else {
    p_Var3 = *param_1;
    p_Var4 = param_1[1];
  }
  *pp_Var1 = p_Var3;
  *(__acrt_ptd **)((int)this + 8) = p_Var4;
  return (__acrt_ptd **)this;
}



// Library Function - Multiple Matches With Different Base Names
//  public: bool __thiscall <lambda_0b87716a0b73cdfba1cd37fcaaa20711>::operator()(void)const 
//  public: bool __thiscall <lambda_644f8ab42ed3fd1d660977a2364b3a7d>::operator()(void)const 
//  public: bool __thiscall <lambda_c7c3f778895f47e7f4eff38a8fef279a>::operator()(void)const 
//  public: bool __thiscall <lambda_e41f1170c8800e4a6fed1afad60fab6f>::operator()(void)const 
//   6 names - too many to list
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __fastcall FID_conflict_operator__(input_adapter_character_source<> **param_1)

{
  __crt_strtox::input_adapter_character_source<>::unget(*param_1,(char)*param_1[1]);
  *param_1[1] = (input_adapter_character_source<>)0x0;
  restore_state(*param_1,*(int *)param_1[2],*(int *)((int)param_1[2] + 4));
  return;
}



// Library Function - Single Match
//  public: int __thiscall <lambda_21448eb78dd3c4a522ed7c65a98d88e6>::operator()(void)const 
// 
// Library: Visual Studio 2019 Release

int __thiscall <>::operator()(<> *this)

{
  int iVar1;
  int local_90;
  undefined local_8c [8];
  char local_84;
  undefined4 local_80;
  undefined4 local_7c;
  input_processor<> local_78 [112];
  uint local_8;
  
  local_8 = DAT_00423014 ^ (uint)&stack0xfffffffc;
  FUN_00408ded(&local_90,(__acrt_ptd **)**(undefined4 **)this);
  local_7c = 0;
  local_80 = **(undefined4 **)(this + 4);
  FUN_00408d60(local_78,&local_80,**(undefined4 **)(this + 8),(*(undefined4 **)(this + 8))[1],
               **(undefined4 **)(this + 0xc),local_8c,**(undefined4 **)(this + 0x10));
  __crt_stdio_input::input_processor<>::process(local_78);
  if (local_84 != '\0') {
    *(uint *)(local_90 + 0x350) = *(uint *)(local_90 + 0x350) & 0xfffffffd;
  }
  iVar1 = FUN_00402125(local_8 ^ (uint)&stack0xfffffffc);
  return iVar1;
}



// Library Function - Multiple Matches With Different Base Names
//  public: bool __thiscall <lambda_0b87716a0b73cdfba1cd37fcaaa20711>::operator()(void)const 
//  public: bool __thiscall <lambda_644f8ab42ed3fd1d660977a2364b3a7d>::operator()(void)const 
//  public: bool __thiscall <lambda_c7c3f778895f47e7f4eff38a8fef279a>::operator()(void)const 
//  public: bool __thiscall <lambda_e41f1170c8800e4a6fed1afad60fab6f>::operator()(void)const 
//   6 names - too many to list
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __fastcall FID_conflict_operator__(input_adapter_character_source<> **param_1)

{
  __crt_strtox::input_adapter_character_source<>::unget(*param_1,(char)*param_1[1]);
  *param_1[1] = (input_adapter_character_source<>)0x0;
  restore_state(*param_1,*(int *)param_1[2],*(int *)((int)param_1[2] + 4));
  return;
}



// Library Function - Single Match
//  public: bool __thiscall __crt_stdio_input::format_string_parser<char>::advance(void)
// 
// Library: Visual Studio 2019 Release

bool __thiscall
__crt_stdio_input::format_string_parser<char>::advance(format_string_parser<char> *this)

{
  format_string_parser<char> *pfVar1;
  format_string_parser<char> fVar2;
  format_string_parser<char> *pfVar3;
  bool bVar4;
  int iVar5;
  uint uVar6;
  
  if (*(int *)(this + 0xc) == 0) {
    *(undefined4 *)(this + 0x10) = 0;
    *(undefined2 *)(this + 0x14) = 0;
    this[0x16] = (format_string_parser<char>)0x0;
    *(undefined4 *)(this + 0x18) = 0;
    *(undefined4 *)(this + 0x1c) = 0;
    *(undefined4 *)(this + 0x20) = 0;
    this[0x24] = (format_string_parser<char>)0x0;
    *(undefined4 *)(this + 0x28) = 0;
    if (**(byte **)(this + 8) == 0) {
      *(undefined4 *)(this + 0x10) = 1;
    }
    else {
      iVar5 = _isspace((uint)**(byte **)(this + 8));
      pfVar3 = *(format_string_parser<char> **)(this + 8);
      if (iVar5 != 0) {
        *(undefined4 *)(this + 0x10) = 2;
        fVar2 = *pfVar3;
        while (iVar5 = _isspace((uint)(byte)fVar2), iVar5 != 0) {
          *(int *)(this + 8) = *(int *)(this + 8) + 1;
          fVar2 = **(format_string_parser<char> **)(this + 8);
        }
        return true;
      }
      if ((*pfVar3 != (format_string_parser<char>)0x25) ||
         (pfVar1 = pfVar3 + 1, *pfVar1 == (format_string_parser<char>)0x25)) {
        *(undefined4 *)(this + 0x10) = 3;
        this[0x14] = *pfVar3;
        *(format_string_parser<char> **)(this + 8) =
             pfVar3 + (*pfVar3 == (format_string_parser<char>)0x25) + 1;
        bVar4 = scan_optional_literal_character_trail_bytes_tchar(this,'\0');
        return bVar4;
      }
      *(undefined4 *)(this + 0x10) = 4;
      *(format_string_parser<char> **)(this + 8) = pfVar1;
      if (*pfVar1 == (format_string_parser<char>)0x2a) {
        this[0x16] = (format_string_parser<char>)0x1;
        *(format_string_parser<char> **)(this + 8) = pfVar3 + 2;
      }
      iVar5 = FUN_0040c1f9((int)this);
      if ((char)iVar5 != '\0') {
        FUN_0040c28d((int)this);
        scan_optional_wide_modifier(this);
        uVar6 = FUN_0040c07d((int)this);
        if ((char)uVar6 != '\0') {
          if ((&DAT_0041c8e8)[*(int *)(this + 0x20) + *(int *)(this + 0x28) * 0xc] != '\0') {
            return true;
          }
          *(undefined4 *)(this + 0x10) = 0;
          *(undefined2 *)(this + 0x14) = 0;
          this[0x16] = (format_string_parser<char>)0x0;
          *(undefined4 *)(this + 0x18) = 0;
          *(undefined4 *)(this + 0x1c) = 0;
          *(undefined4 *)(this + 0x20) = 0;
          this[0x24] = (format_string_parser<char>)0x0;
          *(undefined4 *)(this + 0x28) = 0;
          *(undefined4 *)(this + 0xc) = 0x16;
        }
      }
    }
  }
  return false;
}



// Library Function - Single Match
//  public: double & __thiscall __crt_strtox::floating_point_value::as_double(void)const 
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

double * __thiscall __crt_strtox::floating_point_value::as_double(floating_point_value *this)

{
  if (this[4] != (floating_point_value)0x0) {
    return *(double **)this;
  }
                    // WARNING: Subroutine does not return
  __invoke_watson(L"_is_double",L"__crt_strtox::floating_point_value::as_double",
                  L"minkernel\\crts\\ucrt\\inc\\corecrt_internal_strtox.h",0x1db,0);
}



// Library Function - Single Match
//  public: float & __thiscall __crt_strtox::floating_point_value::as_float(void)const 
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

float * __thiscall __crt_strtox::floating_point_value::as_float(floating_point_value *this)

{
  if (this[4] == (floating_point_value)0x0) {
    return *(float **)this;
  }
                    // WARNING: Subroutine does not return
  __invoke_watson(L"!_is_double",L"__crt_strtox::floating_point_value::as_float",
                  L"minkernel\\crts\\ucrt\\inc\\corecrt_internal_strtox.h",0x1e1,0);
}



// Library Function - Single Match
//  void __cdecl __crt_strtox::assemble_floating_point_infinity(bool,class
// __crt_strtox::floating_point_value const &)
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __cdecl
__crt_strtox::assemble_floating_point_infinity(bool param_1,floating_point_value *param_2)

{
  double *pdVar1;
  float *pfVar2;
  
  if (param_2[4] != (floating_point_value)0x0) {
    pdVar1 = floating_point_value::as_double(param_2);
    *(undefined4 *)pdVar1 = 0;
    *(uint *)((int)pdVar1 + 4) = (uint)param_1 << 0x1f | 0x7ff00000;
    return;
  }
  pfVar2 = floating_point_value::as_float(param_2);
  *pfVar2 = (float)((uint)param_1 << 0x1f | 0x7f800000);
  return;
}



// WARNING: Removing unreachable block (ram,0x00409289)
// WARNING: Removing unreachable block (ram,0x004093ae)

SLD_STATUS __cdecl
FUN_004090e5(uint param_1,uint param_2,int param_3,bool param_4,char param_5,
            floating_point_value *param_6)

{
  floating_point_value fVar1;
  bool bVar2;
  bool bVar3;
  int iVar4;
  int iVar5;
  double *pdVar6;
  SLD_STATUS SVar7;
  float *pfVar8;
  byte bVar9;
  int iVar10;
  uint uVar11;
  bool bVar12;
  longlong lVar13;
  longlong lVar14;
  ulonglong uVar15;
  ulonglong uVar16;
  uint uStack_28;
  uint uStack_24;
  uint uStack_20;
  uint uStack_1c;
  int iStack_c;
  
  uVar11 = 0;
  uVar15 = CONCAT44(param_2,param_1);
  if (param_2 == 0) {
    iVar10 = 0x1f;
    if (param_1 != 0) {
      for (; param_1 >> iVar10 == 0; iVar10 = iVar10 + -1) {
      }
    }
    if (param_1 == 0) {
      iVar10 = 0;
    }
    else {
      iVar10 = iVar10 + 1;
    }
  }
  else {
    iVar10 = 0x1f;
    if (param_2 != 0) {
      for (; param_2 >> iVar10 == 0; iVar10 = iVar10 + -1) {
      }
    }
    if (param_2 == 0) {
      iVar10 = 0;
    }
    else {
      iVar10 = iVar10 + 1;
    }
    iVar10 = iVar10 + 0x20;
  }
  fVar1 = param_6[4];
  iVar10 = (((fVar1 == (floating_point_value)0x0) - 1 & 0x1d) + 0x18) - iVar10;
  iStack_c = param_3 - iVar10;
  iVar4 = ((fVar1 == (floating_point_value)0x0) - 1 & 0x380) + 0x7f;
  if (iVar4 < iStack_c) {
LAB_004093d6:
    __crt_strtox::assemble_floating_point_infinity(param_4,param_6);
    SVar7 = 3;
  }
  else {
    if (iStack_c < (int)(((fVar1 == (floating_point_value)0x0) - 1 & 0xfffffc80) - 0x7e)) {
      iStack_c = -iVar4;
      iVar4 = param_3 + -1 + iVar4;
      if (iVar4 < 0) {
        if (0x3f < (uint)-iVar4) {
LAB_004092a0:
          __crt_strtox::assemble_floating_point_zero(param_4,param_6);
          return 2;
        }
        bVar9 = (byte)-iVar4;
        lVar13 = __allshl(bVar9 - 1,0);
        lVar14 = __allshl(bVar9,0);
        bVar12 = ((uint)lVar13 & param_1 | (uint)((ulonglong)lVar13 >> 0x20) & param_2) != 0;
        if ((param_5 == '\0') ||
           (((uint)(lVar13 + -1) & param_1 | (uint)((ulonglong)(lVar13 + -1) >> 0x20) & param_2) !=
            0)) {
          bVar2 = true;
          bVar3 = true;
        }
        else {
          bVar2 = false;
          bVar3 = false;
        }
        if ((bVar12) || (bVar2)) {
          iVar5 = _fegetround();
          if (iVar5 == 0) {
            if ((bVar12) &&
               ((bVar3 || (((uint)lVar14 & param_1 | (uint)((ulonglong)lVar14 >> 0x20) & param_2) !=
                           0)))) {
              uVar11 = 1;
            }
          }
          else if (iVar5 == 0x100) {
            uVar11 = (uint)param_4;
          }
          else if (iVar5 == 0x200) {
            uVar11 = (uint)!param_4;
          }
        }
        uVar15 = __aullshr(bVar9,param_2);
        uVar15 = uVar15 + uVar11;
        if (uVar15 == 0) goto LAB_004092a0;
        uVar16 = FUN_0040b451((int)param_6);
        if (uVar16 < uVar15) {
          iStack_c = ((param_3 - iVar4) - iVar10) + -1;
        }
      }
      else {
        bVar9 = (byte)iVar4;
LAB_004093ee:
        uVar15 = __allshl(bVar9,param_2);
      }
    }
    else if (iVar10 < 0) {
      if ((uint)-iVar10 < 0x40) {
        bVar9 = (byte)-iVar10;
        lVar13 = __allshl(bVar9 - 1,0);
        lVar14 = __allshl(bVar9,0);
        uStack_28 = (uint)lVar13;
        uStack_24 = (uint)((ulonglong)lVar13 >> 0x20);
        bVar12 = (uStack_28 & param_1 | uStack_24 & param_2) != 0;
        if (param_5 == '\0') {
LAB_00409346:
          bVar2 = true;
          bVar3 = true;
        }
        else {
          uStack_20 = (uint)(lVar13 + -1);
          uStack_1c = (uint)((ulonglong)(lVar13 + -1) >> 0x20);
          if ((uStack_20 & param_1 | uStack_1c & param_2) != 0) goto LAB_00409346;
          bVar2 = false;
          bVar3 = false;
        }
        if ((bVar12) || (bVar2)) {
          iVar10 = _fegetround();
          if (iVar10 == 0) {
            if ((bVar12) &&
               ((bVar3 || (((uint)lVar14 & param_1 | (uint)((ulonglong)lVar14 >> 0x20) & param_2) !=
                           0)))) {
              uVar11 = 1;
            }
          }
          else if (iVar10 == 0x100) {
            uVar11 = (uint)param_4;
          }
          else if (iVar10 == 0x200) {
            uVar11 = (uint)!param_4;
          }
        }
        uVar15 = __aullshr(bVar9,param_2);
        uVar15 = uVar15 + uVar11;
      }
      else {
        uVar15 = 0;
      }
      uVar16 = FUN_0040ba95((int)param_6);
      if (uVar16 < uVar15) {
        uVar15 = uVar15 >> 1;
        iStack_c = iStack_c + 1;
        if ((int)(((param_6[4] == (floating_point_value)0x0) - 1 & 0x380) + 0x7f) < iStack_c)
        goto LAB_004093d6;
      }
    }
    else if (0 < iVar10) {
      bVar9 = (byte)iVar10;
      goto LAB_004093ee;
    }
    uVar16 = FUN_0040b451((int)param_6);
    if (param_6[4] == (floating_point_value)0x0) {
      pfVar8 = __crt_strtox::floating_point_value::as_float(param_6);
      SVar7 = __crt_strtox::assemble_floating_point_value_t<float>
                        (param_4,iStack_c,uVar15 & uVar16,pfVar8);
    }
    else {
      pdVar6 = __crt_strtox::floating_point_value::as_double(param_6);
      SVar7 = __crt_strtox::assemble_floating_point_value_t<double>
                        (param_4,iStack_c,uVar15 & uVar16,pdVar6);
    }
  }
  return SVar7;
}



void __cdecl
FUN_0040943e(uint *param_1,uint param_2,bool param_3,byte param_4,floating_point_value *param_5)

{
  uint *puVar1;
  uint *puVar2;
  byte bVar3;
  byte bVar4;
  uint uVar5;
  int iVar6;
  uint uVar7;
  int iVar8;
  uint uVar9;
  longlong lVar10;
  ulonglong uVar11;
  longlong lVar12;
  
  iVar6 = ((param_5[4] == (floating_point_value)0x0) - 1 & 0x1d) + 0x17;
  if (0x40 < param_2) {
    uVar9 = param_2 >> 5;
    uVar7 = param_2 & 0x1f;
    iVar8 = uVar9 - 2;
    uVar5 = param_1[uVar9 - 1];
    puVar1 = param_1 + uVar9;
    if (uVar7 == 0) {
      iVar6 = iVar6 + iVar8 * 0x20;
      puVar2 = param_1 + (uVar9 - 1);
      bVar3 = param_4 ^ 1;
      for (; iVar8 != 0; iVar8 = iVar8 + -1) {
        param_1 = param_1 + 1;
        bVar3 = bVar3 & (*param_1 != 0) - 1U;
      }
      lVar12 = CONCAT44(*puVar1,*puVar2);
    }
    else {
      bVar3 = 1;
      bVar4 = (byte)uVar7;
      iVar6 = uVar7 + iVar8 * 0x20 + iVar6;
      lVar10 = __allshl(-bVar4 + 0x20,0);
      uVar11 = __aullshr(bVar4,0);
      lVar12 = __allshl(-bVar4 + 0x40,0);
      lVar12 = lVar10 + uVar11 + lVar12;
      if ((param_4 != 0) || ((uVar5 & (1 << bVar4) - 1U) != 0)) {
        bVar3 = 0;
      }
      for (; iVar8 != 0; iVar8 = iVar8 + -1) {
        param_1 = param_1 + 1;
        bVar3 = bVar3 & (*param_1 != 0) - 1U;
      }
    }
    goto LAB_004095c3;
  }
  if (*param_1 == 0) {
    uVar5 = 0;
LAB_0040947a:
    uVar7 = 0;
  }
  else {
    uVar5 = param_1[1];
    if (*param_1 < 2) goto LAB_0040947a;
    uVar7 = param_1[2];
  }
  lVar12 = CONCAT44(uVar7,uVar5);
  bVar3 = param_4 ^ 1;
LAB_004095c3:
  FUN_004090e5((uint)lVar12,(uint)((ulonglong)lVar12 >> 0x20),iVar6,param_3,bVar3,param_5);
  return;
}



// Library Function - Single Match
//  void __cdecl __crt_strtox::assemble_floating_point_zero(bool,class
// __crt_strtox::floating_point_value const &)
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __cdecl __crt_strtox::assemble_floating_point_zero(bool param_1,floating_point_value *param_2)

{
  double *pdVar1;
  float *pfVar2;
  
  if (param_2[4] != (floating_point_value)0x0) {
    pdVar1 = floating_point_value::as_double(param_2);
    *(undefined4 *)pdVar1 = 0;
    *(uint *)((int)pdVar1 + 4) = (uint)param_1 << 0x1f;
    return;
  }
  pfVar2 = floating_point_value::as_float(param_2);
  *pfVar2 = (float)((uint)param_1 << 0x1f);
  return;
}



void FUN_00409605(uint *param_1,floating_point_value *param_2)

{
  uint ******ppppppuVar1;
  undefined uVar2;
  uint *****pppppuVar3;
  uint *****pppppuVar4;
  bool bVar5;
  int iVar6;
  byte bVar7;
  uint uVar8;
  uint ******ppppppuVar9;
  uint *****pppppuVar10;
  uint ******ppppppuVar11;
  uint uVar12;
  uint uVar13;
  uint ******ppppppuVar14;
  uint ******ppppppuVar15;
  uint ****ppppuVar16;
  bool bVar17;
  longlong lVar18;
  ulonglong uVar19;
  rsize_t _MaxCount;
  uint ****local_b2c [115];
  uint ******local_960;
  uint ******local_95c;
  floating_point_value *local_958;
  uint ******local_954;
  uint *local_950;
  uint local_94c;
  uint ******local_948;
  uint ******local_944;
  uint ******local_940;
  uint ******local_93c;
  uint ******local_938;
  uint ******local_934;
  uint ******local_930;
  undefined4 local_92c;
  uint ******local_928;
  uint ******local_924;
  uint ******local_920;
  uint ******local_91c;
  uint ******local_918;
  uint *****local_914 [115];
  uint ******local_748;
  uint *****local_744 [115];
  uint ******ppppppuStack_578;
  uint *****apppppuStack_574 [115];
  uint ******ppppppuStack_3a8;
  uint *****apppppuStack_3a4 [115];
  uint ******local_1d8;
  uint *****local_1d4 [115];
  uint local_8;
  
  local_8 = DAT_00423014 ^ (uint)&stack0xfffffffc;
  uVar13 = *param_1;
  local_950 = param_1;
  local_958 = param_2;
  local_954 = (uint ******)(((param_2[4] == (floating_point_value)0x0) - 1 & 0x1d) + 0x19);
  if ((int)uVar13 < 0) {
    uVar13 = 0;
  }
  uVar12 = param_1[1];
  uVar8 = uVar13;
  if (uVar12 <= uVar13) {
    uVar8 = uVar12;
  }
  local_934 = (uint ******)(uVar13 - uVar8);
  ppppppuVar15 = (uint ******)(param_1 + 2);
  local_95c = (uint ******)(uVar8 + 8 + (int)param_1);
  local_960 = (uint ******)(uVar12 + 8 + (int)param_1);
  ppppppuVar14 = (uint ******)0x0;
  local_944 = (uint ******)((int)local_960 - (int)local_95c);
  local_91c = (uint ******)0x0;
  ppppppuVar9 = (uint ******)0x0;
  local_1d8 = (uint ******)0x0;
  local_924 = (uint ******)0x0;
  if (ppppppuVar15 != local_95c) {
    do {
      if (ppppppuVar9 == (uint ******)0x9) {
        local_940 = ppppppuVar15;
        if (ppppppuVar14 != (uint ******)0x0) {
          pppppuVar10 = (uint *****)0x0;
          ppppppuVar9 = (uint ******)0x0;
          do {
            lVar18 = ZEXT48((&local_1d8)[(int)ppppppuVar9 + 1]) * 1000000000 + ZEXT48(pppppuVar10);
            (&local_1d8)[(int)ppppppuVar9 + 1] = (uint ******)(uint *****)lVar18;
            pppppuVar10 = (uint *****)((ulonglong)lVar18 >> 0x20);
            ppppppuVar9 = (uint ******)((int)ppppppuVar9 + 1);
          } while (ppppppuVar9 != ppppppuVar14);
          ppppppuVar14 = local_1d8;
          if (pppppuVar10 != (uint *****)0x0) {
            if (local_1d8 < (uint ******)0x73) {
              (&local_1d8)[(int)local_1d8 + 1] = (uint ******)pppppuVar10;
              local_1d8 = (uint ******)((int)local_1d8 + 1);
              ppppppuVar14 = local_1d8;
            }
            else {
              local_918 = (uint ******)0x0;
              local_1d8 = (uint ******)0x0;
              _memcpy_s(&local_1d8 + 1,0x1cc,local_914,0);
              ppppppuVar14 = local_1d8;
            }
          }
        }
        if (local_924 != (uint ******)0x0) {
          ppppppuVar11 = (uint ******)0x0;
          ppppppuVar9 = local_924;
          if (ppppppuVar14 != (uint ******)0x0) {
            do {
              ppppppuVar14 = (uint ******)(&local_1d8 + (int)ppppppuVar11 + 1);
              pppppuVar10 = *ppppppuVar14;
              *ppppppuVar14 = (uint *****)((int)*ppppppuVar14 + (int)ppppppuVar9);
              ppppppuVar9 = (uint ******)(uint)CARRY4((uint)pppppuVar10,(uint)ppppppuVar9);
              ppppppuVar11 = (uint ******)((int)ppppppuVar11 + 1);
            } while (ppppppuVar11 != local_1d8);
            ppppppuVar14 = local_1d8;
            if (ppppppuVar9 == (uint ******)0x0) goto LAB_004097b3;
          }
          if (ppppppuVar14 < (uint ******)0x73) {
            (&local_1d8)[(int)ppppppuVar14 + 1] = ppppppuVar9;
            local_1d8 = (uint ******)((int)local_1d8 + 1);
            ppppppuVar14 = local_1d8;
          }
          else {
            local_918 = (uint ******)0x0;
            local_1d8 = (uint ******)0x0;
            _memcpy_s(&local_1d8 + 1,0x1cc,local_914,0);
            ppppppuVar14 = local_1d8;
          }
        }
LAB_004097b3:
        local_924 = (uint ******)0x0;
        ppppppuVar9 = (uint ******)0x0;
      }
      local_924 = (uint ******)((int)local_924 * 10 + (uint)*(byte *)ppppppuVar15);
      ppppppuVar9 = (uint ******)((int)ppppppuVar9 + 1);
      ppppppuVar15 = (uint ******)((int)ppppppuVar15 + 1);
    } while (ppppppuVar15 != local_95c);
    local_948 = ppppppuVar9;
    local_91c = ppppppuVar14;
    if (ppppppuVar9 != (uint ******)0x0) {
      local_940 = ppppppuVar15;
      for (local_930 = (uint ******)((uint)ppppppuVar9 / 10); local_91c = ppppppuVar14,
          local_930 != (uint ******)0x0; local_930 = (uint ******)((int)local_930 - (int)local_928))
      {
        local_928 = local_930;
        if ((uint ******)0x26 < local_930) {
          local_928 = (uint ******)0x26;
        }
        uVar13 = (uint)(byte)(&DAT_0041c6ce)[(int)local_928 * 4];
        bVar7 = (&DAT_0041c6cf)[(int)local_928 * 4];
        local_918 = (uint ******)(uVar13 + bVar7);
        _memset(local_914,0,uVar13 * 4);
        FID_conflict__memcpy
                  (local_914 + uVar13,
                   &UNK_0041bdc8 + (uint)*(ushort *)(&UNK_0041c6cc + (int)local_928 * 4) * 4,
                   (uint)bVar7 << 2);
        uVar13 = (uint)local_1d4[0];
        if (local_918 < (uint ******)0x2) {
          if (local_914[0] == (uint *****)0x0) {
            local_748 = (uint ******)0x0;
            pppppuVar10 = (uint *****)local_744;
LAB_004098a2:
            local_1d8 = (uint ******)0x0;
            _memcpy_s(&local_1d8 + 1,0x1cc,pppppuVar10,0);
          }
          else {
            if ((local_914[0] == (uint *****)0x1) || (ppppppuVar14 == (uint ******)0x0)) {
              bVar17 = true;
              goto LAB_00409bc0;
            }
            pppppuVar10 = (uint *****)0x0;
            ppppppuVar15 = (uint ******)0x0;
            do {
              lVar18 = ZEXT48(local_914[0]) * ZEXT48((&local_1d8)[(int)ppppppuVar15 + 1]) +
                       ZEXT48(pppppuVar10);
              (&local_1d8)[(int)ppppppuVar15 + 1] = (uint ******)(uint *****)lVar18;
              pppppuVar10 = (uint *****)((ulonglong)lVar18 >> 0x20);
              ppppppuVar15 = (uint ******)((int)ppppppuVar15 + 1);
            } while (ppppppuVar15 != ppppppuVar14);
            if (pppppuVar10 != (uint *****)0x0) {
              if ((uint ******)0x72 < local_1d8) {
LAB_00409921:
                local_918 = (uint ******)0x0;
                local_1d8 = (uint ******)0x0;
                _memcpy_s(&local_1d8 + 1,0x1cc,local_914,0);
                local_91c = local_1d8;
                bVar17 = false;
                goto LAB_00409bc0;
              }
              (&local_1d8)[(int)local_1d8 + 1] = (uint ******)pppppuVar10;
LAB_0040990c:
              local_1d8 = (uint ******)((int)local_1d8 + 1);
            }
          }
LAB_004098bd:
          bVar17 = true;
          local_91c = local_1d8;
        }
        else if (ppppppuVar14 < (uint ******)0x2) {
          local_1d8 = local_918;
          _memcpy_s(&local_1d8 + 1,0x1cc,local_914,(int)local_918 << 2);
          if (uVar13 == 0) {
            local_918 = (uint ******)0x0;
            pppppuVar10 = (uint *****)local_914;
            goto LAB_004098a2;
          }
          bVar17 = true;
          local_91c = local_1d8;
          if ((uVar13 != 1) && (local_1d8 != (uint ******)0x0)) {
            pppppuVar10 = (uint *****)0x0;
            ppppppuVar15 = (uint ******)0x0;
            do {
              lVar18 = (ulonglong)uVar13 * ZEXT48((&local_1d8)[(int)ppppppuVar15 + 1]) +
                       ZEXT48(pppppuVar10);
              (&local_1d8)[(int)ppppppuVar15 + 1] = (uint ******)(uint *****)lVar18;
              pppppuVar10 = (uint *****)((ulonglong)lVar18 >> 0x20);
              ppppppuVar15 = (uint ******)((int)ppppppuVar15 + 1);
            } while (ppppppuVar15 != local_1d8);
            if (pppppuVar10 != (uint *****)0x0) {
              if ((uint ******)0x72 < local_1d8) goto LAB_00409921;
              (&local_1d8)[(int)local_1d8 + 1] = (uint ******)pppppuVar10;
              goto LAB_0040990c;
            }
            goto LAB_004098bd;
          }
        }
        else {
          local_93c = local_914;
          if (local_918 < ppppppuVar14) {
            local_940 = (uint ******)(&local_1d8 + 1);
            local_938 = local_918;
          }
          else {
            local_93c = (uint ******)(&local_1d8 + 1);
            local_940 = local_914;
            local_938 = ppppppuVar14;
            ppppppuVar14 = local_918;
          }
          local_1d8 = (uint ******)0x0;
          ppppppuVar15 = (uint ******)0x0;
          local_748 = (uint ******)0x0;
          if (local_938 != (uint ******)0x0) {
            do {
              if (local_93c[(int)ppppppuVar15] == (uint *****)0x0) {
                if (ppppppuVar15 == local_1d8) {
                  local_744[(int)ppppppuVar15] = (uint *****)0x0;
                  local_1d8 = (uint ******)((int)ppppppuVar15 + 1);
                  local_748 = local_1d8;
                }
              }
              else {
                local_920 = (uint ******)0x0;
                local_92c = (uint ******)0x0;
                ppppppuVar9 = ppppppuVar15;
                if (ppppppuVar14 != (uint ******)0x0) {
                  do {
                    if (ppppppuVar9 == (uint ******)0x73) break;
                    if (ppppppuVar9 == local_1d8) {
                      local_744[(int)ppppppuVar9] = (uint *****)0x0;
                      local_748 = (uint ******)((int)ppppppuVar15 + 1 + (int)local_92c);
                    }
                    pppppuVar10 = local_940[(int)local_92c];
                    pppppuVar3 = local_93c[(int)ppppppuVar15];
                    uVar13 = (uint)(ZEXT48(pppppuVar10) * ZEXT48(pppppuVar3));
                    ppppuVar16 = (uint ****)local_744[(int)ppppppuVar9];
                    uVar12 = uVar13 + (int)local_744[(int)ppppppuVar9];
                    local_744[(int)ppppppuVar9] = (uint *****)(uVar12 + (int)local_920);
                    local_920 = (uint ******)
                                ((int)(ZEXT48(pppppuVar10) * ZEXT48(pppppuVar3) >> 0x20) +
                                 (uint)CARRY4(uVar13,(uint)ppppuVar16) +
                                (uint)CARRY4(uVar12,(uint)local_920));
                    local_92c = (uint ******)((int)local_92c + 1);
                    ppppppuVar9 = (uint ******)((int)ppppppuVar9 + 1);
                    local_1d8 = local_748;
                  } while (local_92c != ppppppuVar14);
                  if (local_920 != (uint ******)0x0) {
                    ppppppuVar11 = ppppppuVar9;
                    local_91c = local_744 + (int)ppppppuVar9;
                    do {
                      if (ppppppuVar11 == (uint ******)0x73) goto LAB_00409c3a;
                      ppppppuVar9 = (uint ******)((int)ppppppuVar11 + 1);
                      if (ppppppuVar11 == local_1d8) {
                        *local_91c = (uint *****)0x0;
                        local_748 = ppppppuVar9;
                      }
                      pppppuVar10 = *local_91c;
                      ppppppuVar1 = local_91c + 1;
                      *local_91c = (uint *****)((int)pppppuVar10 + (int)local_920);
                      local_920 = (uint ******)(uint)CARRY4((uint)pppppuVar10,(uint)local_920);
                      local_1d8 = local_748;
                      ppppppuVar11 = ppppppuVar9;
                      local_91c = ppppppuVar1;
                    } while (local_920 != (uint ******)0x0);
                  }
                }
                if (ppppppuVar9 == (uint ******)0x73) {
LAB_00409c3a:
                  local_1d8 = (uint ******)0x0;
                  _memcpy_s(&local_1d8 + 1,0x1cc,local_b2c,0);
                  bVar17 = false;
                  goto LAB_00409bb1;
                }
              }
              ppppppuVar15 = (uint ******)((int)ppppppuVar15 + 1);
            } while (ppppppuVar15 != local_938);
          }
          _memcpy_s(&local_1d8 + 1,0x1cc,local_744,(int)local_1d8 << 2);
          bVar17 = true;
LAB_00409bb1:
          local_91c = local_1d8;
        }
LAB_00409bc0:
        if (!bVar17) goto LAB_00409bfe;
        ppppppuVar14 = local_91c;
      }
      if ((uint)local_948 % 10 != 0) {
        uVar13 = *(uint *)(&DAT_0041c764 + ((uint)local_948 % 10) * 2);
        if (uVar13 == 0) {
LAB_00409bfe:
          local_1d8 = (uint ******)0x0;
          _memcpy_s(&local_1d8 + 1,0x1cc,local_b2c,0);
LAB_00409c2f:
          local_91c = local_1d8;
        }
        else if ((uVar13 != 1) && (ppppppuVar14 != (uint ******)0x0)) {
          pppppuVar10 = (uint *****)0x0;
          ppppppuVar15 = (uint ******)0x0;
          do {
            lVar18 = (ulonglong)uVar13 * ZEXT48((&local_1d8)[(int)ppppppuVar15 + 1]) +
                     ZEXT48(pppppuVar10);
            (&local_1d8)[(int)ppppppuVar15 + 1] = (uint ******)(uint *****)lVar18;
            pppppuVar10 = (uint *****)((ulonglong)lVar18 >> 0x20);
            ppppppuVar15 = (uint ******)((int)ppppppuVar15 + 1);
          } while (ppppppuVar15 != ppppppuVar14);
          if (pppppuVar10 == (uint *****)0x0) goto LAB_00409c2f;
          if ((uint ******)0x72 < local_1d8) goto LAB_00409bfe;
          (&local_1d8)[(int)local_1d8 + 1] = (uint ******)pppppuVar10;
          local_1d8 = (uint ******)((int)local_1d8 + 1);
          local_91c = local_1d8;
        }
      }
      if (local_924 != (uint ******)0x0) {
        ppppppuVar14 = (uint ******)0x0;
        ppppppuVar15 = local_924;
        if (local_91c != (uint ******)0x0) {
          do {
            ppppppuVar9 = (uint ******)(&local_1d8 + (int)ppppppuVar14 + 1);
            pppppuVar10 = *ppppppuVar9;
            *ppppppuVar9 = (uint *****)((int)*ppppppuVar9 + (int)ppppppuVar15);
            ppppppuVar15 = (uint ******)(uint)CARRY4((uint)pppppuVar10,(uint)ppppppuVar15);
            ppppppuVar14 = (uint ******)((int)ppppppuVar14 + 1);
            local_91c = local_1d8;
          } while (ppppppuVar14 != local_1d8);
          if (ppppppuVar15 == (uint ******)0x0) goto LAB_00409d66;
        }
        if (local_91c < (uint ******)0x73) {
          (&local_1d8)[(int)local_91c + 1] = ppppppuVar15;
          local_1d8 = (uint ******)((int)local_1d8 + 1);
          local_91c = local_1d8;
        }
        else {
          local_1d8 = (uint ******)0x0;
          _memcpy_s(&local_1d8 + 1,0x1cc,local_b2c,0);
          local_91c = local_1d8;
        }
      }
    }
  }
LAB_00409d66:
  if (local_934 != (uint ******)0x0) {
    ppppppuVar15 = local_91c;
    for (local_940 = (uint ******)((uint)local_934 / 10); local_91c = ppppppuVar15,
        local_940 != (uint ******)0x0; local_940 = (uint ******)((int)local_940 - (int)local_93c)) {
      local_93c = local_940;
      if ((uint ******)0x26 < local_940) {
        local_93c = (uint ******)0x26;
      }
      uVar13 = (uint)(byte)(&DAT_0041c6ce)[(int)local_93c * 4];
      bVar7 = (&DAT_0041c6cf)[(int)local_93c * 4];
      local_918 = (uint ******)(uVar13 + bVar7);
      _memset(local_914,0,uVar13 * 4);
      FID_conflict__memcpy
                (local_914 + uVar13,
                 &UNK_0041bdc8 + (uint)*(ushort *)(&UNK_0041c6cc + (int)local_93c * 4) * 4,
                 (uint)bVar7 << 2);
      uVar13 = (uint)local_1d4[0];
      if (local_918 < (uint ******)0x2) {
        if (local_914[0] == (uint *****)0x0) {
LAB_00409e27:
          local_1d8 = (uint ******)0x0;
          _memcpy_s(&local_1d8 + 1,0x1cc,local_b2c,0);
        }
        else {
          if ((local_914[0] == (uint *****)0x1) || (ppppppuVar15 == (uint ******)0x0)) {
            bVar17 = true;
            goto LAB_0040a12e;
          }
          pppppuVar10 = (uint *****)0x0;
          ppppppuVar14 = (uint ******)0x0;
          do {
            lVar18 = ZEXT48(local_914[0]) * ZEXT48((&local_1d8)[(int)ppppppuVar14 + 1]) +
                     ZEXT48(pppppuVar10);
            (&local_1d8)[(int)ppppppuVar14 + 1] = (uint ******)(uint *****)lVar18;
            pppppuVar10 = (uint *****)((ulonglong)lVar18 >> 0x20);
            ppppppuVar14 = (uint ******)((int)ppppppuVar14 + 1);
          } while (ppppppuVar14 != ppppppuVar15);
          if (pppppuVar10 != (uint *****)0x0) {
            if ((uint ******)0x72 < local_1d8) {
LAB_00409ea6:
              local_1d8 = (uint ******)0x0;
              _memcpy_s(&local_1d8 + 1,0x1cc,local_b2c,0);
              local_91c = local_1d8;
              bVar17 = false;
              goto LAB_0040a12e;
            }
            (&local_1d8)[(int)local_1d8 + 1] = (uint ******)pppppuVar10;
LAB_00409e91:
            local_1d8 = (uint ******)((int)local_1d8 + 1);
          }
        }
LAB_00409e42:
        bVar17 = true;
        local_91c = local_1d8;
      }
      else if (ppppppuVar15 < (uint ******)0x2) {
        local_1d8 = local_918;
        _memcpy_s(&local_1d8 + 1,0x1cc,local_914,(int)local_918 << 2);
        if (uVar13 == 0) goto LAB_00409e27;
        bVar17 = true;
        local_91c = local_1d8;
        if ((uVar13 != 1) && (local_1d8 != (uint ******)0x0)) {
          pppppuVar10 = (uint *****)0x0;
          ppppppuVar15 = (uint ******)0x0;
          do {
            lVar18 = (ulonglong)uVar13 * ZEXT48((&local_1d8)[(int)ppppppuVar15 + 1]) +
                     ZEXT48(pppppuVar10);
            (&local_1d8)[(int)ppppppuVar15 + 1] = (uint ******)(uint *****)lVar18;
            pppppuVar10 = (uint *****)((ulonglong)lVar18 >> 0x20);
            ppppppuVar15 = (uint ******)((int)ppppppuVar15 + 1);
          } while (ppppppuVar15 != local_1d8);
          if (pppppuVar10 != (uint *****)0x0) {
            if ((uint ******)0x72 < local_1d8) goto LAB_00409ea6;
            (&local_1d8)[(int)local_1d8 + 1] = (uint ******)pppppuVar10;
            goto LAB_00409e91;
          }
          goto LAB_00409e42;
        }
      }
      else {
        local_928 = local_914;
        if (local_918 < ppppppuVar15) {
          local_930 = (uint ******)(&local_1d8 + 1);
          local_938 = local_918;
        }
        else {
          local_928 = (uint ******)(&local_1d8 + 1);
          local_930 = local_914;
          local_938 = ppppppuVar15;
          ppppppuVar15 = local_918;
        }
        local_1d8 = (uint ******)0x0;
        ppppppuVar14 = (uint ******)0x0;
        local_748 = (uint ******)0x0;
        if (local_938 != (uint ******)0x0) {
          do {
            if (local_928[(int)ppppppuVar14] == (uint *****)0x0) {
              if (ppppppuVar14 == local_1d8) {
                local_744[(int)ppppppuVar14] = (uint *****)0x0;
                local_1d8 = (uint ******)((int)ppppppuVar14 + 1);
                local_748 = local_1d8;
              }
            }
            else {
              local_924 = (uint ******)0x0;
              local_920 = (uint ******)0x0;
              ppppppuVar9 = ppppppuVar14;
              if (ppppppuVar15 != (uint ******)0x0) {
                do {
                  if (ppppppuVar9 == (uint ******)0x73) break;
                  if (ppppppuVar9 == local_1d8) {
                    local_744[(int)ppppppuVar9] = (uint *****)0x0;
                    local_748 = (uint ******)((int)local_924 + 1 + (int)ppppppuVar14);
                  }
                  pppppuVar3 = local_930[(int)local_924];
                  pppppuVar4 = local_928[(int)ppppppuVar14];
                  uVar13 = (uint)(ZEXT48(pppppuVar3) * ZEXT48(pppppuVar4));
                  uVar12 = uVar13 + (int)local_920;
                  pppppuVar10 = (uint *****)(local_744 + (int)ppppppuVar9);
                  ppppuVar16 = *pppppuVar10;
                  *pppppuVar10 = (uint ****)((int)*pppppuVar10 + uVar12);
                  local_920 = (uint ******)
                              ((int)(ZEXT48(pppppuVar3) * ZEXT48(pppppuVar4) >> 0x20) +
                               (uint)CARRY4(uVar13,(uint)local_920) +
                              (uint)CARRY4((uint)ppppuVar16,uVar12));
                  local_924 = (uint ******)((int)local_924 + 1);
                  ppppppuVar9 = (uint ******)((int)ppppppuVar9 + 1);
                  local_1d8 = local_748;
                } while (local_924 != ppppppuVar15);
                if (local_920 != (uint ******)0x0) {
                  pppppuVar10 = (uint *****)(local_744 + (int)ppppppuVar9);
                  ppppppuVar11 = ppppppuVar9;
                  do {
                    if (ppppppuVar11 == (uint ******)0x73) goto LAB_0040a1a7;
                    ppppppuVar9 = (uint ******)((int)ppppppuVar11 + 1);
                    if (ppppppuVar11 == local_1d8) {
                      *pppppuVar10 = (uint ****)0x0;
                      local_748 = ppppppuVar9;
                    }
                    ppppuVar16 = *pppppuVar10;
                    *pppppuVar10 = (uint ****)((int)*pppppuVar10 + (int)local_920);
                    local_920 = (uint ******)(uint)CARRY4((uint)ppppuVar16,(uint)local_920);
                    local_1d8 = local_748;
                    pppppuVar10 = pppppuVar10 + 1;
                    ppppppuVar11 = ppppppuVar9;
                  } while (local_920 != (uint ******)0x0);
                }
              }
              if (ppppppuVar9 == (uint ******)0x73) {
LAB_0040a1a7:
                local_1d8 = (uint ******)0x0;
                _memcpy_s(&local_1d8 + 1,0x1cc,local_b2c,0);
                bVar17 = false;
                goto LAB_0040a122;
              }
            }
            ppppppuVar14 = (uint ******)((int)ppppppuVar14 + 1);
          } while (ppppppuVar14 != local_938);
        }
        _memcpy_s(&local_1d8 + 1,0x1cc,local_744,(int)local_1d8 << 2);
        bVar17 = true;
LAB_0040a122:
        local_91c = local_1d8;
      }
LAB_0040a12e:
      if (!bVar17) goto LAB_0040a259;
      ppppppuVar15 = local_91c;
    }
    if ((uint)local_934 % 10 != 0) {
      uVar13 = *(uint *)(&DAT_0041c764 + ((uint)local_934 % 10) * 2);
      if (uVar13 == 0) {
        local_1d8 = (uint ******)0x0;
        _memcpy_s(&local_1d8 + 1,0x1cc,local_b2c,0);
LAB_0040a196:
        local_91c = local_1d8;
      }
      else if ((uVar13 != 1) && (ppppppuVar15 != (uint ******)0x0)) {
        pppppuVar10 = (uint *****)0x0;
        ppppppuVar14 = (uint ******)0x0;
        do {
          lVar18 = (ulonglong)uVar13 * ZEXT48((&local_1d8)[(int)ppppppuVar14 + 1]) +
                   ZEXT48(pppppuVar10);
          (&local_1d8)[(int)ppppppuVar14 + 1] = (uint ******)(uint *****)lVar18;
          pppppuVar10 = (uint *****)((ulonglong)lVar18 >> 0x20);
          ppppppuVar14 = (uint ******)((int)ppppppuVar14 + 1);
        } while (ppppppuVar14 != ppppppuVar15);
        if (pppppuVar10 == (uint *****)0x0) goto LAB_0040a196;
        if ((uint ******)0x72 < local_1d8) {
LAB_0040a259:
          local_1d8 = (uint ******)0x0;
          _memcpy_s(&local_1d8 + 1,0x1cc,local_b2c,0);
          __crt_strtox::assemble_floating_point_infinity(*(bool *)(local_950 + 0xc2),local_958);
          goto LAB_0040b39c;
        }
        (&local_1d8)[(int)local_1d8 + 1] = (uint ******)pppppuVar10;
        local_1d8 = (uint ******)((int)local_1d8 + 1);
        local_91c = local_1d8;
      }
    }
  }
  local_940 = local_91c;
  if (local_91c != (uint ******)0x0) {
    pppppuVar10 = (uint *****)(&local_1d8)[(int)local_91c];
    local_94c = 0;
    iVar6 = 0x1f;
    if (pppppuVar10 != (uint *****)0x0) {
      for (; (uint)pppppuVar10 >> iVar6 == 0; iVar6 = iVar6 + -1) {
      }
    }
    if (pppppuVar10 == (uint *****)0x0) {
      iVar6 = 0;
    }
    else {
      iVar6 = iVar6 + 1;
    }
    local_940 = (uint ******)(((int)local_91c + -1) * 0x20 + iVar6);
  }
  if ((local_954 <= local_940) || (local_944 == (uint ******)0x0)) {
    bVar17 = local_960 != local_95c;
    uVar2 = *(undefined *)(local_950 + 0xc2);
LAB_0040b38d:
    FUN_0040943e((uint *)&local_1d8,(uint)local_940,(bool)uVar2,bVar17,local_958);
    goto LAB_0040b39c;
  }
  ppppppuVar15 = (uint ******)0x0;
  ppppppuStack_3a8 = (uint ******)0x0;
  ppppppuVar9 = (uint ******)0x0;
  local_92c = (uint ******)0x0;
  local_924 = local_95c;
  ppppppuVar14 = local_95c;
  if (local_95c != local_960) {
    do {
      ppppppuVar11 = local_92c;
      if (ppppppuVar9 == (uint ******)0x9) {
        local_924 = ppppppuVar14;
        if (ppppppuVar15 != (uint ******)0x0) {
          pppppuVar10 = (uint *****)0x0;
          ppppppuVar14 = (uint ******)0x0;
          do {
            lVar18 = ZEXT48((&ppppppuStack_3a8)[(int)ppppppuVar14 + 1]) * 1000000000 +
                     ZEXT48(pppppuVar10);
            (&ppppppuStack_3a8)[(int)ppppppuVar14 + 1] = (uint ******)(uint *****)lVar18;
            pppppuVar10 = (uint *****)((ulonglong)lVar18 >> 0x20);
            ppppppuVar14 = (uint ******)((int)ppppppuVar14 + 1);
          } while (ppppppuVar14 != ppppppuVar15);
          ppppppuVar15 = ppppppuStack_3a8;
          if (pppppuVar10 != (uint *****)0x0) {
            if (ppppppuStack_3a8 < (uint ******)0x73) {
              (&ppppppuStack_3a8)[(int)ppppppuStack_3a8 + 1] = (uint ******)pppppuVar10;
              ppppppuStack_3a8 = (uint ******)((int)ppppppuStack_3a8 + 1);
              ppppppuVar15 = ppppppuStack_3a8;
            }
            else {
              ppppppuStack_3a8 = (uint ******)0x0;
              _memcpy_s(&ppppppuStack_3a8 + 1,0x1cc,local_b2c,0);
              ppppppuVar15 = ppppppuStack_3a8;
            }
          }
        }
        ppppppuVar14 = local_924;
        if (ppppppuVar11 != (uint ******)0x0) {
          ppppppuVar9 = (uint ******)0x0;
          if (ppppppuVar15 != (uint ******)0x0) {
            do {
              ppppppuVar15 = (uint ******)(&ppppppuStack_3a8 + (int)ppppppuVar9 + 1);
              pppppuVar10 = *ppppppuVar15;
              *ppppppuVar15 = (uint *****)((int)*ppppppuVar15 + (int)ppppppuVar11);
              ppppppuVar11 = (uint ******)(uint)CARRY4((uint)pppppuVar10,(uint)ppppppuVar11);
              ppppppuVar9 = (uint ******)((int)ppppppuVar9 + 1);
            } while (ppppppuVar9 != ppppppuStack_3a8);
            ppppppuVar15 = ppppppuStack_3a8;
            if (ppppppuVar11 == (uint ******)0x0) goto LAB_0040a416;
          }
          if (ppppppuVar15 < (uint ******)0x73) {
            (&ppppppuStack_3a8)[(int)ppppppuVar15 + 1] = ppppppuVar11;
            ppppppuStack_3a8 = (uint ******)((int)ppppppuStack_3a8 + 1);
            ppppppuVar15 = ppppppuStack_3a8;
          }
          else {
            ppppppuStack_3a8 = (uint ******)0x0;
            _memcpy_s(&ppppppuStack_3a8 + 1,0x1cc,local_b2c,0);
            ppppppuVar15 = ppppppuStack_3a8;
          }
        }
LAB_0040a416:
        local_92c = (uint ******)0x0;
        ppppppuVar9 = (uint ******)0x0;
      }
      local_92c = (uint ******)((int)local_92c * 10 + (uint)*(byte *)ppppppuVar14);
      ppppppuVar9 = (uint ******)((int)ppppppuVar9 + 1);
      ppppppuVar14 = (uint ******)((int)ppppppuVar14 + 1);
    } while (ppppppuVar14 != local_960);
    local_948 = ppppppuVar9;
    local_924 = ppppppuVar14;
    if (ppppppuVar9 != (uint ******)0x0) {
      for (local_924 = (uint ******)((uint)ppppppuVar9 / 10); local_924 != (uint ******)0x0;
          local_924 = (uint ******)((int)local_924 - (int)local_93c)) {
        local_93c = local_924;
        if ((uint ******)0x26 < local_924) {
          local_93c = (uint ******)0x26;
        }
        uVar13 = (uint)(byte)(&DAT_0041c6ce)[(int)local_93c * 4];
        bVar7 = (&DAT_0041c6cf)[(int)local_93c * 4];
        local_918 = (uint ******)(uVar13 + bVar7);
        _memset(local_914,0,uVar13 * 4);
        FID_conflict__memcpy
                  (local_914 + uVar13,
                   &UNK_0041bdc8 + (uint)*(ushort *)(&UNK_0041c6cc + (int)local_93c * 4) * 4,
                   (uint)bVar7 << 2);
        uVar13 = (uint)apppppuStack_3a4[0];
        if (local_918 < (uint ******)0x2) {
          if (local_914[0] == (uint *****)0x0) {
            ppppppuStack_3a8 = (uint ******)0x0;
            _MaxCount = 0;
            pppppuVar10 = local_b2c;
            goto LAB_0040a797;
          }
          if ((local_914[0] == (uint *****)0x1) || (ppppppuVar15 == (uint ******)0x0)) {
            bVar17 = true;
          }
          else {
            pppppuVar10 = (uint *****)0x0;
            ppppppuVar14 = (uint ******)0x0;
            do {
              lVar18 = ZEXT48(local_914[0]) * ZEXT48((&ppppppuStack_3a8)[(int)ppppppuVar14 + 1]) +
                       ZEXT48(pppppuVar10);
              (&ppppppuStack_3a8)[(int)ppppppuVar14 + 1] = (uint ******)(uint *****)lVar18;
              pppppuVar10 = (uint *****)((ulonglong)lVar18 >> 0x20);
              ppppppuVar14 = (uint ******)((int)ppppppuVar14 + 1);
            } while (ppppppuVar14 != ppppppuVar15);
LAB_0040a52d:
            if (pppppuVar10 != (uint *****)0x0) {
              if ((uint ******)0x72 < ppppppuStack_3a8) {
                ppppppuStack_3a8 = (uint ******)0x0;
                _memcpy_s(&ppppppuStack_3a8 + 1,0x1cc,local_b2c,0);
                bVar17 = false;
                ppppppuVar15 = ppppppuStack_3a8;
                goto LAB_0040a7ae;
              }
              (&ppppppuStack_3a8)[(int)ppppppuStack_3a8 + 1] = (uint ******)pppppuVar10;
              ppppppuStack_3a8 = (uint ******)((int)ppppppuStack_3a8 + 1);
            }
            bVar17 = true;
            ppppppuVar15 = ppppppuStack_3a8;
          }
        }
        else {
          if (ppppppuVar15 < (uint ******)0x2) {
            ppppppuStack_3a8 = local_918;
            _memcpy_s(&ppppppuStack_3a8 + 1,0x1cc,local_914,(int)local_918 << 2);
            if (uVar13 != 0) {
              bVar17 = true;
              ppppppuVar15 = ppppppuStack_3a8;
              if ((uVar13 != 1) && (ppppppuStack_3a8 != (uint ******)0x0)) {
                pppppuVar10 = (uint *****)0x0;
                ppppppuVar15 = (uint ******)0x0;
                do {
                  lVar18 = (ulonglong)uVar13 * ZEXT48((&ppppppuStack_3a8)[(int)ppppppuVar15 + 1]) +
                           ZEXT48(pppppuVar10);
                  (&ppppppuStack_3a8)[(int)ppppppuVar15 + 1] = (uint ******)(uint *****)lVar18;
                  pppppuVar10 = (uint *****)((ulonglong)lVar18 >> 0x20);
                  ppppppuVar15 = (uint ******)((int)ppppppuVar15 + 1);
                } while (ppppppuVar15 != ppppppuStack_3a8);
                goto LAB_0040a52d;
              }
              goto LAB_0040a7ae;
            }
            _MaxCount = 0;
            ppppppuStack_3a8 = (uint ******)0x0;
            pppppuVar10 = local_b2c;
          }
          else {
            local_928 = local_914;
            if (local_918 < ppppppuVar15) {
              local_934 = (uint ******)(&ppppppuStack_3a8 + 1);
              local_938 = local_918;
            }
            else {
              local_928 = (uint ******)(&ppppppuStack_3a8 + 1);
              local_934 = local_914;
              local_938 = ppppppuVar15;
              ppppppuVar15 = local_918;
            }
            ppppppuStack_3a8 = (uint ******)0x0;
            ppppppuVar14 = (uint ******)0x0;
            local_748 = (uint ******)0x0;
            if (local_938 != (uint ******)0x0) {
              do {
                if (local_928[(int)ppppppuVar14] == (uint *****)0x0) {
                  if (ppppppuVar14 == ppppppuStack_3a8) {
                    local_744[(int)ppppppuVar14] = (uint *****)0x0;
                    ppppppuStack_3a8 = (uint ******)((int)ppppppuVar14 + 1);
                    local_748 = ppppppuStack_3a8;
                  }
                }
                else {
                  local_920 = (uint ******)0x0;
                  local_930 = (uint ******)0x0;
                  ppppppuVar9 = ppppppuVar14;
                  if (ppppppuVar15 != (uint ******)0x0) {
                    do {
                      if (ppppppuVar9 == (uint ******)0x73) break;
                      if (ppppppuVar9 == ppppppuStack_3a8) {
                        local_744[(int)ppppppuVar9] = (uint *****)0x0;
                        local_748 = (uint ******)((int)ppppppuVar14 + 1 + (int)local_930);
                      }
                      pppppuVar3 = local_934[(int)local_930];
                      pppppuVar4 = local_928[(int)ppppppuVar14];
                      uVar13 = (uint)(ZEXT48(pppppuVar3) * ZEXT48(pppppuVar4));
                      uVar12 = uVar13 + (int)local_920;
                      pppppuVar10 = (uint *****)(local_744 + (int)ppppppuVar9);
                      ppppuVar16 = *pppppuVar10;
                      *pppppuVar10 = (uint ****)((int)*pppppuVar10 + uVar12);
                      local_920 = (uint ******)
                                  ((int)(ZEXT48(pppppuVar3) * ZEXT48(pppppuVar4) >> 0x20) +
                                   (uint)CARRY4(uVar13,(uint)local_920) +
                                  (uint)CARRY4((uint)ppppuVar16,uVar12));
                      local_930 = (uint ******)((int)local_930 + 1);
                      ppppppuVar9 = (uint ******)((int)ppppppuVar9 + 1);
                      ppppppuStack_3a8 = local_748;
                    } while (local_930 != ppppppuVar15);
                    if (local_920 != (uint ******)0x0) {
                      pppppuVar10 = (uint *****)(local_744 + (int)ppppppuVar9);
                      ppppppuVar11 = ppppppuVar9;
                      do {
                        if (ppppppuVar11 == (uint ******)0x73) goto LAB_0040a84e;
                        ppppppuVar9 = (uint ******)((int)ppppppuVar11 + 1);
                        if (ppppppuVar11 == ppppppuStack_3a8) {
                          *pppppuVar10 = (uint ****)0x0;
                          local_748 = ppppppuVar9;
                        }
                        ppppuVar16 = *pppppuVar10;
                        *pppppuVar10 = (uint ****)((int)*pppppuVar10 + (int)local_920);
                        local_920 = (uint ******)(uint)CARRY4((uint)ppppuVar16,(uint)local_920);
                        ppppppuStack_3a8 = local_748;
                        pppppuVar10 = pppppuVar10 + 1;
                        ppppppuVar11 = ppppppuVar9;
                      } while (local_920 != (uint ******)0x0);
                    }
                  }
                  if (ppppppuVar9 == (uint ******)0x73) {
LAB_0040a84e:
                    ppppppuStack_3a8 = (uint ******)0x0;
                    _memcpy_s(&ppppppuStack_3a8 + 1,0x1cc,local_b2c,0);
                    bVar17 = false;
                    ppppppuVar15 = ppppppuStack_3a8;
                    goto LAB_0040a7ae;
                  }
                }
                ppppppuVar14 = (uint ******)((int)ppppppuVar14 + 1);
              } while (ppppppuVar14 != local_938);
            }
            _MaxCount = (int)ppppppuStack_3a8 << 2;
            pppppuVar10 = (uint *****)local_744;
          }
LAB_0040a797:
          _memcpy_s(&ppppppuStack_3a8 + 1,0x1cc,pppppuVar10,_MaxCount);
          bVar17 = true;
          ppppppuVar15 = ppppppuStack_3a8;
        }
LAB_0040a7ae:
        if (!bVar17) goto LAB_0040a8a0;
      }
      if ((uint)local_948 % 10 != 0) {
        uVar13 = *(uint *)(&DAT_0041c764 + ((uint)local_948 % 10) * 2);
        if (uVar13 == 0) {
LAB_0040a8a0:
          ppppppuStack_3a8 = (uint ******)0x0;
          _memcpy_s(&ppppppuStack_3a8 + 1,0x1cc,local_b2c,0);
          ppppppuVar15 = ppppppuStack_3a8;
        }
        else if ((uVar13 != 1) && (ppppppuVar15 != (uint ******)0x0)) {
          pppppuVar10 = (uint *****)0x0;
          ppppppuVar14 = (uint ******)0x0;
          do {
            lVar18 = (ulonglong)uVar13 * ZEXT48((&ppppppuStack_3a8)[(int)ppppppuVar14 + 1]) +
                     ZEXT48(pppppuVar10);
            (&ppppppuStack_3a8)[(int)ppppppuVar14 + 1] = (uint ******)(uint *****)lVar18;
            pppppuVar10 = (uint *****)((ulonglong)lVar18 >> 0x20);
            ppppppuVar14 = (uint ******)((int)ppppppuVar14 + 1);
          } while (ppppppuVar14 != ppppppuVar15);
          ppppppuVar15 = ppppppuStack_3a8;
          if (pppppuVar10 != (uint *****)0x0) {
            if ((uint ******)0x72 < ppppppuStack_3a8) goto LAB_0040a8a0;
            (&ppppppuStack_3a8)[(int)ppppppuStack_3a8 + 1] = (uint ******)pppppuVar10;
            ppppppuStack_3a8 = (uint ******)((int)ppppppuStack_3a8 + 1);
            ppppppuVar15 = ppppppuStack_3a8;
          }
        }
      }
      if (local_92c != (uint ******)0x0) {
        ppppppuVar9 = (uint ******)0x0;
        ppppppuVar14 = local_92c;
        if (ppppppuVar15 != (uint ******)0x0) {
          do {
            ppppppuVar15 = (uint ******)(&ppppppuStack_3a8 + (int)ppppppuVar9 + 1);
            pppppuVar10 = *ppppppuVar15;
            *ppppppuVar15 = (uint *****)((int)*ppppppuVar15 + (int)ppppppuVar14);
            ppppppuVar14 = (uint ******)(uint)CARRY4((uint)pppppuVar10,(uint)ppppppuVar14);
            ppppppuVar9 = (uint ******)((int)ppppppuVar9 + 1);
          } while (ppppppuVar9 != ppppppuStack_3a8);
          ppppppuVar15 = ppppppuStack_3a8;
          if (ppppppuVar14 == (uint ******)0x0) goto LAB_0040a941;
        }
        if (ppppppuVar15 < (uint ******)0x73) {
          (&ppppppuStack_3a8)[(int)ppppppuVar15 + 1] = ppppppuVar14;
          ppppppuStack_3a8 = (uint ******)((int)ppppppuStack_3a8 + 1);
          ppppppuVar15 = ppppppuStack_3a8;
        }
        else {
          ppppppuStack_3a8 = (uint ******)0x0;
          _memcpy_s(&ppppppuStack_3a8 + 1,0x1cc,local_b2c,0);
          ppppppuVar15 = ppppppuStack_3a8;
        }
      }
    }
  }
LAB_0040a941:
  if ((int)*local_950 < 0) {
    local_944 = (uint ******)((int)local_944 - *local_950);
  }
  apppppuStack_574[1] = (uint *****)0x0;
  apppppuStack_574[0] = (uint *****)0x1;
  local_920 = (uint ******)0x1;
  ppppppuStack_578 = (uint ******)0x1;
  for (local_928 = (uint ******)((uint)local_944 / 10); local_928 != (uint ******)0x0;
      local_928 = (uint ******)((int)local_928 - (int)local_938)) {
    local_938 = local_928;
    if ((uint ******)0x26 < local_928) {
      local_938 = (uint ******)0x26;
    }
    ppppppuVar15 = local_938;
    uVar13 = (uint)(byte)(&DAT_0041c6ce)[(int)local_938 * 4];
    bVar7 = (&DAT_0041c6cf)[(int)local_938 * 4];
    local_918 = (uint ******)(uVar13 + bVar7);
    _memset(local_914,0,uVar13 * 4);
    FID_conflict__memcpy
              (local_914 + uVar13,
               &UNK_0041bdc8 + (uint)*(ushort *)(&UNK_0041c6cc + (int)ppppppuVar15 * 4) * 4,
               (uint)bVar7 << 2);
    pppppuVar10 = apppppuStack_574[0];
    if (local_918 < (uint ******)0x2) {
      if (local_914[0] == (uint *****)0x0) {
LAB_0040aa27:
        ppppppuStack_578 = (uint ******)0x0;
        _memcpy_s(apppppuStack_574,0x1cc,local_b2c,0);
      }
      else {
        if ((local_914[0] == (uint *****)0x1) || (local_920 == (uint ******)0x0)) {
          bVar17 = true;
          goto LAB_0040ad25;
        }
        ppppuVar16 = (uint ****)0x0;
        ppppppuVar15 = (uint ******)0x0;
        do {
          lVar18 = ZEXT48(local_914[0]) * ZEXT48(apppppuStack_574[(int)ppppppuVar15]) +
                   ZEXT48(ppppuVar16);
          apppppuStack_574[(int)ppppppuVar15] = (uint *****)(uint ****)lVar18;
          ppppuVar16 = (uint ****)((ulonglong)lVar18 >> 0x20);
          ppppppuVar15 = (uint ******)((int)ppppppuVar15 + 1);
        } while (ppppppuVar15 != local_920);
LAB_0040ab72:
        if (ppppuVar16 != (uint ****)0x0) {
          if ((uint ******)0x72 < ppppppuStack_578) {
            ppppppuStack_578 = (uint ******)0x0;
            _memcpy_s(apppppuStack_574,0x1cc,local_b2c,0);
            bVar5 = false;
            goto LAB_0040aace;
          }
          apppppuStack_574[(int)ppppppuStack_578] = (uint *****)ppppuVar16;
          ppppppuStack_578 = (uint ******)((int)ppppppuStack_578 + 1);
        }
      }
      bVar17 = true;
      local_920 = ppppppuStack_578;
    }
    else if (local_920 < (uint ******)0x2) {
      ppppppuStack_578 = local_918;
      _memcpy_s(apppppuStack_574,0x1cc,local_914,(int)local_918 << 2);
      if (pppppuVar10 == (uint *****)0x0) goto LAB_0040aa27;
      bVar17 = true;
      bVar5 = true;
      if (pppppuVar10 == (uint *****)0x1) {
LAB_0040aace:
        bVar17 = bVar5;
        local_920 = ppppppuStack_578;
      }
      else {
        local_920 = ppppppuStack_578;
        if (ppppppuStack_578 != (uint ******)0x0) {
          ppppuVar16 = (uint ****)0x0;
          ppppppuVar15 = (uint ******)0x0;
          do {
            lVar18 = ZEXT48(pppppuVar10) * ZEXT48(apppppuStack_574[(int)ppppppuVar15]) +
                     ZEXT48(ppppuVar16);
            apppppuStack_574[(int)ppppppuVar15] = (uint *****)(uint ****)lVar18;
            ppppuVar16 = (uint ****)((ulonglong)lVar18 >> 0x20);
            ppppppuVar15 = (uint ******)((int)ppppppuVar15 + 1);
          } while (ppppppuVar15 != ppppppuStack_578);
          goto LAB_0040ab72;
        }
      }
    }
    else {
      local_92c = local_914;
      if (local_918 < local_920) {
        local_934 = apppppuStack_574;
        local_930 = local_918;
        ppppppuVar15 = local_920;
      }
      else {
        local_92c = apppppuStack_574;
        local_934 = local_914;
        local_930 = local_920;
        ppppppuVar15 = local_918;
      }
      ppppppuStack_578 = (uint ******)0x0;
      ppppppuVar14 = (uint ******)0x0;
      local_748 = (uint ******)0x0;
      if (local_930 != (uint ******)0x0) {
        do {
          if (local_92c[(int)ppppppuVar14] == (uint *****)0x0) {
            if (ppppppuVar14 == ppppppuStack_578) {
              local_744[(int)ppppppuVar14] = (uint *****)0x0;
              ppppppuStack_578 = (uint ******)((int)ppppppuVar14 + 1);
              local_748 = ppppppuStack_578;
            }
          }
          else {
            local_924 = (uint ******)0x0;
            local_920 = (uint ******)0x0;
            ppppppuVar9 = ppppppuVar14;
            if (ppppppuVar15 != (uint ******)0x0) {
              do {
                if (ppppppuVar9 == (uint ******)0x73) break;
                if (ppppppuVar9 == ppppppuStack_578) {
                  local_744[(int)ppppppuVar9] = (uint *****)0x0;
                  local_748 = (uint ******)((int)local_924 + 1 + (int)ppppppuVar14);
                }
                pppppuVar3 = local_934[(int)local_924];
                pppppuVar4 = local_92c[(int)ppppppuVar14];
                uVar13 = (uint)(ZEXT48(pppppuVar3) * ZEXT48(pppppuVar4));
                uVar12 = uVar13 + (int)local_920;
                pppppuVar10 = (uint *****)(local_744 + (int)ppppppuVar9);
                ppppuVar16 = *pppppuVar10;
                *pppppuVar10 = (uint ****)((int)*pppppuVar10 + uVar12);
                local_920 = (uint ******)
                            ((int)(ZEXT48(pppppuVar3) * ZEXT48(pppppuVar4) >> 0x20) +
                             (uint)CARRY4(uVar13,(uint)local_920) +
                            (uint)CARRY4((uint)ppppuVar16,uVar12));
                local_924 = (uint ******)((int)local_924 + 1);
                ppppppuVar9 = (uint ******)((int)ppppppuVar9 + 1);
                ppppppuStack_578 = local_748;
              } while (local_924 != ppppppuVar15);
              if (local_920 != (uint ******)0x0) {
                pppppuVar10 = (uint *****)(local_744 + (int)ppppppuVar9);
                ppppppuVar11 = ppppppuVar9;
                do {
                  if (ppppppuVar11 == (uint ******)0x73) goto LAB_0040adb4;
                  ppppppuVar9 = (uint ******)((int)ppppppuVar11 + 1);
                  if (ppppppuVar11 == ppppppuStack_578) {
                    *pppppuVar10 = (uint ****)0x0;
                    local_748 = ppppppuVar9;
                  }
                  ppppuVar16 = *pppppuVar10;
                  *pppppuVar10 = (uint ****)((int)*pppppuVar10 + (int)local_920);
                  local_920 = (uint ******)(uint)CARRY4((uint)ppppuVar16,(uint)local_920);
                  ppppppuStack_578 = local_748;
                  pppppuVar10 = pppppuVar10 + 1;
                  ppppppuVar11 = ppppppuVar9;
                } while (local_920 != (uint ******)0x0);
              }
            }
            if (ppppppuVar9 == (uint ******)0x73) {
LAB_0040adb4:
              ppppppuStack_578 = (uint ******)0x0;
              _memcpy_s(apppppuStack_574,0x1cc,local_b2c,0);
              bVar17 = false;
              goto LAB_0040ad19;
            }
          }
          ppppppuVar14 = (uint ******)((int)ppppppuVar14 + 1);
        } while (ppppppuVar14 != local_930);
      }
      _memcpy_s(apppppuStack_574,0x1cc,local_744,(int)ppppppuStack_578 << 2);
      bVar17 = true;
LAB_0040ad19:
      local_920 = ppppppuStack_578;
    }
LAB_0040ad25:
    if (!bVar17) goto LAB_0040ae6b;
    ppppppuVar15 = ppppppuStack_3a8;
  }
  if ((uint)local_944 % 10 != 0) {
    local_948 = *(uint *******)(&DAT_0041c764 + ((uint)local_944 % 10) * 2);
    if (local_948 == (uint ******)0x0) {
      ppppppuStack_578 = local_948;
      _memcpy_s(apppppuStack_574,0x1cc,local_b2c,0);
      ppppppuVar15 = ppppppuStack_3a8;
LAB_0040ada3:
      local_920 = ppppppuStack_578;
    }
    else if ((local_948 != (uint ******)0x1) && (local_920 != (uint ******)0x0)) {
      ppppuVar16 = (uint ****)0x0;
      ppppppuVar14 = (uint ******)0x0;
      do {
        lVar18 = ZEXT48(local_948) * ZEXT48(apppppuStack_574[(int)ppppppuVar14]) +
                 ZEXT48(ppppuVar16);
        apppppuStack_574[(int)ppppppuVar14] = (uint *****)(uint ****)lVar18;
        ppppuVar16 = (uint ****)((ulonglong)lVar18 >> 0x20);
        ppppppuVar14 = (uint ******)((int)ppppppuVar14 + 1);
      } while (ppppppuVar14 != local_920);
      if (ppppuVar16 == (uint ****)0x0) goto LAB_0040ada3;
      if ((uint ******)0x72 < ppppppuStack_578) {
LAB_0040ae6b:
        ppppppuStack_578 = (uint ******)0x0;
        _memcpy_s(apppppuStack_574,0x1cc,local_b2c,0);
        __crt_strtox::assemble_floating_point_zero(*(bool *)(local_950 + 0xc2),local_958);
        goto LAB_0040b39c;
      }
      apppppuStack_574[(int)ppppppuStack_578] = (uint *****)ppppuVar16;
      local_920 = (uint ******)((int)ppppppuStack_578 + 1);
      ppppppuStack_578 = local_920;
    }
  }
  if (ppppppuVar15 == (uint ******)0x0) {
    uVar13 = 0;
  }
  else {
    pppppuVar10 = (uint *****)(&ppppppuStack_3a8)[(int)ppppppuVar15];
    local_94c = 0;
    iVar6 = 0x1f;
    if (pppppuVar10 != (uint *****)0x0) {
      for (; (uint)pppppuVar10 >> iVar6 == 0; iVar6 = iVar6 + -1) {
      }
    }
    if (pppppuVar10 == (uint *****)0x0) {
      iVar6 = 0;
    }
    else {
      iVar6 = iVar6 + 1;
    }
    uVar13 = ((int)ppppppuVar15 + -1) * 0x20 + iVar6;
  }
  if (local_920 == (uint ******)0x0) {
    uVar12 = 0;
  }
  else {
    ppppuVar16 = (uint ****)apppppuStack_574[(int)local_920 + -1];
    local_94c = 0;
    iVar6 = 0x1f;
    if (ppppuVar16 != (uint ****)0x0) {
      for (; (uint)ppppuVar16 >> iVar6 == 0; iVar6 = iVar6 + -1) {
      }
    }
    if (ppppuVar16 == (uint ****)0x0) {
      iVar6 = 0;
    }
    else {
      iVar6 = iVar6 + 1;
    }
    uVar12 = ((int)local_920 + -1) * 0x20 + iVar6;
  }
  local_924 = (uint ******)(-(uint)(uVar13 < uVar12) & uVar12 - uVar13);
  ppppppuVar14 = local_920;
  if (local_924 != (uint ******)0x0) {
    ppppppuVar14 = (uint ******)((uint)local_924 & 0x1f);
    uVar13 = (uint)local_924 >> 5;
    local_92c = (uint ******)(0x20 - (int)ppppppuVar14);
    local_94c = uVar13;
    local_948 = ppppppuVar14;
    lVar18 = __allshl((byte)local_92c,0);
    pppppuVar10 = (uint *****)(&ppppppuStack_3a8)[(int)ppppppuVar15];
    local_928 = (uint ******)((int)lVar18 + -1);
    iVar6 = 0x1f;
    if (pppppuVar10 != (uint *****)0x0) {
      for (; (uint)pppppuVar10 >> iVar6 == 0; iVar6 = iVar6 + -1) {
      }
    }
    local_938 = (uint ******)~(uint)local_928;
    local_934 = (uint ******)0x0;
    if (pppppuVar10 == (uint *****)0x0) {
      iVar6 = 0;
    }
    else {
      iVar6 = iVar6 + 1;
    }
    if ((uVar13 + (int)ppppppuVar15 < 0x74) &&
       (local_944 = (uint ******)
                    (((uint ******)(0x20 - iVar6) < ppppppuVar14) + uVar13 + (int)ppppppuVar15),
       local_944 < (uint ******)0x74)) {
      local_93c = (uint ******)(uVar13 - 1);
      local_930 = (uint ******)((int)local_944 + -1);
      if (local_930 != local_93c) {
        ppppppuVar9 = (uint ******)((int)local_930 - uVar13);
        ppppppuVar14 = (uint ******)(&ppppppuStack_3a8 + (int)ppppppuVar9);
        do {
          if (ppppppuVar9 < ppppppuVar15) {
            local_934 = (uint ******)ppppppuVar14[1];
          }
          else {
            local_934 = (uint ******)0x0;
          }
          if ((uint ******)((int)ppppppuVar9 + -1) < ppppppuVar15) {
            pppppuVar10 = *ppppppuVar14;
          }
          else {
            pppppuVar10 = (uint *****)0x0;
          }
          ppppppuVar14 = ppppppuVar14 + -1;
          (&ppppppuStack_3a8)[(int)local_930 + 1] =
               (uint ******)
               (((uint)pppppuVar10 & (uint)local_938) >> ((byte)local_92c & 0x1f) |
               ((uint)local_934 & (uint)local_928) << ((byte)local_948 & 0x1f));
          local_930 = (uint ******)((int)local_930 + -1);
          ppppppuVar9 = (uint ******)((int)ppppppuVar9 + -1);
          ppppppuVar15 = ppppppuStack_3a8;
          uVar13 = local_94c;
        } while (local_930 != local_93c);
      }
      if (uVar13 != 0) {
        ppppppuVar15 = (uint ******)&ppppppuStack_3a8;
        for (; ppppppuVar15 = ppppppuVar15 + 1, uVar13 != 0; uVar13 = uVar13 - 1) {
          *ppppppuVar15 = (uint *****)0x0;
        }
      }
      ppppppuStack_3a8 = local_944;
      ppppppuVar14 = local_920;
      ppppppuVar15 = ppppppuStack_3a8;
    }
    else {
      ppppppuStack_3a8 = (uint ******)0x0;
      _memcpy_s(&ppppppuStack_3a8 + 1,0x1cc,local_b2c,0);
      ppppppuVar14 = ppppppuStack_578;
      ppppppuVar15 = ppppppuStack_3a8;
    }
  }
  local_954 = (uint ******)((int)local_954 - (int)local_940);
  ppppppuVar9 = local_954;
  if (local_940 != (uint ******)0x0) {
    if (local_954 < local_924) {
      bVar17 = local_960 != local_95c;
      uVar2 = *(undefined *)(local_950 + 0xc2);
      goto LAB_0040b38d;
    }
    ppppppuVar9 = (uint ******)((int)local_954 - (int)local_924);
  }
  if (ppppppuVar15 <= ppppppuVar14) {
    ppppppuVar11 = ppppppuVar15;
    if (ppppppuVar14 <= ppppppuVar15) {
      do {
        ppppppuVar14 = (uint ******)((int)ppppppuVar11 + -1);
        if (ppppppuVar14 == (uint ******)0xffffffff) goto LAB_0040b111;
        ppppppuVar1 = (uint ******)(&ppppppuStack_3a8 + (int)ppppppuVar11);
        ppppppuVar11 = ppppppuVar14;
      } while (*ppppppuVar1 == apppppuStack_574[(int)ppppppuVar14]);
      if (apppppuStack_574[(int)ppppppuVar14] < *ppppppuVar1) goto LAB_0040b111;
    }
    local_924 = (uint ******)((int)local_924 + 1);
  }
LAB_0040b111:
  uVar12 = (uint)ppppppuVar9 & 0x1f;
  uVar13 = (uint)ppppppuVar9 >> 5;
  local_948 = (uint ******)(0x20 - uVar12);
  local_92c = (uint ******)uVar12;
  lVar18 = __allshl((byte)local_948,0);
  pppppuVar10 = (uint *****)(&ppppppuStack_3a8)[(int)ppppppuVar15];
  local_938 = (uint ******)((int)lVar18 + -1);
  iVar6 = 0x1f;
  if (pppppuVar10 != (uint *****)0x0) {
    for (; (uint)pppppuVar10 >> iVar6 == 0; iVar6 = iVar6 + -1) {
    }
  }
  local_94c = ~(uint)local_938;
  local_934 = (uint ******)0x0;
  if (pppppuVar10 == (uint *****)0x0) {
    iVar6 = 0;
  }
  else {
    iVar6 = iVar6 + 1;
  }
  if ((uVar13 + (int)ppppppuVar15 < 0x74) &&
     (local_928 = (uint ******)((0x20U - iVar6 < uVar12) + uVar13 + (int)ppppppuVar15),
     local_928 < (uint ******)0x74)) {
    local_930 = (uint ******)((int)local_928 + -1);
    if (local_930 != (uint ******)(uVar13 - 1)) {
      ppppppuVar9 = (uint ******)((int)local_930 - uVar13);
      ppppppuVar14 = (uint ******)(&ppppppuStack_3a8 + (int)ppppppuVar9);
      do {
        if (ppppppuVar9 < ppppppuVar15) {
          local_934 = (uint ******)ppppppuVar14[1];
        }
        else {
          local_934 = (uint ******)0x0;
        }
        if ((uint ******)((int)ppppppuVar9 + -1) < ppppppuVar15) {
          pppppuVar10 = *ppppppuVar14;
        }
        else {
          pppppuVar10 = (uint *****)0x0;
        }
        ppppppuVar14 = ppppppuVar14 + -1;
        (&ppppppuStack_3a8)[(int)local_930 + 1] =
             (uint ******)
             (((uint)pppppuVar10 & local_94c) >> ((byte)local_948 & 0x1f) |
             ((uint)local_934 & (uint)local_938) << ((byte)local_92c & 0x1f));
        local_930 = (uint ******)((int)local_930 + -1);
        ppppppuVar9 = (uint ******)((int)ppppppuVar9 + -1);
        ppppppuVar15 = ppppppuStack_3a8;
      } while (local_930 != (uint ******)(uVar13 - 1));
    }
    ppppppuStack_3a8 = local_928;
    if (uVar13 != 0) {
      ppppppuVar15 = (uint ******)&ppppppuStack_3a8;
      for (; ppppppuVar15 = ppppppuVar15 + 1, uVar13 != 0; uVar13 = uVar13 - 1) {
        *ppppppuVar15 = (uint *****)0x0;
      }
    }
  }
  else {
    ppppppuStack_3a8 = (uint ******)0x0;
    _memcpy_s(&ppppppuStack_3a8 + 1,0x1cc,local_b2c,0);
  }
  uVar19 = FUN_0040b470((uint *)&ppppppuStack_3a8,(uint *)&ppppppuStack_578);
  uVar12 = (uint)(uVar19 >> 0x20);
  uVar13 = (uint)uVar19;
  local_92c = (uint ******)CONCAT31(local_92c._1_3_,ppppppuStack_3a8 == (uint ******)0x0);
  if (uVar12 == 0) {
    iVar6 = 0x1f;
    if (uVar13 != 0) {
      for (; uVar13 >> iVar6 == 0; iVar6 = iVar6 + -1) {
      }
    }
    if (uVar13 == 0) {
      ppppppuVar15 = (uint ******)0x0;
    }
    else {
      ppppppuVar15 = (uint ******)(iVar6 + 1);
    }
  }
  else {
    iVar6 = 0x1f;
    if (uVar12 != 0) {
      for (; uVar12 >> iVar6 == 0; iVar6 = iVar6 + -1) {
      }
    }
    if (uVar12 == 0) {
      iVar6 = 0;
    }
    else {
      iVar6 = iVar6 + 1;
    }
    ppppppuVar15 = (uint ******)(iVar6 + 0x20);
  }
  if (local_954 < ppppppuVar15) {
    bVar7 = (char)ppppppuVar15 - (char)local_954;
    if (ppppppuStack_3a8 == (uint ******)0x0) {
      lVar18 = __allshl(bVar7,0);
      local_92c = (uint ******)CONCAT31(local_92c._1_3_,1);
      if ((lVar18 - 1U & uVar19) != 0) goto LAB_0040b2da;
    }
    else {
LAB_0040b2da:
      local_92c = (uint ******)((uint)local_92c & 0xffffff00);
    }
    uVar19 = __aullshr(bVar7,uVar12);
  }
  lVar18 = __allshl((byte)local_954,-(uint)((uint ******)0x1 < local_91c) & (uint)local_1d4[1]);
  if (local_940 == (uint ******)0x0) {
    uVar13 = ~(uint)local_924;
  }
  else {
    uVar13 = (int)local_940 - 2;
  }
  FUN_004090e5((uint)(uVar19 + lVar18),(uint)(uVar19 + lVar18 >> 0x20),uVar13,
               *(bool *)(local_950 + 0xc2),(char)local_92c,local_958);
LAB_0040b39c:
  FUN_00402125(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



// WARNING: Removing unreachable block (ram,0x0040b3f6)

void __cdecl FUN_0040b3ab(int *param_1,floating_point_value *param_2)

{
  byte bVar1;
  uint uVar2;
  int *piVar3;
  int iVar4;
  int *piVar5;
  uint uVar6;
  uint uVar7;
  bool bVar8;
  ulonglong uVar9;
  uint local_8;
  
  uVar6 = 0;
  piVar5 = param_1 + 2;
  local_8 = 0;
  piVar3 = (int *)(param_1[1] + 8 + (int)param_1);
  iVar4 = ((param_2[4] == (floating_point_value)0x0) - 1 & 0x1d) + 0x17 + *param_1;
  for (; (piVar5 != piVar3 && (uVar9 = FUN_0040ba95((int)param_2), CONCAT44(local_8,uVar6) <= uVar9)
         ); local_8 = (local_8 << 4 | uVar2) + (uint)CARRY4(uVar7,(uint)bVar1)) {
    bVar1 = *(byte *)piVar5;
    piVar5 = (int *)((int)piVar5 + 1);
    uVar2 = uVar6 >> 0x1c;
    uVar7 = uVar6 * 0x10;
    uVar6 = uVar7 + bVar1;
    iVar4 = iVar4 + -4;
  }
  bVar8 = true;
  while ((piVar5 != piVar3 && (bVar8))) {
    bVar1 = *(byte *)piVar5;
    piVar5 = (int *)((int)piVar5 + 1);
    bVar8 = bVar1 == 0;
  }
  FUN_004090e5(uVar6,local_8,iVar4,*(bool *)(param_1 + 0xc2),bVar8,param_2);
  return;
}



undefined8 __fastcall FUN_0040b451(int param_1)

{
  if (*(char *)(param_1 + 4) != '\0') {
    return 0xfffffffffffff;
  }
  return 0x7fffff;
}



// WARNING: Removing unreachable block (ram,0x0040b7d8)
// WARNING: Removing unreachable block (ram,0x0040b7b3)

ulonglong __cdecl FUN_0040b470(uint *param_1,uint *param_2)

{
  uint uVar1;
  uint *puVar2;
  byte bVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  uint *puVar7;
  uint uVar8;
  uint uVar9;
  bool bVar10;
  undefined8 uVar11;
  undefined8 uVar12;
  longlong lVar13;
  ulonglong uVar14;
  undefined local_220 [460];
  int iStack_54;
  uint uStack_50;
  uint uStack_4c;
  undefined8 uStack_48;
  uint *puStack_40;
  uint uStack_3c;
  uint uStack_38;
  uint uStack_34;
  int iStack_30;
  uint uStack_28;
  uint local_24;
  int iStack_20;
  uint *local_1c;
  uint local_18;
  uint uStack_14;
  uint local_10;
  uint local_c;
  uint local_8;
  
  local_c = *param_1;
  if ((local_c != 0) && (local_18 = *param_2, local_18 != 0)) {
    uVar1 = local_c - 1;
    uVar8 = local_18 - 1;
    local_10 = uVar1;
    if (uVar8 == 0) {
      uVar8 = param_2[1];
      if (uVar8 == 1) {
        uVar1 = param_1[1];
        *param_1 = 0;
        _memcpy_s(param_1 + 1,0x1cc,local_220,0);
        return (ulonglong)uVar1;
      }
      if (uVar1 != 0) {
        local_10 = 0;
        local_8 = 0;
        uVar12 = 0;
        uVar11 = 0;
        if (uVar1 != 0xffffffff) {
          local_1c = param_1 + local_c;
          do {
            local_18 = (uint)((ulonglong)uVar12 >> 0x20);
            uVar1 = *local_1c;
            uVar11 = __aulldiv(uVar1,(uint)uVar12,uVar8,0);
            local_8 = local_10;
            local_10 = (int)uVar11;
            uVar12 = __aullrem(uVar1,(uint)uVar12,uVar8,0);
            local_1c = local_1c + -1;
            local_c = local_c - 1;
          } while (local_c != 0);
          local_c = 0;
          uVar11 = uVar12;
        }
        local_18 = (uint)((ulonglong)uVar11 >> 0x20);
        *param_1 = 0;
        _memcpy_s(param_1 + 1,0x1cc,local_220,0);
        param_1[1] = (uint)uVar11;
        param_1[2] = local_18;
        *param_1 = (local_18 != 0) + 1;
        return CONCAT44(local_8,local_10);
      }
      uVar1 = param_1[1];
      *param_1 = 0;
      _memcpy_s(param_1 + 1,0x1cc,local_220,0);
      uVar5 = uVar1 % uVar8;
      param_1[1] = uVar5;
      *param_1 = (uint)(uVar5 != 0);
      return (ulonglong)uVar1 / (ulonglong)uVar8;
    }
    if (uVar8 <= uVar1) {
      iVar6 = uVar1 - uVar8;
      if (iVar6 <= (int)uVar1) {
        puVar2 = param_1 + local_c;
        puVar7 = param_2 + local_18;
        do {
          if (*puVar7 != *puVar2) {
            if (*puVar2 <= *puVar7) goto LAB_0040b61b;
            break;
          }
          uVar1 = uVar1 - 1;
          puVar7 = puVar7 + -1;
          puVar2 = puVar2 + -1;
        } while (iVar6 <= (int)uVar1);
      }
      iVar6 = iVar6 + 1;
LAB_0040b61b:
      if (iVar6 != 0) {
        local_24 = param_2[local_18 - 1];
        uStack_34 = param_2[local_18];
        iStack_20 = 0x1f;
        if (uStack_34 != 0) {
          for (; uStack_34 >> iStack_20 == 0; iStack_20 = iStack_20 + -1) {
          }
        }
        if (uStack_34 == 0) {
          iStack_20 = 0x20;
        }
        else {
          iStack_20 = 0x1f - iStack_20;
        }
        iStack_30 = 0x20 - iStack_20;
        if (iStack_20 != 0) {
          uStack_34 = uStack_34 << ((byte)iStack_20 & 0x1f) | local_24 >> ((byte)iStack_30 & 0x1f);
          local_24 = local_24 << ((byte)iStack_20 & 0x1f);
          if (2 < local_18) {
            local_24 = local_24 | param_2[local_18 - 2] >> ((byte)iStack_30 & 0x1f);
          }
        }
        iStack_54 = iVar6 + -1;
        uStack_50 = 0;
        if (iStack_54 < 0) {
          uVar1 = 0;
          uStack_50 = 0;
        }
        else {
          uStack_3c = iStack_54 + local_18;
          puStack_40 = param_1 + iVar6;
          local_1c = param_1 + (uStack_3c - 1);
          uVar1 = uStack_50;
          do {
            uStack_50 = uVar1;
            if (local_10 < uStack_3c) {
              uStack_4c = 0;
            }
            else {
              uStack_4c = local_1c[2];
            }
            local_8 = local_1c[1];
            uVar1 = *local_1c;
            uStack_28 = uStack_4c;
            local_c = uVar1;
            if (iStack_20 != 0) {
              bVar3 = (byte)iStack_30;
              lVar13 = __allshl((byte)iStack_20,uStack_4c);
              uStack_28 = (uint)((ulonglong)lVar13 >> 0x20);
              local_8 = (uint)lVar13 | uVar1 >> (bVar3 & 0x1f);
              local_c = uVar1 << ((byte)iStack_20 & 0x1f);
              if (2 < uStack_3c) {
                local_c = local_c | local_1c[-1] >> ((byte)iStack_30 & 0x1f);
              }
            }
            uVar8 = uStack_34;
            uStack_48 = __aulldiv(local_8,uStack_28,uStack_34,0);
            uStack_14 = (uint)(uStack_48 >> 0x20);
            uVar1 = (uint)uStack_48;
            uStack_38 = uVar1;
            uVar14 = __aullrem(local_8,uStack_28,uVar8,0);
            uVar14 = uVar14 & 0xffffffff;
            local_8 = 0;
            if (uStack_14 != 0) {
              lVar13 = __allmul(uVar1 + 1,(uStack_14 - 1) + (uint)(0xfffffffe < uVar1),uStack_34,0);
              uVar14 = lVar13 + uVar14;
              local_8 = (uint)(uVar14 >> 0x20);
              uVar1 = 0xffffffff;
              uStack_38 = 0xffffffff;
              uStack_14 = 0;
              uStack_48 = 0xffffffff;
            }
            uVar5 = (uint)uVar14;
            uVar8 = uStack_38;
            if ((int)(uVar14 >> 0x20) == 0) {
              while( true ) {
                uStack_28 = local_c;
                uVar14 = __allmul(local_24,0,uVar1,uStack_14);
                uVar8 = uVar1;
                if (uVar14 <= CONCAT44(uVar5,uStack_28)) break;
                bVar10 = uVar1 != 0;
                uVar1 = uVar1 - 1;
                uStack_14 = (uStack_14 - 1) + (uint)bVar10;
                bVar10 = CARRY4(uVar5,uStack_34);
                uVar5 = uVar5 + uStack_34;
                uStack_48 = CONCAT44(uStack_14,uVar1);
                uVar8 = uVar1;
                if (local_8 + bVar10 != 0) break;
                local_8 = 0;
              }
            }
            uStack_38 = uVar8;
            if ((uStack_14 != 0) || (uVar1 != 0)) {
              uVar5 = 0;
              uVar8 = 0;
              if (local_18 != 0) {
                puVar2 = param_2 + 1;
                local_8 = local_18;
                puVar7 = puStack_40;
                do {
                  lVar13 = (uStack_48 & 0xffffffff) * (ulonglong)*puVar2;
                  uVar1 = (uint)lVar13;
                  uVar9 = uVar5 + uVar1;
                  uVar5 = uVar8 + (int)((ulonglong)lVar13 >> 0x20) + uStack_48._4_4_ * *puVar2 +
                          (uint)CARRY4(uVar5,uVar1);
                  uVar8 = 0;
                  if (*puVar7 < uVar9) {
                    bVar10 = 0xfffffffe < uVar5;
                    uVar5 = uVar5 + 1;
                    uVar8 = (uint)bVar10;
                  }
                  *puVar7 = *puVar7 - uVar9;
                  puVar7 = puVar7 + 1;
                  puVar2 = puVar2 + 1;
                  local_8 = local_8 - 1;
                  uVar1 = uStack_38;
                } while (local_8 != 0);
              }
              if ((uVar8 != 0) || (uStack_4c < uVar5)) {
                if (local_18 != 0) {
                  uVar5 = 0;
                  puVar7 = puStack_40;
                  puVar2 = param_2 + 1;
                  uVar8 = local_18;
                  do {
                    uVar1 = *puVar7;
                    uVar9 = *puVar2;
                    uVar4 = uVar1 + *puVar2;
                    *puVar7 = uVar4 + uVar5;
                    uVar5 = (uint)CARRY4(uVar1,uVar9) + (uint)CARRY4(uVar4,uVar5);
                    uVar8 = uVar8 - 1;
                    puVar7 = puVar7 + 1;
                    uVar1 = uStack_38;
                    puVar2 = puVar2 + 1;
                  } while (uVar8 != 0);
                }
                uVar1 = uVar1 - 1;
              }
              local_10 = uStack_3c - 1;
            }
            puStack_40 = puStack_40 + -1;
            iStack_54 = iStack_54 + -1;
            uStack_3c = uStack_3c - 1;
            local_1c = local_1c + -1;
          } while (-1 < iStack_54);
        }
        uVar8 = local_10 + 1;
        if (uVar8 < *param_1) {
          puVar7 = param_1 + local_10 + 2;
          uVar5 = uVar8;
          do {
            *puVar7 = 0;
            puVar7 = puVar7 + 1;
            uVar5 = uVar5 + 1;
          } while (uVar5 < *param_1);
        }
        *param_1 = uVar8;
        while ((uVar8 != 0 && (param_1[uVar8] == 0))) {
          uVar8 = uVar8 - 1;
          *param_1 = uVar8;
        }
        return CONCAT44(uStack_50,uVar1);
      }
    }
  }
  return 0;
}



// Library Function - Single Match
//  public: char __thiscall __crt_strtox::input_adapter_character_source<class
// __crt_stdio_input::stream_input_adapter<char> >::get(void)
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

char __thiscall
__crt_strtox::input_adapter_character_source<>::get(input_adapter_character_source<> *this)

{
  FILE **ppFVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  
  uVar3 = *(uint *)(this + 0x10) + 1;
  uVar4 = *(int *)(this + 0x14) + (uint)(0xfffffffe < *(uint *)(this + 0x10));
  *(uint *)(this + 0x10) = uVar3;
  *(uint *)(this + 0x14) = uVar4;
  if (((*(uint *)(this + 8) | *(uint *)(this + 0xc)) == 0) ||
     ((uVar4 <= *(uint *)(this + 0xc) &&
      ((uVar4 < *(uint *)(this + 0xc) || (uVar3 <= *(uint *)(this + 8))))))) {
    ppFVar1 = *(FILE ***)this;
    iVar2 = FUN_0040cb0c(*ppFVar1);
    if (iVar2 != -1) {
      ppFVar1 = ppFVar1 + 1;
      *ppFVar1 = (FILE *)((int)&(*ppFVar1)->_ptr + 1);
      return (char)iVar2;
    }
  }
  return '\0';
}



// Library Function - Single Match
//  public: char __thiscall __crt_strtox::input_adapter_character_source<class
// __crt_stdio_input::string_input_adapter<char> >::get(void)
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

char __thiscall
__crt_strtox::input_adapter_character_source<>::get(input_adapter_character_source<> *this)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  
  uVar2 = *(uint *)(this + 0x10) + 1;
  uVar3 = *(int *)(this + 0x14) + (uint)(0xfffffffe < *(uint *)(this + 0x10));
  *(uint *)(this + 0x10) = uVar2;
  *(uint *)(this + 0x14) = uVar3;
  if (((*(uint *)(this + 8) | *(uint *)(this + 0xc)) == 0) ||
     ((uVar3 <= *(uint *)(this + 0xc) &&
      ((uVar3 < *(uint *)(this + 0xc) || (uVar2 <= *(uint *)(this + 8))))))) {
    iVar1 = __crt_stdio_input::string_input_adapter<char>::get(*(string_input_adapter<char> **)this)
    ;
    if (iVar1 != -1) goto LAB_0040b98f;
  }
  iVar1 = 0;
LAB_0040b98f:
  return (char)iVar1;
}



// Library Function - Single Match
//  public: int __thiscall __crt_stdio_input::string_input_adapter<char>::get(void)
// 
// Library: Visual Studio 2019 Release

int __thiscall __crt_stdio_input::string_input_adapter<char>::get(string_input_adapter<char> *this)

{
  byte bVar1;
  byte *pbVar2;
  
  pbVar2 = *(byte **)(this + 8);
  if (pbVar2 == *(byte **)(this + 4)) {
    return -1;
  }
  bVar1 = *pbVar2;
  *(byte **)(this + 8) = pbVar2 + 1;
  return (uint)bVar1;
}



uint __thiscall FUN_0040b9a7(void *this,int param_1,uint param_2)

{
  uint in_EAX;
  uint uVar1;
  bool bVar2;
  
  if (param_2 == 0xffffffff) goto LAB_0040b9f0;
  if (param_1 == 0) {
LAB_0040b9ec:
    uVar1 = CONCAT31((int3)((uint)param_1 >> 8),1);
  }
  else {
    if (param_1 == 1) {
      in_EAX = 0;
      if (((int)param_2 < 9) || (0xd < (int)param_2)) {
        bVar2 = param_2 == 0x20;
        goto LAB_0040b9ea;
      }
    }
    else {
      in_EAX = param_1 - 8;
      if (in_EAX == 0) {
        in_EAX = param_1 + -7 << ((byte)param_2 & 7);
        bVar2 = (*(byte *)(((param_2 & 0xff) >> 3) + 0x3c + (int)this) & (byte)in_EAX) == 0;
LAB_0040b9ea:
        param_1 = in_EAX;
        if (!bVar2) goto LAB_0040b9ec;
      }
    }
LAB_0040b9f0:
    uVar1 = in_EAX & 0xffffff00;
  }
  return uVar1;
}



uint __thiscall FUN_0040b9f7(void *this,int param_1,uint param_2)

{
  uint in_EAX;
  uint uVar1;
  bool bVar2;
  
  if (param_2 == 0xffffffff) goto LAB_0040ba40;
  if (param_1 == 0) {
LAB_0040ba3c:
    uVar1 = CONCAT31((int3)((uint)param_1 >> 8),1);
  }
  else {
    if (param_1 == 1) {
      in_EAX = 0;
      if (((int)param_2 < 9) || (0xd < (int)param_2)) {
        bVar2 = param_2 == 0x20;
        goto LAB_0040ba3a;
      }
    }
    else {
      in_EAX = param_1 - 8;
      if (in_EAX == 0) {
        in_EAX = param_1 + -7 << ((byte)param_2 & 7);
        bVar2 = (*(byte *)(((param_2 & 0xff) >> 3) + 0x44 + (int)this) & (byte)in_EAX) == 0;
LAB_0040ba3a:
        param_1 = in_EAX;
        if (!bVar2) goto LAB_0040ba3c;
      }
    }
LAB_0040ba40:
    uVar1 = in_EAX & 0xffffff00;
  }
  return uVar1;
}



uint __fastcall FUN_0040ba47(int param_1)

{
  uint uVar1;
  
  switch(*(undefined4 *)(param_1 + 0x28)) {
  case 0:
  case 1:
  case 8:
    return (*(char *)(param_1 + 0x24) != '\0') + 1;
  case 2:
  case 3:
  case 4:
  case 5:
  case 6:
  case 9:
    uVar1 = __crt_stdio_input::to_integer_length(*(length_modifier *)(param_1 + 0x20));
    return uVar1;
  case 7:
    uVar1 = __crt_stdio_input::to_floating_point_length(*(length_modifier *)(param_1 + 0x20));
    return uVar1;
  default:
    return 0;
  }
}



undefined8 __fastcall FUN_0040ba95(int param_1)

{
  if (*(char *)(param_1 + 4) != '\0') {
    return 0x1fffffffffffff;
  }
  return 0xffffff;
}



// Library Function - Single Match
//  public: int __thiscall __crt_stdio_input::input_processor<char,class
// __crt_stdio_input::stream_input_adapter<char> >::process(void)
// 
// Library: Visual Studio 2019 Release

int __thiscall __crt_stdio_input::input_processor<>::process(input_processor<> *this)

{
  FILE **this_00;
  bool bVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  
  this_00 = (FILE **)(this + 8);
  bVar1 = stream_input_adapter<char>::validate((stream_input_adapter<char> *)this_00);
  if (bVar1) {
    bVar1 = format_string_parser<char>::validate((format_string_parser<char> *)(this + 0x10));
    if (bVar1) {
      do {
        bVar1 = format_string_parser<char>::advance((format_string_parser<char> *)(this + 0x10));
        if (!bVar1) break;
        bVar1 = process_state(this);
      } while (bVar1);
      iVar4 = *(int *)(this + 0x68);
      if ((iVar4 == 0) && (*(int *)(this + 0x20) != 1)) {
        iVar2 = FUN_0040cb0c(*this_00);
        if (iVar2 == -1) {
          iVar4 = -1;
        }
        else {
          *(int *)(this + 0xc) = *(int *)(this + 0xc) + 1;
        }
        stream_input_adapter<char>::unget((stream_input_adapter<char> *)this_00,iVar2);
      }
      if ((*(uint *)this & 1) == 0) {
        return iVar4;
      }
      iVar2 = *(int *)(this + 0x1c);
      if (iVar2 == 0) {
        return iVar4;
      }
      piVar3 = (int *)FUN_0040e304();
      *piVar3 = iVar2;
      FUN_0040e223();
      return iVar4;
    }
  }
  return -1;
}



// Library Function - Single Match
//  public: int __thiscall __crt_stdio_input::input_processor<char,class
// __crt_stdio_input::string_input_adapter<char> >::process(void)
// 
// Library: Visual Studio 2019 Release

int __thiscall __crt_stdio_input::input_processor<>::process(input_processor<> *this)

{
  string_input_adapter<char> *this_00;
  bool bVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  
  this_00 = (string_input_adapter<char> *)(this + 8);
  bVar1 = string_input_adapter<char>::validate(this_00);
  if (bVar1) {
    bVar1 = format_string_parser<char>::validate((format_string_parser<char> *)(this + 0x18));
    if (bVar1) {
      do {
        bVar1 = format_string_parser<char>::advance((format_string_parser<char> *)(this + 0x18));
        if (!bVar1) break;
        bVar1 = process_state(this);
      } while (bVar1);
      iVar4 = *(int *)(this + 0x70);
      if ((iVar4 == 0) && (*(int *)(this + 0x28) != 1)) {
        iVar2 = string_input_adapter<char>::get(this_00);
        if (iVar2 == -1) {
          iVar4 = -1;
        }
        string_input_adapter<char>::unget(this_00,iVar2);
      }
      if ((*(uint *)this & 1) == 0) {
        return iVar4;
      }
      iVar2 = *(int *)(this + 0x24);
      if (iVar2 == 0) {
        return iVar4;
      }
      piVar3 = (int *)FUN_0040e304();
      *piVar3 = iVar2;
      FUN_0040e223();
      return iVar4;
    }
  }
  return -1;
}



// Library Function - Single Match
//  private: bool __thiscall __crt_stdio_input::input_processor<char,class
// __crt_stdio_input::stream_input_adapter<char> >::process_character_count_specifier(void)
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

bool __thiscall
__crt_stdio_input::input_processor<>::process_character_count_specifier(input_processor<> *this)

{
  undefined4 uVar1;
  
  if (this[0x26] != (input_processor<>)0x0) {
    return true;
  }
  uVar1 = FUN_0040c846(this,*(undefined4 *)(this + 0xc),0);
  return SUB41(uVar1,0);
}



// Library Function - Multiple Matches With Same Base Name
//  private: bool __thiscall __crt_stdio_input::input_processor<char,class
// __crt_stdio_input::console_input_adapter<char> >::process_conversion_specifier(void)
//  private: bool __thiscall __crt_stdio_input::input_processor<char,class
// __crt_stdio_input::stream_input_adapter<char> >::process_conversion_specifier(void)
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

uint __fastcall process_conversion_specifier(input_processor<> *param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  uint uVar2;
  undefined3 extraout_var_00;
  undefined3 extraout_var_01;
  undefined in_DL;
  undefined4 uVar3;
  conversion_mode cVar4;
  undefined4 uVar5;
  
  switch(*(uint *)(param_1 + 0x38)) {
  case 0:
    cVar4 = 0;
    goto LAB_0040bbf8;
  case 1:
    cVar4 = 1;
    goto LAB_0040bbf8;
  case 2:
    uVar5 = 1;
    uVar3 = 0;
    break;
  case 3:
    uVar5 = 1;
    goto LAB_0040bc12;
  case 4:
    uVar5 = 0;
    uVar3 = 8;
    break;
  case 5:
    uVar5 = 0;
LAB_0040bc12:
    uVar3 = 10;
    break;
  case 6:
    uVar5 = 0;
    uVar3 = 0x10;
    break;
  case 7:
    bVar1 = __crt_stdio_input::input_processor<>::process_floating_point_specifier(param_1);
    return CONCAT31(extraout_var_00,bVar1);
  case 8:
    cVar4 = 8;
LAB_0040bbf8:
    bVar1 = __crt_stdio_input::input_processor<>::process_string_specifier(param_1,cVar4);
    return CONCAT31(extraout_var,bVar1);
  case 9:
    bVar1 = __crt_stdio_input::input_processor<>::process_character_count_specifier(param_1);
    return CONCAT31(extraout_var_01,bVar1);
  default:
    return *(uint *)(param_1 + 0x38) & 0xffffff00;
  }
  uVar2 = FUN_0040bd2f(param_1,in_DL,uVar3,uVar5);
  return uVar2;
}



// Library Function - Multiple Matches With Same Base Name
//  private: bool __thiscall __crt_stdio_input::input_processor<char,class
// __crt_stdio_input::string_input_adapter<char> >::process_conversion_specifier(void)
//  private: bool __thiscall __crt_stdio_input::input_processor<wchar_t,class
// __crt_stdio_input::console_input_adapter<wchar_t> >::process_conversion_specifier(void)
//  private: bool __thiscall __crt_stdio_input::input_processor<wchar_t,class
// __crt_stdio_input::stream_input_adapter<wchar_t> >::process_conversion_specifier(void)
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

uint __fastcall process_conversion_specifier(input_processor<> *param_1)

{
  bool bVar1;
  uint uVar2;
  uint3 uVar3;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  undefined in_DL;
  undefined4 uVar4;
  conversion_mode cVar5;
  undefined4 uVar6;
  
  uVar3 = (uint3)((uint)*(undefined4 *)(param_1 + 0x40) >> 8);
  switch(*(undefined4 *)(param_1 + 0x40)) {
  case 0:
    cVar5 = 0;
    goto LAB_0040bc6c;
  case 1:
    cVar5 = 1;
    goto LAB_0040bc6c;
  case 2:
    uVar6 = 1;
    uVar4 = 0;
    break;
  case 3:
    uVar6 = 1;
    goto LAB_0040bc86;
  case 4:
    uVar6 = 0;
    uVar4 = 8;
    break;
  case 5:
    uVar6 = 0;
LAB_0040bc86:
    uVar4 = 10;
    break;
  case 6:
    uVar6 = 0;
    uVar4 = 0x10;
    break;
  case 7:
    bVar1 = __crt_stdio_input::input_processor<>::process_floating_point_specifier(param_1);
    return CONCAT31(extraout_var_00,bVar1);
  case 8:
    cVar5 = 8;
LAB_0040bc6c:
    bVar1 = __crt_stdio_input::input_processor<>::process_string_specifier(param_1,cVar5);
    return CONCAT31(extraout_var,bVar1);
  case 9:
    if (param_1[0x2e] == (input_processor<>)0x0) {
      uVar2 = FUN_0040c8b5(param_1,*(int *)(param_1 + 0x10) - *(int *)(param_1 + 8),0);
      return uVar2;
    }
    return CONCAT31(uVar3,1);
  default:
    return (uint)uVar3 << 8;
  }
  uVar2 = FUN_0040bd94(param_1,in_DL,uVar4,uVar6);
  return uVar2;
}



// Library Function - Single Match
//  private: bool __thiscall __crt_stdio_input::input_processor<char,class
// __crt_stdio_input::stream_input_adapter<char> >::process_floating_point_specifier(void)
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

bool __thiscall
__crt_stdio_input::input_processor<>::process_floating_point_specifier(input_processor<> *this)

{
  uint uVar1;
  
  process_whitespace(this);
  uVar1 = FUN_0040ba47((int)(this + 0x10));
  if (uVar1 == 4) {
    uVar1 = FUN_004083f6(this);
    return SUB41(uVar1,0);
  }
  if (uVar1 != 8) {
    return false;
  }
  uVar1 = FUN_004084c8(this);
  return SUB41(uVar1,0);
}



// Library Function - Single Match
//  private: bool __thiscall __crt_stdio_input::input_processor<char,class
// __crt_stdio_input::string_input_adapter<char> >::process_floating_point_specifier(void)
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

bool __thiscall
__crt_stdio_input::input_processor<>::process_floating_point_specifier(input_processor<> *this)

{
  uint uVar1;
  
  process_whitespace(this);
  uVar1 = FUN_0040ba47((int)(this + 0x18));
  if (uVar1 == 4) {
    uVar1 = FUN_0040845f(this);
    return SUB41(uVar1,0);
  }
  if (uVar1 != 8) {
    return false;
  }
  uVar1 = FUN_00408531(this);
  return SUB41(uVar1,0);
}



int __fastcall
FUN_0040bd2f(input_processor<> *param_1,undefined param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 *puVar1;
  uint3 uVar3;
  int iVar2;
  ulonglong uVar4;
  undefined auStack_3c [28];
  undefined4 uStack_20;
  undefined4 uStack_8;
  
  uStack_8 = param_1;
  __crt_stdio_input::input_processor<>::process_whitespace(param_1);
  puVar1 = *(undefined4 **)(param_1 + 0x60);
  uStack_8 = (input_processor<> *)((uint)uStack_8 & 0xffffff);
  FUN_00406b26(auStack_3c,param_1 + 8,*(undefined4 *)(param_1 + 0x28),
               *(undefined4 *)(param_1 + 0x2c),(undefined *)((int)&uStack_8 + 3));
  uVar4 = FUN_0040803a(puVar1);
  uVar3 = (uint3)(uVar4 >> 8);
  if (uStack_8._3_1_ == '\0') {
    iVar2 = (uint)uVar3 << 8;
  }
  else if (param_1[0x26] == (input_processor<>)0x0) {
    uStack_20 = 0x40bd8e;
    iVar2 = FUN_0040c846(param_1,(int)uVar4,(int)(uVar4 >> 0x20));
  }
  else {
    iVar2 = CONCAT31(uVar3,1);
  }
  return iVar2;
}



int __fastcall
FUN_0040bd94(input_processor<> *param_1,undefined param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 *puVar1;
  uint3 uVar3;
  int iVar2;
  ulonglong uVar4;
  undefined auStack_3c [28];
  undefined4 uStack_20;
  undefined4 uStack_8;
  
  uStack_8 = param_1;
  __crt_stdio_input::input_processor<>::process_whitespace(param_1);
  puVar1 = *(undefined4 **)(param_1 + 0x68);
  uStack_8 = (input_processor<> *)((uint)uStack_8 & 0xffffff);
  FUN_00406b26(auStack_3c,param_1 + 8,*(undefined4 *)(param_1 + 0x30),
               *(undefined4 *)(param_1 + 0x34),(undefined *)((int)&uStack_8 + 3));
  uVar4 = FUN_0040839a(puVar1);
  uVar3 = (uint3)(uVar4 >> 8);
  if (uStack_8._3_1_ == '\0') {
    iVar2 = (uint)uVar3 << 8;
  }
  else if (param_1[0x2e] == (input_processor<>)0x0) {
    uStack_20 = 0x40bdf3;
    iVar2 = FUN_0040c8b5(param_1,(int)uVar4,(int)(uVar4 >> 0x20));
  }
  else {
    iVar2 = CONCAT31(uVar3,1);
  }
  return iVar2;
}



// Library Function - Single Match
//  private: bool __thiscall __crt_stdio_input::input_processor<char,class
// __crt_stdio_input::stream_input_adapter<char> >::process_literal_character(void)
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

bool __thiscall
__crt_stdio_input::input_processor<>::process_literal_character(input_processor<> *this)

{
  bool bVar1;
  uint uVar2;
  
  uVar2 = FUN_0040cb0c(*(FILE **)(this + 8));
  if (uVar2 != 0xffffffff) {
    *(int *)(this + 0xc) = *(int *)(this + 0xc) + 1;
    if (uVar2 == (byte)this[0x24]) {
      bVar1 = process_literal_character_tchar(this,(char)uVar2);
      return bVar1;
    }
    stream_input_adapter<char>::unget((stream_input_adapter<char> *)(this + 8),uVar2);
  }
  return false;
}



// Library Function - Single Match
//  private: bool __thiscall __crt_stdio_input::input_processor<char,class
// __crt_stdio_input::string_input_adapter<char> >::process_literal_character(void)
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

bool __thiscall
__crt_stdio_input::input_processor<>::process_literal_character(input_processor<> *this)

{
  bool bVar1;
  uint uVar2;
  
  uVar2 = string_input_adapter<char>::get((string_input_adapter<char> *)(this + 8));
  if (uVar2 != 0xffffffff) {
    if (uVar2 == (byte)this[0x2c]) {
      bVar1 = process_literal_character_tchar(this,(char)uVar2);
      return bVar1;
    }
    string_input_adapter<char>::unget((string_input_adapter<char> *)(this + 8),uVar2);
  }
  return false;
}



// Library Function - Single Match
//  private: bool __thiscall __crt_stdio_input::input_processor<char,class
// __crt_stdio_input::stream_input_adapter<char> >::process_literal_character_tchar(char)
// 
// Library: Visual Studio 2019 Release

bool __thiscall
__crt_stdio_input::input_processor<>::process_literal_character_tchar
          (input_processor<> *this,char param_1)

{
  FILE **this_00;
  ushort *puVar1;
  uint uVar2;
  
  puVar1 = ___pctype_func();
  if ((short)puVar1[(byte)param_1] < 0) {
    this_00 = (FILE **)(this + 8);
    uVar2 = FUN_0040cb0c(*this_00);
    if (uVar2 != 0xffffffff) {
      *(int *)(this + 0xc) = *(int *)(this + 0xc) + 1;
    }
    if (uVar2 != (byte)this[0x25]) {
      stream_input_adapter<char>::unget((stream_input_adapter<char> *)this_00,uVar2);
      stream_input_adapter<char>::unget((stream_input_adapter<char> *)this_00,(int)param_1);
      return false;
    }
  }
  return true;
}



// Library Function - Single Match
//  private: bool __thiscall __crt_stdio_input::input_processor<char,class
// __crt_stdio_input::string_input_adapter<char> >::process_literal_character_tchar(char)
// 
// Library: Visual Studio 2019 Release

bool __thiscall
__crt_stdio_input::input_processor<>::process_literal_character_tchar
          (input_processor<> *this,char param_1)

{
  string_input_adapter<char> *this_00;
  ushort *puVar1;
  uint uVar2;
  
  puVar1 = ___pctype_func();
  if ((short)puVar1[(byte)param_1] < 0) {
    this_00 = (string_input_adapter<char> *)(this + 8);
    uVar2 = string_input_adapter<char>::get(this_00);
    if (uVar2 != (byte)this[0x2d]) {
      string_input_adapter<char>::unget(this_00,uVar2);
      string_input_adapter<char>::unget(this_00,(int)param_1);
      return false;
    }
  }
  return true;
}



// Library Function - Single Match
//  private: bool __thiscall __crt_stdio_input::input_processor<char,class
// __crt_stdio_input::stream_input_adapter<char> >::process_state(void)
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

bool __thiscall __crt_stdio_input::input_processor<>::process_state(input_processor<> *this)

{
  int iVar1;
  undefined uVar2;
  bool bVar3;
  uint uVar4;
  
  iVar1 = *(int *)(this + 0x20);
  if (iVar1 == 2) {
    bVar3 = process_whitespace(this);
    return bVar3;
  }
  if (iVar1 != 3) {
    if (iVar1 == 4) {
      uVar4 = process_conversion_specifier(this);
      uVar2 = (undefined)uVar4;
      if ((((bool)uVar2 != false) && (*(int *)(this + 0x38) != 9)) &&
         (this[0x26] == (input_processor<>)0x0)) {
        *(int *)(this + 0x68) = *(int *)(this + 0x68) + 1;
        return (bool)uVar2;
      }
    }
    else {
      uVar2 = 0;
    }
    return (bool)uVar2;
  }
  bVar3 = process_literal_character(this);
  return bVar3;
}



// Library Function - Single Match
//  private: bool __thiscall __crt_stdio_input::input_processor<char,class
// __crt_stdio_input::string_input_adapter<char> >::process_state(void)
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

bool __thiscall __crt_stdio_input::input_processor<>::process_state(input_processor<> *this)

{
  int iVar1;
  undefined uVar2;
  bool bVar3;
  uint uVar4;
  
  iVar1 = *(int *)(this + 0x28);
  if (iVar1 == 2) {
    bVar3 = process_whitespace(this);
    return bVar3;
  }
  if (iVar1 != 3) {
    if (iVar1 == 4) {
      uVar4 = process_conversion_specifier(this);
      uVar2 = (undefined)uVar4;
      if ((((bool)uVar2 != false) && (*(int *)(this + 0x40) != 9)) &&
         (this[0x2e] == (input_processor<>)0x0)) {
        *(int *)(this + 0x70) = *(int *)(this + 0x70) + 1;
        return (bool)uVar2;
      }
    }
    else {
      uVar2 = 0;
    }
    return (bool)uVar2;
  }
  bVar3 = process_literal_character(this);
  return bVar3;
}



// Library Function - Single Match
//  private: bool __thiscall __crt_stdio_input::input_processor<char,class
// __crt_stdio_input::stream_input_adapter<char> >::process_string_specifier(enum
// __crt_stdio_input::conversion_mode)
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

bool __thiscall
__crt_stdio_input::input_processor<>::process_string_specifier
          (input_processor<> *this,conversion_mode param_1)

{
  undefined uVar1;
  uint uVar2;
  
  if (param_1 == 1) {
    process_whitespace(this);
  }
  uVar2 = FUN_0040ba47((int)(this + 0x10));
  if (uVar2 == 1) {
    uVar2 = FUN_0040859a(this,param_1);
    uVar1 = (undefined)uVar2;
  }
  else if (uVar2 == 2) {
    uVar2 = FUN_00408872(this,param_1);
    uVar1 = (undefined)uVar2;
  }
  else {
    uVar1 = 0;
  }
  return (bool)uVar1;
}



// Library Function - Single Match
//  private: bool __thiscall __crt_stdio_input::input_processor<char,class
// __crt_stdio_input::string_input_adapter<char> >::process_string_specifier(enum
// __crt_stdio_input::conversion_mode)
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

bool __thiscall
__crt_stdio_input::input_processor<>::process_string_specifier
          (input_processor<> *this,conversion_mode param_1)

{
  undefined uVar1;
  uint uVar2;
  
  if (param_1 == 1) {
    process_whitespace(this);
  }
  uVar2 = FUN_0040ba47((int)(this + 0x18));
  if (uVar2 == 1) {
    uVar2 = FUN_00408710(this,param_1);
    uVar1 = (undefined)uVar2;
  }
  else if (uVar2 == 2) {
    uVar2 = FUN_004089f4(this,param_1);
    uVar1 = (undefined)uVar2;
  }
  else {
    uVar1 = 0;
  }
  return (bool)uVar1;
}



// Library Function - Single Match
//  private: bool __thiscall __crt_stdio_input::input_processor<char,class
// __crt_stdio_input::stream_input_adapter<char> >::process_whitespace(void)
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

bool __thiscall __crt_stdio_input::input_processor<>::process_whitespace(input_processor<> *this)

{
  int iVar1;
  
  iVar1 = skip_whitespace<>((stream_input_adapter<char> *)(this + 8),
                            *(__crt_locale_pointers **)(this + 0x60));
  stream_input_adapter<char>::unget((stream_input_adapter<char> *)(this + 8),iVar1);
  return true;
}



// Library Function - Single Match
//  private: bool __thiscall __crt_stdio_input::input_processor<char,class
// __crt_stdio_input::string_input_adapter<char> >::process_whitespace(void)
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

bool __thiscall __crt_stdio_input::input_processor<>::process_whitespace(input_processor<> *this)

{
  int iVar1;
  
  iVar1 = skip_whitespace<>((string_input_adapter<char> *)(this + 8),
                            *(__crt_locale_pointers **)(this + 0x68));
  string_input_adapter<char>::unget((string_input_adapter<char> *)(this + 8),iVar1);
  return true;
}



// Library Function - Multiple Matches With Same Base Name
//  public: bool __thiscall __crt_strtox::input_adapter_character_source<class
// __crt_stdio_input::console_input_adapter<char> >::restore_state(unsigned __int64)
//  public: bool __thiscall __crt_strtox::input_adapter_character_source<class
// __crt_stdio_input::stream_input_adapter<char> >::restore_state(unsigned __int64)
//  public: bool __thiscall __crt_strtox::input_adapter_character_source<class
// __crt_stdio_input::string_input_adapter<char> >::restore_state(unsigned __int64)
// 
// Libraries: Visual Studio 2015, Visual Studio 2017, Visual Studio 2019

uint __thiscall restore_state(void *this,int param_1,int param_2)

{
  undefined *puVar1;
  uint uVar2;
  
  if ((param_1 == *(int *)((int)this + 0x10)) && (param_2 == *(int *)((int)this + 0x14))) {
    uVar2 = CONCAT31((int3)((uint)param_2 >> 8),1);
  }
  else {
    puVar1 = *(undefined **)((int)this + 0x18);
    *puVar1 = 0;
    uVar2 = (uint)puVar1 & 0xffffff00;
  }
  return uVar2;
}



uint __fastcall FUN_0040c07d(int param_1)

{
  uint uVar1;
  byte *pbVar2;
  
  uVar1 = (uint)**(byte **)(param_1 + 8);
  if (uVar1 < 0x65) {
    if (uVar1 == 100) {
      *(undefined4 *)(param_1 + 0x28) = 3;
    }
    else {
      if (0x49 < uVar1) {
        if (uVar1 == 0x53) {
LAB_0040c1cd:
          pbVar2 = (byte *)FUN_0040c581(param_1);
          *(undefined4 *)(param_1 + 0x28) = 1;
        }
        else {
          if (uVar1 == 0x58) goto LAB_0040c1e7;
          if (uVar1 == 0x5b) {
            FUN_0040c581(param_1);
            *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
            *(undefined4 *)(param_1 + 0x28) = 8;
            uVar1 = FUN_0040c41d(param_1);
            return uVar1;
          }
          if (uVar1 == 0x61) goto LAB_0040c0c2;
          uVar1 = uVar1 - 99;
          if (uVar1 != 0) goto LAB_0040c19e;
LAB_0040c0f4:
          if ((*(uint *)(param_1 + 0x18) | *(uint *)(param_1 + 0x1c)) == 0) {
            *(undefined4 *)(param_1 + 0x18) = 1;
            *(undefined4 *)(param_1 + 0x1c) = 0;
          }
          pbVar2 = (byte *)FUN_0040c581(param_1);
          *(undefined4 *)(param_1 + 0x28) = 0;
        }
        *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
        goto LAB_0040c1f4;
      }
      if (uVar1 == 0x49) {
LAB_0040c177:
        *(undefined4 *)(param_1 + 0x28) = 2;
      }
      else {
        if (uVar1 != 0x41) {
          if (uVar1 == 0x43) goto LAB_0040c0f4;
          if (((uVar1 != 0x45) && (uVar1 != 0x46)) && (uVar1 = uVar1 - 0x47, uVar1 != 0))
          goto LAB_0040c19e;
        }
LAB_0040c0c2:
        *(undefined4 *)(param_1 + 0x28) = 7;
      }
    }
  }
  else if (uVar1 < 0x70) {
    if (uVar1 == 0x6f) {
      *(undefined4 *)(param_1 + 0x28) = 4;
    }
    else {
      if (((uVar1 == 0x65) || (uVar1 == 0x66)) || (uVar1 == 0x67)) goto LAB_0040c0c2;
      if (uVar1 == 0x69) goto LAB_0040c177;
      uVar1 = uVar1 - 0x6e;
      if (uVar1 != 0) {
LAB_0040c19e:
        *(undefined4 *)(param_1 + 0xc) = 0x16;
        *(undefined4 *)(param_1 + 0x10) = 0;
        *(undefined2 *)(param_1 + 0x14) = 0;
        *(undefined *)(param_1 + 0x16) = 0;
        *(undefined4 *)(param_1 + 0x18) = 0;
        *(undefined4 *)(param_1 + 0x1c) = 0;
        *(undefined4 *)(param_1 + 0x20) = 0;
        *(undefined *)(param_1 + 0x24) = 0;
        *(undefined4 *)(param_1 + 0x28) = 0;
        return uVar1 & 0xffffff00;
      }
      *(undefined4 *)(param_1 + 0x28) = 9;
    }
  }
  else {
    if (uVar1 == 0x70) {
      *(undefined4 *)(param_1 + 0x20) = 9;
    }
    else {
      if (uVar1 == 0x73) goto LAB_0040c1cd;
      if (uVar1 == 0x75) {
        *(undefined4 *)(param_1 + 0x28) = 5;
        goto LAB_0040c1ee;
      }
      uVar1 = uVar1 - 0x78;
      if (uVar1 != 0) goto LAB_0040c19e;
    }
LAB_0040c1e7:
    *(undefined4 *)(param_1 + 0x28) = 6;
  }
LAB_0040c1ee:
  pbVar2 = *(byte **)(param_1 + 8) + 1;
  *(byte **)(param_1 + 8) = pbVar2;
LAB_0040c1f4:
  return CONCAT31((int3)((uint)pbVar2 >> 8),1);
}



int __fastcall FUN_0040c1f9(int param_1)

{
  char cVar1;
  uint uVar2;
  ulonglong uVar3;
  int local_8;
  
  cVar1 = **(char **)(param_1 + 8);
  if ((byte)(cVar1 - 0x30U) < 10) {
    uVar2 = (int)cVar1 - 0x30;
  }
  else if ((byte)(cVar1 + 0x9fU) < 0x1a) {
    uVar2 = (int)cVar1 - 0x57;
  }
  else {
    uVar2 = CONCAT31((int3)((uint)param_1 >> 8),cVar1) - 0x41;
    if (0x19 < (byte)uVar2) goto LAB_0040c263;
    uVar2 = (int)cVar1 - 0x37;
  }
  if (uVar2 < 10) {
    local_8 = 0;
    uVar3 = FUN_00410914(*(char **)(param_1 + 8),&local_8,10);
    uVar2 = (uint)uVar3;
    if ((uVar3 == 0) || (local_8 == *(int *)(param_1 + 8))) {
      *(undefined4 *)(param_1 + 0x10) = 0;
      *(undefined2 *)(param_1 + 0x14) = 0;
      *(undefined *)(param_1 + 0x16) = 0;
      *(undefined4 *)(param_1 + 0x18) = 0;
      *(undefined4 *)(param_1 + 0x1c) = 0;
      *(undefined4 *)(param_1 + 0x20) = 0;
      *(undefined *)(param_1 + 0x24) = 0;
      *(undefined4 *)(param_1 + 0x28) = 0;
      *(undefined4 *)(param_1 + 0xc) = 0x16;
      return (uint)(uint3)(uVar3 >> 8) << 8;
    }
    *(ulonglong *)(param_1 + 0x18) = uVar3;
    *(int *)(param_1 + 8) = local_8;
  }
LAB_0040c263:
  return CONCAT31((int3)(uVar2 >> 8),1);
}



void __fastcall FUN_0040c28d(int param_1)

{
  byte bVar1;
  byte *pbVar2;
  byte *pbVar3;
  
  pbVar2 = *(byte **)(param_1 + 8);
  bVar1 = *pbVar2;
  if (bVar1 < 0x6b) {
    if (bVar1 == 0x6a) {
      *(undefined4 *)(param_1 + 0x20) = 5;
      *(byte **)(param_1 + 8) = pbVar2 + 1;
      return;
    }
    if (bVar1 == 0x49) {
      bVar1 = pbVar2[1];
      if ((bVar1 == 0x33) && (pbVar2[2] == 0x32)) {
        *(byte **)(param_1 + 8) = pbVar2 + 3;
LAB_0040c30a:
        *(undefined4 *)(param_1 + 0x20) = 9;
        return;
      }
      if (bVar1 == 0x36) {
        if (pbVar2[2] == 0x34) {
          *(undefined4 *)(param_1 + 0x20) = 10;
          *(byte **)(param_1 + 8) = pbVar2 + 3;
          return;
        }
      }
      else if ((((bVar1 == 100) || (bVar1 == 0x69)) || (bVar1 == 0x6f)) ||
              (((bVar1 == 0x75 || (bVar1 == 0x78)) || (bVar1 == 0x58)))) {
        *(byte **)(param_1 + 8) = pbVar2 + 1;
        goto LAB_0040c30a;
      }
    }
    else {
      if (bVar1 == 0x4c) {
        *(undefined4 *)(param_1 + 0x20) = 8;
        *(byte **)(param_1 + 8) = pbVar2 + 1;
        return;
      }
      if (bVar1 == 0x54) {
        *(undefined4 *)(param_1 + 0x20) = 0xb;
        *(byte **)(param_1 + 8) = pbVar2 + 1;
        return;
      }
      if (bVar1 == 0x68) {
        pbVar3 = pbVar2 + 1;
        bVar1 = *pbVar3;
        if (bVar1 == 0x68) {
          pbVar3 = pbVar2 + 2;
        }
        *(byte **)(param_1 + 8) = pbVar3;
        *(uint *)(param_1 + 0x20) = (bVar1 != 0x68) + 1;
        return;
      }
    }
  }
  else if (bVar1 == 0x6c) {
    if (pbVar2[1] == 0x6c) {
      *(undefined4 *)(param_1 + 0x20) = 4;
      *(byte **)(param_1 + 8) = pbVar2 + 2;
      return;
    }
    *(byte **)(param_1 + 8) = pbVar2 + 1;
    *(undefined4 *)(param_1 + 0x20) = 3;
  }
  else {
    if (bVar1 == 0x74) {
      *(undefined4 *)(param_1 + 0x20) = 7;
      *(byte **)(param_1 + 8) = pbVar2 + 1;
      return;
    }
    if (bVar1 == 0x7a) {
      *(undefined4 *)(param_1 + 0x20) = 6;
      *(byte **)(param_1 + 8) = pbVar2 + 1;
      return;
    }
  }
  return;
}



// Library Function - Single Match
//  private: bool __thiscall
// __crt_stdio_input::format_string_parser<char>::scan_optional_literal_character_trail_bytes_tchar(char)
// 
// Library: Visual Studio 2019 Release

bool __thiscall
__crt_stdio_input::format_string_parser<char>::scan_optional_literal_character_trail_bytes_tchar
          (format_string_parser<char> *this,char param_1)

{
  format_string_parser<char> fVar1;
  ushort *puVar2;
  
  puVar2 = ___pctype_func();
  if ((short)puVar2[(byte)this[0x14]] < 0) {
    fVar1 = **(format_string_parser<char> **)(this + 8);
    if (fVar1 == (format_string_parser<char>)0x0) {
      *(undefined4 *)(this + 0x10) = 0;
      *(undefined2 *)(this + 0x14) = 0;
      this[0x16] = (format_string_parser<char>)0x0;
      *(undefined4 *)(this + 0x18) = 0;
      *(undefined4 *)(this + 0x1c) = 0;
      *(undefined4 *)(this + 0x20) = 0;
      this[0x24] = (format_string_parser<char>)0x0;
      *(undefined4 *)(this + 0x28) = 0;
      *(undefined4 *)(this + 0xc) = 0x2a;
      return false;
    }
    this[0x15] = fVar1;
    *(format_string_parser<char> **)(this + 8) = *(format_string_parser<char> **)(this + 8) + 1;
  }
  return true;
}



// Library Function - Single Match
//  private: void __thiscall
// __crt_stdio_input::format_string_parser<char>::scan_optional_wide_modifier(void)
// 
// Libraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual
// Studio 2019 Release

void __thiscall
__crt_stdio_input::format_string_parser<char>::scan_optional_wide_modifier
          (format_string_parser<char> *this)

{
  char cVar1;
  
  cVar1 = **(char **)(this + 8);
  if (cVar1 == 'w') {
    *(char **)(this + 8) = *(char **)(this + 8) + 1;
  }
  else if ((cVar1 != 'C') && (cVar1 != 'S')) {
    return;
  }
  this[0x24] = (format_string_parser<char>)0x1;
  return;
}



uint __fastcall FUN_0040c41d(int param_1)

{
  byte bVar1;
  byte bVar2;
  byte *in_EAX;
  byte *pbVar3;
  int iVar4;
  byte bVar5;
  byte bVar6;
  undefined4 *puVar7;
  byte *local_c;
  
  if ((undefined4 *)(param_1 + 0x2c) == (undefined4 *)0x0) {
    *(undefined4 *)(param_1 + 0xc) = 0xc;
    *(undefined2 *)(param_1 + 0x14) = 0;
  }
  else {
    puVar7 = (undefined4 *)(param_1 + 0x2c);
    for (iVar4 = 8; iVar4 != 0; iVar4 = iVar4 + -1) {
      *puVar7 = 0;
      puVar7 = puVar7 + 1;
    }
    pbVar3 = *(byte **)(param_1 + 8);
    bVar1 = *pbVar3;
    bVar5 = bVar1;
    if (bVar1 == 0x5e) {
      pbVar3 = pbVar3 + 1;
      *(byte **)(param_1 + 8) = pbVar3;
      bVar5 = *pbVar3;
    }
    if (bVar5 == 0x5d) {
      pbVar3 = pbVar3 + 1;
      *(byte **)(param_1 + 8) = pbVar3;
      *(byte *)(param_1 + 0x37) = *(byte *)(param_1 + 0x37) | 0x20;
    }
    local_c = (byte *)0x0;
    in_EAX = pbVar3;
    if (*pbVar3 != 0x5d) {
      bVar5 = *pbVar3;
      do {
        if (bVar5 == 0) break;
        if (((bVar5 == 0x2d) && (in_EAX + -1 != local_c)) && (in_EAX != pbVar3)) {
          bVar6 = in_EAX[1];
          if (bVar6 == 0x5d) goto LAB_0040c503;
          bVar5 = in_EAX[-1];
          bVar2 = bVar5;
          if (bVar6 < bVar5) {
            bVar2 = bVar6;
            bVar6 = bVar5;
          }
          for (; local_c = in_EAX + 1, bVar2 != (byte)(bVar6 + 1); bVar2 = bVar2 + 1) {
            __crt_stdio_input::scanset_buffer<>::set((scanset_buffer<> *)(param_1 + 0x2c),bVar2);
          }
        }
        else {
LAB_0040c503:
          __crt_stdio_input::scanset_buffer<>::set((scanset_buffer<> *)(param_1 + 0x2c),bVar5);
        }
        in_EAX = (byte *)(*(int *)(param_1 + 8) + 1);
        *(byte **)(param_1 + 8) = in_EAX;
        bVar5 = *in_EAX;
      } while (bVar5 != 0x5d);
    }
    pbVar3 = (byte *)(param_1 + 0x2c);
    if (*in_EAX != 0) {
      if (bVar1 == 0x5e) {
        in_EAX = (byte *)(param_1 + 0x4c);
        for (; pbVar3 != in_EAX; pbVar3 = pbVar3 + 1) {
          *pbVar3 = ~*pbVar3;
        }
      }
      *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
      return CONCAT31((int3)((uint)in_EAX >> 8),1);
    }
    *(undefined2 *)(param_1 + 0x14) = 0;
    *(undefined4 *)(param_1 + 0xc) = 0x16;
  }
  *(undefined4 *)(param_1 + 0x28) = 0;
  *(undefined *)(param_1 + 0x24) = 0;
  *(undefined4 *)(param_1 + 0x20) = 0;
  *(undefined4 *)(param_1 + 0x1c) = 0;
  *(undefined4 *)(param_1 + 0x18) = 0;
  *(undefined *)(param_1 + 0x16) = 0;
  *(undefined4 *)(param_1 + 0x10) = 0;
  return (uint)in_EAX & 0xffffff00;
}



// WARNING: Removing unreachable block (ram,0x0040c571)
// Library Function - Single Match
//  public: void __thiscall __crt_stdio_input::scanset_buffer<unsigned char>::set(unsigned char)
// 
// Libraries: Visual Studio 2015 Debug, Visual Studio 2015 Release

void __thiscall __crt_stdio_input::scanset_buffer<>::set(scanset_buffer<> *this,uchar param_1)

{
  this[param_1 >> 3] = (scanset_buffer<>)((byte)this[param_1 >> 3] | (byte)(1 << (param_1 & 7)));
  return;
}



void __fastcall FUN_0040c581(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x20);
  if (iVar1 == 2) {
    *(undefined *)(param_1 + 0x24) = 0;
    return;
  }
  if (((iVar1 == 3) || (iVar1 == 4)) || (iVar1 == 8)) {
    *(undefined *)(param_1 + 0x24) = 1;
  }
  return;
}



// Library Function - Single Match
//  unsigned int __cdecl __crt_stdio_input::to_floating_point_length(enum
// __crt_stdio_input::length_modifier)
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

uint __cdecl __crt_stdio_input::to_floating_point_length(length_modifier param_1)

{
  uint uStack_8;
  
  if (param_1 == 0) {
    uStack_8 = 4;
  }
  else {
    if ((param_1 != 3) && (param_1 != 8)) {
      return 0;
    }
    uStack_8 = 8;
  }
  return uStack_8;
}



// Library Function - Single Match
//  unsigned int __cdecl __crt_stdio_input::to_integer_length(enum
// __crt_stdio_input::length_modifier)
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

uint __cdecl __crt_stdio_input::to_integer_length(length_modifier param_1)

{
  uint uStack_8;
  
  switch(param_1) {
  case 0:
  case 3:
  case 6:
  case 7:
  case 9:
    uStack_8 = 4;
    break;
  case 1:
    return 1;
  case 2:
    uStack_8 = 2;
    break;
  case 4:
  case 5:
  case 10:
    uStack_8 = 8;
    break;
  default:
    return 0;
  }
  return uStack_8;
}



// Library Function - Single Match
//  public: void __thiscall __crt_strtox::input_adapter_character_source<class
// __crt_stdio_input::stream_input_adapter<char> >::unget(char)
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __thiscall
__crt_strtox::input_adapter_character_source<>::unget
          (input_adapter_character_source<> *this,char param_1)

{
  uint uVar1;
  uint uVar2;
  
  uVar1 = *(int *)(this + 0x10) - 1;
  uVar2 = *(int *)(this + 0x14) + -1 + (uint)(*(int *)(this + 0x10) != 0);
  *(uint *)(this + 0x10) = uVar1;
  *(uint *)(this + 0x14) = uVar2;
  if (((((*(uint *)(this + 8) | *(uint *)(this + 0xc)) == 0) ||
       ((uVar2 <= *(uint *)(this + 0xc) &&
        ((uVar2 < *(uint *)(this + 0xc) || (uVar1 <= *(uint *)(this + 8))))))) && (param_1 != '\0'))
     && (param_1 != -1)) {
    __crt_stdio_input::stream_input_adapter<char>::unget
              (*(stream_input_adapter<char> **)this,(int)param_1);
  }
  return;
}



// Library Function - Single Match
//  public: void __thiscall __crt_strtox::input_adapter_character_source<class
// __crt_stdio_input::string_input_adapter<char> >::unget(char)
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __thiscall
__crt_strtox::input_adapter_character_source<>::unget
          (input_adapter_character_source<> *this,char param_1)

{
  uint uVar1;
  uint uVar2;
  
  uVar1 = *(int *)(this + 0x10) - 1;
  uVar2 = *(int *)(this + 0x14) + -1 + (uint)(*(int *)(this + 0x10) != 0);
  *(uint *)(this + 0x10) = uVar1;
  *(uint *)(this + 0x14) = uVar2;
  if (((((*(uint *)(this + 8) | *(uint *)(this + 0xc)) == 0) ||
       ((uVar2 <= *(uint *)(this + 0xc) &&
        ((uVar2 < *(uint *)(this + 0xc) || (uVar1 <= *(uint *)(this + 8))))))) && (param_1 != '\0'))
     && (param_1 != -1)) {
    __crt_stdio_input::string_input_adapter<char>::unget
              (*(string_input_adapter<char> **)this,(int)param_1);
  }
  return;
}



// Library Function - Single Match
//  public: void __thiscall __crt_stdio_input::stream_input_adapter<char>::unget(int)
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __thiscall
__crt_stdio_input::stream_input_adapter<char>::unget(stream_input_adapter<char> *this,int param_1)

{
  if (param_1 != -1) {
    *(int *)(this + 4) = *(int *)(this + 4) + -1;
    FUN_00410960(param_1,*(FILE **)this);
  }
  return;
}



// Library Function - Single Match
//  public: void __thiscall __crt_stdio_input::string_input_adapter<char>::unget(int)
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __thiscall
__crt_stdio_input::string_input_adapter<char>::unget(string_input_adapter<char> *this,int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(this + 8);
  if ((iVar1 != *(int *)this) && ((iVar1 != *(int *)(this + 4) || (param_1 != -1)))) {
    *(int *)(this + 8) = iVar1 + -1;
  }
  return;
}



// Library Function - Single Match
//  public: bool __thiscall __crt_stdio_input::format_string_parser<char>::validate(void)const 
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

bool __thiscall
__crt_stdio_input::format_string_parser<char>::validate(format_string_parser<char> *this)

{
  undefined4 *puVar1;
  
  if (*(int *)(this + 8) == 0) {
    puVar1 = (undefined4 *)FUN_0040e304();
    *puVar1 = 0x16;
    FUN_0040e223();
    return false;
  }
  return true;
}



uint __fastcall FUN_0040c6ff(int *param_1)

{
  undefined4 in_EAX;
  undefined4 *puVar1;
  uint uVar2;
  
  if ((*param_1 != 0) && (param_1[6] != 0)) {
    return CONCAT31((int3)((uint)in_EAX >> 8),1);
  }
  puVar1 = (undefined4 *)FUN_0040e304();
  *puVar1 = 0x16;
  uVar2 = FUN_0040e223();
  return uVar2 & 0xffffff00;
}



// Library Function - Single Match
//  public: bool __thiscall __crt_stdio_input::stream_input_adapter<char>::validate(void)const 
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

bool __thiscall
__crt_stdio_input::stream_input_adapter<char>::validate(stream_input_adapter<char> *this)

{
  bool bVar1;
  undefined4 *puVar2;
  
  if (*(_iobuf **)this == (_iobuf *)0x0) {
    puVar2 = (undefined4 *)FUN_0040e304();
    *puVar2 = 0x16;
    FUN_0040e223();
    return false;
  }
  bVar1 = __acrt_stdio_char_traits<char>::validate_stream_is_ansi_if_required(*(_iobuf **)this);
  return bVar1;
}



// Library Function - Single Match
//  public: bool __thiscall __crt_stdio_input::string_input_adapter<char>::validate(void)
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

bool __thiscall
__crt_stdio_input::string_input_adapter<char>::validate(string_input_adapter<char> *this)

{
  undefined4 *puVar1;
  
  if ((*(uint *)(this + 8) != 0) && (*(uint *)(this + 8) <= *(uint *)(this + 4))) {
    return true;
  }
  puVar1 = (undefined4 *)FUN_0040e304();
  *puVar1 = 0x16;
  FUN_0040e223();
  return false;
}



// Library Function - Single Match
//  private: bool __thiscall __crt_stdio_input::input_processor<char,class
// __crt_stdio_input::stream_input_adapter<char> >::write_character(wchar_t * const,unsigned
// int,wchar_t * &,unsigned int &,char)
// 
// Library: Visual Studio 2019 Release

bool __thiscall
__crt_stdio_input::input_processor<>::write_character
          (input_processor<> *this,wchar_t *param_1,uint param_2,wchar_t **param_3,uint *param_4,
          char param_5)

{
  ushort *puVar1;
  int iVar2;
  undefined4 local_c;
  undefined4 local_8;
  
  local_8._2_2_ = (undefined2)((uint)this >> 0x10);
  local_8._0_2_ = (ushort)(byte)param_5;
  local_c = this;
  puVar1 = ___pctype_func();
  if ((short)puVar1[(byte)param_5] < 0) {
    iVar2 = FUN_0040cb0c(*(FILE **)(this + 8));
    if (iVar2 != -1) {
      *(int *)(this + 0xc) = *(int *)(this + 0xc) + 1;
    }
    local_8._0_2_ = CONCAT11((char)iVar2,(undefined)local_8);
  }
  local_c = (input_processor<> *)CONCAT22(local_c._2_2_,0x3f);
  FUN_0040ffa3((LPWSTR)&local_c,(byte *)&local_8,*(uint *)(**(int **)(this + 0x60) + 4),
               *(int **)(this + 0x60));
  **param_3 = (short)param_5;
  *param_3 = *param_3 + 1;
  *param_4 = *param_4 - 1;
  return true;
}



// Library Function - Single Match
//  private: bool __thiscall __crt_stdio_input::input_processor<char,class
// __crt_stdio_input::string_input_adapter<char> >::write_character(wchar_t * const,unsigned
// int,wchar_t * &,unsigned int &,char)
// 
// Library: Visual Studio 2019 Release

bool __thiscall
__crt_stdio_input::input_processor<>::write_character
          (input_processor<> *this,wchar_t *param_1,uint param_2,wchar_t **param_3,uint *param_4,
          char param_5)

{
  ushort *puVar1;
  int iVar2;
  undefined4 local_c;
  undefined4 local_8;
  
  local_8._2_2_ = (undefined2)((uint)this >> 0x10);
  local_8._0_2_ = (ushort)(byte)param_5;
  local_c = this;
  puVar1 = ___pctype_func();
  if ((short)puVar1[(byte)param_5] < 0) {
    iVar2 = string_input_adapter<char>::get((string_input_adapter<char> *)(this + 8));
    local_8._0_2_ = CONCAT11((char)iVar2,(undefined)local_8);
  }
  local_c = (input_processor<> *)CONCAT22(local_c._2_2_,0x3f);
  FUN_0040ffa3((LPWSTR)&local_c,(byte *)&local_8,*(uint *)(**(int **)(this + 0x68) + 4),
               *(int **)(this + 0x68));
  **param_3 = (short)param_5;
  *param_3 = *param_3 + 1;
  *param_4 = *param_4 - 1;
  return true;
}



uint __thiscall FUN_0040c846(void *this,uint param_1,uint param_2)

{
  uint **ppuVar1;
  uint *puVar2;
  undefined4 *puVar3;
  uint uVar4;
  uint uVar5;
  
  ppuVar1 = *(uint ***)((int)this + 100);
  *(uint ***)((int)this + 100) = ppuVar1 + 1;
  puVar2 = *ppuVar1;
  if (puVar2 == (uint *)0x0) {
    puVar3 = (undefined4 *)FUN_0040e304();
    *puVar3 = 0x16;
    uVar4 = FUN_0040e223();
LAB_0040c86b:
    uVar4 = uVar4 & 0xffffff00;
  }
  else {
    uVar4 = FUN_0040ba47((int)this + 0x10);
    if (uVar4 == 1) {
      uVar5 = 0;
      *(undefined *)puVar2 = (undefined)param_1;
    }
    else if (uVar4 == 2) {
      uVar5 = param_1 & 0xffff;
      *(undefined2 *)puVar2 = (undefined2)param_1;
    }
    else {
      uVar5 = param_1;
      if (uVar4 == 4) {
        *puVar2 = param_1;
      }
      else {
        uVar4 = uVar4 - 8;
        if (uVar4 != 0) goto LAB_0040c86b;
        *puVar2 = param_1;
        puVar2[1] = param_2;
      }
    }
    uVar4 = CONCAT31((int3)(uVar5 >> 8),1);
  }
  return uVar4;
}



uint __thiscall FUN_0040c8b5(void *this,uint param_1,uint param_2)

{
  uint **ppuVar1;
  uint *puVar2;
  undefined4 *puVar3;
  uint uVar4;
  uint uVar5;
  
  ppuVar1 = *(uint ***)((int)this + 0x6c);
  *(uint ***)((int)this + 0x6c) = ppuVar1 + 1;
  puVar2 = *ppuVar1;
  if (puVar2 == (uint *)0x0) {
    puVar3 = (undefined4 *)FUN_0040e304();
    *puVar3 = 0x16;
    uVar4 = FUN_0040e223();
LAB_0040c8da:
    uVar4 = uVar4 & 0xffffff00;
  }
  else {
    uVar4 = FUN_0040ba47((int)this + 0x18);
    if (uVar4 == 1) {
      uVar5 = 0;
      *(undefined *)puVar2 = (undefined)param_1;
    }
    else if (uVar4 == 2) {
      uVar5 = param_1 & 0xffff;
      *(undefined2 *)puVar2 = (undefined2)param_1;
    }
    else {
      uVar5 = param_1;
      if (uVar4 == 4) {
        *puVar2 = param_1;
      }
      else {
        uVar4 = uVar4 - 8;
        if (uVar4 != 0) goto LAB_0040c8da;
        *puVar2 = param_1;
        puVar2[1] = param_2;
      }
    }
    uVar4 = CONCAT31((int3)(uVar5 >> 8),1);
  }
  return uVar4;
}



int __cdecl
FUN_0040c924(undefined4 param_1,undefined4 param_2,int param_3,int param_4,undefined4 param_5,
            undefined4 param_6)

{
  undefined4 *puVar1;
  int iVar2;
  undefined4 *local_3c;
  int *local_38;
  undefined4 *local_34;
  int *local_30;
  undefined4 *local_2c;
  undefined4 local_28;
  undefined4 local_24;
  int local_20;
  int local_1c;
  undefined4 local_18;
  int local_14;
  int local_10;
  undefined4 local_c;
  __crt_seh_guarded_call<int> local_5;
  
  local_18 = param_6;
  local_c = param_5;
  local_10 = param_3;
  local_28 = param_1;
  local_24 = param_2;
  local_14 = param_4;
  if ((param_3 == 0) || (param_4 == 0)) {
    puVar1 = (undefined4 *)FUN_0040e304();
    *puVar1 = 0x16;
    FUN_0040e223();
    iVar2 = -1;
  }
  else {
    local_3c = &local_c;
    local_1c = param_3;
    local_38 = &local_10;
    local_20 = param_3;
    local_34 = &local_28;
    local_30 = &local_14;
    local_2c = &local_18;
    iVar2 = __crt_seh_guarded_call<int>::operator()<>
                      (&local_5,(<> *)&local_20,(<> *)&local_3c,(<> *)&local_1c);
  }
  return iVar2;
}



// Library Function - Single Match
//  ___stdio_common_vsscanf
// 
// Library: Visual Studio 2019 Release

void __cdecl
___stdio_common_vsscanf
          (undefined4 param_1,undefined4 param_2,char *param_3,uint param_4,char *param_5,
          __crt_locale_pointers *param_6,char *param_7)

{
  common_vsscanf<char>(CONCAT44(param_2,param_1),param_3,param_4,param_5,param_6,param_7);
  return;
}



uint __cdecl FUN_0040c9cd(int param_1,uint param_2,_locale_t param_3)

{
  ushort uVar1;
  ushort *puVar2;
  undefined2 extraout_var;
  uint uVar3;
  
  if (param_3 == (_locale_t)0x0) {
    puVar2 = ___pctype_func();
    uVar1 = ___acrt_locale_get_ctype_array_value((int)puVar2,param_1,(ushort)param_2);
    return CONCAT22(extraout_var,uVar1);
  }
  if (param_1 + 1U < 0x101) {
    uVar3 = *(ushort *)(param_3->locinfo->refcount + param_1 * 2) & param_2;
  }
  else if ((int)param_3->locinfo->lc_codepage < 2) {
    uVar3 = 0;
  }
  else {
    uVar3 = __isctype_l(param_1,param_2,param_3);
  }
  return uVar3;
}



// Library Function - Single Match
//  _memcpy_s
// 
// Libraries: Visual Studio 2012, Visual Studio 2015, Visual Studio 2017, Visual Studio 2019

errno_t __cdecl _memcpy_s(void *_Dst,rsize_t _DstSize,void *_Src,rsize_t _MaxCount)

{
  errno_t eVar1;
  undefined4 *puVar2;
  errno_t *peVar3;
  
  if (_MaxCount == 0) {
    eVar1 = 0;
  }
  else if (_Dst == (void *)0x0) {
    puVar2 = (undefined4 *)FUN_0040e304();
    eVar1 = 0x16;
    *puVar2 = 0x16;
    FUN_0040e223();
  }
  else if ((_Src == (void *)0x0) || (_DstSize < _MaxCount)) {
    _memset(_Dst,0,_DstSize);
    if (_Src == (void *)0x0) {
      peVar3 = (errno_t *)FUN_0040e304();
      eVar1 = 0x16;
    }
    else {
      if (_MaxCount <= _DstSize) {
        return 0x16;
      }
      peVar3 = (errno_t *)FUN_0040e304();
      eVar1 = 0x22;
    }
    *peVar3 = eVar1;
    FUN_0040e223();
  }
  else {
    FID_conflict__memcpy(_Dst,_Src,_MaxCount);
    eVar1 = 0;
  }
  return eVar1;
}



void __cdecl FUN_0040caa5(LPVOID param_1)

{
  FUN_0040e374(param_1);
  return;
}



// Library Function - Single Match
//  __fgetc_nolock
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

uint __cdecl __fgetc_nolock(FILE *param_1)

{
  char **ppcVar1;
  byte bVar2;
  undefined4 *puVar3;
  uint uVar4;
  
  if (param_1 == (FILE *)0x0) {
    puVar3 = (undefined4 *)FUN_0040e304();
    *puVar3 = 0x16;
    FUN_0040e223();
    return 0xffffffff;
  }
  ppcVar1 = &param_1->_base;
  *ppcVar1 = *ppcVar1 + -1;
  if ((int)*ppcVar1 < 0) {
    uVar4 = FUN_00410bf0(param_1);
    return uVar4;
  }
  bVar2 = *param_1->_ptr;
  param_1->_ptr = param_1->_ptr + 1;
  return (uint)bVar2;
}



void FUN_0040cafc(void)

{
  FILE *pFVar1;
  
  pFVar1 = (FILE *)FUN_00404989(0);
  FUN_0040cb17(pFVar1);
  return;
}



void __cdecl FUN_0040cb0c(FILE *param_1)

{
  __fgetc_nolock(param_1);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4

uint __cdecl FUN_0040cb17(FILE *param_1)

{
  bool bVar1;
  undefined4 *puVar2;
  uint uVar3;
  undefined *puVar4;
  undefined *local_20;
  void *local_14 [2];
  undefined4 uStack_c;
  undefined *local_8;
  
  local_8 = &DAT_00421dc8;
  uStack_c = 0x40cb23;
  if (param_1 == (FILE *)0x0) {
    puVar2 = (undefined4 *)FUN_0040e304();
    *puVar2 = 0x16;
    FUN_0040e223();
    ExceptionList = local_14[0];
    return 0xffffffff;
  }
  bVar1 = false;
  __lock_file(param_1);
  local_8 = (undefined *)0x0;
  if (((uint)param_1->_flag >> 0xc & 1) == 0) {
    uVar3 = __fileno(param_1);
    if ((uVar3 == 0xffffffff) || (uVar3 == 0xfffffffe)) {
      local_20 = &DAT_004230f8;
    }
    else {
      local_20 = (undefined *)((uVar3 & 0x3f) * 0x38 + (&DAT_004240c8)[(int)uVar3 >> 6]);
    }
    puVar4 = &DAT_004230f8;
    if (local_20[0x29] != '\0') goto LAB_0040cbcc;
    if ((uVar3 != 0xffffffff) && (uVar3 != 0xfffffffe)) {
      puVar4 = (undefined *)((uVar3 & 0x3f) * 0x38 + (&DAT_004240c8)[(int)uVar3 >> 6]);
    }
    if ((puVar4[0x2d] & 1) != 0) goto LAB_0040cbcc;
  }
  bVar1 = true;
LAB_0040cbcc:
  if (!bVar1) {
    puVar2 = (undefined4 *)FUN_0040e304();
    *puVar2 = 0x16;
    FUN_0040e223();
    FUN_00402790(&DAT_00423014,(int)local_14,0xfffffffe);
    ExceptionList = local_14[0];
    return 0xffffffff;
  }
  uVar3 = __fgetc_nolock(param_1);
  local_8 = (undefined *)0xfffffffe;
  FUN_0040cc28();
  ExceptionList = local_14[0];
  return uVar3;
}



void FUN_0040cc28(void)

{
  FILE *unaff_ESI;
  
  __unlock_file(unaff_ESI);
  return;
}



void thunk_FUN_0040cafc(void)

{
  FILE *pFVar1;
  
  pFVar1 = (FILE *)FUN_00404989(0);
  FUN_0040cb17(pFVar1);
  return;
}



void FUN_0040cc35(SIZE_T param_1)

{
  __malloc_base(param_1);
  return;
}



undefined4 __cdecl FUN_0040cc40(uint param_1,uint *param_2)

{
  uint *puVar1;
  code *pcVar2;
  uint *puVar3;
  uint **ppuVar4;
  uint *puVar5;
  uint *puVar6;
  undefined4 uVar7;
  uint uVar8;
  
  ppuVar4 = (uint **)FUN_004105fa();
  if (ppuVar4 != (uint **)0x0) {
    puVar1 = *ppuVar4;
    for (puVar6 = puVar1; puVar6 != puVar1 + 0x24; puVar6 = puVar6 + 3) {
      if (*puVar6 == param_1) {
        if (puVar6 == (uint *)0x0) {
          return 0;
        }
        pcVar2 = (code *)puVar6[2];
        if (pcVar2 == (code *)0x0) {
          return 0;
        }
        if (pcVar2 == (code *)0x5) {
          puVar6[2] = 0;
          return 1;
        }
        if (pcVar2 != (code *)0x1) {
          puVar3 = ppuVar4[1];
          ppuVar4[1] = param_2;
          if (puVar6[1] == 8) {
            for (puVar5 = puVar1 + 9; puVar5 != puVar1 + 0x24; puVar5 = puVar5 + 3) {
              puVar5[2] = 0;
            }
            puVar1 = ppuVar4[2];
            puVar5 = puVar1;
            if (*puVar6 < 0xc0000092) {
              if (*puVar6 == 0xc0000091) {
                puVar5 = (uint *)0x84;
              }
              else if (*puVar6 == 0xc000008d) {
                puVar5 = (uint *)0x82;
              }
              else if (*puVar6 == 0xc000008e) {
                puVar5 = (uint *)0x83;
              }
              else if (*puVar6 == 0xc000008f) {
                puVar5 = (uint *)0x86;
              }
              else {
                if (*puVar6 != 0xc0000090) goto LAB_0040cd54;
                puVar5 = (uint *)0x81;
              }
LAB_0040cd51:
              ppuVar4[2] = puVar5;
            }
            else {
              if (*puVar6 == 0xc0000092) {
                puVar5 = (uint *)0x8a;
                goto LAB_0040cd51;
              }
              if (*puVar6 == 0xc0000093) {
                puVar5 = (uint *)0x85;
                goto LAB_0040cd51;
              }
              if (*puVar6 == 0xc00002b4) {
                puVar5 = (uint *)0x8e;
                goto LAB_0040cd51;
              }
              if (*puVar6 == 0xc00002b5) {
                puVar5 = (uint *)0x8d;
                goto LAB_0040cd51;
              }
            }
LAB_0040cd54:
            uVar7 = 8;
            _guard_check_icall();
            (*pcVar2)(uVar7,puVar5);
            ppuVar4[2] = puVar1;
          }
          else {
            puVar6[2] = 0;
            uVar8 = puVar6[1];
            _guard_check_icall();
            (*pcVar2)(uVar8);
          }
          ppuVar4[1] = puVar3;
        }
        return 0xffffffff;
      }
    }
  }
  return 0;
}



undefined4 FUN_0040cd86(void)

{
  return DAT_00423d24;
}



void __cdecl FUN_0040cd8c(undefined4 param_1)

{
  DAT_00423d24 = param_1;
  return;
}



bool FUN_0040cd9b(void)

{
  byte bVar1;
  
  bVar1 = (byte)DAT_00423014 & 0x1f;
  return ((DAT_00423d28 ^ DAT_00423014) >> bVar1 | (DAT_00423d28 ^ DAT_00423014) << 0x20 - bVar1) !=
         0;
}



void __cdecl FUN_0040cdb8(undefined4 param_1)

{
  DAT_00423d28 = param_1;
  return;
}



undefined4 __cdecl FUN_0040cdc7(undefined4 param_1)

{
  undefined4 uVar1;
  byte bVar2;
  code *pcVar3;
  
  bVar2 = (byte)DAT_00423014 & 0x1f;
  pcVar3 = (code *)((DAT_00423d28 ^ DAT_00423014) >> bVar2 |
                   (DAT_00423d28 ^ DAT_00423014) << 0x20 - bVar2);
  if (pcVar3 == (code *)0x0) {
    uVar1 = 0;
  }
  else {
    _guard_check_icall();
    uVar1 = (*pcVar3)(param_1);
  }
  return uVar1;
}



// Library Function - Single Match
//  ___setusermatherr
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void __cdecl ___setusermatherr(_func_void_void_ptr_ulong_void_ptr *param_1)

{
  DAT_00423d28 = __crt_fast_encode_pointer<>(param_1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int __cdecl FUN_0040ce12(int param_1)

{
  byte **ppbVar1;
  int iVar2;
  undefined4 *puVar3;
  byte **ppbVar4;
  byte *pbVar5;
  uint local_10;
  byte **local_c;
  uint local_8;
  
  if (param_1 == 0) {
    iVar2 = 0;
  }
  else if ((param_1 == 2) || (param_1 == 1)) {
    ___acrt_initialize_multibyte();
    ___acrt_GetModuleFileNameA((HMODULE)0x0,&DAT_00423d30,0x104);
    _DAT_00423e48 = &DAT_00423d30;
    if ((DAT_00423e58 == (byte *)0x0) || (pbVar5 = DAT_00423e58, *DAT_00423e58 == 0)) {
      pbVar5 = &DAT_00423d30;
    }
    local_8 = 0;
    local_10 = 0;
    FUN_0040cf4f(pbVar5,(byte **)0x0,(byte *)0x0,(int *)&local_8,(int *)&local_10);
    ppbVar4 = (byte **)___acrt_allocate_buffer_for_argv(local_8,local_10,1);
    if (ppbVar4 == (byte **)0x0) {
      puVar3 = (undefined4 *)FUN_0040e304();
      iVar2 = 0xc;
      *puVar3 = 0xc;
    }
    else {
      FUN_0040cf4f(pbVar5,ppbVar4,(byte *)(ppbVar4 + local_8),(int *)&local_8,(int *)&local_10);
      if (param_1 != 1) {
        local_c = (byte **)0x0;
        iVar2 = FUN_0041141e(ppbVar4,&local_c);
        ppbVar1 = local_c;
        if (iVar2 == 0) {
          _DAT_00423e4c = 0;
          pbVar5 = *local_c;
          while (pbVar5 != (byte *)0x0) {
            local_c = local_c + 1;
            _DAT_00423e4c = _DAT_00423e4c + 1;
            pbVar5 = *local_c;
          }
          local_c = (byte **)0x0;
          _DAT_00423e50 = ppbVar1;
          FUN_0040e374((LPVOID)0x0);
          iVar2 = 0;
        }
        else {
          FUN_0040e374(local_c);
        }
        local_c = (byte **)0x0;
        FUN_0040e374(ppbVar4);
        return iVar2;
      }
      _DAT_00423e4c = local_8 - 1;
      iVar2 = 0;
      _DAT_00423e50 = ppbVar4;
    }
    FUN_0040e374((LPVOID)0x0);
  }
  else {
    puVar3 = (undefined4 *)FUN_0040e304();
    iVar2 = 0x16;
    *puVar3 = 0x16;
    FUN_0040e223();
  }
  return iVar2;
}



void __cdecl FUN_0040cf4f(byte *param_1,byte **param_2,byte *param_3,int *param_4,int *param_5)

{
  bool bVar1;
  bool bVar2;
  byte bVar3;
  uint uVar4;
  int iVar5;
  byte *pbVar6;
  
  *param_5 = 0;
  *param_4 = 1;
  if (param_2 != (byte **)0x0) {
    *param_2 = param_3;
    param_2 = param_2 + 1;
  }
  bVar1 = false;
  bVar2 = false;
  do {
    if (*param_1 == 0x22) {
      bVar1 = !bVar1;
      bVar3 = 0x22;
      pbVar6 = param_1 + 1;
      bVar2 = bVar1;
    }
    else {
      *param_5 = *param_5 + 1;
      if (param_3 != (byte *)0x0) {
        *param_3 = *param_1;
        param_3 = param_3 + 1;
      }
      bVar3 = *param_1;
      pbVar6 = param_1 + 1;
      iVar5 = FUN_00411df3(bVar3);
      if (iVar5 != 0) {
        *param_5 = *param_5 + 1;
        if (param_3 != (byte *)0x0) {
          *param_3 = *pbVar6;
          param_3 = param_3 + 1;
        }
        pbVar6 = param_1 + 2;
      }
      if (bVar3 == 0) {
        pbVar6 = pbVar6 + -1;
        goto LAB_0040cfde;
      }
    }
    param_1 = pbVar6;
  } while ((bVar2) || ((bVar3 != 0x20 && (bVar3 != 9))));
  if (param_3 != (byte *)0x0) {
    param_3[-1] = 0;
  }
LAB_0040cfde:
  bVar1 = false;
  while (bVar3 = *pbVar6, bVar3 != 0) {
    while ((bVar3 == 0x20 || (bVar3 == 9))) {
      pbVar6 = pbVar6 + 1;
      bVar3 = *pbVar6;
    }
    if (bVar3 == 0) break;
    if (param_2 != (byte **)0x0) {
      *param_2 = param_3;
      param_2 = param_2 + 1;
    }
    *param_4 = *param_4 + 1;
    while( true ) {
      bVar2 = true;
      uVar4 = 0;
      for (; *pbVar6 == 0x5c; pbVar6 = pbVar6 + 1) {
        uVar4 = uVar4 + 1;
      }
      if (*pbVar6 == 0x22) {
        if ((uVar4 & 1) == 0) {
          if ((bVar1) && (pbVar6[1] == 0x22)) {
            pbVar6 = pbVar6 + 1;
          }
          else {
            bVar2 = false;
            bVar1 = !bVar1;
          }
        }
        uVar4 = uVar4 >> 1;
      }
      while (uVar4 != 0) {
        uVar4 = uVar4 - 1;
        if (param_3 != (byte *)0x0) {
          *param_3 = 0x5c;
          param_3 = param_3 + 1;
        }
        *param_5 = *param_5 + 1;
      }
      bVar3 = *pbVar6;
      if ((bVar3 == 0) || ((!bVar1 && ((bVar3 == 0x20 || (bVar3 == 9)))))) break;
      if (bVar2) {
        if (param_3 != (byte *)0x0) {
          *param_3 = bVar3;
          param_3 = param_3 + 1;
        }
        iVar5 = FUN_00411df3(*pbVar6);
        if (iVar5 != 0) {
          pbVar6 = pbVar6 + 1;
          *param_5 = *param_5 + 1;
          if (param_3 != (byte *)0x0) {
            *param_3 = *pbVar6;
            param_3 = param_3 + 1;
          }
        }
        *param_5 = *param_5 + 1;
      }
      pbVar6 = pbVar6 + 1;
    }
    if (param_3 != (byte *)0x0) {
      *param_3 = 0;
      param_3 = param_3 + 1;
    }
    *param_5 = *param_5 + 1;
  }
  if (param_2 != (byte **)0x0) {
    *param_2 = (byte *)0x0;
  }
  *param_4 = *param_4 + 1;
  return;
}



// Library Function - Single Match
//  ___acrt_allocate_buffer_for_argv
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

LPVOID __cdecl ___acrt_allocate_buffer_for_argv(uint param_1,uint param_2,uint param_3)

{
  LPVOID pvVar1;
  
  if ((param_1 < 0x3fffffff) && (param_2 < (uint)(0xffffffff / (ulonglong)param_3))) {
    if (param_2 * param_3 < ~(param_1 * 4)) {
      pvVar1 = __calloc_base(param_1 * 4 + param_2 * param_3,1);
      FUN_0040e374((LPVOID)0x0);
      return pvVar1;
    }
  }
  return (LPVOID)0x0;
}



void __cdecl FUN_0040d112(int param_1)

{
  FUN_0040ce12(param_1);
  return;
}



// Library Function - Multiple Matches With Same Base Name
//  char * * __cdecl common_get_or_create_environment_nolock<char>(void)
//  wchar_t * * __cdecl common_get_or_create_environment_nolock<wchar_t>(void)
// 
// Libraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual
// Studio 2019 Release

int common_get_or_create_environment_nolock<>(void)

{
  int iVar1;
  
  iVar1 = DAT_00423e38;
  if (DAT_00423e38 == 0) {
    if (DAT_00423e3c != 0) {
      iVar1 = FUN_0040d149();
      if (iVar1 == 0) {
        return DAT_00423e38;
      }
      iVar1 = FUN_0040d2b4();
      if (iVar1 == 0) {
        return DAT_00423e38;
      }
    }
    iVar1 = 0;
  }
  return iVar1;
}



undefined4 FUN_0040d149(void)

{
  LPWCH pWVar1;
  char **ppcVar2;
  undefined4 uVar3;
  
  if (DAT_00423e38 != (char **)0x0) {
    return 0;
  }
  ___acrt_initialize_multibyte();
  pWVar1 = FUN_00412000();
  if (pWVar1 == (LPWCH)0x0) {
    FUN_0040e374((LPVOID)0x0);
    return 0xffffffff;
  }
  ppcVar2 = FUN_0040d1a3((char *)pWVar1);
  if (ppcVar2 == (char **)0x0) {
    uVar3 = 0xffffffff;
  }
  else {
    uVar3 = 0;
    DAT_00423e38 = ppcVar2;
    DAT_00423e44 = ppcVar2;
  }
  FUN_0040e374((LPVOID)0x0);
  FUN_0040e374(pWVar1);
  return uVar3;
}



char ** __cdecl FUN_0040d1a3(char *param_1)

{
  char cVar1;
  char **ppcVar2;
  char *pcVar3;
  char *pcVar4;
  int iVar5;
  char **local_8;
  
  iVar5 = 0;
  cVar1 = *param_1;
  pcVar4 = param_1;
  while (cVar1 != '\0') {
    if (cVar1 != '=') {
      iVar5 = iVar5 + 1;
    }
    do {
      cVar1 = *pcVar4;
      pcVar4 = pcVar4 + 1;
    } while (cVar1 != '\0');
    cVar1 = *pcVar4;
  }
  ppcVar2 = (char **)__calloc_base(iVar5 + 1,4);
  local_8 = ppcVar2;
  if (ppcVar2 == (char **)0x0) {
    FUN_0040e374((LPVOID)0x0);
    ppcVar2 = (char **)0x0;
  }
  else {
    for (; *param_1 != '\0'; param_1 = param_1 + (int)pcVar4) {
      pcVar4 = param_1;
      do {
        cVar1 = *pcVar4;
        pcVar4 = pcVar4 + 1;
      } while (cVar1 != '\0');
      pcVar4 = pcVar4 + (1 - (int)(param_1 + 1));
      if (*param_1 != '=') {
        pcVar3 = (char *)__calloc_base((uint)pcVar4,1);
        if (pcVar3 == (char *)0x0) {
          free_environment<>(ppcVar2);
          FUN_0040e374((LPVOID)0x0);
          FUN_0040e374((LPVOID)0x0);
          return (char **)0x0;
        }
        iVar5 = FUN_0040daef(pcVar3,(int)pcVar4,(int)param_1);
        if (iVar5 != 0) {
                    // WARNING: Subroutine does not return
          __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
        }
        *local_8 = pcVar3;
        local_8 = local_8 + 1;
        FUN_0040e374((LPVOID)0x0);
      }
    }
    FUN_0040e374((LPVOID)0x0);
  }
  return ppcVar2;
}



// Library Function - Multiple Matches With Same Base Name
//  void __cdecl free_environment<char>(char * * const)
//  void __cdecl free_environment<wchar_t>(wchar_t * * const)
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void __cdecl free_environment<>(LPVOID *param_1)

{
  LPVOID pvVar1;
  LPVOID *ppvVar2;
  
  if (param_1 != (LPVOID *)0x0) {
    pvVar1 = *param_1;
    ppvVar2 = param_1;
    while (pvVar1 != (LPVOID)0x0) {
      FUN_0040e374(pvVar1);
      ppvVar2 = ppvVar2 + 1;
      pvVar1 = *ppvVar2;
    }
    FUN_0040e374(param_1);
  }
  return;
}



undefined4 FUN_0040d2b4(void)

{
  LPCWSTR pWVar1;
  uint uVar2;
  char *pcVar3;
  int iVar4;
  undefined4 uVar5;
  LPCWSTR *ppWVar6;
  char *pcVar7;
  
  if (DAT_00423e3c == (LPCWSTR *)0x0) {
LAB_0040d330:
    uVar5 = 0xffffffff;
  }
  else {
    pWVar1 = *DAT_00423e3c;
    ppWVar6 = DAT_00423e3c;
    while (pWVar1 != (LPCWSTR)0x0) {
      uVar2 = FUN_00411f5d(0,0,pWVar1,-1,(LPSTR)0x0,0,0,(undefined4 *)0x0);
      if (uVar2 == 0) goto LAB_0040d330;
      pcVar3 = (char *)__calloc_base(uVar2,1);
      pcVar7 = (char *)0x0;
      if ((pcVar3 == (char *)0x0) ||
         (iVar4 = FUN_00411f5d(0,0,*ppWVar6,-1,pcVar3,uVar2,0,(undefined4 *)0x0), pcVar7 = pcVar3,
         iVar4 == 0)) {
        FUN_0040e374(pcVar7);
        goto LAB_0040d330;
      }
      FUN_0041241f(pcVar3,0);
      FUN_0040e374((LPVOID)0x0);
      ppWVar6 = ppWVar6 + 1;
      pWVar1 = *ppWVar6;
    }
    uVar5 = 0;
  }
  return uVar5;
}



// Library Function - Multiple Matches With Same Base Name
//  void __cdecl uninitialize_environment_internal<char>(char * * &)
//  void __cdecl uninitialize_environment_internal<wchar_t>(wchar_t * * &)
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void __cdecl uninitialize_environment_internal<>(undefined4 *param_1)

{
  if ((LPVOID *)*param_1 != DAT_00423e44) {
    free_environment<>((LPVOID *)*param_1);
  }
  return;
}



// Library Function - Multiple Matches With Same Base Name
//  void __cdecl uninitialize_environment_internal<char>(char * * &)
//  void __cdecl uninitialize_environment_internal<wchar_t>(wchar_t * * &)
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void __cdecl uninitialize_environment_internal<>(undefined4 *param_1)

{
  if ((LPVOID *)*param_1 != DAT_00423e40) {
    free_environment<>((LPVOID *)*param_1);
  }
  return;
}



int common_get_or_create_environment_nolock<>(void)

{
  int iVar1;
  
  iVar1 = DAT_00423e38;
  if (DAT_00423e38 == 0) {
    if (DAT_00423e3c != 0) {
      iVar1 = FUN_0040d149();
      if (iVar1 == 0) {
        return DAT_00423e38;
      }
      iVar1 = FUN_0040d2b4();
      if (iVar1 == 0) {
        return DAT_00423e38;
      }
    }
    iVar1 = 0;
  }
  return iVar1;
}



// WARNING: Function: __EH_prolog3 replaced with injection: EH_prolog3
// WARNING: Function: __EH_epilog3 replaced with injection: EH_epilog3

void FUN_0040d372(void)

{
  uninitialize_environment_internal<>(&DAT_00423e38);
  uninitialize_environment_internal<>(&DAT_00423e3c);
  free_environment<>(DAT_00423e44);
  free_environment<>(DAT_00423e40);
  return;
}



// Library Function - Multiple Matches With Different Base Names
//  __get_initial_narrow_environment
//  __get_initial_wide_environment
// 
// Library: Visual Studio 2019 Release

void FID_conflict___get_initial_narrow_environment(void)

{
  if (DAT_00423e44 == 0) {
    DAT_00423e44 = common_get_or_create_environment_nolock<>();
  }
  return;
}



undefined4 thunk_FUN_0040d149(void)

{
  LPWCH pWVar1;
  char **ppcVar2;
  undefined4 uVar3;
  
  if (DAT_00423e38 != (char **)0x0) {
    return 0;
  }
  ___acrt_initialize_multibyte();
  pWVar1 = FUN_00412000();
  if (pWVar1 == (LPWCH)0x0) {
    FUN_0040e374((LPVOID)0x0);
    return 0xffffffff;
  }
  ppcVar2 = FUN_0040d1a3((char *)pWVar1);
  if (ppcVar2 == (char **)0x0) {
    uVar3 = 0xffffffff;
  }
  else {
    uVar3 = 0;
    DAT_00423e38 = ppcVar2;
    DAT_00423e44 = ppcVar2;
  }
  FUN_0040e374((LPVOID)0x0);
  FUN_0040e374(pWVar1);
  return uVar3;
}



void __cdecl FUN_0040d3dc(undefined **param_1,undefined **param_2)

{
  code *pcVar1;
  
  if (param_1 != param_2) {
    do {
      pcVar1 = (code *)*param_1;
      if (pcVar1 != (code *)0x0) {
        _guard_check_icall();
        (*pcVar1)();
      }
      param_1 = (code **)param_1 + 1;
    } while (param_1 != param_2);
  }
  return;
}



// Library Function - Single Match
//  __initterm_e
// 
// Library: Visual Studio 2019 Release

int __cdecl __initterm_e(undefined **param_1,undefined **param_2)

{
  code *pcVar1;
  int iVar2;
  
  do {
    if (param_1 == param_2) {
      return 0;
    }
    pcVar1 = (code *)*param_1;
    if (pcVar1 != (code *)0x0) {
      _guard_check_icall();
      iVar2 = (*pcVar1)();
      if (iVar2 != 0) {
        return iVar2;
      }
    }
    param_1 = (code **)param_1 + 1;
  } while( true );
}



// Library Function - Single Match
//  __set_fmode
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

errno_t __cdecl __set_fmode(int _Mode)

{
  undefined4 *puVar1;
  
  if (((_Mode != 0x4000) && (_Mode != 0x8000)) && (_Mode != 0x10000)) {
    puVar1 = (undefined4 *)FUN_0040e304();
    *puVar1 = 0x16;
    FUN_0040e223();
    return 0x16;
  }
  LOCK();
  DAT_004242f8 = _Mode;
  UNLOCK();
  return 0;
}



undefined * FUN_0040d48b(void)

{
  return &DAT_00423e4c;
}



undefined * FUN_0040d491(void)

{
  return &DAT_00423e50;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// Library Function - Single Match
//  public: void __thiscall __crt_seh_guarded_call<void>::operator()<class
// <lambda_e5124f882df8998aaf41531e079ba474>,class <lambda_3e16ef9562a7dcce91392c22ab16ea36> &,class
// <lambda_e25ca0880e6ef98be67edffd8c599615> >(class <lambda_e5124f882df8998aaf41531e079ba474>
// &&,class <lambda_3e16ef9562a7dcce91392c22ab16ea36> &,class
// <lambda_e25ca0880e6ef98be67edffd8c599615> &&)
// 
// Library: Visual Studio 2019 Release

void __thiscall
__crt_seh_guarded_call<void>::operator()<>
          (__crt_seh_guarded_call<void> *this,<> *param_1,<> *param_2,<> *param_3)

{
  undefined **ppuVar1;
  LPVOID *ppvVar2;
  void *local_14;
  
  ___acrt_lock(*(int *)param_1);
  for (ppvVar2 = (LPVOID *)&DAT_004242e0; ppvVar2 != (LPVOID *)&DAT_004242e4; ppvVar2 = ppvVar2 + 1)
  {
    if ((undefined **)*ppvVar2 != &PTR_DAT_00423138) {
      ppuVar1 = __updatetlocinfoEx_nolock(ppvVar2,&PTR_DAT_00423138);
      *ppvVar2 = ppuVar1;
    }
  }
  FUN_0040d4f9();
  ExceptionList = local_14;
  return;
}



void FUN_0040d4f9(void)

{
  int unaff_EBP;
  
  ___acrt_unlock(**(int **)(unaff_EBP + 0x10));
  return;
}



undefined4 FUN_0040d505(void)

{
  undefined4 uVar1;
  
  uVar1 = DAT_00423e60;
  LOCK();
  DAT_00423e60 = 1;
  UNLOCK();
  return uVar1;
}



// Library Function - Single Match
//  ___acrt_uninitialize_locale
// 
// Library: Visual Studio 2019 Release

void ___acrt_uninitialize_locale(void)

{
  undefined4 local_10;
  undefined4 local_c;
  __crt_seh_guarded_call<void> local_5;
  
  local_c = 4;
  local_10 = 4;
  __crt_seh_guarded_call<void>::operator()<>(&local_5,(<> *)&local_10,(<> *)&local_5,(<> *)&local_c)
  ;
  return;
}



// Library Function - Single Match
//  __configthreadlocale
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

int __cdecl __configthreadlocale(int _Flag)

{
  uint uVar1;
  __acrt_ptd *p_Var2;
  undefined4 *puVar3;
  uint uVar4;
  
  p_Var2 = FUN_004104a9();
  uVar1 = *(uint *)(p_Var2 + 0x350);
  if (_Flag == -1) {
    DAT_00423778 = 0xffffffff;
  }
  else if (_Flag != 0) {
    if (_Flag == 1) {
      uVar4 = uVar1 | 2;
    }
    else {
      if (_Flag != 2) {
        puVar3 = (undefined4 *)FUN_0040e304();
        *puVar3 = 0x16;
        FUN_0040e223();
        return -1;
      }
      uVar4 = uVar1 & 0xfffffffd;
    }
    *(uint *)(p_Var2 + 0x350) = uVar4;
  }
  return ((uVar1 & 2) == 0) + 1;
}



undefined4 FUN_0040d599(void)

{
  return DAT_00423e64;
}



// Library Function - Single Match
//  __set_new_mode
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

undefined4 __cdecl __set_new_mode(int param_1)

{
  undefined4 uVar1;
  undefined4 *puVar2;
  
  uVar1 = DAT_00423e64;
  if ((param_1 != 0) && (param_1 != 1)) {
    puVar2 = (undefined4 *)FUN_0040e304();
    *puVar2 = 0x16;
    FUN_0040e223();
    return 0xffffffff;
  }
  LOCK();
  DAT_00423e64 = param_1;
  UNLOCK();
  return uVar1;
}



undefined * FUN_0040d5cf(void)

{
  return &DAT_00423e68;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// Library Function - Single Match
//  public: int __thiscall __crt_seh_guarded_call<int>::operator()<class
// <lambda_69a2805e680e0e292e8ba93315fe43a8>,class <lambda_f03950bc5685219e0bcd2087efbe011e> &,class
// <lambda_03fcd07e894ec930e3f35da366ca99d6> >(class <lambda_69a2805e680e0e292e8ba93315fe43a8>
// &&,class <lambda_f03950bc5685219e0bcd2087efbe011e> &,class
// <lambda_03fcd07e894ec930e3f35da366ca99d6> &&)
// 
// Library: Visual Studio 2019 Release

int __thiscall
__crt_seh_guarded_call<int>::operator()<>
          (__crt_seh_guarded_call<int> *this,<> *param_1,<> *param_2,<> *param_3)

{
  int iVar1;
  void *local_14;
  
  ___acrt_lock(*(int *)param_1);
  iVar1 = <>::operator()(param_2);
  FUN_0040d624();
  ExceptionList = local_14;
  return iVar1;
}



void FUN_0040d624(void)

{
  int unaff_EBP;
  
  ___acrt_unlock(**(int **)(unaff_EBP + 0x10));
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// Library Function - Single Match
//  public: int __thiscall __crt_seh_guarded_call<int>::operator()<class
// <lambda_8e746cf0007f6ed984d6f78af1fec997>,class <lambda_22ebabd17bc4fa466a2aca6d8deb888d> &,class
// <lambda_18ed0c0b38a6dc0daf1e7ac6d6adf05e> >(class <lambda_8e746cf0007f6ed984d6f78af1fec997>
// &&,class <lambda_22ebabd17bc4fa466a2aca6d8deb888d> &,class
// <lambda_18ed0c0b38a6dc0daf1e7ac6d6adf05e> &&)
// 
// Library: Visual Studio 2019 Release

int __thiscall
__crt_seh_guarded_call<int>::operator()<>
          (__crt_seh_guarded_call<int> *this,<> *param_1,<> *param_2,<> *param_3)

{
  int iVar1;
  void *local_14;
  
  ___acrt_lock(*(int *)param_1);
  iVar1 = FUN_0040d68b((int **)param_2);
  FUN_0040d67f();
  ExceptionList = local_14;
  return iVar1;
}



void FUN_0040d67f(void)

{
  int unaff_EBP;
  
  ___acrt_unlock(**(int **)(unaff_EBP + 0x10));
  return;
}



undefined4 __fastcall FUN_0040d68b(int **param_1)

{
  uint *puVar1;
  uint uVar2;
  _func_void_void_ptr_ulong_void_ptr *p_Var3;
  _func_void_void_ptr_ulong_void_ptr **pp_Var4;
  undefined4 uVar5;
  byte bVar6;
  _func_void_void_ptr_ulong_void_ptr *p_Var7;
  _func_void_void_ptr_ulong_void_ptr **pp_Var8;
  uint uVar9;
  _func_void_void_ptr_ulong_void_ptr **pp_Var10;
  
  puVar1 = (uint *)**param_1;
  if (puVar1 == (uint *)0x0) {
LAB_0040d785:
    uVar5 = 0xffffffff;
  }
  else {
    bVar6 = (byte)DAT_00423014 & 0x1f;
    pp_Var10 = (_func_void_void_ptr_ulong_void_ptr **)
               ((puVar1[1] ^ (uint)DAT_00423014) >> bVar6 |
               (puVar1[1] ^ (uint)DAT_00423014) << 0x20 - bVar6);
    pp_Var8 = (_func_void_void_ptr_ulong_void_ptr **)
              ((puVar1[2] ^ (uint)DAT_00423014) >> bVar6 |
              (puVar1[2] ^ (uint)DAT_00423014) << 0x20 - bVar6);
    p_Var7 = (_func_void_void_ptr_ulong_void_ptr *)
             ((*puVar1 ^ (uint)DAT_00423014) >> bVar6 |
             (*puVar1 ^ (uint)DAT_00423014) << 0x20 - bVar6);
    p_Var3 = p_Var7;
    if (pp_Var10 == pp_Var8) {
      uVar9 = (int)pp_Var8 - (int)p_Var7 >> 2;
      uVar2 = 0x200;
      if (uVar9 < 0x201) {
        uVar2 = uVar9;
      }
      uVar2 = uVar2 + uVar9;
      if (uVar2 == 0) {
        uVar2 = 0x20;
      }
      if (uVar2 < uVar9) {
LAB_0040d703:
        uVar2 = uVar9 + 4;
        p_Var3 = (_func_void_void_ptr_ulong_void_ptr *)__recalloc_base(p_Var7,uVar2,4);
        FUN_0040e374((LPVOID)0x0);
        if (p_Var3 == (_func_void_void_ptr_ulong_void_ptr *)0x0) goto LAB_0040d785;
      }
      else {
        p_Var3 = (_func_void_void_ptr_ulong_void_ptr *)__recalloc_base(p_Var7,uVar2,4);
        FUN_0040e374((LPVOID)0x0);
        if (p_Var3 == (_func_void_void_ptr_ulong_void_ptr *)0x0) goto LAB_0040d703;
      }
      p_Var7 = DAT_00423014;
      pp_Var8 = (_func_void_void_ptr_ulong_void_ptr **)(p_Var3 + uVar2 * 4);
      pp_Var10 = (_func_void_void_ptr_ulong_void_ptr **)(p_Var3 + uVar9 * 4);
      for (pp_Var4 = pp_Var10; pp_Var4 != pp_Var8; pp_Var4 = pp_Var4 + 1) {
        *pp_Var4 = p_Var7;
      }
    }
    p_Var7 = __crt_fast_encode_pointer<>((_func_void_void_ptr_ulong_void_ptr *)*param_1[1]);
    *pp_Var10 = p_Var7;
    p_Var3 = __crt_fast_encode_pointer<>(p_Var3);
    *(_func_void_void_ptr_ulong_void_ptr **)**param_1 = p_Var3;
    p_Var3 = __crt_fast_encode_pointer<>((_func_void_void_ptr_ulong_void_ptr *)(pp_Var10 + 1));
    *(_func_void_void_ptr_ulong_void_ptr **)(**param_1 + 4) = p_Var3;
    p_Var3 = __crt_fast_encode_pointer<>((_func_void_void_ptr_ulong_void_ptr *)pp_Var8);
    *(_func_void_void_ptr_ulong_void_ptr **)(**param_1 + 8) = p_Var3;
    uVar5 = 0;
  }
  return uVar5;
}



// Library Function - Single Match
//  public: int __thiscall <lambda_f03950bc5685219e0bcd2087efbe011e>::operator()(void)const 
// 
// Library: Visual Studio 2019 Release

int __thiscall <>::operator()(<> *this)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  uint *puVar4;
  sbyte sVar5;
  uint uVar6;
  uint *puVar7;
  uint *puVar8;
  uint *puVar9;
  uint *puVar10;
  
  uVar1 = DAT_00423014;
  puVar9 = **(uint ***)this;
  if (puVar9 == (uint *)0x0) {
    iVar2 = -1;
  }
  else {
    uVar6 = DAT_00423014 & 0x1f;
    sVar5 = (sbyte)uVar6;
    puVar8 = (uint *)((*puVar9 ^ DAT_00423014) >> sVar5 | (*puVar9 ^ DAT_00423014) << 0x20 - sVar5);
    puVar9 = (uint *)((puVar9[1] ^ DAT_00423014) >> sVar5 |
                     (puVar9[1] ^ DAT_00423014) << 0x20 - sVar5);
    if ((puVar8 != (uint *)0x0) &&
       (uVar3 = DAT_00423014, puVar10 = puVar9, puVar8 != (uint *)0xffffffff)) {
      while (puVar9 = puVar9 + -1, puVar8 <= puVar9) {
        if (*puVar9 != uVar1) {
          uVar3 = *puVar9 ^ uVar3;
          *puVar9 = uVar1;
          _guard_check_icall();
          (*(code *)(uVar3 >> (sbyte)uVar6 | uVar3 << 0x20 - (sbyte)uVar6))();
          uVar6 = DAT_00423014 & 0x1f;
          uVar3 = ***(uint ***)this ^ DAT_00423014;
          sVar5 = (sbyte)uVar6;
          puVar7 = (uint *)(uVar3 >> sVar5 | uVar3 << 0x20 - sVar5);
          uVar3 = (**(uint ***)this)[1] ^ DAT_00423014;
          puVar4 = (uint *)(uVar3 >> sVar5 | uVar3 << 0x20 - sVar5);
          uVar3 = DAT_00423014;
          if ((puVar7 != puVar8) || (puVar4 != puVar10)) {
            puVar9 = puVar4;
            puVar10 = puVar4;
            puVar8 = puVar7;
          }
        }
      }
      if (puVar8 != (uint *)0xffffffff) {
        FUN_0040e374(puVar8);
        uVar3 = DAT_00423014;
      }
      ***(uint ***)this = uVar3;
      *(uint *)(**(int **)this + 4) = uVar3;
      *(uint *)(**(int **)this + 8) = uVar3;
    }
    iVar2 = 0;
  }
  return iVar2;
}



// Library Function - Single Match
//  __crt_atexit
// 
// Library: Visual Studio 2019 Release

void __crt_atexit(undefined4 param_1)

{
  __register_onexit_function(0x6c,(undefined1)param_1);
  return;
}



// WARNING: Function: __EH_prolog3 replaced with injection: EH_prolog3
// WARNING: Function: __EH_epilog3 replaced with injection: EH_epilog3

void FUN_0040d87d(undefined param_1)

{
  undefined4 local_20;
  undefined1 *local_1c;
  undefined4 local_18;
  __crt_seh_guarded_call<int> local_11 [9];
  undefined4 local_8;
  undefined4 uStack_4;
  
  uStack_4 = 0x10;
  local_1c = &param_1;
  local_8 = 0;
  local_18 = 2;
  local_20 = 2;
  __crt_seh_guarded_call<int>::operator()<>
            (local_11,(<> *)&local_20,(<> *)&local_1c,(<> *)&local_18);
  return;
}



// Library Function - Single Match
//  __initialize_onexit_table
// 
// Library: Visual Studio 2019 Release

undefined4 __cdecl __initialize_onexit_table(int *param_1)

{
  int iVar1;
  
  iVar1 = DAT_00423014;
  if (param_1 == (int *)0x0) {
    return 0xffffffff;
  }
  if (*param_1 == param_1[2]) {
    *param_1 = DAT_00423014;
    param_1[1] = iVar1;
    param_1[2] = iVar1;
  }
  return 0;
}



// Library Function - Single Match
//  __register_onexit_function
// 
// Library: Visual Studio 2019 Release

void __register_onexit_function(undefined param_1,undefined param_2)

{
  undefined1 *local_18;
  undefined1 *local_14;
  undefined4 local_10;
  undefined4 local_c;
  __crt_seh_guarded_call<int> local_5;
  
  local_18 = &param_1;
  local_14 = &param_2;
  local_c = 2;
  local_10 = 2;
  __crt_seh_guarded_call<int>::operator()<>(&local_5,(<> *)&local_10,(<> *)&local_18,(<> *)&local_c)
  ;
  return;
}



// Library Function - Single Match
//  _uninitialize_allocated_memory
// 
// Library: Visual Studio 2019 Release

undefined _uninitialize_allocated_memory(void)

{
  <> local_5;
  
  <>::operator()(&local_5,(__crt_multibyte_data **)&DAT_004242ec);
  return 1;
}



// Library Function - Single Match
//  public: void __thiscall <lambda_af42a3ee9806e9a7305d451646e05244>::operator()(struct
// __crt_multibyte_data * &)const 
// 
// Library: Visual Studio 2019 Release

void __thiscall <>::operator()(<> *this,__crt_multibyte_data **param_1)

{
  int iVar1;
  
  LOCK();
  iVar1 = *(int *)*param_1 + -1;
  *(int *)*param_1 = iVar1;
  UNLOCK();
  if ((iVar1 == 0) && (*param_1 != (__crt_multibyte_data *)&DAT_00423200)) {
    FUN_0040e374(*param_1);
    *param_1 = (__crt_multibyte_data *)&DAT_00423200;
  }
  return;
}



// Library Function - Single Match
//  ___acrt_initialize
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void ___acrt_initialize(void)

{
  ___acrt_execute_initializers(&PTR_LAB_0041ca70,(undefined **)&DAT_0041caf0);
  return;
}



// Library Function - Single Match
//  ___acrt_uninitialize
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

undefined4 __cdecl ___acrt_uninitialize(char param_1)

{
  int in_EAX;
  undefined4 uVar1;
  
  if (param_1 != '\0') {
    if (DAT_00423d1c != 0) {
      in_EAX = __flushall();
    }
    return CONCAT31((int3)((uint)in_EAX >> 8),1);
  }
  uVar1 = ___acrt_execute_uninitializers(0x41ca70,0x41caf0);
  return uVar1;
}



// Library Function - Single Match
//  __controlfp_s
// 
// Library: Visual Studio 2019 Release

errno_t __cdecl __controlfp_s(uint *_CurrentState,uint _NewValue,uint _Mask)

{
  undefined4 *puVar1;
  errno_t eVar2;
  uint uVar3;
  
  uVar3 = _Mask & 0xfff7ffff;
  if ((_NewValue & uVar3 & 0xfcf0fce0) == 0) {
    if (_CurrentState == (uint *)0x0) {
      __control87(_NewValue,uVar3);
    }
    else {
      uVar3 = __control87(_NewValue,uVar3);
      *_CurrentState = uVar3;
    }
    eVar2 = 0;
  }
  else {
    if (_CurrentState != (uint *)0x0) {
      uVar3 = __control87(0,0);
      *_CurrentState = uVar3;
    }
    puVar1 = (undefined4 *)FUN_0040e304();
    eVar2 = 0x16;
    *puVar1 = 0x16;
    FUN_0040e223();
  }
  return eVar2;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// Library Function - Single Match
//  _terminate
// 
// Library: Visual Studio 2019 Release

void _terminate(void)

{
  code *pcVar1;
  __acrt_ptd *p_Var2;
  
  p_Var2 = FUN_004104a9();
  pcVar1 = *(code **)(p_Var2 + 0xc);
  if (pcVar1 != (code *)0x0) {
    _guard_check_icall();
    (*pcVar1)();
  }
                    // WARNING: Subroutine does not return
  _abort();
}



undefined4 __cdecl FUN_0040daef(char *param_1,int param_2,int param_3)

{
  char cVar1;
  undefined4 *puVar2;
  char *pcVar3;
  undefined4 uStack_10;
  
  if ((param_1 != (char *)0x0) && (param_2 != 0)) {
    if (param_3 != 0) {
      pcVar3 = param_1;
      do {
        cVar1 = pcVar3[param_3 - (int)param_1];
        *pcVar3 = cVar1;
        pcVar3 = pcVar3 + 1;
        if (cVar1 == '\0') {
          return 0;
        }
        param_2 = param_2 + -1;
      } while (param_2 != 0);
      *param_1 = '\0';
      puVar2 = (undefined4 *)FUN_0040e304();
      uStack_10 = 0x22;
      goto LAB_0040db15;
    }
    *param_1 = '\0';
  }
  puVar2 = (undefined4 *)FUN_0040e304();
  uStack_10 = 0x16;
LAB_0040db15:
  *puVar2 = uStack_10;
  FUN_0040e223();
  return uStack_10;
}



// Library Function - Single Match
//  _abort
// 
// Library: Visual Studio 2019 Release

void __cdecl _abort(void)

{
  code *pcVar1;
  int iVar2;
  BOOL BVar3;
  
  iVar2 = ___acrt_get_sigabrt_handler();
  if (iVar2 != 0) {
    FUN_004130c4(0x16);
  }
  if ((DAT_004230e8 & 2) != 0) {
    BVar3 = IsProcessorFeaturePresent(0x17);
    if (BVar3 != 0) {
      pcVar1 = (code *)swi(0x29);
      (*pcVar1)();
    }
    ___acrt_call_reportfault(3,0x40000015,1);
  }
  __exit(3);
  pcVar1 = (code *)swi(3);
  (*pcVar1)();
  return;
}



void FUN_0040db8d(uint param_1,uint param_2)

{
  __calloc_base(param_1,param_2);
  return;
}



// WARNING: Removing unreachable block (ram,0x0040dd91)

ulonglong __cdecl
FUN_0040db98(__acrt_ptd **param_1,byte *param_2,byte **param_3,uint param_4,byte param_5)

{
  byte bVar1;
  ulonglong uVar2;
  byte *pbVar3;
  char cVar4;
  undefined4 uVar5;
  uint uVar6;
  int iVar7;
  uint uVar8;
  uint uVar9;
  undefined8 uVar10;
  ulonglong uVar11;
  uint local_24;
  uint local_20;
  uint local_14;
  byte local_c;
  uint local_8;
  
  uVar5 = FUN_0040653b((int *)&param_2);
  uVar9 = param_4;
  pbVar3 = param_2;
  if ((char)uVar5 == '\0') {
LAB_0040dbde:
    if (param_3 != (byte **)0x0) {
      *param_3 = param_2;
    }
    return 0;
  }
  if ((param_4 != 0) && (((int)param_4 < 2 || (0x24 < (int)param_4)))) {
    *(undefined *)(param_1 + 7) = 1;
    param_1[6] = (__acrt_ptd *)0x16;
    FUN_0040e1a6((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0,param_1);
    goto LAB_0040dbde;
  }
  uVar2 = 0;
  local_c = *param_2;
  param_2 = param_2 + 1;
  if (*(char *)(param_1 + 5) == '\0') {
    FUN_004064e0(param_1);
  }
  uVar6 = FUN_0040c9cd((uint)local_c,8,(_locale_t)(param_1 + 3));
  while (uVar6 != 0) {
    local_c = *param_2;
    param_2 = param_2 + 1;
    uVar6 = FUN_0040c9cd((uint)local_c,8,(_locale_t)(param_1 + 3));
    uVar9 = param_4;
  }
  local_8 = (uint)param_5;
  if (local_c == 0x2d) {
    local_8 = local_8 | 2;
LAB_0040dc72:
    local_c = *param_2;
    param_2 = param_2 + 1;
  }
  else if (local_c == 0x2b) goto LAB_0040dc72;
  if ((uVar9 != 0) && (uVar9 != 0x10)) goto LAB_0040dcfe;
  if ((byte)(local_c - 0x30) < 10) {
    iVar7 = (char)local_c + -0x30;
LAB_0040dcba:
    if (iVar7 == 0) {
      bVar1 = *param_2;
      if ((bVar1 == 0x78) || (bVar1 == 0x58)) {
        if (uVar9 == 0) {
          uVar9 = 0x10;
        }
        local_c = param_2[1];
        param_2 = param_2 + 2;
      }
      else {
        if (uVar9 == 0) {
          uVar9 = 8;
        }
        param_2 = param_2 + 1;
        __crt_strtox::c_string_character_source<char>::unget
                  ((c_string_character_source<char> *)&param_2,bVar1);
      }
      goto LAB_0040dcfe;
    }
  }
  else {
    if ((byte)(local_c + 0x9f) < 0x1a) {
      iVar7 = (char)local_c + -0x57;
      goto LAB_0040dcba;
    }
    if ((byte)(local_c + 0xbf) < 0x1a) {
      iVar7 = (char)local_c + -0x37;
      goto LAB_0040dcba;
    }
  }
  if (uVar9 == 0) {
    uVar9 = 10;
  }
LAB_0040dcfe:
  uVar10 = __aulldiv(0xffffffff,0xffffffff,uVar9,(int)uVar9 >> 0x1f);
  while( true ) {
    uVar6 = (uint)(uVar2 >> 0x20);
    local_14 = (uint)uVar2;
    if ((byte)(local_c - 0x30) < 10) {
      uVar8 = (int)(char)local_c - 0x30;
    }
    else if ((byte)(local_c + 0x9f) < 0x1a) {
      uVar8 = (int)(char)local_c - 0x57;
    }
    else if ((byte)(local_c + 0xbf) < 0x1a) {
      uVar8 = (int)(char)local_c - 0x37;
    }
    else {
      uVar8 = 0xffffffff;
    }
    if (uVar9 <= uVar8) break;
    uVar11 = __allmul(uVar9,(int)uVar9 >> 0x1f,local_14,uVar6);
    uVar2 = uVar11 + uVar8;
    local_20 = (uint)((ulonglong)uVar10 >> 0x20);
    if ((uVar6 < local_20) ||
       ((uVar6 <= local_20 && (local_24 = (uint)uVar10, local_14 <= local_24)))) {
      uVar6 = 0;
    }
    else {
      uVar6 = 1;
    }
    local_8 = local_8 | (uVar2 < uVar11 | uVar6) << 2 | 8;
    local_c = *param_2;
    param_2 = param_2 + 1;
  }
  __crt_strtox::c_string_character_source<char>::unget
            ((c_string_character_source<char> *)&param_2,local_c);
  if ((local_8 & 8) == 0) {
    if (param_3 == (byte **)0x0) {
      return 0;
    }
    *param_3 = pbVar3;
    return 0;
  }
  cVar4 = FUN_00406ae5((byte)local_8,local_14,uVar6);
  if (cVar4 == '\0') {
    if ((local_8 & 2) != 0) {
      uVar2 = CONCAT44(-(uVar6 + (local_14 != 0)),-local_14);
    }
  }
  else {
    *(undefined *)(param_1 + 7) = 1;
    param_1[6] = (__acrt_ptd *)0x22;
    if ((local_8 & 1) != 0) {
      if ((local_8 & 2) == 0) {
        if (param_3 != (byte **)0x0) {
          *param_3 = param_2;
        }
        return 0x7fffffffffffffff;
      }
      if (param_3 != (byte **)0x0) {
        *param_3 = param_2;
      }
      return 0x8000000000000000;
    }
    uVar2 = 0xffffffffffffffff;
  }
  if (param_3 != (byte **)0x0) {
    *param_3 = param_2;
    return uVar2;
  }
  return uVar2;
}



// Library Function - Single Match
//  _wcsncmp
// 
// Library: Visual Studio 2019 Release

int __cdecl _wcsncmp(wchar_t *_Str1,wchar_t *_Str2,size_t _MaxCount)

{
  if (_MaxCount != 0) {
    for (; ((_MaxCount = _MaxCount - 1, _MaxCount != 0 && (*_Str1 != L'\0')) && (*_Str1 == *_Str2));
        _Str1 = _Str1 + 1) {
      _Str2 = _Str2 + 1;
    }
    return (uint)(ushort)*_Str1 - (uint)(ushort)*_Str2;
  }
  return _MaxCount;
}



// Library Function - Single Match
//  ___acrt_lock
// 
// Library: Visual Studio 2019 Release

void __cdecl ___acrt_lock(int param_1)

{
  EnterCriticalSection((LPCRITICAL_SECTION)(&DAT_00423e88 + param_1 * 0x18));
  return;
}



undefined4 FUN_0040df6a(void)

{
  undefined4 in_EAX;
  undefined4 extraout_EAX;
  int iVar1;
  LPCRITICAL_SECTION lpCriticalSection;
  
  if (DAT_00423fd8 != 0) {
    lpCriticalSection = (LPCRITICAL_SECTION)(&DAT_00423e70 + DAT_00423fd8 * 0x18);
    iVar1 = DAT_00423fd8;
    do {
      DeleteCriticalSection(lpCriticalSection);
      DAT_00423fd8 = DAT_00423fd8 + -1;
      lpCriticalSection = lpCriticalSection + -1;
      iVar1 = iVar1 + -1;
      in_EAX = extraout_EAX;
    } while (iVar1 != 0);
  }
  return CONCAT31((int3)((uint)in_EAX >> 8),1);
}



// Library Function - Single Match
//  ___acrt_unlock
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void __cdecl ___acrt_unlock(int param_1)

{
  LeaveCriticalSection((LPCRITICAL_SECTION)(&DAT_00423e88 + param_1 * 0x18));
  return;
}



uint FUN_0040dfb2(void)

{
  return *(uint *)((int)ProcessEnvironmentBlock + 0x68) >> 8 & 0xffffff01;
}



uint FUN_0040dfc4(void)

{
  return *(uint *)(*(int *)((int)ProcessEnvironmentBlock + 0x10) + 8) >> 0x1f;
}



bool FUN_0040dfd7(void)

{
  uint uVar1;
  int local_8;
  
  local_8 = 0;
  uVar1 = FUN_0040dfc4();
  if ((char)uVar1 == '\0') {
    FUN_0040e566((ulong)&local_8);
  }
  return local_8 != 1;
}



undefined4 __fastcall FUN_0040dffe(int param_1)

{
  DWORD dwErrCode;
  
  if (*(char *)(param_1 + 8) == '\0') {
    dwErrCode = GetLastError();
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined *)(param_1 + 8) = 1;
    SetLastError(dwErrCode);
    return 0;
  }
  return *(undefined4 *)(param_1 + 4);
}



// Library Function - Single Match
//  ___acrt_call_reportfault
// 
// Library: Visual Studio 2019 Release

void __cdecl ___acrt_call_reportfault(int param_1,DWORD param_2,DWORD param_3)

{
  uint uVar1;
  BOOL BVar2;
  LONG LVar3;
  _EXCEPTION_POINTERS local_32c;
  EXCEPTION_RECORD local_324;
  undefined4 local_2d4 [39];
  
  uVar1 = DAT_00423014 ^ (uint)&stack0xfffffffc;
  if (param_1 != -1) {
    FUN_00401e9b();
  }
  _memset(&local_324,0,0x50);
  _memset(local_2d4,0,0x2cc);
  local_32c.ExceptionRecord = &local_324;
  local_32c.ContextRecord = (PCONTEXT)local_2d4;
  local_2d4[0] = 0x10001;
  local_324.ExceptionCode = param_2;
  local_324.ExceptionFlags = param_3;
  BVar2 = IsDebuggerPresent();
  SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0);
  LVar3 = UnhandledExceptionFilter(&local_32c);
  if (((LVar3 == 0) && (BVar2 == 0)) && (param_1 != -1)) {
    FUN_00401e9b();
  }
  FUN_00402125(uVar1 ^ (uint)&stack0xfffffffc);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_0040e160(undefined4 param_1)

{
  _DAT_00423fdc = param_1;
  return;
}



void __cdecl
FUN_0040e16f(wchar_t *param_1,wchar_t *param_2,wchar_t *param_3,uint param_4,uintptr_t param_5)

{
  __acrt_ptd *local_2c [10];
  
  FUN_004055d0(local_2c,(undefined4 *)0x0);
  FUN_0040e1a6(param_1,param_2,param_3,param_4,param_5,local_2c);
  FUN_00405630(local_2c);
  return;
}



void __cdecl
FUN_0040e1a6(wchar_t *param_1,wchar_t *param_2,wchar_t *param_3,uint param_4,uintptr_t param_5,
            __acrt_ptd **param_6)

{
  __acrt_ptd *p_Var1;
  int iVar2;
  byte bVar3;
  code *pcVar4;
  
  p_Var1 = *param_6;
  if (((p_Var1 == (__acrt_ptd *)0x0) &&
      (p_Var1 = FUN_00405840(param_6), p_Var1 == (__acrt_ptd *)0x0)) ||
     (pcVar4 = *(code **)(p_Var1 + 0x35c), pcVar4 == (code *)0x0)) {
    iVar2 = FUN_0040dffe((int)param_6);
    bVar3 = (byte)DAT_00423014 & 0x1f;
    pcVar4 = (code *)((*(uint *)(&DAT_00423fdc + iVar2 * 4) ^ DAT_00423014) >> bVar3 |
                     (*(uint *)(&DAT_00423fdc + iVar2 * 4) ^ DAT_00423014) << 0x20 - bVar3);
    if (pcVar4 == (code *)0x0) {
                    // WARNING: Subroutine does not return
      __invoke_watson(param_1,param_2,param_3,param_4,param_5);
    }
  }
  _guard_check_icall();
  (*pcVar4)(param_1,param_2,param_3,param_4,param_5);
  return;
}



void FUN_0040e223(void)

{
  FUN_0040e16f((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  return;
}



// Library Function - Single Match
//  __invoke_watson
// 
// Library: Visual Studio 2019 Release

void __cdecl
__invoke_watson(wchar_t *param_1,wchar_t *param_2,wchar_t *param_3,uint param_4,uintptr_t param_5)

{
  code *pcVar1;
  BOOL BVar2;
  HANDLE hProcess;
  UINT uExitCode;
  
  BVar2 = IsProcessorFeaturePresent(0x17);
  if (BVar2 != 0) {
    pcVar1 = (code *)swi(0x29);
    (*pcVar1)();
  }
  ___acrt_call_reportfault(2,0xc0000417,1);
  uExitCode = 0xc0000417;
  hProcess = GetCurrentProcess();
  TerminateProcess(hProcess,uExitCode);
  return;
}



// Library Function - Multiple Matches With Different Base Names
//  ___acrt_errno_from_os_error
//  __get_errno_from_oserr
// 
// Libraries: Visual Studio 2012 Release, Visual Studio 2015 Release, Visual Studio 2017 Release,
// Visual Studio 2019 Release

int __cdecl FID_conflict____acrt_errno_from_os_error(ulong param_1)

{
  uint uVar1;
  
  uVar1 = 0;
  do {
    if (param_1 == (&DAT_0041caf0)[uVar1 * 2]) {
      return (&DAT_0041caf4)[uVar1 * 2];
    }
    uVar1 = uVar1 + 1;
  } while (uVar1 < 0x2d);
  if (param_1 - 0x13 < 0x12) {
    return 0xd;
  }
  return (-(uint)(0xe < param_1 - 0xbc) & 0xe) + 8;
}



// Library Function - Single Match
//  ___acrt_errno_map_os_error
// 
// Library: Visual Studio 2019 Release

void __cdecl ___acrt_errno_map_os_error(ulong param_1)

{
  ulong *puVar1;
  int iVar2;
  int *piVar3;
  
  puVar1 = (ulong *)FUN_0040e2f1();
  *puVar1 = param_1;
  iVar2 = FID_conflict____acrt_errno_from_os_error(param_1);
  piVar3 = (int *)FUN_0040e304();
  *piVar3 = iVar2;
  return;
}



void __cdecl FUN_0040e2cd(ulong param_1,int param_2)

{
  int iVar1;
  
  *(undefined *)(param_2 + 0x24) = 1;
  *(ulong *)(param_2 + 0x20) = param_1;
  iVar1 = FID_conflict____acrt_errno_from_os_error(param_1);
  *(undefined *)(param_2 + 0x1c) = 1;
  *(int *)(param_2 + 0x18) = iVar1;
  return;
}



__acrt_ptd * FUN_0040e2f1(void)

{
  __acrt_ptd *p_Var1;
  
  p_Var1 = FUN_004105fa();
  if (p_Var1 == (__acrt_ptd *)0x0) {
    return (__acrt_ptd *)&DAT_004230f4;
  }
  return p_Var1 + 0x14;
}



undefined * FUN_0040e304(void)

{
  __acrt_ptd *p_Var1;
  
  p_Var1 = FUN_004105fa();
  if (p_Var1 == (__acrt_ptd *)0x0) {
    return &DAT_004230f0;
  }
  return p_Var1 + 0x10;
}



// Library Function - Single Match
//  __calloc_base
// 
// Library: Visual Studio 2019 Release

LPVOID __cdecl __calloc_base(uint param_1,uint param_2)

{
  bool bVar1;
  int iVar2;
  undefined3 extraout_var;
  LPVOID pvVar3;
  undefined4 *puVar4;
  SIZE_T dwBytes;
  
  if ((param_1 == 0) || (param_2 <= 0xffffffe0 / param_1)) {
    dwBytes = param_1 * param_2;
    if (dwBytes == 0) {
      dwBytes = 1;
    }
    do {
      pvVar3 = HeapAlloc(DAT_00424304,8,dwBytes);
      if (pvVar3 != (LPVOID)0x0) {
        return pvVar3;
      }
      iVar2 = FUN_0040d599();
    } while ((iVar2 != 0) && (bVar1 = FUN_00412f2a(dwBytes), CONCAT31(extraout_var,bVar1) != 0));
  }
  puVar4 = (undefined4 *)FUN_0040e304();
  *puVar4 = 0xc;
  return (LPVOID)0x0;
}



void __cdecl FUN_0040e374(LPVOID param_1)

{
  BOOL BVar1;
  DWORD DVar2;
  int iVar3;
  int *piVar4;
  
  if (param_1 != (LPVOID)0x0) {
    BVar1 = HeapFree(DAT_00424304,0,param_1);
    if (BVar1 == 0) {
      DVar2 = GetLastError();
      iVar3 = FID_conflict____acrt_errno_from_os_error(DVar2);
      piVar4 = (int *)FUN_0040e304();
      *piVar4 = iVar3;
    }
  }
  return;
}



// Library Function - Single Match
//  int (__stdcall*__cdecl try_get_AreFileApisANSI(void))(void)
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

_func_int * __cdecl try_get_AreFileApisANSI(void)

{
  _func_void_void_ptr_ulong_void_ptr *p_Var1;
  
  p_Var1 = FUN_0040e4e1(0,"AreFileApisANSI",(int *)&DAT_0041d164,(int *)"AreFileApisANSI");
  return (_func_int *)p_Var1;
}



// Library Function - Single Match
//  int (__stdcall*__cdecl try_get_CompareStringEx(void))(wchar_t const *,unsigned long,wchar_t
// const *,int,wchar_t const *,int,struct _nlsversioninfo *,void *,long)
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

_func_int_wchar_t_ptr_ulong_wchar_t_ptr_int_wchar_t_ptr_int__nlsversioninfo_ptr_void_ptr_long *
__cdecl try_get_CompareStringEx(void)

{
  _func_int_wchar_t_ptr_ulong_wchar_t_ptr_int_wchar_t_ptr_int__nlsversioninfo_ptr_void_ptr_long
  *p_Var1;
  
  p_Var1 = (_func_int_wchar_t_ptr_ulong_wchar_t_ptr_int_wchar_t_ptr_int__nlsversioninfo_ptr_void_ptr_long
            *)FUN_0040e4e1(1,"CompareStringEx",(int *)&DAT_0041d178,(int *)"CompareStringEx");
  return p_Var1;
}



// Library Function - Multiple Matches With Different Base Names
//  int (__stdcall*__cdecl try_get_CompareStringEx(void))(wchar_t const *,unsigned long,wchar_t
// const *,int,wchar_t const *,int,struct _nlsversioninfo *,void *,long)
//  int (__stdcall*__cdecl try_get_LCMapStringEx(void))(wchar_t const *,unsigned long,wchar_t const
// *,int,wchar_t *,int,struct _nlsversioninfo *,void *,long)
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

_func_int_wchar_t_ptr_ulong_wchar_t_ptr_int_wchar_t_ptr_int__nlsversioninfo_ptr_void_ptr_long *
__cdecl try_get_LCMapStringEx(void)

{
  _func_int_wchar_t_ptr_ulong_wchar_t_ptr_int_wchar_t_ptr_int__nlsversioninfo_ptr_void_ptr_long
  *p_Var1;
  
  p_Var1 = (_func_int_wchar_t_ptr_ulong_wchar_t_ptr_int_wchar_t_ptr_int__nlsversioninfo_ptr_void_ptr_long
            *)FUN_0040e4e1(0x11,"LCMapStringEx",(int *)&DAT_0041d198,(int *)"LCMapStringEx");
  return p_Var1;
}



// Library Function - Single Match
//  unsigned long (__stdcall*__cdecl try_get_LocaleNameToLCID(void))(wchar_t const *,unsigned long)
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

_func_ulong_wchar_t_ptr_ulong * __cdecl try_get_LocaleNameToLCID(void)

{
  _func_void_void_ptr_ulong_void_ptr *p_Var1;
  
  p_Var1 = FUN_0040e4e1(0x13,"LocaleNameToLCID",(int *)&DAT_0041d1b0,(int *)"LocaleNameToLCID");
  return (_func_ulong_wchar_t_ptr_ulong *)p_Var1;
}



HMODULE __cdecl FUN_0040e416(int *param_1,int *param_2)

{
  HMODULE pHVar1;
  int iVar2;
  LPCWSTR lpLibFileName;
  HMODULE pHVar3;
  DWORD DVar4;
  int iVar5;
  
  do {
    if (param_1 == param_2) {
      return (HMODULE)0x0;
    }
    iVar2 = *param_1;
    pHVar3 = (HMODULE)(&DAT_00423fe0)[iVar2];
    if (pHVar3 == (HMODULE)0x0) {
      lpLibFileName = (LPCWSTR)(&PTR_u_api_ms_win_core_datetime_l1_1_1_0041cc58)[iVar2];
      pHVar3 = LoadLibraryExW(lpLibFileName,(HANDLE)0x0,0x800);
      if ((pHVar3 != (HMODULE)0x0) ||
         ((((DVar4 = GetLastError(), DVar4 == 0x57 &&
            (iVar5 = _wcsncmp(lpLibFileName,L"api-ms-",7), iVar5 != 0)) &&
           (iVar5 = _wcsncmp(lpLibFileName,L"ext-ms-",7), iVar5 != 0)) &&
          (pHVar3 = LoadLibraryExW(lpLibFileName,(HANDLE)0x0,0), pHVar3 != (HMODULE)0x0)))) {
        LOCK();
        pHVar1 = (HMODULE)(&DAT_00423fe0)[iVar2];
        (&DAT_00423fe0)[iVar2] = pHVar3;
        UNLOCK();
        if (pHVar1 == (HMODULE)0x0) {
          return pHVar3;
        }
        FreeLibrary(pHVar3);
        return pHVar3;
      }
      LOCK();
      (&DAT_00423fe0)[iVar2] = 0xffffffff;
      UNLOCK();
    }
    else if (pHVar3 != (HMODULE)0xffffffff) {
      return pHVar3;
    }
    param_1 = param_1 + 1;
  } while( true );
}



_func_void_void_ptr_ulong_void_ptr * __cdecl
FUN_0040e4e1(int param_1,LPCSTR param_2,int *param_3,int *param_4)

{
  _func_void_void_ptr_ulong_void_ptr **pp_Var1;
  HMODULE hModule;
  _func_void_void_ptr_ulong_void_ptr *p_Var2;
  byte bVar3;
  _func_void_void_ptr_ulong_void_ptr *p_Var4;
  
  pp_Var1 = (_func_void_void_ptr_ulong_void_ptr **)(&DAT_00424038 + param_1);
  bVar3 = (byte)DAT_00423014 & 0x1f;
  p_Var4 = (_func_void_void_ptr_ulong_void_ptr *)
           (((uint)*pp_Var1 ^ DAT_00423014) >> bVar3 |
           ((uint)*pp_Var1 ^ DAT_00423014) << 0x20 - bVar3);
  if (p_Var4 == (_func_void_void_ptr_ulong_void_ptr *)0xffffffff) {
    p_Var4 = (_func_void_void_ptr_ulong_void_ptr *)0x0;
  }
  else if (p_Var4 == (_func_void_void_ptr_ulong_void_ptr *)0x0) {
    hModule = FUN_0040e416(param_3,param_4);
    if ((hModule == (HMODULE)0x0) ||
       (p_Var4 = (_func_void_void_ptr_ulong_void_ptr *)GetProcAddress(hModule,param_2),
       p_Var4 == (_func_void_void_ptr_ulong_void_ptr *)0x0)) {
      bVar3 = 0x20 - ((byte)DAT_00423014 & 0x1f) & 0x1f;
      LOCK();
      *pp_Var1 = (_func_void_void_ptr_ulong_void_ptr *)
                 ((0xffffffffU >> bVar3 | -1 << 0x20 - bVar3) ^ DAT_00423014);
      UNLOCK();
      p_Var4 = (_func_void_void_ptr_ulong_void_ptr *)0x0;
    }
    else {
      p_Var2 = __crt_fast_encode_pointer<>(p_Var4);
      LOCK();
      *pp_Var1 = p_Var2;
      UNLOCK();
    }
  }
  return p_Var4;
}



undefined4 FUN_0040e566(ulong param_1)

{
  _func_void_void_ptr_ulong_void_ptr *p_Var1;
  undefined4 uVar2;
  void *unaff_ESI;
  void *pvVar3;
  
  p_Var1 = FUN_0040e4e1(0x19,"AppPolicyGetProcessTerminationMethod",(int *)&DAT_0041d1cc,
                        (int *)"AppPolicyGetProcessTerminationMethod");
  if (p_Var1 == (_func_void_void_ptr_ulong_void_ptr *)0x0) {
    uVar2 = 0xc0000225;
  }
  else {
    pvVar3 = (void *)0xfffffffa;
    _guard_check_icall();
    uVar2 = (*p_Var1)(pvVar3,param_1,unaff_ESI);
  }
  return uVar2;
}



// Library Function - Single Match
//  ___acrt_AreFileApisANSI@0
// 
// Library: Visual Studio 2019 Release

int ___acrt_AreFileApisANSI_0(void)

{
  _func_int *p_Var1;
  int iVar2;
  
  p_Var1 = try_get_AreFileApisANSI();
  if (p_Var1 != (_func_int *)0x0) {
    _guard_check_icall();
    iVar2 = (*p_Var1)();
    return iVar2;
  }
  return 1;
}



// Library Function - Multiple Matches With Different Base Names
//  ___acrt_CompareStringEx@36
//  ___acrt_LCMapStringEx@36
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void FID_conflict____acrt_CompareStringEx_36
               (wchar_t *param_1,ulong param_2,wchar_t *param_3,int param_4,wchar_t *param_5,
               int param_6,_nlsversioninfo *param_7,void *param_8,long param_9)

{
  _func_int_wchar_t_ptr_ulong_wchar_t_ptr_int_wchar_t_ptr_int__nlsversioninfo_ptr_void_ptr_long
  *p_Var1;
  LCID Locale;
  
  p_Var1 = try_get_CompareStringEx();
  if (p_Var1 == (_func_int_wchar_t_ptr_ulong_wchar_t_ptr_int_wchar_t_ptr_int__nlsversioninfo_ptr_void_ptr_long
                 *)0x0) {
    Locale = ___acrt_LocaleNameToLCID_8(param_1,0);
    CompareStringW(Locale,param_2,param_3,param_4,param_5,param_6);
  }
  else {
    _guard_check_icall();
    (*p_Var1)(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
  }
  return;
}



// Library Function - Single Match
//  ___acrt_FlsAlloc@4
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void ___acrt_FlsAlloc_4(void *param_1)

{
  _func_void_void_ptr_ulong_void_ptr *p_Var1;
  void *unaff_EBP;
  ulong unaff_ESI;
  
  p_Var1 = FUN_0040e4e1(0x1f,"FlsAlloc",(int *)&DAT_0041d1f8,(int *)&DAT_0041d200);
  if (p_Var1 == (_func_void_void_ptr_ulong_void_ptr *)0x0) {
    TlsAlloc();
  }
  else {
    _guard_check_icall();
    (*p_Var1)(param_1,unaff_ESI,unaff_EBP);
  }
  return;
}



void FUN_0040e661(void *param_1)

{
  _func_void_void_ptr_ulong_void_ptr *p_Var1;
  void *unaff_EBP;
  ulong unaff_ESI;
  
  p_Var1 = FUN_0040e4e1(0x20,"FlsFree",(int *)&DAT_0041d200,(int *)&DAT_0041d208);
  if (p_Var1 != (_func_void_void_ptr_ulong_void_ptr *)0x0) {
    _guard_check_icall();
    (*p_Var1)(param_1,unaff_ESI,unaff_EBP);
    return;
  }
                    // WARNING: Could not recover jumptable at 0x0040e69a. Too many branches
                    // WARNING: Treating indirect jump as call
  TlsFree((DWORD)param_1);
  return;
}



void FUN_0040e6a0(void *param_1)

{
  _func_void_void_ptr_ulong_void_ptr *p_Var1;
  void *unaff_EBP;
  ulong unaff_ESI;
  
  p_Var1 = FUN_0040e4e1(0x21,"FlsGetValue",(int *)&DAT_0041d208,(int *)&DAT_0041d210);
  if (p_Var1 != (_func_void_void_ptr_ulong_void_ptr *)0x0) {
    _guard_check_icall();
    (*p_Var1)(param_1,unaff_ESI,unaff_EBP);
    return;
  }
                    // WARNING: Could not recover jumptable at 0x0040e6d9. Too many branches
                    // WARNING: Treating indirect jump as call
  TlsGetValue((DWORD)param_1);
  return;
}



// Library Function - Single Match
//  ___acrt_FlsSetValue@8
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void ___acrt_FlsSetValue_8(void *param_1,LPVOID param_2)

{
  _func_void_void_ptr_ulong_void_ptr *p_Var1;
  void *unaff_ESI;
  
  p_Var1 = FUN_0040e4e1(0x22,"FlsSetValue",(int *)&DAT_0041d210,(int *)&PTR_DAT_0041d218);
  if (p_Var1 != (_func_void_void_ptr_ulong_void_ptr *)0x0) {
    _guard_check_icall();
    (*p_Var1)(param_1,(ulong)param_2,unaff_ESI);
    return;
  }
                    // WARNING: Could not recover jumptable at 0x0040e71b. Too many branches
                    // WARNING: Treating indirect jump as call
  TlsSetValue((DWORD)param_1,param_2);
  return;
}



// Library Function - Single Match
//  ___acrt_InitializeCriticalSectionEx@12
// 
// Library: Visual Studio 2019 Release

void ___acrt_InitializeCriticalSectionEx_12(LPCRITICAL_SECTION param_1,DWORD param_2,void *param_3)

{
  _func_void_void_ptr_ulong_void_ptr *p_Var1;
  
  p_Var1 = FUN_0040e4e1(0xf,"InitializeCriticalSectionEx",(int *)&DAT_0041d190,(int *)&DAT_0041d198)
  ;
  if (p_Var1 == (_func_void_void_ptr_ulong_void_ptr *)0x0) {
    InitializeCriticalSectionAndSpinCount(param_1,param_2);
  }
  else {
    _guard_check_icall();
    (*p_Var1)(param_1,param_2,param_3);
  }
  return;
}



// Library Function - Multiple Matches With Different Base Names
//  ___acrt_CompareStringEx@36
//  ___acrt_LCMapStringEx@36
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void FID_conflict____acrt_CompareStringEx_36
               (wchar_t *param_1,ulong param_2,wchar_t *param_3,int param_4,wchar_t *param_5,
               int param_6,_nlsversioninfo *param_7,void *param_8,long param_9)

{
  _func_int_wchar_t_ptr_ulong_wchar_t_ptr_int_wchar_t_ptr_int__nlsversioninfo_ptr_void_ptr_long
  *p_Var1;
  LCID Locale;
  
  p_Var1 = try_get_LCMapStringEx();
  if (p_Var1 == (_func_int_wchar_t_ptr_ulong_wchar_t_ptr_int_wchar_t_ptr_int__nlsversioninfo_ptr_void_ptr_long
                 *)0x0) {
    Locale = ___acrt_LocaleNameToLCID_8(param_1,0);
    LCMapStringW(Locale,param_2,param_3,param_4,param_5,param_6);
  }
  else {
    _guard_check_icall();
    (*p_Var1)(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
  }
  return;
}



// Library Function - Single Match
//  ___acrt_LocaleNameToLCID@8
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void ___acrt_LocaleNameToLCID_8(wchar_t *param_1,ulong param_2)

{
  _func_ulong_wchar_t_ptr_ulong *p_Var1;
  
  p_Var1 = try_get_LocaleNameToLCID();
  if (p_Var1 == (_func_ulong_wchar_t_ptr_ulong *)0x0) {
    ___acrt_DownlevelLocaleNameToLCID((ushort *)param_1);
  }
  else {
    _guard_check_icall();
    (*p_Var1)(param_1,param_2);
  }
  return;
}



// Library Function - Single Match
//  ___acrt_uninitialize_winapi_thunks
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

undefined __cdecl ___acrt_uninitialize_winapi_thunks(char param_1)

{
  HMODULE *ppHVar1;
  
  if (param_1 == '\0') {
    ppHVar1 = (HMODULE *)&DAT_00423fe0;
    do {
      if (*ppHVar1 != (HMODULE)0x0) {
        if (*ppHVar1 != (HMODULE)0xffffffff) {
          FreeLibrary(*ppHVar1);
        }
        *ppHVar1 = (HMODULE)0x0;
      }
      ppHVar1 = ppHVar1 + 1;
    } while (ppHVar1 != (HMODULE *)&DAT_00424038);
  }
  return 1;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4

int FUN_0040e844(void)

{
  int iVar1;
  int iVar2;
  int local_20;
  void *local_14;
  
  local_20 = 0;
  ___acrt_lock(8);
  for (iVar2 = 3; iVar2 != DAT_00423d18; iVar2 = iVar2 + 1) {
    iVar1 = *(int *)(DAT_00423d1c + iVar2 * 4);
    if (iVar1 != 0) {
      if ((*(uint *)(iVar1 + 0xc) >> 0xd & 1) != 0) {
        iVar1 = FUN_0041397b(*(FILE **)(DAT_00423d1c + iVar2 * 4));
        if (iVar1 != -1) {
          local_20 = local_20 + 1;
        }
      }
      DeleteCriticalSection((LPCRITICAL_SECTION)(*(int *)(DAT_00423d1c + iVar2 * 4) + 0x20));
      FUN_0040e374(*(LPVOID *)(DAT_00423d1c + iVar2 * 4));
      *(undefined4 *)(DAT_00423d1c + iVar2 * 4) = 0;
    }
  }
  FUN_0040e8e6();
  ExceptionList = local_14;
  return local_20;
}



void FUN_0040e8e6(void)

{
  ___acrt_unlock(8);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// Library Function - Single Match
//  public: void __thiscall __crt_seh_guarded_call<void>::operator()<class
// <lambda_2866be3712abc81a800a822484c830d8>,class <lambda_39ca0ed439415581b5b15c265174cece> &,class
// <lambda_2b24c74d71094a6cd0cb82e44167d71b> >(class <lambda_2866be3712abc81a800a822484c830d8>
// &&,class <lambda_39ca0ed439415581b5b15c265174cece> &,class
// <lambda_2b24c74d71094a6cd0cb82e44167d71b> &&)
// 
// Library: Visual Studio 2019 Release

void __thiscall
__crt_seh_guarded_call<void>::operator()<>
          (__crt_seh_guarded_call<void> *this,<> *param_1,<> *param_2,<> *param_3)

{
  undefined4 uVar1;
  int iVar2;
  void *local_14;
  
  __lock_file(*(FILE **)param_1);
  uVar1 = FUN_0040ea74(**(int **)param_2,*(int **)(param_2 + 4));
  if (((char)uVar1 != '\0') &&
     ((**(char **)(param_2 + 8) != '\0' || ((*(uint *)(**(int **)param_2 + 0xc) >> 1 & 1) != 0)))) {
    iVar2 = FUN_0040eb31(**(FILE ***)param_2);
    if (iVar2 == -1) {
      **(undefined4 **)(param_2 + 0xc) = 0xffffffff;
    }
    else {
      **(int **)(param_2 + 4) = **(int **)(param_2 + 4) + 1;
    }
  }
  FUN_0040e96f();
  ExceptionList = local_14;
  return;
}



void FUN_0040e96f(void)

{
  int unaff_EBP;
  
  __unlock_file(**(FILE ***)(unaff_EBP + 0x10));
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// Library Function - Single Match
//  public: void __thiscall __crt_seh_guarded_call<void>::operator()<class
// <lambda_2cc53f568c5a2bb6f192f930a45d44ea>,class <lambda_ab61a845afdef5b7c387490eaf3616ee> &,class
// <lambda_c2ffc0b7726aa6be21d5f0026187e748> >(class <lambda_2cc53f568c5a2bb6f192f930a45d44ea>
// &&,class <lambda_ab61a845afdef5b7c387490eaf3616ee> &,class
// <lambda_c2ffc0b7726aa6be21d5f0026187e748> &&)
// 
// Library: Visual Studio 2019 Release

void __thiscall
__crt_seh_guarded_call<void>::operator()<>
          (__crt_seh_guarded_call<void> *this,<> *param_1,<> *param_2,<> *param_3)

{
  int *piVar1;
  undefined4 uVar2;
  int *piVar3;
  int *local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  int *local_30;
  int local_2c;
  int local_28;
  int local_24;
  __crt_seh_guarded_call<void> local_1d [9];
  void *local_14;
  undefined4 uStack_c;
  undefined *local_8;
  
  local_8 = &DAT_00421f00;
  uStack_c = 0x40e987;
  ___acrt_lock(*(int *)param_1);
  local_8 = (undefined *)0x0;
  piVar1 = DAT_00423d1c + DAT_00423d18;
  for (piVar3 = DAT_00423d1c; local_30 = piVar3, piVar3 != piVar1; piVar3 = piVar3 + 1) {
    local_24 = *piVar3;
    uVar2 = FUN_0040ea74(local_24,*(int **)param_2);
    if ((char)uVar2 != '\0') {
      local_34 = *(undefined4 *)(param_2 + 8);
      local_38 = *(undefined4 *)(param_2 + 4);
      local_3c = *(undefined4 *)param_2;
      local_40 = &local_24;
      local_28 = local_24;
      local_2c = local_24;
      operator()<>(local_1d,(<> *)&local_2c,(<> *)&local_40,(<> *)&local_28);
    }
  }
  local_8 = (undefined *)0xfffffffe;
  FUN_0040ea1b();
  ExceptionList = local_14;
  return;
}



void FUN_0040ea1b(void)

{
  int unaff_EBP;
  
  ___acrt_unlock(**(int **)(unaff_EBP + 0x10));
  return;
}



// Library Function - Single Match
//  int __cdecl common_flush_all(bool)
// 
// Library: Visual Studio 2019 Release

int __cdecl common_flush_all(bool param_1)

{
  int *local_24;
  bool *local_20;
  int *local_1c;
  undefined4 local_18;
  undefined4 local_14;
  int local_10;
  int local_c;
  __crt_seh_guarded_call<void> local_5;
  
  local_c = 0;
  local_24 = &local_c;
  local_10 = 0;
  local_20 = &param_1;
  local_1c = &local_10;
  local_14 = 8;
  local_18 = 8;
  __crt_seh_guarded_call<void>::operator()<>
            (&local_5,(<> *)&local_18,(<> *)&local_24,(<> *)&local_14);
  if (param_1 == false) {
    local_c = local_10;
  }
  return local_c;
}



uint __cdecl FUN_0040ea74(int param_1,int *param_2)

{
  uint *puVar1;
  uint uVar2;
  
  if (param_1 != 0) {
    puVar1 = (uint *)(param_1 + 0xc);
    param_1 = *puVar1 >> 0xd;
    if ((param_1 & 1U) != 0) {
      uVar2 = FUN_0040eaa5(*puVar1);
      if ((char)uVar2 != '\0') {
        return CONCAT31((int3)(uVar2 >> 8),1);
      }
      *param_2 = *param_2 + 1;
      param_1 = (int)param_2;
    }
  }
  return param_1 & 0xffffff00;
}



uint __cdecl FUN_0040eaa5(uint param_1)

{
  undefined3 uVar1;
  
  uVar1 = (undefined3)((param_1 & 0xffffff03) >> 8);
  if (((char)(param_1 & 0xffffff03) == '\x02') && ((param_1 & 0xc0) != 0)) {
    return CONCAT31(uVar1,1);
  }
  return CONCAT31(uVar1,(char)(param_1 >> 0xb)) & 0xffffff01;
}



undefined4 __cdecl FUN_0040eac8(FILE *param_1,__acrt_ptd **param_2)

{
  int *piVar1;
  byte *pbVar2;
  char *pcVar3;
  uint uVar4;
  uint uVar5;
  
  piVar1 = &param_1->_flag;
  if ((((byte)*piVar1 & 3) == 2) && ((*piVar1 & 0xc0U) != 0)) {
    pbVar2 = (byte *)param_1->_cnt;
    uVar5 = (int)param_1->_ptr - (int)pbVar2;
    param_1->_ptr = (char *)pbVar2;
    param_1->_base = (char *)0x0;
    if (0 < (int)uVar5) {
      pcVar3 = (char *)__fileno(param_1);
      uVar4 = FUN_0041426c(pcVar3,pbVar2,uVar5,param_2);
      if (uVar5 != uVar4) {
        LOCK();
        *piVar1 = *piVar1 | 0x10;
        UNLOCK();
        return 0xffffffff;
      }
      if (((uint)*piVar1 >> 2 & 1) != 0) {
        LOCK();
        *piVar1 = *piVar1 & 0xfffffffd;
        UNLOCK();
      }
    }
  }
  return 0;
}



int __cdecl FUN_0040eb31(FILE *param_1)

{
  int iVar1;
  int iVar2;
  __acrt_ptd *local_2c [10];
  
  iVar2 = 0;
  FUN_004055d0(local_2c,(undefined4 *)0x0);
  if (param_1 == (FILE *)0x0) {
    iVar2 = common_flush_all(false);
    goto LAB_0040eb88;
  }
  iVar1 = FUN_0040eac8(param_1,local_2c);
  if (iVar1 == 0) {
    if (((uint)param_1->_flag >> 0xb & 1) == 0) goto LAB_0040eb88;
    iVar1 = __fileno(param_1);
    iVar1 = __commit(iVar1);
    if (iVar1 == 0) goto LAB_0040eb88;
  }
  iVar2 = -1;
LAB_0040eb88:
  FUN_00405630(local_2c);
  return iVar2;
}



// Library Function - Single Match
//  __flushall
// 
// Library: Visual Studio 2019 Release

int __cdecl __flushall(void)

{
  int iVar1;
  
  iVar1 = common_flush_all(true);
  return iVar1;
}



// Library Function - Single Match
//  ___acrt_stdio_free_buffer_nolock
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void __cdecl ___acrt_stdio_free_buffer_nolock(undefined4 *param_1)

{
  uint *puVar1;
  
  puVar1 = param_1 + 3;
  if (((*puVar1 >> 0xd & 1) != 0) && ((*puVar1 >> 6 & 1) != 0)) {
    FUN_0040e374((LPVOID)param_1[1]);
    LOCK();
    *puVar1 = *puVar1 & 0xfffffebf;
    UNLOCK();
    param_1[1] = 0;
    *param_1 = 0;
    param_1[2] = 0;
  }
  return;
}



// Library Function - Single Match
//  void __cdecl initialize_inherited_file_handles_nolock(void)
// 
// Library: Visual Studio 2019 Release

void __cdecl initialize_inherited_file_handles_nolock(void)

{
  byte bVar1;
  HANDLE hFile;
  DWORD DVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  _STARTUPINFOW local_4c;
  HANDLE *local_8;
  
  GetStartupInfoW(&local_4c);
  if ((local_4c.cbReserved2 != 0) && ((uint *)local_4c.lpReserved2 != (uint *)0x0)) {
    uVar4 = *(uint *)local_4c.lpReserved2;
    local_8 = (HANDLE *)((int)local_4c.lpReserved2 + uVar4 + 4);
    if (0x1fff < (int)uVar4) {
      uVar4 = 0x2000;
    }
    ___acrt_lowio_ensure_fh_exists(uVar4);
    if ((int)DAT_004242c8 < (int)uVar4) {
      uVar4 = DAT_004242c8;
    }
    uVar5 = 0;
    if (uVar4 != 0) {
      do {
        hFile = *local_8;
        if ((((hFile != (HANDLE)0xffffffff) && (hFile != (HANDLE)0xfffffffe)) &&
            (bVar1 = *(byte *)(uVar5 + 4 + (int)local_4c.lpReserved2), (bVar1 & 1) != 0)) &&
           (((bVar1 & 8) != 0 || (DVar2 = GetFileType(hFile), DVar2 != 0)))) {
          iVar3 = (uVar5 & 0x3f) * 0x38 + (&DAT_004240c8)[(int)uVar5 >> 6];
          *(HANDLE *)(iVar3 + 0x18) = *local_8;
          *(undefined *)(iVar3 + 0x28) = *(undefined *)(uVar5 + 4 + (int)local_4c.lpReserved2);
        }
        uVar5 = uVar5 + 1;
        local_8 = local_8 + 1;
      } while (uVar5 != uVar4);
    }
  }
  return;
}



void FUN_0040ec95(void)

{
  HANDLE hFile;
  int iVar1;
  uint uVar2;
  DWORD DVar3;
  
  uVar2 = 0;
  do {
    iVar1 = (uVar2 & 0x3f) * 0x38 + (&DAT_004240c8)[(int)uVar2 >> 6];
    if ((*(int *)(iVar1 + 0x18) == -1) || (*(int *)(iVar1 + 0x18) == -2)) {
      *(undefined *)(iVar1 + 0x28) = 0x81;
      if (uVar2 == 0) {
        DVar3 = 0xfffffff6;
      }
      else if (uVar2 == 1) {
        DVar3 = 0xfffffff5;
      }
      else {
        DVar3 = 0xfffffff4;
      }
      hFile = GetStdHandle(DVar3);
      if ((hFile != (HANDLE)0xffffffff) && (hFile != (HANDLE)0x0)) {
        DVar3 = GetFileType(hFile);
        if (DVar3 != 0) {
          *(HANDLE *)(iVar1 + 0x18) = hFile;
          if ((DVar3 & 0xff) == 2) {
            *(byte *)(iVar1 + 0x28) = *(byte *)(iVar1 + 0x28) | 0x40;
          }
          else if ((DVar3 & 0xff) == 3) {
            *(byte *)(iVar1 + 0x28) = *(byte *)(iVar1 + 0x28) | 8;
          }
          goto LAB_0040ed37;
        }
      }
      *(byte *)(iVar1 + 0x28) = *(byte *)(iVar1 + 0x28) | 0x40;
      *(undefined4 *)(iVar1 + 0x18) = 0xfffffffe;
      if (DAT_00423d1c != 0) {
        *(undefined4 *)(*(int *)(DAT_00423d1c + uVar2 * 4) + 0x10) = 0xfffffffe;
      }
    }
    else {
      *(byte *)(iVar1 + 0x28) = *(byte *)(iVar1 + 0x28) | 0x80;
    }
LAB_0040ed37:
    uVar2 = uVar2 + 1;
    if (uVar2 == 3) {
      return;
    }
  } while( true );
}



void FUN_0040ed9c(void)

{
  ___acrt_unlock(7);
  return;
}



// Library Function - Single Match
//  __malloc_base
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

LPVOID __cdecl __malloc_base(SIZE_T param_1)

{
  bool bVar1;
  int iVar2;
  undefined3 extraout_var;
  LPVOID pvVar3;
  undefined4 *puVar4;
  
  if (param_1 < 0xffffffe1) {
    if (param_1 == 0) {
      param_1 = 1;
    }
    do {
      pvVar3 = HeapAlloc(DAT_00424304,0,param_1);
      if (pvVar3 != (LPVOID)0x0) {
        return pvVar3;
      }
      iVar2 = FUN_0040d599();
    } while ((iVar2 != 0) && (bVar1 = FUN_00412f2a(param_1), CONCAT31(extraout_var,bVar1) != 0));
  }
  puVar4 = (undefined4 *)FUN_0040e304();
  *puVar4 = 0xc;
  return (LPVOID)0x0;
}



uint __cdecl FUN_0040ee1f(undefined (*param_1) [32],uint param_2)

{
  undefined *puVar1;
  undefined (*pauVar2) [32];
  uint uVar3;
  uint uVar4;
  undefined auVar5 [16];
  undefined auVar6 [32];
  undefined in_YMM1 [32];
  
  if (DAT_0042393c < 5) {
    if (DAT_0042393c < 1) {
      pauVar2 = param_1;
      if (param_1 != (undefined (*) [32])(*param_1 + param_2)) {
        do {
          if ((*pauVar2)[0] == '\0') break;
          pauVar2 = (undefined (*) [32])(*pauVar2 + 1);
        } while (pauVar2 != (undefined (*) [32])(*param_1 + param_2));
      }
      uVar3 = (int)pauVar2 - (int)param_1;
    }
    else {
      uVar4 = -(uint)(((uint)param_1 & 0xf) != 0) & 0x10 - ((uint)param_1 & 0xf);
      if (param_2 < uVar4) {
        uVar4 = param_2;
      }
      pauVar2 = param_1;
      if (param_1 != (undefined (*) [32])(*param_1 + uVar4)) {
        do {
          if ((*pauVar2)[0] == '\0') break;
          pauVar2 = (undefined (*) [32])(*pauVar2 + 1);
        } while (pauVar2 != (undefined (*) [32])(*param_1 + uVar4));
      }
      uVar3 = (int)pauVar2 - (int)param_1;
      if (uVar3 == uVar4) {
        puVar1 = *pauVar2;
        while ((pauVar2 != (undefined (*) [32])(puVar1 + (param_2 - uVar4 & 0xfffffff0)) &&
               (auVar5[0] = -((*pauVar2)[0] == '\0'), auVar5[1] = -((*pauVar2)[1] == '\0'),
               auVar5[2] = -((*pauVar2)[2] == '\0'), auVar5[3] = -((*pauVar2)[3] == '\0'),
               auVar5[4] = -((*pauVar2)[4] == '\0'), auVar5[5] = -((*pauVar2)[5] == '\0'),
               auVar5[6] = -((*pauVar2)[6] == '\0'), auVar5[7] = -((*pauVar2)[7] == '\0'),
               auVar5[8] = -((*pauVar2)[8] == '\0'), auVar5[9] = -((*pauVar2)[9] == '\0'),
               auVar5[10] = -((*pauVar2)[10] == '\0'), auVar5[11] = -((*pauVar2)[0xb] == '\0'),
               auVar5[12] = -((*pauVar2)[0xc] == '\0'), auVar5[13] = -((*pauVar2)[0xd] == '\0'),
               auVar5[14] = -((*pauVar2)[0xe] == '\0'), auVar5[15] = -((*pauVar2)[0xf] == '\0'),
               (ushort)((ushort)(SUB161(auVar5 >> 7,0) & 1) |
                        (ushort)(SUB161(auVar5 >> 0xf,0) & 1) << 1 |
                        (ushort)(SUB161(auVar5 >> 0x17,0) & 1) << 2 |
                        (ushort)(SUB161(auVar5 >> 0x1f,0) & 1) << 3 |
                        (ushort)(SUB161(auVar5 >> 0x27,0) & 1) << 4 |
                        (ushort)(SUB161(auVar5 >> 0x2f,0) & 1) << 5 |
                        (ushort)(SUB161(auVar5 >> 0x37,0) & 1) << 6 |
                        (ushort)(SUB161(auVar5 >> 0x3f,0) & 1) << 7 |
                        (ushort)(SUB161(auVar5 >> 0x47,0) & 1) << 8 |
                        (ushort)(SUB161(auVar5 >> 0x4f,0) & 1) << 9 |
                        (ushort)(SUB161(auVar5 >> 0x57,0) & 1) << 10 |
                        (ushort)(SUB161(auVar5 >> 0x5f,0) & 1) << 0xb |
                        (ushort)(SUB161(auVar5 >> 0x67,0) & 1) << 0xc |
                        (ushort)(SUB161(auVar5 >> 0x6f,0) & 1) << 0xd |
                        (ushort)(SUB161(auVar5 >> 0x77,0) & 1) << 0xe |
                       (ushort)(auVar5[15] >> 7) << 0xf) == 0))) {
          pauVar2 = (undefined (*) [32])(*pauVar2 + 0x10);
        }
        for (; (pauVar2 != (undefined (*) [32])(*param_1 + param_2) && ((*pauVar2)[0] != '\0'));
            pauVar2 = (undefined (*) [32])(*pauVar2 + 1)) {
        }
        uVar3 = (int)pauVar2 - (int)param_1;
      }
    }
  }
  else {
    uVar4 = -(uint)(((uint)param_1 & 0x1f) != 0) & 0x20 - ((uint)param_1 & 0x1f);
    if (param_2 < uVar4) {
      uVar4 = param_2;
    }
    pauVar2 = param_1;
    if (param_1 != (undefined (*) [32])(*param_1 + uVar4)) {
      do {
        if ((*pauVar2)[0] == '\0') break;
        pauVar2 = (undefined (*) [32])(*pauVar2 + 1);
      } while (pauVar2 != (undefined (*) [32])(*param_1 + uVar4));
    }
    uVar3 = (int)pauVar2 - (int)param_1;
    if (uVar3 == uVar4) {
      puVar1 = *pauVar2;
      auVar5 = vpxor_avx(in_YMM1._0_16_,in_YMM1._0_16_);
      while ((pauVar2 != (undefined (*) [32])(puVar1 + (param_2 - uVar4 & 0xffffffe0)) &&
             (auVar6 = vpcmpeqb_avx2(ZEXT1632(auVar5),*pauVar2),
             ((uint)(SUB321(auVar6 >> 7,0) & 1) | (uint)(SUB321(auVar6 >> 0xf,0) & 1) << 1 |
              (uint)(SUB321(auVar6 >> 0x17,0) & 1) << 2 | (uint)(SUB321(auVar6 >> 0x1f,0) & 1) << 3
              | (uint)(SUB321(auVar6 >> 0x27,0) & 1) << 4 |
              (uint)(SUB321(auVar6 >> 0x2f,0) & 1) << 5 | (uint)(SUB321(auVar6 >> 0x37,0) & 1) << 6
              | (uint)(SUB321(auVar6 >> 0x3f,0) & 1) << 7 |
              (uint)(SUB321(auVar6 >> 0x47,0) & 1) << 8 | (uint)(SUB321(auVar6 >> 0x4f,0) & 1) << 9
              | (uint)(SUB321(auVar6 >> 0x57,0) & 1) << 10 |
              (uint)(SUB321(auVar6 >> 0x5f,0) & 1) << 0xb |
              (uint)(SUB321(auVar6 >> 0x67,0) & 1) << 0xc |
              (uint)(SUB321(auVar6 >> 0x6f,0) & 1) << 0xd |
              (uint)(SUB321(auVar6 >> 0x77,0) & 1) << 0xe | (uint)SUB321(auVar6 >> 0x7f,0) << 0xf |
              (uint)(SUB321(auVar6 >> 0x87,0) & 1) << 0x10 |
              (uint)(SUB321(auVar6 >> 0x8f,0) & 1) << 0x11 |
              (uint)(SUB321(auVar6 >> 0x97,0) & 1) << 0x12 |
              (uint)(SUB321(auVar6 >> 0x9f,0) & 1) << 0x13 |
              (uint)(SUB321(auVar6 >> 0xa7,0) & 1) << 0x14 |
              (uint)(SUB321(auVar6 >> 0xaf,0) & 1) << 0x15 |
              (uint)(SUB321(auVar6 >> 0xb7,0) & 1) << 0x16 | (uint)SUB321(auVar6 >> 0xbf,0) << 0x17
              | (uint)(SUB321(auVar6 >> 199,0) & 1) << 0x18 |
              (uint)(SUB321(auVar6 >> 0xcf,0) & 1) << 0x19 |
              (uint)(SUB321(auVar6 >> 0xd7,0) & 1) << 0x1a |
              (uint)(SUB321(auVar6 >> 0xdf,0) & 1) << 0x1b |
              (uint)(SUB321(auVar6 >> 0xe7,0) & 1) << 0x1c |
              (uint)(SUB321(auVar6 >> 0xef,0) & 1) << 0x1d |
              (uint)(SUB321(auVar6 >> 0xf7,0) & 1) << 0x1e | (uint)(byte)(auVar6[31] >> 7) << 0x1f)
             == 0))) {
        pauVar2 = pauVar2 + 1;
      }
      for (; (pauVar2 != (undefined (*) [32])(*param_1 + param_2) && ((*pauVar2)[0] != '\0'));
          pauVar2 = (undefined (*) [32])(*pauVar2 + 1)) {
      }
      uVar3 = (int)pauVar2 - (int)param_1;
    }
  }
  return uVar3;
}



uint __cdecl FUN_0040ef41(short *param_1,uint param_2)

{
  int iVar1;
  uint uVar3;
  uint uVar4;
  undefined (*pauVar5) [32];
  undefined auVar6 [16];
  undefined auVar7 [32];
  undefined in_YMM1 [32];
  short *psVar2;
  
  psVar2 = param_1;
  if (DAT_0042393c < 5) {
    if (DAT_0042393c < 1) {
      if (param_1 != param_1 + param_2) {
        do {
          if (*psVar2 == 0) break;
          psVar2 = psVar2 + 1;
        } while (psVar2 != param_1 + param_2);
      }
      iVar1 = (int)psVar2 - (int)param_1;
      goto LAB_0040f0e9;
    }
    if (((uint)param_1 & 1) == 0) {
      uVar4 = (-(uint)(((uint)param_1 & 0xf) != 0) & 0x10 - ((uint)param_1 & 0xf)) >> 1;
      if (param_2 < uVar4) {
        uVar4 = param_2;
      }
      if (param_1 != param_1 + uVar4) {
        do {
          if (*psVar2 == 0) break;
          psVar2 = psVar2 + 1;
        } while (psVar2 != param_1 + uVar4);
      }
      uVar3 = (int)psVar2 - (int)param_1 >> 1;
      if (uVar3 != uVar4) {
        return uVar3;
      }
      for (psVar2 = param_1 + uVar3; psVar2 != param_1 + (param_2 - uVar4 & 0xfffffff0) + uVar3;
          psVar2 = psVar2 + 8) {
        auVar6._0_2_ = -(ushort)(*psVar2 == 0);
        auVar6._2_2_ = -(ushort)(psVar2[1] == 0);
        auVar6._4_2_ = -(ushort)(psVar2[2] == 0);
        auVar6._6_2_ = -(ushort)(psVar2[3] == 0);
        auVar6._8_2_ = -(ushort)(psVar2[4] == 0);
        auVar6._10_2_ = -(ushort)(psVar2[5] == 0);
        auVar6._12_2_ = -(ushort)(psVar2[6] == 0);
        auVar6._14_2_ = -(ushort)(psVar2[7] == 0);
        if ((ushort)((ushort)(SUB161(auVar6 >> 7,0) & 1) |
                     (ushort)(SUB161(auVar6 >> 0xf,0) & 1) << 1 |
                     (ushort)(SUB161(auVar6 >> 0x17,0) & 1) << 2 |
                     (ushort)(SUB161(auVar6 >> 0x1f,0) & 1) << 3 |
                     (ushort)(SUB161(auVar6 >> 0x27,0) & 1) << 4 |
                     (ushort)(SUB161(auVar6 >> 0x2f,0) & 1) << 5 |
                     (ushort)(SUB161(auVar6 >> 0x37,0) & 1) << 6 |
                     (ushort)(SUB161(auVar6 >> 0x3f,0) & 1) << 7 |
                     (ushort)(SUB161(auVar6 >> 0x47,0) & 1) << 8 |
                     (ushort)(SUB161(auVar6 >> 0x4f,0) & 1) << 9 |
                     (ushort)(SUB161(auVar6 >> 0x57,0) & 1) << 10 |
                     (ushort)(SUB161(auVar6 >> 0x5f,0) & 1) << 0xb |
                     (ushort)(SUB161(auVar6 >> 0x67,0) & 1) << 0xc |
                     (ushort)(SUB161(auVar6 >> 0x6f,0) & 1) << 0xd |
                     (ushort)((byte)(auVar6._14_2_ >> 7) & 1) << 0xe | auVar6._14_2_ & 0x8000) != 0)
        break;
      }
      for (; (psVar2 != param_1 + param_2 && (*psVar2 != 0)); psVar2 = psVar2 + 1) {
      }
    }
    else if (param_1 != param_1 + param_2) {
      do {
        if (*psVar2 == 0) break;
        psVar2 = psVar2 + 1;
      } while (psVar2 != param_1 + param_2);
    }
  }
  else {
    if (((uint)param_1 & 1) == 0) {
      uVar4 = (-(uint)(((uint)param_1 & 0x1f) != 0) & 0x20 - ((uint)param_1 & 0x1f)) >> 1;
      if (param_2 < uVar4) {
        uVar4 = param_2;
      }
      if (param_1 != param_1 + uVar4) {
        do {
          if (*psVar2 == 0) break;
          psVar2 = psVar2 + 1;
        } while (psVar2 != param_1 + uVar4);
      }
      uVar3 = (int)psVar2 - (int)param_1 >> 1;
      if (uVar3 != uVar4) {
        return uVar3;
      }
      pauVar5 = (undefined (*) [32])(param_1 + uVar3);
      auVar6 = vpxor_avx(in_YMM1._0_16_,in_YMM1._0_16_);
      while ((pauVar5 != (undefined (*) [32])(param_1 + (param_2 - uVar4 & 0xffffffe0) + uVar3) &&
             (auVar7 = vpcmpeqw_avx2(ZEXT1632(auVar6),*pauVar5),
             ((uint)(SUB321(auVar7 >> 7,0) & 1) | (uint)(SUB321(auVar7 >> 0xf,0) & 1) << 1 |
              (uint)(SUB321(auVar7 >> 0x17,0) & 1) << 2 | (uint)(SUB321(auVar7 >> 0x1f,0) & 1) << 3
              | (uint)(SUB321(auVar7 >> 0x27,0) & 1) << 4 |
              (uint)(SUB321(auVar7 >> 0x2f,0) & 1) << 5 | (uint)(SUB321(auVar7 >> 0x37,0) & 1) << 6
              | (uint)(SUB321(auVar7 >> 0x3f,0) & 1) << 7 |
              (uint)(SUB321(auVar7 >> 0x47,0) & 1) << 8 | (uint)(SUB321(auVar7 >> 0x4f,0) & 1) << 9
              | (uint)(SUB321(auVar7 >> 0x57,0) & 1) << 10 |
              (uint)(SUB321(auVar7 >> 0x5f,0) & 1) << 0xb |
              (uint)(SUB321(auVar7 >> 0x67,0) & 1) << 0xc |
              (uint)(SUB321(auVar7 >> 0x6f,0) & 1) << 0xd |
              (uint)(SUB321(auVar7 >> 0x77,0) & 1) << 0xe | (uint)SUB321(auVar7 >> 0x7f,0) << 0xf |
              (uint)(SUB321(auVar7 >> 0x87,0) & 1) << 0x10 |
              (uint)(SUB321(auVar7 >> 0x8f,0) & 1) << 0x11 |
              (uint)(SUB321(auVar7 >> 0x97,0) & 1) << 0x12 |
              (uint)(SUB321(auVar7 >> 0x9f,0) & 1) << 0x13 |
              (uint)(SUB321(auVar7 >> 0xa7,0) & 1) << 0x14 |
              (uint)(SUB321(auVar7 >> 0xaf,0) & 1) << 0x15 |
              (uint)(SUB321(auVar7 >> 0xb7,0) & 1) << 0x16 | (uint)SUB321(auVar7 >> 0xbf,0) << 0x17
              | (uint)(SUB321(auVar7 >> 199,0) & 1) << 0x18 |
              (uint)(SUB321(auVar7 >> 0xcf,0) & 1) << 0x19 |
              (uint)(SUB321(auVar7 >> 0xd7,0) & 1) << 0x1a |
              (uint)(SUB321(auVar7 >> 0xdf,0) & 1) << 0x1b |
              (uint)(SUB321(auVar7 >> 0xe7,0) & 1) << 0x1c |
              (uint)(SUB321(auVar7 >> 0xef,0) & 1) << 0x1d |
              (uint)(SUB321(auVar7 >> 0xf7,0) & 1) << 0x1e | (uint)(byte)(auVar7[31] >> 7) << 0x1f)
             == 0))) {
        pauVar5 = pauVar5 + 1;
      }
      for (; (pauVar5 != (undefined (*) [32])(param_1 + param_2) && (*(short *)*pauVar5 != 0));
          pauVar5 = (undefined (*) [32])(*pauVar5 + 2)) {
      }
      return (int)pauVar5 - (int)param_1 >> 1;
    }
    if (param_1 != param_1 + param_2) {
      do {
        if (*psVar2 == 0) break;
        psVar2 = psVar2 + 1;
      } while (psVar2 != param_1 + param_2);
    }
  }
  iVar1 = (int)psVar2 - (int)param_1;
LAB_0040f0e9:
  return iVar1 >> 1;
}



// Library Function - Single Match
//  ___acrt_update_locale_info
// 
// Library: Visual Studio 2019 Release

void __cdecl ___acrt_update_locale_info(int param_1,LPVOID *param_2)

{
  LPVOID pvVar1;
  
  if ((*param_2 != DAT_004242e0) && ((*(uint *)(param_1 + 0x350) & DAT_00423778) == 0)) {
    pvVar1 = ___acrt_update_thread_locale_data();
    *param_2 = pvVar1;
  }
  return;
}



void __cdecl FUN_0040f11e(int param_1,LPVOID *param_2,int param_3)

{
  LPVOID pvVar1;
  
  if ((*param_2 != (LPVOID)(&DAT_004242e0)[param_3]) &&
     ((*(uint *)(param_1 + 0x350) & DAT_00423778) == 0)) {
    pvVar1 = ___acrt_update_thread_locale_data();
    *param_2 = pvVar1;
  }
  return;
}



void __cdecl FUN_0040f14f(int param_1,int *param_2)

{
  int iVar1;
  
  if ((*param_2 != DAT_004242ec) && ((*(uint *)(param_1 + 0x350) & DAT_00423778) == 0)) {
    iVar1 = FUN_00411b8b();
    *param_2 = iVar1;
  }
  return;
}



void __cdecl FUN_0040f17c(int param_1,int *param_2,int param_3)

{
  int iVar1;
  
  if ((*param_2 != (&DAT_004242ec)[param_3]) && ((*(uint *)(param_1 + 0x350) & DAT_00423778) == 0))
  {
    iVar1 = FUN_00411b8b();
    *param_2 = iVar1;
  }
  return;
}



// Library Function - Single Match
//  enum __acrt_fp_class __cdecl __acrt_fp_classify(double const &)
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

__acrt_fp_class __cdecl __acrt_fp_classify(double *param_1)

{
  uint uVar1;
  __acrt_fp_class _Stack_10;
  
  uVar1 = *(uint *)((int)param_1 + 4);
  if ((uVar1 >> 0x14 & 0x7ff) == 0x7ff) {
    if ((*(uint *)param_1 | uVar1 & 0xfffff) == 0) {
      _Stack_10 = 1;
    }
    else if (((((int)uVar1 < 1) && ((int)uVar1 < 0)) && (*(uint *)param_1 == 0)) &&
            ((uVar1 & 0xfffff) == 0x80000)) {
      _Stack_10 = 4;
    }
    else if ((uVar1 & 0x80000) == 0) {
      _Stack_10 = 3;
    }
    else {
      _Stack_10 = 2;
    }
  }
  else {
    _Stack_10 = 0;
  }
  return _Stack_10;
}



// Library Function - Single Match
//  bool __cdecl fe_to_nearest(double const * const,unsigned __int64,short)
// 
// Library: Visual Studio 2019 Release

bool __cdecl fe_to_nearest(double *param_1,__uint64 param_2,short param_3)

{
  uint uVar1;
  uint uVar2;
  byte bVar3;
  ulonglong uVar4;
  longlong lVar5;
  
  uVar1 = *(uint *)((int)param_1 + 4);
  uVar2 = *(uint *)param_1;
  bVar3 = (byte)(param_2 >> 0x20);
  uVar4 = __aullshr(bVar3,uVar1 & (uint)param_2 & 0xfffff);
  if ((ushort)uVar4 < 9) {
    if ((ushort)uVar4 < 8) {
      return false;
    }
    lVar5 = __allshl(bVar3,0);
    if (((uint)(lVar5 + -1) & uVar2 | (uint)((ulonglong)(lVar5 + -1) >> 0x20) & uVar1 & 0xfffff) ==
        0) {
      if (param_2._4_2_ == 0x30) {
        bVar3 = 0;
        if ((uVar1 & 0x7ff00000) != 0) {
          bVar3 = 1;
        }
      }
      else {
        uVar4 = __aullshr(bVar3,uVar1 >> 4 & (uint)param_2 & 0xffff);
        bVar3 = (byte)uVar4;
      }
      return (bool)(bVar3 & 1);
    }
  }
  return true;
}



int __cdecl
FUN_0040f2b2(double *param_1,char *param_2,uint param_3,uint *******param_4,int param_5,
            size_t param_6,byte param_7,int param_8,int param_9,__acrt_ptd **param_10)

{
  char cVar1;
  short sVar2;
  ushort uVar3;
  int iVar4;
  char *pcVar5;
  char *pcVar6;
  ushort uVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  char *_Dst;
  char *pcVar11;
  bool bVar12;
  ulonglong uVar13;
  undefined8 uVar14;
  longlong lVar15;
  char local_2c;
  uint local_1c;
  uint local_18;
  uint local_14;
  
  if ((int)param_6 < 0) {
    param_6 = 0;
  }
  *param_2 = '\0';
  if (param_3 <= param_6 + 0xb) {
    *(undefined *)(param_10 + 7) = 1;
    param_10[6] = (__acrt_ptd *)0x22;
    FUN_0040e1a6((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0,param_10);
    return 0x22;
  }
  if ((*(uint *)((int)param_1 + 4) >> 0x14 & 0x7ff) == 0x7ff) {
    iVar4 = FUN_0040f5df((undefined4 *)param_1,param_2,param_3,param_4,param_5,param_6,'\0',param_8,
                         param_9,param_10);
    if (iVar4 != 0) {
      *param_2 = '\0';
      return iVar4;
    }
    pcVar5 = _strrchr(param_2,0x65);
    if (pcVar5 == (char *)0x0) {
      return 0;
    }
    *pcVar5 = (param_7 ^ 1) * ' ' + 'P';
    pcVar5[3] = '\0';
    return 0;
  }
  if ((*(int *)((int)param_1 + 4) < 1) && (*(int *)((int)param_1 + 4) < 0)) {
    *param_2 = '-';
    param_2 = param_2 + 1;
  }
  pcVar5 = param_2 + 1;
  sVar2 = (ushort)(param_7 ^ 1) * 0x20 + 7;
  local_14 = 0x3ff;
  if ((*(uint *)((int)param_1 + 4) & 0x7ff00000) == 0) {
    *param_2 = '0';
    if ((*(uint *)param_1 | *(uint *)((int)param_1 + 4) & 0xfffff) == 0) {
      local_14 = 0;
    }
    else {
      local_14 = 0x3fe;
    }
  }
  else {
    *param_2 = '1';
  }
  _Dst = param_2 + 2;
  if (param_6 == 0) {
    cVar1 = '\0';
  }
  else {
    if (*(char *)(param_10 + 5) == '\0') {
      FUN_004064e0(param_10);
    }
    cVar1 = ***(char ***)(param_10[3] + 0x88);
  }
  *pcVar5 = cVar1;
  if (((*(uint *)((int)param_1 + 4) & 0xfffff) != 0) || (*(int *)param_1 != 0)) {
    uVar7 = 0x30;
    local_1c = 0xf0000;
    local_18 = 0;
    do {
      if ((int)param_6 < 1) {
        cVar1 = FUN_0040faf2(param_1,local_18,local_1c,(uint)uVar7,param_9);
        pcVar11 = _Dst;
        if (cVar1 != '\0') goto LAB_0040f49c;
        goto LAB_0040f4da;
      }
      uVar13 = __aullshr((byte)uVar7,*(uint *)((int)param_1 + 4) & local_1c);
      uVar3 = (short)uVar13 + 0x30;
      if (0x39 < uVar3) {
        uVar3 = uVar3 + sVar2;
      }
      *_Dst = (char)uVar3;
      uVar7 = uVar7 - 4;
      _Dst = _Dst + 1;
      local_18 = local_18 >> 4 | local_1c << 0x1c;
      local_1c = local_1c >> 4;
      param_6 = param_6 - 1;
    } while (-1 < (short)uVar7);
  }
LAB_0040f4c6:
  if (0 < (int)param_6) {
    _memset(_Dst,0x30,param_6);
    _Dst = _Dst + param_6;
  }
LAB_0040f4da:
  if (*pcVar5 == '\0') {
    _Dst = pcVar5;
  }
  *_Dst = (param_7 ^ 1) * ' ' + 'P';
  uVar13 = __aullshr(0x34,*(uint *)((int)param_1 + 4));
  uVar8 = (uint)uVar13 & 0x7ff;
  pcVar5 = _Dst + 2;
  uVar9 = uVar8 - local_14;
  uVar8 = (uint)(uVar8 < local_14);
  uVar10 = -uVar8;
  if (uVar8 == 0) {
    cVar1 = '+';
  }
  else {
    bVar12 = uVar9 != 0;
    uVar9 = -uVar9;
    uVar10 = -(uVar10 + bVar12);
    cVar1 = '-';
  }
  lVar15 = CONCAT44(uVar10,uVar9);
  _Dst[1] = cVar1;
  *pcVar5 = '0';
  pcVar11 = pcVar5;
  if ((int)uVar10 < 0) goto LAB_0040f5cd;
  if (((int)uVar10 < 1) && (uVar9 < 1000)) {
LAB_0040f570:
    uVar9 = (uint)lVar15;
    if (-1 >= lVar15) goto LAB_0040f5cd;
    if (((int)((ulonglong)lVar15 >> 0x20) != 0 && -1 < lVar15) || (99 < uVar9)) goto LAB_0040f57b;
LAB_0040f5a2:
    uVar9 = (uint)lVar15;
    if ((lVar15 < 0) || (((int)((ulonglong)lVar15 >> 0x20) == 0 || lVar15 < 0 && (uVar9 < 10))))
    goto LAB_0040f5cd;
  }
  else {
    uVar14 = __alldiv(uVar9,uVar10,1000,0);
    *pcVar5 = (char)uVar14 + '0';
    pcVar11 = _Dst + 3;
    lVar15 = __allrem(uVar9,uVar10,1000,0);
    if (pcVar11 == pcVar5) goto LAB_0040f570;
LAB_0040f57b:
    uVar8 = (uint)((ulonglong)lVar15 >> 0x20);
    uVar14 = __alldiv((uint)lVar15,uVar8,100,0);
    *pcVar11 = (char)uVar14 + '0';
    pcVar11 = pcVar11 + 1;
    lVar15 = __allrem((uint)lVar15,uVar8,100,0);
    if (pcVar11 == pcVar5) goto LAB_0040f5a2;
  }
  uVar8 = (uint)((ulonglong)lVar15 >> 0x20);
  uVar14 = __alldiv((uint)lVar15,uVar8,10,0);
  *pcVar11 = (char)uVar14 + '0';
  pcVar11 = pcVar11 + 1;
  uVar14 = __allrem((uint)lVar15,uVar8,10,0);
  uVar9 = (uint)uVar14;
LAB_0040f5cd:
  *pcVar11 = (char)uVar9 + '0';
  pcVar11[1] = '\0';
  return 0;
LAB_0040f49c:
  while( true ) {
    pcVar6 = pcVar11 + -1;
    local_2c = *pcVar6;
    if ((local_2c != 'f') && (local_2c != 'F')) break;
    *pcVar6 = '0';
    pcVar11 = pcVar6;
  }
  if (pcVar6 == pcVar5) {
    pcVar11[-2] = pcVar11[-2] + '\x01';
  }
  else {
    if (local_2c == '9') {
      local_2c = (char)sVar2;
      local_2c = local_2c + '9';
    }
    *pcVar6 = local_2c + '\x01';
  }
  goto LAB_0040f4c6;
}



void __cdecl
FUN_0040f5df(undefined4 *param_1,char *param_2,uint param_3,uint *******param_4,int param_5,
            int param_6,char param_7,int param_8,int param_9,__acrt_ptd **param_10)

{
  int iVar1;
  __acrt_ptd *p_Var2;
  uint uVar3;
  int local_10 [3];
  
  iVar1 = FUN_00414744((uint *******)*param_1,param_1[1],param_6 + 1,1,local_10,param_4,param_5);
  uVar3 = 0xffffffff;
  if (param_3 != 0xffffffff) {
    uVar3 = (param_3 - (local_10[0] == 0x2d)) - (uint)(0 < param_6);
  }
  p_Var2 = FUN_0041464a(param_2 + (uint)(0 < param_6) + (uint)(local_10[0] == 0x2d),uVar3,
                        param_6 + 1,local_10,iVar1,param_9,param_10);
  if (p_Var2 == (__acrt_ptd *)0x0) {
    FUN_0040f683(param_2,param_3,param_6,param_7,param_8,local_10,0,param_10);
  }
  else {
    *param_2 = '\0';
  }
  return;
}



undefined4 __cdecl
FUN_0040f683(char *param_1,uint param_2,int param_3,char param_4,int param_5,int *param_6,
            byte param_7,__acrt_ptd **param_8)

{
  int iVar1;
  char *pcVar2;
  undefined4 uVar3;
  char *pcVar4;
  
  iVar1 = param_3;
  if (param_3 < 1) {
    iVar1 = 0;
  }
  if (iVar1 + 9U < param_2) {
    if (param_7 != 0) {
      shift_bytes(param_1,param_2,param_1 + (*param_6 == 0x2d),(uint)(0 < param_3));
    }
    pcVar4 = param_1;
    if (*param_6 == 0x2d) {
      *param_1 = '-';
      pcVar4 = param_1 + 1;
    }
    if (0 < param_3) {
      *pcVar4 = pcVar4[1];
      pcVar4 = pcVar4 + 1;
      if (*(char *)(param_8 + 5) == '\0') {
        FUN_004064e0(param_8);
      }
      *pcVar4 = ***(char ***)(param_8[3] + 0x88);
    }
    pcVar4 = pcVar4 + (param_7 ^ 1) + param_3;
    pcVar2 = (char *)0xffffffff;
    if (param_2 != 0xffffffff) {
      pcVar2 = param_1 + (param_2 - (int)pcVar4);
    }
    iVar1 = FUN_0040daef(pcVar4,(int)pcVar2,0x41d298);
    if (iVar1 != 0) {
                    // WARNING: Subroutine does not return
      __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    }
    if (param_4 != '\0') {
      *pcVar4 = 'E';
    }
    if (*(char *)param_6[2] != '0') {
      iVar1 = param_6[1] + -1;
      if (iVar1 < 0) {
        iVar1 = -iVar1;
        pcVar4[1] = '-';
      }
      if (99 < iVar1) {
        pcVar4[2] = pcVar4[2] + (char)(iVar1 / 100);
        iVar1 = iVar1 % 100;
      }
      if (9 < iVar1) {
        pcVar4[3] = pcVar4[3] + (char)(iVar1 / 10);
        iVar1 = iVar1 % 10;
      }
      pcVar4[4] = pcVar4[4] + (char)iVar1;
    }
    if ((param_5 == 2) && (pcVar4[2] == '0')) {
      FID_conflict__memcpy(pcVar4 + 2,pcVar4 + 3,3);
    }
    uVar3 = 0;
  }
  else {
    uVar3 = 0x22;
    *(undefined *)(param_8 + 7) = 1;
    param_8[6] = (__acrt_ptd *)0x22;
    FUN_0040e1a6((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0,param_8);
  }
  return uVar3;
}



void __cdecl
FUN_0040f7d6(undefined4 *param_1,char *param_2,uint param_3,uint *******param_4,int param_5,
            size_t param_6,int param_7,__acrt_ptd **param_8)

{
  int iVar1;
  __acrt_ptd *p_Var2;
  uint uVar3;
  int local_10;
  int local_c;
  undefined4 uStack_8;
  
  local_10 = 0;
  local_c = 0;
  uStack_8 = 0;
  iVar1 = FUN_00414744((uint *******)*param_1,param_1[1],param_6,0,&local_10,param_4,param_5);
  uVar3 = 0xffffffff;
  if (param_3 != 0xffffffff) {
    uVar3 = param_3 - (local_10 == 0x2d);
  }
  p_Var2 = FUN_0041464a(param_2 + (local_10 == 0x2d),uVar3,local_c + param_6,&local_10,iVar1,param_7
                        ,param_8);
  if (p_Var2 == (__acrt_ptd *)0x0) {
    FUN_0040f86c(param_2,param_3,param_6,&local_10,'\0',param_8);
  }
  else {
    *param_2 = '\0';
  }
  return;
}



undefined4 __cdecl
FUN_0040f86c(char *param_1,uint param_2,size_t param_3,int *param_4,char param_5,
            __acrt_ptd **param_6)

{
  bool bVar1;
  int iVar2;
  size_t sVar3;
  char *local_8;
  
  bVar1 = false;
  if ((param_5 != '\0') && (param_4[1] - 1U == param_3)) {
    *(undefined2 *)(param_1 + (uint)(*param_4 == 0x2d) + (param_4[1] - 1U)) = 0x30;
  }
  local_8 = param_1;
  if (*param_4 == 0x2d) {
    local_8 = param_1 + 1;
    *param_1 = '-';
  }
  iVar2 = param_4[1];
  if (iVar2 < 1) {
    if ((iVar2 == 0) && (*(char *)param_4[2] == '0')) {
      bVar1 = true;
    }
    if ((param_5 == '\0') || (!bVar1)) {
      shift_bytes(param_1,param_2,local_8,1);
    }
    *local_8 = '0';
    iVar2 = 1;
  }
  local_8 = local_8 + iVar2;
  if (0 < (int)param_3) {
    shift_bytes(param_1,param_2,local_8,1);
    if (*(char *)(param_6 + 5) == '\0') {
      FUN_004064e0(param_6);
    }
    *local_8 = ***(char ***)(param_6[3] + 0x88);
    if (param_4[1] < 0) {
      sVar3 = -param_4[1];
      if ((param_5 != '\0') || ((int)sVar3 < (int)param_3)) {
        param_3 = sVar3;
      }
      shift_bytes(param_1,param_2,local_8 + 1,param_3);
      _memset(local_8 + 1,0x30,param_3);
    }
  }
  return 0;
}



void __cdecl
FUN_0040f95a(undefined4 *param_1,char *param_2,uint param_3,uint *******param_4,int param_5,
            size_t param_6,char param_7,int param_8,int param_9,__acrt_ptd **param_10)

{
  char *pcVar1;
  uint uVar2;
  __acrt_ptd *p_Var3;
  int iVar4;
  char *pcVar5;
  bool bVar6;
  int local_18;
  int local_14;
  undefined4 uStack_10;
  int local_c;
  int local_8;
  
  local_18 = 0;
  local_14 = 0;
  uStack_10 = 0;
  local_8 = FUN_00414744((uint *******)*param_1,param_1[1],param_6,0,&local_18,param_4,param_5);
  bVar6 = local_18 == 0x2d;
  local_c = local_14 + -1;
  uVar2 = 0xffffffff;
  if (param_3 != 0xffffffff) {
    uVar2 = param_3 - bVar6;
  }
  p_Var3 = FUN_0041464a(param_2 + bVar6,uVar2,param_6,&local_18,local_8,param_9,param_10);
  if (p_Var3 == (__acrt_ptd *)0x0) {
    iVar4 = local_14 + -1;
    if ((iVar4 < -4) || ((int)param_6 <= iVar4)) {
      FUN_0040f683(param_2,param_3,param_6,param_7,param_8,&local_18,1,param_10);
    }
    else {
      pcVar1 = param_2 + bVar6;
      if (local_c < iVar4) {
        do {
          pcVar5 = pcVar1;
          pcVar1 = pcVar5 + 1;
        } while (*pcVar5 != '\0');
        pcVar5[-1] = '\0';
      }
      FUN_0040f86c(param_2,param_3,param_6,&local_18,'\x01',param_10);
    }
  }
  else {
    *param_2 = '\0';
  }
  return;
}



// Library Function - Single Match
//  int __cdecl fp_format_nan_or_infinity(enum __acrt_fp_class,bool,char *,unsigned int,bool)
// 
// Library: Visual Studio 2019 Release

int __cdecl
fp_format_nan_or_infinity
          (__acrt_fp_class param_1,bool param_2,char *param_3,uint param_4,bool param_5)

{
  char *pcVar1;
  char cVar2;
  int iVar3;
  char *pcVar4;
  
  if (param_4 < param_2 + 4) {
    *param_3 = '\0';
    return 0xc;
  }
  if (param_2) {
    *param_3 = '-';
    param_3 = param_3 + 1;
    *param_3 = '\0';
    if (param_4 != 0xffffffff) {
      param_4 = param_4 - 1;
    }
  }
  iVar3 = (param_5 ^ 1) * 2;
  pcVar4 = (&PTR_DAT_0041d218)[param_1 * 4 + -4 + iVar3];
  pcVar1 = pcVar4 + 1;
  do {
    cVar2 = *pcVar4;
    pcVar4 = pcVar4 + 1;
  } while (cVar2 != '\0');
  iVar3 = FUN_0040daef(param_3,param_4,
                       (int)(&PTR_DAT_0041d218)
                            [((param_1 * 4 + -3) -
                             (uint)((uint)((int)pcVar4 - (int)pcVar1) < param_4)) + iVar3]);
  if (iVar3 == 0) {
    return 0;
  }
                    // WARNING: Subroutine does not return
  __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
}



// Library Function - Single Match
//  void __cdecl shift_bytes(char * const,unsigned int,char * const,int)
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void __cdecl shift_bytes(char *param_1,uint param_2,char *param_3,int param_4)

{
  char cVar1;
  char *pcVar2;
  
  if (param_4 != 0) {
    pcVar2 = param_3;
    do {
      cVar1 = *pcVar2;
      pcVar2 = pcVar2 + 1;
    } while (cVar1 != '\0');
    FID_conflict__memcpy(param_3 + param_4,param_3,(size_t)(pcVar2 + (1 - (int)(param_3 + 1))));
  }
  return;
}



// WARNING: Removing unreachable block (ram,0x0040fb7c)

char __cdecl
FUN_0040faf2(double *param_1,undefined4 param_2,uint param_3,undefined4 param_4,int param_5)

{
  char cVar1;
  int iVar2;
  short unaff_DI;
  ulonglong uVar3;
  
  uVar3 = __aullshr((byte)param_4,*(uint *)((int)param_1 + 4) & param_3 & 0xfffff);
  if (param_5 == 0) {
    cVar1 = '\x01' - (((uint)uVar3 & 0xffff) < 8);
  }
  else {
    iVar2 = _fegetround();
    if (iVar2 == 0) {
      cVar1 = fe_to_nearest(param_1,CONCAT44(param_4,param_3),unaff_DI);
    }
    else {
      if (iVar2 == 0x200) {
        if ((short)uVar3 == 0) {
          return '\0';
        }
        if (*(int *)((int)param_1 + 4) < 0) {
          return '\0';
        }
      }
      else {
        if (iVar2 != 0x100) {
          return '\0';
        }
        if ((short)uVar3 == 0) {
          return '\0';
        }
        if (0 < *(int *)((int)param_1 + 4)) {
          return '\0';
        }
        if (-1 < *(int *)((int)param_1 + 4)) {
          return '\0';
        }
      }
      cVar1 = '\x01';
    }
  }
  return cVar1;
}



int __cdecl
FUN_0040fb85(double *param_1,char *param_2,uint param_3,uint *******param_4,int param_5,int param_6,
            size_t param_7,uint param_8,undefined4 param_9,int param_10,__acrt_ptd **param_11)

{
  __acrt_fp_class _Var1;
  int iVar2;
  int iVar3;
  int iVar4;
  bool local_c;
  bool local_8;
  
  if (param_2 == (char *)0x0) {
    *(undefined *)(param_11 + 7) = 1;
    param_11[6] = (__acrt_ptd *)0x16;
  }
  else if ((param_3 == 0) || (param_4 == (uint *******)0x0)) {
    *(undefined *)(param_11 + 7) = 1;
    param_11[6] = (__acrt_ptd *)0x16;
  }
  else {
    if (param_5 != 0) {
      if ((((param_6 == 0x41) || (param_6 == 0x45)) || (param_6 == 0x46)) ||
         (local_8 = false, param_6 == 0x47)) {
        local_8 = true;
      }
      if (((param_8 & 8) == 0) && (_Var1 = __acrt_fp_classify(param_1), _Var1 != 0)) {
        if ((*(int *)((int)param_1 + 4) < 1) && (*(int *)((int)param_1 + 4) < 0)) {
          local_c = true;
        }
        else {
          local_c = false;
        }
        iVar2 = fp_format_nan_or_infinity(_Var1,local_c,param_2,param_3,local_8);
        return iVar2;
      }
      if ((param_8 & 0x10) == 0) {
        iVar2 = 2;
      }
      else {
        iVar2 = 3;
      }
      iVar3 = 0;
      if ((param_8 & 0x20) != 0) {
        iVar3 = param_10;
      }
      if (param_6 < 0x62) {
        if ((param_6 == 0x61) || (param_6 == 0x41)) {
          iVar2 = FUN_0040f2b2(param_1,param_2,param_3,param_4,param_5,param_7,local_8,iVar2,iVar3,
                               param_11);
          return iVar2;
        }
        iVar4 = param_6 + -0x45;
      }
      else {
        iVar4 = param_6 + -0x65;
      }
      if (iVar4 == 0) {
        iVar2 = FUN_0040f5df((undefined4 *)param_1,param_2,param_3,param_4,param_5,param_7,local_8,
                             iVar2,iVar3,param_11);
        return iVar2;
      }
      if (iVar4 != 1) {
        iVar2 = FUN_0040f95a((undefined4 *)param_1,param_2,param_3,param_4,param_5,param_7,local_8,
                             iVar2,iVar3,param_11);
        return iVar2;
      }
      iVar2 = FUN_0040f7d6((undefined4 *)param_1,param_2,param_3,param_4,param_5,param_7,iVar3,
                           param_11);
      return iVar2;
    }
    *(undefined *)(param_11 + 7) = 1;
    param_11[6] = (__acrt_ptd *)0x16;
  }
  FUN_0040e1a6((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0,param_11);
  return 0x16;
}



__acrt_ptd * __cdecl
FUN_0040fd06(int *param_1,byte *param_2,uint param_3,WCHAR param_4,__acrt_ptd **param_5)

{
  __acrt_ptd **pp_Var1;
  int iVar2;
  DWORD DVar3;
  __acrt_ptd *p_Var4;
  undefined4 local_10;
  uint local_c;
  int local_8;
  
  pp_Var1 = param_5;
  if ((param_2 == (byte *)0x0) && (param_3 != 0)) {
    if (param_1 == (int *)0x0) {
      return (__acrt_ptd *)0x0;
    }
    *param_1 = 0;
    return (__acrt_ptd *)0x0;
  }
  if (param_1 != (int *)0x0) {
    *param_1 = -1;
  }
  if (param_3 < 0x80000000) {
    if (*(char *)(param_5 + 5) == '\0') {
      FUN_004064e0(param_5);
    }
    local_c = *(uint *)(pp_Var1[3] + 8);
    if (local_c == 0xfde9) {
      local_10 = 0;
      local_c = 0;
      iVar2 = FUN_00415d2c(param_2,(uint)(ushort)param_4,&local_10,(int)pp_Var1);
      if (param_1 != (int *)0x0) {
        *param_1 = iVar2;
      }
      if (iVar2 < 5) {
        return (__acrt_ptd *)0x0;
      }
      if (*(char *)(pp_Var1 + 7) != '\0') {
        return pp_Var1[6];
      }
      return (__acrt_ptd *)0x0;
    }
    if (*(int *)(pp_Var1[3] + 0xa8) == 0) {
      local_8 = 0xff;
      if (0xff < (ushort)param_4) {
        if ((param_2 != (byte *)0x0) && (param_3 != 0)) {
          _memset(param_2,0,param_3);
        }
        goto LAB_0040fdd9;
      }
      if (param_2 == (byte *)0x0) {
LAB_0040fdf2:
        if (param_1 != (int *)0x0) {
          *param_1 = 1;
        }
        return (__acrt_ptd *)0x0;
      }
      if (param_3 != 0) {
        *param_2 = (byte)param_4;
        goto LAB_0040fdf2;
      }
    }
    else {
      local_8 = 0;
      iVar2 = FUN_00411f5d(local_c,0,&param_4,1,(LPSTR)param_2,param_3,0,&local_8);
      if (iVar2 != 0) {
        if (local_8 == 0) {
          if (param_1 == (int *)0x0) {
            return (__acrt_ptd *)0x0;
          }
          *param_1 = iVar2;
          return (__acrt_ptd *)0x0;
        }
LAB_0040fdd9:
        pp_Var1[6] = (__acrt_ptd *)0x2a;
        *(undefined *)(pp_Var1 + 7) = 1;
        return (__acrt_ptd *)0x2a;
      }
      DVar3 = GetLastError();
      if (DVar3 != 0x7a) goto LAB_0040fdd9;
      if ((param_2 != (byte *)0x0) && (param_3 != 0)) {
        _memset(param_2,0,param_3);
      }
    }
    p_Var4 = (__acrt_ptd *)0x22;
  }
  else {
    p_Var4 = (__acrt_ptd *)0x16;
  }
  pp_Var1[6] = p_Var4;
  *(undefined *)(pp_Var1 + 7) = 1;
  FUN_0040e1a6((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0,pp_Var1);
  return p_Var4;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint __cdecl FUN_0040fe70(LPWSTR param_1,byte *param_2,uint param_3,__acrt_ptd **param_4)

{
  int *piVar1;
  uint uVar2;
  int iVar3;
  
  if ((param_2 == (byte *)0x0) || (param_3 == 0)) {
    _DAT_004242cc = 0;
    _DAT_004242d0 = 0;
  }
  else {
    if (*param_2 != 0) {
      if (*(char *)(param_4 + 5) == '\0') {
        FUN_004064e0(param_4);
      }
      piVar1 = (int *)param_4[3];
      uVar2 = piVar1[2];
      if (uVar2 == 0xfde9) {
        uVar2 = FUN_00415e08(param_1,param_2,param_3,(uint *)&DAT_004242cc,(int)param_4);
        if (-1 < (int)uVar2) {
          return uVar2;
        }
      }
      else {
        if (piVar1[0x2a] == 0) {
          if (param_1 != (LPWSTR)0x0) {
            *param_1 = (ushort)*param_2;
          }
          return 1;
        }
        if (*(short *)(*piVar1 + (uint)*param_2 * 2) < 0) {
          iVar3 = *(int *)(param_4[3] + 4);
          if ((((1 < iVar3) && (iVar3 <= (int)param_3)) &&
              (iVar3 = FUN_00411ea3(uVar2,9,(LPCSTR)param_2,iVar3,param_1,
                                    (uint)(param_1 != (LPWSTR)0x0)), iVar3 != 0)) ||
             ((*(uint *)(param_4[3] + 4) <= param_3 && (param_2[1] != 0)))) {
            return *(uint *)(param_4[3] + 4);
          }
        }
        else {
          iVar3 = FUN_00411ea3(uVar2,9,(LPCSTR)param_2,1,param_1,(uint)(param_1 != (LPWSTR)0x0));
          if (iVar3 != 0) {
            return 1;
          }
        }
        *(undefined *)(param_4 + 7) = 1;
        param_4[6] = (__acrt_ptd *)0x2a;
      }
      return 0xffffffff;
    }
    if (param_1 != (LPWSTR)0x0) {
      *param_1 = L'\0';
    }
  }
  return 0;
}



uint __cdecl FUN_0040ffa3(LPWSTR param_1,byte *param_2,uint param_3,undefined4 *param_4)

{
  uint uVar1;
  __acrt_ptd *local_2c [10];
  
  FUN_004055d0(local_2c,param_4);
  uVar1 = FUN_0040fe70(param_1,param_2,param_3,local_2c);
  FUN_00405630(local_2c);
  return uVar1;
}



// Library Function - Single Match
//  __fileno
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

int __cdecl __fileno(FILE *_File)

{
  undefined4 *puVar1;
  
  if (_File == (FILE *)0x0) {
    puVar1 = (undefined4 *)FUN_0040e304();
    *puVar1 = 0x16;
    FUN_0040e223();
    return -1;
  }
  return _File->_file;
}



bool FUN_00410002(void)

{
  return DAT_004242d4 == (DAT_00423014 | 1);
}



uint __cdecl FUN_00410017(byte param_1,FILE *param_2,__acrt_ptd **param_3)

{
  char **ppcVar1;
  uint uVar2;
  
  ppcVar1 = &param_2->_base;
  *ppcVar1 = *ppcVar1 + -1;
  if ((int)*ppcVar1 < 0) {
    uVar2 = FUN_004161a0(param_1,param_2,param_3);
    return uVar2;
  }
  *param_2->_ptr = param_1;
  param_2->_ptr = param_2->_ptr + 1;
  return (uint)param_1;
}



undefined4 __cdecl FUN_00410044(FILE *param_1)

{
  byte bVar1;
  FILE *pFVar2;
  uint uVar3;
  undefined3 extraout_var;
  
  pFVar2 = (FILE *)FUN_00404989(2);
  if (param_1 == pFVar2) {
    return CONCAT31((int3)((uint)pFVar2 >> 8),1);
  }
  pFVar2 = (FILE *)FUN_00404989(1);
  if (param_1 == pFVar2) {
    uVar3 = __fileno(param_1);
    bVar1 = FUN_004161ab(uVar3);
    return CONCAT31(extraout_var,CONCAT31(extraout_var,bVar1) != 0);
  }
  return (uint)pFVar2 & 0xffffff00;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint __cdecl FUN_00410082(FILE *param_1)

{
  int *piVar1;
  FILE *pFVar2;
  char *pcVar3;
  char **ppcVar4;
  
  pFVar2 = (FILE *)FUN_00410044(param_1);
  if ((char)pFVar2 != '\0') {
    pFVar2 = (FILE *)FUN_00404989(1);
    if (param_1 == pFVar2) {
      ppcVar4 = (char **)&DAT_004242d8;
    }
    else {
      pFVar2 = (FILE *)FUN_00404989(2);
      if (param_1 != pFVar2) goto LAB_00410126;
      ppcVar4 = (char **)&DAT_004242dc;
    }
    _DAT_00423d20 = _DAT_00423d20 + 1;
    piVar1 = &param_1->_flag;
    pFVar2 = (FILE *)*piVar1;
    if (((uint)pFVar2 & 0x4c0) == 0) {
      pcVar3 = (char *)0x282;
      LOCK();
      *piVar1 = *piVar1 | 0x282;
      UNLOCK();
      if (*ppcVar4 == (char *)0x0) {
        pcVar3 = (char *)__malloc_base(0x1000);
        *ppcVar4 = pcVar3;
        pcVar3 = (char *)FUN_0040e374((LPVOID)0x0);
      }
      if (*ppcVar4 == (char *)0x0) {
        param_1->_base = (char *)0x2;
        param_1->_cnt = (int)&param_1->_charbuf;
        param_1->_ptr = (char *)&param_1->_charbuf;
        param_1->_bufsiz = 2;
      }
      else {
        param_1->_cnt = (int)*ppcVar4;
        pcVar3 = *ppcVar4;
        param_1->_ptr = pcVar3;
        param_1->_base = (char *)0x1000;
        param_1->_bufsiz = 0x1000;
      }
      return CONCAT31((int3)((uint)pcVar3 >> 8),1);
    }
  }
LAB_00410126:
  return (uint)pFVar2 & 0xffffff00;
}



void __cdecl FUN_0041012d(char param_1,FILE *param_2,__acrt_ptd **param_3)

{
  int *piVar1;
  
  if ((param_1 != '\0') && (piVar1 = &param_2->_flag, ((uint)*piVar1 >> 9 & 1) != 0)) {
    FUN_0040eac8(param_2,param_3);
    LOCK();
    *piVar1 = *piVar1 & 0xfffffd7f;
    UNLOCK();
    param_2->_bufsiz = 0;
    param_2->_cnt = 0;
    param_2->_ptr = (char *)0x0;
  }
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// Library Function - Single Match
//  public: void __thiscall __crt_seh_guarded_call<void>::operator()<class
// <lambda_15ade71b0218206bbe3333a0c9b79046>,class <lambda_da44e0f8b0f19ba52fefafb335991732> &,class
// <lambda_207f2d024fc103971653565357d6cd41> >(class <lambda_15ade71b0218206bbe3333a0c9b79046>
// &&,class <lambda_da44e0f8b0f19ba52fefafb335991732> &,class
// <lambda_207f2d024fc103971653565357d6cd41> &&)
// 
// Library: Visual Studio 2019 Release

void __thiscall
__crt_seh_guarded_call<void>::operator()<>
          (__crt_seh_guarded_call<void> *this,<> *param_1,<> *param_2,<> *param_3)

{
  void *local_14;
  
  ___acrt_lock(*(int *)param_1);
  LOCK();
  **(int **)(**(int **)param_2 + 0x48) = **(int **)(**(int **)param_2 + 0x48) + 1;
  UNLOCK();
  FUN_004101b1();
  ExceptionList = local_14;
  return;
}



void FUN_004101b1(void)

{
  int unaff_EBP;
  
  ___acrt_unlock(**(int **)(unaff_EBP + 0x10));
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// Library Function - Single Match
//  public: void __thiscall __crt_seh_guarded_call<void>::operator()<class
// <lambda_38edbb1296d33220d7e4dd0ed76b244a>,class <lambda_5ce1d447e08cb34b2473517608e21441> &,class
// <lambda_fb385d3da700c9147fc39e65dd577a8c> >(class <lambda_38edbb1296d33220d7e4dd0ed76b244a>
// &&,class <lambda_5ce1d447e08cb34b2473517608e21441> &,class
// <lambda_fb385d3da700c9147fc39e65dd577a8c> &&)
// 
// Library: Visual Studio 2019 Release

void __thiscall
__crt_seh_guarded_call<void>::operator()<>
          (__crt_seh_guarded_call<void> *this,<> *param_1,<> *param_2,<> *param_3)

{
  int iVar1;
  int *piVar2;
  void *local_14;
  
  ___acrt_lock(*(int *)param_1);
  piVar2 = *(int **)(**(int **)param_2 + 0x48);
  if (piVar2 != (int *)0x0) {
    LOCK();
    iVar1 = *piVar2;
    *piVar2 = iVar1 + -1;
    UNLOCK();
    if ((iVar1 + -1 == 0) && (piVar2 != (int *)&DAT_00423200)) {
      FUN_0040e374(piVar2);
    }
  }
  FUN_0041021c();
  ExceptionList = local_14;
  return;
}



void FUN_0041021c(void)

{
  int unaff_EBP;
  
  ___acrt_unlock(**(int **)(unaff_EBP + 0x10));
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// Library Function - Single Match
//  public: void __thiscall __crt_seh_guarded_call<void>::operator()<class
// <lambda_6affb1475c98b40b75cdec977db92e3c>,class <lambda_b8d4b9c228a6ecc3f80208dbb4b4a104> &,class
// <lambda_608742c3c92a14382c1684fc64f96c88> >(class <lambda_6affb1475c98b40b75cdec977db92e3c>
// &&,class <lambda_b8d4b9c228a6ecc3f80208dbb4b4a104> &,class
// <lambda_608742c3c92a14382c1684fc64f96c88> &&)
// 
// Library: Visual Studio 2019 Release

void __thiscall
__crt_seh_guarded_call<void>::operator()<>
          (__crt_seh_guarded_call<void> *this,<> *param_1,<> *param_2,<> *param_3)

{
  void *local_14;
  
  ___acrt_lock(*(int *)param_1);
  replace_current_thread_locale_nolock(**(__acrt_ptd ***)param_2,(__crt_locale_data *)0x0);
  FUN_00410271();
  ExceptionList = local_14;
  return;
}



void FUN_00410271(void)

{
  int unaff_EBP;
  
  ___acrt_unlock(**(int **)(unaff_EBP + 0x10));
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// Library Function - Single Match
//  public: void __thiscall __crt_seh_guarded_call<void>::operator()<class
// <lambda_a7e850c220f1c8d1e6efeecdedd162c6>,class <lambda_46720907175c18b6c9d2717bc0d2d362> &,class
// <lambda_9048902d66e8d99359bc9897bbb930a8> >(class <lambda_a7e850c220f1c8d1e6efeecdedd162c6>
// &&,class <lambda_46720907175c18b6c9d2717bc0d2d362> &,class
// <lambda_9048902d66e8d99359bc9897bbb930a8> &&)
// 
// Library: Visual Studio 2019 Release

void __thiscall
__crt_seh_guarded_call<void>::operator()<>
          (__crt_seh_guarded_call<void> *this,<> *param_1,<> *param_2,<> *param_3)

{
  void *local_14;
  
  ___acrt_lock(*(int *)param_1);
  replace_current_thread_locale_nolock
            (**(__acrt_ptd ***)param_2,*(__crt_locale_data **)**(undefined4 **)(param_2 + 4));
  FUN_004102cb();
  ExceptionList = local_14;
  return;
}



void FUN_004102cb(void)

{
  int unaff_EBP;
  
  ___acrt_unlock(**(int **)(unaff_EBP + 0x10));
  return;
}



// Library Function - Single Match
//  void __cdecl construct_ptd(struct __acrt_ptd * const,struct __crt_locale_data * * const)
// 
// Library: Visual Studio 2019 Release

void __cdecl construct_ptd(__acrt_ptd *param_1,__crt_locale_data **param_2)

{
  undefined4 local_18;
  __acrt_ptd **local_14;
  __acrt_ptd **local_10;
  __crt_locale_data ***local_c;
  __crt_seh_guarded_call<void> local_5;
  
  *(undefined4 *)(param_1 + 0x18) = 1;
  *(undefined **)param_1 = &DAT_0041c9d0;
  *(undefined4 *)(param_1 + 0x350) = 1;
  *(undefined **)(param_1 + 0x48) = &DAT_00423200;
  *(undefined2 *)(param_1 + 0x6c) = 0x43;
  *(undefined2 *)(param_1 + 0x172) = 0x43;
  *(undefined4 *)(param_1 + 0x34c) = 0;
  local_14 = &param_1;
  local_c = (__crt_locale_data ***)0x5;
  local_18 = 5;
  __crt_seh_guarded_call<void>::operator()<>
            (&local_5,(<> *)&local_18,(<> *)&local_14,(<> *)&local_c);
  local_10 = &param_1;
  local_c = &param_2;
  local_18 = 4;
  local_14 = (__acrt_ptd **)0x4;
  __crt_seh_guarded_call<void>::operator()<>
            (&local_5,(<> *)&local_14,(<> *)&local_10,(<> *)&local_18);
  return;
}



// Library Function - Single Match
//  void __stdcall destroy_fls(void *)
// 
// Library: Visual Studio 2019 Release

void destroy_fls(void *param_1)

{
  if (param_1 != (void *)0x0) {
    destroy_ptd((__acrt_ptd *)param_1);
    FUN_0040e374(param_1);
  }
  return;
}



// Library Function - Single Match
//  void __cdecl destroy_ptd(struct __acrt_ptd * const)
// 
// Library: Visual Studio 2019 Release

void __cdecl destroy_ptd(__acrt_ptd *param_1)

{
  undefined4 local_14;
  __acrt_ptd **local_10;
  undefined4 local_c;
  __crt_seh_guarded_call<void> local_5;
  
  if (*(undefined **)param_1 != &DAT_0041c9d0) {
    FUN_0040e374(*(undefined **)param_1);
  }
  FUN_0040e374(*(LPVOID *)(param_1 + 0x3c));
  FUN_0040e374(*(LPVOID *)(param_1 + 0x30));
  FUN_0040e374(*(LPVOID *)(param_1 + 0x34));
  FUN_0040e374(*(LPVOID *)(param_1 + 0x38));
  FUN_0040e374(*(LPVOID *)(param_1 + 0x28));
  FUN_0040e374(*(LPVOID *)(param_1 + 0x2c));
  FUN_0040e374(*(LPVOID *)(param_1 + 0x40));
  FUN_0040e374(*(LPVOID *)(param_1 + 0x44));
  FUN_0040e374(*(LPVOID *)(param_1 + 0x360));
  local_10 = &param_1;
  local_c = 5;
  local_14 = 5;
  __crt_seh_guarded_call<void>::operator()<>
            (&local_5,(<> *)&local_14,(<> *)&local_10,(<> *)&local_c);
  local_10 = &param_1;
  local_14 = 4;
  local_c = 4;
  __crt_seh_guarded_call<void>::operator()<>
            (&local_5,(<> *)&local_c,(<> *)&local_10,(<> *)&local_14);
  return;
}



// Library Function - Single Match
//  void __cdecl replace_current_thread_locale_nolock(struct __acrt_ptd * const,struct
// __crt_locale_data * const)
// 
// Library: Visual Studio 2019 Release

void __cdecl replace_current_thread_locale_nolock(__acrt_ptd *param_1,__crt_locale_data *param_2)

{
  undefined **ppuVar1;
  
  if (*(int *)(param_1 + 0x4c) != 0) {
    ___acrt_release_locale_ref(*(int *)(param_1 + 0x4c));
    ppuVar1 = *(undefined ***)(param_1 + 0x4c);
    if (((ppuVar1 != DAT_004242e0) && (ppuVar1 != &PTR_DAT_00423138)) &&
       (ppuVar1[3] == (undefined *)0x0)) {
      ___acrt_free_locale(ppuVar1);
    }
  }
  *(__crt_locale_data **)(param_1 + 0x4c) = param_2;
  if (param_2 != (__crt_locale_data *)0x0) {
    ___acrt_add_locale_ref((int)param_2);
  }
  return;
}



__acrt_ptd * FUN_004104a9(void)

{
  DWORD dwErrCode;
  uint uVar1;
  int iVar2;
  __acrt_ptd *p_Var3;
  __acrt_ptd *p_Var4;
  
  dwErrCode = GetLastError();
  if ((DAT_00423130 == (void *)0xffffffff) || (uVar1 = FUN_0040e6a0(DAT_00423130), uVar1 == 0)) {
    iVar2 = ___acrt_FlsSetValue_8(DAT_00423130,(LPVOID)0xffffffff);
    if (iVar2 == 0) {
      p_Var3 = (__acrt_ptd *)0x0;
    }
    else {
      p_Var3 = (__acrt_ptd *)__calloc_base(1,0x364);
      if (p_Var3 == (__acrt_ptd *)0x0) {
        ___acrt_FlsSetValue_8(DAT_00423130,(LPVOID)0x0);
        p_Var4 = (__acrt_ptd *)0x0;
      }
      else {
        iVar2 = ___acrt_FlsSetValue_8(DAT_00423130,p_Var3);
        if (iVar2 != 0) {
          construct_ptd(p_Var3,(__crt_locale_data **)&DAT_004242e0);
          FUN_0040e374((LPVOID)0x0);
          goto LAB_0041054e;
        }
        ___acrt_FlsSetValue_8(DAT_00423130,(LPVOID)0x0);
        p_Var4 = p_Var3;
      }
      p_Var3 = (__acrt_ptd *)0x0;
      FUN_0040e374(p_Var4);
    }
  }
  else {
    p_Var3 = (__acrt_ptd *)(-(uint)(uVar1 != 0xffffffff) & uVar1);
  }
LAB_0041054e:
  SetLastError(dwErrCode);
  if (p_Var3 == (__acrt_ptd *)0x0) {
                    // WARNING: Subroutine does not return
    _abort();
  }
  return p_Var3;
}



__acrt_ptd * FUN_00410564(void)

{
  __acrt_ptd *p_Var1;
  int iVar2;
  
  if ((DAT_00423130 == (void *)0xffffffff) ||
     (p_Var1 = (__acrt_ptd *)FUN_0040e6a0(DAT_00423130), p_Var1 == (__acrt_ptd *)0x0)) {
    iVar2 = ___acrt_FlsSetValue_8(DAT_00423130,(LPVOID)0xffffffff);
    if (iVar2 != 0) {
      p_Var1 = (__acrt_ptd *)__calloc_base(1,0x364);
      if (p_Var1 == (__acrt_ptd *)0x0) {
        ___acrt_FlsSetValue_8(DAT_00423130,(LPVOID)0x0);
      }
      else {
        iVar2 = ___acrt_FlsSetValue_8(DAT_00423130,p_Var1);
        if (iVar2 != 0) {
          construct_ptd(p_Var1,(__crt_locale_data **)&DAT_004242e0);
          FUN_0040e374((LPVOID)0x0);
          return p_Var1;
        }
        ___acrt_FlsSetValue_8(DAT_00423130,(LPVOID)0x0);
      }
      FUN_0040e374(p_Var1);
    }
  }
  else if (p_Var1 != (__acrt_ptd *)0xffffffff) {
    return p_Var1;
  }
                    // WARNING: Subroutine does not return
  _abort();
}



__acrt_ptd * FUN_004105fa(void)

{
  DWORD dwErrCode;
  uint uVar1;
  int iVar2;
  __acrt_ptd *p_Var3;
  __acrt_ptd *p_Var4;
  
  dwErrCode = GetLastError();
  if ((DAT_00423130 == (void *)0xffffffff) || (uVar1 = FUN_0040e6a0(DAT_00423130), uVar1 == 0)) {
    iVar2 = ___acrt_FlsSetValue_8(DAT_00423130,(LPVOID)0xffffffff);
    if (iVar2 == 0) {
      p_Var3 = (__acrt_ptd *)0x0;
    }
    else {
      p_Var3 = (__acrt_ptd *)__calloc_base(1,0x364);
      if (p_Var3 == (__acrt_ptd *)0x0) {
        ___acrt_FlsSetValue_8(DAT_00423130,(LPVOID)0x0);
        p_Var4 = (__acrt_ptd *)0x0;
      }
      else {
        iVar2 = ___acrt_FlsSetValue_8(DAT_00423130,p_Var3);
        if (iVar2 != 0) {
          construct_ptd(p_Var3,(__crt_locale_data **)&DAT_004242e0);
          FUN_0040e374((LPVOID)0x0);
          goto LAB_0041069f;
        }
        ___acrt_FlsSetValue_8(DAT_00423130,(LPVOID)0x0);
        p_Var4 = p_Var3;
      }
      p_Var3 = (__acrt_ptd *)0x0;
      FUN_0040e374(p_Var4);
    }
  }
  else {
    p_Var3 = (__acrt_ptd *)(-(uint)(uVar1 != 0xffffffff) & uVar1);
  }
LAB_0041069f:
  SetLastError(dwErrCode);
  return p_Var3;
}



__acrt_ptd * __cdecl FUN_004106ab(undefined4 param_1,int param_2)

{
  __acrt_ptd *p_Var1;
  int iVar2;
  __acrt_ptd *p_Var3;
  
  p_Var3 = (__acrt_ptd *)0x0;
  if ((DAT_00423130 == (void *)0xffffffff) ||
     (p_Var1 = (__acrt_ptd *)FUN_0040e6a0(DAT_00423130), p_Var1 == (__acrt_ptd *)0x0)) {
    iVar2 = ___acrt_FlsSetValue_8(DAT_00423130,(LPVOID)0xffffffff);
    if (iVar2 == 0) {
      return (__acrt_ptd *)0x0;
    }
    p_Var1 = (__acrt_ptd *)__calloc_base(1,0x364);
    if (p_Var1 == (__acrt_ptd *)0x0) {
      ___acrt_FlsSetValue_8(DAT_00423130,(LPVOID)0x0);
      p_Var1 = (__acrt_ptd *)0x0;
    }
    else {
      iVar2 = ___acrt_FlsSetValue_8(DAT_00423130,p_Var1);
      if (iVar2 != 0) {
        construct_ptd(p_Var1,(__crt_locale_data **)&DAT_004242e0);
        FUN_0040e374((LPVOID)0x0);
        goto LAB_0041073f;
      }
      ___acrt_FlsSetValue_8(DAT_00423130,(LPVOID)0x0);
    }
    FUN_0040e374(p_Var1);
  }
  else {
    if (p_Var1 == (__acrt_ptd *)0xffffffff) {
      return (__acrt_ptd *)0x0;
    }
LAB_0041073f:
    p_Var3 = p_Var1 + param_2 * 0x364;
  }
  return p_Var3;
}



undefined4 FUN_0041077a(void)

{
  void *pvVar1;
  
  pvVar1 = DAT_00423130;
  if (DAT_00423130 != (void *)0xffffffff) {
    pvVar1 = (void *)FUN_0040e661(DAT_00423130);
    DAT_00423130 = (void *)0xffffffff;
  }
  return CONCAT31((int3)((uint)pvVar1 >> 8),1);
}



// Library Function - Single Match
//  ___pctype_func
// 
// Library: Visual Studio 2019 Release

ushort * __cdecl ___pctype_func(void)

{
  __acrt_ptd *p_Var1;
  ushort **local_8;
  
  p_Var1 = FUN_004104a9();
  local_8 = *(ushort ***)(p_Var1 + 0x4c);
  ___acrt_update_locale_info((int)p_Var1,&local_8);
  return *local_8;
}



// Library Function - Single Match
//  __isctype_l
// 
// Library: Visual Studio 2019 Release

int __cdecl __isctype_l(int _C,int _Type,_locale_t _Locale)

{
  int iVar1;
  int local_24;
  int *local_20 [2];
  char local_18;
  CHAR local_14;
  CHAR local_13;
  undefined local_12;
  undefined4 local_10;
  undefined2 local_c;
  uint local_8;
  
  local_8 = DAT_00423014 ^ (uint)&stack0xfffffffc;
  FUN_00408ded(&local_24,(__acrt_ptd **)_Locale);
  if ((_C < -1) || (0xff < _C)) {
    if (*(short *)(*local_20[0] + (_C >> 8 & 0xffU) * 2) < 0) {
      local_12 = 0;
      iVar1 = 2;
      local_14 = (CHAR)((uint)_C >> 8);
      local_13 = (CHAR)_C;
    }
    else {
      local_13 = '\0';
      iVar1 = 1;
      local_14 = (CHAR)_C;
    }
    local_10 = 0;
    local_c = 0;
    iVar1 = FUN_0041293f((__acrt_ptd **)local_20,1,&local_14,iVar1,(LPWORD)&local_10,local_20[0][2],
                         1);
    if (iVar1 == 0) {
      if (local_18 != '\0') {
        *(uint *)(local_24 + 0x350) = *(uint *)(local_24 + 0x350) & 0xfffffffd;
      }
      goto LAB_00410877;
    }
  }
  if (local_18 != '\0') {
    *(uint *)(local_24 + 0x350) = *(uint *)(local_24 + 0x350) & 0xfffffffd;
  }
LAB_00410877:
  iVar1 = FUN_00402125(local_8 ^ (uint)&stack0xfffffffc);
  return iVar1;
}



// Library Function - Single Match
//  _isspace
// 
// Library: Visual Studio 2019 Release

int __cdecl _isspace(int _C)

{
  __acrt_ptd *p_Var1;
  int iVar2;
  int *local_8;
  
  if (DAT_00423e60 == 0) {
    if (_C + 1U < 0x101) {
      return *(ushort *)(PTR_DAT_00423138 + _C * 2) & 8;
    }
  }
  else {
    p_Var1 = FUN_004104a9();
    local_8 = *(int **)(p_Var1 + 0x4c);
    ___acrt_update_locale_info((int)p_Var1,&local_8);
    if (_C + 1U < 0x101) {
      return *(ushort *)(*local_8 + _C * 2) & 8;
    }
    if (1 < local_8[1]) {
      iVar2 = __isctype_l(_C,8,(_locale_t)0x0);
      return iVar2;
    }
  }
  return 0;
}



ulonglong __cdecl FUN_00410914(undefined4 param_1,undefined4 *param_2,uint param_3)

{
  byte **extraout_ECX;
  ulonglong uVar1;
  byte **ppbVar2;
  byte **ppbVar3;
  byte bVar4;
  __acrt_ptd *local_30 [11];
  
  FUN_004055d0(local_30,(undefined4 *)0x0);
  bVar4 = 0;
  ppbVar2 = extraout_ECX;
  ppbVar3 = extraout_ECX;
  make_c_string_character_source<>((undefined4 *)&stack0xffffffb8,param_1,param_2);
  uVar1 = FUN_0040db98(local_30,(byte *)ppbVar2,ppbVar3,param_3,bVar4);
  FUN_00405630(local_30);
  return uVar1;
}



uint __cdecl FUN_00410960(uint param_1,FILE *param_2)

{
  char *pcVar1;
  char *pcVar2;
  uint uVar3;
  undefined4 *puVar4;
  int *piVar5;
  undefined *puVar6;
  undefined *puVar7;
  
  if (((uint)param_2->_flag >> 0xc & 1) == 0) {
    uVar3 = __fileno(param_2);
    puVar7 = &DAT_004230f8;
    if ((uVar3 == 0xffffffff) || (uVar3 == 0xfffffffe)) {
      puVar6 = &DAT_004230f8;
    }
    else {
      puVar6 = (undefined *)((uVar3 & 0x3f) * 0x38 + (&DAT_004240c8)[(int)uVar3 >> 6]);
    }
    if (puVar6[0x29] == '\0') {
      if ((uVar3 != 0xffffffff) && (uVar3 != 0xfffffffe)) {
        puVar7 = (undefined *)((uVar3 & 0x3f) * 0x38 + (&DAT_004240c8)[(int)uVar3 >> 6]);
      }
      if ((puVar7[0x2d] & 1) == 0) goto LAB_004109eb;
    }
    puVar4 = (undefined4 *)FUN_0040e304();
    *puVar4 = 0x16;
    FUN_0040e223();
  }
  else {
LAB_004109eb:
    if ((param_1 != 0xffffffff) &&
       (((param_2->_flag & 1U) != 0 || (((byte)param_2->_flag & 6) == 6)))) {
      if (param_2->_cnt == 0) {
        ___acrt_stdio_allocate_buffer_nolock(&param_2->_ptr);
      }
      piVar5 = &param_2->_flag;
      if (param_2->_ptr == (char *)param_2->_cnt) {
        if (param_2->_base != (char *)0x0) {
          return 0xffffffff;
        }
        param_2->_ptr = param_2->_ptr + 1;
      }
      pcVar2 = param_2->_ptr;
      pcVar1 = pcVar2 + -1;
      param_2->_ptr = pcVar1;
      if (((uint)*piVar5 >> 0xc & 1) == 0) {
        *pcVar1 = (char)param_1;
      }
      else if (*pcVar1 != (char)param_1) {
        param_2->_ptr = pcVar2;
        return 0xffffffff;
      }
      param_2->_base = param_2->_base + 1;
      LOCK();
      *piVar5 = *piVar5 & 0xfffffff7;
      UNLOCK();
      LOCK();
      *piVar5 = *piVar5 | 1;
      UNLOCK();
      return param_1 & 0xff;
    }
  }
  return 0xffffffff;
}



// Library Function - Single Match
//  _fegetround
// 
// Library: Visual Studio 2019 Release

void _fegetround(void)

{
  uint uVar1;
  
  uVar1 = ___acrt_fenv_get_control();
  ___acrt_fenv_get_common_round_control(uVar1);
  return;
}



uint __cdecl FUN_00410a61(FILE *param_1)

{
  byte bVar1;
  LPWSTR pWVar2;
  undefined4 *puVar3;
  uint uVar4;
  char *pcVar5;
  int iVar6;
  uint uVar7;
  undefined *puVar8;
  
  if (param_1 == (FILE *)0x0) {
    puVar3 = (undefined4 *)FUN_0040e304();
    *puVar3 = 0x16;
    FUN_0040e223();
  }
  else if ((((uint)param_1->_flag >> 0xd & 1) != 0) && (((uint)param_1->_flag >> 0xc & 1) == 0)) {
    if (((uint)param_1->_flag >> 1 & 1) == 0) {
      LOCK();
      param_1->_flag = param_1->_flag | 1;
      UNLOCK();
      if ((param_1->_flag & 0x4c0U) == 0) {
        ___acrt_stdio_allocate_buffer_nolock(&param_1->_ptr);
      }
      param_1->_ptr = (char *)param_1->_cnt;
      uVar7 = param_1->_bufsiz;
      pWVar2 = (LPWSTR)param_1->_cnt;
      uVar4 = __fileno(param_1);
      pcVar5 = (char *)FUN_00416cc5(uVar4,pWVar2,uVar7);
      param_1->_base = pcVar5;
      pcVar5 = param_1->_base;
      if ((pcVar5 != (char *)0x0) && (pcVar5 != (char *)0xffffffff)) {
        if ((param_1->_flag & 6U) == 0) {
          iVar6 = __fileno(param_1);
          if ((iVar6 == -1) || (iVar6 = __fileno(param_1), iVar6 == -2)) {
            puVar8 = &DAT_004230f8;
          }
          else {
            iVar6 = __fileno(param_1);
            uVar7 = __fileno(param_1);
            puVar8 = (undefined *)((&DAT_004240c8)[iVar6 >> 6] + (uVar7 & 0x3f) * 0x38);
          }
          if ((puVar8[0x28] & 0x82) == 0x82) {
            LOCK();
            param_1->_flag = param_1->_flag | 0x20;
            UNLOCK();
          }
        }
        if (((param_1->_bufsiz == 0x200) && (((uint)param_1->_flag >> 6 & 1) != 0)) &&
           ((param_1->_flag & 0x100U) == 0)) {
          param_1->_bufsiz = 0x1000;
        }
        param_1->_base = param_1->_base + -1;
        bVar1 = *param_1->_ptr;
        param_1->_ptr = param_1->_ptr + 1;
        return (uint)bVar1;
      }
      LOCK();
      param_1->_flag = param_1->_flag | (uint)(pcVar5 != (char *)0x0) * 8 + 8;
      UNLOCK();
      param_1->_base = (char *)0x0;
    }
    else {
      LOCK();
      param_1->_flag = param_1->_flag | 0x10;
      UNLOCK();
    }
  }
  return 0xffffffff;
}



void __cdecl FUN_00410bf0(FILE *param_1)

{
  FUN_00410a61(param_1);
  return;
}



uint __cdecl FUN_00410bfb(uint param_1,uint param_2)

{
  if (param_1 < param_2) {
    return 0xffffffff;
  }
  return (uint)(param_2 < param_1);
}



// Library Function - Single Match
//  int __cdecl __acrt_convert_wcs_mbs_cp<char,wchar_t,class
// <lambda_62f6974d9771e494a5ea317cc32e971c>,struct
// __crt_win32_buffer_internal_dynamic_resizing>(char const * const,class
// __crt_win32_buffer<wchar_t,struct __crt_win32_buffer_internal_dynamic_resizing> &,class
// <lambda_62f6974d9771e494a5ea317cc32e971c> const &,unsigned int)
// 
// Library: Visual Studio 2019 Release

int __cdecl
__acrt_convert_wcs_mbs_cp<>(char *param_1,__crt_win32_buffer<> *param_2,<> *param_3,uint param_4)

{
  int iVar1;
  uint uVar2;
  DWORD DVar3;
  int *piVar4;
  
  if (param_1 == (char *)0x0) {
    __crt_win32_buffer<>::_deallocate(param_2);
    *(undefined4 *)(param_2 + 8) = 0;
    *(undefined4 *)(param_2 + 0xc) = 0;
  }
  else {
    if (*param_1 != '\0') {
      uVar2 = FUN_00411ea3(param_4,9,param_1,-1,(LPWSTR)0x0,0);
      if (uVar2 != 0) {
        if ((*(uint *)(param_2 + 0xc) < uVar2) &&
           (iVar1 = __crt_win32_buffer<>::allocate(param_2,uVar2), iVar1 != 0)) {
          return iVar1;
        }
        iVar1 = FUN_00411ea3(param_4,9,param_1,-1,*(LPWSTR *)(param_2 + 8),*(int *)(param_2 + 0xc));
        if (iVar1 != 0) {
          *(int *)(param_2 + 0x10) = iVar1 + -1;
          return 0;
        }
      }
      DVar3 = GetLastError();
      ___acrt_errno_map_os_error(DVar3);
      piVar4 = (int *)FUN_0040e304();
      return *piVar4;
    }
    if ((*(int *)(param_2 + 0xc) == 0) &&
       (iVar1 = __crt_win32_buffer<>::allocate(param_2,1), iVar1 != 0)) {
      return iVar1;
    }
    **(undefined2 **)(param_2 + 8) = 0;
  }
  *(undefined4 *)(param_2 + 0x10) = 0;
  return 0;
}



int __cdecl
FUN_00410cc5(LPCWSTR param_1,__crt_win32_buffer<> *param_2,undefined4 param_3,uint param_4)

{
  int iVar1;
  uint uVar2;
  DWORD DVar3;
  int *piVar4;
  
  if (param_1 == (LPCWSTR)0x0) {
    __crt_win32_buffer<>::_deallocate(param_2);
    *(undefined4 *)(param_2 + 8) = 0;
    *(undefined4 *)(param_2 + 0xc) = 0;
  }
  else {
    if (*param_1 != L'\0') {
      uVar2 = FUN_00411f5d(param_4,0,param_1,-1,(LPSTR)0x0,0,0,(undefined4 *)0x0);
      if (uVar2 == 0) {
        DVar3 = GetLastError();
        ___acrt_errno_map_os_error(DVar3);
        piVar4 = (int *)FUN_0040e304();
        return *piVar4;
      }
      if ((*(uint *)(param_2 + 0xc) < uVar2) && (iVar1 = allocate(param_2,uVar2), iVar1 != 0)) {
        return iVar1;
      }
      iVar1 = FUN_00411280(param_4,param_1,*(LPSTR *)(param_2 + 8),*(int *)(param_2 + 0xc));
      if (iVar1 == 0) {
        DVar3 = GetLastError();
        ___acrt_errno_map_os_error(DVar3);
        piVar4 = (int *)FUN_0040e304();
        return *piVar4;
      }
      *(int *)(param_2 + 0x10) = iVar1 + -1;
      return 0;
    }
    if ((*(int *)(param_2 + 0xc) == 0) && (iVar1 = allocate(param_2,1), iVar1 != 0)) {
      return iVar1;
    }
    **(undefined **)(param_2 + 8) = 0;
  }
  *(undefined4 *)(param_2 + 0x10) = 0;
  return 0;
}



// Library Function - Single Match
//  int __cdecl __acrt_mbs_to_wcs_cp<struct __crt_win32_buffer_internal_dynamic_resizing>(char const
// * const,class __crt_win32_buffer<wchar_t,struct __crt_win32_buffer_internal_dynamic_resizing>
// &,unsigned int)
// 
// Library: Visual Studio 2019 Release

int __cdecl __acrt_mbs_to_wcs_cp<>(char *param_1,__crt_win32_buffer<> *param_2,uint param_3)

{
  int iVar1;
  <> local_5;
  
  iVar1 = __acrt_convert_wcs_mbs_cp<>(param_1,param_2,&local_5,param_3);
  return iVar1;
}



int __cdecl FUN_00410da8(uchar **param_1,LPVOID *param_2)

{
  char cVar1;
  undefined4 *puVar2;
  uchar *puVar3;
  int iVar4;
  LPVOID pvVar5;
  char *pcVar6;
  uint uVar7;
  char **ppcVar8;
  char **ppcVar9;
  char **local_24;
  char **local_20;
  undefined4 local_1c;
  int local_18;
  char *local_14;
  char *local_10;
  char *local_c;
  undefined4 local_8;
  
  if (param_2 == (LPVOID *)0x0) {
    puVar2 = (undefined4 *)FUN_0040e304();
    iVar4 = 0x16;
    *puVar2 = 0x16;
    FUN_0040e223();
  }
  else {
    *param_2 = (LPVOID)0x0;
    local_1c = 0;
    local_20 = (char **)0x0;
    local_24 = (char **)0x0;
    puVar3 = *param_1;
    ppcVar9 = local_24;
    while (local_24 = ppcVar9, puVar3 != (uchar *)0x0) {
      uVar7 = (uint)local_8 >> 0x18;
      local_8 = (char *)CONCAT13((char)uVar7,0x3f2a);
      puVar3 = (uchar *)_strpbrk((char *)puVar3,(char *)&local_8);
      if (puVar3 == (uchar *)0x0) {
        iVar4 = copy_and_add_argument_to_buffer<char>
                          ((char *)*param_1,(char *)0x0,0,(argument_list<char> *)&local_24);
      }
      else {
        iVar4 = FUN_00410fd6(*param_1,puVar3,(int *)&local_24);
      }
      if (iVar4 != 0) goto LAB_00410e8f;
      param_1 = param_1 + 1;
      ppcVar9 = local_24;
      puVar3 = *param_1;
    }
    uVar7 = ((int)local_20 - (int)ppcVar9 >> 2) + 1;
    local_c = (char *)0x0;
    for (ppcVar8 = ppcVar9; ppcVar8 != local_20; ppcVar8 = ppcVar8 + 1) {
      pcVar6 = *ppcVar8;
      local_10 = pcVar6 + 1;
      do {
        cVar1 = *pcVar6;
        pcVar6 = pcVar6 + 1;
      } while (cVar1 != '\0');
      local_c = pcVar6 + (int)(local_c + (1 - (int)local_10));
    }
    pvVar5 = ___acrt_allocate_buffer_for_argv(uVar7,(uint)local_c,1);
    ppcVar8 = local_20;
    if (pvVar5 == (LPVOID)0x0) {
      FUN_0040e374((LPVOID)0x0);
      iVar4 = -1;
LAB_00410e8f:
      ~argument_list<>(&local_24);
    }
    else {
      local_8 = (char *)((int)pvVar5 + uVar7 * 4);
      local_14 = local_8;
      if (ppcVar9 != local_20) {
        local_18 = (int)pvVar5 - (int)ppcVar9;
        do {
          local_10 = *ppcVar9;
          pcVar6 = local_10 + 1;
          do {
            cVar1 = *local_10;
            local_10 = local_10 + 1;
          } while (cVar1 != '\0');
          local_10 = local_10 + (1 - (int)pcVar6);
          iVar4 = FUN_00417715(local_8,(int)(local_14 + ((int)local_c - (int)local_8)),(int)*ppcVar9
                               ,(int)local_10);
          if (iVar4 != 0) {
                    // WARNING: Subroutine does not return
            __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
          }
          *(char **)(local_18 + (int)ppcVar9) = local_8;
          ppcVar9 = ppcVar9 + 1;
          local_8 = local_8 + (int)local_10;
        } while (ppcVar9 != ppcVar8);
      }
      *param_2 = pvVar5;
      FUN_0040e374((LPVOID)0x0);
      ~argument_list<>(&local_24);
      iVar4 = 0;
    }
  }
  return iVar4;
}



// Library Function - Single Match
//  int __cdecl copy_and_add_argument_to_buffer<char>(char const * const,char const * const,unsigned
// int,class `anonymous namespace'::argument_list<char> &)
// 
// Library: Visual Studio 2019 Release

int __cdecl
copy_and_add_argument_to_buffer<char>
          (char *param_1,char *param_2,uint param_3,argument_list<char> *param_4)

{
  char cVar1;
  char *pcVar2;
  int iVar3;
  char *pcVar4;
  char *pcVar5;
  
  pcVar4 = param_1;
  do {
    cVar1 = *pcVar4;
    pcVar4 = pcVar4 + 1;
  } while (cVar1 != '\0');
  pcVar4 = pcVar4 + (1 - (int)(param_1 + 1));
  if ((char *)~param_3 < pcVar4) {
    iVar3 = 0xc;
  }
  else {
    pcVar5 = pcVar4 + param_3 + 1;
    pcVar2 = (char *)__calloc_base((uint)pcVar5,1);
    if (param_3 != 0) {
      iVar3 = FUN_00417715(pcVar2,(int)pcVar5,(int)param_2,param_3);
      if (iVar3 != 0) goto LAB_00410fc9;
    }
    iVar3 = FUN_00417715(pcVar2 + param_3,(int)pcVar5 - param_3,(int)param_1,(int)pcVar4);
    if (iVar3 != 0) {
LAB_00410fc9:
                    // WARNING: Subroutine does not return
      __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
    }
    iVar3 = `anonymous_namespace'::argument_list<char>::expand_if_necessary(param_4);
    if (iVar3 == 0) {
      **(char ***)(param_4 + 4) = pcVar2;
      iVar3 = 0;
      *(int *)(param_4 + 4) = *(int *)(param_4 + 4) + 4;
    }
    else {
      FUN_0040e374(pcVar2);
    }
    FUN_0040e374((LPVOID)0x0);
  }
  return iVar3;
}



void __cdecl FUN_00410fd6(uchar *param_1,uchar *param_2,int *param_3)

{
  uchar uVar1;
  byte bVar2;
  uint uVar3;
  int iVar4;
  HANDLE hFindFile;
  int iVar5;
  char *pcVar6;
  BOOL BVar7;
  undefined4 local_290;
  undefined4 local_28c;
  LPVOID local_288;
  undefined4 local_284;
  undefined4 local_280;
  char local_27c;
  undefined4 local_278;
  undefined4 local_274;
  LPVOID local_270;
  undefined4 local_26c;
  undefined4 local_268;
  char local_264;
  int *local_260;
  uchar local_259;
  _WIN32_FIND_DATAW local_258;
  uint local_8;
  
  local_8 = DAT_00423014 ^ (uint)&stack0xfffffffc;
  local_260 = param_3;
  if (param_2 != param_1) {
    do {
      uVar1 = *param_2;
      if (((uVar1 == '/') || (uVar1 == '\\')) || (uVar1 == ':')) break;
      param_2 = __mbsdec(param_1,param_2);
    } while (param_2 != param_1);
  }
  local_259 = *param_2;
  if ((local_259 == ':') && (param_2 != param_1 + 1)) {
    copy_and_add_argument_to_buffer<char>
              ((char *)param_1,(char *)0x0,0,(argument_list<char> *)local_260);
  }
  else {
    if (((local_259 == '/') || (local_259 == '\\')) || (bVar2 = 0, local_259 == ':')) {
      bVar2 = 1;
    }
    local_290 = 0;
    local_28c = 0;
    local_288 = (LPVOID)0x0;
    local_284 = 0;
    local_280 = 0;
    local_27c = '\0';
    uVar3 = __acrt_get_utf8_acp_compatibility_codepage();
    iVar4 = __acrt_mbs_to_wcs_cp<>((char *)param_1,(__crt_win32_buffer<> *)&local_290,uVar3);
    hFindFile = FindFirstFileExW((LPCWSTR)(~-(uint)(iVar4 != 0) & (uint)local_288),
                                 FindExInfoStandard,&local_258,FindExSearchNameMatch,(LPVOID)0x0,0);
    if (hFindFile == (HANDLE)0xffffffff) {
      copy_and_add_argument_to_buffer<char>
                ((char *)param_1,(char *)0x0,0,(argument_list<char> *)local_260);
      if (local_27c != '\0') {
        FUN_0040e374(local_288);
      }
    }
    else {
      iVar4 = local_260[1] - *local_260 >> 2;
      do {
        local_278 = 0;
        local_274 = 0;
        local_270 = (LPVOID)0x0;
        local_26c = 0;
        local_268 = 0;
        local_264 = '\0';
        uVar3 = __acrt_get_utf8_acp_compatibility_codepage();
        iVar5 = FUN_00410cc5(local_258.cFileName,(__crt_win32_buffer<> *)&local_278,&local_259,uVar3
                            );
        pcVar6 = (char *)(~-(uint)(iVar5 != 0) & (uint)local_270);
        if (((*pcVar6 != '.') ||
            ((pcVar6[1] != '\0' && ((pcVar6[1] != '.' || (pcVar6[2] != '\0')))))) &&
           (iVar5 = copy_and_add_argument_to_buffer<char>
                              (pcVar6,(char *)param_1,
                               -(uint)bVar2 & (uint)(param_2 + (1 - (int)param_1)),
                               (argument_list<char> *)local_260), iVar5 != 0)) {
          if (local_264 != '\0') {
            FUN_0040e374(local_270);
          }
          FindClose(hFindFile);
          if (local_27c != '\0') {
            FUN_0040e374(local_288);
          }
          goto LAB_0041124d;
        }
        if (local_264 != '\0') {
          FUN_0040e374(local_270);
        }
        BVar7 = FindNextFileW(hFindFile,&local_258);
      } while (BVar7 != 0);
      iVar5 = local_260[1] - *local_260 >> 2;
      if (iVar4 != iVar5) {
        _qsort((void *)(*local_260 + iVar4 * 4),iVar5 - iVar4,4,FUN_00410bfb);
      }
      FindClose(hFindFile);
      if (local_27c != '\0') {
        FUN_0040e374(local_288);
      }
    }
  }
LAB_0041124d:
  FUN_00402125(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



// Library Function - Multiple Matches With Same Base Name
//  public: __thiscall `anonymous namespace'::argument_list<char>::~argument_list<char>(void)
//  public: __thiscall `anonymous namespace'::argument_list<char>::~argument_list<char>(void)
//  public: __thiscall `anonymous namespace'::argument_list<wchar_t>::~argument_list<wchar_t>(void)
//  public: __thiscall `anonymous namespace'::argument_list<wchar_t>::~argument_list<wchar_t>(void)
// 
// Library: Visual Studio 2015 Release

void __fastcall ~argument_list<>(LPVOID *param_1)

{
  LPVOID *ppvVar1;
  
  for (ppvVar1 = (LPVOID *)*param_1; ppvVar1 != (LPVOID *)param_1[1]; ppvVar1 = ppvVar1 + 1) {
    FUN_0040e374(*ppvVar1);
  }
  FUN_0040e374(*param_1);
  return;
}



void FUN_00411280(uint param_1,LPCWSTR param_2,LPSTR param_3,int param_4)

{
  FUN_00411f5d(param_1,0,param_2,-1,param_3,param_4,0,(undefined4 *)0x0);
  return;
}



// Library Function - Single Match
//  unsigned int __cdecl __acrt_get_utf8_acp_compatibility_codepage(void)
// 
// Library: Visual Studio 2019 Release

uint __cdecl __acrt_get_utf8_acp_compatibility_codepage(void)

{
  int iVar1;
  uint uVar2;
  int local_14;
  int local_10;
  char local_8;
  
  FUN_00408ded(&local_14,(__acrt_ptd **)0x0);
  uVar2 = 0xfde9;
  if (*(int *)(local_10 + 8) != 0xfde9) {
    iVar1 = ___acrt_AreFileApisANSI_0();
    uVar2 = 0;
    if (iVar1 == 0) {
      uVar2 = 1;
    }
  }
  if (local_8 != '\0') {
    *(uint *)(local_14 + 0x350) = *(uint *)(local_14 + 0x350) & 0xfffffffd;
  }
  return uVar2;
}



// Library Function - Single Match
//  private: void __thiscall __crt_win32_buffer<wchar_t,struct
// __crt_win32_buffer_internal_dynamic_resizing>::_deallocate(void)
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __thiscall __crt_win32_buffer<>::_deallocate(__crt_win32_buffer<> *this)

{
  if (this[0x14] != (__crt_win32_buffer<>)0x0) {
    FUN_0040e374(*(LPVOID *)(this + 8));
    this[0x14] = (__crt_win32_buffer<>)0x0;
  }
  return;
}



// Library Function - Multiple Matches With Same Base Name
//  public: int __thiscall __crt_win32_buffer<char,struct
// __crt_win32_buffer_internal_dynamic_resizing>::allocate(unsigned int)
//  public: int __thiscall __crt_win32_buffer<char,struct
// __crt_win32_buffer_public_dynamic_resizing>::allocate(unsigned int)
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

int __thiscall allocate(void *this,uint param_1)

{
  int iVar1;
  
  __crt_win32_buffer<>::_deallocate((__crt_win32_buffer<> *)this);
  iVar1 = __crt_win32_buffer_internal_dynamic_resizing::allocate
                    ((void **)((int)this + 8),param_1,(__crt_win32_buffer_empty_debug_info *)this);
  if (iVar1 == 0) {
    *(undefined *)((int)this + 0x14) = 1;
    iVar1 = 0;
    *(uint *)((int)this + 0xc) = param_1;
  }
  else {
    *(undefined4 *)((int)this + 0xc) = 0;
    *(undefined *)((int)this + 0x14) = 0;
  }
  return iVar1;
}



// Library Function - Single Match
//  public: int __thiscall __crt_win32_buffer<wchar_t,struct
// __crt_win32_buffer_internal_dynamic_resizing>::allocate(unsigned int)
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

int __thiscall __crt_win32_buffer<>::allocate(__crt_win32_buffer<> *this,uint param_1)

{
  int iVar1;
  
  _deallocate(this);
  iVar1 = __crt_win32_buffer_internal_dynamic_resizing::allocate
                    ((void **)(this + 8),param_1 * 2,(__crt_win32_buffer_empty_debug_info *)this);
  if (iVar1 == 0) {
    this[0x14] = (__crt_win32_buffer<>)0x1;
    iVar1 = 0;
    *(uint *)(this + 0xc) = param_1;
  }
  else {
    *(undefined4 *)(this + 0xc) = 0;
    this[0x14] = (__crt_win32_buffer<>)0x0;
  }
  return iVar1;
}



// Library Function - Single Match
//  public: static int __cdecl __crt_win32_buffer_internal_dynamic_resizing::allocate(void * *
// const,unsigned int,class __crt_win32_buffer_empty_debug_info const &)
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

int __cdecl
__crt_win32_buffer_internal_dynamic_resizing::allocate
          (void **param_1,uint param_2,__crt_win32_buffer_empty_debug_info *param_3)

{
  LPVOID pvVar1;
  
  pvVar1 = __malloc_base(param_2);
  *param_1 = pvVar1;
  return (-(uint)(pvVar1 != (LPVOID)0x0) & 0xfffffff4) + 0xc;
}



// Library Function - Single Match
//  private: int __thiscall `anonymous namespace'::argument_list<char>::expand_if_necessary(void)
// 
// Library: Visual Studio 2019 Release

int __thiscall
`anonymous_namespace'::argument_list<char>::expand_if_necessary(argument_list<char> *this)

{
  int iVar1;
  LPVOID pvVar2;
  uint uVar3;
  
  if (*(int *)(this + 4) == *(int *)(this + 8)) {
    if (*(int *)this == 0) {
      pvVar2 = __calloc_base(4,4);
      *(LPVOID *)this = pvVar2;
      FUN_0040e374((LPVOID)0x0);
      iVar1 = *(int *)this;
      if (iVar1 != 0) {
        *(int *)(this + 4) = iVar1;
        *(int *)(this + 8) = iVar1 + 0x10;
        goto LAB_004113a5;
      }
    }
    else {
      uVar3 = *(int *)(this + 8) - *(int *)this >> 2;
      if (uVar3 < 0x80000000) {
        pvVar2 = __recalloc_base(*(void **)this,uVar3 * 2,4);
        if (pvVar2 == (LPVOID)0x0) {
          iVar1 = 0xc;
        }
        else {
          *(LPVOID *)this = pvVar2;
          *(LPVOID *)(this + 4) = (LPVOID)((int)pvVar2 + uVar3 * 4);
          *(LPVOID *)(this + 8) = (LPVOID)((int)pvVar2 + uVar3 * 8);
          iVar1 = 0;
        }
        FUN_0040e374((LPVOID)0x0);
        return iVar1;
      }
    }
    iVar1 = 0xc;
  }
  else {
LAB_004113a5:
    iVar1 = 0;
  }
  return iVar1;
}



void __cdecl FUN_0041141e(uchar **param_1,LPVOID *param_2)

{
  FUN_00410da8(param_1,param_2);
  return;
}



int __cdecl FUN_00411429(LPCWSTR param_1,int param_2,undefined4 param_3,uint param_4)

{
  int iVar1;
  uint uVar2;
  DWORD DVar3;
  int *piVar4;
  
  if (param_1 == (LPCWSTR)0x0) {
    FUN_00411512(param_2);
    iVar1 = 0;
  }
  else if (*param_1 == L'\0') {
    if ((*(int *)(param_2 + 0xc) != 0) || (iVar1 = allocate(param_2), iVar1 == 0)) {
      **(undefined **)(param_2 + 8) = 0;
      iVar1 = 0;
      *(undefined4 *)(param_2 + 0x10) = 0;
    }
  }
  else {
    uVar2 = FUN_00411f5d(param_4,0,param_1,-1,(LPSTR)0x0,0,0,(undefined4 *)0x0);
    if (uVar2 == 0) {
      DVar3 = GetLastError();
      ___acrt_errno_map_os_error(DVar3);
      piVar4 = (int *)FUN_0040e304();
      iVar1 = *piVar4;
    }
    else if ((uVar2 <= *(uint *)(param_2 + 0xc)) || (iVar1 = allocate(param_2), iVar1 == 0)) {
      iVar1 = FUN_00411280(param_4,param_1,*(LPSTR *)(param_2 + 8),*(int *)(param_2 + 0xc));
      if (iVar1 == 0) {
        DVar3 = GetLastError();
        ___acrt_errno_map_os_error(DVar3);
        piVar4 = (int *)FUN_0040e304();
        iVar1 = *piVar4;
      }
      else {
        *(int *)(param_2 + 0x10) = iVar1 + -1;
        iVar1 = 0;
      }
    }
  }
  return iVar1;
}



// Library Function - Multiple Matches With Same Base Name
//  public: int __thiscall __crt_win32_buffer<char,struct
// __crt_win32_buffer_no_resizing>::allocate(unsigned int)
//  public: int __thiscall __crt_win32_buffer<wchar_t,struct
// __crt_win32_buffer_no_resizing>::allocate(unsigned int)
// 
// Libraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual
// Studio 2019 Release

undefined4 __fastcall allocate(int param_1)

{
  undefined4 *puVar1;
  
  if (*(char *)(param_1 + 0x14) != '\0') {
    *(undefined *)(param_1 + 0x14) = 0;
  }
  puVar1 = (undefined4 *)FUN_0040e304();
  *puVar1 = 0x22;
  *(undefined4 *)(param_1 + 0xc) = 0;
  *(undefined *)(param_1 + 0x14) = 0;
  return 0x22;
}



void __fastcall FUN_00411512(int param_1)

{
  if (*(char *)(param_1 + 0x14) != '\0') {
    *(undefined *)(param_1 + 0x14) = 0;
  }
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 0;
  *(undefined4 *)(param_1 + 0x10) = 0;
  return;
}



// Library Function - Single Match
//  ___acrt_GetModuleFileNameA
// 
// Library: Visual Studio 2019 Release

void __cdecl ___acrt_GetModuleFileNameA(HMODULE param_1,undefined4 param_2,undefined4 param_3)

{
  DWORD DVar1;
  uint uVar2;
  undefined4 local_230;
  undefined4 local_22c;
  undefined4 local_228;
  undefined4 local_224;
  undefined4 local_220;
  undefined local_21c;
  undefined local_215;
  WCHAR local_214 [262];
  uint local_8;
  
  local_8 = DAT_00423014 ^ (uint)&stack0xfffffffc;
  DVar1 = GetModuleFileNameW(param_1,local_214,0x105);
  if (DVar1 == 0) {
    DVar1 = GetLastError();
    ___acrt_errno_map_os_error(DVar1);
  }
  else {
    local_220 = 0;
    local_230 = param_2;
    local_22c = param_3;
    local_228 = param_2;
    local_224 = param_3;
    local_21c = 0;
    uVar2 = __acrt_get_utf8_acp_compatibility_codepage();
    FUN_00411429(local_214,(int)&local_230,&local_215,uVar2);
  }
  FUN_00402125(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// Library Function - Single Match
//  public: void __thiscall __crt_seh_guarded_call<void>::operator()<class
// <lambda_ceb1ee4838e85a9d631eb091e2fbe199>,class <lambda_ae742caa10f662c28703da3d2ea5e57e> &,class
// <lambda_cd08b5d6af4937fe54fc07d0c9bf6b37> >(class <lambda_ceb1ee4838e85a9d631eb091e2fbe199>
// &&,class <lambda_ae742caa10f662c28703da3d2ea5e57e> &,class
// <lambda_cd08b5d6af4937fe54fc07d0c9bf6b37> &&)
// 
// Library: Visual Studio 2019 Release

void __thiscall
__crt_seh_guarded_call<void>::operator()<>
          (__crt_seh_guarded_call<void> *this,<> *param_1,<> *param_2,<> *param_3)

{
  void *local_14;
  
  ___acrt_lock(*(int *)param_1);
  <>::operator()(param_2);
  FUN_00411608();
  ExceptionList = local_14;
  return;
}



void FUN_00411608(void)

{
  int unaff_EBP;
  
  ___acrt_unlock(**(int **)(unaff_EBP + 0x10));
  return;
}



// Library Function - Single Match
//  public: void __thiscall <lambda_ae742caa10f662c28703da3d2ea5e57e>::operator()(void)const 
// 
// Library: Visual Studio 2019 Release

void __thiscall <>::operator()(<> *this)

{
  int iVar1;
  
  _memcpy_s(DAT_004242e4,0x101,(void *)(*(int *)(**(int **)this + 0x48) + 0x18),0x101);
  _memcpy_s(DAT_004242e8,0x100,(void *)(*(int *)(**(int **)this + 0x48) + 0x119),0x100);
  LOCK();
  iVar1 = **(int **)**(undefined4 **)(this + 4) + -1;
  **(int **)**(undefined4 **)(this + 4) = iVar1;
  UNLOCK();
  if ((iVar1 == 0) && (*(undefined **)(LPVOID *)**(undefined4 **)(this + 4) != &DAT_00423200)) {
    FUN_0040e374(*(LPVOID *)**(undefined4 **)(this + 4));
  }
  *(undefined4 *)**(undefined4 **)(this + 4) = *(undefined4 *)(**(int **)this + 0x48);
  LOCK();
  **(int **)(**(int **)this + 0x48) = **(int **)(**(int **)this + 0x48) + 1;
  UNLOCK();
  return;
}



// Library Function - Single Match
//  wchar_t const * __cdecl CPtoLocaleName(int)
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

wchar_t * __cdecl CPtoLocaleName(int param_1)

{
  if (param_1 == 0x3a4) {
    return L"ja-JP";
  }
  if (param_1 == 0x3a8) {
    return L"zh-CN";
  }
  if (param_1 == 0x3b5) {
    return L"ko-KR";
  }
  if (param_1 != 0x3b6) {
    return (wchar_t *)0x0;
  }
  return L"zh-TW";
}



// Library Function - Single Match
//  int __cdecl getSystemCP(int)
// 
// Library: Visual Studio 2019 Release

int __cdecl getSystemCP(int param_1)

{
  int local_14;
  int local_10;
  char local_8;
  
  FUN_00408ded(&local_14,(__acrt_ptd **)0x0);
  DAT_004242f0 = 0;
  if (param_1 == -2) {
    DAT_004242f0 = 1;
    param_1 = GetOEMCP();
  }
  else if (param_1 == -3) {
    DAT_004242f0 = 1;
    param_1 = GetACP();
  }
  else if (param_1 == -4) {
    DAT_004242f0 = 1;
    param_1 = *(UINT *)(local_10 + 8);
  }
  if (local_8 != '\0') {
    *(uint *)(local_14 + 0x350) = *(uint *)(local_14 + 0x350) & 0xfffffffd;
  }
  return param_1;
}



void __cdecl FUN_00411746(int param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = 0;
  _memset((void *)(param_1 + 0x18),0,0x101);
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0x21c) = 0;
  *(undefined4 *)(param_1 + 0xc) = 0;
  iVar1 = 0;
  *(undefined4 *)(param_1 + 0x10) = 0;
  *(undefined4 *)(param_1 + 0x14) = 0;
  do {
    *(undefined1 *)(param_1 + 0x18 + iVar1) = (&DAT_00423218)[iVar1];
    iVar1 = iVar1 + 1;
  } while (iVar1 < 0x101);
  do {
    *(undefined1 *)(param_1 + 0x119 + iVar2) = (&DAT_00423319)[iVar2];
    iVar2 = iVar2 + 1;
  } while (iVar2 < 0x100);
  return;
}



void __cdecl FUN_004117a9(int param_1)

{
  char cVar1;
  byte bVar2;
  BOOL BVar3;
  uint uVar4;
  byte *pbVar5;
  BYTE *pBVar6;
  int iVar7;
  int iVar8;
  _cpinfo local_71c;
  WORD local_708 [512];
  wchar_t local_308 [128];
  wchar_t local_208 [128];
  CHAR local_108 [256];
  uint local_8;
  
  local_8 = DAT_00423014 ^ (uint)&stack0xfffffffc;
  if ((*(int *)(param_1 + 4) == 0xfde9) ||
     (BVar3 = GetCPInfo(*(UINT *)(param_1 + 4),&local_71c), BVar3 == 0)) {
    pbVar5 = (byte *)(param_1 + 0x19);
    do {
      if (pbVar5 + (-0x5a - param_1) < (byte *)0x1a) {
        *pbVar5 = *pbVar5 | 0x10;
        cVar1 = (char)pbVar5 + ' ';
LAB_00411925:
        bVar2 = cVar1 + (char)(-0x19 - param_1);
      }
      else {
        if (pbVar5 + (-0x7a - param_1) < (byte *)0x1a) {
          *pbVar5 = *pbVar5 | 0x20;
          cVar1 = (char)pbVar5 + -0x20;
          goto LAB_00411925;
        }
        bVar2 = 0;
      }
      pbVar5[0x100] = bVar2;
      pbVar5 = pbVar5 + 1;
    } while (pbVar5 + (-0x19 - param_1) < (byte *)0x100);
  }
  else {
    iVar8 = 0x100;
    uVar4 = 0;
    do {
      local_108[uVar4] = (CHAR)uVar4;
      uVar4 = uVar4 + 1;
    } while (uVar4 < 0x100);
    pBVar6 = local_71c.LeadByte;
    local_108[0] = ' ';
    while (local_71c.LeadByte[0] != 0) {
      bVar2 = pBVar6[1];
      for (uVar4 = (uint)local_71c.LeadByte[0]; (uVar4 <= bVar2 && (uVar4 < 0x100));
          uVar4 = uVar4 + 1) {
        local_108[uVar4] = ' ';
      }
      pBVar6 = pBVar6 + 2;
      local_71c.LeadByte[0] = *pBVar6;
    }
    FUN_0041293f((__acrt_ptd **)0x0,1,local_108,0x100,local_708,*(uint *)(param_1 + 4),0);
    ___acrt_LCMapStringA
              ((__acrt_ptd **)0x0,*(wchar_t **)(param_1 + 0x21c),0x100,local_108,0x100,local_208,
               0x100,*(uint *)(param_1 + 4),0);
    ___acrt_LCMapStringA
              ((__acrt_ptd **)0x0,*(wchar_t **)(param_1 + 0x21c),0x200,local_108,0x100,local_308,
               0x100,*(uint *)(param_1 + 4),0);
    pbVar5 = (byte *)(param_1 + 0x19);
    iVar7 = 0;
    do {
      if ((local_708[iVar7] & 1) == 0) {
        if ((local_708[iVar7] & 2) == 0) {
          bVar2 = 0;
        }
        else {
          *pbVar5 = *pbVar5 | 0x20;
          bVar2 = *(byte *)((int)local_308 + iVar7);
        }
      }
      else {
        *pbVar5 = *pbVar5 | 0x10;
        bVar2 = *(byte *)((int)local_208 + iVar7);
      }
      iVar7 = iVar7 + 1;
      pbVar5[0x100] = bVar2;
      pbVar5 = pbVar5 + 1;
      iVar8 = iVar8 + -1;
    } while (iVar8 != 0);
  }
  FUN_00402125(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



int __cdecl
FUN_0041194e(int param_1,char param_2,__acrt_ptd *param_3,__crt_multibyte_data **param_4)

{
  int *piVar1;
  int iVar2;
  undefined4 *puVar3;
  int iVar4;
  undefined4 *puVar5;
  undefined4 *puVar6;
  undefined4 local_248 [137];
  __acrt_ptd **local_24;
  __crt_multibyte_data ***local_20;
  int local_1c;
  __crt_seh_guarded_call<void> local_15;
  undefined4 *local_14;
  
  update_thread_multibyte_data_internal(param_3,param_4);
  local_1c = getSystemCP(param_1);
  if (local_1c == *(int *)(*(int *)(param_3 + 0x48) + 4)) {
    iVar2 = 0;
  }
  else {
    puVar3 = (undefined4 *)__malloc_base(0x220);
    iVar2 = local_1c;
    local_14 = puVar3;
    if (puVar3 == (undefined4 *)0x0) {
      FUN_0040e374((LPVOID)0x0);
      iVar2 = -1;
    }
    else {
      puVar5 = *(undefined4 **)(param_3 + 0x48);
      puVar6 = local_248;
      for (iVar4 = 0x88; iVar4 != 0; iVar4 = iVar4 + -1) {
        *puVar6 = *puVar5;
        puVar5 = puVar5 + 1;
        puVar6 = puVar6 + 1;
      }
      puVar5 = local_248;
      puVar6 = puVar3;
      for (iVar4 = 0x88; iVar4 != 0; iVar4 = iVar4 + -1) {
        *puVar6 = *puVar5;
        puVar5 = puVar5 + 1;
        puVar6 = puVar6 + 1;
      }
      *puVar3 = 0;
      iVar2 = FUN_00411b9e(iVar2,(int)puVar3);
      if (iVar2 == -1) {
        puVar3 = (undefined4 *)FUN_0040e304();
        *puVar3 = 0x16;
        FUN_0040e374(local_14);
        iVar2 = -1;
      }
      else {
        if (param_2 == '\0') {
          FUN_0040d505();
        }
        piVar1 = *(int **)(param_3 + 0x48);
        LOCK();
        iVar4 = *piVar1;
        *piVar1 = *piVar1 + -1;
        UNLOCK();
        if ((iVar4 == 1) && (*(undefined **)(param_3 + 0x48) != &DAT_00423200)) {
          FUN_0040e374(*(LPVOID *)(param_3 + 0x48));
        }
        *local_14 = 1;
        *(undefined4 **)(param_3 + 0x48) = local_14;
        if ((*(uint *)(param_3 + 0x350) & DAT_00423778) == 0) {
          local_24 = &param_3;
          local_20 = &param_4;
          local_1c = 5;
          local_14 = (undefined4 *)0x5;
          __crt_seh_guarded_call<void>::operator()<>
                    (&local_15,(<> *)&local_14,(<> *)&local_24,(<> *)&local_1c);
          if (param_2 != '\0') {
            PTR_DAT_004231f4 = *param_4;
          }
        }
        FUN_0040e374((LPVOID)0x0);
      }
    }
  }
  return iVar2;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// Library Function - Single Match
//  struct __crt_multibyte_data * __cdecl update_thread_multibyte_data_internal(struct __acrt_ptd *
// const,struct __crt_multibyte_data * * const)
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

__crt_multibyte_data * __cdecl
update_thread_multibyte_data_internal(__acrt_ptd *param_1,__crt_multibyte_data **param_2)

{
  int iVar1;
  __crt_multibyte_data *p_Var2;
  int *piVar3;
  
  if (((*(uint *)(param_1 + 0x350) & DAT_00423778) == 0) || (*(int *)(param_1 + 0x4c) == 0)) {
    ___acrt_lock(5);
    piVar3 = *(int **)(param_1 + 0x48);
    if (piVar3 != (int *)*param_2) {
      if (piVar3 != (int *)0x0) {
        LOCK();
        iVar1 = *piVar3;
        *piVar3 = iVar1 + -1;
        UNLOCK();
        if ((iVar1 + -1 == 0) && (piVar3 != (int *)&DAT_00423200)) {
          FUN_0040e374(piVar3);
        }
      }
      piVar3 = (int *)*param_2;
      *(int **)(param_1 + 0x48) = piVar3;
      LOCK();
      *piVar3 = *piVar3 + 1;
      UNLOCK();
    }
    FUN_00411b22();
  }
  else {
    piVar3 = *(int **)(param_1 + 0x48);
  }
  if (piVar3 != (int *)0x0) {
    p_Var2 = (__crt_multibyte_data *)FUN_00411b2b();
    return p_Var2;
  }
                    // WARNING: Subroutine does not return
  _abort();
}



void FUN_00411b22(void)

{
  ___acrt_unlock(5);
  return;
}



void FUN_00411b2b(void)

{
  int unaff_EBP;
  
  ExceptionList = *(void **)(unaff_EBP + -0x10);
  return;
}



// Library Function - Single Match
//  ___acrt_initialize_multibyte
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

undefined4 ___acrt_initialize_multibyte(void)

{
  int in_EAX;
  __acrt_ptd *p_Var1;
  
  if (DAT_004242f4 == '\0') {
    DAT_004242ec = &DAT_00423200;
    DAT_004242e8 = &DAT_00423528;
    DAT_004242e4 = &DAT_00423420;
    p_Var1 = FUN_00410564();
    in_EAX = FUN_0041194e(-3,'\x01',p_Var1,(__crt_multibyte_data **)&DAT_004242ec);
    DAT_004242f4 = '\x01';
  }
  return CONCAT31((int3)((uint)in_EAX >> 8),1);
}



void FUN_00411b8b(void)

{
  __acrt_ptd *p_Var1;
  
  p_Var1 = FUN_004104a9();
  update_thread_multibyte_data_internal(p_Var1,(__crt_multibyte_data **)&DAT_004242ec);
  return;
}



void __cdecl FUN_00411b9e(int param_1,int param_2)

{
  byte bVar1;
  undefined2 uVar2;
  uint uVar3;
  uint uVar4;
  BOOL BVar5;
  BYTE *pBVar6;
  wchar_t *pwVar7;
  int iVar8;
  byte *pbVar9;
  undefined2 *puVar10;
  byte *pbVar11;
  undefined2 *puVar12;
  byte *pbVar13;
  uint uVar14;
  int local_20;
  _cpinfo local_1c;
  uint local_8;
  
  local_8 = DAT_00423014 ^ (uint)&stack0xfffffffc;
  uVar3 = getSystemCP(param_1);
  if (uVar3 != 0) {
    uVar14 = 0;
    uVar4 = 0;
    local_20 = 0;
LAB_00411bd5:
    if (*(uint *)((int)&DAT_00423630 + uVar4) != uVar3) goto code_r0x00411be1;
    _memset((void *)(param_2 + 0x18),0,0x101);
    pbVar11 = &DAT_00423640 + local_20 * 0x30;
    do {
      bVar1 = *pbVar11;
      pbVar9 = pbVar11;
      while ((bVar1 != 0 && (pbVar9[1] != 0))) {
        uVar4 = (uint)*pbVar9;
        if (uVar4 <= pbVar9[1]) {
          pbVar13 = (byte *)(param_2 + 0x19 + uVar4);
          do {
            if (0xff < uVar4) break;
            *pbVar13 = *pbVar13 | (&DAT_00423628)[uVar14];
            uVar4 = uVar4 + 1;
            pbVar13 = pbVar13 + 1;
          } while (uVar4 <= pbVar9[1]);
        }
        pbVar9 = pbVar9 + 2;
        bVar1 = *pbVar9;
      }
      uVar14 = uVar14 + 1;
      pbVar11 = pbVar11 + 8;
    } while (uVar14 < 4);
    *(uint *)(param_2 + 4) = uVar3;
    *(undefined4 *)(param_2 + 8) = 1;
    pwVar7 = CPtoLocaleName(uVar3);
    *(wchar_t **)(param_2 + 0x21c) = pwVar7;
    puVar10 = (undefined2 *)(param_2 + 0xc);
    puVar12 = (undefined2 *)(&DAT_00423634 + local_20 * 0x30);
    iVar8 = 6;
    do {
      uVar2 = *puVar12;
      puVar12 = puVar12 + 1;
      *puVar10 = uVar2;
      puVar10 = puVar10 + 1;
      iVar8 = iVar8 + -1;
    } while (iVar8 != 0);
    goto LAB_00411d83;
  }
LAB_00411d8b:
  FUN_00411746(param_2);
LAB_00411d94:
  FUN_00402125(local_8 ^ (uint)&stack0xfffffffc);
  return;
code_r0x00411be1:
  local_20 = local_20 + 1;
  uVar4 = uVar4 + 0x30;
  if (0xef < uVar4) goto code_r0x00411bef;
  goto LAB_00411bd5;
code_r0x00411bef:
  if ((uVar3 == 65000) || (BVar5 = IsValidCodePage(uVar3 & 0xffff), BVar5 == 0)) goto LAB_00411d94;
  if (uVar3 == 0xfde9) {
    *(undefined4 *)(param_2 + 4) = 0xfde9;
    *(undefined4 *)(param_2 + 0x21c) = 0;
    *(undefined4 *)(param_2 + 0x18) = 0;
    *(undefined2 *)(param_2 + 0x1c) = 0;
  }
  else {
    BVar5 = GetCPInfo(uVar3,&local_1c);
    if (BVar5 == 0) {
      if (DAT_004242f0 == 0) goto LAB_00411d94;
      goto LAB_00411d8b;
    }
    _memset((void *)(param_2 + 0x18),0,0x101);
    *(uint *)(param_2 + 4) = uVar3;
    *(undefined4 *)(param_2 + 0x21c) = 0;
    if (local_1c.MaxCharSize == 2) {
      pBVar6 = local_1c.LeadByte;
      while ((local_1c.LeadByte[0] != 0 && (bVar1 = pBVar6[1], bVar1 != 0))) {
        uVar3 = (uint)*pBVar6;
        if (uVar3 <= bVar1) {
          pbVar11 = (byte *)(param_2 + 0x19 + uVar3);
          iVar8 = (bVar1 - uVar3) + 1;
          do {
            *pbVar11 = *pbVar11 | 4;
            pbVar11 = pbVar11 + 1;
            iVar8 = iVar8 + -1;
          } while (iVar8 != 0);
        }
        pBVar6 = pBVar6 + 2;
        local_1c.LeadByte[0] = *pBVar6;
      }
      pbVar11 = (byte *)(param_2 + 0x1a);
      iVar8 = 0xfe;
      do {
        *pbVar11 = *pbVar11 | 8;
        pbVar11 = pbVar11 + 1;
        iVar8 = iVar8 + -1;
      } while (iVar8 != 0);
      pwVar7 = CPtoLocaleName(*(int *)(param_2 + 4));
      *(wchar_t **)(param_2 + 0x21c) = pwVar7;
      uVar14 = 1;
    }
  }
  *(uint *)(param_2 + 8) = uVar14;
  *(undefined4 *)(param_2 + 0xc) = 0;
  *(undefined4 *)(param_2 + 0x10) = 0;
  *(undefined4 *)(param_2 + 0x14) = 0;
LAB_00411d83:
  FUN_004117a9(param_2);
  goto LAB_00411d94;
}



undefined4 __cdecl FUN_00411da3(__acrt_ptd **param_1,byte param_2,uint param_3,byte param_4)

{
  undefined4 uVar1;
  int local_14;
  int *local_10;
  int local_c;
  char local_8;
  
  FUN_00408ded(&local_14,param_1);
  if (((*(byte *)(local_c + 0x19 + (uint)param_2) & param_4) == 0) &&
     ((param_3 == 0 || ((param_3 & *(ushort *)(*local_10 + (uint)param_2 * 2)) == 0)))) {
    uVar1 = 0;
  }
  else {
    uVar1 = 1;
  }
  if (local_8 != '\0') {
    *(uint *)(local_14 + 0x350) = *(uint *)(local_14 + 0x350) & 0xfffffffd;
  }
  return uVar1;
}



void __cdecl FUN_00411df3(byte param_1)

{
  FUN_00411da3((__acrt_ptd **)0x0,param_1,0,4);
  return;
}



uint __cdecl FUN_00411e0b(uint param_1,uint param_2)

{
  int iVar1;
  
  if (param_1 < 0xdead) {
    if (param_1 == 0xdeac) {
      return 0;
    }
    if (param_1 < 0xc434) {
      if (param_1 == 0xc433) {
        return 0;
      }
      if (param_1 == 0x2a) {
        return 0;
      }
      if (param_1 == 0xc42c) {
        return 0;
      }
      if (param_1 == 0xc42d) {
        return 0;
      }
      if (param_1 == 0xc42e) {
        return 0;
      }
      iVar1 = param_1 - 0xc431;
      goto LAB_00411e42;
    }
    if (param_1 == 0xc435) {
      return 0;
    }
    if (param_1 == 0xd698) goto LAB_00411e9b;
    iVar1 = param_1 - 0xdeaa;
  }
  else {
    if (0xdeb1 < param_1) {
      if (param_1 == 0xdeb2) {
        return 0;
      }
      if (param_1 == 0xdeb3) {
        return 0;
      }
      if (param_1 == 65000) {
        return 0;
      }
      if (param_1 != 0xfde9) {
        return param_2;
      }
LAB_00411e9b:
      return param_2 & 8;
    }
    if (param_1 == 0xdeb1) {
      return 0;
    }
    if (param_1 == 0xdead) {
      return 0;
    }
    if (param_1 == 0xdeae) {
      return 0;
    }
    iVar1 = param_1 - 0xdeaf;
  }
  if (iVar1 == 0) {
    return 0;
  }
  iVar1 = iVar1 + -1;
LAB_00411e42:
  if (iVar1 == 0) {
    return 0;
  }
  return param_2;
}



void __cdecl
FUN_00411ea3(uint param_1,uint param_2,LPCSTR param_3,int param_4,LPWSTR param_5,int param_6)

{
  uint dwFlags;
  
  dwFlags = FUN_00411e0b(param_1,param_2);
  MultiByteToWideChar(param_1,dwFlags,param_3,param_4,param_5,param_6);
  return;
}



uint __cdecl FUN_00411ecd(uint param_1,uint param_2)

{
  int iVar1;
  bool bVar2;
  
  if (param_1 < 0xdead) {
    if (param_1 == 0xdeac) {
      return 0;
    }
    if (param_1 < 0xc434) {
      if (param_1 == 0xc433) {
        return 0;
      }
      if (param_1 == 0x2a) {
        return 0;
      }
      if (param_1 == 0xc42c) {
        return 0;
      }
      if (param_1 == 0xc42d) {
        return 0;
      }
      if (param_1 == 0xc42e) {
        return 0;
      }
      iVar1 = param_1 - 0xc431;
      goto LAB_00411f4d;
    }
    if (param_1 == 0xc435) {
      return 0;
    }
    if (param_1 == 0xd698) {
      return 0;
    }
    iVar1 = param_1 - 0xdeaa;
    bVar2 = iVar1 == 0;
  }
  else if (param_1 < 0xdeb2) {
    if (param_1 == 0xdeb1) {
      return 0;
    }
    if (param_1 == 0xdead) {
      return 0;
    }
    if (param_1 == 0xdeae) {
      return 0;
    }
    iVar1 = param_1 - 0xdeaf;
    bVar2 = iVar1 == 0;
  }
  else {
    if (param_1 == 0xdeb2) {
      return 0;
    }
    if (param_1 == 0xdeb3) {
      return 0;
    }
    iVar1 = param_1 - 65000;
    bVar2 = iVar1 == 0;
  }
  if (bVar2) {
    return 0;
  }
  iVar1 = iVar1 + -1;
LAB_00411f4d:
  if (iVar1 == 0) {
    return 0;
  }
  return param_2 & 0xffffff7f;
}



void __cdecl
FUN_00411f5d(uint param_1,uint param_2,LPCWSTR param_3,int param_4,LPSTR param_5,int param_6,
            uint param_7,undefined4 *param_8)

{
  bool bVar1;
  uint dwFlags;
  UINT CodePage;
  
  if ((param_1 == 65000) || (param_1 == 0xfde9)) {
    bVar1 = true;
  }
  else {
    bVar1 = false;
  }
  dwFlags = FUN_00411ecd(param_1,param_2);
  if ((bVar1) && (param_8 != (undefined4 *)0x0)) {
    *param_8 = 0;
  }
  WideCharToMultiByte(CodePage,dwFlags,param_3,param_4,param_5,param_6,
                      (LPCSTR)(~-(uint)bVar1 & param_7),(LPBOOL)(~-(uint)bVar1 & (uint)param_8));
  return;
}



// Library Function - Single Match
//  wchar_t const * __cdecl find_end_of_double_null_terminated_sequence(wchar_t const * const)
// 
// Libraries: Visual Studio 2015, Visual Studio 2017, Visual Studio 2019

wchar_t * __cdecl find_end_of_double_null_terminated_sequence(wchar_t *param_1)

{
  wchar_t wVar1;
  wchar_t *pwVar2;
  
  wVar1 = *param_1;
  while (wVar1 != L'\0') {
    pwVar2 = param_1;
    do {
      wVar1 = *pwVar2;
      pwVar2 = pwVar2 + 1;
    } while (wVar1 != L'\0');
    param_1 = param_1 + ((int)pwVar2 - (int)(param_1 + 1) >> 1) + 1;
    wVar1 = *param_1;
  }
  return param_1 + 1;
}



LPWCH FUN_00412000(void)

{
  LPWCH pWVar1;
  wchar_t *pwVar2;
  int iVar3;
  SIZE_T SVar4;
  LPWCH pWVar5;
  
  pWVar1 = GetEnvironmentStringsW();
  pWVar5 = pWVar1;
  if (pWVar1 != (LPWCH)0x0) {
    pwVar2 = find_end_of_double_null_terminated_sequence(pWVar1);
    iVar3 = (int)pwVar2 - (int)pWVar1 >> 1;
    SVar4 = FUN_00411f5d(0,0,pWVar1,iVar3,(LPSTR)0x0,0,0,(undefined4 *)0x0);
    if (SVar4 == 0) {
      FreeEnvironmentStringsW(pWVar1);
      pWVar5 = (LPWCH)0x0;
    }
    else {
      pWVar5 = (LPWCH)__malloc_base(SVar4);
      if (pWVar5 == (LPWCH)0x0) {
        FUN_0040e374((LPVOID)0x0);
        FreeEnvironmentStringsW(pWVar1);
        pWVar5 = (LPWCH)0x0;
      }
      else {
        iVar3 = FUN_00411f5d(0,0,pWVar1,iVar3,(LPSTR)pWVar5,SVar4,0,(undefined4 *)0x0);
        if (iVar3 == 0) {
          FUN_0040e374(pWVar5);
          pWVar5 = (LPWCH)0x0;
        }
        else {
          FUN_0040e374((LPVOID)0x0);
        }
        FreeEnvironmentStringsW(pWVar1);
      }
    }
  }
  return pWVar5;
}



undefined4 __cdecl FUN_004120a0(char *param_1,int param_2)

{
  uint uVar1;
  char cVar2;
  char cVar3;
  undefined4 *puVar4;
  char *pcVar5;
  int iVar6;
  uint uVar7;
  int *piVar8;
  char *pcVar9;
  BOOL BVar10;
  undefined4 uVar11;
  char *pcVar12;
  char *pcVar13;
  
  if (param_1 == (char *)0x0) {
    puVar4 = (undefined4 *)FUN_0040e304();
    *puVar4 = 0x16;
    return 0xffffffff;
  }
  pcVar5 = _strchr(param_1,0x3d);
  if ((pcVar5 == (char *)0x0) || (pcVar5 == param_1)) {
    puVar4 = (undefined4 *)FUN_0040e304();
    *puVar4 = 0x16;
    FUN_0040e374(param_1);
    return 0xffffffff;
  }
  cVar2 = pcVar5[1];
  ensure_current_environment_is_not_initial_environment_nolock<char>();
  uVar11 = 0;
  if (DAT_00423e38 == (int *)0x0) {
    if ((param_2 != 0) && (DAT_00423e3c != (LPVOID)0x0)) {
      iVar6 = common_get_or_create_environment_nolock<>();
      if (iVar6 == 0) {
        puVar4 = (undefined4 *)FUN_0040e304();
        *puVar4 = 0x16;
        goto LAB_0041211a;
      }
      ensure_current_environment_is_not_initial_environment_nolock<char>();
      goto LAB_00412175;
    }
    if (cVar2 == '\0') goto LAB_004122c1;
    DAT_00423e38 = (int *)__calloc_base(1,4);
    FUN_0040e374((LPVOID)0x0);
    if (DAT_00423e38 != (int *)0x0) {
      if (DAT_00423e3c == (LPVOID)0x0) {
        DAT_00423e3c = __calloc_base(1,4);
        FUN_0040e374((LPVOID)0x0);
        if (DAT_00423e3c == (LPVOID)0x0) goto LAB_0041211a;
      }
      goto LAB_00412175;
    }
  }
  else {
LAB_00412175:
    piVar8 = DAT_00423e38;
    if (DAT_00423e38 != (int *)0x0) {
      uVar7 = find_in_environment_nolock<char>(param_1,(int)pcVar5 - (int)param_1);
      if ((-1 < (int)uVar7) && (*piVar8 != 0)) {
        FUN_0040e374((LPVOID)piVar8[uVar7]);
        if (cVar2 == '\0') {
          for (; piVar8[uVar7] != 0; uVar7 = uVar7 + 1) {
            piVar8[uVar7] = piVar8[uVar7 + 1];
          }
          piVar8 = (int *)__recalloc_base(piVar8,uVar7,4);
          FUN_0040e374((LPVOID)0x0);
          pcVar13 = param_1;
          if (piVar8 != (int *)0x0) {
LAB_00412239:
            DAT_00423e38 = piVar8;
          }
        }
        else {
          pcVar13 = (char *)0x0;
          piVar8[uVar7] = (int)param_1;
        }
        if (param_2 == 0) {
LAB_004122d1:
          FUN_0040e374(pcVar13);
          return 0;
        }
        pcVar12 = param_1;
        do {
          cVar3 = *pcVar12;
          pcVar12 = pcVar12 + 1;
        } while (cVar3 != '\0');
        pcVar9 = (char *)__calloc_base((uint)(pcVar12 + (2 - (int)(param_1 + 1))),1);
        if (pcVar9 == (char *)0x0) {
          FUN_0040e374((LPVOID)0x0);
          param_1 = pcVar13;
        }
        else {
          iVar6 = FUN_0040daef(pcVar9,(int)(pcVar12 + (2 - (int)(param_1 + 1))),(int)param_1);
          if (iVar6 != 0) {
                    // WARNING: Subroutine does not return
            __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
          }
          pcVar5[(int)pcVar9 - (int)param_1] = '\0';
          BVar10 = ___acrt_SetEnvironmentVariableA
                             (pcVar9,(char *)(-(uint)(cVar2 != '\0') &
                                             (uint)(pcVar5 + ((int)pcVar9 - (int)param_1) + 1)));
          if (BVar10 != 0) {
            FUN_0040e374(pcVar9);
            goto LAB_004122d1;
          }
          puVar4 = (undefined4 *)FUN_0040e304();
          *puVar4 = 0x2a;
          FUN_0040e374(pcVar9);
          uVar11 = 0xffffffff;
          param_1 = pcVar13;
        }
        goto LAB_004122c1;
      }
      if (cVar2 == '\0') goto LAB_004122c1;
      uVar1 = -uVar7 + 2;
      if ((-uVar7 <= uVar1) && (uVar1 < 0x3fffffff)) {
        piVar8 = (int *)__recalloc_base(piVar8,uVar1,4);
        FUN_0040e374((LPVOID)0x0);
        if (piVar8 != (int *)0x0) {
          piVar8[-uVar7] = (int)param_1;
          piVar8[1 - uVar7] = 0;
          pcVar13 = (char *)0x0;
          goto LAB_00412239;
        }
      }
    }
  }
LAB_0041211a:
  uVar11 = 0xffffffff;
LAB_004122c1:
  FUN_0040e374(param_1);
  return uVar11;
}



// Library Function - Single Match
//  char * * __cdecl copy_environment<char>(char * * const)
// 
// Library: Visual Studio 2019 Release

char ** __cdecl copy_environment<char>(char **param_1)

{
  char *pcVar1;
  char cVar2;
  char **ppcVar3;
  LPVOID pvVar4;
  int iVar5;
  int iVar6;
  char *pcVar7;
  
  if (param_1 == (char **)0x0) {
    ppcVar3 = (char **)0x0;
  }
  else {
    iVar6 = 0;
    pcVar7 = *param_1;
    ppcVar3 = param_1;
    while (pcVar7 != (char *)0x0) {
      ppcVar3 = ppcVar3 + 1;
      iVar6 = iVar6 + 1;
      pcVar7 = *ppcVar3;
    }
    ppcVar3 = (char **)__calloc_base(iVar6 + 1,4);
    if (ppcVar3 == (char **)0x0) {
LAB_0041239e:
                    // WARNING: Subroutine does not return
      _abort();
    }
    pcVar7 = *param_1;
    if (pcVar7 != (char *)0x0) {
      iVar6 = (int)ppcVar3 - (int)param_1;
      do {
        pcVar1 = pcVar7 + 1;
        do {
          cVar2 = *pcVar7;
          pcVar7 = pcVar7 + 1;
        } while (cVar2 != '\0');
        pvVar4 = __calloc_base((uint)(pcVar7 + (1 - (int)pcVar1)),1);
        *(LPVOID *)(iVar6 + (int)param_1) = pvVar4;
        FUN_0040e374((LPVOID)0x0);
        if (*(int *)(iVar6 + (int)param_1) == 0) goto LAB_0041239e;
        iVar5 = FUN_0040daef(*(char **)(iVar6 + (int)param_1),(int)(pcVar7 + (1 - (int)pcVar1)),
                             (int)*param_1);
        if (iVar5 != 0) {
                    // WARNING: Subroutine does not return
          __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
        }
        param_1 = param_1 + 1;
        pcVar7 = *param_1;
      } while (pcVar7 != (char *)0x0);
    }
    FUN_0040e374((LPVOID)0x0);
  }
  return ppcVar3;
}



// Library Function - Single Match
//  void __cdecl ensure_current_environment_is_not_initial_environment_nolock<char>(void)
// 
// Library: Visual Studio 2019 Release

void __cdecl ensure_current_environment_is_not_initial_environment_nolock<char>(void)

{
  if (DAT_00423e38 == DAT_00423e44) {
    DAT_00423e38 = copy_environment<char>(DAT_00423e38);
  }
  return;
}



// Library Function - Single Match
//  int __cdecl find_in_environment_nolock<char>(char const * const,unsigned int)
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

int __cdecl find_in_environment_nolock<char>(char *param_1,uint param_2)

{
  char *_Str2;
  char **ppcVar1;
  int iVar2;
  char **ppcVar3;
  
  ppcVar1 = DAT_00423e38;
  _Str2 = *DAT_00423e38;
  ppcVar3 = DAT_00423e38;
  while( true ) {
    if (_Str2 == (char *)0x0) {
      return -((int)ppcVar3 - (int)ppcVar1 >> 2);
    }
    iVar2 = __strnicoll(param_1,_Str2,param_2);
    if ((iVar2 == 0) && (((*ppcVar3)[param_2] == '=' || ((*ppcVar3)[param_2] == '\0')))) break;
    ppcVar3 = ppcVar3 + 1;
    _Str2 = *ppcVar3;
  }
  return (int)ppcVar3 - (int)ppcVar1 >> 2;
}



void __cdecl FUN_0041241f(char *param_1,int param_2)

{
  FUN_004120a0(param_1,param_2);
  return;
}



// Library Function - Single Match
//  ___acrt_lowio_create_handle_array
// 
// Library: Visual Studio 2019 Release

undefined4 * ___acrt_lowio_create_handle_array(void)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  
  puVar2 = (undefined4 *)__calloc_base(0x40,0x38);
  if (puVar2 == (undefined4 *)0x0) {
    puVar2 = (undefined4 *)0x0;
  }
  else if (puVar2 != puVar2 + 0x380) {
    puVar3 = puVar2 + 8;
    do {
      ___acrt_InitializeCriticalSectionEx_12((LPCRITICAL_SECTION)(puVar3 + -8),4000,(void *)0x0);
      puVar3[-2] = 0xffffffff;
      *(byte *)((int)puVar3 + 0xd) = *(byte *)((int)puVar3 + 0xd) & 0xf8;
      *puVar3 = 0;
      puVar3[1] = 0;
      puVar1 = puVar3 + 6;
      puVar3[2] = 0xa0a0000;
      *(undefined *)(puVar3 + 3) = 10;
      *(undefined4 *)((int)puVar3 + 0xe) = 0;
      *(undefined *)((int)puVar3 + 0x12) = 0;
      puVar3 = puVar3 + 0xe;
    } while (puVar1 != puVar2 + 0x380);
  }
  FUN_0040e374((LPVOID)0x0);
  return puVar2;
}



// Library Function - Single Match
//  ___acrt_lowio_destroy_handle_array
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __cdecl ___acrt_lowio_destroy_handle_array(LPCRITICAL_SECTION param_1)

{
  LPCRITICAL_SECTION lpCriticalSection;
  
  if (param_1 != (LPCRITICAL_SECTION)0x0) {
    lpCriticalSection = param_1;
    if (param_1 != (LPCRITICAL_SECTION)&param_1[0x95].RecursionCount) {
      do {
        DeleteCriticalSection(lpCriticalSection);
        lpCriticalSection = (LPCRITICAL_SECTION)&lpCriticalSection[2].RecursionCount;
      } while (lpCriticalSection != (LPCRITICAL_SECTION)&param_1[0x95].RecursionCount);
    }
    FUN_0040e374(param_1);
  }
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// Library Function - Single Match
//  ___acrt_lowio_ensure_fh_exists
// 
// Library: Visual Studio 2019 Release

undefined4 __cdecl ___acrt_lowio_ensure_fh_exists(uint param_1)

{
  undefined4 *puVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  void *local_14;
  
  if (param_1 < 0x2000) {
    uVar3 = 0;
    ___acrt_lock(7);
    iVar4 = 0;
    iVar2 = DAT_004242c8;
    while (iVar2 <= (int)param_1) {
      if ((&DAT_004240c8)[iVar4] == 0) {
        puVar1 = ___acrt_lowio_create_handle_array();
        (&DAT_004240c8)[iVar4] = puVar1;
        if (puVar1 == (undefined4 *)0x0) {
          uVar3 = 0xc;
          break;
        }
        iVar2 = DAT_004242c8 + 0x40;
        DAT_004242c8 = iVar2;
      }
      iVar4 = iVar4 + 1;
    }
    FUN_0041256f();
  }
  else {
    puVar1 = (undefined4 *)FUN_0040e304();
    uVar3 = 9;
    *puVar1 = 9;
    FUN_0040e223();
  }
  ExceptionList = local_14;
  return uVar3;
}



void FUN_0041256f(void)

{
  ___acrt_unlock(7);
  return;
}



void __cdecl FUN_00412578(uint param_1)

{
  EnterCriticalSection
            ((LPCRITICAL_SECTION)((param_1 & 0x3f) * 0x38 + (&DAT_004240c8)[(int)param_1 >> 6]));
  return;
}



// Library Function - Single Match
//  ___acrt_lowio_unlock_fh
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __cdecl ___acrt_lowio_unlock_fh(uint param_1)

{
  LeaveCriticalSection
            ((LPCRITICAL_SECTION)((param_1 & 0x3f) * 0x38 + (&DAT_004240c8)[(int)param_1 >> 6]));
  return;
}



undefined4 __cdecl FUN_004125be(uint param_1)

{
  int iVar1;
  undefined4 *puVar2;
  int iVar3;
  DWORD nStdHandle;
  
  if ((-1 < (int)param_1) && (param_1 < DAT_004242c8)) {
    iVar3 = (param_1 & 0x3f) * 0x38;
    if (((*(byte *)(iVar3 + 0x28 + (&DAT_004240c8)[param_1 >> 6]) & 1) != 0) &&
       (*(int *)(iVar3 + 0x18 + (&DAT_004240c8)[param_1 >> 6]) != -1)) {
      iVar1 = FUN_0040cd86();
      if (iVar1 == 1) {
        if (param_1 == 0) {
          nStdHandle = 0xfffffff6;
        }
        else if (param_1 == 1) {
          nStdHandle = 0xfffffff5;
        }
        else {
          if (param_1 != 2) goto LAB_00412624;
          nStdHandle = 0xfffffff4;
        }
        SetStdHandle(nStdHandle,(HANDLE)0x0);
      }
LAB_00412624:
      *(undefined4 *)((&DAT_004240c8)[param_1 >> 6] + 0x18 + iVar3) = 0xffffffff;
      return 0;
    }
  }
  puVar2 = (undefined4 *)FUN_0040e304();
  *puVar2 = 9;
  puVar2 = (undefined4 *)FUN_0040e2f1();
  *puVar2 = 0;
  return 0xffffffff;
}



undefined4 __cdecl FUN_0041264f(uint param_1)

{
  undefined4 *puVar1;
  int iVar2;
  
  if (param_1 == 0xfffffffe) {
    puVar1 = (undefined4 *)FUN_0040e2f1();
    *puVar1 = 0;
    puVar1 = (undefined4 *)FUN_0040e304();
    *puVar1 = 9;
  }
  else {
    if ((-1 < (int)param_1) && (param_1 < DAT_004242c8)) {
      iVar2 = (param_1 & 0x3f) * 0x38;
      if ((*(byte *)((&DAT_004240c8)[param_1 >> 6] + 0x28 + iVar2) & 1) != 0) {
        return *(undefined4 *)((&DAT_004240c8)[param_1 >> 6] + 0x18 + iVar2);
      }
    }
    puVar1 = (undefined4 *)FUN_0040e2f1();
    *puVar1 = 0;
    puVar1 = (undefined4 *)FUN_0040e304();
    *puVar1 = 9;
    FUN_0040e223();
  }
  return 0xffffffff;
}



// Library Function - Single Match
//  ___acrt_locale_free_monetary
// 
// Library: Visual Studio 2019 Release

void __cdecl ___acrt_locale_free_monetary(int param_1)

{
  if (param_1 != 0) {
    if (*(undefined **)(param_1 + 0xc) != PTR_DAT_0042372c) {
      FUN_0040e374(*(undefined **)(param_1 + 0xc));
    }
    if (*(undefined **)(param_1 + 0x10) != PTR_DAT_00423730) {
      FUN_0040e374(*(undefined **)(param_1 + 0x10));
    }
    if (*(undefined **)(param_1 + 0x14) != PTR_DAT_00423734) {
      FUN_0040e374(*(undefined **)(param_1 + 0x14));
    }
    if (*(undefined **)(param_1 + 0x18) != PTR_DAT_00423738) {
      FUN_0040e374(*(undefined **)(param_1 + 0x18));
    }
    if (*(undefined **)(param_1 + 0x1c) != PTR_DAT_0042373c) {
      FUN_0040e374(*(undefined **)(param_1 + 0x1c));
    }
    if (*(undefined **)(param_1 + 0x20) != PTR_DAT_00423740) {
      FUN_0040e374(*(undefined **)(param_1 + 0x20));
    }
    if (*(undefined **)(param_1 + 0x24) != PTR_DAT_00423744) {
      FUN_0040e374(*(undefined **)(param_1 + 0x24));
    }
    if (*(undefined **)(param_1 + 0x38) != PTR_DAT_00423758) {
      FUN_0040e374(*(undefined **)(param_1 + 0x38));
    }
    if (*(undefined **)(param_1 + 0x3c) != PTR_DAT_0042375c) {
      FUN_0040e374(*(undefined **)(param_1 + 0x3c));
    }
    if (*(undefined **)(param_1 + 0x40) != PTR_DAT_00423760) {
      FUN_0040e374(*(undefined **)(param_1 + 0x40));
    }
    if (*(undefined **)(param_1 + 0x44) != PTR_DAT_00423764) {
      FUN_0040e374(*(undefined **)(param_1 + 0x44));
    }
    if (*(undefined **)(param_1 + 0x48) != PTR_DAT_00423768) {
      FUN_0040e374(*(undefined **)(param_1 + 0x48));
    }
    if (*(undefined **)(param_1 + 0x4c) != PTR_DAT_0042376c) {
      FUN_0040e374(*(undefined **)(param_1 + 0x4c));
    }
  }
  return;
}



// Library Function - Single Match
//  ___acrt_locale_free_numeric
// 
// Library: Visual Studio 2019 Release

void __cdecl ___acrt_locale_free_numeric(LPVOID *param_1)

{
  if (param_1 != (LPVOID *)0x0) {
    if ((undefined *)*param_1 != PTR_DAT_00423720) {
      FUN_0040e374(*param_1);
    }
    if ((undefined *)param_1[1] != PTR_DAT_00423724) {
      FUN_0040e374(param_1[1]);
    }
    if ((undefined *)param_1[2] != PTR_DAT_00423728) {
      FUN_0040e374(param_1[2]);
    }
    if ((undefined *)param_1[0xc] != PTR_DAT_00423750) {
      FUN_0040e374(param_1[0xc]);
    }
    if ((undefined *)param_1[0xd] != PTR_DAT_00423754) {
      FUN_0040e374(param_1[0xd]);
    }
  }
  return;
}



void __cdecl FUN_00412836(LPVOID *param_1,int param_2)

{
  LPVOID *ppvVar1;
  
  ppvVar1 = param_1 + param_2;
  for (; param_1 != ppvVar1; param_1 = param_1 + 1) {
    FUN_0040e374(*param_1);
  }
  return;
}



// Library Function - Single Match
//  ___acrt_locale_free_time
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void __cdecl ___acrt_locale_free_time(LPVOID *param_1)

{
  if (param_1 != (LPVOID *)0x0) {
    FUN_00412836(param_1,7);
    FUN_00412836(param_1 + 7,7);
    FUN_00412836(param_1 + 0xe,0xc);
    FUN_00412836(param_1 + 0x1a,0xc);
    FUN_00412836(param_1 + 0x26,2);
    FUN_0040e374(param_1[0x28]);
    FUN_0040e374(param_1[0x29]);
    FUN_0040e374(param_1[0x2a]);
    FUN_00412836(param_1 + 0x2d,7);
    FUN_00412836(param_1 + 0x34,7);
    FUN_00412836(param_1 + 0x3b,0xc);
    FUN_00412836(param_1 + 0x47,0xc);
    FUN_00412836(param_1 + 0x53,2);
    FUN_0040e374(param_1[0x55]);
    FUN_0040e374(param_1[0x56]);
    FUN_0040e374(param_1[0x57]);
    FUN_0040e374(param_1[0x58]);
  }
  return;
}



// WARNING: Function: __alloca_probe_16 replaced with injection: alloca_probe

void __cdecl
FUN_0041293f(__acrt_ptd **param_1,DWORD param_2,LPCSTR param_3,int param_4,LPWORD param_5,
            uint param_6,int param_7)

{
  uint uVar1;
  undefined4 *lpSrcStr;
  int cchSrc;
  undefined4 *puVar2;
  int local_20;
  int local_1c;
  char local_14;
  int local_10;
  uint local_c;
  uint local_8;
  
  local_8 = DAT_00423014 ^ (uint)&stack0xfffffffc;
  FUN_00408ded(&local_20,param_1);
  if (param_6 == 0) {
    param_6 = *(uint *)(local_1c + 8);
  }
  local_10 = FUN_00411ea3(param_6,(uint)(param_7 != 0) * 8 + 1,param_3,param_4,(LPWSTR)0x0,0);
  if (local_10 == 0) goto LAB_00412a1c;
  local_c = local_10 * 2;
  uVar1 = -(uint)(local_c < local_c + 8) & local_c + 8;
  if (uVar1 == 0) {
    lpSrcStr = (undefined4 *)0x0;
  }
  else if (uVar1 < 0x401) {
    puVar2 = (undefined4 *)&stack0xffffffd4;
    lpSrcStr = (undefined4 *)&stack0xffffffd4;
    if (&stack0x00000000 != (undefined *)0x2c) {
LAB_004129d7:
      lpSrcStr = puVar2 + 2;
      if (lpSrcStr != (undefined4 *)0x0) {
        _memset(lpSrcStr,0,local_c);
        cchSrc = FUN_00411ea3(param_6,1,param_3,param_4,(LPWSTR)lpSrcStr,local_10);
        if (cchSrc != 0) {
          GetStringTypeW(param_2,(LPCWSTR)lpSrcStr,cchSrc,param_5);
        }
      }
    }
  }
  else {
    lpSrcStr = (undefined4 *)__malloc_base(uVar1);
    if (lpSrcStr != (undefined4 *)0x0) {
      *lpSrcStr = 0xdddd;
      puVar2 = lpSrcStr;
      goto LAB_004129d7;
    }
  }
  FUN_00412a40((int)lpSrcStr);
LAB_00412a1c:
  if (local_14 != '\0') {
    *(uint *)(local_20 + 0x350) = *(uint *)(local_20 + 0x350) & 0xfffffffd;
  }
  FUN_00402125(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



void __cdecl FUN_00412a40(int param_1)

{
  if ((param_1 != 0) && (*(int *)(param_1 + -8) == 0xdddd)) {
    FUN_0040e374((int *)(param_1 + -8));
  }
  return;
}



// Library Function - Single Match
//  ___acrt_add_locale_ref
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void __cdecl ___acrt_add_locale_ref(int param_1)

{
  int *piVar1;
  int **ppiVar2;
  int iVar3;
  
  LOCK();
  *(int *)(param_1 + 0xc) = *(int *)(param_1 + 0xc) + 1;
  UNLOCK();
  piVar1 = *(int **)(param_1 + 0x7c);
  if (piVar1 != (int *)0x0) {
    LOCK();
    *piVar1 = *piVar1 + 1;
    UNLOCK();
  }
  piVar1 = *(int **)(param_1 + 0x84);
  if (piVar1 != (int *)0x0) {
    LOCK();
    *piVar1 = *piVar1 + 1;
    UNLOCK();
  }
  piVar1 = *(int **)(param_1 + 0x80);
  if (piVar1 != (int *)0x0) {
    LOCK();
    *piVar1 = *piVar1 + 1;
    UNLOCK();
  }
  piVar1 = *(int **)(param_1 + 0x8c);
  if (piVar1 != (int *)0x0) {
    LOCK();
    *piVar1 = *piVar1 + 1;
    UNLOCK();
  }
  ppiVar2 = (int **)(param_1 + 0x28);
  iVar3 = 6;
  do {
    if ((ppiVar2[-2] != (int *)&DAT_004231f8) && (piVar1 = *ppiVar2, piVar1 != (int *)0x0)) {
      LOCK();
      *piVar1 = *piVar1 + 1;
      UNLOCK();
    }
    if ((ppiVar2[-3] != (int *)0x0) && (piVar1 = ppiVar2[-1], piVar1 != (int *)0x0)) {
      LOCK();
      *piVar1 = *piVar1 + 1;
      UNLOCK();
    }
    ppiVar2 = ppiVar2 + 4;
    iVar3 = iVar3 + -1;
  } while (iVar3 != 0);
  ___acrt_locale_add_lc_time_reference(*(undefined ***)(param_1 + 0x9c));
  return;
}



// Library Function - Single Match
//  ___acrt_free_locale
// 
// Library: Visual Studio 2019 Release

void __cdecl ___acrt_free_locale(LPVOID param_1)

{
  int *piVar1;
  LPVOID *ppvVar2;
  int **ppiVar3;
  int local_8;
  
  if ((((*(undefined ***)((int)param_1 + 0x88) != (undefined **)0x0) &&
       (*(undefined ***)((int)param_1 + 0x88) != &PTR_DAT_00423720)) &&
      (*(int **)((int)param_1 + 0x7c) != (int *)0x0)) && (**(int **)((int)param_1 + 0x7c) == 0)) {
    piVar1 = *(int **)((int)param_1 + 0x84);
    if ((piVar1 != (int *)0x0) && (*piVar1 == 0)) {
      FUN_0040e374(piVar1);
      ___acrt_locale_free_monetary(*(int *)((int)param_1 + 0x88));
    }
    piVar1 = *(int **)((int)param_1 + 0x80);
    if ((piVar1 != (int *)0x0) && (*piVar1 == 0)) {
      FUN_0040e374(piVar1);
      ___acrt_locale_free_numeric(*(LPVOID **)((int)param_1 + 0x88));
    }
    FUN_0040e374(*(LPVOID *)((int)param_1 + 0x7c));
    FUN_0040e374(*(LPVOID *)((int)param_1 + 0x88));
  }
  if ((*(int **)((int)param_1 + 0x8c) != (int *)0x0) && (**(int **)((int)param_1 + 0x8c) == 0)) {
    FUN_0040e374((LPVOID)(*(int *)((int)param_1 + 0x90) + -0xfe));
    FUN_0040e374((LPVOID)(*(int *)((int)param_1 + 0x94) + -0x80));
    FUN_0040e374((LPVOID)(*(int *)((int)param_1 + 0x98) + -0x80));
    FUN_0040e374(*(LPVOID *)((int)param_1 + 0x8c));
  }
  ___acrt_locale_free_lc_time_if_unreferenced(*(undefined ***)((int)param_1 + 0x9c));
  ppvVar2 = (LPVOID *)((int)param_1 + 0xa0);
  local_8 = 6;
  ppiVar3 = (int **)((int)param_1 + 0x28);
  do {
    if (((ppiVar3[-2] != (int *)&DAT_004231f8) && (piVar1 = *ppiVar3, piVar1 != (int *)0x0)) &&
       (*piVar1 == 0)) {
      FUN_0040e374(piVar1);
      FUN_0040e374(*ppvVar2);
    }
    if (((ppiVar3[-3] != (int *)0x0) && (piVar1 = ppiVar3[-1], piVar1 != (int *)0x0)) &&
       (*piVar1 == 0)) {
      FUN_0040e374(piVar1);
    }
    ppvVar2 = ppvVar2 + 1;
    ppiVar3 = ppiVar3 + 4;
    local_8 = local_8 + -1;
  } while (local_8 != 0);
  FUN_0040e374(param_1);
  return;
}



// Library Function - Single Match
//  ___acrt_locale_add_lc_time_reference
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

undefined * __cdecl ___acrt_locale_add_lc_time_reference(undefined **param_1)

{
  undefined **ppuVar1;
  undefined *puVar2;
  
  if ((param_1 != (undefined **)0x0) && (param_1 != &PTR_DAT_0041d2a0)) {
    LOCK();
    ppuVar1 = param_1 + 0x2c;
    puVar2 = *ppuVar1;
    *ppuVar1 = *ppuVar1 + 1;
    UNLOCK();
    return puVar2 + 1;
  }
  return (undefined *)0x7fffffff;
}



// Library Function - Single Match
//  ___acrt_locale_free_lc_time_if_unreferenced
// 
// Library: Visual Studio 2019 Release

void __cdecl ___acrt_locale_free_lc_time_if_unreferenced(undefined **param_1)

{
  if (((param_1 != (undefined **)0x0) && (param_1 != &PTR_DAT_0041d2a0)) &&
     (param_1[0x2c] == (undefined *)0x0)) {
    ___acrt_locale_free_time(param_1);
    FUN_0040e374(param_1);
  }
  return;
}



// Library Function - Single Match
//  ___acrt_locale_release_lc_time_reference
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

undefined * __cdecl ___acrt_locale_release_lc_time_reference(undefined **param_1)

{
  undefined **ppuVar1;
  undefined *puVar2;
  
  if ((param_1 != (undefined **)0x0) && (param_1 != &PTR_DAT_0041d2a0)) {
    LOCK();
    ppuVar1 = param_1 + 0x2c;
    puVar2 = *ppuVar1;
    *ppuVar1 = *ppuVar1 + -1;
    UNLOCK();
    return puVar2 + -1;
  }
  return (undefined *)0x7fffffff;
}



// Library Function - Single Match
//  ___acrt_release_locale_ref
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void __cdecl ___acrt_release_locale_ref(int param_1)

{
  int *piVar1;
  int **ppiVar2;
  int iVar3;
  
  if (param_1 != 0) {
    LOCK();
    *(int *)(param_1 + 0xc) = *(int *)(param_1 + 0xc) + -1;
    UNLOCK();
    piVar1 = *(int **)(param_1 + 0x7c);
    if (piVar1 != (int *)0x0) {
      LOCK();
      *piVar1 = *piVar1 + -1;
      UNLOCK();
    }
    piVar1 = *(int **)(param_1 + 0x84);
    if (piVar1 != (int *)0x0) {
      LOCK();
      *piVar1 = *piVar1 + -1;
      UNLOCK();
    }
    piVar1 = *(int **)(param_1 + 0x80);
    if (piVar1 != (int *)0x0) {
      LOCK();
      *piVar1 = *piVar1 + -1;
      UNLOCK();
    }
    piVar1 = *(int **)(param_1 + 0x8c);
    if (piVar1 != (int *)0x0) {
      LOCK();
      *piVar1 = *piVar1 + -1;
      UNLOCK();
    }
    ppiVar2 = (int **)(param_1 + 0x28);
    iVar3 = 6;
    do {
      if ((ppiVar2[-2] != (int *)&DAT_004231f8) && (piVar1 = *ppiVar2, piVar1 != (int *)0x0)) {
        LOCK();
        *piVar1 = *piVar1 + -1;
        UNLOCK();
      }
      if ((ppiVar2[-3] != (int *)0x0) && (piVar1 = ppiVar2[-1], piVar1 != (int *)0x0)) {
        LOCK();
        *piVar1 = *piVar1 + -1;
        UNLOCK();
      }
      ppiVar2 = ppiVar2 + 4;
      iVar3 = iVar3 + -1;
    } while (iVar3 != 0);
    ___acrt_locale_release_lc_time_reference(*(undefined ***)(param_1 + 0x9c));
  }
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// Library Function - Single Match
//  ___acrt_update_thread_locale_data
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

LPVOID ___acrt_update_thread_locale_data(void)

{
  __acrt_ptd *p_Var1;
  undefined **ppuVar2;
  LPVOID pvVar3;
  void *pvStack_14;
  
  p_Var1 = FUN_004104a9();
  if (((*(uint *)(p_Var1 + 0x350) & DAT_00423778) != 0) &&
     (pvVar3 = *(LPVOID *)(p_Var1 + 0x4c), pvVar3 != (LPVOID)0x0)) {
    ExceptionList = pvStack_14;
    return pvVar3;
  }
  ___acrt_lock(4);
  ppuVar2 = __updatetlocinfoEx_nolock((LPVOID *)(p_Var1 + 0x4c),DAT_004242e0);
  FUN_00412d89();
  if (ppuVar2 != (undefined **)0x0) {
    pvVar3 = (LPVOID)FUN_00412d92();
    return pvVar3;
  }
                    // WARNING: Subroutine does not return
  _abort();
}



void FUN_00412d89(void)

{
  ___acrt_unlock(4);
  return;
}



void FUN_00412d92(void)

{
  int unaff_EBP;
  
  ExceptionList = *(void **)(unaff_EBP + -0x10);
  return;
}



// Library Function - Single Match
//  __updatetlocinfoEx_nolock
// 
// Library: Visual Studio 2019 Release

undefined ** __cdecl __updatetlocinfoEx_nolock(LPVOID *param_1,undefined **param_2)

{
  undefined **ppuVar1;
  
  if ((param_2 == (undefined **)0x0) || (param_1 == (LPVOID *)0x0)) {
    param_2 = (undefined **)0x0;
  }
  else {
    ppuVar1 = (undefined **)*param_1;
    if (ppuVar1 != param_2) {
      *param_1 = param_2;
      ___acrt_add_locale_ref((int)param_2);
      if (((ppuVar1 != (undefined **)0x0) &&
          (___acrt_release_locale_ref((int)ppuVar1), ppuVar1[3] == (undefined *)0x0)) &&
         (ppuVar1 != &PTR_DAT_00423138)) {
        ___acrt_free_locale(ppuVar1);
      }
    }
  }
  return param_2;
}



// Library Function - Single Match
//  __recalloc_base
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

LPVOID __cdecl __recalloc_base(void *param_1,uint param_2,uint param_3)

{
  undefined4 *puVar1;
  LPVOID pvVar2;
  size_t sVar3;
  uint uVar4;
  
  if ((param_2 == 0) || (param_3 <= 0xffffffe0 / param_2)) {
    if (param_1 == (void *)0x0) {
      sVar3 = 0;
    }
    else {
      sVar3 = FID_conflict___msize_base(param_1);
    }
    uVar4 = param_2 * param_3;
    pvVar2 = __realloc_base(param_1,uVar4);
    if ((pvVar2 != (LPVOID)0x0) && (sVar3 < uVar4)) {
      _memset((void *)((int)pvVar2 + sVar3),0,uVar4 - sVar3);
    }
  }
  else {
    puVar1 = (undefined4 *)FUN_0040e304();
    *puVar1 = 0xc;
    pvVar2 = (LPVOID)0x0;
  }
  return pvVar2;
}



// Library Function - Single Match
//  ___acrt_execute_initializers
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

undefined4 __cdecl ___acrt_execute_initializers(undefined **param_1,undefined **param_2)

{
  code *pcVar1;
  code **in_EAX;
  code **ppcVar2;
  undefined4 uVar3;
  
  ppcVar2 = (code **)param_1;
  if (param_1 != param_2) {
    do {
      pcVar1 = *ppcVar2;
      if (pcVar1 != (code *)0x0) {
        _guard_check_icall();
        in_EAX = (code **)(*pcVar1)();
        if ((char)in_EAX == '\0') break;
      }
      ppcVar2 = ppcVar2 + 2;
    } while (ppcVar2 != (code **)param_2);
    if (ppcVar2 != (code **)param_2) {
      if (ppcVar2 != (code **)param_1) {
        ppcVar2 = ppcVar2 + -1;
        do {
          if ((ppcVar2[-1] != (code *)0x0) && (pcVar1 = *ppcVar2, pcVar1 != (code *)0x0)) {
            uVar3 = 0;
            _guard_check_icall();
            (*pcVar1)(uVar3);
          }
          in_EAX = ppcVar2 + -1;
          ppcVar2 = ppcVar2 + -2;
        } while (in_EAX != (code **)param_1);
      }
      return (uint)in_EAX & 0xffffff00;
    }
  }
  return CONCAT31((int3)((uint)in_EAX >> 8),1);
}



// Library Function - Single Match
//  ___acrt_execute_uninitializers
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

undefined __cdecl ___acrt_execute_uninitializers(int param_1,int param_2)

{
  code *pcVar1;
  undefined4 uVar2;
  
  if (param_1 != param_2) {
    do {
      pcVar1 = *(code **)(param_2 + -4);
      if (pcVar1 != (code *)0x0) {
        uVar2 = 0;
        _guard_check_icall();
        (*pcVar1)(uVar2);
      }
      param_2 = param_2 + -8;
    } while (param_2 != param_1);
  }
  return 1;
}



void __cdecl FUN_00412f1b(undefined4 param_1)

{
  DAT_00424308 = param_1;
  return;
}



bool __cdecl FUN_00412f2a(undefined4 param_1)

{
  code *pcVar1;
  int iVar2;
  bool bVar3;
  
  pcVar1 = (code *)FUN_00412f56();
  if (pcVar1 == (code *)0x0) {
    bVar3 = false;
  }
  else {
    _guard_check_icall();
    iVar2 = (*pcVar1)(param_1);
    bVar3 = iVar2 != 0;
  }
  return bVar3;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4

uint FUN_00412f56(void)

{
  uint uVar1;
  void *local_14;
  
  ___acrt_lock(0);
  uVar1 = FUN_004045bd(DAT_00424308);
  FUN_00412fa4();
  ExceptionList = local_14;
  return uVar1;
}



void FUN_00412fa4(void)

{
  ___acrt_unlock(0);
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4

uint FUN_00412fad(int *param_1)

{
  byte bVar1;
  uint uVar2;
  void *local_14;
  
  ___acrt_lock(*param_1);
  bVar1 = (byte)DAT_00423014 & 0x1f;
  uVar2 = DAT_00424314 ^ DAT_00423014;
  FUN_00413009();
  ExceptionList = local_14;
  return uVar2 >> bVar1 | uVar2 << 0x20 - bVar1;
}



void FUN_00413009(void)

{
  int unaff_EBP;
  
  ___acrt_unlock(**(int **)(unaff_EBP + 0x10));
  return;
}



// Library Function - Single Match
//  void (__cdecl** __cdecl get_global_action_nolock(int))(int)
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

_func_void_int ** __cdecl get_global_action_nolock(int param_1)

{
  if (param_1 == 2) {
    return (_func_void_int **)&DAT_0042430c;
  }
  if (param_1 != 6) {
    if (param_1 == 0xf) {
      return (_func_void_int **)&DAT_00424318;
    }
    if (param_1 == 0x15) {
      return (_func_void_int **)&DAT_00424310;
    }
    if (param_1 != 0x16) {
      return (_func_void_int **)0x0;
    }
  }
  return (_func_void_int **)&DAT_00424314;
}



// Library Function - Single Match
//  struct __crt_signal_action_t * __cdecl siglookup(int,struct __crt_signal_action_t * const)
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

__crt_signal_action_t * __cdecl siglookup(int param_1,__crt_signal_action_t *param_2)

{
  __crt_signal_action_t *p_Var1;
  
  p_Var1 = param_2 + 0x90;
  if (param_2 != p_Var1) {
    do {
      if (*(int *)(param_2 + 4) == param_1) {
        return param_2;
      }
      param_2 = param_2 + 0xc;
    } while (param_2 != p_Var1);
  }
  return (__crt_signal_action_t *)0x0;
}



// Library Function - Single Match
//  ___acrt_get_sigabrt_handler
// 
// Library: Visual Studio 2019 Release

void ___acrt_get_sigabrt_handler(void)

{
  int local_10;
  undefined4 local_c;
  
  local_c = 3;
  local_10 = 3;
  FUN_00412fad(&local_10);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_004130a6(undefined4 param_1)

{
  _DAT_0042430c = param_1;
  _DAT_00424310 = param_1;
  DAT_00424314 = param_1;
  _DAT_00424318 = param_1;
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4

undefined4 __cdecl FUN_004130c4(int param_1)

{
  code *pcVar1;
  bool bVar2;
  __crt_signal_action_t *p_Var3;
  undefined4 *puVar4;
  _func_void_int **pp_Var5;
  _func_void_int *p_Var6;
  __acrt_ptd *p_Var7;
  __crt_signal_action_t *p_Var8;
  undefined4 uVar9;
  __crt_signal_action_t **pp_Var10;
  int iVar11;
  undefined4 local_38;
  __crt_signal_action_t *local_34;
  void *local_14;
  
  pp_Var10 = (__crt_signal_action_t **)0x0;
  local_38 = 0;
  bVar2 = true;
  if (param_1 < 0xc) {
    if (param_1 != 0xb) {
      if (param_1 == 2) goto LAB_0041314d;
      if (param_1 != 4) {
        if (param_1 == 6) goto LAB_0041314d;
        if (param_1 != 8) goto LAB_00413120;
      }
    }
    pp_Var10 = (__crt_signal_action_t **)FUN_004105fa();
    if (pp_Var10 == (__crt_signal_action_t **)0x0) {
      ExceptionList = local_14;
      return 0xffffffff;
    }
    p_Var3 = siglookup(param_1,*pp_Var10);
    if (p_Var3 == (__crt_signal_action_t *)0x0) {
LAB_00413120:
      puVar4 = (undefined4 *)FUN_0040e304();
      *puVar4 = 0x16;
      FUN_0040e223();
      ExceptionList = local_14;
      return 0xffffffff;
    }
    pp_Var5 = (_func_void_int **)(p_Var3 + 8);
    bVar2 = false;
  }
  else {
    if (((param_1 != 0xf) && (param_1 != 0x15)) && (param_1 != 0x16)) goto LAB_00413120;
LAB_0041314d:
    pp_Var5 = get_global_action_nolock(param_1);
  }
  local_34 = (__crt_signal_action_t *)0x0;
  if (bVar2) {
    ___acrt_lock(3);
  }
  p_Var6 = *pp_Var5;
  if (bVar2) {
    p_Var6 = (_func_void_int *)FUN_004045bd((uint)p_Var6);
  }
  if (p_Var6 == (_func_void_int *)0x1) goto LAB_0041320e;
  if (p_Var6 == (_func_void_int *)0x0) {
    if (bVar2) {
      ___acrt_unlock(3);
    }
    __exit(3);
    pcVar1 = (code *)swi(3);
    uVar9 = (*pcVar1)();
    return uVar9;
  }
  if (((param_1 == 8) || (param_1 == 0xb)) || (param_1 == 4)) {
    local_34 = pp_Var10[1];
    pp_Var10[1] = (__crt_signal_action_t *)0x0;
    if (param_1 == 8) {
      p_Var7 = FUN_004104a9();
      local_38 = *(undefined4 *)(p_Var7 + 8);
      p_Var7 = FUN_004104a9();
      *(undefined4 *)(p_Var7 + 8) = 0x8c;
      goto LAB_004131dd;
    }
  }
  else {
LAB_004131dd:
    if (param_1 == 8) {
      p_Var3 = *pp_Var10;
      for (p_Var8 = p_Var3 + 0x24; p_Var8 != p_Var3 + 0x90; p_Var8 = p_Var8 + 0xc) {
        *(undefined4 *)(p_Var8 + 8) = 0;
      }
      goto LAB_0041320e;
    }
  }
  *pp_Var5 = DAT_00423014;
LAB_0041320e:
  FUN_0041324e();
  if (p_Var6 != (_func_void_int *)0x1) {
    if (param_1 == 8) {
      FUN_004104a9();
      iVar11 = param_1;
      _guard_check_icall();
      (*p_Var6)(iVar11);
    }
    else {
      iVar11 = param_1;
      _guard_check_icall();
      (*p_Var6)(iVar11);
      if ((param_1 != 0xb) && (param_1 != 4)) {
        ExceptionList = local_14;
        return 0;
      }
    }
    pp_Var10[1] = local_34;
    if (param_1 == 8) {
      p_Var7 = FUN_004104a9();
      *(undefined4 *)(p_Var7 + 8) = local_38;
    }
  }
  ExceptionList = local_14;
  return 0;
}



void FUN_0041324e(void)

{
  char unaff_BL;
  
  if (unaff_BL != '\0') {
    ___acrt_unlock(3);
  }
  return;
}



// Library Function - Single Match
//  ___hw_cw_sse2
// 
// Library: Visual Studio 2019 Release

uint __cdecl ___hw_cw_sse2(uint param_1)

{
  uint uVar1;
  uint uVar2;
  
  uVar1 = (param_1 & 0x10) << 3;
  if ((param_1 & 8) != 0) {
    uVar1 = uVar1 | 0x200;
  }
  if ((param_1 & 4) != 0) {
    uVar1 = uVar1 | 0x400;
  }
  if ((param_1 & 2) != 0) {
    uVar1 = uVar1 | 0x800;
  }
  if ((param_1 & 1) != 0) {
    uVar1 = uVar1 | 0x1000;
  }
  if ((param_1 & 0x80000) != 0) {
    uVar1 = uVar1 | 0x100;
  }
  uVar2 = param_1 & 0x300;
  if (uVar2 != 0) {
    if (uVar2 == 0x100) {
      uVar1 = uVar1 | 0x2000;
    }
    else if (uVar2 == 0x200) {
      uVar1 = uVar1 | 0x4000;
    }
    else if (uVar2 == 0x300) {
      uVar1 = uVar1 | 0x6000;
    }
  }
  uVar2 = param_1 & 0x3000000;
  if (uVar2 == 0x1000000) {
    uVar1 = uVar1 | 0x8040;
  }
  else {
    if (uVar2 == 0x2000000) {
      return uVar1 | 0x40;
    }
    if (uVar2 == 0x3000000) {
      return uVar1 | 0x8000;
    }
  }
  return uVar1;
}



// Library Function - Single Match
//  __clearfp
// 
// Library: Visual Studio 2019 Release

uint __cdecl __clearfp(void)

{
  uint uVar1;
  uint uVar2;
  ushort in_FPUStatusWord;
  
  if (DAT_0042393c < 1) {
    uVar1 = 0;
    if ((in_FPUStatusWord & 0x3f) != 0) {
      uVar1 = (in_FPUStatusWord & 1) << 4;
      if ((in_FPUStatusWord & 4) != 0) {
        uVar1 = uVar1 | 8;
      }
      if ((in_FPUStatusWord & 8) != 0) {
        uVar1 = uVar1 | 4;
      }
      if ((in_FPUStatusWord & 0x10) != 0) {
        uVar1 = uVar1 | 2;
      }
      if ((in_FPUStatusWord & 0x20) != 0) {
        uVar1 = uVar1 | 1;
      }
      if ((in_FPUStatusWord & 2) != 0) {
        uVar1 = uVar1 | 0x80000;
      }
    }
  }
  else {
    uVar1 = 0;
    uVar2 = 0;
    if ((in_FPUStatusWord & 0x3f) != 0) {
      uVar2 = (in_FPUStatusWord & 1) << 4;
      if ((in_FPUStatusWord & 4) != 0) {
        uVar2 = uVar2 | 8;
      }
      if ((in_FPUStatusWord & 8) != 0) {
        uVar2 = uVar2 | 4;
      }
      if ((in_FPUStatusWord & 0x10) != 0) {
        uVar2 = uVar2 | 2;
      }
      if ((in_FPUStatusWord & 0x20) != 0) {
        uVar2 = uVar2 | 1;
      }
      if ((in_FPUStatusWord & 2) != 0) {
        uVar2 = uVar2 | 0x80000;
      }
    }
    if ((MXCSR & 0x3f) != 0) {
      uVar1 = (MXCSR & 1) << 4;
      if ((MXCSR & 4) != 0) {
        uVar1 = uVar1 | 8;
      }
      if ((MXCSR & 8) != 0) {
        uVar1 = uVar1 | 4;
      }
      if ((MXCSR & 0x10) != 0) {
        uVar1 = uVar1 | 2;
      }
      if ((MXCSR & 0x20) != 0) {
        uVar1 = uVar1 | 1;
      }
      if ((MXCSR & 2) != 0) {
        uVar1 = uVar1 | 0x80000;
      }
    }
    uVar1 = uVar1 | uVar2;
    MXCSR = MXCSR & 0xffffffc0;
  }
  return uVar1;
}



// Library Function - Single Match
//  __control87
// 
// Library: Visual Studio 2019 Release

uint __cdecl __control87(uint _NewValue,uint _Mask)

{
  uint uVar1;
  uint uVar2;
  ushort uVar3;
  uint uVar4;
  ushort in_FPUControlWord;
  
  uVar1 = (in_FPUControlWord & 1) << 4;
  if ((in_FPUControlWord & 4) != 0) {
    uVar1 = uVar1 | 8;
  }
  if ((in_FPUControlWord & 8) != 0) {
    uVar1 = uVar1 | 4;
  }
  if ((in_FPUControlWord & 0x10) != 0) {
    uVar1 = uVar1 | 2;
  }
  if ((in_FPUControlWord & 0x20) != 0) {
    uVar1 = uVar1 | 1;
  }
  if ((in_FPUControlWord & 2) != 0) {
    uVar1 = uVar1 | 0x80000;
  }
  uVar3 = in_FPUControlWord & 0xc00;
  if ((in_FPUControlWord & 0xc00) != 0) {
    if (uVar3 == 0x400) {
      uVar1 = uVar1 | 0x100;
    }
    else if (uVar3 == 0x800) {
      uVar1 = uVar1 | 0x200;
    }
    else if (uVar3 == 0xc00) {
      uVar1 = uVar1 | 0x300;
    }
  }
  if ((in_FPUControlWord & 0x300) == 0) {
    uVar1 = uVar1 | 0x20000;
  }
  else if ((in_FPUControlWord & 0x300) == 0x200) {
    uVar1 = uVar1 | 0x10000;
  }
  if ((in_FPUControlWord & 0x1000) != 0) {
    uVar1 = uVar1 | 0x40000;
  }
  uVar4 = ~_Mask & uVar1 | _NewValue & _Mask;
  if (uVar4 != uVar1) {
    uVar1 = __hw_cw(uVar4);
    uVar4 = (uVar1 & 1) << 4;
    if ((uVar1 & 4) != 0) {
      uVar4 = uVar4 | 8;
    }
    if ((uVar1 & 8) != 0) {
      uVar4 = uVar4 | 4;
    }
    if ((uVar1 & 0x10) != 0) {
      uVar4 = uVar4 | 2;
    }
    if ((uVar1 & 0x20) != 0) {
      uVar4 = uVar4 | 1;
    }
    if ((uVar1 & 2) != 0) {
      uVar4 = uVar4 | 0x80000;
    }
    uVar2 = uVar1 & 0xc00;
    if ((uVar1 & 0xc00) != 0) {
      if (uVar2 == 0x400) {
        uVar4 = uVar4 | 0x100;
      }
      else if (uVar2 == 0x800) {
        uVar4 = uVar4 | 0x200;
      }
      else if (uVar2 == 0xc00) {
        uVar4 = uVar4 | 0x300;
      }
    }
    if ((uVar1 & 0x300) == 0) {
      uVar4 = uVar4 | 0x20000;
    }
    else if ((uVar1 & 0x300) == 0x200) {
      uVar4 = uVar4 | 0x10000;
    }
    if ((uVar1 & 0x1000) != 0) {
      uVar4 = uVar4 | 0x40000;
    }
  }
  if (0 < DAT_0042393c) {
    uVar1 = MXCSR >> 3 & 0x10;
    if ((MXCSR & 0x200) != 0) {
      uVar1 = uVar1 | 8;
    }
    if ((MXCSR & 0x400) != 0) {
      uVar1 = uVar1 | 4;
    }
    if ((MXCSR & 0x800) != 0) {
      uVar1 = uVar1 | 2;
    }
    if ((MXCSR & 0x1000) != 0) {
      uVar1 = uVar1 | 1;
    }
    if ((MXCSR & 0x100) != 0) {
      uVar1 = uVar1 | 0x80000;
    }
    uVar2 = MXCSR & 0x6000;
    if (uVar2 != 0) {
      if (uVar2 == 0x2000) {
        uVar1 = uVar1 | 0x100;
      }
      else if (uVar2 == 0x4000) {
        uVar1 = uVar1 | 0x200;
      }
      else if (uVar2 == 0x6000) {
        uVar1 = uVar1 | 0x300;
      }
    }
    uVar2 = MXCSR & 0x8040;
    if (uVar2 == 0x40) {
      uVar1 = uVar1 | 0x2000000;
    }
    else if (uVar2 == 0x8000) {
      uVar1 = uVar1 | 0x3000000;
    }
    else if (uVar2 == 0x8040) {
      uVar1 = uVar1 | 0x1000000;
    }
    uVar2 = ~(_Mask & 0x308031f) & uVar1 | _Mask & 0x308031f & _NewValue;
    if (uVar2 != uVar1) {
      uVar1 = ___hw_cw_sse2(uVar2);
      ___set_fpsr_sse2(uVar1);
      uVar1 = MXCSR >> 3 & 0x10;
      if ((MXCSR & 0x200) != 0) {
        uVar1 = uVar1 | 8;
      }
      if ((MXCSR & 0x400) != 0) {
        uVar1 = uVar1 | 4;
      }
      if ((MXCSR & 0x800) != 0) {
        uVar1 = uVar1 | 2;
      }
      if ((MXCSR & 0x1000) != 0) {
        uVar1 = uVar1 | 1;
      }
      if ((MXCSR & 0x100) != 0) {
        uVar1 = uVar1 | 0x80000;
      }
      uVar2 = MXCSR & 0x6000;
      if (uVar2 != 0) {
        if (uVar2 == 0x2000) {
          uVar1 = uVar1 | 0x100;
        }
        else if (uVar2 == 0x4000) {
          uVar1 = uVar1 | 0x200;
        }
        else if (uVar2 == 0x6000) {
          uVar1 = uVar1 | 0x300;
        }
      }
      uVar2 = MXCSR & 0x8040;
      if (uVar2 == 0x40) {
        uVar1 = uVar1 | 0x2000000;
      }
      else if (uVar2 == 0x8000) {
        uVar1 = uVar1 | 0x3000000;
      }
      else if (uVar2 == 0x8040) {
        uVar1 = uVar1 | 0x1000000;
      }
    }
    uVar2 = uVar1 ^ uVar4;
    uVar4 = uVar1 | uVar4;
    if ((uVar2 & 0x8031f) != 0) {
      uVar4 = uVar4 | 0x80000000;
    }
  }
  return uVar4;
}



// Library Function - Single Match
//  __hw_cw
// 
// Library: Visual Studio 2019 Release

uint __cdecl __hw_cw(uint param_1)

{
  uint uVar1;
  uint uVar2;
  
  uVar1 = param_1 >> 4 & 1;
  if ((param_1 & 8) != 0) {
    uVar1 = uVar1 | 4;
  }
  if ((param_1 & 4) != 0) {
    uVar1 = uVar1 | 8;
  }
  if ((param_1 & 2) != 0) {
    uVar1 = uVar1 | 0x10;
  }
  if ((param_1 & 1) != 0) {
    uVar1 = uVar1 | 0x20;
  }
  if ((param_1 & 0x80000) != 0) {
    uVar1 = uVar1 | 2;
  }
  uVar2 = param_1 & 0x300;
  if (uVar2 != 0) {
    if (uVar2 == 0x100) {
      uVar1 = uVar1 | 0x400;
    }
    else if (uVar2 == 0x200) {
      uVar1 = uVar1 | 0x800;
    }
    else if (uVar2 == 0x300) {
      uVar1 = uVar1 | 0xc00;
    }
  }
  if ((param_1 & 0x30000) == 0) {
    uVar1 = uVar1 | 0x300;
  }
  else if ((param_1 & 0x30000) == 0x10000) {
    uVar1 = uVar1 | 0x200;
  }
  if ((param_1 & 0x40000) != 0) {
    uVar1 = uVar1 | 0x1000;
  }
  return uVar1;
}



// Library Function - Multiple Matches With Different Base Names
//  int __cdecl GetTableIndexFromLocaleName(wchar_t const *)
//  int __cdecl ATL::_AtlGetTableIndexFromLocaleName(wchar_t const *)
//  _GetTableIndexFromLocaleName
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

undefined4 __cdecl FID_conflict_GetTableIndexFromLocaleName(ushort *param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = 0;
  iVar2 = 0xe3;
  do {
    iVar3 = (iVar2 + iVar4) / 2;
    iVar1 = FUN_00417bd1(param_1,*(ushort **)(&UNK_0041eec8 + iVar3 * 8),0x55);
    if (iVar1 == 0) {
      return *(undefined4 *)(&UNK_0041eecc + iVar3 * 8);
    }
    if (iVar1 < 0) {
      iVar2 = iVar3 + -1;
    }
    else {
      iVar4 = iVar3 + 1;
    }
  } while (iVar4 <= iVar2);
  return 0xffffffff;
}



// Library Function - Single Match
//  ___acrt_DownlevelLocaleNameToLCID
// 
// Library: Visual Studio 2019 Release

undefined4 __cdecl ___acrt_DownlevelLocaleNameToLCID(ushort *param_1)

{
  uint uVar1;
  
  if (param_1 != (ushort *)0x0) {
    uVar1 = FID_conflict_GetTableIndexFromLocaleName(param_1);
    if ((-1 < (int)uVar1) && (uVar1 < 0xe4)) {
      return *(undefined4 *)(&DAT_0041dda8 + uVar1 * 8);
    }
  }
  return 0;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4

undefined4 __cdecl FUN_00413856(FILE *param_1,__acrt_ptd **param_2)

{
  undefined4 uVar1;
  void *local_14;
  
  if (param_1 == (FILE *)0x0) {
    *(undefined *)(param_2 + 7) = 1;
    param_2[6] = (__acrt_ptd *)0x16;
    FUN_0040e1a6((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0,param_2);
  }
  else {
    if (((uint)param_1->_flag >> 0xc & 1) == 0) {
      __lock_file(param_1);
      uVar1 = FUN_004138ed(param_1,param_2);
      FUN_004138e5();
      ExceptionList = local_14;
      return uVar1;
    }
    __acrt_stdio_free_stream(SUB41(param_1,0));
  }
  ExceptionList = local_14;
  return 0xffffffff;
}



void FUN_004138e5(void)

{
  FILE *unaff_ESI;
  
  __unlock_file(unaff_ESI);
  return;
}



undefined4 __cdecl FUN_004138ed(FILE *param_1,__acrt_ptd **param_2)

{
  undefined4 uVar1;
  uint uVar2;
  int iVar3;
  
  if (param_1 == (FILE *)0x0) {
    *(undefined *)(param_2 + 7) = 1;
    param_2[6] = (__acrt_ptd *)0x16;
    FUN_0040e1a6((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0,param_2);
    uVar1 = 0xffffffff;
  }
  else {
    uVar1 = 0xffffffff;
    if (((uint)param_1->_flag >> 0xd & 1) != 0) {
      uVar1 = FUN_0040eac8(param_1,param_2);
      ___acrt_stdio_free_buffer_nolock(&param_1->_ptr);
      uVar2 = __fileno(param_1);
      iVar3 = FUN_00417e71(uVar2,param_2);
      if (iVar3 < 0) {
        uVar1 = 0xffffffff;
      }
      else if (param_1->_tmpfname != (char *)0x0) {
        FUN_0040e374(param_1->_tmpfname);
        param_1->_tmpfname = (char *)0x0;
      }
    }
    __acrt_stdio_free_stream(SUB41(param_1,0));
  }
  return uVar1;
}



undefined4 __cdecl FUN_0041397b(FILE *param_1)

{
  undefined4 uVar1;
  __acrt_ptd *local_2c [10];
  
  FUN_004055d0(local_2c,(undefined4 *)0x0);
  uVar1 = FUN_00413856(param_1,local_2c);
  FUN_00405630(local_2c);
  return uVar1;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4

undefined4 FUN_004139ab(uint *param_1,uint **param_2)

{
  uint uVar1;
  HANDLE hFile;
  BOOL BVar2;
  DWORD DVar3;
  DWORD *pDVar4;
  undefined4 *puVar5;
  undefined4 uVar6;
  void *local_14;
  
  uVar6 = 0;
  FUN_00412578(*param_1);
  uVar1 = **param_2;
  if ((*(byte *)((&DAT_004240c8)[(int)uVar1 >> 6] + 0x28 + (uVar1 & 0x3f) * 0x38) & 1) != 0) {
    hFile = (HANDLE)FUN_0041264f(uVar1);
    BVar2 = FlushFileBuffers(hFile);
    if (BVar2 != 0) goto LAB_00413a1b;
    DVar3 = GetLastError();
    pDVar4 = (DWORD *)FUN_0040e2f1();
    *pDVar4 = DVar3;
  }
  puVar5 = (undefined4 *)FUN_0040e304();
  *puVar5 = 9;
  uVar6 = 0xffffffff;
LAB_00413a1b:
  FUN_00413a41();
  ExceptionList = local_14;
  return uVar6;
}



void FUN_00413a41(void)

{
  int unaff_EBP;
  
  ___acrt_lowio_unlock_fh(**(uint **)(unaff_EBP + 0x10));
  return;
}



// Library Function - Single Match
//  __commit
// 
// Library: Visual Studio 2019 Release

int __cdecl __commit(int _FileHandle)

{
  undefined4 *puVar1;
  int iVar2;
  uint local_14;
  uint *local_10;
  int local_c;
  
  if (_FileHandle == -2) {
    puVar1 = (undefined4 *)FUN_0040e304();
    *puVar1 = 9;
  }
  else {
    if (((-1 < _FileHandle) && ((uint)_FileHandle < DAT_004242c8)) &&
       ((*(byte *)((&DAT_004240c8)[_FileHandle >> 6] + 0x28 + (_FileHandle & 0x3fU) * 0x38) & 1) !=
        0)) {
      local_10 = (uint *)&_FileHandle;
      local_c = _FileHandle;
      local_14 = _FileHandle;
      iVar2 = FUN_004139ab(&local_14,&local_10);
      return iVar2;
    }
    puVar1 = (undefined4 *)FUN_0040e304();
    *puVar1 = 9;
    FUN_0040e223();
  }
  return -1;
}



void __cdecl
FUN_00413aca(DWORD *param_1,uint param_2,byte *param_3,int param_4,__acrt_ptd **param_5)

{
  byte bVar1;
  ushort uVar2;
  byte *pbVar3;
  BOOL BVar4;
  DWORD DVar5;
  int iVar6;
  int iVar7;
  uint uVar8;
  undefined4 local_84;
  undefined4 local_80;
  undefined4 local_7c;
  undefined4 local_78;
  int local_74;
  UINT local_70;
  byte *local_6c;
  HANDLE local_68;
  byte *local_64;
  byte *local_60;
  undefined2 local_5c [2];
  byte *local_58;
  int local_54;
  size_t local_50;
  byte *local_4c;
  int local_48;
  undefined4 local_44;
  __acrt_ptd **local_40;
  byte *local_3c;
  uint local_38;
  byte local_31;
  byte *local_30;
  CHAR local_2c [8];
  byte local_24;
  byte local_23;
  byte local_1c [8];
  uint local_14;
  void *local_10;
  undefined *puStack_c;
  undefined4 uStack_8;
  
  uStack_8 = 0xffffffff;
  puStack_c = &LAB_0041adb4;
  local_10 = ExceptionList;
  local_14 = DAT_00423014 ^ (uint)&stack0xfffffffc;
  ExceptionList = &local_10;
  local_54 = (param_2 & 0x3f) * 0x38;
  local_48 = (int)param_2 >> 6;
  local_64 = param_3;
  local_40 = param_5;
  local_68 = *(HANDLE *)(local_54 + 0x18 + (&DAT_004240c8)[local_48]);
  local_58 = param_3 + param_4;
  local_70 = GetConsoleOutputCP();
  if (*(char *)(param_5 + 5) == '\0') {
    FUN_004064e0(param_5);
  }
  local_74 = *(int *)(param_5[3] + 8);
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  local_30 = local_64;
  if (local_58 <= local_64) {
LAB_00413e70:
    ExceptionList = local_10;
    FUN_00402125(local_14 ^ (uint)&stack0xfffffffc);
    return;
  }
  local_4c = (byte *)0x0;
  iVar7 = local_54;
LAB_00413b6f:
  uVar8 = 0;
  local_31 = *local_30;
  local_44 = 0;
  local_38 = 1;
  if (local_74 == 0xfde9) {
    local_4c = (byte *)((&DAT_004240c8)[local_48] + 0x2e + iVar7);
    pbVar3 = local_4c;
    local_38 = uVar8;
    do {
      if (*pbVar3 == 0) break;
      local_38 = local_38 + 1;
      pbVar3 = pbVar3 + 1;
    } while ((int)local_38 < 5);
    iVar7 = (int)local_58 - (int)local_30;
    if ((int)local_38 < 1) {
      local_50 = (int)(char)(&DAT_00423780)[*local_30] + 1;
      if (iVar7 < (int)local_50) {
        if (0 < iVar7) {
          do {
            *(byte *)((&DAT_004240c8)[local_48] + local_54 + 0x2e + uVar8) = local_30[uVar8];
            uVar8 = uVar8 + 1;
          } while ((int)uVar8 < iVar7);
        }
        goto LAB_00413e21;
      }
      local_84 = 0;
      local_80 = 0;
      local_38 = (local_50 == 4) + 1;
      local_3c = local_30;
      iVar6 = FUN_00415e4b(&local_84,(ushort *)&local_44,&local_3c,local_38,&local_84,(int)local_40)
      ;
      iVar7 = local_54;
    }
    else {
      local_3c = (byte *)((int)(char)(&DAT_00423780)[*local_4c] + 1);
      local_50 = (int)local_3c - local_38;
      pbVar3 = local_4c;
      if (iVar7 < (int)local_50) {
        if (0 < iVar7) {
          do {
            pbVar3 = local_30 + uVar8;
            iVar6 = (&DAT_004240c8)[local_48] + local_54 + uVar8;
            uVar8 = uVar8 + 1;
            *(byte *)(iVar6 + 0x2e + local_38) = *pbVar3;
          } while ((int)uVar8 < iVar7);
        }
LAB_00413e21:
        param_1[1] = param_1[1] + iVar7;
        goto LAB_00413e70;
      }
      do {
        local_1c[uVar8] = *pbVar3;
        uVar8 = uVar8 + 1;
        pbVar3 = pbVar3 + 1;
      } while ((int)uVar8 < (int)local_38);
      if (0 < (int)local_50) {
        FID_conflict__memcpy(local_1c + local_38,local_30,local_50);
      }
      iVar7 = local_54;
      iVar6 = 0;
      do {
        *(undefined *)((&DAT_004240c8)[local_48] + local_54 + 0x2e + iVar6) = 0;
        iVar6 = iVar6 + 1;
      } while (iVar6 < (int)local_38);
      local_6c = local_1c;
      local_7c = 0;
      local_78 = 0;
      local_38 = (local_3c == (byte *)0x4) + 1;
      iVar6 = FUN_00415e4b(&local_7c,(ushort *)&local_44,&local_6c,local_38,&local_7c,(int)local_40)
      ;
    }
    if (iVar6 == -1) goto LAB_00413e70;
    pbVar3 = local_30 + (local_50 - 1);
  }
  else {
    local_50 = (&DAT_004240c8)[local_48];
    bVar1 = *(byte *)(local_50 + 0x2d + iVar7);
    if ((bVar1 & 4) == 0) {
      if (*(short *)(*(int *)local_40[3] + (uint)*local_30 * 2) < 0) {
        local_3c = local_30 + 1;
        if (local_3c < local_58) {
          uVar8 = FUN_0040fe70((LPWSTR)&local_44,local_30,2,local_40);
          pbVar3 = local_3c;
          if (uVar8 != 0xffffffff) goto LAB_00413d48;
        }
        else {
          *(byte *)(local_50 + 0x2e + iVar7) = *local_30;
          pbVar3 = (byte *)((&DAT_004240c8)[local_48] + 0x2d + iVar7);
          *pbVar3 = *pbVar3 | 4;
          param_1[1] = (DWORD)(local_4c + 1);
        }
        goto LAB_00413e70;
      }
      uVar8 = 1;
      pbVar3 = local_30;
    }
    else {
      uVar2 = CONCAT11(bVar1,*(undefined *)(local_50 + 0x2e + iVar7)) & 0xfbff;
      local_24 = (byte)uVar2;
      local_23 = *local_30;
      *(char *)(local_50 + 0x2d + iVar7) = (char)(uVar2 >> 8);
      uVar8 = 2;
      pbVar3 = &local_24;
    }
    uVar8 = FUN_0040fe70((LPWSTR)&local_44,pbVar3,uVar8,local_40);
    pbVar3 = local_30;
    if (uVar8 == 0xffffffff) goto LAB_00413e70;
  }
LAB_00413d48:
  local_30 = pbVar3 + 1;
  local_3c = (byte *)FUN_00411f5d(local_70,0,(LPCWSTR)&local_44,local_38,local_2c,5,0,
                                  (undefined4 *)0x0);
  if (local_3c == (byte *)0x0) goto LAB_00413e70;
  BVar4 = WriteFile(local_68,local_2c,(DWORD)local_3c,(LPDWORD)&local_60,(LPOVERLAPPED)0x0);
  if (BVar4 == 0) {
LAB_00413e68:
    DVar5 = GetLastError();
    *param_1 = DVar5;
    goto LAB_00413e70;
  }
  local_4c = local_30 + (param_1[2] - (int)local_64);
  param_1[1] = (DWORD)local_4c;
  if (local_60 < local_3c) goto LAB_00413e70;
  if (local_31 == 10) {
    local_5c[0] = 0xd;
    BVar4 = WriteFile(local_68,local_5c,1,(LPDWORD)&local_60,(LPOVERLAPPED)0x0);
    if (BVar4 == 0) goto LAB_00413e68;
    if (local_60 == (byte *)0x0) goto LAB_00413e70;
    param_1[2] = param_1[2] + 1;
    param_1[1] = param_1[1] + 1;
    local_4c = (byte *)param_1[1];
  }
  if (local_58 <= local_30) goto LAB_00413e70;
  goto LAB_00413b6f;
}



// Library Function - Single Match
//  struct `anonymous namespace'::write_result __cdecl write_double_translated_unicode_nolock(char
// const * const,unsigned int)
// 
// Library: Visual Studio 2019 Release

write_result __cdecl write_double_translated_unicode_nolock(char *param_1,uint param_2)

{
  wchar_t _WCh;
  wchar_t wVar1;
  wint_t wVar2;
  wchar_t *pwVar3;
  DWORD DVar4;
  int in_stack_0000000c;
  
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  pwVar3 = (wchar_t *)(in_stack_0000000c + param_2);
  if (param_2 < pwVar3) {
    do {
      _WCh = *(wchar_t *)param_2;
      wVar1 = __putwch_nolock(_WCh);
      if (wVar1 != _WCh) {
LAB_00413eea:
        DVar4 = GetLastError();
        *(DWORD *)param_1 = DVar4;
        break;
      }
      *(int *)(param_1 + 4) = *(int *)(param_1 + 4) + 2;
      if (_WCh == L'\n') {
        wVar2 = __putwch_nolock(L'\r');
        if (wVar2 != 0xd) goto LAB_00413eea;
        *(int *)(param_1 + 4) = *(int *)(param_1 + 4) + 1;
        *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
      }
      param_2 = param_2 + 2;
    } while (param_2 < pwVar3);
  }
  return SUB41(param_1,0);
}



bool __cdecl FUN_00413ef9(uint param_1,__acrt_ptd **param_2)

{
  byte bVar1;
  undefined3 extraout_var;
  BOOL BVar2;
  int iVar3;
  int iVar4;
  DWORD local_8;
  
  bVar1 = FUN_004161ab(param_1);
  if (CONCAT31(extraout_var,bVar1) != 0) {
    iVar4 = (int)param_1 >> 6;
    iVar3 = (param_1 & 0x3f) * 0x38;
    if (*(char *)((&DAT_004240c8)[iVar4] + 0x28 + iVar3) < '\0') {
      if (*(char *)(param_2 + 5) == '\0') {
        FUN_004064e0(param_2);
      }
      if ((*(int *)(param_2[3] + 0xa8) != 0) ||
         (*(char *)((&DAT_004240c8)[iVar4] + 0x29 + iVar3) != '\0')) {
        BVar2 = GetConsoleMode(*(HANDLE *)((&DAT_004240c8)[iVar4] + 0x18 + iVar3),&local_8);
        return BVar2 != 0;
      }
    }
  }
  return false;
}



// WARNING: Function: __alloca_probe replaced with injection: alloca_probe
// WARNING: Type propagation algorithm not settling
// Library Function - Single Match
//  struct `anonymous namespace'::write_result __cdecl write_text_ansi_nolock(int,char const *
// const,unsigned int)
// 
// Library: Visual Studio 2019 Release

write_result __cdecl write_text_ansi_nolock(int param_1,char *param_2,uint param_3)

{
  char cVar1;
  char *hFile;
  write_result wVar2;
  BOOL BVar3;
  DWORD DVar4;
  char *pcVar5;
  char *pcVar6;
  int in_stack_00000010;
  char *local_140c;
  char local_1408 [5120];
  uint local_8;
  
  local_8 = DAT_00423014 ^ (uint)&stack0xfffffffc;
  hFile = *(char **)((&DAT_004240c8)[(int)param_2 >> 6] + 0x18 + ((uint)param_2 & 0x3f) * 0x38);
  pcVar5 = (char *)(in_stack_00000010 + param_3);
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  local_140c = hFile;
  if (pcVar5 <= param_3) {
LAB_00414040:
    wVar2 = (write_result)FUN_00402125(local_8 ^ (uint)&stack0xfffffffc);
    return wVar2;
  }
  do {
    pcVar6 = local_1408;
    do {
      if (pcVar5 <= param_3) break;
      cVar1 = *(char *)param_3;
      param_3 = param_3 + 1;
      if (cVar1 == '\n') {
        *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
        *pcVar6 = '\r';
        pcVar6 = pcVar6 + 1;
      }
      *pcVar6 = cVar1;
      pcVar6 = pcVar6 + 1;
    } while (pcVar6 < local_1408 + 0x13ff);
    BVar3 = WriteFile(hFile,local_1408,(DWORD)(pcVar6 + -(int)local_1408),(LPDWORD)&local_140c,
                      (LPOVERLAPPED)0x0);
    if (BVar3 == 0) {
      DVar4 = GetLastError();
      *(DWORD *)param_1 = DVar4;
      goto LAB_00414040;
    }
    *(int *)(param_1 + 4) = *(int *)(param_1 + 4) + (int)local_140c;
    if ((local_140c < pcVar6 + -(int)local_1408) || (pcVar5 <= param_3)) goto LAB_00414040;
  } while( true );
}



// WARNING: Function: __alloca_probe replaced with injection: alloca_probe
// Library Function - Single Match
//  struct `anonymous namespace'::write_result __cdecl write_text_utf16le_nolock(int,char const *
// const,unsigned int)
// 
// Library: Visual Studio 2019 Release

write_result __cdecl write_text_utf16le_nolock(int param_1,char *param_2,uint param_3)

{
  short sVar1;
  write_result wVar2;
  BOOL BVar3;
  DWORD DVar4;
  short *psVar5;
  short *psVar6;
  int in_stack_00000010;
  uint local_1410;
  HANDLE local_140c;
  short local_1408 [2560];
  uint local_8;
  
  local_8 = DAT_00423014 ^ (uint)&stack0xfffffffc;
  local_140c = *(HANDLE *)
                ((&DAT_004240c8)[(int)param_2 >> 6] + 0x18 + ((uint)param_2 & 0x3f) * 0x38);
  psVar5 = (short *)(in_stack_00000010 + param_3);
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  do {
    if (psVar5 <= param_3) break;
    psVar6 = local_1408;
    do {
      if (psVar5 <= param_3) break;
      sVar1 = *(short *)param_3;
      param_3 = param_3 + 2;
      if (sVar1 == 10) {
        *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 2;
        *psVar6 = 0xd;
        psVar6 = psVar6 + 1;
      }
      *psVar6 = sVar1;
      psVar6 = psVar6 + 1;
    } while (psVar6 < local_1408 + 0x9ff);
    BVar3 = WriteFile(local_140c,local_1408,(int)psVar6 - (int)local_1408,&local_1410,
                      (LPOVERLAPPED)0x0);
    if (BVar3 == 0) {
      DVar4 = GetLastError();
      *(DWORD *)param_1 = DVar4;
      break;
    }
    *(int *)(param_1 + 4) = *(int *)(param_1 + 4) + local_1410;
  } while ((uint)((int)psVar6 - (int)local_1408) <= local_1410);
  wVar2 = (write_result)FUN_00402125(local_8 ^ (uint)&stack0xfffffffc);
  return wVar2;
}



// WARNING: Function: __alloca_probe replaced with injection: alloca_probe
// Library Function - Single Match
//  struct `anonymous namespace'::write_result __cdecl write_text_utf8_nolock(int,char const *
// const,unsigned int)
// 
// Library: Visual Studio 2019 Release

write_result __cdecl write_text_utf8_nolock(int param_1,char *param_2,uint param_3)

{
  WCHAR WVar1;
  write_result wVar2;
  WCHAR *pWVar3;
  uint uVar4;
  BOOL BVar5;
  DWORD DVar6;
  uint uVar7;
  WCHAR *pWVar8;
  int in_stack_00000010;
  DWORD local_1418;
  HANDLE local_1414;
  WCHAR *local_1410;
  CHAR local_140c [3416];
  WCHAR local_6b4 [854];
  uint local_8;
  
  local_8 = DAT_00423014 ^ (uint)&stack0xfffffffc;
  local_1414 = *(HANDLE *)
                ((&DAT_004240c8)[(int)param_2 >> 6] + 0x18 + ((uint)param_2 & 0x3f) * 0x38);
  local_1410 = (WCHAR *)(in_stack_00000010 + param_3);
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  pWVar8 = (WCHAR *)param_3;
  if (param_3 < local_1410) {
    do {
      pWVar3 = local_6b4;
      do {
        if (local_1410 <= pWVar8) break;
        WVar1 = *pWVar8;
        pWVar8 = pWVar8 + 1;
        if (WVar1 == L'\n') {
          *pWVar3 = L'\r';
          pWVar3 = pWVar3 + 1;
        }
        *pWVar3 = WVar1;
        pWVar3 = pWVar3 + 1;
      } while (pWVar3 < local_6b4 + 0x354);
      uVar4 = FUN_00411f5d(0xfde9,0,local_6b4,(int)pWVar3 - (int)local_6b4 >> 1,local_140c,0xd55,0,
                           (undefined4 *)0x0);
      if (uVar4 == 0) {
LAB_00414253:
        DVar6 = GetLastError();
        *(DWORD *)param_1 = DVar6;
        break;
      }
      uVar7 = 0;
      if (uVar4 != 0) {
        do {
          BVar5 = WriteFile(local_1414,local_140c + uVar7,uVar4 - uVar7,&local_1418,
                            (LPOVERLAPPED)0x0);
          if (BVar5 == 0) goto LAB_00414253;
          uVar7 = uVar7 + local_1418;
        } while (uVar7 < uVar4);
      }
      *(uint *)(param_1 + 4) = (int)pWVar8 - param_3;
    } while (pWVar8 < local_1410);
  }
  wVar2 = (write_result)FUN_00402125(local_8 ^ (uint)&stack0xfffffffc);
  return wVar2;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4

int __cdecl FUN_0041426c(char *param_1,byte *param_2,uint param_3,__acrt_ptd **param_4)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  void *local_14;
  
  if (param_1 == (char *)0xfffffffe) {
    *(undefined *)(param_4 + 9) = 1;
    param_4[8] = (__acrt_ptd *)0x0;
    *(undefined *)(param_4 + 7) = 1;
    param_4[6] = (__acrt_ptd *)0x9;
  }
  else {
    if (((int)param_1 < 0) || (DAT_004242c8 <= param_1)) {
      bVar1 = false;
    }
    else {
      bVar1 = true;
    }
    if (bVar1) {
      iVar2 = ((uint)param_1 & 0x3f) * 0x38;
      if ((*(byte *)((&DAT_004240c8)[(int)param_1 >> 6] + 0x28 + iVar2) & 1) != 0) {
        FUN_00412578((uint)param_1);
        iVar3 = -1;
        if ((*(byte *)(iVar2 + 0x28 + (&DAT_004240c8)[(int)param_1 >> 6]) & 1) == 0) {
          *(undefined *)(param_4 + 7) = 1;
          param_4[6] = (__acrt_ptd *)0x9;
          *(undefined *)(param_4 + 9) = 1;
          param_4[8] = (__acrt_ptd *)0x0;
        }
        else {
          iVar3 = FUN_0041437d(param_1,param_2,param_3,param_4);
        }
        FUN_00414375();
        ExceptionList = local_14;
        return iVar3;
      }
    }
    *(undefined *)(param_4 + 9) = 1;
    param_4[8] = (__acrt_ptd *)0x0;
    *(undefined *)(param_4 + 7) = 1;
    param_4[6] = (__acrt_ptd *)0x9;
    FUN_0040e1a6((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0,param_4);
  }
  ExceptionList = local_14;
  return -1;
}



void FUN_00414375(void)

{
  uint unaff_EDI;
  
  ___acrt_lowio_unlock_fh(unaff_EDI);
  return;
}



int __cdecl FUN_0041437d(char *param_1,byte *param_2,uint param_3,__acrt_ptd **param_4)

{
  bool bVar1;
  write_result wVar2;
  undefined3 extraout_var;
  DWORD *pDVar3;
  undefined3 extraout_var_00;
  undefined3 extraout_var_01;
  undefined3 extraout_var_02;
  BOOL BVar4;
  DWORD DVar5;
  DWORD local_34;
  DWORD local_30;
  undefined4 uStack_2c;
  DWORD local_28;
  DWORD local_24;
  DWORD local_20;
  int local_1c;
  int local_18;
  char *local_14;
  uint local_10;
  byte *local_c;
  char local_5;
  
  local_14 = param_1;
  local_c = param_2;
  local_10 = param_3;
  if (param_3 == 0) {
    return 0;
  }
  if (param_2 == (byte *)0x0) {
LAB_004143a9:
    *(undefined *)(param_4 + 9) = 1;
    param_4[8] = (__acrt_ptd *)0x0;
    *(undefined *)(param_4 + 7) = 1;
    param_4[6] = (__acrt_ptd *)0x16;
    FUN_0040e1a6((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0,param_4);
    return -1;
  }
  local_18 = (int)param_1 >> 6;
  local_1c = ((uint)param_1 & 0x3f) * 0x38;
  local_5 = *(char *)(local_1c + 0x29 + (&DAT_004240c8)[local_18]);
  if (((local_5 == '\x02') || (local_5 == '\x01')) && ((~param_3 & 1) == 0)) goto LAB_004143a9;
  if ((*(byte *)(local_1c + 0x28 + (&DAT_004240c8)[local_18]) & 0x20) != 0) {
    FUN_00418217((uint)param_1,0,0,(PLARGE_INTEGER)0x2,(int)param_4);
  }
  DVar5 = 0;
  local_28 = 0;
  bVar1 = FUN_00413ef9((uint)local_14,param_4);
  if (bVar1) {
    if (local_5 == '\0') {
      pDVar3 = (DWORD *)FUN_00413aca(&local_34,(uint)local_14,local_c,local_10,param_4);
    }
    else {
      if ((local_5 != '\x01') && (local_5 != '\x02')) goto LAB_00414530;
      wVar2 = write_double_translated_unicode_nolock((char *)&local_34,(uint)local_c);
      pDVar3 = (DWORD *)CONCAT31(extraout_var,wVar2);
    }
  }
  else if (*(char *)((&DAT_004240c8)[local_18] + 0x28 + local_1c) < '\0') {
    if (local_5 == '\0') {
      wVar2 = write_text_ansi_nolock((int)&local_34,local_14,(uint)local_c);
      pDVar3 = (DWORD *)CONCAT31(extraout_var_02,wVar2);
    }
    else if (local_5 == '\x01') {
      wVar2 = write_text_utf8_nolock((int)&local_34,local_14,(uint)local_c);
      pDVar3 = (DWORD *)CONCAT31(extraout_var_01,wVar2);
    }
    else {
      if (local_5 != '\x02') goto LAB_00414530;
      wVar2 = write_text_utf16le_nolock((int)&local_34,local_14,(uint)local_c);
      pDVar3 = (DWORD *)CONCAT31(extraout_var_00,wVar2);
    }
  }
  else {
    local_34 = 0;
    local_30 = 0;
    uStack_2c = 0;
    BVar4 = WriteFile(*(HANDLE *)((&DAT_004240c8)[local_18] + 0x18 + local_1c),local_c,local_10,
                      &local_30,(LPOVERLAPPED)0x0);
    if (BVar4 == 0) {
      local_34 = GetLastError();
    }
    pDVar3 = &local_34;
  }
  DVar5 = *pDVar3;
  local_28 = DVar5;
  local_24 = pDVar3[1];
  local_20 = pDVar3[2];
  if (local_24 != 0) {
    return local_24 - local_20;
  }
LAB_00414530:
  if (DVar5 != 0) {
    if (DVar5 == 5) {
      *(undefined *)(param_4 + 7) = 1;
      param_4[6] = (__acrt_ptd *)0x9;
      *(undefined *)(param_4 + 9) = 1;
      param_4[8] = (__acrt_ptd *)0x5;
      return -1;
    }
    FUN_0040e2cd(DVar5,(int)param_4);
    return -1;
  }
  if (((*(byte *)((&DAT_004240c8)[local_18] + 0x28 + local_1c) & 0x40) != 0) && (*local_c == 0x1a))
  {
    return 0;
  }
  *(undefined *)(param_4 + 7) = 1;
  param_4[6] = (__acrt_ptd *)0x1c;
  *(undefined *)(param_4 + 9) = 1;
  param_4[8] = (__acrt_ptd *)0x0;
  return -1;
}



bool __cdecl FUN_00414599(char *param_1,int param_2)

{
  if (param_2 == 0) {
    return true;
  }
  for (; *param_1 == '0'; param_1 = param_1 + 1) {
  }
  return *param_1 != '\0';
}



bool __cdecl FUN_004145bc(int param_1,char *param_2,int param_3,int param_4,int param_5)

{
  bool bVar1;
  int iVar2;
  int extraout_EDX;
  
  if (param_5 == 0) {
    return '4' < *param_2;
  }
  iVar2 = _fegetround();
  if (iVar2 == 0) {
    if ('5' < *param_2) {
      return true;
    }
    if ('4' < *param_2) {
      bVar1 = FUN_00414599(param_2 + 1,param_4);
      if (bVar1) {
        return true;
      }
      if (extraout_EDX != param_1) {
        return (bool)(*(byte *)(extraout_EDX + -1) & 1);
      }
    }
  }
  else if (iVar2 == 0x200) {
    bVar1 = FUN_00414599(param_2,param_4);
    if ((bVar1) && (param_3 != 0x2d)) {
      return true;
    }
  }
  else if (((iVar2 == 0x100) && (bVar1 = FUN_00414599(param_2,param_4), bVar1)) && (param_3 == 0x2d)
          ) {
    return true;
  }
  return false;
}



__acrt_ptd * __cdecl
FUN_0041464a(char *param_1,uint param_2,int param_3,int *param_4,int param_5,int param_6,
            __acrt_ptd **param_7)

{
  char *pcVar1;
  bool bVar2;
  int iVar3;
  char *pcVar4;
  char cVar5;
  char *pcVar6;
  __acrt_ptd *p_Var7;
  
  if (param_1 == (char *)0x0) {
    *(undefined *)(param_7 + 7) = 1;
    param_7[6] = (__acrt_ptd *)0x16;
    FUN_0040e1a6((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0,param_7);
    return (__acrt_ptd *)0x16;
  }
  if (param_2 != 0) {
    *param_1 = '\0';
    iVar3 = param_3;
    if (param_3 < 1) {
      iVar3 = 0;
    }
    if (param_2 <= iVar3 + 1U) {
      p_Var7 = (__acrt_ptd *)0x22;
      goto LAB_004146a3;
    }
    if (param_4 != (int *)0x0) {
      pcVar1 = (char *)param_4[2];
      pcVar6 = param_1 + 1;
      *param_1 = '0';
      pcVar4 = pcVar1;
      if (0 < param_3) {
        do {
          cVar5 = *pcVar4;
          if (cVar5 == '\0') {
            cVar5 = '0';
          }
          else {
            pcVar4 = pcVar4 + 1;
          }
          *pcVar6 = cVar5;
          pcVar6 = pcVar6 + 1;
          param_3 = param_3 + -1;
        } while (0 < param_3);
      }
      *pcVar6 = '\0';
      if ((-1 < param_3) &&
         (bVar2 = FUN_004145bc((int)pcVar1,pcVar4,*param_4,param_5,param_6), bVar2)) {
        while( true ) {
          pcVar6 = pcVar6 + -1;
          if (*pcVar6 != '9') break;
          *pcVar6 = '0';
        }
        *pcVar6 = *pcVar6 + '\x01';
      }
      if (*param_1 == '1') {
        param_4[1] = param_4[1] + 1;
      }
      else {
        pcVar6 = param_1 + 1;
        do {
          cVar5 = *pcVar6;
          pcVar6 = pcVar6 + 1;
        } while (cVar5 != '\0');
        FID_conflict__memcpy(param_1,param_1 + 1,(size_t)(pcVar6 + (1 - (int)(param_1 + 2))));
      }
      return (__acrt_ptd *)0x0;
    }
  }
  p_Var7 = (__acrt_ptd *)0x16;
LAB_004146a3:
  param_7[6] = p_Var7;
  *(undefined *)(param_7 + 7) = 1;
  FUN_0040e1a6((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0,param_7);
  return p_Var7;
}



// WARNING: Type propagation algorithm not settling

void __cdecl
FUN_00414744(uint *******param_1,uint param_2,int param_3,int param_4,undefined4 *param_5,
            uint *******param_6,int param_7)

{
  byte bVar1;
  uint ***********pppppppppppuVar2;
  char cVar3;
  undefined4 uVar4;
  __acrt_fp_class _Var5;
  int iVar6;
  uint ************ppppppppppppuVar7;
  uint ************ppppppppppppuVar8;
  undefined *puVar9;
  uint *************pppppppppppppuVar10;
  rsize_t rVar11;
  uint ***********pppppppppppuVar12;
  uint uVar13;
  uint *************pppppppppppppuVar14;
  uint ************ppppppppppppuVar15;
  uint ************ppppppppppppuVar16;
  undefined4 unaff_ESI;
  uint *************pppppppppppppuVar17;
  undefined4 unaff_EDI;
  uint uVar18;
  uint *************pppppppppppppuVar19;
  uint ************ppppppppppppuVar20;
  bool bVar21;
  float10 fVar22;
  longlong lVar23;
  ulonglong uVar24;
  char *pcVar25;
  uint ***********apppppppppppuStack_974 [115];
  uint local_7a8;
  byte local_7a4;
  char local_79c;
  uint local_798;
  uint local_794;
  undefined4 *local_790;
  uint local_78c;
  uint local_788;
  uint *************pppppppppppppuStack_784;
  undefined8 local_780;
  uint *************local_774;
  uint *************local_770;
  uint *************pppppppppppppuStack_76c;
  uint ************local_768;
  uint *************local_764;
  undefined uStack_75d;
  uint *************local_75c;
  uint *************local_758;
  uint ************local_754;
  uint *************local_750;
  uint *************pppppppppppppuStack_74c;
  uint *************pppppppppppppuStack_748;
  uint ***********apppppppppppuStack_744 [115];
  uint *************local_578;
  uint ***********local_574 [115];
  uint *************pppppppppppppuStack_3a8;
  uint *************pppppppppppppuStack_3a4;
  uint ************appppppppppppuStack_3a0 [114];
  uint *************local_1d8 [2];
  uint ************local_1d0 [114];
  uint local_8;
  
  local_8 = DAT_00423014 ^ (uint)&stack0xfffffffc;
  local_790 = param_5;
  local_764 = (uint *************)param_6;
  _fegetenv((uint *)&local_7a4);
  local_79c = (local_7a4 & 0x1f) != 0x1f;
  if ((bool)local_79c) {
    FUN_004182d0((uint *)&local_7a4);
  }
  uVar13 = param_2;
  uVar4 = 0x20;
  if (((int)param_2 < 1) && ((int)param_2 < 0)) {
    uVar4 = 0x2d;
  }
  *local_790 = uVar4;
  local_790[2] = local_764;
  __controlfp_s(&local_7a8,0,0);
  if (((uVar13 & 0x7ff00000) == 0) &&
     ((((uint)param_1 | uVar13 & 0xfffff) == 0 || ((local_7a8 & 0x1000000) != 0)))) {
    pcVar25 = "0";
    local_790[1] = 0;
LAB_0041485c:
    iVar6 = FUN_0040daef((char *)local_764,param_7,(int)pcVar25);
  }
  else {
    _Var5 = __acrt_fp_classify((double *)&param_1);
    if (_Var5 == 0) {
LAB_0041489f:
      param_2 = uVar13 & 0x7fffffff;
      local_794 = 0x8001f;
      __controlfp_s(&local_798,0,0);
      __controlfp_s((uint *)((int)&local_780 + 4),0x8001f,local_794);
      local_780 = CONCAT44(param_2,param_1);
      local_78c = param_3 + 1;
      bVar21 = (param_2 >> 0x14 & 0x7ff) != 0;
      if (bVar21) {
        iVar6 = 0x100000;
      }
      else {
        iVar6 = 0;
      }
      local_754 = (uint ************)(uint)!bVar21;
      local_774 = (uint *************)param_1;
      uVar13 = (param_2 & 0xfffff) + iVar6;
      local_750 = (uint *************)((int)local_754 + (param_2 >> 0x14 & 0x7ff));
      fVar22 = (float10)FUN_00418320();
      FUN_00418430(SUB84((double)fVar22,0),(double)CONCAT44(unaff_ESI,unaff_EDI));
      local_788 = thunk_FUN_0041a9b0();
      if ((local_788 == 0x7fffffff) || (local_788 == 0x80000000)) {
        local_788 = 0;
      }
      local_1d8[1] = local_774;
      local_1d0[0] = (uint ************)uVar13;
      local_754 = (uint ************)((uVar13 != 0) + 1);
      local_1d8[0] = (uint *************)local_754;
      if (local_750 < (uint *************)0x433) {
        if (local_750 == (uint *************)0x35) {
LAB_00414e75:
          local_780 = local_780 & 0xffffffff;
          ppppppppppppuVar20 = (uint ************)local_1d8[(uVar13 != 0) + 1];
          iVar6 = 0x1f;
          if (ppppppppppppuVar20 != (uint ************)0x0) {
            for (; (uint)ppppppppppppuVar20 >> iVar6 == 0; iVar6 = iVar6 + -1) {
            }
          }
          if (ppppppppppppuVar20 == (uint ************)0x0) {
            iVar6 = 0;
          }
          else {
            iVar6 = iVar6 + 1;
          }
          pppppppppppppuVar14 = (uint *************)((int)local_754 + (uint)(iVar6 == 0x20));
          if (pppppppppppppuVar14 < (uint *************)0x74) {
            if ((uint ************)((int)pppppppppppppuVar14 + -1) != (uint ************)0xffffffff)
            {
              ppppppppppppuVar20 = (uint ************)((int)pppppppppppppuVar14 + -2);
              ppppppppppppuVar7 = local_754;
              ppppppppppppuVar15 = (uint ************)((int)pppppppppppppuVar14 + -1);
              do {
                if (ppppppppppppuVar15 < ppppppppppppuVar7) {
                  ppppppppppppuVar8 =
                       (uint ************)local_1d8[(int)((int)ppppppppppppuVar15 + 1)];
                }
                else {
                  ppppppppppppuVar8 = (uint ************)0x0;
                }
                if (ppppppppppppuVar20 < ppppppppppppuVar7) {
                  ppppppppppppuVar7 = (uint ************)local_1d8[(int)ppppppppppppuVar15];
                }
                else {
                  ppppppppppppuVar7 = (uint ************)0x0;
                }
                ppppppppppppuVar16 = (uint ************)((int)ppppppppppppuVar15 + -1);
                ppppppppppppuVar20 = (uint ************)((int)ppppppppppppuVar20 + -1);
                local_1d8[(int)((int)ppppppppppppuVar15 + 1)] =
                     (uint *************)
                     ((uint)ppppppppppppuVar7 >> 0x1f | (int)ppppppppppppuVar8 * 2);
                ppppppppppppuVar7 = (uint ************)local_1d8[0];
                ppppppppppppuVar15 = ppppppppppppuVar16;
              } while (ppppppppppppuVar16 != (uint ************)0xffffffff);
            }
          }
          else {
            local_578 = (uint *************)0x0;
            local_1d8[0] = (uint *************)0x0;
            _memcpy_s(local_1d8 + 1,0x1cc,local_574,0);
            pppppppppppppuVar14 = local_1d8[0];
          }
          local_1d8[0] = pppppppppppppuVar14;
          uVar13 = 0x434 - (int)local_750;
          uVar18 = uVar13 >> 5;
          _memset(local_574,0,uVar18 * 4);
          local_574[uVar18] = (uint ***********)(1 << ((byte)uVar13 & 0x1f));
        }
        else {
          local_574[0] = (uint ***********)0x0;
          local_574[1] = (uint ***********)0x100000;
          local_578 = (uint *************)0x2;
          if (uVar13 == 0) goto LAB_00414e75;
          iVar6 = 0;
          do {
            if (*(int *)((int)local_574 + iVar6) != *(int *)((int)local_1d8 + iVar6 + 4))
            goto LAB_00414e75;
            iVar6 = iVar6 + 4;
          } while (iVar6 != 8);
          iVar6 = 0x1f;
          if (uVar13 != 0) {
            for (; uVar13 >> iVar6 == 0; iVar6 = iVar6 + -1) {
            }
          }
          local_780 = local_780 & 0xffffffff;
          if (uVar13 == 0) {
            iVar6 = 0;
          }
          else {
            iVar6 = iVar6 + 1;
          }
          pppppppppppppuVar14 = (uint *************)((int)local_754 + (uint)(0x20U - iVar6 < 2));
          if (pppppppppppppuVar14 < (uint *************)0x74) {
            if ((uint ************)((int)pppppppppppppuVar14 + -1) != (uint ************)0xffffffff)
            {
              ppppppppppppuVar20 = (uint ************)((int)pppppppppppppuVar14 + -2);
              ppppppppppppuVar7 = local_754;
              ppppppppppppuVar15 = (uint ************)((int)pppppppppppppuVar14 + -1);
              do {
                if (ppppppppppppuVar15 < ppppppppppppuVar7) {
                  ppppppppppppuVar8 =
                       (uint ************)local_1d8[(int)((int)ppppppppppppuVar15 + 1)];
                }
                else {
                  ppppppppppppuVar8 = (uint ************)0x0;
                }
                if (ppppppppppppuVar20 < ppppppppppppuVar7) {
                  ppppppppppppuVar7 = (uint ************)local_1d8[(int)ppppppppppppuVar15];
                }
                else {
                  ppppppppppppuVar7 = (uint ************)0x0;
                }
                ppppppppppppuVar16 = (uint ************)((int)ppppppppppppuVar15 + -1);
                ppppppppppppuVar20 = (uint ************)((int)ppppppppppppuVar20 + -1);
                local_1d8[(int)((int)ppppppppppppuVar15 + 1)] =
                     (uint *************)
                     ((uint)ppppppppppppuVar7 >> 0x1e | (int)ppppppppppppuVar8 << 2);
                ppppppppppppuVar7 = (uint ************)local_1d8[0];
                ppppppppppppuVar15 = ppppppppppppuVar16;
              } while (ppppppppppppuVar16 != (uint ************)0xffffffff);
            }
          }
          else {
            local_578 = (uint *************)0x0;
            local_1d8[0] = (uint *************)0x0;
            _memcpy_s(local_1d8 + 1,0x1cc,local_574,0);
            pppppppppppppuVar14 = local_1d8[0];
          }
          local_1d8[0] = pppppppppppppuVar14;
          uVar13 = 0x435 - (int)local_750;
          uVar18 = uVar13 >> 5;
          _memset(local_574,0,uVar18 * 4);
          local_574[uVar18] = (uint ***********)(1 << ((byte)uVar13 & 0x1f));
        }
        local_578 = (uint *************)(uVar18 + 1);
        pppppppppppppuStack_3a8 = local_578;
        _memcpy_s(&pppppppppppppuStack_3a4,0x1cc,local_574,(int)local_578 * 4);
      }
      else {
        local_574[0] = (uint ***********)0x0;
        local_574[1] = (uint ***********)0x100000;
        local_578 = (uint *************)0x2;
        if (uVar13 == 0) {
LAB_00414bbe:
          local_75c = (uint *************)((uint)(undefined *)((int)local_750 + -0x432) & 0x1f);
          local_768 = (uint ************)((uint)(undefined *)((int)local_750 + -0x432) >> 5);
          local_758 = (uint *************)(0x20 - (int)local_75c);
          lVar23 = __allshl((byte)local_758,0);
          ppppppppppppuVar7 = local_754;
          local_770 = (uint *************)((int)lVar23 + -1);
          local_780 = local_780 & 0xffffffff;
          local_774 = (uint *************)~(uint)local_770;
          ppppppppppppuVar20 = (uint ************)local_1d8[(int)local_754];
          iVar6 = 0x1f;
          if (ppppppppppppuVar20 != (uint ************)0x0) {
            for (; (uint)ppppppppppppuVar20 >> iVar6 == 0; iVar6 = iVar6 + -1) {
            }
          }
          if (ppppppppppppuVar20 == (uint ************)0x0) {
            local_754 = (uint ************)0x0;
          }
          else {
            local_754 = (uint ************)(iVar6 + 1);
          }
          if (((undefined *)((int)ppppppppppppuVar7 + (int)local_768) < (undefined *)0x74) &&
             (pppppppppppppuStack_74c =
                   (uint *************)
                   ((undefined *)
                    ((int)ppppppppppppuVar7 +
                    (uint)((uint *************)(0x20 - (int)local_754) < local_75c)) +
                   (int)local_768), pppppppppppppuStack_74c < (uint *************)0x74)) {
            pppppppppppppuStack_784 = (uint *************)((int)local_768 - 1);
            local_750 = (uint *************)((int)pppppppppppppuStack_74c + -1);
            if (local_750 != pppppppppppppuStack_784) {
              ppppppppppppuVar20 = (uint ************)((int)local_750 - (int)local_768);
              pppppppppppppuStack_76c = (uint *************)(local_1d8 + (int)ppppppppppppuVar20);
              do {
                if (ppppppppppppuVar20 < ppppppppppppuVar7) {
                  local_754 = pppppppppppppuStack_76c[1];
                }
                else {
                  local_754 = (uint ************)0x0;
                }
                if ((uint ************)((int)ppppppppppppuVar20 + -1) < ppppppppppppuVar7) {
                  ppppppppppppuVar7 = *pppppppppppppuStack_76c;
                }
                else {
                  ppppppppppppuVar7 = (uint ************)0x0;
                }
                local_1d8[(int)((int)local_750 + 1)] =
                     (uint *************)
                     (((uint)ppppppppppppuVar7 & (uint)local_774) >> ((byte)local_758 & 0x1f) |
                     ((uint)local_754 & (uint)local_770) << ((byte)local_75c & 0x1f));
                local_750 = (uint *************)((int)local_750 + -1);
                pppppppppppppuStack_76c = pppppppppppppuStack_76c + -1;
                ppppppppppppuVar20 = (uint ************)((int)ppppppppppppuVar20 + -1);
                ppppppppppppuVar7 = (uint ************)local_1d8[0];
              } while (local_750 != pppppppppppppuStack_784);
            }
            local_1d8[0] = pppppppppppppuStack_74c;
            if (local_768 != (uint ************)0x0) {
              pppppppppppppuVar14 = (uint *************)local_1d8;
              for (ppppppppppppuVar20 = local_768; pppppppppppppuVar14 = pppppppppppppuVar14 + 1,
                  ppppppppppppuVar20 != (uint ************)0x0;
                  ppppppppppppuVar20 = (uint ************)((int)ppppppppppppuVar20 - 1)) {
                *pppppppppppppuVar14 = (uint ************)0x0;
              }
            }
          }
          else {
            local_578 = (uint *************)0x0;
            local_1d8[0] = (uint *************)0x0;
            _memcpy_s(local_1d8 + 1,0x1cc,local_574,0);
          }
          local_574[0] = (uint ***********)0x2;
        }
        else {
          iVar6 = 0;
          do {
            if (*(int *)((int)local_574 + iVar6) != *(int *)((int)local_1d8 + iVar6 + 4))
            goto LAB_00414bbe;
            iVar6 = iVar6 + 4;
          } while (iVar6 != 8);
          local_75c = (uint *************)((uint)(undefined *)((int)local_750 + -0x431) & 0x1f);
          local_768 = (uint ************)((uint)(undefined *)((int)local_750 + -0x431) >> 5);
          local_758 = (uint *************)(0x20 - (int)local_75c);
          lVar23 = __allshl((byte)local_758,0);
          ppppppppppppuVar7 = local_754;
          local_770 = (uint *************)((int)lVar23 + -1);
          local_780 = local_780 & 0xffffffff;
          local_774 = (uint *************)~(uint)local_770;
          ppppppppppppuVar20 = (uint ************)local_1d8[(int)local_754];
          iVar6 = 0x1f;
          if (ppppppppppppuVar20 != (uint ************)0x0) {
            for (; (uint)ppppppppppppuVar20 >> iVar6 == 0; iVar6 = iVar6 + -1) {
            }
          }
          if (ppppppppppppuVar20 == (uint ************)0x0) {
            local_754 = (uint ************)0x0;
          }
          else {
            local_754 = (uint ************)(iVar6 + 1);
          }
          if (((undefined *)((int)ppppppppppppuVar7 + (int)local_768) < (undefined *)0x74) &&
             (pppppppppppppuStack_74c =
                   (uint *************)
                   ((undefined *)
                    ((int)ppppppppppppuVar7 +
                    (uint)((uint *************)(0x20 - (int)local_754) < local_75c)) +
                   (int)local_768), pppppppppppppuStack_74c < (uint *************)0x74)) {
            pppppppppppppuStack_784 = (uint *************)((int)local_768 - 1);
            local_750 = (uint *************)((int)pppppppppppppuStack_74c + -1);
            if (local_750 != pppppppppppppuStack_784) {
              ppppppppppppuVar20 = (uint ************)((int)local_750 - (int)local_768);
              pppppppppppppuStack_76c = (uint *************)(local_1d8 + (int)ppppppppppppuVar20);
              do {
                if (ppppppppppppuVar20 < ppppppppppppuVar7) {
                  local_754 = pppppppppppppuStack_76c[1];
                }
                else {
                  local_754 = (uint ************)0x0;
                }
                if ((uint ************)((int)ppppppppppppuVar20 + -1) < ppppppppppppuVar7) {
                  ppppppppppppuVar7 = *pppppppppppppuStack_76c;
                }
                else {
                  ppppppppppppuVar7 = (uint ************)0x0;
                }
                local_1d8[(int)((int)local_750 + 1)] =
                     (uint *************)
                     (((uint)ppppppppppppuVar7 & (uint)local_774) >> ((byte)local_758 & 0x1f) |
                     ((uint)local_754 & (uint)local_770) << ((byte)local_75c & 0x1f));
                local_750 = (uint *************)((int)local_750 + -1);
                pppppppppppppuStack_76c = pppppppppppppuStack_76c + -1;
                ppppppppppppuVar20 = (uint ************)((int)ppppppppppppuVar20 + -1);
                ppppppppppppuVar7 = (uint ************)local_1d8[0];
              } while (local_750 != pppppppppppppuStack_784);
            }
            local_1d8[0] = pppppppppppppuStack_74c;
            if (local_768 != (uint ************)0x0) {
              pppppppppppppuVar14 = (uint *************)local_1d8;
              for (ppppppppppppuVar20 = local_768; pppppppppppppuVar14 = pppppppppppppuVar14 + 1,
                  ppppppppppppuVar20 != (uint ************)0x0;
                  ppppppppppppuVar20 = (uint ************)((int)ppppppppppppuVar20 - 1)) {
                *pppppppppppppuVar14 = (uint ************)0x0;
              }
            }
          }
          else {
            local_578 = (uint *************)0x0;
            local_1d8[0] = (uint *************)0x0;
            _memcpy_s(local_1d8 + 1,0x1cc,local_574,0);
          }
          local_574[0] = (uint ***********)0x4;
        }
        local_574[1] = (uint ***********)0x0;
        pppppppppppppuStack_3a8 = (uint *************)0x1;
        local_578 = (uint *************)0x1;
        _memcpy_s(&pppppppppppppuStack_3a4,0x1cc,local_574,4);
      }
      local_754 = (uint ************)0xa;
      if ((int)local_788 < 0) {
        local_780 = CONCAT44(-local_788,(undefined4)local_780);
        uVar24 = local_780;
        for (local_774 = (uint *************)(-local_788 / 10); local_780 = uVar24,
            local_774 != (uint *************)0x0;
            local_774 = (uint *************)((int)local_774 - (int)local_75c)) {
          local_75c = local_774;
          if ((uint *************)0x26 < local_774) {
            local_75c = (uint *************)0x26;
          }
          uVar13 = (uint)(byte)(&DAT_0041c6ce)[(int)local_75c * 4];
          bVar1 = (&DAT_0041c6cf)[(int)local_75c * 4];
          local_578 = (uint *************)(uVar13 + bVar1);
          _memset(local_574,0,uVar13 * 4);
          FID_conflict__memcpy
                    (local_574 + uVar13,
                     &UNK_0041bdc8 + (uint)*(ushort *)(&UNK_0041c6cc + (int)local_75c * 4) * 4,
                     (uint)bVar1 << 2);
          pppppppppppppuVar14 = local_1d8[1];
          local_770 = local_578;
          if (local_578 < (uint *************)0x2) {
            if (local_574[0] == (uint ***********)0x0) {
              local_1d8[0] = (uint *************)0x0;
              _memcpy_s(local_1d8 + 1,0x1cc,apppppppppppuStack_974,0);
            }
            else if ((local_574[0] != (uint ***********)0x1) &&
                    (local_1d8[0] != (uint *************)0x0)) {
              ppppppppppppuVar20 = (uint ************)0x0;
              local_758 = local_1d8[0];
              pppppppppppppuVar14 = (uint *************)0x0;
              do {
                lVar23 = ZEXT48(local_574[0]) *
                         ZEXT48(local_1d8[(int)((int)pppppppppppppuVar14 + 1)]) +
                         ZEXT48(ppppppppppppuVar20);
                local_1d8[(int)((int)pppppppppppppuVar14 + 1)] =
                     (uint *************)(uint ************)lVar23;
                ppppppppppppuVar20 = (uint ************)((ulonglong)lVar23 >> 0x20);
                pppppppppppppuVar14 = (uint *************)((int)pppppppppppppuVar14 + 1);
              } while (pppppppppppppuVar14 != local_1d8[0]);
              if (ppppppppppppuVar20 == (uint ************)0x0) goto LAB_00415581;
              if (local_1d8[0] < (uint *************)0x73) {
                local_1d8[(int)((int)local_1d8[0] + 1)] = (uint *************)ppppppppppppuVar20;
                local_1d8[0] = (uint *************)((int)local_1d8[0] + 1);
                goto LAB_00415581;
              }
              local_1d8[0] = (uint *************)0x0;
              _memcpy_s(local_1d8 + 1,0x1cc,apppppppppppuStack_974,0);
              bVar21 = false;
              goto LAB_004158a4;
            }
LAB_00415581:
            bVar21 = true;
          }
          else {
            if (local_1d8[0] < (uint *************)0x2) {
              local_758 = local_1d8[1];
              local_1d8[0] = local_578;
              _memcpy_s(local_1d8 + 1,0x1cc,local_574,(int)local_578 << 2);
              if (pppppppppppppuVar14 == (uint *************)0x0) {
                local_1d8[0] = (uint *************)0x0;
                rVar11 = 0;
                pppppppppppuVar12 = (uint ***********)apppppppppppuStack_974;
                goto LAB_00415891;
              }
              if ((pppppppppppppuVar14 != (uint *************)0x1) &&
                 (local_1d8[0] != (uint *************)0x0)) {
                ppppppppppppuVar20 = (uint ************)0x0;
                local_770 = local_1d8[0];
                pppppppppppppuVar14 = (uint *************)0x0;
                do {
                  lVar23 = ZEXT48(local_758) *
                           ZEXT48(local_1d8[(int)((int)pppppppppppppuVar14 + 1)]) +
                           ZEXT48(ppppppppppppuVar20);
                  local_1d8[(int)((int)pppppppppppppuVar14 + 1)] =
                       (uint *************)(uint ************)lVar23;
                  ppppppppppppuVar20 = (uint ************)((ulonglong)lVar23 >> 0x20);
                  pppppppppppppuVar14 = (uint *************)((int)pppppppppppppuVar14 + 1);
                } while (pppppppppppppuVar14 != local_1d8[0]);
                if (ppppppppppppuVar20 != (uint ************)0x0) {
                  if ((uint *************)0x72 < local_1d8[0]) {
LAB_0041595c:
                    local_1d8[0] = (uint *************)0x0;
                    _memcpy_s(local_1d8 + 1,0x1cc,apppppppppppuStack_974,0);
                    bVar21 = false;
                    goto LAB_004158a4;
                  }
                  local_1d8[(int)((int)local_1d8[0] + 1)] = (uint *************)ppppppppppppuVar20;
                  local_1d8[0] = (uint *************)((int)local_1d8[0] + 1);
                }
              }
            }
            else {
              local_768 = local_574;
              if (local_578 < local_1d8[0]) {
                local_758 = (uint *************)(local_1d8 + 1);
                pppppppppppppuStack_784 = local_578;
                local_770 = local_1d8[0];
              }
              else {
                local_768 = (uint ************)(local_1d8 + 1);
                local_758 = (uint *************)local_574;
                pppppppppppppuStack_784 = local_1d8[0];
              }
              pppppppppppppuVar14 = (uint *************)0x0;
              local_1d8[0] = (uint *************)0x0;
              pppppppppppppuStack_748 = (uint *************)0x0;
              if (pppppppppppppuStack_784 != (uint *************)0x0) {
                do {
                  if (local_768[(int)pppppppppppppuVar14] == (uint ***********)0x0) {
                    if (pppppppppppppuVar14 == local_1d8[0]) {
                      apppppppppppuStack_744[(int)pppppppppppppuVar14] = (uint ***********)0x0;
                      local_1d8[0] = (uint *************)((int)pppppppppppppuVar14 + 1);
                      pppppppppppppuStack_748 = local_1d8[0];
                    }
                  }
                  else {
                    pppppppppppppuStack_74c = (uint *************)0x0;
                    local_750 = (uint *************)0x0;
                    pppppppppppppuVar19 = pppppppppppppuVar14;
                    if (local_770 != (uint *************)0x0) {
                      do {
                        if (pppppppppppppuVar19 == (uint *************)0x73) break;
                        if (pppppppppppppuVar19 == local_1d8[0]) {
                          apppppppppppuStack_744[(int)pppppppppppppuVar19] = (uint ***********)0x0;
                          pppppppppppppuStack_748 =
                               (uint *************)
                               ((undefined *)((int)local_750 + 1) + (int)pppppppppppppuVar14);
                        }
                        ppppppppppppuVar7 = local_758[(int)local_750];
                        pppppppppppuVar2 = local_768[(int)pppppppppppppuVar14];
                        uVar13 = (uint)(ZEXT48(ppppppppppppuVar7) * ZEXT48(pppppppppppuVar2));
                        puVar9 = (undefined *)(uVar13 + (int)pppppppppppppuStack_74c);
                        ppppppppppppuVar20 = apppppppppppuStack_744 + (int)pppppppppppppuVar19;
                        pppppppppppuVar12 = *ppppppppppppuVar20;
                        *ppppppppppppuVar20 = (uint ***********)(puVar9 + (int)*ppppppppppppuVar20);
                        pppppppppppppuStack_74c =
                             (uint *************)
                             ((int)(ZEXT48(ppppppppppppuVar7) * ZEXT48(pppppppppppuVar2) >> 0x20) +
                              (uint)CARRY4(uVar13,(uint)pppppppppppppuStack_74c) +
                             (uint)CARRY4((uint)pppppppppppuVar12,(uint)puVar9));
                        local_750 = (uint *************)((int)local_750 + 1);
                        pppppppppppppuVar19 = (uint *************)((int)pppppppppppppuVar19 + 1);
                        local_1d8[0] = pppppppppppppuStack_748;
                      } while (local_750 != local_770);
                      if (pppppppppppppuStack_74c != (uint *************)0x0) {
                        pppppppppppppuVar17 = pppppppppppppuVar19;
                        pppppppppppppuStack_76c =
                             (uint *************)(apppppppppppuStack_744 + (int)pppppppppppppuVar19)
                        ;
                        do {
                          if (pppppppppppppuVar17 == (uint *************)0x73) goto LAB_0041595c;
                          pppppppppppppuVar19 = (uint *************)((int)pppppppppppppuVar17 + 1);
                          if (pppppppppppppuVar17 == local_1d8[0]) {
                            *pppppppppppppuStack_76c = (uint ************)0x0;
                            pppppppppppppuStack_748 = pppppppppppppuVar19;
                          }
                          pppppppppppppuVar10 = pppppppppppppuStack_76c + 1;
                          ppppppppppppuVar20 = *pppppppppppppuStack_76c;
                          *pppppppppppppuStack_76c =
                               (uint ************)
                               ((int)*pppppppppppppuStack_76c + (int)pppppppppppppuStack_74c);
                          pppppppppppppuStack_74c =
                               (uint *************)
                               (uint)CARRY4((uint)ppppppppppppuVar20,(uint)pppppppppppppuStack_74c);
                          local_1d8[0] = pppppppppppppuStack_748;
                          pppppppppppppuVar17 = pppppppppppppuVar19;
                          pppppppppppppuStack_76c = pppppppppppppuVar10;
                        } while (pppppppppppppuStack_74c != (uint *************)0x0);
                      }
                    }
                    if (pppppppppppppuVar19 == (uint *************)0x73) goto LAB_0041595c;
                  }
                  pppppppppppppuVar14 = (uint *************)((int)pppppppppppppuVar14 + 1);
                } while (pppppppppppppuVar14 != pppppppppppppuStack_784);
              }
              rVar11 = (int)local_1d8[0] << 2;
              pppppppppppuVar12 = (uint ***********)apppppppppppuStack_744;
LAB_00415891:
              _memcpy_s(local_1d8 + 1,0x1cc,pppppppppppuVar12,rVar11);
            }
            bVar21 = true;
          }
LAB_004158a4:
          if (!bVar21) goto LAB_004159aa;
          uVar24 = local_780;
        }
        local_780._4_4_ = (uint)(uVar24 >> 0x20);
        uVar13 = local_780._4_4_ % 10;
        if (uVar13 != 0) {
          uVar13 = *(uint *)(&DAT_0041c764 + uVar13 * 2);
          local_780._0_4_ = (undefined4)uVar24;
          local_780 = CONCAT44(uVar13,(undefined4)local_780);
          if (uVar13 == 0) {
LAB_004159aa:
            local_1d8[0] = (uint *************)0x0;
            pppppppppppppuVar14 = (uint *************)(local_1d8 + 1);
            goto LAB_004159b7;
          }
          if ((uVar13 != 1) && (local_1d8[0] != (uint *************)0x0)) {
            local_774 = (uint *************)0x0;
            pppppppppppppuVar14 = (uint *************)0x0;
            do {
              lVar23 = (ulonglong)uVar13 * ZEXT48(local_1d8[(int)((int)pppppppppppppuVar14 + 1)]) +
                       ZEXT48(local_774);
              local_1d8[(int)((int)pppppppppppppuVar14 + 1)] =
                   (uint *************)(uint ************)lVar23;
              local_774 = (uint *************)((ulonglong)lVar23 >> 0x20);
              pppppppppppppuVar14 = (uint *************)((int)pppppppppppppuVar14 + 1);
            } while (pppppppppppppuVar14 != local_1d8[0]);
            if (local_774 != (uint *************)0x0) {
              if ((uint *************)0x72 < local_1d8[0]) goto LAB_004159aa;
              local_1d8[(int)local_1d8[0] + 1] = local_774;
              local_1d8[0] = (uint *************)((int)local_1d8[0] + 1);
            }
          }
        }
      }
      else {
        for (local_758 = (uint *************)(local_788 / 10); local_758 != (uint *************)0x0;
            local_758 = (uint *************)((int)local_758 - (int)pppppppppppppuStack_76c)) {
          pppppppppppppuStack_76c = local_758;
          if ((uint *************)0x26 < local_758) {
            pppppppppppppuStack_76c = (uint *************)0x26;
          }
          uVar13 = (uint)(byte)(&DAT_0041c6ce)[(int)pppppppppppppuStack_76c * 4];
          bVar1 = (&DAT_0041c6cf)[(int)pppppppppppppuStack_76c * 4];
          local_578 = (uint *************)(uVar13 + bVar1);
          _memset(local_574,0,uVar13 * 4);
          FID_conflict__memcpy
                    (local_574 + uVar13,
                     &UNK_0041bdc8 +
                     (uint)*(ushort *)(&UNK_0041c6cc + (int)pppppppppppppuStack_76c * 4) * 4,
                     (uint)bVar1 << 2);
          pppppppppppppuVar14 = pppppppppppppuStack_3a4;
          pppppppppppppuStack_784 = local_578;
          if (local_578 < (uint *************)0x2) {
            if (local_574[0] == (uint ***********)0x0) {
              pppppppppppppuStack_748 = (uint *************)0x0;
              pppppppppppppuStack_3a8 = (uint *************)0x0;
              _memcpy_s(&pppppppppppppuStack_3a4,0x1cc,apppppppppppuStack_744,0);
            }
            else if ((local_574[0] != (uint ***********)0x1) &&
                    (pppppppppppppuStack_3a8 != (uint *************)0x0)) {
              ppppppppppppuVar20 = (uint ************)0x0;
              local_774 = pppppppppppppuStack_3a8;
              pppppppppppppuVar14 = (uint *************)0x0;
              do {
                lVar23 = ZEXT48(local_574[0]) *
                         ZEXT48((&pppppppppppppuStack_3a4)[(int)pppppppppppppuVar14]) +
                         ZEXT48(ppppppppppppuVar20);
                (&pppppppppppppuStack_3a4)[(int)pppppppppppppuVar14] =
                     (uint *************)(uint ************)lVar23;
                ppppppppppppuVar20 = (uint ************)((ulonglong)lVar23 >> 0x20);
                pppppppppppppuVar14 = (uint *************)((int)pppppppppppppuVar14 + 1);
              } while (pppppppppppppuVar14 != pppppppppppppuStack_3a8);
              if (ppppppppppppuVar20 == (uint ************)0x0) goto LAB_00415065;
              if (pppppppppppppuStack_3a8 < (uint *************)0x73) {
                (&pppppppppppppuStack_3a4)[(int)pppppppppppppuStack_3a8] =
                     (uint *************)ppppppppppppuVar20;
                pppppppppppppuStack_3a8 = (uint *************)((int)pppppppppppppuStack_3a8 + 1);
                goto LAB_00415065;
              }
              local_578 = (uint *************)0x0;
              pppppppppppppuStack_3a8 = (uint *************)0x0;
              _memcpy_s(&pppppppppppppuStack_3a4,0x1cc,local_574,0);
              bVar21 = false;
              goto LAB_0041539e;
            }
LAB_00415065:
            bVar21 = true;
          }
          else {
            if (pppppppppppppuStack_3a8 < (uint *************)0x2) {
              local_774 = pppppppppppppuStack_3a4;
              pppppppppppppuStack_3a8 = local_578;
              _memcpy_s(&pppppppppppppuStack_3a4,0x1cc,local_574,(int)local_578 << 2);
              if (pppppppppppppuVar14 == (uint *************)0x0) {
                local_578 = (uint *************)0x0;
                pppppppppppppuStack_3a8 = (uint *************)0x0;
                rVar11 = 0;
                ppppppppppppuVar20 = local_574;
                goto LAB_0041538b;
              }
              if ((pppppppppppppuVar14 != (uint *************)0x1) &&
                 (pppppppppppppuStack_3a8 != (uint *************)0x0)) {
                ppppppppppppuVar20 = (uint ************)0x0;
                local_770 = pppppppppppppuStack_3a8;
                pppppppppppppuVar14 = (uint *************)0x0;
                do {
                  lVar23 = ZEXT48(local_774) *
                           ZEXT48((&pppppppppppppuStack_3a4)[(int)pppppppppppppuVar14]) +
                           ZEXT48(ppppppppppppuVar20);
                  (&pppppppppppppuStack_3a4)[(int)pppppppppppppuVar14] =
                       (uint *************)(uint ************)lVar23;
                  ppppppppppppuVar20 = (uint ************)((ulonglong)lVar23 >> 0x20);
                  pppppppppppppuVar14 = (uint *************)((int)pppppppppppppuVar14 + 1);
                } while (pppppppppppppuVar14 != pppppppppppppuStack_3a8);
                if (ppppppppppppuVar20 != (uint ************)0x0) {
                  if ((uint *************)0x72 < pppppppppppppuStack_3a8) {
                    local_578 = (uint *************)0x0;
                    ppppppppppppuVar20 = local_574;
LAB_0041540f:
                    pppppppppppppuStack_3a8 = (uint *************)0x0;
                    _memcpy_s(&pppppppppppppuStack_3a4,0x1cc,ppppppppppppuVar20,0);
                    bVar21 = false;
                    goto LAB_0041539e;
                  }
                  (&pppppppppppppuStack_3a4)[(int)pppppppppppppuStack_3a8] =
                       (uint *************)ppppppppppppuVar20;
                  pppppppppppppuStack_3a8 = (uint *************)((int)pppppppppppppuStack_3a8 + 1);
                }
              }
            }
            else {
              local_768 = local_574;
              if (local_578 < pppppppppppppuStack_3a8) {
                local_75c = (uint *************)&pppppppppppppuStack_3a4;
                local_770 = local_578;
                pppppppppppppuStack_784 = pppppppppppppuStack_3a8;
              }
              else {
                local_768 = (uint ************)&pppppppppppppuStack_3a4;
                local_75c = (uint *************)local_574;
                local_770 = pppppppppppppuStack_3a8;
              }
              pppppppppppppuVar14 = (uint *************)0x0;
              pppppppppppppuStack_3a8 = (uint *************)0x0;
              pppppppppppppuStack_748 = (uint *************)0x0;
              if (local_770 != (uint *************)0x0) {
                do {
                  if (local_768[(int)pppppppppppppuVar14] == (uint ***********)0x0) {
                    if (pppppppppppppuVar14 == pppppppppppppuStack_3a8) {
                      apppppppppppuStack_744[(int)pppppppppppppuVar14] = (uint ***********)0x0;
                      pppppppppppppuStack_3a8 = (uint *************)((int)pppppppppppppuVar14 + 1);
                      pppppppppppppuStack_748 = pppppppppppppuStack_3a8;
                    }
                  }
                  else {
                    pppppppppppppuStack_74c = (uint *************)0x0;
                    local_750 = (uint *************)0x0;
                    pppppppppppppuVar19 = pppppppppppppuVar14;
                    if (pppppppppppppuStack_784 != (uint *************)0x0) {
                      do {
                        if (pppppppppppppuVar19 == (uint *************)0x73) break;
                        if (pppppppppppppuVar19 == pppppppppppppuStack_3a8) {
                          apppppppppppuStack_744[(int)pppppppppppppuVar19] = (uint ***********)0x0;
                          pppppppppppppuStack_748 =
                               (uint *************)
                               ((undefined *)((int)local_750 + 1) + (int)pppppppppppppuVar14);
                        }
                        ppppppppppppuVar7 = local_75c[(int)local_750];
                        pppppppppppuVar2 = local_768[(int)pppppppppppppuVar14];
                        uVar13 = (uint)(ZEXT48(ppppppppppppuVar7) * ZEXT48(pppppppppppuVar2));
                        puVar9 = (undefined *)(uVar13 + (int)pppppppppppppuStack_74c);
                        ppppppppppppuVar20 = apppppppppppuStack_744 + (int)pppppppppppppuVar19;
                        pppppppppppuVar12 = *ppppppppppppuVar20;
                        *ppppppppppppuVar20 = (uint ***********)(puVar9 + (int)*ppppppppppppuVar20);
                        pppppppppppppuStack_74c =
                             (uint *************)
                             ((int)(ZEXT48(ppppppppppppuVar7) * ZEXT48(pppppppppppuVar2) >> 0x20) +
                              (uint)CARRY4(uVar13,(uint)pppppppppppppuStack_74c) +
                             (uint)CARRY4((uint)pppppppppppuVar12,(uint)puVar9));
                        local_750 = (uint *************)((int)local_750 + 1);
                        pppppppppppppuVar19 = (uint *************)((int)pppppppppppppuVar19 + 1);
                        pppppppppppppuStack_3a8 = pppppppppppppuStack_748;
                      } while (local_750 != pppppppppppppuStack_784);
                      if (pppppppppppppuStack_74c != (uint *************)0x0) {
                        pppppppppppppuVar17 = pppppppppppppuVar19;
                        local_750 = (uint *************)
                                    (apppppppppppuStack_744 + (int)pppppppppppppuVar19);
                        do {
                          if (pppppppppppppuVar17 == (uint *************)0x73) goto LAB_004153f5;
                          pppppppppppppuVar19 = (uint *************)((int)pppppppppppppuVar17 + 1);
                          if (pppppppppppppuVar17 == pppppppppppppuStack_3a8) {
                            *local_750 = (uint ************)0x0;
                            pppppppppppppuStack_748 = pppppppppppppuVar19;
                          }
                          pppppppppppppuVar10 = local_750 + 1;
                          ppppppppppppuVar20 = *local_750;
                          *local_750 = (uint ************)
                                       ((int)*local_750 + (int)pppppppppppppuStack_74c);
                          pppppppppppppuStack_74c =
                               (uint *************)
                               (uint)CARRY4((uint)ppppppppppppuVar20,(uint)pppppppppppppuStack_74c);
                          pppppppppppppuStack_3a8 = pppppppppppppuStack_748;
                          pppppppppppppuVar17 = pppppppppppppuVar19;
                          local_750 = pppppppppppppuVar10;
                        } while (pppppppppppppuStack_74c != (uint *************)0x0);
                      }
                    }
                    if (pppppppppppppuVar19 == (uint *************)0x73) {
LAB_004153f5:
                      ppppppppppppuVar20 = apppppppppppuStack_974;
                      goto LAB_0041540f;
                    }
                  }
                  pppppppppppppuVar14 = (uint *************)((int)pppppppppppppuVar14 + 1);
                } while (pppppppppppppuVar14 != local_770);
              }
              rVar11 = (int)pppppppppppppuStack_3a8 << 2;
              ppppppppppppuVar20 = apppppppppppuStack_744;
LAB_0041538b:
              _memcpy_s(&pppppppppppppuStack_3a4,0x1cc,ppppppppppppuVar20,rVar11);
            }
            bVar21 = true;
          }
LAB_0041539e:
          if (!bVar21) goto LAB_00415437;
        }
        if (local_788 % 10 != 0) {
          local_774 = *(uint **************)(&DAT_0041c764 + (local_788 % 10) * 2);
          if (local_774 == (uint *************)0x0) {
LAB_00415437:
            pppppppppppppuStack_3a8 = (uint *************)0x0;
            pppppppppppppuVar14 = (uint *************)&pppppppppppppuStack_3a4;
LAB_004159b7:
            _memcpy_s(pppppppppppppuVar14,0x1cc,apppppppppppuStack_974,0);
          }
          else if ((local_774 != (uint *************)0x1) &&
                  (pppppppppppppuStack_3a8 != (uint *************)0x0)) {
            local_758 = (uint *************)0x0;
            pppppppppppppuVar14 = (uint *************)0x0;
            do {
              lVar23 = ZEXT48(local_774) *
                       ZEXT48((&pppppppppppppuStack_3a4)[(int)pppppppppppppuVar14]) +
                       ZEXT48(local_758);
              (&pppppppppppppuStack_3a4)[(int)pppppppppppppuVar14] =
                   (uint *************)(uint ************)lVar23;
              local_758 = (uint *************)((ulonglong)lVar23 >> 0x20);
              pppppppppppppuVar14 = (uint *************)((int)pppppppppppppuVar14 + 1);
            } while (pppppppppppppuVar14 != pppppppppppppuStack_3a8);
            if (local_758 != (uint *************)0x0) {
              if ((uint *************)0x72 < pppppppppppppuStack_3a8) goto LAB_00415437;
              (&pppppppppppppuStack_3a4)[(int)pppppppppppppuStack_3a8] = local_758;
              pppppppppppppuStack_3a8 = (uint *************)((int)pppppppppppppuStack_3a8 + 1);
            }
          }
        }
      }
      pppppppppppppuVar14 = local_764;
      pppppppppppppuStack_74c = local_764;
      if (local_1d8[0] != (uint *************)0x0) {
        local_774 = (uint *************)0x0;
        pppppppppppppuVar19 = (uint *************)0x0;
        do {
          lVar23 = ZEXT48(local_1d8[(int)((int)pppppppppppppuVar19 + 1)]) * 10 + ZEXT48(local_774);
          local_1d8[(int)((int)pppppppppppppuVar19 + 1)] =
               (uint *************)(uint ************)lVar23;
          local_774 = (uint *************)((ulonglong)lVar23 >> 0x20);
          pppppppppppppuVar19 = (uint *************)((int)pppppppppppppuVar19 + 1);
        } while (pppppppppppppuVar19 != local_1d8[0]);
        if (local_774 != (uint *************)0x0) {
          if (local_1d8[0] < (uint *************)0x73) {
            local_1d8[(int)((int)local_1d8[0] + 1)] = local_774;
            local_1d8[0] = (uint *************)((int)local_1d8[0] + 1);
          }
          else {
            local_1d8[0] = (uint *************)0x0;
            _memcpy_s(local_1d8 + 1,0x1cc,apppppppppppuStack_974,0);
          }
        }
      }
      uVar24 = FUN_0040b470((uint *)local_1d8,(uint *)&pppppppppppppuStack_3a8);
      if ((int)uVar24 == 10) {
        pppppppppppppuVar14 = (uint *************)((int)local_764 + 1);
        local_788 = local_788 + 1;
        *(undefined *)local_764 = 0x31;
        local_780 = CONCAT44(pppppppppppppuStack_3a8,(undefined4)local_780);
        pppppppppppppuStack_74c = pppppppppppppuVar14;
        if (pppppppppppppuStack_3a8 != (uint *************)0x0) {
          ppppppppppppuVar20 = (uint ************)0x0;
          pppppppppppppuVar19 = (uint *************)0x0;
          do {
            lVar23 = ZEXT48((&pppppppppppppuStack_3a4)[(int)pppppppppppppuVar19]) * 10 +
                     ZEXT48(ppppppppppppuVar20);
            (&pppppppppppppuStack_3a4)[(int)pppppppppppppuVar19] =
                 (uint *************)(uint ************)lVar23;
            ppppppppppppuVar20 = (uint ************)((ulonglong)lVar23 >> 0x20);
            pppppppppppppuVar19 = (uint *************)((int)pppppppppppppuVar19 + 1);
          } while (pppppppppppppuVar19 != pppppppppppppuStack_3a8);
          local_780 = CONCAT44(ppppppppppppuVar20,(undefined4)local_780);
          if (ppppppppppppuVar20 != (uint ************)0x0) {
            if (pppppppppppppuStack_3a8 < (uint *************)0x73) {
              (&pppppppppppppuStack_3a4)[(int)pppppppppppppuStack_3a8] =
                   (uint *************)ppppppppppppuVar20;
              pppppppppppppuStack_3a8 = (uint *************)((int)pppppppppppppuStack_3a8 + 1);
            }
            else {
              pppppppppppppuStack_3a8 = (uint *************)0x0;
              _memcpy_s(&pppppppppppppuStack_3a4,0x1cc,apppppppppppuStack_974,0);
            }
          }
        }
      }
      else if ((int)uVar24 == 0) {
        local_788 = local_788 - 1;
      }
      else {
        pppppppppppppuVar14 = (uint *************)((int)local_764 + 1);
        *(char *)local_764 = (char)uVar24 + '0';
        pppppppppppppuStack_74c = pppppppppppppuVar14;
      }
      local_790[1] = local_788;
      uVar13 = local_78c;
      if (((-1 < (int)local_788) && (local_78c < 0x80000000)) && (param_4 == 0)) {
        uVar13 = local_78c + local_788;
      }
      uVar18 = param_7 - 1U;
      if (uVar13 <= param_7 - 1U) {
        uVar18 = uVar13;
      }
      local_758 = (uint *************)(uVar18 + (int)local_764);
      uStack_75d = 0;
      if (pppppppppppppuVar14 != local_758) {
        do {
          pppppppppppppuVar19 = pppppppppppppuStack_74c;
          local_780 = CONCAT44(local_1d8[0],(undefined4)local_780);
          if (local_1d8[0] == (uint *************)0x0) break;
          ppppppppppppuVar20 = (uint ************)0x0;
          pppppppppppppuVar14 = (uint *************)0x0;
          do {
            lVar23 = ZEXT48(local_1d8[(int)((int)pppppppppppppuVar14 + 1)]) * 1000000000 +
                     ZEXT48(ppppppppppppuVar20);
            local_1d8[(int)((int)pppppppppppppuVar14 + 1)] =
                 (uint *************)(uint ************)lVar23;
            ppppppppppppuVar20 = (uint ************)((ulonglong)lVar23 >> 0x20);
            pppppppppppppuVar14 = (uint *************)((int)pppppppppppppuVar14 + 1);
          } while (pppppppppppppuVar14 != local_1d8[0]);
          local_780 = CONCAT44(ppppppppppppuVar20,(undefined4)local_780);
          if (ppppppppppppuVar20 != (uint ************)0x0) {
            if (local_1d8[0] < (uint *************)0x73) {
              local_1d8[(int)((int)local_1d8[0] + 1)] = (uint *************)ppppppppppppuVar20;
              local_1d8[0] = (uint *************)((int)local_1d8[0] + 1);
            }
            else {
              local_1d8[0] = (uint *************)0x0;
              _memcpy_s(local_1d8 + 1,0x1cc,apppppppppppuStack_974,0);
            }
          }
          uVar24 = FUN_0040b470((uint *)local_1d8,(uint *)&pppppppppppppuStack_3a8);
          local_75c = (uint *************)uVar24;
          uVar13 = (int)local_758 - (int)pppppppppppppuVar19;
          local_774 = (uint *************)0x8;
          do {
            uVar24 = (uVar24 & 0xffffffff) % ZEXT48(local_754);
            cVar3 = (char)uVar24 + '0';
            local_78c = CONCAT31((int3)(uVar24 >> 8),cVar3);
            local_75c = (uint *************)((uint)local_75c / (uint)local_754);
            if (local_774 < uVar13) {
              *(char *)((int)local_774 + (int)pppppppppppppuVar19) = cVar3;
            }
            else if (cVar3 != '0') {
              uStack_75d = 1;
            }
            local_774 = (uint *************)((int)local_774 - 1);
            uVar24 = (ulonglong)CONCAT14(uStack_75d,local_75c);
          } while (local_774 != (uint *************)0xffffffff);
          if (9 < uVar13) {
            uVar13 = 9;
          }
          pppppppppppppuVar14 = (uint *************)((int)pppppppppppppuVar19 + uVar13);
          local_774 = (uint *************)0xffffffff;
          pppppppppppppuStack_74c = pppppppppppppuVar14;
        } while (pppppppppppppuVar14 != local_758);
      }
      *(undefined *)pppppppppppppuVar14 = 0;
      __controlfp_s((uint *)((int)&local_780 + 4),local_798,local_794);
      goto LAB_00415cf8;
    }
    local_790[1] = 1;
    if (_Var5 != 1) {
      if (_Var5 == 2) {
        pcVar25 = "1#QNAN";
      }
      else if (_Var5 == 3) {
        pcVar25 = "1#SNAN";
      }
      else {
        if (_Var5 != 4) goto LAB_0041489f;
        pcVar25 = "1#IND";
      }
      goto LAB_0041485c;
    }
    iVar6 = FUN_0040daef((char *)local_764,param_7,0x41fe1c);
  }
  if (iVar6 != 0) {
                    // WARNING: Subroutine does not return
    __invoke_watson((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0);
  }
LAB_00415cf8:
  if (local_79c != '\0') {
    FUN_00418284((uint *)&local_7a4);
  }
  FUN_00402125(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



undefined4 __cdecl FUN_00415d2c(byte *param_1,uint param_2,undefined4 *param_3,int param_4)

{
  byte bVar1;
  undefined4 uVar2;
  byte bVar3;
  int iVar4;
  int iVar5;
  
  if (param_1 != (byte *)0x0) {
    if (param_2 != 0) {
      if ((param_2 & 0xffffff80) == 0) {
        *param_1 = (byte)param_2;
        return 1;
      }
      if ((param_2 & 0xfffff800) == 0) {
        bVar3 = 0xc0;
        iVar4 = 1;
        iVar5 = iVar4;
      }
      else if ((param_2 & 0xffff0000) == 0) {
        if ((0xd7ff < param_2) && (param_2 < 0xe000)) {
LAB_00415dcb:
          uVar2 = FUN_00418561(param_3,param_4);
          return uVar2;
        }
        iVar4 = 2;
        bVar3 = 0xe0;
        iVar5 = iVar4;
      }
      else {
        if (((param_2 & 0xffe00000) != 0) || (0x10ffff < param_2)) goto LAB_00415dcb;
        iVar4 = 3;
        bVar3 = 0xf0;
        iVar5 = iVar4;
      }
      do {
        bVar1 = (byte)param_2;
        param_2 = param_2 >> 6;
        param_1[iVar4] = bVar1 & 0x3f | 0x80;
        iVar4 = iVar4 + -1;
      } while (iVar4 != 0);
      *param_1 = (byte)param_2 | bVar3;
      uVar2 = FUN_0041854d(iVar5 + 1,param_3);
      return uVar2;
    }
    *param_1 = (byte)param_2;
  }
  *param_3 = 0;
  param_3[1] = 0;
  return 1;
}



char FUN_00415ddc(char *param_1)

{
  char cVar1;
  
  if (*param_1 == '\0') {
    cVar1 = '\x01';
  }
  else if (param_1[1] == '\0') {
    cVar1 = '\x02';
  }
  else {
    cVar1 = (param_1[2] != '\0') + '\x03';
  }
  return cVar1;
}



uint __cdecl FUN_00415e08(undefined2 *param_1,byte *param_2,uint param_3,uint *param_4,int param_5)

{
  uint uVar1;
  uint *local_8;
  
  uVar1 = FUN_00418583(&local_8,param_2,param_3,param_4,param_5);
  if (uVar1 < 5) {
    if ((uint *)0xffff < local_8) {
      local_8 = (uint *)0xfffd;
    }
    if (param_1 != (undefined2 *)0x0) {
      *param_1 = (short)local_8;
    }
  }
  return uVar1;
}



int __thiscall
FUN_00415e4b(void *this,ushort *param_1,byte **param_2,uint param_3,uint *param_4,int param_5)

{
  char cVar1;
  undefined3 extraout_var;
  int iVar2;
  uint uVar3;
  undefined3 extraout_var_01;
  int iVar4;
  uint *puVar5;
  ushort *puVar6;
  byte *pbVar7;
  uint *local_c;
  void *pvStack_8;
  undefined3 extraout_var_00;
  
  pbVar7 = *param_2;
  local_c = (uint *)this;
  pvStack_8 = this;
  if (param_1 == (ushort *)0x0) {
    iVar2 = 0;
    cVar1 = FUN_00415ddc((char *)pbVar7);
    uVar3 = CONCAT31(extraout_var_00,cVar1);
    while (iVar4 = FUN_00418583((uint **)0x0,pbVar7,uVar3,param_4,param_5), iVar4 != -1) {
      if (iVar4 == 0) {
        return iVar2;
      }
      if (iVar4 == 4) {
        iVar2 = iVar2 + 1;
      }
      pbVar7 = pbVar7 + iVar4;
      iVar2 = iVar2 + 1;
      cVar1 = FUN_00415ddc((char *)pbVar7);
      uVar3 = CONCAT31(extraout_var_01,cVar1);
    }
    *(undefined *)(param_5 + 0x1c) = 1;
    *(undefined4 *)(param_5 + 0x18) = 0x2a;
    iVar2 = -1;
  }
  else {
    puVar6 = param_1;
    if (param_3 != 0) {
      do {
        cVar1 = FUN_00415ddc((char *)pbVar7);
        iVar2 = FUN_00418583(&local_c,pbVar7,CONCAT31(extraout_var,cVar1),param_4,param_5);
        if (iVar2 == -1) {
          *param_2 = pbVar7;
          *(undefined *)(param_5 + 0x1c) = 1;
          *(undefined4 *)(param_5 + 0x18) = 0x2a;
          return -1;
        }
        if (iVar2 == 0) {
          pbVar7 = (byte *)0x0;
          *puVar6 = 0;
          break;
        }
        puVar5 = local_c;
        if ((uint *)0xffff < local_c) {
          if (param_3 < 2) break;
          local_c = local_c + -0x4000;
          param_3 = param_3 - 1;
          *puVar6 = (ushort)((uint)local_c >> 10) | 0xd800;
          puVar6 = puVar6 + 1;
          puVar5 = (uint *)((uint)local_c & 0x3ff | 0xdc00);
        }
        *puVar6 = (ushort)puVar5;
        pbVar7 = pbVar7 + iVar2;
        puVar6 = puVar6 + 1;
        param_3 = param_3 - 1;
      } while (param_3 != 0);
    }
    iVar2 = (int)puVar6 - (int)param_1 >> 1;
    *param_2 = pbVar7;
  }
  return iVar2;
}



uint __cdecl FUN_00415f53(byte param_1,FILE *param_2,__acrt_ptd **param_3)

{
  bool bVar1;
  char cVar2;
  undefined4 uVar3;
  uint uVar4;
  
  __fileno(param_2);
  if ((param_2->_flag & 6U) == 0) {
    param_3[6] = (__acrt_ptd *)0x9;
  }
  else {
    if (((uint)param_2->_flag >> 0xc & 1) == 0) {
      if ((param_2->_flag & 1U) == 0) {
LAB_00415fd8:
        LOCK();
        param_2->_flag = param_2->_flag | 2;
        UNLOCK();
        LOCK();
        param_2->_flag = param_2->_flag & 0xfffffff7;
        UNLOCK();
        param_2->_base = (char *)0x0;
        if ((param_2->_flag & 0x4c0U) == 0) {
          uVar3 = FUN_00410044(param_2);
          if ((char)uVar3 == '\0') {
            ___acrt_stdio_allocate_buffer_nolock(&param_2->_ptr);
          }
        }
        cVar2 = FUN_00416049(param_1,param_2,param_3);
        if (cVar2 == '\0') {
          LOCK();
          param_2->_flag = param_2->_flag | 0x10;
          UNLOCK();
          uVar4 = 0xffffffff;
        }
        else {
          uVar4 = (uint)param_1;
        }
        return uVar4;
      }
      bVar1 = stream_is_at_end_of_file_nolock(SUB41(param_2,0));
      param_2->_base = (char *)0x0;
      if (bVar1) {
        param_2->_ptr = (char *)param_2->_cnt;
        LOCK();
        param_2->_flag = param_2->_flag & 0xfffffffe;
        UNLOCK();
        goto LAB_00415fd8;
      }
      goto LAB_00415f7d;
    }
    param_3[6] = (__acrt_ptd *)0x22;
  }
  *(undefined *)(param_3 + 7) = 1;
LAB_00415f7d:
  LOCK();
  param_2->_flag = param_2->_flag | 0x10;
  UNLOCK();
  return 0xffffffff;
}



char __cdecl FUN_00416049(byte param_1,FILE *param_2,__acrt_ptd **param_3)

{
  char *pcVar1;
  undefined *puVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  char cVar6;
  longlong lVar7;
  
  pcVar1 = (char *)__fileno(param_2);
  if ((param_2->_flag & 0xc0U) == 0) {
    iVar3 = FUN_0041426c(pcVar1,&param_1,1,param_3);
    cVar6 = '\x01' - (iVar3 != 1);
  }
  else {
    uVar5 = 0;
    uVar4 = (int)param_2->_ptr - param_2->_cnt;
    param_2->_ptr = (char *)(param_2->_cnt + 1);
    param_2->_base = (char *)(param_2->_bufsiz + -1);
    if ((int)uVar4 < 1) {
      if ((pcVar1 == (char *)0xffffffff) || (pcVar1 == (char *)0xfffffffe)) {
        puVar2 = &DAT_004230f8;
      }
      else {
        puVar2 = (undefined *)(((uint)pcVar1 & 0x3f) * 0x38 + (&DAT_004240c8)[(int)pcVar1 >> 6]);
      }
      if (((puVar2[0x28] & 0x20) != 0) &&
         (lVar7 = FUN_00418197((uint)pcVar1,0,0,(PLARGE_INTEGER)0x2), lVar7 == -1)) {
        LOCK();
        param_2->_flag = param_2->_flag | 0x10;
        UNLOCK();
        return '\x01';
      }
    }
    else {
      uVar5 = FUN_0041426c(pcVar1,(byte *)param_2->_cnt,uVar4,param_3);
    }
    cVar6 = uVar5 == uVar4;
    *(byte *)param_2->_cnt = param_1;
  }
  return cVar6;
}



// Library Function - Single Match
//  bool __cdecl stream_is_at_end_of_file_nolock(class __crt_stdio_stream)
// 
// Library: Visual Studio 2019 Release

bool __cdecl stream_is_at_end_of_file_nolock(__crt_stdio_stream param_1)

{
  HANDLE hFile;
  BOOL BVar1;
  DWORD unaff_ESI;
  undefined3 in_stack_00000005;
  LARGE_INTEGER local_14;
  DWORD local_c;
  int local_8;
  
  if (((uint)_param_1[3] >> 3 & 1) != 0) {
    return true;
  }
  if (((((_param_1[3] & 0xc0U) == 0) || (*_param_1 != _param_1[1])) &&
      (hFile = (HANDLE)FUN_0041264f(_param_1[4]), hFile != (HANDLE)0xffffffff)) &&
     ((BVar1 = SetFilePointerEx(hFile,(LARGE_INTEGER)(ZEXT48(&local_c) << 0x20),(PLARGE_INTEGER)0x1,
                                unaff_ESI), BVar1 != 0 &&
      (BVar1 = GetFileSizeEx(hFile,&local_14), BVar1 != 0)))) {
    if ((local_c == local_14.s.LowPart) && (local_8 == local_14.s.HighPart)) {
      return true;
    }
    return false;
  }
  return false;
}



void __cdecl FUN_004161a0(byte param_1,FILE *param_2,__acrt_ptd **param_3)

{
  FUN_00415f53(param_1,param_2,param_3);
  return;
}



byte __cdecl FUN_004161ab(uint param_1)

{
  undefined4 *puVar1;
  
  if (param_1 == 0xfffffffe) {
    puVar1 = (undefined4 *)FUN_0040e304();
    *puVar1 = 9;
  }
  else {
    if ((-1 < (int)param_1) && (param_1 < DAT_004242c8)) {
      return *(byte *)((&DAT_004240c8)[param_1 >> 6] + 0x28 + (param_1 & 0x3f) * 0x38) & 0x40;
    }
    puVar1 = (undefined4 *)FUN_0040e304();
    *puVar1 = 9;
    FUN_0040e223();
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  ___acrt_stdio_allocate_buffer_nolock
// 
// Library: Visual Studio 2019 Release

void __cdecl ___acrt_stdio_allocate_buffer_nolock(undefined4 *param_1)

{
  uint *puVar1;
  LPVOID pvVar2;
  undefined4 uVar3;
  
  _DAT_00423d20 = _DAT_00423d20 + 1;
  uVar3 = 0x1000;
  pvVar2 = __calloc_base(0x1000,1);
  param_1[1] = pvVar2;
  FUN_0040e374((LPVOID)0x0);
  puVar1 = param_1 + 3;
  if (param_1[1] == 0) {
    LOCK();
    *puVar1 = *puVar1 | 0x400;
    UNLOCK();
    param_1[1] = param_1 + 5;
    uVar3 = 2;
  }
  else {
    LOCK();
    *puVar1 = *puVar1 | 0x40;
    UNLOCK();
  }
  param_1[6] = uVar3;
  param_1[2] = 0;
  *param_1 = param_1[1];
  return;
}



uint __cdecl FUN_0041625d(uint param_1)

{
  ushort uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  
  uVar4 = 0;
  uVar1 = (ushort)param_1 & 0x8040;
  if (uVar1 == 0x8000) {
    uVar3 = 0xc00;
  }
  else if (uVar1 == 0x40) {
    uVar3 = 0x800;
  }
  else {
    uVar3 = 0x400;
    if (uVar1 != 0x8040) {
      uVar3 = 0;
    }
  }
  uVar2 = param_1 & 0x6000;
  if (uVar2 != 0) {
    if (uVar2 == 0x2000) {
      uVar4 = 0x100;
    }
    else if (uVar2 == 0x4000) {
      uVar4 = 0x200;
    }
    else if (uVar2 == 0x6000) {
      uVar4 = 0x300;
    }
  }
  return (((param_1 & 0x400 | (param_1 >> 2 & 0x400 | param_1 & 0x800) >> 2) >> 2 | param_1 & 0x200)
          >> 3 | param_1 & 0x180) >> 3 | uVar3 | uVar4;
}



uint __cdecl FUN_0041630d(uint param_1)

{
  uint uVar1;
  uint uVar2;
  uint local_8;
  
  local_8 = 0x1000;
  uVar2 = 0;
  if ((param_1 & 0x300) == 0) {
    local_8 = 0x2000;
  }
  else if ((param_1 & 0x300) != 0x200) {
    local_8 = 0;
  }
  uVar1 = param_1 & 0xc00;
  if (uVar1 != 0) {
    if (uVar1 == 0x400) {
      uVar2 = 0x100;
    }
    else if (uVar1 == 0x800) {
      uVar2 = 0x200;
    }
    else if (uVar1 == 0xc00) {
      uVar2 = 0x300;
    }
  }
  return (param_1 & 4 | (param_1 & 2) << 3) * 2 |
         ((param_1 >> 2 & 8 | param_1 & 0x10) >> 2 | param_1 & 8) >> 1 | (param_1 & 1) << 4 |
         (param_1 & 0x1000) << 2 | local_8 | uVar2;
}



uint __cdecl FUN_004163ba(uint param_1)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  
  uVar1 = param_1 >> 2;
  uVar2 = param_1 & 0xc00;
  uVar3 = (param_1 & 0xc03fffff) >> 0x16;
  uVar4 = 0;
  if (uVar2 == 0x400) {
    uVar2 = 0x8040;
  }
  else if (uVar2 == 0x800) {
    uVar2 = 0x40;
  }
  else if (uVar2 == 0xc00) {
    uVar2 = 0x8000;
  }
  else {
    uVar2 = 0;
  }
  if (uVar3 != 0) {
    if (uVar3 == 0x100) {
      uVar4 = 0x2000;
    }
    else if (uVar3 == 0x200) {
      uVar4 = 0x4000;
    }
    else if (uVar3 == 0x300) {
      uVar4 = 0x6000;
    }
  }
  return ((((uVar1 & 0x1000000) >> 0x16 |
           (((uVar1 & 0x400000) >> 0x16) << 2 | (uVar1 & 0x800000) >> 0x16) << 2) << 2 |
          (uVar1 & 0x2000000) >> 0x16) << 3 | (uVar1 & 0xc000000) >> 0x16) << 3 | uVar2 | uVar4;
}



uint __cdecl FUN_00416470(uint param_1)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  
  uVar3 = param_1 >> 2;
  uVar4 = 0;
  if ((param_1 & 0x3000) == 0) {
    uVar2 = 0x300;
  }
  else {
    uVar2 = uVar4;
    if ((param_1 & 0x3000) == 0x1000) {
      uVar2 = 0x200;
    }
  }
  uVar1 = (param_1 & 0xc00000) >> 0xe;
  if (uVar1 != 0) {
    if (uVar1 == 0x100) {
      uVar4 = 0x400;
    }
    else if (uVar1 == 0x200) {
      uVar4 = 0x800;
    }
    else if (uVar1 == 0x300) {
      uVar4 = 0xc00;
    }
  }
  return ((uVar3 & 0x10000) >> 0xe | (((uVar3 & 0x4000) >> 0xe) << 2 | (uVar3 & 0x8000) >> 0xe) << 2
         ) * 2 | (uVar3 & 0xc0000) >> 0x12 | (uVar3 & 0x20000) >> 0xf | param_1 >> 2 & 0x1000 |
         uVar2 | uVar4;
}



// Library Function - Single Match
//  ___acrt_fenv_get_common_round_control
// 
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

uint __cdecl ___acrt_fenv_get_common_round_control(uint param_1)

{
  uint uVar1;
  
  uVar1 = param_1 >> 0xe & 0x300;
  if (uVar1 != (param_1 >> 0x16 & 0x300)) {
    uVar1 = 0xffffffff;
  }
  return uVar1;
}



// Library Function - Single Match
//  ___acrt_fenv_get_control
// 
// Library: Visual Studio 2019 Release

uint ___acrt_fenv_get_control(void)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  undefined4 *puVar4;
  ushort in_FPUControlWord;
  undefined4 local_24;
  uint local_8;
  
  puVar4 = &local_24;
  for (iVar2 = 7; iVar2 != 0; iVar2 = iVar2 + -1) {
    *puVar4 = 0;
    puVar4 = puVar4 + 1;
  }
  local_24 = CONCAT22(local_24._2_2_,in_FPUControlWord);
  uVar1 = FUN_0041630d(in_FPUControlWord & 7999);
  if (DAT_0042393c < 1) {
    uVar3 = 0;
  }
  else {
    local_8 = MXCSR;
    uVar3 = MXCSR & 0xffc0;
  }
  uVar3 = FUN_0041625d(uVar3);
  return uVar3 | ((((uVar3 & 0x3f) << 2 | uVar3 & 0xffffff00) << 6 | uVar1 & 0x3f) << 2 |
                 uVar1 & 0x300) << 0xe | uVar1;
}



uint FUN_004165c8(void)

{
  uint uVar1;
  uint uVar2;
  ushort in_FPUStatusWord;
  
  uVar1 = (uint)in_FPUStatusWord;
  uVar1 = ((in_FPUStatusWord >> 2 & 8 | uVar1 & 0x10) >> 2 | uVar1 & 8) >> 1 |
          ((uVar1 & 2) << 3 | uVar1 & 4) * 2 | (uVar1 & 1) << 4;
  if (DAT_0042393c < 1) {
    uVar2 = 0;
  }
  else {
    uVar2 = MXCSR & 0x3f;
  }
  uVar2 = ((uVar2 >> 2 & 8 | uVar2 & 0x10) >> 2 | uVar2 & 8) >> 1 |
          ((uVar2 & 2) << 3 | uVar2 & 4) * 2 | (uVar2 & 1) << 4;
  return (uVar2 << 8 | uVar1) << 0x10 | uVar2 | uVar1;
}



void __cdecl FUN_00416672(uint param_1)

{
  uint uVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined2 in_FPUControlWord;
  undefined4 local_24;
  uint local_8;
  
  uVar1 = FUN_00416470(param_1);
  puVar3 = &local_24;
  for (iVar2 = 7; iVar2 != 0; iVar2 = iVar2 + -1) {
    *puVar3 = 0;
    puVar3 = puVar3 + 1;
  }
  local_24 = CONCAT22(local_24._2_2_,in_FPUControlWord);
  local_8 = uVar1 & 7999;
  local_24 = local_24 & 0xffffe0c0 | local_8;
  uVar1 = FUN_004163ba(param_1);
  if (0 < DAT_0042393c) {
    MXCSR = MXCSR & 0xffff003f | uVar1 & 0xffc0;
  }
  return;
}



void __cdecl FUN_004166ed(uint param_1)

{
  int iVar1;
  uint uVar2;
  undefined4 *puVar3;
  undefined4 local_24 [8];
  
  puVar3 = local_24;
  for (iVar1 = 7; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar3 = 0;
    puVar3 = puVar3 + 1;
  }
  uVar2 = param_1 >> 0x18;
  if (0 < DAT_0042393c) {
    MXCSR = MXCSR & 0xffffffc0 |
            -(uint)((uVar2 & 1) != 0) & 0x20 | -(uint)((uVar2 & 2) != 0) & 0x10 |
            -(uint)((uVar2 & 4) != 0) & 8 | -(uint)((uVar2 & 8) != 0) & 4 |
            (uint)((uVar2 & 0x10) != 0) | -(uint)((uVar2 & 0x20) != 0) & 2;
  }
  return;
}



int __cdecl FUN_004167e9(uint param_1,char *param_2,int param_3)

{
  byte *pbVar1;
  char cVar2;
  byte bVar3;
  int iVar4;
  HANDLE hFile;
  char *pcVar5;
  BOOL BVar6;
  char *pcVar7;
  char *pcVar8;
  int iVar9;
  char *local_14;
  int local_10;
  char *local_c;
  char local_5;
  
  local_10 = (int)param_1 >> 6;
  iVar9 = (param_1 & 0x3f) * 0x38;
  iVar4 = (&DAT_004240c8)[local_10];
  hFile = *(HANDLE *)(iVar9 + 0x18 + iVar4);
  if ((param_3 == 0) || (*param_2 != '\n')) {
    pbVar1 = (byte *)(iVar9 + 0x28 + iVar4);
    *pbVar1 = *pbVar1 & 0xfb;
  }
  else {
    pbVar1 = (byte *)(iVar9 + 0x28 + iVar4);
    *pbVar1 = *pbVar1 | 4;
  }
  local_14 = param_2 + param_3;
  local_c = param_2;
  pcVar8 = param_2;
  pcVar7 = param_2;
  if (param_2 < local_14) {
    do {
      cVar2 = *local_c;
      pcVar8 = pcVar7;
      if (cVar2 == '\x1a') {
        bVar3 = *(byte *)((&DAT_004240c8)[local_10] + 0x28 + iVar9);
        if ((bVar3 & 0x40) == 0) {
          *(byte *)((&DAT_004240c8)[local_10] + 0x28 + iVar9) = bVar3 | 2;
        }
        else {
          *pcVar7 = '\x1a';
LAB_0041692c:
          pcVar8 = pcVar7 + 1;
        }
        break;
      }
      pcVar5 = local_c + 1;
      if (cVar2 == '\r') {
        if (local_14 <= pcVar5) {
          BVar6 = ReadFile(hFile,&local_5,1,(LPDWORD)&local_14,(LPOVERLAPPED)0x0);
          if ((BVar6 != 0) && (local_14 != (char *)0x0)) {
            if ((*(byte *)((&DAT_004240c8)[local_10] + 0x28 + iVar9) & 0x48) != 0) {
              pcVar8 = pcVar7 + 1;
              if (local_5 == '\n') {
                *pcVar7 = '\n';
              }
              else {
                *pcVar7 = '\r';
                *(char *)((&DAT_004240c8)[local_10] + 0x2a + iVar9) = local_5;
              }
              break;
            }
            if ((local_5 == '\n') && (pcVar7 == param_2)) {
              *pcVar7 = '\n';
              goto LAB_0041692c;
            }
            FUN_004181d7(param_1,0xffffffff,0xffffffff,(PLARGE_INTEGER)0x1);
            if (local_5 == '\n') break;
          }
          *pcVar7 = '\r';
          goto LAB_0041692c;
        }
        cVar2 = *pcVar5;
        pcVar5 = local_c + (cVar2 == '\n') + 1;
        *pcVar7 = ((cVar2 == '\n') - 1U & 3) + 10;
      }
      else {
        *pcVar7 = cVar2;
      }
      pcVar8 = pcVar7 + 1;
      pcVar7 = pcVar8;
      local_c = pcVar5;
    } while (pcVar5 < local_14);
  }
  return (int)pcVar8 - (int)param_2;
}



uint __cdecl FUN_00416936(uint param_1,ushort *param_2,int param_3)

{
  byte *pbVar1;
  byte bVar2;
  int iVar3;
  HANDLE hFile;
  ushort uVar4;
  ushort *puVar5;
  BOOL BVar6;
  ushort *puVar7;
  ushort *puVar8;
  int iVar9;
  DWORD local_1c;
  uint local_18;
  undefined4 local_14;
  ushort *local_10;
  int local_c;
  ushort *local_8;
  
  local_c = (int)param_1 >> 6;
  iVar9 = (param_1 & 0x3f) * 0x38;
  iVar3 = (&DAT_004240c8)[local_c];
  local_1c = 10;
  hFile = *(HANDLE *)(iVar3 + 0x18 + iVar9);
  if ((param_3 == 0) || (*param_2 != 10)) {
    pbVar1 = (byte *)(iVar3 + 0x28 + iVar9);
    *pbVar1 = *pbVar1 & 0xfb;
  }
  else {
    pbVar1 = (byte *)(iVar3 + 0x28 + iVar9);
    *pbVar1 = *pbVar1 | 4;
  }
  local_10 = param_2 + param_3;
  local_8 = param_2;
  puVar8 = param_2;
  if (param_2 < local_10) {
    local_14 = 0xd;
    puVar7 = param_2;
    do {
      uVar4 = *local_8;
      local_18 = (uint)uVar4;
      puVar8 = puVar7;
      if (local_18 == 0x1a) {
        bVar2 = *(byte *)((&DAT_004240c8)[local_c] + 0x28 + iVar9);
        if ((bVar2 & 0x40) == 0) {
          *(byte *)((&DAT_004240c8)[local_c] + 0x28 + iVar9) = bVar2 | 2;
        }
        else {
          *puVar7 = uVar4;
LAB_00416ae1:
          puVar8 = puVar7 + 1;
        }
        break;
      }
      puVar5 = local_8 + 1;
      if (uVar4 == 0xd) {
        if (local_10 <= puVar5) {
          BVar6 = ReadFile(hFile,&local_8,2,&local_1c,(LPOVERLAPPED)0x0);
          if ((BVar6 == 0) || (local_1c == 0)) {
LAB_00416abf:
            uVar4 = 0xd;
          }
          else {
            if ((*(byte *)((&DAT_004240c8)[local_c] + 0x28 + iVar9) & 0x48) != 0) {
              puVar8 = puVar7 + 1;
              if ((short)local_8 == 10) {
                *puVar7 = 10;
              }
              else {
                *puVar7 = 0xd;
                *(char *)((&DAT_004240c8)[local_c] + 0x2a + iVar9) = (char)local_8;
                *(char *)((&DAT_004240c8)[local_c] + 0x2b + iVar9) = (char)((uint)local_8 >> 8);
                *(undefined *)((&DAT_004240c8)[local_c] + 0x2c + iVar9) = 10;
              }
              break;
            }
            uVar4 = 10;
            if (((short)local_8 != 10) || (puVar7 != param_2)) {
              FUN_004181d7(param_1,0xfffffffe,0xffffffff,(PLARGE_INTEGER)0x1);
              if ((short)local_8 != 10) goto LAB_00416abf;
              break;
            }
          }
          *puVar7 = uVar4;
          goto LAB_00416ae1;
        }
        uVar4 = *puVar5;
        puVar5 = local_8 + (uVar4 == 10) + 1;
        *puVar7 = ((uVar4 == 10) - 1 & 3) + 10;
      }
      else {
        *puVar7 = uVar4;
      }
      puVar8 = puVar7 + 1;
      puVar7 = puVar8;
      local_8 = puVar5;
    } while (puVar5 < local_10);
  }
  return (int)puVar8 - (int)param_2 & 0xfffffffe;
}



int __cdecl FUN_00416af0(uint param_1,byte *param_2,int param_3,LPWSTR param_4,int param_5)

{
  byte bVar1;
  int iVar2;
  int iVar3;
  undefined4 *puVar4;
  DWORD DVar5;
  int iVar6;
  uint uVar7;
  byte *pbVar8;
  byte *pbVar9;
  int iVar10;
  
  iVar3 = FUN_004167e9(param_1,(char *)param_2,param_3);
  if (iVar3 == 0) {
    return 0;
  }
  iVar6 = (int)param_1 >> 6;
  iVar10 = (param_1 & 0x3f) * 0x38;
  iVar2 = (&DAT_004240c8)[iVar6];
  if (*(char *)(iVar2 + 0x29 + iVar10) != '\0') {
    pbVar8 = param_2 + iVar3;
    bVar1 = pbVar8[-1];
    if ((char)bVar1 < '\0') {
      uVar7 = 1;
      pbVar8 = pbVar8 + -1;
      while ((((&DAT_00423780)[bVar1] == '\0' && (uVar7 < 5)) && (param_2 <= pbVar8))) {
        pbVar8 = pbVar8 + -1;
        uVar7 = uVar7 + 1;
        bVar1 = *pbVar8;
      }
      if ((char)(&DAT_00423780)[*pbVar8] == 0) {
        puVar4 = (undefined4 *)FUN_0040e304();
        *puVar4 = 0x2a;
        return -1;
      }
      if ((int)(char)(&DAT_00423780)[*pbVar8] + 1U == uVar7) {
        pbVar8 = pbVar8 + uVar7;
      }
      else if ((*(byte *)(iVar2 + 0x28 + iVar10) & 0x48) == 0) {
        FUN_004181d7(param_1,-uVar7,(int)-uVar7 >> 0x1f,(PLARGE_INTEGER)0x1);
      }
      else {
        pbVar9 = pbVar8 + 1;
        *(byte *)(iVar2 + 0x2a + iVar10) = *pbVar8;
        if (1 < uVar7) {
          bVar1 = *pbVar9;
          pbVar9 = pbVar8 + 2;
          *(byte *)(iVar10 + 0x2b + (&DAT_004240c8)[iVar6]) = bVar1;
        }
        if (uVar7 == 3) {
          bVar1 = *pbVar9;
          pbVar9 = pbVar9 + 1;
          *(byte *)(iVar10 + 0x2c + (&DAT_004240c8)[iVar6]) = bVar1;
        }
        pbVar8 = pbVar9 + -uVar7;
      }
    }
    iVar3 = FUN_00411ea3(0xfde9,0,(LPCSTR)param_2,(int)pbVar8 - (int)param_2,param_4,param_5);
    if (iVar3 == 0) {
      DVar5 = GetLastError();
      ___acrt_errno_map_os_error(DVar5);
      return -1;
    }
    *(byte *)(iVar10 + 0x2d + (&DAT_004240c8)[iVar6]) =
         (iVar3 == (int)pbVar8 - (int)param_2) - 1U & 2 |
         *(byte *)(iVar10 + 0x2d + (&DAT_004240c8)[iVar6]) & 0xfd;
    return iVar3 * 2;
  }
  return iVar3;
}



uint __cdecl FUN_00416c47(uint param_1,short *param_2,int param_3)

{
  short *psVar1;
  byte *pbVar2;
  short sVar3;
  short *psVar4;
  short *psVar5;
  short *psVar6;
  int iStack_18;
  
  psVar1 = param_2 + param_3;
  psVar4 = param_2;
  psVar5 = param_2;
  psVar6 = param_2;
  if (param_2 < psVar1) {
    do {
      sVar3 = *psVar4;
      if (sVar3 == 0x1a) {
        pbVar2 = (byte *)((&DAT_004240c8)[(int)param_1 >> 6] + 0x28 + (param_1 & 0x3f) * 0x38);
        *pbVar2 = *pbVar2 | 2;
        psVar6 = psVar5;
        break;
      }
      if (((sVar3 == 0xd) && (psVar4 + 1 < psVar1)) && (psVar4[1] == 10)) {
        iStack_18 = 4;
        sVar3 = 10;
      }
      else {
        iStack_18 = 2;
      }
      psVar6 = psVar5 + 1;
      *psVar5 = sVar3;
      psVar4 = (short *)((int)psVar4 + iStack_18);
      psVar5 = psVar6;
    } while (psVar4 < psVar1);
  }
  return (int)psVar6 - (int)param_2 & 0xfffffffe;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4

uint __cdecl FUN_00416cc5(uint param_1,LPWSTR param_2,uint param_3)

{
  bool bVar1;
  undefined4 *puVar2;
  int iVar3;
  uint uVar4;
  void *local_14;
  
  if (param_1 == 0xfffffffe) {
    puVar2 = (undefined4 *)FUN_0040e2f1();
    *puVar2 = 0;
    puVar2 = (undefined4 *)FUN_0040e304();
    *puVar2 = 9;
    ExceptionList = local_14;
    return 0xffffffff;
  }
  if (((int)param_1 < 0) || (DAT_004242c8 <= param_1)) {
    bVar1 = false;
  }
  else {
    bVar1 = true;
  }
  if (bVar1) {
    iVar3 = (param_1 & 0x3f) * 0x38;
    if ((*(byte *)((&DAT_004240c8)[(int)param_1 >> 6] + 0x28 + iVar3) & 1) != 0) {
      if (param_3 < 0x80000000) {
        FUN_00412578(param_1);
        uVar4 = 0xffffffff;
        if ((*(byte *)((&DAT_004240c8)[(int)param_1 >> 6] + 0x28 + iVar3) & 1) == 0) {
          puVar2 = (undefined4 *)FUN_0040e304();
          *puVar2 = 9;
          puVar2 = (undefined4 *)FUN_0040e2f1();
          *puVar2 = 0;
        }
        else {
          uVar4 = FUN_00416dde(param_1,param_2,param_3);
        }
        FUN_00416dd6();
        ExceptionList = local_14;
        return uVar4;
      }
      puVar2 = (undefined4 *)FUN_0040e2f1();
      *puVar2 = 0;
      puVar2 = (undefined4 *)FUN_0040e304();
      *puVar2 = 0x16;
      goto LAB_00416d1e;
    }
  }
  puVar2 = (undefined4 *)FUN_0040e2f1();
  *puVar2 = 0;
  puVar2 = (undefined4 *)FUN_0040e304();
  *puVar2 = 9;
LAB_00416d1e:
  FUN_0040e223();
  ExceptionList = local_14;
  return 0xffffffff;
}



void FUN_00416dd6(void)

{
  uint unaff_ESI;
  
  ___acrt_lowio_unlock_fh(unaff_ESI);
  return;
}



uint __cdecl FUN_00416dde(uint param_1,LPWSTR param_2,uint param_3)

{
  byte bVar1;
  undefined4 *puVar2;
  LPWSTR pWVar3;
  undefined3 extraout_var;
  BOOL BVar4;
  ulong uVar5;
  LPWSTR pWVar6;
  SIZE_T SVar7;
  SIZE_T nNumberOfBytesToRead;
  LPWSTR pWVar8;
  int iVar9;
  int iVar10;
  uint uVar11;
  undefined8 uVar12;
  DWORD local_28;
  LPWSTR local_24;
  uint local_20;
  uint local_1c;
  HANDLE local_18;
  int local_14;
  LPWSTR local_10;
  uint local_c;
  byte local_5;
  
  if (param_1 == 0xfffffffe) {
    puVar2 = (undefined4 *)FUN_0040e2f1();
    *puVar2 = 0;
    puVar2 = (undefined4 *)FUN_0040e304();
    *puVar2 = 9;
    return 0xffffffff;
  }
  if ((-1 < (int)param_1) && (param_1 < DAT_004242c8)) {
    local_c = param_1 >> 6;
    iVar9 = (param_1 & 0x3f) * 0x38;
    local_20 = 1;
    iVar10 = (&DAT_004240c8)[local_c];
    local_5 = *(byte *)(iVar9 + 0x28 + iVar10);
    local_14 = iVar9;
    if ((local_5 & 1) != 0) {
      if (param_3 < 0x80000000) {
        if ((param_3 == 0) || ((local_5 & 2) != 0)) {
          return 0;
        }
        if (param_2 != (LPWSTR)0x0) {
          local_18 = *(HANDLE *)(iVar9 + 0x18 + iVar10);
          local_5 = *(char *)(iVar9 + 0x29 + iVar10);
          if (local_5 == '\x01') {
            if ((~(byte)param_3 & 1) == 0) goto LAB_00416eac;
            SVar7 = 4;
            if (3 < param_3 >> 1) {
              SVar7 = param_3 >> 1;
            }
            pWVar3 = (LPWSTR)__malloc_base(SVar7);
            FUN_0040e374((LPVOID)0x0);
            FUN_0040e374((LPVOID)0x0);
            local_10 = pWVar3;
            if (pWVar3 != (LPWSTR)0x0) {
              uVar12 = FUN_004181d7(param_1,0,0,(PLARGE_INTEGER)0x1);
              iVar10 = (&DAT_004240c8)[local_c];
              *(int *)(iVar9 + 0x20 + iVar10) = (int)uVar12;
              *(int *)(iVar9 + 0x24 + iVar10) = (int)((ulonglong)uVar12 >> 0x20);
              pWVar8 = pWVar3;
              goto LAB_00416f45;
            }
            puVar2 = (undefined4 *)FUN_0040e304();
            *puVar2 = 0xc;
            puVar2 = (undefined4 *)FUN_0040e2f1();
            *puVar2 = 8;
          }
          else if ((local_5 == '\x02') && ((~(byte)param_3 & 1) == 0)) {
LAB_00416eac:
            puVar2 = (undefined4 *)FUN_0040e2f1();
            *puVar2 = 0;
            puVar2 = (undefined4 *)FUN_0040e304();
            *puVar2 = 0x16;
            FUN_0040e223();
            pWVar3 = (LPWSTR)0x0;
          }
          else {
            local_10 = param_2;
            pWVar3 = param_2;
            SVar7 = param_3;
            pWVar8 = (LPWSTR)0x0;
LAB_00416f45:
            iVar10 = 0;
            local_1c = (&DAT_004240c8)[local_c];
            nNumberOfBytesToRead = SVar7;
            pWVar6 = local_10;
            if ((((*(byte *)(local_14 + 0x28 + local_1c) & 0x48) != 0) &&
                (bVar1 = *(byte *)(local_14 + 0x2a + local_1c), bVar1 != 10)) && (SVar7 != 0)) {
              iVar10 = 1;
              *(byte *)local_10 = bVar1;
              pWVar6 = (LPWSTR)((int)local_10 + 1);
              nNumberOfBytesToRead = SVar7 - 1;
              *(undefined *)(local_14 + 0x2a + (&DAT_004240c8)[local_c]) = 10;
              if (((local_5 != '\0') &&
                  (bVar1 = *(byte *)(local_14 + 0x2b + (&DAT_004240c8)[local_c]), bVar1 != 10)) &&
                 (nNumberOfBytesToRead != 0)) {
                *(byte *)pWVar6 = bVar1;
                pWVar6 = local_10 + 1;
                nNumberOfBytesToRead = SVar7 - 2;
                iVar10 = 2;
                *(undefined *)(local_14 + 0x2b + (&DAT_004240c8)[local_c]) = 10;
                if (((local_5 == '\x01') &&
                    (bVar1 = *(byte *)(local_14 + 0x2c + (&DAT_004240c8)[local_c]), bVar1 != 10)) &&
                   (nNumberOfBytesToRead != 0)) {
                  *(byte *)pWVar6 = bVar1;
                  nNumberOfBytesToRead = SVar7 - 3;
                  iVar10 = 3;
                  *(undefined *)(local_14 + 0x2c + (&DAT_004240c8)[local_c]) = 10;
                  pWVar6 = (LPWSTR)((int)local_10 + 3);
                }
              }
            }
            local_10 = pWVar6;
            local_24 = pWVar3;
            bVar1 = FUN_004161ab(param_1);
            pWVar3 = pWVar8;
            if (((CONCAT31(extraout_var,bVar1) == 0) ||
                (-1 < *(char *)(local_14 + 0x28 + (&DAT_004240c8)[local_c]))) ||
               (BVar4 = GetConsoleMode(local_18,&local_28), pWVar6 = local_10, BVar4 == 0)) {
              local_20 = local_20 & 0xffffff00;
LAB_0041709e:
              pWVar6 = local_10;
              BVar4 = ReadFile(local_18,local_10,nNumberOfBytesToRead,&local_1c,(LPOVERLAPPED)0x0);
              if ((BVar4 != 0) && (uVar11 = local_1c, local_1c <= param_3)) {
LAB_004170c1:
                uVar11 = iVar10 + uVar11;
                if (*(char *)(local_14 + 0x28 + (&DAT_004240c8)[local_c]) < '\0') {
                  if (local_5 == '\x02') {
                    if ((char)local_20 == '\0') {
                      uVar11 = FUN_00416936(param_1,(ushort *)local_24,uVar11 >> 1);
                    }
                    else {
                      uVar11 = FUN_00416c47(param_1,local_24,uVar11 >> 1);
                    }
                  }
                  else {
                    uVar11 = FUN_00416af0(param_1,(byte *)pWVar6,uVar11,param_2,param_3 >> 1);
                  }
                }
                goto LAB_00417080;
              }
              uVar5 = GetLastError();
              if (uVar5 != 5) {
                if (uVar5 == 0x6d) {
                  uVar11 = 0;
                  goto LAB_00417080;
                }
                goto LAB_00417076;
              }
              puVar2 = (undefined4 *)FUN_0040e304();
              *puVar2 = 9;
              puVar2 = (undefined4 *)FUN_0040e2f1();
              *puVar2 = 5;
            }
            else {
              if (local_5 != '\x02') goto LAB_0041709e;
              BVar4 = ReadConsoleW(local_18,local_10,nNumberOfBytesToRead >> 1,&local_1c,
                                   (PCONSOLE_READCONSOLE_CONTROL)0x0);
              if (BVar4 != 0) {
                uVar11 = local_1c * 2;
                goto LAB_004170c1;
              }
              uVar5 = GetLastError();
LAB_00417076:
              ___acrt_errno_map_os_error(uVar5);
            }
          }
          uVar11 = 0xffffffff;
          pWVar8 = pWVar3;
LAB_00417080:
          FUN_0040e374(pWVar8);
          return uVar11;
        }
      }
      puVar2 = (undefined4 *)FUN_0040e2f1();
      *puVar2 = 0;
      puVar2 = (undefined4 *)FUN_0040e304();
      *puVar2 = 0x16;
      goto LAB_0041715d;
    }
  }
  puVar2 = (undefined4 *)FUN_0040e2f1();
  *puVar2 = 0;
  puVar2 = (undefined4 *)FUN_0040e304();
  *puVar2 = 9;
LAB_0041715d:
  FUN_0040e223();
  return 0xffffffff;
}



// Library Function - Single Match
//  _qsort
// 
// Library: Visual Studio 2019 Release

void __cdecl
_qsort(void *_Base,size_t _NumOfElements,size_t _SizeOfElements,_PtFuncCompare *_PtFuncCompare)

{
  undefined uVar1;
  undefined4 *puVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  undefined *puVar6;
  undefined *puVar7;
  undefined *puVar8;
  size_t sVar9;
  undefined *puVar10;
  undefined *puVar11;
  int local_11c;
  undefined *local_110;
  undefined *local_108;
  undefined *local_100;
  undefined4 auStack_f8 [30];
  undefined4 auStack_80 [30];
  uint local_8;
  
  local_8 = DAT_00423014 ^ (uint)&stack0xfffffffc;
  local_108 = (undefined *)_Base;
  if ((((_Base == (void *)0x0) && (_NumOfElements != 0)) || (_SizeOfElements == 0)) ||
     (_PtFuncCompare == (_PtFuncCompare *)0x0)) {
    puVar2 = (undefined4 *)FUN_0040e304();
    *puVar2 = 0x16;
    FUN_0040e223();
  }
  else {
    local_11c = 0;
    if (1 < _NumOfElements) {
      puVar6 = (undefined *)((_NumOfElements - 1) * _SizeOfElements + (int)_Base);
LAB_004171f2:
      while (uVar3 = (uint)((int)puVar6 - (int)local_108) / _SizeOfElements + 1, 8 < uVar3) {
        iVar4 = (uVar3 >> 1) * _SizeOfElements;
        puVar7 = local_108 + iVar4;
        puVar10 = local_108;
        puVar8 = puVar7;
        _guard_check_icall();
        iVar5 = (*_PtFuncCompare)(puVar10,puVar8);
        if ((0 < iVar5) && (sVar9 = _SizeOfElements, puVar10 = puVar7, local_108 != puVar7)) {
          do {
            uVar1 = puVar10[-iVar4];
            puVar10[-iVar4] = *puVar10;
            *puVar10 = uVar1;
            sVar9 = sVar9 - 1;
            puVar10 = puVar10 + 1;
          } while (sVar9 != 0);
        }
        puVar10 = local_108;
        puVar8 = puVar6;
        _guard_check_icall();
        iVar4 = (*_PtFuncCompare)(puVar10,puVar8);
        if ((0 < iVar4) && (sVar9 = _SizeOfElements, puVar10 = puVar6, local_108 != puVar6)) {
          do {
            puVar8 = puVar10 + 1;
            uVar1 = puVar8[(int)(local_108 + (-1 - (int)puVar6))];
            puVar8[(int)(local_108 + (-1 - (int)puVar6))] = *puVar10;
            *puVar10 = uVar1;
            sVar9 = sVar9 - 1;
            puVar10 = puVar8;
          } while (sVar9 != 0);
        }
        puVar10 = puVar7;
        puVar8 = puVar6;
        _guard_check_icall();
        iVar4 = (*_PtFuncCompare)(puVar10,puVar8);
        local_110 = local_108;
        local_100 = puVar6;
        if ((0 < iVar4) && (sVar9 = _SizeOfElements, puVar10 = puVar6, puVar7 != puVar6)) {
          do {
            puVar8 = puVar10 + 1;
            uVar1 = puVar8[(int)(puVar7 + (-1 - (int)puVar6))];
            puVar8[(int)(puVar7 + (-1 - (int)puVar6))] = *puVar10;
            *puVar10 = uVar1;
            sVar9 = sVar9 - 1;
            puVar10 = puVar8;
          } while (sVar9 != 0);
        }
LAB_00417403:
        if (local_110 < puVar7) {
          do {
            local_110 = local_110 + _SizeOfElements;
            if (puVar7 <= local_110) goto LAB_00417450;
            puVar10 = local_110;
            puVar8 = puVar7;
            _guard_check_icall();
            iVar4 = (*_PtFuncCompare)(puVar10,puVar8);
            puVar10 = local_100;
          } while (iVar4 < 1);
        }
        else {
LAB_00417450:
          do {
            local_110 = local_110 + _SizeOfElements;
            puVar10 = local_100;
            if (puVar6 < local_110) break;
            puVar10 = local_110;
            puVar8 = puVar7;
            _guard_check_icall();
            iVar4 = (*_PtFuncCompare)(puVar10,puVar8);
            puVar10 = local_100;
          } while (iVar4 < 1);
        }
        do {
          local_100 = puVar10;
          puVar10 = local_100 + -_SizeOfElements;
          if (puVar10 <= puVar7) break;
          puVar8 = puVar10;
          puVar11 = puVar7;
          _guard_check_icall();
          iVar4 = (*_PtFuncCompare)(puVar8,puVar11);
        } while (0 < iVar4);
        if (local_110 <= puVar10) {
          puVar8 = puVar10;
          sVar9 = _SizeOfElements;
          if (puVar10 != local_110) {
            do {
              puVar11 = puVar8 + 1;
              uVar1 = puVar11[(int)(local_110 + (-1 - (int)puVar10))];
              puVar11[(int)(local_110 + (-1 - (int)puVar10))] = *puVar8;
              *puVar8 = uVar1;
              sVar9 = sVar9 - 1;
              puVar8 = puVar11;
            } while (sVar9 != 0);
          }
          local_100 = puVar10;
          if (puVar7 == puVar10) {
            puVar7 = local_110;
          }
          goto LAB_00417403;
        }
        if (puVar7 < local_100) {
          do {
            local_100 = local_100 + -_SizeOfElements;
            if (local_100 <= puVar7) goto LAB_00417570;
            puVar10 = local_100;
            puVar8 = puVar7;
            _guard_check_icall();
            iVar4 = (*_PtFuncCompare)(puVar10,puVar8);
          } while (iVar4 == 0);
        }
        else {
LAB_00417570:
          do {
            local_100 = local_100 + -_SizeOfElements;
            if (local_100 <= local_108) break;
            puVar10 = local_100;
            puVar8 = puVar7;
            _guard_check_icall();
            iVar4 = (*_PtFuncCompare)(puVar10,puVar8);
          } while (iVar4 == 0);
        }
        if ((int)local_100 - (int)local_108 < (int)puVar6 - (int)local_110) goto LAB_004175fa;
        if (local_108 < local_100) {
          auStack_80[local_11c] = local_108;
          auStack_f8[local_11c] = local_100;
          local_11c = local_11c + 1;
        }
        local_108 = local_110;
        if (puVar6 <= local_110) goto LAB_00417633;
      }
      for (; puVar10 = local_108, puVar7 = local_108, local_108 < puVar6;
          puVar6 = puVar6 + -_SizeOfElements) {
        while (puVar7 = puVar7 + _SizeOfElements, puVar7 <= puVar6) {
          puVar8 = puVar7;
          puVar11 = puVar10;
          _guard_check_icall();
          iVar4 = (*_PtFuncCompare)(puVar8,puVar11);
          if (0 < iVar4) {
            puVar10 = puVar7;
          }
        }
        if (puVar10 != puVar6) {
          puVar7 = puVar6;
          sVar9 = _SizeOfElements;
          do {
            uVar1 = puVar7[(int)puVar10 - (int)puVar6];
            (puVar7 + 1)[((int)puVar10 - (int)puVar6) + -1] = *puVar7;
            *puVar7 = uVar1;
            sVar9 = sVar9 - 1;
            puVar7 = puVar7 + 1;
          } while (sVar9 != 0);
        }
      }
      goto LAB_00417633;
    }
  }
LAB_004171be:
  FUN_00402125(local_8 ^ (uint)&stack0xfffffffc);
  return;
LAB_004175fa:
  if (local_110 < puVar6) {
    auStack_80[local_11c] = local_110;
    auStack_f8[local_11c] = puVar6;
    local_11c = local_11c + 1;
  }
  puVar6 = local_100;
  if (local_100 <= local_108) {
LAB_00417633:
    local_11c = local_11c + -1;
    if (-1 < local_11c) {
      local_108 = (undefined *)auStack_80[local_11c];
      puVar6 = (undefined *)auStack_f8[local_11c];
      goto LAB_004171f2;
    }
    goto LAB_004171be;
  }
  goto LAB_004171f2;
}



undefined4 __cdecl FUN_0041765e(char *param_1,int param_2,int param_3,int param_4)

{
  char cVar1;
  undefined4 *puVar2;
  char *pcVar3;
  int iVar4;
  undefined4 uStack_18;
  int local_8;
  
  if (param_4 == 0) {
    if (param_1 == (char *)0x0) {
      if (param_2 == 0) {
        return 0;
      }
    }
    else {
LAB_00417697:
      if (param_2 != 0) {
        if (param_4 == 0) {
          *param_1 = '\0';
          return 0;
        }
        if (param_3 != 0) {
          local_8 = param_4;
          pcVar3 = param_1;
          iVar4 = param_2;
          if (param_4 == -1) {
            do {
              cVar1 = pcVar3[param_3 - (int)param_1];
              *pcVar3 = cVar1;
              pcVar3 = pcVar3 + 1;
              if (cVar1 == '\0') {
                return 0;
              }
              iVar4 = iVar4 + -1;
            } while (iVar4 != 0);
            iVar4 = 0;
          }
          else {
            do {
              cVar1 = pcVar3[param_3 - (int)param_1];
              *pcVar3 = cVar1;
              pcVar3 = pcVar3 + 1;
              if (cVar1 == '\0') {
                return 0;
              }
              iVar4 = iVar4 + -1;
            } while ((iVar4 != 0) && (local_8 = local_8 + -1, local_8 != 0));
            if (local_8 == 0) {
              *pcVar3 = '\0';
            }
          }
          if (iVar4 != 0) {
            return 0;
          }
          if (param_4 == -1) {
            param_1[param_2 + -1] = '\0';
            return 0x50;
          }
          *param_1 = '\0';
          puVar2 = (undefined4 *)FUN_0040e304();
          uStack_18 = 0x22;
          goto LAB_00417684;
        }
        *param_1 = '\0';
      }
    }
  }
  else if (param_1 != (char *)0x0) goto LAB_00417697;
  puVar2 = (undefined4 *)FUN_0040e304();
  uStack_18 = 0x16;
LAB_00417684:
  *puVar2 = uStack_18;
  FUN_0040e223();
  return uStack_18;
}



void __cdecl FUN_00417715(char *param_1,int param_2,int param_3,int param_4)

{
  FUN_0041765e(param_1,param_2,param_3,param_4);
  return;
}



// Library Function - Single Match
//  _strpbrk
// 
// Library: Visual Studio

char * __cdecl _strpbrk(char *_Str,char *_Control)

{
  byte bVar1;
  byte *pbVar2;
  undefined4 uStack_28;
  undefined4 uStack_24;
  undefined4 uStack_20;
  undefined4 uStack_1c;
  undefined4 uStack_18;
  undefined4 uStack_14;
  undefined4 uStack_10;
  undefined4 uStack_c;
  
  uStack_c = 0;
  uStack_10 = 0;
  uStack_14 = 0;
  uStack_18 = 0;
  uStack_1c = 0;
  uStack_20 = 0;
  uStack_24 = 0;
  uStack_28 = 0;
  while( true ) {
    bVar1 = *_Control;
    if (bVar1 == 0) break;
    _Control = (char *)((byte *)_Control + 1);
    pbVar2 = (byte *)((int)&uStack_28 + ((int)(uint)bVar1 >> 3));
    *pbVar2 = *pbVar2 | '\x01' << (bVar1 & 7);
  }
  do {
    pbVar2 = (byte *)_Str;
    bVar1 = *pbVar2;
    if (bVar1 == 0) {
      return (char *)(uint)bVar1;
    }
    _Str = (char *)(pbVar2 + 1);
  } while ((*(byte *)((int)&uStack_28 + ((int)(char *)(uint)bVar1 >> 3)) >> (bVar1 & 7) & 1) == 0);
  return (char *)pbVar2;
}



// Library Function - Single Match
//  __mbsdec
// 
// Library: Visual Studio 2019 Release

uchar * __cdecl __mbsdec(uchar *_Start,uchar *_Pos)

{
  uchar *puVar1;
  
  puVar1 = __mbsdec_l(_Start,_Pos,(_locale_t)0x0);
  return puVar1;
}



// Library Function - Single Match
//  __mbsdec_l
// 
// Library: Visual Studio 2019 Release

uchar * __cdecl __mbsdec_l(uchar *_Start,uchar *_Pos,_locale_t _Locale)

{
  undefined4 *puVar1;
  byte *pbVar2;
  int local_14 [2];
  int local_c;
  char local_8;
  
  if (_Start == (uchar *)0x0) {
    puVar1 = (undefined4 *)FUN_0040e304();
    *puVar1 = 0x16;
    FUN_0040e223();
    return (uchar *)0x0;
  }
  if (_Pos == (uchar *)0x0) {
    puVar1 = (undefined4 *)FUN_0040e304();
    *puVar1 = 0x16;
    FUN_0040e223();
  }
  else if (_Start < _Pos) {
    FUN_00408ded(local_14,(__acrt_ptd **)_Locale);
    pbVar2 = _Pos + -1;
    if (*(int *)(local_c + 8) != 0) {
      do {
        pbVar2 = pbVar2 + -1;
        if (pbVar2 < _Start) break;
      } while ((*(byte *)(*pbVar2 + 0x19 + local_c) & 4) != 0);
      pbVar2 = _Pos + (-1 - ((int)_Pos - (int)pbVar2 & 1U));
    }
    if (local_8 == '\0') {
      return pbVar2;
    }
    *(uint *)(local_14[0] + 0x350) = *(uint *)(local_14[0] + 0x350) & 0xfffffffd;
    return pbVar2;
  }
  return (uchar *)0x0;
}



// WARNING: Function: __alloca_probe_16 replaced with injection: alloca_probe

void __cdecl
FUN_00417804(int *param_1,wchar_t *param_2,uint param_3,char *param_4,int param_5,wchar_t *param_6,
            int param_7,uint param_8,int param_9)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  undefined4 *puVar4;
  int iVar5;
  undefined4 *puVar6;
  undefined4 *puVar7;
  
  uVar1 = DAT_00423014 ^ (uint)&stack0xfffffffc;
  iVar5 = param_5;
  if (0 < param_5) {
    iVar2 = ___strncnt(param_4,param_5);
    iVar5 = iVar2 + 1;
    if (param_5 <= iVar2) {
      iVar5 = iVar2;
    }
  }
  if (param_8 == 0) {
    param_8 = *(uint *)(*param_1 + 8);
  }
  iVar2 = FUN_00411ea3(param_8,(uint)(param_9 != 0) * 8 + 1,param_4,iVar5,(LPWSTR)0x0,0);
  if (iVar2 == 0) goto LAB_004179e1;
  uVar3 = iVar2 * 2 + 8;
  uVar3 = -(uint)((uint)(iVar2 * 2) < uVar3) & uVar3;
  if (uVar3 == 0) {
    puVar4 = (undefined4 *)0x0;
  }
  else if (uVar3 < 0x401) {
    puVar6 = (undefined4 *)&stack0xffffffe8;
    puVar4 = (undefined4 *)&stack0xffffffe8;
    if (&stack0x00000000 != (undefined *)0x18) {
LAB_004178b7:
      puVar4 = puVar6 + 2;
      if (((puVar4 != (undefined4 *)0x0) &&
          (iVar5 = FUN_00411ea3(param_8,1,param_4,iVar5,(LPWSTR)puVar4,iVar2), iVar5 != 0)) &&
         (iVar5 = FID_conflict____acrt_CompareStringEx_36
                            (param_2,param_3,(wchar_t *)puVar4,iVar2,(wchar_t *)0x0,0,
                             (_nlsversioninfo *)0x0,(void *)0x0,0), iVar5 != 0)) {
        if ((param_3 & 0x400) == 0) {
          uVar3 = iVar5 * 2 + 8;
          uVar3 = -(uint)((uint)(iVar5 * 2) < uVar3) & uVar3;
          if (uVar3 == 0) {
            puVar6 = (undefined4 *)0x0;
          }
          else if (uVar3 < 0x401) {
            puVar7 = (undefined4 *)&stack0xffffffe8;
            puVar6 = (undefined4 *)&stack0xffffffe8;
            if (&stack0x00000000 != (undefined *)0x18) {
LAB_00417978:
              puVar6 = puVar7 + 2;
              if ((puVar6 != (undefined4 *)0x0) &&
                 (iVar2 = FID_conflict____acrt_CompareStringEx_36
                                    (param_2,param_3,(wchar_t *)puVar4,iVar2,(wchar_t *)puVar6,iVar5
                                     ,(_nlsversioninfo *)0x0,(void *)0x0,0), iVar2 != 0)) {
                if (param_7 == 0) {
                  param_7 = 0;
                  param_6 = (wchar_t *)0x0;
                }
                iVar5 = FUN_00411f5d(param_8,0,(LPCWSTR)puVar6,iVar5,(LPSTR)param_6,param_7,0,
                                     (undefined4 *)0x0);
                if (iVar5 != 0) {
                  FUN_00412a40((int)puVar6);
                  goto LAB_004179d8;
                }
              }
            }
          }
          else {
            puVar6 = (undefined4 *)__malloc_base(uVar3);
            if (puVar6 != (undefined4 *)0x0) {
              *puVar6 = 0xdddd;
              puVar7 = puVar6;
              goto LAB_00417978;
            }
          }
          FUN_00412a40((int)puVar6);
        }
        else if ((param_7 != 0) && (iVar5 <= param_7)) {
          FID_conflict____acrt_CompareStringEx_36
                    (param_2,param_3,(wchar_t *)puVar4,iVar2,param_6,param_7,(_nlsversioninfo *)0x0,
                     (void *)0x0,0);
        }
      }
    }
  }
  else {
    puVar4 = (undefined4 *)__malloc_base(uVar3);
    if (puVar4 != (undefined4 *)0x0) {
      *puVar4 = 0xdddd;
      puVar6 = puVar4;
      goto LAB_004178b7;
    }
  }
LAB_004179d8:
  FUN_00412a40((int)puVar4);
LAB_004179e1:
  FUN_00402125(uVar1 ^ (uint)&stack0xfffffffc);
  return;
}



// Library Function - Single Match
//  ___acrt_LCMapStringA
// 
// Library: Visual Studio 2019 Release

void __cdecl
___acrt_LCMapStringA
          (__acrt_ptd **param_1,wchar_t *param_2,uint param_3,char *param_4,int param_5,
          wchar_t *param_6,int param_7,uint param_8,int param_9)

{
  int local_14;
  int local_10 [2];
  char local_8;
  
  FUN_00408ded(&local_14,param_1);
  FUN_00417804(local_10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
  if (local_8 != '\0') {
    *(uint *)(local_14 + 0x350) = *(uint *)(local_14 + 0x350) & 0xfffffffd;
  }
  return;
}



// Library Function - Single Match
//  __strnicoll
// 
// Library: Visual Studio 2019 Release

int __cdecl __strnicoll(char *_Str1,char *_Str2,size_t _MaxCount)

{
  int iVar1;
  
  if (DAT_00423e60 == 0) {
    iVar1 = __strnicmp(_Str1,_Str2,_MaxCount);
    return iVar1;
  }
  iVar1 = __strnicoll_l(_Str1,_Str2,_MaxCount,(_locale_t)0x0);
  return iVar1;
}



// Library Function - Single Match
//  __strnicoll_l
// 
// Library: Visual Studio 2019 Release

int __cdecl __strnicoll_l(char *_Str1,char *_Str2,size_t _MaxCount,_locale_t _Locale)

{
  undefined4 *puVar1;
  int iVar2;
  int iVar3;
  int local_14;
  __acrt_ptd *local_10 [2];
  char local_8;
  
  FUN_00408ded(&local_14,(__acrt_ptd **)_Locale);
  if (_MaxCount == 0) {
    iVar3 = 0;
  }
  else if ((_Str1 == (char *)0x0) || (_Str2 == (char *)0x0)) {
    puVar1 = (undefined4 *)FUN_0040e304();
    *puVar1 = 0x16;
    FUN_0040e223();
    iVar3 = 0x7fffffff;
  }
  else {
    iVar3 = 0x7fffffff;
    if (_MaxCount < 0x80000000) {
      if (*(wchar_t **)(local_10[0] + 0xa4) == (wchar_t *)0x0) {
        iVar3 = FUN_004187bd((byte *)_Str1,(byte *)_Str2,_MaxCount,local_10);
      }
      else {
        iVar2 = ___acrt_CompareStringA
                          (local_10,*(wchar_t **)(local_10[0] + 0xa4),0x1001,(byte *)_Str1,_MaxCount
                           ,(byte *)_Str2,_MaxCount,*(uint *)(local_10[0] + 0x10));
        if (iVar2 == 0) {
          puVar1 = (undefined4 *)FUN_0040e304();
          *puVar1 = 0x16;
        }
        else {
          iVar3 = iVar2 + -2;
        }
      }
    }
    else {
      puVar1 = (undefined4 *)FUN_0040e304();
      *puVar1 = 0x16;
      FUN_0040e223();
    }
  }
  if (local_8 != '\0') {
    *(uint *)(local_14 + 0x350) = *(uint *)(local_14 + 0x350) & 0xfffffffd;
  }
  return iVar3;
}



// Library Function - Single Match
//  ___acrt_SetEnvironmentVariableA
// 
// Library: Visual Studio 2019 Release

BOOL __cdecl ___acrt_SetEnvironmentVariableA(char *param_1,char *param_2)

{
  uint uVar1;
  int iVar2;
  BOOL BVar3;
  LPCWSTR pWVar4;
  undefined4 local_34;
  undefined4 local_30;
  LPCWSTR local_2c;
  undefined4 local_28;
  undefined4 local_24;
  char local_20;
  undefined4 local_1c;
  undefined4 local_18;
  LPCWSTR local_14;
  undefined4 local_10;
  undefined4 local_c;
  char local_8;
  
  BVar3 = 0;
  pWVar4 = (LPCWSTR)0x0;
  local_34 = 0;
  local_30 = 0;
  local_2c = (LPCWSTR)0x0;
  local_28 = 0;
  local_24 = 0;
  local_20 = '\0';
  local_1c = 0;
  local_18 = 0;
  local_14 = (LPCWSTR)0x0;
  local_10 = 0;
  local_c = 0;
  local_8 = '\0';
  uVar1 = __acrt_get_utf8_acp_compatibility_codepage();
  iVar2 = __acrt_mbs_to_wcs_cp<>(param_1,(__crt_win32_buffer<> *)&local_34,uVar1);
  if (iVar2 == 0) {
    uVar1 = __acrt_get_utf8_acp_compatibility_codepage();
    iVar2 = __acrt_mbs_to_wcs_cp<>(param_2,(__crt_win32_buffer<> *)&local_1c,uVar1);
    pWVar4 = local_14;
    if (iVar2 == 0) {
      BVar3 = SetEnvironmentVariableW(local_2c,local_14);
    }
  }
  if (local_8 != '\0') {
    FUN_0040e374(pWVar4);
  }
  if (local_20 != '\0') {
    FUN_0040e374(local_2c);
  }
  return BVar3;
}



int __cdecl FUN_00417bd1(ushort *param_1,ushort *param_2,int param_3)

{
  uint uVar1;
  uint uVar2;
  
  if (param_3 != 0) {
    do {
      uVar1 = (uint)*param_1;
      param_1 = param_1 + 1;
      if (uVar1 - 0x41 < 0x1a) {
        uVar1 = uVar1 + 0x20;
      }
      uVar2 = (uint)*param_2;
      param_2 = param_2 + 1;
      if (uVar2 - 0x41 < 0x1a) {
        uVar2 = uVar2 + 0x20;
      }
    } while (((uVar1 - uVar2 == 0) && (uVar1 != 0)) && (param_3 = param_3 + -1, param_3 != 0));
    return uVar1 - uVar2;
  }
  return 0;
}



// Library Function - Multiple Matches With Different Base Names
//  __msize
//  __msize_base
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

size_t __cdecl FID_conflict___msize_base(void *_Memory)

{
  undefined4 *puVar1;
  SIZE_T SVar2;
  
  if (_Memory == (void *)0x0) {
    puVar1 = (undefined4 *)FUN_0040e304();
    *puVar1 = 0x16;
    FUN_0040e223();
    return 0xffffffff;
  }
  SVar2 = HeapSize(DAT_00424304,0,_Memory);
  return SVar2;
}



// Library Function - Single Match
//  __realloc_base
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

LPVOID __cdecl __realloc_base(LPVOID param_1,uint param_2)

{
  bool bVar1;
  LPVOID pvVar2;
  undefined4 *puVar3;
  int iVar4;
  undefined3 extraout_var;
  
  if (param_1 == (LPVOID)0x0) {
    pvVar2 = __malloc_base(param_2);
  }
  else {
    if (param_2 == 0) {
      FUN_0040e374(param_1);
    }
    else {
      if (param_2 < 0xffffffe1) {
        do {
          pvVar2 = HeapReAlloc(DAT_00424304,0,param_1,param_2);
          if (pvVar2 != (LPVOID)0x0) {
            return pvVar2;
          }
          iVar4 = FUN_0040d599();
        } while ((iVar4 != 0) && (bVar1 = FUN_00412f2a(param_2), CONCAT31(extraout_var,bVar1) != 0))
        ;
      }
      puVar3 = (undefined4 *)FUN_0040e304();
      *puVar3 = 0xc;
    }
    pvVar2 = (LPVOID)0x0;
  }
  return pvVar2;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4
// Library Function - Single Match
//  ___set_fpsr_sse2
// 
// Library: Visual Studio 2019 Release

void __cdecl ___set_fpsr_sse2(uint param_1)

{
  void *local_14;
  
  if (0 < DAT_0042393c) {
    if (((param_1 & 0x40) == 0) || (DAT_00423880 == 0)) {
      MXCSR = param_1 & 0xffffffbf;
    }
    else {
      MXCSR = param_1;
    }
  }
  ExceptionList = local_14;
  return;
}



int FUN_00417d3c(void)

{
  short in_FPUStatusWord;
  
  return (int)in_FPUStatusWord;
}



// Library Function - Single Match
//  __ctrlfp
// 
// Library: Visual Studio 2019 Release

int __ctrlfp(undefined4 param_1,undefined4 param_2)

{
  short in_FPUControlWord;
  
  return (int)in_FPUControlWord;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00417d77(uint param_1)

{
  return;
}



int FUN_00417dd0(void)

{
  short in_FPUStatusWord;
  
  return (int)in_FPUStatusWord;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4

undefined4 FUN_00417de0(uint *param_1,uint **param_2)

{
  uint uVar1;
  uint *puVar2;
  undefined4 uVar3;
  void *local_14;
  
  FUN_00412578(*param_1);
  uVar1 = **param_2;
  puVar2 = param_2[1];
  if ((*(byte *)((&DAT_004240c8)[(int)uVar1 >> 6] + 0x28 + (uVar1 & 0x3f) * 0x38) & 1) == 0) {
    *(undefined *)(puVar2 + 7) = 1;
    puVar2[6] = 9;
    uVar3 = 0xffffffff;
  }
  else {
    uVar3 = FUN_00417f14(uVar1,(int)puVar2);
  }
  FUN_00417e65();
  ExceptionList = local_14;
  return uVar3;
}



void FUN_00417e65(void)

{
  int unaff_EBP;
  
  ___acrt_lowio_unlock_fh(**(uint **)(unaff_EBP + 0x10));
  return;
}



undefined4 __cdecl FUN_00417e71(uint param_1,__acrt_ptd **param_2)

{
  undefined4 uVar1;
  uint *local_18;
  __acrt_ptd **local_14;
  uint local_10;
  uint local_c;
  
  if (param_1 == 0xfffffffe) {
    param_2[8] = (__acrt_ptd *)0x0;
    *(undefined *)(param_2 + 9) = 1;
    *(undefined *)(param_2 + 7) = 1;
    param_2[6] = (__acrt_ptd *)0x9;
  }
  else {
    if (((-1 < (int)param_1) && (param_1 < DAT_004242c8)) &&
       ((*(byte *)((&DAT_004240c8)[(int)param_1 >> 6] + 0x28 + (param_1 & 0x3f) * 0x38) & 1) != 0))
    {
      local_18 = &param_1;
      local_c = param_1;
      local_14 = param_2;
      local_10 = param_1;
      uVar1 = FUN_00417de0(&local_10,&local_18);
      return uVar1;
    }
    *(undefined *)(param_2 + 9) = 1;
    param_2[8] = (__acrt_ptd *)0x0;
    *(undefined *)(param_2 + 7) = 1;
    param_2[6] = (__acrt_ptd *)0x9;
    FUN_0040e1a6((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0,param_2);
  }
  return 0xffffffff;
}



undefined4 __cdecl FUN_00417f14(uint param_1,int param_2)

{
  int iVar1;
  int iVar2;
  HANDLE hObject;
  BOOL BVar3;
  undefined4 uVar4;
  DWORD DVar5;
  
  iVar1 = FUN_0041264f(param_1);
  if (iVar1 != -1) {
    if (((param_1 == 1) && ((*(byte *)(DAT_004240c8 + 0x98) & 1) != 0)) ||
       ((param_1 == 2 && ((*(byte *)(DAT_004240c8 + 0x60) & 1) != 0)))) {
      iVar1 = FUN_0041264f(2);
      iVar2 = FUN_0041264f(1);
      if (iVar2 == iVar1) goto LAB_00417f2a;
    }
    hObject = (HANDLE)FUN_0041264f(param_1);
    BVar3 = CloseHandle(hObject);
    if (BVar3 == 0) {
      DVar5 = GetLastError();
      goto LAB_00417f7c;
    }
  }
LAB_00417f2a:
  DVar5 = 0;
LAB_00417f7c:
  FUN_004125be(param_1);
  *(undefined *)((&DAT_004240c8)[(int)param_1 >> 6] + 0x28 + (param_1 & 0x3f) * 0x38) = 0;
  if (DVar5 == 0) {
    uVar4 = 0;
  }
  else {
    FUN_0040e2cd(DVar5,param_2);
    uVar4 = 0xffffffff;
  }
  return uVar4;
}



// Library Function - Single Match
//  void __cdecl __acrt_stdio_free_stream(class __crt_stdio_stream)
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void __cdecl __acrt_stdio_free_stream(__crt_stdio_stream param_1)

{
  undefined3 in_stack_00000005;
  
  *_param_1 = 0;
  _param_1[1] = 0;
  _param_1[2] = 0;
  _param_1[4] = 0xffffffff;
  _param_1[5] = 0;
  _param_1[6] = 0;
  _param_1[7] = 0;
  LOCK();
  _param_1[3] = 0;
  UNLOCK();
  return;
}



// WARNING: Function: __SEH_prolog4 replaced with injection: SEH_prolog4

undefined8 __cdecl
FUN_00417fef(uint param_1,undefined4 param_2,undefined4 param_3,PLARGE_INTEGER param_4,
            __acrt_ptd **param_5)

{
  bool bVar1;
  int iVar2;
  undefined8 uVar3;
  void *local_14;
  
  if (param_1 == 0xfffffffe) {
    *(undefined *)(param_5 + 9) = 1;
    param_5[8] = (__acrt_ptd *)0x0;
    *(undefined *)(param_5 + 7) = 1;
    param_5[6] = (__acrt_ptd *)0x9;
  }
  else {
    if (((int)param_1 < 0) || (DAT_004242c8 <= param_1)) {
      bVar1 = false;
    }
    else {
      bVar1 = true;
    }
    if (bVar1) {
      iVar2 = (param_1 & 0x3f) * 0x38;
      if ((*(byte *)((&DAT_004240c8)[(int)param_1 >> 6] + 0x28 + iVar2) & 1) != 0) {
        FUN_00412578(param_1);
        if ((*(byte *)(iVar2 + 0x28 + (&DAT_004240c8)[(int)param_1 >> 6]) & 1) == 0) {
          *(undefined *)(param_5 + 7) = 1;
          param_5[6] = (__acrt_ptd *)0x9;
          *(undefined *)(param_5 + 9) = 1;
          param_5[8] = (__acrt_ptd *)0x0;
          uVar3 = 0xffffffffffffffff;
        }
        else {
          uVar3 = FUN_00418114(param_1,param_2,param_3,param_4,(int)param_5);
        }
        FUN_0041810c();
        ExceptionList = local_14;
        return uVar3;
      }
    }
    *(undefined *)(param_5 + 9) = 1;
    param_5[8] = (__acrt_ptd *)0x0;
    *(undefined *)(param_5 + 7) = 1;
    param_5[6] = (__acrt_ptd *)0x9;
    FUN_0040e1a6((wchar_t *)0x0,(wchar_t *)0x0,(wchar_t *)0x0,0,0,param_5);
  }
  ExceptionList = local_14;
  return 0xffffffffffffffff;
}



void FUN_0041810c(void)

{
  uint unaff_EBX;
  
  ___acrt_lowio_unlock_fh(unaff_EBX);
  return;
}



undefined8 __cdecl
FUN_00418114(uint param_1,undefined4 param_2,undefined4 param_3,PLARGE_INTEGER param_4,int param_5)

{
  byte *pbVar1;
  LARGE_INTEGER liDistanceToMove;
  HANDLE hFile;
  BOOL BVar2;
  DWORD DVar3;
  DWORD unaff_EDI;
  uint local_c;
  uint local_8;
  
  hFile = (HANDLE)FUN_0041264f(param_1);
  if (hFile == (HANDLE)0xffffffff) {
    *(undefined *)(param_5 + 0x1c) = 1;
    *(undefined4 *)(param_5 + 0x18) = 9;
  }
  else {
    liDistanceToMove.s.HighPart = (LONG)&local_c;
    liDistanceToMove.s.LowPart = param_3;
    BVar2 = SetFilePointerEx(hFile,liDistanceToMove,param_4,unaff_EDI);
    if (BVar2 == 0) {
      DVar3 = GetLastError();
      FUN_0040e2cd(DVar3,param_5);
    }
    else if ((local_c & local_8) != 0xffffffff) {
      pbVar1 = (byte *)((&DAT_004240c8)[(int)param_1 >> 6] + 0x28 + (param_1 & 0x3f) * 0x38);
      *pbVar1 = *pbVar1 & 0xfd;
      goto LAB_00418193;
    }
  }
  local_c = 0xffffffff;
  local_8 = 0xffffffff;
LAB_00418193:
  return CONCAT44(local_8,local_c);
}



undefined8 __cdecl
FUN_00418197(uint param_1,undefined4 param_2,undefined4 param_3,PLARGE_INTEGER param_4)

{
  undefined8 uVar1;
  __acrt_ptd *local_2c [10];
  
  FUN_004055d0(local_2c,(undefined4 *)0x0);
  uVar1 = FUN_00417fef(param_1,param_2,param_3,param_4,local_2c);
  FUN_00405630(local_2c);
  return uVar1;
}



undefined8 __cdecl
FUN_004181d7(uint param_1,undefined4 param_2,undefined4 param_3,PLARGE_INTEGER param_4)

{
  undefined8 uVar1;
  __acrt_ptd *local_2c [10];
  
  FUN_004055d0(local_2c,(undefined4 *)0x0);
  uVar1 = FUN_00418114(param_1,param_2,param_3,param_4,(int)local_2c);
  FUN_00405630(local_2c);
  return uVar1;
}



undefined8 __cdecl
FUN_00418217(uint param_1,undefined4 param_2,undefined4 param_3,PLARGE_INTEGER param_4,int param_5)

{
  undefined8 uVar1;
  
  uVar1 = FUN_00418114(param_1,param_2,param_3,param_4,param_5);
  return uVar1;
}



// Library Function - Single Match
//  __putwch_nolock
// 
// Library: Visual Studio 2019 Release

wint_t __cdecl __putwch_nolock(wchar_t _WCh)

{
  bool bVar1;
  undefined3 extraout_var;
  BOOL BVar2;
  DWORD local_8;
  
  bVar1 = ___dcrt_lowio_ensure_console_output_initialized();
  if (CONCAT31(extraout_var,bVar1) != 0) {
    BVar2 = ___dcrt_write_console(&_WCh,1,&local_8);
    if (BVar2 != 0) {
      return _WCh;
    }
  }
  return 0xffff;
}



// Library Function - Single Match
//  _fegetenv
// 
// Library: Visual Studio 2019 Release

undefined4 __cdecl _fegetenv(uint *param_1)

{
  uint uVar1;
  
  uVar1 = ___acrt_fenv_get_control();
  *param_1 = uVar1;
  uVar1 = FUN_004165c8();
  param_1[1] = uVar1;
  return 0;
}



bool __cdecl FUN_00418284(uint *param_1)

{
  int iVar1;
  bool bVar2;
  uint local_c;
  uint local_8;
  
  FUN_00416672(*param_1);
  FUN_004166ed(param_1[1]);
  local_c = 0;
  local_8 = 0;
  iVar1 = _fegetenv(&local_c);
  if ((iVar1 == 0) && (*param_1 == local_c)) {
    bVar2 = param_1[1] != local_8;
  }
  else {
    bVar2 = true;
  }
  return bVar2;
}



undefined4 __cdecl FUN_004182d0(uint *param_1)

{
  bool bVar1;
  int iVar2;
  undefined3 extraout_var;
  uint local_c;
  uint local_8;
  
  local_c = 0;
  local_8 = 0;
  iVar2 = _fegetenv(&local_c);
  if (iVar2 == 0) {
    *param_1 = local_c;
    local_c = local_c | 0x1f;
    param_1[1] = local_8;
    bVar1 = FUN_00418284(&local_c);
    if (CONCAT31(extraout_var,bVar1) == 0) {
      __clearfp();
      return 0;
    }
  }
  return 1;
}



void FUN_00418320(void)

{
  undefined4 extraout_ECX;
  undefined4 extraout_EDX;
  bool bVar1;
  ushort in_FPUControlWord;
  float10 in_ST0;
  double dVar2;
  uint in_stack_fffffffc;
  
  if (DAT_00424558 != 0) {
    bVar1 = (MXCSR & 0x7f80) == 0x1f80;
    if (bVar1) {
      bVar1 = (in_FPUControlWord & 0x7f) == 0x7f;
    }
    in_stack_fffffffc = MXCSR;
    if (bVar1) {
      __CIlog10_pentium4();
      return;
    }
  }
  dVar2 = (double)in_ST0;
  FUN_004193b8(SUB84(dVar2,0),(uint)((ulonglong)dVar2 >> 0x20));
  FUN_00418378(extraout_ECX,extraout_EDX,SUB84(dVar2,0),(float10 *)((ulonglong)dVar2 >> 0x20),
               in_stack_fffffffc);
  return;
}



float10 * __fastcall
FUN_00418378(undefined4 param_1,undefined4 param_2,int param_3,float10 *param_4,undefined4 param_5)

{
  float10 *pfVar1;
  uint in_EAX;
  float10 *pfVar2;
  bool in_ZF;
  undefined2 in_FPUControlWord;
  ushort unaff_retaddr;
  int iVar3;
  
  iVar3 = CONCAT22((short)((uint)param_2 >> 0x10),in_FPUControlWord);
  if (in_ZF) {
    if (((in_EAX & 0xfffff) != 0) || (param_3 != 0)) {
      pfVar2 = (float10 *)FUN_0041935c();
      goto LAB_00418411;
    }
    pfVar2 = (float10 *)(in_EAX & 0x80000000);
    pfVar1 = pfVar2;
  }
  else {
    pfVar1 = param_4;
    if (((uint)param_4 & 0x7ff00000) == 0) {
      if ((((uint)param_4 & 0xfffff) == 0) && (param_3 == 0)) {
        pfVar2 = (float10 *)0x2;
        goto LAB_00418411;
      }
      pfVar2 = (float10 *)((uint)param_4 & 0x80000000);
    }
    else {
      pfVar2 = (float10 *)((uint)param_4 & 0x80000000);
    }
  }
  if (pfVar2 == (float10 *)0x0) {
    if (DAT_00424324 != 0) {
      return pfVar1;
    }
    pfVar2 = (float10 *)__math_exit((float10 *)"log10",0x1b,unaff_retaddr,param_3,param_4,param_5);
    return pfVar2;
  }
  pfVar2 = (float10 *)0x1;
LAB_00418411:
  if (DAT_00424324 != 0) {
    return pfVar2;
  }
  pfVar2 = __startOneArgErrorHandling
                     ((float10 *)"log10",0x1b,iVar3,unaff_retaddr,param_3,param_4,param_5);
  return pfVar2;
}



float10 * __cdecl FUN_00418430(float10 *__return_storage_ptr__,double param_1)

{
  double dVar1;
  byte bVar2;
  float10 *pfVar3;
  uint uVar4;
  undefined3 extraout_var;
  undefined4 unaff_EBX;
  undefined4 unaff_ESI;
  bool bVar6;
  ushort in_FPUControlWord;
  float10 extraout_ST0;
  uint in_stack_00000008;
  uint uVar7;
  int iVar5;
  
  if (DAT_00424558 != 0) {
    bVar6 = (MXCSR & 0x7f80) == 0x1f80;
    if (bVar6) {
      bVar6 = (in_FPUControlWord & 0x7f) == 0x7f;
    }
    if (bVar6) {
      pfVar3 = (float10 *)(in_stack_00000008 >> 0x14);
      if (((uint)pfVar3 & 0x800) == 0) {
        if (pfVar3 < (float10 *)0x3ff) {
          return pfVar3;
        }
        if (pfVar3 < (float10 *)0x433) {
          return pfVar3;
        }
      }
      else {
        if (pfVar3 < (float10 *)0xbff) {
          return pfVar3;
        }
        if (pfVar3 < (float10 *)0xc33) {
          return pfVar3;
        }
      }
      if (NAN(___return_storage_ptr__)) {
        pfVar3 = (float10 *)
                 ___libm_error_support
                           ((undefined8 *)&__return_storage_ptr__,
                            (undefined8 *)&__return_storage_ptr__,
                            (undefined8 *)&__return_storage_ptr__,0x3ec);
      }
      return pfVar3;
    }
  }
  uVar4 = __ctrlfp(0x1b3f,0xffff);
  if ((in_stack_00000008._2_2_ & 0x7ff0) == 0x7ff0) {
    bVar2 = FUN_0041a34e((int)SUB84(___return_storage_ptr__,0),
                         (uint)((ulonglong)___return_storage_ptr__ >> 0x20));
    iVar5 = CONCAT31(extraout_var,bVar2);
    if (((iVar5 == 1) || (iVar5 == 2)) || (iVar5 == 3)) {
      pfVar3 = (float10 *)__ctrlfp(uVar4,0xffff);
      return pfVar3;
    }
    dVar1 = ___return_storage_ptr__ + 1.0;
    uVar7 = 8;
  }
  else {
    __frnd(SUB84(___return_storage_ptr__,0),(double)CONCAT44(unaff_EBX,unaff_ESI));
    if (((NAN((float10)___return_storage_ptr__) || NAN(extraout_ST0)) !=
         ((float10)___return_storage_ptr__ == extraout_ST0)) || ((uVar4 & 0x20) != 0)) {
      pfVar3 = (float10 *)__ctrlfp(uVar4,0xffff);
      return pfVar3;
    }
    dVar1 = (double)extraout_ST0;
    uVar7 = 0x10;
  }
  pfVar3 = (float10 *)__except1(uVar7,0xc,___return_storage_ptr__,dVar1,uVar4);
  return pfVar3;
}



undefined4 __cdecl FUN_0041854d(undefined4 param_1,undefined4 *param_2)

{
  *param_2 = 0;
  param_2[1] = 0;
  return param_1;
}



undefined4 __cdecl FUN_00418561(undefined4 *param_1,int param_2)

{
  *param_1 = 0;
  param_1[1] = 0;
  *(undefined *)(param_2 + 0x1c) = 1;
  *(undefined4 *)(param_2 + 0x18) = 0x2a;
  return 0xffffffff;
}



void __cdecl FUN_00418583(uint **param_1,byte *param_2,uint param_3,uint *param_4,int param_5)

{
  uint uVar1;
  uint uVar2;
  uint **ppuVar3;
  byte bVar5;
  uint uVar4;
  byte *pbVar6;
  uint **local_1c;
  byte local_16;
  byte local_15;
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  uint local_8;
  
  local_8 = DAT_00423014 ^ (uint)&stack0xfffffffc;
  local_1c = param_1;
  if (param_4 == (uint *)0x0) {
    param_4 = &DAT_0042431c;
  }
  if (param_2 == (byte *)0x0) {
    param_3 = 1;
    local_1c = (uint **)0x0;
    pbVar6 = &DAT_0041b5be;
  }
  else {
    pbVar6 = param_2;
    if (param_3 == 0) goto LAB_00418725;
  }
  if (*(short *)((int)param_4 + 6) == 0) {
    bVar5 = *pbVar6;
    pbVar6 = pbVar6 + 1;
    if (-1 < (char)bVar5) {
      if (local_1c != (uint **)0x0) {
        *local_1c = (uint *)(uint)bVar5;
      }
      goto LAB_00418725;
    }
    if ((bVar5 & 0xe0) == 0xc0) {
      uVar4 = (uint)CONCAT11(2,bVar5);
    }
    else if ((bVar5 & 0xf0) == 0xe0) {
      uVar4 = (uint)CONCAT11(3,bVar5);
    }
    else {
      if ((bVar5 & 0xf8) != 0xf0) goto LAB_0041871d;
      uVar4 = (uint)CONCAT11(4,bVar5);
    }
    local_15 = (byte)(uVar4 >> 8);
    ppuVar3 = (uint **)((1 << (7 - local_15 & 0x1f)) - 1U & uVar4 & 0xff);
    uVar4 = CONCAT31((int3)(uVar4 >> 8),local_15);
LAB_0041866c:
    uVar1 = uVar4 & 0xff;
    if (uVar1 < param_3) {
      param_3 = uVar1;
    }
    uVar2 = (int)pbVar6 - (int)param_2;
    while (uVar2 < param_3) {
      local_16 = *pbVar6;
      pbVar6 = pbVar6 + 1;
      uVar2 = uVar2 + 1;
      uVar4 = CONCAT31((int3)(uVar4 >> 8),local_15);
      if ((local_16 & 0xc0) != 0x80) goto LAB_0041871d;
      ppuVar3 = (uint **)((int)ppuVar3 << 6 | local_16 & 0x3f);
    }
    bVar5 = (byte)(uVar4 >> 8);
    if (param_3 < uVar1) {
      *(ushort *)(param_4 + 1) = (ushort)bVar5;
      *param_4 = (uint)ppuVar3;
      *(ushort *)((int)param_4 + 6) = (ushort)(byte)((char)uVar4 - (char)param_3);
      goto LAB_00418725;
    }
    if (((ppuVar3 < (uint **)0xd800) || ((uint **)0xdfff < ppuVar3)) &&
       (ppuVar3 < (uint **)0x110000)) {
      local_14 = 0x80;
      local_10 = 0x800;
      local_c = 0x10000;
      if ((&local_1c)[bVar5] <= ppuVar3) {
        if (local_1c != (uint **)0x0) {
          *local_1c = (uint *)ppuVar3;
        }
        FUN_0041854d(-(uint)(ppuVar3 != (uint **)0x0) & uVar1,param_4);
        goto LAB_00418725;
      }
    }
  }
  else {
    bVar5 = *(byte *)(param_4 + 1);
    local_15 = *(byte *)((int)param_4 + 6);
    uVar4 = (uint)CONCAT11(bVar5,local_15);
    ppuVar3 = (uint **)*param_4;
    if ((((byte)(bVar5 - 2) < 3) && (local_15 != 0)) && (local_15 < bVar5)) goto LAB_0041866c;
  }
LAB_0041871d:
  FUN_00418561(param_4,param_5);
LAB_00418725:
  FUN_00402125(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



// Library Function - Single Match
//  ___strncnt
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void __cdecl ___strncnt(char *param_1,int param_2)

{
  char cVar1;
  int iVar2;
  
  iVar2 = 0;
  cVar1 = *param_1;
  while ((cVar1 != '\0' && (iVar2 != param_2))) {
    iVar2 = iVar2 + 1;
    cVar1 = param_1[iVar2];
  }
  return;
}



// Library Function - Single Match
//  __strnicmp
// 
// Libraries: Visual Studio 2012 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

int __cdecl __strnicmp(char *_Str1,char *_Str2,size_t _MaxCount)

{
  undefined4 *puVar1;
  int iVar2;
  
  if (DAT_00423e60 == 0) {
    if ((_Str1 == (char *)0x0) || (_Str2 == (char *)0x0)) {
      puVar1 = (undefined4 *)FUN_0040e304();
      *puVar1 = 0x16;
      FUN_0040e223();
      iVar2 = 0x7fffffff;
    }
    else {
      if (_MaxCount < 0x80000000) {
        iVar2 = ___ascii_strnicmp(_Str1,_Str2,_MaxCount);
        return iVar2;
      }
      puVar1 = (undefined4 *)FUN_0040e304();
      *puVar1 = 0x16;
      FUN_0040e223();
      iVar2 = 0x7fffffff;
    }
  }
  else {
    iVar2 = FUN_004187bd((byte *)_Str1,(byte *)_Str2,_MaxCount,(__acrt_ptd **)0x0);
  }
  return iVar2;
}



int __cdecl FUN_004187bd(byte *param_1,byte *param_2,uint param_3,__acrt_ptd **param_4)

{
  byte bVar1;
  undefined4 *puVar2;
  int iVar3;
  uint uVar4;
  int local_18;
  int local_14;
  char local_c;
  
  if (param_1 == (byte *)0x0) {
    puVar2 = (undefined4 *)FUN_0040e304();
    *puVar2 = 0x16;
    FUN_0040e223();
    iVar3 = 0x7fffffff;
  }
  else if (param_2 == (byte *)0x0) {
    puVar2 = (undefined4 *)FUN_0040e304();
    *puVar2 = 0x16;
    FUN_0040e223();
    iVar3 = 0x7fffffff;
  }
  else if (param_3 < 0x80000000) {
    if (param_3 == 0) {
      iVar3 = 0;
    }
    else {
      FUN_00408ded(&local_18,param_4);
      do {
        bVar1 = *param_1;
        param_1 = param_1 + 1;
        uVar4 = (uint)*(byte *)((uint)bVar1 + *(int *)(local_14 + 0x94));
        bVar1 = *param_2;
        param_2 = param_2 + 1;
        iVar3 = uVar4 - *(byte *)((uint)bVar1 + *(int *)(local_14 + 0x94));
        if ((iVar3 != 0) || (uVar4 == 0)) break;
        param_3 = param_3 - 1;
      } while (param_3 != 0);
      if (local_c != '\0') {
        *(uint *)(local_18 + 0x350) = *(uint *)(local_18 + 0x350) & 0xfffffffd;
      }
    }
  }
  else {
    puVar2 = (undefined4 *)FUN_0040e304();
    *puVar2 = 0x16;
    FUN_0040e223();
    iVar3 = 0x7fffffff;
  }
  return iVar3;
}



// WARNING: Function: __alloca_probe_16 replaced with injection: alloca_probe

void __cdecl
FUN_00418888(int *param_1,wchar_t *param_2,ulong param_3,byte *param_4,int param_5,byte *param_6,
            int param_7,uint param_8)

{
  BOOL BVar1;
  BYTE *pBVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  undefined4 *puVar7;
  undefined4 *puVar8;
  _cpinfo local_1c;
  uint local_8;
  
  local_8 = DAT_00423014 ^ (uint)&stack0xfffffffc;
  if (param_5 < 1) {
    if (param_5 < -1) goto LAB_00418ad2;
  }
  else {
    param_5 = ___strncnt((char *)param_4,param_5);
  }
  if (param_7 < 1) {
    if (param_7 < -1) goto LAB_00418ad2;
  }
  else {
    param_7 = ___strncnt((char *)param_6,param_7);
  }
  if (param_8 == 0) {
    param_8 = *(uint *)(*param_1 + 8);
  }
  if ((param_5 == 0) || (param_7 == 0)) {
    if ((param_5 == param_7) ||
       (((1 < param_7 || (1 < param_5)) || (BVar1 = GetCPInfo(param_8,&local_1c), BVar1 == 0))))
    goto LAB_00418ad2;
    if (0 < param_5) {
      if (1 < local_1c.MaxCharSize) {
        pBVar2 = local_1c.LeadByte;
        while (((local_1c.LeadByte[0] != 0 && (pBVar2[1] != 0)) &&
               ((*param_4 < *pBVar2 || (pBVar2[1] < *param_4))))) {
          pBVar2 = pBVar2 + 2;
          local_1c.LeadByte[0] = *pBVar2;
        }
      }
      goto LAB_00418ad2;
    }
    if (0 < param_7) {
      if (1 < local_1c.MaxCharSize) {
        pBVar2 = local_1c.LeadByte;
        while (((local_1c.LeadByte[0] != 0 && (pBVar2[1] != 0)) &&
               ((*param_6 < *pBVar2 || (pBVar2[1] < *param_6))))) {
          pBVar2 = pBVar2 + 2;
          local_1c.LeadByte[0] = *pBVar2;
        }
      }
      goto LAB_00418ad2;
    }
  }
  iVar3 = FUN_00411ea3(param_8,9,(LPCSTR)param_4,param_5,(LPWSTR)0x0,0);
  if (iVar3 == 0) goto LAB_00418ad2;
  uVar4 = iVar3 * 2 + 8;
  uVar4 = -(uint)((uint)(iVar3 * 2) < uVar4) & uVar4;
  if (uVar4 == 0) {
LAB_00418b1c:
    puVar8 = (undefined4 *)0x0;
  }
  else {
    if (0x400 < uVar4) {
      puVar8 = (undefined4 *)__malloc_base(uVar4);
      if (puVar8 != (undefined4 *)0x0) {
        *puVar8 = 0xdddd;
        goto LAB_00418a17;
      }
      goto LAB_00418b1c;
    }
    puVar8 = (undefined4 *)&stack0xffffffc8;
    if (&stack0x00000000 == (undefined *)0x38) goto LAB_00418b1c;
LAB_00418a17:
    puVar8 = puVar8 + 2;
    if (puVar8 == (undefined4 *)0x0) goto LAB_00418b1c;
    iVar5 = FUN_00411ea3(param_8,1,(LPCSTR)param_4,param_5,(LPWSTR)puVar8,iVar3);
    if ((iVar5 != 0) &&
       (iVar5 = FUN_00411ea3(param_8,9,(LPCSTR)param_6,param_7,(LPWSTR)0x0,0), iVar5 != 0)) {
      uVar4 = iVar5 * 2 + 8;
      uVar4 = -(uint)((uint)(iVar5 * 2) < uVar4) & uVar4;
      if (uVar4 == 0) {
LAB_00418b10:
        puVar7 = (undefined4 *)0x0;
      }
      else {
        if (0x400 < uVar4) {
          puVar7 = (undefined4 *)__malloc_base(uVar4);
          if (puVar7 != (undefined4 *)0x0) {
            *puVar7 = 0xdddd;
            goto LAB_00418aa2;
          }
          goto LAB_00418b10;
        }
        puVar7 = (undefined4 *)&stack0xffffffc8;
        if (&stack0x00000000 == (undefined *)0x38) goto LAB_00418b10;
LAB_00418aa2:
        puVar7 = puVar7 + 2;
        if (puVar7 == (undefined4 *)0x0) goto LAB_00418b10;
        iVar6 = FUN_00411ea3(param_8,1,(LPCSTR)param_6,param_7,(LPWSTR)puVar7,iVar5);
        if (iVar6 != 0) {
          FID_conflict____acrt_CompareStringEx_36
                    (param_2,param_3,(wchar_t *)puVar8,iVar3,(wchar_t *)puVar7,iVar5,
                     (_nlsversioninfo *)0x0,(void *)0x0,0);
          FUN_00412a40((int)puVar7);
          FUN_00412a40((int)puVar8);
          goto LAB_00418ad2;
        }
      }
      FUN_00412a40((int)puVar7);
      FUN_00412a40((int)puVar8);
      goto LAB_00418ad2;
    }
  }
  FUN_00412a40((int)puVar8);
LAB_00418ad2:
  FUN_00402125(local_8 ^ (uint)&stack0xfffffffc);
  return;
}



// Library Function - Single Match
//  ___acrt_CompareStringA
// 
// Library: Visual Studio 2019 Release

void __cdecl
___acrt_CompareStringA
          (__acrt_ptd **param_1,wchar_t *param_2,ulong param_3,byte *param_4,int param_5,
          byte *param_6,int param_7,uint param_8)

{
  int local_14;
  int local_10 [2];
  char local_8;
  
  FUN_00408ded(&local_14,param_1);
  FUN_00418888(local_10,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  if (local_8 != '\0') {
    *(uint *)(local_14 + 0x350) = *(uint *)(local_14 + 0x350) & 0xfffffffd;
  }
  return;
}



// Library Function - Single Match
//  void __cdecl __dcrt_lowio_initialize_console_output(void)
// 
// Libraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual
// Studio 2019 Release

void __cdecl __dcrt_lowio_initialize_console_output(void)

{
  DAT_00423890 = CreateFileW(L"CONOUT$",0x40000000,3,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
  return;
}



// Library Function - Single Match
//  ___dcrt_lowio_ensure_console_output_initialized
// 
// Libraries: Visual Studio 2019 Debug, Visual Studio 2019 Release

bool ___dcrt_lowio_ensure_console_output_initialized(void)

{
  if (DAT_00423890 == -2) {
    __dcrt_lowio_initialize_console_output();
  }
  return DAT_00423890 != -1;
}



// Library Function - Multiple Matches With Different Base Names
//  ___dcrt_terminate_console_input
//  ___dcrt_terminate_console_output
// 
// Libraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual
// Studio 2019 Release

void FID_conflict____dcrt_terminate_console_output(void)

{
  if ((DAT_00423890 != (HANDLE)0xffffffff) && (DAT_00423890 != (HANDLE)0xfffffffe)) {
    CloseHandle(DAT_00423890);
  }
  return;
}



// Library Function - Single Match
//  ___dcrt_write_console
// 
// Libraries: Visual Studio 2019 Debug, Visual Studio 2019 Release

BOOL __cdecl ___dcrt_write_console(void *param_1,DWORD param_2,LPDWORD param_3)

{
  BOOL BVar1;
  DWORD DVar2;
  
  BVar1 = WriteConsoleW(DAT_00423890,param_1,param_2,param_3,(LPVOID)0x0);
  if (BVar1 == 0) {
    DVar2 = GetLastError();
    if (DVar2 == 6) {
      FID_conflict____dcrt_terminate_console_output();
      __dcrt_lowio_initialize_console_output();
      BVar1 = WriteConsoleW(DAT_00423890,param_1,param_2,param_3,(LPVOID)0x0);
    }
  }
  return BVar1;
}



// Library Function - Single Match
//  __CIlog10_pentium4
// 
// Library: Visual Studio

void __CIlog10_pentium4(void)

{
  undefined4 unaff_EBP;
  float10 in_ST0;
  undefined4 in_stack_fffffff8;
  
  start(SUB84((double)in_ST0,0),(double)CONCAT44(unaff_EBP,in_stack_fffffff8));
  return;
}



// Library Function - Single Match
//  start
// 
// Library: Visual Studio 2019 Release

float10 * __cdecl start(float10 *__return_storage_ptr__,double param_1)

{
  uint uVar1;
  float10 *pfVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  ulonglong uVar6;
  undefined in_XMM0 [16];
  double dVar7;
  uint in_stack_00000008;
  longlong local_c;
  
  iVar5 = 0;
  while( true ) {
    uVar6 = in_XMM0._0_8_;
    uVar3 = (uint)(ushort)(in_XMM0._6_2_ >> 4);
    uVar1 = SUB82((double)(uVar6 & 0xfffffffffffff | 0x3ff0000000000000) + 4398046511103.008,0) &
            0x7f0;
    dVar7 = (double)(uVar6 & 0xfffff80000000 | 0x3ff0000000000000);
    in_XMM0._8_8_ =
         ((double)(uVar6 & 0xfffffffffffff | 0x3ff0000000000000) - dVar7) *
         *(double *)(&UNK_00420508 + uVar1) +
         (dVar7 * *(double *)(&UNK_00420508 + uVar1) - 0.43359375);
    uVar4 = uVar3 - 1;
    if (uVar4 < 0x7fe) {
      return (float10 *)(uVar1 + ((uVar3 - 0x3ff) + iVar5) * 0x400);
    }
    local_c = -(ulonglong)((double)CONCAT44(in_stack_00000008,__return_storage_ptr__) == 0.0);
    if ((short)local_c != 0) break;
    if (uVar4 != 0xffffffff) {
      if (uVar4 < 0x7ff) {
        local_c = 0xfffffffffffff;
        pfVar2 = (float10 *)
                 (uint)(ushort)-(ushort)((double)(CONCAT44(in_stack_00000008,__return_storage_ptr__)
                                                  & 0xfffffffffffff | 0x3ff0000000000000) == 1.0);
        if (pfVar2 != (float10 *)0x0) {
          return pfVar2;
        }
        iVar5 = 0x3e9;
      }
      else if (((uVar3 & 0x7ff) < 0x7ff) ||
              (((uint)__return_storage_ptr__ | in_stack_00000008 & 0xfffff) == 0)) {
        local_c = -0x8000000000000;
        iVar5 = 9;
      }
      else {
        iVar5 = 0x3e9;
      }
      goto LAB_00418e5a;
    }
    in_XMM0._0_8_ = (double)CONCAT44(in_stack_00000008,__return_storage_ptr__) * 4503599627370496.0;
    iVar5 = -0x34;
  }
  local_c = -0x10000000000000;
  iVar5 = 8;
LAB_00418e5a:
  pfVar2 = (float10 *)
           ___libm_error_support
                     ((undefined8 *)&__return_storage_ptr__,(undefined8 *)&__return_storage_ptr__,
                      &local_c,iVar5);
  return pfVar2;
}



undefined4 FUN_0041935c(void)

{
  uint in_EAX;
  
  if ((in_EAX & 0x80000) != 0) {
    return 0;
  }
  return 0;
}



uint __cdecl FUN_004193b8(undefined4 param_1,uint param_2)

{
  if ((param_2 & 0x7ff00000) != 0x7ff00000) {
    return param_2 & 0x7ff00000;
  }
  return param_2;
}



// Library Function - Single Match
//  __math_exit
// 
// Library: Visual Studio

void __fastcall
__math_exit(float10 *param_1,undefined4 param_2,ushort param_3,undefined4 param_4,undefined4 param_5
           ,undefined4 param_6)

{
  ushort in_FPUStatusWord;
  uint unaff_retaddr;
  
  if ((((short)unaff_retaddr != 0x27f) && ((unaff_retaddr & 0x20) != 0)) &&
     ((in_FPUStatusWord & 0x20) != 0)) {
    __startOneArgErrorHandling(param_1,param_2,unaff_retaddr,param_3,param_4,param_5,param_6);
    return;
  }
  return;
}



float10 * __fastcall
FUN_004194c0(float10 *__return_storage_ptr__,int param_1,undefined4 param_2,undefined2 param_3,
            undefined4 param_4,undefined4 param_5,undefined4 param_6,undefined4 param_7,
            undefined4 param_8)

{
  float10 *pfVar1;
  float10 in_ST0;
  int local_24;
  float10 *pfStack_20;
  undefined4 uStack_1c;
  undefined4 uStack_18;
  undefined4 local_14;
  undefined4 local_10;
  double dStack_c;
  
  local_14 = param_6;
  local_10 = param_7;
  dStack_c = (double)in_ST0;
  uStack_1c = param_4;
  uStack_18 = param_5;
  pfStack_20 = __return_storage_ptr__;
  pfVar1 = (float10 *)FUN_004199c4(param_1,&local_24,(ushort *)&param_2);
  return pfVar1;
}



// Library Function - Single Match
//  __startOneArgErrorHandling
// 
// Library: Visual Studio

float10 * __fastcall
__startOneArgErrorHandling
          (float10 *__return_storage_ptr__,int param_1,int param_2,ushort param_3,undefined4 param_4
          ,undefined4 param_5,undefined4 param_6)

{
  float10 *pfVar1;
  float10 in_ST0;
  int local_24;
  float10 *local_20;
  undefined4 local_1c;
  undefined4 local_18;
  double local_c;
  
  local_c = (double)in_ST0;
  local_1c = param_4;
  local_18 = param_5;
  local_20 = __return_storage_ptr__;
  pfVar1 = (float10 *)FUN_004199c4(param_1,&local_24,(ushort *)&param_2);
  return pfVar1;
}



// Library Function - Single Match
//  ___libm_error_support
// 
// Library: Visual Studio 2019 Release

void __cdecl
___libm_error_support(undefined8 *param_1,undefined8 *param_2,undefined8 *param_3,int param_4)

{
  undefined8 uVar1;
  code *pcVar2;
  int iVar3;
  undefined4 *puVar4;
  undefined4 local_24;
  char *local_20;
  undefined8 local_1c;
  undefined8 local_14;
  undefined8 local_c;
  
  if (DAT_00424328 == 0) {
    pcVar2 = FUN_0040cdc7;
  }
  else {
    pcVar2 = (code *)DecodePointer(DAT_00424554);
  }
  if (0x1a < param_4) {
    if (param_4 != 0x1b) {
      if (param_4 == 0x1c) {
        local_20 = "pow";
      }
      else if (param_4 == 0x31) {
        local_20 = "sqrt";
      }
      else if (param_4 == 0x3a) {
        local_20 = "acos";
      }
      else {
        if (param_4 != 0x3d) {
          if ((param_4 != 1000) && (param_4 != 0x3e9)) {
            return;
          }
          uVar1 = *param_1;
          goto LAB_0041961b;
        }
        local_20 = "asin";
      }
      goto LAB_0041967b;
    }
    local_24 = 2;
LAB_004196c1:
    local_20 = "pow";
    goto LAB_004196c8;
  }
  if (param_4 == 0x1a) {
    uVar1 = 0x3ff0000000000000;
LAB_0041961b:
    *param_3 = uVar1;
    return;
  }
  if (0xe < param_4) {
    if (param_4 == 0xf) {
      local_20 = &DAT_004200c0;
    }
    else {
      if (param_4 == 0x18) {
        local_24 = 3;
        goto LAB_004196c1;
      }
      if (param_4 != 0x19) {
        return;
      }
      local_20 = &DAT_004200c4;
    }
    local_24 = 4;
    local_1c = *param_1;
    local_14 = *param_2;
    puVar4 = &local_24;
    local_c = *param_3;
    _guard_check_icall();
    (*pcVar2)(puVar4);
    goto LAB_004196fe;
  }
  if (param_4 == 0xe) {
    local_24 = 3;
    local_20 = "exp";
  }
  else {
    if (param_4 != 2) {
      if (param_4 == 3) {
        local_20 = "log";
      }
      else {
        if (param_4 == 8) {
          local_24 = 2;
          local_20 = "log10";
          goto LAB_004196c8;
        }
        if (param_4 != 9) {
          return;
        }
        local_20 = "log10";
      }
LAB_0041967b:
      local_24 = 1;
      local_1c = *param_1;
      local_14 = *param_2;
      puVar4 = &local_24;
      local_c = *param_3;
      _guard_check_icall();
      iVar3 = (*pcVar2)(puVar4);
      if (iVar3 == 0) {
        puVar4 = (undefined4 *)FUN_0040e304();
        *puVar4 = 0x21;
      }
      goto LAB_004196fe;
    }
    local_24 = 2;
    local_20 = "log";
  }
LAB_004196c8:
  local_1c = *param_1;
  local_14 = *param_2;
  puVar4 = &local_24;
  local_c = *param_3;
  _guard_check_icall();
  iVar3 = (*pcVar2)(puVar4);
  if (iVar3 == 0) {
    puVar4 = (undefined4 *)FUN_0040e304();
    *puVar4 = 0x22;
  }
LAB_004196fe:
  *param_3 = local_c;
  return;
}



// Library Function - Single Match
//  ___ascii_strnicmp
// 
// Libraries: Visual Studio 2012 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

int __cdecl ___ascii_strnicmp(char *_Str1,char *_Str2,size_t _MaxCount)

{
  char cVar1;
  byte bVar2;
  ushort uVar3;
  uint uVar4;
  bool bVar5;
  
  if (_MaxCount != 0) {
    do {
      bVar2 = *_Str1;
      cVar1 = *_Str2;
      uVar3 = CONCAT11(bVar2,cVar1);
      if (bVar2 == 0) break;
      uVar3 = CONCAT11(bVar2,cVar1);
      uVar4 = (uint)uVar3;
      if (cVar1 == '\0') break;
      _Str1 = (char *)((byte *)_Str1 + 1);
      _Str2 = _Str2 + 1;
      if ((0x40 < bVar2) && (bVar2 < 0x5b)) {
        uVar4 = (uint)CONCAT11(bVar2 + 0x20,cVar1);
      }
      uVar3 = (ushort)uVar4;
      bVar2 = (byte)uVar4;
      if ((0x40 < bVar2) && (bVar2 < 0x5b)) {
        uVar3 = (ushort)CONCAT31((int3)(uVar4 >> 8),bVar2 + 0x20);
      }
      bVar2 = (byte)(uVar3 >> 8);
      bVar5 = bVar2 < (byte)uVar3;
      if (bVar2 != (byte)uVar3) goto LAB_00419821;
      _MaxCount = _MaxCount - 1;
    } while (_MaxCount != 0);
    _MaxCount = 0;
    bVar2 = (byte)(uVar3 >> 8);
    bVar5 = bVar2 < (byte)uVar3;
    if (bVar2 != (byte)uVar3) {
LAB_00419821:
      _MaxCount = 0xffffffff;
      if (!bVar5) {
        _MaxCount = 1;
      }
    }
  }
  return _MaxCount;
}



undefined4 __cdecl FUN_00419831(double param_1)

{
  uint uVar1;
  float10 extraout_ST0;
  float10 fVar2;
  float10 extraout_ST0_00;
  double extraout_var;
  double dVar3;
  
  uVar1 = __fpclass(param_1);
  if ((uVar1 & 0x90) == 0) {
    __frnd(SUB84(param_1,0),extraout_var);
    fVar2 = (float10)param_1;
    if ((NAN(fVar2) || NAN(extraout_ST0)) != (fVar2 == extraout_ST0)) {
      dVar3 = (double)(fVar2 * (float10)0.5);
      __frnd(SUB84((double)(fVar2 * (float10)0.5),0),dVar3);
      if ((NAN((float10)dVar3) || NAN(extraout_ST0_00)) == ((float10)dVar3 == extraout_ST0_00)) {
        return 1;
      }
      return 2;
    }
  }
  return 0;
}



undefined4 __cdecl FUN_00419899(int param_1,int param_2,int param_3,int param_4,undefined8 *param_5)

{
  double dVar1;
  undefined8 uVar2;
  int iVar3;
  
  dVar1 = ABS((double)CONCAT44(param_2,param_1));
  if (param_4 == 0x7ff00000) {
    if (param_3 != 0) goto LAB_0041992d;
    uVar2 = 0x3ff0000000000000;
    if (1.0 < dVar1 == NAN(dVar1)) {
      if (dVar1 < 1.0) {
        uVar2 = 0;
      }
      goto LAB_004199be;
    }
  }
  else {
    if ((param_4 == -0x100000) && (param_3 == 0)) {
      if (1.0 < dVar1 == NAN(dVar1)) {
        uVar2 = 0x3ff0000000000000;
        if (dVar1 < 1.0) {
          uVar2 = 0x7ff0000000000000;
        }
      }
      else {
        uVar2 = 0;
      }
      goto LAB_004199be;
    }
LAB_0041992d:
    if (param_2 != 0x7ff00000) {
      if (param_2 != -0x100000) {
        return 0;
      }
      if (param_1 != 0) {
        return 0;
      }
      iVar3 = FUN_00419831((double)CONCAT44(param_4,param_3));
      uVar2 = 0;
      dVar1 = (double)CONCAT44(param_4,param_3);
      if (dVar1 <= 0.0) {
        if (dVar1 < 0.0 == NAN(dVar1)) {
          uVar2 = 0x3ff0000000000000;
        }
        else if (iVar3 == 1) {
          uVar2 = 0x8000000000000000;
        }
      }
      else {
        uVar2 = 0x7ff0000000000000;
        if (iVar3 == 1) {
          uVar2 = 0xfff0000000000000;
        }
      }
      goto LAB_004199be;
    }
    if (param_1 != 0) {
      return 0;
    }
    dVar1 = (double)CONCAT44(param_4,param_3);
    if (dVar1 <= 0.0) {
      uVar2 = 0;
      if (dVar1 < 0.0 == NAN(dVar1)) {
        uVar2 = 0x3ff0000000000000;
      }
      goto LAB_004199be;
    }
  }
  uVar2 = 0x7ff0000000000000;
LAB_004199be:
  *param_5 = uVar2;
  return 0;
}



void __cdecl FUN_004199c4(int param_1,int *param_2,ushort *param_3)

{
  bool bVar1;
  undefined3 extraout_var;
  int iVar2;
  uint uVar3;
  uint local_94;
  uint local_90 [12];
  undefined8 local_60;
  uint local_50;
  uint local_14;
  
  local_14 = DAT_00423014 ^ (uint)&stack0xfffffff0;
  local_94 = (uint)*param_3;
  iVar2 = *param_2;
  if (iVar2 == 1) {
LAB_00419a32:
    uVar3 = 8;
LAB_00419a34:
    bVar1 = FUN_00419bea(uVar3,(double *)(param_2 + 6),local_94);
    if (CONCAT31(extraout_var,bVar1) == 0) {
      if (((param_1 == 0x10) || (param_1 == 0x16)) || (param_1 == 0x1d)) {
        local_60 = *(undefined8 *)(param_2 + 4);
        local_50 = local_50 & 0xffffffe3 | 3;
      }
      else {
        local_50 = local_50 & 0xfffffffe;
      }
      __raise_exc(local_90,&local_94,uVar3,param_1,(undefined8 *)(param_2 + 2),
                  (undefined8 *)(param_2 + 6));
    }
  }
  else {
    if (iVar2 == 2) {
      uVar3 = 4;
      goto LAB_00419a34;
    }
    if (iVar2 == 3) {
      uVar3 = 0x11;
      goto LAB_00419a34;
    }
    if (iVar2 == 4) {
      uVar3 = 0x12;
      goto LAB_00419a34;
    }
    if (iVar2 == 5) goto LAB_00419a32;
    if ((iVar2 != 7) && (iVar2 == 8)) {
      uVar3 = 0x10;
      goto LAB_00419a34;
    }
  }
  __ctrlfp(local_94,0xffff);
  if (*param_2 != 8) {
    bVar1 = FUN_0040cd9b();
    if (bVar1) {
      iVar2 = FUN_0040cdc7(param_2);
      if (iVar2 != 0) goto LAB_00419ac1;
    }
  }
  FUN_0041a17e(*param_2);
LAB_00419ac1:
  FUN_00402125(local_14 ^ (uint)&stack0xfffffff0);
  return;
}



// Library Function - Single Match
//  __frnd
// 
// Libraries: Visual Studio 2008 Release, Visual Studio 2010 Release, Visual Studio 2012 Release,
// Visual Studio 2019 Release

float10 * __cdecl __frnd(float10 *__return_storage_ptr__,double param_1)

{
  float10 *in_EAX;
  
  return in_EAX;
}



// Library Function - Single Match
//  __errcode
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

int __cdecl __errcode(uint param_1)

{
  int iStack_8;
  
  if ((param_1 & 0x20) == 0) {
    if ((param_1 & 8) != 0) {
      return 1;
    }
    if ((param_1 & 4) == 0) {
      if ((param_1 & 1) == 0) {
        return (param_1 & 2) * 2;
      }
      iStack_8 = 3;
    }
    else {
      iStack_8 = 2;
    }
  }
  else {
    iStack_8 = 5;
  }
  return iStack_8;
}



// Library Function - Single Match
//  __except1
// 
// Library: Visual Studio 2015 Release

void __cdecl __except1(uint param_1,int param_2,undefined8 param_3,double param_4,uint param_5)

{
  bool bVar1;
  undefined3 extraout_var;
  float10 *__return_storage_ptr__;
  uint uVar2;
  uint local_90 [16];
  uint local_50;
  uint local_14;
  
  uVar2 = param_5;
  local_14 = DAT_00423014 ^ (uint)&stack0xfffffff0;
  bVar1 = FUN_00419bea(param_1,&param_4,param_5);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    local_50 = local_50 & 0xfffffffe;
    __raise_exc_ex(local_90,&param_5,param_1,param_2,&param_3,&param_4,0);
    uVar2 = param_5;
  }
  __return_storage_ptr__ = (float10 *)__errcode(param_1);
  bVar1 = FUN_0040cd9b();
  if ((bVar1) && (__return_storage_ptr__ != (float10 *)0x0)) {
    FUN_0041a1af(__return_storage_ptr__,param_2,(int)param_3,(int)((ulonglong)param_3 >> 0x20),0,0,
                 SUB84(param_4,0),(int)((ulonglong)param_4 >> 0x20),uVar2);
  }
  else {
    FUN_0041a17e((int)__return_storage_ptr__);
    __ctrlfp(uVar2,0xffff);
  }
  FUN_00402125(local_14 ^ (uint)&stack0xfffffff0);
  return;
}



bool __cdecl FUN_00419bea(uint param_1,double *param_2,uint param_3)

{
  double dVar1;
  float10 fVar2;
  byte bVar3;
  bool bVar4;
  int iVar5;
  uint uVar6;
  uint uVar7;
  float10 fVar8;
  float10 fVar9;
  uint local_24;
  byte bStack_20;
  undefined uStack_1f;
  ushort uStack_1e;
  int local_18;
  double local_14;
  uint local_c;
  char local_7;
  char local_6;
  byte local_5;
  
  uVar7 = param_1 & 0x1f;
  if (((param_1 & 8) != 0) && ((param_3 & 1) != 0)) {
    FUN_00417d77(1);
    uVar7 = param_1 & 0x17;
    goto LAB_00419e49;
  }
  if ((param_1 & param_3 & 4) != 0) {
    FUN_00417d77(4);
    uVar7 = param_1 & 0x1b;
    goto LAB_00419e49;
  }
  if (((param_1 & 1) == 0) || ((param_3 & 8) == 0)) {
    if (((param_1 & 2) == 0) || ((param_3 & 0x10) == 0)) goto LAB_00419e49;
    dVar1 = *param_2;
    uVar7 = param_1 >> 4 & 1;
    local_c = uVar7;
    if (NAN(dVar1) == (dVar1 == 0.0)) {
      fVar8 = (float10)FUN_0041a24f(SUB84(dVar1,0),(uint)((ulonglong)dVar1 >> 0x20),&local_18);
      local_18 = local_18 + -0x600;
      dVar1 = (double)fVar8;
      local_24 = SUB84(dVar1,0);
      bStack_20 = (byte)((ulonglong)dVar1 >> 0x20);
      uStack_1f = (undefined)((ulonglong)dVar1 >> 0x28);
      uStack_1e = (ushort)((ulonglong)dVar1 >> 0x30);
      fVar2 = (float10)0;
      if (local_18 < -0x432) {
        fVar9 = fVar2 * fVar8;
        uVar7 = 1;
      }
      else {
        local_5 = fVar8 < fVar2;
        uStack_1e = uStack_1e & 0xf | 0x10;
        bVar4 = false;
        local_7 = false;
        local_6 = '\0';
        if (local_18 < -0x3fd) {
          local_18 = -0x3fd - local_18;
          local_6 = '\0';
          do {
            uVar6 = local_24 & 1;
            if ((uVar6 != 0) && (uVar7 == 0)) {
              uVar7 = 1;
            }
            if (local_6 != '\0') {
              bVar4 = true;
            }
            local_24 = local_24 >> 1;
            local_6 = (char)uVar6;
            if ((bStack_20 & 1) != 0) {
              local_24 = local_24 | 0x80000000;
            }
            uVar6 = CONCAT22(uStack_1e,CONCAT11(uStack_1f,bStack_20)) >> 1;
            bStack_20 = (byte)uVar6;
            uStack_1f = (undefined)(uVar6 >> 8);
            uStack_1e = uStack_1e >> 1;
            local_18 = local_18 + -1;
            local_c = uVar7;
            local_7 = bVar4;
          } while (local_18 != 0);
        }
        local_14 = (double)CONCAT26(uStack_1e,CONCAT15(uStack_1f,CONCAT14(bStack_20,local_24)));
        fVar9 = (float10)local_14;
        if (fVar8 < fVar2) {
          fVar9 = -fVar9;
          local_14 = (double)fVar9;
          dVar1 = (double)fVar9;
          local_24 = SUB84(dVar1,0);
          bStack_20 = (byte)((ulonglong)dVar1 >> 0x20);
          uStack_1f = (undefined)((ulonglong)dVar1 >> 0x28);
          uStack_1e = (ushort)((ulonglong)dVar1 >> 0x30);
        }
        if ((local_6 != '\0') || (uVar7 = local_c, (bool)local_7)) {
          iVar5 = _fegetround();
          uVar7 = local_c;
          if (iVar5 == 0) {
            if (local_6 == '\0') goto LAB_00419e2a;
            if (local_7 == '\0') {
              bVar3 = (byte)local_24 & 1;
              goto LAB_00419e19;
            }
          }
          else {
            bVar3 = local_5;
            if (iVar5 != 0x100) {
              if (iVar5 != 0x200) goto LAB_00419e2a;
              bVar3 = local_5 ^ 1;
            }
LAB_00419e19:
            if (bVar3 == 0) {
LAB_00419e2a:
              fVar9 = (float10)local_14;
              goto LAB_00419e30;
            }
          }
          iVar5 = CONCAT22(uStack_1e,CONCAT11(uStack_1f,bStack_20)) + (uint)(0xfffffffe < local_24);
          bStack_20 = (byte)iVar5;
          uStack_1f = (undefined)((uint)iVar5 >> 8);
          uStack_1e = (ushort)((uint)iVar5 >> 0x10);
          fVar9 = (float10)(double)CONCAT26(uStack_1e,
                                            CONCAT15(uStack_1f,CONCAT14(bStack_20,local_24 + 1)));
        }
      }
LAB_00419e30:
      *param_2 = (double)fVar9;
      if (uVar7 != 0) goto LAB_00419e3d;
    }
    else {
LAB_00419e3d:
      FUN_00417d77(0x10);
    }
    uVar7 = param_1 & 0x1d;
    goto LAB_00419e49;
  }
  FUN_00417d77(8);
  uVar7 = param_3 & 0xc00;
  if (uVar7 == 0) {
    if (0.0 < *param_2 == NAN(*param_2)) {
LAB_00419cc1:
      dVar1 = INFINITY;
      goto LAB_00419cc7;
    }
LAB_00419cb9:
    dVar1 = INFINITY;
LAB_00419cc9:
    *param_2 = dVar1;
  }
  else {
    if (uVar7 == 0x400) {
      if (0.0 < *param_2 == NAN(*param_2)) goto LAB_00419cc1;
      dVar1 = 1.797693134862316e+308;
      goto LAB_00419cc9;
    }
    if (uVar7 == 0x800) {
      if (0.0 < *param_2 != NAN(*param_2)) goto LAB_00419cb9;
      dVar1 = 1.797693134862316e+308;
LAB_00419cc7:
      dVar1 = -dVar1;
      goto LAB_00419cc9;
    }
    if (uVar7 == 0xc00) {
      dVar1 = 1.797693134862316e+308;
      if (0.0 < *param_2 != NAN(*param_2)) goto LAB_00419cc9;
      goto LAB_00419cc7;
    }
  }
  uVar7 = param_1 & 0x1e;
LAB_00419e49:
  if (((param_1 & 0x10) != 0) && ((param_3 & 0x20) != 0)) {
    FUN_00417d77(0x20);
    uVar7 = uVar7 & 0xffffffef;
  }
  return uVar7 == 0;
}



// Library Function - Single Match
//  __raise_exc
// 
// Library: Visual Studio 2015 Release

void __cdecl
__raise_exc(uint *param_1,uint *param_2,uint param_3,int param_4,undefined8 *param_5,
           undefined8 *param_6)

{
  __raise_exc_ex(param_1,param_2,param_3,param_4,param_5,param_6,0);
  return;
}



// Library Function - Single Match
//  __raise_exc_ex
// 
// Library: Visual Studio 2015 Release

void __cdecl
__raise_exc_ex(uint *param_1,uint *param_2,uint param_3,int param_4,undefined8 *param_5,
              undefined8 *param_6,int param_7)

{
  uint *puVar1;
  undefined8 *puVar2;
  uint uVar3;
  DWORD dwExceptionCode;
  
  puVar1 = param_2;
  param_1[1] = 0;
  dwExceptionCode = 0xc000000d;
  param_1[2] = 0;
  param_1[3] = 0;
  if ((param_3 & 0x10) != 0) {
    dwExceptionCode = 0xc000008f;
    param_1[1] = param_1[1] | 1;
  }
  if ((param_3 & 2) != 0) {
    dwExceptionCode = 0xc0000093;
    param_1[1] = param_1[1] | 2;
  }
  if ((param_3 & 1) != 0) {
    dwExceptionCode = 0xc0000091;
    param_1[1] = param_1[1] | 4;
  }
  if ((param_3 & 4) != 0) {
    dwExceptionCode = 0xc000008e;
    param_1[1] = param_1[1] | 8;
  }
  if ((param_3 & 8) != 0) {
    dwExceptionCode = 0xc0000090;
    param_1[1] = param_1[1] | 0x10;
  }
  param_1[2] = param_1[2] ^ (~(*param_2 << 4) ^ param_1[2]) & 0x10;
  param_1[2] = param_1[2] ^ (~(*param_2 * 2) ^ param_1[2]) & 8;
  param_1[2] = param_1[2] ^ (~(*param_2 >> 1) ^ param_1[2]) & 4;
  param_1[2] = param_1[2] ^ (~(*param_2 >> 3) ^ param_1[2]) & 2;
  param_1[2] = param_1[2] ^ (~(*param_2 >> 5) ^ param_1[2]) & 1;
  uVar3 = FUN_00417dd0();
  puVar2 = param_6;
  if ((uVar3 & 1) != 0) {
    param_1[3] = param_1[3] | 0x10;
  }
  if ((uVar3 & 4) != 0) {
    param_1[3] = param_1[3] | 8;
  }
  if ((uVar3 & 8) != 0) {
    param_1[3] = param_1[3] | 4;
  }
  if ((uVar3 & 0x10) != 0) {
    param_1[3] = param_1[3] | 2;
  }
  if ((uVar3 & 0x20) != 0) {
    param_1[3] = param_1[3] | 1;
  }
  uVar3 = *puVar1 & 0xc00;
  if (uVar3 == 0) {
    *param_1 = *param_1 & 0xfffffffc;
  }
  else {
    if (uVar3 == 0x400) {
      uVar3 = *param_1 & 0xfffffffd | 1;
    }
    else {
      if (uVar3 != 0x800) {
        if (uVar3 == 0xc00) {
          *param_1 = *param_1 | 3;
        }
        goto LAB_00419fef;
      }
      uVar3 = *param_1 & 0xfffffffe | 2;
    }
    *param_1 = uVar3;
  }
LAB_00419fef:
  uVar3 = *puVar1 & 0x300;
  if (uVar3 == 0) {
    uVar3 = *param_1 & 0xffffffeb | 8;
LAB_0041a025:
    *param_1 = uVar3;
  }
  else {
    if (uVar3 == 0x200) {
      uVar3 = *param_1 & 0xffffffe7 | 4;
      goto LAB_0041a025;
    }
    if (uVar3 == 0x300) {
      *param_1 = *param_1 & 0xffffffe3;
    }
  }
  *param_1 = *param_1 ^ (param_4 << 5 ^ *param_1) & 0x1ffe0;
  param_1[8] = param_1[8] | 1;
  if (param_7 == 0) {
    param_1[8] = param_1[8] & 0xffffffe3 | 2;
    *(undefined8 *)(param_1 + 4) = *param_5;
    param_1[0x18] = param_1[0x18] | 1;
    param_1[0x18] = param_1[0x18] & 0xffffffe3 | 2;
    *(undefined8 *)(param_1 + 0x14) = *param_6;
  }
  else {
    param_1[8] = param_1[8] & 0xffffffe1;
    param_1[4] = *(uint *)param_5;
    param_1[0x18] = param_1[0x18] | 1;
    param_1[0x18] = param_1[0x18] & 0xffffffe1;
    param_1[0x14] = *(uint *)param_6;
  }
  FUN_00417d3c();
  RaiseException(dwExceptionCode,0,1,(ULONG_PTR *)&param_1);
  if ((*(byte *)(param_1 + 2) & 0x10) != 0) {
    *puVar1 = *puVar1 & 0xfffffffe;
  }
  if ((*(byte *)(param_1 + 2) & 8) != 0) {
    *puVar1 = *puVar1 & 0xfffffffb;
  }
  if ((*(byte *)(param_1 + 2) & 4) != 0) {
    *puVar1 = *puVar1 & 0xfffffff7;
  }
  if ((*(byte *)(param_1 + 2) & 2) != 0) {
    *puVar1 = *puVar1 & 0xffffffef;
  }
  if ((*(byte *)(param_1 + 2) & 1) != 0) {
    *puVar1 = *puVar1 & 0xffffffdf;
  }
  uVar3 = *param_1 & 3;
  if (uVar3 == 0) {
    *puVar1 = *puVar1 & 0xfffff3ff;
  }
  else {
    if (uVar3 == 1) {
      uVar3 = *puVar1 & 0xfffff7ff | 0x400;
    }
    else {
      if (uVar3 != 2) {
        if (uVar3 == 3) {
          *puVar1 = *puVar1 | 0xc00;
        }
        goto LAB_0041a136;
      }
      uVar3 = *puVar1 & 0xfffffbff | 0x800;
    }
    *puVar1 = uVar3;
  }
LAB_0041a136:
  uVar3 = *param_1 >> 2 & 7;
  if (uVar3 == 0) {
    uVar3 = *puVar1 & 0xfffff3ff | 0x300;
  }
  else {
    if (uVar3 != 1) {
      if (uVar3 == 2) {
        *puVar1 = *puVar1 & 0xfffff3ff;
      }
      goto LAB_0041a167;
    }
    uVar3 = *puVar1 & 0xfffff3ff | 0x200;
  }
  *puVar1 = uVar3;
LAB_0041a167:
  if (param_7 == 0) {
    *puVar2 = *(undefined8 *)(param_1 + 0x14);
  }
  else {
    *(uint *)puVar2 = param_1[0x14];
  }
  return;
}



void __cdecl FUN_0041a17e(int param_1)

{
  undefined4 *puVar1;
  
  if (param_1 == 1) {
    puVar1 = (undefined4 *)FUN_0040e304();
    *puVar1 = 0x21;
  }
  else if ((param_1 == 2) || (param_1 == 3)) {
    puVar1 = (undefined4 *)FUN_0040e304();
    *puVar1 = 0x22;
    return;
  }
  return;
}



float10 * __cdecl
FUN_0041a1af(float10 *__return_storage_ptr__,int param_1,int param_2,undefined4 param_3,
            undefined4 param_4,undefined4 param_5,undefined4 param_6,undefined4 param_7,
            undefined4 param_8)

{
  int iVar1;
  float10 *pfVar2;
  float10 *local_24;
  undefined *local_20;
  int local_1c;
  undefined4 local_18;
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  undefined4 uStack_8;
  
  iVar1 = 0;
  do {
    if ((&DAT_00420918)[iVar1 * 2] == param_1) {
      local_20 = (&PTR_DAT_0042091c)[iVar1 * 2];
      if (local_20 != (undefined *)0x0) {
        local_1c = param_2;
        local_18 = param_3;
        local_14 = param_4;
        local_10 = param_5;
        local_c = param_6;
        local_24 = __return_storage_ptr__;
        uStack_8 = param_7;
        __ctrlfp(param_8,0xffff);
        pfVar2 = (float10 *)FUN_0040cdc7(&local_24);
        if (pfVar2 == (float10 *)0x0) {
          pfVar2 = (float10 *)FUN_0041a17e((int)__return_storage_ptr__);
        }
        return pfVar2;
      }
      goto LAB_0041a1cf;
    }
    iVar1 = iVar1 + 1;
  } while (iVar1 < 0x1d);
  local_20 = (undefined *)0x0;
LAB_0041a1cf:
  __ctrlfp(param_8,0xffff);
  pfVar2 = (float10 *)FUN_0041a17e((int)__return_storage_ptr__);
  return pfVar2;
}



void __cdecl FUN_0041a24f(float10 *param_1,uint param_2,int *param_3)

{
  uint uVar1;
  double dVar2;
  short unaff_SI;
  int iVar3;
  uint unaff_EDI;
  
  dVar2 = (double)CONCAT17(param_2._3_1_,
                           CONCAT16(param_2._2_1_,CONCAT24((undefined2)param_2,param_1)));
  if (NAN(dVar2) == (dVar2 == 0.0)) {
    if (((param_2 & 0x7ff00000) == 0) && (((param_2 & 0xfffff) != 0 || (param_1 != (float10 *)0x0)))
       ) {
      iVar3 = -0x3fd;
      for (uVar1 = param_2 & 0x100000; uVar1 == 0; uVar1 = uVar1 & 0x100000) {
        uVar1 = param_2 * 2;
        param_2 = uVar1;
        if ((int)param_1 < 0) {
          param_2 = uVar1 | 1;
        }
        param_1 = (float10 *)((int)param_1 * 2);
        iVar3 = iVar3 + -1;
      }
      __set_exp(param_1,(ulonglong)unaff_EDI << 0x20,unaff_SI);
    }
    else {
      __set_exp(param_1,(ulonglong)unaff_EDI << 0x20,unaff_SI);
      iVar3 = (param_2 >> 0x14 & 0x7ff) - 0x3fe;
    }
  }
  else {
    iVar3 = 0;
  }
  *param_3 = iVar3;
  return;
}



// Library Function - Single Match
//  __set_exp
// 
// Library: Visual Studio 2019 Release

float10 * __cdecl __set_exp(float10 *__return_storage_ptr__,undefined8 param_1,short param_2)

{
  ushort in_stack_0000000a;
  
  return (float10 *)(in_stack_0000000a & 0x800f);
}



byte __cdecl FUN_0041a34e(int param_1,uint param_2)

{
  byte bVar1;
  
  if (param_2 == 0x7ff00000) {
    if (param_1 == 0) {
      return 1;
    }
  }
  else if ((param_2 == 0xfff00000) && (param_1 == 0)) {
    return 2;
  }
  if ((param_2._2_2_ & 0x7ff8) == 0x7ff8) {
    bVar1 = 3;
  }
  else {
    if ((param_2._2_2_ & 0x7ff8) != 0x7ff0) {
      return 0;
    }
    if ((param_2 & 0x7ffff) == 0) {
      return -(param_1 != 0) & 4;
    }
    bVar1 = 4;
  }
  return bVar1;
}



// Library Function - Single Match
//  __fpclass
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

int __cdecl __fpclass(double _X)

{
  byte bVar1;
  undefined3 extraout_var;
  int iVar2;
  
  if ((_X._6_2_ & 0x7ff0) == 0x7ff0) {
    bVar1 = FUN_0041a34e(_X._0_4_,(uint)((ulonglong)_X >> 0x20));
    iVar2 = CONCAT31(extraout_var,bVar1);
    if (iVar2 == 1) {
      return 0x200;
    }
    if (iVar2 == 2) {
      iVar2 = 4;
    }
    else {
      if (iVar2 != 3) {
        return 1;
      }
      iVar2 = 2;
    }
    return iVar2;
  }
  if ((((ulonglong)_X & 0x7ff0000000000000) == 0) &&
     ((((ulonglong)_X & 0xfffff00000000) != 0 || (_X._0_4_ != 0)))) {
    return (-(uint)(((ulonglong)_X & 0x8000000000000000) != 0) & 0xffffff90) + 0x80;
  }
  if (NAN(_X) != (_X == 0.0)) {
    return (-(uint)(((ulonglong)_X & 0x8000000000000000) != 0) & 0xffffffe0) + 0x40;
  }
  return (-(uint)(((ulonglong)_X & 0x8000000000000000) != 0) & 0xffffff08) + 0x100;
}



// Library Function - Single Match
//  __FindPESection
// 
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

PIMAGE_SECTION_HEADER __cdecl __FindPESection(PBYTE pImageBase,DWORD_PTR rva)

{
  int iVar1;
  PIMAGE_SECTION_HEADER p_Var2;
  uint uVar3;
  
  uVar3 = 0;
  iVar1 = *(int *)(pImageBase + 0x3c);
  p_Var2 = (PIMAGE_SECTION_HEADER)
           (pImageBase + *(ushort *)(pImageBase + iVar1 + 0x14) + 0x18 + iVar1);
  if (*(ushort *)(pImageBase + iVar1 + 6) != 0) {
    do {
      if ((p_Var2->VirtualAddress <= rva) &&
         (rva < (p_Var2->Misc).PhysicalAddress + p_Var2->VirtualAddress)) {
        return p_Var2;
      }
      uVar3 = uVar3 + 1;
      p_Var2 = p_Var2 + 1;
    } while (uVar3 < *(ushort *)(pImageBase + iVar1 + 6));
  }
  return (PIMAGE_SECTION_HEADER)0x0;
}



// Library Function - Single Match
//  __IsNonwritableInCurrentImage
// 
// Library: Visual Studio 2019 Release

BOOL __cdecl __IsNonwritableInCurrentImage(PBYTE pTarget)

{
  bool bVar1;
  undefined3 extraout_var;
  PIMAGE_SECTION_HEADER p_Var2;
  void *local_14;
  code *pcStack_10;
  uint local_c;
  undefined4 local_8;
  
  pcStack_10 = __except_handler4;
  local_14 = ExceptionList;
  local_c = DAT_00423014 ^ 0x422180;
  ExceptionList = &local_14;
  local_8 = 0;
  bVar1 = FUN_0041a570((short *)&IMAGE_DOS_HEADER_00400000);
  if (CONCAT31(extraout_var,bVar1) != 0) {
    p_Var2 = __FindPESection((PBYTE)&IMAGE_DOS_HEADER_00400000,(DWORD_PTR)(pTarget + -0x400000));
    if (p_Var2 != (PIMAGE_SECTION_HEADER)0x0) {
      ExceptionList = local_14;
      return ~(p_Var2->Characteristics >> 0x1f) & 1;
    }
  }
  ExceptionList = local_14;
  return 0;
}



bool __cdecl FUN_0041a570(short *param_1)

{
  if ((*param_1 == 0x5a4d) && (*(int *)(*(int *)(param_1 + 0x1e) + (int)param_1) == 0x4550)) {
    return *(short *)((int *)(*(int *)(param_1 + 0x1e) + (int)param_1) + 6) == 0x10b;
  }
  return false;
}



undefined4 * __thiscall FUN_0041a5a1(void *this,byte param_1)

{
  *(undefined ***)this = type_info::vftable;
  if ((param_1 & 1) != 0) {
    FUN_0041a650(this);
  }
  return (undefined4 *)this;
}



// WARNING: This is an inlined function
// Library Function - Single Match
//  __EH_epilog3
// 
// Libraries: Visual Studio 2005, Visual Studio 2008, Visual Studio 2010, Visual Studio 2012

void __EH_epilog3(void)

{
  undefined4 *unaff_EBP;
  undefined4 unaff_retaddr;
  
  ExceptionList = (void *)unaff_EBP[-3];
  *unaff_EBP = unaff_retaddr;
  return;
}



// WARNING: This is an inlined function
// WARNING: Unable to track spacebase fully for stack
// WARNING: Variable defined which should be unmapped: param_1
// Library Function - Single Match
//  __EH_prolog3
// 
// Libraries: Visual Studio 2005, Visual Studio 2008, Visual Studio 2010, Visual Studio 2012

void __cdecl __EH_prolog3(int param_1)

{
  int iVar1;
  undefined4 unaff_EBX;
  undefined4 unaff_ESI;
  undefined4 unaff_EDI;
  undefined4 unaff_retaddr;
  uint auStack_1c [5];
  undefined local_8 [8];
  
  iVar1 = -param_1;
  *(undefined4 *)((int)auStack_1c + iVar1 + 0x10) = unaff_EBX;
  *(undefined4 *)((int)auStack_1c + iVar1 + 0xc) = unaff_ESI;
  *(undefined4 *)((int)auStack_1c + iVar1 + 8) = unaff_EDI;
  *(uint *)((int)auStack_1c + iVar1 + 4) = DAT_00423014 ^ (uint)&param_1;
  *(undefined4 *)((int)auStack_1c + iVar1) = unaff_retaddr;
  ExceptionList = local_8;
  return;
}



// WARNING: This is an inlined function
// WARNING: Unable to track spacebase fully for stack
// WARNING: Variable defined which should be unmapped: param_1
// Library Function - Single Match
//  __EH_prolog3_catch
// 
// Libraries: Visual Studio 2005, Visual Studio 2008, Visual Studio 2010, Visual Studio 2012

void __cdecl __EH_prolog3_catch(int param_1)

{
  int iVar1;
  undefined4 unaff_EBX;
  undefined4 unaff_ESI;
  undefined4 unaff_EDI;
  undefined4 unaff_retaddr;
  uint auStack_1c [5];
  undefined local_8 [8];
  
  iVar1 = -param_1;
  *(undefined4 *)((int)auStack_1c + iVar1 + 0x10) = unaff_EBX;
  *(undefined4 *)((int)auStack_1c + iVar1 + 0xc) = unaff_ESI;
  *(undefined4 *)((int)auStack_1c + iVar1 + 8) = unaff_EDI;
  *(uint *)((int)auStack_1c + iVar1 + 4) = DAT_00423014 ^ (uint)&param_1;
  *(undefined4 *)((int)auStack_1c + iVar1) = unaff_retaddr;
  ExceptionList = local_8;
  return;
}



void __cdecl FUN_0041a650(LPVOID param_1)

{
  thunk_FUN_0040caa5(param_1);
  return;
}



// Library Function - Single Match
//  __aulldiv
// 
// Library: Visual Studio

undefined8 __aulldiv(uint param_1,uint param_2,uint param_3,uint param_4)

{
  ulonglong uVar1;
  longlong lVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  
  uVar3 = param_1;
  uVar8 = param_4;
  uVar6 = param_2;
  uVar9 = param_3;
  if (param_4 == 0) {
    uVar3 = param_2 / param_3;
    iVar4 = (int)(((ulonglong)param_2 % (ulonglong)param_3 << 0x20 | (ulonglong)param_1) /
                 (ulonglong)param_3);
  }
  else {
    do {
      uVar5 = uVar8 >> 1;
      uVar9 = uVar9 >> 1 | (uint)((uVar8 & 1) != 0) << 0x1f;
      uVar7 = uVar6 >> 1;
      uVar3 = uVar3 >> 1 | (uint)((uVar6 & 1) != 0) << 0x1f;
      uVar8 = uVar5;
      uVar6 = uVar7;
    } while (uVar5 != 0);
    uVar1 = CONCAT44(uVar7,uVar3) / (ulonglong)uVar9;
    iVar4 = (int)uVar1;
    lVar2 = (ulonglong)param_3 * (uVar1 & 0xffffffff);
    uVar3 = (uint)((ulonglong)lVar2 >> 0x20);
    uVar8 = uVar3 + iVar4 * param_4;
    if (((CARRY4(uVar3,iVar4 * param_4)) || (param_2 < uVar8)) ||
       ((param_2 <= uVar8 && (param_1 < (uint)lVar2)))) {
      iVar4 = iVar4 + -1;
    }
    uVar3 = 0;
  }
  return CONCAT44(uVar3,iVar4);
}



// Library Function - Single Match
//  __aullrem
// 
// Library: Visual Studio

undefined8 __aullrem(uint param_1,uint param_2,uint param_3,uint param_4)

{
  ulonglong uVar1;
  longlong lVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  bool bVar11;
  
  uVar3 = param_1;
  uVar4 = param_4;
  uVar9 = param_2;
  uVar10 = param_3;
  if (param_4 == 0) {
    iVar6 = (int)(((ulonglong)param_2 % (ulonglong)param_3 << 0x20 | (ulonglong)param_1) %
                 (ulonglong)param_3);
    iVar7 = 0;
  }
  else {
    do {
      uVar5 = uVar4 >> 1;
      uVar10 = uVar10 >> 1 | (uint)((uVar4 & 1) != 0) << 0x1f;
      uVar8 = uVar9 >> 1;
      uVar3 = uVar3 >> 1 | (uint)((uVar9 & 1) != 0) << 0x1f;
      uVar4 = uVar5;
      uVar9 = uVar8;
    } while (uVar5 != 0);
    uVar1 = CONCAT44(uVar8,uVar3) / (ulonglong)uVar10;
    uVar3 = (int)uVar1 * param_4;
    lVar2 = (uVar1 & 0xffffffff) * (ulonglong)param_3;
    uVar9 = (uint)((ulonglong)lVar2 >> 0x20);
    uVar4 = (uint)lVar2;
    uVar10 = uVar9 + uVar3;
    if (((CARRY4(uVar9,uVar3)) || (param_2 < uVar10)) || ((param_2 <= uVar10 && (param_1 < uVar4))))
    {
      bVar11 = uVar4 < param_3;
      uVar4 = uVar4 - param_3;
      uVar10 = (uVar10 - param_4) - (uint)bVar11;
    }
    iVar6 = -(uVar4 - param_1);
    iVar7 = -(uint)(uVar4 - param_1 != 0) - ((uVar10 - param_2) - (uint)(uVar4 < param_1));
  }
  return CONCAT44(iVar7,iVar6);
}



// Library Function - Single Match
//  __allmul
// 
// Library: Visual Studio

longlong __allmul(uint param_1,uint param_2,uint param_3,uint param_4)

{
  if ((param_4 | param_2) == 0) {
    return (ulonglong)param_1 * (ulonglong)param_3;
  }
  return CONCAT44((int)((ulonglong)param_1 * (ulonglong)param_3 >> 0x20) +
                  param_2 * param_3 + param_1 * param_4,
                  (int)((ulonglong)param_1 * (ulonglong)param_3));
}



// Library Function - Single Match
//  __allshl
// 
// Library: Visual Studio 2019 Release

longlong __fastcall __allshl(byte param_1,int param_2)

{
  uint in_EAX;
  
  if (0x3f < param_1) {
    return 0;
  }
  if (param_1 < 0x20) {
    return CONCAT44(param_2 << (param_1 & 0x1f) | in_EAX >> 0x20 - (param_1 & 0x1f),
                    in_EAX << (param_1 & 0x1f));
  }
  return (ulonglong)(in_EAX << (param_1 & 0x1f)) << 0x20;
}



// Library Function - Single Match
//  __aullshr
// 
// Library: Visual Studio 2019 Release

ulonglong __fastcall __aullshr(byte param_1,uint param_2)

{
  uint in_EAX;
  
  if (0x3f < param_1) {
    return 0;
  }
  if (param_1 < 0x20) {
    return CONCAT44(param_2 >> (param_1 & 0x1f),
                    in_EAX >> (param_1 & 0x1f) | param_2 << 0x20 - (param_1 & 0x1f));
  }
  return (ulonglong)(param_2 >> (param_1 & 0x1f));
}



// Library Function - Single Match
//  __alldiv
// 
// Library: Visual Studio

undefined8 __alldiv(uint param_1,uint param_2,uint param_3,uint param_4)

{
  ulonglong uVar1;
  longlong lVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  bool bVar10;
  char cVar11;
  uint uVar9;
  
  cVar11 = (int)param_2 < 0;
  if ((bool)cVar11) {
    bVar10 = param_1 != 0;
    param_1 = -param_1;
    param_2 = -(uint)bVar10 - param_2;
  }
  if ((int)param_4 < 0) {
    cVar11 = cVar11 + '\x01';
    bVar10 = param_3 != 0;
    param_3 = -param_3;
    param_4 = -(uint)bVar10 - param_4;
  }
  uVar3 = param_1;
  uVar5 = param_3;
  uVar6 = param_2;
  uVar9 = param_4;
  if (param_4 == 0) {
    uVar3 = param_2 / param_3;
    iVar4 = (int)(((ulonglong)param_2 % (ulonglong)param_3 << 0x20 | (ulonglong)param_1) /
                 (ulonglong)param_3);
  }
  else {
    do {
      uVar8 = uVar9 >> 1;
      uVar5 = uVar5 >> 1 | (uint)((uVar9 & 1) != 0) << 0x1f;
      uVar7 = uVar6 >> 1;
      uVar3 = uVar3 >> 1 | (uint)((uVar6 & 1) != 0) << 0x1f;
      uVar6 = uVar7;
      uVar9 = uVar8;
    } while (uVar8 != 0);
    uVar1 = CONCAT44(uVar7,uVar3) / (ulonglong)uVar5;
    iVar4 = (int)uVar1;
    lVar2 = (ulonglong)param_3 * (uVar1 & 0xffffffff);
    uVar3 = (uint)((ulonglong)lVar2 >> 0x20);
    uVar5 = uVar3 + iVar4 * param_4;
    if (((CARRY4(uVar3,iVar4 * param_4)) || (param_2 < uVar5)) ||
       ((param_2 <= uVar5 && (param_1 < (uint)lVar2)))) {
      iVar4 = iVar4 + -1;
    }
    uVar3 = 0;
  }
  if (cVar11 == '\x01') {
    bVar10 = iVar4 != 0;
    iVar4 = -iVar4;
    uVar3 = -(uint)bVar10 - uVar3;
  }
  return CONCAT44(uVar3,iVar4);
}



// Library Function - Single Match
//  __allrem
// 
// Library: Visual Studio

undefined8 __allrem(uint param_1,uint param_2,uint param_3,uint param_4)

{
  ulonglong uVar1;
  longlong lVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  bool bVar12;
  bool bVar13;
  
  bVar13 = (int)param_2 < 0;
  if (bVar13) {
    bVar12 = param_1 != 0;
    param_1 = -param_1;
    param_2 = -(uint)bVar12 - param_2;
  }
  uVar11 = (uint)bVar13;
  if ((int)param_4 < 0) {
    bVar13 = param_3 != 0;
    param_3 = -param_3;
    param_4 = -(uint)bVar13 - param_4;
  }
  uVar3 = param_1;
  uVar4 = param_3;
  uVar8 = param_2;
  uVar9 = param_4;
  if (param_4 == 0) {
    iVar5 = (int)(((ulonglong)param_2 % (ulonglong)param_3 << 0x20 | (ulonglong)param_1) %
                 (ulonglong)param_3);
    iVar6 = 0;
    if ((int)(uVar11 - 1) < 0) goto LAB_0041a92d;
  }
  else {
    do {
      uVar10 = uVar9 >> 1;
      uVar4 = uVar4 >> 1 | (uint)((uVar9 & 1) != 0) << 0x1f;
      uVar7 = uVar8 >> 1;
      uVar3 = uVar3 >> 1 | (uint)((uVar8 & 1) != 0) << 0x1f;
      uVar8 = uVar7;
      uVar9 = uVar10;
    } while (uVar10 != 0);
    uVar1 = CONCAT44(uVar7,uVar3) / (ulonglong)uVar4;
    uVar3 = (int)uVar1 * param_4;
    lVar2 = (uVar1 & 0xffffffff) * (ulonglong)param_3;
    uVar8 = (uint)((ulonglong)lVar2 >> 0x20);
    uVar4 = (uint)lVar2;
    uVar9 = uVar8 + uVar3;
    if (((CARRY4(uVar8,uVar3)) || (param_2 < uVar9)) || ((param_2 <= uVar9 && (param_1 < uVar4)))) {
      bVar13 = uVar4 < param_3;
      uVar4 = uVar4 - param_3;
      uVar9 = (uVar9 - param_4) - (uint)bVar13;
    }
    iVar5 = uVar4 - param_1;
    iVar6 = (uVar9 - param_2) - (uint)(uVar4 < param_1);
    if (-1 < (int)(uVar11 - 1)) goto LAB_0041a92d;
  }
  bVar13 = iVar5 != 0;
  iVar5 = -iVar5;
  iVar6 = -(uint)bVar13 - iVar6;
LAB_0041a92d:
  return CONCAT44(iVar6,iVar5);
}



// WARNING: This is an inlined function
// WARNING: Function: __alloca_probe replaced with injection: alloca_probe
// Library Function - Single Match
//  __alloca_probe_16
// 
// Library: Visual Studio

uint __alloca_probe_16(undefined1 param_1)

{
  uint in_EAX;
  uint uVar1;
  
  uVar1 = 4 - in_EAX & 0xf;
  return in_EAX + uVar1 | -(uint)CARRY4(in_EAX,uVar1);
}



// WARNING: This is an inlined function
// WARNING: Function: __alloca_probe replaced with injection: alloca_probe
// Library Function - Single Match
//  __alloca_probe_8
// 
// Library: Visual Studio

uint __alloca_probe_8(undefined1 param_1)

{
  uint in_EAX;
  uint uVar1;
  
  uVar1 = 4 - in_EAX & 7;
  return in_EAX + uVar1 | -(uint)CARRY4(in_EAX,uVar1);
}



// WARNING: This is an inlined function
// Library Function - Single Match
//  __chkstk
// 
// Library: Visual Studio 2019 Release

void __alloca_probe(void)

{
  undefined *in_EAX;
  undefined4 *puVar1;
  undefined4 *puVar2;
  undefined4 unaff_retaddr;
  undefined auStack_4 [4];
  
  puVar2 = (undefined4 *)((int)&stack0x00000000 - (int)in_EAX & ~-(uint)(&stack0x00000000 < in_EAX))
  ;
  for (puVar1 = (undefined4 *)((uint)auStack_4 & 0xfffff000); puVar2 < puVar1;
      puVar1 = puVar1 + -0x400) {
  }
  *puVar2 = unaff_retaddr;
  return;
}



uint thunk_FUN_0041a9b0(void)

{
  uint uVar1;
  ushort uVar2;
  float10 in_ST0;
  uint uStack_1c;
  ushort uStack_18;
  
  if (1 < DAT_0042393c) {
    return (int)in_ST0;
  }
  uStack_1c = (uint)((unkuint10)in_ST0 >> 0x20);
  uStack_18 = (ushort)((unkuint10)in_ST0 >> 0x40);
  uVar2 = uStack_18 & 0x7fff;
  uVar1 = (uint)((short)uStack_18 < 0);
  if (uVar2 < 0x3fff) {
    return 0;
  }
  if ((int)uStack_1c < 0) {
    if (uVar2 < 0x401e) {
      return (uStack_1c >> (0x3eU - (char)uVar2 & 0x1f) ^ -uVar1) + uVar1;
    }
    if (((uVar2 < 0x401f) && (uVar1 != 0)) && (uStack_1c == 0x80000000)) {
      return uStack_1c;
    }
  }
  return 0x80000000;
}



uint FUN_0041a9b0(void)

{
  uint uVar1;
  ushort uVar2;
  float10 in_ST0;
  uint uStack_1c;
  ushort uStack_18;
  
  if (1 < DAT_0042393c) {
    return (int)in_ST0;
  }
  uStack_1c = (uint)((unkuint10)in_ST0 >> 0x20);
  uStack_18 = (ushort)((unkuint10)in_ST0 >> 0x40);
  uVar2 = uStack_18 & 0x7fff;
  uVar1 = (uint)((short)uStack_18 < 0);
  if (uVar2 < 0x3fff) {
    return 0;
  }
  if ((int)uStack_1c < 0) {
    if (uVar2 < 0x401e) {
      return (uStack_1c >> (0x3eU - (char)uVar2 & 0x1f) ^ -uVar1) + uVar1;
    }
    if (((uVar2 < 0x401f) && (uVar1 != 0)) && (uStack_1c == 0x80000000)) {
      return uStack_1c;
    }
  }
  return 0x80000000;
}



void __cdecl thunk_FUN_0040caa5(LPVOID param_1)

{
  FUN_0040e374(param_1);
  return;
}



// Library Function - Single Match
//  _strrchr
// 
// Libraries: Visual Studio 2012, Visual Studio 2015, Visual Studio 2017, Visual Studio 2019

char * __cdecl _strrchr(char *_Str,int _Ch)

{
  char cVar1;
  uint uVar2;
  undefined (*pauVar3) [16];
  uint uVar4;
  int iVar5;
  char *pcVar6;
  char *pcVar7;
  undefined (*pauVar8) [16];
  undefined auVar9 [16];
  undefined auVar10 [16];
  undefined auVar11 [16];
  undefined auVar12 [16];
  
  if (DAT_0042393c != 0) {
    if (DAT_0042393c < 2) {
      auVar12 = pshuflw(ZEXT216(CONCAT11((char)_Ch,(char)_Ch)),
                        ZEXT216(CONCAT11((char)_Ch,(char)_Ch)),0);
      uVar2 = -1 << (sbyte)((uint)_Str & 0xf);
      pcVar7 = _Str + -((uint)_Str & 0xf);
      pcVar6 = (char *)0x0;
      while( true ) {
        auVar11[0] = -(*pcVar7 == '\0');
        auVar11[1] = -(pcVar7[1] == '\0');
        auVar11[2] = -(pcVar7[2] == '\0');
        auVar11[3] = -(pcVar7[3] == '\0');
        auVar11[4] = -(pcVar7[4] == '\0');
        auVar11[5] = -(pcVar7[5] == '\0');
        auVar11[6] = -(pcVar7[6] == '\0');
        auVar11[7] = -(pcVar7[7] == '\0');
        auVar11[8] = -(pcVar7[8] == '\0');
        auVar11[9] = -(pcVar7[9] == '\0');
        auVar11[10] = -(pcVar7[10] == '\0');
        auVar11[11] = -(pcVar7[0xb] == '\0');
        auVar11[12] = -(pcVar7[0xc] == '\0');
        auVar11[13] = -(pcVar7[0xd] == '\0');
        auVar11[14] = -(pcVar7[0xe] == '\0');
        auVar11[15] = -(pcVar7[0xf] == '\0');
        auVar10[0] = -(*pcVar7 == auVar12[0]);
        auVar10[1] = -(pcVar7[1] == auVar12[1]);
        auVar10[2] = -(pcVar7[2] == auVar12[2]);
        auVar10[3] = -(pcVar7[3] == auVar12[3]);
        auVar10[4] = -(pcVar7[4] == auVar12[4]);
        auVar10[5] = -(pcVar7[5] == auVar12[5]);
        auVar10[6] = -(pcVar7[6] == auVar12[6]);
        auVar10[7] = -(pcVar7[7] == auVar12[7]);
        auVar10[8] = -(pcVar7[8] == auVar12[0]);
        auVar10[9] = -(pcVar7[9] == auVar12[1]);
        auVar10[10] = -(pcVar7[10] == auVar12[2]);
        auVar10[11] = -(pcVar7[0xb] == auVar12[3]);
        auVar10[12] = -(pcVar7[0xc] == auVar12[4]);
        auVar10[13] = -(pcVar7[0xd] == auVar12[5]);
        auVar10[14] = -(pcVar7[0xe] == auVar12[6]);
        auVar10[15] = -(pcVar7[0xf] == auVar12[7]);
        uVar4 = (ushort)((ushort)(SUB161(auVar11 >> 7,0) & 1) |
                         (ushort)(SUB161(auVar11 >> 0xf,0) & 1) << 1 |
                         (ushort)(SUB161(auVar11 >> 0x17,0) & 1) << 2 |
                         (ushort)(SUB161(auVar11 >> 0x1f,0) & 1) << 3 |
                         (ushort)(SUB161(auVar11 >> 0x27,0) & 1) << 4 |
                         (ushort)(SUB161(auVar11 >> 0x2f,0) & 1) << 5 |
                         (ushort)(SUB161(auVar11 >> 0x37,0) & 1) << 6 |
                         (ushort)(SUB161(auVar11 >> 0x3f,0) & 1) << 7 |
                         (ushort)(SUB161(auVar11 >> 0x47,0) & 1) << 8 |
                         (ushort)(SUB161(auVar11 >> 0x4f,0) & 1) << 9 |
                         (ushort)(SUB161(auVar11 >> 0x57,0) & 1) << 10 |
                         (ushort)(SUB161(auVar11 >> 0x5f,0) & 1) << 0xb |
                         (ushort)(SUB161(auVar11 >> 0x67,0) & 1) << 0xc |
                         (ushort)(SUB161(auVar11 >> 0x6f,0) & 1) << 0xd |
                         (ushort)(SUB161(auVar11 >> 0x77,0) & 1) << 0xe |
                        (ushort)(auVar11[15] >> 7) << 0xf) & uVar2;
        if (uVar4 != 0) break;
        uVar2 = (ushort)((ushort)(SUB161(auVar10 >> 7,0) & 1) |
                         (ushort)(SUB161(auVar10 >> 0xf,0) & 1) << 1 |
                         (ushort)(SUB161(auVar10 >> 0x17,0) & 1) << 2 |
                         (ushort)(SUB161(auVar10 >> 0x1f,0) & 1) << 3 |
                         (ushort)(SUB161(auVar10 >> 0x27,0) & 1) << 4 |
                         (ushort)(SUB161(auVar10 >> 0x2f,0) & 1) << 5 |
                         (ushort)(SUB161(auVar10 >> 0x37,0) & 1) << 6 |
                         (ushort)(SUB161(auVar10 >> 0x3f,0) & 1) << 7 |
                         (ushort)(SUB161(auVar10 >> 0x47,0) & 1) << 8 |
                         (ushort)(SUB161(auVar10 >> 0x4f,0) & 1) << 9 |
                         (ushort)(SUB161(auVar10 >> 0x57,0) & 1) << 10 |
                         (ushort)(SUB161(auVar10 >> 0x5f,0) & 1) << 0xb |
                         (ushort)(SUB161(auVar10 >> 0x67,0) & 1) << 0xc |
                         (ushort)(SUB161(auVar10 >> 0x6f,0) & 1) << 0xd |
                         (ushort)(SUB161(auVar10 >> 0x77,0) & 1) << 0xe |
                        (ushort)(auVar10[15] >> 7) << 0xf) & uVar2;
        iVar5 = 0x1f;
        if (uVar2 != 0) {
          for (; uVar2 >> iVar5 == 0; iVar5 = iVar5 + -1) {
          }
        }
        if (uVar2 != 0) {
          pcVar6 = pcVar7 + iVar5;
        }
        uVar2 = 0xffffffff;
        pcVar7 = pcVar7 + 0x10;
      }
      uVar2 = (uVar4 * 2 & uVar4 * -2) - 1 &
              (ushort)((ushort)(SUB161(auVar10 >> 7,0) & 1) |
                       (ushort)(SUB161(auVar10 >> 0xf,0) & 1) << 1 |
                       (ushort)(SUB161(auVar10 >> 0x17,0) & 1) << 2 |
                       (ushort)(SUB161(auVar10 >> 0x1f,0) & 1) << 3 |
                       (ushort)(SUB161(auVar10 >> 0x27,0) & 1) << 4 |
                       (ushort)(SUB161(auVar10 >> 0x2f,0) & 1) << 5 |
                       (ushort)(SUB161(auVar10 >> 0x37,0) & 1) << 6 |
                       (ushort)(SUB161(auVar10 >> 0x3f,0) & 1) << 7 |
                       (ushort)(SUB161(auVar10 >> 0x47,0) & 1) << 8 |
                       (ushort)(SUB161(auVar10 >> 0x4f,0) & 1) << 9 |
                       (ushort)(SUB161(auVar10 >> 0x57,0) & 1) << 10 |
                       (ushort)(SUB161(auVar10 >> 0x5f,0) & 1) << 0xb |
                       (ushort)(SUB161(auVar10 >> 0x67,0) & 1) << 0xc |
                       (ushort)(SUB161(auVar10 >> 0x6f,0) & 1) << 0xd |
                       (ushort)(SUB161(auVar10 >> 0x77,0) & 1) << 0xe |
                      (ushort)(auVar10[15] >> 7) << 0xf) & uVar2;
      iVar5 = 0x1f;
      if (uVar2 != 0) {
        for (; uVar2 >> iVar5 == 0; iVar5 = iVar5 + -1) {
        }
      }
      pcVar7 = pcVar7 + iVar5;
      if (uVar2 == 0) {
        pcVar7 = pcVar6;
      }
      return pcVar7;
    }
    uVar2 = _Ch & 0xff;
    if (uVar2 == 0) {
      pcVar6 = (char *)((uint)_Str & 0xfffffff0);
      auVar12[0] = -(*pcVar6 == '\0');
      auVar12[1] = -(pcVar6[1] == '\0');
      auVar12[2] = -(pcVar6[2] == '\0');
      auVar12[3] = -(pcVar6[3] == '\0');
      auVar12[4] = -(pcVar6[4] == '\0');
      auVar12[5] = -(pcVar6[5] == '\0');
      auVar12[6] = -(pcVar6[6] == '\0');
      auVar12[7] = -(pcVar6[7] == '\0');
      auVar12[8] = -(pcVar6[8] == '\0');
      auVar12[9] = -(pcVar6[9] == '\0');
      auVar12[10] = -(pcVar6[10] == '\0');
      auVar12[11] = -(pcVar6[0xb] == '\0');
      auVar12[12] = -(pcVar6[0xc] == '\0');
      auVar12[13] = -(pcVar6[0xd] == '\0');
      auVar12[14] = -(pcVar6[0xe] == '\0');
      auVar12[15] = -(pcVar6[0xf] == '\0');
      uVar2 = (uint)(ushort)((ushort)(SUB161(auVar12 >> 7,0) & 1) |
                             (ushort)(SUB161(auVar12 >> 0xf,0) & 1) << 1 |
                             (ushort)(SUB161(auVar12 >> 0x17,0) & 1) << 2 |
                             (ushort)(SUB161(auVar12 >> 0x1f,0) & 1) << 3 |
                             (ushort)(SUB161(auVar12 >> 0x27,0) & 1) << 4 |
                             (ushort)(SUB161(auVar12 >> 0x2f,0) & 1) << 5 |
                             (ushort)(SUB161(auVar12 >> 0x37,0) & 1) << 6 |
                             (ushort)(SUB161(auVar12 >> 0x3f,0) & 1) << 7 |
                             (ushort)(SUB161(auVar12 >> 0x47,0) & 1) << 8 |
                             (ushort)(SUB161(auVar12 >> 0x4f,0) & 1) << 9 |
                             (ushort)(SUB161(auVar12 >> 0x57,0) & 1) << 10 |
                             (ushort)(SUB161(auVar12 >> 0x5f,0) & 1) << 0xb |
                             (ushort)(SUB161(auVar12 >> 0x67,0) & 1) << 0xc |
                             (ushort)(SUB161(auVar12 >> 0x6f,0) & 1) << 0xd |
                             (ushort)(SUB161(auVar12 >> 0x77,0) & 1) << 0xe |
                            (ushort)(auVar12[15] >> 7) << 0xf) & -1 << ((byte)_Str & 0xf);
      while (uVar2 == 0) {
        auVar9[0] = -(pcVar6[0x10] == '\0');
        auVar9[1] = -(pcVar6[0x11] == '\0');
        auVar9[2] = -(pcVar6[0x12] == '\0');
        auVar9[3] = -(pcVar6[0x13] == '\0');
        auVar9[4] = -(pcVar6[0x14] == '\0');
        auVar9[5] = -(pcVar6[0x15] == '\0');
        auVar9[6] = -(pcVar6[0x16] == '\0');
        auVar9[7] = -(pcVar6[0x17] == '\0');
        auVar9[8] = -(pcVar6[0x18] == '\0');
        auVar9[9] = -(pcVar6[0x19] == '\0');
        auVar9[10] = -(pcVar6[0x1a] == '\0');
        auVar9[11] = -(pcVar6[0x1b] == '\0');
        auVar9[12] = -(pcVar6[0x1c] == '\0');
        auVar9[13] = -(pcVar6[0x1d] == '\0');
        auVar9[14] = -(pcVar6[0x1e] == '\0');
        auVar9[15] = -(pcVar6[0x1f] == '\0');
        pcVar6 = pcVar6 + 0x10;
        uVar2 = (uint)(ushort)((ushort)(SUB161(auVar9 >> 7,0) & 1) |
                               (ushort)(SUB161(auVar9 >> 0xf,0) & 1) << 1 |
                               (ushort)(SUB161(auVar9 >> 0x17,0) & 1) << 2 |
                               (ushort)(SUB161(auVar9 >> 0x1f,0) & 1) << 3 |
                               (ushort)(SUB161(auVar9 >> 0x27,0) & 1) << 4 |
                               (ushort)(SUB161(auVar9 >> 0x2f,0) & 1) << 5 |
                               (ushort)(SUB161(auVar9 >> 0x37,0) & 1) << 6 |
                               (ushort)(SUB161(auVar9 >> 0x3f,0) & 1) << 7 |
                               (ushort)(SUB161(auVar9 >> 0x47,0) & 1) << 8 |
                               (ushort)(SUB161(auVar9 >> 0x4f,0) & 1) << 9 |
                               (ushort)(SUB161(auVar9 >> 0x57,0) & 1) << 10 |
                               (ushort)(SUB161(auVar9 >> 0x5f,0) & 1) << 0xb |
                               (ushort)(SUB161(auVar9 >> 0x67,0) & 1) << 0xc |
                               (ushort)(SUB161(auVar9 >> 0x6f,0) & 1) << 0xd |
                               (ushort)(SUB161(auVar9 >> 0x77,0) & 1) << 0xe |
                              (ushort)(auVar9[15] >> 7) << 0xf);
      }
      iVar5 = 0;
      if (uVar2 != 0) {
        for (; (uVar2 >> iVar5 & 1) == 0; iVar5 = iVar5 + 1) {
        }
      }
      pauVar3 = (undefined (*) [16])(pcVar6 + iVar5);
    }
    else {
      pauVar3 = (undefined (*) [16])0x0;
      uVar4 = (uint)_Str & 0xf;
      while (uVar4 != 0) {
        if ((byte)*_Str == uVar2) {
          pauVar3 = (undefined (*) [16])_Str;
        }
        if ((byte)*_Str == 0) {
          return (char *)pauVar3;
        }
        _Str = _Str + 1;
        uVar4 = (uint)_Str & 0xf;
      }
      do {
        pauVar8 = (undefined (*) [16])((int)_Str + 0x10);
        iVar5 = pcmpistri(ZEXT416(uVar2),*(undefined (*) [16])_Str,0x40);
        if ((undefined (*) [16])0xffffffef < _Str) {
          pauVar3 = (undefined (*) [16])(pauVar8[-1] + iVar5);
        }
        _Str = (char *)pauVar8;
      } while (pauVar8 != (undefined (*) [16])0x0);
    }
    return (char *)pauVar3;
  }
  iVar5 = -1;
  do {
    pcVar6 = _Str;
    if (iVar5 == 0) break;
    iVar5 = iVar5 + -1;
    pcVar6 = _Str + 1;
    cVar1 = *_Str;
    _Str = pcVar6;
  } while (cVar1 != '\0');
  iVar5 = -(iVar5 + 1);
  pcVar6 = pcVar6 + -1;
  do {
    pcVar7 = pcVar6;
    if (iVar5 == 0) break;
    iVar5 = iVar5 + -1;
    pcVar7 = pcVar6 + -1;
    cVar1 = *pcVar6;
    pcVar6 = pcVar7;
  } while ((char)_Ch != cVar1);
  pcVar7 = pcVar7 + 1;
  if (*pcVar7 != (char)_Ch) {
    pcVar7 = (char *)0x0;
  }
  return pcVar7;
}



// Library Function - Single Match
//  _strchr
// 
// Libraries: Visual Studio 2012, Visual Studio 2015, Visual Studio 2017, Visual Studio 2019

char * __cdecl _strchr(char *_Str,int _Val)

{
  int iVar1;
  char cVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  char *pcVar6;
  uint *puVar7;
  undefined auVar8 [16];
  undefined auVar9 [16];
  undefined auVar10 [16];
  
  if (DAT_0042393c != 0) {
    auVar10 = pshuflw(ZEXT216(CONCAT11((char)_Val,(char)_Val)),
                      ZEXT216(CONCAT11((char)_Val,(char)_Val)),0);
    uVar3 = -1 << (sbyte)((uint)_Str & 0xf);
    pcVar6 = _Str + -((uint)_Str & 0xf);
    while( true ) {
      auVar9[0] = -(*pcVar6 == '\0');
      auVar9[1] = -(pcVar6[1] == '\0');
      auVar9[2] = -(pcVar6[2] == '\0');
      auVar9[3] = -(pcVar6[3] == '\0');
      auVar9[4] = -(pcVar6[4] == '\0');
      auVar9[5] = -(pcVar6[5] == '\0');
      auVar9[6] = -(pcVar6[6] == '\0');
      auVar9[7] = -(pcVar6[7] == '\0');
      auVar9[8] = -(pcVar6[8] == '\0');
      auVar9[9] = -(pcVar6[9] == '\0');
      auVar9[10] = -(pcVar6[10] == '\0');
      auVar9[11] = -(pcVar6[0xb] == '\0');
      auVar9[12] = -(pcVar6[0xc] == '\0');
      auVar9[13] = -(pcVar6[0xd] == '\0');
      auVar9[14] = -(pcVar6[0xe] == '\0');
      auVar9[15] = -(pcVar6[0xf] == '\0');
      cVar2 = auVar10[0];
      auVar8[0] = -(*pcVar6 == cVar2);
      auVar8[1] = -(pcVar6[1] == auVar10[1]);
      auVar8[2] = -(pcVar6[2] == auVar10[2]);
      auVar8[3] = -(pcVar6[3] == auVar10[3]);
      auVar8[4] = -(pcVar6[4] == auVar10[4]);
      auVar8[5] = -(pcVar6[5] == auVar10[5]);
      auVar8[6] = -(pcVar6[6] == auVar10[6]);
      auVar8[7] = -(pcVar6[7] == auVar10[7]);
      auVar8[8] = -(pcVar6[8] == cVar2);
      auVar8[9] = -(pcVar6[9] == auVar10[1]);
      auVar8[10] = -(pcVar6[10] == auVar10[2]);
      auVar8[11] = -(pcVar6[0xb] == auVar10[3]);
      auVar8[12] = -(pcVar6[0xc] == auVar10[4]);
      auVar8[13] = -(pcVar6[0xd] == auVar10[5]);
      auVar8[14] = -(pcVar6[0xe] == auVar10[6]);
      auVar8[15] = -(pcVar6[0xf] == auVar10[7]);
      auVar9 = auVar9 | auVar8;
      uVar3 = (ushort)((ushort)(SUB161(auVar9 >> 7,0) & 1) |
                       (ushort)(SUB161(auVar9 >> 0xf,0) & 1) << 1 |
                       (ushort)(SUB161(auVar9 >> 0x17,0) & 1) << 2 |
                       (ushort)(SUB161(auVar9 >> 0x1f,0) & 1) << 3 |
                       (ushort)(SUB161(auVar9 >> 0x27,0) & 1) << 4 |
                       (ushort)(SUB161(auVar9 >> 0x2f,0) & 1) << 5 |
                       (ushort)(SUB161(auVar9 >> 0x37,0) & 1) << 6 |
                       (ushort)(SUB161(auVar9 >> 0x3f,0) & 1) << 7 |
                       (ushort)(SUB161(auVar9 >> 0x47,0) & 1) << 8 |
                       (ushort)(SUB161(auVar9 >> 0x4f,0) & 1) << 9 |
                       (ushort)(SUB161(auVar9 >> 0x57,0) & 1) << 10 |
                       (ushort)(SUB161(auVar9 >> 0x5f,0) & 1) << 0xb |
                       (ushort)(SUB161(auVar9 >> 0x67,0) & 1) << 0xc |
                       (ushort)(SUB161(auVar9 >> 0x6f,0) & 1) << 0xd |
                       (ushort)(SUB161(auVar9 >> 0x77,0) & 1) << 0xe |
                      (ushort)(byte)(auVar9[15] >> 7) << 0xf) & uVar3;
      if (uVar3 != 0) break;
      uVar3 = 0xffffffff;
      pcVar6 = pcVar6 + 0x10;
    }
    iVar1 = 0;
    if (uVar3 != 0) {
      for (; (uVar3 >> iVar1 & 1) == 0; iVar1 = iVar1 + 1) {
      }
    }
    pcVar6 = pcVar6 + iVar1;
    if (cVar2 != *pcVar6) {
      pcVar6 = (char *)0x0;
    }
    return pcVar6;
  }
  uVar3 = (uint)_Str & 3;
  while (uVar3 != 0) {
    if (*_Str == (char)_Val) {
      return (char *)(uint *)_Str;
    }
    if (*_Str == '\0') {
      return (char *)0x0;
    }
    uVar3 = (uint)(uint *)((int)_Str + 1) & 3;
    _Str = (char *)(uint *)((int)_Str + 1);
  }
  while( true ) {
    while( true ) {
      uVar3 = *(uint *)_Str;
      uVar5 = uVar3 ^ CONCAT22(CONCAT11((char)_Val,(char)_Val),CONCAT11((char)_Val,(char)_Val));
      uVar4 = uVar3 ^ 0xffffffff ^ uVar3 + 0x7efefeff;
      puVar7 = (uint *)((int)_Str + 4);
      if (((uVar5 ^ 0xffffffff ^ uVar5 + 0x7efefeff) & 0x81010100) != 0) break;
      _Str = (char *)puVar7;
      if ((uVar4 & 0x81010100) != 0) {
        if ((uVar4 & 0x1010100) != 0) {
          return (char *)0x0;
        }
        if ((uVar3 + 0x7efefeff & 0x80000000) == 0) {
          return (char *)0x0;
        }
      }
    }
    uVar3 = *(uint *)_Str;
    if ((char)uVar3 == (char)_Val) {
      return (char *)(uint *)_Str;
    }
    if ((char)uVar3 == '\0') {
      return (char *)0x0;
    }
    cVar2 = (char)(uVar3 >> 8);
    if (cVar2 == (char)_Val) {
      return (char *)((int)_Str + 1);
    }
    if (cVar2 == '\0') break;
    cVar2 = (char)(uVar3 >> 0x10);
    if (cVar2 == (char)_Val) {
      return (char *)((int)_Str + 2);
    }
    if (cVar2 == '\0') {
      return (char *)0x0;
    }
    cVar2 = (char)(uVar3 >> 0x18);
    if (cVar2 == (char)_Val) {
      return (char *)((int)_Str + 3);
    }
    _Str = (char *)puVar7;
    if (cVar2 == '\0') {
      return (char *)0x0;
    }
  }
  return (char *)0x0;
}



// Library Function - Single Match
//  __filter_x86_sse2_floating_point_exception_default
// 
// Library: Visual Studio 2019 Release

int __cdecl __filter_x86_sse2_floating_point_exception_default(int param_1)

{
  uint uVar1;
  
  if ((DAT_0042393c < 1) || ((param_1 != -0x3ffffd4c && (param_1 != -0x3ffffd4b)))) {
    return param_1;
  }
  uVar1 = MXCSR ^ 0x3f;
  if ((uVar1 & 0x81) != 0) {
    if ((uVar1 & 0x204) == 0) {
      return -0x3fffff72;
    }
    if ((uVar1 & 0x102) != 0) {
      if ((uVar1 & 0x408) == 0) {
        return -0x3fffff6f;
      }
      if ((uVar1 & 0x810) != 0) {
        if ((uVar1 & 0x1020) != 0) {
          return param_1;
        }
        return -0x3fffff71;
      }
      return -0x3fffff6d;
    }
  }
  return -0x3fffff70;
}


