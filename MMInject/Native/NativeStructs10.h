#pragma once

//
// Native structures W10
//
#pragma warning(disable : 4214 4201)
#pragma pack(push, 1)

typedef struct _MM_AVL_NODE // Size=24
{
	struct _MM_AVL_NODE *LeftChild; // Size=8 Offset=0
	struct _MM_AVL_NODE *RightChild; // Size=8 Offset=8

	union ___unnamed1666 // Size=8
	{
		struct
		{
			__int64 Balance : 2; // Size=8 Offset=0 BitOffset=0 BitCount=2
		};
		struct _MM_AVL_NODE *Parent; // Size=8 Offset=0
	} u1;
} MM_AVL_NODE, *PMM_AVL_NODE, *PMMADDRESS_NODE;

typedef struct _RTL_AVL_TREE // Size=8
{
	PMM_AVL_NODE BalancedRoot;
	void *NodeHint;
	unsigned __int64 NumberGenericTableElements;
} RTL_AVL_TREE, *PRTL_AVL_TREE, MM_AVL_TABLE, *PMM_AVL_TABLE;

union _EX_PUSH_LOCK // Size=8
{
	struct
	{
		unsigned __int64 Locked : 1; // Size=8 Offset=0 BitOffset=0 BitCount=1
		unsigned __int64 Waiting : 1; // Size=8 Offset=0 BitOffset=1 BitCount=1
		unsigned __int64 Waking : 1; // Size=8 Offset=0 BitOffset=2 BitCount=1
		unsigned __int64 MultipleShared : 1; // Size=8 Offset=0 BitOffset=3 BitCount=1
		unsigned __int64 Shared : 60; // Size=8 Offset=0 BitOffset=4 BitCount=60
	};
	unsigned __int64 Value; // Size=8 Offset=0
	void *Ptr; // Size=8 Offset=0
};

struct _MMVAD_FLAGS // Size=4 // PRE 19H1
{
	unsigned long VadType : 3; // Size=4 Offset=0 BitOffset=0 BitCount=3
	unsigned long Protection : 5; // Size=4 Offset=0 BitOffset=3 BitCount=5
	unsigned long PreferredNode : 6; // Size=4 Offset=0 BitOffset=8 BitCount=6
	unsigned long NoChange : 1; // Size=4 Offset=0 BitOffset=14 BitCount=1
	unsigned long PrivateMemory : 1; // Size=4 Offset=0 BitOffset=15 BitCount=1
	unsigned long Teb : 1; // Size=4 Offset=0 BitOffset=16 BitCount=1
	unsigned long PrivateFixup : 1; // Size=4 Offset=0 BitOffset=17 BitCount=1
	unsigned long ManySubsections : 1; // Size=4 Offset=0 BitOffset=18 BitCount=1
	unsigned long Spare : 12; // Size=4 Offset=0 BitOffset=19 BitCount=12
	unsigned long DeleteInProgress : 1; // Size=4 Offset=0 BitOffset=31 BitCount=1
};

struct _MMVAD_FLAGS_19H1
{
	unsigned long Lock : 1;
	unsigned long LockContended : 1;
	unsigned long DeleteInProgress : 1;
	unsigned long NoChange : 1;
	unsigned long VadType : 3;
	unsigned long Protection : 5;
	unsigned long PreferredNode : 6;
	unsigned long PageSize : 2;
	unsigned long PrivateMemory : 1;
};

struct _MMVAD_FLAGS1 // Size=4
{
	unsigned long CommitCharge : 31; // Size=4 Offset=0 BitOffset=0 BitCount=31
	unsigned long MemCommit : 1; // Size=4 Offset=0 BitOffset=31 BitCount=1
};

struct _MMVAD_FLAGS2 // Size=4 // PRE 19H1
{
	unsigned long FileOffset : 24; // Size=4 Offset=0 BitOffset=0 BitCount=24
	unsigned long Large : 1; // Size=4 Offset=0 BitOffset=24 BitCount=1
	unsigned long TrimBehind : 1; // Size=4 Offset=0 BitOffset=25 BitCount=1
	unsigned long Inherit : 1; // Size=4 Offset=0 BitOffset=26 BitCount=1
	unsigned long CopyOnWrite : 1; // Size=4 Offset=0 BitOffset=27 BitCount=1
	unsigned long NoValidationNeeded : 1; // Size=4 Offset=0 BitOffset=28 BitCount=1
	unsigned long Spare : 3; // Size=4 Offset=0 BitOffset=29 BitCount=3
};

struct _MMVAD_FLAGS2_19H1
{
	unsigned long FileOffset : 24;
	unsigned long Large : 1;
	unsigned long TrimBehind : 1;
	unsigned long Inherit : 1;
	unsigned long NoValidationNeeded : 1;
	unsigned long PrivateDemandZero : 1;
	unsigned long Spare : 3;
};

struct _MI_VAD_SEQUENTIAL_INFO // Size=8
{
	unsigned __int64 Length : 12; // Size=8 Offset=0 BitOffset=0 BitCount=12
	unsigned __int64 Vpn : 52; // Size=8 Offset=0 BitOffset=12 BitCount=52
};

union ___unnamed1951 // Size=4
{
	unsigned long LongFlags; // Size=4 Offset=0
	struct _MMVAD_FLAGS VadFlags; // Size=4 Offset=0
};

union ___unnamed1952 // Size=4
{
	unsigned long LongFlags1; // Size=4 Offset=0
	struct _MMVAD_FLAGS1 VadFlags1; // Size=4 Offset=0
};

union ___unnamed2047 // Size=4
{
	unsigned long LongFlags2; // Size=4 Offset=0
	union
	{
		struct _MMVAD_FLAGS2 VadFlags2; // Size=4 Offset=0 // PRE 19H1
		struct _MMVAD_FLAGS2_19H1 VadFlags219H1; // Size=4 Offset=0
	};
};

union ___unnamed2048 // Size=8
{
	struct _MI_VAD_SEQUENTIAL_INFO SequentialVa; // Size=8 Offset=0
	struct _MMEXTEND_INFO *ExtendedInfo; // Size=8 Offset=0
};

typedef struct _MM_PRIVATE_VAD_FLAGS
{
	/* 0x0000 */ unsigned long Lock : 1; /* bit position: 0 */
	/* 0x0000 */ unsigned long LockContended : 1; /* bit position: 1 */
	/* 0x0000 */ unsigned long DeleteInProgress : 1; /* bit position: 2 */
	/* 0x0000 */ unsigned long NoChange : 1; /* bit position: 3 */
	/* 0x0000 */ unsigned long VadType : 3; /* bit position: 4 */
	/* 0x0000 */ unsigned long Protection : 5; /* bit position: 7 */
	/* 0x0000 */ unsigned long PreferredNode : 6; /* bit position: 12 */
	/* 0x0000 */ unsigned long PageSize : 2; /* bit position: 18 */
	/* 0x0000 */ unsigned long PrivateMemoryAlwaysSet : 1; /* bit position: 20 */
	/* 0x0000 */ unsigned long WriteWatch : 1; /* bit position: 21 */
	/* 0x0000 */ unsigned long FixedLargePageSize : 1; /* bit position: 22 */
	/* 0x0000 */ unsigned long ZeroFillPagesOptional : 1; /* bit position: 23 */
	/* 0x0000 */ unsigned long Graphics : 1; /* bit position: 24 */
	/* 0x0000 */ unsigned long Enclave : 1; /* bit position: 25 */
	/* 0x0000 */ unsigned long ShadowStack : 1; /* bit position: 26 */
} MM_PRIVATE_VAD_FLAGS, *PMM_PRIVATE_VAD_FLAGS; /* size: 0x0004 */

typedef struct _MM_GRAPHICS_VAD_FLAGS
{
	/* 0x0000 */ unsigned long Lock : 1; /* bit position: 0 */
	/* 0x0000 */ unsigned long LockContended : 1; /* bit position: 1 */
	/* 0x0000 */ unsigned long DeleteInProgress : 1; /* bit position: 2 */
	/* 0x0000 */ unsigned long NoChange : 1; /* bit position: 3 */
	/* 0x0000 */ unsigned long VadType : 3; /* bit position: 4 */
	/* 0x0000 */ unsigned long Protection : 5; /* bit position: 7 */
	/* 0x0000 */ unsigned long PreferredNode : 6; /* bit position: 12 */
	/* 0x0000 */ unsigned long PageSize : 2; /* bit position: 18 */
	/* 0x0000 */ unsigned long PrivateMemoryAlwaysSet : 1; /* bit position: 20 */
	/* 0x0000 */ unsigned long WriteWatch : 1; /* bit position: 21 */
	/* 0x0000 */ unsigned long FixedLargePageSize : 1; /* bit position: 22 */
	/* 0x0000 */ unsigned long ZeroFillPagesOptional : 1; /* bit position: 23 */
	/* 0x0000 */ unsigned long GraphicsAlwaysSet : 1; /* bit position: 24 */
	/* 0x0000 */ unsigned long GraphicsUseCoherentBus : 1; /* bit position: 25 */
	/* 0x0000 */ unsigned long GraphicsPageProtection : 3; /* bit position: 26 */
} MM_GRAPHICS_VAD_FLAGS, *PMM_GRAPHICS_VAD_FLAGS; /* size: 0x0004 */

typedef struct _MM_SHARED_VAD_FLAGS
{
	/* 0x0000 */ unsigned long Lock : 1; /* bit position: 0 */
	/* 0x0000 */ unsigned long LockContended : 1; /* bit position: 1 */
	/* 0x0000 */ unsigned long DeleteInProgress : 1; /* bit position: 2 */
	/* 0x0000 */ unsigned long NoChange : 1; /* bit position: 3 */
	/* 0x0000 */ unsigned long VadType : 3; /* bit position: 4 */
	/* 0x0000 */ unsigned long Protection : 5; /* bit position: 7 */
	/* 0x0000 */ unsigned long PreferredNode : 6; /* bit position: 12 */
	/* 0x0000 */ unsigned long PageSize : 2; /* bit position: 18 */
	/* 0x0000 */ unsigned long PrivateMemoryAlwaysClear : 1; /* bit position: 20 */
	/* 0x0000 */ unsigned long PrivateFixup : 1; /* bit position: 21 */
	/* 0x0000 */ unsigned long HotPatchAllowed : 1; /* bit position: 22 */
} MM_SHARED_VAD_FLAGS, *PMM_SHARED_VAD_FLAGS; /* size: 0x0004 */

typedef struct _MMVAD_SHORT // Size=64 // PRE 19H1
{
	union
	{
		struct _RTL_BALANCED_NODE VadNode; // Size=24 Offset=0
		struct _MMVAD_SHORT *NextVad; // Size=8 Offset=0
	};
	unsigned long StartingVpn; // Size=4 Offset=24
	unsigned long EndingVpn; // Size=4 Offset=28
	unsigned char StartingVpnHigh; // Size=1 Offset=32
	unsigned char EndingVpnHigh; // Size=1 Offset=33
	unsigned char CommitChargeHigh; // Size=1 Offset=34
	unsigned char SpareNT64VadUChar; // Size=1 Offset=35
	long ReferenceCount; // Size=4 Offset=36
	union _EX_PUSH_LOCK PushLock; // Size=8 Offset=40
	union ___unnamed1951 u; // Size=4 Offset=48
	union ___unnamed1952 u1; // Size=4 Offset=52
	struct _MI_VAD_EVENT_BLOCK *EventList; // Size=8 Offset=56
} MMVAD_SHORT, *PMMVAD_SHORT;

typedef struct _MMVAD_SHORT_19H1
{
	union
	{
		struct
		{
			/* 0x0000 */ struct _MMVAD_SHORT_19H1* NextVad;
			/* 0x0008 */ void* ExtraCreateInfo;
		}; /* size: 0x0010 */
		/* 0x0000 */ _RTL_BALANCED_NODE VadNode;
	}; /* size: 0x0018 */
	/* 0x0018 */ unsigned long StartingVpn;
	/* 0x001c */ unsigned long EndingVpn;
	/* 0x0020 */ unsigned char StartingVpnHigh;
	/* 0x0021 */ unsigned char EndingVpnHigh;
	/* 0x0022 */ unsigned char CommitChargeHigh;
	/* 0x0023 */ unsigned char SpareNT64VadUChar;
	/* 0x0024 */ long ReferenceCount;
	/* 0x0028 */ _EX_PUSH_LOCK PushLock;
	union
	{
		union
		{
			/* 0x0030 */ unsigned long LongFlags;
			/* 0x0030 */ _MMVAD_FLAGS_19H1 VadFlags;
			/* 0x0030 */ _MM_PRIVATE_VAD_FLAGS PrivateVadFlags;
			/* 0x0030 */ _MM_GRAPHICS_VAD_FLAGS GraphicsVadFlags;
			/* 0x0030 */ _MM_SHARED_VAD_FLAGS SharedVadFlags;
			/* 0x0030 */ volatile unsigned long VolatileVadLong;
		}; /* size: 0x0004 */
	} /* size: 0x0004 */ u;
	union
	{
		union
		{
			/* 0x0034 */ unsigned long LongFlags1;
			/* 0x0034 */ struct _MMVAD_FLAGS1 VadFlags1;
		}; /* size: 0x0004 */
	} /* size: 0x0004 */ u1;
	/* 0x0038 */ struct _MI_VAD_EVENT_BLOCK* EventList;
} MMVAD_SHORT_19H1, *PMMVAD_SHORT_19H1; /* size: 0x0040 */

typedef struct _MMVAD // Size=128
{
	struct _MMVAD_SHORT Core; // Size=64 Offset=0
	union ___unnamed2047 u2; // Size=4 Offset=64
	unsigned long pad0; // Size=4 Offset=68
	struct _SUBSECTION *Subsection; // Size=8 Offset=72
	struct _MMPTE *FirstPrototypePte; // Size=8 Offset=80
	struct _MMPTE *LastContiguousPte; // Size=8 Offset=88
	struct _LIST_ENTRY ViewLinks; // Size=16 Offset=96
	struct _EPROCESS *VadsProcess; // Size=8 Offset=112
	union ___unnamed2048 u4; // Size=8 Offset=120
	struct _FILE_OBJECT *FileObject; // Size=8 Offset=128
} MMVAD, *PMMVAD;
#pragma pack(pop)

typedef struct _HANDLE_TABLE
{
	ULONG NextHandleNeedingPool;
	long ExtraInfoPages;
	LONG_PTR TableCode;
	PEPROCESS QuotaProcess;
	LIST_ENTRY HandleTableList;
	ULONG UniqueProcessId;
	ULONG Flags;
	EX_PUSH_LOCK HandleContentionEvent;
	EX_PUSH_LOCK HandleTableLock;
	// More fields here...
} HANDLE_TABLE, *PHANDLE_TABLE;

#pragma warning(default : 4214 4201)

#define GET_VAD_ROOT(Table) Table->BalancedRoot
