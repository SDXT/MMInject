#pragma once

#include "MMInject.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SANITIZE_PARENT_NODE(Parent) ((PMMADDRESS_NODE)(((ULONG_PTR)(Parent)) & ~0x3))

#define MiParent(Links) ( \
	(PRTL_SPLAY_LINKS)(SANITIZE_PARENT_NODE((Links)->u1.Parent)))

#define MiIsLeftChild(Links) ( \
	(RtlLeftChild(MiParent(Links)) == (PRTL_SPLAY_LINKS)(Links)))

#define MiIsRightChild(Links) ( \
	(RtlRightChild(MiParent(Links)) == (PRTL_SPLAY_LINKS)(Links)))

#define MI_MAKE_PARENT(ParentNode, ExistingBalance) \
	(PMMADDRESS_NODE)((ULONG_PTR)(ParentNode) | (((ULONG_PTR)ExistingBalance) & 0x3))

#define COUNT_BALANCE_MAX(a)


TABLE_SEARCH_RESULT
MiFindNodeOrParent(
	_In_ PMM_AVL_TABLE Table,
	_In_ ULONG_PTR StartingVpn,
	_Out_ PMMADDRESS_NODE *NodeOrParent
	);

VOID
MiPromoteNode(
	_In_ PMMADDRESS_NODE C
	);

ULONG
MiRebalanceNode(
	_In_ PMMADDRESS_NODE S
	);

VOID
MiRemoveNode(
	_In_ PMMADDRESS_NODE NodeToDelete,
	_In_ PMM_AVL_TABLE Table
	);

PMMVAD_SHORT
MiCheckForConflictingVad(
	_In_ PMM_AVL_TABLE Table,
	_In_ ULONG_PTR StartingVpn,
	_In_ ULONG_PTR EndingVpn
	);

#ifdef __cplusplus
}
#endif
