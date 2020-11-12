#include "MMInject.h"
#include "VadHelpers.h"


#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, MiPromoteNode)
#pragma alloc_text(PAGE, MiRebalanceNode)
#pragma alloc_text(PAGE, MiRemoveNode)
#pragma alloc_text(PAGE, MiFindNodeOrParent)
#pragma alloc_text(PAGE, MiCheckForConflictingVad)
#endif

extern DYNAMIC_DATA DynData;

VOID
MiPromoteNode(
	_In_ PMMADDRESS_NODE C
	)

{
	PAGED_CODE();

	PMMADDRESS_NODE P;
	PMMADDRESS_NODE G;

	P = SANITIZE_PARENT_NODE(C->u1.Parent);
	G = SANITIZE_PARENT_NODE(P->u1.Parent);

	if (P->LeftChild == C)
	{
		
		P->LeftChild = C->RightChild;

		if (P->LeftChild != NULL)
		{
			P->LeftChild->u1.Parent = MI_MAKE_PARENT(P, P->LeftChild->u1.Balance);
		}

		C->RightChild = P;

		
	}
	else
	{
		
		P->RightChild = C->LeftChild;

		if (P->RightChild != NULL)
		{
			P->RightChild->u1.Parent = MI_MAKE_PARENT(P, P->RightChild->u1.Balance);
		}

		C->LeftChild = P;
	}

	
	P->u1.Parent = MI_MAKE_PARENT(C, P->u1.Balance);

	
	if (G->LeftChild == P)
	{
		G->LeftChild = C;
	}
	else
	{
		G->RightChild = C;
	}
	C->u1.Parent = MI_MAKE_PARENT(G, C->u1.Balance);
}

ULONG
MiRebalanceNode(
	_In_ PMMADDRESS_NODE S
	)


{
	PAGED_CODE();

	PMMADDRESS_NODE R, P;
	SCHAR a;

	a = (SCHAR)S->u1.Balance;

	if (a == +1)
	{
		R = S->RightChild;
	}
	else
	{
		R = S->LeftChild;
	}

	
	if ((SCHAR)R->u1.Balance == a)
	{
		MiPromoteNode(R);
		R->u1.Balance = 0;
		S->u1.Balance = 0;

		return FALSE;
	}

	if ((SCHAR)R->u1.Balance == -a)
	{
		
		if (a == 1)
		{
			P = R->LeftChild;
		}
		else
		{
			P = R->RightChild;
		}

		
		MiPromoteNode(P);
		MiPromoteNode(P);
		S->u1.Balance = 0;
		R->u1.Balance = 0;
		if ((SCHAR)P->u1.Balance == a)
		{
			COUNT_BALANCE_MAX((SCHAR)-a);
			S->u1.Balance = (ULONG_PTR)-a;
		}
		else if ((SCHAR)P->u1.Balance == -a)
		{
			COUNT_BALANCE_MAX((SCHAR)a);
			R->u1.Balance = (ULONG_PTR)a;
		}

		P->u1.Balance = 0;
		return FALSE;
	}

	MiPromoteNode(R);
	COUNT_BALANCE_MAX((SCHAR)-a);
	R->u1.Balance = -a;

	return TRUE;
}

VOID
MiRemoveNode(
	_In_ PMMADDRESS_NODE NodeToDelete,
	_In_ PMM_AVL_TABLE Table
	)

{
	PAGED_CODE();

	PMMADDRESS_NODE Parent;
	PMMADDRESS_NODE EasyDelete;
	PMMADDRESS_NODE P;
	SCHAR a;

	if ((NodeToDelete->LeftChild == NULL) ||
		(NodeToDelete->RightChild == NULL))
	{
		EasyDelete = NodeToDelete;
	}

	
	else if ((SCHAR)NodeToDelete->u1.Balance >= 0)
	{
		
		EasyDelete = NodeToDelete->RightChild;
		while (EasyDelete->LeftChild != NULL)
		{
			EasyDelete = EasyDelete->LeftChild;
		}
	}
	else
	{

		EasyDelete = NodeToDelete->LeftChild;
		while (EasyDelete->RightChild != NULL)
		{
			EasyDelete = EasyDelete->RightChild;
		}
	}


	a = -1;

	if (EasyDelete->LeftChild == NULL)
	{
		Parent = SANITIZE_PARENT_NODE(EasyDelete->u1.Parent);

		if (MiIsLeftChild(EasyDelete))
		{
			Parent->LeftChild = EasyDelete->RightChild;
		}
		else
		{
			Parent->RightChild = EasyDelete->RightChild;
			a = 1;
		}

		if (EasyDelete->RightChild != NULL)
		{
			EasyDelete->RightChild->u1.Parent = MI_MAKE_PARENT(Parent, EasyDelete->RightChild->u1.Balance);
		}

	}
	else
	{
		Parent = SANITIZE_PARENT_NODE(EasyDelete->u1.Parent);

		if (MiIsLeftChild(EasyDelete))
		{
			Parent->LeftChild = EasyDelete->LeftChild;
		}
		else
		{
			Parent->RightChild = EasyDelete->LeftChild;
			a = 1;
		}

		EasyDelete->LeftChild->u1.Parent = MI_MAKE_PARENT(Parent,
														EasyDelete->LeftChild->u1.Balance);
	}

#if NTDDI_VERSION >= NTDDI_WINBLUE
	Table->BalancedRoot->u1.Balance = 0;
#else
	Table->BalancedRoot.u1.Balance = 0;
#endif
	P = SANITIZE_PARENT_NODE(EasyDelete->u1.Parent);

	for (;;)
	{
		if (P == nullptr)
			break;

		
		if ((SCHAR)P->u1.Balance == a)
		{
			P->u1.Balance = 0;

			
		}
		else if ((SCHAR)P->u1.Balance == 0)
		{
			COUNT_BALANCE_MAX((SCHAR)-a);
			P->u1.Balance = -a;

#if NTDDI_VERSION < NTDDI_WINBLUE
			if (Table->BalancedRoot.u1.Balance != 0)
			{
				Table->DepthOfTree -= 1;
			}
#endif

			break;

			
		}
		else
		{
			
			if (MiRebalanceNode(P))
			{
				break;
			}

			P = SANITIZE_PARENT_NODE(P->u1.Parent);
		}

		a = -1;
		if (MiIsRightChild(P))
		{
			a = 1;
		}

		P = SANITIZE_PARENT_NODE(P->u1.Parent);
	}

	
	if (NodeToDelete != EasyDelete)
	{
		
		EasyDelete->u1.Parent = NodeToDelete->u1.Parent;
		EasyDelete->LeftChild = NodeToDelete->LeftChild;
		EasyDelete->RightChild = NodeToDelete->RightChild;

		if (MiIsLeftChild(NodeToDelete))
		{
			Parent = SANITIZE_PARENT_NODE(EasyDelete->u1.Parent);
			Parent->LeftChild = EasyDelete;
		}
		else
		{
			Parent = SANITIZE_PARENT_NODE(EasyDelete->u1.Parent);
			Parent->RightChild = EasyDelete;
		}
		if (EasyDelete->LeftChild != NULL)
		{
			EasyDelete->LeftChild->u1.Parent = MI_MAKE_PARENT(EasyDelete,
															EasyDelete->LeftChild->u1.Balance);
		}
		if (EasyDelete->RightChild != NULL)
		{
			EasyDelete->RightChild->u1.Parent = MI_MAKE_PARENT(EasyDelete,
															EasyDelete->RightChild->u1.Balance);
		}
	}
}

TABLE_SEARCH_RESULT
MiFindNodeOrParent(
	_In_ PMM_AVL_TABLE Table,
	_In_ ULONG_PTR StartingVpn,
	_Out_ PMMADDRESS_NODE *NodeOrParent
	)


{
	PAGED_CODE();

	PMMADDRESS_NODE Child;
	PMMADDRESS_NODE NodeToExamine;

	*NodeOrParent = nullptr;

	if (Table->NumberGenericTableElements == 0)
	{
		return TableEmptyTree;
	}

	NodeToExamine = (PMMADDRESS_NODE)GET_VAD_ROOT(Table);

	TABLE_SEARCH_RESULT Result;

	for (;;)
	{
		PMMVAD_SHORT VpnCompare = (PMMVAD_SHORT)NodeToExamine;
#if NTDDI_VERSION >= NTDDI_WIN10
		PMMVAD_SHORT_19H1 VpnCompare19H1 = (PMMVAD_SHORT_19H1)NodeToExamine;
		ULONG_PTR startVpn = DynData.Version >= WINVER_10_19H1 ? VpnCompare19H1->StartingVpn : VpnCompare->StartingVpn;
		ULONG_PTR endVpn = DynData.Version >= WINVER_10_19H1 ? VpnCompare19H1->EndingVpn : VpnCompare->EndingVpn;
#else
		ULONG_PTR startVpn = VpnCompare->StartingVpn;
		ULONG_PTR endVpn = VpnCompare->EndingVpn;
#endif

#if NTDDI_VERSION >= NTDDI_WINBLUE

#if NTDDI_VERSION >= NTDDI_WIN10
		startVpn |= DynData.Version >= WINVER_10_19H1 ? ((ULONG64)VpnCompare19H1->StartingVpnHigh << 32) : ((ULONG64)VpnCompare->StartingVpnHigh << 32);
		endVpn |= DynData.Version >= WINVER_10_19H1 ? ((ULONG64)VpnCompare19H1->EndingVpnHigh << 32) : ((ULONG64)VpnCompare->EndingVpnHigh << 32);
#else
		startVpn |= (ULONG_PTR)VpnCompare->StartingVpnHigh << 32;
		endVpn |= (ULONG_PTR)VpnCompare->EndingVpnHigh << 32;
#endif

#endif

		if (StartingVpn < startVpn)
		{
			Child = NodeToExamine->LeftChild;

			if (Child != NULL)
			{
				NodeToExamine = Child;
			}
			else
			{
				
				*NodeOrParent = NodeToExamine;
				Result = TableInsertAsLeft;
				break;
			}
		}
		else if (StartingVpn <= endVpn)
		{
			*NodeOrParent = NodeToExamine;
			Result = TableFoundNode;
			break;
		}
		else
		{
			Child = NodeToExamine->RightChild;

			if (Child != NULL)
			{
				NodeToExamine = Child;
			}
			else
			{
				
				*NodeOrParent = NodeToExamine;
				Result = TableInsertAsRight;
				break;
			}
		}
	}

	return Result;
}

PMMVAD_SHORT
MiCheckForConflictingVad(
	_In_ PMM_AVL_TABLE Table,
	_In_ ULONG_PTR StartingVpn,
	_In_ ULONG_PTR EndingVpn
	)

{
	PAGED_CODE();

	PMM_AVL_NODE NodeToExamine = GET_VAD_ROOT(Table);
	if (NodeToExamine == nullptr)
	{
		return nullptr;
	}

	while (true)
	{
		PMMVAD_SHORT VpnCompare = (PMMVAD_SHORT)NodeToExamine;
#if NTDDI_VERSION >= NTDDI_WIN10
		PMMVAD_SHORT_19H1 VpnCompare19H1 = (PMMVAD_SHORT_19H1)NodeToExamine;
		ULONG_PTR StartVpnCompare = DynData.Version >= WINVER_10_19H1 ? VpnCompare19H1->StartingVpn : VpnCompare->StartingVpn;
		ULONG_PTR EndVpnCompare = DynData.Version >= WINVER_10_19H1 ? VpnCompare19H1->EndingVpn : VpnCompare->EndingVpn;
#else
		ULONG_PTR StartVpnCompare = VpnCompare->StartingVpn;
		ULONG_PTR EndVpnCompare = VpnCompare->EndingVpn;
#endif

#if NTDDI_VERSION >= NTDDI_WINBLUE

#if NTDDI_VERSION >= NTDDI_WIN10
		StartVpnCompare |= DynData.Version >= WINVER_10_19H1 ? ((ULONG64)VpnCompare19H1->StartingVpnHigh << 32) : ((ULONG64)VpnCompare->StartingVpnHigh << 32);
		EndVpnCompare |= DynData.Version >= WINVER_10_19H1 ? ((ULONG64)VpnCompare19H1->EndingVpnHigh << 32) : ((ULONG64)VpnCompare->EndingVpnHigh << 32);
#else
		StartVpnCompare |= (ULONG_PTR)VpnCompare->StartingVpnHigh << 32;
		EndVpnCompare |= (ULONG_PTR)VpnCompare->EndingVpnHigh << 32;
#endif

#endif

		if (EndingVpn < StartVpnCompare)
		{
			NodeToExamine = NodeToExamine->LeftChild;

			if (NodeToExamine == nullptr)
				return nullptr;
			continue;
		}

		if (StartingVpn > EndVpnCompare)
		{
			NodeToExamine = NodeToExamine->RightChild;

			if (NodeToExamine == nullptr)
				return nullptr;
			continue;
		}

		break;
	}

	return (PMMVAD_SHORT)NodeToExamine;
}
