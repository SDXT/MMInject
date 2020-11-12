#if !defined(_DEBUG) && (!defined(DBG) || !DBG)

#include "MMInject.h"
#include <ntimage.h>

extern "C"
{
#ifdef _M_IX86
	extern ULONG __safe_se_handler_table;
	extern ULONG __safe_se_handler_count;

	uintptr_t __security_cookie = 0xBB40E64E;

	#ifdef _KERNEL_MODE
		void __fastcall __security_check_cookie(uintptr_t) {}
		__declspec(noreturn) void __cdecl __report_rangecheckfailure() {}
	#endif
#else
	uintptr_t __security_cookie = 0x2B992DDFA232;
#endif

	extern "C" const IMAGE_LOAD_CONFIG_DIRECTORY _load_config_used =
	{
		
		FIELD_OFFSET(IMAGE_LOAD_CONFIG_DIRECTORY, GuardFlags) + sizeof(IMAGE_LOAD_CONFIG_DIRECTORY::GuardFlags),
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		reinterpret_cast<decltype(IMAGE_LOAD_CONFIG_DIRECTORY::SecurityCookie)>(&__security_cookie),
#ifdef _M_IX86
		reinterpret_cast<ULONG>(&__safe_se_handler_table),
		reinterpret_cast<ULONG>(&__safe_se_handler_count),
#else
		0,		
		0,		
#endif
		0,		
		0,		
		0,		
		0,		
		IMAGE_GUARD_SECURITY_COOKIE_UNUSED

	};
}

#endif
