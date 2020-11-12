#pragma once

#include "VMProtectDDK.h"

#undef VMP_IMPORT
#define VMP_IMPORT inline

#ifdef __cplusplus
extern "C" {
#endif

VMP_IMPORT void VMP_API VMProtectBegin(const char *) { }
VMP_IMPORT void VMP_API VMProtectBeginVirtualization(const char *) { }
VMP_IMPORT void VMP_API VMProtectBeginMutation(const char *) { }
VMP_IMPORT void VMP_API VMProtectBeginUltra(const char *) { }
VMP_IMPORT void VMP_API VMProtectBeginVirtualizationLockByKey(const char *) { }
VMP_IMPORT void VMP_API VMProtectBeginUltraLockByKey(const char *) { }
VMP_IMPORT void VMP_API VMProtectEnd(void) { }

VMP_IMPORT BOOLEAN VMP_API VMProtectIsProtected() { return FALSE; }
VMP_IMPORT BOOLEAN VMP_API VMProtectIsDebuggerPresent(BOOLEAN) { return FALSE; }
VMP_IMPORT BOOLEAN VMP_API VMProtectIsVirtualMachinePresent(void) { return FALSE; }
VMP_IMPORT BOOLEAN VMP_API VMProtectIsValidImageCRC(void) { return TRUE; }
VMP_IMPORT const char * VMP_API VMProtectDecryptStringA(const char *value) { return value; }
VMP_IMPORT const VMP_WCHAR * VMP_API VMProtectDecryptStringW(const VMP_WCHAR *value) { return value; }
VMP_IMPORT BOOLEAN VMP_API VMProtectFreeString(const void *value) { UNREFERENCED_PARAMETER(value); return TRUE; }

VMP_IMPORT int VMP_API VMProtectSetSerialNumber(const char *serial) { UNREFERENCED_PARAMETER(serial); return SERIAL_STATE_SUCCESS; }
VMP_IMPORT int VMP_API VMProtectGetSerialNumberState() { return SERIAL_STATE_SUCCESS; }
VMP_IMPORT BOOLEAN VMP_API VMProtectGetSerialNumberData(VMProtectSerialNumberData *data, int size) { if (size >= (int)sizeof(VMProtectSerialStateFlags)) data->nState = SERIAL_STATE_SUCCESS; return TRUE; }
VMP_IMPORT int VMP_API VMProtectGetCurrentHWID(char *hwid, int size)
{
	if (hwid != NULL && size > 0)
		*hwid = '\0';
	return sizeof('\0');
}

VMP_IMPORT int VMP_API VMProtectActivateLicense(const char *code, char *serial, int size)
{
	UNREFERENCED_PARAMETER(code); UNREFERENCED_PARAMETER(serial); UNREFERENCED_PARAMETER(size); return ACTIVATION_OK;
}
VMP_IMPORT int VMP_API VMProtectDeactivateLicense(const char *serial) { UNREFERENCED_PARAMETER(serial); return ACTIVATION_OK; }
VMP_IMPORT int VMP_API VMProtectGetOfflineActivationString(const char *code, char *buf, int size)
{
	if (code != NULL && buf != NULL && size > 0)
		*buf = '\0';
	return sizeof('\0');
}
VMP_IMPORT int VMP_API VMProtectGetOfflineDeactivationString(const char *serial, char *buf, int size)
{
	if (serial != NULL && buf != NULL && size > 0)
		*buf = '\0';
	return sizeof('\0');
}

#ifdef __cplusplus
}
#endif
