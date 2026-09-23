/* Fictional TPM-backed device identity example. */
#include <tss2/tss2_esys.h>

TSS2_RC sign_device_challenge(ESYS_CONTEXT *esys, ESYS_TR keyHandle) {
    return Esys_Sign(esys, keyHandle, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                     NULL, NULL, NULL, NULL);
}
