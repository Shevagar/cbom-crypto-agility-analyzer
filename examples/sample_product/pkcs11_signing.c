/* Fictional PKCS#11 signing example. */
#include <pkcs11.h>

CK_RV token_sign(CK_SESSION_HANDLE session) {
    return C_Sign(session, NULL, 0, NULL, NULL);
}
