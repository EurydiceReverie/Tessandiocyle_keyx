#include "random.hpp"
#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "advapi32.lib")
#endif
#include <cstdlib>
#include <cstdio>

namespace td18 {

void randombytes(uint8_t *out, size_t len) {
#ifdef _WIN32
    HCRYPTPROV h = 0;
    if (!CryptAcquireContext(&h, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        for (size_t i = 0; i < len; ++i) out[i] = static_cast<uint8_t>(rand());
        return;
    }
    CryptGenRandom(h, static_cast<DWORD>(len), out);
    CryptReleaseContext(h, 0);
#else
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) { fread(out, 1, len, f); fclose(f); }
#endif
}

} // namespace td18
