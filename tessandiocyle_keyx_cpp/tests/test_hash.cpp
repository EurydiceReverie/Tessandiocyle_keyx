#include "shake.hpp"
#include <cstdio>
#include <cstring>

int main() {
    /* SHA3-256 empty string test vector */
    uint8_t out256[32];
    td18::Keccak1600::sha3_256(out256, nullptr, 0);
    printf("SHA3-256(\"\"): ");
    for (int i = 0; i < 32; ++i) printf("%02x", out256[i]);
    printf("\n");
    /* Expected: a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a */

    /* SHA3-512 empty string test vector */
    uint8_t out512[64];
    td18::Keccak1600::sha3_512(out512, nullptr, 0);
    printf("SHA3-512(\"\"): ");
    for (int i = 0; i < 64; ++i) printf("%02x", out512[i]);
    printf("\n");
    /* Expected: a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a614b0003fee3dd44f4dedd7c2b5cab4f5b8c35b16a7e7a7d4c556f0e6ef5f5 */

    return 0;
}
