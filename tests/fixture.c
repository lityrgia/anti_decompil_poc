#include <stdio.h>

#ifndef PATCH_NO_CAVE
__asm__(
    ".pushsection .text\n"
    ".balign 16\n"
    ".global patch_fixture_cave\n"
    "patch_fixture_cave:\n"
    ".zero 512\n"
    ".popsection\n");
#endif

#ifdef _WIN32
__declspec(dllexport)
#endif
int main(void) {
    puts("dispatcher-ok");
    return 7;
}
