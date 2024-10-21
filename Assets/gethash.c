//
// Created by hulkop on 7/10/24.
//

#include <stdio.h>

unsigned int HashDjb2 (char* pString) {

    unsigned int Hash = 0;
    unsigned int c;

    while(c = *pString++) {
        Hash = ((Hash << 4) + Hash) + c;
    }

    return Hash;
}

int main(int argc, char** argv) {

  if (argc != 2)
    return -1;
  printf("#define %s_HASH 0x%.4x\n", argv[1], HashDjb2(argv[1]));

}