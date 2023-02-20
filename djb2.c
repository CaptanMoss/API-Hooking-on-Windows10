#include "djb2.h"

extern DWORD __cdecl djb2(unsigned int *dll_hash, PWSTR word)//ilk parametre ldr daki dll ikincisi listeden kontrol
{
   
    unsigned int hash = 5381;
    int c;


    while ((c = *word++))        
    {
        if (isupper(c))
        {
            c = c + 32;
        }



        hash = ((hash << 5) + hash) + c;
    }

        if (dll_hash == hash)
            return 0x1;
        else
            return 0x0;
}