#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <stdio.h>
#include <string.h>

#define CHUNK_SIZE 0x190
#define ALLOC_COUNT 10
#define V_ALLOC 40

/*
Typedef for functionpointer
This is a reference for
indirect jumps to functions
with the signature void <name>(void);
*/
typedef void (*functionpointer)();

/* Utility Function to fill array */
void fill_array(functionpointer* arr, functionpointer* ptr, unsigned size) {
    for (int i = 0; i < size; i++)
        arr[i] = ptr;
    return;
}

/* Stub Functions for Example */
void nicecode(int a) {
    printf("Hi~ I'm Nice! ^ v ^ %d\n", a);
}

void evilcode(int a) {
    printf("Hi~ I'm Evil! * o * %d\n", a);
}


int main(int args, char** argv) {
    int arg = 0;
    HANDLE hChunk;
    void* allocations[ALLOC_COUNT];
    functionpointer* v_allocs[ALLOC_COUNT];
    functionpointer* v_n;    
    functionpointer obj = nicecode; // Allocate Function Pointer on the heap.
    printf("Obj address : 0x%08x\n", obj);
    int allocSize = V_ALLOC;

    HANDLE defaultHeap = GetProcessHeap();

    void (*funPtr)(int) = &evilcode;
    int evilPtr = (int)funPtr;
    printf("Evilcode address : 0x%08x\n", evilPtr);

    for (int i = 0; i < ALLOC_COUNT; i++) {
        hChunk = HeapAlloc(defaultHeap, 0, CHUNK_SIZE);
        memset(hChunk, 'A', CHUNK_SIZE);
        allocations[i] = hChunk;
        printf("[%d] Heap chunk in backend : 0x%08x\n", i, hChunk);
    }

    HeapFree(defaultHeap, HEAP_NO_SERIALIZE, allocations[6]);
    // Various Heap Allocations
    for (int i = 0; i < ALLOC_COUNT; ++i) {
        v_n =  malloc(sizeof(functionpointer) * allocSize);
        fill_array(v_n, obj, allocSize);
        v_allocs[i] = v_n; 
        printf("vector alloc %d: 0x%08x\n", i, v_n);
    }


    printf("====================================\n");
    printf("Before heap overflow, call v1[0]\n");
    printf("Before heap overflow, v1[0] = %08x\n", v_allocs[0][0]);
    printf("====================================\n");
    (v_allocs[0][0])(arg);
 

    char evilString[600];
    sprintf(evilString, "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBabcdefghijklmnopqrstuvwxyzCC%c%c%c%cGHUJCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC", (char)evilcode, (char)((int)evilcode >> 8), (char)((int)evilcode >> 16), (char)((int)evilcode >> 24));
    printf("%s\n", evilString);
    system("PAUSE");


    memcpy(allocations[5], evilString, sizeof(evilString));
    printf("====================================\n");
    printf("After heap overflow, call v1[0]\n");
    printf("After heap overflow, v1[0] = %08x\n", v_allocs[0][0]);
    printf("====================================\n");
    (v_allocs[0][0])(arg);
    system("PAUSE");
    return 0;
}