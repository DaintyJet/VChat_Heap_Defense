#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <stdio.h>
#include <string.h>

#define CHUNK_SIZE 0x927C0
#define ALLOC_COUNT 10
// Modified it so V_ALLOC is calculated based on CHUNK_SIZE
//#define V_ALLOC 0x249F0 // Divide target size by the width of pointer to get this

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
    long offset;
    HANDLE hChunk;
    functionpointer* v_n;
    functionpointer* allocations[ALLOC_COUNT];
    functionpointer obj = nicecode; // Allocate Function Pointer on the heap.
    printf("obj address : 0x%08x\n", obj);
    int allocSize = CHUNK_SIZE / 4;

    HANDLE defaultHeap = GetProcessHeap();

    void (*funPtr)(int) = &evilcode;
    unsigned evilPtr = (unsigned)funPtr;
    printf("Evilcode address : 0x%08x\n", evilPtr);

    
    for (int i = 0; i < ALLOC_COUNT; i++) {
        v_n = HeapAlloc(defaultHeap, NULL, sizeof(functionpointer) * allocSize);
        fill_array(v_n, obj, allocSize);
        allocations[i] = v_n;
        printf("[%d] Heap chunk addr: 0x%08x\n", i, v_n);
    }

    offset = (unsigned long)(allocations[6]) - (unsigned long)(allocations[5]);

    printf("====================================\n");
    printf("Before heap overflow, call v1[0]\n");
    printf("Before heap overflow, v1[0] = %08x\n", allocations[6][0]);
    printf("====================================\n");
    (allocations[6][0])(arg);

    system("PAUSE");
    // memset(allocations[5], 'B', offset); // We could use memset, but I will do a loop for a little more control.
    for (unsigned long i = 0; i < offset; ++i) {
        ((char*)(allocations[5]))[i] = 'B';
    }

    printf("====================================\n");
    printf("After heap overflow, call v1[0]\n");
    printf("After heap overflow, v1[0] = %08x\n", allocations[6][0]);
    printf("====================================\n");
    (allocations[6][0])(arg);
    system("PAUSE");

    return 0;
}