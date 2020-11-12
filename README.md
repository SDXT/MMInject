# MMInject

Kernel DLL Injector using NX Bit Swapping and VAD hide for hiding injected DLL

## Method

1) allocate pages with only read and write permission
2) get the physical page table entry's of your allocated pages
3) add execute permission to your page under the covers

## NOTE

Physical regions can be enumerated using NtQuery* APIs and then tested for the correctness of corresponding protection flags.
