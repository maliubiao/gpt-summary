Response:
Let's break down the thought process for analyzing this C code and generating the comprehensive response.

1. **Understand the Goal:** The primary goal is to analyze the provided C source code (`upload-receiver.c`) for the Frida dynamic instrumentation tool and explain its functionality, relating it to reverse engineering, low-level concepts, and potential user errors. The instructions also emphasize providing concrete examples, assumptions, and debugging information.

2. **Initial Skim and High-Level Understanding:** First, quickly read through the code to get a general sense of its purpose. Keywords like `upload`, `receiver`, `command`, `write`, `apply_threaded`, `process_fixups`, `protect`, `construct`, and function names like `frida_receive`, `frida_read_chunk`, `frida_write_chunk` immediately suggest network communication and some form of code manipulation or data transfer. The presence of `mach-o/loader.h` and types like `FridaChainedFixupsHeader` strongly indicate interaction with Mach-O binaries, common on macOS and iOS.

3. **Identify Key Data Structures and Enums:**  Pay close attention to `typedef`s, `struct` definitions, and `enum`s. These define the data formats used in the communication protocol. Understanding these structures is crucial to understanding the commands and their parameters. For example, the `FridaUploadCommandType` enum tells us the possible operations the receiver can perform. The `FridaChainedFixupsHeader` and related structs suggest dynamic linking and relocation mechanisms.

4. **Analyze the `frida_receive` Function:** This is the core function. It handles the network connection, reads commands, and dispatches to other functions based on the `command_type`. Key observations here include:
    * It uses sockets (`accept`, `read`, `write`, `close`).
    * There's a session ID verification step.
    * It uses a `switch` statement to handle different commands.
    * It calls functions like `frida_read_chunk` and `frida_write_chunk` for reliable data transfer.
    * It interacts with memory management (`api->sys_icache_invalidate`, `api->sys_dcache_flush`, `api->mprotect`).

5. **Deconstruct Each Command Handler within `frida_receive`:** For each `case` in the `switch` statement:
    * **`FRIDA_UPLOAD_COMMAND_WRITE`:** This is straightforward: write data to a specific memory address.
    * **`FRIDA_UPLOAD_COMMAND_APPLY_THREADED`:** This involves applying "threaded" items, likely related to fixing up pointers during dynamic linking. The parameters suggest symbol and region information.
    * **`FRIDA_UPLOAD_COMMAND_PROCESS_FIXUPS`:** This deals with chained fixups, a Mach-O linking optimization technique. It takes fixups header and Mach-O header addresses as input.
    * **`FRIDA_UPLOAD_COMMAND_PROTECT`:** This changes memory protection attributes (read, write, execute).
    * **`FRIDA_UPLOAD_COMMAND_CONSTRUCT_FROM_POINTERS` and `FRIDA_UPLOAD_COMMAND_CONSTRUCT_FROM_OFFSETS`:** These appear to call constructor functions, either directly via pointers or by calculating their addresses from offsets within the loaded Mach-O.
    * **`FRIDA_UPLOAD_COMMAND_CHECK`:**  A simple handshake mechanism.

6. **Examine Helper Functions:** Analyze the functions called within the command handlers. This reveals more detailed functionality:
    * **`frida_apply_threaded_items`:**  Iterates through regions, reads values, and potentially modifies them based on type (rebase or bind) and authentication status. This is directly related to runtime linking.
    * **`frida_process_chained_fixups`:** This is complex. It involves:
        * Allocating temporary memory (`mach_vm_allocate`).
        * Loading dynamic libraries (`dlopen`).
        * Resolving symbols (`frida_resolve_import`, `dlsym`).
        * Processing fixups within segments using functions like `frida_process_chained_fixups_in_segment_generic64` and `frida_process_chained_fixups_in_segment_arm64e`.
    * **`frida_process_chained_fixups_in_segment_generic64` and `frida_process_chained_fixups_in_segment_arm64e`:** These handle the platform-specific details of applying fixups within memory. They interpret the `FridaChainedPtr*` structures to update pointers.
    * **`frida_resolve_import`:** Uses `dlsym` to find the address of a symbol in a loaded library.
    * **`frida_sign_pointer`:** Deals with pointer authentication codes (PAC) on ARM64e, a security feature.
    * **`frida_symbol_name_from_darwin`:** Removes the leading underscore from symbol names.
    * **`frida_sign_extend_int19`:**  Handles sign extension of 19-bit integers.
    * **`frida_read_chunk` and `frida_write_chunk`:** Implement reliable reading and writing from the socket, handling potential interruptions.

7. **Connect to Reverse Engineering Concepts:**  Think about how each function and command relates to reverse engineering techniques:
    * **Memory Manipulation:** `WRITE`, `PROTECT` directly enable modifying and controlling memory.
    * **Dynamic Linking Analysis:** `APPLY_THREADED`, `PROCESS_FIXUPS` are crucial for understanding how code is linked and resolved at runtime. This is key to intercepting function calls and understanding dependencies.
    * **Code Injection:**  The ability to write arbitrary data and potentially execute code (through constructors) facilitates code injection.
    * **Bypassing Security Measures:**  Understanding PAC (`frida_sign_pointer`) can be relevant to bypassing pointer authentication.

8. **Identify Low-Level Concepts:** Note the usage of:
    * **Sockets:** For network communication.
    * **Memory Management:** `mprotect`, cache invalidation/flushing.
    * **Mach-O:** The binary format on macOS/iOS.
    * **Dynamic Linking:** `dlopen`, `dlsym`, fixups.
    * **ARM64e PAC:** Pointer Authentication Codes.
    * **Linux/Android Kernels (implicitly):** Although the code leans towards macOS/iOS, the concepts of memory protection and caching are general.

9. **Consider User Errors and Debugging:**  Think about how a user interacting with Frida might trigger this code and what could go wrong:
    * **Incorrect Addresses/Sizes:**  Providing wrong addresses or sizes in the `WRITE` or `PROTECT` commands can lead to crashes or unexpected behavior.
    * **Incorrect Session IDs:**  The session ID check prevents unauthorized access.
    * **Network Issues:**  Connection problems can prevent the receiver from functioning.

10. **Formulate Assumptions and Examples:**  Create hypothetical scenarios and inputs/outputs to illustrate the behavior of the code. This helps solidify understanding and provides concrete examples.

11. **Structure the Response:** Organize the analysis into logical sections as requested by the prompt: functionality, reverse engineering relevance, low-level details, logical reasoning, user errors, and debugging. Use clear and concise language.

12. **Review and Refine:**  Read through the generated response to ensure accuracy, completeness, and clarity. Check for any logical inconsistencies or missing information. Ensure that the examples are relevant and easy to understand. For example, initially, I might have just listed the functions, but the prompt asks for *how* they relate to reverse engineering, requiring a more detailed explanation. Similarly, simply stating "it uses sockets" isn't as helpful as explaining *why* (network communication for remote instrumentation).
This C source file, `upload-receiver.c`, is a crucial component of Frida responsible for receiving and processing commands from a Frida client running on a different process or machine. It acts as the server-side handler for various operations that Frida performs on the target process.

Here's a breakdown of its functionality:

**Core Functionality: Receiving and Processing Commands**

The primary function of this file is the `frida_receive` function. It establishes a listening socket and waits for connections from Frida clients. Once a client connects, it enters a loop to receive and process commands sent by the client.

The types of commands it handles are defined by the `FridaUploadCommandType` enum:

* **`FRIDA_UPLOAD_COMMAND_WRITE`:**  Writes a chunk of data received from the client to a specified memory address in the target process. This is fundamental for injecting code or modifying data in the target.
* **`FRIDA_UPLOAD_COMMAND_APPLY_THREADED`:**  Applies "threaded" fixups. This is a mechanism used on Darwin (macOS, iOS) to patch up pointers in memory after a library is loaded at runtime. It involves adjusting pointers based on a slide (the difference between the preferred base address and the actual load address).
* **`FRIDA_UPLOAD_COMMAND_PROCESS_FIXUPS`:** Processes "chained fixups," another Darwin-specific mechanism for optimizing dynamic linking. It involves iterating through data structures that describe how pointers within the loaded image should be adjusted.
* **`FRIDA_UPLOAD_COMMAND_PROTECT`:**  Changes the memory protection attributes (e.g., read, write, execute permissions) of a specified memory region in the target process. This is essential for making injected code executable or preventing modifications to certain memory regions.
* **`FRIDA_UPLOAD_COMMAND_CONSTRUCT_FROM_POINTERS`:**  Calls constructor functions located at specified memory addresses. This is often used to initialize injected code or C++ objects.
* **`FRIDA_UPLOAD_COMMAND_CONSTRUCT_FROM_OFFSETS`:** Calls constructor functions whose addresses are calculated as offsets from the base address of the Mach-O header. This is another way to initialize code within a loaded library.
* **`FRIDA_UPLOAD_COMMAND_CHECK`:** A simple command used for checking the connection.

**Relationship to Reverse Engineering:**

This file is deeply intertwined with reverse engineering techniques:

* **Code Injection:** The `FRIDA_UPLOAD_COMMAND_WRITE` command is the cornerstone of code injection. Reverse engineers can craft shellcode or custom libraries and use Frida to write them into the target process's memory.
    * **Example:** A reverse engineer discovers a vulnerability in a function. They can write a small piece of code that exploits this vulnerability into the process's memory using this command.
* **Data Manipulation:**  Similarly, `FRIDA_UPLOAD_COMMAND_WRITE` can be used to modify data structures, variables, or flags within the target process. This can be used to bypass security checks or alter the program's behavior.
    * **Example:** A game cheat might involve finding the memory location storing the player's health and using this command to write a very large value to it.
* **Dynamic Analysis of Libraries:** The commands related to fixups (`FRIDA_UPLOAD_COMMAND_APPLY_THREADED`, `FRIDA_UPLOAD_COMMAND_PROCESS_FIXUPS`) are essential for understanding how dynamically linked libraries are loaded and initialized. Reverse engineers often need to analyze these processes to understand dependencies and potential hooking points.
    * **Example:** To hook a function in a dynamically loaded library, a reverse engineer might need to understand how the library's pointers are resolved at runtime, which involves analyzing the fixup information.
* **Bypassing Memory Protections:**  The `FRIDA_UPLOAD_COMMAND_PROTECT` command allows changing memory permissions. This can be used to make memory regions writable that were previously read-only (to inject code) or executable that were previously data regions.
    * **Example:** After injecting code into a data segment, a reverse engineer would use this command to make that memory region executable.
* **Analyzing Object Initialization:** The constructor commands (`FRIDA_UPLOAD_COMMAND_CONSTRUCT_FROM_POINTERS`, `FRIDA_UPLOAD_COMMAND_CONSTRUCT_FROM_OFFSETS`) are useful for understanding how C++ objects are created and initialized. This can be important when analyzing complex applications with object-oriented architectures.
    * **Example:** A reverse engineer might want to understand how a particular class is initialized to find out where important data members are located or to intercept calls to its methods.

**Involvement of Binary Bottom, Linux, Android Kernel & Framework Knowledge:**

This file touches upon several low-level concepts and platform-specific details:

* **Binary Bottom (Mach-O on Darwin):** The code heavily relies on the Mach-O binary format, common on macOS and iOS. Structures like `FridaChainedFixupsHeader`, `FridaChainedStartsInImage`, and the handling of load commands (like `LC_LOAD_DYLIB`) directly relate to the Mach-O specification. Understanding this format is crucial for interpreting the fixup data and how dynamic linking works on these platforms.
    * **Example:** The code iterates through load commands in the Mach-O header to find dynamically linked libraries and uses `dlopen` to load them. It then uses the fixup information within the Mach-O to resolve symbols.
* **Linux/Android Kernel (Implicit):** While the code primarily targets Darwin, the fundamental concepts of memory management (reading, writing, protection) and inter-process communication (sockets) are relevant to Linux and Android as well. The `FridaUploadApi` structure (not fully defined in this snippet) likely provides platform-specific implementations for these operations.
    * **Example:** The `api->mprotect()` call is a system call that exists in both Linux/Android and macOS/iOS, though the specific numerical values for protection flags might differ. Similarly, socket operations are a standard part of the operating system kernel.
* **Memory Management:**  Functions like `api->sys_icache_invalidate`, `api->sys_dcache_flush`, and `api->mprotect` directly interact with the operating system's memory management mechanisms. Understanding how caches work and how memory protections are enforced is essential for using these commands effectively.
    * **Example:** After writing code into memory, it's crucial to invalidate the instruction cache (`sys_icache_invalidate`) to ensure that the CPU fetches the newly written instructions instead of stale cached ones.
* **Dynamic Linking:** The code demonstrates knowledge of dynamic linking principles, particularly on Darwin. It deals with concepts like rebasing (adjusting addresses based on the load slide) and binding (resolving symbolic references to their actual addresses).
    * **Example:** The `frida_apply_threaded_items` function handles the rebasing of pointers in memory when a library is loaded at a different address than its preferred base.
* **ARM64e PAC (Pointer Authentication Codes):**  The presence of structures like `FridaChainedPtrArm64eAuthRebase` and `FridaChainedPtrArm64eAuthBind` and the use of `ptrauth_sign_pointer` indicate awareness of ARM64e's pointer authentication features, a security mechanism to prevent pointer corruption.
    * **Example:** When processing fixups on ARM64e, Frida needs to sign pointers with the correct keys and diversities to ensure they are valid and haven't been tampered with.

**Logical Reasoning (Assumptions, Input & Output):**

Let's consider the `FRIDA_UPLOAD_COMMAND_WRITE` command as an example of logical reasoning:

**Assumption:** The Frida client wants to modify a byte of data at memory address `0x12345678` to the value `0xAA`.

**Input (sent by the client):**

1. `command_type`: `FRIDA_UPLOAD_COMMAND_WRITE` (value would be `1` based on the enum)
2. `address`: `0x12345678` (uint64_t)
3. `size`: `1` (uint32_t, representing the number of bytes to write)
4. `data`: `0xAA` (the actual byte to be written)

**Processing Logic in `frida_receive`:**

1. The `switch` statement matches the `command_type` to `FRIDA_UPLOAD_COMMAND_WRITE`.
2. It reads the `address` (`0x12345678`) and `size` (`1`) from the client.
3. It calls `frida_read_chunk` to read `size` (1) byte from the client into the memory location pointed to by `address` (`0x12345678`).
4. `frida_read_chunk` uses the `api->read` function (likely a wrapper around the `read()` system call) to read the data from the client socket.
5. The `api->sys_icache_invalidate` and `api->sys_dcache_flush` functions are called to ensure cache coherency, which is important if the written data is code that will be executed.

**Output (effect on the target process):**

The byte at memory address `0x12345678` in the target process will be changed to the value `0xAA`.

**User or Programming Common Usage Errors:**

* **Incorrect Memory Address:** If the user provides an invalid or unintended memory address to the `FRIDA_UPLOAD_COMMAND_WRITE` or `FRIDA_UPLOAD_COMMAND_PROTECT` commands, it can lead to crashes or unexpected behavior in the target process.
    * **Example:**  Accidentally specifying an address within kernel space could cause a system crash.
* **Incorrect Size:** Providing an incorrect size to `FRIDA_UPLOAD_COMMAND_WRITE` could lead to writing beyond the intended buffer, potentially corrupting adjacent memory.
    * **Example:**  Intending to write 4 bytes but specifying a size of 4096 could overwrite a large chunk of memory.
* **Incorrect Memory Protection Flags:** Setting inappropriate memory protection flags with `FRIDA_UPLOAD_COMMAND_PROTECT` can also cause issues.
    * **Example:** Making a code segment non-executable would lead to crashes when the program tries to execute instructions in that region.
* **Session ID Mismatch:** The `frida_receive` function checks for a matching session ID. If the client sends the wrong session ID, the connection will be ignored. This is a basic security measure.
    * **Example:** Trying to connect a Frida client to a Frida agent running in a different session.
* **Network Issues:** If the network connection between the client and the target process is interrupted, the communication will fail, and commands won't be processed.
    * **Example:** Firewall blocking the connection, network cable disconnected.

**User Operation Steps to Reach This Code (Debugging Clues):**

1. **Start a Frida Agent:** The user would typically start a Frida agent within the target process. This agent would include the `upload-receiver.c` code (compiled into a shared library or the agent itself).
2. **Frida Client Connects:** The user would then use a Frida client (e.g., Python script using the `frida` library) to connect to the running Frida agent in the target process. This connection involves establishing a socket connection.
3. **Client Sends a Command:** The Frida client would then issue a command using the Frida API. For example, to write memory, the client might use `frida.memory.write_bytes(address, data)`.
4. **Command Serialization:** The Frida client library serializes this command and its parameters into a binary format according to the protocol defined by the `FridaUploadCommandType` enum and related structures.
5. **Data Transmission:** This serialized command data is sent over the established socket connection to the target process.
6. **`frida_receive` Receives Data:** The `frida_receive` function in the Frida agent is listening on the socket and receives this data.
7. **Command Deserialization and Dispatch:** `frida_receive` reads the `command_type` and then uses the `switch` statement to dispatch the execution to the appropriate handler (e.g., the code block for `FRIDA_UPLOAD_COMMAND_WRITE`).
8. **Specific Handler Execution:** The corresponding handler function (or inline code) performs the requested operation, such as writing to memory, changing memory protections, or processing fixups, using the provided parameters.

**Debugging Clues:**

* **Network Errors:** If there are issues with the socket connection (e.g., connection refused, timeout), the debugging would involve checking network configurations, firewalls, and ensuring the Frida agent is running and listening on the correct port.
* **Session ID Mismatch:** If commands are being ignored, check if the Frida client and agent are using the same session ID.
* **Memory Access Errors (Crashes):** If the target process crashes after sending a command, the likely cause is an invalid memory address or size in a `WRITE` or `PROTECT` command. Debugging would involve examining the provided addresses and sizes in the client's code.
* **Incorrect Functionality:** If the target process doesn't behave as expected after sending a command, it could indicate an error in the logic of the injected code or a misunderstanding of the target process's memory layout. Debugging would involve carefully analyzing the command parameters and the target process's state.
* **Use of Frida's Logging:** Frida often provides logging capabilities that can be enabled to trace the commands being sent and received, which can be helpful for diagnosing issues.

In summary, `upload-receiver.c` is a fundamental piece of Frida's architecture, enabling powerful dynamic instrumentation capabilities by allowing a client to remotely control and manipulate the memory and execution environment of a target process. Its functionality is deeply rooted in low-level operating system concepts and binary formats, making it a crucial component for reverse engineering and dynamic analysis tasks.

### 提示词
```
这是目录为frida/subprojects/frida-core/src/fruity/helpers/upload-receiver.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
#include "upload-api.h"

#include <ptrauth.h>
#include <stdbool.h>
#include <stdint.h>
#include <mach-o/loader.h>

#define FRIDA_INT2_MASK  0x00000003U
#define FRIDA_INT11_MASK 0x000007ffU
#define FRIDA_INT16_MASK 0x0000ffffU
#define FRIDA_INT32_MASK 0xffffffffU

typedef uint8_t FridaUploadCommandType;
typedef uint8_t FridaDarwinThreadedItemType;

typedef void (* FridaConstructorFunc) (int argc, const char * argv[], const char * env[], const char * apple[], int * result);

typedef struct _FridaChainedFixupsHeader FridaChainedFixupsHeader;

typedef struct _FridaChainedStartsInImage FridaChainedStartsInImage;
typedef struct _FridaChainedStartsInSegment FridaChainedStartsInSegment;
typedef uint16_t FridaChainedPtrFormat;

typedef struct _FridaChainedPtr64Rebase FridaChainedPtr64Rebase;
typedef struct _FridaChainedPtr64Bind FridaChainedPtr64Bind;
typedef struct _FridaChainedPtrArm64eRebase FridaChainedPtrArm64eRebase;
typedef struct _FridaChainedPtrArm64eBind FridaChainedPtrArm64eBind;
typedef struct _FridaChainedPtrArm64eBind24 FridaChainedPtrArm64eBind24;
typedef struct _FridaChainedPtrArm64eAuthRebase FridaChainedPtrArm64eAuthRebase;
typedef struct _FridaChainedPtrArm64eAuthBind FridaChainedPtrArm64eAuthBind;
typedef struct _FridaChainedPtrArm64eAuthBind24 FridaChainedPtrArm64eAuthBind24;

typedef uint32_t FridaChainedImportFormat;
typedef uint32_t FridaChainedSymbolFormat;

typedef struct _FridaChainedImport FridaChainedImport;
typedef struct _FridaChainedImportAddend FridaChainedImportAddend;
typedef struct _FridaChainedImportAddend64 FridaChainedImportAddend64;

enum _FridaUploadCommandType
{
  FRIDA_UPLOAD_COMMAND_WRITE = 1,
  FRIDA_UPLOAD_COMMAND_APPLY_THREADED,
  FRIDA_UPLOAD_COMMAND_PROCESS_FIXUPS,
  FRIDA_UPLOAD_COMMAND_PROTECT,
  FRIDA_UPLOAD_COMMAND_CONSTRUCT_FROM_POINTERS,
  FRIDA_UPLOAD_COMMAND_CONSTRUCT_FROM_OFFSETS,
  FRIDA_UPLOAD_COMMAND_CHECK,
};

enum _FridaDarwinThreadedItemType
{
  FRIDA_DARWIN_THREADED_REBASE,
  FRIDA_DARWIN_THREADED_BIND
};

struct _FridaChainedFixupsHeader
{
  uint32_t fixups_version;
  uint32_t starts_offset;
  uint32_t imports_offset;
  uint32_t symbols_offset;
  uint32_t imports_count;
  FridaChainedImportFormat imports_format;
  FridaChainedSymbolFormat symbols_format;
};

struct _FridaChainedStartsInImage
{
  uint32_t seg_count;
  uint32_t seg_info_offset[1];
};

struct _FridaChainedStartsInSegment
{
  uint32_t size;
  uint16_t page_size;
  FridaChainedPtrFormat pointer_format;
  uint64_t segment_offset;
  uint32_t max_valid_pointer;
  uint16_t page_count;
  uint16_t page_start[1];
};

enum _FridaChainedPtrStart
{
  FRIDA_CHAINED_PTR_START_NONE  = 0xffff,
  FRIDA_CHAINED_PTR_START_MULTI = 0x8000,
  FRIDA_CHAINED_PTR_START_LAST  = 0x8000,
};

enum _FridaChainedPtrFormat
{
  FRIDA_CHAINED_PTR_ARM64E              =  1,
  FRIDA_CHAINED_PTR_64                  =  2,
  FRIDA_CHAINED_PTR_32                  =  3,
  FRIDA_CHAINED_PTR_32_CACHE            =  4,
  FRIDA_CHAINED_PTR_32_FIRMWARE         =  5,
  FRIDA_CHAINED_PTR_64_OFFSET           =  6,
  FRIDA_CHAINED_PTR_ARM64E_OFFSET       =  7,
  FRIDA_CHAINED_PTR_ARM64E_KERNEL       =  7,
  FRIDA_CHAINED_PTR_64_KERNEL_CACHE     =  8,
  FRIDA_CHAINED_PTR_ARM64E_USERLAND     =  9,
  FRIDA_CHAINED_PTR_ARM64E_FIRMWARE     = 10,
  FRIDA_CHAINED_PTR_X86_64_KERNEL_CACHE = 11,
  FRIDA_CHAINED_PTR_ARM64E_USERLAND24   = 12,
};

struct _FridaChainedPtr64Rebase
{
  uint64_t target   : 36,
           high8    :  8,
           reserved :  7,
           next     : 12,
           bind     :  1;
};

struct _FridaChainedPtr64Bind
{
  uint64_t ordinal  : 24,
           addend   :  8,
           reserved : 19,
           next     : 12,
           bind     :  1;
};

struct _FridaChainedPtrArm64eRebase
{
  uint64_t target : 43,
           high8  :  8,
           next   : 11,
           bind   :  1,
           auth   :  1;
};

struct _FridaChainedPtrArm64eBind
{
  uint64_t ordinal : 16,
           zero    : 16,
           addend  : 19,
           next    : 11,
           bind    :  1,
           auth    :  1;
};

struct _FridaChainedPtrArm64eBind24
{
  uint64_t ordinal : 24,
           zero    :  8,
           addend  : 19,
           next    : 11,
           bind    :  1,
           auth    :  1;
};

struct _FridaChainedPtrArm64eAuthRebase
{
  uint64_t target    : 32,
           diversity : 16,
           addr_div  :  1,
           key       :  2,
           next      : 11,
           bind      :  1,
           auth      :  1;
};

struct _FridaChainedPtrArm64eAuthBind
{
  uint64_t ordinal   : 16,
           zero      : 16,
           diversity : 16,
           addr_div  :  1,
           key       :  2,
           next      : 11,
           bind      :  1,
           auth      :  1;
};

struct _FridaChainedPtrArm64eAuthBind24
{
  uint64_t ordinal   : 24,
           zero      :  8,
           diversity : 16,
           addr_div  :  1,
           key       :  2,
           next      : 11,
           bind      :  1,
           auth      :  1;
};

enum _FridaChainedImportFormat
{
  FRIDA_CHAINED_IMPORT          = 1,
  FRIDA_CHAINED_IMPORT_ADDEND   = 2,
  FRIDA_CHAINED_IMPORT_ADDEND64 = 3,
};

enum _FridaChainedSymbolFormat
{
  FRIDA_CHAINED_SYMBOL_UNCOMPRESSED,
  FRIDA_CHAINED_SYMBOL_ZLIB_COMPRESSED,
};

struct _FridaChainedImport
{
  uint32_t lib_ordinal :  8,
           weak_import :  1,
           name_offset : 23;
};

struct _FridaChainedImportAddend
{
  uint32_t lib_ordinal :  8,
           weak_import :  1,
           name_offset : 23;
  int32_t  addend;
};

struct _FridaChainedImportAddend64
{
  uint64_t lib_ordinal : 16,
           weak_import :  1,
           reserved    : 15,
           name_offset : 32;
  uint64_t addend;
};

#define FRIDA_TEMP_FAILURE_RETRY(expression) \
  ({ \
    ssize_t __result; \
    \
    do __result = expression; \
    while (__result == -1 && *(api->get_errno_storage ()) == EINTR); \
    \
    __result; \
  })

static void frida_apply_threaded_items (uint64_t preferred_base_address, uint64_t slide, uint16_t num_symbols, const uint64_t * symbols,
    uint16_t num_regions, uint64_t * regions);

static void frida_process_chained_fixups (const FridaChainedFixupsHeader * fixups_header, struct mach_header_64 * mach_header,
    size_t preferred_base_address, const FridaUploadApi * api);
static void frida_process_chained_fixups_in_segment_generic64 (void * cursor, FridaChainedPtrFormat format, uint64_t actual_base_address,
    uint64_t preferred_base_address, void ** bound_pointers);
static void frida_process_chained_fixups_in_segment_arm64e (void * cursor, FridaChainedPtrFormat format, uint64_t actual_base_address,
    uint64_t preferred_base_address, void ** bound_pointers);
static void * frida_resolve_import (void ** dylib_handles, int dylib_ordinal, const char * symbol_strings, uint32_t symbol_offset,
    const FridaUploadApi * api);

static void * frida_sign_pointer (void * ptr, uint8_t key, uintptr_t diversity, bool use_address_diversity, void * address_of_ptr);
static const char * frida_symbol_name_from_darwin (const char * name);
static int64_t frida_sign_extend_int19 (uint64_t i19);

static bool frida_read_chunk (int fd, void * buffer, size_t length, size_t * bytes_read, const FridaUploadApi * api);
static bool frida_write_chunk (int fd, const void * buffer, size_t length, size_t * bytes_written, const FridaUploadApi * api);

int64_t
frida_receive (int listener_fd, uint64_t session_id_top, uint64_t session_id_bottom, const char * apple[], const FridaUploadApi * api)
{
  int result = 0;
  bool expecting_client;
  int res;
  struct sockaddr_in addr;
  socklen_t addr_len;
  int client_fd;
  uint32_t ACK_MAGIC = 0xac4ac4ac;

  expecting_client = true;

  do
  {
    uint64_t client_sid[2];

    addr_len = sizeof (addr);

    res = FRIDA_TEMP_FAILURE_RETRY (api->accept (listener_fd, (struct sockaddr *) &addr, &addr_len));
    if (res == -1)
      goto beach;
    client_fd = res;

    #define FRIDA_READ_VALUE(v) \
        if (!frida_read_chunk (client_fd, &(v), sizeof (v), NULL, api)) \
          goto next_client

    #define FRIDA_WRITE_VALUE(v) \
        if (!frida_write_chunk (client_fd, &(v), sizeof (v), NULL, api)) \
          goto next_client

    FRIDA_READ_VALUE (client_sid);
    if (client_sid[0] != session_id_top || client_sid[1] != session_id_bottom)
      goto next_client;

    expecting_client = false;

    FRIDA_WRITE_VALUE (ACK_MAGIC);

    while (true)
    {
      bool success = false;
      FridaUploadCommandType command_type;

      FRIDA_READ_VALUE (command_type);

      switch (command_type)
      {
        case FRIDA_UPLOAD_COMMAND_WRITE:
        {
          uint64_t address;
          uint32_t size;
          size_t n;

          FRIDA_READ_VALUE (address);
          FRIDA_READ_VALUE (size);

          success = frida_read_chunk (client_fd, (void *) address, size, &n, api);

          api->sys_icache_invalidate ((void *) address, n);
          api->sys_dcache_flush ((void *) address, n);

          break;
        }
        case FRIDA_UPLOAD_COMMAND_APPLY_THREADED:
        {
          uint64_t preferred_base_address, slide;
          uint16_t num_symbols, num_regions;

          FRIDA_READ_VALUE (preferred_base_address);
          FRIDA_READ_VALUE (slide);

          FRIDA_READ_VALUE (num_symbols);
          uint64_t symbols[num_symbols];
          if (!frida_read_chunk (client_fd, symbols, num_symbols * sizeof (uint64_t), NULL, api))
            goto next_client;

          FRIDA_READ_VALUE (num_regions);
          uint64_t regions[num_regions];
          if (!frida_read_chunk (client_fd, regions, num_regions * sizeof (uint64_t), NULL, api))
            goto next_client;

          frida_apply_threaded_items (preferred_base_address, slide, num_symbols, symbols, num_regions, regions);

          success = true;

          break;
        }
        case FRIDA_UPLOAD_COMMAND_PROCESS_FIXUPS:
        {
          uint64_t fixups_header_address, mach_header_address, preferred_base_address;

          FRIDA_READ_VALUE (fixups_header_address);
          FRIDA_READ_VALUE (mach_header_address);
          FRIDA_READ_VALUE (preferred_base_address);

          frida_process_chained_fixups ((const FridaChainedFixupsHeader *) fixups_header_address,
              (struct mach_header_64 *) mach_header_address, (size_t) preferred_base_address, api);

          success = true;

          break;
        }
        case FRIDA_UPLOAD_COMMAND_PROTECT:
        {
          uint64_t address;
          uint32_t size;
          int32_t prot;

          FRIDA_READ_VALUE (address);
          FRIDA_READ_VALUE (size);
          FRIDA_READ_VALUE (prot);

          success = api->mprotect ((void *) address, size, prot) == 0;

          break;
        }
        case FRIDA_UPLOAD_COMMAND_CONSTRUCT_FROM_POINTERS:
        {
          uint64_t address;
          uint32_t count;
          FridaConstructorFunc * constructors;
          uint32_t i;

          FRIDA_READ_VALUE (address);
          FRIDA_READ_VALUE (count);

          constructors = (FridaConstructorFunc *) address;

          for (i = 0; i != count; i++)
          {
            const int argc = 0;
            const char * argv[] = { NULL };
            const char * env[] = { NULL };

            constructors[i] (argc, argv, env, apple, &result);
          }

          success = true;

          break;
        }
        case FRIDA_UPLOAD_COMMAND_CONSTRUCT_FROM_OFFSETS:
        {
          uint64_t address;
          uint32_t count;
          uint64_t mach_header_address;
          uint32_t * constructor_offsets;
          uint32_t i;

          FRIDA_READ_VALUE (address);
          FRIDA_READ_VALUE (count);
          FRIDA_READ_VALUE (mach_header_address);

          constructor_offsets = (uint32_t *) address;

          for (i = 0; i != count; i++)
          {
            FridaConstructorFunc constructor;
            const int argc = 0;
            const char * argv[] = { NULL };
            const char * env[] = { NULL };

            constructor = (FridaConstructorFunc) (mach_header_address + constructor_offsets[i]);

            constructor (argc, argv, env, apple, &result);
          }

          success = true;

          break;
        }
        case FRIDA_UPLOAD_COMMAND_CHECK:
        {
          FRIDA_WRITE_VALUE (ACK_MAGIC);

          success = true;

          break;
        }
      }

      if (!success)
        goto next_client;
    }

next_client:
    api->close (client_fd);
  }
  while (expecting_client);

beach:
  api->close (listener_fd);

  return result;
}

static void
frida_apply_threaded_items (uint64_t preferred_base_address, uint64_t slide, uint16_t num_symbols, const uint64_t * symbols,
    uint16_t num_regions, uint64_t * regions)
{
  uint16_t i;

  for (i = 0; i != num_regions; i++)
  {
    uint64_t * slot = (uint64_t *) regions[i];
    uint16_t delta;

    do
    {
      uint64_t value;
      bool is_authenticated;
      FridaDarwinThreadedItemType type;
      uint8_t key;
      bool has_address_diversity;
      uint16_t diversity;
      uint64_t bound_value;

      value = *slot;

      is_authenticated      = (value >> 63) & 1;
      type                  = (value >> 62) & 1;
      delta                 = (value >> 51) & FRIDA_INT11_MASK;
      key                   = (value >> 49) & FRIDA_INT2_MASK;
      has_address_diversity = (value >> 48) & 1;
      diversity             = (value >> 32) & FRIDA_INT16_MASK;

      if (type == FRIDA_DARWIN_THREADED_BIND)
      {
        uint16_t bind_ordinal;

        bind_ordinal = value & FRIDA_INT16_MASK;

        bound_value = symbols[bind_ordinal];
      }
      else if (type == FRIDA_DARWIN_THREADED_REBASE)
      {
        uint64_t rebase_address;

        if (is_authenticated)
        {
          rebase_address = value & FRIDA_INT32_MASK;
        }
        else
        {
          uint64_t top_8_bits, bottom_43_bits, sign_bits;
          bool sign_bit_set;

          top_8_bits = (value << 13) & 0xff00000000000000UL;
          bottom_43_bits = value     & 0x000007ffffffffffUL;

          sign_bit_set = (value >> 42) & 1;
          if (sign_bit_set)
            sign_bits = 0x00fff80000000000UL;
          else
            sign_bits = 0;

          rebase_address = top_8_bits | sign_bits | bottom_43_bits;
        }

        bound_value = rebase_address;

        if (is_authenticated)
          bound_value += preferred_base_address;

        bound_value += slide;
      }

      if (is_authenticated)
      {
        *slot = (uint64_t) frida_sign_pointer ((void *) bound_value, key, diversity, has_address_diversity, slot);
      }
      else
      {
        *slot = bound_value;
      }

      slot += delta;
    }
    while (delta != 0);
  }
}

static void
frida_process_chained_fixups (const FridaChainedFixupsHeader * fixups_header, struct mach_header_64 * mach_header,
    size_t preferred_base_address, const FridaUploadApi * api)
{
  mach_port_t task;
  mach_vm_address_t slab_start;
  size_t slab_size;
  void * slab_cursor;
  void ** dylib_handles;
  size_t dylib_count;
  const void * command;
  uint32_t command_index;
  void ** bound_pointers;
  size_t bound_count, i;
  const char * symbols;
  const FridaChainedStartsInImage * image_starts;
  uint32_t seg_index;

  task = api->_mach_task_self ();

  slab_start = 0;
  slab_size = 64 * 1024;
  api->mach_vm_allocate (task, &slab_start, slab_size, VM_FLAGS_ANYWHERE);
  slab_cursor = (void *) slab_start;

  dylib_handles = slab_cursor;
  dylib_count = 0;

  command = mach_header + 1;
  for (command_index = 0; command_index != mach_header->ncmds; command_index++)
  {
    const struct load_command * lc = command;

    switch (lc->cmd)
    {
      case LC_LOAD_DYLIB:
      case LC_LOAD_WEAK_DYLIB:
      case LC_REEXPORT_DYLIB:
      case LC_LOAD_UPWARD_DYLIB:
      {
        const struct dylib_command * dc = command;
        const char * name = command + dc->dylib.name.offset;

        dylib_handles[dylib_count++] = api->dlopen (name, RTLD_LAZY | RTLD_GLOBAL);

        break;
      }
      default:
        break;
    }

    command += lc->cmdsize;
  }

  slab_cursor += dylib_count * sizeof (void *);

  bound_pointers = slab_cursor;
  bound_count = fixups_header->imports_count;
  slab_cursor += bound_count * sizeof (void *);

  symbols = (const char *) fixups_header + fixups_header->symbols_offset;

  switch (fixups_header->imports_format)
  {
    case FRIDA_CHAINED_IMPORT:
    {
      const FridaChainedImport * imports = ((const void *) fixups_header + fixups_header->imports_offset);

      for (i = 0; i != bound_count; i++)
      {
        const FridaChainedImport * import = &imports[i];

        bound_pointers[i] = frida_resolve_import (dylib_handles,
            import->lib_ordinal, symbols, import->name_offset, api);
      }

      break;
    }
    case FRIDA_CHAINED_IMPORT_ADDEND:
    {
      const FridaChainedImportAddend * imports = ((const void *) fixups_header + fixups_header->imports_offset);

      for (i = 0; i != bound_count; i++)
      {
        const FridaChainedImportAddend * import = &imports[i];

        bound_pointers[i] = frida_resolve_import (dylib_handles,
            import->lib_ordinal, symbols, import->name_offset, api);
        bound_pointers[i] += import->addend;
      }

      break;
    }
    case FRIDA_CHAINED_IMPORT_ADDEND64:
    {
      const FridaChainedImportAddend64 * imports = ((const void *) fixups_header + fixups_header->imports_offset);

      for (i = 0; i != bound_count; i++)
      {
        const FridaChainedImportAddend64 * import = &imports[i];

        bound_pointers[i] = frida_resolve_import (dylib_handles,
            import->lib_ordinal, symbols, import->name_offset, api);
        bound_pointers[i] += import->addend;
      }

      break;
    }
  }

  image_starts = (const FridaChainedStartsInImage *) ((const void *) fixups_header + fixups_header->starts_offset);

  for (seg_index = 0; seg_index != image_starts->seg_count; seg_index++)
  {
    const uint32_t seg_offset = image_starts->seg_info_offset[seg_index];
    const FridaChainedStartsInSegment * seg_starts;
    FridaChainedPtrFormat format;
    uint16_t page_index;

    if (seg_offset == 0)
      continue;

    seg_starts = (const FridaChainedStartsInSegment *) ((const void *) image_starts + seg_offset);
    format = seg_starts->pointer_format;

    for (page_index = 0; page_index != seg_starts->page_count; page_index++)
    {
      uint16_t start;
      void * cursor;

      start = seg_starts->page_start[page_index];
      if (start == FRIDA_CHAINED_PTR_START_NONE)
        continue;
      /* Ignoring MULTI for now as it only applies to 32-bit formats. */

      cursor = (void *) mach_header + seg_starts->segment_offset + (page_index * seg_starts->page_size) + start;

      if (format == FRIDA_CHAINED_PTR_64 || format == FRIDA_CHAINED_PTR_64_OFFSET)
      {
        frida_process_chained_fixups_in_segment_generic64 (cursor, format, (uintptr_t) mach_header, preferred_base_address, bound_pointers);
      }
      else
      {
        frida_process_chained_fixups_in_segment_arm64e (cursor, format, (uintptr_t) mach_header, preferred_base_address, bound_pointers);
      }
    }
  }

  api->mach_vm_deallocate (task, slab_start, slab_size);
}

static void
frida_process_chained_fixups_in_segment_generic64 (void * cursor, FridaChainedPtrFormat format, uint64_t actual_base_address,
    uint64_t preferred_base_address, void ** bound_pointers)
{
  const int64_t slide = actual_base_address - preferred_base_address;
  const size_t stride = 4;

  while (TRUE)
  {
    uint64_t * slot = cursor;
    size_t delta;

    if ((*slot >> 63) == 0)
    {
      FridaChainedPtr64Rebase * item = cursor;
      uint64_t top_8_bits, bottom_36_bits, unpacked_target;

      delta = item->next;

      top_8_bits = (uint64_t) item->high8 << (64 - 8);
      bottom_36_bits = item->target;
      unpacked_target = top_8_bits | bottom_36_bits;

      if (format == FRIDA_CHAINED_PTR_64_OFFSET)
        *slot = actual_base_address + unpacked_target;
      else
        *slot = unpacked_target + slide;
    }
    else
    {
      FridaChainedPtr64Bind * item = cursor;

      delta = item->next;

      *slot = (uint64_t) (bound_pointers[item->ordinal] + item->addend);
    }

    if (delta == 0)
      break;

    cursor += delta * stride;
  }
}

static void
frida_process_chained_fixups_in_segment_arm64e (void * cursor, FridaChainedPtrFormat format, uint64_t actual_base_address,
    uint64_t preferred_base_address, void ** bound_pointers)
{
  const int64_t slide = actual_base_address - preferred_base_address;
  const size_t stride = 8;

  while (TRUE)
  {
    uint64_t * slot = cursor;
    size_t delta;

    switch (*slot >> 62)
    {
      case 0b00:
      {
        FridaChainedPtrArm64eRebase * item = cursor;
        uint64_t top_8_bits, bottom_43_bits, unpacked_target;

        delta = item->next;

        top_8_bits = (uint64_t) item->high8 << (64 - 8);
        bottom_43_bits = item->target;

        unpacked_target = top_8_bits | bottom_43_bits;

        if (format == FRIDA_CHAINED_PTR_ARM64E)
          *slot = unpacked_target + slide;
        else
          *slot = actual_base_address + unpacked_target;

        break;
      }
      case 0b01:
      {
        FridaChainedPtrArm64eBind * item = cursor;
        FridaChainedPtrArm64eBind24 * item24 = cursor;
        uint32_t ordinal;

        delta = item->next;

        ordinal = (format == FRIDA_CHAINED_PTR_ARM64E_USERLAND24)
            ? item24->ordinal
            : item->ordinal;

        *slot = (uint64_t) (bound_pointers[ordinal] +
            frida_sign_extend_int19 (item->addend));

        break;
      }
      case 0b10:
      {
        FridaChainedPtrArm64eAuthRebase * item = cursor;

        delta = item->next;

        *slot = (uint64_t) frida_sign_pointer ((void *) (preferred_base_address + item->target + slide), item->key, item->diversity,
            item->addr_div, slot);

        break;
      }
      case 0b11:
      {
        FridaChainedPtrArm64eAuthBind * item = cursor;
        FridaChainedPtrArm64eAuthBind24 * item24 = cursor;
        uint32_t ordinal;

        delta = item->next;

        ordinal = (format == FRIDA_CHAINED_PTR_ARM64E_USERLAND24)
            ? item24->ordinal
            : item->ordinal;

        *slot = (uint64_t) frida_sign_pointer (bound_pointers[ordinal], item->key, item->diversity, item->addr_div, slot);

        break;
      }
    }

    if (delta == 0)
      break;

    cursor += delta * stride;
  }
}

static void *
frida_resolve_import (void ** dylib_handles, int dylib_ordinal, const char * symbol_strings, uint32_t symbol_offset,
    const FridaUploadApi * api)
{
  void * result;
  const char * raw_name, * name;

  if (dylib_ordinal <= 0)
    return NULL; /* Placeholder if we ever need to support this. */

  raw_name = symbol_strings + symbol_offset;
  name = frida_symbol_name_from_darwin (raw_name);

  result = api->dlsym (dylib_handles[dylib_ordinal - 1], name);

  result = ptrauth_strip (result, ptrauth_key_asia);

  return result;
}

static void *
frida_sign_pointer (void * ptr, uint8_t key, uintptr_t diversity, bool use_address_diversity, void * address_of_ptr)
{
  void * p = ptr;
  uintptr_t d = diversity;

  if (use_address_diversity)
    d = ptrauth_blend_discriminator (address_of_ptr, d);

  switch (key)
  {
    case ptrauth_key_asia:
      p = ptrauth_sign_unauthenticated (p, ptrauth_key_asia, d);
      break;
    case ptrauth_key_asib:
      p = ptrauth_sign_unauthenticated (p, ptrauth_key_asib, d);
      break;
    case ptrauth_key_asda:
      p = ptrauth_sign_unauthenticated (p, ptrauth_key_asda, d);
      break;
    case ptrauth_key_asdb:
      p = ptrauth_sign_unauthenticated (p, ptrauth_key_asdb, d);
      break;
  }

  return p;
}

static const char *
frida_symbol_name_from_darwin (const char * name)
{
  return (name[0] == '_') ? name + 1 : name;
}

static int64_t
frida_sign_extend_int19 (uint64_t i19)
{
  int64_t result;
  bool sign_bit_set;

  result = i19;

  sign_bit_set = i19 >> (19 - 1);
  if (sign_bit_set)
    result |= 0xfffffffffff80000ULL;

  return result;
}

static bool
frida_read_chunk (int fd, void * buffer, size_t length, size_t * bytes_read, const FridaUploadApi * api)
{
  void * cursor = buffer;
  size_t remaining = length;

  if (bytes_read != NULL)
    *bytes_read = 0;

  while (remaining != 0)
  {
    ssize_t n;

    n = FRIDA_TEMP_FAILURE_RETRY (api->read (fd, cursor, remaining));
    if (n <= 0)
      return false;

    if (bytes_read != NULL)
      *bytes_read += n;

    cursor += n;
    remaining -= n;
  }

  return true;
}

static bool
frida_write_chunk (int fd, const void * buffer, size_t length, size_t * bytes_written, const FridaUploadApi * api)
{
  const void * cursor = buffer;
  size_t remaining = length;

  if (bytes_written != NULL)
    *bytes_written = 0;

  while (remaining != 0)
  {
    ssize_t n;

    n = FRIDA_TEMP_FAILURE_RETRY (api->write (fd, cursor, remaining));
    if (n <= 0)
      return false;

    if (bytes_written != NULL)
      *bytes_written += n;

    cursor += n;
    remaining -= n;
  }

  return true;
}

#ifdef BUILDING_TEST_PROGRAM

#include <assert.h>
#include <pthread.h>
#include <stdio.h>

# undef BUILDING_TEST_PROGRAM
# include "upload-listener.c"
# define BUILDING_TEST_PROGRAM
# undef FRIDA_WRITE_VALUE

typedef struct _FridaTestState FridaTestState;

struct _FridaTestState
{
  uint16_t port;

  uint64_t session_id_top;
  uint64_t session_id_bottom;

  uint8_t target_a[4];
  uint8_t target_b[2];

  const FridaUploadApi * api;
};

static void * frida_emulate_client (void * user_data);

int
main (void)
{
  const FridaUploadApi api = FRIDA_UPLOAD_API_INIT;
  uint64_t result;
  uint8_t error_code;
  uint32_t listener_fd;
  uint16_t port;
  pthread_t client_thread;
  FridaTestState state;
  const char * apple[] = { NULL };

  result = frida_listen (FRIDA_RX_BUFFER_SIZE, &api);

  error_code  = (result >> 56) & 0xff;
  listener_fd = (result >> 16) & 0xffffffff;
  port        =  result        & 0xffff;

  printf ("listen() => error_code=%u fd=%u port=%u\n", error_code, listener_fd, port);

  assert (error_code == 0);

  state.port = port;

  state.session_id_top = 1;
  state.session_id_bottom = 2;

  state.target_a[0] = 0;
  state.target_a[1] = 0;
  state.target_a[2] = 3;
  state.target_a[3] = 4;
  state.target_b[0] = 0;
  state.target_b[1] = 6;

  state.api = &api;

  pthread_create (&client_thread, NULL, frida_emulate_client, &state);

  frida_receive (listener_fd, 1, 2, apple, &api);

  pthread_join (client_thread, NULL);

  assert (state.target_a[0] == 1);
  assert (state.target_a[1] == 2);
  assert (state.target_a[2] == 3);
  assert (state.target_a[3] == 4);
  assert (state.target_b[0] == 5);
  assert (state.target_b[1] == 6);

  return 0;
}

static void *
frida_emulate_client (void * user_data)
{
  FridaTestState * state = user_data;
  const FridaUploadApi * api = state->api;
  struct sockaddr_in addr;
  int fd;
  int res;
  bool success;
  const FridaUploadCommandType write_command_type = FRIDA_UPLOAD_COMMAND_WRITE;
  uint64_t address;
  uint32_t size;
  uint8_t val_a[2], val_b;

  fd = api->socket (AF_INET, SOCK_STREAM, 0);
  assert (fd != -1);

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  addr.sin_port = htons (state->port);

  res = FRIDA_TEMP_FAILURE_RETRY (connect (fd, (const struct sockaddr *) &addr, sizeof (addr)));
  assert (res != -1);

  #define FRIDA_WRITE_VALUE(v) \
      success = frida_write_chunk (fd, &(v), sizeof (v), NULL, api); \
      assert (success)

  FRIDA_WRITE_VALUE (state->session_id_top);
  FRIDA_WRITE_VALUE (state->session_id_bottom);

  FRIDA_WRITE_VALUE (write_command_type);
  address = (uint64_t) &state->target_a;
  FRIDA_WRITE_VALUE (address);
  size = 2;
  FRIDA_WRITE_VALUE (size);
  val_a[0] = 1;
  val_a[1] = 2;
  FRIDA_WRITE_VALUE (val_a);

  FRIDA_WRITE_VALUE (write_command_type);
  address = (uint64_t) &state->target_b;
  FRIDA_WRITE_VALUE (address);
  size = 1;
  FRIDA_WRITE_VALUE (size);
  val_b = 5;
  FRIDA_WRITE_VALUE (val_b);

  api->close (fd);

  return NULL;
}

#endif
```