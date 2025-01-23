Response:
Let's break down the thought process for analyzing the `gumv8kernel.cpp` file.

1. **Identify the Purpose:** The filename itself (`gumv8kernel.cpp`) strongly suggests this file is related to the "Kernel" functionality within Frida, specifically interacting with V8 (JavaScript engine). The initial comments confirm this: it's part of Frida's Gum library and handles interactions between JavaScript and the underlying kernel.

2. **High-Level Overview:**  A quick scan of the includes (`gum/gumkernel.h`) and the `GUMJS_MODULE_NAME Kernel` definition confirms its role as a bridge to kernel operations. The presence of `v8::` types indicates JavaScript interaction.

3. **Categorize Functionality:** Start grouping the code into logical blocks based on keywords, function names, and data structures:

    * **Memory Access (Read/Write):**  The `GumMemoryValueType` enum and the `gum_v8_kernel_read` and `gum_v8_kernel_write` functions (along with their macros) are a clear indicator of memory manipulation. The different `GUM_MEMORY_VALUE_*` types suggest support for various data types.

    * **Module Enumeration:** Functions like `gumjs_kernel_enumerate_modules` and `gum_emit_module` clearly deal with listing loaded modules.

    * **Memory Range Enumeration:** `gumjs_kernel_enumerate_ranges` and `gum_emit_range` focus on iterating through memory regions. `gumjs_kernel_enumerate_module_ranges` is a more specific version for module memory.

    * **Memory Allocation/Protection:**  `gumjs_kernel_alloc` and `gumjs_kernel_protect` are self-explanatory.

    * **Memory Scanning:** `gumjs_kernel_scan` and `gumjs_kernel_scan_sync` deal with searching memory for patterns.

    * **API Availability Check:** `gumjs_kernel_get_available` and `gum_v8_kernel_check_api_available` manage the kernel API's status.

    * **Base Address Manipulation:** `gumjs_kernel_get_base` and `gumjs_kernel_set_base` allow getting and setting the kernel's base address.

    * **Internal Setup (`_gum_v8_kernel_init`):** This function likely handles the initialization of the "Kernel" module within the V8 environment.

4. **Analyze Each Category in Detail:**

    * **Memory Access:**
        * **Functionality:**  Provides functions to read and write various data types (int, uint, float, double, strings, byte arrays) from/to memory addresses.
        * **Reverse Engineering:** Crucial for inspecting data structures, function arguments, and return values in a running process. Example: Reading the value of a flag variable.
        * **Binary/OS:** Direct interaction with memory addresses, understanding data types in memory is essential.
        * **Logic:**  Takes an address and data type as input, returns/writes the corresponding value.
        * **User Errors:** Incorrect address, wrong data type specified, insufficient length for strings/byte arrays.
        * **Debugging:** User calls `Kernel.read*` or `Kernel.write*` in their Frida script, which maps to these C++ functions.

    * **Module/Range Enumeration:**
        * **Functionality:** Lists loaded modules and memory regions with their properties (base address, size, protection).
        * **Reverse Engineering:** Essential for identifying code and data segments, libraries, and their locations. Example: Finding the base address of `libc`.
        * **OS:** Requires knowledge of how operating systems manage memory and load executables/libraries.
        * **Logic:** Iterates through the system's module/memory maps and calls a JavaScript callback for each entry.
        * **User Errors:**  Incorrectly specifying module names for `enumerateModuleRanges`.
        * **Debugging:** User calls `Kernel._enumerateModules`, `Kernel._enumerateRanges`, or `Kernel._enumerateModuleRanges`.

    * **Allocation/Protection:**
        * **Functionality:** Allocates memory in the target process and changes the memory protection attributes (read, write, execute).
        * **Reverse Engineering:** Used for injecting code or data, bypassing security checks. Example: Allocating memory for a custom hook.
        * **Binary/OS:**  Directly manipulates memory management mechanisms. Understanding page sizes and protection flags is important.
        * **Logic:**  Takes size/address and protection flags as input, calls the underlying OS functions.
        * **User Errors:** Requesting invalid sizes, setting incorrect protection flags.
        * **Debugging:** User calls `Kernel.alloc` or `Kernel.protect`.

    * **Scanning:**
        * **Functionality:** Searches a memory region for a given byte pattern. Offers both synchronous and asynchronous versions.
        * **Reverse Engineering:** Finding specific instructions, data patterns, or magic numbers in memory. Example: Searching for a specific opcode sequence.
        * **Binary:** Requires understanding byte patterns and potentially assembly instructions.
        * **Logic:**  Iterates through the memory range, comparing bytes against the pattern.
        * **User Errors:** Providing an invalid pattern, scanning an unmapped region.
        * **Debugging:** User calls `Kernel.scan` or `Kernel.scanSync`.

    * **Base Address:**
        * **Functionality:** Gets or sets the assumed base address of the kernel.
        * **Reverse Engineering:**  Useful when the kernel's ASLR needs to be adjusted or when dealing with kernel modules.
        * **OS/Kernel:** Directly interacts with kernel address space.
        * **Logic:**  Gets/sets a global variable representing the kernel base.
        * **User Errors:** Setting an incorrect base address, which can lead to crashes.
        * **Debugging:** User calls `Kernel.base` (getter) or `Kernel.base = ...` (setter).

5. **Look for Interdependencies and Relationships:** Notice how the enumeration functions provide information that can be used by the read/write and scan functions. Allocation provides memory that can be further manipulated.

6. **Address Specific Instructions (as requested):**

    * **Reverse Engineering Examples:**  Explicitly provide examples for each relevant function, demonstrating their use in a reverse engineering context.

    * **Binary/OS/Kernel Details:**  Explain the underlying concepts involved (memory layout, page protection, kernel modules, etc.).

    * **Logic and Input/Output:**  Create simple hypothetical scenarios to illustrate the input and output of specific functions (e.g., reading an integer).

    * **User Errors:** Give concrete examples of common mistakes users might make when interacting with these functions.

    * **Debugging Steps:** Describe how a user's actions in a Frida script lead to the execution of code within this C++ file. Emphasize the flow of control.

7. **Structure the Output:** Organize the information clearly using headings, bullet points, and code examples where appropriate. Start with a general overview and then delve into the details of each functional area.

8. **Review and Refine:**  Read through the analysis to ensure accuracy, clarity, and completeness. Check if all aspects of the prompt have been addressed.

This systematic approach allows for a comprehensive understanding of the `gumv8kernel.cpp` file and its role within the Frida framework. It goes beyond simply listing the functions and explains their purpose, usage in reverse engineering, and interaction with the underlying system.
This C++ source file, `gumv8kernel.cpp`, is a crucial part of the Frida dynamic instrumentation toolkit. It defines the "Kernel" module in Frida's JavaScript API, allowing users to interact with the underlying operating system kernel from their JavaScript scripts. Here's a breakdown of its functionalities:

**Core Functionality:**

1. **Provides an Interface to Kernel Operations:**  The primary goal is to expose kernel-level functionalities to Frida users through a JavaScript API. This allows for introspection and manipulation of the target process's kernel environment.

2. **Memory Access (Read/Write):**
   - Offers functions to read and write data to arbitrary memory addresses within the kernel space. This includes various data types like signed/unsigned 8, 16, 32, 64-bit integers, floats, doubles, byte arrays, and C/UTF-8/UTF-16 strings.
   - **Reverse Engineering Relevance:** This is fundamental for inspecting kernel data structures, function arguments, return values, and even patching kernel code on the fly.
     - **Example:** Reading the value of a specific kernel variable to understand its current state. For instance, reading a flag that controls a certain behavior.
   - **Binary/OS/Kernel:**  Direct interaction with memory addresses, requiring knowledge of data layout and endianness.
   - **Logic:** Takes a memory address and a data type (and optionally length for strings/arrays) as input, and either retrieves the data or writes the provided data to that location.
   - **Assumed Input:**  A valid memory address in the kernel space, the desired data type to read/write.
   - **Possible Output:** The value read from memory, or success/failure of the write operation.
   - **User Errors:**
     - Providing an invalid memory address that leads to a crash.
     - Specifying the wrong data type, resulting in incorrect interpretation of the memory contents.
     - Providing an insufficient length when reading strings or byte arrays, leading to incomplete data.
   - **User Operation to Reach Here:** A Frida script calls functions like `Kernel.readU32(address)`, `Kernel.writeStringUtf8(address, "new string")`, etc. These JavaScript calls are then mapped to the corresponding C++ functions in this file.

3. **Module Enumeration:**
   - Provides functions to list all loaded kernel modules.
   - **Reverse Engineering Relevance:**  Essential for identifying the base addresses and sizes of kernel modules, which is crucial for hooking functions or analyzing module-specific data.
     - **Example:**  Finding the base address of a specific driver to hook one of its functions.
   - **Binary/OS/Kernel:**  Relies on the operating system's mechanisms for tracking loaded modules. On Linux, this might involve reading information from `/proc/modules` or similar kernel interfaces. On Android, it interacts with the kernel's module management.
   - **Logic:** Iterates through the kernel's module list and calls a user-provided JavaScript callback function (`onMatch`) for each module, passing information like the module name, base address, and size.
   - **Assumed Input:**  A JavaScript function to be called when a module is found.
   - **Possible Output:**  The JavaScript callback being executed multiple times with details of each loaded module.
   - **User Errors:** Providing an invalid callback function.
   - **User Operation to Reach Here:** A Frida script calls `Kernel._enumerateModules({ onMatch: function(module) { ... } })`.

4. **Memory Range Enumeration:**
   - Allows listing all memory ranges in the kernel address space with specific protection attributes (e.g., readable, writable, executable).
   - **Reverse Engineering Relevance:** Helps in understanding the memory layout of the kernel, identifying regions of interest (like code sections or data segments), and locating memory regions with specific permissions.
     - **Example:** Finding all executable memory regions to identify potential code injection targets.
   - **Binary/OS/Kernel:**  Uses kernel APIs to query the memory map. On Linux, this could involve reading `/proc/self/maps` or using system calls like `get_vm_area`. On Android, it interacts with the kernel's memory management.
   - **Logic:** Iterates through the kernel's memory map and calls a user-provided JavaScript callback (`onMatch`) for each range, providing the base address, size, and protection flags.
   - **Assumed Input:**  A protection mask specifying the types of memory ranges to enumerate, and a JavaScript callback function.
   - **Possible Output:** The JavaScript callback being executed with details of matching memory ranges.
   - **User Errors:**  Providing an invalid protection mask or callback function.
   - **User Operation to Reach Here:** A Frida script calls `Kernel._enumerateRanges(protectionMask, { onMatch: function(range) { ... } })`.

5. **Module-Specific Memory Range Enumeration:**
   - Similar to the above, but allows enumerating memory ranges specifically within a given kernel module.
   - **Reverse Engineering Relevance:**  Focuses the memory analysis within a particular module, making it easier to find specific code or data segments.
     - **Example:**  Listing all readable memory ranges within a specific driver to find global variables.
   - **Binary/OS/Kernel:**  Combines module enumeration with memory range enumeration.
   - **Logic:** First identifies the target module, then iterates through its memory ranges.
   - **Assumed Input:**  The name of a kernel module, a protection mask, and a JavaScript callback.
   - **Possible Output:** The JavaScript callback being executed with details of memory ranges within the specified module.
   - **User Errors:**  Providing an incorrect module name, invalid protection mask, or callback function.
   - **User Operation to Reach Here:** A Frida script calls `Kernel._enumerateModuleRanges("ModuleName", protectionMask, { onMatch: function(range) { ... } })`.

6. **Memory Allocation:**
   - Provides a way to allocate memory within the kernel address space.
   - **Reverse Engineering Relevance:**  Used for injecting code or data into the kernel, potentially for creating custom hooks or modifying kernel behavior.
     - **Example:** Allocating memory to store a JIT-compiled function to replace an existing kernel function.
   - **Binary/OS/Kernel:**  Relies on the kernel's memory allocation mechanisms (e.g., `kmalloc` on Linux).
   - **Logic:** Takes the desired size as input, allocates a memory block in the kernel, and returns the allocated address as a JavaScript object representing the allocated memory.
   - **Assumed Input:** The size of the memory to allocate.
   - **Possible Output:** A JavaScript object representing the allocated memory region.
   - **User Errors:** Requesting an excessively large allocation that the kernel cannot fulfill.
   - **User Operation to Reach Here:** A Frida script calls `Kernel.alloc(size)`.

7. **Memory Protection Modification:**
   - Allows changing the memory protection attributes (read, write, execute) of a given memory region in the kernel.
   - **Reverse Engineering Relevance:** Crucial for tasks like making code sections writable for patching, or making data sections executable for code injection.
     - **Example:**  Making a read-only code section writable to modify a function's instructions.
   - **Binary/OS/Kernel:**  Interacts with the kernel's memory management unit (MMU) to change page permissions, using system calls like `mprotect` on Linux.
   - **Logic:** Takes a memory address, size, and desired protection flags as input, and attempts to change the protection of the specified memory region.
   - **Assumed Input:** A memory address, the size of the region, and the new protection flags.
   - **Possible Output:** A boolean indicating whether the protection change was successful.
   - **User Errors:** Attempting to change the protection of memory regions they don't have the necessary privileges for, or setting invalid protection flags.
   - **User Operation to Reach Here:** A Frida script calls `Kernel.protect(address, size, protection)`.

8. **Memory Scanning (Synchronous and Asynchronous):**
   - Provides functionality to search for a specific byte pattern within a given memory range in the kernel.
   - **Reverse Engineering Relevance:**  Useful for locating specific code sequences, data patterns, or magic numbers within the kernel's memory.
     - **Example:** Searching for a specific function prologue to find the beginning of a function without knowing its exact address.
   - **Binary/OS/Kernel:**  Performs a byte-by-byte comparison of the search pattern against the memory contents.
   - **Logic:**
     - **Synchronous (`scanSync`):**  Blocks until the scan is complete and returns an array of found matches (address and size).
     - **Asynchronous (`_scan`):**  Performs the scan in the background and calls user-provided JavaScript callback functions (`onMatch`, `onError`, `onComplete`) to report results.
   - **Assumed Input:** A memory address, a size to scan, and the byte pattern to search for. For asynchronous scanning, it also takes callback functions.
   - **Possible Output:**
     - **`scanSync`:** An array of objects, each containing the address and size of a match.
     - **`_scan`:** The `onMatch` callback being called for each match, and the `onComplete` callback being called when the scan finishes.
   - **User Errors:** Providing an invalid memory range or search pattern. For asynchronous scanning, providing invalid callback functions.
   - **User Operation to Reach Here:** A Frida script calls `Kernel.scanSync(address, size, pattern)` or `Kernel._scan(address, size, pattern, { onMatch: ..., onError: ..., onComplete: ... })`.

9. **Kernel Base Address Management:**
   - Allows getting and setting the assumed base address of the kernel.
   - **Reverse Engineering Relevance:**  Useful when dealing with Address Space Layout Randomization (ASLR) and needing to calculate the actual addresses of kernel symbols.
     - **Example:** Getting the current kernel base address to calculate the offset of a known kernel function.
   - **Binary/OS/Kernel:** Interacts with the operating system to determine the kernel's load address. Setting the base address might be necessary in specific scenarios where Frida needs to be informed of a non-standard kernel base.
   - **Logic:**
     - **`get_base`:** Retrieves the currently assumed kernel base address.
     - **`set_base`:** Sets the kernel base address.
   - **Assumed Input:** For setting, a new base address.
   - **Possible Output:** For getting, the current kernel base address.
   - **User Errors:** Setting an incorrect kernel base address, which can lead to incorrect address calculations and crashes.
   - **User Operation to Reach Here:** A Frida script accesses `Kernel.base` (getter) or assigns a value to it (`Kernel.base = newBaseAddress`).

10. **Kernel API Availability Check:**
    - Provides a way to check if the kernel API is available on the current system.
    - **Reverse Engineering Relevance:**  Allows Frida scripts to gracefully handle situations where kernel-level operations are not supported (e.g., due to insufficient privileges or OS limitations).
    - **OS/Kernel:**  Checks for the presence of necessary kernel interfaces or capabilities.
    - **Logic:** Calls an internal Frida function (`gum_kernel_api_is_available`) to determine API availability.
    - **Possible Output:** A boolean indicating whether the kernel API is available.
    - **User Operation to Reach Here:**  Internally used by other `Kernel` module functions to ensure the API is usable. Users might check it explicitly with `Kernel.available`.

**Relationship to Reverse Engineering:**

As highlighted throughout the functionality descriptions, almost every feature in this file is directly relevant to reverse engineering. It provides the fundamental building blocks for:

* **Introspection:** Examining the internal state of the kernel by reading memory and enumerating modules/ranges.
* **Code Analysis:** Locating code within kernel modules and understanding its structure.
* **Dynamic Analysis:** Observing kernel behavior by reading and writing data, and potentially patching code.
* **Hooking:**  A precursor to hooking, as you need to find the target functions (using enumeration and scanning) and potentially allocate memory for your hooks.

**Binary 底层 (Binary Low-Level), Linux, Android 内核及框架知识 (Linux, Android Kernel and Framework Knowledge):**

This file heavily relies on knowledge of:

* **Memory Management:** Understanding how the operating system manages memory, including virtual addresses, physical addresses, page tables, and memory protection mechanisms (read, write, execute).
* **Executable and Linkable Format (ELF):**  Understanding the structure of kernel modules (often in ELF format) to parse module information like base addresses and section boundaries.
* **Operating System Internals:**  Knowledge of how Linux and Android kernels are structured, how modules are loaded, and how to interact with kernel APIs (system calls or internal interfaces).
* **Address Space Layout Randomization (ASLR):**  Understanding how ASLR randomizes the base addresses of modules and the kernel itself, and how to calculate actual addresses.
* **Data Types and Endianness:**  Knowing the sizes and byte order of different data types in memory.
* **Kernel APIs:**  Utilizing underlying kernel APIs (like those exposed through `/proc` on Linux or specific system calls) to retrieve information about modules and memory.

**逻辑推理 (Logical Reasoning):**

Consider the `gumjs_kernel_scan` function (asynchronous scan).

* **假设输入 (Hypothetical Input):**
    - `address`: `0xffffffff81000000` (a hypothetical kernel address)
    - `size`: `4096` (4KB to scan)
    - `pattern`: A byte array representing the machine code for `mov rax, 0xcafebabedeadbeef; ret`
    - `onMatch`: A JavaScript function `function(address, size) { console.log("Found match at " + address); if (address > 0xffffffff81001000) return "stop"; }`
    - `onError`: A simple error handling function.
    - `onComplete`: A function to be called when the scan finishes.

* **逻辑推理 (Logical Reasoning):** The `gum_kernel_scan` function will iterate through the memory range `0xffffffff81000000` to `0xffffffff81000fff`, comparing chunks of memory with the provided `pattern`. If a match is found, the `onMatch` callback will be executed with the address and size of the match. The `onMatch` function in this example logs the address and tells the scanner to stop if it finds a match beyond `0xffffffff81001000`.

* **预期输出 (Expected Output):**  If the specified byte pattern exists within the scanned range, the console will log "Found match at [address]". If a match is found after address `0xffffffff81001000`, the scan will terminate prematurely due to the "stop" return value from `onMatch`. The `onComplete` function will be called at the end.

**用户或编程常见的使用错误 (Common User or Programming Errors):**

1. **Incorrect Memory Addresses:**  Providing invalid or unmapped memory addresses, leading to crashes or errors.
2. **Incorrect Data Types:** Using the wrong `read` or `write` function for the data being accessed, resulting in misinterpretations.
3. **Insufficient Buffer Sizes:** When reading strings or byte arrays, not allocating enough space to hold the data, leading to truncation.
4. **Permissions Issues:** Attempting to read or write to memory regions without the necessary permissions.
5. **Incorrect Pattern in `scan`:** Providing a pattern that doesn't accurately represent the data being searched for.
6. **Forgetting to Unref Allocated Memory (though this file doesn't directly manage user-facing allocation):**  While `gumv8kernel.cpp` handles the underlying kernel allocation, higher-level Frida APIs built on top might require users to manage allocated memory.
7. **Race Conditions:** In multithreaded environments, accessing shared kernel data without proper synchronization can lead to unpredictable results. (While not directly in this file, it's a concern when using these primitives).
8. **Setting Incorrect Kernel Base:**  Manually setting the kernel base address to a wrong value will break all subsequent address calculations.

**用户操作是如何一步步的到达这里，作为调试线索 (How User Operations Reach Here as Debugging Clues):**

1. **User writes a Frida script:** The user starts by writing a JavaScript script that utilizes the `Kernel` module. For example:
   ```javascript
   console.log("Kernel base: " + Kernel.base);
   let someValue = Kernel.readU32(0xffffffff82001000);
   console.log("Value at address: " + someValue);
   Kernel._enumerateModules({
       onMatch: function(module) {
           console.log("Module: " + module.name + " at " + module.base);
       }
   });
   ```

2. **Frida executes the script:** When the user runs this script using the Frida CLI or API, the Frida runtime starts executing the JavaScript code.

3. **JavaScript calls map to C++ functions:**  When the JavaScript code calls functions like `Kernel.base`, `Kernel.readU32`, or `Kernel._enumerateModules`, the V8 JavaScript engine within Frida identifies these calls and maps them to the corresponding C++ functions defined in `gumv8kernel.cpp`. This mapping is established during the initialization of the `Kernel` module (within the `_gum_v8_kernel_init` function).

4. **C++ functions interact with the target process:** The C++ functions then use the underlying Gum library (which interfaces with the target process) to perform the requested kernel operations. For example, `gum_kernel_find_base_address()` for `Kernel.base`, `gum_kernel_read()` for `Kernel.readU32`, and `gum_kernel_enumerate_modules()` for `Kernel._enumerateModules`.

5. **Results are returned to JavaScript:** The results of the kernel operations are then passed back from the C++ functions to the V8 engine, which makes them available to the JavaScript code.

**Debugging Clues:**

If a user encounters an error in their Frida script involving kernel operations, the stack trace or error messages might point back to functions within `gumv8kernel.cpp`. For example:

* **"Access violation reading address..."**: This strongly suggests an issue with the `Kernel.read*` functions, likely due to an invalid memory address.
* **Errors during module enumeration:**  Might indicate issues with the underlying OS APIs for retrieving module information.
* **Crashes related to memory allocation or protection:**  Point to problems within the `Kernel.alloc` or `Kernel.protect` functions, potentially due to invalid sizes or protection flags.

By understanding the functionality of `gumv8kernel.cpp` and how user actions trigger the execution of its functions, developers can effectively debug issues related to kernel interaction in their Frida scripts. They can examine the input parameters passed to these C++ functions and analyze the error conditions within the code to pinpoint the root cause of the problem.

### 提示词
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumv8kernel.cpp的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2015-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2021 Abdelrahman Eid <hot3eed@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8kernel.h"

#include "gumv8macros.h"
#include "gumv8matchcontext.h"

#include <gum/gumkernel.h>
#include <string.h>

#define GUMJS_MODULE_NAME Kernel

using namespace v8;

enum GumMemoryValueType
{
  GUM_MEMORY_VALUE_S8,
  GUM_MEMORY_VALUE_U8,
  GUM_MEMORY_VALUE_S16,
  GUM_MEMORY_VALUE_U16,
  GUM_MEMORY_VALUE_S32,
  GUM_MEMORY_VALUE_U32,
  GUM_MEMORY_VALUE_S64,
  GUM_MEMORY_VALUE_U64,
  GUM_MEMORY_VALUE_LONG,
  GUM_MEMORY_VALUE_ULONG,
  GUM_MEMORY_VALUE_FLOAT,
  GUM_MEMORY_VALUE_DOUBLE,
  GUM_MEMORY_VALUE_BYTE_ARRAY,
  GUM_MEMORY_VALUE_C_STRING,
  GUM_MEMORY_VALUE_UTF8_STRING,
  GUM_MEMORY_VALUE_UTF16_STRING
};

struct GumKernelScanContext
{
  GumMemoryRange range;
  GumMatchPattern * pattern;
  Global<Function> * on_match;
  Global<Function> * on_error;
  Global<Function> * on_complete;

  GumV8Core * core;
};

struct GumKernelScanSyncContext
{
  Local<Array> matches;

  GumV8Core * core;
};

GUMJS_DECLARE_GETTER (gumjs_kernel_get_available)
GUMJS_DECLARE_GETTER (gumjs_kernel_get_base)
GUMJS_DECLARE_SETTER (gumjs_kernel_set_base)
GUMJS_DECLARE_FUNCTION (gumjs_kernel_enumerate_modules)
static gboolean gum_emit_module (const GumModuleDetails * details,
    GumV8MatchContext<GumV8Kernel> * mc);
static Local<Object> gum_parse_module_details (
    const GumModuleDetails * details, GumV8Core * core);
GUMJS_DECLARE_FUNCTION (gumjs_kernel_enumerate_ranges)
static gboolean gum_emit_range (const GumRangeDetails * details,
    GumV8MatchContext<GumV8Kernel> * mc);
GUMJS_DECLARE_FUNCTION (gumjs_kernel_enumerate_module_ranges)
static gboolean gum_emit_module_range (
    const GumKernelModuleRangeDetails * details,
    GumV8MatchContext<GumV8Kernel> * mc);
GUMJS_DECLARE_FUNCTION (gumjs_kernel_alloc)
GUMJS_DECLARE_FUNCTION (gumjs_kernel_protect)

static void gum_v8_kernel_read (GumMemoryValueType type,
    const GumV8Args * args, ReturnValue<Value> return_value);
static void gum_v8_kernel_write (GumMemoryValueType type,
    const GumV8Args * args);

#define GUM_DEFINE_MEMORY_READ(T) \
    GUMJS_DEFINE_FUNCTION (gumjs_kernel_read_##T) \
    { \
      gum_v8_kernel_read (GUM_MEMORY_VALUE_##T, args, info.GetReturnValue ()); \
    }
#define GUM_DEFINE_MEMORY_WRITE(T) \
    GUMJS_DEFINE_FUNCTION (gumjs_kernel_write_##T) \
    { \
      gum_v8_kernel_write (GUM_MEMORY_VALUE_##T, args); \
    }
#define GUM_DEFINE_MEMORY_READ_WRITE(T) \
    GUM_DEFINE_MEMORY_READ (T); \
    GUM_DEFINE_MEMORY_WRITE (T)

#define GUMJS_EXPORT_MEMORY_READ(N, T) \
    { "read" N, gumjs_kernel_read_##T }
#define GUMJS_EXPORT_MEMORY_WRITE(N, T) \
    { "write" N, gumjs_kernel_write_##T }
#define GUMJS_EXPORT_MEMORY_READ_WRITE(N, T) \
    GUMJS_EXPORT_MEMORY_READ (N, T), \
    GUMJS_EXPORT_MEMORY_WRITE (N, T)

GUM_DEFINE_MEMORY_READ_WRITE (S8)
GUM_DEFINE_MEMORY_READ_WRITE (U8)
GUM_DEFINE_MEMORY_READ_WRITE (S16)
GUM_DEFINE_MEMORY_READ_WRITE (U16)
GUM_DEFINE_MEMORY_READ_WRITE (S32)
GUM_DEFINE_MEMORY_READ_WRITE (U32)
GUM_DEFINE_MEMORY_READ_WRITE (S64)
GUM_DEFINE_MEMORY_READ_WRITE (U64)
GUM_DEFINE_MEMORY_READ_WRITE (LONG)
GUM_DEFINE_MEMORY_READ_WRITE (ULONG)
GUM_DEFINE_MEMORY_READ_WRITE (FLOAT)
GUM_DEFINE_MEMORY_READ_WRITE (DOUBLE)
GUM_DEFINE_MEMORY_READ_WRITE (BYTE_ARRAY)
GUM_DEFINE_MEMORY_READ (C_STRING)
GUM_DEFINE_MEMORY_READ_WRITE (UTF8_STRING)
GUM_DEFINE_MEMORY_READ_WRITE (UTF16_STRING)

GUMJS_DECLARE_FUNCTION (gumjs_kernel_scan)
static void gum_kernel_scan_context_free (GumKernelScanContext * self);
static void gum_kernel_scan_context_run (GumKernelScanContext * self);
static gboolean gum_kernel_scan_context_emit_match (GumAddress address,
    gsize size, GumKernelScanContext * self);
GUMJS_DECLARE_FUNCTION (gumjs_kernel_scan_sync)
static gboolean gum_append_match (GumAddress address, gsize size,
    GumKernelScanSyncContext * ctx);

static gboolean gum_v8_kernel_check_api_available (Isolate * isolate);

static const GumV8Property gumjs_kernel_values[] =
{
  { "available", gumjs_kernel_get_available, NULL },
  { "base", gumjs_kernel_get_base, gumjs_kernel_set_base },

  { NULL, NULL, NULL }
};

static const GumV8Function gumjs_kernel_functions[] =
{
  { "_enumerateModules", gumjs_kernel_enumerate_modules },
  { "_enumerateRanges", gumjs_kernel_enumerate_ranges },
  { "_enumerateModuleRanges", gumjs_kernel_enumerate_module_ranges },
  { "alloc", gumjs_kernel_alloc },
  { "protect", gumjs_kernel_protect },

  GUMJS_EXPORT_MEMORY_READ_WRITE ("S8", S8),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("U8", U8),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("S16", S16),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("U16", U16),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("S32", S32),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("U32", U32),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("S64", S64),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("U64", U64),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("Short", S16),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("UShort", U16),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("Int", S32),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("UInt", U32),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("Long", LONG),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("ULong", ULONG),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("Float", FLOAT),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("Double", DOUBLE),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("ByteArray", BYTE_ARRAY),
  GUMJS_EXPORT_MEMORY_READ ("CString", C_STRING),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("Utf8String", UTF8_STRING),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("Utf16String", UTF16_STRING),

  { "_scan", gumjs_kernel_scan },
  { "scanSync", gumjs_kernel_scan_sync },

  { NULL, NULL }
};

void
_gum_v8_kernel_init (GumV8Kernel * self,
                     GumV8Core * core,
                     Local<ObjectTemplate> scope)
{
  auto isolate = core->isolate;

  self->core = core;

  auto module = External::New (isolate, self);

  auto kernel = _gum_v8_create_module ("Kernel", scope, isolate);
  kernel->Set (_gum_v8_string_new_ascii (isolate, "pageSize"),
      Number::New (isolate, gum_kernel_query_page_size ()), ReadOnly);
  _gum_v8_module_add (module, kernel, gumjs_kernel_values, isolate);
  _gum_v8_module_add (module, kernel, gumjs_kernel_functions, isolate);
}

void
_gum_v8_kernel_realize (GumV8Kernel * self)
{
}

void
_gum_v8_kernel_dispose (GumV8Kernel * self)
{
}

void
_gum_v8_kernel_finalize (GumV8Kernel * self)
{
}

GUMJS_DEFINE_GETTER (gumjs_kernel_get_available)
{
  info.GetReturnValue ().Set (!!gum_kernel_api_is_available ());
}

GUMJS_DEFINE_GETTER (gumjs_kernel_get_base)
{
  if (!gum_v8_kernel_check_api_available (isolate))
    return;

  GumAddress address = gum_kernel_find_base_address ();
  info.GetReturnValue ().Set (_gum_v8_uint64_new (address, core));
}

GUMJS_DEFINE_SETTER (gumjs_kernel_set_base)
{
  if (!gum_v8_kernel_check_api_available (isolate))
    return;

  GumAddress address;
  if (!_gum_v8_uint64_get (value, &address, core))
    return;

  gum_kernel_set_base_address (address);
}

GUMJS_DEFINE_FUNCTION (gumjs_kernel_enumerate_modules)
{
  if (!gum_v8_kernel_check_api_available (isolate))
    return;

  GumV8MatchContext<GumV8Kernel> mc (isolate, module);
  if (!_gum_v8_args_parse (args, "F{onMatch,onComplete}", &mc.on_match,
      &mc.on_complete))
    return;

  gum_kernel_enumerate_modules ((GumFoundModuleFunc) gum_emit_module, &mc);

  mc.OnComplete ();
}

static gboolean
gum_emit_module (const GumModuleDetails * details,
                 GumV8MatchContext<GumV8Kernel> * mc)
{
  auto module = gum_parse_module_details (details, mc->parent->core);

  return mc->OnMatch (module);
}

static Local<Object>
gum_parse_module_details (const GumModuleDetails * details,
                          GumV8Core * core)
{
  auto module = Object::New (core->isolate);
  _gum_v8_object_set_utf8 (module, "name", details->name, core);
  _gum_v8_object_set_uint64 (module, "base", details->range->base_address,
      core);
  _gum_v8_object_set_uint (module, "size", details->range->size, core);
  return module;
}

GUMJS_DEFINE_FUNCTION (gumjs_kernel_enumerate_ranges)
{
  if (!gum_v8_kernel_check_api_available (isolate))
    return;

  GumPageProtection prot;
  GumV8MatchContext<GumV8Kernel> mc (isolate, module);
  if (!_gum_v8_args_parse (args, "mF{onMatch,onComplete}", &prot, &mc.on_match,
      &mc.on_complete))
    return;

  gum_kernel_enumerate_ranges (prot, (GumFoundRangeFunc) gum_emit_range, &mc);

  mc.OnComplete ();
}

static gboolean
gum_emit_range (const GumRangeDetails * details,
                GumV8MatchContext<GumV8Kernel> * mc)
{
  auto core = mc->parent->core;

  auto range = Object::New (mc->isolate);
  _gum_v8_object_set_uint64 (range, "base", details->range->base_address,
      core);
  _gum_v8_object_set_uint (range, "size", details->range->size, core);
  _gum_v8_object_set_page_protection (range, "protection", details->protection,
      core);

  return mc->OnMatch (range);
}

GUMJS_DEFINE_FUNCTION (gumjs_kernel_enumerate_module_ranges)
{
  if (!gum_v8_kernel_check_api_available (isolate))
    return;

  gchar * module_name;
  GumPageProtection prot;
  GumV8MatchContext<GumV8Kernel> mc (isolate, module);
  if (!_gum_v8_args_parse (args, "s?mF{onMatch,onComplete}", &module_name,
      &prot, &mc.on_match, &mc.on_complete))
    return;

  gum_kernel_enumerate_module_ranges (
    (module_name == NULL) ? "Kernel" : module_name, prot,
    (GumFoundKernelModuleRangeFunc) gum_emit_module_range, &mc);

  mc.OnComplete ();
}

static gboolean
gum_emit_module_range (const GumKernelModuleRangeDetails * details,
                       GumV8MatchContext<GumV8Kernel> * mc)
{
  auto core = mc->parent->core;

  auto range = Object::New (mc->isolate);
  _gum_v8_object_set_utf8 (range, "name", details->name, core);
  _gum_v8_object_set_uint64 (range, "base", details->address, core);
  _gum_v8_object_set_uint (range, "size", details->size, core);
  _gum_v8_object_set_page_protection (range, "protection", details->protection,
      core);

  return mc->OnMatch (range);
}

GUMJS_DEFINE_FUNCTION (gumjs_kernel_alloc)
{
  if (!gum_v8_kernel_check_api_available (isolate))
    return;

  gsize size;
  if (!_gum_v8_args_parse (args, "Z", &size))
    return;

  if (size == 0 || size > 0x7fffffff)
  {
    _gum_v8_throw_ascii_literal (isolate, "invalid size");
    return;
  }

  gsize page_size = gum_kernel_query_page_size ();
  guint n_pages = ((size + page_size - 1) & ~(page_size - 1)) / page_size;

  GumAddress address = gum_kernel_alloc_n_pages (n_pages);

  GumV8KernelResource * res = _gum_v8_kernel_resource_new (address,
      n_pages * page_size, gum_kernel_free_pages, core);

  info.GetReturnValue ().Set (Local<Object>::New (isolate, *res->instance));
}

GUMJS_DEFINE_FUNCTION (gumjs_kernel_protect)
{
  if (!gum_v8_kernel_check_api_available (isolate))
    return;

  GumAddress address;
  gsize size;
  GumPageProtection prot;
  if (!_gum_v8_args_parse (args, "QZm", &address, &size, &prot))
    return;

  if (size > 0x7fffffff)
  {
    _gum_v8_throw_ascii_literal (isolate, "invalid size");
    return;
  }

  bool success;
  if (size != 0)
    success = !!gum_kernel_try_mprotect (address, size, prot);
  else
    success = true;

  info.GetReturnValue ().Set (success);
}

static void
gum_v8_kernel_read (GumMemoryValueType type,
                    const GumV8Args * args,
                    ReturnValue<Value> return_value)
{
  auto core = args->core;
  auto isolate = core->isolate;
  if (!gum_v8_kernel_check_api_available (isolate))
    return;

  GumAddress address;
  gssize length = 0;

  switch (type)
  {
    case GUM_MEMORY_VALUE_BYTE_ARRAY:
    case GUM_MEMORY_VALUE_C_STRING:
    case GUM_MEMORY_VALUE_UTF8_STRING:
    case GUM_MEMORY_VALUE_UTF16_STRING:
      if (!_gum_v8_args_parse (args, "QZ", &address, &length))
        return;
      break;
    default:
      if (!_gum_v8_args_parse (args, "Q", &address))
        return;
      break;
  }

  if (address == 0)
  {
    return_value.Set (Null (isolate));
    return;
  }

  if (length == 0)
  {
    switch (type)
    {
      case GUM_MEMORY_VALUE_S8:
      case GUM_MEMORY_VALUE_U8:
        length = 1;
        break;
      case GUM_MEMORY_VALUE_S16:
      case GUM_MEMORY_VALUE_U16:
        length = 2;
        break;
      case GUM_MEMORY_VALUE_S32:
      case GUM_MEMORY_VALUE_U32:
      case GUM_MEMORY_VALUE_FLOAT:
        length = 4;
        break;
      case GUM_MEMORY_VALUE_S64:
      case GUM_MEMORY_VALUE_U64:
      case GUM_MEMORY_VALUE_LONG:
      case GUM_MEMORY_VALUE_ULONG:
      case GUM_MEMORY_VALUE_DOUBLE:
        length = 8;
        break;
      default:
        g_assert_not_reached ();
    }
  }

  Local<Value> result;
  if (length > 0)
  {
    gsize n_bytes_read;
    auto data = gum_kernel_read (address, length, &n_bytes_read);
    if (data == NULL)
    {
      _gum_v8_throw_ascii (isolate,
          "access violation reading 0x%" G_GINT64_MODIFIER "x",
          address);
      return;
    }

    switch (type)
    {
      case GUM_MEMORY_VALUE_S8:
        result = Integer::New (isolate, *((gint8 *) data));
        break;
      case GUM_MEMORY_VALUE_U8:
        result = Integer::NewFromUnsigned (isolate, *((guint8 *) data));
        break;
      case GUM_MEMORY_VALUE_S16:
        result = Integer::New (isolate, *((gint16 *) data));
        break;
      case GUM_MEMORY_VALUE_U16:
        result = Integer::NewFromUnsigned (isolate, *((guint16 *) data));
        break;
      case GUM_MEMORY_VALUE_S32:
        result = Integer::New (isolate, *((gint32 *) data));
        break;
      case GUM_MEMORY_VALUE_U32:
        result = Integer::NewFromUnsigned (isolate, *((guint32 *) data));
        break;
      case GUM_MEMORY_VALUE_S64:
        result = _gum_v8_int64_new (*((gint64 *) data), core);
        break;
      case GUM_MEMORY_VALUE_U64:
        result = _gum_v8_uint64_new (*((guint64 *) data), core);
        break;
      case GUM_MEMORY_VALUE_LONG:
        result = _gum_v8_int64_new (*((glong *) data), core);
        break;
      case GUM_MEMORY_VALUE_ULONG:
        result = _gum_v8_uint64_new (*((gulong *) data), core);
        break;
      case GUM_MEMORY_VALUE_FLOAT:
        result = Number::New (isolate, *((gfloat *) data));
        break;
      case GUM_MEMORY_VALUE_DOUBLE:
        result = Number::New (isolate, *((gdouble *) data));
        break;
      case GUM_MEMORY_VALUE_BYTE_ARRAY:
        result = _gum_v8_array_buffer_new_take (isolate,
            g_steal_pointer (&data), n_bytes_read);
        break;
      case GUM_MEMORY_VALUE_C_STRING:
      {
        gchar * str = g_utf8_make_valid ((gchar *) data, length);
        result = String::NewFromUtf8 (isolate, str).ToLocalChecked ();
        g_free (str);

        break;
      }
      case GUM_MEMORY_VALUE_UTF8_STRING:
      {
        const gchar * end;
        if (!g_utf8_validate ((gchar *) data, length, &end))
        {
          _gum_v8_throw_ascii (isolate,
              "can't decode byte 0x%02x in position %u",
              (guint8) *end, (guint) (end - (gchar *) data));
          break;
        }

        result = String::NewFromUtf8 (isolate, (gchar *) data,
            NewStringType::kNormal, length).ToLocalChecked ();

        break;
      }
      case GUM_MEMORY_VALUE_UTF16_STRING:
      {
        auto str_utf16 = (gunichar2 *) data;

        glong size;
        auto str_utf8 = g_utf16_to_utf8 (str_utf16, length, NULL, &size, NULL);
        if (str_utf8 == NULL)
        {
          _gum_v8_throw_ascii_literal (isolate, "invalid string");
          break;
        }

        if (size != 0)
        {
          result = String::NewFromUtf8 (isolate, str_utf8,
              NewStringType::kNormal, size).ToLocalChecked ();
        }
        else
        {
          result = String::Empty (isolate);
        }

        g_free (str_utf8);

        break;
      }
    }

    g_free (data);
  }
  else
  {
    switch (type)
    {
      case GUM_MEMORY_VALUE_C_STRING:
      case GUM_MEMORY_VALUE_UTF8_STRING:
      case GUM_MEMORY_VALUE_UTF16_STRING:
        result = String::Empty (isolate);
        break;
      case GUM_MEMORY_VALUE_BYTE_ARRAY:
        result = ArrayBuffer::New (isolate, 0);
        break;
      default:
        _gum_v8_throw_ascii (isolate, "please provide a length > 0");
        return;
    }
  }

  if (!result.IsEmpty ())
    return_value.Set (result);
}

static void
gum_v8_kernel_write (GumMemoryValueType type,
                     const GumV8Args * args)
{
  auto core = args->core;
  auto isolate = core->isolate;
  gssize s = 0;
  gsize u = 0;
  gint64 s64 = 0;
  guint64 u64 = 0;
  gdouble number = 0;
  gfloat number32 = 0;
  GBytes * bytes = NULL;
  gchar * str = NULL;
  gsize str_length = 0;
  gunichar2 * str_utf16 = NULL;

  if (!gum_v8_kernel_check_api_available (isolate))
    return;

  GumAddress address = 0;
  guint8 * data = NULL;

  switch (type)
  {
    case GUM_MEMORY_VALUE_S8:
    case GUM_MEMORY_VALUE_S16:
    case GUM_MEMORY_VALUE_S32:
      if (!_gum_v8_args_parse (args, "Qz", &address, &s))
        return;
      break;
    case GUM_MEMORY_VALUE_U8:
    case GUM_MEMORY_VALUE_U16:
    case GUM_MEMORY_VALUE_U32:
      if (!_gum_v8_args_parse (args, "QZ", &address, &u))
        return;
      break;
    case GUM_MEMORY_VALUE_S64:
    case GUM_MEMORY_VALUE_LONG:
      if (!_gum_v8_args_parse (args, "Qq", &address, &s64))
        return;
      break;
    case GUM_MEMORY_VALUE_U64:
    case GUM_MEMORY_VALUE_ULONG:
      if (!_gum_v8_args_parse (args, "QQ", &address, &u64))
        return;
      break;
    case GUM_MEMORY_VALUE_FLOAT:
    case GUM_MEMORY_VALUE_DOUBLE:
      if (!_gum_v8_args_parse (args, "Qn", &address, &number))
        return;
      number32 = (gfloat) number;
      break;
    case GUM_MEMORY_VALUE_BYTE_ARRAY:
      if (!_gum_v8_args_parse (args, "QB", &address, &bytes))
        return;
      break;
    case GUM_MEMORY_VALUE_UTF8_STRING:
    case GUM_MEMORY_VALUE_UTF16_STRING:
      if (!_gum_v8_args_parse (args, "Qs", &address, &str))
        return;

      str_length = g_utf8_strlen (str, -1);

      if (type == GUM_MEMORY_VALUE_UTF16_STRING)
        str_utf16 = g_utf8_to_utf16 (str, -1, NULL, NULL, NULL);

      break;
    default:
      g_assert_not_reached ();
  }

  gsize length = 0;

  switch (type)
  {
    case GUM_MEMORY_VALUE_S8:
      data = (guint8 *) &s;
      length = 1;
      break;
    case GUM_MEMORY_VALUE_U8:
      data = (guint8 *) &u;
      length = 1;
      break;
    case GUM_MEMORY_VALUE_S16:
      data = (guint8 *) &s;
      length = 2;
      break;
    case GUM_MEMORY_VALUE_U16:
      data = (guint8 *) &u;
      length = 2;
      break;
    case GUM_MEMORY_VALUE_S32:
      data = (guint8 *) &s;
      length = 4;
      break;
    case GUM_MEMORY_VALUE_U32:
      data = (guint8 *) &u;
      length = 4;
      break;
    case GUM_MEMORY_VALUE_LONG:
    case GUM_MEMORY_VALUE_S64:
      data = (guint8 *) &s64;
      length = 8;
      break;
    case GUM_MEMORY_VALUE_ULONG:
    case GUM_MEMORY_VALUE_U64:
      data = (guint8 *) &u64;
      length = 8;
      break;
    case GUM_MEMORY_VALUE_FLOAT:
      data = (guint8 *) &number32;
      length = 4;
      break;
    case GUM_MEMORY_VALUE_DOUBLE:
      data = (guint8 *) &number;
      length = 8;
      break;
    case GUM_MEMORY_VALUE_BYTE_ARRAY:
    {
      data = (guint8 *) g_bytes_get_data (bytes, &length);
      break;
    }
    case GUM_MEMORY_VALUE_UTF8_STRING:
    {
      data = (guint8 *) str;
      length = g_utf8_offset_to_pointer (str, str_length) - str + 1;
      break;
    }
    case GUM_MEMORY_VALUE_UTF16_STRING:
    {
      data = (guint8 *) str_utf16;
      length = (str_length + 1) * sizeof (gunichar2);
      break;
    }
    default:
      g_assert_not_reached ();
  }

  if (length > 0)
  {
    if (!gum_kernel_write (address, data, length))
    {
      _gum_v8_throw_ascii (isolate,
          "access violation writing to 0x%" G_GINT64_MODIFIER "x",
          address);
    }
  }
  else
  {
    _gum_v8_throw_ascii (isolate, "please provide a length > 0");
  }

  g_bytes_unref (bytes);
  g_free (str);
  g_free (str_utf16);
}

GUMJS_DEFINE_FUNCTION (gumjs_kernel_scan)
{
  GumAddress address;
  gsize size;
  GumMatchPattern * pattern;
  Local<Function> on_match, on_error, on_complete;
  if (!_gum_v8_args_parse (args, "QZMF{onMatch,onError,onComplete}", &address,
      &size, &pattern, &on_match, &on_error, &on_complete))
    return;

  GumMemoryRange range;
  range.base_address = address;
  range.size = size;

  auto ctx = g_slice_new0 (GumKernelScanContext);
  ctx->range = range;
  ctx->pattern = pattern;
  ctx->on_match = new Global<Function> (isolate, on_match);
  ctx->on_error = new Global<Function> (isolate, on_error);
  ctx->on_complete = new Global<Function> (isolate, on_complete);
  ctx->core = core;

  _gum_v8_core_pin (core);
  _gum_v8_core_push_job (core, (GumScriptJobFunc) gum_kernel_scan_context_run,
      ctx, (GDestroyNotify) gum_kernel_scan_context_free);
}

static void
gum_kernel_scan_context_free (GumKernelScanContext * self)
{
  auto core = self->core;

  {
    ScriptScope script_scope (core->script);

    delete self->on_match;
    delete self->on_error;
    delete self->on_complete;

    _gum_v8_core_unpin (core);
  }

  gum_match_pattern_unref (self->pattern);

  g_slice_free (GumKernelScanContext, self);
}

static void
gum_kernel_scan_context_run (GumKernelScanContext * self)
{
  auto core = self->core;
  auto isolate = core->isolate;
  auto context = isolate->GetCurrentContext ();

  gum_kernel_scan (&self->range, self->pattern,
      (GumMemoryScanMatchFunc) gum_kernel_scan_context_emit_match, self);

  ScriptScope script_scope (core->script);

  auto on_complete (Local<Function>::New (isolate, *self->on_complete));
  auto recv = Undefined (isolate);
  auto result = on_complete->Call (context, recv, 0, nullptr);
  _gum_v8_ignore_result (result);
}

static gboolean
gum_kernel_scan_context_emit_match (GumAddress address,
                                    gsize size,
                                    GumKernelScanContext * self)
{
  ScriptScope scope (self->core->script);
  auto isolate = self->core->isolate;
  auto context = isolate->GetCurrentContext ();

  gboolean proceed = TRUE;

  auto on_match = Local<Function>::New (isolate, *self->on_match);
  auto recv = Undefined (isolate);
  Local<Value> argv[] = {
    _gum_v8_uint64_new (address, self->core),
    Integer::NewFromUnsigned (isolate, size)
  };
  Local<Value> result;
  if (on_match->Call (context, recv, G_N_ELEMENTS (argv), argv)
      .ToLocal (&result) && result->IsString ())
  {
    v8::String::Utf8Value str (isolate, result);
    proceed = strcmp (*str, "stop") != 0;
  }

  return proceed;
}

GUMJS_DEFINE_FUNCTION (gumjs_kernel_scan_sync)
{
  GumAddress address;
  gsize size;
  GumMatchPattern * pattern;
  if (!_gum_v8_args_parse (args, "QZM", &address, &size, &pattern))
    return;

  GumMemoryRange range;
  range.base_address = address;
  range.size = size;

  GumKernelScanSyncContext ctx;
  ctx.matches = Array::New (isolate);
  ctx.core = core;

  gum_kernel_scan (&range, pattern, (GumMemoryScanMatchFunc) gum_append_match,
      &ctx);

  info.GetReturnValue ().Set (ctx.matches);

  gum_match_pattern_unref (pattern);
}

static gboolean
gum_append_match (GumAddress address,
                  gsize size,
                  GumKernelScanSyncContext * ctx)
{
  GumV8Core * core = ctx->core;

  auto match = Object::New (core->isolate);
  _gum_v8_object_set_uint64 (match, "address", address, core);
  _gum_v8_object_set_uint (match, "size", size, core);
  ctx->matches->Set (core->isolate->GetCurrentContext (),
      ctx->matches->Length (), match).ToChecked ();

  return TRUE;
}

static gboolean
gum_v8_kernel_check_api_available (Isolate * isolate)
{
  if (!gum_kernel_api_is_available ())
  {
    _gum_v8_throw_ascii_literal (isolate,
        "Kernel API is not available on this system");
    return FALSE;
  }

  return TRUE;
}
```