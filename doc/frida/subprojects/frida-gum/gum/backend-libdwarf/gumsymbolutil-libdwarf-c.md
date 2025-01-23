Response:
Let's break down the thought process for analyzing this C code. The goal is to understand the functionality of `gumsymbolutil-libdwarf.c` within the Frida context.

**1. Initial Skim and High-Level Understanding:**

* **File Path:**  `frida/subprojects/frida-gum/gum/backend-libdwarf/gumsymbolutil-libdwarf.c`. This immediately tells us it's part of Frida's "Gum" library, specifically for symbol utilities and using the "libdwarf" backend. This hints at its core purpose: dealing with debugging information (DWARF).
* **Copyright:**  Confirms it's part of the Frida project and gives author information.
* **Includes:**  Key includes are `gumsymbolutil.h`, `gum-init.h`, `gumelfmodule.h`, `dlfcn.h`, `libdwarf.h`, `libelf.h`, and `strings.h`. These point to the following responsibilities:
    * `gumsymbolutil.h`: Likely defines the public interface of this module.
    * `gum-init.h`:  Initialization/deinitialization routines for Gum.
    * `gumelfmodule.h`:  Working with ELF (Executable and Linkable Format) files, the standard binary format on Linux and Android.
    * `dlfcn.h`:  Dynamic linking functions (like `dladdr`).
    * `libdwarf.h`:  The core DWARF debugging information library.
    * `libelf.h`:  Library for parsing ELF files.
    * `strings.h`:  String manipulation functions.
* **Typedefs and Structs:**  The numerous `typedef struct _...` declarations signal the internal data structures used to manage module information, symbol details, and source code locations. Keywords like `Symbol`, `Dwarf`, `Source`, `Module`, and `Die` (Debugging Information Entry) are strong indicators of the module's purpose.

**2. Identifying Key Functionalities by Analyzing Function Signatures and Logic:**

* **`gum_symbol_details_from_address(gpointer address, GumDebugSymbolDetails *details)`:** This function takes an address and attempts to populate a `GumDebugSymbolDetails` structure. The internal logic uses `gum_module_entry_from_address`, `gum_find_cu_die_by_virtual_address`, `gum_find_symbol_by_virtual_address`, and `gum_find_line_by_virtual_address`. This strongly suggests it retrieves detailed debugging information (module, symbol name, file, line number) for a given memory address. The "no_debug_info" block provides fallback logic if DWARF information is unavailable.
* **`gum_symbol_name_from_address(gpointer address)`:** Similar to the above, but focuses on retrieving just the symbol name. Again, it uses DWARF information if available and falls back to dynamic linking or address-based naming.
* **`gum_find_function(const gchar *name)`:**  Searches for a function by name. It uses a hash table (`gum_function_addresses`) for efficient lookup.
* **`gum_find_nearest_symbol_by_address(gpointer address, GumNearestSymbolDetails *nearest)`:** Finds the symbol closest to a given address, even if the address falls within the symbol's bounds. This is crucial for understanding code execution flow.
* **`gum_find_functions_named(const gchar *name)`:** Returns all functions with a specific name (handling potential overloads or multiple definitions).
* **`gum_find_functions_matching(const gchar *str)`:**  Uses pattern matching to find functions with names that match a given string.
* **`gum_load_symbols(const gchar *path)`:**  Currently returns `FALSE`, suggesting this functionality might be unimplemented or handled elsewhere.
* **`gum_module_entry_from_address(...)` and `gum_module_entry_from_path_and_base(...)`:** These functions are responsible for managing cached information about loaded modules (ELF files and their associated DWARF data). They handle loading DWARF data from the ELF file.
* **`gum_collect_module_functions(...)` and `gum_collect_symbol_if_function(...)`:**  These functions iterate through the symbols in an ELF module and populate the `gum_function_addresses` and `gum_address_symbols` hash tables. This is the mechanism for building the symbol cache.
* **Functions prefixed with `gum_read_attribute_*` and `gum_enumerate_*`:** These functions directly interact with the `libdwarf` API to parse the DWARF information. They read attributes from DWARF entries (Dies) and iterate through the DWARF structure.

**3. Connecting Functionalities to Reverse Engineering Concepts:**

As each function's purpose became clearer, the connections to reverse engineering techniques became more apparent. For example:

* **Symbol Resolution:**  `gum_symbol_details_from_address` and `gum_symbol_name_from_address` are fundamental for understanding what code is being executed at a particular address. This is core to debugging and reverse engineering.
* **Function Hooking/Tracing:** Knowing the function name and address (`gum_find_function`, `gum_find_functions_named`, `gum_find_functions_matching`) is essential for setting breakpoints or hooks in Frida.
* **Code Flow Analysis:**  `gum_find_nearest_symbol_by_address` helps to understand the context of an instruction pointer, even if it's inside a function.
* **Understanding Binary Structure:** The code's interaction with ELF and DWARF formats highlights the importance of understanding binary file structures in reverse engineering.

**4. Identifying Interactions with the Underlying System:**

* **ELF and DWARF:**  The heavy reliance on `libelf` and `libdwarf` directly ties this code to understanding the binary format and debugging information standards used in Linux and Android.
* **Dynamic Linking (`dlfcn.h`):** The use of `dladdr` indicates that the module can also retrieve symbol information from the dynamic linker's symbol table.
* **Memory Management:** Functions like `gum_process_resolve_module_pointer` (though not fully defined in the snippet) imply interaction with the operating system's memory management to determine which module owns a particular memory address.
* **Caching:** The `gum_maybe_refresh_symbol_caches` function and the `gum_cache_timer` demonstrate an optimization technique to avoid repeatedly parsing symbol information.

**5. Logical Reasoning and Examples:**

Once the functions and their purposes were identified, constructing hypothetical inputs and outputs became easier. The examples focused on how specific functions would behave given a particular address or symbol name.

**6. Identifying Potential User Errors:**

Thinking about how a programmer might use this API led to potential error scenarios, such as trying to get symbol information for an invalid address or a non-existent module.

**7. Tracing User Operations:**

The final step was to consider how a Frida user's actions would lead to this code being executed. This involved understanding Frida's core use cases, such as attaching to a process, setting hooks, and examining memory.

**Self-Correction/Refinement during Analysis:**

* **Initial Overemphasis on Single Functions:**  Initially, I might have focused too much on individual functions in isolation. The realization that the functions work together (e.g., `gum_symbol_details_from_address` calls other functions) led to a better understanding of the overall workflow.
* **Understanding the "Fallback" Logic:**  The "no_debug_info" sections in `gum_symbol_details_from_address` and `gum_symbol_name_from_address` are important. Recognizing this fallback mechanism provides a more complete picture of the module's capabilities.
* **The Importance of Caching:**  Realizing the role of the caching mechanism explained why the code enumerates modules and symbols periodically.

By following these steps, the detailed analysis of the `gumsymbolutil-libdwarf.c` file became more systematic and comprehensive.
This C source code file, `gumsymbolutil-libdwarf.c`, belonging to the Frida dynamic instrumentation toolkit, is responsible for **resolving symbols and retrieving debugging information** using the **libdwarf** library. Essentially, it translates memory addresses back into meaningful names (like function names, variable names) and source code locations (file and line number).

Here's a breakdown of its functionalities with examples and connections to reverse engineering concepts:

**Core Functionalities:**

1. **Retrieving Detailed Symbol Information from an Address (`gum_symbol_details_from_address`):**
   - **Functionality:** Given a memory address, this function attempts to find the corresponding module, symbol name, source file path, line number, and column number. It leverages DWARF debugging information embedded in the executable or shared library.
   - **Reverse Engineering Relevance:** This is fundamental for understanding what code is being executed at a specific point. When you set a breakpoint in Frida and the execution stops, this function helps you identify the exact location in the source code.
   - **Binary Underpinnings:**
     - It interacts with the ELF (Executable and Linkable Format) structure of the loaded modules to find the DWARF sections.
     - It uses `libdwarf` to parse the DWARF data, which contains information about compilation units, functions, variables, and their locations.
   - **Linux/Android Kernel/Framework:**  It works with the memory layout of processes on Linux and Android. It needs to understand how modules are loaded and their address spaces.
   - **Logic & Assumptions:**
     - **Input:** A memory address within a loaded module.
     - **Output:** A `GumDebugSymbolDetails` structure containing the module name, symbol name, file name, line number, and column.
     - **Assumption:** The module at the given address has been compiled with DWARF debugging information. If not, it falls back to less precise methods.
   - **User/Programming Errors:**  Passing an invalid memory address (e.g., an address outside of any loaded module) would likely result in failure to find symbol details.

2. **Retrieving Symbol Name from an Address (`gum_symbol_name_from_address`):**
   - **Functionality:** A simpler version of the above, focused solely on getting the name of the symbol at a given address.
   - **Reverse Engineering Relevance:** Quickly identifying function or variable names at specific memory locations.
   - **Binary Underpinnings:** Similar to the previous function, it uses ELF and DWARF data. It might also fall back to using dynamic linking information (`dladdr`) if DWARF is unavailable.
   - **Linux/Android Kernel/Framework:**  Relies on understanding the memory map of processes.
   - **Logic & Assumptions:**
     - **Input:** A memory address.
     - **Output:** A dynamically allocated string containing the symbol name.
     - **Assumption:**  Similar to the above, DWARF is preferred, but it can use dynamic linking information as a fallback.
   - **User/Programming Errors:**  Providing an invalid address could lead to a `NULL` return or a generic address representation.

3. **Finding a Function's Address by Name (`gum_find_function`):**
   - **Functionality:** Given a function name, it searches through the loaded modules and returns the address of the first function matching that name.
   - **Reverse Engineering Relevance:**  Crucial for setting hooks or breakpoints on specific functions by their name, which is often easier than remembering memory addresses.
   - **Binary Underpinnings:** It likely maintains a cache of function names and their addresses, built by parsing the symbol tables of loaded modules (using `gumelfmodule`).
   - **Linux/Android Kernel/Framework:**  Needs to enumerate loaded modules and their symbols.
   - **Logic & Assumptions:**
     - **Input:** A function name (string).
     - **Output:** The memory address of the function, or `NULL` if not found.
     - **Assumption:** The function exists and its symbol is exported or present in the debugging information.
   - **User/Programming Errors:** Typographical errors in the function name will result in the function not being found.

4. **Finding the Nearest Symbol to an Address (`gum_find_nearest_symbol_by_address`):**
   - **Functionality:** Finds the symbol whose address is closest to, but not exceeding, the given address. This is useful when an address falls within a function's code, but not at the exact start of a known symbol.
   - **Reverse Engineering Relevance:** Helps provide context when examining arbitrary memory locations within a function's body.
   - **Binary Underpinnings:**  Requires iterating through the sorted list of symbol addresses.
   - **Linux/Android Kernel/Framework:**  Relies on the process's memory layout and symbol tables.
   - **Logic & Assumptions:**
     - **Input:** A memory address.
     - **Output:** A `GumNearestSymbolDetails` structure containing the name and address of the nearest symbol.
     - **Assumption:** The symbol tables are accurately representing the code layout.
   - **User/Programming Errors:**  Providing an address before the first symbol might result in no nearest symbol being found.

5. **Finding All Functions Matching a Name (`gum_find_functions_named`):**
   - **Functionality:**  Returns an array of addresses for all functions that have the specified name. This is important for handling overloaded functions or functions defined in multiple shared libraries.
   - **Reverse Engineering Relevance:**  Essential when dealing with C++ overloading or when a library might have internal helper functions with common names.
   - **Binary Underpinnings:**  It likely iterates through the symbol cache and collects all entries matching the given name.
   - **Linux/Android Kernel/Framework:**  Needs to consider all loaded modules.
   - **Logic & Assumptions:**
     - **Input:** A function name (string).
     - **Output:** An array of memory addresses.
     - **Assumption:**  Symbol information is available for all matching functions.
   - **User/Programming Errors:** Incorrect function name will result in an empty array.

6. **Finding Functions Matching a Pattern (`gum_find_functions_matching`):**
   - **Functionality:** Uses a wildcard pattern to find functions whose names match the given pattern.
   - **Reverse Engineering Relevance:**  Allows for more flexible searching of functions, for example, finding all functions starting with a specific prefix.
   - **Binary Underpinnings:** Uses pattern matching algorithms (like `g_pattern_match_string`).
   - **Linux/Android Kernel/Framework:** Operates on the symbol names retrieved from loaded modules.
   - **Logic & Assumptions:**
     - **Input:** A pattern string.
     - **Output:** An array of memory addresses of matching functions.
     - **Assumption:** The pattern syntax is understood and correctly applied.
   - **User/Programming Errors:** Incorrect pattern syntax or overly broad patterns might return unexpected results.

7. **Loading Symbols from a Path (`gum_load_symbols`):**
   - **Functionality:** Currently returns `FALSE`, suggesting this functionality might be unimplemented or handled in a different part of Frida. The intention is likely to explicitly load symbols from a given file path.
   - **Reverse Engineering Relevance:** Could be used to load symbols from files that are not automatically loaded by the process, or to refresh symbol information.

**Relationship to Reverse Engineering Methods:**

- **Static Analysis:** While `gumsymbolutil-libdwarf.c` is used during dynamic instrumentation, the underlying mechanism of parsing DWARF and ELF data is rooted in static analysis techniques. Frida leverages this static information at runtime.
- **Dynamic Analysis:** The core purpose of this code is to enhance dynamic analysis by providing context to memory addresses during runtime execution.
- **Symbol Resolution:** This is a fundamental step in reverse engineering. Being able to translate addresses to names is crucial for understanding code.
- **Code Navigation:**  Knowing the function names and addresses allows for easy navigation within the code during debugging or analysis.

**Binary Underlying, Linux/Android Kernel & Framework:**

- **ELF Format:** The code heavily relies on understanding the structure of ELF files, including sections like `.debug_info`, `.symtab`, and `.dynsym`.
- **DWARF Debugging Information:**  The entire module is built around parsing DWARF data, which is a standard format for storing debugging information. This includes information about compilation units, types, variables, and their locations.
- **Process Memory Management:**  The code needs to interact with the operating system to understand the memory layout of the target process, including the base addresses of loaded modules. Functions like `gum_process_resolve_module_pointer` (not fully shown in the snippet) are likely involved in this.
- **Dynamic Linking:** The use of `dlfcn.h` and `dladdr` indicates that the code can also retrieve symbol information from the dynamic linker's symbol tables. This is used as a fallback when DWARF information might be missing.

**Logical Reasoning (Assumptions, Inputs, Outputs):**

Examples are provided within the functionality descriptions above.

**User or Programming Common Usage Errors:**

- **Incorrect Addresses:** Passing invalid memory addresses (e.g., outside the process's address space or within unmapped memory regions) will lead to failures in symbol resolution.
- **Typographical Errors in Symbol Names:** When using functions like `gum_find_function`, typos in the function name will result in the function not being found.
- **Incorrect Pattern Syntax:**  Using incorrect wildcard syntax in `gum_find_functions_matching` can lead to unexpected or no results.
- **Targeting Modules Without Debug Information:** If the target module was not compiled with DWARF debugging information, the detailed symbol information (source file, line number) will not be available, and the functions might fall back to less informative results (like just the function name or a generic address).
- **Assumptions about Symbol Visibility:**  Assuming all symbols are accessible. Static binaries or stripped binaries might have limited symbol information.

**User Operation Steps to Reach This Code (Debugging Clues):**

A user interacting with Frida might reach this code through various actions:

1. **Setting a Breakpoint by Symbol Name:**
   - User calls `frida.bp("module!function_name")`.
   - Frida needs to resolve the address of `function_name` in the specified `module`. This would involve calls to functions like `gum_find_function` or internal functions that use the logic within `gumsymbolutil-libdwarf.c`.

2. **Examining Stack Traces:**
   - When an exception occurs or a breakpoint is hit, Frida often displays a stack trace.
   - To provide meaningful information, Frida needs to resolve the addresses on the stack back to function names and source code locations. This involves calling functions like `gum_symbol_details_from_address`.

3. **Listing Loaded Modules and Symbols:**
   - Frida commands or APIs to list loaded modules and their symbols would internally use the symbol resolution capabilities of this file.

4. **Using `Module.findExportByName()` or Similar APIs:**
   - When a user wants to find the address of an exported function in a module, Frida will utilize functions within `gumsymbolutil-libdwarf.c` or related modules to perform this lookup.

5. **Manually Resolving Addresses:**
   - A user might have a memory address obtained through other means and use Frida APIs to get symbol information for that address, directly triggering functions like `gum_symbol_name_from_address`.

In essence, any Frida operation that requires mapping memory addresses to symbolic information or finding symbols by name will likely involve the functionalities implemented in `gumsymbolutil-libdwarf.c`. This module acts as a crucial bridge between raw memory addresses and human-readable representations of code and data.

### 提示词
```
这是目录为frida/subprojects/frida-gum/gum/backend-libdwarf/gumsymbolutil-libdwarf.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
/*
 * Copyright (C) 2017-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2020 Matt Oh <oh.jeongwook@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumsymbolutil.h"

#include "gum-init.h"
#include "gumelfmodule.h"

#include <dlfcn.h>
#include <dwarf.h>
#ifdef __clang__
# pragma clang diagnostic push
# pragma clang diagnostic ignored "-Wtypedef-redefinition"
#endif
#include <libdwarf.h>
#ifdef __clang__
# pragma clang diagnostic pop
#endif
#include <libelf.h>
#include <strings.h>

#define GUM_MAX_CACHE_AGE (0.5)

typedef struct _GumModuleEntry GumModuleEntry;

typedef struct _GumNearestSymbolDetails GumNearestSymbolDetails;
typedef struct _GumDwarfSymbolDetails GumDwarfSymbolDetails;
typedef struct _GumDwarfSourceDetails GumDwarfSourceDetails;
typedef struct _GumFindCuDieOperation GumFindCuDieOperation;
typedef struct _GumFindSymbolOperation GumFindSymbolOperation;

typedef struct _GumCuDieDetails GumCuDieDetails;
typedef struct _GumDieDetails GumDieDetails;

typedef gboolean (* GumFoundCuDieFunc) (const GumCuDieDetails * details,
    gpointer user_data);
typedef gboolean (* GumFoundDieFunc) (const GumDieDetails * details,
    gpointer user_data);

struct _GumModuleEntry
{
  GumElfModule * module;
  Elf * elf;
  Dwarf_Debug dbg;
  gboolean collected;
};

struct _GumNearestSymbolDetails
{
  const gchar * name;
  gpointer address;
};

struct _GumDwarfSymbolDetails
{
  gchar * name;
  guint line_number;
};

struct _GumDwarfSourceDetails
{
  gchar * path;
  guint line_number;
  guint column;
};

struct _GumFindCuDieOperation
{
  Dwarf_Addr needle;
  gboolean found;
  Dwarf_Off cu_die_offset;
};

struct _GumFindSymbolOperation
{
  GumAddress needle;
  GumDwarfSymbolDetails * symbol;
  GumAddress closest_address;
};

struct _GumCuDieDetails
{
  Dwarf_Die cu_die;

  Dwarf_Debug dbg;
};

struct _GumDieDetails
{
  Dwarf_Die die;
  Dwarf_Half tag;

  Dwarf_Debug dbg;
};

static gboolean gum_find_nearest_symbol_by_address (gpointer address,
    GumNearestSymbolDetails * nearest);
static GumModuleEntry * gum_module_entry_from_address (gpointer address,
    GumNearestSymbolDetails * nearest);
static GumModuleEntry * gum_module_entry_from_path_and_base (const gchar * path,
    GumAddress base_address);

static GHashTable * gum_get_function_addresses (void);
static GHashTable * gum_get_address_symbols (void);
static void gum_maybe_refresh_symbol_caches (void);
static gboolean gum_collect_module_functions (const GumModuleDetails * details,
    gpointer user_data);
static gboolean gum_collect_symbol_if_function (
    const GumElfSymbolDetails * details, gpointer user_data);

static void gum_symbol_util_ensure_initialized (void);
static void gum_symbol_util_deinitialize (void);

static void gum_on_dwarf_error (Dwarf_Error error, Dwarf_Ptr errarg);

static Dwarf_Die gum_find_cu_die_by_virtual_address (Dwarf_Debug dbg,
    Dwarf_Addr address);
static gboolean gum_store_cu_die_offset_if_containing_address (
    const GumCuDieDetails * details, GumFindCuDieOperation * op);
static gboolean gum_find_symbol_by_virtual_address (Dwarf_Debug dbg,
    Dwarf_Die cu_die, Dwarf_Addr address, GumDwarfSymbolDetails * details);
static gboolean gum_collect_die_if_closest_so_far (
    const GumDieDetails * details, GumFindSymbolOperation * op);
static gboolean gum_find_line_by_virtual_address (Dwarf_Debug dbg,
    Dwarf_Die cu_die, Dwarf_Addr address, guint symbol_line_number,
    GumDwarfSourceDetails * details);

static void gum_enumerate_cu_dies (Dwarf_Debug dbg, gboolean is_info,
    GumFoundCuDieFunc func, gpointer user_data);
static void gum_enumerate_dies (Dwarf_Debug dbg, Dwarf_Die die,
    GumFoundDieFunc func, gpointer user_data);
static gboolean gum_enumerate_dies_recurse (Dwarf_Debug dbg, Dwarf_Die die,
    GumFoundDieFunc func, gpointer user_data);

static gboolean gum_read_die_name (Dwarf_Debug dbg, Dwarf_Die die,
    gchar ** name);
static gboolean gum_read_attribute_location (Dwarf_Debug dbg, Dwarf_Die die,
    Dwarf_Half id, Dwarf_Addr * address);
static gboolean gum_read_attribute_address (Dwarf_Debug dbg, Dwarf_Die die,
    Dwarf_Half id, Dwarf_Addr * address);
static gboolean gum_read_attribute_uint (Dwarf_Debug dbg, Dwarf_Die die,
    Dwarf_Half id, Dwarf_Unsigned * value);

static gint gum_compare_pointers (gconstpointer a, gconstpointer b);

G_LOCK_DEFINE_STATIC (gum_symbol_util);
static GHashTable * gum_module_entries = NULL;
static GHashTable * gum_function_addresses = NULL;
static GHashTable * gum_address_symbols = NULL;
static GTimer * gum_cache_timer = NULL;

gboolean
gum_symbol_details_from_address (gpointer address,
                                 GumDebugSymbolDetails * details)
{
  gboolean success;
  GumModuleEntry * entry;
  GumNearestSymbolDetails nearest;
  Dwarf_Addr file_address;
  Dwarf_Die cu_die;
  GumDwarfSymbolDetails symbol;
  GumDwarfSourceDetails source;
  gchar * str, * canonicalized;

  success = FALSE;

  G_LOCK (gum_symbol_util);

  entry = gum_module_entry_from_address (address, &nearest);
  if (entry == NULL)
    goto entry_not_found;
  if (entry->dbg == NULL)
    goto no_debug_info;

  file_address = gum_elf_module_translate_to_offline (entry->module,
      GUM_ADDRESS (address));

  cu_die = gum_find_cu_die_by_virtual_address (entry->dbg, file_address);
  if (cu_die == NULL)
    goto cu_die_not_found;

  if (!gum_find_symbol_by_virtual_address (entry->dbg, cu_die, file_address,
      &symbol))
    goto symbol_not_found;

  if (!gum_find_line_by_virtual_address (entry->dbg, cu_die, file_address,
      symbol.line_number, &source))
    goto line_not_found;

  details->address = GUM_ADDRESS (address);

  str = g_path_get_basename (gum_elf_module_get_source_path (entry->module));
  g_strlcpy (details->module_name, str, sizeof (details->module_name));
  g_free (str);
  g_strlcpy (details->symbol_name, symbol.name, sizeof (details->symbol_name));

  canonicalized = g_canonicalize_filename (source.path, "/");
  g_strlcpy (details->file_name, canonicalized, sizeof (details->file_name));
  details->line_number = source.line_number;
  details->column = source.column;

  success = TRUE;

  g_free (canonicalized);
  g_free (source.path);

line_not_found:
  g_free (symbol.name);

symbol_not_found:
  dwarf_dealloc (entry->dbg, cu_die, DW_DLA_DIE);

cu_die_not_found:
  if (!success)
    goto no_debug_info;

entry_not_found:
  G_UNLOCK (gum_symbol_util);

  return success;

no_debug_info:
  {
    gsize offset;

    details->address = GUM_ADDRESS (address);

    str = g_path_get_basename (gum_elf_module_get_source_path (entry->module));
    g_strlcpy (details->module_name, str, sizeof (details->module_name));
    g_free (str);

    if (nearest.name == NULL)
      gum_find_nearest_symbol_by_address (address, &nearest);

    if (nearest.name != NULL)
    {
      offset = GPOINTER_TO_SIZE (address) - GPOINTER_TO_SIZE (nearest.address);

      if (offset == 0)
      {
        g_strlcpy (details->symbol_name, nearest.name,
            sizeof (details->symbol_name));
      }
      else
      {
        g_snprintf (details->symbol_name, sizeof (details->symbol_name),
            "%s+0x%" G_GSIZE_MODIFIER "x", nearest.name, offset);
      }
    }
    else
    {
      offset = details->address -
          gum_elf_module_get_base_address (entry->module);

      g_snprintf (details->symbol_name, sizeof (details->symbol_name),
          "0x%" G_GSIZE_MODIFIER "x", offset);
    }

    details->file_name[0] = '\0';
    details->line_number = 0;
    details->column = 0;

    G_UNLOCK (gum_symbol_util);

    return TRUE;
  }
}

gchar *
gum_symbol_name_from_address (gpointer address)
{
  GumDwarfSymbolDetails symbol;
  GumModuleEntry * entry;
  GumNearestSymbolDetails nearest;
  Dwarf_Addr file_address;
  Dwarf_Die cu_die;

  symbol.name = NULL;

  G_LOCK (gum_symbol_util);

  entry = gum_module_entry_from_address (address, &nearest);
  if (entry == NULL)
    goto entry_not_found;
  if (entry->dbg == NULL)
    goto no_debug_info;

  file_address = gum_elf_module_translate_to_offline (entry->module,
      GUM_ADDRESS (address));

  cu_die = gum_find_cu_die_by_virtual_address (entry->dbg, file_address);
  if (cu_die == NULL)
    goto cu_die_not_found;

  gum_find_symbol_by_virtual_address (entry->dbg, cu_die, file_address,
      &symbol);

  dwarf_dealloc (entry->dbg, cu_die, DW_DLA_DIE);

cu_die_not_found:
  if (symbol.name == NULL)
    goto no_debug_info;

entry_not_found:
  G_UNLOCK (gum_symbol_util);

  return symbol.name;

no_debug_info:
  {
    gsize offset;

    if (nearest.name == NULL)
      gum_find_nearest_symbol_by_address (address, &nearest);

    if (nearest.name != NULL)
    {
      offset = GPOINTER_TO_SIZE (address) - GPOINTER_TO_SIZE (nearest.address);

      if (offset == 0)
      {
        symbol.name = g_strdup (nearest.name);
      }
      else
      {
        symbol.name = g_strdup_printf ("%s+0x%" G_GSIZE_MODIFIER "x",
            nearest.name, offset);
      }
    }
    else
    {
      offset = GPOINTER_TO_SIZE (address) -
          gum_elf_module_get_base_address (entry->module);

      symbol.name = g_strdup_printf ("0x%" G_GSIZE_MODIFIER "x", offset);
    }

    G_UNLOCK (gum_symbol_util);

    return symbol.name;
  }
}

gpointer
gum_find_function (const gchar * name)
{
  gpointer address;
  GArray * addresses;

  address = NULL;

  G_LOCK (gum_symbol_util);

  addresses = g_hash_table_lookup (gum_get_function_addresses (), name);

  if (addresses != NULL)
  {
    address = g_array_index (addresses, gpointer, 0);
  }

  G_UNLOCK (gum_symbol_util);

  return address;
}

static gboolean
gum_find_nearest_symbol_by_address (gpointer address,
                                    GumNearestSymbolDetails * nearest)
{
  GHashTable * table;
  GumElfSymbolDetails * details;
  GHashTableIter iter;
  gpointer value;

  table = gum_get_address_symbols ();

  details = g_hash_table_lookup (table, address);
  if (details != NULL)
  {
    nearest->name = details->name;
    nearest->address = address;
    return TRUE;
  }

  g_hash_table_iter_init (&iter, table);
  while (g_hash_table_iter_next (&iter, NULL, &value))
  {
    GumElfSymbolDetails * current_symbol = value;

    if (current_symbol->address > GUM_ADDRESS (address))
      continue;

    if (current_symbol->address + current_symbol->size <= GUM_ADDRESS (address))
    {
      continue;
    }

    nearest->address = GSIZE_TO_POINTER (current_symbol->address);
    nearest->name = current_symbol->name;
    return TRUE;
  }

  return FALSE;
}

GArray *
gum_find_functions_named (const gchar * name)
{
  GArray * result, * addresses;

  result = g_array_new (FALSE, FALSE, sizeof (gpointer));

  G_LOCK (gum_symbol_util);

  addresses = g_hash_table_lookup (gum_get_function_addresses (), name);

  if (addresses != NULL)
  {
    g_array_append_vals (result, addresses->data, addresses->len);
  }

  G_UNLOCK (gum_symbol_util);

  return result;
}

GArray *
gum_find_functions_matching (const gchar * str)
{
  GArray * matches;
  GHashTable * seen;
  GPatternSpec * pspec;
  GHashTableIter iter;
  gpointer key, value;

  matches = g_array_new (FALSE, FALSE, sizeof (gpointer));
  seen = g_hash_table_new (NULL, NULL);
  pspec = g_pattern_spec_new (str);

  G_LOCK (gum_symbol_util);

  g_hash_table_iter_init (&iter, gum_get_function_addresses ());
  while (g_hash_table_iter_next (&iter, &key, &value))
  {
    const gchar * name = key;
    GArray * addresses = value;

    if (g_pattern_match_string (pspec, name))
    {
      guint i;

      for (i = 0; i != addresses->len; i++)
      {
        gpointer address;

        address = g_array_index (addresses, gpointer, i);

        if (!g_hash_table_contains (seen, address))
        {
          g_array_append_val (matches, address);

          g_hash_table_add (seen, address);
        }
      }
    }
  }

  G_UNLOCK (gum_symbol_util);

  g_array_sort (matches, gum_compare_pointers);

  g_pattern_spec_free (pspec);
  g_hash_table_unref (seen);

  return matches;
}

gboolean
gum_load_symbols (const gchar * path)
{
  return FALSE;
}

static GumModuleEntry *
gum_module_entry_from_address (gpointer address,
                               GumNearestSymbolDetails * nearest)
{
  GumModuleEntry * entry;
  gchar * path;
  GumMemoryRange range;

  nearest->name = NULL;
  nearest->address = NULL;

  if (!gum_process_resolve_module_pointer (address, &path, &range))
    return NULL;

  entry = gum_module_entry_from_path_and_base (path, range.base_address);

  g_free (path);

  if (entry == NULL)
    return NULL;

  if (entry->dbg == NULL)
  {
    Dl_info dl_info;

    if (dladdr (address, &dl_info) != 0)
    {
      nearest->name = dl_info.dli_sname;
      nearest->address = dl_info.dli_saddr;
    }
  }

  return entry;
}

static GumModuleEntry *
gum_module_entry_from_path_and_base (const gchar * path,
                                     GumAddress base_address)
{
  GumModuleEntry * entry;
  GumElfModule * module;
  Elf * elf;
  Dwarf_Debug dbg;

  gum_symbol_util_ensure_initialized ();

  entry = g_hash_table_lookup (gum_module_entries, path);
  if (entry != NULL)
    goto have_entry;

  module = gum_elf_module_new_from_memory (path, base_address, NULL);
  if (module != NULL)
  {
    gconstpointer file_data;
    gsize file_size;

    file_data = gum_elf_module_get_file_data (module, &file_size);

    elf_version (EV_CURRENT);

    elf = elf_memory ((char *) file_data, file_size);
  }
  else
  {
    elf = NULL;
  }

  dbg = NULL;
  if (elf != NULL)
  {
    Dwarf_Error error = NULL;

    if (dwarf_elf_init_b (elf, DW_DLC_READ, DW_GROUPNUMBER_ANY,
          gum_on_dwarf_error, NULL, &dbg, &error) != DW_DLV_OK)
    {
      dwarf_dealloc (dbg, error, DW_DLA_ERROR);
      error = NULL;
    }
  }

  entry = g_slice_new (GumModuleEntry);
  entry->module = module;
  entry->elf = elf;
  entry->dbg = dbg;
  entry->collected = FALSE;

  g_hash_table_insert (gum_module_entries, g_strdup (path), entry);

have_entry:
  return (entry->module != NULL) ? entry : NULL;
}

static void
gum_module_entry_free (GumModuleEntry * entry)
{
  if (entry->dbg != NULL)
    dwarf_finish (entry->dbg, NULL);

  if (entry->elf != NULL)
    elf_end (entry->elf);

  if (entry->module != NULL)
    gum_object_unref (entry->module);

  g_slice_free (GumModuleEntry, entry);
}

static GHashTable *
gum_get_function_addresses (void)
{
  gum_maybe_refresh_symbol_caches ();
  return gum_function_addresses;
}

static GHashTable *
gum_get_address_symbols (void)
{
  gum_maybe_refresh_symbol_caches ();
  return gum_address_symbols;
}

static void
gum_maybe_refresh_symbol_caches (void)
{
  gboolean need_update;

  gum_symbol_util_ensure_initialized ();

  if (gum_cache_timer == NULL)
  {
    gum_cache_timer = g_timer_new ();

    need_update = TRUE;
  }
  else
  {
    need_update = g_timer_elapsed (gum_cache_timer, NULL) >= GUM_MAX_CACHE_AGE;
  }

  if (need_update)
  {
    gum_process_enumerate_modules (gum_collect_module_functions, NULL);
  }
}

static gboolean
gum_collect_module_functions (const GumModuleDetails * details,
                              gpointer user_data)
{
  GumModuleEntry * entry;

  entry = gum_module_entry_from_path_and_base (details->path,
      details->range->base_address);
  if (entry == NULL || entry->collected)
    return TRUE;

  gum_elf_module_enumerate_dynamic_symbols (entry->module,
      gum_collect_symbol_if_function, NULL);

  gum_elf_module_enumerate_symbols (entry->module,
      gum_collect_symbol_if_function, NULL);

  entry->collected = TRUE;

  return TRUE;
}

static gboolean
gum_collect_symbol_if_function (const GumElfSymbolDetails * details,
                                gpointer user_data)
{
  const gchar * name;
  gpointer address;
  GArray * addresses;
  gboolean already_collected;
  GumElfSymbolDetails * address_symbol;

  if (details->section == NULL || details->type != GUM_ELF_SYMBOL_FUNC)
    return TRUE;

  name = details->name;
  address = GSIZE_TO_POINTER (details->address);

  already_collected = FALSE;

  addresses = g_hash_table_lookup (gum_function_addresses, name);
  if (addresses == NULL)
  {
    addresses = g_array_sized_new (FALSE, FALSE, sizeof (gpointer), 1);
    g_hash_table_insert (gum_function_addresses, g_strdup (name), addresses);
  }
  else
  {
    guint i;

    for (i = 0; i != addresses->len; i++)
    {
      if (g_array_index (addresses, gpointer, i) == address)
      {
        already_collected = TRUE;
        break;
      }
    }
  }

  if (!already_collected)
    g_array_append_val (addresses, address);

  address_symbol = g_hash_table_lookup (gum_address_symbols, address);
  if (address_symbol == NULL)
  {
    address_symbol = g_slice_new (GumElfSymbolDetails);
    address_symbol->name = g_strdup (name);
    address_symbol->address = details->address;
    address_symbol->size = details->size;
    address_symbol->type = details->type;
    address_symbol->bind = details->bind;
    address_symbol->section = NULL;
    g_hash_table_insert (gum_address_symbols, address, address_symbol);
  }

  return TRUE;
}

static void
gum_function_addresses_free (GArray * addresses)
{
  g_array_free (addresses, TRUE);
}

static void
gum_address_symbols_value_free (GumElfSymbolDetails * details)
{
  g_free ((gpointer) details->name);
  g_slice_free (GumElfSymbolDetails, details);
}

static void
gum_symbol_util_ensure_initialized (void)
{
  if (gum_module_entries != NULL)
    return;

  gum_module_entries = g_hash_table_new_full (g_str_hash, g_str_equal, g_free,
      (GDestroyNotify) gum_module_entry_free);
  gum_function_addresses = g_hash_table_new_full (g_str_hash, g_str_equal,
      g_free, (GDestroyNotify) gum_function_addresses_free);
  gum_address_symbols = g_hash_table_new_full (g_direct_hash, g_direct_equal,
      NULL, (GDestroyNotify) gum_address_symbols_value_free);

  _gum_register_destructor (gum_symbol_util_deinitialize);
}

static void
gum_symbol_util_deinitialize (void)
{
  g_clear_pointer (&gum_cache_timer, g_timer_destroy);

  g_hash_table_unref (gum_address_symbols);
  gum_address_symbols = NULL;

  g_hash_table_unref (gum_function_addresses);
  gum_function_addresses = NULL;

  g_hash_table_unref (gum_module_entries);
  gum_module_entries = NULL;
}

static void
gum_on_dwarf_error (Dwarf_Error error,
                    Dwarf_Ptr errarg)
{
}

static Dwarf_Die
gum_find_cu_die_by_virtual_address (Dwarf_Debug dbg,
                                    Dwarf_Addr address)
{
  Dwarf_Die result;
  GumFindCuDieOperation op;

  op.needle = address;
  op.found = FALSE;
  op.cu_die_offset = 0;

  gum_enumerate_cu_dies (dbg, TRUE,
      (GumFoundCuDieFunc) gum_store_cu_die_offset_if_containing_address, &op);

  if (!op.found)
    return NULL;

  result = NULL;
  dwarf_offdie (dbg, op.cu_die_offset, &result, NULL);

  return result;
}

static gboolean
gum_store_cu_die_offset_if_containing_address (const GumCuDieDetails * details,
                                               GumFindCuDieOperation * op)
{
  Dwarf_Debug dbg = details->dbg;
  Dwarf_Die die = details->cu_die;
  Dwarf_Addr low_pc, high_pc;
  Dwarf_Attribute high_pc_attr;
  Dwarf_Attribute attribute = NULL;
  Dwarf_Half form;
  int res;
  Dwarf_Off ranges_offset;
  Dwarf_Half version, offset_size;
  Dwarf_Rnglists_Head rngl = NULL;

  if (gum_read_attribute_address (dbg, die, DW_AT_low_pc, &low_pc) &&
      dwarf_attr (die, DW_AT_high_pc, &high_pc_attr, NULL) == DW_DLV_OK)
  {
    Dwarf_Half form;

    dwarf_whatform (high_pc_attr, &form, NULL);
    if (form == DW_FORM_addr)
    {
      dwarf_formaddr (high_pc_attr, &high_pc, NULL);
    }
    else
    {
      Dwarf_Unsigned offset;

      dwarf_formudata (high_pc_attr, &offset, NULL);

      high_pc = low_pc + offset;
    }

    if (op->needle >= low_pc && op->needle < high_pc)
    {
      op->found = TRUE;
      dwarf_dieoffset (die, &op->cu_die_offset, NULL);
    }

    return !op->found;
  }

  if (dwarf_attr (die, DW_AT_ranges, &attribute, NULL) != DW_DLV_OK)
    goto skip;

  if (dwarf_whatform (attribute, &form, NULL) != DW_DLV_OK)
    goto skip;

  if (form == DW_FORM_rnglistx)
    res = dwarf_formudata (attribute, &ranges_offset, NULL);
  else
    res = dwarf_global_formref (attribute, &ranges_offset, NULL);
  if (res != DW_DLV_OK)
    goto skip;

  dwarf_get_version_of_die (die, &version, &offset_size);

  if (version >= 5)
  {
    Dwarf_Unsigned n, global_offset, i;

    if (dwarf_rnglists_get_rle_head (attribute, form, ranges_offset, &rngl, &n,
          &global_offset, NULL) != DW_DLV_OK)
      goto skip;

    for (i = 0; i != n; i++)
    {
      guint len, code;
      Dwarf_Unsigned raw_low_pc, raw_high_pc, low_pc, high_pc;
      Dwarf_Bool debug_addr_unavailable;

      if (dwarf_get_rnglists_entry_fields_a (rngl, i, &len, &code,
            &raw_low_pc, &raw_high_pc, &debug_addr_unavailable, &low_pc,
            &high_pc, NULL) != DW_DLV_OK)
        goto skip;

      if (code == DW_RLE_end_of_list)
        break;
      if (code == DW_RLE_base_address || code == DW_RLE_base_addressx)
        continue;
      if (code == debug_addr_unavailable)
        continue;

      if (op->needle >= low_pc && op->needle < high_pc)
      {
        op->found = TRUE;
        dwarf_dieoffset (die, &op->cu_die_offset, NULL);

        break;
      }
    }
  }
  else
  {
    Dwarf_Ranges * ranges;
    Dwarf_Signed n, i;

    if (dwarf_get_ranges_a (dbg, ranges_offset, die, &ranges, &n, NULL,
        NULL) != DW_DLV_OK)
      goto skip;

    for (i = 0; i != n; i++)
    {
      Dwarf_Ranges * range = &ranges[i];

      if (range->dwr_type != DW_RANGES_ENTRY)
        break;

      if (op->needle >= range->dwr_addr1 && op->needle < range->dwr_addr2)
      {
        op->found = TRUE;
        dwarf_dieoffset (die, &op->cu_die_offset, NULL);

        break;
      }
    }

    dwarf_ranges_dealloc (dbg, ranges, n);
  }

skip:
  g_clear_pointer (&rngl, dwarf_dealloc_rnglists_head);
  dwarf_dealloc (dbg, attribute, DW_DLA_ATTR);

  return !op->found;
}

static gboolean
gum_find_symbol_by_virtual_address (Dwarf_Debug dbg,
                                    Dwarf_Die cu_die,
                                    Dwarf_Addr address,
                                    GumDwarfSymbolDetails * details)
{
  GumFindSymbolOperation op;

  details->name = NULL;
  details->line_number = 0;

  op.needle = address;
  op.symbol = details;
  op.closest_address = 0;

  gum_enumerate_dies (dbg, cu_die,
      (GumFoundDieFunc) gum_collect_die_if_closest_so_far, &op);

  return details->name != NULL;
}

static gboolean
gum_collect_die_if_closest_so_far (const GumDieDetails * details,
                                   GumFindSymbolOperation * op)
{
  Dwarf_Debug dbg = details->dbg;
  Dwarf_Die die = details->die;
  GumDwarfSymbolDetails * symbol = op->symbol;
  Dwarf_Half tag;
  Dwarf_Addr address;

  if (dwarf_tag (die, &tag, NULL) != DW_DLV_OK)
    return TRUE;

  if (tag == DW_TAG_subprogram)
  {
    if (!gum_read_attribute_address (dbg, die, DW_AT_low_pc, &address))
      return TRUE;
  }
  else if (tag == DW_TAG_variable)
  {
    if (!gum_read_attribute_location (dbg, die, DW_AT_location, &address))
      return TRUE;
  }
  else
  {
    return TRUE;
  }

  if (op->needle < address)
    return TRUE;

  if (op->closest_address == 0 ||
      (op->needle - address) < (op->needle - op->closest_address))
  {
    Dwarf_Unsigned line_number;

    op->closest_address = address;

    g_clear_pointer (&symbol->name, g_free);
    gum_read_die_name (dbg, die, &symbol->name);

    if (gum_read_attribute_uint (dbg, die, DW_AT_decl_line, &line_number))
    {
      symbol->line_number = line_number;
    }
  }

  return TRUE;
}

static gboolean
gum_find_line_by_virtual_address (Dwarf_Debug dbg,
                                  Dwarf_Die cu_die,
                                  Dwarf_Addr address,
                                  guint symbol_line_number,
                                  GumDwarfSourceDetails * details)
{
  gboolean success;
  Dwarf_Line * lines;
  Dwarf_Signed line_count, line_index;

  if (dwarf_srclines (cu_die, &lines, &line_count, NULL) != DW_DLV_OK)
    return FALSE;

  success = FALSE;

  for (line_index = 0; line_index != line_count; line_index++)
  {
    Dwarf_Line line = lines[line_index];
    Dwarf_Addr line_address;

    if (dwarf_lineaddr (line, &line_address, NULL) != DW_DLV_OK)
      continue;

    if (line_address >= address)
    {
      Dwarf_Unsigned line_number, column;
      char * path;

      if (dwarf_lineno (line, &line_number, NULL) != DW_DLV_OK)
        continue;

      if (line_number < symbol_line_number)
        continue;

      if (dwarf_lineoff_b (line, &column, NULL) != DW_DLV_OK)
        continue;

      if (dwarf_linesrc (line, &path, NULL) != DW_DLV_OK)
        continue;

      details->path = g_strdup (path);
      details->line_number = line_number;
      details->column = column;

      success = TRUE;

      dwarf_dealloc (dbg, path, DW_DLA_STRING);

      break;
    }
  }

  dwarf_srclines_dealloc (dbg, lines, line_count);

  return success;
}

static void
gum_enumerate_cu_dies (Dwarf_Debug dbg,
                       gboolean is_info,
                       GumFoundCuDieFunc func,
                       gpointer user_data)
{
  GumCuDieDetails details;
  gboolean carry_on;

  details.dbg = dbg;

  carry_on = TRUE;

  while (TRUE)
  {
    Dwarf_Unsigned next_cu_header_offset;
    const Dwarf_Die no_die = NULL;

    if (dwarf_next_cu_header_d (dbg, is_info, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, &next_cu_header_offset, NULL, NULL) != DW_DLV_OK)
      break;

    if (!carry_on)
      continue;

    if (dwarf_siblingof_b (dbg, no_die, is_info, &details.cu_die, NULL)
        != DW_DLV_OK)
      continue;

    carry_on = func (&details, user_data);

    dwarf_dealloc (dbg, details.cu_die, DW_DLA_DIE);
  }
}

static void
gum_enumerate_dies (Dwarf_Debug dbg,
                    Dwarf_Die die,
                    GumFoundDieFunc func,
                    gpointer user_data)
{
  gum_enumerate_dies_recurse (dbg, die, func, user_data);
}

static gboolean
gum_enumerate_dies_recurse (Dwarf_Debug dbg,
                            Dwarf_Die die,
                            GumFoundDieFunc func,
                            gpointer user_data)
{
  gboolean carry_on;
  GumDieDetails details;
  Dwarf_Die child, cur, sibling;

  details.die = die;
  if (dwarf_tag (die, &details.tag, NULL) != DW_DLV_OK)
    return TRUE;

  details.dbg = dbg;

  carry_on = func (&details, user_data);
  if (!carry_on)
    return FALSE;

  if (dwarf_child (die, &child, NULL) != DW_DLV_OK)
    return TRUE;

  carry_on = gum_enumerate_dies_recurse (dbg, child, func, user_data);
  if (!carry_on)
  {
    dwarf_dealloc (dbg, child, DW_DLA_DIE);
    return FALSE;
  }

  cur = child;

  while (TRUE)
  {
    int status;

    status = dwarf_siblingof (dbg, cur, &sibling, NULL);
    dwarf_dealloc (dbg, cur, DW_DLA_DIE);
    if (status != DW_DLV_OK)
      break;
    cur = sibling;

    carry_on = gum_enumerate_dies_recurse (dbg, cur, func, user_data);
    if (!carry_on)
    {
      dwarf_dealloc (dbg, cur, DW_DLA_DIE);
      break;
    }
  }

  return carry_on;
}

static gboolean
gum_read_die_name (Dwarf_Debug dbg,
                   Dwarf_Die die,
                   gchar ** name)
{
  char * str;

  if (dwarf_diename (die, &str, NULL) != DW_DLV_OK)
    return FALSE;

  *name = g_strdup (str);

  dwarf_dealloc (dbg, str, DW_DLA_STRING);

  return TRUE;
}

static gboolean
gum_read_attribute_location (Dwarf_Debug dbg,
                             Dwarf_Die die,
                             Dwarf_Half id,
                             Dwarf_Addr * address)
{
  gboolean success;
  Dwarf_Attribute attribute;
  Dwarf_Loc_Head_c locations;
  Dwarf_Unsigned count;
  Dwarf_Small lle_value;
  Dwarf_Addr low_pc, high_pc;
  Dwarf_Unsigned loclist_count;
  Dwarf_Locdesc_c loclist;
  Dwarf_Small loclist_source;
  Dwarf_Unsigned expression_offset;
  Dwarf_Unsigned locdesc_offset;
  Dwarf_Small atom;
  Dwarf_Unsigned op1, op2, op3;
  Dwarf_Unsigned offset_for_branch;

  success = FALSE;

  if (dwarf_attr (die, id, &attribute, NULL) != DW_DLV_OK)
    goto invalid_attribute;

  if (dwarf_get_loclist_c (attribute, &locations, &count, NULL) != DW_DLV_OK)
    goto invalid_type;

  if (count != 1)
    goto invalid_locations;

  if (dwarf_get_locdesc_entry_c (locations,
      0,
      &lle_value,
      &low_pc,
      &high_pc,
      &loclist_count,
      &loclist,
      &loclist_source,
      &expression_offset,
      &locdesc_offset,
      NULL) != DW_DLV_OK)
  {
    goto invalid_locations;
  }

  if (lle_value != DW_LLE_offset_pair)
    goto invalid_locations;
  if (loclist_count != 1)
    goto invalid_locations;

  if (dwarf_get_location_op_value_c (loclist,
      0,
      &atom,
      &op1,
      &op2,
      &op3,
      &offset_for_branch,
      NULL) != DW_DLV_OK)
  {
    goto invalid_locations;
  }

  if (atom != DW_OP_addr)
    goto invalid_locations;

  *address = op1;

  success = TRUE;

invalid_locations:
  dwarf_loc_head_c_dealloc (locations);

invalid_type:
  dwarf_dealloc (dbg, attribute, DW_DLA_ATTR);

invalid_attribute:
  return success;
}

static gboolean
gum_read_attribute_address (Dwarf_Debug dbg,
                            Dwarf_Die die,
                            Dwarf_Half id,
                            Dwarf_Addr * address)
{
  gboolean success;
  Dwarf_Attribute attribute;

  if (dwarf_attr (die, id, &attribute, NULL) != DW_DLV_OK)
    return FALSE;

  success = dwarf_formaddr (attribute, address, NULL) == DW_DLV_OK;

  dwarf_dealloc (dbg, attribute, DW_DLA_ATTR);

  return success;
}

static gboolean
gum_read_attribute_uint (Dwarf_Debug dbg,
                         Dwarf_Die die,
                         Dwarf_Half id,
                         Dwarf_Unsigned * value)
{
  gboolean success;
  Dwarf_Attribute attribute;

  if (dwarf_attr (die, id, &attribute, NULL) != DW_DLV_OK)
    return FALSE;

  success = dwarf_formudata (attribute, value, NULL) == DW_DLV_OK;

  dwarf_dealloc (dbg, attribute, DW_DLA_ATTR);

  return success;
}

static gint
gum_compare_pointers (gconstpointer a,
                      gconstpointer b)
{
  return *((gconstpointer *) a) - *((gconstpointer *) b);
}
```