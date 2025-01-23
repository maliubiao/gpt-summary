Response:
Let's break down the thought process for analyzing this C code.

1. **Understand the Goal:** The primary goal is to understand the functionality of `gumcodesegment-darwin.c` within the Frida framework. This involves identifying its core purpose, how it interacts with the operating system, and its relevance to dynamic instrumentation and reverse engineering.

2. **Initial Scan for Keywords and Structure:**  Quickly skim the code for important keywords and data structures. Look for:
    * Includes (`#include`): What OS/system libraries are being used? (e.g., `mach-o`, `CommonCrypto`, `sys/mman.h`, `unistd.h`) This immediately suggests a focus on macOS/iOS and low-level operations.
    * Data Structures (`struct`):  The `GumCodeSegment`, `GumCodeLayout`, `GumCsSuperBlob`, etc. structures define the data being manipulated. Understanding these is crucial.
    * Function Names: Names like `gum_code_segment_new`, `gum_code_segment_realize`, `gum_code_segment_map`, `gum_code_segment_mark` provide hints about the actions performed.
    * Constants and Defines (`#define`):  Look for magic numbers (`GUM_CS_MAGIC_EMBEDDED_SIGNATURE`), hash types, and offsets. These are often related to file formats or OS structures.
    * Conditional Compilation (`#if defined(...)`):  Identify platform-specific logic, particularly for iOS/tvOS.

3. **Identify Core Functionality - The "Code Segment":** The central concept is `GumCodeSegment`. The functions around it suggest it's responsible for managing a block of executable code. The `new`, `free`, `get_address`, `get_size`, `get_virtual_size` functions are standard object lifecycle and property accessors.

4. **Focus on Key Operations:**  The more interesting functions are `realize`, `map`, and `mark`.
    * **`realize`:** The comments and platform checks (`HAVE_IOS`, `HAVE_TVOS`) point to a process of making the code segment executable. The use of temporary files, Mach-O headers, and code signatures hints at bypassing code signing restrictions.
    * **`map`:** This clearly relates to mapping the code segment into memory, potentially at a specific address. The different implementations based on `self->fd` and the use of `mmap` and `mach_vm_remap` are important distinctions.
    * **`mark`:**  This function deals with marking the memory region as executable. The fallback to `mprotect` suggests a standard approach, while the conditional logic for iOS/tvOS and the use of `substrated` indicate a more advanced or privileged approach.

5. **Trace the Logic of `realize`:** This function seems complex, so trace its steps:
    * Create a temporary file.
    * Compute the layout of the Mach-O file (headers, text segment, code signature).
    * Create Mach-O headers.
    * Create a code signature.
    * Write these components to the temporary file.
    * Use `fcntl(F_ADDFILESIGS)` - this is a key step in adding a code signature to a file.
    * Unlink the temporary file.

6. **Connect to Reverse Engineering Concepts:**
    * **Code Signing Bypass:** The `realize` function clearly aims to create a validly signed (at least in a way the OS accepts) code segment dynamically. This is a core technique in reverse engineering and dynamic instrumentation to inject and execute arbitrary code.
    * **Memory Manipulation:**  The `map` and `mark` functions directly manipulate memory mappings and protections, essential for code injection and hooking.
    * **Dynamic Library Injection:**  The creation of a temporary "dylib" (dynamic library) hints at a technique for loading code into a running process.

7. **Identify Binary/OS Interactions:**
    * **Mach-O Format:** The code directly manipulates Mach-O header structures, demonstrating a deep understanding of the executable file format on macOS/iOS.
    * **Code Signing:** The constants and structures related to code signatures directly interact with the OS's code signing mechanism.
    * **Virtual Memory Management:** Functions like `mmap` and `mach_vm_remap` are fundamental to how the operating system manages memory.
    * **System Calls:** `open`, `close`, `write`, `unlink`, `fcntl` are low-level system calls used for file manipulation.
    * **`substrated`:** The interaction with `substrated` (likely a privileged helper process) highlights a technique to overcome OS restrictions.

8. **Infer Logical Reasoning and Assumptions:**
    * **Layout Calculation:** The `gum_code_segment_compute_layout` function makes assumptions about the structure and sizes of the Mach-O file and code signature. *Hypothesis: If the actual requirements of the OS for code signing change, this function might need to be updated.*
    * **Temporary File Creation:** The code assumes it can create and write to temporary files. *Hypothesis: If the sandbox environment restricts file creation, this process will fail.*

9. **Consider User Errors:**
    * **Incorrect Size:** Passing an incorrect size to `gum_code_segment_new` could lead to buffer overflows or other memory corruption issues.
    * **Conflicting Memory Regions:**  Trying to map a code segment to an already occupied memory region will likely fail.
    * **Sandbox Restrictions:**  If Frida is running in a restricted sandbox, the file operations in `gum_code_segment_try_realize` might be blocked.

10. **Trace User Interaction (Debugging Clues):** Think about how a user would end up calling these functions:
    * **Frida Script:** A user writes a Frida script to inject code.
    * **`Memory.allocCode()`:**  The script likely uses `Memory.allocCode()` to allocate memory for the injected code. This might internally call `gum_code_segment_new`.
    * **`Process.getCurrentModule().base` (or similar):**  The script might target a specific memory address.
    * **`Memory.protect()` or `Memory.patchCode()`:**  These operations might trigger the `gum_code_segment_mark` function to ensure the injected code is executable.
    * **Error Messages:** If something goes wrong, the error messages generated by functions like `substrated_mark` or `mprotect` would be important debugging clues.

11. **Structure the Analysis:** Organize the findings into clear categories as requested (functionality, reverse engineering, binary/OS, logic, errors, debugging). Use examples to illustrate the points.

12. **Refine and Review:**  Read through the analysis to ensure accuracy and clarity. Check for any inconsistencies or missing information. For example, ensure the explanation of code signing is clear and concise.

By following this structured approach, we can effectively analyze the C code and extract the key information about its functionality and its role within the Frida framework.
This C source file, `gumcodesegment-darwin.c`, is a core component of Frida's Gum library, specifically designed for handling executable code segments on Darwin-based operating systems (macOS, iOS, tvOS). Its primary responsibility is to manage memory regions intended for code execution, taking into account the security mechanisms present on these platforms, particularly code signing.

Here's a breakdown of its functionalities:

**1. Managing Code Segment Memory:**

* **Allocation (`gum_code_segment_new`, `gum_code_segment_new_full`):**  It provides functions to allocate memory regions that will hold executable code. This allocation can be either at an arbitrary address or near a specified address (using `GumAddressSpec`). It also keeps track of the allocated size and virtual size (which is page-aligned).
* **Deallocation (`gum_code_segment_free`):**  Releases the allocated memory for the code segment.
* **Getting Address and Size (`gum_code_segment_get_address`, `gum_code_segment_get_size`, `gum_code_segment_get_virtual_size`):** Provides accessors to retrieve the starting address, actual size, and page-aligned virtual size of the code segment.

**2. "Realizing" Code Segments (Code Signing Bypass):**

* **`gum_code_segment_realize` and related functions (`gum_code_segment_is_realize_supported`, `gum_code_segment_try_realize`, `gum_code_segment_compute_layout`, `gum_put_mach_headers`, `gum_put_code_signature`, `gum_file_open_tmp`, `gum_file_write_all`):** This is a crucial part of the file. On iOS and tvOS, simply allocating memory and marking it executable isn't enough due to code signing requirements. This set of functions aims to create a temporary, validly-signed (as much as possible without proper entitlements) Mach-O dynamic library in memory.
    * It creates a temporary file.
    * It constructs a minimal Mach-O header for a dynamic library.
    * It calculates the layout of the Mach-O file, including the code signature.
    * It generates a basic code signature for the allocated code segment.
    * It writes the Mach-O header, the code itself, and the generated code signature to the temporary file.
    * It uses the `fcntl(F_ADDFILESIGS)` system call to associate the generated signature with the temporary file. This is a key step in making the OS treat the memory region as if it were backed by a signed file.
    * The temporary file is then unlinked.

**3. Mapping and Remapping Code Segments:**

* **`gum_code_segment_map` and related functions (`gum_code_segment_try_map`, `gum_code_segment_try_remap_locally`, `gum_code_segment_try_remap_using_substrated`):**  These functions handle the process of mapping the code segment into the target process's memory space with execute permissions.
    * **`gum_code_segment_try_map`:** If the code segment has been "realized" (a temporary signed file was created), it uses `mmap` with `MAP_FIXED` to map the contents of the temporary file into the desired memory location with execute permissions. The offset into the file is adjusted to skip the Mach-O header.
    * **`gum_code_segment_try_remap_locally`:** If "realization" isn't used (or fails), this function attempts to remap the existing memory region using `mach_vm_remap`. This essentially moves the existing allocation to the desired target address and sets the permissions to read and execute.
    * **`gum_code_segment_try_remap_using_substrated`:** This attempts to use a privileged helper process (`substrated`) to perform the remapping. This is likely a fallback or an alternative method for bypassing certain security restrictions.

**4. Marking Code as Executable:**

* **`gum_code_segment_mark`:** This function ensures that the memory region containing the code has execute permissions.
    * On iOS/tvOS, if code segment realization is supported, it uses the `realize` and `map` functions to "sign" and map the code.
    * If realization isn't supported (or as a fallback), it attempts to use `substrated` to mark the memory executable.
    * As a final fallback, it uses the standard `mprotect` system call to change the memory protection to read and execute. This might not work on locked-down systems without proper entitlements.

**5. Interaction with `substrated`:**

* Several functions interact with a process named `substrated`. This is a common component in jailbroken iOS environments and potentially in some Frida setups. It provides privileged operations that the Frida agent running within a sandboxed application might not have. The functions `gum_try_get_substrated_port` and `gum_deallocate_substrated_port` handle establishing and closing a connection to this privileged process via Mach ports.

**Relationship to Reverse Engineering:**

This file is deeply intertwined with reverse engineering techniques, particularly dynamic instrumentation:

* **Code Injection:** The core purpose is to enable the injection and execution of arbitrary code into a running process. Frida relies on this to implement its instrumentation capabilities.
* **Code Signing Bypass:** The "realization" process is a direct attempt to circumvent iOS/tvOS's code signing restrictions, allowing the execution of dynamically generated code. This is a common challenge in iOS reverse engineering.
* **Memory Manipulation:** The functions that map and remap memory with execute permissions are fundamental for controlling where and how injected code runs.
* **Hooking:** While not directly implementing hooking, the ability to allocate and execute code at specific locations is a prerequisite for implementing function hooks.

**Examples of Reverse Engineering Use Cases:**

* **Injecting custom logic into an app's functions:** Frida users can allocate a code segment using `gum_code_segment_new`, write their custom assembly or machine code into it, and then use the mapping functions to execute it within the target process, effectively hooking or modifying existing functionality.
* **Bypassing security checks:** If an app performs integrity checks or uses code signing verification, the techniques in this file can be used to inject code that disables or alters these checks.
* **Dynamic analysis:** By injecting code and observing its execution, reverse engineers can understand the internal workings of an application without relying solely on static analysis.

**Binary Bottom, Linux, Android Kernel & Framework Knowledge:**

* **Binary Bottom (Mach-O):** The code has extensive knowledge of the Mach-O executable format used on macOS and iOS. It directly manipulates Mach-O header structures (`mach_header`, `segment_command`, `section`, etc.) to construct a valid dynamic library image.
* **Darwin Kernel (macOS, iOS, tvOS):** The code heavily relies on Darwin kernel APIs and concepts:
    * **Virtual Memory Management:** Functions like `mmap`, `mach_vm_remap`, `mach_vm_protect` are direct interactions with the kernel's memory management subsystem.
    * **Code Signing:** The `fcntl(F_ADDFILESIGS)` system call and the structures related to code signatures directly interact with the kernel's code signing enforcement mechanisms.
    * **Mach Ports:** The communication with `substrated` uses Mach ports, a fundamental inter-process communication mechanism in the Darwin kernel.
* **Linux/Android Kernel & Framework:** While this specific file targets Darwin, the *concept* of managing executable code segments and dealing with code signing (or similar security measures) exists on Linux and Android as well. However, the implementation details would be significantly different. Linux uses ELF executables, and Android uses the ART/Dalvik virtual machines and has its own code signing mechanisms. The core idea of allocating memory, marking it executable, and potentially needing to bypass security restrictions remains relevant across these platforms, but the APIs and techniques used would be different.

**Logical Reasoning, Assumptions, Inputs, and Outputs:**

* **Assumption:** The code assumes that the target process allows for memory mapping and manipulation, even if it requires bypassing security measures.
* **Assumption:** The "realization" process assumes that creating a minimally valid signed Mach-O file in memory will be sufficient to satisfy the OS's basic code signing checks for execution within the process's context. This might not work in all scenarios, especially with stricter security policies.
* **Input (for `gum_code_segment_compute_layout`):**
    * `self`: A `GumCodeSegment` structure containing the data and size of the code to be signed.
* **Output (for `gum_code_segment_compute_layout`):**
    * `layout`: A `GumCodeLayout` structure populated with calculated offsets and sizes for the Mach-O header, text segment (code), and code signature within the temporary file.
* **Logical Reasoning Example (in `gum_code_segment_compute_layout`):** The code calculates the number of hash entries needed for the code signature based on the page size of the code segment. It divides the total size of the header and code by the code signature page size to determine how many pages need to be hashed.

**User or Programming Common Usage Errors:**

* **Incorrect Size Calculation:**  Providing an incorrect `size` when creating a `GumCodeSegment` might lead to buffer overflows or other memory corruption issues when writing code into it.
* **Mapping to an Occupied Address:** Attempting to map a code segment to a memory address that is already in use will likely fail. The `MAP_FIXED` flag in `mmap` will overwrite existing mappings, potentially causing crashes if not done carefully.
* **Permissions Issues:**  If the user attempts to map or mark memory as executable without the necessary permissions (even after the "realization" process), the operation might fail. This can happen if the target process has strong security restrictions.
* **Sandbox Restrictions:** Frida itself runs within a sandboxed environment. If the sandbox is too restrictive, operations like creating temporary files (`gum_file_open_tmp`) or using `fcntl(F_ADDFILESIGS)` might be blocked.
* **Using on Unsupported Platforms:**  The initial check in `gum_code_segment_is_supported` highlights a common error: trying to use this Darwin-specific functionality on other platforms like Linux or Android.

**User Operation Stepping Stones to Reach Here (Debugging Clues):**

1. **User wants to inject code:** A Frida user wants to dynamically inject and execute custom code within a running application on macOS, iOS, or tvOS.
2. **Frida script uses `Memory.allocCode()`:**  The user's Frida script likely utilizes `Memory.allocCode(size)` to allocate a block of memory intended for executable code. This function internally calls `gum_code_segment_new`.
3. **Frida script writes code:** The user then writes their assembly instructions or machine code into the allocated memory region using `Memory.writeByteArray()` or similar functions.
4. **Frida needs to make it executable:**  Before the injected code can be executed, Frida needs to ensure the memory region has execute permissions. This triggers a call to `gum_code_segment_mark(address, size)`.
5. **`gum_code_segment_mark` calls `gum_code_segment_realize` (on iOS/tvOS):** If the target is iOS or tvOS, and the system conditions allow, `gum_code_segment_mark` will attempt to "realize" the code segment by creating the temporary signed file. This involves calls to `gum_code_segment_compute_layout`, `gum_put_mach_headers`, `gum_put_code_signature`, and file I/O operations.
6. **`gum_code_segment_mark` calls `gum_code_segment_map`:** After (or instead of) realization, `gum_code_segment_mark` calls `gum_code_segment_map` to map the code segment into the process's memory with execute permissions. This might involve `mmap` or `mach_vm_remap`.
7. **Potential errors and debugging:** If any of these steps fail (e.g., file creation fails due to sandbox restrictions, `fcntl` fails, memory mapping fails), the user will encounter errors. Debugging would involve checking:
    * **Frida error messages:** Frida usually provides informative error messages indicating the stage of failure.
    * **Sandbox profiles:** Verify if the Frida agent is running under a restrictive sandbox profile that blocks necessary operations.
    * **Code signing status:** On iOS/tvOS, ensure that the target process doesn't have overly strict code signing requirements that prevent the injected code from running even after the "realization" process.
    * **Memory conflicts:** Check if the target address for mapping is already occupied.
    * **`substrated` status:** If the code attempts to use `substrated`, verify that the `substrated` process is running and accessible.

In summary, `gumcodesegment-darwin.c` is a crucial file in Frida, providing the low-level mechanisms to manage executable code segments on Darwin-based systems, including sophisticated techniques to bypass code signing restrictions and enable dynamic code injection for instrumentation purposes. Its functionality is deeply rooted in the operating system's binary format, kernel APIs, and security mechanisms.

### 提示词
```
这是目录为frida/subprojects/frida-gum/gum/backend-darwin/gumcodesegment-darwin.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
/*
 * Copyright (C) 2016-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumcodesegment.h"

#include "gumtvos.h"
#include "gum-init.h"
#include "gumcloak.h"
#include "gum/gumdarwin.h"
#include "substratedclient.h"

#include <CommonCrypto/CommonDigest.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <mach-o/loader.h>
#include <math.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define GUM_CS_MAGIC_EMBEDDED_SIGNATURE 0xfade0cc0
#define GUM_CS_MAGIC_CODE_DIRECTORY 0xfade0c02
#define GUM_CS_MAGIC_REQUIREMENTS 0xfade0c01

#define GUM_CS_HASH_SHA1 1
#define GUM_CS_HASH_SHA1_SIZE 20

#define GUM_OFFSET_NONE -1

typedef struct _GumCodeLayout GumCodeLayout;
typedef struct _GumCsSuperBlob GumCsSuperBlob;
typedef struct _GumCsBlobIndex GumCsBlobIndex;
typedef struct _GumCsDirectory GumCsDirectory;
typedef struct _GumCsRequirements GumCsRequirements;
typedef guint GumSandboxFilterType;

struct _GumCodeSegment
{
  gpointer data;
  gsize size;
  gsize virtual_size;
  gboolean owns_data;

  gint fd;
};

struct _GumCodeLayout
{
  gsize header_file_size;

  gsize text_file_offset;
  gsize text_file_size;
  gsize text_size;

  gsize code_signature_file_offset;
  gsize code_signature_file_size;
  gsize code_signature_page_size;
  gsize code_signature_size;
  gsize code_signature_hash_count;
  gsize code_signature_hash_size;
};

struct _GumCsBlobIndex
{
  guint32 type;
  guint32 offset;
};

struct _GumCsSuperBlob
{
  guint32 magic;
  guint32 length;
  guint32 count;
  GumCsBlobIndex index[];
};

struct _GumCsDirectory
{
  guint32 magic;
  guint32 length;
  guint32 version;
  guint32 flags;
  guint32 hash_offset;
  guint32 ident_offset;
  guint32 num_special_slots;
  guint32 num_code_slots;
  guint32 code_limit;
  guint8 hash_size;
  guint8 hash_type;
  guint8 reserved_1;
  guint8 page_size;
  guint32 reserved_2;
};

struct _GumCsRequirements
{
  guint32 magic;
  guint32 length;
  guint32 count;
};

enum _GumSandboxFilterType
{
  GUM_SANDBOX_FILTER_PATH = 1,
};

static GumCodeSegment * gum_code_segment_new_full (gpointer data, gsize size,
    gsize virtual_size, gboolean owns_data);

G_GNUC_UNUSED static gboolean gum_code_segment_is_realize_supported (void);
G_GNUC_UNUSED static gboolean gum_code_segment_try_realize (
    GumCodeSegment * self);
G_GNUC_UNUSED static gboolean gum_code_segment_try_map (GumCodeSegment * self,
    gsize source_offset, gsize source_size, gpointer target_address);
static gboolean gum_code_segment_try_remap_locally (GumCodeSegment * self,
    gsize source_offset, gsize source_size, gpointer target_address);
G_GNUC_UNUSED static gboolean gum_code_segment_try_remap_using_substrated (
    GumCodeSegment * self, gsize source_offset, gsize source_size,
    gpointer target_address);

static void gum_code_segment_compute_layout (GumCodeSegment * self,
    GumCodeLayout * layout);

static void gum_put_mach_headers (const gchar * dylib_path,
    const GumCodeLayout * layout, gpointer output, gsize * output_size);
static void gum_put_code_signature (gconstpointer header, gconstpointer text,
    const GumCodeLayout * layout, gpointer output);

static gint gum_file_open_tmp (const gchar * tmpl, gchar ** name_used);
static void gum_file_write_all (gint fd, gssize offset, gconstpointer data,
    gsize size);
static gboolean gum_file_check_sandbox_allows (const gchar * path,
    const gchar * operation);

static mach_port_t gum_try_get_substrated_port (void);
static void gum_deallocate_substrated_port (void);

kern_return_t bootstrap_look_up (mach_port_t bp, const char * service_name,
    mach_port_t * sp);

gboolean
gum_code_segment_is_supported (void)
{
#if (defined (HAVE_MACOS) && defined (HAVE_ARM64)) || \
    defined (HAVE_IOS) || defined (HAVE_TVOS)
  /* Not going to work on newer kernels, such as on iOS >= 15.6.1. */
  return !gum_darwin_check_xnu_version (8020, 142, 0);
#else
  return FALSE;
#endif
}

GumCodeSegment *
gum_code_segment_new (gsize size,
                      const GumAddressSpec * spec)
{
  gsize page_size, size_in_pages, virtual_size;
  gpointer data;

  page_size = gum_query_page_size ();
  size_in_pages = size / page_size;
  if (size % page_size != 0)
    size_in_pages++;
  virtual_size = size_in_pages * page_size;

  if (spec == NULL)
  {
    data = gum_alloc_n_pages (size_in_pages, GUM_PAGE_RW);
  }
  else
  {
    data = gum_try_alloc_n_pages_near (size_in_pages, GUM_PAGE_RW, spec);
    if (data == NULL)
      return NULL;
  }

  return gum_code_segment_new_full (data, size, virtual_size, TRUE);
}

G_GNUC_UNUSED static GumCodeSegment *
gum_code_segment_new_static (gpointer data,
                             gsize size)
{
  return gum_code_segment_new_full (data, size, size, FALSE);
}

static GumCodeSegment *
gum_code_segment_new_full (gpointer data,
                           gsize size,
                           gsize virtual_size,
                           gboolean owns_data)
{
  GumCodeSegment * segment;

  segment = g_slice_new (GumCodeSegment);

  segment->data = data;
  segment->size = size;
  segment->virtual_size = virtual_size;
  segment->owns_data = owns_data;

  segment->fd = -1;

  if (owns_data)
  {
    GumMemoryRange range;

    gum_query_page_allocation_range (segment->data, segment->virtual_size,
        &range);

    gum_cloak_add_range (&range);
  }

  return segment;
}

void
gum_code_segment_free (GumCodeSegment * segment)
{
  if (segment->fd != -1)
    close (segment->fd);

  if (segment->owns_data)
  {
    GumMemoryRange range;

    gum_query_page_allocation_range (segment->data, segment->virtual_size,
        &range);

    gum_free_pages (segment->data);

    gum_cloak_remove_range (&range);
  }

  g_slice_free (GumCodeSegment, segment);
}

gpointer
gum_code_segment_get_address (GumCodeSegment * self)
{
  return self->data;
}

gsize
gum_code_segment_get_size (GumCodeSegment * self)
{
  return self->size;
}

gsize
gum_code_segment_get_virtual_size (GumCodeSegment * self)
{
  return self->virtual_size;
}

void
gum_code_segment_realize (GumCodeSegment * self)
{
#if defined (HAVE_IOS) || defined (HAVE_TVOS)
  if (gum_code_segment_is_realize_supported ())
  {
    gum_code_segment_try_realize (self);
  }
#endif
}

static gboolean
gum_code_segment_is_realize_supported (void)
{
#if defined (HAVE_IOS) || defined (HAVE_TVOS)
  static gsize realize_supported = 0;

  if (g_once_init_enter (&realize_supported))
  {
    gboolean supported = FALSE;
    gpointer scratch_page;
    GumCodeSegment * segment;

    if (g_file_test ("/usr/libexec/corelliumd", G_FILE_TEST_EXISTS))
      goto not_necessary;

    segment = gum_code_segment_new (1, NULL);
    scratch_page = gum_code_segment_get_address (segment);
    supported = gum_code_segment_try_realize (segment);
    if (supported)
      supported = gum_code_segment_try_map (segment, 0, 1, scratch_page);
    gum_code_segment_free (segment);

not_necessary:
    g_once_init_leave (&realize_supported, supported + 1);
  }

  return realize_supported - 1;
#else
  return FALSE;
#endif
}

void
gum_code_segment_map (GumCodeSegment * self,
                      gsize source_offset,
                      gsize source_size,
                      gpointer target_address)
{
  G_GNUC_UNUSED gboolean mapped_successfully;

#if defined (HAVE_IOS) || defined (HAVE_TVOS)
  if (self->fd != -1)
  {
    mapped_successfully = gum_code_segment_try_map (self, source_offset,
        source_size, target_address);
  }
  else
  {
    mapped_successfully = gum_code_segment_try_remap_using_substrated (self,
        source_offset, source_size, target_address);
    if (!mapped_successfully)
    {
      mapped_successfully = gum_code_segment_try_remap_locally (self,
          source_offset, source_size, target_address);
    }
  }
#else
  mapped_successfully = gum_code_segment_try_remap_locally (self, source_offset,
      source_size, target_address);
#endif

  g_assert (mapped_successfully);
}

gboolean
gum_code_segment_mark (gpointer code,
                       gsize size,
                       GError ** error)
{
#if defined (HAVE_IOS) || defined (HAVE_TVOS)
  if (gum_process_is_debugger_attached ())
    goto fallback;

  if (gum_code_segment_is_realize_supported ())
  {
    GumCodeSegment * segment;

    segment = gum_code_segment_new_static (code, size);

    gum_code_segment_realize (segment);
    gum_code_segment_map (segment, 0, size, code);

    gum_code_segment_free (segment);

    return TRUE;
  }
  else
  {
    mach_port_t server_port;
    mach_vm_address_t address;
    kern_return_t kr;

    server_port = gum_try_get_substrated_port ();
    if (server_port == MACH_PORT_NULL)
      goto fallback;

    address = GPOINTER_TO_SIZE (code);

    kr = substrated_mark (server_port, mach_task_self (), address, size,
        &address);

    if (kr != KERN_SUCCESS)
    {
      g_set_error (error, GUM_ERROR, GUM_ERROR_FAILED,
          "Unable to mark code (substrated returned %d)", kr);
      return FALSE;
    }

    return TRUE;
  }

fallback:
#endif
  {
    if (!gum_try_mprotect (code, size, GUM_PAGE_RX))
    {
      g_set_error (error, GUM_ERROR, GUM_ERROR_INVALID_ARGUMENT,
          "Invalid address");
      return FALSE;
    }

    return TRUE;
  }
}

static gboolean
gum_code_segment_try_realize (GumCodeSegment * self)
{
  gchar * dylib_path;
  GumCodeLayout layout;
  guint8 * dylib_header;
  gsize dylib_header_size;
  guint8 * code_signature;
  gint res;
  fsignatures_t sigs;

  self->fd = gum_file_open_tmp ("frida-XXXXXX.dylib", &dylib_path);
  if (self->fd == -1)
    return FALSE;

  gum_code_segment_compute_layout (self, &layout);

  dylib_header = g_malloc0 (layout.header_file_size);
  gum_put_mach_headers (dylib_path, &layout, dylib_header, &dylib_header_size);

  code_signature = g_malloc0 (layout.code_signature_file_size);
  gum_put_code_signature (dylib_header, self->data, &layout, code_signature);

  gum_file_write_all (self->fd, GUM_OFFSET_NONE, dylib_header,
      dylib_header_size);
  gum_file_write_all (self->fd, layout.text_file_offset, self->data,
      layout.text_size);
  gum_file_write_all (self->fd, layout.code_signature_file_offset,
      code_signature, layout.code_signature_file_size);

  sigs.fs_file_start = 0;
  sigs.fs_blob_start = GSIZE_TO_POINTER (layout.code_signature_file_offset);
  sigs.fs_blob_size = layout.code_signature_file_size;

  res = fcntl (self->fd, F_ADDFILESIGS, &sigs);

  unlink (dylib_path);

  g_free (code_signature);
  g_free (dylib_header);
  g_free (dylib_path);

  return res == 0;
}

static gboolean
gum_code_segment_try_map (GumCodeSegment * self,
                          gsize source_offset,
                          gsize source_size,
                          gpointer target_address)
{
  gpointer result;

  result = mmap (target_address, source_size, PROT_READ | PROT_EXEC,
      MAP_PRIVATE | MAP_FIXED, self->fd,
      gum_query_page_size () + source_offset);

  return result != MAP_FAILED;
}

static gboolean
gum_code_segment_try_remap_locally (GumCodeSegment * self,
                                    gsize source_offset,
                                    gsize source_size,
                                    gpointer target_address)
{
  mach_port_t self_task;
  mach_vm_address_t address;
  vm_offset_t source_address;
  vm_prot_t cur_protection, max_protection;
  kern_return_t kr;

  self_task = mach_task_self ();
  address = (mach_vm_address_t) target_address;
  source_address = (vm_offset_t) self->data + source_offset;

  mach_vm_protect (self_task, source_address, source_size, FALSE,
      VM_PROT_READ | VM_PROT_EXECUTE);
  kr = mach_vm_remap (self_task, &address, source_size, 0,
      VM_FLAGS_OVERWRITE | VM_FLAGS_FIXED, self_task, source_address, TRUE,
      &cur_protection, &max_protection, VM_INHERIT_COPY);

  if (kr == KERN_NO_SPACE)
  {
    /* Get rid of permanent map entries in target range. */
    mach_vm_protect (self_task, address, source_size, FALSE,
        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);

    kr = mach_vm_remap (self_task, &address, source_size, 0,
        VM_FLAGS_OVERWRITE | VM_FLAGS_FIXED, self_task, source_address, TRUE,
        &cur_protection, &max_protection, VM_INHERIT_COPY);

    mach_vm_protect (self_task, address, source_size, FALSE,
        VM_PROT_READ | VM_PROT_EXECUTE);
  }

  return kr == KERN_SUCCESS;
}

static gboolean
gum_code_segment_try_remap_using_substrated (GumCodeSegment * self,
                                             gsize source_offset,
                                             gsize source_size,
                                             gpointer target_address)
{
  mach_port_t server_port;
  mach_vm_address_t source_address, target_address_value;
  kern_return_t kr;

  server_port = gum_try_get_substrated_port ();
  if (server_port == MACH_PORT_NULL)
    return FALSE;

  source_address = (mach_vm_address_t) self->data + source_offset;
  target_address_value = GPOINTER_TO_SIZE (target_address);

  kr = substrated_mark (server_port, mach_task_self (), source_address,
      source_size, &target_address_value);

  return kr == KERN_SUCCESS;
}

static void
gum_code_segment_compute_layout (GumCodeSegment * self,
                                 GumCodeLayout * layout)
{
  gsize page_size, cs_page_size, cs_hash_count, cs_hash_size;
  gsize cs_size, cs_file_size;

  page_size = gum_query_page_size ();

  layout->header_file_size = page_size;

  layout->text_file_offset = layout->header_file_size;
  layout->text_file_size = self->virtual_size;
  layout->text_size = self->size;

  cs_page_size = 4096;
  cs_hash_count =
      (layout->text_file_offset + layout->text_file_size) / cs_page_size;
  cs_hash_size = GUM_CS_HASH_SHA1_SIZE;

  cs_size = 125 + (cs_hash_count * cs_hash_size);
  cs_file_size = cs_size;
  if (cs_file_size % 4 != 0)
    cs_file_size += 4 - (cs_file_size % 4);

  layout->code_signature_file_offset =
      layout->text_file_offset + layout->text_file_size;
  layout->code_signature_file_size = cs_file_size;
  layout->code_signature_page_size = cs_page_size;
  layout->code_signature_size = cs_size;
  layout->code_signature_hash_count = cs_hash_count;
  layout->code_signature_hash_size = cs_hash_size;
}

static void
gum_put_mach_headers (const gchar * dylib_path,
                      const GumCodeLayout * layout,
                      gpointer output,
                      gsize * output_size)
{
  gsize dylib_path_size;
  gum_mach_header_t * header = output;
  gum_segment_command_t * seg, * text_segment;
  gum_section_t * sect;
  struct dylib_command * dl;
  struct linkedit_data_command * sig;

  dylib_path_size = strlen (dylib_path);

  if (sizeof (gpointer) == 4)
  {
    header->magic = MH_MAGIC;
    header->cputype = CPU_TYPE_ARM;
    header->cpusubtype = CPU_SUBTYPE_UVAXII;
  }
  else
  {
    header->magic = MH_MAGIC_64;
    header->cputype = CPU_TYPE_ARM64;
    header->cpusubtype = CPU_SUBTYPE_LITTLE_ENDIAN;
  }
  header->filetype = MH_DYLIB;
  header->ncmds = 5;
  header->flags = MH_DYLDLINK | MH_PIE;

  seg = (gum_segment_command_t *) (header + 1);
  seg->cmd = GUM_LC_SEGMENT;
  seg->cmdsize = sizeof (gum_segment_command_t);
  strcpy (seg->segname, SEG_PAGEZERO);
  seg->vmaddr = 0;
  seg->vmsize = gum_query_page_size ();
  seg->fileoff = 0;
  seg->filesize = 0;
  seg->maxprot = PROT_NONE;
  seg->initprot = PROT_NONE;
  seg->nsects = 0;
  seg->flags = 0;

  seg++;
  seg->cmd = GUM_LC_SEGMENT;
  seg->cmdsize =
      sizeof (gum_segment_command_t) + sizeof (gum_section_t);
  strcpy (seg->segname, SEG_TEXT);
  seg->vmaddr = layout->text_file_offset;
  seg->vmsize = layout->text_file_size;
  seg->fileoff = layout->text_file_offset;
  seg->filesize = layout->text_file_size;
  seg->maxprot = PROT_READ | PROT_WRITE | PROT_EXEC;
  seg->initprot = PROT_READ | PROT_EXEC;
  seg->nsects = 1;
  seg->flags = 0;
  sect = (gum_section_t *) (seg + 1);
  strcpy (sect->sectname, SECT_TEXT);
  strcpy (sect->segname, SEG_TEXT);
  sect->addr = layout->text_file_offset;
  sect->size = layout->text_size;
  sect->offset = layout->text_file_offset;
  sect->align = 4;
  sect->reloff = 0;
  sect->nreloc = 0;
  sect->flags =
      S_REGULAR | S_ATTR_SOME_INSTRUCTIONS | S_ATTR_PURE_INSTRUCTIONS;
  text_segment = seg;

  seg = (gum_segment_command_t *) (sect + 1);
  seg->cmd = GUM_LC_SEGMENT;
  seg->cmdsize = sizeof (gum_segment_command_t);
  strcpy (seg->segname, SEG_LINKEDIT);
  seg->vmaddr = text_segment->vmaddr + text_segment->vmsize;
  seg->vmsize = 4096;
  seg->fileoff = layout->code_signature_file_offset;
  seg->filesize = layout->code_signature_file_size;
  seg->maxprot = PROT_READ;
  seg->initprot = PROT_READ;
  seg->nsects = 0;
  seg->flags = 0;

  dl = (struct dylib_command *) (seg + 1);
  dl->cmd = LC_ID_DYLIB;
  dl->cmdsize = sizeof (struct dylib_command) + dylib_path_size;
  if ((dl->cmdsize % 8) != 0)
    dl->cmdsize += 8 - (dl->cmdsize % 8);
  dl->dylib.name.offset = sizeof (struct dylib_command);
  dl->dylib.timestamp = 0;
  dl->dylib.current_version = 0;
  dl->dylib.compatibility_version = 0;
  memcpy ((gchar *) (dl + 1), dylib_path, dylib_path_size);

  sig = (struct linkedit_data_command *) (((guint8 *) dl) + dl->cmdsize);
  sig->cmd = LC_CODE_SIGNATURE;
  sig->cmdsize = sizeof (struct linkedit_data_command);
  sig->dataoff = layout->code_signature_file_offset;
  sig->datasize = layout->code_signature_file_size;

  header->sizeofcmds = ((guint8 *) (sig + 1)) - ((guint8 *) (header + 1));

  *output_size = sizeof (gum_mach_header_t) + header->sizeofcmds;
}

static void
gum_put_code_signature (gconstpointer header,
                        gconstpointer text,
                        const GumCodeLayout * layout,
                        gpointer output)
{
  GumCsSuperBlob * sb;
  GumCsBlobIndex * bi;
  GumCsDirectory * dir;
  guint8 * ident, * hashes;
  gsize cs_hashes_size, cs_page_size;
  GumCsRequirements * req;
  gsize i;

  cs_hashes_size =
      (layout->code_signature_hash_count * layout->code_signature_hash_size);

  sb = output;
  sb->magic = GUINT32_TO_BE (GUM_CS_MAGIC_EMBEDDED_SIGNATURE);
  sb->length = GUINT32_TO_BE (layout->code_signature_size);
  sb->count = GUINT32_TO_BE (2);

  bi = &sb->index[0];
  bi->type = GUINT32_TO_BE (0);
  bi->offset = GUINT32_TO_BE (28);

  bi = &sb->index[1];
  bi->type = GUINT32_TO_BE (2);
  bi->offset = GUINT32_TO_BE (113 + cs_hashes_size);

  dir = (GumCsDirectory *) (bi + 1);

  ident = ((guint8 *) dir) + 44;
  hashes = ident + 41;

  dir->magic = GUINT32_TO_BE (GUM_CS_MAGIC_CODE_DIRECTORY);
  dir->length = GUINT32_TO_BE (85 + cs_hashes_size);
  dir->version = GUINT32_TO_BE (0x00020001);
  dir->flags = GUINT32_TO_BE (0);
  dir->hash_offset = GUINT32_TO_BE (hashes - (guint8 *) dir);
  dir->ident_offset = GUINT32_TO_BE (ident - (guint8 *) dir);
  dir->num_special_slots = GUINT32_TO_BE (2);
  dir->num_code_slots = GUINT32_TO_BE (layout->code_signature_hash_count);
  dir->code_limit =
      GUINT32_TO_BE (layout->text_file_offset + layout->text_file_size);
  dir->hash_size = layout->code_signature_hash_size;
  dir->hash_type = GUM_CS_HASH_SHA1;
  dir->page_size = log2 (layout->code_signature_page_size);

  req = (GumCsRequirements *) (hashes + cs_hashes_size);
  req->magic = GUINT32_TO_BE (GUM_CS_MAGIC_REQUIREMENTS);
  req->length = GUINT32_TO_BE (12);
  req->count = GUINT32_TO_BE (0);

  CC_SHA1 (req, 12, ident + 1);

  cs_page_size = layout->code_signature_page_size;

  for (i = 0; i != layout->header_file_size / cs_page_size; i++)
  {
    CC_SHA1 (header + (i * cs_page_size), cs_page_size, hashes);
    hashes += 20;
  }

  for (i = 0; i != layout->text_file_size / cs_page_size; i++)
  {
    CC_SHA1 (text + (i * cs_page_size), cs_page_size, hashes);
    hashes += 20;
  }
}

static gint
gum_file_open_tmp (const gchar * tmpl,
                   gchar ** name_used)
{
  gchar * path;
  gint res;

  path = g_build_filename (g_get_tmp_dir (), tmpl, NULL);
  res = g_mkstemp (path);
  if (res == -1 || !gum_file_check_sandbox_allows (path, "file-map-executable"))
  {
    if (res != -1)
    {
      close (res);
      unlink (path);
    }
    g_free (path);
    path = g_build_filename ("/Library/Caches", tmpl, NULL);
    res = g_mkstemp (path);
  }

  if (res != -1)
  {
    *name_used = path;
  }
  else
  {
    *name_used = NULL;
    g_free (path);
  }

  return res;
}

static void
gum_file_write_all (gint fd,
                    gssize offset,
                    gconstpointer data,
                    gsize size)
{
  gssize written;

  if (offset != GUM_OFFSET_NONE)
    lseek (fd, offset, SEEK_SET);

  written = 0;
  do
  {
    gint res;

    res = write (fd, data + written, size - written);
    if (res == -1)
    {
      if (errno == EINTR)
        continue;
      else
        return;
    }

    written += res;
  }
  while (written != size);
}

static gboolean
gum_file_check_sandbox_allows (const gchar * path,
                               const gchar * operation)
{
  static gsize initialized = FALSE;
  static gint (* check) (pid_t pid, const gchar * operation,
      GumSandboxFilterType type, ...) = NULL;
  static GumSandboxFilterType no_report = 0;

  if (g_once_init_enter (&initialized))
  {
    void * sandbox;

    sandbox = dlopen ("/usr/lib/system/libsystem_sandbox.dylib",
        RTLD_NOLOAD | RTLD_LAZY);
    if (sandbox != NULL)
    {
      GumSandboxFilterType * no_report_ptr;

      no_report_ptr = dlsym (sandbox, "SANDBOX_CHECK_NO_REPORT");
      if (no_report_ptr != NULL)
      {
        no_report = *no_report_ptr;

        check = dlsym (sandbox, "sandbox_check");
      }

      dlclose (sandbox);
    }

    g_once_init_leave (&initialized, TRUE);
  }

  if (check == NULL)
    return TRUE;

  return !check (getpid (), operation, GUM_SANDBOX_FILTER_PATH | no_report,
      path);
}

static mach_port_t
gum_try_get_substrated_port (void)
{
  static gsize cached_result = 0;

  if (g_once_init_enter (&cached_result))
  {
    mach_port_t server_port = MACH_PORT_NULL;

    if (getpid () == 1)
    {
      host_get_special_port (mach_host_self (), HOST_LOCAL_NODE,
          HOST_LOCKD_PORT, &server_port);
    }
    else
    {
      mach_port_t self_task, bootstrap_port;

      self_task = mach_task_self ();

      if (task_get_bootstrap_port (self_task, &bootstrap_port) == KERN_SUCCESS)
      {
        bootstrap_look_up (bootstrap_port, "cy:com.saurik.substrated",
            &server_port);

        mach_port_deallocate (self_task, bootstrap_port);
      }
    }

    if (server_port != MACH_PORT_NULL)
      _gum_register_destructor (gum_deallocate_substrated_port);

    g_once_init_leave (&cached_result, server_port + 1);
  }

  return cached_result - 1;
}

static void
gum_deallocate_substrated_port (void)
{
  mach_port_deallocate (mach_task_self (), gum_try_get_substrated_port ());
}
```