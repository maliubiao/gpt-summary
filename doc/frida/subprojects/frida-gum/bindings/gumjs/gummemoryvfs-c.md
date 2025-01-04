Response:
My thought process to analyze the C code and address the prompt's requests would go something like this:

1. **Understand the Core Purpose:** I'd first read the initial comments and the overall structure to grasp the fundamental function of `gummemoryvfs.c`. The comments indicate it's related to a memory-based virtual file system (VFS) for SQLite within Frida. This immediately tells me it's about manipulating file-like data in memory without touching the actual file system.

2. **Identify Key Data Structures:**  Next, I'd focus on the `struct` definitions: `GumMemoryFile`, `GumMemoryFileEntry`, and `GumMemoryVfs`. These are the building blocks of the VFS. I'd note the key members of each structure:
    * `GumMemoryFile`: Links a standard `sqlite3_file` to a `GumMemoryFileEntry`. This suggests it's wrapping the standard SQLite file interface.
    * `GumMemoryFileEntry`: Holds the actual file data (`data`), its `size`, a `ref_count` for memory management, and `lock_level` for concurrency control.
    * `GumMemoryVfs`:  The main VFS structure. It contains the `sqlite3_vfs` structure (the standard SQLite VFS interface), a `name`, a pointer to the `default_vfs` (the underlying real file system VFS), and a hash table (`entries`) to store the in-memory file entries.

3. **Analyze Functionality by Examining Functions:** I would then go through the functions, grouping them by their purpose:

    * **VFS Management:** `gum_memory_vfs_new`, `gum_memory_vfs_free`, `gum_memory_vfs_add_file`, `gum_memory_vfs_remove_file`, `gum_memory_vfs_get_file_contents`. These functions manage the lifecycle and content of the in-memory VFS.

    * **SQLite VFS Interface Implementation:**  Functions starting with `gum_memory_vfs_` that correspond to `sqlite3_vfs` methods (e.g., `gum_memory_vfs_open`, `gum_memory_vfs_delete`, `gum_memory_vfs_access`, `gum_memory_vfs_dlopen`, etc.). These are the core of the VFS, providing the necessary hooks for SQLite to interact with the in-memory files. I'd notice that many of the `dlopen`, `dlerror`, `dlsym`, `dlclose`, time, and randomness functions delegate to the `default_vfs`.

    * **SQLite File Interface Implementation:** Functions starting with `gum_memory_file_` that implement the `sqlite3_io_methods` structure (e.g., `gum_memory_file_close`, `gum_memory_file_read`, `gum_memory_file_write`, `gum_memory_file_truncate`, etc.). These functions define how SQLite interacts with the individual in-memory files.

    * **Helper Functions:** `gum_memory_file_entry_ref`, `gum_memory_file_entry_unref` (reference counting for memory management), and the compression/decompression functions `gum_memory_vfs_contents_to_string` and `gum_memory_vfs_contents_from_string`.

4. **Address Specific Prompt Questions:**  With the function analysis complete, I would then address each part of the prompt:

    * **Functionality Listing:**  I'd summarize the purposes of the major function groups identified in step 3, being specific about what each part does.

    * **Relationship to Reversing:** I would look for aspects relevant to dynamic analysis and reverse engineering. The ability to inject and inspect in-memory databases is a key aspect here. I would formulate examples like modifying SQL queries, injecting data, and observing database interactions.

    * **Binary/Kernel/Framework Knowledge:** I'd focus on aspects that touch on lower-level concepts. The usage of `sqlite3_vfs`, the concepts of file locking, shared memory (`shm_map`, `shm_lock`), and dynamic linking (`dlopen`, `dlsym`) are relevant. I'd explain how these relate to OS and library internals. The use of `gio` library functions would also fall under this category.

    * **Logical Reasoning (Input/Output):**  I'd pick a simple function like `gum_memory_file_read` or `gum_memory_file_write` and create hypothetical scenarios to demonstrate how input parameters influence the output. For example, reading beyond the file boundary.

    * **Common User Errors:**  I'd think about how a developer using this API might make mistakes. Forgetting to `unref` entries, providing incorrect sizes, or attempting operations on non-existent files are good examples.

    * **User Operation and Debugging:**  I'd consider how a Frida user would actually trigger this code. The process would involve using Frida's JavaScript API to interact with the target process, including creating and manipulating these in-memory databases. I'd outline the steps a debugger would follow to trace execution into this code.

5. **Structure and Refine:** Finally, I'd organize the information logically, using clear headings and examples to make the explanation easy to understand. I would review and refine the language to ensure accuracy and clarity. For example, I would make sure to distinguish between the `sqlite3_vfs` and the custom `GumMemoryVfs`.

This systematic approach ensures that all aspects of the code are considered and that the answers to the prompt's questions are comprehensive and accurate. It involves understanding the big picture, breaking it down into smaller pieces, and then synthesizing the information to provide a complete explanation.
好的，让我们来详细分析一下 `gummemoryvfs.c` 这个文件。

**功能列举:**

`gummemoryvfs.c` 文件实现了 Frida Gum 框架的一个**内存虚拟文件系统 (VFS)**。它允许在内存中创建、访问和操作文件，而无需实际的文件 I/O 操作。这主要用于在目标进程的内存空间中模拟文件系统的行为，例如：

1. **创建内存文件:** 允许在内存中创建虚拟文件，这些文件不对应磁盘上的实际文件。
2. **读取内存文件:** 可以读取内存中虚拟文件的内容。
3. **写入内存文件:** 可以修改内存中虚拟文件的内容。
4. **删除内存文件:** 可以移除内存中的虚拟文件。
5. **文件属性模拟:**  模拟了部分文件属性，例如文件大小。
6. **动态链接库加载模拟:**  通过委托给默认的 VFS，间接支持了动态链接库的加载和符号查找，但这部分自身没有实现内存加载逻辑。
7. **时间和随机数生成:**  同样委托给默认的 VFS。
8. **文件锁定:**  支持基本的文件锁定机制。
9. **共享内存映射 (有限):**  提供 `shm_map` 等接口，但实现返回 `SQLITE_IOERR_NOMEM`，意味着它并没有真正实现共享内存映射。
10. **内容的序列化和反序列化:** 提供了 `gum_memory_vfs_contents_to_string` 和 `gum_memory_vfs_contents_from_string` 函数，用于将内存中的文件内容转换为字符串（Base64 编码并可选压缩）以及反向操作。

**与逆向方法的关联及举例:**

内存 VFS 在动态逆向分析中非常有用：

* **模拟文件依赖:**  有些程序可能依赖于某些配置文件或者数据文件。使用内存 VFS，可以在不修改磁盘文件的情况下，提供修改后的文件内容给目标程序，观察其行为变化。
    * **举例:**  假设一个程序读取一个名为 `config.ini` 的配置文件。通过 Frida，我们可以创建一个内存 VFS，并在其中创建一个名为 `config.ini` 的内存文件，并注入我们自定义的配置内容。当目标程序尝试打开 `config.ini` 时，它实际上会访问我们内存中的版本，从而允许我们动态地修改程序的行为。
* **Hook 文件操作:**  Frida 可以 hook 目标程序的文件操作 API（例如 `open`, `read`, `write`）。结合内存 VFS，可以重定向目标程序的文件访问到内存中的虚拟文件，方便观察和修改数据流。
    * **举例:**  某个恶意软件可能会将解密后的 payload 写入一个临时文件。通过 hook `open` 和结合内存 VFS，我们可以让恶意软件将内容“写入”到一个内存文件，而不会触及磁盘。然后，我们可以直接从内存中读取解密后的 payload，进行进一步分析。
* **数据库操作分析:**  该 VFS 的实现是基于 SQLite 的，这使得它可以方便地用于分析与 SQLite 数据库交互的程序。可以将数据库文件加载到内存中，修改数据，或者观察程序对数据库的查询和修改操作。
    * **举例:**  一个 Android 应用可能使用 SQLite 数据库存储用户信息。可以使用 Frida 加载应用的数据库文件到内存 VFS 中，然后通过执行自定义的 SQL 查询来分析数据库结构和内容，或者修改数据库中的数据来观察应用的行为变化。

**涉及二进制底层、Linux/Android 内核及框架的知识及举例:**

* **SQLite VFS 接口:** 该代码实现了 SQLite 的 VFS 接口 (`sqlite3_vfs` 和 `sqlite3_io_methods`)。理解这些接口是理解代码功能的基础。SQLite 的 VFS 允许开发者自定义 SQLite 如何与底层存储交互，这里就是创建了一个内存中的存储实现。
* **文件操作语义:**  代码模拟了基本的文件操作，例如 open, read, write, close, delete 等。理解这些操作的底层语义，例如文件描述符、文件偏移量等，有助于理解代码的实现。
* **内存管理:**  代码使用了 GLib 库的内存管理函数，例如 `g_slice_new0`, `g_slice_free`, `g_realloc`, `g_free` 等。理解内存分配和释放对于避免内存泄漏至关重要。
* **文件锁定:**  代码实现了基本的文件锁定机制，涉及共享锁和排他锁的概念。这与操作系统底层的文件锁定机制相关。
* **动态链接:**  虽然大部分动态链接相关的操作委托给了默认的 VFS，但理解 `dlopen`, `dlsym`, `dlclose` 的作用是重要的。在逆向分析中，经常需要处理动态链接库的加载和符号解析。
* **Android 框架 (间接):**  由于 Frida 常用于 Android 平台的动态分析，并且许多 Android 应用使用 SQLite 数据库，因此这个内存 VFS 可以用于分析 Android 应用的数据库操作。虽然代码本身没有直接涉及 Android 特有的 API，但其应用场景与 Android 逆向密切相关。
* **GIO 库:**  代码使用了 GLib 的 GIO 库来进行 Base64 编码和 Zlib 压缩/解压缩。理解这些操作对于理解 `gum_memory_vfs_contents_to_string` 和 `gum_memory_vfs_contents_from_string` 的功能至关重要。

**逻辑推理、假设输入与输出:**

假设我们使用 Frida 的 JavaScript API 创建了一个 `GumMemoryVfs` 实例，并添加了一个内容为 "Hello, World!" 的文件，路径为 "/myfile.txt"。

**假设输入:**

1. 调用 `gum_memory_vfs_add_file` 函数，传入 `GumMemoryVfs` 实例指针，内容为 "Hello, World!" 的字符串指针，以及字符串长度。
2. 随后，目标程序尝试打开 "/myfile.txt" 进行读取。Frida hook 了 `open` 系统调用，并将其重定向到我们的内存 VFS 的 `gum_memory_vfs_open` 函数。
3. 目标程序调用 `read` 系统调用读取文件内容，Frida 将其重定向到 `gum_memory_file_read` 函数。假设目标程序请求读取 10 个字节，从偏移量 0 开始。

**逻辑推理:**

* `gum_memory_vfs_add_file` 会创建一个 `GumMemoryFileEntry` 结构，将 "Hello, World!" 存储在 `data` 字段中，并将大小设置为 13。
* `gum_memory_vfs_open` 会在内存 VFS 的哈希表中查找 "/myfile.txt" 对应的 `GumMemoryFileEntry`，并创建一个 `GumMemoryFile` 结构与之关联。
* `gum_memory_file_read` 会检查偏移量和请求读取的字节数是否超出文件大小。在这个例子中，偏移量为 0，请求读取 10 个字节，都在文件范围内。
* `memcpy` 函数会将 `GumMemoryFileEntry` 的 `data` 指针指向的内容，从偏移量 0 开始，复制 10 个字节到目标程序的缓冲区。

**预期输出:**

目标程序的缓冲区将包含字符串 "Hello, Wor"。

**涉及用户或编程常见的使用错误及举例:**

1. **忘记释放内存:**  `GumMemoryFileEntry` 结构体使用了引用计数 (`ref_count`) 进行管理。如果用户在自定义的 VFS 操作中，不正确地增加或减少引用计数，可能会导致内存泄漏或过早释放。
    * **举例:**  如果用户在 `gum_memory_vfs_open` 中获取了 `GumMemoryFileEntry` 的引用，但在某个错误处理路径中忘记调用 `gum_memory_file_entry_unref`，就会导致内存泄漏。
2. **访问越界:**  在 `gum_memory_file_read` 和 `gum_memory_file_write` 中，如果用户提供的偏移量或读取/写入的长度超出了文件的大小，可能会导致程序崩溃或数据损坏。虽然代码中做了一些边界检查，但错误的使用仍然可能导致问题。
    * **举例:**  如果用户尝试从偏移量 100 处读取一个只有 50 字节的文件，`gum_memory_file_read` 会返回 `SQLITE_IOERR_READ`。但如果用户没有正确处理这个错误，可能会导致程序逻辑错误。
3. **VFS 操作与实际文件系统的混淆:**  用户可能会误认为对内存 VFS 的操作会影响实际的文件系统，导致不期望的结果。
    * **举例:**  用户在内存 VFS 中修改了一个文件的内容，然后期望磁盘上的原始文件也被修改了，这是不正确的。
4. **多线程安全问题:** 代码中对 `next_entry_id` 使用了原子操作，但对于 `entries` 哈希表的并发访问可能需要额外的同步机制，如果多个线程同时操作同一个内存文件，可能会出现数据竞争。

**用户操作是如何一步步的到达这里，作为调试线索:**

作为 Frida 的用户，与 `gummemoryvfs.c` 交互的典型步骤如下：

1. **编写 Frida 脚本 (JavaScript):** 用户会编写一个 JavaScript 脚本，使用 Frida 提供的 API 来操作目标进程。
2. **创建 `MemoryFile` 对象 (Frida API):**  用户会使用 `MemoryFile` API 来创建一个内存文件，可以指定文件的路径和内容。这个操作在底层会调用 `gum_memory_vfs_add_file`。
   ```javascript
   const memoryFile = MemoryFile.fromString('/mydata.txt', 'Some initial content');
   ```
3. **创建 `MemoryFileSystem` 对象 (Frida API):** 用户会创建一个内存文件系统，并将之前创建的内存文件添加到这个文件系统中。这会创建 `GumMemoryVfs` 实例。
   ```javascript
   const memoryFs = new MemoryFileSystem({
       '/mydata.txt': memoryFile
   });
   ```
4. **挂载内存文件系统 (Frida API):** 用户需要将这个内存文件系统挂载到目标进程，这样目标进程的文件访问操作才能被重定向到这个内存文件系统。
   ```javascript
   memoryFs.mount();
   ```
5. **目标进程执行文件操作:**  目标进程执行代码，尝试打开、读取或写入 `/mydata.txt` 文件。
6. **Frida Hook 介入:** Frida 会 hook 目标进程的文件操作相关的系统调用（例如 `open`, `read`, `write`）。
7. **VFS 方法调用:**  当目标进程尝试访问挂载点下的文件时，Frida 会将这些文件操作重定向到 `gummemoryvfs.c` 中实现的相应 VFS 方法，例如 `gum_memory_vfs_open`, `gum_memory_file_read` 等。

**调试线索:**

* **Frida 脚本错误:**  用户编写的 Frida 脚本中创建和挂载内存文件系统的逻辑可能存在错误，例如文件路径不匹配，导致目标进程无法访问到内存文件。
* **Hook 点错误:**  Frida 可能没有成功 hook 到目标进程的文件操作 API，或者 hook 的时机不对。
* **目标进程行为:**  目标进程可能并没有按照预期的方式访问文件，或者访问的是其他路径的文件。
* **内存 VFS 的状态:**  可以使用 Frida 提供的 API 来检查内存 VFS 的状态，例如已添加的文件列表和内容，来排查问题。

总而言之，`gummemoryvfs.c` 提供了一个强大的机制，可以在不修改磁盘文件的情况下，模拟文件系统的行为，这对于动态分析和逆向工程来说是一个非常有用的工具。理解其内部实现有助于更好地利用 Frida 进行程序分析和调试。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gummemoryvfs.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummemoryvfs.h"

#include <gio/gio.h>
#include <string.h>

#define GUM_MEMORY_VFS(vfs) ((GumMemoryVfs *) (vfs))
#define GUM_MEMORY_FILE(f) ((GumMemoryFile *) (f))

typedef struct _GumMemoryFile GumMemoryFile;
typedef struct _GumMemoryFileEntry GumMemoryFileEntry;

typedef void (* GumDlFunc) (void);

struct _GumMemoryFile
{
  sqlite3_file file;
  GumMemoryFileEntry * entry;
};

struct _GumMemoryFileEntry
{
  guint ref_count;
  guint8 * data;
  gsize size;
  gint lock_level;
};

static GumMemoryFileEntry * gum_memory_vfs_add_entry (GumMemoryVfs * self,
    gchar * path, guint8 * data, gsize size);
static int gum_memory_vfs_open (sqlite3_vfs * vfs, const char * name,
    sqlite3_file * file, int flags, int * out_flags);
static int gum_memory_vfs_delete (sqlite3_vfs * vfs, const char * name,
    int sync_dir);
static int gum_memory_vfs_access (sqlite3_vfs * vfs, const char * name,
    int flags, int * res_out);
static int gum_memory_vfs_full_pathname (sqlite3_vfs * vfs, const char * name,
    int n_out, char * z_out);
static void * gum_memory_vfs_dlopen (sqlite3_vfs * vfs, const char * filename);
static void gum_memory_vfs_dlerror (sqlite3_vfs * vfs, int n_bytes,
    char * error_message);
static GumDlFunc gum_memory_vfs_dlsym (sqlite3_vfs * vfs, void * module,
    const char * symbol);
static void gum_memory_vfs_dlclose (sqlite3_vfs * vfs, void * module);
static int gum_memory_vfs_randomness (sqlite3_vfs * vfs, int n_bytes,
    char * z_out);
static int gum_memory_vfs_sleep (sqlite3_vfs * vfs, int microseconds);
static int gum_memory_vfs_current_time (sqlite3_vfs * vfs, double * t);
static int gum_memory_vfs_current_time_int64 (sqlite3_vfs * vfs,
    sqlite3_int64 * t);

static GumMemoryFileEntry * gum_memory_file_entry_ref (
    GumMemoryFileEntry * self);
static void gum_memory_file_entry_unref (GumMemoryFileEntry * self);
static int gum_memory_file_close (sqlite3_file * file);
static int gum_memory_file_read (sqlite3_file * file, void * buffer, int amount,
    sqlite3_int64 offset);
static int gum_memory_file_write (sqlite3_file * file, const void * buffer,
    int amount, sqlite3_int64 offset);
static int gum_memory_file_truncate (sqlite3_file * file, sqlite3_int64 size);
static int gum_memory_file_sync (sqlite3_file * file, int flags);
static int gum_memory_file_size (sqlite3_file * file, sqlite3_int64 * size);
static int gum_memory_file_lock (sqlite3_file * file, int level);
static int gum_memory_file_unlock (sqlite3_file * file, int level);
static int gum_memory_file_check_reserved_lock (sqlite3_file * file,
    int * result);
static int gum_memory_file_control (sqlite3_file * file, int op, void * arg);
static int gum_memory_file_sector_size (sqlite3_file * file);
static int gum_memory_file_device_characteristics (sqlite3_file * file);
static int gum_memory_file_shm_map (sqlite3_file * file, int region,
    int region_size, int extend, void volatile ** memory);
static int gum_memory_file_shm_lock (sqlite3_file * file, int offset, int n,
    int flags);
static void gum_memory_file_shm_barrier (sqlite3_file * file);
static int gum_memory_file_shm_unmap (sqlite3_file * file, int delete_flag);
static int gum_memory_file_fetch (sqlite3_file * file, sqlite3_int64 offset,
    int amount, void ** memory);
static int gum_memory_file_unfetch (sqlite3_file * file, sqlite3_int64 offset,
    void * memory);

static gint gum_vfs_next_id = 1;

static const sqlite3_io_methods gum_memory_file_methods = {
  3,

  gum_memory_file_close,
  gum_memory_file_read,
  gum_memory_file_write,
  gum_memory_file_truncate,
  gum_memory_file_sync,
  gum_memory_file_size,
  gum_memory_file_lock,
  gum_memory_file_unlock,
  gum_memory_file_check_reserved_lock,
  gum_memory_file_control,
  gum_memory_file_sector_size,
  gum_memory_file_device_characteristics,

  gum_memory_file_shm_map,
  gum_memory_file_shm_lock,
  gum_memory_file_shm_barrier,
  gum_memory_file_shm_unmap,

  gum_memory_file_fetch,
  gum_memory_file_unfetch
};

GumMemoryVfs *
gum_memory_vfs_new (void)
{
  GumMemoryVfs * self;
  sqlite3_vfs * vfs;

  self = g_slice_new0 (GumMemoryVfs);

  self->name = g_strdup_printf ("gum-%d",
      g_atomic_int_add (&gum_vfs_next_id, 1));
  self->default_vfs = sqlite3_vfs_find (NULL);
  self->entries = g_hash_table_new_full (g_str_hash, g_str_equal, g_free,
      (GDestroyNotify) gum_memory_file_entry_unref);
  self->next_entry_id = 1;

  vfs = &self->vfs;

  vfs->iVersion = 3;
  vfs->szOsFile = sizeof (GumMemoryFile);
  vfs->mxPathname = self->default_vfs->mxPathname;
  vfs->zName = self->name;

  vfs->xOpen = gum_memory_vfs_open;
  vfs->xDelete = gum_memory_vfs_delete;
  vfs->xAccess = gum_memory_vfs_access;
  vfs->xFullPathname = gum_memory_vfs_full_pathname;
  vfs->xDlOpen = gum_memory_vfs_dlopen;
  vfs->xDlError = gum_memory_vfs_dlerror;
  vfs->xDlSym = gum_memory_vfs_dlsym;
  vfs->xDlClose = gum_memory_vfs_dlclose;
  vfs->xRandomness = gum_memory_vfs_randomness;
  vfs->xSleep = gum_memory_vfs_sleep;
  vfs->xCurrentTime = gum_memory_vfs_current_time;

  vfs->xCurrentTimeInt64 = gum_memory_vfs_current_time_int64;

  return self;
}

void
gum_memory_vfs_free (GumMemoryVfs * self)
{
  g_hash_table_unref (self->entries);
  g_free (self->name);

  g_slice_free (GumMemoryVfs, self);
}

const gchar *
gum_memory_vfs_add_file (GumMemoryVfs * self,
                         gpointer contents,
                         gsize size)
{
  gchar * path;

  path = g_strdup_printf ("/f%d.db", self->next_entry_id++);

  gum_memory_vfs_add_entry (self, path, contents, size);

  return path;
}

void
gum_memory_vfs_remove_file (GumMemoryVfs * self,
                            const gchar * path)
{
  self->vfs.xDelete (&self->vfs, path, FALSE);
}

gboolean
gum_memory_vfs_get_file_contents (GumMemoryVfs * self,
                                  const gchar * path,
                                  gpointer * contents,
                                  gsize * size)
{
  GumMemoryFileEntry * entry;

  entry = g_hash_table_lookup (self->entries, path);
  if (entry == NULL)
    return FALSE;

  *contents = entry->data;
  *size = entry->size;

  return TRUE;
}

static GumMemoryFileEntry *
gum_memory_vfs_add_entry (GumMemoryVfs * self,
                          gchar * path,
                          guint8 * data,
                          gsize size)
{
  GumMemoryFileEntry * entry;

  entry = g_slice_new (GumMemoryFileEntry);
  entry->ref_count = 1;
  entry->data = data;
  entry->size = size;
  entry->lock_level = SQLITE_LOCK_NONE;
  g_hash_table_replace (self->entries, path, entry);

  return entry;
}

static int
gum_memory_vfs_open (sqlite3_vfs * vfs,
                     const char * name,
                     sqlite3_file * file,
                     int flags,
                     int * out_flags)
{
  GumMemoryVfs * self = GUM_MEMORY_VFS (vfs);
  GumMemoryFile * f = GUM_MEMORY_FILE (file);
  GumMemoryFileEntry * entry;

  memset (f, 0, sizeof (GumMemoryFile));

  if ((flags & SQLITE_OPEN_CREATE) != 0)
  {
    entry = gum_memory_vfs_add_entry (self, g_strdup (name), NULL, 0);
  }
  else
  {
    entry = g_hash_table_lookup (self->entries, name);
    if (entry == NULL)
      return SQLITE_CANTOPEN;
  }

  file->pMethods = &gum_memory_file_methods;

  f->entry = gum_memory_file_entry_ref (entry);

  if (out_flags != NULL)
    *out_flags = flags;

  return SQLITE_OK;
}

static int
gum_memory_vfs_delete (sqlite3_vfs * vfs,
                       const char * name,
                       int sync_dir)
{
  GumMemoryVfs * self = GUM_MEMORY_VFS (vfs);
  gboolean removed;

  removed = g_hash_table_remove (self->entries, name);

  return removed ? SQLITE_OK : SQLITE_IOERR_DELETE_NOENT;
}

static int
gum_memory_vfs_access (sqlite3_vfs * vfs,
                       const char * name,
                       int flags,
                       int * res_out)
{
  GumMemoryVfs * self = GUM_MEMORY_VFS (vfs);

  *res_out = g_hash_table_contains (self->entries, name);
  return SQLITE_OK;
}

static int
gum_memory_vfs_full_pathname (sqlite3_vfs * vfs,
                              const char * name,
                              int n_out,
                              char * z_out)
{
  gchar * full_path;
  gboolean buffer_too_small;

  full_path = (name[0] == '/')
      ? g_strdup (name)
      : g_strconcat ("/", name, NULL);

  g_strlcpy (z_out, full_path, n_out);
  buffer_too_small = strlen (full_path) >= (gsize) n_out;

  g_free (full_path);

  return buffer_too_small ? SQLITE_CANTOPEN : SQLITE_OK;
}

static void *
gum_memory_vfs_dlopen (sqlite3_vfs * vfs,
                       const char * filename)
{
  sqlite3_vfs * dvfs = GUM_MEMORY_VFS (vfs)->default_vfs;

  return dvfs->xDlOpen (dvfs, filename);
}

static void
gum_memory_vfs_dlerror (sqlite3_vfs * vfs,
                        int n_bytes,
                        char * error_message)
{
  sqlite3_vfs * dvfs = GUM_MEMORY_VFS (vfs)->default_vfs;

  dvfs->xDlError (dvfs, n_bytes, error_message);
}

static GumDlFunc
gum_memory_vfs_dlsym (sqlite3_vfs * vfs,
                      void * module,
                      const char * symbol)
{
  sqlite3_vfs * dvfs = GUM_MEMORY_VFS (vfs)->default_vfs;

  return dvfs->xDlSym (dvfs, module, symbol);
}

static void
gum_memory_vfs_dlclose (sqlite3_vfs * vfs,
                        void * module)
{
  sqlite3_vfs * dvfs = GUM_MEMORY_VFS (vfs)->default_vfs;

  dvfs->xDlClose (dvfs, module);
}

static int
gum_memory_vfs_randomness (sqlite3_vfs * vfs,
                           int n_bytes,
                           char * z_out)
{
  sqlite3_vfs * dvfs = GUM_MEMORY_VFS (vfs)->default_vfs;

  return dvfs->xRandomness (dvfs, n_bytes, z_out);
}

static int
gum_memory_vfs_sleep (sqlite3_vfs * vfs,
                      int microseconds)
{
  sqlite3_vfs * dvfs = GUM_MEMORY_VFS (vfs)->default_vfs;

  return dvfs->xSleep (dvfs, microseconds);
}

static int
gum_memory_vfs_current_time (sqlite3_vfs * vfs,
                             double * t)
{
  sqlite3_vfs * dvfs = GUM_MEMORY_VFS (vfs)->default_vfs;

  return dvfs->xCurrentTime (dvfs, t);
}

static int
gum_memory_vfs_current_time_int64 (sqlite3_vfs * vfs,
                                   sqlite3_int64 * t)
{
  sqlite3_vfs * dvfs = GUM_MEMORY_VFS (vfs)->default_vfs;

  return dvfs->xCurrentTimeInt64 (dvfs, t);
}

static GumMemoryFileEntry *
gum_memory_file_entry_ref (GumMemoryFileEntry * self)
{
  self->ref_count++;
  return self;
}

static void
gum_memory_file_entry_unref (GumMemoryFileEntry * self)
{
  if (--self->ref_count == 0)
  {
    g_free (self->data);

    g_slice_free (GumMemoryFileEntry, self);
  }
}

static int
gum_memory_file_close (sqlite3_file * file)
{
  GumMemoryFile * self = GUM_MEMORY_FILE (file);

  gum_memory_file_entry_unref (self->entry);
  self->entry = NULL;

  return SQLITE_OK;
}

static int
gum_memory_file_read (sqlite3_file * file,
                      void * buffer,
                      int amount,
                      sqlite3_int64 offset)
{
  GumMemoryFile * self = GUM_MEMORY_FILE (file);
  GumMemoryFileEntry * entry = self->entry;
  gint available, n;

  if (offset < 0 || (gsize) offset >= entry->size)
    return SQLITE_IOERR_READ;

  available = entry->size - offset;
  n = MIN (amount, available);

  memcpy (buffer, entry->data + offset, n);

  if (n < amount)
  {
    memset ((guint8 *) buffer + n, 0, amount - n);
    return SQLITE_IOERR_SHORT_READ;
  }

  return SQLITE_OK;
}

static int
gum_memory_file_write (sqlite3_file * file,
                       const void * buffer,
                       int amount,
                       sqlite3_int64 offset)
{
  GumMemoryFile * self = GUM_MEMORY_FILE (file);
  GumMemoryFileEntry * entry = self->entry;
  gsize required_size;

  if (offset < 0)
    return SQLITE_IOERR_WRITE;

  required_size = offset + amount;
  if (required_size > entry->size)
  {
    entry->data = g_realloc (entry->data, required_size);
    entry->size = required_size;
  }

  memcpy (entry->data + offset, buffer, amount);

  return SQLITE_OK;
}

static int
gum_memory_file_truncate (sqlite3_file * file,
                          sqlite3_int64 size)
{
  GumMemoryFile * self = GUM_MEMORY_FILE (file);
  GumMemoryFileEntry * entry = self->entry;

  g_free (g_steal_pointer (&entry->data));
  entry->size = 0;

  return SQLITE_OK;
}

static int
gum_memory_file_sync (sqlite3_file * file,
                      int flags)
{
  return SQLITE_OK;
}

static int
gum_memory_file_size (sqlite3_file * file,
                      sqlite3_int64 * size)
{
  GumMemoryFile * self = GUM_MEMORY_FILE (file);

  *size = self->entry->size;
  return SQLITE_OK;
}

static int
gum_memory_file_lock (sqlite3_file * file,
                      int level)
{
  GumMemoryFile * self = GUM_MEMORY_FILE (file);

  self->entry->lock_level = level;

  return SQLITE_OK;
}

static int
gum_memory_file_unlock (sqlite3_file * file,
                        int level)
{
  GumMemoryFile * self = GUM_MEMORY_FILE (file);
  GumMemoryFileEntry * entry = self->entry;

  if (entry->lock_level < level)
    return SQLITE_OK;

  entry->lock_level = level;

  return SQLITE_OK;
}

static int
gum_memory_file_check_reserved_lock (sqlite3_file * file,
                                     int * result)
{
  GumMemoryFile * self = GUM_MEMORY_FILE (file);

  *result = self->entry->lock_level > SQLITE_LOCK_SHARED;
  return SQLITE_OK;
}

static int
gum_memory_file_control (sqlite3_file * file,
                         int op,
                         void * arg)
{
  return SQLITE_NOTFOUND;
}

static int
gum_memory_file_sector_size (sqlite3_file * file)
{
  return 4096;
}

static int
gum_memory_file_device_characteristics (sqlite3_file * file)
{
  return SQLITE_IOCAP_ATOMIC |
      SQLITE_IOCAP_SAFE_APPEND |
      SQLITE_IOCAP_SEQUENTIAL |
      SQLITE_IOCAP_POWERSAFE_OVERWRITE;
}

static int
gum_memory_file_shm_map (sqlite3_file * file,
                         int region,
                         int region_size,
                         int extend,
                         void volatile ** memory)
{
  return SQLITE_IOERR_NOMEM;
}

static int
gum_memory_file_shm_lock (sqlite3_file * file,
                          int offset,
                          int n,
                          int flags)
{
  return SQLITE_OK;
}

static void
gum_memory_file_shm_barrier (sqlite3_file * file)
{
}

static int
gum_memory_file_shm_unmap (sqlite3_file * file,
                           int delete_flag)
{
  return SQLITE_OK;
}

static int
gum_memory_file_fetch (sqlite3_file * file,
                       sqlite3_int64 offset,
                       int amount,
                       void ** memory)
{
  *memory = NULL;
  return SQLITE_OK;
}

static int
gum_memory_file_unfetch (sqlite3_file * file,
                         sqlite3_int64 offset,
                         void * memory)
{
  return SQLITE_OK;
}

gchar *
gum_memory_vfs_contents_to_string (gconstpointer contents,
                                   gsize size)
{
  GInputStream * uncompressed_input;
  GOutputStream * compressed_output;
  GMemoryOutputStream * compressed_output_memory;
  GConverter * converter;
  GOutputStream * uncompressed_output;
  gchar * encoded_contents;

  uncompressed_input =
      g_memory_input_stream_new_from_data (contents, size, NULL);

  compressed_output = g_memory_output_stream_new_resizable ();
  compressed_output_memory = G_MEMORY_OUTPUT_STREAM (compressed_output);

  converter = G_CONVERTER (
      g_zlib_compressor_new (G_ZLIB_COMPRESSOR_FORMAT_GZIP, -1));
  uncompressed_output =
      g_converter_output_stream_new (compressed_output, converter);
  g_object_unref (converter);

  g_output_stream_splice (uncompressed_output,
      uncompressed_input, G_OUTPUT_STREAM_SPLICE_CLOSE_SOURCE |
      G_OUTPUT_STREAM_SPLICE_CLOSE_TARGET, NULL, NULL);

  g_object_unref (uncompressed_output);
  g_object_unref (uncompressed_input);

  encoded_contents = g_base64_encode (
      g_memory_output_stream_get_data (compressed_output_memory),
      g_memory_output_stream_get_data_size (compressed_output_memory));

  g_object_unref (compressed_output);

  return encoded_contents;
}

gboolean
gum_memory_vfs_contents_from_string (const gchar * str,
                                     gpointer * contents,
                                     gsize * size)
{
  guchar * data;
  gsize data_size;
  gboolean is_compressed;
  GOutputStream * uncompressed_output;

  data = g_base64_decode (str, &data_size);
  if (data == NULL)
    goto invalid_base64;

  is_compressed = data_size >= 2 && data[0] == 0x1f && data[1] == 0x8b;
  if (is_compressed)
  {
    GInputStream * compressed_input, * uncompressed_input;
    GConverter * converter;
    gssize uncompressed_size;

    compressed_input =
        g_memory_input_stream_new_from_data (data, data_size, g_free);
    converter = G_CONVERTER (
        g_zlib_decompressor_new (G_ZLIB_COMPRESSOR_FORMAT_GZIP));
    uncompressed_input =
        g_converter_input_stream_new (compressed_input, converter);
    g_object_unref (converter);
    g_object_unref (compressed_input);

    uncompressed_output = g_memory_output_stream_new_resizable ();

    uncompressed_size = g_output_stream_splice (uncompressed_output,
        uncompressed_input, G_OUTPUT_STREAM_SPLICE_CLOSE_SOURCE |
        G_OUTPUT_STREAM_SPLICE_CLOSE_TARGET, NULL, NULL);
    g_object_unref (uncompressed_input);
    if (uncompressed_size == -1)
      goto invalid_data;

    *contents = g_memory_output_stream_steal_data (G_MEMORY_OUTPUT_STREAM (
        uncompressed_output));
    *size = uncompressed_size;

    g_object_unref (uncompressed_output);
  }
  else
  {
    *contents = data;
    *size = data_size;
  }

  return TRUE;

invalid_base64:
  {
    return FALSE;
  }
invalid_data:
  {
    g_object_unref (uncompressed_output);
    return FALSE;
  }
}

"""

```