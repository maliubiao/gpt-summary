Response:
The user wants a summary of the functionality of the provided C code snippet, which is part of the `dlmalloc.c` file in the Frida dynamic instrumentation tool. The summary should cover several aspects:

1. **Core Functionality**: What does this code do?
2. **Relationship to Reverse Engineering**: How is this code relevant to reverse engineering?
3. **Low-Level Details**:  How does it interact with the operating system (Linux/Android kernel and frameworks)?
4. **Logical Reasoning (Input/Output)**: Are there any logical deductions or transformations happening? If so, what are the inputs and outputs?
5. **Common Usage Errors**: What are typical mistakes programmers might make that would lead to this code being executed?
6. **User Path to Execution**: How does a user's action eventually lead to this specific code being run (as a debugging clue)?
7. **Overall Functionality (Summary)**: A concise summarization of the code's purpose.

The prompt indicates this is the 4th of a 7-part series, suggesting the focus should be on the specific sections presented here, which deal with:

*   **Tree-based binning for free chunks**: The `malloc_tree_chunk` structure and related logic.
*   **Segment management**: The `malloc_segment` structure and how memory segments are handled.
*   **`malloc_state` structure**: The central structure holding the state of a memory space.
*   **Global parameters**: The `malloc_params` structure.
*   **System allocation setup**:  Macros and functions related to system memory allocation (e.g., `mmap`, `MORECORE`).
*   **Hooks and error handling**:  `PREACTION`, `POSTACTION`, `CORRUPTION_ERROR_ACTION`, `USAGE_ERROR_ACTION`.
*   **Debugging support**: Macros and functions for debugging.
*   **Indexing bins**: Logic for mapping chunk sizes to bin indices.
*   **Operations on bin maps**:  Manipulating bitmaps to track non-empty bins.
*   **Runtime checks**:  Assertions and checks for memory corruption.
*   **Setting `mparams`**: Initialization of global parameters.

**Plan:**

1. **Analyze each section**:  Break down the functionality of the tree bins, segments, `malloc_state`, `mparams`, system allocation, hooks, debugging, indexing, bit manipulation, runtime checks, and `mparams` initialization.
2. **Identify Reverse Engineering Relevance**: Consider how these mechanisms (especially free list management and memory layout) are targets for reverse engineering (e.g., heap exploitation).
3. **Connect to Low-Level Concepts**: Point out interactions with kernel concepts like memory mapping, page sizes, and system calls.
4. **Infer Logical Transformations**:  Describe how the code manipulates data structures (e.g., inserting/removing from trees, consolidating segments). Provide hypothetical input/output examples where applicable.
5. **Consider User Errors**: Think about common memory management errors (e.g., double frees, use-after-free) and how they might be detected or related to this code.
6. **Trace User Actions**:  Imagine a typical scenario where `frida` is used (e.g., hooking a function that allocates memory) and how that leads to the execution of these malloc internals.
7. **Synthesize the Summary**: Combine the findings into a concise summary of the code's functionality.
好的，让我们来分析一下 `frida/subprojects/frida-gum/gum/dlmalloc.c` 文件的第 4 部分代码的功能。

**1. 功能列举:**

这部分代码主要定义和实现了 `dlmalloc` 内存分配器的一些核心数据结构和辅助功能，用于管理和组织空闲的内存块。具体功能包括：

*   **树形结构的空闲块组织 (`malloc_tree_chunk`)**:  定义了用于在树形结构中存储空闲内存块的结构体 `malloc_tree_chunk`。这种结构优化了在较大尺寸范围内查找合适空闲块的速度。
*   **内存段管理 (`malloc_segment`)**: 定义了 `malloc_segment` 结构体，用于管理内存分配器从操作系统获取的不同内存段。这允许分配器处理不连续的内存区域。
*   **内存状态 (`malloc_state`)**: 定义了 `malloc_state` 结构体，这是内存分配器的核心状态管理结构，包含了所有用于跟踪内存使用情况的关键信息，例如：
    *   `smallbins`: 用于存储小尺寸空闲块的双向链表数组。
    *   `treebins`: 指向存储中等和大尺寸空闲块的树形结构根节点的指针数组。
    *   `smallmap`, `treemap`: 位图，用于快速查找非空的 `smallbins` 和 `treebins`。
    *   `top`: 指向当前内存段顶部的空闲块。
    *   `dv`:  指向“指定牺牲块”，用于优化小块内存的分配。
    *   内存段链表 (`seg`)。
*   **全局参数 (`malloc_params`)**: 定义了 `malloc_params` 结构体，存储全局的配置参数，例如页大小、粒度、mmap 阈值等。
*   **系统分配设置**: 定义了一些宏和函数，用于处理与操作系统内存分配相关的操作，例如使用 `mmap` 或 `MORECORE` 获取内存。
*   **钩子函数 (`PREACTION`, `POSTACTION`) 和错误处理 (`CORRUPTION_ERROR_ACTION`, `USAGE_ERROR_ACTION`)**:  定义了一些宏，用于在关键操作前后执行自定义代码（例如加锁/解锁），以及处理检测到的内存错误。
*   **调试支持**:  定义了一些宏（在 `DEBUG` 模式下启用）用于进行运行时检查，例如检查空闲块和已用块的完整性。
*   **索引计算**: 定义了用于将内存块大小映射到 `smallbins` 和 `treebins` 索引的宏。
*   **位图操作**: 定义了用于操作 `smallmap` 和 `treemap` 位图的宏，以快速查找非空的 bin。
*   **运行时检查支持**: 定义了用于在运行时进行各种安全检查的宏，例如检查地址有效性、块状态等。
*   **`mparams` 的设置**: 实现了 `init_mparams` 函数，用于初始化全局参数 `mparams`。

**2. 与逆向方法的联系 (举例说明):**

这部分代码与逆向工程密切相关，因为它揭示了内存分配器的内部工作原理。逆向工程师可以通过分析这段代码来理解目标程序是如何管理内存的，这对于以下逆向任务至关重要：

*   **漏洞挖掘**: 理解内存分配器的结构和机制有助于识别潜在的漏洞，例如堆溢出、double-free 等。例如，逆向工程师可以分析 `check_free_chunk` 和 `check_inuse_chunk` 等调试函数，了解分配器如何检测内存损坏，并思考绕过这些检查的方法。
*   **恶意代码分析**: 恶意代码经常利用堆来进行 shellcode 注入或进行其他攻击。理解目标程序使用的内存分配器可以帮助分析师确定恶意代码的注入点和利用方式。例如，分析空闲链表或树形结构的组织方式，可以找到在释放后被重用的内存块。
*   **程序行为分析**: 理解内存分配模式可以帮助逆向工程师更好地理解程序的运行时行为，例如确定哪些操作会分配大量内存，或者哪些数据结构被频繁地分配和释放。例如，观察 `smallbins` 和 `treebins` 的使用情况，可以推断程序中不同大小对象的分配模式。
*   **动态调试**:  在动态调试过程中，了解内存分配器的结构可以帮助逆向工程师更好地理解内存布局，设置断点以观察特定内存块的状态，以及追踪内存分配和释放的过程。例如，可以监控 `top` 指针的变化来观察内存段的扩展。

**举例说明:**

假设逆向工程师在分析一个存在堆溢出漏洞的程序。通过分析 `dlmalloc.c` 的代码，他们可以了解到：

*   空闲块是通过双向链表 (`smallbins`) 或树形结构 (`treebins`) 来组织的。
*   每个内存块都有头部 (`head`) 记录其大小和状态。
*   程序可能使用了 `FOOTERS` 机制来检测堆损坏。

基于这些知识，逆向工程师可以：

*   在调试器中查看 `smallbins` 或 `treebins` 的状态，找到目标溢出位置附近的空闲块。
*   分析目标程序如何操作内存块的头部，确定溢出是否修改了关键的元数据，例如块大小或状态标志。
*   如果启用了 `FOOTERS`，可以检查溢出是否破坏了块的尾部，导致 `free()` 函数在校验时报错。

**3. 涉及二进制底层，Linux, Android 内核及框架的知识 (举例说明):**

这部分代码深入到二进制底层和操作系统内核的交互：

*   **`mmap` 和 `MORECORE`**: 代码中使用了 `mmap` 和 `MORECORE` (或类似的系统调用) 来从操作系统获取内存。这直接涉及到操作系统内核的内存管理功能。在 Linux 和 Android 中，`mmap` 用于映射文件或匿名内存区域到进程的地址空间，而 `MORECORE` (通常通过 `sbrk` 系统调用实现) 用于扩展进程的数据段。
*   **页大小 (`page_size`) 和粒度 (`granularity`)**: 这些参数直接来源于操作系统内核的信息。页大小是操作系统内存管理的基本单位，而粒度可能与分配器能够向操作系统请求的最小内存单位有关。在 Android 中，这些值可能因设备架构和内核版本而异。
*   **内存对齐 (`MALLOC_ALIGNMENT`)**:  代码中强制内存块按特定字节数对齐，这与 CPU 的架构有关，能够提高内存访问效率。
*   **锁机制 (`USE_LOCKS`, `MLOCK_T`)**: 为了保证多线程环境下的线程安全，内存分配器通常会使用锁。在 Linux 和 Android 中，这通常是 POSIX 线程库提供的互斥锁 (`pthread_mutex_t`)。
*   **虚拟地址空间**:  内存分配器操作的是进程的虚拟地址空间。理解虚拟地址到物理地址的映射是理解内存分配器工作原理的基础。
*   **系统调用**:  `init_mparams` 函数中可能调用了 `open`, `read`, `close` (例如在尝试读取 `/dev/urandom` 时) 以及平台特定的 API (如 Windows 的 `GetSystemInfo`)。

**举例说明:**

*   代码中 `page_align(S)` 宏的定义 `(((S) + (mparams.page_size - SIZE_T_ONE)) & ~(mparams.page_size - SIZE_T_ONE))` 说明了内存分配器在处理 `mmap` 分配时会按照操作系统页的大小进行对齐。这反映了内核内存管理的基本单位。
*   `#ifdef WIN32` 和 `#ifndef WIN32` 的条件编译块表明代码需要处理不同操作系统的内存分配机制差异。例如，Windows 使用 `VirtualAlloc` 等 API，而 Linux 和 Android 主要依赖 `mmap` 和 `brk`/`sbrk`。

**4. 逻辑推理 (假设输入与输出):**

*   **假设输入:**  一个程序请求分配一块大小为 `S` 字节的内存，且该大小落在 `treebins` 的某个区间内。
*   **逻辑推理:**
    1. 分配器首先检查对应的 `treemap` 位图，确定该大小范围的 `treebin` 是否非空。
    2. 如果非空，则访问对应的 `treebin`，它指向一个树形结构的根节点。
    3. 分配器会遍历该树形结构，查找一个大小最合适 (best-fit) 的空闲块。遍历过程涉及到比较请求大小与树节点的大小，并根据比较结果选择遍历左子树或右子树。
    4. 找到合适的空闲块后，可能会将其分割成两部分：一部分满足请求大小，另一部分作为剩余的空闲块放回树中或 `smallbins`。
    5. 更新 `treemap` 位图，如果该 `treebin` 变为空，则清除相应的位。
*   **假设输出:**  返回一个指向新分配内存块的指针。

*   **假设输入:**  一个程序释放一个指向通过 `mmap` 分配的内存块的指针 `P`。
*   **逻辑推理:**
    1. 分配器检查该内存块的头部，判断它是通过 `mmap` 分配的。
    2. 调用操作系统的 `munmap` 系统调用，将该内存区域从进程的地址空间中解除映射。
    3. 可能需要更新内存分配器的内部状态，例如从已分配的内存总量中减去释放的内存大小。
*   **假设输出:**  该内存块被释放，其对应的虚拟地址可以被操作系统回收或重新分配。

**5. 涉及用户或者编程常见的使用错误 (举例说明):**

常见的内存管理错误会导致程序执行到 `dlmalloc.c` 的代码，并且可能触发错误处理机制：

*   **Double Free (重复释放)**: 用户代码尝试释放同一个内存块两次。`dlmalloc` 的调试检查 (如果启用) 可能会在 `free()` 函数中检测到这种情况，因为空闲块会被标记，再次尝试释放已标记为 free 的块会触发错误。`USAGE_ERROR_ACTION` 宏可能会被调用。
*   **Use After Free (释放后使用)**: 用户代码在释放内存块后仍然尝试访问该内存。这可能导致程序崩溃或数据损坏。虽然 `dlmalloc` 本身无法完全阻止这种情况，但其内部结构 (例如空闲链表的修改) 可能会在后续的内存操作中暴露问题。
*   **Heap Overflow (堆溢出)**: 用户代码写入的数据超过了分配的内存块的边界，覆盖了相邻内存块的元数据 (例如 `head`, `prev_foot`) 或其他数据。`dlmalloc` 的调试检查 (例如 `check_free_chunk`, `check_inuse_chunk`) 可能会检测到这种损坏，例如检测到不一致的块大小或状态标志。`CORRUPTION_ERROR_ACTION` 宏可能会被调用。
*   **Invalid Free (释放无效指针)**: 用户代码尝试释放一个不是由 `malloc` 分配的指针，或者指针指向已分配块的中间位置。`dlmalloc` 会进行地址检查 (`ok_address`) 和块状态检查 (`is_inuse`)，如果发现指针无效，则会触发错误处理。

**举例说明:**

假设用户代码中存在 double free 的错误：

```c
char *ptr = malloc(10);
free(ptr);
free(ptr); // 错误：重复释放
```

当第二次调用 `free(ptr)` 时，`dlmalloc` 内部的检查机制可能会发现 `ptr` 指向的内存块已经被标记为空闲，从而触发 `USAGE_ERROR_ACTION`。

**6. 说明用户操作是如何一步步的到达这里，作为调试线索:**

作为调试线索，用户操作如何逐步到达 `dlmalloc.c` 的代码取决于 Frida 的使用场景。以下是一个可能的步骤：

1. **用户使用 Frida hook 目标进程的内存分配或释放函数**:  例如，用户使用 Frida 的 JavaScript API 来 hook `malloc`, `free`, `calloc`, `realloc` 等函数。
    ```javascript
    Interceptor.attach(Module.findExportByName(null, 'malloc'), {
      onEnter: function (args) {
        console.log('malloc called with size:', args[0]);
      },
      onLeave: function (retval) {
        console.log('malloc returned:', retval);
      }
    });
    ```
2. **目标进程执行到被 hook 的内存分配或释放函数**: 当目标进程执行到 `malloc` 函数时，Frida 的拦截器会介入，执行用户定义的 `onEnter` 和 `onLeave` 回调函数。
3. **Frida 的拦截器调用 `dlmalloc` 的实现**: 目标进程的 `malloc` 函数通常会链接到系统提供的 `malloc` 实现，在本例中是 `dlmalloc`。因此，执行被 hook 的 `malloc` 函数实际上会进入 `frida-gum/gum/dlmalloc.c` 的代码。
4. **执行 `dlmalloc` 内部的逻辑**:  根据用户请求的分配大小和当前的内存状态，`dlmalloc` 会执行相应的逻辑，例如查找合适的空闲块、分割块、更新内部数据结构等。用户提供的代码片段就展示了 `dlmalloc` 管理空闲块的数据结构和相关操作。
5. **如果发生错误，可能触发错误处理**: 如果在 `dlmalloc` 的执行过程中检测到内存错误 (例如 double free, heap corruption)，则可能会调用 `CORRUPTION_ERROR_ACTION` 或 `USAGE_ERROR_ACTION` 中定义的行为。

**作为调试线索:**  当用户在使用 Frida 调试目标程序时，如果发现程序在内存分配或释放相关的操作中崩溃或行为异常，就可以利用 Frida hook 这些内存管理函数。通过查看 Frida 的输出日志，用户可以跟踪 `malloc` 和 `free` 的调用情况，包括分配的大小、返回的地址等。如果崩溃发生在 `dlmalloc.c` 内部，结合代码分析和调试器的信息，用户可以定位到具体的错误发生位置，例如在空闲链表操作或树结构遍历时出现问题。

**7. 归纳一下它的功能 (第 4 部分):**

这部分 `dlmalloc.c` 代码主要定义了内存分配器的核心数据结构和管理机制，包括用于组织空闲内存块的树形结构、用于管理内存段的结构、用于维护分配器状态的结构，以及全局参数的定义。它还包含了与操作系统内存分配交互的设置、用于调试和错误处理的钩子和宏，以及用于实现高效空闲块查找的索引和位图操作。总而言之，这部分代码是 `dlmalloc` 分配器的基础骨架，负责内存块的组织、管理和关键参数的维护。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/gum/dlmalloc.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共7部分，请归纳一下它的功能

"""
contains all smaller
  sizes than its right subtree.  However, the node at the root of each
  subtree has no particular ordering relationship to either.  (The
  dividing line between the subtree sizes is based on trie relation.)
  If we remove the last chunk of a given size from the interior of the
  tree, we need to replace it with a leaf node.  The tree ordering
  rules permit a node to be replaced by any leaf below it.

  The smallest chunk in a tree (a common operation in a best-fit
  allocator) can be found by walking a path to the leftmost leaf in
  the tree.  Unlike a usual binary tree, where we follow left child
  pointers until we reach a null, here we follow the right child
  pointer any time the left one is null, until we reach a leaf with
  both child pointers null. The smallest chunk in the tree will be
  somewhere along that path.

  The worst case number of steps to add, find, or remove a node is
  bounded by the number of bits differentiating chunks within
  bins. Under current bin calculations, this ranges from 6 up to 21
  (for 32 bit sizes) or up to 53 (for 64 bit sizes). The typical case
  is of course much better.
*/

struct malloc_tree_chunk {
  /* The first four fields must be compatible with malloc_chunk */
  size_t                    prev_foot;
  size_t                    head;
  struct malloc_tree_chunk* fd;
  struct malloc_tree_chunk* bk;

  struct malloc_tree_chunk* child[2];
  struct malloc_tree_chunk* parent;
  bindex_t                  index;
};

typedef struct malloc_tree_chunk  tchunk;
typedef struct malloc_tree_chunk* tchunkptr;
typedef struct malloc_tree_chunk* tbinptr; /* The type of bins of trees */

/* A little helper macro for trees */
#define leftmost_child(t) ((t)->child[0] != 0? (t)->child[0] : (t)->child[1])

/* ----------------------------- Segments -------------------------------- */

/*
  Each malloc space may include non-contiguous segments, held in a
  list headed by an embedded malloc_segment record representing the
  top-most space. Segments also include flags holding properties of
  the space. Large chunks that are directly allocated by mmap are not
  included in this list. They are instead independently created and
  destroyed without otherwise keeping track of them.

  Segment management mainly comes into play for spaces allocated by
  MMAP.  Any call to MMAP might or might not return memory that is
  adjacent to an existing segment.  MORECORE normally contiguously
  extends the current space, so this space is almost always adjacent,
  which is simpler and faster to deal with. (This is why MORECORE is
  used preferentially to MMAP when both are available -- see
  sys_alloc.)  When allocating using MMAP, we don't use any of the
  hinting mechanisms (inconsistently) supported in various
  implementations of unix mmap, or distinguish reserving from
  committing memory. Instead, we just ask for space, and exploit
  contiguity when we get it.  It is probably possible to do
  better than this on some systems, but no general scheme seems
  to be significantly better.

  Management entails a simpler variant of the consolidation scheme
  used for chunks to reduce fragmentation -- new adjacent memory is
  normally prepended or appended to an existing segment. However,
  there are limitations compared to chunk consolidation that mostly
  reflect the fact that segment processing is relatively infrequent
  (occurring only when getting memory from system) and that we
  don't expect to have huge numbers of segments:

  * Segments are not indexed, so traversal requires linear scans.  (It
    would be possible to index these, but is not worth the extra
    overhead and complexity for most programs on most platforms.)
  * New segments are only appended to old ones when holding top-most
    memory; if they cannot be prepended to others, they are held in
    different segments.

  Except for the top-most segment of an mstate, each segment record
  is kept at the tail of its segment. Segments are added by pushing
  segment records onto the list headed by &mstate.seg for the
  containing mstate.

  Segment flags control allocation/merge/deallocation policies:
  * If EXTERN_BIT set, then we did not allocate this segment,
    and so should not try to deallocate or merge with others.
    (This currently holds only for the initial segment passed
    into create_mspace_with_base.)
  * If USE_MMAP_BIT set, the segment may be merged with
    other surrounding mmapped segments and trimmed/de-allocated
    using munmap.
  * If neither bit is set, then the segment was obtained using
    MORECORE so can be merged with surrounding MORECORE'd segments
    and deallocated/trimmed using MORECORE with negative arguments.
*/

struct malloc_segment {
  char*        base;             /* base address */
  size_t       size;             /* allocated size */
  struct malloc_segment* next;   /* ptr to next segment */
  flag_t       sflags;           /* mmap and extern flag */
};

#define is_mmapped_segment(S)  ((S)->sflags & USE_MMAP_BIT)
#define is_extern_segment(S)   ((S)->sflags & EXTERN_BIT)

typedef struct malloc_segment  msegment;
typedef struct malloc_segment* msegmentptr;

/* ---------------------------- malloc_state ----------------------------- */

/*
   A malloc_state holds all of the bookkeeping for a space.
   The main fields are:

  Top
    The topmost chunk of the currently active segment. Its size is
    cached in topsize.  The actual size of topmost space is
    topsize+TOP_FOOT_SIZE, which includes space reserved for adding
    fenceposts and segment records if necessary when getting more
    space from the system.  The size at which to autotrim top is
    cached from mparams in trim_check, except that it is disabled if
    an autotrim fails.

  Designated victim (dv)
    This is the preferred chunk for servicing small requests that
    don't have exact fits.  It is normally the chunk split off most
    recently to service another small request.  Its size is cached in
    dvsize. The link fields of this chunk are not maintained since it
    is not kept in a bin.

  SmallBins
    An array of bin headers for free chunks.  These bins hold chunks
    with sizes less than MIN_LARGE_SIZE bytes. Each bin contains
    chunks of all the same size, spaced 8 bytes apart.  To simplify
    use in double-linked lists, each bin header acts as a malloc_chunk
    pointing to the real first node, if it exists (else pointing to
    itself).  This avoids special-casing for headers.  But to avoid
    waste, we allocate only the fd/bk pointers of bins, and then use
    repositioning tricks to treat these as the fields of a chunk.

  TreeBins
    Treebins are pointers to the roots of trees holding a range of
    sizes. There are 2 equally spaced treebins for each power of two
    from TREE_SHIFT to TREE_SHIFT+16. The last bin holds anything
    larger.

  Bin maps
    There is one bit map for small bins ("smallmap") and one for
    treebins ("treemap).  Each bin sets its bit when non-empty, and
    clears the bit when empty.  Bit operations are then used to avoid
    bin-by-bin searching -- nearly all "search" is done without ever
    looking at bins that won't be selected.  The bit maps
    conservatively use 32 bits per map word, even if on 64bit system.
    For a good description of some of the bit-based techniques used
    here, see Henry S. Warren Jr's book "Hacker's Delight" (and
    supplement at http://hackersdelight.org/). Many of these are
    intended to reduce the branchiness of paths through malloc etc, as
    well as to reduce the number of memory locations read or written.

  Segments
    A list of segments headed by an embedded malloc_segment record
    representing the initial space.

  Address check support
    The least_addr field is the least address ever obtained from
    MORECORE or MMAP. Attempted frees and reallocs of any address less
    than this are trapped (unless INSECURE is defined).

  Magic tag
    A cross-check field that should always hold same value as mparams.magic.

  Max allowed footprint
    The maximum allowed bytes to allocate from system (zero means no limit)

  Flags
    Bits recording whether to use MMAP, locks, or contiguous MORECORE

  Statistics
    Each space keeps track of current and maximum system memory
    obtained via MORECORE or MMAP.

  Trim support
    Fields holding the amount of unused topmost memory that should trigger
    trimming, and a counter to force periodic scanning to release unused
    non-topmost segments.

  Locking
    If USE_LOCKS is defined, the "mutex" lock is acquired and released
    around every public call using this mspace.

  Extension support
    A void* pointer and a size_t field that can be used to help implement
    extensions to this malloc.
*/

/* Bin types, widths and sizes */
#define NSMALLBINS        (32U)
#define NTREEBINS         (32U)
#define SMALLBIN_SHIFT    (3U)
#define SMALLBIN_WIDTH    (SIZE_T_ONE << SMALLBIN_SHIFT)
#define TREEBIN_SHIFT     (8U)
#define MIN_LARGE_SIZE    (SIZE_T_ONE << TREEBIN_SHIFT)
#define MAX_SMALL_SIZE    (MIN_LARGE_SIZE - SIZE_T_ONE)
#define MAX_SMALL_REQUEST (MAX_SMALL_SIZE - CHUNK_ALIGN_MASK - CHUNK_OVERHEAD)

struct malloc_state {
  binmap_t   smallmap;
  binmap_t   treemap;
  size_t     dvsize;
  size_t     topsize;
  char*      least_addr;
  mchunkptr  dv;
  mchunkptr  top;
  size_t     trim_check;
  size_t     release_checks;
  size_t     magic;
  mchunkptr  smallbins[(NSMALLBINS+1)*2];
  tbinptr    treebins[NTREEBINS];
  size_t     footprint;
  size_t     max_footprint;
  size_t     footprint_limit; /* zero means no limit */
  flag_t     mflags;
#if USE_LOCKS
  MLOCK_T    mutex;     /* locate lock among fields that rarely change */
#endif /* USE_LOCKS */
  msegment   seg;
  void*      extp;      /* Unused but available for extensions */
  size_t     exts;
};

typedef struct malloc_state*    mstate;

/* ------------- Global malloc_state and malloc_params ------------------- */

/*
  malloc_params holds global properties, including those that can be
  dynamically set using mallopt. There is a single instance, mparams,
  initialized in init_mparams. Note that the non-zeroness of "magic"
  also serves as an initialization flag.
*/

struct malloc_params {
  size_t magic;
  size_t page_size;
  size_t granularity;
  size_t mmap_threshold;
  size_t trim_threshold;
  flag_t default_mflags;
};

static struct malloc_params mparams;

/* Ensure mparams initialized */
#define ensure_initialization() (void)(mparams.magic != 0 || init_mparams())

#if !ONLY_MSPACES

/* The global malloc_state used for all non-"mspace" calls */
static struct malloc_state _gm_;
#define gm                 (&_gm_)
#define is_global(M)       ((M) == &_gm_)

#endif /* !ONLY_MSPACES */

#define is_initialized(M)  ((M)->top != 0)

/* -------------------------- system alloc setup ------------------------- */

/* Operations on mflags */

#define use_lock(M)           ((M)->mflags &   USE_LOCK_BIT)
#define enable_lock(M)        ((M)->mflags |=  USE_LOCK_BIT)
#if USE_LOCKS
#define disable_lock(M)       ((M)->mflags &= ~USE_LOCK_BIT)
#else
#define disable_lock(M)
#endif

#define use_mmap(M)           ((M)->mflags &   USE_MMAP_BIT)
#define enable_mmap(M)        ((M)->mflags |=  USE_MMAP_BIT)
#if HAVE_MMAP
#define disable_mmap(M)       ((M)->mflags &= ~USE_MMAP_BIT)
#else
#define disable_mmap(M)
#endif

#define use_noncontiguous(M)  ((M)->mflags &   USE_NONCONTIGUOUS_BIT)
#define disable_contiguous(M) ((M)->mflags |=  USE_NONCONTIGUOUS_BIT)

#define set_lock(M,L)\
 ((M)->mflags = (L)?\
  ((M)->mflags | USE_LOCK_BIT) :\
  ((M)->mflags & ~USE_LOCK_BIT))

/* page-align a size */
#define page_align(S)\
 (((S) + (mparams.page_size - SIZE_T_ONE)) & ~(mparams.page_size - SIZE_T_ONE))

/* granularity-align a size */
#define granularity_align(S)\
  (((S) + (mparams.granularity - SIZE_T_ONE))\
   & ~(mparams.granularity - SIZE_T_ONE))


/* For mmap, use granularity alignment on windows, else page-align */
#ifdef WIN32
#define mmap_align(S) granularity_align(S)
#else
#define mmap_align(S) page_align(S)
#endif

/* For sys_alloc, enough padding to ensure can malloc request on success */
#define SYS_ALLOC_PADDING (TOP_FOOT_SIZE + MALLOC_ALIGNMENT)

#define is_page_aligned(S)\
   (((size_t)(S) & (mparams.page_size - SIZE_T_ONE)) == 0)
#define is_granularity_aligned(S)\
   (((size_t)(S) & (mparams.granularity - SIZE_T_ONE)) == 0)

/*  True if segment S holds address A */
#define segment_holds(S, A)\
  ((char*)(A) >= S->base && (char*)(A) < S->base + S->size)

/* Return segment holding given address */
static msegmentptr segment_holding(mstate m, char* addr) {
  msegmentptr sp = &m->seg;
  for (;;) {
    if (addr >= sp->base && addr < sp->base + sp->size)
      return sp;
    if ((sp = sp->next) == 0)
      return 0;
  }
}

/* Return true if segment contains a segment link */
static int has_segment_link(mstate m, msegmentptr ss) {
  msegmentptr sp = &m->seg;
  for (;;) {
    if ((char*)sp >= ss->base && (char*)sp < ss->base + ss->size)
      return 1;
    if ((sp = sp->next) == 0)
      return 0;
  }
}

#ifndef MORECORE_CANNOT_TRIM
#define should_trim(M,s)  ((s) > (M)->trim_check)
#else  /* MORECORE_CANNOT_TRIM */
#define should_trim(M,s)  (0)
#endif /* MORECORE_CANNOT_TRIM */

/*
  TOP_FOOT_SIZE is padding at the end of a segment, including space
  that may be needed to place segment records and fenceposts when new
  noncontiguous segments are added.
*/
#define TOP_FOOT_SIZE\
  (align_offset(chunk2mem(0))+pad_request(sizeof(struct malloc_segment))+MIN_CHUNK_SIZE)


/* -------------------------------  Hooks -------------------------------- */

/*
  PREACTION should be defined to return 0 on success, and nonzero on
  failure. If you are not using locking, you can redefine these to do
  anything you like.
*/

#if USE_LOCKS
#define PREACTION(M)  ((use_lock(M))? ACQUIRE_LOCK(&(M)->mutex) : 0)
#define POSTACTION(M) { if (use_lock(M)) RELEASE_LOCK(&(M)->mutex); }
#else /* USE_LOCKS */

#ifndef PREACTION
#define PREACTION(M) (0)
#endif  /* PREACTION */

#ifndef POSTACTION
#define POSTACTION(M)
#endif  /* POSTACTION */

#endif /* USE_LOCKS */

/*
  CORRUPTION_ERROR_ACTION is triggered upon detected bad addresses.
  USAGE_ERROR_ACTION is triggered on detected bad frees and
  reallocs. The argument p is an address that might have triggered the
  fault. It is ignored by the two predefined actions, but might be
  useful in custom actions that try to help diagnose errors.
*/

#if PROCEED_ON_ERROR

/* A count of the number of corruption errors causing resets */
int malloc_corruption_error_count;

/* default corruption action */
static void reset_on_error(mstate m);

#define CORRUPTION_ERROR_ACTION(m)  reset_on_error(m)
#define USAGE_ERROR_ACTION(m, p)

#else /* PROCEED_ON_ERROR */

#ifndef CORRUPTION_ERROR_ACTION
#define CORRUPTION_ERROR_ACTION(m) ABORT
#endif /* CORRUPTION_ERROR_ACTION */

#ifndef USAGE_ERROR_ACTION
#define USAGE_ERROR_ACTION(m,p) ABORT
#endif /* USAGE_ERROR_ACTION */

#endif /* PROCEED_ON_ERROR */


/* -------------------------- Debugging setup ---------------------------- */

#if ! DEBUG

#define check_free_chunk(M,P)
#define check_inuse_chunk(M,P)
#define check_malloced_chunk(M,P,N)
#define check_mmapped_chunk(M,P)
#define check_malloc_state(M)
#define check_top_chunk(M,P)

#else /* DEBUG */
#define check_free_chunk(M,P)       do_check_free_chunk(M,P)
#define check_inuse_chunk(M,P)      do_check_inuse_chunk(M,P)
#define check_top_chunk(M,P)        do_check_top_chunk(M,P)
#define check_malloced_chunk(M,P,N) do_check_malloced_chunk(M,P,N)
#define check_mmapped_chunk(M,P)    do_check_mmapped_chunk(M,P)
#define check_malloc_state(M)       do_check_malloc_state(M)

static void   do_check_any_chunk(mstate m, mchunkptr p);
static void   do_check_top_chunk(mstate m, mchunkptr p);
static void   do_check_mmapped_chunk(mstate m, mchunkptr p);
static void   do_check_inuse_chunk(mstate m, mchunkptr p);
static void   do_check_free_chunk(mstate m, mchunkptr p);
static void   do_check_malloced_chunk(mstate m, void* mem, size_t s);
static void   do_check_tree(mstate m, tchunkptr t);
static void   do_check_treebin(mstate m, bindex_t i);
static void   do_check_smallbin(mstate m, bindex_t i);
static void   do_check_malloc_state(mstate m);
static int    bin_find(mstate m, mchunkptr x);
static size_t traverse_and_check(mstate m);
#endif /* DEBUG */

/* ---------------------------- Indexing Bins ---------------------------- */

#define is_small(s)         (((s) >> SMALLBIN_SHIFT) < NSMALLBINS)
#define small_index(s)      (bindex_t)((s)  >> SMALLBIN_SHIFT)
#define small_index2size(i) ((i)  << SMALLBIN_SHIFT)
#define MIN_SMALL_INDEX     (small_index(MIN_CHUNK_SIZE))

/* addressing by index. See above about smallbin repositioning */
#define smallbin_at(M, i)   ((sbinptr)((char*)&((M)->smallbins[(i)<<1])))
#define treebin_at(M,i)     (&((M)->treebins[i]))

/* assign tree index for size S to variable I. Use x86 asm if possible  */
#if defined(__GNUC__) && (defined(__i386__) || defined(__x86_64__))
#define compute_tree_index(S, I)\
{\
  unsigned int X = S >> TREEBIN_SHIFT;\
  if (X == 0)\
    I = 0;\
  else if (X > 0xFFFF)\
    I = NTREEBINS-1;\
  else {\
    unsigned int K = (unsigned) sizeof(X)*__CHAR_BIT__ - 1 - (unsigned) __builtin_clz(X); \
    I =  (bindex_t)((K << 1) + ((S >> (K + (TREEBIN_SHIFT-1)) & 1)));\
  }\
}

#elif defined (__INTEL_COMPILER)
#define compute_tree_index(S, I)\
{\
  size_t X = S >> TREEBIN_SHIFT;\
  if (X == 0)\
    I = 0;\
  else if (X > 0xFFFF)\
    I = NTREEBINS-1;\
  else {\
    unsigned int K = _bit_scan_reverse (X); \
    I =  (bindex_t)((K << 1) + ((S >> (K + (TREEBIN_SHIFT-1)) & 1)));\
  }\
}

#elif defined(_MSC_VER) && _MSC_VER>=1300
#define compute_tree_index(S, I)\
{\
  size_t X = S >> TREEBIN_SHIFT;\
  if (X == 0)\
    I = 0;\
  else if (X > 0xFFFF)\
    I = NTREEBINS-1;\
  else {\
    unsigned int K;\
    _BitScanReverse((DWORD *) &K, (DWORD) X);\
    I =  (bindex_t)((K << 1) + ((S >> (K + (TREEBIN_SHIFT-1)) & 1)));\
  }\
}

#else /* GNUC */
#define compute_tree_index(S, I)\
{\
  size_t X = S >> TREEBIN_SHIFT;\
  if (X == 0)\
    I = 0;\
  else if (X > 0xFFFF)\
    I = NTREEBINS-1;\
  else {\
    unsigned int Y = (unsigned int)X;\
    unsigned int N = ((Y - 0x100) >> 16) & 8;\
    unsigned int K = (((Y <<= N) - 0x1000) >> 16) & 4;\
    N += K;\
    N += K = (((Y <<= K) - 0x4000) >> 16) & 2;\
    K = 14 - N + ((Y <<= K) >> 15);\
    I = (K << 1) + ((S >> (K + (TREEBIN_SHIFT-1)) & 1));\
  }\
}
#endif /* GNUC */

/* Bit representing maximum resolved size in a treebin at i */
#define bit_for_tree_index(i) \
   (i == NTREEBINS-1)? (SIZE_T_BITSIZE-1) : (((i) >> 1) + TREEBIN_SHIFT - 2)

/* Shift placing maximum resolved bit in a treebin at i as sign bit */
#define leftshift_for_tree_index(i) \
   ((i == NTREEBINS-1)? 0 : \
    ((SIZE_T_BITSIZE-SIZE_T_ONE) - (((i) >> 1) + TREEBIN_SHIFT - 2)))

/* The size of the smallest chunk held in bin with index i */
#define minsize_for_tree_index(i) \
   ((SIZE_T_ONE << (((i) >> 1) + TREEBIN_SHIFT)) |  \
   (((size_t)((i) & SIZE_T_ONE)) << (((i) >> 1) + TREEBIN_SHIFT - 1)))


/* ------------------------ Operations on bin maps ----------------------- */

/* bit corresponding to given index */
#define idx2bit(i)              ((binmap_t)(1) << (i))

/* Mark/Clear bits with given index */
#define mark_smallmap(M,i)      ((M)->smallmap |=  idx2bit(i))
#define clear_smallmap(M,i)     ((M)->smallmap &= ~idx2bit(i))
#define smallmap_is_marked(M,i) ((M)->smallmap &   idx2bit(i))

#define mark_treemap(M,i)       ((M)->treemap  |=  idx2bit(i))
#define clear_treemap(M,i)      ((M)->treemap  &= ~idx2bit(i))
#define treemap_is_marked(M,i)  ((M)->treemap  &   idx2bit(i))

/* isolate the least set bit of a bitmap */
#define least_bit(x)         ((x) & -(x))

/* mask with all bits to left of least bit of x on */
#define left_bits(x)         ((x<<1) | -(x<<1))

/* mask with all bits to left of or equal to least bit of x on */
#define same_or_left_bits(x) ((x) | -(x))

/* index corresponding to given bit. Use x86 asm if possible */

#if defined(__GNUC__) && (defined(__i386__) || defined(__x86_64__))
#define compute_bit2idx(X, I)\
{\
  unsigned int J;\
  J = __builtin_ctz(X); \
  I = (bindex_t)J;\
}

#elif defined (__INTEL_COMPILER)
#define compute_bit2idx(X, I)\
{\
  unsigned int J;\
  J = _bit_scan_forward (X); \
  I = (bindex_t)J;\
}

#elif defined(_MSC_VER) && _MSC_VER>=1300
#define compute_bit2idx(X, I)\
{\
  unsigned int J;\
  _BitScanForward((DWORD *) &J, X);\
  I = (bindex_t)J;\
}

#elif USE_BUILTIN_FFS
#define compute_bit2idx(X, I) I = ffs(X)-1

#else
#define compute_bit2idx(X, I)\
{\
  unsigned int Y = X - 1;\
  unsigned int K = Y >> (16-4) & 16;\
  unsigned int N = K;        Y >>= K;\
  N += K = Y >> (8-3) &  8;  Y >>= K;\
  N += K = Y >> (4-2) &  4;  Y >>= K;\
  N += K = Y >> (2-1) &  2;  Y >>= K;\
  N += K = Y >> (1-0) &  1;  Y >>= K;\
  I = (bindex_t)(N + Y);\
}
#endif /* GNUC */


/* ----------------------- Runtime Check Support ------------------------- */

/*
  For security, the main invariant is that malloc/free/etc never
  writes to a static address other than malloc_state, unless static
  malloc_state itself has been corrupted, which cannot occur via
  malloc (because of these checks). In essence this means that we
  believe all pointers, sizes, maps etc held in malloc_state, but
  check all of those linked or offsetted from other embedded data
  structures.  These checks are interspersed with main code in a way
  that tends to minimize their run-time cost.

  When FOOTERS is defined, in addition to range checking, we also
  verify footer fields of inuse chunks, which can be used guarantee
  that the mstate controlling malloc/free is intact.  This is a
  streamlined version of the approach described by William Robertson
  et al in "Run-time Detection of Heap-based Overflows" LISA'03
  http://www.usenix.org/events/lisa03/tech/robertson.html The footer
  of an inuse chunk holds the xor of its mstate and a random seed,
  that is checked upon calls to free() and realloc().  This is
  (probabalistically) unguessable from outside the program, but can be
  computed by any code successfully malloc'ing any chunk, so does not
  itself provide protection against code that has already broken
  security through some other means.  Unlike Robertson et al, we
  always dynamically check addresses of all offset chunks (previous,
  next, etc). This turns out to be cheaper than relying on hashes.
*/

#if !INSECURE
/* Check if address a is at least as high as any from MORECORE or MMAP */
#define ok_address(M, a) ((char*)(a) >= (M)->least_addr)
/* Check if address of next chunk n is higher than base chunk p */
#define ok_next(p, n)    ((char*)(p) < (char*)(n))
/* Check if p has inuse status */
#define ok_inuse(p)     is_inuse(p)
/* Check if p has its pinuse bit on */
#define ok_pinuse(p)     pinuse(p)

#else /* !INSECURE */
#define ok_address(M, a) (1)
#define ok_next(b, n)    (1)
#define ok_inuse(p)      (1)
#define ok_pinuse(p)     (1)
#endif /* !INSECURE */

#if (FOOTERS && !INSECURE)
/* Check if (alleged) mstate m has expected magic field */
#define ok_magic(M)      ((M)->magic == mparams.magic)
#else  /* (FOOTERS && !INSECURE) */
#define ok_magic(M)      (1)
#endif /* (FOOTERS && !INSECURE) */

/* In gcc, use __builtin_expect to minimize impact of checks */
#if !INSECURE
#if defined(__GNUC__) && __GNUC__ >= 3
#define RTCHECK(e)  __builtin_expect(e, 1)
#else /* GNUC */
#define RTCHECK(e)  (e)
#endif /* GNUC */
#else /* !INSECURE */
#define RTCHECK(e)  (1)
#endif /* !INSECURE */

/* macros to set up inuse chunks with or without footers */

#if !FOOTERS

#define mark_inuse_foot(M,p,s)

/* Macros for setting head/foot of non-mmapped chunks */

/* Set cinuse bit and pinuse bit of next chunk */
#define set_inuse(M,p,s)\
  ((p)->head = (((p)->head & PINUSE_BIT)|s|CINUSE_BIT),\
  ((mchunkptr)(((char*)(p)) + (s)))->head |= PINUSE_BIT)

/* Set cinuse and pinuse of this chunk and pinuse of next chunk */
#define set_inuse_and_pinuse(M,p,s)\
  ((p)->head = (s|PINUSE_BIT|CINUSE_BIT),\
  ((mchunkptr)(((char*)(p)) + (s)))->head |= PINUSE_BIT)

/* Set size, cinuse and pinuse bit of this chunk */
#define set_size_and_pinuse_of_inuse_chunk(M, p, s)\
  ((p)->head = (s|PINUSE_BIT|CINUSE_BIT))

#else /* FOOTERS */

/* Set foot of inuse chunk to be xor of mstate and seed */
#define mark_inuse_foot(M,p,s)\
  (((mchunkptr)((char*)(p) + (s)))->prev_foot = ((size_t)(M) ^ mparams.magic))

#define get_mstate_for(p)\
  ((mstate)(((mchunkptr)((char*)(p) +\
    (chunksize(p))))->prev_foot ^ mparams.magic))

#define set_inuse(M,p,s)\
  ((p)->head = (((p)->head & PINUSE_BIT)|s|CINUSE_BIT),\
  (((mchunkptr)(((char*)(p)) + (s)))->head |= PINUSE_BIT), \
  mark_inuse_foot(M,p,s))

#define set_inuse_and_pinuse(M,p,s)\
  ((p)->head = (s|PINUSE_BIT|CINUSE_BIT),\
  (((mchunkptr)(((char*)(p)) + (s)))->head |= PINUSE_BIT),\
 mark_inuse_foot(M,p,s))

#define set_size_and_pinuse_of_inuse_chunk(M, p, s)\
  ((p)->head = (s|PINUSE_BIT|CINUSE_BIT),\
  mark_inuse_foot(M, p, s))

#endif /* !FOOTERS */

/* ---------------------------- setting mparams -------------------------- */

#if LOCK_AT_FORK
static void pre_fork(void)         { ACQUIRE_LOCK(&(gm)->mutex); }
static void post_fork_parent(void) { RELEASE_LOCK(&(gm)->mutex); }
static void post_fork_child(void)  { INITIAL_LOCK(&(gm)->mutex); }
#endif /* LOCK_AT_FORK */

/* Initialize mparams */
static int init_mparams(void) {
#ifdef NEED_GLOBAL_LOCK_INIT
  if (malloc_global_mutex_status <= 0)
    init_malloc_global_mutex();
#endif

  ACQUIRE_MALLOC_GLOBAL_LOCK();
  if (mparams.magic == 0) {
    size_t magic;
    size_t psize;
    size_t gsize;

#ifndef WIN32
    psize = malloc_getpagesize;
    gsize = ((DEFAULT_GRANULARITY != 0)? DEFAULT_GRANULARITY : psize);
#else /* WIN32 */
    {
      SYSTEM_INFO system_info;
      GetSystemInfo(&system_info);
      psize = system_info.dwPageSize;
      gsize = ((DEFAULT_GRANULARITY != 0)?
               DEFAULT_GRANULARITY : system_info.dwAllocationGranularity);
    }
#endif /* WIN32 */

    /* Sanity-check configuration:
       size_t must be unsigned and as wide as pointer type.
       ints must be at least 4 bytes.
       alignment must be at least 8.
       Alignment, min chunk size, and page size must all be powers of 2.
    */
    if ((sizeof(size_t) != sizeof(char*)) ||
        (MAX_SIZE_T < MIN_CHUNK_SIZE)  ||
        (sizeof(int) < 4)  ||
        (MALLOC_ALIGNMENT < (size_t)8U) ||
        ((MALLOC_ALIGNMENT & (MALLOC_ALIGNMENT-SIZE_T_ONE)) != 0) ||
        ((MCHUNK_SIZE      & (MCHUNK_SIZE-SIZE_T_ONE))      != 0) ||
        ((gsize            & (gsize-SIZE_T_ONE))            != 0) ||
        ((psize            & (psize-SIZE_T_ONE))            != 0))
      ABORT;
    mparams.granularity = gsize;
    mparams.page_size = psize;
    mparams.mmap_threshold = DEFAULT_MMAP_THRESHOLD;
    mparams.trim_threshold = DEFAULT_TRIM_THRESHOLD;
#if MORECORE_CONTIGUOUS
    mparams.default_mflags = USE_LOCK_BIT|USE_MMAP_BIT;
#else  /* MORECORE_CONTIGUOUS */
    mparams.default_mflags = USE_LOCK_BIT|USE_MMAP_BIT|USE_NONCONTIGUOUS_BIT;
#endif /* MORECORE_CONTIGUOUS */

#if !ONLY_MSPACES
    /* Set up lock for main malloc area */
    gm->mflags = mparams.default_mflags;
    (void)INITIAL_LOCK(&gm->mutex);
#endif
#if LOCK_AT_FORK
    pthread_atfork(&pre_fork, &post_fork_parent, &post_fork_child);
#endif

    {
#if USE_DEV_RANDOM
      int fd;
      unsigned char buf[sizeof(size_t)];
      /* Try to use /dev/urandom, else fall back on using time */
      if ((fd = open("/dev/urandom", O_RDONLY)) >= 0 &&
          read(fd, buf, sizeof(buf)) == sizeof(buf)) {
        magic = *((size_t *) buf);
        close(fd);
      }
      else
#endif /* USE_DEV_RANDOM */
#ifdef WIN32
      magic = (size_t)(GetTickCount() ^ (size_t)0x55555555U);
#elif defined(LACKS_TIME_H)
      magic = (size_t)&magic ^ (size_t)0x55555555U;
#else
      magic = (size_t)(time(0) ^ (size_t)0x55555555U);
#endif
      magic |= (size_t)8U;    /* ensure nonzero */
      magic &= ~(size_t)7U;   /* improve chances of fault for bad values */
      /* Until memory modes commonly available, use volatile-write */
      (*(volatile size_t *)(&(mparams.magic))) = magic;
    }
  }

  RELEASE_MALLOC_GLOBAL_LOCK();
  return 1;
}

/* support for mallopt */
static int change_mparam(int param_number, int value) {
  size_t val;
  ensure_initialization();
  val = (value == -1)? MAX_SIZE_T : (size_t)value;
  switch(param_number) {
  case M_TRIM_THRESHOLD:
    mparams.trim_threshold = val;
    return 1;
  case M_GRANULARITY:
    if (val >= mparams.page_size && ((val & (val-1)) == 0)) {
      mparams.granularity = val;
      return 1;
    }
    else
      return 0;
  case M_MMAP_THRESHOLD:
    mparams.mmap_threshold = val;
    return 1;
  default:
    return 0;
  }
}

#if DEBUG
/* ------------------------- Debugging Support --------------------------- */

/* Check properties of any chunk, whether free, inuse, mmapped etc  */
static void do_check_any_chunk(mstate m, mchunkptr p) {
  assert((is_aligned(chunk2mem(p))) || (p->head == FENCEPOST_HEAD));
  assert(ok_address(m, p));
}

/* Check properties of top chunk */
static void do_check_top_chunk(mstate m, mchunkptr p) {
  msegmentptr sp = segment_holding(m, (char*)p);
  size_t  sz = p->head & ~INUSE_BITS; /* third-lowest bit can be set! */
  assert(sp != 0);
  assert((is_aligned(chunk2mem(p))) || (p->head == FENCEPOST_HEAD));
  assert(ok_address(m, p));
  assert(sz == m->topsize);
  assert(sz > 0);
  assert(sz == ((sp->base + sp->size) - (char*)p) - TOP_FOOT_SIZE);
  assert(pinuse(p));
  assert(!pinuse(chunk_plus_offset(p, sz)));
}

/* Check properties of (inuse) mmapped chunks */
static void do_check_mmapped_chunk(mstate m, mchunkptr p) {
  size_t  sz = chunksize(p);
  size_t len = (sz + (p->prev_foot) + MMAP_FOOT_PAD);
  assert(is_mmapped(p));
  assert(use_mmap(m));
  assert((is_aligned(chunk2mem(p))) || (p->head == FENCEPOST_HEAD));
  assert(ok_address(m, p));
  assert(!is_small(sz));
  assert((len & (mparams.page_size-SIZE_T_ONE)) == 0);
  assert(chunk_plus_offset(p, sz)->head == FENCEPOST_HEAD);
  assert(chunk_plus_offset(p, sz+SIZE_T_SIZE)->head == 0);
}

/* Check properties of inuse chunks */
static void do_check_inuse_chunk(mstate m, mchunkptr p) {
  do_check_any_chunk(m, p);
  assert(is_inuse(p));
  assert(next_pinuse(p));
  /* If not pinuse and not mmapped, previous chunk has OK offset */
  assert(is_mmapped(p) || pinuse(p) || next_chunk(prev_chunk(p)) == p);
  if (is_mmapped(p))
    do_check_mmapped_chunk(m, p);
}

/* Check properties of free chunks */
static void do_check_free_chunk(mstate m, mchunkptr p) {
  size_t sz = chunksize(p);
  mchunkptr next = chunk_plus_offset(p, sz);
  do_check_any_chunk(m, p);
  assert(!is_inuse(p));
  assert(!next_pinuse(p));
  assert (!is_mmapped(p));
  if (p != m->dv && p != m->top) {
    if (sz >= MIN_CHUNK_SIZE) {
      assert((sz & CHUNK_ALIGN_MASK) == 0);
      assert(is_aligned(chunk2mem(p)));
      assert(next->prev_foot == sz);
      assert(pinuse(p));
      assert (next == m->top || is_inuse(next));
      assert(p->fd->bk == p);
      assert(p->bk->fd == p);
    }
    else  /* markers are always of size SIZE_T_SIZE */
      assert(sz == SIZE_T_SIZE);
  }
}

/* Check properties of malloced chunks at the point they are malloced */
static void do_check_malloced_chunk(mstate m, void* mem, size_t s) {
  if (mem != 0) {
    mchunkptr p = mem2chunk(mem);
    size_t sz = p->head & ~INUSE_BITS;
    do_check_inuse_chunk(m, p);
    assert((sz & CHUNK_ALIGN_MASK) == 0);
    assert(sz >= MIN_CHUNK_SIZE);
    assert(sz >= s);
    /* unless mmapped, size is less than MIN_CHUNK_SIZE more than request */
    assert(is_mmapped(p) || sz < (s + MIN_CHUNK_SIZE));
  }
}

/* Check a tree and its subtrees.  */
static void do_check_tree(mstate m, tchunkptr t) {
  tchunkptr head = 0;
  tchunkptr u = t;
  bindex_t tindex = t->index;
  size_t tsize = chunksize(t);
  bindex_t idx;
  compute_tree_index(tsize, idx);
  assert(tindex == idx);
  assert(tsize >= MIN_LARGE_SIZE);
  assert(tsize >= minsize_for_tree_index(idx));
  assert((idx == NTREEBINS-1) || (tsize < minsize_for_tree_index((idx+1))));

  do { /* traverse through chain of same-sized nodes */
    do_check_any_chunk(m, ((mchunkptr)u));
    assert(u->index == tindex);
    assert(chunksize(u) == tsize);
    assert(!is_inuse(u));
    assert(!next_pinuse(u));
    assert(u->fd->bk == u);
    assert(u->bk->fd == u);
    if (u->parent == 0) {
      assert(u->child[0] == 0);
      assert(u->child[1] == 0);
    }
    else {
      assert(head == 0); /* only one node on chain has parent */
      head = u;
      assert(u->parent != u);
      assert (u
"""


```