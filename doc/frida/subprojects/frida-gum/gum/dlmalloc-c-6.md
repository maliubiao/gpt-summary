Response:
The user wants to understand the functionality of a specific code snippet from `dlmalloc.c`, a memory allocation implementation used in Frida. I need to analyze the provided code, identify its role within the larger memory allocation process, and explain its relationship to reverse engineering, low-level systems, and potential user errors.

**Code Analysis:**

The code snippet is located within the `internal_malloc` function of `dlmalloc.c`. It handles allocation requests for small chunks. It first checks for exact fits in "small bins," which are lists of free chunks of the same size. If an exact fit isn't found, it might try to find a suitable chunk using a "treemap" (likely for more efficient searching in some configurations). If those fail, it might fall back to allocating from the "dv" (last remainder from a split chunk) or the "top" (remaining space at the end of the heap). Finally, if all else fails, it calls `sys_alloc` to request more memory from the system.

**Breakdown of the Code:**

1. **`bindex_t i;`**: Declares an index variable for iterating through small bins.
2. **`binmap_t leftbits = (smallbits << idx) & left_bits(idx2bit(idx));`**:  This line calculates a bitmask to find available small bins starting from the requested size (`idx`).
3. **`binmap_t leastbit = least_bit(leftbits);`**:  Finds the smallest available chunk size.
4. **`compute_bit2idx(leastbit, i);`**: Converts the bitmask back to an index.
5. **`b = smallbin_at(ms, i);`**: Gets the bin corresponding to the found size.
6. **`p = b->fd;`**: Gets the first free chunk from the bin.
7. **`assert(chunksize(p) == small_index2size(i));`**:  A safety check to ensure the chunk size matches the bin size.
8. **`unlink_first_small_chunk(ms, b, p, i);`**: Removes the chunk from the free list.
9. **`rsize = small_index2size(i) - nb;`**: Calculates the remaining size if the chunk is larger than requested.
10. **`if (SIZE_T_SIZE != 4 && rsize < MIN_CHUNK_SIZE)`**: Checks if splitting the chunk would create too small a remainder (and if the size type isn't 4 bytes).
11. **`set_inuse_and_pinuse(ms, p, small_index2size(i));`**: Marks the entire chunk as used.
12. **`else { ... }`**: Splits the chunk.
13. **`set_size_and_pinuse_of_inuse_chunk(ms, p, nb);`**: Marks the allocated portion as used.
14. **`r = chunk_plus_offset(p, nb);`**: Calculates the address of the remainder.
15. **`set_size_and_pinuse_of_free_chunk(r, rsize);`**: Marks the remainder as free.
16. **`replace_dv(ms, r, rsize);`**: Updates the "dv" to the new remainder.
17. **`mem = chunk2mem(p);`**:  Gets the user-accessible memory address from the chunk.
18. **`check_malloced_chunk(ms, mem, nb);`**:  A debugging check.
19. **`goto postaction;`**: Jumps to the end of the allocation process.
20. **`else if (ms->treemap != 0 && (mem = tmalloc_small(ms, nb)) != 0)`**: If small bins didn't work, try allocating using a treemap.
21. **`else if (bytes >= MAX_REQUEST)`**: Handles very large allocation requests by forcing a failure.
22. **`else { ... }`**: Handles larger-than-small but not huge requests, potentially using a treemap for large allocations.
23. **`if (nb <= ms->dvsize)`**: Attempts to allocate from the "dv".
24. **`else if (nb < ms->topsize)`**: Attempts to allocate from the "top".
25. **`mem = sys_alloc(ms, nb);`**: If none of the above worked, request more memory from the system.

**Planning the Response:**

I will address each point in the user's request:

1. **Functionality:** Explain that this code snippet is a part of the small chunk allocation logic within `dlmalloc`. It tries to find a free chunk of the right size from pre-existing free lists or splits existing chunks.
2. **Relationship to Reversing:** Explain how understanding the allocator's behavior is crucial for reverse engineering, particularly for heap exploitation. I'll use an example like identifying heap overflows by observing metadata corruption.
3. **Binary/Kernel Knowledge:** Discuss concepts like chunk headers, free lists, and how `sys_alloc` interacts with the operating system's memory management (e.g., `sbrk`, `mmap`). I'll also touch upon how this relates to the Android framework's memory management.
4. **Logical Reasoning (Hypothetical Input/Output):** Provide a simplified scenario where a small allocation request is made, and the code finds an exact fit in a small bin, demonstrating the flow of execution.
5. **User/Programming Errors:**  Explain how double frees, use-after-frees, and heap overflows can corrupt the allocator's metadata, leading to crashes or vulnerabilities.
6. **User Steps to Reach Here (Debugging):**  Describe how a program's `malloc` call eventually leads into this specific code path within the `dlmalloc` implementation. Tools like debuggers can be used to trace this.
7. **Summary of Functionality:**  Reiterate that this section is responsible for efficiently allocating small memory chunks by managing free lists and splitting larger chunks when necessary.
这是 `dlmalloc.c` 文件中 `internal_malloc` 函数的一部分，专门处理小块内存的分配。 让我们分解一下它的功能以及与您提到的各个方面的联系。

**功能列举:**

这段代码的主要功能是从 `dlmalloc` 管理的内存堆中分配一块指定大小的内存（`nb` 表示请求的大小）。 其核心逻辑是：

1. **查找精确匹配的小块 (Small Bins):**
   - 它首先尝试在 `smallbins` 中找到一个大小完全匹配的空闲块。 `smallbins` 是预先组织好的、按照大小排列的空闲内存块链表。
   - `smallbits << idx` 和 `left_bits(idx2bit(idx))` 用于生成一个位掩码，以快速定位可能包含所需大小空闲块的 `smallbins`。
   - `least_bit(leftbits)` 找到位掩码中最低的置位比特，指示了第一个大小不小于请求大小的空闲链表。
   - `compute_bit2idx(leastbit, i)` 将该比特位置转换回 `smallbins` 的索引。
   - `smallbin_at(ms, i)` 获取对应索引的 `smallbin` 链表的头部。
   - `p = b->fd;` 获取该链表中的第一个空闲块。
   - `assert(chunksize(p) == small_index2size(i));` 是一个断言，用于检查找到的块的大小是否与 `smallbin` 的预期大小一致，这是一个内部一致性检查。
   - `unlink_first_small_chunk(ms, b, p, i);` 将找到的空闲块从 `smallbin` 链表中移除。

2. **处理剩余空间 (Splitting):**
   - `rsize = small_index2size(i) - nb;` 计算分配后剩余的空间。
   - 如果剩余空间足够大（`SIZE_T_SIZE != 4 && rsize < MIN_CHUNK_SIZE` 考虑了 4 字节大小的情况，避免产生过小的碎片），则将原始块分割成两部分：已分配部分和剩余的空闲部分。
   - `set_size_and_pinuse_of_inuse_chunk(ms, p, nb);` 设置已分配部分的大小和使用状态。
   - `r = chunk_plus_offset(p, nb);` 计算剩余部分的起始地址。
   - `set_size_and_pinuse_of_free_chunk(r, rsize);` 设置剩余部分的大小和空闲状态。
   - `replace_dv(ms, r, rsize);` 将剩余部分设置为新的 "dv" (last remainder from a split chunk)，以便下次分配时优先考虑。

3. **使用 Treemap (如果启用):**
   - `else if (ms->treemap != 0 && (mem = tmalloc_small(ms, nb)) != 0)`: 如果 `smallbins` 中没有找到合适的块，并且启用了 `treemap`（一种更高级的数据结构，用于管理空闲块），则尝试使用 `tmalloc_small` 从 `treemap` 中分配。

4. **处理大块请求:**
   - `else if (bytes >= MAX_REQUEST)`: 如果请求的大小超过了 `MAX_REQUEST`，则将其设置为 `MAX_SIZE_T`，这通常会导致后续分配失败。

5. **使用 Treemap 处理稍大的请求:**
   - `else { nb = pad_request(bytes); if (ms->treemap != 0 && (mem = tmalloc_large(ms, nb)) != 0)`:  对于比 `smallbins` 大但又不是非常大的请求，先进行对齐 (`pad_request`)，然后尝试使用 `tmalloc_large` 从 `treemap` 中分配。

6. **使用剩余空间 (dv):**
   - `if (nb <= ms->dvsize)`: 如果请求的大小小于等于 `dv` 的大小，则尝试从 `dv` 中分配。
   - 如果剩余空间足够大，则分割 `dv`。
   - 否则，将整个 `dv` 分配出去。

7. **使用堆顶空间 (top):**
   - `else if (nb < ms->topsize)`: 如果请求的大小小于堆顶剩余空间的大小，则从堆顶分配。

8. **向系统请求更多内存 (sys_alloc):**
   - `mem = sys_alloc(ms, nb);`: 如果以上所有方法都失败了，则调用 `sys_alloc` 向操作系统请求更多的内存。

9. **分配后处理 (postaction):**
   - `postaction:`: 这是一个标签，表示分配成功后的跳转目标。
   - `POSTACTION(ms);`: 执行分配后的清理或统计操作。
   - `return mem;`: 返回分配到的内存地址。

**与逆向方法的联系:**

理解内存分配器的运作方式对于逆向工程至关重要，尤其是在分析漏洞利用和恶意软件时：

* **堆溢出分析:**  逆向工程师需要了解堆的结构和分配策略，才能识别和分析堆溢出漏洞。 例如，在上面的代码中，如果 `unlink_first_small_chunk` 或后续的分割逻辑存在缺陷，攻击者可能能够利用这些缺陷来覆盖相邻的内存块，从而控制程序的执行流程。 理解 `smallbins` 和 `dv` 的管理方式有助于分析溢出发生的位置和影响。
* **内存布局分析:**  了解 `dlmalloc` 如何管理空闲块以及如何进行分配和释放，有助于逆向工程师推断程序的内存布局。 这对于理解对象之间的关系、寻找敏感数据以及分析漏洞至关重要。
* **调试技巧:**  当遇到与内存相关的崩溃或异常时，理解 `dlmalloc` 的工作原理可以帮助逆向工程师更有效地进行调试。例如，通过观察 `smallbins` 或 `dv` 的状态，可以判断内存是否被意外释放或损坏。

**举例说明:**

假设一个程序申请了一块较小的内存，`nb` 的值为 32 字节。 `dlmalloc` 首先会检查 `smallbins` 中是否有大小为 32 字节的空闲块。 如果找到了，它会调用 `unlink_first_small_chunk` 将其从链表中移除，然后将该块标记为已使用，并将指向该内存块的指针返回给程序。 如果 `smallbins` 中没有完全匹配的块，但找到了一个 64 字节的空闲块，则会执行分割操作，分配 32 字节，并将剩余的 32 字节重新放回空闲列表中（可能成为新的 `dv`）。

**涉及二进制底层、Linux、Android 内核及框架的知识:**

* **二进制底层:** 代码直接操作内存地址和位运算 (`<<`, `&`)，这都是二进制底层的概念。例如，`PINUSE_BIT` 这样的标志位用于在块的头部存储元数据。
* **Linux 内核:**  `sys_alloc` 通常会调用 Linux 内核的 `brk` 或 `mmap` 系统调用来扩展堆空间。理解这些系统调用是理解内存分配根本的关键。
* **Android 内核及框架:**  Android 使用 Linux 内核，因此底层的内存分配机制与 Linux 类似。Frida 在 Android 环境中使用 `dlmalloc` (或其变种)，所以理解这段代码对于在 Android 上进行动态 instrumentation 和逆向工程至关重要。Android 框架中的内存管理机制，如 ART (Android Runtime) 的堆管理，可能基于或借鉴了类似的分配器设计思想。

**举例说明:**

`sys_alloc` 在 Linux 下可能会调用 `brk` 系统调用，逐渐移动堆的边界来分配新的内存页。 在 Android 中，由于安全性和隔离性的考虑，`mmap` 可能会更频繁地被使用，它允许分配独立的内存映射区域。 `chunksize(p)` 和 `set_size_and_pinuse_of_inuse_chunk` 等操作直接操作内存块的头部信息，这些头部信息是 `dlmalloc` 用来管理内存的关键数据结构。

**逻辑推理 (假设输入与输出):**

假设输入：
- `ms`: 一个指向 `malloc_state` 结构的指针，代表当前的内存堆状态。
- `nb`:  请求分配的字节数，例如 64 字节。

如果 `smallbins` 中存在一个大小为 64 字节的空闲块，则：
- 输出: `mem` 指向该空闲块的起始地址。
- 副作用: 该空闲块从 `smallbins` 中移除，其头部的标志位被设置为已使用。

如果 `smallbins` 中不存在大小为 64 字节的空闲块，但存在一个大小为 128 字节的空闲块，且分割后剩余空间足够大：
- 输出: `mem` 指向从该 128 字节块分割出的前 64 字节的起始地址。
- 副作用: 原始 128 字节块被分割成一个 64 字节的已分配块和一个 64 字节的空闲块，空闲块可能成为新的 `dv`。

**用户或编程常见的使用错误:**

* **重复释放 (Double Free):** 用户代码错误地释放同一块内存两次。如果第二次释放的内存块恰好位于 `smallbins` 中，`unlink_first_small_chunk` 可能会导致链表结构损坏，因为该块已经被移除了。
* **使用已释放的内存 (Use-After-Free):** 用户代码在释放内存后仍然尝试访问该内存。 这可能导致读取到脏数据或更严重的问题，例如，如果被释放的内存被重新分配给其他对象，可能会导致数据错乱。
* **堆溢出 (Heap Overflow):** 用户代码写入超过已分配内存块边界的数据。这可能覆盖相邻内存块的元数据（例如，块的大小或 `inuse` 标志），从而导致 `dlmalloc` 的内部状态不一致，最终可能在后续的分配或释放操作中崩溃。 例如，如果堆溢出覆盖了下一个空闲块的 `size` 字段，`unlink_chunk` 等操作可能会访问到错误的地址。

**用户操作到达这里的调试线索:**

用户程序执行以下操作时，最终会调用到 `internal_malloc` 中的这段代码：

1. **调用 `malloc` 或 `calloc` 等内存分配函数:** 用户代码显式地调用标准库提供的内存分配函数，例如 `malloc(64)`。
2. **Frida 拦截分配函数:**  Frida 工具通过 hook 技术拦截了这些分配函数的调用。
3. **Frida 执行原始分配逻辑:**  Frida 的设计允许在拦截后选择执行原始的函数逻辑。  如果 Frida 没有完全替换 `malloc` 的实现，它会继续调用 `dlmalloc` 中的 `malloc` 函数。
4. **`malloc` 函数调用 `internal_malloc`:** `dlmalloc` 的 `malloc` 函数会进行一些预处理和检查，然后根据请求的大小将分配任务委托给 `internal_malloc`。
5. **`internal_malloc` 执行小块分配逻辑:** 如果请求的大小满足小块的标准，`internal_malloc` 就会执行这段代码，尝试从 `smallbins` 中分配内存。

**调试线索:**

当你在 Frida 中调试一个程序，并且你设置了断点在 `frida/subprojects/frida-gum/gum/dlmalloc.c` 的这个位置时，这意味着：

* 目标程序正在尝试分配一块相对较小的内存。
* Frida 已经成功地 hook 了内存分配相关的函数。
* 程序的执行流程到达了 `dlmalloc` 中处理小块分配的特定逻辑。

你可以通过观察以下信息来进一步调试：

* **`ms` 的值:**  查看当前的内存堆状态，例如 `smallbins` 的内容。
* **`idx` 的值:** 查看请求分配的大小对应的 `smallbins` 索引。
* **`nb` 的值:** 查看实际请求分配的字节数。
* **`b` 和 `p` 的值:** 查看找到的空闲块的地址和内容。

**第 7 部分功能归纳:**

作为 `dlmalloc.c` 的一部分，这段代码负责 **高效地分配小尺寸的内存块**。 它通过维护 `smallbins` 这种优化的空闲链表结构，可以快速地找到并分配精确大小的空闲块。 如果没有精确匹配，它还会尝试分割较大的空闲块来满足请求，并将剩余部分重新管理起来。 这是 `dlmalloc` 内存分配器中一个核心的性能优化环节，对于提高小对象分配的效率至关重要。 它与逆向工程、底层系统知识以及用户错误都有着密切的联系。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/gum/dlmalloc.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第7部分，共7部分，请归纳一下它的功能

"""
   bindex_t i;
          binmap_t leftbits = (smallbits << idx) & left_bits(idx2bit(idx));
          binmap_t leastbit = least_bit(leftbits);
          compute_bit2idx(leastbit, i);
          b = smallbin_at(ms, i);
          p = b->fd;
          assert(chunksize(p) == small_index2size(i));
          unlink_first_small_chunk(ms, b, p, i);
          rsize = small_index2size(i) - nb;
          /* Fit here cannot be remainderless if 4byte sizes */
          if (SIZE_T_SIZE != 4 && rsize < MIN_CHUNK_SIZE)
            set_inuse_and_pinuse(ms, p, small_index2size(i));
          else {
            set_size_and_pinuse_of_inuse_chunk(ms, p, nb);
            r = chunk_plus_offset(p, nb);
            set_size_and_pinuse_of_free_chunk(r, rsize);
            replace_dv(ms, r, rsize);
          }
          mem = chunk2mem(p);
          check_malloced_chunk(ms, mem, nb);
          goto postaction;
        }

        else if (ms->treemap != 0 && (mem = tmalloc_small(ms, nb)) != 0) {
          check_malloced_chunk(ms, mem, nb);
          goto postaction;
        }
      }
    }
    else if (bytes >= MAX_REQUEST)
      nb = MAX_SIZE_T; /* Too big to allocate. Force failure (in sys alloc) */
    else {
      nb = pad_request(bytes);
      if (ms->treemap != 0 && (mem = tmalloc_large(ms, nb)) != 0) {
        check_malloced_chunk(ms, mem, nb);
        goto postaction;
      }
    }

    if (nb <= ms->dvsize) {
      size_t rsize = ms->dvsize - nb;
      mchunkptr p = ms->dv;
      if (rsize >= MIN_CHUNK_SIZE) { /* split dv */
        mchunkptr r = ms->dv = chunk_plus_offset(p, nb);
        ms->dvsize = rsize;
        set_size_and_pinuse_of_free_chunk(r, rsize);
        set_size_and_pinuse_of_inuse_chunk(ms, p, nb);
      }
      else { /* exhaust dv */
        size_t dvs = ms->dvsize;
        ms->dvsize = 0;
        ms->dv = 0;
        set_inuse_and_pinuse(ms, p, dvs);
      }
      mem = chunk2mem(p);
      check_malloced_chunk(ms, mem, nb);
      goto postaction;
    }

    else if (nb < ms->topsize) { /* Split top */
      size_t rsize = ms->topsize -= nb;
      mchunkptr p = ms->top;
      mchunkptr r = ms->top = chunk_plus_offset(p, nb);
      r->head = rsize | PINUSE_BIT;
      set_size_and_pinuse_of_inuse_chunk(ms, p, nb);
      mem = chunk2mem(p);
      check_top_chunk(ms, ms->top);
      check_malloced_chunk(ms, mem, nb);
      goto postaction;
    }

    mem = sys_alloc(ms, nb);

  postaction:
    POSTACTION(ms);
    return mem;
  }

  return 0;
}

void mspace_free(mspace msp, void* mem) {
  if (mem != 0) {
    mchunkptr p  = mem2chunk(mem);
#if FOOTERS
    mstate fm = get_mstate_for(p);
    (void)msp; /* placate people compiling -Wunused */
#else /* FOOTERS */
    mstate fm = (mstate)msp;
#endif /* FOOTERS */
    if (!ok_magic(fm)) {
      USAGE_ERROR_ACTION(fm, p);
      return;
    }
    if (!PREACTION(fm)) {
      check_inuse_chunk(fm, p);
      if (RTCHECK(ok_address(fm, p) && ok_inuse(p))) {
        size_t psize = chunksize(p);
        mchunkptr next = chunk_plus_offset(p, psize);
        if (!pinuse(p)) {
          size_t prevsize = p->prev_foot;
          if (is_mmapped(p)) {
            psize += prevsize + MMAP_FOOT_PAD;
            if (CALL_MUNMAP((char*)p - prevsize, psize) == 0)
              fm->footprint -= psize;
            goto postaction;
          }
          else {
            mchunkptr prev = chunk_minus_offset(p, prevsize);
            psize += prevsize;
            p = prev;
            if (RTCHECK(ok_address(fm, prev))) { /* consolidate backward */
              if (p != fm->dv) {
                unlink_chunk(fm, p, prevsize);
              }
              else if ((next->head & INUSE_BITS) == INUSE_BITS) {
                fm->dvsize = psize;
                set_free_with_pinuse(p, psize, next);
                goto postaction;
              }
            }
            else
              goto erroraction;
          }
        }

        if (RTCHECK(ok_next(p, next) && ok_pinuse(next))) {
          if (!cinuse(next)) {  /* consolidate forward */
            if (next == fm->top) {
              size_t tsize = fm->topsize += psize;
              fm->top = p;
              p->head = tsize | PINUSE_BIT;
              if (p == fm->dv) {
                fm->dv = 0;
                fm->dvsize = 0;
              }
              if (should_trim(fm, tsize))
                sys_trim(fm, 0);
              goto postaction;
            }
            else if (next == fm->dv) {
              size_t dsize = fm->dvsize += psize;
              fm->dv = p;
              set_size_and_pinuse_of_free_chunk(p, dsize);
              goto postaction;
            }
            else {
              size_t nsize = chunksize(next);
              psize += nsize;
              unlink_chunk(fm, next, nsize);
              set_size_and_pinuse_of_free_chunk(p, psize);
              if (p == fm->dv) {
                fm->dvsize = psize;
                goto postaction;
              }
            }
          }
          else
            set_free_with_pinuse(p, psize, next);

          if (is_small(psize)) {
            insert_small_chunk(fm, p, psize);
            check_free_chunk(fm, p);
          }
          else {
            tchunkptr tp = (tchunkptr)p;
            insert_large_chunk(fm, tp, psize);
            check_free_chunk(fm, p);
            if (--fm->release_checks == 0)
              release_unused_segments(fm);
          }
          goto postaction;
        }
      }
    erroraction:
      USAGE_ERROR_ACTION(fm, p);
    postaction:
      POSTACTION(fm);
    }
  }
}

void* mspace_calloc(mspace msp, size_t n_elements, size_t elem_size) {
  void* mem;
  size_t req = 0;
  mstate ms = (mstate)msp;
  if (!ok_magic(ms)) {
    USAGE_ERROR_ACTION(ms,ms);
    return 0;
  }
  if (n_elements != 0) {
    req = n_elements * elem_size;
    if (((n_elements | elem_size) & ~(size_t)0xffff) &&
        (req / n_elements != elem_size))
      req = MAX_SIZE_T; /* force downstream failure on overflow */
  }
  mem = internal_malloc(ms, req);
  if (mem != 0 && calloc_must_clear(mem2chunk(mem)))
    gum_memset(mem, 0, req);
  return mem;
}

void* mspace_realloc(mspace msp, void* oldmem, size_t bytes) {
  void* mem = 0;
  if (oldmem == 0) {
    mem = mspace_malloc(msp, bytes);
  }
  else if (bytes >= MAX_REQUEST) {
    MALLOC_FAILURE_ACTION;
  }
#ifdef REALLOC_ZERO_BYTES_FREES
  else if (bytes == 0) {
    mspace_free(msp, oldmem);
  }
#endif /* REALLOC_ZERO_BYTES_FREES */
  else {
    size_t nb = request2size(bytes);
    mchunkptr oldp = mem2chunk(oldmem);
#if ! FOOTERS
    mstate m = (mstate)msp;
#else /* FOOTERS */
    mstate m = get_mstate_for(oldp);
    if (!ok_magic(m)) {
      USAGE_ERROR_ACTION(m, oldmem);
      return 0;
    }
#endif /* FOOTERS */
    if (!PREACTION(m)) {
      mchunkptr newp = try_realloc_chunk(m, oldp, nb, 1);
      POSTACTION(m);
      if (newp != 0) {
        check_inuse_chunk(m, newp);
        mem = chunk2mem(newp);
      }
      else {
        mem = mspace_malloc(m, bytes);
        if (mem != 0) {
          size_t oc = chunksize(oldp) - overhead_for(oldp);
          gum_memcpy(mem, oldmem, (oc < bytes)? oc : bytes);
          mspace_free(m, oldmem);
        }
      }
    }
  }
  return mem;
}

void* mspace_realloc_in_place(mspace msp, void* oldmem, size_t bytes) {
  void* mem = 0;
  if (oldmem != 0) {
    if (bytes >= MAX_REQUEST) {
      MALLOC_FAILURE_ACTION;
    }
    else {
      size_t nb = request2size(bytes);
      mchunkptr oldp = mem2chunk(oldmem);
#if ! FOOTERS
      mstate m = (mstate)msp;
#else /* FOOTERS */
      mstate m = get_mstate_for(oldp);
      (void)msp; /* placate people compiling -Wunused */
      if (!ok_magic(m)) {
        USAGE_ERROR_ACTION(m, oldmem);
        return 0;
      }
#endif /* FOOTERS */
      if (!PREACTION(m)) {
        mchunkptr newp = try_realloc_chunk(m, oldp, nb, 0);
        POSTACTION(m);
        if (newp == oldp) {
          check_inuse_chunk(m, newp);
          mem = oldmem;
        }
      }
    }
  }
  return mem;
}

void* mspace_memalign(mspace msp, size_t alignment, size_t bytes) {
  mstate ms = (mstate)msp;
  if (!ok_magic(ms)) {
    USAGE_ERROR_ACTION(ms,ms);
    return 0;
  }
  if (alignment <= MALLOC_ALIGNMENT)
    return mspace_malloc(msp, bytes);
  return internal_memalign(ms, alignment, bytes);
}

void** mspace_independent_calloc(mspace msp, size_t n_elements,
                                 size_t elem_size, void* chunks[]) {
  size_t sz = elem_size; /* serves as 1-element array */
  mstate ms = (mstate)msp;
  if (!ok_magic(ms)) {
    USAGE_ERROR_ACTION(ms,ms);
    return 0;
  }
  return ialloc(ms, n_elements, &sz, 3, chunks);
}

void** mspace_independent_comalloc(mspace msp, size_t n_elements,
                                   size_t sizes[], void* chunks[]) {
  mstate ms = (mstate)msp;
  if (!ok_magic(ms)) {
    USAGE_ERROR_ACTION(ms,ms);
    return 0;
  }
  return ialloc(ms, n_elements, sizes, 0, chunks);
}

size_t mspace_bulk_free(mspace msp, void* array[], size_t nelem) {
  return internal_bulk_free((mstate)msp, array, nelem);
}

#if MALLOC_INSPECT_ALL
void mspace_inspect_all(mspace msp,
                        void(*handler)(void *start,
                                       void *end,
                                       size_t used_bytes,
                                       void* callback_arg),
                        void* arg) {
  mstate ms = (mstate)msp;
  if (ok_magic(ms)) {
    if (!PREACTION(ms)) {
      internal_inspect_all(ms, handler, arg);
      POSTACTION(ms);
    }
  }
  else {
    USAGE_ERROR_ACTION(ms,ms);
  }
}
#endif /* MALLOC_INSPECT_ALL */

int mspace_trim(mspace msp, size_t pad) {
  int result = 0;
  mstate ms = (mstate)msp;
  if (ok_magic(ms)) {
    if (!PREACTION(ms)) {
      result = sys_trim(ms, pad);
      POSTACTION(ms);
    }
  }
  else {
    USAGE_ERROR_ACTION(ms,ms);
  }
  return result;
}

#if !NO_MALLOC_STATS
void mspace_malloc_stats(mspace msp) {
  mstate ms = (mstate)msp;
  if (ok_magic(ms)) {
    internal_malloc_stats(ms);
  }
  else {
    USAGE_ERROR_ACTION(ms,ms);
  }
}
#endif /* NO_MALLOC_STATS */

size_t mspace_footprint(mspace msp) {
  size_t result = 0;
  mstate ms = (mstate)msp;
  if (ok_magic(ms)) {
    result = ms->footprint;
  }
  else {
    USAGE_ERROR_ACTION(ms,ms);
  }
  return result;
}

size_t mspace_max_footprint(mspace msp) {
  size_t result = 0;
  mstate ms = (mstate)msp;
  if (ok_magic(ms)) {
    result = ms->max_footprint;
  }
  else {
    USAGE_ERROR_ACTION(ms,ms);
  }
  return result;
}

size_t mspace_footprint_limit(mspace msp) {
  size_t result = 0;
  mstate ms = (mstate)msp;
  if (ok_magic(ms)) {
    size_t maf = ms->footprint_limit;
    result = (maf == 0) ? MAX_SIZE_T : maf;
  }
  else {
    USAGE_ERROR_ACTION(ms,ms);
  }
  return result;
}

size_t mspace_set_footprint_limit(mspace msp, size_t bytes) {
  size_t result = 0;
  mstate ms = (mstate)msp;
  if (ok_magic(ms)) {
    if (bytes == 0)
      result = granularity_align(1); /* Use minimal size */
    if (bytes == MAX_SIZE_T)
      result = 0;                    /* disable */
    else
      result = granularity_align(bytes);
    ms->footprint_limit = result;
  }
  else {
    USAGE_ERROR_ACTION(ms,ms);
  }
  return result;
}

#if !NO_MALLINFO
struct mallinfo mspace_mallinfo(mspace msp) {
  mstate ms = (mstate)msp;
  if (!ok_magic(ms)) {
    USAGE_ERROR_ACTION(ms,ms);
  }
  return internal_mallinfo(ms);
}
#endif /* NO_MALLINFO */

size_t mspace_usable_size(const void* mem) {
  if (mem != 0) {
    mchunkptr p = mem2chunk(mem);
    if (is_inuse(p))
      return chunksize(p) - overhead_for(p);
  }
  return 0;
}

int mspace_mallopt(int param_number, int value) {
  return change_mparam(param_number, value);
}

#endif /* MSPACES */


/* -------------------- Alternative MORECORE functions ------------------- */

/*
  Guidelines for creating a custom version of MORECORE:

  * For best performance, MORECORE should allocate in multiples of pagesize.
  * MORECORE may allocate more memory than requested. (Or even less,
      but this will usually result in a malloc failure.)
  * MORECORE must not allocate memory when given argument zero, but
      instead return one past the end address of memory from previous
      nonzero call.
  * For best performance, consecutive calls to MORECORE with positive
      arguments should return increasing addresses, indicating that
      space has been contiguously extended.
  * Even though consecutive calls to MORECORE need not return contiguous
      addresses, it must be OK for malloc'ed chunks to span multiple
      regions in those cases where they do happen to be contiguous.
  * MORECORE need not handle negative arguments -- it may instead
      just return MFAIL when given negative arguments.
      Negative arguments are always multiples of pagesize. MORECORE
      must not misinterpret negative args as large positive unsigned
      args. You can suppress all such calls from even occurring by defining
      MORECORE_CANNOT_TRIM,

  As an example alternative MORECORE, here is a custom allocator
  kindly contributed for pre-OSX macOS.  It uses virtually but not
  necessarily physically contiguous non-paged memory (locked in,
  present and won't get swapped out).  You can use it by uncommenting
  this section, adding some #includes, and setting up the appropriate
  defines above:

      #define MORECORE osMoreCore

  There is also a shutdown routine that should somehow be called for
  cleanup upon program exit.

  #define MAX_POOL_ENTRIES 100
  #define MINIMUM_MORECORE_SIZE  (64 * 1024U)
  static int next_os_pool;
  void *our_os_pools[MAX_POOL_ENTRIES];

  void *osMoreCore(int size)
  {
    void *ptr = 0;
    static void *sbrk_top = 0;

    if (size > 0)
    {
      if (size < MINIMUM_MORECORE_SIZE)
         size = MINIMUM_MORECORE_SIZE;
      if (CurrentExecutionLevel() == kTaskLevel)
         ptr = PoolAllocateResident(size + RM_PAGE_SIZE, 0);
      if (ptr == 0)
      {
        return (void *) MFAIL;
      }
      // save ptrs so they can be freed during cleanup
      our_os_pools[next_os_pool] = ptr;
      next_os_pool++;
      ptr = (void *) ((((size_t) ptr) + RM_PAGE_MASK) & ~RM_PAGE_MASK);
      sbrk_top = (char *) ptr + size;
      return ptr;
    }
    else if (size < 0)
    {
      // we don't currently support shrink behavior
      return (void *) MFAIL;
    }
    else
    {
      return sbrk_top;
    }
  }

  // cleanup any allocated memory pools
  // called as last thing before shutting down driver

  void osCleanupMem(void)
  {
    void **ptr;

    for (ptr = our_os_pools; ptr < &our_os_pools[MAX_POOL_ENTRIES]; ptr++)
      if (*ptr)
      {
         PoolDeallocate(*ptr);
         *ptr = 0;
      }
  }

*/


/* -----------------------------------------------------------------------
History:
    v2.8.6 Wed Aug 29 06:57:58 2012  Doug Lea
      * fix bad comparison in dlposix_memalign
      * don't reuse adjusted asize in sys_alloc
      * add LOCK_AT_FORK -- thanks to Kirill Artamonov for the suggestion
      * reduce compiler warnings -- thanks to all who reported/suggested these

    v2.8.5 Sun May 22 10:26:02 2011  Doug Lea  (dl at gee)
      * Always perform unlink checks unless INSECURE
      * Add posix_memalign.
      * Improve realloc to expand in more cases; expose realloc_in_place.
        Thanks to Peter Buhr for the suggestion.
      * Add footprint_limit, inspect_all, bulk_free. Thanks
        to Barry Hayes and others for the suggestions.
      * Internal refactorings to avoid calls while holding locks
      * Use non-reentrant locks by default. Thanks to Roland McGrath
        for the suggestion.
      * Small fixes to mspace_destroy, reset_on_error.
      * Various configuration extensions/changes. Thanks
         to all who contributed these.

    V2.8.4a Thu Apr 28 14:39:43 2011 (dl at gee.cs.oswego.edu)
      * Update Creative Commons URL

    V2.8.4 Wed May 27 09:56:23 2009  Doug Lea  (dl at gee)
      * Use zeros instead of prev foot for is_mmapped
      * Add mspace_track_large_chunks; thanks to Jean Brouwers
      * Fix set_inuse in internal_realloc; thanks to Jean Brouwers
      * Fix insufficient sys_alloc padding when using 16byte alignment
      * Fix bad error check in mspace_footprint
      * Adaptations for ptmalloc; thanks to Wolfram Gloger.
      * Reentrant spin locks; thanks to Earl Chew and others
      * Win32 improvements; thanks to Niall Douglas and Earl Chew
      * Add NO_SEGMENT_TRAVERSAL and MAX_RELEASE_CHECK_RATE options
      * Extension hook in malloc_state
      * Various small adjustments to reduce warnings on some compilers
      * Various configuration extensions/changes for more platforms. Thanks
         to all who contributed these.

    V2.8.3 Thu Sep 22 11:16:32 2005  Doug Lea  (dl at gee)
      * Add max_footprint functions
      * Ensure all appropriate literals are size_t
      * Fix conditional compilation problem for some #define settings
      * Avoid concatenating segments with the one provided
        in create_mspace_with_base
      * Rename some variables to avoid compiler shadowing warnings
      * Use explicit lock initialization.
      * Better handling of sbrk interference.
      * Simplify and fix segment insertion, trimming and mspace_destroy
      * Reinstate REALLOC_ZERO_BYTES_FREES option from 2.7.x
      * Thanks especially to Dennis Flanagan for help on these.

    V2.8.2 Sun Jun 12 16:01:10 2005  Doug Lea  (dl at gee)
      * Fix memalign brace error.

    V2.8.1 Wed Jun  8 16:11:46 2005  Doug Lea  (dl at gee)
      * Fix improper #endif nesting in C++
      * Add explicit casts needed for C++

    V2.8.0 Mon May 30 14:09:02 2005  Doug Lea  (dl at gee)
      * Use trees for large bins
      * Support mspaces
      * Use segments to unify sbrk-based and mmap-based system allocation,
        removing need for emulation on most platforms without sbrk.
      * Default safety checks
      * Optional footer checks. Thanks to William Robertson for the idea.
      * Internal code refactoring
      * Incorporate suggestions and platform-specific changes.
        Thanks to Dennis Flanagan, Colin Plumb, Niall Douglas,
        Aaron Bachmann,  Emery Berger, and others.
      * Speed up non-fastbin processing enough to remove fastbins.
      * Remove useless cfree() to avoid conflicts with other apps.
      * Remove internal memcpy, memset. Compilers handle builtins better.
      * Remove some options that no one ever used and rename others.

    V2.7.2 Sat Aug 17 09:07:30 2002  Doug Lea  (dl at gee)
      * Fix malloc_state bitmap array misdeclaration

    V2.7.1 Thu Jul 25 10:58:03 2002  Doug Lea  (dl at gee)
      * Allow tuning of FIRST_SORTED_BIN_SIZE
      * Use PTR_UINT as type for all ptr->int casts. Thanks to John Belmonte.
      * Better detection and support for non-contiguousness of MORECORE.
        Thanks to Andreas Mueller, Conal Walsh, and Wolfram Gloger
      * Bypass most of malloc if no frees. Thanks To Emery Berger.
      * Fix freeing of old top non-contiguous chunk im sysmalloc.
      * Raised default trim and map thresholds to 256K.
      * Fix mmap-related #defines. Thanks to Lubos Lunak.
      * Fix copy macros; added LACKS_FCNTL_H. Thanks to Neal Walfield.
      * Branch-free bin calculation
      * Default trim and mmap thresholds now 256K.

    V2.7.0 Sun Mar 11 14:14:06 2001  Doug Lea  (dl at gee)
      * Introduce independent_comalloc and independent_calloc.
        Thanks to Michael Pachos for motivation and help.
      * Make optional .h file available
      * Allow > 2GB requests on 32bit systems.
      * new WIN32 sbrk, mmap, munmap, lock code from <Walter@GeNeSys-e.de>.
        Thanks also to Andreas Mueller <a.mueller at paradatec.de>,
        and Anonymous.
      * Allow override of MALLOC_ALIGNMENT (Thanks to Ruud Waij for
        helping test this.)
      * memalign: check alignment arg
      * realloc: don't try to shift chunks backwards, since this
        leads to  more fragmentation in some programs and doesn't
        seem to help in any others.
      * Collect all cases in malloc requiring system memory into sysmalloc
      * Use mmap as backup to sbrk
      * Place all internal state in malloc_state
      * Introduce fastbins (although similar to 2.5.1)
      * Many minor tunings and cosmetic improvements
      * Introduce USE_PUBLIC_MALLOC_WRAPPERS, USE_MALLOC_LOCK
      * Introduce MALLOC_FAILURE_ACTION, MORECORE_CONTIGUOUS
        Thanks to Tony E. Bennett <tbennett@nvidia.com> and others.
      * Include errno.h to support default failure action.

    V2.6.6 Sun Dec  5 07:42:19 1999  Doug Lea  (dl at gee)
      * return null for negative arguments
      * Added Several WIN32 cleanups from Martin C. Fong <mcfong at yahoo.com>
         * Add 'LACKS_SYS_PARAM_H' for those systems without 'sys/param.h'
          (e.g. WIN32 platforms)
         * Cleanup header file inclusion for WIN32 platforms
         * Cleanup code to avoid Microsoft Visual C++ compiler complaints
         * Add 'USE_DL_PREFIX' to quickly allow co-existence with existing
           memory allocation routines
         * Set 'malloc_getpagesize' for WIN32 platforms (needs more work)
         * Use 'assert' rather than 'ASSERT' in WIN32 code to conform to
           usage of 'assert' in non-WIN32 code
         * Improve WIN32 'sbrk()' emulation's 'findRegion()' routine to
           avoid infinite loop
      * Always call 'fREe()' rather than 'free()'

    V2.6.5 Wed Jun 17 15:57:31 1998  Doug Lea  (dl at gee)
      * Fixed ordering problem with boundary-stamping

    V2.6.3 Sun May 19 08:17:58 1996  Doug Lea  (dl at gee)
      * Added pvalloc, as recommended by H.J. Liu
      * Added 64bit pointer support mainly from Wolfram Gloger
      * Added anonymously donated WIN32 sbrk emulation
      * Malloc, calloc, getpagesize: add optimizations from Raymond Nijssen
      * malloc_extend_top: fix mask error that caused wastage after
        foreign sbrks
      * Add linux mremap support code from HJ Liu

    V2.6.2 Tue Dec  5 06:52:55 1995  Doug Lea  (dl at gee)
      * Integrated most documentation with the code.
      * Add support for mmap, with help from
        Wolfram Gloger (Gloger@lrz.uni-muenchen.de).
      * Use last_remainder in more cases.
      * Pack bins using idea from  colin@nyx10.cs.du.edu
      * Use ordered bins instead of best-fit threshhold
      * Eliminate block-local decls to simplify tracing and debugging.
      * Support another case of realloc via move into top
      * Fix error occuring when initial sbrk_base not word-aligned.
      * Rely on page size for units instead of SBRK_UNIT to
        avoid surprises about sbrk alignment conventions.
      * Add mallinfo, mallopt. Thanks to Raymond Nijssen
        (raymond@es.ele.tue.nl) for the suggestion.
      * Add `pad' argument to malloc_trim and top_pad mallopt parameter.
      * More precautions for cases where other routines call sbrk,
        courtesy of Wolfram Gloger (Gloger@lrz.uni-muenchen.de).
      * Added macros etc., allowing use in linux libc from
        H.J. Lu (hjl@gnu.ai.mit.edu)
      * Inverted this history list

    V2.6.1 Sat Dec  2 14:10:57 1995  Doug Lea  (dl at gee)
      * Re-tuned and fixed to behave more nicely with V2.6.0 changes.
      * Removed all preallocation code since under current scheme
        the work required to undo bad preallocations exceeds
        the work saved in good cases for most test programs.
      * No longer use return list or unconsolidated bins since
        no scheme using them consistently outperforms those that don't
        given above changes.
      * Use best fit for very large chunks to prevent some worst-cases.
      * Added some support for debugging

    V2.6.0 Sat Nov  4 07:05:23 1995  Doug Lea  (dl at gee)
      * Removed footers when chunks are in use. Thanks to
        Paul Wilson (wilson@cs.texas.edu) for the suggestion.

    V2.5.4 Wed Nov  1 07:54:51 1995  Doug Lea  (dl at gee)
      * Added malloc_trim, with help from Wolfram Gloger
        (wmglo@Dent.MED.Uni-Muenchen.DE).

    V2.5.3 Tue Apr 26 10:16:01 1994  Doug Lea  (dl at g)

    V2.5.2 Tue Apr  5 16:20:40 1994  Doug Lea  (dl at g)
      * realloc: try to expand in both directions
      * malloc: swap order of clean-bin strategy;
      * realloc: only conditionally expand backwards
      * Try not to scavenge used bins
      * Use bin counts as a guide to preallocation
      * Occasionally bin return list chunks in first scan
      * Add a few optimizations from colin@nyx10.cs.du.edu

    V2.5.1 Sat Aug 14 15:40:43 1993  Doug Lea  (dl at g)
      * faster bin computation & slightly different binning
      * merged all consolidations to one part of malloc proper
         (eliminating old malloc_find_space & malloc_clean_bin)
      * Scan 2 returns chunks (not just 1)
      * Propagate failure in realloc if malloc returns 0
      * Add stuff to allow compilation on non-ANSI compilers
          from kpv@research.att.com

    V2.5 Sat Aug  7 07:41:59 1993  Doug Lea  (dl at g.oswego.edu)
      * removed potential for odd address access in prev_chunk
      * removed dependency on getpagesize.h
      * misc cosmetics and a bit more internal documentation
      * anticosmetics: mangled names in macros to evade debugger strangeness
      * tested on sparc, hp-700, dec-mips, rs6000
          with gcc & native cc (hp, dec only) allowing
          Detlefs & Zorn comparison study (in SIGPLAN Notices.)

    Trial version Fri Aug 28 13:14:29 1992  Doug Lea  (dl at g.oswego.edu)
      * Based loosely on libg++-1.2X malloc. (It retains some of the overall
         structure of old version,  but most details differ.)

*/

"""


```