Response:
Let's break down the thought process for analyzing this C code and generating the explanation.

**1. Understanding the Goal:**

The request asks for a comprehensive analysis of the `fixupchainprocessor.c` file within the Frida framework. The key aspects to address are:

* **Functionality:** What does the code do?
* **Relevance to Reverse Engineering:** How is this useful for reverse engineers?
* **Low-Level Concepts:** What underlying system knowledge is required?
* **Logical Reasoning:** Can we infer input/output behavior?
* **Common Errors:** What mistakes might users make?
* **User Path:** How does a user's interaction lead to this code?

**2. Initial Code Scan and Keyword Identification:**

First, I scanned the code for important keywords and structures. These jumped out:

* `#include`: `fixupchainprocessor.h`, `ptrauth.h`, `stdbool.h`. These hint at the code's purpose (processing fixups, using pointer authentication, and boolean logic).
* `gum_`:  This prefix suggests the code is part of the Frida "gum" library, related to dynamic instrumentation.
* `fixupchain`:  A central theme – processing chained fixups.
* `mach_header_64`: This clearly points to macOS (and potentially iOS) Mach-O executable format.
* `preferred_base_address`, `actual_base_address`, `slide`: These terms are crucial in understanding address space layout randomization (ASLR) and relocation.
* `bound_pointers`:  This suggests interaction with dynamically linked libraries and symbol resolution.
* `GUM_CHAINED_PTR_*`:  Enumerated types likely defining different formats of chained pointers.
* `#ifdef __arm64e__`: Conditional compilation for ARM64e architecture, which is relevant to newer Apple devices with pointer authentication.
* `ptrauth_`: Functions related to pointer authentication codes (PACs).
* `rebase`, `bind`, `auth`:  Terms related to different types of fixups.
* `ordinal`: Index into a table, likely related to imported symbols.
* `delta`:  Offset or stride.

**3. Deconstructing the Main Function (`gum_process_chained_fixups`):**

This function is the entry point. I traced its logic:

* It takes a `fixups_header`, `mach_header`, `preferred_base_address`, and `bound_pointers`.
* It iterates through segments (`seg_count`).
* Within each segment, it iterates through pages (`page_count`).
* It calculates a `cursor` pointing to the start of a chain of fixups within a page.
* It calls different processing functions based on the `format` of the chained pointers (`gum_process_chained_fixups_in_segment_generic64` or `gum_process_chained_fixups_in_segment_arm64e`).

**4. Analyzing the Segment Processing Functions:**

* **`gum_process_chained_fixups_in_segment_generic64`:**  Handles 64-bit architectures without pointer authentication. It processes `Rebase` and `Bind` fixups. `Rebase` adjusts addresses based on ASLR. `Bind` resolves external symbols. The `delta` determines the next fixup in the chain.
* **`gum_process_chained_fixups_in_segment_arm64e`:** Handles ARM64e, which *does* have pointer authentication. It has similar logic for `Rebase` and `Bind` but also includes `AuthRebase` and `AuthBind` which involve signing pointers using PACs. The `gum_sign_pointer` function is crucial here.

**5. Understanding Pointer Authentication (`gum_sign_pointer`):**

This function implements the pointer signing logic. It uses `ptrauth_sign_unauthenticated` with different keys (`asia`, `asib`, `asda`, `asdb`) and potentially blends a discriminator based on the address of the pointer.

**6. Sign Extension (`gum_sign_extend_int19`):**

This utility function is used to handle signed 19-bit values, common in certain ARM instructions.

**7. Connecting to Reverse Engineering:**

With the core functionality understood, I could now connect it to reverse engineering concepts:

* **Dynamic Analysis:** Frida is a dynamic instrumentation tool, making this directly relevant.
* **ASLR Bypassing/Understanding:** The code directly deals with ASLR by calculating the `slide`.
* **Symbol Resolution:** The `bound_pointers` and `Bind` fixups are about understanding how external functions are linked.
* **Pointer Authentication:**  The ARM64e specific code is critical for reverse engineering on modern Apple devices.

**8. Identifying Low-Level Concepts:**

This step involved thinking about the system knowledge required to understand the code:

* **Executable File Formats:** Mach-O is central.
* **Dynamic Linking:** The concept of fixups and binding is key.
* **Memory Management:** Understanding virtual addresses and how the loader works is important.
* **CPU Architectures:**  The distinction between generic 64-bit and ARM64e is vital.
* **Operating System Internals:** The loader's role in applying fixups.

**9. Logical Reasoning (Input/Output):**

I considered hypothetical inputs and the expected behavior:

* **Input:** A Mach-O file loaded at a different address than its preferred base.
* **Output:** The pointers within the data segment being updated to the correct runtime addresses.

* **Input:** A Mach-O file with dependencies on shared libraries.
* **Output:** The `bound_pointers` array being used to resolve the addresses of those external symbols.

**10. Common User Errors:**

This involved thinking about how someone using Frida might trigger issues related to this code:

* **Incorrect Base Address:** If the provided `preferred_base_address` is wrong.
* **Incorrect `bound_pointers`:**  If the Frida instrumentation doesn't correctly capture the loaded library addresses.

**11. Tracing User Operations:**

Finally, I considered how a user would interact with Frida to reach this code:

* **Basic Instrumentation:** Injecting a script to hook functions.
* **Library Loading:** Observing the loading of new libraries.
* **Memory Manipulation:**  Directly modifying memory, which might involve fixups.

**Self-Correction/Refinement:**

During the process, I might have initially focused too much on one aspect. For example, I might have initially spent too much time on the details of `GumChainedStartsInImage` without fully grasping the bigger picture of how the fixup process works. I would then step back, reread the code comments and variable names, and try to connect the pieces. The conditional compilation (`#ifdef __arm64e__`) was a clear indicator of distinct processing paths, which helped structure the explanation. Seeing the `ptrauth_` functions was a strong clue about pointer authentication being a key feature.
好的，让我们来详细分析一下 `frida/subprojects/frida-gum/gum/backend-darwin/helpers/fixupchainprocessor.c` 这个文件的功能。

**功能概述**

这个 C 源代码文件的主要功能是处理 macOS 和 iOS 等 Darwin 系统下 Mach-O 可执行文件和动态链接库中的 **chained fixups (链式修复)**。 Chained fixups 是一种优化动态链接过程的技术，用于在程序加载时更新代码和数据段中的指针，以适应实际加载的内存地址。

更具体地说，`fixupchainprocessor.c` 实现了以下关键功能：

1. **解析 Chained Fixups 数据结构:** 该文件定义了用于解析 Mach-O 文件中 `__LINKEDIT` 段的 `__chained_fixups` section 中存储的链式修复信息的逻辑。它读取并解释 `GumChainedFixupsHeader`、`GumChainedStartsInImage`、`GumChainedStartsInSegment` 等结构，这些结构描述了 fixup 信息在文件中的布局。

2. **遍历 Fixup 链:**  代码会遍历每个段（segment）和页（page）内的 fixup 链。 每个 fixup 条目指示了一个需要被修正的指针及其修正方式。

3. **应用 Fixup:** 根据不同的 fixup 类型（例如 `REBASE` 用于地址重定位，`BIND` 用于绑定外部符号）和架构（x86-64, ARM64e），代码会执行相应的操作来更新内存中的指针值。

4. **处理地址重定位 (Rebase):**  当 Mach-O 文件被加载到与首选基地址不同的实际地址时，需要对代码和数据段中的某些地址进行调整。  `gum_process_chained_fixups_in_segment_generic64` 和 `gum_process_chained_fixups_in_segment_arm64e` 函数会根据实际加载地址和首选加载地址的差异（称为 slide）来修正指针。

5. **处理符号绑定 (Bind):**  动态链接的程序依赖于外部库提供的符号（函数、变量等）。在加载时，动态链接器会解析这些符号的地址，并将这些地址写入到可执行文件或库的相应位置。`gum_process_chained_fixups_in_segment_generic64` 和 `gum_process_chained_fixups_in_segment_arm64e` 函数会使用 `bound_pointers` 数组来获取已解析符号的地址，并更新相应的指针。

6. **支持 ARM64e 的 Pointer Authentication (指针认证):** 对于 ARM64e 架构（Apple 新一代处理器），该文件还支持处理带有指针认证码 (PAC) 的指针。`gum_sign_pointer` 函数实现了对指针进行签名（在原始地址上应用 PAC）的操作，以确保指针的完整性和来源可靠性。

**与逆向方法的关联及举例说明**

`fixupchainprocessor.c` 与逆向工程密切相关，因为它处理的是程序加载和动态链接的关键步骤。逆向工程师需要理解这些过程才能正确分析程序的行为。

**举例说明:**

假设一个逆向工程师正在分析一个被 ASLR 保护的 macOS 应用程序。该应用程序调用了一个动态链接库中的函数。

1. **静态分析阶段:** 逆向工程师可能会使用工具（如 Hopper 或 IDA Pro）来查看 Mach-O 文件的结构，包括 `__LINKEDIT` 段中的 `__chained_fixups` section。他们会看到一系列的 fixup 条目，指示哪些指针需要被重定位或绑定。然而，在静态分析中，这些指针的值是相对于首选基地址的，而不是实际运行时的地址。

2. **动态分析阶段 (Frida 的作用):**  当逆向工程师使用 Frida 来动态分析该程序时，`fixupchainprocessor.c` 这样的代码就在幕后发挥作用。当程序被加载时，操作系统会将库加载到内存中的某个地址。Frida 通过某种机制（不在本文档的讨论范围，但涉及到操作系统 API 的调用）获取到实际的加载地址和已解析的符号地址。

3. **`gum_process_chained_fixups` 的执行:** Frida 会调用 `gum_process_chained_fixups` 函数，将 Mach-O 头、首选基地址和已解析的符号地址传递给它。

4. **Fixup 的应用:**  `fixupchainprocessor.c` 会根据 fixup 信息，计算出实际的内存地址，并修改程序代码段或数据段中的指针。例如，如果一个指令原本指向库中某个函数的首选地址，但由于 ASLR，库被加载到不同的地址，那么 fixup 过程会将该指令中的地址更新为实际的运行时地址。

5. **逆向工程师的观察:** 逆向工程师通过 Frida 可以观察到程序在实际运行时的行为，包括函数调用、内存访问等。由于 Frida 能够正确处理 fixup，逆向工程师看到的是程序在内存中实际的状态，而不是静态分析中看到的未修正的状态。这对于理解程序的真实逻辑至关重要。

**二进制底层、Linux, Android 内核及框架的知识**

虽然此代码是针对 Darwin 系统的，但它涉及的许多概念在其他操作系统中也有相似之处：

* **二进制底层知识:**  理解 Mach-O 文件格式、段（segment）、节（section）、指针、内存地址、字节序等是理解这段代码的基础。
* **动态链接:**  了解动态链接的概念、重定位表、符号表、延迟绑定等有助于理解 fixup 的目的和机制。
* **内存管理:**  理解虚拟内存、地址空间布局随机化 (ASLR) 是理解地址重定位的关键。
* **CPU 架构:**  代码中针对 x86-64 和 ARM64e 的不同处理方式体现了对不同 CPU 架构的理解，特别是 ARM64e 的指针认证机制。

**Linux 和 Android 的对比:**

* **Linux:** Linux 系统使用 ELF (Executable and Linkable Format) 文件格式，其动态链接过程与 Mach-O 类似，但数据结构和实现细节有所不同。Linux 内核也有类似的机制来处理地址重定位和符号绑定。
* **Android:** Android 基于 Linux 内核，其可执行文件格式主要是 ELF 或 APK 中的 DEX/ART 格式。动态链接过程与 Linux 类似，但 Android Runtime (ART) 对代码的加载和链接有自己的优化和处理方式。

虽然 `fixupchainprocessor.c` 直接处理的是 Darwin 特定的 fixup 机制，但 Frida 的核心理念是跨平台的。Frida 在 Linux 和 Android 上也有类似的模块来处理 ELF 文件的重定位和符号绑定。

**逻辑推理、假设输入与输出**

**假设输入:**

* `fixups_header`: 指向 Mach-O 文件 `__LINKEDIT` 段中 `__chained_fixups` section 的起始地址，包含链式修复的元数据。
* `mach_header`: 指向 Mach-O 文件头的指针。
* `preferred_base_address`:  Mach-O 文件指定的首选加载基地址。
* `bound_pointers`: 一个数组，包含了动态链接器解析出的外部符号的实际内存地址。

**逻辑推理与输出:**

1. **读取 `fixups_header`:** 代码首先读取 `fixups_header` 来获取 fixup 信息的偏移量，例如 `starts_offset` 指向 `GumChainedStartsInImage` 结构。

2. **遍历段和页:**  代码遍历 `GumChainedStartsInImage` 和 `GumChainedStartsInSegment` 结构来确定每个段和页中 fixup 链的起始位置。

3. **处理 64 位 Rebase Fixup (假设 `format` 为 `GUM_CHAINED_PTR_64`):**
   - **输入:** `cursor` 指向一个 `GumChainedPtr64Rebase` 结构，包含 `next` (下一个 fixup 的偏移量), `high8` (目标地址的高 8 位), `target` (目标地址的低 36 位)。
   - **计算:**
     - `slide = actual_base_address - preferred_base_address;` 计算地址偏移量。
     - `unpacked_target = (uint64_t) item->high8 << (64 - 8) | item->target;` 重构目标地址。
     - `*slot = unpacked_target + slide;` 将指针的值更新为实际运行时地址。
   - **输出:** `cursor` 指向的内存位置被更新为正确的运行时地址。

4. **处理 64 位 Bind Fixup (假设 `format` 对应 Bind 类型):**
   - **输入:** `cursor` 指向一个 `GumChainedPtr64Bind` 结构，包含 `next` 和 `ordinal` (绑定符号在 `bound_pointers` 数组中的索引), `addend` (附加偏移量)。
   - **计算:**
     - `*slot = (uint64_t) (bound_pointers[item->ordinal] + item->addend);` 从 `bound_pointers` 数组中获取符号地址并加上偏移量。
   - **输出:** `cursor` 指向的内存位置被更新为绑定符号的实际运行时地址。

5. **循环处理:** 代码根据 `delta` 值移动 `cursor`，处理链中的下一个 fixup，直到 `delta` 为 0，表示 fixup 链结束。

**用户或编程常见的使用错误**

虽然用户通常不会直接调用 `gum_process_chained_fixups` 这样的底层函数，但在使用 Frida 进行高级操作时，可能会因为不当操作而间接导致问题：

1. **错误地修改 Mach-O 文件头或 Fixup 数据:**  如果用户试图手动修改 Mach-O 文件或其内存中的表示，可能会破坏 fixup 数据的完整性，导致 `gum_process_chained_fixups` 无法正确解析或应用 fixup。这可能会导致程序崩溃或行为异常。

2. **在错误的时刻干预内存:** 如果用户在 fixup 过程尚未完成时就修改了与 fixup 相关的内存区域，可能会导致 fixup 过程出错，例如覆盖了尚未被修正的指针。

3. **不正确的 `bound_pointers`:**  在某些高级的 Frida 使用场景中，用户可能需要模拟或提供自定义的 `bound_pointers` 数组。如果提供的符号地址不正确，会导致程序绑定到错误的地址，从而引发错误。

4. **与操作系统的加载器行为冲突:**  用户进行的一些内存操作可能与操作系统的动态链接器行为冲突，例如尝试在 fixup 过程完成后再次修改被 fixup 的指针。

**用户操作如何一步步到达这里（调试线索）**

`fixupchainprocessor.c` 通常在 Frida 内部的加载和代码修改过程中被调用。以下是一些可能的用户操作路径：

1. **Frida 脚本注入:** 用户编写 Frida 脚本并将其注入到目标进程中。
2. **进程附加:** Frida Agent 连接到目标进程。
3. **模块加载事件:** 当目标进程加载新的动态链接库时，Frida Agent 会收到通知。
4. **解析 Mach-O 文件:** Frida Agent 会解析新加载的库的 Mach-O 文件头，包括 `__LINKEDIT` 段和 `__chained_fixups` section。
5. **调用 `gum_process_chained_fixups`:** Frida Agent 的 Gum 库会调用 `gum_process_chained_fixups` 函数，将解析出的 fixup 信息、Mach-O 头和实际加载地址等参数传递给它。
6. **应用 Fixup:** `fixupchainprocessor.c` 中的代码会遍历并应用 fixup，更新库代码和数据段中的指针。
7. **代码修改 (Instrumentation):**  Frida 的核心功能是动态代码修改。当用户使用 Frida API（例如 `Interceptor.attach`，`Memory.write*` 等）修改目标进程的代码时，这些修改可能涉及到被 fixup 的地址。理解 fixup 过程有助于确保 Frida 的修改不会与动态链接过程冲突。
8. **符号解析:** 当 Frida 需要获取某个函数或变量的地址时，它需要考虑动态链接的影响。`fixupchainprocessor.c` 确保了内存中的指针指向正确的运行时地址，使得 Frida 能够准确地找到目标符号。

**作为调试线索:**

如果在使用 Frida 的过程中遇到与内存地址、函数调用、库加载等相关的异常行为，可以考虑以下调试线索：

* **查看 Frida 的日志:** Frida 通常会输出详细的日志信息，包括模块加载、内存操作等。这些日志可能包含与 fixup 过程相关的信息。
* **使用 Frida 的内存读取功能:**  可以在关键时间点读取内存中被 fixup 的地址，检查其值是否符合预期。
* **分析 Mach-O 文件:**  可以使用工具查看目标模块的 Mach-O 文件结构和 fixup 信息，了解预期的 fixup 行为。
* **检查目标进程的内存布局:**  了解目标进程的内存布局和模块加载地址有助于理解 fixup 的上下文。
* **逐步调试 Frida 脚本:**  使用 Frida 提供的调试功能，逐步执行脚本，观察在 fixup 过程前后内存的变化。

总而言之，`frida/subprojects/frida-gum/gum/backend-darwin/helpers/fixupchainprocessor.c` 是 Frida 在 Darwin 系统上实现动态 instrumentation 的关键组成部分，它负责确保程序在运行时能够正确地访问代码和数据，为 Frida 的代码注入、hook 和其他动态分析功能提供了坚实的基础。理解它的工作原理对于深入使用 Frida 和进行高级逆向工程至关重要。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/gum/backend-darwin/helpers/fixupchainprocessor.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2020-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "fixupchainprocessor.h"

#include <ptrauth.h>
#include <stdbool.h>

static void gum_process_chained_fixups_in_segment_generic64 (void * cursor,
    GumChainedPtrFormat format, uint64_t actual_base_address,
    uint64_t preferred_base_address, void ** bound_pointers);
#ifdef __arm64e__
static void gum_process_chained_fixups_in_segment_arm64e (void * cursor,
    GumChainedPtrFormat format, uint64_t actual_base_address,
    uint64_t preferred_base_address, void ** bound_pointers);
static void * gum_sign_pointer (void * ptr, uint8_t key, uintptr_t diversity,
    bool use_address_diversity, void * address_of_ptr);
static int64_t gum_sign_extend_int19 (uint64_t i19);
#endif

void
gum_process_chained_fixups (const GumChainedFixupsHeader * fixups_header,
                            struct mach_header_64 * mach_header,
                            size_t preferred_base_address,
                            void ** bound_pointers)
{
  const GumChainedStartsInImage * image_starts;
  uint32_t seg_index;

  image_starts = (const GumChainedStartsInImage *)
      ((const void *) fixups_header + fixups_header->starts_offset);

  for (seg_index = 0; seg_index != image_starts->seg_count; seg_index++)
  {
    const uint32_t seg_offset = image_starts->seg_info_offset[seg_index];
    const GumChainedStartsInSegment * seg_starts;
    GumChainedPtrFormat format;
    uint16_t page_index;

    if (seg_offset == 0)
      continue;

    seg_starts = (const GumChainedStartsInSegment *)
        ((const void *) image_starts + seg_offset);
    format = seg_starts->pointer_format;

    for (page_index = 0; page_index != seg_starts->page_count; page_index++)
    {
      uint16_t start;
      void * cursor;

      start = seg_starts->page_start[page_index];
      if (start == GUM_CHAINED_PTR_START_NONE)
        continue;
      /* Ignoring MULTI for now as it only applies to 32-bit formats. */

      cursor = (void *) mach_header + seg_starts->segment_offset +
          (page_index * seg_starts->page_size) +
          start;

      if (format == GUM_CHAINED_PTR_64 || format == GUM_CHAINED_PTR_64_OFFSET)
      {
        gum_process_chained_fixups_in_segment_generic64 (cursor, format,
            (uintptr_t) mach_header, preferred_base_address, bound_pointers);
      }
      else
      {
#ifdef __arm64e__
        gum_process_chained_fixups_in_segment_arm64e (cursor, format,
            (uintptr_t) mach_header, preferred_base_address, bound_pointers);
#else
        __builtin_unreachable ();
#endif
      }
    }
  }
}

static void
gum_process_chained_fixups_in_segment_generic64 (
    void * cursor,
    GumChainedPtrFormat format,
    uint64_t actual_base_address,
    uint64_t preferred_base_address,
    void ** bound_pointers)
{
  const int64_t slide = actual_base_address - preferred_base_address;
  const size_t stride = 4;

  while (TRUE)
  {
    uint64_t * slot = cursor;
    size_t delta;

    if ((*slot >> 63) == 0)
    {
      GumChainedPtr64Rebase * item = cursor;
      uint64_t top_8_bits, bottom_36_bits, unpacked_target;

      delta = item->next;

      top_8_bits = (uint64_t) item->high8 << (64 - 8);
      bottom_36_bits = item->target;
      unpacked_target = top_8_bits | bottom_36_bits;

      if (format == GUM_CHAINED_PTR_64_OFFSET)
        *slot = actual_base_address + unpacked_target;
      else
        *slot = unpacked_target + slide;
    }
    else
    {
      GumChainedPtr64Bind * item = cursor;

      delta = item->next;

      *slot = (uint64_t) (bound_pointers[item->ordinal] + item->addend);
    }

    if (delta == 0)
      break;

    cursor += delta * stride;
  }
}

#ifdef __arm64e__

static void
gum_process_chained_fixups_in_segment_arm64e (void * cursor,
                                              GumChainedPtrFormat format,
                                              uint64_t actual_base_address,
                                              uint64_t preferred_base_address,
                                              void ** bound_pointers)
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
        GumChainedPtrArm64eRebase * item = cursor;
        uint64_t top_8_bits, bottom_43_bits, unpacked_target;

        delta = item->next;

        top_8_bits = (uint64_t) item->high8 << (64 - 8);
        bottom_43_bits = item->target;

        unpacked_target = top_8_bits | bottom_43_bits;

        if (format == GUM_CHAINED_PTR_ARM64E)
          *slot = unpacked_target + slide;
        else
          *slot = actual_base_address + unpacked_target;

        break;
      }
      case 0b01:
      {
        GumChainedPtrArm64eBind * item = cursor;
        GumChainedPtrArm64eBind24 * item24 = cursor;
        uint32_t ordinal;

        delta = item->next;

        ordinal = (format == GUM_CHAINED_PTR_ARM64E_USERLAND24)
            ? item24->ordinal
            : item->ordinal;

        *slot = (uint64_t) (bound_pointers[ordinal] +
            gum_sign_extend_int19 (item->addend));

        break;
      }
      case 0b10:
      {
        GumChainedPtrArm64eAuthRebase * item = cursor;

        delta = item->next;

        *slot = (uint64_t) gum_sign_pointer (
            (void *) (preferred_base_address + item->target + slide),
            item->key, item->diversity, item->addr_div, slot);

        break;
      }
      case 0b11:
      {
        GumChainedPtrArm64eAuthBind * item = cursor;
        GumChainedPtrArm64eAuthBind24 * item24 = cursor;
        uint32_t ordinal;

        delta = item->next;

        ordinal = (format == GUM_CHAINED_PTR_ARM64E_USERLAND24)
            ? item24->ordinal
            : item->ordinal;

        *slot = (uint64_t) gum_sign_pointer (bound_pointers[ordinal],
            item->key, item->diversity, item->addr_div, slot);

        break;
      }
    }

    if (delta == 0)
      break;

    cursor += delta * stride;
  }
}

static void *
gum_sign_pointer (void * ptr,
                  uint8_t key,
                  uintptr_t diversity,
                  bool use_address_diversity,
                  void * address_of_ptr)
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

static int64_t
gum_sign_extend_int19 (uint64_t i19)
{
  int64_t result;
  bool sign_bit_set;

  result = i19;

  sign_bit_set = i19 >> (19 - 1);
  if (sign_bit_set)
    result |= 0xfffffffffff80000ULL;

  return result;
}

#endif

"""

```