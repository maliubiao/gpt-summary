Response:
Let's break down the thought process for answering the prompt about `bionic/libc/bionic/elf_note.cpp`.

**1. Understanding the Goal:**

The primary goal is to analyze the provided C++ code snippet and explain its functionality within the context of Android's Bionic library, particularly focusing on its role in handling ELF notes. The request is multi-faceted, requiring explanations of individual functions, their relationship to Android, dynamic linking, potential errors, and how it's reached from higher levels.

**2. Initial Code Analysis (Superficial):**

First, I quickly read through the code. I noticed two main functions: `__get_elf_note` and `__find_elf_note`. The names suggest they are related to retrieving or locating ELF notes. I see they interact with ELF header structures (`ElfW(Nhdr)`, `ElfW(Phdr)`). The presence of `PT_NOTE` confirms the focus on note segments.

**3. Deeper Dive into `__get_elf_note`:**

* **Purpose:** This function appears to iterate through the notes within a single PT_NOTE segment of an ELF file.
* **Inputs:** It takes the desired `note_type`, `note_name`, the starting address of the note segment (`note_addr`), the corresponding program header (`phdr_note`), and output pointers for the found note header and description.
* **Logic:**  The function iterates byte by byte within the note segment. For each potential note entry:
    * It interprets the bytes as an `ElfW(Nhdr)`.
    * It extracts the name and description, accounting for padding (using `__builtin_align_up`).
    * It compares the extracted name and type with the target.
* **Error Handling:** It checks for invalid input (null pointers, incorrect segment type) and potential buffer overflows within the note segment.

**4. Deeper Dive into `__find_elf_note`:**

* **Purpose:** This function searches for a specific ELF note across *multiple* program headers.
* **Inputs:** It takes the desired `note_type`, `note_name`, an array of program headers (`phdr_start`), the number of program headers (`phdr_ct`), output pointers, and a `load_bias`.
* **Logic:** It iterates through each program header. If the header's type is `PT_NOTE`, it calls `__get_elf_note` to search within that segment. The `load_bias` is crucial for calculating the correct virtual address of the note segment in memory.

**5. Connecting to Android and Dynamic Linking:**

* **ELF Notes in Android:**  I know ELF notes are used in Android for various purposes, including identifying build IDs, ABI information, and security-related data (like SELinux contexts). This is a key connection to make.
* **Dynamic Linker's Role:** The dynamic linker (`linker64` or `linker`) is responsible for loading shared libraries and resolving symbols. It needs to parse ELF headers, including note segments, to perform these tasks correctly. This is a critical point.
* **`load_bias`:** The `load_bias` is fundamental in ASLR (Address Space Layout Randomization), a security feature in Android. The dynamic linker calculates this and uses it to relocate libraries in memory. `__find_elf_note` correctly incorporates this.

**6. Illustrative Examples and Scenarios:**

* **Basic Usage:**  Imagine a tool trying to read the build ID from a shared library. It would use these functions to find the `NT_GNU_BUILD_ID` note.
* **Dynamic Linking Process:**  When a shared library is loaded, the linker iterates through its program headers. If it finds a `PT_NOTE` segment, it might use `__find_elf_note` (or similar logic) to find specific notes for its internal operations.
* **User Errors:** Common errors would involve incorrect `note_type` or `note_name` values, or trying to access notes in a non-PT_NOTE segment.

**7. SO Layout and Linking Process:**

To illustrate the dynamic linking aspect, I need to create a simplified example of an SO file's layout, focusing on the note segment and the relevant parts of the linking process. This involves showing:

* **ELF Header:**  Identifying the entry point, program header table offset, etc.
* **Program Header Table:**  Highlighting the `PT_NOTE` entry.
* **Note Segment:**  Demonstrating the structure of a note (Nhdr, name, description).
* **Linking Process:** Briefly explaining how the linker locates and processes this information.

**8. Frida Hooking:**

To demonstrate how to observe this in action, Frida is a great tool. I need to provide a simple Frida script that intercepts calls to `__get_elf_note` or `__find_elf_note`, logs the arguments, and potentially modifies the behavior. This requires understanding Frida's basic syntax for hooking functions.

**9. Structure and Language (Chinese):**

Finally, I need to organize the information logically and present it clearly in Chinese, as requested. This involves:

* **Introduction:** Briefly explaining the file's purpose.
* **Function Explanations:**  Describing each function, its inputs, outputs, and logic.
* **Android Integration:**  Explaining the connection to Android's functionalities.
* **Dynamic Linking Details:** Providing the SO layout and linking process description.
* **User Errors:** Listing common pitfalls.
* **Android Framework/NDK Path:** Tracing how these components might lead to the execution of these functions.
* **Frida Example:**  Presenting the hook script.

**Self-Correction/Refinement During the Process:**

* **Initial Thought:**  Perhaps focusing too much on the low-level bit manipulation.
* **Correction:** Realizing the importance of explaining the *why* and the higher-level context of ELF notes in Android.
* **Initial Thought:**  Maybe a very complex SO layout example.
* **Correction:**  Simplifying the SO layout for clarity, focusing on the essential elements.
* **Initial Thought:**  A very technical Frida script with advanced features.
* **Correction:** A basic, easy-to-understand Frida script for demonstrating the concept.

By following these steps and constantly refining the approach, I can generate a comprehensive and accurate answer that addresses all aspects of the prompt.
这是一个关于 Android Bionic 库中 `elf_note.cpp` 文件的功能解释。这个文件主要负责处理 ELF (Executable and Linkable Format) 文件中的 Note 段 (NOTE segment)。Note 段可以包含各种辅助信息，例如构建 ID、ABI 信息等。

**功能列举:**

1. **`__get_elf_note` 函数:**
   - 功能：在给定的 PT_NOTE 程序头指向的内存区域中，查找特定类型的和名称的 ELF Note。
   - 核心任务是解析 Note 段的结构，遍历其中的 Note 条目，并比对类型和名称。

2. **`__find_elf_note` 函数:**
   - 功能：遍历 ELF 文件的所有程序头，查找类型为 PT_NOTE 的段，并在这些段中调用 `__get_elf_note` 来查找指定的 Note。
   - 核心任务是在整个 ELF 文件中定位包含 Note 的段，并委托 `__get_elf_note` 进行具体的查找。

**与 Android 功能的关系及举例说明:**

ELF Note 在 Android 中被广泛用于存储各种元数据，对于系统的正常运行和安全至关重要。

* **构建 ID (Build ID):**  ELF Note 可以包含构建 ID，用于唯一标识一个库或可执行文件的构建版本。这在调试和问题追踪中非常有用。例如，当报告一个崩溃时，可以包含库的构建 ID 以帮助开发者找到对应的代码版本。
    * **例子:** 动态链接器在加载共享库时，可能会读取其构建 ID 并与系统的期望值进行比较，以确保兼容性。
* **ABI 信息 (ABI Tag):** ELF Note 可以包含 ABI (Application Binary Interface) 信息，用于描述库或可执行文件所依赖的二进制接口。这对于确保不同组件之间的互操作性非常重要。
    * **例子:**  动态链接器会检查共享库的 ABI 信息，确保它与应用程序的 ABI 兼容。
* **SELinux 上下文 (SELinux Note):**  Android 使用 SELinux 进行强制访问控制。ELF Note 可以包含与安全上下文相关的信息。
    * **例子:**  `installd` 服务在安装 APK 时，可能会读取 native 库的 SELinux Note 来设置正确的文件安全上下文。
* **堆栈保护信息 (Stack Protector Note):**  一些编译器会在编译时添加堆栈保护机制。相关的配置信息可能会存储在 ELF Note 中。
    * **例子:**  动态链接器可能会读取这些信息来决定是否需要进行额外的安全检查。

**详细解释 libc 函数的功能实现:**

**1. `__get_elf_note` 函数实现:**

```c++
bool __get_elf_note(unsigned note_type, const char* note_name, const ElfW(Addr) note_addr,
                    const ElfW(Phdr)* phdr_note, const ElfW(Nhdr)** note_hdr,
                    const char** note_desc) {
  // 检查输入参数是否有效：程序头类型是否为 PT_NOTE，note_name 和 note_addr 是否为空。
  if (phdr_note->p_type != PT_NOTE || !note_name || !note_addr) {
    return false;
  }

  // 计算目标 Note 名称的长度（包括 null 终止符）。
  size_t note_name_len = strlen(note_name) + 1;

  // 从 Note 段的起始地址开始遍历。
  ElfW(Addr) p = note_addr;
  // 计算 Note 段的结束地址。
  ElfW(Addr) note_end = p + phdr_note->p_memsz;

  // 循环遍历 Note 段中的每个 Note 条目。
  while (p + sizeof(ElfW(Nhdr)) <= note_end) {
    // 将当前地址解释为 Note 头。
    const ElfW(Nhdr)* note = reinterpret_cast<const ElfW(Nhdr)*>(p);
    // 指针移动到 Note 头之后。
    p += sizeof(ElfW(Nhdr));

    // 将当前地址解释为 Note 名称。
    const char* name = reinterpret_cast<const char*>(p);
    // 计算 Note 名称占用的实际字节数（需要进行 4 字节对齐）。
    if (__builtin_add_overflow(p, __builtin_align_up(note->n_namesz, 4), &p)) {
      return false; // 防止溢出
    }

    // 将当前地址解释为 Note 描述。
    const char* desc = reinterpret_cast<const char*>(p);
    // 计算 Note 描述占用的实际字节数（需要进行 4 字节对齐）。
    if (__builtin_add_overflow(p, __builtin_align_up(note->n_descsz, 4), &p)) {
      return false; // 防止溢出
    }

    // 检查是否超出 Note 段的范围。
    if (p > note_end) {
      return false;
    }

    // 检查当前 Note 是否是我们要查找的 Note。
    if (note->n_type == note_type &&
        note->n_namesz == note_name_len &&
        strncmp(note_name, name, note_name_len) == 0) {
      // 找到目标 Note，将 Note 头和描述的指针赋值给输出参数。
      *note_hdr = note;
      *note_desc = desc;
      return true;
    }
  }
  // 未找到目标 Note。
  return false;
}
```

**关键实现点:**

* **参数校验:** 确保输入的程序头类型正确，名称和地址有效。
* **遍历 Note 段:**  循环遍历 Note 段中的每个 Note 条目。
* **解析 Note 结构:**  将内存中的数据按照 `ElfW(Nhdr)` 结构进行解析，获取 Note 的类型、名称大小和描述大小。
* **名称和描述定位:**  根据 Note 头的信息，计算出名称和描述在内存中的位置。
* **字节对齐:**  ELF Note 结构要求名称和描述字段进行 4 字节对齐。`__builtin_align_up` 用于计算对齐后的字节数。
* **比较:**  比较当前 Note 的类型和名称是否与目标匹配。

**2. `__find_elf_note` 函数实现:**

```c++
bool __find_elf_note(unsigned int note_type, const char* note_name, const ElfW(Phdr)* phdr_start,
                     size_t phdr_ct, const ElfW(Nhdr)** note_hdr, const char** note_desc,
                     const ElfW(Addr) load_bias) {
  // 遍历 ELF 文件的所有程序头。
  for (size_t i = 0; i < phdr_ct; ++i) {
    const ElfW(Phdr)* phdr = &phdr_start[i];

    // 如果当前程序头的类型是 PT_NOTE。
    if (phdr->p_type == PT_NOTE) {
      // 计算 Note 段在内存中的实际地址 (加上加载基址 load_bias)。
      ElfW(Addr) note_addr = load_bias + phdr->p_vaddr;
      // 调用 __get_elf_note 在当前 Note 段中查找目标 Note。
      if (__get_elf_note(note_type, note_name, note_addr, phdr, note_hdr, note_desc)) {
        // 找到目标 Note，返回 true。
        return true;
      }
    }
  }

  // 在所有 PT_NOTE 段中都未找到目标 Note。
  return false;
}
```

**关键实现点:**

* **遍历程序头:**  迭代 ELF 文件的程序头表。
* **查找 PT_NOTE 段:**  筛选出类型为 `PT_NOTE` 的程序头。
* **计算实际地址:**  由于共享库在加载时会被加载到随机的内存地址，需要加上 `load_bias` 来计算 Note 段在内存中的实际地址。
* **调用 `__get_elf_note`:**  将找到的 PT_NOTE 段的信息传递给 `__get_elf_note` 函数进行具体的 Note 查找。

**涉及 dynamic linker 的功能，对应的 so 布局样本和链接处理过程:**

假设我们有一个简单的共享库 `libtest.so`，它的布局可能如下（简化版）：

```
ELF Header:
  ...
  程序头表偏移量: ...
  程序头表条目数: ...
  ...

程序头表:
  [0]: 类型 PT_LOAD,  虚拟地址 0x... , 内存大小 0x...
  [1]: 类型 PT_NOTE,  虚拟地址 0x1000, 内存大小 0x100
  [2]: 类型 PT_DYNAMIC, 虚拟地址 0x... , 内存大小 0x...
  ...

.note 段 (对应 PT_NOTE):
  Note 1:
    n_namesz: 4
    n_descsz: 16
    n_type: 3 (假设是 NT_GNU_BUILD_ID)
    name: "GNU\0"
    description: [16 字节的构建 ID]

  Note 2:
    n_namesz: 8
    n_descsz: 8
    n_type: 1
    name: "Android\0"
    description: [8 字节的 ABI 信息]
  ...
```

**链接处理过程:**

1. **加载共享库:** 当应用程序需要使用 `libtest.so` 时，动态链接器（例如 `linker64`）会负责加载它到内存中。
2. **解析 ELF 头:** 链接器会首先解析 `libtest.so` 的 ELF 头，获取程序头表的位置和大小。
3. **遍历程序头表:** 链接器会遍历程序头表，找到类型为 `PT_NOTE` 的段。
4. **定位 Note 段:** 根据 `PT_NOTE` 段的 `p_vaddr` 和 `p_memsz`，链接器可以找到 Note 段在内存中的位置。
5. **查找特定 Note:**  如果链接器需要查找特定的 Note，例如构建 ID 或 ABI 信息，它会使用类似 `__find_elf_note` 的逻辑（或者直接实现类似的功能）来遍历 Note 段，并查找符合条件的 Note。
6. **使用 Note 信息:** 链接器会使用找到的 Note 信息进行后续的操作，例如验证构建 ID 的一致性或处理 ABI 兼容性。

**假设输入与输出 (针对 `__get_elf_note`):**

**假设输入:**

* `note_type`: 3 (假设要查找 `NT_GNU_BUILD_ID`)
* `note_name`: "GNU"
* `note_addr`:  0x1000 (PT_NOTE 段的起始地址)
* `phdr_note`: 指向 PT_NOTE 程序头的结构体
* `note_hdr`: 指向一个未初始化的 `ElfW(Nhdr)*` 指针
* `note_desc`: 指向一个未初始化的 `const char**` 指针

**预期输出:**

* 函数返回 `true` (如果找到了匹配的 Note)
* `*note_hdr`: 指向内存中构建 ID Note 的 `ElfW(Nhdr)` 结构
* `*note_desc`: 指向内存中构建 ID Note 的描述部分的起始地址

**假设输入与输出 (针对 `__find_elf_note`):**

**假设输入:**

* `note_type`: 1 (假设要查找 ABI 信息 Note)
* `note_name`: "Android"
* `phdr_start`: 指向 `libtest.so` 程序头表起始地址的指针
* `phdr_ct`: 程序头表中条目的数量
* `note_hdr`: 指向一个未初始化的 `ElfW(Nhdr)*` 指针
* `note_desc`: 指向一个未初始化的 `const char**` 指针
* `load_bias`: `libtest.so` 的加载基址

**预期输出:**

* 函数返回 `true` (如果找到了匹配的 Note)
* `*note_hdr`: 指向内存中 ABI 信息 Note 的 `ElfW(Nhdr)` 结构
* `*note_desc`: 指向内存中 ABI 信息 Note 的描述部分的起始地址

**用户或编程常见的使用错误:**

1. **错误的 `note_type` 或 `note_name`:**  如果提供的 `note_type` 或 `note_name` 与实际 Note 段中的值不匹配，将无法找到目标 Note。

   ```c++
   // 尝试查找不存在的 Note 类型
   ElfW(Nhdr)* note_header;
   const char* note_description;
   __find_elf_note(999, "MyNote", phdr_table, phdr_count, &note_header, &note_description, load_bias);
   // note_header 和 note_description 将不会被赋值
   ```

2. **在非 PT_NOTE 段调用 `__get_elf_note`:** `__get_elf_note` 假设输入的程序头类型是 `PT_NOTE`。如果在其他类型的段上调用，会导致错误的行为。

   ```c++
   // 错误的程序头，假设 phdr 指向 PT_LOAD 段
   ElfW(Nhdr)* note_header;
   const char* note_description;
   __get_elf_note(3, "GNU", load_address, phdr, &note_header, &note_description); // 错误的使用方式
   ```

3. **忘记添加加载基址 (`load_bias`):** 在 `__find_elf_note` 中，`load_bias` 对于计算 Note 段的实际内存地址至关重要。如果忘记添加，会导致在错误的内存地址查找。

   ```c++
   // 忘记添加 load_bias
   ElfW(Addr) note_addr_wrong = phdr->p_vaddr;
   __get_elf_note(3, "GNU", note_addr_wrong, phdr, &note_header, &note_description); // 可能会找不到 Note
   ```

4. **假设 Note 段总是存在:** 并非所有的 ELF 文件都包含 Note 段。在尝试查找 Note 之前，应该先检查是否存在 `PT_NOTE` 段。

**Android framework 或 NDK 如何一步步到达这里:**

1. **NDK 开发:** 开发者使用 NDK 编写 C/C++ 代码，这些代码会被编译成共享库 (`.so` 文件)。
2. **编译和链接:** 编译和链接过程中，编译器和链接器会将一些元数据信息写入到 `.so` 文件的 ELF Note 段中，例如构建 ID、ABI 信息等。
3. **APK 打包:** 这些 `.so` 文件会被打包到 APK 文件中。
4. **应用安装:** 当用户安装 APK 时，`installd` 服务会解析 APK 文件，并将其中的 native 库复制到设备上。
5. **加载共享库:** 当应用程序启动并需要使用某个 native 库时，Android 的动态链接器 (`/system/bin/linker` 或 `/system/bin/linker64`) 会负责加载该库到内存中。
6. **链接器操作:**  在加载和链接的过程中，动态链接器可能会需要读取 native 库的 ELF Note 信息，例如：
   - 验证构建 ID，确保加载的库是预期的版本。
   - 检查 ABI 兼容性，确保库与应用程序的 ABI 兼容。
   - 获取其他安全相关的元数据。
7. **调用 `elf_note.cpp` 中的函数:**  动态链接器内部会使用类似于 `__find_elf_note` 和 `__get_elf_note` 的逻辑（或者直接调用这些函数）来解析 ELF Note 段并获取所需的信息。

**Frida Hook 示例调试步骤:**

以下是一个使用 Frida Hook `__get_elf_note` 函数的示例：

```javascript
function hookGetElfNote() {
  const getElfNotePtr = Module.findExportByName("libc.so", "__get_elf_note");
  if (getElfNotePtr) {
    Interceptor.attach(getElfNotePtr, {
      onEnter: function (args) {
        const note_type = args[0].toInt();
        const note_name_ptr = args[1];
        const note_name = note_name_ptr.readCString();
        const note_addr = args[2];
        const phdr_note_ptr = args[3];

        console.log("Called __get_elf_note");
        console.log("  note_type:", note_type);
        console.log("  note_name:", note_name);
        console.log("  note_addr:", note_addr);
        // 可以进一步解析 phdr_note_ptr 指向的结构体
      },
      onLeave: function (retval) {
        console.log("__get_elf_note returned:", retval);
      },
    });
    console.log("Hooked __get_elf_note");
  } else {
    console.error("Failed to find __get_elf_note in libc.so");
  }
}

rpc.exports = {
  hook_elf_note: hookGetElfNote,
};
```

**调试步骤:**

1. **准备环境:** 确保已安装 Frida 和 adb，并且目标 Android 设备已 root 并运行 Frida Server。
2. **编写 Frida 脚本:** 将上面的 JavaScript 代码保存为例如 `hook_elf_note.js`。
3. **运行 Frida:** 使用 adb 连接到目标设备，并使用 Frida 附加到目标进程（例如，你要调试的应用程序的进程）：
   ```bash
   frida -U -f <your_app_package_name> -l hook_elf_note.js --no-pause
   ```
   或者，如果应用程序已经在运行：
   ```bash
   frida -U <your_app_package_name> -l hook_elf_note.js
   ```
4. **触发代码执行:**  在应用程序中执行会触发动态链接器加载共享库或访问 ELF Note 的操作。例如，启动一个使用了 native 库的功能。
5. **查看 Frida 输出:** Frida 会在控制台上打印出 `__get_elf_note` 被调用时的参数和返回值，你可以观察到动态链接器正在查找哪些类型的 Note，以及传递的参数。

通过这种方式，你可以深入了解 Android 系统在加载和链接共享库时如何处理 ELF Note 信息。你可以修改 Frida 脚本来 Hook `__find_elf_note` 或其他相关函数，以进一步分析链接过程。

### 提示词
```
这是目录为bionic/libc/bionic/elf_note.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
```

### 源代码
```cpp
/*
 * Copyright (C) 2024 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "platform/bionic/macros.h"
#include "private/elf_note.h"

#include <string.h>

bool __get_elf_note(unsigned note_type, const char* note_name, const ElfW(Addr) note_addr,
                    const ElfW(Phdr)* phdr_note, const ElfW(Nhdr)** note_hdr,
                    const char** note_desc) {
  if (phdr_note->p_type != PT_NOTE || !note_name || !note_addr) {
    return false;
  }

  size_t note_name_len = strlen(note_name) + 1;

  ElfW(Addr) p = note_addr;
  ElfW(Addr) note_end = p + phdr_note->p_memsz;
  while (p + sizeof(ElfW(Nhdr)) <= note_end) {
    // Parse the note and check it's structurally valid.
    const ElfW(Nhdr)* note = reinterpret_cast<const ElfW(Nhdr)*>(p);
    p += sizeof(ElfW(Nhdr));
    const char* name = reinterpret_cast<const char*>(p);
    if (__builtin_add_overflow(p, __builtin_align_up(note->n_namesz, 4), &p)) {
      return false;
    }
    const char* desc = reinterpret_cast<const char*>(p);
    if (__builtin_add_overflow(p, __builtin_align_up(note->n_descsz, 4), &p)) {
      return false;
    }
    if (p > note_end) {
      return false;
    }

    // Is this the note we're looking for?
    if (note->n_type == note_type &&
        note->n_namesz == note_name_len &&
        strncmp(note_name, name, note_name_len) == 0) {
      *note_hdr = note;
      *note_desc = desc;
      return true;
    }
  }
  return false;
}

bool __find_elf_note(unsigned int note_type, const char* note_name, const ElfW(Phdr)* phdr_start,
                     size_t phdr_ct, const ElfW(Nhdr)** note_hdr, const char** note_desc,
                     const ElfW(Addr) load_bias) {
  for (size_t i = 0; i < phdr_ct; ++i) {
    const ElfW(Phdr)* phdr = &phdr_start[i];

    ElfW(Addr) note_addr = load_bias + phdr->p_vaddr;
    if (__get_elf_note(note_type, note_name, note_addr, phdr, note_hdr, note_desc)) {
      return true;
    }
  }

  return false;
}
```