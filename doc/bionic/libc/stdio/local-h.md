Response:
Let's break down the thought process for analyzing the `local.h` file.

**1. Initial Understanding - Context is Key:**

The prompt provides crucial context:  "bionic/libc/stdio/local.handroid bionic is Android's C library, math library, and dynamic linker." This immediately tells us:

* **Location:** This header file is specific to Android's C library (`libc`) and its standard input/output (`stdio`) implementation.
* **Purpose:** It likely contains internal definitions and data structures used *within* the `stdio` implementation, not necessarily exposed to regular user code. The `local.` prefix reinforces this idea of internal use.
* **Relevance to Android:**  Anything in this file is inherently tied to how Android handles standard I/O.

**2. High-Level Structure and Key Sections:**

I scanned the file for major structural elements:

* **Copyright and License:** Standard boilerplate, but confirms the origin and licensing. Knowing it's derived from BSD is useful background.
* **Includes:**  `pthread.h`, `stdbool.h`, `wchar.h`, and potentially `private/bionic_fortify.h`. These hint at threading support, boolean types, wide character support, and security hardening mechanisms within Android.
* **`__BEGIN_DECLS` / `__END_DECLS`:** These are common C preprocessor macros for managing C++ name mangling when mixing C and C++ code. This reinforces the fact that Android's `libc` needs to interact with C++ components.
* **`struct __sbuf`:**  A buffer structure, likely used internally for file I/O buffering.
* **`struct __sFILE`:**  The core structure representing a file stream. This is a *critical* element.
* **`struct wchar_io_data`:**  Data specific to wide character I/O operations.
* **`struct __sfileext`:** An "extension" structure for `__sFILE`, designed to avoid breaking ABI compatibility when adding new features. This is a common technique in system libraries.
* **Macros (starting with `__S...` and `_...`):**  Lots of macros defining flags, and accessing members of the structures.
* **Function Declarations:** Declarations of internal `stdio` functions. The `__LIBC32_LEGACY_PUBLIC__` macro is a strong indicator that these functions are (or were) public in 32-bit Android, likely for compatibility reasons.
* **More Macros (`cantwrite`, `HASUB`, `FREEUB`, `FLOCKFILE`, `FUNLOCKFILE`, `__sferror`, etc.):**  More utility macros.
* **Floating Point Related Definitions:** `MAXEXP`, `MAXFRACT`, `MAXEXPDIG`, and function declarations like `__hdtoa`, `__hldtoa`, `__ldtoa`.
* **Wide Character I/O Macros:** `WCIO_GET`, `_SET_ORIENTATION`, `WCIO_FREE`.
* **`CHECK_FP` Macro:** A safety check for null file pointers.

**3. Deeper Dive into Key Structures and Macros:**

* **`__sFILE`:** This is the heart of the `stdio` implementation. I examined each member:
    * `_p`, `_r`, `_w`:  Pointers and counters for buffer management (current position, read space, write space).
    * `_flags`, `_file`: Status flags and the underlying file descriptor. The `LP64` conditional compilation is important – different sizes for 32-bit and 64-bit architectures.
    * `_bf`: The buffer itself.
    * `_lbfsize`:  Line buffering size optimization.
    * Function Pointers (`_close`, `_read`, `_seek`, `_write`):  This immediately suggests the use of function pointers for custom I/O implementations (like `funopen`).
    * `_ext`, `_up`, `_ur`, `_ubuf`, `_nbuf`, `_lb`, `_blksize`, `_unused_0`: Extension data, ungetc buffer management, line buffer, block size, and a placeholder for an old field. The comments are valuable here.

* **`__sfileext`:** The comments explaining its purpose (ABI compatibility) are key. The members like `_ub` (ungetc buffer), `_wcio` (wide char I/O), `_lock` (threading), `_caller_handles_locking`, `_seek64`, and `_popen_pid` reveal important aspects of `stdio`'s functionality.

* **Flags (`__SLBF`, `__SNBF`, `__SRD`, etc.):**  Understanding the meaning of these flags is essential for understanding the state of a `FILE` object.

* **Macros:**  I paid attention to how macros like `_EXT`, `_UB`, `CHECK_FP`, and the locking macros operate. The use of `reinterpret_cast` and `static_cast` in the macros is notable.

**4. Identifying Android-Specific Aspects:**

* **`local.handroid` in the path:** This explicitly indicates Android-specific modifications or additions to the standard `stdio` implementation.
* **`__LIBC32_LEGACY_PUBLIC__`:**  This clearly points to Android's need to maintain backward compatibility for 32-bit applications.
* **`private/bionic_fortify.h`:** The inclusion of this header suggests security features specific to Android's `libc`.
* **`_popen_pid` in `__sfileext`:**  The comment directly links this to `popen(3)`, which is a common Unix/Linux function, but its presence here indicates its specific handling within Android.
* **The comment about NDK and indexing into the `__sFILE` array:** This is a *very* specific Android detail about how the NDK interacts with `stdio`.

**5. Connecting to System Concepts:**

* **Dynamic Linking:** The prompt mentions the dynamic linker. While this header doesn't directly *implement* dynamic linking, the concept of ABI stability and the `__sfileext` structure are closely related. Changes to the core `__sFILE` structure could break compatibility with dynamically linked libraries.
* **Threading (pthreads):** The inclusion of `pthread.h` and the `_lock` member in `__sfileext` clearly indicate that Android's `stdio` implementation is thread-safe (or at least aims to be).
* **File Descriptors:** The `_file` member directly relates to the underlying operating system's file descriptor concept.
* **Buffering:** The `__sbuf`, `_bf`, `_ubuf`, `_nbuf`, and `_lb` members are all about how `stdio` manages buffering for efficiency.

**6. Anticipating User Errors and Debugging:**

Based on the structure and functionality, I could anticipate common errors:

* **Null `FILE*`:** The `CHECK_FP` macro directly addresses this.
* **Incorrect Locking:**  The presence of locking mechanisms means users *could* misuse them or encounter deadlocks.
* **Buffer overflows (less likely with this header, but related to `stdio` in general).**
* **Incorrect handling of wide characters.**

For debugging, `frida` hooks are a natural fit for inspecting the state of `__sFILE` structures and intercepting calls to the internal `stdio` functions.

**7. Structuring the Output:**

Finally, I organized the information into logical sections as requested by the prompt: functionality, Android relevance, function implementation details, dynamic linker aspects, logical reasoning, common errors, and the Android framework/NDK path with Frida examples. I tried to provide concrete examples where possible. The iterative refinement of the explanation comes from revisiting the code and comments multiple times.
好的，让我们来详细分析一下 `bionic/libc/stdio/local.h` 这个头文件的内容和功能。

**文件功能概述**

`local.h` 是 Android Bionic C 库中 `stdio` 库的内部头文件。它的主要作用是定义了 `stdio` 库内部使用的数据结构、宏和函数声明。这些内容对于 `stdio` 库的实现至关重要，但通常不会直接暴露给用户代码。

**与 Android 功能的关系及举例**

这个文件直接关系到 Android 系统中所有涉及标准输入输出的功能。几乎所有 Android 应用程序都会间接或直接地使用 `stdio` 库提供的功能，例如：

* **文件操作:**  `fopen`, `fclose`, `fread`, `fwrite` 等函数依赖于 `__sFILE` 结构体的定义以及相关的内部函数。例如，当你使用 `fopen` 打开一个文件时，Bionic 的 `stdio` 实现会分配一个 `__sFILE` 结构体来表示这个文件流，并填充相关的信息，如文件描述符、缓冲区等。
* **格式化输入输出:** `printf`, `scanf`, `fprintf`, `fscanf` 等函数也依赖于此文件中的定义。例如，`printf` 函数需要知道如何处理缓冲区、如何与底层的文件描述符交互，这些都涉及到 `__sFILE` 结构体的成员。
* **错误处理:** `ferror`, `feof` 等函数通过检查 `__sFILE` 结构体中的 `_flags` 成员来判断是否发生错误或到达文件末尾。

**每一个 libc 函数的功能是如何实现的 (基于此头文件)**

此头文件本身并没有实现任何 `libc` 函数，它只是定义了数据结构和声明。但我们可以根据头文件中的定义来理解一些关键函数的实现思路：

* **`fopen`:**  `fopen` 的实现会分配一个 `__sFILE` 结构体，根据打开模式设置 `_flags`，获取或分配缓冲区 (`_bf`)，并设置文件描述符 (`_file`)。如果需要，还会初始化扩展信息 (`__sfileext`)。
* **`fread`:** `fread` 的实现会检查 `__sFILE` 结构体中的缓冲区 (`_bf`)，如果缓冲区有足够的数据，则直接从缓冲区读取。否则，会调用底层的 `read` 系统调用来填充缓冲区。读取后，更新 `_p` 指针和 `_r` 计数器。
* **`fwrite`:** `fwrite` 的实现会将数据写入 `__sFILE` 结构体的缓冲区 (`_bf`)。如果缓冲区满了，会调用底层的 `write` 系统调用将缓冲区的内容刷新到磁盘，然后再写入新的数据。更新 `_p` 指针和 `_w` 计数器。
* **`fclose`:** `fclose` 的实现会先刷新缓冲区中的数据（如果文件是以写入模式打开的），然后调用底层的 `close` 系统调用关闭文件描述符，并释放 `__sFILE` 结构体和相关缓冲区占用的内存。

**涉及 dynamic linker 的功能、so 布局样本和链接处理过程**

虽然 `local.h` 文件本身不直接涉及 dynamic linker 的具体实现细节，但其中一些设计考虑与动态链接有关：

* **`__sfileext` 结构体:**  这个结构体的存在是为了避免在 `__sFILE` 结构体中添加新成员导致 ABI (Application Binary Interface) 兼容性问题。当 `stdio` 库需要添加新的功能或状态时，可以将其添加到 `__sfileext` 中，而不是修改 `__sFILE` 的布局。这对于保持与已编译的动态链接库的兼容性至关重要。

**so 布局样本：**

```
# 假设 lib.so 是一个使用了 stdio 的动态链接库

ELF Header:
  ...
Program Headers:
  ...
  LOAD           0x00001000 vaddr 0x... memsz ... # 代码段
  LOAD           0x00002000 vaddr 0x... memsz ... # 数据段
Dynamic Section:
  NEEDED      libc.so  # 依赖 libc.so
  ...
Symbol Table:
  ...
  00003000 g    F .text  my_function  # 库中的函数
  ...
Relocation Table:
  OFFSET   TYPE             VALUE
  0x00004000 R_ARM_CALL       printf  # 需要链接到 libc.so 的 printf
  ...
```

**链接处理过程：**

1. **加载时：** 当 `lib.so` 被加载到内存时，dynamic linker 会解析其 `Dynamic Section`，发现它依赖于 `libc.so`。
2. **查找依赖：** dynamic linker 会在系统路径中查找 `libc.so`。
3. **符号解析：** dynamic linker 会解析 `lib.so` 的 `Relocation Table`，找到需要链接到 `libc.so` 的符号（例如 `printf`）。
4. **地址重定向：** dynamic linker 会在 `libc.so` 的符号表中查找 `printf` 的地址，并将这个地址填入 `lib.so` 中调用 `printf` 的位置。这样，`lib.so` 在运行时就能正确地调用 `libc.so` 中的 `printf` 函数。

**假设输入与输出 (逻辑推理)**

由于 `local.h` 主要定义数据结构，直接进行逻辑推理的例子可能不多。但我们可以考虑一个与缓冲区相关的假设：

**假设：** 调用 `fwrite` 向一个以行缓冲模式打开的文件写入少量数据，这些数据不足以填满缓冲区。

**输入：**
* 一个 `__sFILE` 结构体，其 `_flags` 设置了 `__SLBF` (行缓冲)。
* 要写入的数据，例如 "hello\n"。
* 缓冲区 `_bf` 的大小大于 "hello\n" 的长度。

**输出：**
* 数据 "hello\n" 被写入到 `__sFILE` 结构体的缓冲区 `_bf` 中。
* `_p` 指针向前移动相应的字节数。
* `_w` 计数器减少相应的字节数。
* 由于遇到了换行符 `\n`，缓冲区的内容会被刷新到文件描述符。

**用户或编程常见的使用错误**

* **忘记 `fclose`:**  打开文件后忘记关闭，会导致资源泄漏，特别是当程序运行时间较长时。
* **缓冲区溢出:**  在使用 `sprintf` 等函数时，如果提供的缓冲区大小不足以容纳格式化后的字符串，会导致缓冲区溢出，可能引发安全问题。
* **多线程访问同一个 `FILE*` 而没有进行适当的同步:**  `stdio` 库的一些操作不是线程安全的，多个线程同时操作同一个文件指针可能会导致数据竞争和未定义的行为。虽然 `__sfileext` 中有 `_lock` 成员，但在用户代码中仍然需要注意同步。
* **错误地假设缓冲区的大小:**  用户不应该直接操作 `__sFILE` 结构体的缓冲区，而应该使用 `stdio` 提供的函数。直接操作可能会导致数据不一致。
* **在二进制模式下读取文本文件或反之:**  这可能导致换行符处理错误或其他数据解析问题。

**Android framework 或 NDK 如何一步步的到达这里，给出 frida hook 示例调试这些步骤**

1. **Android Framework (Java 层):**  例如，`java.io.FileOutputStream` 或 `java.io.FileReader` 等类在底层会通过 JNI 调用到 Native 代码。
2. **NDK (Native 层):**  C/C++ 代码通过 NDK 调用 `fopen`, `fwrite`, `fread` 等 `stdio` 函数。
3. **Bionic libc:** 这些 `stdio` 函数的实现位于 Bionic libc 中，会涉及到 `local.h` 中定义的数据结构。

**Frida Hook 示例：**

假设我们想观察 `fopen` 函数的调用，以及它如何初始化 `__sFILE` 结构体。

```python
import frida
import sys

package_name = "your.app.package" # 替换成你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] Received: {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Process with package name '{package_name}' not found.")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "fopen"), {
    onEnter: function(args) {
        var filename = Memory.readUtf8String(args[0]);
        var mode = Memory.readUtf8String(args[1]);
        send({type: "info", data: "fopen called with filename: " + filename + ", mode: " + mode});
        this.filename = filename;
        this.mode = mode;
    },
    onLeave: function(retval) {
        send({type: "info", data: "fopen returned: " + retval});
        if (retval != 0) {
            // 读取 __sFILE 结构体的信息
            var fp = ptr(retval);
            var flags = Memory.readU16(fp.add(8)); // _flags 在 __sFILE 中的偏移量 (32位)
            var file = Memory.readS16(fp.add(10)); // _file 在 __sFILE 中的偏移量 (32位)
            send({type: "info", data: "__sFILE info: flags=" + flags + ", file=" + file});
        }
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**解释 Frida Hook 代码：**

1. **`frida.get_usb_device().attach(package_name)`:** 连接到 USB 设备上正在运行的目标应用进程。
2. **`Interceptor.attach(Module.findExportByName("libc.so", "fopen"), ...)`:**  Hook `libc.so` 中的 `fopen` 函数。
3. **`onEnter`:** 在 `fopen` 函数调用之前执行，读取文件名和打开模式。
4. **`onLeave`:** 在 `fopen` 函数返回之后执行，读取返回值（`FILE*` 指针），如果成功打开，则尝试读取 `__sFILE` 结构体的一些成员（`_flags` 和 `_file`）。**注意：这里的偏移量是基于 32 位架构的，64 位架构的偏移量可能不同。需要根据实际架构调整。**
5. **`send(...)`:**  将信息发送回 Frida 客户端。

**调试步骤：**

1. 确保你的 Android 设备已连接并通过 USB 调试授权。
2. 安装 Frida 和 Frida-tools (`pip install frida-tools`).
3. 运行包含要调试的 `stdio` 操作的 Android 应用。
4. 运行上述 Frida 脚本，替换 `your.app.package` 为你的应用包名。
5. 当应用调用 `fopen` 时，Frida 脚本会拦截调用并打印相关信息，包括传入的参数和返回的 `__sFILE` 结构体的部分信息。

要 hook 其他 `stdio` 函数，例如 `fwrite` 或 `fread`，只需要修改 `Module.findExportByName` 中的函数名即可。要观察 `__sFILE` 结构体的更多成员，需要找到这些成员在结构体中的偏移量，并使用 `Memory.read*` 函数读取它们。可以使用 GDB 或其他调试工具来确定这些偏移量。

希望以上详细的解释能够帮助你理解 `bionic/libc/stdio/local.h` 的作用以及它在 Android 系统中的地位。

Prompt: 
```
这是目录为bionic/libc/stdio/local.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*	$OpenBSD: local.h,v 1.12 2005/10/10 17:37:44 espie Exp $	*/

/*-
 * Copyright (c) 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Chris Torek.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#pragma once

#include <pthread.h>
#include <stdbool.h>
#include <wchar.h>

#if defined(__cplusplus)  // Until we fork all of stdio...
#include "private/bionic_fortify.h"
#endif

/*
 * Information local to this implementation of stdio,
 * in particular, macros and private variables.
 */

__BEGIN_DECLS

struct __sbuf {
  unsigned char* _base;
  size_t _size;
};

struct __sFILE {
  unsigned char* _p; /* current position in (some) buffer */
  int _r;            /* read space left for getc() */
  int _w;            /* write space left for putc() */
#if defined(__LP64__)
  int _flags; /* flags, below; this FILE is free if 0 */
  int _file;  /* fileno, if Unix descriptor, else -1 */
#else
  short _flags; /* flags, below; this FILE is free if 0 */
  short _file;  /* fileno, if Unix descriptor, else -1 */
#endif
  struct __sbuf _bf; /* the buffer (at least 1 byte, if !NULL) */
  int _lbfsize;      /* 0 or -_bf._size, for inline putc */

  // Function pointers used by `funopen`.
  // Note that `_seek` is ignored if `_seek64` (in __sfileext) is set.
  // TODO: NetBSD has `funopen2` which corrects the `int`s to `size_t`s.
  // TODO: glibc has `fopencookie` which passes the function pointers in a struct.
  void* _cookie; /* cookie passed to io functions */
  int (*_close)(void*);
  int (*_read)(void*, char*, int);
  fpos_t (*_seek)(void*, fpos_t, int);
  int (*_write)(void*, const char*, int);

  /* extension data, to avoid further ABI breakage */
  struct __sbuf _ext;
  /* data for long sequences of ungetc() */
  unsigned char* _up; /* saved _p when _p is doing ungetc data */
  int _ur;            /* saved _r when _r is counting ungetc data */

  /* tricks to meet minimum requirements even when malloc() fails */
  unsigned char _ubuf[3]; /* guarantee an ungetc() buffer */
  unsigned char _nbuf[1]; /* guarantee a getc() buffer */

  /* separate buffer for fgetln() when line crosses buffer boundary */
  struct __sbuf _lb; /* buffer for fgetln() */

  /* Unix stdio files get aligned to block boundaries on fseek() */
  int _blksize; /* stat.st_blksize (may be != _bf._size) */

  fpos_t _unused_0;  // This was the `_offset` field (see below).

  // Do not add new fields here. (Or remove or change the size of any above.)
  // Although bionic currently exports `stdin`, `stdout`, and `stderr` symbols,
  // that still hasn't made it to the NDK. All NDK-built apps index directly
  // into an array of this struct (which was in <stdio.h> historically), so if
  // you need to make any changes, they need to be in the `__sfileext` struct
  // below, and accessed via `_EXT`.
};

/* minimal requirement of SUSv2 */
#define WCIO_UNGETWC_BUFSIZE 1

struct wchar_io_data {
  mbstate_t wcio_mbstate_in;
  mbstate_t wcio_mbstate_out;

  wchar_t wcio_ungetwc_buf[WCIO_UNGETWC_BUFSIZE];
  size_t wcio_ungetwc_inbuf;

  int wcio_mode; /* orientation */
};

struct __sfileext {
  // ungetc buffer.
  struct __sbuf _ub;

  // Wide char io status.
  struct wchar_io_data _wcio;

  // File lock.
  pthread_mutex_t _lock;

  // __fsetlocking support.
  bool _caller_handles_locking;

  // Equivalent to `_seek` but for _FILE_OFFSET_BITS=64.
  // Callers should use this but fall back to `__sFILE::_seek`.
  off64_t (*_seek64)(void*, off64_t, int);

  // The pid of the child if this FILE* is from popen(3).
  pid_t _popen_pid;
};

// Values for `__sFILE::_flags`.
#define __SLBF 0x0001  // Line buffered.
#define __SNBF 0x0002  // Unbuffered.
// __SRD and __SWR are mutually exclusive because they indicate what we did last.
// If you want to know whether we were opened read-write, check __SRW instead.
#define __SRD 0x0004   // Last operation was read.
#define __SWR 0x0008   // Last operation was write.
#define __SRW 0x0010   // Was opened for reading & writing.
#define __SEOF 0x0020  // Found EOF.
#define __SERR 0x0040  // Found error.
#define __SMBF 0x0080  // `_buf` is from malloc.
// #define __SAPP 0x0100 --- historical (fdopen()ed in append mode).
#define __SSTR 0x0200  // This is an sprintf/snprintf string.
// #define __SOPT 0x0400 --- historical (do fseek() optimization).
// #define __SNPT 0x0800 --- historical (do not do fseek() optimization).
// #define __SOFF 0x1000 --- historical (set iff _offset is in fact correct).
// #define __SMOD 0x2000 --- historical (set iff fgetln modified _p text).
#define __SALC 0x4000  // Allocate string space dynamically.
#define __SIGN 0x8000  // Ignore this file in _fwalk.

// TODO: remove remaining references to these obsolete flags (see above).
#define __SMOD 0
#define __SNPT 0
#define __SOPT 0

#define _EXT(fp) __BIONIC_CAST(reinterpret_cast, struct __sfileext*, (fp)->_ext._base)

#define _UB(fp) _EXT(fp)->_ub

#define _FILEEXT_SETUP(fp, fext)                                              \
  do {                                                                        \
    (fp)->_ext._base = __BIONIC_CAST(reinterpret_cast, unsigned char*, fext); \
    memset(_EXT(fp), 0, sizeof(struct __sfileext));                           \
    _EXT(fp)->_caller_handles_locking = true;                                 \
  } while (0)

// Android <= 19 had getc/putc macros in <stdio.h> that referred
// to __srget/__swbuf, so those symbols need to be public for LP32
// but can be hidden for LP64. Moreover, the NDK continued to ship
// those macros until r15 made unified headers the default.
__LIBC32_LEGACY_PUBLIC__ int __srget(FILE*);
__LIBC32_LEGACY_PUBLIC__ int __swbuf(int, FILE*);
__LIBC32_LEGACY_PUBLIC__ int __srefill(FILE*);

/* This was referenced by the apportable middleware for LP32. */
__LIBC32_LEGACY_PUBLIC__ int __swsetup(FILE*);

/* These were referenced by a couple of different pieces of middleware and the Crystax NDK. */
__LIBC32_LEGACY_PUBLIC__ int __sflags(const char*, int*);
__LIBC32_LEGACY_PUBLIC__ FILE* __sfp(void);
__LIBC32_LEGACY_PUBLIC__ void __smakebuf(FILE*);

/* These are referenced by the Greed for Glory franchise. */
__LIBC32_LEGACY_PUBLIC__ int __sflush(FILE*);
__LIBC32_LEGACY_PUBLIC__ int __sread(void*, char*, int);
__LIBC32_LEGACY_PUBLIC__ int __swrite(void*, const char*, int);
__LIBC32_LEGACY_PUBLIC__ fpos_t __sseek(void*, fpos_t, int);
__LIBC32_LEGACY_PUBLIC__ int __sclose(void*);
__LIBC32_LEGACY_PUBLIC__ int _fwalk(int (*)(FILE*));

off64_t __sseek64(void*, off64_t, int);
int __sflush_locked(FILE*);
int __swhatbuf(FILE*, size_t*, int*);
wint_t __fgetwc_unlock(FILE*);
wint_t __ungetwc(wint_t, FILE*);
int __vfprintf(FILE*, const char*, va_list);
int __svfscanf(FILE*, const char*, va_list);
int __vfwprintf(FILE*, const wchar_t*, va_list);
int __vfwscanf(FILE*, const wchar_t*, va_list);

/*
 * Return true if the given FILE cannot be written now.
 */
#define cantwrite(fp) ((((fp)->_flags & __SWR) == 0 || (fp)->_bf._base == NULL) && __swsetup(fp))

/*
 * Test whether the given stdio file has an active ungetc buffer;
 * release such a buffer, without restoring ordinary unread data.
 */
#define HASUB(fp) (_UB(fp)._base != NULL)
#define FREEUB(fp)                                         \
  {                                                        \
    if (_UB(fp)._base != (fp)->_ubuf) free(_UB(fp)._base); \
    _UB(fp)._base = NULL;                                  \
  }

#define FLOCKFILE(fp) \
  if (!_EXT(fp)->_caller_handles_locking) flockfile(fp)
#define FUNLOCKFILE(fp) \
  if (!_EXT(fp)->_caller_handles_locking) funlockfile(fp)

/* OpenBSD exposes these in <stdio.h>, but we only want them exposed to the implementation. */
#define __sferror(p) (((p)->_flags & __SERR) != 0)
#define __sclearerr(p) ((void)((p)->_flags &= ~(__SERR | __SEOF)))
#define __sgetc(p) (--(p)->_r < 0 ? __srget(p) : __BIONIC_CAST(static_cast, int, *(p)->_p++))

/* OpenBSD declares these in fvwrite.h, but we share them with C++ parts of the implementation. */
struct __siov {
  void* iov_base;
  size_t iov_len;
};
struct __suio {
  struct __siov* uio_iov;
  int uio_iovcnt;
  size_t uio_resid;
};
int __sfvwrite(FILE*, struct __suio*);
wint_t __fputwc_unlock(wchar_t wc, FILE* fp);

/* Remove the if (!__sdidinit) __sinit() idiom from untouched upstream stdio code. */
extern void __sinit(void);  // Not actually implemented.
#define __sdidinit 1

size_t parsefloat(FILE*, char*, char*);
size_t wparsefloat(FILE*, wchar_t*, wchar_t*);

// Check a FILE* isn't nullptr, so we can emit a clear diagnostic message
// instead of just crashing with SIGSEGV.
#define CHECK_FP(fp) \
  if (fp == nullptr) __fortify_fatal("%s: null FILE*", __FUNCTION__)

/*
 * Floating point scanf/printf (input/output) definitions.
 */

/* 11-bit exponent (VAX G floating point) is 308 decimal digits */
#define MAXEXP 308
/* 128 bit fraction takes up 39 decimal digits; max reasonable precision */
#define MAXFRACT 39

/*
 * MAXEXPDIG is the maximum number of decimal digits needed to store a
 * floating point exponent in the largest supported format.  It should
 * be ceil(log10(LDBL_MAX_10_EXP)) or, if hexadecimal floating point
 * conversions are supported, ceil(log10(LDBL_MAX_EXP)).  But since it
 * is presently never greater than 5 in practice, we fudge it.
 */
#define MAXEXPDIG 6
#if LDBL_MAX_EXP > 999999
#error "floating point buffers too small"
#endif

char* __hdtoa(double, const char*, int, int*, int*, char**);
char* __hldtoa(long double, const char*, int, int*, int*, char**);
char* __ldtoa(long double*, int, int, int*, int*, char**);

#define WCIO_GET(fp) (_EXT(fp) ? &(_EXT(fp)->_wcio) : NULL)

#define ORIENT_BYTES (-1)
#define ORIENT_UNKNOWN 0
#define ORIENT_CHARS 1

#define _SET_ORIENTATION(fp, mode)                                              \
  do {                                                                          \
    struct wchar_io_data* _wcio = WCIO_GET(fp);                                 \
    if (_wcio && _wcio->wcio_mode == ORIENT_UNKNOWN) _wcio->wcio_mode = (mode); \
  } while (0)

#define WCIO_FREE(fp)                           \
  do {                                          \
    struct wchar_io_data* _wcio = WCIO_GET(fp); \
    if (_wcio) {                                \
      _wcio->wcio_mode = ORIENT_UNKNOWN;        \
      _wcio->wcio_ungetwc_inbuf = 0;            \
    }                                           \
  } while (0)

__END_DECLS

"""

```