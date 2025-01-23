Response:
Let's break down the thought process for answering the request about `mntent.h`.

**1. Understanding the Core Request:**

The core request is to analyze the `mntent.h` header file within the context of Android's Bionic library. This means explaining its purpose, functionality, relationship to Android, implementation details (especially for libc functions), and potential interactions with the dynamic linker. The request also asks for examples of usage errors, how Android reaches this code, and debugging techniques.

**2. Initial Analysis of `mntent.h`:**

The first step is to carefully read the header file. Key observations are:

* **Purpose:** It defines a structure `mntent` and functions for working with mount information. The comments and definitions like `MOUNTED` (`_PATH_MOUNTED`) point towards interacting with the `/proc/mounts` file (or a similar mechanism).
* **Structure `mntent`:**  It contains fields like `mnt_fsname`, `mnt_dir`, `mnt_type`, `mnt_opts`, `mnt_freq`, and `mnt_passno`. These directly correspond to the fields in a typical `/proc/mounts` entry.
* **Functions:**  The header declares functions like `getmntent`, `setmntent`, `endmntent`, and `hasmntopt`. These suggest operations like reading, writing, and querying mount information.
* **Bionic Context:** The inclusion of `<sys/cdefs.h>` and the `__BEGIN_DECLS` and `__END_DECLS` macros confirm this is part of Bionic. The `__BIONIC_AVAILABILITY_GUARD` macro indicates a feature added in API level 26.

**3. Categorizing the Required Information:**

To structure the answer, it's helpful to break down the requested information into categories:

* **Functionality:** What does this header file do?
* **Android Relationship:** How does this relate to the Android operating system?
* **libc Function Details:** How are the declared libc functions implemented?
* **Dynamic Linker:**  Is the dynamic linker involved? If so, how?
* **Logic/Examples:**  Provide concrete examples of usage and potential issues.
* **Android Framework/NDK Interaction:** How does Android use this?
* **Debugging:** How can this be debugged?

**4. Addressing Each Category (Iterative Process):**

* **Functionality:** This is straightforward. The header defines data structures and functions for accessing mount point information. The key file here is `/proc/mounts`.

* **Android Relationship:**  Think about where mount information is used in Android. Applications need to know about mounted filesystems for accessing files, checking permissions, etc. The Android framework needs to manage storage and mount points. Examples: StorageManager, PackageManager (for app installation locations), and system services that manage storage.

* **libc Function Details (The Core of the Analysis):** This requires deeper thinking about how these functions would be implemented:
    * **`getmntent`:**  Needs to open the mount file (likely `/proc/mounts`), read lines, parse each line according to a specific format (space-separated fields), allocate memory for the `mntent` structure, and populate its fields. It needs to handle potential errors like file not found or invalid format.
    * **`setmntent`:**  Opens a file for reading or writing mount information. The "type" argument indicates the mode ("r", "w", "a", etc.).
    * **`endmntent`:**  Closes the file pointer opened by `setmntent` or implicitly by `getmntent`. Important for resource management.
    * **`hasmntopt`:** Iterates through the comma-separated options string in `mnt_opts` and checks if the given option exists.
    * **`getmntent_r`:**  The reentrant version. Crucially, it requires the caller to provide the buffer, making it thread-safe. This highlights the importance of reentrancy in multithreaded environments.

* **Dynamic Linker:**  Initially, it might seem like the dynamic linker isn't directly involved. However, remember that `mntent.h` is part of libc, and applications link against libc. The dynamic linker loads libc into the process's memory space. While `mntent.h` itself doesn't introduce new shared libraries, the functions declared here are *part* of the libc.so. Therefore, when an application calls `getmntent`, the dynamic linker has already resolved this symbol to the address of the `getmntent` implementation *within* libc.so. The SO layout would be the standard libc.so layout.

* **Logic/Examples:**  Think of simple scenarios: reading mount information, checking for a specific mount option. Consider edge cases: an empty `/proc/mounts`, a malformed entry, trying to write to a read-only file.

* **Android Framework/NDK Interaction:** Trace the path from a high-level Android operation down to these low-level libc calls. For example, installing an app involves the PackageManager determining the installation location, which might involve checking mount points. The NDK allows developers to directly use these libc functions.

* **Debugging:**  `frida` is a natural choice for hooking these functions. Think about what you'd want to inspect: the filename passed to `setmntent`, the content of the `mntent` structure returned by `getmntent`, the options being checked by `hasmntopt`.

**5. Structuring the Output:**

Organize the answer logically, addressing each part of the request. Use clear headings and examples. Explain concepts simply. For the dynamic linker part, clarify that while the header itself isn't a separate SO, the functions are part of libc.so.

**6. Refinement and Review:**

After drafting the answer, review it for clarity, accuracy, and completeness. Are the explanations easy to understand? Are the examples helpful? Have all parts of the request been addressed?  For instance, make sure to explicitly mention `/proc/mounts` as the primary data source.

**Self-Correction Example during the process:**

Initially, I might focus too much on the file I/O aspects of `getmntent` and forget to explicitly mention the parsing of the lines in `/proc/mounts`. During the refinement stage, I would realize this is a crucial detail and add it to the explanation. Similarly, I might initially overlook the subtle but important role of the dynamic linker in resolving the symbols of these libc functions. Reviewing the request would remind me to address this aspect.

By following this structured thought process, we can generate a comprehensive and accurate answer to the complex request.
这个C头文件 `bionic/libc/include/mntent.handroid bionic` 定义了与**挂载点**信息相关的结构体和函数。它允许程序读取、操作和查询系统中的挂载点信息。由于 `bionic` 是 Android 的 C 库，这个文件提供的功能是 Android 系统基础功能的一部分。

**功能列举:**

1. **定义 `mntent` 结构体:**  该结构体用于存储单个挂载点的信息，包括挂载的文件系统、挂载点目录、文件系统类型、挂载选项等。
2. **定义与挂载点相关的常量:**  例如，`MOUNTED` 定义了挂载信息文件的路径（通常是 `/proc/mounts`），以及一些常见的挂载类型和选项字符串，如 `MNTTYPE_IGNORE`, `MNTTYPE_NFS`, `MNTOPT_RO` 等。
3. **声明用于操作挂载点信息的函数:**
   - `getmntent()`: 从一个打开的挂载信息文件中读取下一条挂载信息，并将其存储在 `mntent` 结构体中。
   - `setmntent()`: 打开一个挂载信息文件用于读取或写入。
   - `endmntent()`: 关闭由 `setmntent()` 打开的挂载信息文件。
   - `getmntent_r()`:  `getmntent()` 的线程安全版本，需要调用者提供用于存储结果的 `mntent` 结构体和缓冲区。
   - `hasmntopt()`: (Android API level 26 引入) 检查给定的挂载选项是否存在于 `mntent` 结构体的选项字符串中。

**与 Android 功能的关系及举例说明:**

`mntent.h` 中定义的功能是 Android 系统管理和应用程序运行时环境的关键组成部分。Android 需要了解文件系统的挂载状态来执行各种操作，例如：

* **存储管理:**  Android 的存储管理服务需要读取 `/proc/mounts` 来确定哪些分区被挂载，它们的类型，以及可用的空间等。例如，当你插入一个 SD 卡时，系统会读取挂载信息来识别新的存储设备并将其挂载。
* **应用安装和管理:**  PackageManager 服务需要知道应用可以安装在哪些分区。不同的分区可能有不同的属性（例如，是否允许执行代码），这可以通过检查挂载选项来确定。
* **权限管理:**  某些挂载选项（如 `nosuid`）会影响应用程序的权限。系统需要读取挂载信息来正确处理这些权限限制。
* **设备管理:**  Android 的设备管理服务可能需要访问挂载信息来了解设备的状态和配置。

**举例说明:**

假设一个应用需要知道外部存储（例如 SD 卡）是否以只读模式挂载。应用或 Android 框架可以使用以下步骤：

1. 使用 `setmntent(MOUNTED, "r")` 打开 `/proc/mounts` 文件进行读取。
2. 使用 `getmntent()` 循环读取每一条挂载信息。
3. 对于每一条挂载信息，检查 `mnt_dir` 是否为外部存储的挂载点（例如 `/sdcard` 或 `/mnt/media_rw/<uuid>`).
4. 如果找到了外部存储的挂载点，使用 `hasmntopt(mntent_struct, "ro")` 检查其挂载选项是否包含 "ro"。

**libc 函数的实现细节:**

由于没有提供 `mntent.c` 的源代码，我们只能推测其实现方式。这些函数通常会与底层的操作系统调用交互，来读取和解析挂载信息。

* **`getmntent(FILE* fp)`:**
    1. **读取行:** 从文件指针 `fp` 指向的文件中读取一行。这个文件通常是 `/proc/mounts`。
    2. **解析行:** 将读取的行按照特定的分隔符（通常是空格）分割成多个字段。每个字段对应 `mntent` 结构体中的一个成员。
    3. **分配内存:**  为 `mntent` 结构体中的字符串成员（`mnt_fsname`, `mnt_dir`, `mnt_type`, `mnt_opts`) 分配内存，并将解析出的字段复制到这些内存中。
    4. **填充结构体:** 将解析出的值填充到 `mntent` 结构体的相应成员中。
    5. **返回:** 返回指向填充后的 `mntent` 结构体的指针。如果到达文件末尾或发生错误，则返回 `NULL`。

* **`setmntent(const char* filename, const char* type)`:**
    1. **打开文件:** 使用 `fopen()` 函数以指定的模式 (`type`) 打开 `filename` 指定的文件。常见的模式有 "r" (只读), "r+" (读写), "w" (只写，覆盖), "a" (追加)。
    2. **返回:** 返回 `fopen()` 返回的文件指针。如果打开失败，则返回 `NULL`。

* **`endmntent(FILE* fp)`:**
    1. **关闭文件:** 使用 `fclose()` 函数关闭文件指针 `fp` 指向的文件。
    2. **返回:** 返回 `fclose()` 的返回值（通常是 0 表示成功，非 0 表示失败）。

* **`getmntent_r(FILE* fp, struct mntent* entry, char* buf, int size)`:**
    这个函数与 `getmntent()` 的功能类似，但它是线程安全的，因为它避免了静态存储。
    1. **读取行和解析:** 与 `getmntent()` 类似，从文件中读取一行并解析字段。
    2. **使用提供的缓冲区:** 将解析出的字符串复制到调用者提供的缓冲区 `buf` 中，大小为 `size`。这避免了 `getmntent()` 中动态分配内存的需求。
    3. **填充结构体:** 将解析出的值填充到调用者提供的 `mntent` 结构体 `entry` 中。
    4. **返回:** 返回指向 `entry` 的指针。如果到达文件末尾或发生错误，则返回 `NULL`。

* **`hasmntopt(const struct mntent* entry, const char* option)`:**
    1. **获取选项字符串:** 从 `mntent` 结构体中获取 `mnt_opts` 成员，这是一个逗号分隔的字符串，包含挂载选项。
    2. **查找选项:** 在 `mnt_opts` 字符串中查找是否存在给定的 `option` 字符串。通常需要处理选项之间可能的空格和逗号。
    3. **返回:** 如果找到选项，则返回指向该选项的指针（在 `mnt_opts` 中），否则返回 `NULL`。

**涉及 dynamic linker 的功能:**

`mntent.h` 本身是一个头文件，不包含可执行代码，因此不直接涉及 dynamic linker 的加载和链接过程。但是，它声明的函数（`getmntent`, `setmntent` 等）的实现在 `libc.so` 中。当一个应用程序调用这些函数时，dynamic linker 负责：

1. **加载 `libc.so`:** 在程序启动时，如果程序依赖于 `libc.so`，dynamic linker 会将其加载到进程的内存空间。
2. **符号解析:** 当程序调用 `getmntent` 时，dynamic linker 会在 `libc.so` 的符号表中查找 `getmntent` 函数的地址。
3. **重定位:**  如果 `getmntent` 函数内部引用了其他 `libc.so` 中的函数或全局变量，dynamic linker 会更新这些引用，使其指向正确的内存地址。

**so 布局样本 (libc.so 的简化示意):**

```
libc.so:
  .text:
    ...
    <getmntent 函数的代码>
    <setmntent 函数的代码>
    ...
  .data:
    ...
  .bss:
    ...
  .symtab:
    ...
    getmntent (地址: 0xXXXXXXXX)
    setmntent (地址: 0xYYYYYYYY)
    ...
  .dynsym:
    ...
    getmntent (地址: 0xXXXXXXXX)
    setmntent (地址: 0xYYYYYYYY)
    ...
```

**链接的处理过程:**

1. **编译时:** 编译器在编译应用程序的代码时，遇到对 `getmntent` 等函数的调用，会在其生成的对象文件中记录下对这些外部符号的引用。
2. **链接时:** 链接器将应用程序的多个对象文件以及所需的库（如 `libc.so`）链接在一起，生成最终的可执行文件。链接器会解析应用程序中对外部符号的引用，将其指向对应库中的符号地址。
3. **运行时:** 当应用程序启动时，操作系统的加载器会加载可执行文件。如果可执行文件依赖于共享库（如 `libc.so`），加载器会启动 dynamic linker。
4. **dynamic linker 接管:** dynamic linker 负责加载所有需要的共享库，并进行符号的动态解析和重定位。当应用程序首次调用 `getmntent` 时，dynamic linker 会确保 `libc.so` 已经被加载，并且 `getmntent` 的地址已经被正确解析和重定位。

**假设输入与输出 (针对 `getmntent`)**

**假设输入:**

一个包含以下内容的 `/proc/mounts` 文件：

```
sysfs /sys sysfs rw,seclabel,nosuid,nodev,noexec,relatime 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
devtmpfs /dev devtmpfs rw,seclabel,nosuid,size=1952752k,nr_inodes=488188,mode=755 0 0
none /mnt/media_rw/sdcard vfat rw,dirsync,nosuid,nodev,noexec,relatime,uid=1023,gid=1023,fmask=0007,dmask=0007,allow_utime=0020,codepage=437,iocharset=iso8859-1,shortname=mixed,utf8,errors=remount-ro 0 0
```

**假设调用:**

```c
FILE *fp = fopen("/proc/mounts", "r");
struct mntent *mnt;

while ((mnt = getmntent(fp)) != NULL) {
  printf("fsname: %s, dir: %s, type: %s, opts: %s\n",
         mnt->mnt_fsname, mnt->mnt_dir, mnt->mnt_type, mnt->mnt_opts);
}

fclose(fp);
```

**预期输出:**

```
fsname: sysfs, dir: /sys, type: sysfs, opts: rw,seclabel,nosuid,nodev,noexec,relatime
fsname: proc, dir: /proc, type: proc, opts: rw,nosuid,nodev,noexec,relatime
fsname: devtmpfs, dir: /dev, type: devtmpfs, opts: rw,seclabel,nosuid,size=1952752k,nr_inodes=488188,mode=755
fsname: none, dir: /mnt/media_rw/sdcard, type: vfat, opts: rw,dirsync,nosuid,nodev,noexec,relatime,uid=1023,gid=1023,fmask=0007,dmask=0007,allow_utime=0020,codepage=437,iocharset=iso8859-1,shortname=mixed,utf8,errors=remount-ro
```

**用户或编程常见的使用错误:**

1. **忘记关闭文件:** 使用 `setmntent` 打开文件后，忘记使用 `endmntent` 关闭文件，可能导致资源泄漏。
   ```c
   FILE *fp = setmntent(MOUNTED, "r");
   if (fp == NULL) {
       perror("setmntent");
       return 1;
   }
   // ... 使用 getmntent 读取信息 ...
   // 忘记调用 endmntent(fp);
   ```

2. **错误的文件打开模式:** 使用 `setmntent` 时，指定了错误的文件打开模式，例如尝试以写入模式打开 `/proc/mounts`，这通常是不允许的。
   ```c
   FILE *fp = setmntent(MOUNTED, "w"); // 错误：通常不能写入 /proc/mounts
   if (fp == NULL) {
       perror("setmntent");
       return 1;
   }
   ```

3. **假设 `mntent` 结构体中的字符串是持久的:**  `getmntent` 返回的 `mntent` 结构体中的字符串指针指向的内存可能在下次调用 `getmntent` 时被覆盖或释放。因此，如果需要长期保存这些字符串，必须进行复制。
   ```c
   FILE *fp = setmntent(MOUNTED, "r");
   struct mntent *mnt = getmntent(fp);
   char *fsname = mnt->mnt_fsname; // 错误：fsname 指向的内存可能在下次 getmntent 调用后无效
   // ... 稍后使用 fsname ...
   endmntent(fp);
   ```
   应该这样做：
   ```c
   FILE *fp = setmntent(MOUNTED, "r");
   struct mntent *mnt = getmntent(fp);
   char *fsname = strdup(mnt->mnt_fsname);
   // ... 使用 fsname ...
   free(fsname); // 使用完后释放内存
   endmntent(fp);
   ```

4. **在多线程环境中使用 `getmntent` 而不使用 `getmntent_r`:**  `getmntent` 使用静态内部缓冲区，因此在多线程环境下是非线程安全的。应该使用 `getmntent_r`，并为每个线程提供独立的 `mntent` 结构体和缓冲区。

**Android framework or ndk 是如何一步步的到达这里:**

以下是一个简化的路径，说明 Android framework 或 NDK 如何最终使用到 `mntent.h` 中定义的功能：

**Android Framework 示例 (StorageManager 获取挂载信息):**

1. **Java Framework (StorageManager.java):** Android Framework 中的 `StorageManager` 类提供了访问存储状态和管理存储设备的功能。
2. **Native Service (storaged):** `StorageManager` 的某些操作会通过 Binder IPC 调用到 native service `storaged`。
3. **Native Code (storaged):** `storaged` 是一个用 C++ 编写的守护进程。为了获取挂载信息，它可能会调用 Bionic 库提供的函数。
4. **Bionic Libc (getmntent 等):** `storaged` 会调用 `getmntent` 或相关函数来读取 `/proc/mounts` 并解析挂载信息。这些函数的实现就在 `bionic/libc/` 目录下。

**NDK 示例 (应用程序直接使用 libc 函数):**

1. **NDK Application Code (C/C++):** 使用 NDK 开发的应用程序可以直接包含 `mntent.h` 头文件。
2. **调用 libc 函数:** 应用程序代码可以调用 `getmntent`, `setmntent`, `hasmntopt` 等函数。
3. **链接到 libc.so:**  编译时，NDK 会将应用程序链接到 `libc.so`。
4. **运行时调用:**  当应用程序运行时，对 `getmntent` 等函数的调用会被 dynamic linker 解析并执行 `libc.so` 中对应的实现。

**Frida Hook 示例调试步骤:**

假设我们要 Hook `getmntent` 函数，查看每次读取到的挂载信息。

```python
import frida
import sys

package_name = "com.example.myapp" # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Received: {message['payload']}")
    else:
        print(message)

try:
    device = frida.get_usb_device(timeout=10)
    pid = device.spawn([package_name])
    session = device.attach(pid)
    script = session.create_script("""
        Interceptor.attach(Module.findExportByName("libc.so", "getmntent"), {
            onEnter: function(args) {
                console.log("[*] getmntent called");
            },
            onLeave: function(retval) {
                if (retval.isNull()) {
                    console.log("[*] getmntent returned NULL");
                    return;
                }
                const mntent = ptr(retval);
                const fsname = mntent.readPointer().readCString();
                const dir = mntent.add(Process.pointerSize).readPointer().readCString();
                const type = mntent.add(Process.pointerSize * 2).readPointer().readCString();
                const opts = mntent.add(Process.pointerSize * 3).readPointer().readCString();
                console.log("[*] getmntent returned:");
                console.log("    fsname: " + fsname);
                console.log("    dir: " + dir);
                console.log("    type: " + type);
                console.log("    opts: " + opts);
            }
        });
    """)
    script.on('message', on_message)
    script.load()
    device.resume(pid)
    sys.stdin.read()
except frida.ProcessNotFoundError:
    print(f"Error: Process with package name '{package_name}' not found.")
except Exception as e:
    print(f"An error occurred: {e}")
```

**步骤解释:**

1. **导入 frida 库:** 导入必要的库。
2. **指定包名:** 设置要附加的应用程序的包名。
3. **连接设备并附加进程:**  使用 `frida.get_usb_device()` 获取 USB 设备，并使用 `device.spawn()` 启动目标应用（如果它还未运行）或 `device.attach()` 附加到已运行的进程。
4. **创建 Frida Script:** 创建一个 Frida script，用于 Hook `getmntent` 函数。
5. **`Interceptor.attach`:** 使用 `Interceptor.attach` 函数来拦截对 `getmntent` 的调用。
6. **`onEnter`:** 在 `getmntent` 函数被调用之前执行的代码，这里简单地打印一条日志。
7. **`onLeave`:** 在 `getmntent` 函数返回之后执行的代码。
   - 检查返回值是否为 `NULL`。
   - 如果返回值不为 `NULL`，将其转换为 `NativePointer` 对象。
   - 根据 `mntent` 结构体的布局，读取各个成员的值（`fsname`, `dir`, `type`, `opts`）。注意需要根据系统的指针大小 (`Process.pointerSize`) 来计算偏移量。
   - 打印读取到的挂载信息。
8. **加载 Script 并恢复执行:** 使用 `script.load()` 加载脚本，并使用 `device.resume(pid)` 恢复目标应用程序的执行。
9. **监听消息:** 使用 `script.on('message', on_message)` 监听来自 Frida script 的消息。
10. **保持运行:** 使用 `sys.stdin.read()` 使脚本保持运行状态，以便持续监听 Hook 的结果。

运行此 Frida 脚本后，每当目标应用程序调用 `getmntent` 函数时，你将在控制台中看到相应的日志信息，包括读取到的挂载点信息。你可以根据需要修改脚本来 Hook 其他函数或执行更复杂的操作。

### 提示词
```
这是目录为bionic/libc/include/mntent.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
```c
/*
 * Copyright (C) 2008 The Android Open Source Project
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

#ifndef _MNTENT_H_
#define _MNTENT_H_

#include <sys/cdefs.h>

#include <stdio.h>
#include <paths.h>  /* for _PATH_MOUNTED */

#define MOUNTED _PATH_MOUNTED

#define MNTTYPE_IGNORE "ignore"
#define MNTTYPE_NFS "nfs"
#define MNTTYPE_SWAP "swap"

#define MNTOPT_DEFAULTS "defaults"
#define MNTOPT_NOAUTO "noauto"
#define MNTOPT_NOSUID "nosuid"
#define MNTOPT_RO "ro"
#define MNTOPT_RW "rw"
#define MNTOPT_SUID "suid"

struct mntent {
  char* _Nullable mnt_fsname;
  char* _Nullable mnt_dir;
  char* _Nullable mnt_type;
  char* _Nullable mnt_opts;
  int mnt_freq;
  int mnt_passno;
};

__BEGIN_DECLS

int endmntent(FILE* _Nullable __fp);
struct mntent* _Nullable getmntent(FILE* _Nonnull __fp);
struct mntent* _Nullable getmntent_r(FILE* _Nonnull __fp, struct mntent* _Nonnull __entry, char* _Nonnull __buf, int __size);
FILE* _Nullable setmntent(const char* _Nonnull __filename, const char* _Nonnull __type);

#if __BIONIC_AVAILABILITY_GUARD(26)
char* _Nullable hasmntopt(const struct mntent* _Nonnull __entry, const char* _Nonnull __option) __INTRODUCED_IN(26);
#endif /* __BIONIC_AVAILABILITY_GUARD(26) */


__END_DECLS

#endif
```