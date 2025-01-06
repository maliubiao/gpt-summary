Response:
Let's break down the thought process for analyzing this kernel header file.

**1. Initial Understanding and Goal:**

The first step is to understand what the file *is* and what the request asks for. The prompt clearly states this is a kernel UAPI (userspace API) header file for the `wmi.handroid` subsystem within the Android kernel. The main goal is to explain its functionality, its connection to Android, and how it's used.

**2. Deconstructing the File Content - Keyword Analysis:**

Next, we examine the contents of the header file itself. I would look for keywords and patterns:

* **`#ifndef _UAPI_LINUX_WMI_H` / `#define _UAPI_LINUX_WMI_H` / `#endif`:** This is a standard header guard, preventing multiple inclusions. It's important to note, but doesn't reveal specific functionality.
* **`#include <linux/ioctl.h>` / `#include <linux/types.h>`:** These are crucial. They tell us that this subsystem likely uses the `ioctl` system call for communication between userspace and the kernel driver, and it relies on standard Linux data types.
* **`#define WMI_IOC 'W'`:** This defines the "magic number" for the `ioctl` commands. This is a key identifier for the WMI subsystem.
* **`struct wmi_ioctl_buffer`:** This looks like a generic buffer structure likely used for passing data through `ioctl`. The flexible array member `data[]` is a strong indicator of this.
* **`struct calling_interface_buffer`:**  This structure contains `cmd_class`, `cmd_select`, `input`, and `output`. This strongly suggests a command/response mechanism. The `volatile` keyword implies these fields might be accessed by both the user-space application and the kernel driver concurrently. The `__attribute__((__packed__))` is vital – it ensures no padding is added by the compiler, which is critical for binary data exchange with the kernel.
* **`struct dell_wmi_extensions`:** This suggests Dell-specific extensions to the WMI interface.
* **`struct dell_wmi_smbios_buffer`:** This combines the `calling_interface_buffer` with the Dell extensions, likely for specific SMBIOS-related commands.
* **`#define CLASS_TOKEN_READ 0` / `#define CLASS_TOKEN_WRITE 1` / ... and other `#define`s:** These are symbolic constants that define specific commands and sub-commands within the WMI interface. They provide a higher-level abstraction over raw numbers. The names themselves offer clues about their function (e.g., `CLASS_FLASH_INTERFACE`, `SELECT_RFKILL`).
* **`#define DELL_WMI_SMBIOS_CMD _IOWR(WMI_IOC, 0, struct dell_wmi_smbios_buffer)`:** This is the definition of a specific `ioctl` command. `_IOWR` signifies it's for writing data to the kernel and reading data back. `WMI_IOC` is the magic number, `0` is the command number (within the WMI subsystem), and `struct dell_wmi_smbios_buffer` specifies the data structure used.

**3. Inferring Functionality and Connections to Android:**

Based on the keywords and structure, I can start inferring functionality:

* **WMI (Windows Management Instrumentation) connection:** The name itself is a strong clue. This likely provides access to hardware and system information, originally inspired by or compatible with Windows' WMI.
* **`ioctl`-based communication:** The inclusion of `linux/ioctl.h` and the `_IOWR` macro confirm this.
* **Command/Response structure:** The `calling_interface_buffer` structure suggests sending commands with input and receiving responses in the output fields.
* **Dell Specificity:** The `dell_` prefixes indicate that this specific header deals with Dell hardware.
* **SMBIOS Access:** The `dell_wmi_smbios_buffer` and `DELL_WMI_SMBIOS_CMD` strongly point towards accessing SMBIOS (System Management BIOS) data, which contains hardware information.
* **Various Functionalities:** The defined constants like `CLASS_FLASH_INTERFACE`, `SELECT_RFKILL`, `SELECT_DOCK` hint at various functionalities like controlling flash devices, managing the radio kill switch (WiFi/Bluetooth), and interacting with docking stations.
* **Power Management:** Constants like `SELECT_TOKEN_BAT` and `SELECT_TOKEN_AC` suggest power management related functions.

Knowing this is within the Android kernel, the connection becomes clearer: Android devices (specifically Dell devices in this case) use this interface to interact with the hardware at a low level.

**4. Addressing Specific Requirements of the Prompt:**

* **Listing Functionality:**  Summarize the inferred functionalities based on the keyword analysis.
* **Android Relationship:** Explain how these functionalities are relevant to Android (e.g., getting battery info, controlling radios).
* **`libc` Functions:** This is where careful reading is important. The header *defines structures and constants*, but it doesn't contain *implementations* of `libc` functions. The `ioctl` system call *is* a `libc` function, so focus on explaining its role in this context.
* **Dynamic Linker:**  This header file itself doesn't directly involve the dynamic linker. It's a *kernel* header. However, *using* this interface from a user-space application *will* involve the dynamic linker loading `libc`. So the answer should focus on that connection and provide a basic example of a dynamically linked executable using `ioctl`.
* **Logic Reasoning (Assumptions):**  The command/response structure allows for basic input/output examples.
* **Common Errors:** Focus on the common pitfalls when using `ioctl`, like incorrect data structures, sizes, or permissions.
* **Android Framework/NDK Path:** Explain the layers involved: Framework (Java) -> JNI -> NDK (C/C++) -> `ioctl` system call.
* **Frida Hook:** Provide a basic Frida example targeting the `ioctl` system call when the WMI magic number is used.

**5. Structuring the Answer:**

Organize the information logically, addressing each point in the prompt clearly. Use headings and bullet points for better readability. Provide code examples where necessary (Frida hook, SO layout).

**Self-Correction/Refinement during the process:**

* **Initial thought:** "Are there any specific `libc` functions *defined* in this file?"  **Correction:** Realize it's a UAPI header, defining data structures for interaction *with* the kernel, not implementing `libc` functions. Focus on `ioctl`.
* **Initial thought:** "How does the dynamic linker *directly* interact with this?" **Correction:**  The header itself doesn't. The dynamic linker's role is in loading the `libc` that contains the `ioctl` function used to interact with this kernel interface.
* **Clarity:** Ensure the explanation of the Android framework/NDK path is clear and step-by-step.

By following this systematic approach, breaking down the file content, and addressing each aspect of the prompt, I can generate a comprehensive and accurate answer.
这是一个位于 Android Bionic 库中的内核 UAPI (用户空间应用程序接口) 头文件，用于定义与 Linux 内核中的 WMI (Windows Management Instrumentation) 子系统交互的数据结构和常量。由于历史原因，即使在 Linux 中，也经常能看到 WMI 的概念，特别是在硬件管理和系统信息获取方面。这里的 "handroid" 很可能是指针对 Android 平台进行了一些定制或适配。

让我们逐步分析其功能：

**1. 功能列举:**

* **定义用于与内核 WMI 驱动通信的数据结构:**
    * `struct wmi_ioctl_buffer`: 一个通用的缓冲区结构，用于通过 `ioctl` 系统调用向内核传递数据。
    * `struct calling_interface_buffer`: 定义了 WMI 命令的通用接口，包含命令类别 (`cmd_class`)、命令选择 (`cmd_select`) 以及输入 (`input`) 和输出 (`output`) 缓冲区。
    * `struct dell_wmi_extensions`:  定义了戴尔 (Dell) 特定 WMI 扩展的信息，可能用于传递额外的参数或属性。
    * `struct dell_wmi_smbios_buffer`: 结合了通用的命令接口和戴尔的扩展，专门用于与 SMBIOS (System Management BIOS) 相关的功能进行交互。
* **定义 WMI 命令的类别和选择码:**
    * `CLASS_TOKEN_READ`, `CLASS_TOKEN_WRITE`:  与令牌相关的读写操作。
    * `SELECT_TOKEN_STD`, `SELECT_TOKEN_BAT`, `SELECT_TOKEN_AC`:  令牌选择，可能与标准、电池和交流电源相关。
    * `CLASS_FLASH_INTERFACE`, `SELECT_FLASH_INTERFACE`:  与 Flash 接口相关的操作。
    * `CLASS_ADMIN_PROP`, `SELECT_ADMIN_PROP`:  管理属性相关的操作。
    * `CLASS_INFO`, `SELECT_RFKILL`:  信息查询，特别是与射频开关 (RFKill) 状态相关。
    * `SELECT_APP_REGISTRATION`:  应用注册相关的操作。
    * `SELECT_DOCK`:  与底座相关的操作。
* **定义特定的 WMI 命令令牌:**
    * `CAPSULE_EN_TOKEN`, `CAPSULE_DIS_TOKEN`:  可能与固件胶囊更新的启用和禁用相关。
    * `WSMT_EN_TOKEN`, `WSMT_DIS_TOKEN`:  可能与 Dell Wireless System Management Technology (WSMT) 的启用和禁用相关。
* **定义 `ioctl` 命令:**
    * `DELL_WMI_SMBIOS_CMD`:  用于执行与戴尔 SMBIOS 相关的 WMI 命令的 `ioctl` 请求。

**2. 与 Android 功能的关系及举例:**

这个头文件定义了 Android 系统中与特定硬件 (尤其是 Dell 设备) 进行底层交互的接口。Android Framework 或 Native 代码可以通过这个接口来获取硬件信息或控制硬件行为。以下是一些可能的应用场景：

* **获取电池信息:**  `SELECT_TOKEN_BAT` 可能用于获取电池状态、电量等信息。Android 的 BatteryManager 服务可能会通过 JNI 调用底层的代码，最终使用这个接口来获取电池数据并在 UI 上显示。
* **控制射频开关 (WiFi/蓝牙):** `SELECT_RFKILL` 可能用于查询或控制 WiFi 和蓝牙的开启/关闭状态。Android 的 ConnectivityService 或 Bluetooth 服务可能会用到这个接口。
* **获取设备硬件信息:** `DELL_WMI_SMBIOS_CMD` 用于访问 SMBIOS 数据，其中包含了主板型号、BIOS 版本、序列号等重要的硬件信息。Android 系统可以用这些信息进行设备识别、性能优化或者诊断。
* **控制设备功能:** 例如，`SELECT_DOCK` 可能用于检测或配置底座连接状态。
* **固件更新:** `CAPSULE_EN_TOKEN` 和 `CAPSULE_DIS_TOKEN` 暗示了系统可能通过 WMI 接口来控制固件更新过程。

**举例说明:**

假设 Android 系统需要获取设备的 BIOS 版本。一个可能的流程是：

1. **Android Framework (Java):**  某个系统服务 (例如 DeviceInfoManager) 需要获取 BIOS 版本。
2. **JNI (C/C++):**  Framework 层调用 Native 代码。
3. **Native 代码:**  Native 代码构造一个 `dell_wmi_smbios_buffer` 结构体，设置 `cmd_class` 和 `cmd_select` 为访问 SMBIOS 信息的对应值 (可能需要查阅更详细的文档，这里假设有对应的定义)。
4. **`ioctl` 调用:** Native 代码使用 `ioctl` 系统调用，传入文件描述符 (对应打开的 WMI 设备文件，例如 `/dev/wmi`) 和 `DELL_WMI_SMBIOS_CMD` 以及构造好的 `dell_wmi_smbios_buffer`。
5. **内核驱动:** 内核中的 WMI 驱动程序接收到 `ioctl` 请求，解析命令和数据，并与硬件 (SMBIOS) 进行交互。
6. **数据返回:**  驱动程序将从 SMBIOS 读取到的 BIOS 版本信息填充到 `dell_wmi_smbios_buffer` 的 `std.output` 缓冲区中。
7. **Native 代码处理:** Native 代码从 `ioctl` 调用中获取返回的数据，并解析出 BIOS 版本。
8. **JNI 返回:** Native 代码将 BIOS 版本信息返回给 Java 层。
9. **Android Framework 使用:** Framework 层获取到 BIOS 版本信息，可以用于显示或记录。

**3. 详细解释每一个 `libc` 函数的功能是如何实现的:**

这个头文件本身并没有定义或实现任何 `libc` 函数。它定义的是与内核交互的数据结构和常量。其中涉及到的是 `ioctl` 系统调用，它是一个 `libc` 函数，用于执行设备特定的控制操作。

**`ioctl` 函数的功能实现：**

`ioctl` 的实现非常复杂，因为它是一个通用的接口，可以执行各种不同的操作，具体行为取决于设备驱动程序。其基本流程如下：

1. **系统调用入口:** 用户空间的程序调用 `ioctl` 函数，这个调用会陷入内核，进入 `syscall` 或类似的入口点。
2. **参数检查:** 内核首先会检查 `ioctl` 的参数，包括文件描述符的有效性、命令码的有效性以及用户空间传递的缓冲区地址的有效性。
3. **查找设备驱动:** 内核根据文件描述符找到对应的设备驱动程序。
4. **调用设备驱动的 `ioctl` 函数:**  每个设备驱动程序都会实现自己的 `ioctl` 函数，内核会调用这个函数，并将用户空间传递的命令码和数据传递给驱动程序。
5. **驱动程序处理:** 设备驱动程序的 `ioctl` 函数会根据命令码执行相应的操作。这可能包括与硬件设备进行通信、读取或写入设备寄存器、执行特定的控制指令等等。
6. **数据传递:**  如果 `ioctl` 命令涉及到数据的传递 (例如 `_IOWR` 表示读写)，驱动程序会将数据从用户空间复制到内核空间，或者从内核空间复制到用户空间。
7. **返回结果:** 设备驱动程序的 `ioctl` 函数执行完毕后，会将结果返回给内核，内核再将结果返回给用户空间的程序。

**错误处理:** `ioctl` 调用可能会失败，例如文件描述符无效、命令码不支持、权限不足等等。如果发生错误，`ioctl` 函数通常会返回 -1，并设置 `errno` 全局变量来指示具体的错误类型。

**4. 对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件本身不直接涉及动态链接器。但是，用户空间的应用程序要使用这里定义的接口 (例如调用 `ioctl`)，就需要链接到 C 标准库 (`libc.so`)。

**so 布局样本 (libc.so 的部分):**

```
libc.so:
    ...
    .text:
        ioctl:  <ioctl 函数的机器码>
        ...
    .data:
        ...
    .bss:
        ...
    .dynsym:  <动态符号表，包含 ioctl 等符号>
        ioctl
        ...
    .dynstr:  <动态字符串表，包含符号名称>
        ioctl
        ...
    .plt:      <过程链接表，用于延迟绑定>
        ioctl@plt:
            jmp *GOT entry for ioctl
    .got:      <全局偏移表>
        ioctl:  <初始值为动态链接器的地址>
        ...
```

**链接的处理过程:**

1. **编译时:** 当编译链接用户空间的程序时，链接器 (例如 `ld`) 会注意到程序中使用了 `ioctl` 函数。由于 `ioctl` 是 `libc` 提供的，链接器会在生成的可执行文件中记录一个对 `ioctl` 符号的未定义引用。同时，链接器会记录需要链接的共享库 `libc.so`。
2. **加载时:** 当 Android 系统加载可执行文件时，动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 负责加载程序依赖的共享库。
3. **查找共享库:** 动态链接器会根据预定义的路径 (例如 `/system/lib64`, `/vendor/lib64` 等) 查找 `libc.so`。
4. **加载共享库:** 找到 `libc.so` 后，动态链接器将其加载到内存中。
5. **符号解析 (动态链接):** 动态链接器会遍历可执行文件和已加载的共享库的动态符号表 (`.dynsym`)。当遇到一个未定义的符号引用 (例如 `ioctl`) 时，动态链接器会在已加载的共享库的符号表中查找该符号的定义。
6. **重定位:** 找到 `ioctl` 的定义后，动态链接器会修改可执行文件中的全局偏移表 (GOT) 或过程链接表 (PLT) 中的条目，使其指向 `libc.so` 中 `ioctl` 函数的实际地址。
7. **延迟绑定 (如果使用 PLT):**  通常情况下，为了提高启动速度，动态链接器会使用延迟绑定。这意味着在程序第一次调用 `ioctl` 时，才会通过 PLT 跳转到动态链接器，由动态链接器完成符号解析和重定位，并将 `ioctl` 的实际地址填充到 GOT 中。后续的调用将直接通过 GOT 跳转到 `ioctl` 函数。

**5. 如果做了逻辑推理，请给出假设输入与输出:**

假设我们要通过 WMI 接口读取电池的剩余电量。

**假设输入 (基于 `struct calling_interface_buffer`):**

* `cmd_class`: 假设电池信息读取的类别是 `CLASS_TOKEN_READ` (值为 0)。
* `cmd_select`: 假设电池信息读取的选择码是 `SELECT_TOKEN_BAT` (值为 1)。
* `input`:  可能不需要输入参数，或者需要指定一些额外的参数，这里假设不需要，所以 `input` 数组可能都为 0。

**预期输出 (假设电量信息放在 `output` 数组的第一个元素):**

* `output[0]`:  假设返回的是剩余电量的百分比，例如 `85` 表示 85%。
* `output` 的其他元素可能包含其他电池相关信息，具体取决于 WMI 驱动的实现。

**逻辑推理:**

当用户空间的程序构造好包含上述输入的 `calling_interface_buffer` 结构体，并通过 `ioctl` 系统调用发送给内核 WMI 驱动后，驱动程序会根据 `cmd_class` 和 `cmd_select` 执行相应的操作，读取电池的电量信息，并将结果填充到 `output` 缓冲区中。用户空间的程序在 `ioctl` 调用返回后，可以读取 `output[0]` 的值来获取电池电量。

**6. 如果涉及用户或者编程常见的使用错误，请举例说明:**

* **错误的 `ioctl` 命令码:** 使用了错误的 `DELL_WMI_SMBIOS_CMD` 或自定义的命令码，导致内核驱动无法识别，`ioctl` 调用返回错误，`errno` 可能设置为 `ENOTTY` (Inappropriate ioctl for device)。
* **传递了错误大小的数据结构:**  例如，用户空间构造的 `dell_wmi_smbios_buffer` 结构体的大小与内核驱动期望的大小不一致，可能导致数据错乱或内核崩溃。
* **未初始化或错误初始化数据结构:**  例如，`calling_interface_buffer` 中的 `input` 或 `output` 缓冲区未正确初始化，导致传递给内核的数据不正确，或者读取到的数据无效。
* **权限问题:** 访问 WMI 设备文件 (例如 `/dev/wmi`) 需要特定的权限。如果用户空间的程序没有足够的权限，`open` 或 `ioctl` 调用会失败，`errno` 可能设置为 `EACCES` (Permission denied)。
* **并发访问问题:** 如果多个进程或线程同时尝试访问 WMI 设备，可能会导致竞争条件，数据不一致或崩溃。需要采取适当的同步机制。
* **假设输出格式:**  没有仔细阅读 WMI 驱动的文档，错误地假设 `output` 缓冲区中数据的格式和含义，导致解析结果错误。

**7. 说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**步骤说明:**

1. **Android Framework (Java):**  例如，`android.os.BatteryManager` 类提供了获取电池信息的 API。
2. **System Server (Java):** `BatteryService` 是一个运行在 System Server 进程中的服务，负责管理电池状态。`BatteryService` 内部会调用底层的 Native 代码来获取电池信息.
3. **JNI (C/C++):** `BatteryService` 通过 JNI 调用到 `frameworks/base/core/jni/android_os_BatteryStats.cpp` 中的 Native 方法。
4. **Native 代码 (C/C++):** `android_os_BatteryStats.cpp` 中的 Native 方法会打开 WMI 设备文件 (例如 `/dev/wmi`)，并构造相应的 `ioctl` 请求，使用这里定义的结构体和常量。
5. **`ioctl` 系统调用:** Native 代码调用 `ioctl` 函数，将请求发送给内核。
6. **内核驱动:** Linux 内核中的 WMI 驱动程序接收到 `ioctl` 请求，与硬件交互，获取电池信息。
7. **数据返回:** 内核驱动将获取到的数据返回给 Native 代码。
8. **JNI 返回:** Native 代码将数据返回给 `BatteryService`。
9. **Android Framework 使用:** `BatteryService` 将电池信息传递给其他的 Framework 组件，最终显示在 UI 上或供其他应用使用。

**Frida Hook 示例:**

以下是一个使用 Frida Hook 拦截 `ioctl` 系统调用，并打印与 WMI 相关的调用的示例：

```javascript
if (Process.arch === 'arm64' || Process.arch === 'x64') {
  const ioctlPtr = Module.getExportByName(null, 'ioctl');
  if (ioctlPtr) {
    Interceptor.attach(ioctlPtr, {
      onEnter: function (args) {
        const fd = args[0].toInt32();
        const request = args[1].toInt32();
        const argp = args[2];

        // 假设 WMI 设备的路径是 /dev/wmi
        try {
          const pathBuf = Memory.allocUtf8String(256);
          const ret = recv(fd, pathBuf, 255, 0);
          if (ret > 0) {
            const path = pathBuf.readUtf8String();
            if (path.includes('wmi')) {
              console.log(`[ioctl] FD: ${fd}, Request: 0x${request.toString(16)}`);
              // 可以进一步解析 argp 指向的数据，例如当 request 等于 DELL_WMI_SMBIOS_CMD 时
              if (request === 0xc0105700) { // DELL_WMI_SMBIOS_CMD 的值
                const bufferPtr = argp;
                const length = bufferPtr.readU64();
                console.log(`[ioctl]   Length: ${length}`);
                // 可以进一步读取 bufferPtr + 8 的数据
              }
            }
          }
        } catch (e) {
          // 某些 fd 可能无法通过 recv 获取路径
        }
      },
      onLeave: function (retval) {
        // console.log('[ioctl] Result:', retval);
      }
    });
  } else {
    console.error('Could not find ioctl symbol.');
  }
} else {
  console.warn('Frida hook example is for arm64/x64.');
}
```

**解释:**

1. **获取 `ioctl` 函数地址:**  使用 `Module.getExportByName(null, 'ioctl')` 获取 `ioctl` 函数在内存中的地址。
2. **拦截 `ioctl` 调用:** 使用 `Interceptor.attach` 拦截对 `ioctl` 函数的调用。
3. **`onEnter` 函数:**  在 `ioctl` 函数被调用之前执行。
4. **获取参数:**  `args` 数组包含了 `ioctl` 函数的参数：文件描述符 `fd`，请求码 `request`，以及指向参数的指针 `argp`。
5. **判断是否是 WMI 相关调用:**  这里尝试通过文件描述符获取打开的文件路径，如果路径包含 "wmi"，则认为是 WMI 相关的 `ioctl` 调用。
6. **打印信息:** 打印文件描述符和请求码。
7. **解析参数 (可选):**  如果请求码是 `DELL_WMI_SMBIOS_CMD`，则进一步解析 `argp` 指向的 `dell_wmi_smbios_buffer` 结构体，打印其长度。
8. **`onLeave` 函数:** 在 `ioctl` 函数调用返回后执行，可以打印返回值。

**运行 Frida 脚本:**

1. 将上述 JavaScript 代码保存为 `wmi_hook.js`。
2. 使用 Frida 连接到 Android 设备或模拟器上的 System Server 进程 (假设电池相关的操作在 System Server 进程中)：
   ```bash
   frida -U -f system_server -l wmi_hook.js --no-pause
   ```
   或者，如果进程已经运行：
   ```bash
   frida -U system_server -l wmi_hook.js
   ```
3. 当系统尝试获取电池信息时，Frida 脚本会拦截相关的 `ioctl` 调用，并在控制台上打印信息，帮助你理解 Android Framework 如何与底层的 WMI 接口进行交互。

通过这个 Frida Hook 示例，你可以观察到 `ioctl` 系统调用的参数，验证上述的步骤和假设，并深入了解 Android 系统与硬件的交互过程。 请注意，实际的请求码和数据结构可能需要根据具体的 Android 版本和设备进行调整。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/wmi.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*
 * This file is auto-generated. Modifications will be lost.
 *
 * See https://android.googlesource.com/platform/bionic/+/master/libc/kernel/
 * for more information.
 */
#ifndef _UAPI_LINUX_WMI_H
#define _UAPI_LINUX_WMI_H
#include <linux/ioctl.h>
#include <linux/types.h>
#define WMI_IOC 'W'
struct wmi_ioctl_buffer {
  __u64 length;
  __u8 data[];
};
struct calling_interface_buffer {
  __u16 cmd_class;
  __u16 cmd_select;
  volatile __u32 input[4];
  volatile __u32 output[4];
} __attribute__((__packed__));
struct dell_wmi_extensions {
  __u32 argattrib;
  __u32 blength;
  __u8 data[];
} __attribute__((__packed__));
struct dell_wmi_smbios_buffer {
  __u64 length;
  struct calling_interface_buffer std;
  struct dell_wmi_extensions ext;
} __attribute__((__packed__));
#define CLASS_TOKEN_READ 0
#define CLASS_TOKEN_WRITE 1
#define SELECT_TOKEN_STD 0
#define SELECT_TOKEN_BAT 1
#define SELECT_TOKEN_AC 2
#define CLASS_FLASH_INTERFACE 7
#define SELECT_FLASH_INTERFACE 3
#define CLASS_ADMIN_PROP 10
#define SELECT_ADMIN_PROP 3
#define CLASS_INFO 17
#define SELECT_RFKILL 11
#define SELECT_APP_REGISTRATION 3
#define SELECT_DOCK 22
#define CAPSULE_EN_TOKEN 0x0461
#define CAPSULE_DIS_TOKEN 0x0462
#define WSMT_EN_TOKEN 0x04EC
#define WSMT_DIS_TOKEN 0x04ED
#define DELL_WMI_SMBIOS_CMD _IOWR(WMI_IOC, 0, struct dell_wmi_smbios_buffer)
#endif

"""

```