Response:
Let's break down the thought process to answer the request about the `psp-sev.handroid` header file.

**1. Understanding the Core Request:**

The fundamental request is to analyze a C header file and explain its functionality, its relevance to Android, its implementation details (especially concerning libc and the dynamic linker), potential errors, and how it's used within the Android ecosystem. The user also requested a Frida hook example.

**2. Initial Analysis of the Header File:**

* **`auto-generated` and `bionic` context:** The header clearly states it's auto-generated and part of Bionic, Android's core C library. This immediately tells me it's related to low-level system interactions.
* **`psp-sev` naming:**  "PSP" likely stands for Platform Security Processor (or similar), and "SEV" likely refers to Secure Encrypted Virtualization, a technology from AMD. "handroid" reinforces its Android-specific nature. This suggests it deals with hardware-based security features.
* **`linux/types.h` inclusion:**  Standard Linux types are used, confirming interaction with the Linux kernel.
* **`enum` of commands (`SEV_FACTORY_RESET`, etc.):** This strongly indicates a set of specific operations that can be performed related to the SEV feature. These commands give hints about the functionality: managing platform status, keys, certificates, IDs, etc. The presence of `SNP_` prefixed commands suggests support for Secure Nested Paging, another security feature.
* **`enum` of return codes (`SEV_RET_SUCCESS`, `SEV_RET_INVALID_PLATFORM_STATE`, etc.):**  Standard error handling mechanism. The specific error codes provide insight into potential issues during SEV operations.
* **`struct` definitions:** These define the data structures used to pass information to and from the kernel for each command. The names of the structures usually correspond to the command they are associated with (e.g., `sev_user_data_status` for `SEV_PLATFORM_STATUS`). The `__attribute__((__packed__))` is important; it means these structures have no padding, ensuring binary compatibility.
* **`SEV_IOC_TYPE` and `SEV_ISSUE_CMD`:**  This reveals that the communication with the SEV subsystem happens through an ioctl system call. `_IOWR` indicates it's a command that both writes to and reads from the device.

**3. Connecting to Android Functionality:**

Given the security focus and the Bionic context, I started thinking about Android's security features. Hardware-backed key storage (Keystore/Keymaster), verified boot, and potentially even features like TrustZone (although SEV is AMD-specific, the concept is similar) came to mind. The presence of certificate management operations (PEK, PDH) strongly suggests involvement in attestation and secure boot processes.

**4. Explaining Libc Functions (ioctl):**

The core libc function here is `ioctl`. I needed to explain its general purpose (device control), how it works (file descriptor, request code, optional argument), and how it's used in this context (sending commands to the SEV driver).

**5. Dynamic Linker Aspects (Less Relevant Here):**

While this header file *is* part of Bionic, it primarily defines kernel interfaces. It doesn't directly involve dynamic linking. I recognized this and stated that the header itself doesn't directly link. However, *code that uses this header* will be part of a dynamically linked library or executable. I explained the basics of shared libraries, the linker's role, and provided a generic `.so` layout as requested, even though it's not specific to this header. The linking process involves resolving symbols, but this header mostly defines constants and structures.

**6. Logical Reasoning, Assumptions, Inputs, and Outputs:**

For logical reasoning, I focused on the ioctl interaction. I made the assumption that an Android process would open a device file (likely under `/dev`) associated with the SEV driver. Then, to execute a command like `SEV_PLATFORM_STATUS`, it would:

* Fill the `sev_issue_cmd` structure with the command and a pointer to a `sev_user_data_status` structure.
* Call `ioctl` with the file descriptor, `SEV_ISSUE_CMD`, and the address of the `sev_issue_cmd` structure.
* Check the `error` field in the `sev_issue_cmd` structure after the `ioctl` call.
* Access the data returned in the `sev_user_data_status` structure.

This formed the basis for the "假设输入与输出" section.

**7. Common Usage Errors:**

I thought about common mistakes when working with ioctl and kernel interfaces:

* **Incorrect file descriptor:** Trying to call ioctl on a closed or wrong file.
* **Invalid command code:** Using a command that's not defined.
* **Incorrect data structure:** Passing a structure with the wrong size or layout.
* **Memory management issues:**  Not allocating enough memory for buffers, passing invalid pointers.
* **Permissions:** Not having the necessary permissions to access the device file.

**8. Android Framework and NDK Usage:**

This is where I tried to connect the low-level header to higher-level Android components. I reasoned that:

* **Kernel Driver:** The SEV functionality is first implemented in a kernel driver.
* **HAL (Hardware Abstraction Layer):**  Android likely has a HAL module to abstract the kernel driver, providing a more stable and Android-specific interface.
* **NDK:**  NDK developers working on security-sensitive components might directly use the system call interface (through Bionic wrappers).
* **Framework (System Services):**  Android system services responsible for security features (like Keymaster) would likely interact with the HAL or potentially even the NDK interface.

I then constructed a hypothetical call flow.

**9. Frida Hook Example:**

The Frida example needed to target the `ioctl` call with the `SEV_ISSUE_CMD`. The hook should:

* Identify the target function (`ioctl`).
* Filter for calls where the `request` argument is `SEV_ISSUE_CMD`.
* Extract the `cmd` field from the `sev_issue_cmd` structure to identify the specific SEV operation.
* Potentially modify arguments or observe return values.

**10. Structuring the Answer:**

Finally, I organized the information into logical sections based on the user's request: 功能, 与 Android 的关系, libc 函数实现, 动态链接器, 逻辑推理, 使用错误, Android Framework/NDK, and Frida Hook. I used clear headings and formatting to make the answer easier to read.

**Self-Correction/Refinement during the process:**

* Initially, I might have overemphasized the dynamic linker's direct involvement with the *header file itself*. I corrected this to focus on how code *using* the header would be linked.
* I made sure to clearly distinguish between SEV and SNP commands.
* I tried to provide specific examples where possible (e.g., the ioctl call sequence, the Frida hook).
* I double-checked the meaning of `__attribute__((__packed__))` and its importance.

By following this thought process, breaking down the problem, and focusing on the key aspects of the request, I was able to generate a comprehensive and informative answer.
好的，让我们详细分析一下 `bionic/libc/kernel/uapi/linux/psp-sev.handroid` 这个头文件。

**文件功能：**

该头文件定义了用户空间程序与 Linux 内核中 Platform Security Processor Secure Encrypted Virtualization (PSP SEV) 子系统交互所需的常量、数据结构和命令。简单来说，它提供了用户空间调用 SEV 功能的接口。

具体来说，它定义了：

* **SEV 操作命令枚举 (`enum`)**:  列出了可以向 SEV 子系统发起的各种操作，例如：
    * `SEV_FACTORY_RESET`: 重置 SEV 固件。
    * `SEV_PLATFORM_STATUS`: 获取平台状态信息。
    * `SEV_PEK_GEN`: 生成平台密钥 (PEK)。
    * `SEV_PEK_CSR`: 生成 PEK 的证书签名请求 (CSR)。
    * `SEV_PDH_GEN`: 生成平台设备句柄 (PDH)。
    * `SEV_PDH_CERT_EXPORT`: 导出 PDH 证书。
    * `SEV_PEK_CERT_IMPORT`: 导入 PEK 证书。
    * `SEV_GET_ID`, `SEV_GET_ID2`: 获取平台标识符。
    * `SNP_PLATFORM_STATUS`: 获取安全嵌套分页 (SNP) 平台状态。
    * `SNP_COMMIT`: 提交 SNP 配置。
    * `SNP_SET_CONFIG`: 设置 SNP 配置。
    * `SNP_VLEK_LOAD`: 加载虚拟机启动密钥 (VLEK)。
* **SEV 返回码枚举 (`typedef enum`)**: 定义了 SEV 操作可能返回的各种结果代码，包括成功和各种错误状态。例如：
    * `SEV_RET_SUCCESS`: 操作成功。
    * `SEV_RET_INVALID_PLATFORM_STATE`: 无效的平台状态。
    * `SEV_RET_INVALID_LEN`: 无效的长度。
    * `SEV_RET_POLICY_FAILURE`: 策略失败。
* **数据结构 (`struct`)**:  定义了与不同 SEV 命令交互时需要传递的数据结构。这些结构体用于向内核传递参数或接收内核返回的数据。例如：
    * `sev_user_data_status`: 用于获取平台状态信息。
    * `sev_user_data_pek_csr`: 用于生成 PEK CSR。
    * `sev_user_data_pek_cert_import`: 用于导入 PEK 证书。
    * `sev_user_data_snp_status`: 用于获取 SNP 状态信息。
    * `sev_issue_cmd`:  核心结构体，用于封装要执行的 SEV 命令及其相关数据地址。
* **ioctl 定义 (`#define`)**:  定义了用于向 SEV 设备发送命令的 ioctl 请求码 (`SEV_ISSUE_CMD`)。

**与 Android 功能的关系及举例说明：**

这个头文件中的功能与 Android 的安全特性密切相关，尤其是在涉及硬件安全和虚拟机隔离方面。SEV 技术允许在 AMD 平台上创建加密的虚拟机，保护虚拟机内存不被 hypervisor 或其他虚拟机访问。Android 可以利用 SEV 来增强其安全性和可信执行环境 (TEE)。

以下是一些可能的关联举例：

* **密钥管理 (Keystore/Keymaster):** Android 的 Keystore 系统可以利用 SEV 来安全地生成和存储密钥。例如，`SEV_PEK_GEN` 可以用于生成平台相关的密钥，而 `SEV_PEK_CSR` 可以用于请求证书。
* **安全启动 (Verified Boot):**  SEV 可以作为 Android 安全启动过程的一部分，确保启动的固件和操作系统是可信的。平台状态 (`SEV_PLATFORM_STATUS`) 可以提供有关安全启动状态的信息。
* **虚拟机隔离 (Virtualization):** Android 可以利用 SEV 的加密虚拟机功能来隔离敏感进程或组件，例如支付相关的应用或安全模块。SNP 相关命令 (`SNP_PLATFORM_STATUS`, `SNP_COMMIT`, `SNP_SET_CONFIG`, `SNP_VLEK_LOAD`) 直接支持这种安全虚拟机技术。
* **远程证明 (Remote Attestation):**  通过使用 PDH (`SEV_PDH_GEN`, `SEV_PDH_CERT_EXPORT`)，Android 设备可以生成平台身份证明，供远程服务器验证设备的完整性和安全性。

**libc 函数的实现 (ioctl)：**

这个头文件本身并没有实现任何 libc 函数。它只是定义了与内核交互的接口。真正执行 SEV 操作的是内核驱动。

用户空间程序（包括 Android 的组件）会使用 libc 提供的 `ioctl` 系统调用来与 SEV 驱动进行通信。

`ioctl` 函数的原型如下：

```c
#include <sys/ioctl.h>

int ioctl(int fd, unsigned long request, ...);
```

* `fd`:  表示打开的设备文件的文件描述符，这个设备文件通常对应于 SEV 驱动（例如 `/dev/sev` 或类似的设备）。
* `request`:  是一个与设备相关的请求码，用于指定要执行的操作。在这个例子中，`request` 会是 `SEV_ISSUE_CMD`。
* `...`:  可选的第三个参数，通常是指向数据结构的指针，用于向设备传递数据或从设备接收数据。对于 `SEV_ISSUE_CMD`，这个参数会是指向 `struct sev_issue_cmd` 结构体的指针。

**实现流程：**

1. **打开设备文件：** 用户空间程序首先需要使用 `open()` 系统调用打开 SEV 驱动对应的设备文件。
2. **填充 `sev_issue_cmd` 结构体：**  程序根据需要执行的 SEV 操作，填充 `sev_issue_cmd` 结构体的 `cmd` 字段（例如，设置为 `SEV_PLATFORM_STATUS`）和 `data` 字段（指向包含操作参数的数据结构的地址）。
3. **调用 `ioctl`：**  程序调用 `ioctl()` 函数，将打开的设备文件描述符、`SEV_ISSUE_CMD` 请求码以及指向填充好的 `sev_issue_cmd` 结构体的指针作为参数传递给它。
4. **内核处理：** Linux 内核接收到 `ioctl` 调用后，会根据 `SEV_ISSUE_CMD` 请求码找到对应的 SEV 驱动处理函数。
5. **SEV 驱动执行操作：** SEV 驱动根据 `sev_issue_cmd` 结构体中的 `cmd` 和 `data` 信息，与 PSP 硬件进行交互，执行相应的 SEV 操作。
6. **返回结果：** SEV 驱动将操作结果（包括返回码和可能的数据）写回到用户空间指定的内存地址（通过 `sev_issue_cmd` 结构体传递），并返回 `ioctl` 系统调用。
7. **用户空间处理结果：** 用户空间程序检查 `ioctl` 的返回值和 `sev_issue_cmd` 结构体中的 `error` 字段，以确定操作是否成功，并处理返回的数据。

**动态链接器的功能和 SO 布局样本及链接处理过程：**

这个头文件本身并不直接涉及动态链接器的功能。它定义的是与内核交互的接口。然而，使用这个头文件的代码通常会编译成共享库 (`.so`)，这些共享库需要通过动态链接器加载和链接。

**SO 布局样本：**

一个可能包含使用 `psp-sev.handroid` 头文件中定义的接口的 `.so` 文件的布局样本如下：

```
my_sev_library.so:
  .init         # 初始化段
  .plt          # 过程链接表 (Procedure Linkage Table)
  .text         # 代码段，包含使用 ioctl 调用 SEV 功能的函数
  .rodata       # 只读数据段
  .data         # 可读写数据段
  .bss          # 未初始化数据段
  .dynamic      # 动态链接信息
  .symtab       # 符号表
  .strtab       # 字符串表
  .rel.plt      # PLT 重定位信息
  .rel.dyn      # 动态重定位信息
```

**链接处理过程：**

1. **编译时链接：** 当编译依赖于 `psp-sev.handroid` 的代码时，编译器会识别出需要调用 `ioctl` 等系统调用。由于 `ioctl` 是 libc 的一部分，编译器会在生成目标文件时记录下对 `ioctl` 的未解析引用。
2. **动态链接：** 当 Android 系统加载包含这些未解析引用的 `.so` 文件时，动态链接器 (linker，通常是 `linker64` 或 `linker`) 会执行以下步骤：
    * **加载共享库：** 将 `.so` 文件加载到内存中。
    * **解析符号：** 动态链接器会查找所需的符号（例如 `ioctl`）在哪些已加载的共享库中定义。对于 `ioctl`，它会在 `libc.so` 中找到。
    * **重定位：** 动态链接器会修改 `.so` 文件中的代码和数据，将对外部符号的引用绑定到它们在内存中的实际地址。这包括更新过程链接表 (PLT) 中的条目，以便在调用 `ioctl` 时跳转到 `libc.so` 中 `ioctl` 函数的正确地址。
    * **执行初始化代码：** 动态链接器会执行 `.init` 段中的代码，进行库的初始化。

**逻辑推理、假设输入与输出：**

假设一个 Android 组件想要获取 SEV 平台的当前状态。

**假设输入：**

* 打开 SEV 驱动的设备文件描述符 `fd`。
* `cmd` 设置为 `SEV_PLATFORM_STATUS`。
* `data` 指向一个 `sev_user_data_status` 结构体 `status` 的内存地址。

**执行过程：**

1. 用户空间程序分配 `sev_user_data_status` 结构体的内存。
2. 用户空间程序构造 `sev_issue_cmd` 结构体，设置 `cmd = SEV_PLATFORM_STATUS`，`data = (uintptr_t)&status`。
3. 用户空间程序调用 `ioctl(fd, SEV_ISSUE_CMD, &cmd)`。

**假设输出：**

* 如果 `ioctl` 返回 0，表示调用成功。
* `status` 结构体中的字段将被 SEV 驱动填充，例如：
    * `api_major`: SEV API 的主版本号。
    * `api_minor`: SEV API 的次版本号。
    * `state`: 当前平台状态（例如，初始化、准备就绪等）。
    * `flags`: 平台状态标志。
    * `build`: SEV 固件构建版本。
    * `guest_count`: 当前运行的加密虚拟机数量。
* 如果 `ioctl` 返回 -1，并且 `cmd.error` 中包含错误码（例如 `SEV_RET_NO_FW_CALL` 表示没有固件调用），则表示操作失败。

**用户或编程常见的使用错误：**

1. **未打开设备文件：**  在调用 `ioctl` 之前忘记使用 `open()` 打开 SEV 驱动的设备文件。
2. **使用了错误的设备文件路径：** 使用了错误的 SEV 驱动设备文件路径（可能因 Android 版本或硬件平台而异）。
3. **`sev_issue_cmd` 结构体填充错误：**
    * `cmd` 设置了无效的命令码。
    * `data` 指向了无效的内存地址或未分配内存。
    * `data` 指向的内存区域大小不足以容纳对应命令所需的数据结构。
4. **权限问题：**  用户空间程序没有足够的权限访问 SEV 驱动的设备文件。
5. **错误地解析返回码：**  没有正确检查 `ioctl` 的返回值或 `sev_issue_cmd.error` 字段，导致忽略了操作失败的情况。
6. **并发访问冲突：**  多个进程或线程同时尝试访问 SEV 驱动，可能导致资源竞争或状态错误。
7. **假设 SEV 功能始终可用：**  在某些 Android 设备或配置中，SEV 功能可能不可用或未启用，程序需要进行适当的检查和处理。

**Android Framework 或 NDK 如何一步步到达这里：**

1. **Android Framework/System Server:** Android Framework 中的某个系统服务（例如，负责密钥管理的 `Keymaster` 服务或虚拟机管理的 `VirtualizationService`）可能需要执行与 SEV 相关的操作。
2. **HAL (Hardware Abstraction Layer):**  系统服务通常不会直接调用内核接口，而是通过硬件抽象层 (HAL) 进行交互。可能会存在一个专门负责 SEV 功能的 HAL 模块。
3. **NDK (Native Development Kit):**  如果 Android 应用或库使用 NDK 开发，并且需要直接访问 SEV 功能，开发者可以使用 NDK 提供的系统调用接口。
4. **Bionic Libc:**  无论是通过 HAL 还是 NDK，最终都会调用 Bionic libc 提供的系统调用封装函数，例如 `ioctl`。
5. **系统调用 (syscall):**  Bionic libc 中的 `ioctl` 函数会触发一个系统调用，陷入内核态。
6. **Linux Kernel:** Linux 内核接收到 `ioctl` 系统调用后，会根据设备文件描述符找到对应的字符设备驱动程序，也就是 SEV 驱动。
7. **SEV 驱动:** SEV 驱动会解析 `ioctl` 请求中的命令和数据，并与 PSP 硬件进行通信，执行相应的安全操作。
8. **返回路径:** SEV 驱动将执行结果返回给内核，内核再将结果返回给 Bionic libc 的 `ioctl` 函数，最终返回到调用方（HAL 或 NDK 代码）。

**Frida Hook 示例调试步骤：**

假设我们想 hook `ioctl` 系统调用，查看当调用 `SEV_ISSUE_CMD` 时传递的命令参数。

```python
import frida
import sys

package_name = "your.target.package"  # 替换为目标应用的包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Message: {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"进程 '{package_name}' 未找到，请确保应用正在运行。")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "ioctl"), {
    onEnter: function(args) {
        const fd = args[0].toInt32();
        const request = args[1].toInt32();
        const argp = args[2];

        if (request === 0xc0105300) { // SEV_ISSUE_CMD 的值，需要根据实际情况确定
            console.log("[*] ioctl called with SEV_ISSUE_CMD");
            const cmdStruct = Memory.readByteArray(argp, 16); // 假设 sev_issue_cmd 结构体大小为 16 字节
            console.log("[*] sev_issue_cmd struct:", hexdump(cmdStruct));

            const cmd = ptr(argp).readU32();
            console.log("[*] Command:", cmd);

            // 可以根据 cmd 的值判断具体的 SEV 操作
            if (cmd === 0) {
                console.log("[*] SEV_FACTORY_RESET");
            } else if (cmd === 1) {
                console.log("[*] SEV_PLATFORM_STATUS");
                // 可以进一步读取 data 指向的结构体内容
            }
            // ... 其他命令的判断
        }
    },
    onLeave: function(retval) {
        console.log("[*] ioctl returned:", retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
session.detach()
```

**Frida Hook 调试步骤：**

1. **安装 Frida 和 Python 绑定：** 确保你的系统上安装了 Frida 和 Python 的 Frida 绑定。
2. **连接 Android 设备：** 将你的 Android 设备通过 USB 连接到电脑，并确保 adb 可用。
3. **找到目标进程：** 确定你想 hook 的 Android 应用或进程的包名或进程 ID。
4. **编写 Frida 脚本：**  根据上面的示例编写 Frida 脚本。
    * **确定 `SEV_ISSUE_CMD` 的值：** 你可能需要通过查看头文件或反汇编相关代码来确定 `SEV_ISSUE_CMD` 宏定义的实际数值（在示例中是 `0xc0105300`，你需要验证其正确性）。
    * **读取结构体内存：**  根据 `sev_issue_cmd` 结构体的定义，使用 `Memory.readByteArray` 读取其内容。
    * **解析命令参数：**  从读取的内存中解析出 `cmd` 字段，并根据其值判断具体的 SEV 操作。
    * **进一步读取 `data` 指向的内存：** 如果需要查看传递给 SEV 操作的具体数据，可以进一步读取 `sev_issue_cmd` 结构体中 `data` 字段指向的内存。
5. **运行 Frida 脚本：**  使用 `frida -U -f your.target.package -l your_script.py` 命令运行脚本（替换 `your.target.package` 和 `your_script.py`）。如果应用已经在运行，可以使用 `-n` 参数指定进程名称。
6. **观察输出：**  当目标应用调用 `ioctl` 并使用 `SEV_ISSUE_CMD` 时，Frida 脚本会在控制台打印出相关信息，包括传递的命令和参数。

通过这个 Frida hook 示例，你可以动态地观察 Android 系统或应用如何与 SEV 驱动进行交互，从而更好地理解其工作原理和调试相关问题。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/psp-sev.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * This file is auto-generated. Modifications will be lost.
 *
 * See https://android.googlesource.com/platform/bionic/+/master/libc/kernel/
 * for more information.
 */
#ifndef __PSP_SEV_USER_H__
#define __PSP_SEV_USER_H__
#include <linux/types.h>
enum {
  SEV_FACTORY_RESET = 0,
  SEV_PLATFORM_STATUS,
  SEV_PEK_GEN,
  SEV_PEK_CSR,
  SEV_PDH_GEN,
  SEV_PDH_CERT_EXPORT,
  SEV_PEK_CERT_IMPORT,
  SEV_GET_ID,
  SEV_GET_ID2,
  SNP_PLATFORM_STATUS,
  SNP_COMMIT,
  SNP_SET_CONFIG,
  SNP_VLEK_LOAD,
  SEV_MAX,
};
typedef enum {
  SEV_RET_NO_FW_CALL = - 1,
  SEV_RET_SUCCESS = 0,
  SEV_RET_INVALID_PLATFORM_STATE,
  SEV_RET_INVALID_GUEST_STATE,
  SEV_RET_INAVLID_CONFIG,
  SEV_RET_INVALID_CONFIG = SEV_RET_INAVLID_CONFIG,
  SEV_RET_INVALID_LEN,
  SEV_RET_ALREADY_OWNED,
  SEV_RET_INVALID_CERTIFICATE,
  SEV_RET_POLICY_FAILURE,
  SEV_RET_INACTIVE,
  SEV_RET_INVALID_ADDRESS,
  SEV_RET_BAD_SIGNATURE,
  SEV_RET_BAD_MEASUREMENT,
  SEV_RET_ASID_OWNED,
  SEV_RET_INVALID_ASID,
  SEV_RET_WBINVD_REQUIRED,
  SEV_RET_DFFLUSH_REQUIRED,
  SEV_RET_INVALID_GUEST,
  SEV_RET_INVALID_COMMAND,
  SEV_RET_ACTIVE,
  SEV_RET_HWSEV_RET_PLATFORM,
  SEV_RET_HWSEV_RET_UNSAFE,
  SEV_RET_UNSUPPORTED,
  SEV_RET_INVALID_PARAM,
  SEV_RET_RESOURCE_LIMIT,
  SEV_RET_SECURE_DATA_INVALID,
  SEV_RET_INVALID_KEY = 0x27,
  SEV_RET_INVALID_PAGE_SIZE,
  SEV_RET_INVALID_PAGE_STATE,
  SEV_RET_INVALID_MDATA_ENTRY,
  SEV_RET_INVALID_PAGE_OWNER,
  SEV_RET_INVALID_PAGE_AEAD_OFLOW,
  SEV_RET_RMP_INIT_REQUIRED,
  SEV_RET_MAX,
} sev_ret_code;
struct sev_user_data_status {
  __u8 api_major;
  __u8 api_minor;
  __u8 state;
  __u32 flags;
  __u8 build;
  __u32 guest_count;
} __attribute__((__packed__));
#define SEV_STATUS_FLAGS_CONFIG_ES 0x0100
struct sev_user_data_pek_csr {
  __u64 address;
  __u32 length;
} __attribute__((__packed__));
struct sev_user_data_pek_cert_import {
  __u64 pek_cert_address;
  __u32 pek_cert_len;
  __u64 oca_cert_address;
  __u32 oca_cert_len;
} __attribute__((__packed__));
struct sev_user_data_pdh_cert_export {
  __u64 pdh_cert_address;
  __u32 pdh_cert_len;
  __u64 cert_chain_address;
  __u32 cert_chain_len;
} __attribute__((__packed__));
struct sev_user_data_get_id {
  __u8 socket1[64];
  __u8 socket2[64];
} __attribute__((__packed__));
struct sev_user_data_get_id2 {
  __u64 address;
  __u32 length;
} __attribute__((__packed__));
struct sev_user_data_snp_status {
  __u8 api_major;
  __u8 api_minor;
  __u8 state;
  __u8 is_rmp_initialized : 1;
  __u8 rsvd : 7;
  __u32 build_id;
  __u32 mask_chip_id : 1;
  __u32 mask_chip_key : 1;
  __u32 vlek_en : 1;
  __u32 rsvd1 : 29;
  __u32 guest_count;
  __u64 current_tcb_version;
  __u64 reported_tcb_version;
} __attribute__((__packed__));
struct sev_user_data_snp_config {
  __u64 reported_tcb;
  __u32 mask_chip_id : 1;
  __u32 mask_chip_key : 1;
  __u32 rsvd : 30;
  __u8 rsvd1[52];
} __attribute__((__packed__));
struct sev_user_data_snp_vlek_load {
  __u32 len;
  __u8 vlek_wrapped_version;
  __u8 rsvd[3];
  __u64 vlek_wrapped_address;
} __attribute__((__packed__));
struct sev_user_data_snp_wrapped_vlek_hashstick {
  __u8 data[432];
} __attribute__((__packed__));
struct sev_issue_cmd {
  __u32 cmd;
  __u64 data;
  __u32 error;
} __attribute__((__packed__));
#define SEV_IOC_TYPE 'S'
#define SEV_ISSUE_CMD _IOWR(SEV_IOC_TYPE, 0x0, struct sev_issue_cmd)
#endif
```