Response:
Let's break down the thought process for answering the user's request. The request is multifaceted, demanding understanding of kernel headers, system calls (ioctl), and their relationship to Android.

**1. Initial Understanding of the Context:**

The first step is to recognize that this is a header file (`.h`) located within the Android Bionic library's kernel interface. This immediately signals that it's defining constants, structures, and potentially inline functions intended for communication between user-space Android processes and kernel drivers. The filename `bcm_vk.handroid` suggests a Broadcom vendor kernel module related to some "vk" functionality. The auto-generated comment reinforces this is a low-level interface.

**2. Identifying Core Functionality:**

The header file defines two primary functionalities based on the `ioctl` definitions:

* **Loading Images (`VK_IOCTL_LOAD_IMAGE`):** This involves a `vk_image` structure, suggesting the ability to load firmware or other image types into the kernel module. The `VK_IMAGE_TYPE_BOOT1` and `VK_IMAGE_TYPE_BOOT2` constants hint at different boot stages.
* **Resetting (`VK_IOCTL_RESET`):** This involves a `vk_reset` structure, implying a mechanism to trigger a reset within the kernel module. The `arg1` and `arg2` members suggest configurable reset parameters.

**3. Deconstructing the `ioctl` Macros:**

Understanding the `_IOW` macro is crucial. It's a standard Linux macro for creating `ioctl` request codes. The pattern `_IOW(magic, nr, type)` means:

* `magic`: A magic number identifying the specific device or driver (here, `VK_MAGIC = 0x5e`).
* `nr`:  A unique command number within that driver (0x2 for load, 0x4 for reset).
* `type`: The data structure associated with the `ioctl` call (`struct vk_image` or `struct vk_reset`).

This tells us that user-space applications will likely use the `ioctl()` system call with these generated codes and the corresponding structures to interact with the `bcm_vk` driver.

**4. Analyzing Firmware Status (`VK_FWSTS_*`):**

The numerous `VK_FWSTS_*` constants represent bit flags within a firmware status register. These flags provide insights into the firmware's lifecycle, including:

* **Initialization stages:**  `INIT_START`, `ARCH_INIT_DONE`, `PRE_KNL1_INIT_DONE`, etc.
* **Application initialization:** `APP_INIT_START`, `APP_INIT_DONE`.
* **De-initialization:** `APP_DEINIT_START`, `APP_DEINIT_DONE`, `DRV_DEINIT_START`, `DRV_DEINIT_DONE`.
* **Reset status:** `RESET_DONE`, along with detailed reset reasons encoded in `VK_FWSTS_RESET_REASON_SHIFT` and related masks/values.

The `VK_BAR_FWSTS` and `VK_BAR_COP_FWSTS` constants suggest memory-mapped I/O addresses where these status values can be read.

**5. Connecting to Android Functionality:**

The next step is to consider how this low-level interface relates to Android. Given the "boot" references and the "firmware status" indicators, the most likely connection is to:

* **Boot process:**  Loading firmware for hardware components during the Android boot sequence.
* **Hardware initialization:** Managing the initialization and reset of a specific hardware component (likely related to Broadcom).

The prompt asks for concrete examples. A plausible scenario is a Broadcom Wi-Fi or Bluetooth chip requiring firmware loading during boot.

**6. Addressing Libc Functions and Dynamic Linker:**

The prompt specifically asks about `libc` functions and the dynamic linker. In this header file *itself*, there are no direct calls to `libc` functions or involvement of the dynamic linker. However, *using* this header would involve:

* **`open()`:** To open the device node associated with the `bcm_vk` driver (e.g., `/dev/bcm_vk`).
* **`ioctl()`:**  The core system call for interacting with the driver.
* **Potentially `read()`/`write()` or `mmap()`:** If there are other ways to communicate with the driver, though not evident in the provided header.

The dynamic linker comes into play when considering the user-space libraries or applications that would utilize these system calls. These applications would need to be linked against `libc`.

**7. Hypothetical Input/Output and Common Errors:**

Consider a scenario where an Android service wants to load firmware. The input would be the path to the firmware file. The expected output is successful loading (kernel logs, potential changes in firmware status). Common errors include:

* **Invalid file path:**  The specified firmware file doesn't exist or is inaccessible.
* **Incorrect image type:**  Using the wrong `VK_IMAGE_TYPE_...` value.
* **Permission issues:** The user-space process doesn't have permission to open the device node.
* **Driver not loaded:** The `bcm_vk` kernel module isn't loaded.

**8. Tracing the Call Path (Framework/NDK to Kernel):**

This requires reverse engineering the Android stack. The general flow would be:

* **Android Framework (Java/Kotlin):** A high-level system service (perhaps related to connectivity or hardware management) might initiate the firmware load.
* **JNI (Java Native Interface):**  The framework code would call down to native code (C/C++) via JNI.
* **NDK Library:** The native code might use a custom library or directly call `libc` functions.
* **`libc`:** The `open()` and `ioctl()` functions in `libc` are used to interact with the kernel.
* **Kernel System Call Interface:** The `ioctl()` call triggers a system call.
* **Kernel Driver (`bcm_vk`):** The registered `ioctl` handler for the `bcm_vk` driver processes the request.

**9. Frida Hooking:**

Frida is a dynamic instrumentation toolkit. To hook this, you could target:

* **User-space:** Hook the `ioctl()` call in `libc` to see which arguments are being passed.
* **Kernel-space (more advanced):** Hook the `bcm_vk` driver's `ioctl` handler.

The provided Frida examples in the final answer demonstrate hooking the `ioctl` function in `libc`.

**10. Structuring the Answer:**

Finally, organize the information logically, addressing each part of the user's request:

* Functionality overview.
* Relationship to Android with examples.
* Detailed explanation of `libc` functions (even if indirectly used).
* Dynamic linker aspects (even if minimal).
* Hypothetical input/output.
* Common errors.
* Tracing the call path.
* Frida hooking examples.

This step-by-step approach, starting with understanding the basic purpose of the header file and then progressively digging into the details, allows for a comprehensive and accurate answer. The key is to connect the low-level kernel interface with the higher-level Android components.
这个头文件 `bionic/libc/kernel/uapi/linux/misc/bcm_vk.handroid` 定义了用于与名为 `bcm_vk` 的 Linux 内核模块进行交互的接口。这个模块很可能与 Broadcom（`bcm`）的某些虚拟化（`vk`）相关的功能有关，并且特别针对 Android（`handroid`）。由于它位于 `uapi` 目录下，意味着它是用户空间应用程序可以直接使用的头文件，定义了与内核交互的“用户空间应用程序接口”。

**功能列表:**

1. **加载镜像 (Load Image):**  允许用户空间向内核模块加载特定的镜像文件。支持两种镜像类型：`VK_IMAGE_TYPE_BOOT1` 和 `VK_IMAGE_TYPE_BOOT2`。这可能用于加载固件、微码或其他需要在特定启动阶段加载的二进制文件。

2. **重置 (Reset):** 提供一种机制来触发内核模块的重置操作。可以通过 `arg1` 和 `arg2` 传递重置相关的参数。

3. **获取/监控固件状态 (Firmware Status):** 定义了多个标志位 (`VK_FWSTS_*`)，用于表示固件的不同状态，例如初始化阶段、应用程序初始化、去初始化以及各种重置原因。用户空间可以通过某种方式（可能不是直接通过这个头文件定义的ioctl，而是通过读取特定的寄存器）来读取这些状态。

**与 Android 功能的关系及举例说明:**

这个文件定义的接口很可能用于 Android 系统启动过程中的硬件初始化或者某些特定硬件功能的管理。考虑到 `bcm` 前缀，这很可能与 Broadcom 的硬件相关，例如 Wi-Fi 或蓝牙芯片。

* **启动过程中的固件加载:**  在 Android 系统启动时，可能需要加载 Wi-Fi 或蓝牙芯片的固件。`VK_IOCTL_LOAD_IMAGE` 可以用于将这些固件加载到芯片的内存中。例如，Android 的 init 进程或 HAL (Hardware Abstraction Layer) 中的特定模块可能会使用这个 ioctl 来加载 Wi-Fi 固件。

* **硬件重置:** 当硬件出现问题或者需要重新初始化时，可以使用 `VK_IOCTL_RESET` 来触发硬件的重置。例如，在 Wi-Fi 连接不稳定时，系统可能会尝试重置 Wi-Fi 芯片。

* **监控硬件状态:**  `VK_FWSTS_*` 标志位可以用来监控硬件的初始化状态、运行状态以及是否发生过重置。Android 系统可能会使用这些状态信息来判断硬件是否正常工作，并在出现问题时进行诊断或处理。例如，系统可能会等待 `VK_FWSTS_READY` 标志位被设置，表示硬件初始化完成。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个头文件本身**没有**定义任何 libc 函数。它只是定义了一些宏、结构体和常量，用于与内核模块进行交互。用户空间的程序会使用 libc 提供的系统调用接口，例如 `ioctl()`，来利用这里定义的常量。

* **`ioctl()` 函数:**
    * **功能:** `ioctl()` 是一个系统调用，允许用户空间程序向设备驱动程序发送控制命令和传递数据。
    * **实现:**  当用户空间程序调用 `ioctl()` 时，会陷入内核态。内核会根据 `ioctl()` 的第一个参数（文件描述符）找到对应的设备驱动程序，然后调用该驱动程序中注册的 `ioctl` 处理函数。`ioctl()` 的第二个参数是要执行的命令码，通常由宏生成（例如 `_IOW`），第三个参数是传递给驱动程序的数据。在这个例子中，`VK_IOCTL_LOAD_IMAGE` 和 `VK_IOCTL_RESET` 就是通过 `_IOW` 宏定义的命令码，分别对应加载镜像和重置操作。内核驱动程序会解析这些命令码和传递的数据（`struct vk_image` 或 `struct vk_reset`），然后执行相应的操作。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件本身并不直接涉及动态链接器。动态链接器主要负责加载和链接共享库 (`.so` 文件)。 然而，使用这个头文件的用户空间应用程序可能需要链接到一些共享库，例如 `libc.so`。

**so 布局样本 (假设一个使用此功能的 HAL 模块):**

```
# 目录结构
/system/lib64/hw/vendor.foo.hardware.vk@1.0-service.so

# vendor.foo.hardware.vk@1.0-service.so 的内容 (示意)
.init
.plt        <-- 可能包含对 libc 中 ioctl 的调用
.text       <-- 实现加载镜像或重置的逻辑
.rodata     <-- 可能包含固件路径等常量
.data
.bss
.dynamic    <-- 动态链接信息
.symtab
.strtab
...
```

**链接的处理过程:**

1. **编译时链接:** 在编译 `vendor.foo.hardware.vk@1.0-service.so` 时，编译器会识别出对 `ioctl` 等 libc 函数的调用。链接器会将这些符号标记为需要外部解析。

2. **运行时加载:** 当 Android 系统启动并需要运行这个 HAL 服务时，`linker64`（或 `linker`）动态链接器会负责加载这个 `.so` 文件。

3. **符号解析:** 动态链接器会扫描 `.so` 文件的 `.dynamic` 段，找到其依赖的共享库（通常是 `libc.so`）。然后，它会加载 `libc.so` 到内存中。

4. **重定位:** 动态链接器会根据 `.so` 文件中的重定位信息，将 `vendor.foo.hardware.vk@1.0-service.so` 中对 `ioctl` 等符号的引用，指向 `libc.so` 中 `ioctl` 函数的实际地址。这通常通过修改 `.plt` (Procedure Linkage Table) 和 `.got.plt` (Global Offset Table) 中的条目来实现。

**假设输入与输出 (针对 ioctl 调用):**

**假设输入 (加载镜像):**

* 文件描述符: 指向 `/dev/bcm_vk` 设备节点的有效文件描述符。
* `ioctl` 命令: `VK_IOCTL_LOAD_IMAGE`
* `arg`: 指向 `struct vk_image` 结构的指针，例如:
  ```c
  struct vk_image image_info;
  image_info.type = VK_IMAGE_TYPE_BOOT1;
  strncpy(image_info.filename, "/vendor/firmware/bcm_wifi.bin", BCM_VK_MAX_FILENAME - 1);
  image_info.filename[BCM_VK_MAX_FILENAME - 1] = '\0';
  ```

**预期输出:**

* `ioctl()` 系统调用成功返回 0。
* 内核模块接收到加载镜像的请求，并开始加载 `/vendor/firmware/bcm_wifi.bin` 到硬件。
* 可能会在内核日志中看到相关的加载信息。
* 硬件状态可能会发生变化，例如 `VK_FWSTS_INIT_START` 等标志位被设置。

**假设输入 (重置):**

* 文件描述符: 指向 `/dev/bcm_vk` 设备节点的有效文件描述符。
* `ioctl` 命令: `VK_IOCTL_RESET`
* `arg`: 指向 `struct vk_reset` 结构的指针，例如:
  ```c
  struct vk_reset reset_info;
  reset_info.arg1 = 0; // 假设的重置参数
  reset_info.arg2 = 1; // 假设的重置参数
  ```

**预期输出:**

* `ioctl()` 系统调用成功返回 0。
* 内核模块接收到重置请求，并触发硬件的重置操作。
* 可能会在内核日志中看到相关的重置信息。
* 硬件状态可能会发生变化，例如 `VK_FWSTS_RESET_DONE` 标志位被设置。

**用户或编程常见的使用错误:**

1. **无效的文件描述符:**  在调用 `ioctl()` 之前没有正确地打开 `/dev/bcm_vk` 设备节点。
   ```c
   int fd = open("/dev/bcm_vk", O_RDWR);
   if (fd < 0) {
       perror("open /dev/bcm_vk failed");
       // ... 错误处理
   }
   // 忘记使用 fd 或使用了错误的 fd
   ioctl(INVALID_FD, VK_IOCTL_LOAD_IMAGE, &image_info); // 错误
   close(fd);
   ```

2. **错误的 `ioctl` 命令码:**  使用了错误的 `ioctl` 命令宏。
   ```c
   ioctl(fd, VK_IOCTL_RESET + 1, &reset_info); // 错误的命令码
   ```

3. **传递了不正确的参数结构体:**  传递的结构体指针为空或者结构体成员的值不正确。
   ```c
   struct vk_image *null_image = NULL;
   ioctl(fd, VK_IOCTL_LOAD_IMAGE, null_image); // 错误，空指针

   struct vk_image image_info;
   image_info.type = 99; // 无效的镜像类型
   // 忘记初始化 filename
   ioctl(fd, VK_IOCTL_LOAD_IMAGE, &image_info); // 可能导致问题
   ```

4. **文件名过长:** 提供的文件名超过了 `BCM_VK_MAX_FILENAME` 的限制，可能导致缓冲区溢出。
   ```c
   struct vk_image image_info;
   strncpy(image_info.filename, "a_very_long_filename_that_exceeds_the_maximum_length_allowed.bin", sizeof(image_info.filename));
   ioctl(fd, VK_IOCTL_LOAD_IMAGE, &image_info); // 潜在的缓冲区溢出
   ```

5. **权限问题:** 用户空间程序可能没有足够的权限访问 `/dev/bcm_vk` 设备节点。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

通常，与硬件交互的操作不会直接在 Android Framework 的 Java 代码中完成。相反，Framework 会调用 Native 代码 (通过 JNI)，这些 Native 代码可能会使用 NDK 提供的库或直接调用 libc 函数来与内核交互。

**步骤:**

1. **Android Framework (Java/Kotlin):** Framework 中的某个服务或组件需要与 `bcm_vk` 模块交互，例如一个负责 Wi-Fi 或蓝牙管理的 Service。

2. **JNI (Java Native Interface):** Framework 通过 JNI 调用到 Native 代码。可能是一个实现了特定 HAL 接口的 `.so` 库。

3. **NDK 库或自定义 Native 代码 (C/C++):** Native 代码可能会使用 NDK 提供的标准 C 库函数（例如 `open`, `ioctl`）或者自定义的辅助函数来执行操作。

4. **libc 函数:** Native 代码调用 `libc.so` 中的 `open()` 系统调用打开 `/dev/bcm_vk`，然后调用 `ioctl()` 系统调用，并使用此头文件中定义的宏和结构体与内核模块通信。

5. **Linux Kernel:** `ioctl()` 系统调用会陷入内核，内核根据文件描述符找到 `bcm_vk` 驱动程序，并调用其注册的 `ioctl` 处理函数。驱动程序会解析命令和数据，执行相应的操作。

**Frida Hook 示例:**

我们可以 hook `libc.so` 中的 `ioctl` 函数，来观察哪些参数被传递，从而追踪对 `bcm_vk` 模块的交互。

**Hook `ioctl` 函数 (User-Space):**

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

device = frida.get_usb_device(timeout=10)
pid = device.spawn(["com.android.systemui"]) # 替换为目标进程的包名或进程名
process = device.attach(pid)
device.resume(pid)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "ioctl"), {
    onEnter: function(args) {
        var fd = args[0].toInt32();
        var request = args[1].toInt32();
        var argp = args[2];

        // 检查文件描述符是否可能与 /dev/bcm_vk 相关
        try {
            var path = Socket.fromFd(fd).path;
            if (path && path.indexOf("bcm_vk") !== -1) {
                send({
                    type: "ioctl",
                    fd: fd,
                    request: request.toString(16),
                    // 可以进一步解析 argp 指向的数据结构
                });
            }
        } catch (e) {
            // 可能不是 socket fd
        }

        if (request === 0xc0100002) { // 假设 VK_IOCTL_LOAD_IMAGE 的值
            send("ioctl called with VK_IOCTL_LOAD_IMAGE");
            // 可以进一步读取 vk_image 结构体的内容
            var vk_image_ptr = ptr(argp);
            send("vk_image type: " + vk_image_ptr.readU32());
            send("vk_image filename: " + vk_image_ptr.add(4).readCString());
        } else if (request === 0xc0080004) { // 假设 VK_IOCTL_RESET 的值
            send("ioctl called with VK_IOCTL_RESET");
            // 可以进一步读取 vk_reset 结构体的内容
            var vk_reset_ptr = ptr(argp);
            send("vk_reset arg1: " + vk_reset_ptr.readU32());
            send("vk_reset arg2: " + vk_reset_ptr.add(4).readU32());
        }
    },
    onLeave: function(retval) {
        //console.log("ioctl returned:", retval.toInt32());
    }
});
"""

script = process.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**解释 Frida Hook 代码:**

1. **连接到设备和进程:** 代码首先连接到 USB 设备，然后启动或附加到目标 Android 进程（这里以 `com.android.systemui` 为例，你需要根据实际情况替换）。

2. **Hook `ioctl`:** 使用 `Interceptor.attach` hook 了 `libc.so` 中的 `ioctl` 函数。

3. **`onEnter`:** 当 `ioctl` 函数被调用时，`onEnter` 函数会被执行。
   - 它获取了 `ioctl` 的参数：文件描述符 (`fd`) 和请求码 (`request`)。
   - 它尝试通过 `Socket.fromFd(fd).path` 获取文件描述符对应的路径，如果路径包含 "bcm_vk"，则打印相关信息。
   - 它检查 `request` 的值是否与 `VK_IOCTL_LOAD_IMAGE` 或 `VK_IOCTL_RESET` 对应（你需要将宏的值替换为实际值）。
   - 如果匹配，它会读取 `argp` 指向的 `vk_image` 或 `vk_reset` 结构体的成员，并打印出来。

4. **`onLeave`:**  `onLeave` 函数在 `ioctl` 函数返回时执行，这里被注释掉了，但可以用来观察返回值。

**使用 Frida Hook 调试步骤:**

1. **找到目标进程:** 确定哪个 Android 进程可能与 `bcm_vk` 模块交互。这可能涉及到 Wi-Fi、蓝牙或底层硬件管理相关的进程。

2. **运行 Frida 脚本:** 将上述 Python 代码保存为 `.py` 文件，并在 adb shell 中运行它。

3. **触发相关操作:** 在 Android 设备上触发可能导致与 `bcm_vk` 模块交互的操作，例如开启/关闭 Wi-Fi、连接蓝牙设备等。

4. **观察 Frida 输出:** Frida 脚本会打印出 `ioctl` 函数的调用信息，包括文件描述符、请求码以及传递的结构体内容，从而帮助你理解 Framework 和 Native 代码是如何与内核模块交互的。

请注意，`VK_IOCTL_LOAD_IMAGE` 和 `VK_IOCTL_RESET` 的实际数值需要根据编译环境确定，可以通过查看编译后的头文件或者在内核源码中查找。 上述 Frida 脚本中的假设值 `0xc0100002` 和 `0xc0080004` 仅为示例。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/misc/bcm_vk.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef __UAPI_LINUX_MISC_BCM_VK_H
#define __UAPI_LINUX_MISC_BCM_VK_H
#include <linux/ioctl.h>
#include <linux/types.h>
#define BCM_VK_MAX_FILENAME 64
struct vk_image {
  __u32 type;
#define VK_IMAGE_TYPE_BOOT1 1
#define VK_IMAGE_TYPE_BOOT2 2
  __u8 filename[BCM_VK_MAX_FILENAME];
};
struct vk_reset {
  __u32 arg1;
  __u32 arg2;
};
#define VK_MAGIC 0x5e
#define VK_IOCTL_LOAD_IMAGE _IOW(VK_MAGIC, 0x2, struct vk_image)
#define VK_IOCTL_RESET _IOW(VK_MAGIC, 0x4, struct vk_reset)
#define VK_BAR_FWSTS 0x41c
#define VK_BAR_COP_FWSTS 0x428
#define VK_FWSTS_RELOCATION_ENTRY (1UL << 0)
#define VK_FWSTS_RELOCATION_EXIT (1UL << 1)
#define VK_FWSTS_INIT_START (1UL << 2)
#define VK_FWSTS_ARCH_INIT_DONE (1UL << 3)
#define VK_FWSTS_PRE_KNL1_INIT_DONE (1UL << 4)
#define VK_FWSTS_PRE_KNL2_INIT_DONE (1UL << 5)
#define VK_FWSTS_POST_KNL_INIT_DONE (1UL << 6)
#define VK_FWSTS_INIT_DONE (1UL << 7)
#define VK_FWSTS_APP_INIT_START (1UL << 8)
#define VK_FWSTS_APP_INIT_DONE (1UL << 9)
#define VK_FWSTS_MASK 0xffffffff
#define VK_FWSTS_READY (VK_FWSTS_INIT_START | VK_FWSTS_ARCH_INIT_DONE | VK_FWSTS_PRE_KNL1_INIT_DONE | VK_FWSTS_PRE_KNL2_INIT_DONE | VK_FWSTS_POST_KNL_INIT_DONE | VK_FWSTS_INIT_DONE | VK_FWSTS_APP_INIT_START | VK_FWSTS_APP_INIT_DONE)
#define VK_FWSTS_APP_DEINIT_START (1UL << 23)
#define VK_FWSTS_APP_DEINIT_DONE (1UL << 24)
#define VK_FWSTS_DRV_DEINIT_START (1UL << 25)
#define VK_FWSTS_DRV_DEINIT_DONE (1UL << 26)
#define VK_FWSTS_RESET_DONE (1UL << 27)
#define VK_FWSTS_DEINIT_TRIGGERED (VK_FWSTS_APP_DEINIT_START | VK_FWSTS_APP_DEINIT_DONE | VK_FWSTS_DRV_DEINIT_START | VK_FWSTS_DRV_DEINIT_DONE)
#define VK_FWSTS_RESET_REASON_SHIFT 28
#define VK_FWSTS_RESET_REASON_MASK (0xf << VK_FWSTS_RESET_REASON_SHIFT)
#define VK_FWSTS_RESET_SYS_PWRUP (0x0 << VK_FWSTS_RESET_REASON_SHIFT)
#define VK_FWSTS_RESET_MBOX_DB (0x1 << VK_FWSTS_RESET_REASON_SHIFT)
#define VK_FWSTS_RESET_M7_WDOG (0x2 << VK_FWSTS_RESET_REASON_SHIFT)
#define VK_FWSTS_RESET_TEMP (0x3 << VK_FWSTS_RESET_REASON_SHIFT)
#define VK_FWSTS_RESET_PCI_FLR (0x4 << VK_FWSTS_RESET_REASON_SHIFT)
#define VK_FWSTS_RESET_PCI_HOT (0x5 << VK_FWSTS_RESET_REASON_SHIFT)
#define VK_FWSTS_RESET_PCI_WARM (0x6 << VK_FWSTS_RESET_REASON_SHIFT)
#define VK_FWSTS_RESET_PCI_COLD (0x7 << VK_FWSTS_RESET_REASON_SHIFT)
#define VK_FWSTS_RESET_L1 (0x8 << VK_FWSTS_RESET_REASON_SHIFT)
#define VK_FWSTS_RESET_L0 (0x9 << VK_FWSTS_RESET_REASON_SHIFT)
#define VK_FWSTS_RESET_UNKNOWN (0xf << VK_FWSTS_RESET_REASON_SHIFT)
#endif
```