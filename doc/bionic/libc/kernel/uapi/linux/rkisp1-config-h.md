Response:
Let's break down the thought process for answering the request.

**1. Understanding the Core Request:**

The primary goal is to analyze the provided C header file (`rkisp1-config.handroid`) and explain its purpose and relationship to Android. Key elements requested include: functionality, connection to Android, libc functions (although the file *doesn't* contain libc function definitions), dynamic linker aspects, usage errors, and how Android components access it, along with Frida hooking examples.

**2. Initial Assessment of the File:**

The first thing to notice is the comment: "This file is auto-generated. Modifications will be lost." This immediately suggests that this file is not manually written but created by a build process, likely from some more abstract definition. It also implies that understanding the *generator* might be important for a deeper understanding, but we're focusing on the file itself.

The `#ifndef`, `#define`, and `#include` are standard C preprocessor directives for header file inclusion and preventing multiple inclusions. The `#include <linux/types.h>` is a crucial clue that this file interacts directly with the Linux kernel.

The bulk of the file consists of `#define` macros and `struct` and `enum` definitions. The macros primarily define bit flags and numerical limits. The `struct` definitions represent data structures used to configure the RKISP1 (Rockchip Image Signal Processor 1). The `enum` definitions provide named constants for different modes and options.

**3. Identifying the Functionality:**

The names of the macros, structs, and enums are highly descriptive. Keywords like `RKISP1_CIF_ISP_MODULE_*`, `rkisp1_cif_isp_*_config`, and `rkisp1_cif_isp_*_mode` clearly indicate this file is related to configuring and controlling an image signal processor (ISP) from Rockchip. The various modules (DPCC, BLS, AWB, AEC, etc.) point to different stages or functionalities within the ISP pipeline. The `config` structs define parameters for these modules, and the `enum`s specify the possible settings.

**4. Connecting to Android:**

Since this file is located within `bionic/libc/kernel/uapi/linux`, which is part of Android's Bionic libc, it's clearly used within the Android operating system. ISPs are essential for camera functionality. Therefore, the connection is that this header file provides the definitions for interacting with the RKISP1 hardware, likely through kernel drivers, to control the camera on Android devices using a Rockchip chipset.

**5. Addressing Specific Requests (and where things get interesting):**

* **libc Functions:**  A careful scan reveals *no* function definitions. The file only contains type definitions and constants. The answer needs to explicitly state this and explain *why* header files don't contain function implementations. It's about declarations, not definitions.

* **Dynamic Linker:**  Again, this file itself doesn't directly involve the dynamic linker. It's a header file. However, the *use* of these definitions likely happens within shared libraries (.so files) that are loaded by the dynamic linker. So, the answer needs to explain the connection indirectly. It should provide a hypothetical `.so` layout example and describe how the dynamic linker would handle it, focusing on how the definitions in this header would be used within the `.so`.

* **Logic and Assumptions:**  Since the file defines constants and structures, there isn't really "logic" in the programming sense *within the file itself*. The logic resides in the code that *uses* these definitions. The answer should reflect this by providing examples of how a program might use these structures to configure the ISP.

* **User Errors:**  The primary user error would be providing incorrect values to the configuration structures, violating the defined limits, or misinterpreting the meaning of the fields. The answer should give concrete examples of such errors.

* **Android Framework/NDK Access:** This requires tracing the path from higher-level Android components down to the kernel. The Camera Service and HAL (Hardware Abstraction Layer) are key components. The NDK provides a way for native code to interact with these layers. The answer needs to outline this path.

* **Frida Hooking:**  Frida is used to intercept function calls. To hook interactions with the ISP configuration, one would need to identify the kernel system calls or ioctl calls that are used to pass these configuration structures to the kernel driver. The answer should provide a conceptual example of how Frida could be used, focusing on hooking relevant system calls.

**6. Structuring the Answer:**

The answer should be organized logically, following the points raised in the request. Using clear headings and bullet points improves readability. It's important to explain technical concepts clearly and avoid jargon where possible.

**7. Refinement and Accuracy:**

After drafting the initial response, review it for accuracy and completeness. Ensure that the examples are relevant and easy to understand. Double-check the explanations of technical concepts like the dynamic linker.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This file defines functions for the ISP."  **Correction:**  Careful reading shows *no* function definitions, only declarations (via structs and enums) and constants (via `#define`).
* **Initial thought:** "Explain the implementation of libc functions in this file." **Correction:** There are no libc functions defined here. Shift focus to how the *data structures* defined here are likely used by libc or other system libraries.
* **Initial thought:** Focus solely on the kernel. **Correction:** While kernel interaction is key, also explain how higher-level Android components (framework, HAL) would eventually utilize these definitions.

By following these steps, the comprehensive and accurate answer provided earlier can be constructed. The key is to systematically analyze the provided code, understand the context, and address each part of the request thoughtfully.
这个文件 `bionic/libc/kernel/uapi/linux/rkisp1-config.handroid` 是 Android Bionic 库的一部分，它定义了用于配置 Rockchip ISP1 (Image Signal Processor 1) 硬件的**用户空间 API (UAPI)**。这意味着用户空间程序可以使用这些定义来与内核驱动程序交互，从而控制和配置 ISP 硬件。

**它的功能：**

这个文件的主要功能是**提供常量和数据结构定义**，用于在用户空间程序和 Linux 内核驱动程序之间传递关于 RKISP1 ISP 配置的信息。具体来说，它定义了：

1. **模块使能标志 (Module Enable Flags):**  例如 `RKISP1_CIF_ISP_MODULE_DPCC`, `RKISP1_CIF_ISP_MODULE_BLS` 等，用于指示 ISP 中哪些模块应该被激活。每个宏代表一个不同的 ISP 功能模块，如去坏点校正 (DPCC)、黑电平校正 (BLS) 等。

2. **模块配置参数 (Module Configuration Parameters):**  定义了各种结构体，如 `rkisp1_cif_isp_bls_config`, `rkisp1_cif_isp_dpcc_config` 等，用于设置 ISP 各个模块的详细参数。这些结构体包含了控制特定模块行为的字段。

3. **常量限制 (Constant Limits):**  定义了各种参数的最大值，例如 `RKISP1_CIF_ISP_CTK_COEFF_MAX`, `RKISP1_CIF_ISP_AE_MEAN_MAX` 等，用于限制配置参数的取值范围。

4. **枚举类型 (Enum Types):**  定义了各种枚举类型，如 `rkisp1_cif_isp_version`, `rkisp1_cif_isp_histogram_mode` 等，用于表示不同的工作模式或状态。

5. **统计信息结构体 (Statistics Information Structures):** 定义了用于接收 ISP 硬件输出的统计信息的结构体，例如 `rkisp1_cif_isp_awb_stat`, `rkisp1_cif_isp_ae_stat` 等，包含了自动白平衡、自动曝光等算法的测量结果。

6. **扩展参数配置结构体 (Extended Parameter Configuration Structures):** 定义了用于传递更复杂或可选配置信息的结构体，例如 `rkisp1_ext_params_bls_config`, `rkisp1_ext_params_dpcc_config` 等。

**与 Android 功能的关系及举例说明：**

这个文件对于 Android 的 **相机 (Camera)** 功能至关重要。Android 设备上的相机应用和底层驱动程序需要使用这些定义来配置 ISP 硬件，从而控制图像的采集和处理过程。

**举例说明：**

* **自动白平衡 (AWB):**  `RKISP1_CIF_ISP_MODULE_AWB` 宏用于启用 AWB 模块。`struct rkisp1_cif_isp_awb_meas_config` 结构体允许设置 AWB 的测量窗口、模式 (`RKISP1_CIF_ISP_AWB_MODE_RGB`, `RKISP1_CIF_ISP_AWB_MODE_YCBCR`) 等参数。Android 的 Camera Service 或 Camera HAL 可以使用这些定义来设置 AWB 的行为，使得拍摄的照片色彩看起来自然。

* **自动曝光 (AEC):**  `RKISP1_CIF_ISP_MODULE_AEC` 宏用于启用 AEC 模块。`struct rkisp1_cif_isp_aec_config` 结构体允许设置 AEC 的测量窗口、自动停止条件等参数。Android 的相机框架会根据光照条件调整这些参数，以获得合适的图像亮度。

* **去坏点校正 (DPCC):** `RKISP1_CIF_ISP_MODULE_DPCC` 宏用于启用 DPCC 模块。`struct rkisp1_cif_isp_dpcc_config` 和 `struct rkisp1_cif_isp_dpcc_methods_config` 结构体定义了 DPCC 的工作模式和校正方法。Android 相机可以使用这些配置来去除传感器上的坏点，提高图像质量。

**详细解释每一个 libc 函数的功能是如何实现的:**

**这个文件中并没有定义任何 libc 函数。** 它是一个头文件，只包含了宏定义、结构体定义和枚举类型定义。这些定义用于在不同的代码模块之间共享关于 ISP 配置的常量和数据结构布局信息。

libc 函数的实现位于 Bionic 库的其他源文件中。这个头文件定义的数据结构会被 Bionic 库中与硬件交互的函数使用。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件本身并不直接涉及 dynamic linker。然而，使用这个头文件的代码通常会编译成共享库 (`.so` 文件)，这些共享库会被 Android 的 dynamic linker 加载和链接。

**so 布局样本：**

假设有一个名为 `libcamera_rkisp1.so` 的共享库，它使用了这个头文件中定义的结构体来配置 RKISP1 ISP。该 `.so` 文件的布局可能如下：

```
libcamera_rkisp1.so:
    .text         # 代码段，包含函数实现
    .rodata       # 只读数据段，可能包含一些常量
    .data         # 可读写数据段，可能包含全局变量
    .bss          # 未初始化数据段
    .symtab       # 符号表，包含导出的符号信息
    .strtab       # 字符串表
    .dynsym       # 动态符号表
    .dynstr       # 动态字符串表
    .rel.dyn      # 动态重定位表
    .rel.plt      # PLT (Procedure Linkage Table) 重定位表
    ...
```

**链接的处理过程：**

1. **编译时：** 当编译 `libcamera_rkisp1.so` 的源文件时，编译器会读取 `rkisp1-config.handroid` 头文件，获取 ISP 配置相关的定义。

2. **链接时：** 链接器会将编译后的目标文件链接成共享库。如果 `libcamera_rkisp1.so` 中导出了需要被其他库或程序调用的符号（例如，用于配置 ISP 的函数），这些符号信息会被记录在 `.symtab` 和 `.dynsym` 中。

3. **运行时：** 当 Android 系统需要使用 `libcamera_rkisp1.so` 时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会执行以下步骤：
    * **加载：** 将 `libcamera_rkisp1.so` 加载到内存中。
    * **查找依赖：** 检查 `libcamera_rkisp1.so` 依赖的其他共享库。
    * **重定位：** 根据 `.rel.dyn` 和 `.rel.plt` 中的信息，修正代码和数据中的地址引用。例如，如果 `libcamera_rkisp1.so` 中调用了其他共享库的函数，dynamic linker 会将这些调用地址修正为目标函数的实际内存地址。
    * **符号解析：**  解析动态符号表 (`.dynsym`)，建立符号之间的链接关系。其他共享库或程序可以通过 dynamic linker 找到 `libcamera_rkisp1.so` 中导出的符号，并进行调用。

在这个过程中，`rkisp1-config.handroid` 定义的结构体和常量被用来正确地解释和操作与 ISP 硬件交互的数据。dynamic linker 确保了使用这些定义的代码能够正确地运行，即使这些代码分布在不同的共享库中。

**如果做了逻辑推理，请给出假设输入与输出:**

由于这个文件是定义，不包含执行逻辑，所以不存在直接的逻辑推理和输入输出。但是，我们可以假设一个使用这些定义的场景：

**假设输入：**

一个 Android 相机应用想要启用 RKISP1 的去坏点校正功能，并使用默认的校正方法。

**逻辑推理：**

相机应用或者其调用的底层库会构造一个 `rkisp1_params_cfg` 结构体，其中：

* `module_en_update` 字段会设置相应的位，指示需要更新模块使能状态。
* `module_ens` 字段的 `RKISP1_CIF_ISP_MODULE_DPCC` 位会被设置为 `1`，以启用 DPCC 模块。
* 可能还会配置 `others.dpcc_config` 结构体中的其他 DPCC 相关参数（在这个假设中，使用默认值）。

**假设输出：**

这个配置结构体会被传递给内核驱动程序。驱动程序会解析这个结构体，并根据其中的配置信息，设置 RKISP1 硬件的 DPCC 模块，使其开始工作。最终，ISP 输出的图像将经过坏点校正。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **使用未定义的宏或枚举值：** 如果程序中使用了 `rkisp1-config.handroid` 中未定义的宏或枚举值，会导致编译错误。

   ```c
   // 错误示例：使用了不存在的模块定义
   #define RKISP1_CIF_ISP_MODULE_NEW_FEATURE (1U << 20)
   struct rkisp1_params_cfg cfg;
   cfg.module_ens |= RKISP1_CIF_ISP_MODULE_NEW_FEATURE; // 编译错误
   ```

2. **设置超出范围的参数值：**  尝试将配置参数设置为超出其允许范围的值，可能会导致不可预测的行为或者驱动程序错误。

   ```c
   struct rkisp1_cif_isp_ctk_config ctk_cfg;
   // 错误示例：设置超出最大值的系数
   ctk_cfg.coeff[0][0] = 0x200; // RKISP1_CIF_ISP_CTK_COEFF_MAX 是 0x100
   ```

3. **错误地组合配置标志：** 某些配置标志可能互斥或有特定的组合要求。错误地组合这些标志可能导致 ISP 工作异常。

4. **结构体成员访问错误：**  错误地访问结构体成员，例如访问了不存在的成员或者使用了错误的类型。

5. **忘记初始化结构体：** 在使用配置结构体之前，忘记对其进行初始化，可能导致使用未定义的值。

6. **字节序问题：** 如果用户空间程序和内核运行在不同的字节序平台上，直接传递结构体可能会导致数据解析错误。通常需要进行字节序转换。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

1. **Android Framework:**
   * **Camera Service:** Android Framework 中的 `CameraService` 负责管理设备的相机功能。当应用请求打开相机或进行拍照时，`CameraService` 会协调底层的硬件访问。
   * **Camera HAL (Hardware Abstraction Layer):** `CameraService` 通过 Camera HAL 与特定设备的相机硬件交互。Camera HAL 是一个动态链接库 (`.so` 文件)，由设备制造商提供，用于实现标准的 Camera API。

2. **NDK (Native Development Kit):**
   * 使用 NDK 开发的相机应用可以直接调用 Camera2 NDK API。这些 API 最终也会通过 Camera HAL 与硬件交互。

**步骤:**

1. **应用请求：** 一个 Android 应用（Java 或 Native）通过 Camera API 发起一个操作，例如设置曝光时间或白平衡模式。

2. **Framework 处理：** `CameraService` 接收到请求，并将其转换为对 Camera HAL 的调用。

3. **HAL 实现：** Camera HAL 的实现 (通常是 C/C++ 代码) 会使用 `rkisp1-config.handroid` 中定义的结构体来构造 ISP 配置信息。

4. **ioctl 系统调用：** Camera HAL 通过 **ioctl 系统调用** 将配置信息传递给内核中的 RKISP1 驱动程序。`ioctl` 是一个通用的设备控制系统调用，允许用户空间程序向设备驱动程序发送控制命令和数据。

   ```c
   // Camera HAL 代码示例 (简化)
   #include <linux/ioctl.h>
   #include <linux/rkisp1-config.h> // 包含头文件

   // ...

   int set_awb_mode(int fd, enum rkisp1_cif_isp_awb_mode_type mode) {
       struct rkisp1_params_cfg cfg = {0};
       cfg.module_cfg_update |= RKISP1_CIF_ISP_MODULE_AWB; // 标记需要更新 AWB 配置
       cfg.others.awb_meas_config.awb_mode = mode;

       if (ioctl(fd, RKISP1_CIF_ISP_CONFIG, &cfg) < 0) {
           perror("ioctl failed");
           return -1;
       }
       return 0;
   }
   ```

5. **内核驱动处理：** 内核中的 RKISP1 驱动程序接收到 `ioctl` 调用，解析传入的 `rkisp1_params_cfg` 结构体，并根据其中的配置信息，操作 RKISP1 硬件寄存器。

**Frida Hook 示例调试步骤：**

可以使用 Frida Hook 来拦截 Camera HAL 调用 `ioctl` 系统调用的过程，从而观察传递给内核的 ISP 配置信息。

```python
import frida
import sys

# 要 hook 的进程名称
package_name = "com.android.camera2" # 例如，Android 默认相机应用

# Frida 脚本
hook_script = """
Interceptor.attach(Module.getExportByName(null, "ioctl"), {
    onEnter: function(args) {
        const fd = args[0].toInt32();
        const request = args[1].toInt32();
        const argp = args[2];

        // 检查是否是 RKISP1 的配置 ioctl
        const RKISP1_CIF_ISP_CONFIG = 0x40086900; // 假设的 ioctl 命令，需要根据实际情况确定

        if (request === RKISP1_CIF_ISP_CONFIG) {
            console.log("ioctl called with RKISP1_CIF_ISP_CONFIG");
            console.log("File Descriptor:", fd);
            console.log("Request Code:", request);

            // 读取 rkisp1_params_cfg 结构体的内容
            const rkisp1_params_cfg_ptr = argp;
            if (rkisp1_params_cfg_ptr) {
                console.log("rkisp1_params_cfg:");
                const module_en_update = rkisp1_params_cfg_ptr.readU32();
                console.log("  module_en_update:", module_en_update);
                const module_ens = rkisp1_params_cfg_ptr.add(4).readU32();
                console.log("  module_ens:", module_ens);
                // ... 可以继续读取其他字段
            }
        }
    },
    onLeave: function(retval) {
        // console.log("ioctl returned:", retval);
    }
});
"""

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
    script = session.create_script(hook_script)
    script.on('message', on_message)
    script.load()
    sys.stdin.read()
except frida.common.exceptions.ProcessNotFoundError:
    print(f"未找到进程: {package_name}")
except Exception as e:
    print(e)
```

**使用 Frida 调试步骤：**

1. **安装 Frida 和 USB 驱动。**
2. **在 Android 设备上运行目标相机应用 (`com.android.camera2`)。**
3. **运行上面的 Frida Python 脚本。**
4. **在相机应用中执行一些操作，例如切换白平衡模式或调整曝光。**
5. **Frida 脚本会拦截 `ioctl` 调用，并打印出传递给内核的 `rkisp1_params_cfg` 结构体的部分内容，从而可以观察到 Android Framework 或 NDK 是如何配置 ISP 的。**

**注意：**

* 上面的 `RKISP1_CIF_ISP_CONFIG` 的值是假设的，需要根据具体的内核代码或设备信息来确定真实的 `ioctl` 命令。
*  你需要 root 权限才能在设备上运行 Frida 并 hook 系统进程或应用进程。
*  hook 系统级别的函数需要谨慎操作，不当的操作可能导致设备不稳定。

通过这种方式，可以深入了解 Android 系统如何利用 `rkisp1-config.handroid` 中定义的接口与底层的 ISP 硬件进行交互。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/rkisp1-config.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_RKISP1_CONFIG_H
#define _UAPI_RKISP1_CONFIG_H
#include <linux/types.h>
#define RKISP1_CIF_ISP_MODULE_DPCC (1U << 0)
#define RKISP1_CIF_ISP_MODULE_BLS (1U << 1)
#define RKISP1_CIF_ISP_MODULE_SDG (1U << 2)
#define RKISP1_CIF_ISP_MODULE_HST (1U << 3)
#define RKISP1_CIF_ISP_MODULE_LSC (1U << 4)
#define RKISP1_CIF_ISP_MODULE_AWB_GAIN (1U << 5)
#define RKISP1_CIF_ISP_MODULE_FLT (1U << 6)
#define RKISP1_CIF_ISP_MODULE_BDM (1U << 7)
#define RKISP1_CIF_ISP_MODULE_CTK (1U << 8)
#define RKISP1_CIF_ISP_MODULE_GOC (1U << 9)
#define RKISP1_CIF_ISP_MODULE_CPROC (1U << 10)
#define RKISP1_CIF_ISP_MODULE_AFC (1U << 11)
#define RKISP1_CIF_ISP_MODULE_AWB (1U << 12)
#define RKISP1_CIF_ISP_MODULE_IE (1U << 13)
#define RKISP1_CIF_ISP_MODULE_AEC (1U << 14)
#define RKISP1_CIF_ISP_MODULE_WDR (1U << 15)
#define RKISP1_CIF_ISP_MODULE_DPF (1U << 16)
#define RKISP1_CIF_ISP_MODULE_DPF_STRENGTH (1U << 17)
#define RKISP1_CIF_ISP_CTK_COEFF_MAX 0x100
#define RKISP1_CIF_ISP_CTK_OFFSET_MAX 0x800
#define RKISP1_CIF_ISP_AE_MEAN_MAX_V10 25
#define RKISP1_CIF_ISP_AE_MEAN_MAX_V12 81
#define RKISP1_CIF_ISP_AE_MEAN_MAX RKISP1_CIF_ISP_AE_MEAN_MAX_V12
#define RKISP1_CIF_ISP_HIST_BIN_N_MAX_V10 16
#define RKISP1_CIF_ISP_HIST_BIN_N_MAX_V12 32
#define RKISP1_CIF_ISP_HIST_BIN_N_MAX RKISP1_CIF_ISP_HIST_BIN_N_MAX_V12
#define RKISP1_CIF_ISP_AFM_MAX_WINDOWS 3
#define RKISP1_CIF_ISP_DEGAMMA_CURVE_SIZE 17
#define RKISP1_CIF_ISP_BDM_MAX_TH 0xff
#define RKISP1_CIF_ISP_BLS_START_H_MAX 0x00000fff
#define RKISP1_CIF_ISP_BLS_STOP_H_MAX 0x00000fff
#define RKISP1_CIF_ISP_BLS_START_V_MAX 0x00000fff
#define RKISP1_CIF_ISP_BLS_STOP_V_MAX 0x00000fff
#define RKISP1_CIF_ISP_BLS_SAMPLES_MAX 0x00000012
#define RKISP1_CIF_ISP_BLS_FIX_SUB_MAX 0x00000fff
#define RKISP1_CIF_ISP_BLS_FIX_SUB_MIN 0xfffff000
#define RKISP1_CIF_ISP_BLS_FIX_MASK 0x00001fff
#define RKISP1_CIF_ISP_AWB_MAX_GRID 1
#define RKISP1_CIF_ISP_AWB_MAX_FRAMES 7
#define RKISP1_CIF_ISP_GAMMA_OUT_MAX_SAMPLES_V10 17
#define RKISP1_CIF_ISP_GAMMA_OUT_MAX_SAMPLES_V12 34
#define RKISP1_CIF_ISP_GAMMA_OUT_MAX_SAMPLES RKISP1_CIF_ISP_GAMMA_OUT_MAX_SAMPLES_V12
#define RKISP1_CIF_ISP_LSC_SECTORS_TBL_SIZE 8
#define RKISP1_CIF_ISP_LSC_SAMPLES_MAX 17
#define RKISP1_CIF_ISP_HISTOGRAM_WEIGHT_GRIDS_SIZE_V10 25
#define RKISP1_CIF_ISP_HISTOGRAM_WEIGHT_GRIDS_SIZE_V12 81
#define RKISP1_CIF_ISP_HISTOGRAM_WEIGHT_GRIDS_SIZE RKISP1_CIF_ISP_HISTOGRAM_WEIGHT_GRIDS_SIZE_V12
#define RKISP1_CIF_ISP_DPCC_METHODS_MAX 3
#define RKISP1_CIF_ISP_DPCC_MODE_STAGE1_ENABLE (1U << 2)
#define RKISP1_CIF_ISP_DPCC_OUTPUT_MODE_STAGE1_INCL_G_CENTER (1U << 0)
#define RKISP1_CIF_ISP_DPCC_OUTPUT_MODE_STAGE1_INCL_RB_CENTER (1U << 1)
#define RKISP1_CIF_ISP_DPCC_OUTPUT_MODE_STAGE1_G_3X3 (1U << 2)
#define RKISP1_CIF_ISP_DPCC_OUTPUT_MODE_STAGE1_RB_3X3 (1U << 3)
#define RKISP1_CIF_ISP_DPCC_SET_USE_STAGE1_USE_SET(n) ((n) << 0)
#define RKISP1_CIF_ISP_DPCC_SET_USE_STAGE1_USE_FIX_SET (1U << 3)
#define RKISP1_CIF_ISP_DPCC_METHODS_SET_PG_GREEN_ENABLE (1U << 0)
#define RKISP1_CIF_ISP_DPCC_METHODS_SET_LC_GREEN_ENABLE (1U << 1)
#define RKISP1_CIF_ISP_DPCC_METHODS_SET_RO_GREEN_ENABLE (1U << 2)
#define RKISP1_CIF_ISP_DPCC_METHODS_SET_RND_GREEN_ENABLE (1U << 3)
#define RKISP1_CIF_ISP_DPCC_METHODS_SET_RG_GREEN_ENABLE (1U << 4)
#define RKISP1_CIF_ISP_DPCC_METHODS_SET_PG_RED_BLUE_ENABLE (1U << 8)
#define RKISP1_CIF_ISP_DPCC_METHODS_SET_LC_RED_BLUE_ENABLE (1U << 9)
#define RKISP1_CIF_ISP_DPCC_METHODS_SET_RO_RED_BLUE_ENABLE (1U << 10)
#define RKISP1_CIF_ISP_DPCC_METHODS_SET_RND_RED_BLUE_ENABLE (1U << 11)
#define RKISP1_CIF_ISP_DPCC_METHODS_SET_RG_RED_BLUE_ENABLE (1U << 12)
#define RKISP1_CIF_ISP_DPCC_LINE_THRESH_G(v) ((v) << 0)
#define RKISP1_CIF_ISP_DPCC_LINE_THRESH_RB(v) ((v) << 8)
#define RKISP1_CIF_ISP_DPCC_LINE_MAD_FAC_G(v) ((v) << 0)
#define RKISP1_CIF_ISP_DPCC_LINE_MAD_FAC_RB(v) ((v) << 8)
#define RKISP1_CIF_ISP_DPCC_PG_FAC_G(v) ((v) << 0)
#define RKISP1_CIF_ISP_DPCC_PG_FAC_RB(v) ((v) << 8)
#define RKISP1_CIF_ISP_DPCC_RND_THRESH_G(v) ((v) << 0)
#define RKISP1_CIF_ISP_DPCC_RND_THRESH_RB(v) ((v) << 8)
#define RKISP1_CIF_ISP_DPCC_RG_FAC_G(v) ((v) << 0)
#define RKISP1_CIF_ISP_DPCC_RG_FAC_RB(v) ((v) << 8)
#define RKISP1_CIF_ISP_DPCC_RO_LIMITS_n_G(n,v) ((v) << ((n) * 4))
#define RKISP1_CIF_ISP_DPCC_RO_LIMITS_n_RB(n,v) ((v) << ((n) * 4 + 2))
#define RKISP1_CIF_ISP_DPCC_RND_OFFS_n_G(n,v) ((v) << ((n) * 4))
#define RKISP1_CIF_ISP_DPCC_RND_OFFS_n_RB(n,v) ((v) << ((n) * 4 + 2))
#define RKISP1_CIF_ISP_DPF_MAX_NLF_COEFFS 17
#define RKISP1_CIF_ISP_DPF_MAX_SPATIAL_COEFFS 6
#define RKISP1_CIF_ISP_COMPAND_NUM_POINTS 64
#define RKISP1_CIF_ISP_STAT_AWB (1U << 0)
#define RKISP1_CIF_ISP_STAT_AUTOEXP (1U << 1)
#define RKISP1_CIF_ISP_STAT_AFM (1U << 2)
#define RKISP1_CIF_ISP_STAT_HIST (1U << 3)
enum rkisp1_cif_isp_version {
  RKISP1_V10 = 10,
  RKISP1_V11,
  RKISP1_V12,
  RKISP1_V13,
  RKISP1_V_IMX8MP,
};
enum rkisp1_cif_isp_histogram_mode {
  RKISP1_CIF_ISP_HISTOGRAM_MODE_DISABLE,
  RKISP1_CIF_ISP_HISTOGRAM_MODE_RGB_COMBINED,
  RKISP1_CIF_ISP_HISTOGRAM_MODE_R_HISTOGRAM,
  RKISP1_CIF_ISP_HISTOGRAM_MODE_G_HISTOGRAM,
  RKISP1_CIF_ISP_HISTOGRAM_MODE_B_HISTOGRAM,
  RKISP1_CIF_ISP_HISTOGRAM_MODE_Y_HISTOGRAM
};
enum rkisp1_cif_isp_awb_mode_type {
  RKISP1_CIF_ISP_AWB_MODE_MANUAL,
  RKISP1_CIF_ISP_AWB_MODE_RGB,
  RKISP1_CIF_ISP_AWB_MODE_YCBCR
};
enum rkisp1_cif_isp_flt_mode {
  RKISP1_CIF_ISP_FLT_STATIC_MODE,
  RKISP1_CIF_ISP_FLT_DYNAMIC_MODE
};
enum rkisp1_cif_isp_exp_ctrl_autostop {
  RKISP1_CIF_ISP_EXP_CTRL_AUTOSTOP_0 = 0,
  RKISP1_CIF_ISP_EXP_CTRL_AUTOSTOP_1 = 1,
};
enum rkisp1_cif_isp_exp_meas_mode {
  RKISP1_CIF_ISP_EXP_MEASURING_MODE_0,
  RKISP1_CIF_ISP_EXP_MEASURING_MODE_1,
};
struct rkisp1_cif_isp_window {
  __u16 h_offs;
  __u16 v_offs;
  __u16 h_size;
  __u16 v_size;
};
struct rkisp1_cif_isp_bls_fixed_val {
  __s16 r;
  __s16 gr;
  __s16 gb;
  __s16 b;
};
struct rkisp1_cif_isp_bls_config {
  __u8 enable_auto;
  __u8 en_windows;
  struct rkisp1_cif_isp_window bls_window1;
  struct rkisp1_cif_isp_window bls_window2;
  __u8 bls_samples;
  struct rkisp1_cif_isp_bls_fixed_val fixed_val;
};
struct rkisp1_cif_isp_dpcc_methods_config {
  __u32 method;
  __u32 line_thresh;
  __u32 line_mad_fac;
  __u32 pg_fac;
  __u32 rnd_thresh;
  __u32 rg_fac;
};
struct rkisp1_cif_isp_dpcc_config {
  __u32 mode;
  __u32 output_mode;
  __u32 set_use;
  struct rkisp1_cif_isp_dpcc_methods_config methods[RKISP1_CIF_ISP_DPCC_METHODS_MAX];
  __u32 ro_limits;
  __u32 rnd_offs;
};
struct rkisp1_cif_isp_gamma_corr_curve {
  __u16 gamma_y[RKISP1_CIF_ISP_DEGAMMA_CURVE_SIZE];
};
struct rkisp1_cif_isp_gamma_curve_x_axis_pnts {
  __u32 gamma_dx0;
  __u32 gamma_dx1;
};
struct rkisp1_cif_isp_sdg_config {
  struct rkisp1_cif_isp_gamma_corr_curve curve_r;
  struct rkisp1_cif_isp_gamma_corr_curve curve_g;
  struct rkisp1_cif_isp_gamma_corr_curve curve_b;
  struct rkisp1_cif_isp_gamma_curve_x_axis_pnts xa_pnts;
};
struct rkisp1_cif_isp_lsc_config {
  __u16 r_data_tbl[RKISP1_CIF_ISP_LSC_SAMPLES_MAX][RKISP1_CIF_ISP_LSC_SAMPLES_MAX];
  __u16 gr_data_tbl[RKISP1_CIF_ISP_LSC_SAMPLES_MAX][RKISP1_CIF_ISP_LSC_SAMPLES_MAX];
  __u16 gb_data_tbl[RKISP1_CIF_ISP_LSC_SAMPLES_MAX][RKISP1_CIF_ISP_LSC_SAMPLES_MAX];
  __u16 b_data_tbl[RKISP1_CIF_ISP_LSC_SAMPLES_MAX][RKISP1_CIF_ISP_LSC_SAMPLES_MAX];
  __u16 x_grad_tbl[RKISP1_CIF_ISP_LSC_SECTORS_TBL_SIZE];
  __u16 y_grad_tbl[RKISP1_CIF_ISP_LSC_SECTORS_TBL_SIZE];
  __u16 x_size_tbl[RKISP1_CIF_ISP_LSC_SECTORS_TBL_SIZE];
  __u16 y_size_tbl[RKISP1_CIF_ISP_LSC_SECTORS_TBL_SIZE];
  __u16 config_width;
  __u16 config_height;
};
struct rkisp1_cif_isp_ie_config {
  __u16 effect;
  __u16 color_sel;
  __u16 eff_mat_1;
  __u16 eff_mat_2;
  __u16 eff_mat_3;
  __u16 eff_mat_4;
  __u16 eff_mat_5;
  __u16 eff_tint;
};
struct rkisp1_cif_isp_cproc_config {
  __u8 c_out_range;
  __u8 y_in_range;
  __u8 y_out_range;
  __u8 contrast;
  __u8 brightness;
  __u8 sat;
  __u8 hue;
};
struct rkisp1_cif_isp_awb_meas_config {
  struct rkisp1_cif_isp_window awb_wnd;
  __u32 awb_mode;
  __u8 max_y;
  __u8 min_y;
  __u8 max_csum;
  __u8 min_c;
  __u8 frames;
  __u8 awb_ref_cr;
  __u8 awb_ref_cb;
  __u8 enable_ymax_cmp;
};
struct rkisp1_cif_isp_awb_gain_config {
  __u16 gain_red;
  __u16 gain_green_r;
  __u16 gain_blue;
  __u16 gain_green_b;
};
struct rkisp1_cif_isp_flt_config {
  __u32 mode;
  __u8 grn_stage1;
  __u8 chr_h_mode;
  __u8 chr_v_mode;
  __u32 thresh_bl0;
  __u32 thresh_bl1;
  __u32 thresh_sh0;
  __u32 thresh_sh1;
  __u32 lum_weight;
  __u32 fac_sh1;
  __u32 fac_sh0;
  __u32 fac_mid;
  __u32 fac_bl0;
  __u32 fac_bl1;
};
struct rkisp1_cif_isp_bdm_config {
  __u8 demosaic_th;
};
struct rkisp1_cif_isp_ctk_config {
  __u16 coeff[3][3];
  __u16 ct_offset[3];
};
enum rkisp1_cif_isp_goc_mode {
  RKISP1_CIF_ISP_GOC_MODE_LOGARITHMIC,
  RKISP1_CIF_ISP_GOC_MODE_EQUIDISTANT
};
struct rkisp1_cif_isp_goc_config {
  __u32 mode;
  __u16 gamma_y[RKISP1_CIF_ISP_GAMMA_OUT_MAX_SAMPLES];
};
struct rkisp1_cif_isp_hst_config {
  __u32 mode;
  __u8 histogram_predivider;
  struct rkisp1_cif_isp_window meas_window;
  __u8 hist_weight[RKISP1_CIF_ISP_HISTOGRAM_WEIGHT_GRIDS_SIZE];
};
struct rkisp1_cif_isp_aec_config {
  __u32 mode;
  __u32 autostop;
  struct rkisp1_cif_isp_window meas_window;
};
struct rkisp1_cif_isp_afc_config {
  __u8 num_afm_win;
  struct rkisp1_cif_isp_window afm_win[RKISP1_CIF_ISP_AFM_MAX_WINDOWS];
  __u32 thres;
  __u32 var_shift;
};
enum rkisp1_cif_isp_dpf_gain_usage {
  RKISP1_CIF_ISP_DPF_GAIN_USAGE_DISABLED,
  RKISP1_CIF_ISP_DPF_GAIN_USAGE_NF_GAINS,
  RKISP1_CIF_ISP_DPF_GAIN_USAGE_LSC_GAINS,
  RKISP1_CIF_ISP_DPF_GAIN_USAGE_NF_LSC_GAINS,
  RKISP1_CIF_ISP_DPF_GAIN_USAGE_AWB_GAINS,
  RKISP1_CIF_ISP_DPF_GAIN_USAGE_AWB_LSC_GAINS,
  RKISP1_CIF_ISP_DPF_GAIN_USAGE_MAX
};
enum rkisp1_cif_isp_dpf_rb_filtersize {
  RKISP1_CIF_ISP_DPF_RB_FILTERSIZE_13x9,
  RKISP1_CIF_ISP_DPF_RB_FILTERSIZE_9x9,
};
enum rkisp1_cif_isp_dpf_nll_scale_mode {
  RKISP1_CIF_ISP_NLL_SCALE_LINEAR,
  RKISP1_CIF_ISP_NLL_SCALE_LOGARITHMIC,
};
struct rkisp1_cif_isp_dpf_nll {
  __u16 coeff[RKISP1_CIF_ISP_DPF_MAX_NLF_COEFFS];
  __u32 scale_mode;
};
struct rkisp1_cif_isp_dpf_rb_flt {
  __u32 fltsize;
  __u8 spatial_coeff[RKISP1_CIF_ISP_DPF_MAX_SPATIAL_COEFFS];
  __u8 r_enable;
  __u8 b_enable;
};
struct rkisp1_cif_isp_dpf_g_flt {
  __u8 spatial_coeff[RKISP1_CIF_ISP_DPF_MAX_SPATIAL_COEFFS];
  __u8 gr_enable;
  __u8 gb_enable;
};
struct rkisp1_cif_isp_dpf_gain {
  __u32 mode;
  __u16 nf_r_gain;
  __u16 nf_b_gain;
  __u16 nf_gr_gain;
  __u16 nf_gb_gain;
};
struct rkisp1_cif_isp_dpf_config {
  struct rkisp1_cif_isp_dpf_gain gain;
  struct rkisp1_cif_isp_dpf_g_flt g_flt;
  struct rkisp1_cif_isp_dpf_rb_flt rb_flt;
  struct rkisp1_cif_isp_dpf_nll nll;
};
struct rkisp1_cif_isp_dpf_strength_config {
  __u8 r;
  __u8 g;
  __u8 b;
};
struct rkisp1_cif_isp_isp_other_cfg {
  struct rkisp1_cif_isp_dpcc_config dpcc_config;
  struct rkisp1_cif_isp_bls_config bls_config;
  struct rkisp1_cif_isp_sdg_config sdg_config;
  struct rkisp1_cif_isp_lsc_config lsc_config;
  struct rkisp1_cif_isp_awb_gain_config awb_gain_config;
  struct rkisp1_cif_isp_flt_config flt_config;
  struct rkisp1_cif_isp_bdm_config bdm_config;
  struct rkisp1_cif_isp_ctk_config ctk_config;
  struct rkisp1_cif_isp_goc_config goc_config;
  struct rkisp1_cif_isp_dpf_config dpf_config;
  struct rkisp1_cif_isp_dpf_strength_config dpf_strength_config;
  struct rkisp1_cif_isp_cproc_config cproc_config;
  struct rkisp1_cif_isp_ie_config ie_config;
};
struct rkisp1_cif_isp_isp_meas_cfg {
  struct rkisp1_cif_isp_awb_meas_config awb_meas_config;
  struct rkisp1_cif_isp_hst_config hst_config;
  struct rkisp1_cif_isp_aec_config aec_config;
  struct rkisp1_cif_isp_afc_config afc_config;
};
struct rkisp1_params_cfg {
  __u32 module_en_update;
  __u32 module_ens;
  __u32 module_cfg_update;
  struct rkisp1_cif_isp_isp_meas_cfg meas;
  struct rkisp1_cif_isp_isp_other_cfg others;
};
struct rkisp1_cif_isp_compand_bls_config {
  __u32 r;
  __u32 gr;
  __u32 gb;
  __u32 b;
};
struct rkisp1_cif_isp_compand_curve_config {
  __u8 px[RKISP1_CIF_ISP_COMPAND_NUM_POINTS];
  __u32 x[RKISP1_CIF_ISP_COMPAND_NUM_POINTS];
  __u32 y[RKISP1_CIF_ISP_COMPAND_NUM_POINTS];
};
struct rkisp1_cif_isp_awb_meas {
  __u32 cnt;
  __u8 mean_y_or_g;
  __u8 mean_cb_or_b;
  __u8 mean_cr_or_r;
};
struct rkisp1_cif_isp_awb_stat {
  struct rkisp1_cif_isp_awb_meas awb_mean[RKISP1_CIF_ISP_AWB_MAX_GRID];
};
struct rkisp1_cif_isp_bls_meas_val {
  __u16 meas_r;
  __u16 meas_gr;
  __u16 meas_gb;
  __u16 meas_b;
};
struct rkisp1_cif_isp_ae_stat {
  __u8 exp_mean[RKISP1_CIF_ISP_AE_MEAN_MAX];
  struct rkisp1_cif_isp_bls_meas_val bls_val;
};
struct rkisp1_cif_isp_af_meas_val {
  __u32 sum;
  __u32 lum;
};
struct rkisp1_cif_isp_af_stat {
  struct rkisp1_cif_isp_af_meas_val window[RKISP1_CIF_ISP_AFM_MAX_WINDOWS];
};
struct rkisp1_cif_isp_hist_stat {
  __u32 hist_bins[RKISP1_CIF_ISP_HIST_BIN_N_MAX];
};
struct rkisp1_cif_isp_stat {
  struct rkisp1_cif_isp_awb_stat awb;
  struct rkisp1_cif_isp_ae_stat ae;
  struct rkisp1_cif_isp_af_stat af;
  struct rkisp1_cif_isp_hist_stat hist;
};
struct rkisp1_stat_buffer {
  __u32 meas_type;
  __u32 frame_id;
  struct rkisp1_cif_isp_stat params;
};
enum rkisp1_ext_params_block_type {
  RKISP1_EXT_PARAMS_BLOCK_TYPE_BLS,
  RKISP1_EXT_PARAMS_BLOCK_TYPE_DPCC,
  RKISP1_EXT_PARAMS_BLOCK_TYPE_SDG,
  RKISP1_EXT_PARAMS_BLOCK_TYPE_AWB_GAIN,
  RKISP1_EXT_PARAMS_BLOCK_TYPE_FLT,
  RKISP1_EXT_PARAMS_BLOCK_TYPE_BDM,
  RKISP1_EXT_PARAMS_BLOCK_TYPE_CTK,
  RKISP1_EXT_PARAMS_BLOCK_TYPE_GOC,
  RKISP1_EXT_PARAMS_BLOCK_TYPE_DPF,
  RKISP1_EXT_PARAMS_BLOCK_TYPE_DPF_STRENGTH,
  RKISP1_EXT_PARAMS_BLOCK_TYPE_CPROC,
  RKISP1_EXT_PARAMS_BLOCK_TYPE_IE,
  RKISP1_EXT_PARAMS_BLOCK_TYPE_LSC,
  RKISP1_EXT_PARAMS_BLOCK_TYPE_AWB_MEAS,
  RKISP1_EXT_PARAMS_BLOCK_TYPE_HST_MEAS,
  RKISP1_EXT_PARAMS_BLOCK_TYPE_AEC_MEAS,
  RKISP1_EXT_PARAMS_BLOCK_TYPE_AFC_MEAS,
  RKISP1_EXT_PARAMS_BLOCK_TYPE_COMPAND_BLS,
  RKISP1_EXT_PARAMS_BLOCK_TYPE_COMPAND_EXPAND,
  RKISP1_EXT_PARAMS_BLOCK_TYPE_COMPAND_COMPRESS,
};
#define RKISP1_EXT_PARAMS_FL_BLOCK_DISABLE (1U << 0)
#define RKISP1_EXT_PARAMS_FL_BLOCK_ENABLE (1U << 1)
struct rkisp1_ext_params_block_header {
  __u16 type;
  __u16 flags;
  __u32 size;
};
struct rkisp1_ext_params_bls_config {
  struct rkisp1_ext_params_block_header header;
  struct rkisp1_cif_isp_bls_config config;
} __attribute__((aligned(8)));
struct rkisp1_ext_params_dpcc_config {
  struct rkisp1_ext_params_block_header header;
  struct rkisp1_cif_isp_dpcc_config config;
} __attribute__((aligned(8)));
struct rkisp1_ext_params_sdg_config {
  struct rkisp1_ext_params_block_header header;
  struct rkisp1_cif_isp_sdg_config config;
} __attribute__((aligned(8)));
struct rkisp1_ext_params_lsc_config {
  struct rkisp1_ext_params_block_header header;
  struct rkisp1_cif_isp_lsc_config config;
} __attribute__((aligned(8)));
struct rkisp1_ext_params_awb_gain_config {
  struct rkisp1_ext_params_block_header header;
  struct rkisp1_cif_isp_awb_gain_config config;
} __attribute__((aligned(8)));
struct rkisp1_ext_params_flt_config {
  struct rkisp1_ext_params_block_header header;
  struct rkisp1_cif_isp_flt_config config;
} __attribute__((aligned(8)));
struct rkisp1_ext_params_bdm_config {
  struct rkisp1_ext_params_block_header header;
  struct rkisp1_cif_isp_bdm_config config;
} __attribute__((aligned(8)));
struct rkisp1_ext_params_ctk_config {
  struct rkisp1_ext_params_block_header header;
  struct rkisp1_cif_isp_ctk_config config;
} __attribute__((aligned(8)));
struct rkisp1_ext_params_goc_config {
  struct rkisp1_ext_params_block_header header;
  struct rkisp1_cif_isp_goc_config config;
} __attribute__((aligned(8)));
struct rkisp1_ext_params_dpf_config {
  struct rkisp1_ext_params_block_header header;
  struct rkisp1_cif_isp_dpf_config config;
} __attribute__((aligned(8)));
struct rkisp1_ext_params_dpf_strength_config {
  struct rkisp1_ext_params_block_header header;
  struct rkisp1_cif_isp_dpf_strength_config config;
} __attribute__((aligned(8)));
struct rkisp1_ext_params_cproc_config {
  struct rkisp1_ext_params_block_header header;
  struct rkisp1_cif_isp_cproc_config config;
} __attribute__((aligned(8)));
struct rkisp1_ext_params_ie_config {
  struct rkisp1_ext_params_block_header header;
  struct rkisp1_cif_isp_ie_config config;
} __attribute__((aligned(8)));
struct rkisp1_ext_params_awb_meas_config {
  struct rkisp1_ext_params_block_header header;
  struct rkisp1_cif_isp_awb_meas_config config;
} __attribute__((aligned(8)));
struct rkisp1_ext_params_hst_config {
  struct rkisp1_ext_params_block_header header;
  struct rkisp1_cif_isp_hst_config config;
} __attribute__((aligned(8)));
struct rkisp1_ext_params_aec_config {
  struct rkisp1_ext_params_block_header header;
  struct rkisp1_cif_isp_aec_config config;
} __attribute__((aligned(8)));
struct rkisp1_ext_params_afc_config {
  struct rkisp1_ext_params_block_header header;
  struct rkisp1_cif_isp_afc_config config;
} __attribute__((aligned(8)));
struct rkisp1_ext_params_compand_bls_config {
  struct rkisp1_ext_params_block_header header;
  struct rkisp1_cif_isp_compand_bls_config config;
} __attribute__((aligned(8)));
struct rkisp1_ext_params_compand_curve_config {
  struct rkisp1_ext_params_block_header header;
  struct rkisp1_cif_isp_compand_curve_config config;
} __attribute__((aligned(8)));
#define RKISP1_EXT_PARAMS_MAX_SIZE (sizeof(struct rkisp1_ext_params_bls_config) + sizeof(struct rkisp1_ext_params_dpcc_config) + sizeof(struct rkisp1_ext_params_sdg_config) + sizeof(struct rkisp1_ext_params_lsc_config) + sizeof(struct rkisp1_ext_params_awb_gain_config) + sizeof(struct rkisp1_ext_params_flt_config) + sizeof(struct rkisp1_ext_params_bdm_config) + sizeof(struct rkisp1_ext_params_ctk_config) + sizeof(struct rkisp1_ext_params_goc_config) + sizeof(struct rkisp1_ext_params_dpf_config) + sizeof(struct rkisp1_ext_params_dpf_strength_config) + sizeof(struct rkisp1_ext_params_cproc_config) + sizeof(struct rkisp1_ext_params_ie_config) + sizeof(struct rkisp1_ext_params_awb_meas_config) + sizeof(struct rkisp1_ext_params_hst_config) + sizeof(struct rkisp1_ext_params_aec_config) + sizeof(struct rkisp1_ext_params_afc_config) + sizeof(struct rkisp1_ext_params_compand_bls_config) + sizeof(struct rkisp1_ext_params_compand_curve_config) + sizeof(struct rkisp1_ext_params_compand_curve_config))
enum rksip1_ext_param_buffer_version {
  RKISP1_EXT_PARAM_BUFFER_V1 = 1,
};
struct rkisp1_ext_params_cfg {
  __u32 version;
  __u32 data_size;
  __u8 data[RKISP1_EXT_PARAMS_MAX_SIZE];
};
#endif
```