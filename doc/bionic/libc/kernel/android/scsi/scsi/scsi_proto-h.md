Response:
Let's break down the thought process for analyzing this header file.

1. **Identify the Core Purpose:** The first thing I notice is the filename: `scsi_proto.h`. The `scsi` part immediately tells me it's related to the Small Computer System Interface. The `.h` extension indicates a header file, likely defining constants and data structures for interacting with SCSI devices. The location `bionic/libc/kernel/android/scsi/scsi/` reinforces this is part of Android's low-level SCSI support.

2. **High-Level Overview:** I scan the content and see a lot of `#define` statements. These are preprocessor directives that create symbolic names for numeric values. This is a common way to define constants in C. I also spot some `enum` declarations, which define sets of named integer constants.

3. **Categorization of Defines:** I start grouping the defines based on their prefixes or apparent meaning:
    * Things starting with `TEST_UNIT_READY`, `READ_6`, `WRITE_10`, etc. seem to be SCSI commands.
    * Things starting with `NO_SENSE`, `RECOVERED_ERROR`, etc. look like SCSI status codes or sense keys.
    * Things starting with `TYPE_DISK`, `TYPE_TAPE`, etc. seem to represent different types of SCSI devices.
    * Things starting with `SCSI_ACCESS_STATE_` appear to define the state of a SCSI device.
    * Things starting with `ZBC_` relate to Zoned Block Commands, a more recent extension to SCSI.
    * Things starting with `SCSI_VERSION_DESCRIPTOR_` are related to SCSI versions.
    * Things starting with `SCSI_SUPPORT_` indicate the level of support for certain features.
    * Finally, `SCSI_CONTROL_MASK` and `SCSI_GROUP_NUMBER_MASK` seem like bitmasks.

4. **Functionality Deduction:** Based on the categories, I can infer the file's overall functionality:
    * **Defines SCSI Command Codes:**  It provides a standardized way to refer to various SCSI operations (read, write, format, inquiry, etc.).
    * **Defines SCSI Status and Sense Codes:**  It defines standard error and status indicators returned by SCSI devices.
    * **Defines SCSI Device Types:** It lists common types of devices that might be accessed via SCSI.
    * **Defines SCSI Access States:** It provides constants for describing the operational status of a SCSI device.
    * **Defines Zoned Block Command (ZBC) Specifics:** It includes constants related to the newer ZBC extension, likely for managing zoned storage devices.
    * **Defines SCSI Versioning Information:** It provides constants for identifying different SCSI protocol versions.
    * **Defines Feature Support Levels:** It indicates the extent of support for certain SCSI features.
    * **Defines Control and Group Masks:** These are likely used for bitwise operations to extract specific information.

5. **Relationship to Android:**  I need to connect this low-level SCSI definition to the broader Android system. Here's how I reason:
    * **Hardware Interaction:** Android devices often interact with storage via SCSI, especially for internal storage (like eMMC or UFS) and external storage (like SD cards or USB drives).
    * **Kernel Driver Interface:** This header file is in the `kernel` directory of bionic, indicating it's used by kernel-level drivers. Android's kernel interacts with the hardware using protocols like SCSI.
    * **Abstraction Layer:** While app developers don't directly use these constants, Android's framework provides higher-level APIs for storage access. These APIs eventually translate into low-level SCSI commands.

6. **Libc Function Explanation (Crucially, this file *doesn't define any libc functions*):** This is a key point. This header file *defines constants*. It doesn't contain function definitions. Therefore, I need to explicitly state that there are *no libc functions defined here* and that the *implementation happens in the kernel drivers*. It's important to clarify the distinction between the *definitions* in the header and the *implementation* in the kernel.

7. **Dynamic Linker Aspect (Again, this file is just constants):**  Similarly, this header file doesn't directly involve the dynamic linker. It defines constants that *might be used* by libraries that *are* dynamically linked, but the header itself is just data. I need to acknowledge this and explain that the linking process would involve other shared libraries that use these constants. I'll provide a conceptual example of how a library *might* use these constants and how the dynamic linker would load that library.

8. **Logical Reasoning (Simple Constant Mapping):** The "logic" here is direct mapping. Inputting `TEST_UNIT_READY` (the symbol) effectively outputs `0x00` (the value). There's no complex logic or function involved.

9. **Common Usage Errors (Mostly Conceptual):**  Users (especially developers working with lower-level storage) might make mistakes by:
    * **Using the wrong command code:** Sending `READ_6` when `READ_10` is needed.
    * **Misinterpreting status codes:**  Not handling `NOT_READY` correctly.
    * **Incorrectly using ZBC commands:**  Violating zone write requirements.

10. **Android Framework/NDK Path:** I'll outline a simplified path from a high-level Android operation (like writing a file) down to the SCSI layer:
    * App uses Java `FileOutputStream`.
    * Framework (Java/Kotlin) handles file system operations.
    * Native code (likely in `sdcardfs` or a similar component) interacts with the kernel.
    * Kernel block device driver translates the request into SCSI commands using these constants.

11. **Frida Hook Example:**  I'll create a Frida script that hooks a function within a kernel module (or a userspace library interacting with the kernel) that *uses* these SCSI constants. The hook will log the value of a command code before it's sent. This demonstrates how to observe the usage of these constants in practice.

12. **Review and Refine:** Finally, I'll reread my answer to ensure clarity, accuracy, and completeness. I'll double-check that I've addressed all the prompts and haven't made any incorrect assumptions. I'll pay particular attention to distinguishing between definitions and implementations, and the role (or lack thereof) of the dynamic linker in *this specific file*.
这是一个定义SCSI协议相关常量的C头文件 (`.h`)。它并不包含任何可执行代码或函数实现，而是为使用SCSI协议的软件提供了一组预定义的数值宏和枚举类型。

**功能列举:**

1. **定义SCSI命令代码 (OpCodes):** 文件中大量以大写字母定义的宏，如 `TEST_UNIT_READY`, `READ_10`, `WRITE_16` 等，代表了各种SCSI命令的操作码。这些代码用于指示SCSI设备执行特定的操作，例如测试设备是否就绪、读取数据、写入数据等。

2. **定义SCSI状态代码 (Status Codes):**  `NO_SENSE`, `RECOVERED_ERROR`, `NOT_READY` 等宏定义了SCSI设备返回的状态代码，用于指示命令执行的结果，例如成功、发生错误、设备未就绪等。

3. **定义SCSI设备类型 (Device Types):** `TYPE_DISK`, `TYPE_TAPE`, `TYPE_ROM` 等宏定义了不同类型的SCSI设备，例如磁盘、磁带驱动器、只读存储器等。

4. **定义SCSI访问状态 (Access States):** `SCSI_ACCESS_STATE_OPTIMAL`, `SCSI_ACCESS_STATE_STANDBY` 等宏定义了SCSI设备或逻辑单元的访问状态，例如最佳状态、待机状态等。

5. **定义Zoned Block Command (ZBC) 相关常量:** 文件中包含以 `ZBC_` 开头的枚举和宏，这些常量与ZBC标准相关，用于管理和控制具有区域特性的存储设备。

6. **定义SCSI版本描述符 (Version Descriptors):** `SCSI_VERSION_DESCRIPTOR_FCP4`, `SCSI_VERSION_DESCRIPTOR_SAM5` 等宏定义了不同的SCSI协议版本。

7. **定义SCSI支持的操作码信息:** `SCSI_SUPPORT_NO_INFO`, `SCSI_SUPPORT_FULL` 等宏用于指示对特定SCSI操作码的支持程度。

8. **定义掩码:** `STATUS_MASK`, `SCSI_CONTROL_MASK`, `SCSI_GROUP_NUMBER_MASK` 等宏定义了用于位运算的掩码，可以用来提取或操作SCSI状态或控制信息中的特定位。

**与Android功能的关联及举例:**

这个头文件定义了底层的SCSI协议常量，而Android设备经常使用SCSI协议与存储设备进行通信，例如：

* **内部存储 (eMMC/UFS):** Android手机的内部存储通常通过eMMC或UFS接口连接，这些接口在底层可以使用SCSI协议进行数据传输。当Android系统读写内部存储上的文件时，最终会涉及到向存储设备发送相应的SCSI命令，例如 `READ_10` 或 `WRITE_10`。
* **外部存储 (SD卡/USB存储):** 当用户插入SD卡或USB存储设备时，Android系统会识别这些设备，并可能使用SCSI协议与其通信。例如，执行格式化SD卡的操作会涉及到发送 `FORMAT_UNIT` 命令。
* **蓝牙设备 (某些场景):** 在某些特定的硬件架构中，蓝牙设备也可能通过SCSI协议与系统进行交互。

**举例说明:**

假设Android系统需要从一个SCSI磁盘设备读取数据块。这个过程可能涉及到以下步骤：

1. **Android Framework 发起读取请求:** 用户程序通过Android的文件系统API (例如 `FileInputStream`) 发起读取请求。
2. **VFS (虚拟文件系统) 处理:** Android内核的VFS层接收到请求。
3. **块设备层处理:** VFS将请求传递给相应的块设备驱动程序。
4. **SCSI驱动程序:** 块设备驱动程序将读取请求转换为一个SCSI命令，例如 `READ_10`，并使用该头文件中定义的 `READ_10` 宏表示其操作码 (0x28)。
5. **构建SCSI命令数据包:**  SCSI驱动程序会构建包含操作码和其他参数的SCSI命令数据包。
6. **发送到SCSI控制器:**  该数据包被发送到连接到SCSI设备的控制器。
7. **SCSI设备执行:** SCSI设备接收到命令后，执行相应的读取操作。
8. **返回状态和数据:** SCSI设备将读取的数据和状态码返回给控制器。状态码可能使用该头文件中定义的宏，例如 `COMPLETED` (表示成功) 或 `NOT_READY` (表示设备未就绪)。
9. **逐层向上返回:**  状态码和数据最终会通过驱动程序、块设备层、VFS层，返回到Android Framework，最终到达用户程序。

**详细解释每一个libc函数的功能是如何实现的:**

**这个头文件本身不包含任何 libc 函数的实现。** 它只是定义了一些常量。libc 函数的实现位于 bionic 库的其他源文件中。

**对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程:**

**这个头文件与 dynamic linker 没有直接关联。**  dynamic linker 的作用是加载共享库 (`.so` 文件) 并解析库之间的依赖关系。这个头文件定义的常量可以被编译到不同的共享库中，但它本身不是一个共享库，也不参与动态链接的过程。

**如果做了逻辑推理，请给出假设输入与输出:**

这个文件主要定义常量，没有复杂的逻辑推理。可以理解为一种简单的映射关系：

* **假设输入 (宏名):** `READ_10`
* **输出 (宏值):** `0x28`

* **假设输入 (枚举值名):** `TYPE_DISK`
* **输出 (枚举值):** `0x00`

**如果涉及用户或者编程常见的使用错误，请举例说明:**

尽管这个头文件本身只定义常量，但开发者在使用这些常量时可能会犯错：

1. **使用错误的命令代码:**  例如，在应该使用 `READ_16` 的时候错误地使用了 `READ_10`，可能导致读取的数据长度或地址不正确。
2. **误解状态代码的含义:** 例如，错误地将 `NOT_READY` 解释为致命错误，而实际上可能只是设备需要一些时间来准备。
3. **在不适用的场景下使用特定的ZBC命令:** 例如，在传统非zoned设备上尝试使用 `ZBC_OUT` 或 `ZBC_IN` 相关的命令会导致错误。
4. **直接使用这些常量而忽略了操作系统提供的抽象层:**  在用户空间程序中直接构造和发送SCSI命令通常是不被允许的，且容易出错。应该使用操作系统提供的API来与存储设备交互。

**说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。**

一个典型的路径是从 Android Framework 到达使用这些 SCSI 常量的地方可能如下：

1. **Android Framework (Java/Kotlin):**  用户程序通过 Android Framework 提供的 API 进行文件操作，例如 `FileOutputStream` 的 `write()` 方法。
2. **System Services (Java):** Framework 层调用相应的系统服务，例如 StorageManagerService。
3. **Native Code (C++):**  系统服务通过 JNI 调用到底层的 Native 代码，例如 `sdcardfs` (用于管理 SD 卡和内部存储的文件系统) 或其他相关的 Native 组件。
4. **Kernel Block Device Layer:** Native 代码会与 Linux 内核的块设备层进行交互，通过系统调用 (例如 `read()` 或 `write()`) 操作底层的块设备。
5. **SCSI Driver:** 内核的块设备层会将请求传递给相应的 SCSI 设备驱动程序。SCSI 驱动程序会使用这个 `scsi_proto.h` 头文件中定义的常量来构建 SCSI 命令，并将其发送到硬件。

**Frida Hook 示例:**

假设我们想要观察当 Android 系统读取数据时，实际发送了哪个 SCSI 命令。我们可以 Hook 一个可能涉及发送 SCSI 命令的内核函数或 Native 函数。这里提供一个 Hook Native 函数的示例（Hook 内核函数需要更多的内核知识和 root 权限）：

```python
import frida
import sys

# 目标进程，可以是应用进程或者 system_server
package_name = "com.example.myapp"  # 替换为你的应用包名
process = frida.get_usb_device().attach(package_name)

# 假设我们想 Hook sdcardfs 中处理读取操作的函数，函数名需要根据实际情况确定
# 这里只是一个示例，实际函数名可能不同
script_code = """
Interceptor.attach(Module.findExportByName("libsdcardfs.so", "sdcardfs_read"), {
  onEnter: function(args) {
    console.log("sdcardfs_read called!");
    // 获取传入的参数，这些参数可能包含文件描述符等信息
    var fd = args[0].toInt32();
    var buf = args[1];
    var size = args[2].toInt32();
    console.log("  fd:", fd);
    console.log("  size:", size);

    // 注意：这里无法直接获取到 SCSI 命令，因为 SCSI 命令是在更底层的驱动程序中构建的
    // 但是我们可以在这里观察到文件读取操作的发生
  },
  onLeave: function(retval) {
    console.log("sdcardfs_read returned:", retval.toInt32());
  }
});
"""

script = process.create_script(script_code)
script.on('message', lambda message, data: print(message))
script.load()
sys.stdin.read()
```

**更深入的 Hook（需要内核知识和 root 权限）:**

要直接观察 SCSI 命令，你需要 Hook 内核中负责发送 SCSI 命令的函数。这通常涉及到找到与你的存储设备相关的 SCSI 驱动程序，并 Hook 其发送命令的函数。这需要对 Linux 内核以及 Android 的内核定制有深入的理解。

例如，你可能需要 Hook `scsi_dispatch_cmd` 或类似的函数。使用 Frida 进行内核 Hooking 需要更复杂的设置和技巧，例如使用 `Kernel.get_module_base_address` 找到内核模块的基地址，然后计算目标函数的地址。

**总结:**

`bionic/libc/kernel/android/scsi/scsi/scsi_proto.h` 是一个关键的头文件，它为 Android 系统与 SCSI 设备交互提供了基础的常量定义。虽然开发者通常不会直接使用这些常量，但它们是 Android 底层存储和设备驱动程序的核心组成部分。理解这些常量的作用有助于深入理解 Android 的存储架构和硬件交互机制。

### 提示词
```
这是目录为bionic/libc/kernel/android/scsi/scsi/scsi_proto.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _SCSI_PROTO_H_
#define _SCSI_PROTO_H_
#include <linux/types.h>
#define TEST_UNIT_READY 0x00
#define REZERO_UNIT 0x01
#define REQUEST_SENSE 0x03
#define FORMAT_UNIT 0x04
#define READ_BLOCK_LIMITS 0x05
#define REASSIGN_BLOCKS 0x07
#define INITIALIZE_ELEMENT_STATUS 0x07
#define READ_6 0x08
#define WRITE_6 0x0a
#define SEEK_6 0x0b
#define READ_REVERSE 0x0f
#define WRITE_FILEMARKS 0x10
#define SPACE 0x11
#define INQUIRY 0x12
#define RECOVER_BUFFERED_DATA 0x14
#define MODE_SELECT 0x15
#define RESERVE 0x16
#define RELEASE 0x17
#define COPY 0x18
#define ERASE 0x19
#define MODE_SENSE 0x1a
#define START_STOP 0x1b
#define RECEIVE_DIAGNOSTIC 0x1c
#define SEND_DIAGNOSTIC 0x1d
#define ALLOW_MEDIUM_REMOVAL 0x1e
#define READ_FORMAT_CAPACITIES 0x23
#define SET_WINDOW 0x24
#define READ_CAPACITY 0x25
#define READ_10 0x28
#define WRITE_10 0x2a
#define SEEK_10 0x2b
#define POSITION_TO_ELEMENT 0x2b
#define WRITE_VERIFY 0x2e
#define VERIFY 0x2f
#define SEARCH_HIGH 0x30
#define SEARCH_EQUAL 0x31
#define SEARCH_LOW 0x32
#define SET_LIMITS 0x33
#define PRE_FETCH 0x34
#define READ_POSITION 0x34
#define SYNCHRONIZE_CACHE 0x35
#define LOCK_UNLOCK_CACHE 0x36
#define READ_DEFECT_DATA 0x37
#define MEDIUM_SCAN 0x38
#define COMPARE 0x39
#define COPY_VERIFY 0x3a
#define WRITE_BUFFER 0x3b
#define READ_BUFFER 0x3c
#define UPDATE_BLOCK 0x3d
#define READ_LONG 0x3e
#define WRITE_LONG 0x3f
#define CHANGE_DEFINITION 0x40
#define WRITE_SAME 0x41
#define UNMAP 0x42
#define READ_TOC 0x43
#define READ_HEADER 0x44
#define GET_EVENT_STATUS_NOTIFICATION 0x4a
#define LOG_SELECT 0x4c
#define LOG_SENSE 0x4d
#define XDWRITEREAD_10 0x53
#define MODE_SELECT_10 0x55
#define RESERVE_10 0x56
#define RELEASE_10 0x57
#define MODE_SENSE_10 0x5a
#define PERSISTENT_RESERVE_IN 0x5e
#define PERSISTENT_RESERVE_OUT 0x5f
#define VARIABLE_LENGTH_CMD 0x7f
#define REPORT_LUNS 0xa0
#define SECURITY_PROTOCOL_IN 0xa2
#define MAINTENANCE_IN 0xa3
#define MAINTENANCE_OUT 0xa4
#define MOVE_MEDIUM 0xa5
#define EXCHANGE_MEDIUM 0xa6
#define READ_12 0xa8
#define SERVICE_ACTION_OUT_12 0xa9
#define WRITE_12 0xaa
#define READ_MEDIA_SERIAL_NUMBER 0xab
#define SERVICE_ACTION_IN_12 0xab
#define WRITE_VERIFY_12 0xae
#define VERIFY_12 0xaf
#define SEARCH_HIGH_12 0xb0
#define SEARCH_EQUAL_12 0xb1
#define SEARCH_LOW_12 0xb2
#define SECURITY_PROTOCOL_OUT 0xb5
#define READ_ELEMENT_STATUS 0xb8
#define SEND_VOLUME_TAG 0xb6
#define WRITE_LONG_2 0xea
#define EXTENDED_COPY 0x83
#define RECEIVE_COPY_RESULTS 0x84
#define ACCESS_CONTROL_IN 0x86
#define ACCESS_CONTROL_OUT 0x87
#define READ_16 0x88
#define COMPARE_AND_WRITE 0x89
#define WRITE_16 0x8a
#define READ_ATTRIBUTE 0x8c
#define WRITE_ATTRIBUTE 0x8d
#define WRITE_VERIFY_16 0x8e
#define VERIFY_16 0x8f
#define SYNCHRONIZE_CACHE_16 0x91
#define WRITE_SAME_16 0x93
#define ZBC_OUT 0x94
#define ZBC_IN 0x95
#define WRITE_ATOMIC_16 0x9c
#define SERVICE_ACTION_BIDIRECTIONAL 0x9d
#define SERVICE_ACTION_IN_16 0x9e
#define SERVICE_ACTION_OUT_16 0x9f
#define STATUS_MASK 0xfe
#define NO_SENSE 0x00
#define RECOVERED_ERROR 0x01
#define NOT_READY 0x02
#define MEDIUM_ERROR 0x03
#define HARDWARE_ERROR 0x04
#define ILLEGAL_REQUEST 0x05
#define UNIT_ATTENTION 0x06
#define DATA_PROTECT 0x07
#define BLANK_CHECK 0x08
#define VENDOR_SPECIFIC 0x09
#define COPY_ABORTED 0x0a
#define ABORTED_COMMAND 0x0b
#define VOLUME_OVERFLOW 0x0d
#define MISCOMPARE 0x0e
#define COMPLETED 0x0f
#define TYPE_DISK 0x00
#define TYPE_TAPE 0x01
#define TYPE_PRINTER 0x02
#define TYPE_PROCESSOR 0x03
#define TYPE_WORM 0x04
#define TYPE_ROM 0x05
#define TYPE_SCANNER 0x06
#define TYPE_MOD 0x07
#define TYPE_MEDIUM_CHANGER 0x08
#define TYPE_COMM 0x09
#define TYPE_RAID 0x0c
#define TYPE_ENCLOSURE 0x0d
#define TYPE_RBC 0x0e
#define TYPE_OSD 0x11
#define TYPE_ZBC 0x14
#define TYPE_WLUN 0x1e
#define TYPE_NO_LUN 0x7f
#define SCSI_ACCESS_STATE_OPTIMAL 0x00
#define SCSI_ACCESS_STATE_ACTIVE 0x01
#define SCSI_ACCESS_STATE_STANDBY 0x02
#define SCSI_ACCESS_STATE_UNAVAILABLE 0x03
#define SCSI_ACCESS_STATE_LBA 0x04
#define SCSI_ACCESS_STATE_OFFLINE 0x0e
#define SCSI_ACCESS_STATE_TRANSITIONING 0x0f
#define SCSI_ACCESS_STATE_MASK 0x0f
#define SCSI_ACCESS_STATE_PREFERRED 0x80
enum zbc_zone_reporting_options {
  ZBC_ZONE_REPORTING_OPTION_ALL = 0x00,
  ZBC_ZONE_REPORTING_OPTION_EMPTY = 0x01,
  ZBC_ZONE_REPORTING_OPTION_IMPLICIT_OPEN = 0x02,
  ZBC_ZONE_REPORTING_OPTION_EXPLICIT_OPEN = 0x03,
  ZBC_ZONE_REPORTING_OPTION_CLOSED = 0x04,
  ZBC_ZONE_REPORTING_OPTION_FULL = 0x05,
  ZBC_ZONE_REPORTING_OPTION_READONLY = 0x06,
  ZBC_ZONE_REPORTING_OPTION_OFFLINE = 0x07,
  ZBC_ZONE_REPORTING_OPTION_NEED_RESET_WP = 0x10,
  ZBC_ZONE_REPORTING_OPTION_NON_SEQWRITE = 0x11,
  ZBC_ZONE_REPORTING_OPTION_NON_WP = 0x3f,
};
#define ZBC_REPORT_ZONE_PARTIAL 0x80
enum zbc_zone_type {
  ZBC_ZONE_TYPE_CONV = 0x1,
  ZBC_ZONE_TYPE_SEQWRITE_REQ = 0x2,
  ZBC_ZONE_TYPE_SEQWRITE_PREF = 0x3,
  ZBC_ZONE_TYPE_SEQ_OR_BEFORE_REQ = 0x4,
  ZBC_ZONE_TYPE_GAP = 0x5,
};
enum zbc_zone_cond {
  ZBC_ZONE_COND_NO_WP = 0x0,
  ZBC_ZONE_COND_EMPTY = 0x1,
  ZBC_ZONE_COND_IMP_OPEN = 0x2,
  ZBC_ZONE_COND_EXP_OPEN = 0x3,
  ZBC_ZONE_COND_CLOSED = 0x4,
  ZBC_ZONE_COND_READONLY = 0xd,
  ZBC_ZONE_COND_FULL = 0xe,
  ZBC_ZONE_COND_OFFLINE = 0xf,
};
enum zbc_zone_alignment_method {
  ZBC_CONSTANT_ZONE_LENGTH = 0x1,
  ZBC_CONSTANT_ZONE_START_OFFSET = 0x8,
};
enum scsi_version_descriptor {
  SCSI_VERSION_DESCRIPTOR_FCP4 = 0x0a40,
  SCSI_VERSION_DESCRIPTOR_ISCSI = 0x0960,
  SCSI_VERSION_DESCRIPTOR_SAM5 = 0x00a0,
  SCSI_VERSION_DESCRIPTOR_SAS3 = 0x0c60,
  SCSI_VERSION_DESCRIPTOR_SBC3 = 0x04c0,
  SCSI_VERSION_DESCRIPTOR_SBP3 = 0x0980,
  SCSI_VERSION_DESCRIPTOR_SPC4 = 0x0460,
  SCSI_VERSION_DESCRIPTOR_SRP = 0x0940
};
enum scsi_support_opcode {
  SCSI_SUPPORT_NO_INFO = 0,
  SCSI_SUPPORT_NOT_SUPPORTED = 1,
  SCSI_SUPPORT_FULL = 3,
  SCSI_SUPPORT_VENDOR = 5,
};
#define SCSI_CONTROL_MASK 0
#define SCSI_GROUP_NUMBER_MASK 0
#endif
```