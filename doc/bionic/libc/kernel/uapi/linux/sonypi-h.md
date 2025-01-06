Response:
Let's break down the thought process for analyzing this header file.

**1. Initial Understanding:**

The first thing to recognize is that this is a header file (`.h`). Header files in C/C++ are primarily for *declarations*, not *implementations*. They define constants, data structures, function prototypes, etc., so that different parts of a program can agree on the same definitions.

The comment at the top is crucial: "This file is auto-generated. Modifications will be lost." This immediately tells us *not* to try to understand the *implementation* details within this file itself. The implementation logic will be elsewhere, likely in a kernel driver. The purpose of *this* file is to provide a consistent interface between user-space (Android apps/services) and the kernel driver.

The path `bionic/libc/kernel/uapi/linux/sonypi.handroid` gives us key contextual information:
* `bionic`:  This confirms it's part of Android's C library.
* `libc`: Indicates it's a low-level system interface.
* `kernel`:  Signals interaction with the Linux kernel.
* `uapi`: Stands for "User API," confirming its role as an interface for user-space programs.
* `linux`:  Indicates it's specific to the Linux kernel.
* `sonypi.handroid`: This is the specific device or subsystem this header file describes – likely related to Sony peripherals on Android.

**2. Identifying Key Components:**

Scanning the content of the header file, we can immediately identify several key elements:

* **Include:** `#include <linux/types.h>`: This brings in standard Linux type definitions (like `__u8`, `__u16`). This reinforces that this is about interacting with the kernel.
* **Macros starting with `SONYPI_EVENT_`:** These are clearly defining constants representing different events related to Sony peripherals (buttons, jog dial, lid state, etc.). This is a central part of the file's purpose.
* **Macros starting with `SONYPI_IOCG` and `SONYPI_IOCS`:**  These resemble ioctl (input/output control) commands. The `_IOR` and `_IOW` macros are standard Linux constructs for defining ioctl commands for reading and writing, respectively. The arguments ('v', number, type) suggest a specific driver (likely associated with the 'v' magic number) and data structures being exchanged.
* **Macros starting with `SONYPI_BFLAGS_`:** These look like bit flags for some battery-related status.

**3. Deducing Functionality:**

Based on the identified components, we can infer the main functionality:

* **Event Handling:** The `SONYPI_EVENT_` macros indicate that this interface allows applications to be notified about events from Sony peripherals.
* **Device Control/Status:** The `SONYPI_IOCG` and `SONYPI_IOCS` macros suggest the ability to get (get) and set (set) device parameters like brightness, battery status, Bluetooth/Wi-Fi state, fan control, and temperature.

**4. Connecting to Android:**

The key here is understanding how user-space applications interact with kernel drivers. In Android (and Linux in general), the primary mechanism for this is the `ioctl()` system call.

* **Event Handling in Android:** Android's input subsystem is the likely consumer of these events. The kernel driver would likely translate these `SONYPI_EVENT_` codes into standard Android input events (like `KeyEvent`). Android's `InputReader` and `InputDispatcher` framework components would then process these events and deliver them to the appropriate applications.
* **Device Control in Android:**  Android's hardware abstraction layer (HAL) is the bridge between the Android framework and kernel drivers. A HAL implementation for Sony devices would use the `ioctl()` system call with the `SONYPI_IOC` commands to get and set device properties. Higher-level Android APIs (like `android.provider.Settings` or specific device management APIs) would ultimately use the HAL.

**5. Addressing Specific Questions in the Prompt:**

Now, we can systematically address each point raised in the original request:

* **List Functionality:**  Summarize the inferred event handling and device control capabilities.
* **Relationship to Android:** Explain how the events map to Android's input system and how the `ioctl` calls are used through the HAL.
* **`libc` Function Explanation:** Since this header file *declares* constants, there are no `libc` *functions* implemented here. The relevant `libc` function is `ioctl()`, which is a system call wrapper. The explanation of `ioctl()` should focus on its role in sending commands and data to device drivers.
* **Dynamic Linker:** This header file doesn't directly involve the dynamic linker. The *driver* that uses these definitions might be a loadable kernel module (LKM), but the header itself is just definitions. Therefore, indicate that this aspect isn't directly relevant.
* **Logic Inference:**  Provide examples of how the event codes might be mapped to user actions.
* **Common Errors:** Focus on errors related to incorrect usage of `ioctl()` or misunderstanding the event codes.
* **Android Framework/NDK Path:** Describe the likely path from user interaction or framework calls down to the kernel driver using `ioctl()`.
* **Frida Hook:** Show how Frida could be used to intercept the `ioctl()` calls with the specific `SONYPI_IOC` commands.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe there are some helper functions in `libc` related to this. **Correction:**  Realize this is a `uapi` header, so it's strictly for definitions. The interaction happens through the standard `ioctl()` system call.
* **Initial thought:**  Focus heavily on the `libc` aspect. **Correction:** Shift focus to the kernel driver interaction and the role of the header file as a contract between user-space and the kernel.
* **Considering Dynamic Linking:** Initially, I might think about how the HAL itself is dynamically linked. **Correction:** While relevant to Android, the *specific* header file doesn't directly dictate dynamic linking. Focus on the more direct interaction with the kernel.

By following these steps, combining code analysis with understanding of Android's architecture and kernel interaction, we can arrive at a comprehensive and accurate explanation of the header file's purpose and usage.
好的，让我们详细分析一下 `bionic/libc/kernel/uapi/linux/sonypi.handroid` 这个头文件。

**功能列举**

这个头文件定义了一系列常量，这些常量主要用于：

1. **定义 Sony 外围设备的事件类型：**  它列举了各种 Sony 设备可能产生的事件，例如：
    * 滚轮操作（上下滚动、按下等）：`SONYPI_EVENT_JOGDIAL_DOWN`, `SONYPI_EVENT_JOGDIAL_UP`, 等。
    * 按键操作（按下、释放）：`SONYPI_EVENT_CAPTURE_PRESSED`, `SONYPI_EVENT_BACK_PRESSED`, 等。
    * 功能键（F1-F12，数字键等）：`SONYPI_EVENT_FNKEY_F1`, `SONYPI_EVENT_FNKEY_1`, 等。
    * 系统状态变化（蓝牙、无线开关，盖子开合）：`SONYPI_EVENT_BLUETOOTH_ON`, `SONYPI_EVENT_LID_CLOSED`, 等。
    * 其他硬件事件（电池插拔，Memory Stick 插拔等）：`SONYPI_EVENT_BATTERY_INSERT`, `SONYPI_EVENT_MEMORYSTICK_EJECT`, 等。

2. **定义用于与 Sony 设备驱动交互的 ioctl 命令：**  它定义了一些 `ioctl` (input/output control) 命令，用于读取和设置 Sony 设备的某些属性：
    * 获取/设置亮度：`SONYPI_IOCGBRT`, `SONYPI_IOCSBRT`。
    * 获取电池容量和剩余电量：`SONYPI_IOCGBAT1CAP`, `SONYPI_IOCGBAT1REM`, `SONYPI_IOCGBAT2CAP`, `SONYPI_IOCGBAT2REM` (可能支持两个电池)。
    * 获取电池标志位（如是否连接 AC 电源）：`SONYPI_IOCGBATFLAGS`。
    * 获取/设置蓝牙状态：`SONYPI_IOCGBLUE`, `SONYPI_IOCSBLUE`。
    * 获取/设置风扇状态：`SONYPI_IOCGFAN`, `SONYPI_IOCSFAN`。
    * 获取温度：`SONYPI_IOCGTEMP`。

3. **定义电池标志位：** `SONYPI_BFLAGS_B1`, `SONYPI_BFLAGS_B2`, `SONYPI_BFLAGS_AC` 定义了用于 `SONYPI_IOCGBATFLAGS` 返回值的位掩码，用于判断电池状态。

**与 Android 功能的关系及举例说明**

这个头文件是 Android 底层的一部分，它定义了与特定硬件（很可能是 Sony 制造或涉及 Sony 组件的 Android 设备）交互的接口。Android 系统需要了解这些硬件事件和属性，以便提供相应的功能。

* **输入事件处理：**  当用户操作 Sony 设备的按键或滚轮时，底层的内核驱动会捕获这些事件，并将其转换为 `SONYPI_EVENT_` 定义的事件类型。Android 的输入子系统（Input Subsystem）会读取这些事件，并将其转化为 Android 标准的输入事件（例如 `KeyEvent`），最终传递给应用程序进行处理。
    * **举例：**  当用户按下 Sony 设备的音量增加键时，内核驱动可能会生成 `SONYPI_EVENT_VOLUME_INC_PRESSED` 事件。Android 的输入系统会将其转换为 `KeyEvent.KEYCODE_VOLUME_UP` 事件，然后发送给当前正在运行的应用程序，应用程序可以根据此事件调整音量。

* **系统状态监控和控制：**  Android 系统可以使用 `ioctl` 命令来获取 Sony 设备的电池信息、蓝牙状态、温度等，并在系统 UI 中显示这些信息。用户也可以通过 Android 的设置界面来控制蓝牙、Wi-Fi 等功能，这些操作最终可能会通过 `ioctl` 命令发送给设备驱动。
    * **举例：**  Android 的电池管理服务可以使用 `SONYPI_IOCGBAT1REM` 和 `SONYPI_IOCGBAT1CAP` 来获取电池剩余电量和总容量，并在状态栏中显示电池图标和百分比。当用户在设置中关闭蓝牙时，Android 系统可能会调用底层的 HAL (Hardware Abstraction Layer) 接口，该接口最终会使用 `SONYPI_IOCSBLUE` 命令来关闭蓝牙。

**libc 函数的功能及其实现**

这个头文件本身 **没有定义或实现任何 libc 函数**。它只是定义了一些宏常量。真正与硬件交互的 `ioctl` 是一个 **系统调用**，而不是一个普通的 libc 函数。libc 中提供了对系统调用的封装函数，通常也命名为 `ioctl`。

`ioctl` 系统调用的功能是向设备驱动程序发送控制命令和/或传递数据。它的实现非常底层，涉及到内核的实现细节：

1. **用户空间调用 `ioctl`:**  用户空间程序（例如 Android 的 HAL 模块）调用 `ioctl` 函数，并传入文件描述符（指向打开的设备文件）、请求码（例如 `SONYPI_IOCSBLUE`）以及可选的参数。
2. **系统调用处理：**  内核接收到 `ioctl` 系统调用请求后，会根据文件描述符找到对应的设备驱动程序。
3. **驱动程序处理：**  设备驱动程序的 `ioctl` 函数会被调用，并接收到用户空间传递的请求码和参数。驱动程序会根据请求码执行相应的操作，例如读取硬件寄存器获取电池信息，或者向硬件寄存器写入数据来控制蓝牙开关。
4. **返回结果：**  驱动程序将操作结果返回给内核，内核再将结果返回给用户空间的 `ioctl` 函数调用。

**涉及 dynamic linker 的功能**

这个头文件本身 **与 dynamic linker 没有直接关系**。它定义的是内核与用户空间的接口，而 dynamic linker 主要负责加载和链接动态链接库（.so 文件）。

虽然如此，与这个头文件相关的设备驱动程序可能会以 **内核模块（.ko 文件）** 的形式存在，这些模块会在内核启动时或需要时动态加载。内核模块的加载和链接是由内核自身的机制管理的，而不是由用户空间的 dynamic linker (例如 Android 的 `linker64` 或 `linker`) 管理。

**如果我们将范围扩大到使用这个头文件的 Android 代码，那么 dynamic linker 就有可能参与其中。** 例如，如果一个 HAL 模块使用了这个头文件中定义的常量，那么这个 HAL 模块就是一个 `.so` 文件，它会被 Android 的 dynamic linker 加载。

**so 布局样本 (HAL 模块示例)**

假设一个名为 `vendor.sony.hardware.sonypi@1.0.so` 的 HAL 模块使用了这个头文件：

```
vendor.sony.hardware.sonypi@1.0.so:
    / (根目录)
    ├── AndroidManifest.xml
    ├── vendor
    │   └── lib64 (或 lib)
    │       └── hw
    │           └── vendor.sony.hardware.sonypi@1.0.so
    └── ... (其他可能的资源文件)
```

**链接的处理过程 (HAL 模块示例)**

1. **系统启动或服务启动：** 当 Android 系统启动或某个使用该 HAL 的服务启动时，Android 的 `hwservicemanager` 会查找并加载相应的 HAL 模块。
2. **Dynamic Linker 介入：**  `hwservicemanager` 会调用 dynamic linker (例如 `linker64`) 来加载 `vendor.sony.hardware.sonypi@1.0.so`。
3. **依赖项解析：** dynamic linker 会解析该 HAL 模块的依赖项，这可能包括 Android 的标准库 (`libc.so`) 和其他 vendor 提供的库。
4. **符号解析和重定位：** dynamic linker 会解析 HAL 模块中引用的符号，并将其与已加载的库中的符号进行链接。如果 HAL 模块中使用了 `ioctl` 系统调用，它会链接到 `libc.so` 中提供的 `ioctl` 函数封装。
5. **加载到内存：**  dynamic linker 将 HAL 模块的代码和数据加载到内存中的合适位置。
6. **执行：**  HAL 模块被加载后，`hwservicemanager` 可以通过定义好的接口（通常是 C++ 接口）与 HAL 模块进行通信。HAL 模块内部会使用 `ioctl` 系统调用和这个头文件中定义的常量与 Sony 设备的驱动程序进行交互。

**假设输入与输出 (ioctl 调用)**

假设我们想要读取第一个电池的剩余电量：

* **假设输入：**
    * 打开了 Sony 设备驱动的设备文件，例如 `/dev/sonypi`，得到文件描述符 `fd`。
    * 请求码：`SONYPI_IOCGBAT1REM`。
    * 传递给 `ioctl` 的第三个参数是一个指向 `__u16` 变量的指针，用于接收电量值。

* **输出：**
    * `ioctl(fd, SONYPI_IOCGBAT1REM, &battery_remaining)` 函数调用成功返回 0。
    * `battery_remaining` 变量中存储着第一个电池的剩余电量值（单位可能因驱动而异，通常是百分比或毫伏等）。

**用户或编程常见的使用错误**

1. **未包含头文件：**  在用户空间的程序中，如果没有包含 `sonypi.handroid` 头文件，就无法使用其中定义的常量，会导致编译错误。

2. **错误的 ioctl 请求码：**  传递给 `ioctl` 的请求码不正确，会导致驱动程序无法识别命令，通常会返回错误码。

3. **传递错误的数据结构或大小：**  对于需要传递数据的 `ioctl` 命令，如果传递的数据结构类型或大小与驱动程序期望的不符，会导致数据解析错误或程序崩溃。

4. **权限问题：**  访问设备文件（例如 `/dev/sonypi`）需要相应的权限。如果用户空间的程序没有足够的权限，`open` 或 `ioctl` 调用会失败。

5. **设备文件不存在：**  如果 Sony 设备的驱动程序没有正确加载或设备文件没有创建，尝试打开设备文件会失败。

6. **并发访问问题：**  如果多个进程或线程同时尝试访问和控制 Sony 设备，可能会导致冲突和意外行为。需要采取适当的同步机制来避免这种情况。

**Android Framework 或 NDK 如何到达这里**

1. **用户交互/应用请求：** 用户在 Android 设备上进行操作，例如调整音量、开关蓝牙，或者应用程序请求获取电池信息。
2. **Android Framework API：**  用户的操作或应用程序的请求会触发 Android Framework 中的相应 API 调用。例如，调整音量会调用 `AudioManager` 相关的 API，开关蓝牙会调用 `BluetoothManager` 相关的 API，获取电池信息会调用 `BatteryManager` 相关的 API。
3. **System Services：** Framework API 的调用通常会转发到相应的系统服务，例如 `AudioService`、`BluetoothService`、`BatteryService`。
4. **Hardware Abstraction Layer (HAL)：**  系统服务需要与底层的硬件进行交互，这通常通过 HAL 来完成。针对 Sony 设备的特定功能，可能会有专门的 HAL 模块，例如处理 Sony 特有按键或传感器数据的 HAL。
5. **HAL Implementation：** HAL 模块的实现（通常是 `.so` 文件）会使用 NDK 提供的接口（例如 `ioctl` 函数）与内核驱动程序进行通信。
6. **Kernel Driver：** HAL 模块会打开 Sony 设备驱动程序提供的设备文件（例如 `/dev/sonypi`），并使用 `ioctl` 系统调用，并传入 `sonypi.handroid` 头文件中定义的常量，来发送命令或获取状态信息。
7. **Kernel Interaction：**  内核驱动程序接收到 `ioctl` 命令后，会与 Sony 硬件进行交互，读取或设置硬件状态。
8. **返回路径：**  硬件操作的结果会沿着相反的路径返回给 HAL 模块、系统服务，最终传递回应用程序或反映在系统 UI 上。

**Frida Hook 示例**

可以使用 Frida Hook `ioctl` 系统调用来观察与 Sony 设备驱动的交互。以下是一个 Python 脚本示例：

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] Received: {}".format(message['payload']))
    else:
        print(message)

def main():
    device = frida.get_usb_device()
    pid = device.spawn(['com.android.systemui']) # Hook SystemUI 进程，可能涉及到电池、蓝牙等状态显示
    session = device.attach(pid)
    script = session.create_script("""
        const ioctlPtr = Module.findExportByName(null, "ioctl");
        if (ioctlPtr) {
            Interceptor.attach(ioctlPtr, {
                onEnter: function(args) {
                    const fd = args[0].toInt32();
                    const request = args[1].toInt32();
                    // 检查是否是与 Sony 设备相关的 ioctl 命令
                    if (request >= 0x80760000 && request <= 0x8076000c) { // 假设 'v' 的 ASCII 码是 0x76
                        console.log("[IOCTL] File Descriptor:", fd);
                        console.log("[IOCTL] Request Code:", request.toString(16));
                        // 可以进一步解析 request code，根据头文件中的定义输出对应的命令名称
                        if (request === 0x80760000) {
                            console.log("[IOCTL] Command: SONYPI_IOCGBRT");
                        } else if (request === 0xc0760000) {
                            console.log("[IOCTL] Command: SONYPI_IOCSBRT");
                        } // ... 其他命令
                    }
                },
                onLeave: function(retval) {
                    // console.log("[IOCTL] Return Value:", retval);
                }
            });
            console.log("Hooked ioctl!");
        } else {
            console.log("ioctl not found!");
        }
    """)
    script.on('message', on_message)
    script.load()
    device.resume(pid)
    input()

if __name__ == '__main__':
    main()
```

**使用方法：**

1. 确保你的 Android 设备已 root，并且安装了 Frida 服务端。
2. 在你的电脑上安装 Frida 和 Python 的 Frida 模块 (`pip install frida frida-tools`).
3. 运行这个 Python 脚本。

**预期输出：**

当你操作 Sony 设备的相关功能时，Frida 会拦截 `ioctl` 调用，并输出文件描述符和请求码。你可以根据请求码的十六进制值与 `sonypi.handroid` 头文件中的定义进行比对，了解正在执行的具体操作。例如，当你调整屏幕亮度时，你可能会看到类似以下的输出：

```
[*] Hooked ioctl!
[IOCTL] File Descriptor: 10
[IOCTL] Request Code: c0760000
[IOCTL] Command: SONYPI_IOCSBRT
```

这个示例只是一个基本的 Hook，你可以根据需要进一步解析 `ioctl` 的参数，以获取更详细的信息。

希望以上详细的解释能够帮助你理解 `bionic/libc/kernel/uapi/linux/sonypi.handroid` 这个头文件的作用以及它在 Android 系统中的应用。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/sonypi.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI_SONYPI_H_
#define _UAPI_SONYPI_H_
#include <linux/types.h>
#define SONYPI_EVENT_IGNORE 0
#define SONYPI_EVENT_JOGDIAL_DOWN 1
#define SONYPI_EVENT_JOGDIAL_UP 2
#define SONYPI_EVENT_JOGDIAL_DOWN_PRESSED 3
#define SONYPI_EVENT_JOGDIAL_UP_PRESSED 4
#define SONYPI_EVENT_JOGDIAL_PRESSED 5
#define SONYPI_EVENT_JOGDIAL_RELEASED 6
#define SONYPI_EVENT_CAPTURE_PRESSED 7
#define SONYPI_EVENT_CAPTURE_RELEASED 8
#define SONYPI_EVENT_CAPTURE_PARTIALPRESSED 9
#define SONYPI_EVENT_CAPTURE_PARTIALRELEASED 10
#define SONYPI_EVENT_FNKEY_ESC 11
#define SONYPI_EVENT_FNKEY_F1 12
#define SONYPI_EVENT_FNKEY_F2 13
#define SONYPI_EVENT_FNKEY_F3 14
#define SONYPI_EVENT_FNKEY_F4 15
#define SONYPI_EVENT_FNKEY_F5 16
#define SONYPI_EVENT_FNKEY_F6 17
#define SONYPI_EVENT_FNKEY_F7 18
#define SONYPI_EVENT_FNKEY_F8 19
#define SONYPI_EVENT_FNKEY_F9 20
#define SONYPI_EVENT_FNKEY_F10 21
#define SONYPI_EVENT_FNKEY_F11 22
#define SONYPI_EVENT_FNKEY_F12 23
#define SONYPI_EVENT_FNKEY_1 24
#define SONYPI_EVENT_FNKEY_2 25
#define SONYPI_EVENT_FNKEY_D 26
#define SONYPI_EVENT_FNKEY_E 27
#define SONYPI_EVENT_FNKEY_F 28
#define SONYPI_EVENT_FNKEY_S 29
#define SONYPI_EVENT_FNKEY_B 30
#define SONYPI_EVENT_BLUETOOTH_PRESSED 31
#define SONYPI_EVENT_PKEY_P1 32
#define SONYPI_EVENT_PKEY_P2 33
#define SONYPI_EVENT_PKEY_P3 34
#define SONYPI_EVENT_BACK_PRESSED 35
#define SONYPI_EVENT_LID_CLOSED 36
#define SONYPI_EVENT_LID_OPENED 37
#define SONYPI_EVENT_BLUETOOTH_ON 38
#define SONYPI_EVENT_BLUETOOTH_OFF 39
#define SONYPI_EVENT_HELP_PRESSED 40
#define SONYPI_EVENT_FNKEY_ONLY 41
#define SONYPI_EVENT_JOGDIAL_FAST_DOWN 42
#define SONYPI_EVENT_JOGDIAL_FAST_UP 43
#define SONYPI_EVENT_JOGDIAL_FAST_DOWN_PRESSED 44
#define SONYPI_EVENT_JOGDIAL_FAST_UP_PRESSED 45
#define SONYPI_EVENT_JOGDIAL_VFAST_DOWN 46
#define SONYPI_EVENT_JOGDIAL_VFAST_UP 47
#define SONYPI_EVENT_JOGDIAL_VFAST_DOWN_PRESSED 48
#define SONYPI_EVENT_JOGDIAL_VFAST_UP_PRESSED 49
#define SONYPI_EVENT_ZOOM_PRESSED 50
#define SONYPI_EVENT_THUMBPHRASE_PRESSED 51
#define SONYPI_EVENT_MEYE_FACE 52
#define SONYPI_EVENT_MEYE_OPPOSITE 53
#define SONYPI_EVENT_MEMORYSTICK_INSERT 54
#define SONYPI_EVENT_MEMORYSTICK_EJECT 55
#define SONYPI_EVENT_ANYBUTTON_RELEASED 56
#define SONYPI_EVENT_BATTERY_INSERT 57
#define SONYPI_EVENT_BATTERY_REMOVE 58
#define SONYPI_EVENT_FNKEY_RELEASED 59
#define SONYPI_EVENT_WIRELESS_ON 60
#define SONYPI_EVENT_WIRELESS_OFF 61
#define SONYPI_EVENT_ZOOM_IN_PRESSED 62
#define SONYPI_EVENT_ZOOM_OUT_PRESSED 63
#define SONYPI_EVENT_CD_EJECT_PRESSED 64
#define SONYPI_EVENT_MODEKEY_PRESSED 65
#define SONYPI_EVENT_PKEY_P4 66
#define SONYPI_EVENT_PKEY_P5 67
#define SONYPI_EVENT_SETTINGKEY_PRESSED 68
#define SONYPI_EVENT_VOLUME_INC_PRESSED 69
#define SONYPI_EVENT_VOLUME_DEC_PRESSED 70
#define SONYPI_EVENT_BRIGHTNESS_PRESSED 71
#define SONYPI_EVENT_MEDIA_PRESSED 72
#define SONYPI_EVENT_VENDOR_PRESSED 73
#define SONYPI_IOCGBRT _IOR('v', 0, __u8)
#define SONYPI_IOCSBRT _IOW('v', 0, __u8)
#define SONYPI_IOCGBAT1CAP _IOR('v', 2, __u16)
#define SONYPI_IOCGBAT1REM _IOR('v', 3, __u16)
#define SONYPI_IOCGBAT2CAP _IOR('v', 4, __u16)
#define SONYPI_IOCGBAT2REM _IOR('v', 5, __u16)
#define SONYPI_BFLAGS_B1 0x01
#define SONYPI_BFLAGS_B2 0x02
#define SONYPI_BFLAGS_AC 0x04
#define SONYPI_IOCGBATFLAGS _IOR('v', 7, __u8)
#define SONYPI_IOCGBLUE _IOR('v', 8, __u8)
#define SONYPI_IOCSBLUE _IOW('v', 9, __u8)
#define SONYPI_IOCGFAN _IOR('v', 10, __u8)
#define SONYPI_IOCSFAN _IOW('v', 11, __u8)
#define SONYPI_IOCGTEMP _IOR('v', 12, __u8)
#endif

"""

```