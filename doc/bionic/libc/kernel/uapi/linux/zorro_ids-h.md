Response:
Let's break down the thought process for answering this complex question about the `zorro_ids.handroid` file.

**1. Understanding the Core Purpose:**

The first and most crucial step is to recognize what the file *is*. The initial description tells us it's a header file (`.handroid`) located within the Android Bionic library's kernel UAPI (User Application Programming Interface). The name "zorro_ids" strongly suggests it deals with identifying hardware components on a Zorro bus. The auto-generated comment confirms this and points towards the Bionic repository for more context.

**2. Initial Feature Extraction:**

Based on the file contents, the most obvious features are the `#define` macros. These macros define constants. Specifically, they define manufacturer IDs (starting with `ZORRO_MANUF_`) and product IDs (starting with `ZORRO_PROD_`). The `ZORRO_ID` macro is also clearly defining how these IDs are constructed.

**3. Connecting to Android:**

The next step is to bridge the gap between these low-level hardware IDs and the Android ecosystem. The key insight here is that Android, while running on various hardware, still needs a way to interact with and identify peripherals. Although the Zorro bus itself isn't directly a part of modern Android hardware, the *concept* of identifying hardware components is very relevant.

* **Analogy:**  Think of it like PCI IDs or USB Vendor/Product IDs used in modern systems. This file serves a similar purpose, albeit for older hardware.

* **Potential Android Relevance (Though Indirect):** While Zorro isn't used in current Android devices, this file exists *within* the Android source code. This implies a historical connection or a purpose within an emulator or a specific niche use case (like running older Amiga software on Android).

**4. Analyzing `libc` Functions:**

The request asks about `libc` functions. This file *doesn't contain any `libc` functions*. It only has preprocessor macros. It's important to explicitly state this and clarify that the file's purpose is to *define constants* that other `libc` functions or kernel modules might *use*. Avoid making assumptions or inventing connections where none exist.

**5. Analyzing Dynamic Linker Functionality:**

Similarly, this file doesn't directly involve the dynamic linker. Dynamic linkers deal with linking shared libraries at runtime. This file defines constants for hardware identification. Again, clearly state the absence of dynamic linker functionality.

**6. Logical Deduction and Examples:**

While the file itself doesn't perform complex logic, the *usage* of these IDs involves logic. Imagine a hypothetical scenario where an Android emulator is trying to identify a virtual Zorro card.

* **Hypothetical Input:** The emulator detects a Zorro card with manufacturer ID `0x0201` and product ID `0x01`.

* **Hypothetical Output:**  The code using these macros would compare these values against the defined constants (e.g., `ZORRO_MANUF_COMMODORE_BRAUNSCHWEIG` and `ZORRO_PROD_CBM_A2088_A2286`) and determine that it's a "CBM A2088/A2286" card.

**7. Common User/Programming Errors:**

Since this is a header file, common errors would involve:

* **Incorrect Inclusion:** Forgetting to include the header file.
* **Typos:**  Making mistakes when typing the macro names.
* **Assuming Dynamic Behavior:**  Mistakenly thinking these are variables that can change at runtime instead of constants.
* **Misinterpreting the Scope:**  Assuming these IDs are relevant to modern Android hardware.

**8. Android Framework/NDK Path and Frida Hooking:**

This is the trickiest part. Since the direct relevance to modern Android is limited, the explanation needs to be framed accordingly.

* **Historical/Emulator Context:** The most plausible path involves an emulator that's designed to run software targeting Amiga hardware. The emulator's code (likely C/C++) would include this header file.

* **NDK Relevance (Limited):** While the NDK allows developers to write native code, it's unlikely a typical Android app would directly interact with Zorro bus IDs. However, if someone were building a low-level hardware interface or an emulator within an NDK app, then this file could be relevant.

* **Frida Hooking (Hypothetical):**  The Frida example needs to target a hypothetical scenario. Hooking into a function within an emulator's code that *uses* these Zorro IDs would be the way to go. The example function (`check_zorro_card`) demonstrates how the macros might be used in practice.

**9. Structuring the Answer:**

Finally, organizing the answer clearly is essential. Using headings, bullet points, and code blocks makes the information easier to digest. Start with the core functionality, then address the connections to Android (and their limitations), and then tackle the more technical aspects like `libc`, dynamic linking, and finally, the Android framework/NDK and Frida.

**Self-Correction/Refinement During the Process:**

* **Initial Thought:** "This file is part of `libc`, so it must contain `libc` functions."
* **Correction:** Upon closer inspection, it's just a header file with macros. Adjust the answer to reflect this.

* **Initial Thought:** "Zorro bus is totally irrelevant to Android."
* **Refinement:**  While *directly* irrelevant, acknowledge the historical context and the possibility of its use in emulators running on Android.

* **Initial Thought:** "Explain how the dynamic linker works with this file."
* **Correction:** This file has no direct connection to the dynamic linker. Explain this clearly and avoid inventing artificial links.

By following this structured thought process, focusing on accurate interpretation, and clearly communicating the connections (and lack thereof) to Android components, a comprehensive and helpful answer can be constructed.
好的，让我们详细分析一下 `bionic/libc/kernel/uapi/linux/zorro_ids.handroid` 这个文件。

**文件功能：**

这个 `zorro_ids.handroid` 文件定义了一系列宏定义，用于标识连接到 Zorro II/III 总线的各种硬件设备。Zorro 总线是早期 Commodore Amiga 计算机中使用的一种扩展总线。

具体来说，这个文件定义了：

1. **制造商 ID (Manufacturer ID):**  `ZORRO_MANUF_*` 开头的宏定义，例如 `ZORRO_MANUF_PACIFIC_PERIPHERALS`，代表不同的硬件制造商。
2. **产品 ID (Product ID):** `ZORRO_PROD_*` 开头的宏定义，例如 `ZORRO_PROD_PACIFIC_PERIPHERALS_SE_2000_A500`，代表特定制造商生产的特定硬件产品。
3. **`ZORRO_ID` 宏:**  这是一个辅助宏，用于将制造商 ID 和产品 ID 组合成一个唯一的设备标识符。其定义可能类似于：
   ```c
   #define ZORRO_ID(manufacturer, product_high, product_low) \
       ((manufacturer << 16) | (product_high << 8) | product_low)
   ```
   这个宏将制造商 ID 放在高位，产品 ID 的高字节放在中间，低字节放在低位。

**与 Android 功能的关系：**

**直接关系：几乎没有。**  现代 Android 设备和系统架构（基于 ARM 或 x86 架构）不再使用 Zorro 总线。Zorro 总线是上世纪 80 年代和 90 年代初的技术。

**间接关系：可能存在于模拟器或特定的历史用途中。**

* **模拟器:**  如果 Android 系统上运行着 Amiga 模拟器（例如 UAE4ARM），那么这个文件可能会被模拟器使用。模拟器需要识别模拟的硬件设备，以便正确地运行 Amiga 操作系统和应用程序。在这种情况下，`zorro_ids.handroid` 文件提供了模拟器识别各种虚拟 Zorro 扩展卡所需的信息。

* **历史遗留/测试:**  理论上，这些 ID 可能在 Android 早期开发或测试阶段被使用，以支持某些特定的硬件平台或用于兼容性测试。但这种可能性很小。

**举例说明（模拟器场景）：**

假设一个 Amiga 模拟器启动时，它会扫描虚拟的 Zorro 总线以查找连接的设备。模拟器可能会读取设备的制造商和产品 ID。然后，模拟器会使用 `zorro_ids.handroid` 中定义的宏来判断识别到的设备是什么。

例如，如果模拟器检测到一个设备的 ID 匹配 `ZORRO_PROD_CBM_A2090A`，它可以通过比较得知这是一个 Commodore A2090A 硬盘控制器。模拟器随后会加载并初始化与该控制器相关的模拟驱动程序。

**详细解释 libc 函数的功能实现：**

**这个文件中没有 libc 函数。**  `zorro_ids.handroid` 是一个头文件，它只包含预处理器宏定义。它本身不包含任何可执行的代码或函数实现。

libc 函数通常是 C 标准库提供的函数，例如 `printf`、`malloc`、`memcpy` 等。这些函数在 `zorro_ids.handroid` 中没有定义。

**对于涉及 dynamic linker 的功能：**

**这个文件与 dynamic linker 没有直接关系。** 动态链接器（在 Android 中通常是 `linker64` 或 `linker`）负责在程序运行时加载和链接共享库 (`.so` 文件)。

`zorro_ids.handroid` 定义的是硬件 ID，这些 ID 在编译时就已经确定了，不需要在运行时动态链接。

**so 布局样本以及链接的处理过程：**

由于 `zorro_ids.handroid` 与动态链接器无关，所以这里不需要提供 `.so` 布局样本或链接处理过程的说明。

**逻辑推理、假设输入与输出：**

虽然这个文件本身没有复杂的逻辑，但使用这些 ID 的代码会涉及到逻辑判断。

**假设输入：**  一个模拟器程序尝试读取 Zorro 总线上一个设备的 ID，读取到的值为 `manufacturer = 0x0201`, `product_high = 0x01`, `product_low = 0x00`。

**逻辑推理：**  程序可能会使用如下的代码来判断设备类型：

```c
#include "zorro_ids.handroid"

unsigned short manufacturer = 0x0201;
unsigned char product_high = 0x01;
unsigned char product_low = 0x00;
unsigned int device_id = (manufacturer << 16) | (product_high << 8) | product_low;

if (device_id == ZORRO_PROD_CBM_A2088_A2286) {
    printf("检测到 Commodore A2088/A2286 卡\n");
} else if (device_id == ZORRO_PROD_CBM_A2286) {
    printf("检测到 Commodore A2286 卡\n");
}
// ... 其他设备的判断
```

**输出：**  根据上面的假设输入，程序会输出 "检测到 Commodore A2088/A2286 卡"。

**涉及用户或者编程常见的使用错误：**

1. **头文件包含错误:**  忘记在需要使用这些宏定义的代码文件中包含 `zorro_ids.handroid` 头文件。这会导致编译器找不到这些宏定义而报错。

   ```c
   // 错误示例，缺少头文件包含
   unsigned int id = ZORRO_PROD_CBM_A2090A; // 编译错误：ZORRO_PROD_CBM_A2090A 未定义
   ```

2. **宏定义名称拼写错误:**  在代码中错误地拼写了宏定义的名称。

   ```c
   #include "zorro_ids.handroid"

   unsigned int id = ZORRO_PRDO_CBM_A2090A; // 编译错误：ZORRO_PRDO_CBM_A2090A 未定义
   ```

3. **误用宏定义的值:**  错误地将宏定义的值当作变量来修改。宏定义是常量，不能被赋值。

   ```c
   #include "zorro_ids.handroid"

   ZORRO_PROD_CBM_A2090A = 0x12345678; // 编译错误：表达式不可修改的左值
   ```

4. **假设这些 ID 在现代 Android 硬件中有效:**  尝试在与 Zorro 总线无关的 Android 代码中使用这些 ID，会导致逻辑错误或程序行为不符合预期。

**说明 Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**可能性较低，路径复杂。**  直接从 Android framework 或 NDK 到达 `zorro_ids.handroid` 的路径非常罕见，因为现代 Android 系统不直接处理 Zorro 总线硬件。

**最可能的场景是通过模拟器。**  如果一个 Android 应用程序（可能是使用 NDK 开发的）运行一个 Amiga 模拟器，那么模拟器的代码（通常是 C/C++）会包含 `zorro_ids.handroid`。

**Frida Hook 示例（针对模拟器）：**

假设我们想 hook 模拟器中识别 Zorro 设备的函数，以查看它如何使用 `zorro_ids.handroid` 中的宏。

首先，我们需要找到模拟器中负责识别 Zorro 设备的函数。这需要一些逆向工程的知识。假设我们找到了一个名为 `identify_zorro_device` 的函数，它接受制造商 ID 和产品 ID 作为参数。

**Frida Hook 脚本：**

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

def main():
    if len(sys.argv) != 2:
        print("Usage: python zorro_hook.py <process name or PID>")
        sys.exit(1)

    target = sys.argv[1]

    try:
        session = frida.attach(target)
    except frida.ProcessNotFoundError:
        print(f"Process '{target}' not found.")
        sys.exit(1)

    script_code = """
    Interceptor.attach(Module.findExportByName(null, "identify_zorro_device"), {
        onEnter: function(args) {
            var manufacturer = args[0].toInt();
            var product_high = args[1].toInt();
            var product_low = args[2].toInt();
            var device_id = (manufacturer << 16) | (product_high << 8) | product_low;

            send({
                "type": "zorro_device",
                "manufacturer": manufacturer,
                "product_high": product_high,
                "product_low": product_low,
                "device_id": device_id
            });

            // 可以根据 zorro_ids.handroid 中的宏定义来判断设备类型
            if (device_id === 0x02010100) { // ZORRO_PROD_CBM_A2088_A2286
                send("Detected CBM A2088/A2286");
            } else if (device_id === 0x02010200) { // ZORRO_PROD_CBM_A2286
                send("Detected CBM A2286");
            }
        },
        onLeave: function(retval) {
            // console.log("Return value:", retval);
        }
    });
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    print("[*] Waiting for messages...")
    sys.stdin.read()
    session.detach()

if __name__ == '__main__':
    main()
```

**使用方法：**

1. 将上面的 Python 代码保存为 `zorro_hook.py`。
2. 找到正在运行的 Amiga 模拟器进程的名称或 PID。
3. 运行 Frida 脚本： `python zorro_hook.py <模拟器进程名称或PID>`

**工作原理：**

* Frida 会附加到目标模拟器进程。
* `Interceptor.attach` 会 hook `identify_zorro_device` 函数。
* 当 `identify_zorro_device` 被调用时，`onEnter` 函数会被执行。
* `onEnter` 函数会读取函数的参数（制造商 ID 和产品 ID）。
* 它会将这些 ID 组合成一个 `device_id`。
* 它会使用 `send` 函数将设备信息发送到 Frida 控制台。
* 它还会根据 `zorro_ids.handroid` 中的宏定义来判断检测到的设备类型并输出信息。

**注意：**

* 你需要将 `"identify_zorro_device"` 替换为实际的模拟器函数名。
* 这个示例假设 `identify_zorro_device` 函数的参数顺序是：制造商 ID，产品 ID 高字节，产品 ID 低字节。你需要根据实际情况调整。
* 需要在你的 Android 设备或模拟器上安装 Frida Server。

总而言之，`zorro_ids.handroid` 文件本身的功能是定义用于识别旧式 Zorro 总线设备的 ID。它与现代 Android 系统关系不大，但在特定的情境下，例如 Amiga 模拟器，它仍然扮演着重要的角色。 理解其功能需要一定的历史背景知识。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/zorro_ids.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#define ZORRO_MANUF_PACIFIC_PERIPHERALS 0x00D3
#define ZORRO_PROD_PACIFIC_PERIPHERALS_SE_2000_A500 ZORRO_ID(PACIFIC_PERIPHERALS, 0x00, 0)
#define ZORRO_PROD_PACIFIC_PERIPHERALS_SCSI ZORRO_ID(PACIFIC_PERIPHERALS, 0x0A, 0)
#define ZORRO_MANUF_MACROSYSTEMS_USA_2 0x0100
#define ZORRO_PROD_MACROSYSTEMS_WARP_ENGINE ZORRO_ID(MACROSYSTEMS_USA_2, 0x13, 0)
#define ZORRO_MANUF_KUPKE_1 0x00DD
#define ZORRO_PROD_KUPKE_GOLEM_RAM_BOX_2MB ZORRO_ID(KUPKE_1, 0x00, 0)
#define ZORRO_MANUF_MEMPHIS 0x0100
#define ZORRO_PROD_MEMPHIS_STORMBRINGER ZORRO_ID(MEMPHIS, 0x00, 0)
#define ZORRO_MANUF_3_STATE 0x0200
#define ZORRO_PROD_3_STATE_MEGAMIX_2000 ZORRO_ID(3_STATE, 0x02, 0)
#define ZORRO_MANUF_COMMODORE_BRAUNSCHWEIG 0x0201
#define ZORRO_PROD_CBM_A2088_A2286 ZORRO_ID(COMMODORE_BRAUNSCHWEIG, 0x01, 0)
#define ZORRO_PROD_CBM_A2286 ZORRO_ID(COMMODORE_BRAUNSCHWEIG, 0x02, 0)
#define ZORRO_PROD_CBM_A4091_1 ZORRO_ID(COMMODORE_BRAUNSCHWEIG, 0x54, 0)
#define ZORRO_PROD_CBM_A2386SX_1 ZORRO_ID(COMMODORE_BRAUNSCHWEIG, 0x67, 0)
#define ZORRO_MANUF_COMMODORE_WEST_CHESTER_1 0x0202
#define ZORRO_PROD_CBM_A2090A ZORRO_ID(COMMODORE_WEST_CHESTER_1, 0x01, 0)
#define ZORRO_PROD_CBM_A590_A2091_1 ZORRO_ID(COMMODORE_WEST_CHESTER_1, 0x02, 0)
#define ZORRO_PROD_CBM_A590_A2091_2 ZORRO_ID(COMMODORE_WEST_CHESTER_1, 0x03, 0)
#define ZORRO_PROD_CBM_A2090B ZORRO_ID(COMMODORE_WEST_CHESTER_1, 0x04, 0)
#define ZORRO_PROD_CBM_A2060 ZORRO_ID(COMMODORE_WEST_CHESTER_1, 0x09, 0)
#define ZORRO_PROD_CBM_A590_A2052_A2058_A2091 ZORRO_ID(COMMODORE_WEST_CHESTER_1, 0x0A, 0)
#define ZORRO_PROD_CBM_A560_RAM ZORRO_ID(COMMODORE_WEST_CHESTER_1, 0x20, 0)
#define ZORRO_PROD_CBM_A2232_PROTOTYPE ZORRO_ID(COMMODORE_WEST_CHESTER_1, 0x45, 0)
#define ZORRO_PROD_CBM_A2232 ZORRO_ID(COMMODORE_WEST_CHESTER_1, 0x46, 0)
#define ZORRO_PROD_CBM_A2620 ZORRO_ID(COMMODORE_WEST_CHESTER_1, 0x50, 0)
#define ZORRO_PROD_CBM_A2630 ZORRO_ID(COMMODORE_WEST_CHESTER_1, 0x51, 0)
#define ZORRO_PROD_CBM_A4091_2 ZORRO_ID(COMMODORE_WEST_CHESTER_1, 0x54, 0)
#define ZORRO_PROD_CBM_A2065_1 ZORRO_ID(COMMODORE_WEST_CHESTER_1, 0x5A, 0)
#define ZORRO_PROD_CBM_ROMULATOR ZORRO_ID(COMMODORE_WEST_CHESTER_1, 0x60, 0)
#define ZORRO_PROD_CBM_A3000_TEST_FIXTURE ZORRO_ID(COMMODORE_WEST_CHESTER_1, 0x61, 0)
#define ZORRO_PROD_CBM_A2386SX_2 ZORRO_ID(COMMODORE_WEST_CHESTER_1, 0x67, 0)
#define ZORRO_PROD_CBM_A2065_2 ZORRO_ID(COMMODORE_WEST_CHESTER_1, 0x70, 0)
#define ZORRO_MANUF_COMMODORE_WEST_CHESTER_2 0x0203
#define ZORRO_PROD_CBM_A2090A_CM ZORRO_ID(COMMODORE_WEST_CHESTER_2, 0x03, 0)
#define ZORRO_MANUF_PROGRESSIVE_PERIPHERALS_AND_SYSTEMS_2 0x02F4
#define ZORRO_PROD_PPS_EXP8000 ZORRO_ID(PROGRESSIVE_PERIPHERALS_AND_SYSTEMS_2, 0x02, 0)
#define ZORRO_MANUF_KOLFF_COMPUTER_SUPPLIES 0x02FF
#define ZORRO_PROD_KCS_POWER_PC_BOARD ZORRO_ID(KOLFF_COMPUTER_SUPPLIES, 0x00, 0)
#define ZORRO_MANUF_CARDCO_1 0x03EC
#define ZORRO_PROD_CARDCO_KRONOS_2000_1 ZORRO_ID(CARDCO_1, 0x04, 0)
#define ZORRO_PROD_CARDCO_A1000_1 ZORRO_ID(CARDCO_1, 0x0C, 0)
#define ZORRO_PROD_CARDCO_ESCORT ZORRO_ID(CARDCO_1, 0x0E, 0)
#define ZORRO_PROD_CARDCO_A2410 ZORRO_ID(CARDCO_1, 0xF5, 0)
#define ZORRO_MANUF_A_SQUARED 0x03ED
#define ZORRO_PROD_A_SQUARED_LIVE_2000 ZORRO_ID(A_SQUARED, 0x01, 0)
#define ZORRO_MANUF_COMSPEC_COMMUNICATIONS 0x03EE
#define ZORRO_PROD_COMSPEC_COMMUNICATIONS_AX2000 ZORRO_ID(COMSPEC_COMMUNICATIONS, 0x01, 0)
#define ZORRO_MANUF_ANAKIN_RESEARCH 0x03F1
#define ZORRO_PROD_ANAKIN_RESEARCH_EASYL ZORRO_ID(ANAKIN_RESEARCH, 0x01, 0)
#define ZORRO_MANUF_MICROBOTICS 0x03F2
#define ZORRO_PROD_MICROBOTICS_STARBOARD_II ZORRO_ID(MICROBOTICS, 0x00, 0)
#define ZORRO_PROD_MICROBOTICS_STARDRIVE ZORRO_ID(MICROBOTICS, 0x02, 0)
#define ZORRO_PROD_MICROBOTICS_8_UP_A ZORRO_ID(MICROBOTICS, 0x03, 0)
#define ZORRO_PROD_MICROBOTICS_8_UP_Z ZORRO_ID(MICROBOTICS, 0x04, 0)
#define ZORRO_PROD_MICROBOTICS_DELTA_RAM ZORRO_ID(MICROBOTICS, 0x20, 0)
#define ZORRO_PROD_MICROBOTICS_8_STAR_RAM ZORRO_ID(MICROBOTICS, 0x40, 0)
#define ZORRO_PROD_MICROBOTICS_8_STAR ZORRO_ID(MICROBOTICS, 0x41, 0)
#define ZORRO_PROD_MICROBOTICS_VXL_RAM_32 ZORRO_ID(MICROBOTICS, 0x44, 0)
#define ZORRO_PROD_MICROBOTICS_VXL_68030 ZORRO_ID(MICROBOTICS, 0x45, 0)
#define ZORRO_PROD_MICROBOTICS_DELTA ZORRO_ID(MICROBOTICS, 0x60, 0)
#define ZORRO_PROD_MICROBOTICS_MBX_1200_1200Z_RAM ZORRO_ID(MICROBOTICS, 0x81, 0)
#define ZORRO_PROD_MICROBOTICS_HARDFRAME_2000_1 ZORRO_ID(MICROBOTICS, 0x96, 0)
#define ZORRO_PROD_MICROBOTICS_HARDFRAME_2000_2 ZORRO_ID(MICROBOTICS, 0x9E, 0)
#define ZORRO_PROD_MICROBOTICS_MBX_1200_1200Z ZORRO_ID(MICROBOTICS, 0xC1, 0)
#define ZORRO_MANUF_ACCESS_ASSOCIATES_ALEGRA 0x03F4
#define ZORRO_MANUF_EXPANSION_TECHNOLOGIES 0x03F6
#define ZORRO_MANUF_ASDG 0x03FF
#define ZORRO_PROD_ASDG_MEMORY_1 ZORRO_ID(ASDG, 0x01, 0)
#define ZORRO_PROD_ASDG_MEMORY_2 ZORRO_ID(ASDG, 0x02, 0)
#define ZORRO_PROD_ASDG_EB920_LAN_ROVER ZORRO_ID(ASDG, 0xFE, 0)
#define ZORRO_PROD_ASDG_GPIB_DUALIEEE488_TWIN_X ZORRO_ID(ASDG, 0xFF, 0)
#define ZORRO_MANUF_IMTRONICS_1 0x0404
#define ZORRO_PROD_IMTRONICS_HURRICANE_2800_1 ZORRO_ID(IMTRONICS_1, 0x39, 0)
#define ZORRO_PROD_IMTRONICS_HURRICANE_2800_2 ZORRO_ID(IMTRONICS_1, 0x57, 0)
#define ZORRO_MANUF_CBM_UNIVERSITY_OF_LOWELL 0x0406
#define ZORRO_PROD_CBM_A2410 ZORRO_ID(CBM_UNIVERSITY_OF_LOWELL, 0x00, 0)
#define ZORRO_MANUF_AMERISTAR 0x041D
#define ZORRO_PROD_AMERISTAR_A2065 ZORRO_ID(AMERISTAR, 0x01, 0)
#define ZORRO_PROD_AMERISTAR_A560 ZORRO_ID(AMERISTAR, 0x09, 0)
#define ZORRO_PROD_AMERISTAR_A4066 ZORRO_ID(AMERISTAR, 0x0A, 0)
#define ZORRO_MANUF_SUPRA 0x0420
#define ZORRO_PROD_SUPRA_SUPRADRIVE_4x4 ZORRO_ID(SUPRA, 0x01, 0)
#define ZORRO_PROD_SUPRA_1000_RAM ZORRO_ID(SUPRA, 0x02, 0)
#define ZORRO_PROD_SUPRA_2000_DMA ZORRO_ID(SUPRA, 0x03, 0)
#define ZORRO_PROD_SUPRA_500 ZORRO_ID(SUPRA, 0x05, 0)
#define ZORRO_PROD_SUPRA_500_SCSI ZORRO_ID(SUPRA, 0x08, 0)
#define ZORRO_PROD_SUPRA_500XP_2000_RAM ZORRO_ID(SUPRA, 0x09, 0)
#define ZORRO_PROD_SUPRA_500RX_2000_RAM ZORRO_ID(SUPRA, 0x0A, 0)
#define ZORRO_PROD_SUPRA_2400ZI ZORRO_ID(SUPRA, 0x0B, 0)
#define ZORRO_PROD_SUPRA_500XP_SUPRADRIVE_WORDSYNC ZORRO_ID(SUPRA, 0x0C, 0)
#define ZORRO_PROD_SUPRA_SUPRADRIVE_WORDSYNC_II ZORRO_ID(SUPRA, 0x0D, 0)
#define ZORRO_PROD_SUPRA_2400ZIPLUS ZORRO_ID(SUPRA, 0x10, 0)
#define ZORRO_MANUF_COMPUTER_SYSTEMS_ASSOCIATES 0x0422
#define ZORRO_PROD_CSA_MAGNUM ZORRO_ID(COMPUTER_SYSTEMS_ASSOCIATES, 0x11, 0)
#define ZORRO_PROD_CSA_12_GAUGE ZORRO_ID(COMPUTER_SYSTEMS_ASSOCIATES, 0x15, 0)
#define ZORRO_MANUF_MARC_MICHAEL_GROTH 0x0439
#define ZORRO_MANUF_M_TECH 0x0502
#define ZORRO_PROD_MTEC_AT500_1 ZORRO_ID(M_TECH, 0x03, 0)
#define ZORRO_MANUF_GREAT_VALLEY_PRODUCTS_1 0x06E1
#define ZORRO_PROD_GVP_IMPACT_SERIES_I ZORRO_ID(GREAT_VALLEY_PRODUCTS_1, 0x08, 0)
#define ZORRO_MANUF_BYTEBOX 0x07DA
#define ZORRO_PROD_BYTEBOX_A500 ZORRO_ID(BYTEBOX, 0x00, 0)
#define ZORRO_MANUF_DKB_POWER_COMPUTING 0x07DC
#define ZORRO_PROD_DKB_POWER_COMPUTING_SECUREKEY ZORRO_ID(DKB_POWER_COMPUTING, 0x09, 0)
#define ZORRO_PROD_DKB_POWER_COMPUTING_DKM_3128 ZORRO_ID(DKB_POWER_COMPUTING, 0x0E, 0)
#define ZORRO_PROD_DKB_POWER_COMPUTING_RAPID_FIRE ZORRO_ID(DKB_POWER_COMPUTING, 0x0F, 0)
#define ZORRO_PROD_DKB_POWER_COMPUTING_DKM_1202 ZORRO_ID(DKB_POWER_COMPUTING, 0x10, 0)
#define ZORRO_PROD_DKB_POWER_COMPUTING_COBRA_VIPER_II_68EC030 ZORRO_ID(DKB_POWER_COMPUTING, 0x12, 0)
#define ZORRO_PROD_DKB_POWER_COMPUTING_WILDFIRE_060_1 ZORRO_ID(DKB_POWER_COMPUTING, 0x17, 0)
#define ZORRO_PROD_DKB_POWER_COMPUTING_WILDFIRE_060_2 ZORRO_ID(DKB_POWER_COMPUTING, 0xFF, 0)
#define ZORRO_MANUF_GREAT_VALLEY_PRODUCTS_2 0x07E1
#define ZORRO_PROD_GVP_IMPACT_SERIES_I_4K ZORRO_ID(GREAT_VALLEY_PRODUCTS_2, 0x01, 0)
#define ZORRO_PROD_GVP_IMPACT_SERIES_I_16K_2 ZORRO_ID(GREAT_VALLEY_PRODUCTS_2, 0x02, 0)
#define ZORRO_PROD_GVP_IMPACT_SERIES_I_16K_3 ZORRO_ID(GREAT_VALLEY_PRODUCTS_2, 0x03, 0)
#define ZORRO_PROD_GVP_IMPACT_3001_IDE_1 ZORRO_ID(GREAT_VALLEY_PRODUCTS_2, 0x08, 0)
#define ZORRO_PROD_GVP_IMPACT_3001_RAM ZORRO_ID(GREAT_VALLEY_PRODUCTS_2, 0x09, 0)
#define ZORRO_PROD_GVP_IMPACT_SERIES_II_RAM_1 ZORRO_ID(GREAT_VALLEY_PRODUCTS_2, 0x0A, 0)
#define ZORRO_PROD_GVP_EPC_BASE ZORRO_ID(GREAT_VALLEY_PRODUCTS_2, 0x0B, 0)
#define ZORRO_PROD_GVP_GFORCE_040_1 ZORRO_ID(GREAT_VALLEY_PRODUCTS_2, 0x0B, 0x20)
#define ZORRO_PROD_GVP_GFORCE_040_SCSI_1 ZORRO_ID(GREAT_VALLEY_PRODUCTS_2, 0x0B, 0x30)
#define ZORRO_PROD_GVP_A1291 ZORRO_ID(GREAT_VALLEY_PRODUCTS_2, 0x0B, 0x40)
#define ZORRO_PROD_GVP_COMBO_030_R4 ZORRO_ID(GREAT_VALLEY_PRODUCTS_2, 0x0B, 0x60)
#define ZORRO_PROD_GVP_COMBO_030_R4_SCSI ZORRO_ID(GREAT_VALLEY_PRODUCTS_2, 0x0B, 0x70)
#define ZORRO_PROD_GVP_PHONEPAK ZORRO_ID(GREAT_VALLEY_PRODUCTS_2, 0x0B, 0x78)
#define ZORRO_PROD_GVP_IO_EXTENDER ZORRO_ID(GREAT_VALLEY_PRODUCTS_2, 0x0B, 0x98)
#define ZORRO_PROD_GVP_GFORCE_030 ZORRO_ID(GREAT_VALLEY_PRODUCTS_2, 0x0B, 0xa0)
#define ZORRO_PROD_GVP_GFORCE_030_SCSI ZORRO_ID(GREAT_VALLEY_PRODUCTS_2, 0x0B, 0xb0)
#define ZORRO_PROD_GVP_A530 ZORRO_ID(GREAT_VALLEY_PRODUCTS_2, 0x0B, 0xc0)
#define ZORRO_PROD_GVP_A530_SCSI ZORRO_ID(GREAT_VALLEY_PRODUCTS_2, 0x0B, 0xd0)
#define ZORRO_PROD_GVP_COMBO_030_R3 ZORRO_ID(GREAT_VALLEY_PRODUCTS_2, 0x0B, 0xe0)
#define ZORRO_PROD_GVP_COMBO_030_R3_SCSI ZORRO_ID(GREAT_VALLEY_PRODUCTS_2, 0x0B, 0xf0)
#define ZORRO_PROD_GVP_SERIES_II ZORRO_ID(GREAT_VALLEY_PRODUCTS_2, 0x0B, 0xf8)
#define ZORRO_PROD_GVP_IMPACT_3001_IDE_2 ZORRO_ID(GREAT_VALLEY_PRODUCTS_2, 0x0D, 0)
#define ZORRO_PROD_GVP_GFORCE_040_060 ZORRO_ID(GREAT_VALLEY_PRODUCTS_2, 0x16, 0)
#define ZORRO_PROD_GVP_IMPACT_VISION_24 ZORRO_ID(GREAT_VALLEY_PRODUCTS_2, 0x20, 0)
#define ZORRO_PROD_GVP_GFORCE_040_2 ZORRO_ID(GREAT_VALLEY_PRODUCTS_2, 0xFF, 0)
#define ZORRO_MANUF_CALIFORNIA_ACCESS_SYNERGY 0x07E5
#define ZORRO_PROD_CALIFORNIA_ACCESS_SYNERGY_MALIBU ZORRO_ID(CALIFORNIA_ACCESS_SYNERGY, 0x01, 0)
#define ZORRO_MANUF_XETEC 0x07E6
#define ZORRO_PROD_XETEC_FASTCARD ZORRO_ID(XETEC, 0x01, 0)
#define ZORRO_PROD_XETEC_FASTCARD_RAM ZORRO_ID(XETEC, 0x02, 0)
#define ZORRO_PROD_XETEC_FASTCARD_PLUS ZORRO_ID(XETEC, 0x03, 0)
#define ZORRO_MANUF_PROGRESSIVE_PERIPHERALS_AND_SYSTEMS 0x07EA
#define ZORRO_PROD_PPS_MERCURY ZORRO_ID(PROGRESSIVE_PERIPHERALS_AND_SYSTEMS, 0x00, 0)
#define ZORRO_PROD_PPS_A3000_68040 ZORRO_ID(PROGRESSIVE_PERIPHERALS_AND_SYSTEMS, 0x01, 0)
#define ZORRO_PROD_PPS_A2000_68040 ZORRO_ID(PROGRESSIVE_PERIPHERALS_AND_SYSTEMS, 0x69, 0)
#define ZORRO_PROD_PPS_ZEUS ZORRO_ID(PROGRESSIVE_PERIPHERALS_AND_SYSTEMS, 0x96, 0)
#define ZORRO_PROD_PPS_A500_68040 ZORRO_ID(PROGRESSIVE_PERIPHERALS_AND_SYSTEMS, 0xBB, 0)
#define ZORRO_MANUF_XEBEC 0x07EC
#define ZORRO_MANUF_SPIRIT_TECHNOLOGY 0x07F2
#define ZORRO_PROD_SPIRIT_TECHNOLOGY_INSIDER_IN1000 ZORRO_ID(SPIRIT_TECHNOLOGY, 0x01, 0)
#define ZORRO_PROD_SPIRIT_TECHNOLOGY_INSIDER_IN500 ZORRO_ID(SPIRIT_TECHNOLOGY, 0x02, 0)
#define ZORRO_PROD_SPIRIT_TECHNOLOGY_SIN500 ZORRO_ID(SPIRIT_TECHNOLOGY, 0x03, 0)
#define ZORRO_PROD_SPIRIT_TECHNOLOGY_HDA_506 ZORRO_ID(SPIRIT_TECHNOLOGY, 0x04, 0)
#define ZORRO_PROD_SPIRIT_TECHNOLOGY_AX_S ZORRO_ID(SPIRIT_TECHNOLOGY, 0x05, 0)
#define ZORRO_PROD_SPIRIT_TECHNOLOGY_OCTABYTE ZORRO_ID(SPIRIT_TECHNOLOGY, 0x06, 0)
#define ZORRO_PROD_SPIRIT_TECHNOLOGY_INMATE ZORRO_ID(SPIRIT_TECHNOLOGY, 0x08, 0)
#define ZORRO_MANUF_SPIRIT_TECHNOLOGY_2 0x07F3
#define ZORRO_MANUF_BSC_ALFADATA_1 0x07FE
#define ZORRO_PROD_BSC_ALF_3_1 ZORRO_ID(BSC_ALFADATA_1, 0x03, 0)
#define ZORRO_MANUF_BSC_ALFADATA_2 0x0801
#define ZORRO_PROD_BSC_ALF_2_1 ZORRO_ID(BSC_ALFADATA_2, 0x01, 0)
#define ZORRO_PROD_BSC_ALF_2_2 ZORRO_ID(BSC_ALFADATA_2, 0x02, 0)
#define ZORRO_PROD_BSC_ALF_3_2 ZORRO_ID(BSC_ALFADATA_2, 0x03, 0)
#define ZORRO_MANUF_CARDCO_2 0x0802
#define ZORRO_PROD_CARDCO_KRONOS_2000_2 ZORRO_ID(CARDCO_2, 0x04, 0)
#define ZORRO_PROD_CARDCO_A1000_2 ZORRO_ID(CARDCO_2, 0x0C, 0)
#define ZORRO_MANUF_JOCHHEIM 0x0804
#define ZORRO_PROD_JOCHHEIM_RAM ZORRO_ID(JOCHHEIM, 0x01, 0)
#define ZORRO_MANUF_CHECKPOINT_TECHNOLOGIES 0x0807
#define ZORRO_PROD_CHECKPOINT_TECHNOLOGIES_SERIAL_SOLUTION ZORRO_ID(CHECKPOINT_TECHNOLOGIES, 0x00, 0)
#define ZORRO_MANUF_EDOTRONIK 0x0810
#define ZORRO_PROD_EDOTRONIK_IEEE_488 ZORRO_ID(EDOTRONIK, 0x01, 0)
#define ZORRO_PROD_EDOTRONIK_8032 ZORRO_ID(EDOTRONIK, 0x02, 0)
#define ZORRO_PROD_EDOTRONIK_MULTISERIAL ZORRO_ID(EDOTRONIK, 0x03, 0)
#define ZORRO_PROD_EDOTRONIK_VIDEODIGITIZER ZORRO_ID(EDOTRONIK, 0x04, 0)
#define ZORRO_PROD_EDOTRONIK_PARALLEL_IO ZORRO_ID(EDOTRONIK, 0x05, 0)
#define ZORRO_PROD_EDOTRONIK_PIC_PROTOYPING ZORRO_ID(EDOTRONIK, 0x06, 0)
#define ZORRO_PROD_EDOTRONIK_ADC ZORRO_ID(EDOTRONIK, 0x07, 0)
#define ZORRO_PROD_EDOTRONIK_VME ZORRO_ID(EDOTRONIK, 0x08, 0)
#define ZORRO_PROD_EDOTRONIK_DSP96000 ZORRO_ID(EDOTRONIK, 0x09, 0)
#define ZORRO_MANUF_NES_INC 0x0813
#define ZORRO_PROD_NES_INC_RAM ZORRO_ID(NES_INC, 0x00, 0)
#define ZORRO_MANUF_ICD 0x0817
#define ZORRO_PROD_ICD_ADVANTAGE_2000_SCSI ZORRO_ID(ICD, 0x01, 0)
#define ZORRO_PROD_ICD_ADVANTAGE_IDE ZORRO_ID(ICD, 0x03, 0)
#define ZORRO_PROD_ICD_ADVANTAGE_2080_RAM ZORRO_ID(ICD, 0x04, 0)
#define ZORRO_MANUF_KUPKE_2 0x0819
#define ZORRO_PROD_KUPKE_OMTI ZORRO_ID(KUPKE_2, 0x01, 0)
#define ZORRO_PROD_KUPKE_SCSI_II ZORRO_ID(KUPKE_2, 0x02, 0)
#define ZORRO_PROD_KUPKE_GOLEM_BOX ZORRO_ID(KUPKE_2, 0x03, 0)
#define ZORRO_PROD_KUPKE_030_882 ZORRO_ID(KUPKE_2, 0x04, 0)
#define ZORRO_PROD_KUPKE_SCSI_AT ZORRO_ID(KUPKE_2, 0x05, 0)
#define ZORRO_MANUF_GREAT_VALLEY_PRODUCTS_3 0x081D
#define ZORRO_PROD_GVP_A2000_RAM8 ZORRO_ID(GREAT_VALLEY_PRODUCTS_3, 0x09, 0)
#define ZORRO_PROD_GVP_IMPACT_SERIES_II_RAM_2 ZORRO_ID(GREAT_VALLEY_PRODUCTS_3, 0x0A, 0)
#define ZORRO_MANUF_INTERWORKS_NETWORK 0x081E
#define ZORRO_MANUF_HARDITAL_SYNTHESIS 0x0820
#define ZORRO_PROD_HARDITAL_SYNTHESIS_TQM_68030_68882 ZORRO_ID(HARDITAL_SYNTHESIS, 0x14, 0)
#define ZORRO_MANUF_APPLIED_ENGINEERING 0x0828
#define ZORRO_PROD_APPLIED_ENGINEERING_DL2000 ZORRO_ID(APPLIED_ENGINEERING, 0x10, 0)
#define ZORRO_PROD_APPLIED_ENGINEERING_RAM_WORKS ZORRO_ID(APPLIED_ENGINEERING, 0xE0, 0)
#define ZORRO_MANUF_BSC_ALFADATA_3 0x082C
#define ZORRO_PROD_BSC_OKTAGON_2008 ZORRO_ID(BSC_ALFADATA_3, 0x05, 0)
#define ZORRO_PROD_BSC_TANDEM_AT_2008_508 ZORRO_ID(BSC_ALFADATA_3, 0x06, 0)
#define ZORRO_PROD_BSC_ALFA_RAM_1200 ZORRO_ID(BSC_ALFADATA_3, 0x07, 0)
#define ZORRO_PROD_BSC_OKTAGON_2008_RAM ZORRO_ID(BSC_ALFADATA_3, 0x08, 0)
#define ZORRO_PROD_BSC_MULTIFACE_I ZORRO_ID(BSC_ALFADATA_3, 0x10, 0)
#define ZORRO_PROD_BSC_MULTIFACE_II ZORRO_ID(BSC_ALFADATA_3, 0x11, 0)
#define ZORRO_PROD_BSC_MULTIFACE_III ZORRO_ID(BSC_ALFADATA_3, 0x12, 0)
#define ZORRO_PROD_BSC_FRAMEMASTER_II ZORRO_ID(BSC_ALFADATA_3, 0x20, 0)
#define ZORRO_PROD_BSC_GRAFFITI_RAM ZORRO_ID(BSC_ALFADATA_3, 0x21, 0)
#define ZORRO_PROD_BSC_GRAFFITI_REG ZORRO_ID(BSC_ALFADATA_3, 0x22, 0)
#define ZORRO_PROD_BSC_ISDN_MASTERCARD ZORRO_ID(BSC_ALFADATA_3, 0x40, 0)
#define ZORRO_PROD_BSC_ISDN_MASTERCARD_II ZORRO_ID(BSC_ALFADATA_3, 0x41, 0)
#define ZORRO_MANUF_PHOENIX 0x0835
#define ZORRO_PROD_PHOENIX_ST506 ZORRO_ID(PHOENIX, 0x21, 0)
#define ZORRO_PROD_PHOENIX_SCSI ZORRO_ID(PHOENIX, 0x22, 0)
#define ZORRO_PROD_PHOENIX_RAM ZORRO_ID(PHOENIX, 0xBE, 0)
#define ZORRO_MANUF_ADVANCED_STORAGE_SYSTEMS 0x0836
#define ZORRO_PROD_ADVANCED_STORAGE_SYSTEMS_NEXUS ZORRO_ID(ADVANCED_STORAGE_SYSTEMS, 0x01, 0)
#define ZORRO_PROD_ADVANCED_STORAGE_SYSTEMS_NEXUS_RAM ZORRO_ID(ADVANCED_STORAGE_SYSTEMS, 0x08, 0)
#define ZORRO_MANUF_IMPULSE 0x0838
#define ZORRO_PROD_IMPULSE_FIRECRACKER_24 ZORRO_ID(IMPULSE, 0x00, 0)
#define ZORRO_MANUF_IVS 0x0840
#define ZORRO_PROD_IVS_GRANDSLAM_PIC_2 ZORRO_ID(IVS, 0x02, 0)
#define ZORRO_PROD_IVS_GRANDSLAM_PIC_1 ZORRO_ID(IVS, 0x04, 0)
#define ZORRO_PROD_IVS_OVERDRIVE ZORRO_ID(IVS, 0x10, 0)
#define ZORRO_PROD_IVS_TRUMPCARD_CLASSIC ZORRO_ID(IVS, 0x30, 0)
#define ZORRO_PROD_IVS_TRUMPCARD_PRO_GRANDSLAM ZORRO_ID(IVS, 0x34, 0)
#define ZORRO_PROD_IVS_META_4 ZORRO_ID(IVS, 0x40, 0)
#define ZORRO_PROD_IVS_WAVETOOLS ZORRO_ID(IVS, 0xBF, 0)
#define ZORRO_PROD_IVS_VECTOR_1 ZORRO_ID(IVS, 0xF3, 0)
#define ZORRO_PROD_IVS_VECTOR_2 ZORRO_ID(IVS, 0xF4, 0)
#define ZORRO_MANUF_VECTOR_1 0x0841
#define ZORRO_PROD_VECTOR_CONNECTION_1 ZORRO_ID(VECTOR_1, 0xE3, 0)
#define ZORRO_MANUF_XPERT_PRODEV 0x0845
#define ZORRO_PROD_XPERT_PRODEV_VISIONA_RAM ZORRO_ID(XPERT_PRODEV, 0x01, 0)
#define ZORRO_PROD_XPERT_PRODEV_VISIONA_REG ZORRO_ID(XPERT_PRODEV, 0x02, 0)
#define ZORRO_PROD_XPERT_PRODEV_MERLIN_RAM ZORRO_ID(XPERT_PRODEV, 0x03, 0)
#define ZORRO_PROD_XPERT_PRODEV_MERLIN_REG_1 ZORRO_ID(XPERT_PRODEV, 0x04, 0)
#define ZORRO_PROD_XPERT_PRODEV_MERLIN_REG_2 ZORRO_ID(XPERT_PRODEV, 0xC9, 0)
#define ZORRO_MANUF_HYDRA_SYSTEMS 0x0849
#define ZORRO_PROD_HYDRA_SYSTEMS_AMIGANET ZORRO_ID(HYDRA_SYSTEMS, 0x01, 0)
#define ZORRO_MANUF_SUNRIZE_INDUSTRIES 0x084F
#define ZORRO_PROD_SUNRIZE_INDUSTRIES_AD1012 ZORRO_ID(SUNRIZE_INDUSTRIES, 0x01, 0)
#define ZORRO_PROD_SUNRIZE_INDUSTRIES_AD516 ZORRO_ID(SUNRIZE_INDUSTRIES, 0x02, 0)
#define ZORRO_PROD_SUNRIZE_INDUSTRIES_DD512 ZORRO_ID(SUNRIZE_INDUSTRIES, 0x03, 0)
#define ZORRO_MANUF_TRICERATOPS 0x0850
#define ZORRO_PROD_TRICERATOPS_MULTI_IO ZORRO_ID(TRICERATOPS, 0x01, 0)
#define ZORRO_MANUF_APPLIED_MAGIC 0x0851
#define ZORRO_PROD_APPLIED_MAGIC_DMI_RESOLVER ZORRO_ID(APPLIED_MAGIC, 0x01, 0)
#define ZORRO_PROD_APPLIED_MAGIC_DIGITAL_BROADCASTER ZORRO_ID(APPLIED_MAGIC, 0x06, 0)
#define ZORRO_MANUF_GFX_BASE 0x085E
#define ZORRO_PROD_GFX_BASE_GDA_1_VRAM ZORRO_ID(GFX_BASE, 0x00, 0)
#define ZORRO_PROD_GFX_BASE_GDA_1 ZORRO_ID(GFX_BASE, 0x01, 0)
#define ZORRO_MANUF_ROCTEC 0x0860
#define ZORRO_PROD_ROCTEC_RH_800C ZORRO_ID(ROCTEC, 0x01, 0)
#define ZORRO_PROD_ROCTEC_RH_800C_RAM ZORRO_ID(ROCTEC, 0x01, 0)
#define ZORRO_MANUF_KATO 0x0861
#define ZORRO_PROD_KATO_MELODY ZORRO_ID(KATO, 0x80, 0)
#define ZORRO_MANUF_HELFRICH_1 0x0861
#define ZORRO_PROD_HELFRICH_RAINBOW_II ZORRO_ID(HELFRICH_1, 0x20, 0)
#define ZORRO_PROD_HELFRICH_RAINBOW_III ZORRO_ID(HELFRICH_1, 0x21, 0)
#define ZORRO_MANUF_ATLANTIS 0x0862
#define ZORRO_MANUF_PROTAR 0x0864
#define ZORRO_MANUF_ACS 0x0865
#define ZORRO_MANUF_SOFTWARE_RESULTS_ENTERPRISES 0x0866
#define ZORRO_PROD_SOFTWARE_RESULTS_ENTERPRISES_GOLDEN_GATE_2_BUS_PLUS ZORRO_ID(SOFTWARE_RESULTS_ENTERPRISES, 0x01, 0)
#define ZORRO_MANUF_MASOBOSHI 0x086D
#define ZORRO_PROD_MASOBOSHI_MASTER_CARD_SC201 ZORRO_ID(MASOBOSHI, 0x03, 0)
#define ZORRO_PROD_MASOBOSHI_MASTER_CARD_MC702 ZORRO_ID(MASOBOSHI, 0x04, 0)
#define ZORRO_PROD_MASOBOSHI_MVD_819 ZORRO_ID(MASOBOSHI, 0x07, 0)
#define ZORRO_MANUF_MAINHATTAN_DATA 0x086F
#define ZORRO_PROD_MAINHATTAN_DATA_IDE ZORRO_ID(MAINHATTAN_DATA, 0x01, 0)
#define ZORRO_MANUF_VILLAGE_TRONIC 0x0877
#define ZORRO_PROD_VILLAGE_TRONIC_DOMINO_RAM ZORRO_ID(VILLAGE_TRONIC, 0x01, 0)
#define ZORRO_PROD_VILLAGE_TRONIC_DOMINO_REG ZORRO_ID(VILLAGE_TRONIC, 0x02, 0)
#define ZORRO_PROD_VILLAGE_TRONIC_DOMINO_16M_PROTOTYPE ZORRO_ID(VILLAGE_TRONIC, 0x03, 0)
#define ZORRO_PROD_VILLAGE_TRONIC_PICASSO_II_II_PLUS_RAM ZORRO_ID(VILLAGE_TRONIC, 0x0B, 0)
#define ZORRO_PROD_VILLAGE_TRONIC_PICASSO_II_II_PLUS_REG ZORRO_ID(VILLAGE_TRONIC, 0x0C, 0)
#define ZORRO_PROD_VILLAGE_TRONIC_PICASSO_II_II_PLUS_SEGMENTED_MODE ZORRO_ID(VILLAGE_TRONIC, 0x0D, 0)
#define ZORRO_PROD_VILLAGE_TRONIC_PICASSO_IV_Z2_RAM1 ZORRO_ID(VILLAGE_TRONIC, 0x15, 0)
#define ZORRO_PROD_VILLAGE_TRONIC_PICASSO_IV_Z2_RAM2 ZORRO_ID(VILLAGE_TRONIC, 0x16, 0)
#define ZORRO_PROD_VILLAGE_TRONIC_PICASSO_IV_Z2_REG ZORRO_ID(VILLAGE_TRONIC, 0x17, 0)
#define ZORRO_PROD_VILLAGE_TRONIC_PICASSO_IV_Z3 ZORRO_ID(VILLAGE_TRONIC, 0x18, 0)
#define ZORRO_PROD_VILLAGE_TRONIC_ARIADNE ZORRO_ID(VILLAGE_TRONIC, 0xC9, 0)
#define ZORRO_PROD_VILLAGE_TRONIC_ARIADNE2 ZORRO_ID(VILLAGE_TRONIC, 0xCA, 0)
#define ZORRO_MANUF_UTILITIES_UNLIMITED 0x087B
#define ZORRO_PROD_UTILITIES_UNLIMITED_EMPLANT_DELUXE ZORRO_ID(UTILITIES_UNLIMITED, 0x15, 0)
#define ZORRO_PROD_UTILITIES_UNLIMITED_EMPLANT_DELUXE2 ZORRO_ID(UTILITIES_UNLIMITED, 0x20, 0)
#define ZORRO_MANUF_AMITRIX 0x0880
#define ZORRO_PROD_AMITRIX_MULTI_IO ZORRO_ID(AMITRIX, 0x01, 0)
#define ZORRO_PROD_AMITRIX_CD_RAM ZORRO_ID(AMITRIX, 0x02, 0)
#define ZORRO_MANUF_ARMAX 0x0885
#define ZORRO_PROD_ARMAX_OMNIBUS ZORRO_ID(ARMAX, 0x00, 0)
#define ZORRO_MANUF_ZEUS 0x088D
#define ZORRO_PROD_ZEUS_SPIDER ZORRO_ID(ZEUS, 0x04, 0)
#define ZORRO_MANUF_NEWTEK 0x088F
#define ZORRO_PROD_NEWTEK_VIDEOTOASTER ZORRO_ID(NEWTEK, 0x00, 0)
#define ZORRO_MANUF_M_TECH_GERMANY 0x0890
#define ZORRO_PROD_MTEC_AT500_2 ZORRO_ID(M_TECH_GERMANY, 0x01, 0)
#define ZORRO_PROD_MTEC_68030 ZORRO_ID(M_TECH_GERMANY, 0x03, 0)
#define ZORRO_PROD_MTEC_68020I ZORRO_ID(M_TECH_GERMANY, 0x06, 0)
#define ZORRO_PROD_MTEC_A1200_T68030_RTC ZORRO_ID(M_TECH_GERMANY, 0x20, 0)
#define ZORRO_PROD_MTEC_VIPER_MK_V_E_MATRIX_530 ZORRO_ID(M_TECH_GERMANY, 0x21, 0)
#define ZORRO_PROD_MTEC_8_MB_RAM ZORRO_ID(M_TECH_GERMANY, 0x22, 0)
#define ZORRO_PROD_MTEC_VIPER_MK_V_E_MATRIX_530_SCSI_IDE ZORRO_ID(M_TECH_GERMANY, 0x24, 0)
#define ZORRO_MANUF_GREAT_VALLEY_PRODUCTS_4 0x0891
#define ZORRO_PROD_GVP_EGS_28_24_SPECTRUM_RAM ZORRO_ID(GREAT_VALLEY_PRODUCTS_4, 0x01, 0)
#define ZORRO_PROD_GVP_EGS_28_24_SPECTRUM_REG ZORRO_ID(GREAT_VALLEY_PRODUCTS_4, 0x02, 0)
#define ZORRO_MANUF_APOLLO_1 0x0892
#define ZORRO_PROD_APOLLO_A1200 ZORRO_ID(APOLLO_1, 0x01, 0)
#define ZORRO_MANUF_HELFRICH_2 0x0893
#define ZORRO_PROD_HELFRICH_PICCOLO_RAM ZORRO_ID(HELFRICH_2, 0x05, 0)
#define ZORRO_PROD_HELFRICH_PICCOLO_REG ZORRO_ID(HELFRICH_2, 0x06, 0)
#define ZORRO_PROD_HELFRICH_PEGGY_PLUS_MPEG ZORRO_ID(HELFRICH_2, 0x07, 0)
#define ZORRO_PROD_HELFRICH_VIDEOCRUNCHER ZORRO_ID(HELFRICH_2, 0x08, 0)
#define ZORRO_PROD_HELFRICH_SD64_RAM ZORRO_ID(HELFRICH_2, 0x0A, 0)
#define ZORRO_PROD_HELFRICH_SD64_REG ZORRO_ID(HELFRICH_2, 0x0B, 0)
#define ZORRO_MANUF_MACROSYSTEMS_USA 0x089B
#define ZORRO_PROD_MACROSYSTEMS_WARP_ENGINE_40xx ZORRO_ID(MACROSYSTEMS_USA, 0x13, 0)
#define ZORRO_MANUF_ELBOX_COMPUTER 0x089E
#define ZORRO_PROD_ELBOX_COMPUTER_1200_4 ZORRO_ID(ELBOX_COMPUTER, 0x06, 0)
#define ZORRO_MANUF_HARMS_PROFESSIONAL 0x0A00
#define ZORRO_PROD_HARMS_PROFESSIONAL_030_PLUS ZORRO_ID(HARMS_PROFESSIONAL, 0x10, 0)
#define ZORRO_PROD_HARMS_PROFESSIONAL_3500 ZORRO_ID(HARMS_PROFESSIONAL, 0xD0, 0)
#define ZORRO_MANUF_MICRONIK 0x0A50
#define ZORRO_PROD_MICRONIK_RCA_120 ZORRO_ID(MICRONIK, 0x0A, 0)
#define ZORRO_MANUF_MICRONIK2 0x0F0F
#define ZORRO_PROD_MICRONIK2_Z3I ZORRO_ID(MICRONIK2, 0x01, 0)
#define ZORRO_MANUF_MEGAMICRO 0x1000
#define ZORRO_PROD_MEGAMICRO_SCRAM_500 ZORRO_ID(MEGAMICRO, 0x03, 0)
#define ZORRO_PROD_MEGAMICRO_SCRAM_500_RAM ZORRO_ID(MEGAMICRO, 0x04, 0)
#define ZORRO_MANUF_IMTRONICS_2 0x1028
#define ZORRO_PROD_IMTRONICS_HURRICANE_2800_3 ZORRO_ID(IMTRONICS_2, 0x39, 0)
#define ZORRO_PROD_IMTRONICS_HURRICANE_2800_4 ZORRO_ID(IMTRONICS_2, 0x57, 0)
#define ZORRO_MANUF_INDIVIDUAL_COMPUTERS 0x1212
#define ZORRO_PROD_INDIVIDUAL_COMPUTERS_BUDDHA ZORRO_ID(INDIVIDUAL_COMPUTERS, 0x00, 0)
#define ZORRO_PROD_INDIVIDUAL_COMPUTERS_X_SURF ZORRO_ID(INDIVIDUAL_COMPUTERS, 0x17, 0)
#define ZORRO_PROD_INDIVIDUAL_COMPUTERS_CATWEASEL ZORRO_ID(INDIVIDUAL_COMPUTERS, 0x2A, 0)
#define ZORRO_MANUF_KUPKE_3 0x1248
#define ZORRO_PROD_KUPKE_GOLEM_HD_3000 ZORRO_ID(KUPKE_3, 0x01, 0)
#define ZORRO_MANUF_ITH 0x1388
#define ZORRO_PROD_ITH_ISDN_MASTER_II ZORRO_ID(ITH, 0x01, 0)
#define ZORRO_MANUF_VMC 0x1389
#define ZORRO_PROD_VMC_ISDN_BLASTER_Z2 ZORRO_ID(VMC, 0x01, 0)
#define ZORRO_PROD_VMC_HYPERCOM_4 ZORRO_ID(VMC, 0x02, 0)
#define ZORRO_MANUF_CSLAB 0x1400
#define ZORRO_PROD_CSLAB_WARP_1260 ZORRO_ID(CSLAB, 0x65, 0)
#define ZORRO_MANUF_INFORMATION 0x157C
#define ZORRO_PROD_INFORMATION_ISDN_ENGINE_I ZORRO_ID(INFORMATION, 0x64, 0)
#define ZORRO_MANUF_VORTEX 0x2017
#define ZORRO_PROD_VORTEX_GOLDEN_GATE_80386SX ZORRO_ID(VORTEX, 0x07, 0)
#define ZORRO_PROD_VORTEX_GOLDEN_GATE_RAM ZORRO_ID(VORTEX, 0x08, 0)
#define ZORRO_PROD_VORTEX_GOLDEN_GATE_80486 ZORRO_ID(VORTEX, 0x09, 0)
#define ZORRO_MANUF_EXPANSION_SYSTEMS 0x2062
#define ZORRO_PROD_EXPANSION_SYSTEMS_DATAFLYER_4000SX ZORRO_ID(EXPANSION_SYSTEMS, 0x01, 0)
#define ZORRO_PROD_EXPANSION_SYSTEMS_DATAFLYER_4000SX_RAM ZORRO_ID(EXPANSION_SYSTEMS, 0x02, 0)
#define ZORRO_MANUF_READYSOFT 0x2100
#define ZORRO_PROD_READYSOFT_AMAX_II_IV ZORRO_ID(READYSOFT, 0x01, 0)
#define ZORRO_MANUF_PHASE5 0x2140
#define ZORRO_PROD_PHASE5_BLIZZARD_RAM ZORRO_ID(PHASE5, 0x01, 0)
#define ZORRO_PROD_PHASE5_BLIZZARD ZORRO_ID(PHASE5, 0x02, 0)
#define ZORRO_PROD_PHASE5_BLIZZARD_1220_IV ZORRO_ID(PHASE5, 0x06, 0)
#define ZORRO_PROD_PHASE5_FASTLANE_Z3_RAM ZORRO_ID(PHASE5, 0x0A, 0)
#define ZORRO_PROD_PHASE5_BLIZZARD_1230_II_FASTLANE_Z3_CYBERSCSI_CYBERSTORM060 ZORRO_ID(PHASE5, 0x0B, 0)
#define ZORRO_PROD_PHASE5_BLIZZARD_1220_CYBERSTORM ZORRO_ID(PHASE5, 0x0C, 0)
#define ZORRO_PROD_PHASE5_BLIZZARD_1230 ZORRO_ID(PHASE5, 0x0D, 0)
#define ZORRO_PROD_PHASE5_BLIZZARD_1230_IV_1260 ZORRO_ID(PHASE5, 0x11, 0)
#define ZORRO_PROD_PHASE5_BLIZZARD_2060 ZORRO_ID(PHASE5, 0x18, 0)
#define ZORRO_PROD_PHASE5_CYBERSTORM_MK_II ZORRO_ID(PHASE5, 0x19, 0)
#define ZORRO_PROD_PHASE5_CYBERVISION64 ZORRO_ID(PHASE5, 0x22, 0)
#define ZORRO_PROD_PHASE5_CYBERVISION64_3D_PROTOTYPE ZORRO_ID(PHASE5, 0x32, 0)
#define ZORRO_PROD_PHASE5_CYBERVISION64_3D ZORRO_ID(PHASE5, 0x43, 0)
#define ZORRO_PROD_PHASE5_CYBERSTORM_MK_III ZORRO_ID(PHASE5, 0x64, 0)
#define ZORRO_PROD_PHASE5_BLIZZARD_603E_PLUS ZORRO_ID(PHASE5, 0x6e, 0)
#define ZORRO_MANUF_DPS 0x2169
#define ZORRO_PROD_DPS_PERSONAL_ANIMATION_RECORDER ZORRO_ID(DPS, 0x01, 0)
#define ZORRO_MANUF_APOLLO_2 0x2200
#define ZORRO_PROD_APOLLO_A620_68020_1 ZORRO_ID(APOLLO_2, 0x00, 0)
#define ZORRO_PROD_APOLLO_A620_68020_2 ZORRO_ID(APOLLO_2, 0x01, 0)
#define ZORRO_MANUF_APOLLO_3 0x2222
#define ZORRO_PROD_APOLLO_AT_APOLLO ZORRO_ID(APOLLO_3, 0x22, 0)
#define ZORRO_PROD_APOLLO_1230_1240_1260_2030_4040_4060 ZORRO_ID(APOLLO_3, 0x23, 0)
#define ZORRO_MANUF_PETSOFF_LP 0x38A5
#define ZORRO_PROD_PETSOFF_LP_DELFINA ZORRO_ID(PETSOFF_LP, 0x00, 0)
#define ZORRO_PROD_PETSOFF_LP_DELFINA_LITE ZORRO_ID(PETSOFF_LP, 0x01, 0)
#define ZORRO_MANUF_UWE_GERLACH 0x3FF7
#define ZORRO_PROD_UWE_GERLACH_RAM_ROM ZORRO_ID(UWE_GERLACH, 0xd4, 0)
#define ZORRO_MANUF_ACT 0x4231
#define ZORRO_PROD_ACT_PRELUDE ZORRO_ID(ACT, 0x01, 0)
#define ZORRO_MANUF_MACROSYSTEMS_GERMANY 0x4754
#define ZORRO_PROD_MACROSYSTEMS_MAESTRO ZORRO_ID(MACROSYSTEMS_GERMANY, 0x03, 0)
#define ZORRO_PROD_MACROSYSTEMS_VLAB ZORRO_ID(MACROSYSTEMS_GERMANY, 0x04, 0)
#define ZORRO_PROD_MACROSYSTEMS_MAESTRO_PRO ZORRO_ID(MACROSYSTEMS_GERMANY, 0x05, 0)
#define ZORRO_PROD_MACROSYSTEMS_RETINA ZORRO_ID(MACROSYSTEMS_GERMANY, 0x06, 0)
#define ZORRO_PROD_MACROSYSTEMS_MULTI_EVOLUTION ZORRO_ID(MACROSYSTEMS_GERMANY, 0x08, 0)
#define ZORRO_PROD_MACROSYSTEMS_TOCCATA ZORRO_ID(MACROSYSTEMS_GERMANY, 0x0C, 0)
#define ZORRO_PROD_MACROSYSTEMS_RETINA_Z3 ZORRO_ID(MACROSYSTEMS_GERMANY, 0x10, 0)
#define ZORRO_PROD_MACROSYSTEMS_VLAB_MOTION ZORRO_ID(MACROSYSTEMS_GERMANY, 0x12, 0)
#define ZORRO_PROD_MACROSYSTEMS_ALTAIS ZORRO_ID(MACROSYSTEMS_GERMANY, 0x13, 0)
#define ZORRO_PROD_MACROSYSTEMS_FALCON_040 ZORRO_ID(MACROSYSTEMS_GERMANY, 0xFD, 0)
#define ZORRO_MANUF_COMBITEC 0x6766
#define ZORRO_MANUF_SKI_PERIPHERALS 0x8000
#define ZORRO_PROD_SKI_PERIPHERALS_MAST_FIREBALL ZORRO_ID(SKI_PERIPHERALS, 0x08, 0)
#define ZORRO_PROD_SKI_PERIPHERALS_SCSI_DUAL_SERIAL ZORRO_ID(SKI_PERIPHERALS, 0x80, 0)
#define ZORRO_MANUF_REIS_WARE_2 0xA9AD
#define ZORRO_PROD_REIS_WARE_SCAN_KING ZORRO_ID(REIS_WARE_2, 0x11, 0)
#define ZORRO_MANUF_CAMERON 0xAA01
#define ZORRO_PROD_CAMERON_PERSONAL_A4 ZORRO_ID(CAMERON, 0x10, 0)
#define ZORRO_MANUF_REIS_WARE 0xAA11
#define ZORRO_PROD_REIS_WARE_HANDYSCANNER ZORRO_ID(REIS_WARE, 0x11, 0)
#define ZORRO_MANUF_PHOENIX_2 0xB5A8
#define ZORRO_PROD_PHOENIX_ST506_2 ZORRO_ID(PHOENIX_2, 0x21, 0)
#define ZORRO_PROD_PHOENIX_SCSI_2 ZORRO_ID(PHOENIX_2, 0x22, 0)
#define ZORRO_PROD_PHOENIX_RAM_2 ZORRO_ID(PHOENIX_2, 0xBE, 0)
#define ZORRO_MANUF_COMBITEC_2 0xC008
#define ZORRO_PROD_COMBITEC_HD ZORRO_ID(COMBITEC_2, 0x2A, 0)
#define ZORRO_PROD_COMBITEC_SRAM ZORRO_ID(COMBITEC_2, 0x2B, 0)
#define ZORRO_MANUF_HACKER 0x07DB
#define ZORRO_PROD_GENERAL_PROTOTYPE ZORRO_ID(HACKER, 0x00, 0)
#define ZORRO_PROD_HACKER_SCSI ZORRO_ID(HACKER, 0x01, 0)
#define ZORRO_PROD_RESOURCE_MANAGEMENT_FORCE_QUICKNET_QN2000 ZORRO_ID(HACKER, 0x02, 0)
#define ZORRO_PROD_VECTOR_CONNECTION_2 ZORRO_ID(HACKER, 0xE0, 0)
#define ZORRO_PROD_VECTOR_CONNECTION_3 ZORRO_ID(HACKER, 0xE1, 0)
#define ZORRO_PROD_VECTOR_CONNECTION_4 ZORRO_ID(HACKER, 0xE2, 0)
#define ZORRO_PROD_VECTOR_CONNECTION_5 ZORRO_ID(HACKER, 0xE3, 0)
```