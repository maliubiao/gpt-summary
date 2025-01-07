Response:
Let's break down the thought process for answering the prompt about `map_to_14segment.handroid`.

**1. Understanding the Core Request:**

The main request is to analyze the given C header file (`map_to_14segment.handroid`) and explain its purpose, relationship to Android, implementation details, dynamic linking aspects, potential errors, and how it's used in the Android framework/NDK. The user also requests Frida hook examples.

**2. Initial Scan and Keyword Identification:**

I first scanned the code for keywords and patterns that hint at its function:

* `#define BIT_SEG14_*`:  This strongly suggests the file deals with a 14-segment display or encoding. The names like `A`, `B`, `C`, etc., reinforce this.
* `struct seg14_conversion_map`: This suggests a data structure for mapping something *to* the 14 segments.
* `__be16`:  Indicates a big-endian 16-bit integer, likely used for storing the 14-segment representation.
* `MAP_TO_SEG14_SYSFS_FILE "map_seg14"`:  This is a crucial clue. It points to a sysfs file, meaning this mapping is likely controlled at the kernel level and exposed through the filesystem.
* `_SEG14(...)`: A macro for constructing the 16-bit representation based on the individual segment bits.
* `_MAP_*_ASCII_SEG14_*`:  These macros clearly define mappings between ASCII characters and the 14-segment representation.
* `SEG14_DEFAULT_MAP`: Provides a default mapping.

**3. Formulating the High-Level Functionality:**

Based on the keywords, I concluded that the file's primary purpose is to define a mapping between characters (primarily ASCII) and a 14-segment display representation. This mapping is likely used by some low-level Android component to display text or symbols on hardware that uses this type of display.

**4. Connecting to Android Functionality:**

The presence of a sysfs file (`map_seg14`) is a strong indicator of a kernel-level feature. I reasoned that Android, being based on Linux, could utilize this to control hardware with 14-segment displays. Examples could include older devices, embedded systems within Android devices (like a clock display on a microwave-like interface controlled by Android), or specialized industrial/automotive applications using Android. While not a core, everyday Android feature, it's a possibility within the broader ecosystem.

**5. Deconstructing the Code - Function by Function (or Macro by Macro):**

I went through each macro and the struct, explaining its role:

* `BIT_SEG14_*`:  Individual segment definitions.
* `struct seg14_conversion_map`: The lookup table structure.
* `SEG14_CONVERSION_MAP`: Macro for creating instances of the map.
* `MAP_TO_SEG14_SYSFS_FILE`: The sysfs entry point.
* `_SEG14`: How the 14 bits are packed into a `__be16`.
* `_MAP_*`: The actual mapping definitions for different ASCII ranges.
* `SEG14_DEFAULT_MAP`:  Creates the default ASCII-to-14-segment map.

**6. Addressing Dynamic Linking:**

The file itself doesn't directly involve dynamic linking. It's a header file defining data structures and macros. However, I considered where it *might* be used. A library (likely within the lower levels of Android, maybe even a kernel module or hardware abstraction layer) would use this header. Therefore, I focused on the likely `so` layout and the linking process for such a hypothetical library. I provided a basic `so` example and explained the standard linking process involving the dynamic linker.

**7. Identifying Potential Errors:**

I considered typical programming mistakes:

* Incorrectly setting bit flags in the macros.
* Using the wrong character, leading to an unexpected display.
* Not handling characters outside the defined ASCII range.

**8. Tracing the Path from Android Framework/NDK:**

This was the trickiest part, as the file is low-level. I reasoned the path would be indirect:

1. **Framework/NDK App:** An app wants to display something on a 14-segment display (unlikely directly).
2. **Android Services/HAL:**  The request would go through a system service or Hardware Abstraction Layer (HAL) responsible for controlling the display.
3. **Lower-Level Libraries/Kernel Drivers:** The HAL would interact with lower-level libraries or kernel drivers.
4. **Sysfs Interaction:** The driver would likely write to the `map_seg14` sysfs file (or a related file) to set the mapping.
5. **`map_to_14segment.handroid`:** This header would be used within the kernel driver or the libraries interacting with the driver to define the mapping data.

**9. Frida Hook Example:**

I focused the Frida hook on the likely interaction point – writing to the sysfs file. This is where the mapping defined in the header would be used. I provided an example of hooking the `write` system call, filtering for the `map_seg14` file, and then logging the data being written. This demonstrates how to intercept the usage of this mapping.

**10. Review and Refinement:**

Finally, I reviewed the entire response for clarity, accuracy, and completeness, ensuring all parts of the prompt were addressed. I made sure the language was clear and accessible. I added disclaimers where necessary (e.g., about the likelihood of direct use in typical Android apps).

**Self-Correction/Refinement During the Process:**

* **Initial Thought:**  Maybe this is directly used in some UI component.
* **Correction:** The sysfs file strongly suggests a kernel-level or HAL-level usage, making direct UI interaction less likely.
* **Initial Thought:** Focus on libc function implementation.
* **Correction:** The file itself doesn't *implement* libc functions. It defines data. The focus shifted to how the *data* is used.
* **Initial Thought:**  Provide a complex dynamic linking scenario.
* **Correction:** Keep the dynamic linking explanation relevant but not overly complicated, focusing on the likely `so` usage.

By following this structured approach, combining code analysis with knowledge of Android architecture and system-level concepts, I could generate a comprehensive and informative answer.
这是一个定义了14段显示器字符映射的头文件，属于Android Bionic库的一部分，用于在Linux内核层面定义如何将字符映射到14段显示器的各个段。

**功能列举:**

1. **定义14段显示器的段位:**  通过 `#define BIT_SEG14_A 0` 到 `#define BIT_SEG14_M 13` 定义了14段显示器的每一个段位的位掩码。例如，`BIT_SEG14_A` 代表段 A，对应位 0。 `BIT_SEG14_G1` 和 `BIT_SEG14_G2` 可能是中间横线的两个部分。
2. **定义字符到14段显示的映射表结构:**  `struct seg14_conversion_map` 定义了一个结构体，包含一个 `__be16 table[128]` 数组。这个数组用于存储字符到14段显示状态的映射关系。 `__be16` 表示一个大端序的 16 位整数，用于存储14个段的开关状态（每个段一位）。
3. **提供创建映射表的宏:**  `#define SEG14_CONVERSION_MAP(_name,_map) struct seg14_conversion_map _name = {.table = { _map } }`  这个宏简化了创建 `seg14_conversion_map` 结构体实例的过程，可以直接将一个映射数组赋值给结构体的 `table` 成员。
4. **定义sysfs文件路径:** `#define MAP_TO_SEG14_SYSFS_FILE "map_seg14"` 定义了一个字符串常量，表示在 Linux 的 sysfs 文件系统中，用于控制 14 段显示器映射的文件名是 "map_seg14"。
5. **提供生成14段显示编码的宏:** `#define _SEG14(sym,a,b,c,d,e,f,g1,g2,h,j,k,l,m,n) __cpu_to_be16(a << BIT_SEG14_A | ... | n << BIT_SEG14_M)`  这个宏接受一个字符 `sym` 和 14 个表示段状态的参数（0 或 1），然后将其组合成一个大端序的 16 位整数。`__cpu_to_be16` 用于确保字节顺序正确。
6. **预定义ASCII字符的14段显示映射:**  通过一系列 `#define _MAP_*_ASCII_SEG14_*` 宏，预定义了常见 ASCII 字符（包括数字、字母、符号）对应的 14 段显示状态。例如，`_MAP_48_57_ASCII_SEG14_NUMERIC` 定义了数字 0-9 的映射。
7. **提供默认的ASCII字符映射表:** `#define MAP_ASCII14SEG_ALPHANUM ...` 将所有预定义的 ASCII 映射组合成一个完整的映射表。
8. **提供创建默认映射表的宏:** `#define SEG14_DEFAULT_MAP(_name) SEG14_CONVERSION_MAP(_name, MAP_ASCII14SEG_ALPHANUM)`  这个宏可以方便地创建一个使用默认 ASCII 映射的 `seg14_conversion_map` 结构体实例。

**与Android功能的关联举例:**

虽然这种 14 段显示器不如现代智能手机的 LCD 或 OLED 屏幕常见，但它可能在以下 Android 相关场景中出现：

* **嵌入式Android设备:**  一些基于 Android 的嵌入式系统，例如工业控制面板、某些物联网设备或早期的 Android 设备，可能使用 14 段显示器来显示简单的信息，如数字、状态或简单的字母。
* **硬件抽象层 (HAL):**  Android 的 HAL 层负责与硬件进行交互。如果一个 Android 设备使用了 14 段显示器，那么相关的 HAL 模块可能会使用这个头文件中定义的映射来控制显示器的输出。
* **Linux内核驱动:**  最终控制 14 段显示器的会是 Linux 内核驱动程序。这个头文件就是为内核层提供的，定义了数据结构和常量，方便驱动程序使用。

**详细解释每一个libc函数的功能是如何实现的:**

这个文件中**没有直接定义或实现 libc 函数**。它是一个头文件，定义了常量、宏和数据结构。这些定义会被其他 C 代码（例如内核驱动或 HAL 模块）包含和使用。

* **`__cpu_to_be16`:** 虽然看起来像一个函数，但通常这是一个内联函数或宏，用于将一个 CPU 本地字节序的 16 位整数转换为大端序（Big-Endian）。大端序意味着高位字节存储在低地址。这个函数的具体实现会根据不同的 CPU 架构而有所不同。
    * **实现示例 (假设小端序 CPU):**
      ```c
      static inline __be16 __cpu_to_be16(unsigned short x)
      {
          return ((x >> 8) & 0xff) | ((x << 8) & 0xff00);
      }
      ```
      这个实现通过位移和位掩码操作交换了高低字节的顺序。

**对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程:**

这个头文件本身不直接涉及动态链接。它定义的数据结构和常量可以被编译进动态链接库（`.so` 文件）中使用。

**`.so` 布局样本:**

假设有一个名为 `libseg14display.so` 的动态链接库，它使用了 `map_to_14segment.handroid` 中定义的映射：

```
libseg14display.so:
    .text:  # 存放代码段
        display_char:  # 一个用于显示字符的函数
            # ... 使用 SEG14_DEFAULT_MAP ...
    .rodata: # 存放只读数据
        # 可能会包含一些字符串常量或其他只读数据
    .data:  # 存放已初始化的全局变量
        # ...
    .bss:   # 存放未初始化的全局变量
        # ...
```

**链接的处理过程:**

1. **编译:**  当编译 `libseg14display.so` 的源代码时，编译器会读取 `map_to_14segment.handroid` 头文件，并将其中定义的常量、宏和数据结构纳入编译过程。
2. **链接:**  链接器会将编译后的目标文件链接成一个共享库。在这个过程中，如果 `libseg14display.so` 的代码中使用了 `SEG14_DEFAULT_MAP` 或其他在头文件中定义的符号，链接器会解析这些符号的地址。由于 `SEG14_DEFAULT_MAP` 是在头文件中定义的，它的实际数据会被直接嵌入到 `libseg14display.so` 的 `.rodata` 段中。
3. **加载:**  当 Android 系统加载 `libseg14display.so` 时，动态链接器会将该库加载到内存中，并解析其依赖关系。在这个例子中，由于没有外部的符号依赖于 `map_to_14segment.handroid` 中的定义（因为它们是直接嵌入到 `.so` 中的），动态链接器不需要进行额外的符号查找和重定位来处理这些定义。

**逻辑推理，给出假设输入与输出:**

假设有一个 C 函数 `display_char`，它使用 `SEG14_DEFAULT_MAP` 来将字符显示在 14 段显示器上。

```c
// 假设在 libseg14display.so 中
#include <linux/map_to_14segment.handroid>
#include <stdio.h>

void display_char(char c) {
    if (c >= 0 && c < 128) {
        __be16 segments = SEG14_DEFAULT_MAP(default_map).table[(int)c];
        printf("Displaying char '%c', segment code: 0x%04x\n", c, segments);
        // 这里会调用底层的硬件控制代码，根据 segments 的值来点亮/熄灭对应的段
    } else {
        printf("Character '%c' is out of range.\n", c);
    }
}
```

**假设输入与输出:**

* **输入:** 字符 `'A'`
* **输出:** `Displaying char 'A', segment code: 0x3700`  (0x3700 是根据 `_MAP_65_90_ASCII_SEG14_ALPHA_UPPER` 中 'A' 的定义计算出来的)

* **输入:** 字符 `'8'`
* **输出:** `Displaying char '8', segment code: 0xf700`  (0xf700 是根据 `_MAP_48_57_ASCII_SEG14_NUMERIC` 中 '8' 的定义计算出来的)

* **输入:** 字符 `'?'`
* **输出:** `Displaying char '?', segment code: 0x2010`  (0x2010 是根据 `_MAP_58_64_ASCII_SEG14_SYMBOL` 中 '?' 的定义计算出来的)

**涉及用户或者编程常见的使用错误，请举例说明:**

1. **直接操作位掩码错误:**  用户可能尝试直接操作 `segments` 变量的位，而没有正确理解位掩码的含义，导致错误的段被点亮或熄灭。
   ```c
   __be16 segments = SEG14_DEFAULT_MAP(default_map).table[(int)'A'];
   segments |= 0x0001; // 错误地认为这样会点亮某个特定的段
   ```
   正确的做法是使用头文件中定义的 `BIT_SEG14_*` 常量。

2. **字符超出映射范围:**  如果尝试显示一个不在 0-127 ASCII 范围内的字符，由于映射表只定义了 128 个字符的映射，会导致数组越界访问，或者得到未定义的显示结果。
   ```c
   display_char(128); // 字符编码超出范围
   ```

3. **字节序问题:**  如果直接使用 `segments` 变量而没有考虑到字节序，可能会在不同的架构上得到不同的显示结果。`__cpu_to_be16` 宏的作用就是为了解决这个问题，确保数据以大端序存储。

4. **未初始化映射表:**  如果用户尝试自己创建一个映射表，但没有正确初始化 `table` 数组，会导致程序运行时访问未初始化的内存。

**说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。**

到达 `map_to_14segment.handroid` 的路径通常比较底层，不太可能直接从 Android Framework 或 NDK 的应用层直接调用。更可能的路径是从下往上：

1. **硬件层面:**  实际的 14 段显示器连接到设备的硬件接口（例如 GPIO）。
2. **Linux内核驱动:**  需要一个 Linux 内核驱动程序来控制这个硬件接口。这个驱动程序可能会使用 `map_to_14segment.handroid` 中定义的映射表或常量。驱动程序可能会将当前的字符映射写入到 `MAP_TO_SEG14_SYSFS_FILE` 定义的 sysfs 文件中。
3. **Hardware Abstraction Layer (HAL):** Android 的 HAL 层会提供一个接口，供上层调用来控制硬件。如果涉及到 14 段显示器，可能会有一个对应的 HAL 模块。这个 HAL 模块可能会读取或写入 sysfs 文件 (`map_seg14`)，或者直接与内核驱动进行通信。
4. **Android System Services:**  某些系统服务可能会使用 HAL 提供的接口来控制底层的硬件。
5. **NDK/Framework (间接):**  通常情况下，应用开发者不会直接与 14 段显示器交互。但是，如果 Android 系统或某些特定的硬件抽象层提供了相关的 API，NDK 应用可以通过调用这些 API，最终间接地影响到对 14 段显示器的控制。例如，一个用于工业控制的 Android 应用可能会使用 NDK 来调用底层的 HAL 接口，从而在 14 段显示器上显示信息.

**Frida Hook 示例:**

由于 `map_to_14segment.handroid` 主要在内核或 HAL 层使用，直接 hook 到应用层代码来观察其使用比较困难。一个更有效的方法是 hook 与该文件相关的系统调用或 HAL 函数。

以下是一个使用 Frida hook `write` 系统调用的示例，用于监测对 `map_seg14` sysfs 文件的写入操作：

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    device = frida.get_usb_device(timeout=10)
    pid = device.spawn(["com.example.your_app"]) # 替换成你的目标应用包名
    session = device.attach(pid)
    script = session.create_script("""
        Interceptor.attach(Module.findExportByName(null, "write"), {
            onEnter: function(args) {
                const fd = args[0].toInt32();
                const buf = args[1];
                const count = args[2].toInt32();

                const filename = this.context.rdi.readCString(); // 假设在 x86_64 架构上，文件描述符对应的路径在 rdi 寄存器中

                if (filename && filename.includes("map_seg14")) {
                    const data = Memory.readByteArray(buf, count);
                    console.log("[*] Writing to map_seg14, data:", hexdump(data, { ansi: true }));
                }
            }
        });
    """)
    script.on('message', on_message)
    script.load()
    device.resume(pid)
    sys.stdin.read()
except Exception as e:
    print(e)
```

**解释 Frida Hook 代码:**

1. **导入模块:** 导入 `frida` 和 `sys` 模块。
2. **`on_message` 函数:**  处理 Frida 脚本发送的消息。
3. **连接设备和附加进程:**  使用 `frida.get_usb_device()` 获取 USB 连接的 Android 设备，然后启动或附加到目标进程（需要替换 `com.example.your_app` 为实际的应用包名）。
4. **创建 Frida 脚本:**
   - `Interceptor.attach(Module.findExportByName(null, "write"), ...)`:  Hook `write` 系统调用。`Module.findExportByName(null, "write")` 在所有已加载的模块中查找 `write` 函数。
   - `onEnter`:  在 `write` 函数调用之前执行。
     - 获取文件描述符 `fd`、缓冲区 `buf` 和写入字节数 `count`。
     - **重要:** 获取文件描述符对应的路径。 这部分依赖于 CPU 架构和调用约定。在示例中，假设在 x86_64 架构上，文件描述符对应的路径是通过 `this.context.rdi.readCString()` 读取 `rdi` 寄存器来获取的。在 ARM 或其他架构上，可能需要查看不同的寄存器或使用其他方法来获取文件名。
     - 检查文件名是否包含 "map_seg14"。
     - 如果是，则使用 `Memory.readByteArray(buf, count)` 读取写入的数据，并使用 `hexdump` 打印出来。
5. **加载和运行脚本:** `script.load()` 加载脚本，`device.resume(pid)` 恢复目标进程的执行。
6. **保持脚本运行:** `sys.stdin.read()` 阻塞程序，直到用户按下 Ctrl+C。

**使用 Frida Hook 的步骤:**

1. **确保你的 Android 设备已 root，并且安装了 Frida Server。**
2. **安装 Frida Python 模块:** `pip install frida`
3. **将上述 Python 脚本保存为一个文件（例如 `hook_seg14.py`）。**
4. **替换脚本中的 `com.example.your_app` 为你想要监控的应用的包名（如果适用）。如果想监控系统级别的操作，可以附加到 `system_server` 或其他相关进程。**
5. **运行脚本:** `python hook_seg14.py`
6. **在 Android 设备上执行可能触发 14 段显示器更新的操作。**
7. **查看终端输出，你将看到写入 `map_seg14` 文件的数据，这代表了 14 段显示器的映射被更新。**

**注意:**

* Hook 系统调用需要 root 权限。
* 获取文件描述符对应的路径的方法可能因 Android 版本和架构而异，可能需要进行调整。
* 这个 hook 示例假设写入 `map_seg14` 文件时会直接使用 `map_to_14segment.handroid` 中定义的映射值。实际情况可能更复杂，可能涉及到数据转换或更高级的驱动逻辑。

通过这种 Frida Hook 的方式，你可以观察到系统或应用何时以及如何与 14 段显示器相关的内核机制进行交互，从而理解 `map_to_14segment.handroid` 在实际 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/map_to_14segment.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef MAP_TO_14SEGMENT_H
#define MAP_TO_14SEGMENT_H
#include <linux/errno.h>
#include <linux/types.h>
#include <asm/byteorder.h>
#define BIT_SEG14_A 0
#define BIT_SEG14_B 1
#define BIT_SEG14_C 2
#define BIT_SEG14_D 3
#define BIT_SEG14_E 4
#define BIT_SEG14_F 5
#define BIT_SEG14_G1 6
#define BIT_SEG14_G2 7
#define BIT_SEG14_H 8
#define BIT_SEG14_I 9
#define BIT_SEG14_J 10
#define BIT_SEG14_K 11
#define BIT_SEG14_L 12
#define BIT_SEG14_M 13
#define BIT_SEG14_RESERVED1 14
#define BIT_SEG14_RESERVED2 15
struct seg14_conversion_map {
  __be16 table[128];
};
#define SEG14_CONVERSION_MAP(_name,_map) struct seg14_conversion_map _name = {.table = { _map } }
#define MAP_TO_SEG14_SYSFS_FILE "map_seg14"
#define _SEG14(sym,a,b,c,d,e,f,g1,g2,h,j,k,l,m,n) __cpu_to_be16(a << BIT_SEG14_A | b << BIT_SEG14_B | c << BIT_SEG14_C | d << BIT_SEG14_D | e << BIT_SEG14_E | f << BIT_SEG14_F | g1 << BIT_SEG14_G1 | g2 << BIT_SEG14_G2 | h << BIT_SEG14_H | j << BIT_SEG14_I | k << BIT_SEG14_J | l << BIT_SEG14_K | m << BIT_SEG14_L | n << BIT_SEG14_M)
#define _MAP_0_32_ASCII_SEG14_NON_PRINTABLE 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
#define _MAP_33_47_ASCII_SEG14_SYMBOL _SEG14('!', 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0), _SEG14('"', 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0), _SEG14('#', 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0), _SEG14('$', 1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0), _SEG14('%', 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0), _SEG14('&', 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1), _SEG14('\'', 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0), _SEG14('(', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1), _SEG14(')', 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0), _SEG14('*', 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1), _SEG14('+', 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0), _SEG14(',', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0), _SEG14('-', 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0), _SEG14('.', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1), _SEG14('/', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0),
#define _MAP_48_57_ASCII_SEG14_NUMERIC _SEG14('0', 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0), _SEG14('1', 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0), _SEG14('2', 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0), _SEG14('3', 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0), _SEG14('4', 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0), _SEG14('5', 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1), _SEG14('6', 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0), _SEG14('7', 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0), _SEG14('8', 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0), _SEG14('9', 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0),
#define _MAP_58_64_ASCII_SEG14_SYMBOL _SEG14(':', 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0), _SEG14(';', 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0), _SEG14('<', 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1), _SEG14('=', 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0), _SEG14('>', 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0), _SEG14('?', 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0), _SEG14('@', 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0),
#define _MAP_65_90_ASCII_SEG14_ALPHA_UPPER _SEG14('A', 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0), _SEG14('B', 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0), _SEG14('C', 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0), _SEG14('D', 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0), _SEG14('E', 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0), _SEG14('F', 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0), _SEG14('G', 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0), _SEG14('H', 0, 1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0), _SEG14('I', 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0), _SEG14('J', 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0), _SEG14('K', 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1), _SEG14('L', 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0), _SEG14('M', 0, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0), _SEG14('N', 0, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1), _SEG14('O', 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0), _SEG14('P', 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0), _SEG14('Q', 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1), _SEG14('R', 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1), _SEG14('S', 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0), _SEG14('T', 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0), _SEG14('U', 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0), _SEG14('V', 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0), _SEG14('W', 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1), _SEG14('X', 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1), _SEG14('Y', 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0), _SEG14('Z', 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0),
#define _MAP_91_96_ASCII_SEG14_SYMBOL _SEG14('[', 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0), _SEG14('\\', 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1), _SEG14(']', 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0), _SEG14('^', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1), _SEG14('_', 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0), _SEG14('`', 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0),
#define _MAP_97_122_ASCII_SEG14_ALPHA_LOWER _SEG14('a', 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0), _SEG14('b', 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1), _SEG14('c', 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0), _SEG14('d', 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0), _SEG14('e', 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0), _SEG14('f', 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0), _SEG14('g', 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0), _SEG14('h', 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0), _SEG14('i', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0), _SEG14('j', 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0), _SEG14('k', 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1), _SEG14('l', 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0), _SEG14('m', 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0), _SEG14('n', 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0), _SEG14('o', 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0), _SEG14('p', 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0), _SEG14('q', 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0), _SEG14('r', 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0), _SEG14('s', 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1), _SEG14('t', 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0), _SEG14('u', 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0), _SEG14('v', 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0), _SEG14('w', 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1), _SEG14('x', 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1), _SEG14('y', 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0), _SEG14('z', 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0),
#define _MAP_123_126_ASCII_SEG14_SYMBOL _SEG14('{', 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0), _SEG14('|', 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0), _SEG14('}', 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1), _SEG14('~', 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0),
#define MAP_ASCII14SEG_ALPHANUM _MAP_0_32_ASCII_SEG14_NON_PRINTABLE _MAP_33_47_ASCII_SEG14_SYMBOL _MAP_48_57_ASCII_SEG14_NUMERIC _MAP_58_64_ASCII_SEG14_SYMBOL _MAP_65_90_ASCII_SEG14_ALPHA_UPPER _MAP_91_96_ASCII_SEG14_SYMBOL _MAP_97_122_ASCII_SEG14_ALPHA_LOWER _MAP_123_126_ASCII_SEG14_SYMBOL
#define SEG14_DEFAULT_MAP(_name) SEG14_CONVERSION_MAP(_name, MAP_ASCII14SEG_ALPHANUM)
#endif

"""

```