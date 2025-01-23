Response:
Let's break down the thought process for analyzing this C header file.

**1. Initial Understanding and Goal Identification:**

The first step is to read the provided text and the C header file content. The request asks for a detailed explanation of the file's functionality, its relationship to Android, how its functions are implemented (though this file mostly has macros, so focus shifts), dynamic linking aspects (again, less relevant due to no actual functions), potential errors, and how Android framework/NDK interact with it, along with Frida hooking.

The core goal is to understand how this header file contributes to the broader Android ecosystem, even if it seems simple.

**2. Deconstructing the File - Line by Line:**

Now, let's go through the file line by line and analyze its components:

* **Comments:** Recognize the auto-generated nature and the link for more information. This hints that direct modification is discouraged.
* **Include Guard:**  `#ifndef MAP_TO_7SEGMENT_H`, `#define MAP_TO_7SEGMENT_H`, `#endif` -  Standard practice to prevent multiple inclusions. This is a basic but important part of C/C++ development.
* **`#include <linux/errno.h>`:** Indicates the file might be used in a kernel or low-level context where error codes are relevant.
* **`#define BIT_SEG7_A 0` ... `#define BIT_SEG7_RESERVED 7`:**  These are bitwise definitions. The names clearly indicate they represent the segments of a 7-segment display. The numbers are bit positions.
* **`struct seg7_conversion_map`:** Defines a structure to hold a conversion table. The `unsigned char table[128]` suggests it's mapping ASCII characters (0-127) to their 7-segment representations.
* **`#define SEG7_CONVERSION_MAP(_name,_map) ...`:** This is a macro that simplifies the creation of `seg7_conversion_map` instances. It initializes the `table` member with the provided `_map`.
* **`#define MAP_TO_SEG7_SYSFS_FILE "map_seg7"`:** This suggests interaction with the Linux kernel's `sysfs` interface. This is a key piece of information connecting it to the Android system. It hints at a way to potentially configure or access the mapping from userspace.
* **`#define _SEG7(l,a,b,c,d,e,f,g) ...`:**  This is a crucial macro. It takes individual segment states (0 or 1) and packs them into a single byte. The `l` parameter seems like a label or comment, which is discarded.
* **`#define _MAP_0_32_ASCII_SEG7_NON_PRINTABLE ...`:**  This and subsequent `_MAP_*` macros define the actual 7-segment mappings for different ASCII ranges. The names are descriptive.
* **`#define MAP_ASCII7SEG_ALPHANUM ...`:**  Combines the individual mapping macros to create a full alphanumeric mapping.
* **`#define MAP_ASCII7SEG_ALPHANUM_LC ...`:** Similar to the above, but appears to use lowercase letters in the mapping. This raises a question about why there are two seemingly similar mappings. *Self-correction:  Looking closer, the uppercase mapping uses uppercase letters in the comments of `_SEG7`, while the lowercase uses lowercase. The actual bit patterns might be the same for some, but the intention is different.*
* **`#define SEG7_DEFAULT_MAP(_name) ...`:**  Provides a convenient way to create a `seg7_conversion_map` instance with the `MAP_ASCII7SEG_ALPHANUM` mapping as the default.

**3. Identifying Core Functionality:**

From the deconstruction, the core functionality is clearly mapping ASCII characters to their 7-segment display representations. This is achieved through a lookup table.

**4. Connecting to Android:**

The `#define MAP_TO_SEG7_SYSFS_FILE "map_seg7"` is the crucial link. `sysfs` is a virtual file system in Linux used to expose kernel objects and their attributes to userspace. This indicates that:

* The 7-segment mapping is likely managed by a kernel driver.
* Android userspace (framework, apps, NDK) can potentially interact with this mapping via the `/sys/map_seg7` file. This interaction could involve reading the current mapping or, potentially, even writing to it (though less likely for a predefined mapping).

**5. Considering Dynamic Linking:**

While the file itself doesn't *contain* functions that are dynamically linked, the *use* of this header file could be within a shared library (.so). The explanation should cover this possibility, even if the direct file isn't a .so.

**6. Thinking About Errors and Usage:**

* **Incorrect Usage:**  Using an index outside the bounds of the `table` (0-127) would be a potential error.
* **Misinterpreting Bits:** Incorrectly interpreting the meaning of the bits in the output byte.
* **Kernel/Driver Issues:**  If the underlying kernel driver isn't working correctly, the mapping will be wrong.

**7. Tracing the Path from Android Framework/NDK:**

This requires some educated guessing or prior knowledge of Android internals. The steps would likely involve:

* **Android Framework:**  A system service or UI component might need to display information on a 7-segment display. This service would likely use native code (via JNI).
* **NDK:** An NDK developer could directly use this mapping for custom hardware interaction if they have a 7-segment display.
* **Native Code:**  The native code would open and potentially read (or even write, less likely) the `/sys/map_seg7` file, or it might directly use the `SEG7_DEFAULT_MAP` in its own code.

**8. Frida Hooking:**

Consider what could be hooked. Since it's likely accessed through `sysfs`, hooking `open`, `read`, or `write` calls to the `/sys/map_seg7` file would be relevant. If the mapping is used directly in code, hooking the usage of the `seg7_conversion_map` struct or the macros would be options.

**9. Structuring the Answer:**

Organize the information logically, using the headings requested in the prompt. Provide clear examples and explanations.

**Self-Correction during the Process:**

* Initially, I might have focused too much on the lack of *functions* and dynamic linking within *this specific file*. The correction is to realize that the *usage* of this header can involve dynamic linking.
* I might have overlooked the `sysfs` connection initially and focused only on the C/C++ code. Realizing the significance of `MAP_TO_SEG7_SYSFS_FILE` is crucial.
*  The two different `MAP_ASCII7SEG_*` macros might seem redundant at first glance. A closer look at the comments reveals the subtle difference in intent.

By following these steps, including careful reading, deconstruction, and connecting the pieces to the broader Android context, you can generate a comprehensive and accurate answer to the request.
好的，让我们详细分析一下 `bionic/libc/kernel/uapi/linux/map_to_7segment.handroid` 这个头文件。

**功能列举:**

这个头文件的核心功能是定义了将 ASCII 字符映射到 7 段数码管显示模式的常量和数据结构。具体来说，它实现了以下功能：

1. **定义 7 段数码管的各个段的位掩码:**  `BIT_SEG7_A` 到 `BIT_SEG7_G` 定义了每个段在字节中的位位置。`BIT_SEG7_RESERVED`  是保留位。

2. **定义 7 段数码管的转换映射结构体:** `struct seg7_conversion_map` 定义了一个结构体，其中包含一个 128 字节的数组 `table`，用于存储 ASCII 码 (0-127) 到 7 段码的映射关系。

3. **定义创建转换映射结构体的宏:** `SEG7_CONVERSION_MAP(_name,_map)`  是一个宏，用于方便地创建一个 `seg7_conversion_map` 结构体实例，并使用提供的映射表 `_map` 初始化其 `table` 成员。

4. **定义 sysfs 文件路径:** `MAP_TO_SEG7_SYSFS_FILE` 定义了一个字符串常量 `"map_seg7"`，这暗示了该映射可能与 Linux 内核的 `sysfs` 文件系统有关，允许用户空间程序读取或配置 7 段数码管的映射。

5. **定义将 7 段状态组合成字节的宏:** `_SEG7(l,a,b,c,d,e,f,g)`  是一个宏，它接收 7 个参数 (0 或 1) 代表 7 个段的亮灭状态，并将它们组合成一个字节。参数 `l` 看上去是一个标签，但实际上并没有在宏的实现中使用。

6. **定义预定义的 ASCII 到 7 段码的映射表宏:**
   - `_MAP_0_32_ASCII_SEG7_NON_PRINTABLE` 到 `_MAP_123_126_ASCII_SEG7_SYMBOL` 定义了不同 ASCII 字符范围的 7 段码。这些宏使用 `_SEG7` 宏来定义每个字符的 7 段状态。
   - `MAP_ASCII7SEG_ALPHANUM`  将所有上述映射表宏组合在一起，形成一个包含字母、数字和符号的完整 ASCII 到 7 段码的映射表。
   - `MAP_ASCII7SEG_ALPHANUM_LC`  看起来与 `MAP_ASCII7SEG_ALPHANUM` 类似，但其注释中使用了小写字母。这可能用于区分大小写显示或其他用途。

7. **定义默认映射表的宏:** `SEG7_DEFAULT_MAP(_name)`  是一个宏，它使用 `MAP_ASCII7SEG_ALPHANUM` 作为默认映射表来创建一个 `seg7_conversion_map` 结构体实例。

**与 Android 功能的关系及举例说明:**

这个头文件主要用于 Android 系统中需要控制 7 段数码管显示的场景。这些场景可能包括：

* **硬件指示灯:**  一些 Android 设备可能使用 7 段数码管来显示状态信息，例如充电状态、音量大小、网络连接状态等。
* **嵌入式设备或外围硬件:**  Android 系统可能运行在一些嵌入式设备上，或者连接了带有 7 段数码管的外围硬件。
* **调试或测试用途:**  开发者可能在某些低级调试或硬件测试场景中使用 7 段数码管来显示信息。

**举例说明:**

假设一个 Android 设备使用 7 段数码管来显示当前的电池电量百分比。系统可能需要将数字 "85" 转换为 7 段码并在数码管上显示。这个头文件中定义的宏和结构体可以帮助完成这个转换：

1. **获取要显示的字符:** 系统会提取出字符 '8' 和 '5'。
2. **查阅映射表:**  使用 `MAP_ASCII7SEG_ALPHANUM` 中定义的映射关系，可以找到 '8' 和 '5' 对应的 7 段码。
   - 根据 `#define _MAP_48_57_ASCII_SEG7_NUMERIC _SEG7('0', 1, 1, 1, 1, 1, 1, 0), ... _SEG7('8', 1, 1, 1, 1, 1, 1, 1), _SEG7('9', 1, 1, 1, 1, 0, 1, 1),`，字符 '8' 对应的 7 段码是 `_SEG7('8', 1, 1, 1, 1, 1, 1, 1)`，展开后为 `(1 << 0 | 1 << 1 | 1 << 2 | 1 << 3 | 1 << 4 | 1 << 5 | 1 << 6)`，即二进制 `01111111`。
   - 字符 '5' 对应的 7 段码是 `_SEG7('5', 1, 0, 1, 1, 0, 1, 1)`，展开后为 `(1 << 0 | 0 << 1 | 1 << 2 | 1 << 3 | 0 << 4 | 1 << 5 | 1 << 6)`，即二进制 `01101101`。
3. **控制硬件:**  系统会将这些 7 段码发送到控制 7 段数码管的硬件接口，使其显示相应的数字。

**libc 函数的功能实现:**

这个头文件本身并没有定义任何 libc 函数。它主要定义了宏和数据结构。通常，libc 中不会直接提供操作 7 段数码管的通用函数，因为这属于硬件相关的操作，不同设备的实现方式可能差异很大。

更可能的情况是，Android 的硬件抽象层 (HAL) 或者底层的驱动程序会使用这些定义来操作特定的 7 段数码管硬件。例如，一个硬件制造商可能会提供一个共享库 (.so)，其中包含了使用这些宏定义的函数来控制他们的 7 段数码管模块。

**涉及 dynamic linker 的功能及 so 布局样本和链接处理过程:**

由于这个头文件本身不包含可执行代码，因此它不直接涉及 dynamic linker 的功能。然而，如果一个共享库使用了这个头文件中定义的宏和结构体，那么 dynamic linker 会在加载这个共享库时发挥作用。

**SO 布局样本:**

假设有一个名为 `libseg7display.so` 的共享库，它使用了 `map_to_7segment.h` 中的定义。其布局可能如下：

```
libseg7display.so:
    .text          # 包含可执行代码，例如控制 7 段数码管的函数
    .rodata        # 包含只读数据，可能包含使用 SEG7_DEFAULT_MAP 创建的默认映射表
    .data          # 包含可读写数据
    .bss           # 包含未初始化的数据
    .dynsym        # 动态符号表
    .dynstr        # 动态字符串表
    .plt           # 程序链接表
    .got           # 全局偏移表
    ...
```

在这个 `libseg7display.so` 中，`.rodata` 段可能会包含一个使用 `SEG7_DEFAULT_MAP` 宏定义的 `seg7_conversion_map` 结构体实例。`.text` 段会包含使用这个映射表的函数，例如一个将 ASCII 字符串转换为 7 段码并控制硬件显示的函数。

**链接的处理过程:**

1. **编译时:**  当编译使用了 `map_to_7segment.h` 的 `libseg7display.so` 时，编译器会根据头文件中的定义生成相应的代码。例如，使用 `SEG7_DEFAULT_MAP` 宏会直接在 `.rodata` 段生成一个 `seg7_conversion_map` 结构体的实例。
2. **加载时:** 当 Android 系统加载 `libseg7display.so` 时，dynamic linker (`/system/bin/linker` 或 `/system/bin/linker64`) 会执行以下操作：
   - **加载共享库:** 将 `libseg7display.so` 的各个段加载到内存中的合适位置。
   - **符号解析:** 如果 `libseg7display.so` 依赖于其他共享库，dynamic linker 会解析其符号依赖关系。在这个例子中，`map_to_7segment.h` 主要定义了宏和结构体，不太可能直接引起与其他库的符号依赖。
   - **重定位:**  Dynamic linker 会修改代码和数据中的地址，使其指向正确的内存位置。例如，如果 `.text` 段中的代码访问了 `.rodata` 段中的映射表，dynamic linker 会确保该访问指向正确的内存地址。

**逻辑推理的假设输入与输出:**

假设有一个函数 `ascii_to_seg7(char c)`，它使用 `MAP_ASCII7SEG_ALPHANUM` 映射表将一个 ASCII 字符转换为 7 段码。

**假设输入:** 字符 'A'

**处理过程:**

1. 函数内部会检查输入字符 `c` 的 ASCII 值。
2. 如果 `c` 是 'A'，其 ASCII 值为 65。
3. 函数会访问 `MAP_ASCII7SEG_ALPHANUM` 宏展开后的数组的第 65 个元素（索引从 0 开始）。
4. 根据 `#define _MAP_65_90_ASCII_SEG7_ALPHA_UPPR _SEG7('A', 1, 1, 1, 0, 1, 1, 1), ...`，`MAP_ASCII7SEG_ALPHANUM[65]` 的值将是 `_SEG7('A', 1, 1, 1, 0, 1, 1, 1)` 宏展开后的结果，即 `(1 << 0 | 1 << 1 | 1 << 2 | 0 << 3 | 1 << 4 | 1 << 5 | 1 << 6)`，二进制为 `01110111`。

**输出:**  `ascii_to_seg7('A')` 的输出将是字节值 `01110111` (二进制)，表示 7 段数码管的 A、B、C、E、F、G 段点亮。

**用户或编程常见的使用错误:**

1. **数组越界访问:**  如果尝试访问 `seg7_conversion_map.table` 数组超出 0-127 的索引范围，会导致内存错误。例如，尝试查找 ASCII 值大于 127 的字符的 7 段码。
   ```c
   struct seg7_conversion_map my_map = SEG7_DEFAULT_MAP(my_default_map);
   unsigned char seg7_code = my_map.table[200]; // 错误：索引越界
   ```
2. **错误的位操作:**  如果开发者尝试手动组合 7 段码，可能会错误地设置或清除某些位。
   ```c
   unsigned char incorrect_seg7_code = (1 << 1) | (1 << 3) | (1 << 5); // 可能不是预期的字符
   ```
3. **混淆不同映射表:**  如果代码中使用了多个不同的映射表（例如，自定义的映射表），可能会不小心使用了错误的映射表，导致显示错误。
4. **假设所有字符都有定义:** 开发者可能会假设所有可能的字符都有对应的 7 段码定义，但实际上 `MAP_ASCII7SEG_ALPHANUM` 只定义了 ASCII 字符的映射。对于其他字符编码（如 Unicode），可能需要额外的处理。

**Android framework 或 ndk 如何一步步的到达这里:**

虽然 framework 或 NDK 不会直接操作这个头文件，但它们可以通过以下方式间接使用：

1. **HAL (Hardware Abstraction Layer):**
   - Android Framework 需要控制硬件时，通常会通过 HAL 进行。
   - 假设某个硬件模块（例如，一个带有 7 段数码管的显示模块）的 HAL 实现位于一个共享库中（例如 `vendor/lib/hw/leds.default.so`）。
   - 这个 HAL 库的源代码可能会包含对 `map_to_7segment.h` 的引用，并使用其中定义的宏和结构体来控制 7 段数码管。
   - **步骤:**
     - Framework 中的一个服务（例如 `BatteryService`）需要显示电池电量。
     - 该服务会调用 HAL 接口（例如 `set_led_display(int value)`）。
     - HAL 的实现 (`leds.default.so`) 会将 `value` 转换为字符串，然后使用 `map_to_7segment.h` 中定义的映射表将每个字符转换为 7 段码。
     - HAL 通过底层的驱动程序接口将这些 7 段码发送到硬件。

2. **NDK:**
   - 使用 NDK 开发的应用可以直接访问底层的 C/C++ 代码。
   - 如果一个 NDK 应用需要与带有 7 段数码管的外部硬件进行交互，开发者可能会在 NDK 代码中包含 `map_to_7segment.h`，并使用其中的定义来控制硬件。
   - **步骤:**
     - NDK 应用通过 JNI 调用 native 代码。
     - Native 代码包含了 `<linux/map_to_7segment.handroid>`。
     - Native 代码使用 `SEG7_DEFAULT_MAP` 或自定义的映射表，将要显示的数据转换为 7 段码。
     - Native 代码通过某种硬件接口（例如，通过 `/dev` 节点或者直接访问内存映射的寄存器）将 7 段码发送到硬件。

**Frida hook 示例调试这些步骤:**

假设我们想 hook HAL 库中操作 7 段数码管的函数。

**假设 HAL 库 `vendor/lib/hw/leds.default.so` 中有一个函数 `display_on_7segment(unsigned char seg7_code)`。**

**Frida hook 示例:**

```javascript
function hookSevenSegmentDisplay() {
  const moduleName = "leds.default.so";
  const symbolName = "_ZN4aidl4test4halyleds14LedsHidlService19display_on_7segmentEh"; // 假设 demangled 后的函数名

  const moduleBase = Module.findBaseAddress(moduleName);
  if (moduleBase) {
    const symbolAddress = moduleBase.add(Module.getExportByName(moduleName, symbolName));
    if (symbolAddress) {
      Interceptor.attach(symbolAddress, {
        onEnter: function (args) {
          const seg7Code = args[0].toInt();
          console.log("[+] Hooked display_on_7segment, seg7_code:", seg7Code.toString(2).padStart(8, '0'));
          // 可以进一步分析 seg7Code 的每一位，判断哪些段被点亮
        },
        onLeave: function (retval) {
          console.log("[+] display_on_7segment returned");
        }
      });
      console.log("[+] Successfully hooked display_on_7segment");
    } else {
      console.error(`[-] Symbol ${symbolName} not found in ${moduleName}`);
    }
  } else {
    console.error(`[-] Module ${moduleName} not found`);
  }
}

rpc.exports = {
  hook_seven_segment: hookSevenSegmentDisplay
};
```

**调试步骤:**

1. **找到目标函数:**  使用 `adb shell service list` 或检查 HAL 代码来确定负责控制 7 段数码管的 HAL 库和函数名。可以使用 `frida-ps -U` 或 `frida -U -f <package_name>` 连接到目标进程。
2. **加载 Frida 脚本:** 将上述 Frida 脚本保存为 `.js` 文件，并通过 Frida CLI 加载到目标进程：
   ```bash
   frida -U -f <target_process_name> -l your_script.js --no-pause
   ```
3. **观察输出:** 当 Android 系统调用 `display_on_7segment` 函数时，Frida 脚本会在 `onEnter` 中拦截调用，并打印出 `seg7_code` 的二进制表示，方便分析哪些段被点亮。
4. **进一步分析:**  可以在 `onEnter` 中进一步解析 `seg7_code`，例如，检查每个位的值，并将其与 `BIT_SEG7_A` 等宏定义进行比较，以确定显示的字符。

通过这种方式，可以使用 Frida hook 技术来动态地观察和调试 Android 系统中与 7 段数码管相关的操作。

总而言之，`bionic/libc/kernel/uapi/linux/map_to_7segment.handroid` 这个头文件虽然小巧，但对于需要在 Android 系统中控制 7 段数码管的场景来说非常重要。它提供了一种标准化的方式来表示和映射字符到 7 段码，方便了驱动程序、HAL 和应用开发。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/map_to_7segment.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef MAP_TO_7SEGMENT_H
#define MAP_TO_7SEGMENT_H
#include <linux/errno.h>
#define BIT_SEG7_A 0
#define BIT_SEG7_B 1
#define BIT_SEG7_C 2
#define BIT_SEG7_D 3
#define BIT_SEG7_E 4
#define BIT_SEG7_F 5
#define BIT_SEG7_G 6
#define BIT_SEG7_RESERVED 7
struct seg7_conversion_map {
  unsigned char table[128];
};
#define SEG7_CONVERSION_MAP(_name,_map) struct seg7_conversion_map _name = {.table = { _map } }
#define MAP_TO_SEG7_SYSFS_FILE "map_seg7"
#define _SEG7(l,a,b,c,d,e,f,g) (a << BIT_SEG7_A | b << BIT_SEG7_B | c << BIT_SEG7_C | d << BIT_SEG7_D | e << BIT_SEG7_E | f << BIT_SEG7_F | g << BIT_SEG7_G)
#define _MAP_0_32_ASCII_SEG7_NON_PRINTABLE 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
#define _MAP_33_47_ASCII_SEG7_SYMBOL _SEG7('!', 0, 0, 0, 0, 1, 1, 0), _SEG7('"', 0, 1, 0, 0, 0, 1, 0), _SEG7('#', 0, 1, 1, 0, 1, 1, 0), _SEG7('$', 1, 0, 1, 1, 0, 1, 1), _SEG7('%', 0, 0, 1, 0, 0, 1, 0), _SEG7('&', 1, 0, 1, 1, 1, 1, 1), _SEG7('\'', 0, 0, 0, 0, 0, 1, 0), _SEG7('(', 1, 0, 0, 1, 1, 1, 0), _SEG7(')', 1, 1, 1, 1, 0, 0, 0), _SEG7('*', 0, 1, 1, 0, 1, 1, 1), _SEG7('+', 0, 1, 1, 0, 0, 0, 1), _SEG7(',', 0, 0, 0, 0, 1, 0, 0), _SEG7('-', 0, 0, 0, 0, 0, 0, 1), _SEG7('.', 0, 0, 0, 0, 1, 0, 0), _SEG7('/', 0, 1, 0, 0, 1, 0, 1),
#define _MAP_48_57_ASCII_SEG7_NUMERIC _SEG7('0', 1, 1, 1, 1, 1, 1, 0), _SEG7('1', 0, 1, 1, 0, 0, 0, 0), _SEG7('2', 1, 1, 0, 1, 1, 0, 1), _SEG7('3', 1, 1, 1, 1, 0, 0, 1), _SEG7('4', 0, 1, 1, 0, 0, 1, 1), _SEG7('5', 1, 0, 1, 1, 0, 1, 1), _SEG7('6', 1, 0, 1, 1, 1, 1, 1), _SEG7('7', 1, 1, 1, 0, 0, 0, 0), _SEG7('8', 1, 1, 1, 1, 1, 1, 1), _SEG7('9', 1, 1, 1, 1, 0, 1, 1),
#define _MAP_58_64_ASCII_SEG7_SYMBOL _SEG7(':', 0, 0, 0, 1, 0, 0, 1), _SEG7(';', 0, 0, 0, 1, 0, 0, 1), _SEG7('<', 1, 0, 0, 0, 0, 1, 1), _SEG7('=', 0, 0, 0, 1, 0, 0, 1), _SEG7('>', 1, 1, 0, 0, 0, 0, 1), _SEG7('?', 1, 1, 1, 0, 0, 1, 0), _SEG7('@', 1, 1, 0, 1, 1, 1, 1),
#define _MAP_65_90_ASCII_SEG7_ALPHA_UPPR _SEG7('A', 1, 1, 1, 0, 1, 1, 1), _SEG7('B', 1, 1, 1, 1, 1, 1, 1), _SEG7('C', 1, 0, 0, 1, 1, 1, 0), _SEG7('D', 1, 1, 1, 1, 1, 1, 0), _SEG7('E', 1, 0, 0, 1, 1, 1, 1), _SEG7('F', 1, 0, 0, 0, 1, 1, 1), _SEG7('G', 1, 1, 1, 1, 0, 1, 1), _SEG7('H', 0, 1, 1, 0, 1, 1, 1), _SEG7('I', 0, 1, 1, 0, 0, 0, 0), _SEG7('J', 0, 1, 1, 1, 0, 0, 0), _SEG7('K', 0, 1, 1, 0, 1, 1, 1), _SEG7('L', 0, 0, 0, 1, 1, 1, 0), _SEG7('M', 1, 1, 1, 0, 1, 1, 0), _SEG7('N', 1, 1, 1, 0, 1, 1, 0), _SEG7('O', 1, 1, 1, 1, 1, 1, 0), _SEG7('P', 1, 1, 0, 0, 1, 1, 1), _SEG7('Q', 1, 1, 1, 1, 1, 1, 0), _SEG7('R', 1, 1, 1, 0, 1, 1, 1), _SEG7('S', 1, 0, 1, 1, 0, 1, 1), _SEG7('T', 0, 0, 0, 1, 1, 1, 1), _SEG7('U', 0, 1, 1, 1, 1, 1, 0), _SEG7('V', 0, 1, 1, 1, 1, 1, 0), _SEG7('W', 0, 1, 1, 1, 1, 1, 1), _SEG7('X', 0, 1, 1, 0, 1, 1, 1), _SEG7('Y', 0, 1, 1, 0, 0, 1, 1), _SEG7('Z', 1, 1, 0, 1, 1, 0, 1),
#define _MAP_91_96_ASCII_SEG7_SYMBOL _SEG7('[', 1, 0, 0, 1, 1, 1, 0), _SEG7('\\', 0, 0, 1, 0, 0, 1, 1), _SEG7(']', 1, 1, 1, 1, 0, 0, 0), _SEG7('^', 1, 1, 0, 0, 0, 1, 0), _SEG7('_', 0, 0, 0, 1, 0, 0, 0), _SEG7('`', 0, 1, 0, 0, 0, 0, 0),
#define _MAP_97_122_ASCII_SEG7_ALPHA_LOWER _SEG7('A', 1, 1, 1, 0, 1, 1, 1), _SEG7('b', 0, 0, 1, 1, 1, 1, 1), _SEG7('c', 0, 0, 0, 1, 1, 0, 1), _SEG7('d', 0, 1, 1, 1, 1, 0, 1), _SEG7('E', 1, 0, 0, 1, 1, 1, 1), _SEG7('F', 1, 0, 0, 0, 1, 1, 1), _SEG7('G', 1, 1, 1, 1, 0, 1, 1), _SEG7('h', 0, 0, 1, 0, 1, 1, 1), _SEG7('i', 0, 0, 1, 0, 0, 0, 0), _SEG7('j', 0, 0, 1, 1, 0, 0, 0), _SEG7('k', 0, 0, 1, 0, 1, 1, 1), _SEG7('L', 0, 0, 0, 1, 1, 1, 0), _SEG7('M', 1, 1, 1, 0, 1, 1, 0), _SEG7('n', 0, 0, 1, 0, 1, 0, 1), _SEG7('o', 0, 0, 1, 1, 1, 0, 1), _SEG7('P', 1, 1, 0, 0, 1, 1, 1), _SEG7('q', 1, 1, 1, 0, 0, 1, 1), _SEG7('r', 0, 0, 0, 0, 1, 0, 1), _SEG7('S', 1, 0, 1, 1, 0, 1, 1), _SEG7('T', 0, 0, 0, 1, 1, 1, 1), _SEG7('u', 0, 0, 1, 1, 1, 0, 0), _SEG7('v', 0, 0, 1, 1, 1, 0, 0), _SEG7('W', 0, 1, 1, 1, 1, 1, 1), _SEG7('X', 0, 1, 1, 0, 1, 1, 1), _SEG7('y', 0, 1, 1, 1, 0, 1, 1), _SEG7('Z', 1, 1, 0, 1, 1, 0, 1),
#define _MAP_123_126_ASCII_SEG7_SYMBOL _SEG7('{', 1, 0, 0, 1, 1, 1, 0), _SEG7('|', 0, 0, 0, 0, 1, 1, 0), _SEG7('}', 1, 1, 1, 1, 0, 0, 0), _SEG7('~', 1, 0, 0, 0, 0, 0, 0),
#define MAP_ASCII7SEG_ALPHANUM _MAP_0_32_ASCII_SEG7_NON_PRINTABLE _MAP_33_47_ASCII_SEG7_SYMBOL _MAP_48_57_ASCII_SEG7_NUMERIC _MAP_58_64_ASCII_SEG7_SYMBOL _MAP_65_90_ASCII_SEG7_ALPHA_UPPR _MAP_91_96_ASCII_SEG7_SYMBOL _MAP_97_122_ASCII_SEG7_ALPHA_LOWER _MAP_123_126_ASCII_SEG7_SYMBOL
#define MAP_ASCII7SEG_ALPHANUM_LC _MAP_0_32_ASCII_SEG7_NON_PRINTABLE _MAP_33_47_ASCII_SEG7_SYMBOL _MAP_48_57_ASCII_SEG7_NUMERIC _MAP_58_64_ASCII_SEG7_SYMBOL _MAP_97_122_ASCII_SEG7_ALPHA_LOWER _MAP_91_96_ASCII_SEG7_SYMBOL _MAP_97_122_ASCII_SEG7_ALPHA_LOWER _MAP_123_126_ASCII_SEG7_SYMBOL
#define SEG7_DEFAULT_MAP(_name) SEG7_CONVERSION_MAP(_name, MAP_ASCII7SEG_ALPHANUM)
#endif
```