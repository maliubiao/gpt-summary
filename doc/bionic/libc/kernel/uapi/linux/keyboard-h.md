Response:
Let's break down the thought process for analyzing this header file.

**1. Initial Understanding & Context:**

* The first line tells us it's an auto-generated header file for keyboard definitions in the Linux kernel, specifically for the Android (bionic) environment.
* The `#ifndef _UAPI__LINUX_KEYBOARD_H` and `#define _UAPI__LINUX_KEYBOARD_H` are standard include guards to prevent multiple inclusions.
* The inclusion of `<linux/wait.h>` hints that keyboard-related operations might involve waiting for events.

**2. Identifying Core Functionality (High-Level):**

* **Defining Key Codes:** The vast majority of the file is a series of `#define` statements. These are clearly defining symbolic names for different keyboard keys and combinations.
* **Categorization of Keys:**  The `KT_*` macros (like `KT_FN`, `KT_SPEC`, `KT_PAD`) suggest a way to categorize keys.
* **Shift State Definitions:**  `KG_*` macros define the various shift/control/alt states.
* **Combining Category and Value:** The `K(t,v)` macro and related `KTYP(x)` and `KVAL(x)` macros indicate a way to represent a key by combining its type and value.

**3. Deeper Dive into Specific Elements:**

* **`KG_*` Macros:** These are clearly about keyboard modifiers (Shift, Ctrl, Alt). The numeric values are likely bit flags or indices used internally. The `NR_SHIFT` constant probably indicates the total number of such modifiers.
* **`NR_KEYS`:** 256 suggests a maximum number of distinct keys that can be represented.
* **`MAX_NR_KEYMAPS` and `MAX_NR_OF_USER_KEYMAPS`:** These hint at the possibility of different keyboard layouts or user-defined mappings.
* **`MAX_NR_FUNC`:**  Relates to the number of function key definitions.
* **`KT_*` Macros:** This is the core key categorization. It's important to understand what each category represents:
    * `KT_LATIN`:  Likely standard alphanumeric keys.
    * `KT_FN`: Function keys (F1, F2, etc.).
    * `KT_SPEC`: Special keys (Enter, Caps Lock, etc.).
    * `KT_PAD`: Numpad keys.
    * `KT_DEAD`: Dead keys (for composing accented characters).
    * `KT_CONS`: Console-related keys.
    * `KT_CUR`: Cursor keys (Up, Down, Left, Right).
    * `KT_SHIFT`: Modifier keys (like Shift, Ctrl).
    * `KT_META`:  Often used for Alt or Windows keys. *Self-correction:  Looking at the `K_ALT` and `K_ALTGR` definitions, `KT_META` isn't explicitly used in the simple key definitions here. It might be used in other parts of the kernel or for more advanced keyboard handling.*
    * `KT_ASCII`:  Likely used for generating ASCII characters directly.
    * `KT_LOCK`: Keys that toggle a state (Caps Lock, Num Lock).
    * `KT_LETTER`:  Specifically for letter keys.
    * `KT_SLOCK`:  Sticky lock keys?  (Needs further investigation if this were a real debugging scenario).
    * `KT_DEAD2`, `KT_BRL`:  More specialized key types. `KT_BRL` probably relates to Braille input.
* **`K(t, v)` Macro:**  The bitwise left shift (`<< 8`) and bitwise OR (`|`) operation are a common way to pack two values into a single integer. The top 8 bits represent the type, and the bottom 8 bits represent the value.
* **`K_*` Constants:** These are concrete examples of combining key types and values. For instance, `K_F1` is a function key (KT_FN) with value 0. The sheer number of these constants highlights the extensive nature of keyboard mapping.

**4. Connecting to Android:**

* **Input System:** This header file is a foundational part of Android's input system. When a user presses a key, the hardware generates a scan code. The kernel driver translates this scan code into an event, and this header file defines the symbolic representation of those events.
* **Event Handling:**  Android's framework uses these definitions to interpret keyboard input within applications.
* **NDK:**  NDK developers might indirectly encounter these definitions if they are working with low-level input handling or if they need to map keyboard events.

**5. Considering Dynamic Linking (and realizing its irrelevance here):**

*  The prompt specifically asks about dynamic linking. However, this is a *header file*. Header files are used during compilation, not during runtime linking. There are no function definitions or external symbols that would involve the dynamic linker. Therefore, no SO layout or linking process is directly relevant *to this specific file*. It's crucial to recognize this distinction. If the prompt had provided C source code, dynamic linking would be a factor.

**6. Thinking About Libc Functions and Implementation (and recognizing the header's limitation):**

*  Again, this is a *header file*. It defines *constants*, not *functions*. Therefore, there are no libc functions defined here, and no implementation details to discuss.

**7. User Errors and Frida Hooking:**

* **User Errors:**  Misunderstanding the key codes could lead to incorrect mapping in configuration files or applications.
* **Frida:** Frida can be used to intercept and modify the flow of execution. We can hook into system calls or framework methods that handle keyboard events to observe how these constants are used.

**8. Structuring the Response:**

* Start with a summary of the file's purpose.
* List the main functionalities derived from the analysis.
* Explain the connection to Android, providing concrete examples.
* Explicitly address (and clarify) why dynamic linking and libc function implementation aren't directly applicable to a header file.
* Provide examples of user errors and Frida usage.
* Explain the path from hardware to the application layer.

**Self-Correction/Refinement During the Process:**

* Initially, I might have thought `KT_META` was a direct mapping to Alt keys, but reviewing the specific `K_ALT` and `K_ALTGR` definitions clarifies that it's not used in the simple key definitions here.
* I had to be careful to distinguish between the *definitions* in the header file and the *implementation* in the kernel or libraries.
* Recognizing that this is just a header file is crucial for answering questions about libc functions and dynamic linking correctly.

By following this systematic approach, analyzing the definitions, understanding the context, and critically evaluating the prompt's questions, I can generate a comprehensive and accurate response.
这个文件 `bionic/libc/kernel/uapi/linux/keyboard.h` 是 Android Bionic 库中的一个头文件，它直接来源于 Linux 内核的 UAPI (用户空间应用程序接口) 部分。这意味着它定义了用户空间程序可以使用的与键盘相关的常量和宏定义。

**它的功能：**

1. **定义键盘事件的常量：**  这个头文件定义了各种代表键盘按键和组合的常量，例如：
    * **修饰键 (Modifier Keys):** `KG_SHIFT`, `KG_CTRL`, `KG_ALT`, `KG_ALTGR` 等，以及它们的左右两侧版本。
    * **功能键 (Function Keys):** `K_F1` 到 `K_F245` 等。
    * **特殊键 (Special Keys):** `K_ENTER`, `K_CAPS`, `K_NUM` 等。
    * **小键盘 (Keypad Keys):** `K_P0` 到 `K_PPARENR` 等。
    * **组合键 (Dead Keys):** `K_DGRAVE`, `K_DACUTE` 等，用于输入带音标的字符。
    * **光标键 (Cursor Keys):** `K_DOWN`, `K_LEFT`, `K_RIGHT`, `K_UP`.
    * **ASCII 键:** `K_ASC0` 到 `K_HEXf`，代表 ASCII 字符。
    * **锁定键 (Lock Keys):** `K_SHIFTLOCK`, `K_CTRLLOCK` 等。
    * **Braille 键:** `K_BRL_BLANK` 到 `K_BRL_DOT10`。

2. **定义键的类型：** 使用 `KT_*` 前缀定义了不同类型的键，例如：
    * `KT_FN`: 功能键
    * `KT_SPEC`: 特殊键
    * `KT_PAD`: 小键盘
    * `KT_DEAD`: 组合键
    * `KT_CUR`: 光标键
    * `KT_SHIFT`: 修饰键
    * `KT_LOCK`: 锁定键
    * `KT_ASCII`: ASCII 键

3. **提供宏来组合和解析键值：**
    * `K(t,v)`: 将键类型 `t` 和键值 `v` 组合成一个整数表示。
    * `KTYP(x)`: 从键值 `x` 中提取键类型。
    * `KVAL(x)`: 从键值 `x` 中提取键值。

4. **定义键盘相关的常量：** 例如 `NR_SHIFT` (修饰键的数量), `NR_KEYS` (总键数), `MAX_NR_KEYMAPS` (最大键盘映射数) 等。

**与 Android 功能的关系及举例：**

这个头文件直接关系到 Android 如何处理用户的键盘输入。当用户在 Android 设备上连接了物理键盘，或者使用屏幕键盘时，系统底层会产生键盘事件。这些事件的表示就依赖于这里定义的常量。

* **举例：** 当用户按下 Shift 键时，内核可能会产生一个事件，其内部表示会涉及到 `KG_SHIFT` 这个常量。当用户按下 F1 键时，事件的表示会用到 `K_F1` 这个常量。

* **Android Framework 的使用：** Android Framework 中的 InputManagerService 等组件会接收来自内核的键盘事件，并根据这些事件携带的键码（这些键码就是这个头文件中定义的常量）来判断用户按下了哪个键。Framework 可以将这些事件进一步传递给应用程序。

* **NDK 开发的使用：** NDK (Native Development Kit) 开发者如果需要直接处理键盘输入，例如在开发游戏或者需要底层控制的应用中，可能会使用到这些常量。他们可以通过监听特定的键盘事件，并比较事件的键码与这里定义的常量，来判断用户的输入。

**详细解释每一个 libc 函数的功能是如何实现的：**

**关键点：这个文件中并没有定义 libc 函数。**  它是一个头文件，只包含宏定义和常量。它被用来让其他 C/C++ 代码能够理解和使用 Linux 内核定义的键盘事件。

libc 中与键盘输入相关的函数通常是用来打开设备文件（例如 `/dev/input/event*`），读取键盘事件结构体（`input_event`），以及处理这些事件。`keyboard.h` 中定义的常量会被用来解析 `input_event` 结构体中的 `code` 字段。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

**关键点：这个头文件本身不涉及动态链接。**  它只是定义常量。动态链接发生在可执行文件或共享库加载时，将程序中引用的符号链接到实际的库代码。

如果 NDK 开发者使用到这个头文件，他们的代码最终会被编译成共享库 (`.so`)。这个共享库可能会链接到其他的 Android 系统库。但是，`keyboard.h` 自身不参与动态链接的过程。

**如果做了逻辑推理，请给出假设输入与输出：**

假设一个用户按下了 Shift + A 键。

* **输入 (从硬件角度):** 键盘硬件会产生一系列扫描码。
* **内核处理:** Linux 内核的键盘驱动程序会接收这些扫描码，并将其转换为 `input_event` 结构体。对于 Shift 键，事件的 `type` 可能是 `EV_KEY`，`code` 可能对应 `KEY_LEFTSHIFT` 或 `KEY_RIGHTSHIFT` (在 `input-event-codes.h` 中定义，但概念类似)，`value` 可能为 1 (按下)。对于 A 键，`code` 可能对应 `KEY_A`，`value` 可能为 1。
* **用户空间 (通过 `/dev/input/event*` 读取):** 用户空间的程序（例如 Android 的 InputReader）会读取到这些 `input_event` 结构体。
* **使用 `keyboard.h` 解析:**  虽然 `keyboard.h` 中没有直接对应 `KEY_A` 这样的底层键码，但它定义了高层次的键值。如果系统进一步将这个事件抽象为字符输入，会考虑到 Shift 键的状态。  例如，最终可能应用程序会接收到代表大写字母 'A' 的字符编码。

**如果涉及用户或者编程常见的使用错误，请举例说明：**

1. **错误地比较键值：** 开发者可能错误地直接比较从 `input_event` 中读取的 `code` 值与 `keyboard.h` 中定义的常量。实际上，内核事件的 `code` 值通常对应 `input-event-codes.h` 中定义的 `KEY_*` 常量，而 `keyboard.h` 中的常量是更上层的抽象表示。需要理解这两层之间的映射关系。

2. **假设所有键盘布局一致：** 开发者可能会假设所有键盘都遵循相同的布局和键码。实际上，不同的键盘布局（例如 QWERTY, AZERTY）会产生不同的扫描码和事件。虽然 `keyboard.h` 提供了一定的抽象，但在处理特定于布局的问题时仍然需要注意。

3. **忽略修饰键状态：**  在处理字符输入时，开发者可能忘记检查修饰键（Shift, Ctrl, Alt）的状态，导致无法正确识别用户想要输入的字符。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到达 `keyboard.h` 的路径：**

1. **硬件事件:** 用户按下键盘上的一个键。
2. **内核驱动:** 键盘硬件产生中断，Linux 内核的键盘驱动程序（例如 `drivers/input/keyboard/`) 接收到中断信号和扫描码。
3. **事件生成:** 驱动程序将扫描码转换为 `input_event` 结构体，其中 `type` 为 `EV_KEY`，`code` 为 `KEY_*` 常量 (定义在 `input-event-codes.h`)，`value` 表示按键状态（按下/释放）。
4. **`/dev/input/event*`:** 这些 `input_event` 结构体被写入到 `/dev/input/event*` 设备文件中。
5. **InputReader (Android Framework):** Android Framework 的 `InputReader` 进程会监听这些设备文件。
6. **Event 转换:** `InputReader` 读取 `input_event`，并将其转换为 Android Framework 内部的 KeyEvent 对象。在这个转换过程中，可能会涉及到对键码的映射和处理，`keyboard.h` 中定义的常量可能在更高的层次上被用来表示和识别这些键。
7. **InputDispatcher (Android Framework):** `InputDispatcher` 负责将 `KeyEvent` 分发到具有焦点的窗口。
8. **应用程序:** 应用程序最终接收到 `KeyEvent` 对象，可以通过 `KeyEvent` 的方法（例如 `getKeyCode()`, `getModifiers()`) 获取按下的键和修饰键状态。 `getKeyCode()` 的返回值会对应 Android SDK 中 `KeyEvent` 类定义的常量，这些常量在概念上与 `keyboard.h` 中的常量有联系，但可能经过了进一步的抽象和映射。

**NDK 到达 `keyboard.h` 的路径：**

1. **NDK 应用监听事件:** NDK 应用可以通过 Android 的 Java Framework 接收键盘事件，并通过 JNI 传递到 Native 层。
2. **直接读取 `/dev/input/event*`:**  NDK 应用也可以选择绕过 Framework，直接打开 `/dev/input/event*` 设备文件，读取底层的 `input_event` 结构体。
3. **解析 `input_event`:**  在这种情况下，NDK 代码需要解析 `input_event` 结构体中的 `code` 值。虽然直接比较的是 `input-event-codes.h` 中的 `KEY_*` 常量，但理解 `keyboard.h` 中更高层次的键位定义有助于进行更复杂的输入处理。

**Frida Hook 示例：**

以下是一个使用 Frida Hook Android Framework 中 `InputReader` 来查看键盘事件处理的示例：

```python
import frida
import sys

package_name = "com.android.systemui"  # 例如，Hook 系统界面进程

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Received: {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"进程 '{package_name}' 未找到，请确保设备已连接并运行该进程。")
    sys.exit()

script_code = """
    Java.perform(function() {
        var InputReader = Java.use("android.server.input.InputReader");
        var KeyEvent = Java.use("android.view.KeyEvent");

        InputReader.processKey.implementation = function(ev) {
            console.log("[Frida] InputReader.processKey called!");
            if (ev) {
                var action = ev.getAction();
                var keyCode = ev.getKeyCode();
                var modifiers = ev.getModifiers();
                var keyChar = String.fromCharCode(keyCode); // 尝试转换为字符

                console.log("[Frida] KeyEvent: Action=" + action + ", KeyCode=" + keyCode + " (" + keyChar + "), Modifiers=" + modifiers);
            } else {
                console.log("[Frida] KeyEvent is null");
            }
            this.processKey(ev); // 调用原始方法
        };
    });
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**代码解释：**

1. **导入 Frida 库。**
2. **指定要 Hook 的进程 (例如 `com.android.systemui`)。**
3. **定义消息处理函数 `on_message`。**
4. **连接到目标进程。**
5. **编写 Frida 脚本：**
   * 使用 `Java.perform` 进入 Dalvik 虚拟机环境。
   * 获取 `android.server.input.InputReader` 和 `android.view.KeyEvent` 类的引用。
   * Hook `InputReader.processKey` 方法，该方法是 Framework 处理键盘事件的关键入口点。
   * 在 Hook 的实现中，打印日志，包括 KeyEvent 的 Action、KeyCode 和 Modifiers。
   * 尝试将 KeyCode 转换为字符。
   * 调用原始的 `processKey` 方法，以保证正常的事件处理流程。
6. **创建并加载 Frida 脚本。**
7. **保持脚本运行，直到用户按下 Ctrl+C。**

运行此脚本后，当你在连接的 Android 设备上按下键盘按键时，Frida 将会拦截 `InputReader.processKey` 的调用，并打印出相关的键盘事件信息，包括 KeyCode。你可以通过 KeyCode 的值来推断它与 `keyboard.h` 中定义的常量之间的关系 (尽管 Framework 通常使用 `android.view.KeyEvent` 中定义的常量)。

**请注意：**  直接 Hook 底层的内核键盘驱动通常需要 root 权限和更底层的工具。Frida 通常在用户空间工作，因此 Hook Android Framework 的方式更为常见。

总结来说，`bionic/libc/kernel/uapi/linux/keyboard.h` 是 Android 系统理解和处理键盘输入的基础，它定义了用户空间可以使用的键盘事件常量，连接了底层的内核事件和上层的 Framework 以及 NDK 应用。 虽然它本身不包含 libc 函数或动态链接逻辑，但它定义的常量在整个键盘输入处理流程中扮演着重要的角色。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/linux/keyboard.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI__LINUX_KEYBOARD_H
#define _UAPI__LINUX_KEYBOARD_H
#include <linux/wait.h>
#define KG_SHIFT 0
#define KG_CTRL 2
#define KG_ALT 3
#define KG_ALTGR 1
#define KG_SHIFTL 4
#define KG_KANASHIFT 4
#define KG_SHIFTR 5
#define KG_CTRLL 6
#define KG_CTRLR 7
#define KG_CAPSSHIFT 8
#define NR_SHIFT 9
#define NR_KEYS 256
#define MAX_NR_KEYMAPS 256
#define MAX_NR_OF_USER_KEYMAPS 256
#define MAX_NR_FUNC 256
#define KT_LATIN 0
#define KT_FN 1
#define KT_SPEC 2
#define KT_PAD 3
#define KT_DEAD 4
#define KT_CONS 5
#define KT_CUR 6
#define KT_SHIFT 7
#define KT_META 8
#define KT_ASCII 9
#define KT_LOCK 10
#define KT_LETTER 11
#define KT_SLOCK 12
#define KT_DEAD2 13
#define KT_BRL 14
#define K(t,v) (((t) << 8) | (v))
#define KTYP(x) ((x) >> 8)
#define KVAL(x) ((x) & 0xff)
#define K_F1 K(KT_FN, 0)
#define K_F2 K(KT_FN, 1)
#define K_F3 K(KT_FN, 2)
#define K_F4 K(KT_FN, 3)
#define K_F5 K(KT_FN, 4)
#define K_F6 K(KT_FN, 5)
#define K_F7 K(KT_FN, 6)
#define K_F8 K(KT_FN, 7)
#define K_F9 K(KT_FN, 8)
#define K_F10 K(KT_FN, 9)
#define K_F11 K(KT_FN, 10)
#define K_F12 K(KT_FN, 11)
#define K_F13 K(KT_FN, 12)
#define K_F14 K(KT_FN, 13)
#define K_F15 K(KT_FN, 14)
#define K_F16 K(KT_FN, 15)
#define K_F17 K(KT_FN, 16)
#define K_F18 K(KT_FN, 17)
#define K_F19 K(KT_FN, 18)
#define K_F20 K(KT_FN, 19)
#define K_FIND K(KT_FN, 20)
#define K_INSERT K(KT_FN, 21)
#define K_REMOVE K(KT_FN, 22)
#define K_SELECT K(KT_FN, 23)
#define K_PGUP K(KT_FN, 24)
#define K_PGDN K(KT_FN, 25)
#define K_MACRO K(KT_FN, 26)
#define K_HELP K(KT_FN, 27)
#define K_DO K(KT_FN, 28)
#define K_PAUSE K(KT_FN, 29)
#define K_F21 K(KT_FN, 30)
#define K_F22 K(KT_FN, 31)
#define K_F23 K(KT_FN, 32)
#define K_F24 K(KT_FN, 33)
#define K_F25 K(KT_FN, 34)
#define K_F26 K(KT_FN, 35)
#define K_F27 K(KT_FN, 36)
#define K_F28 K(KT_FN, 37)
#define K_F29 K(KT_FN, 38)
#define K_F30 K(KT_FN, 39)
#define K_F31 K(KT_FN, 40)
#define K_F32 K(KT_FN, 41)
#define K_F33 K(KT_FN, 42)
#define K_F34 K(KT_FN, 43)
#define K_F35 K(KT_FN, 44)
#define K_F36 K(KT_FN, 45)
#define K_F37 K(KT_FN, 46)
#define K_F38 K(KT_FN, 47)
#define K_F39 K(KT_FN, 48)
#define K_F40 K(KT_FN, 49)
#define K_F41 K(KT_FN, 50)
#define K_F42 K(KT_FN, 51)
#define K_F43 K(KT_FN, 52)
#define K_F44 K(KT_FN, 53)
#define K_F45 K(KT_FN, 54)
#define K_F46 K(KT_FN, 55)
#define K_F47 K(KT_FN, 56)
#define K_F48 K(KT_FN, 57)
#define K_F49 K(KT_FN, 58)
#define K_F50 K(KT_FN, 59)
#define K_F51 K(KT_FN, 60)
#define K_F52 K(KT_FN, 61)
#define K_F53 K(KT_FN, 62)
#define K_F54 K(KT_FN, 63)
#define K_F55 K(KT_FN, 64)
#define K_F56 K(KT_FN, 65)
#define K_F57 K(KT_FN, 66)
#define K_F58 K(KT_FN, 67)
#define K_F59 K(KT_FN, 68)
#define K_F60 K(KT_FN, 69)
#define K_F61 K(KT_FN, 70)
#define K_F62 K(KT_FN, 71)
#define K_F63 K(KT_FN, 72)
#define K_F64 K(KT_FN, 73)
#define K_F65 K(KT_FN, 74)
#define K_F66 K(KT_FN, 75)
#define K_F67 K(KT_FN, 76)
#define K_F68 K(KT_FN, 77)
#define K_F69 K(KT_FN, 78)
#define K_F70 K(KT_FN, 79)
#define K_F71 K(KT_FN, 80)
#define K_F72 K(KT_FN, 81)
#define K_F73 K(KT_FN, 82)
#define K_F74 K(KT_FN, 83)
#define K_F75 K(KT_FN, 84)
#define K_F76 K(KT_FN, 85)
#define K_F77 K(KT_FN, 86)
#define K_F78 K(KT_FN, 87)
#define K_F79 K(KT_FN, 88)
#define K_F80 K(KT_FN, 89)
#define K_F81 K(KT_FN, 90)
#define K_F82 K(KT_FN, 91)
#define K_F83 K(KT_FN, 92)
#define K_F84 K(KT_FN, 93)
#define K_F85 K(KT_FN, 94)
#define K_F86 K(KT_FN, 95)
#define K_F87 K(KT_FN, 96)
#define K_F88 K(KT_FN, 97)
#define K_F89 K(KT_FN, 98)
#define K_F90 K(KT_FN, 99)
#define K_F91 K(KT_FN, 100)
#define K_F92 K(KT_FN, 101)
#define K_F93 K(KT_FN, 102)
#define K_F94 K(KT_FN, 103)
#define K_F95 K(KT_FN, 104)
#define K_F96 K(KT_FN, 105)
#define K_F97 K(KT_FN, 106)
#define K_F98 K(KT_FN, 107)
#define K_F99 K(KT_FN, 108)
#define K_F100 K(KT_FN, 109)
#define K_F101 K(KT_FN, 110)
#define K_F102 K(KT_FN, 111)
#define K_F103 K(KT_FN, 112)
#define K_F104 K(KT_FN, 113)
#define K_F105 K(KT_FN, 114)
#define K_F106 K(KT_FN, 115)
#define K_F107 K(KT_FN, 116)
#define K_F108 K(KT_FN, 117)
#define K_F109 K(KT_FN, 118)
#define K_F110 K(KT_FN, 119)
#define K_F111 K(KT_FN, 120)
#define K_F112 K(KT_FN, 121)
#define K_F113 K(KT_FN, 122)
#define K_F114 K(KT_FN, 123)
#define K_F115 K(KT_FN, 124)
#define K_F116 K(KT_FN, 125)
#define K_F117 K(KT_FN, 126)
#define K_F118 K(KT_FN, 127)
#define K_F119 K(KT_FN, 128)
#define K_F120 K(KT_FN, 129)
#define K_F121 K(KT_FN, 130)
#define K_F122 K(KT_FN, 131)
#define K_F123 K(KT_FN, 132)
#define K_F124 K(KT_FN, 133)
#define K_F125 K(KT_FN, 134)
#define K_F126 K(KT_FN, 135)
#define K_F127 K(KT_FN, 136)
#define K_F128 K(KT_FN, 137)
#define K_F129 K(KT_FN, 138)
#define K_F130 K(KT_FN, 139)
#define K_F131 K(KT_FN, 140)
#define K_F132 K(KT_FN, 141)
#define K_F133 K(KT_FN, 142)
#define K_F134 K(KT_FN, 143)
#define K_F135 K(KT_FN, 144)
#define K_F136 K(KT_FN, 145)
#define K_F137 K(KT_FN, 146)
#define K_F138 K(KT_FN, 147)
#define K_F139 K(KT_FN, 148)
#define K_F140 K(KT_FN, 149)
#define K_F141 K(KT_FN, 150)
#define K_F142 K(KT_FN, 151)
#define K_F143 K(KT_FN, 152)
#define K_F144 K(KT_FN, 153)
#define K_F145 K(KT_FN, 154)
#define K_F146 K(KT_FN, 155)
#define K_F147 K(KT_FN, 156)
#define K_F148 K(KT_FN, 157)
#define K_F149 K(KT_FN, 158)
#define K_F150 K(KT_FN, 159)
#define K_F151 K(KT_FN, 160)
#define K_F152 K(KT_FN, 161)
#define K_F153 K(KT_FN, 162)
#define K_F154 K(KT_FN, 163)
#define K_F155 K(KT_FN, 164)
#define K_F156 K(KT_FN, 165)
#define K_F157 K(KT_FN, 166)
#define K_F158 K(KT_FN, 167)
#define K_F159 K(KT_FN, 168)
#define K_F160 K(KT_FN, 169)
#define K_F161 K(KT_FN, 170)
#define K_F162 K(KT_FN, 171)
#define K_F163 K(KT_FN, 172)
#define K_F164 K(KT_FN, 173)
#define K_F165 K(KT_FN, 174)
#define K_F166 K(KT_FN, 175)
#define K_F167 K(KT_FN, 176)
#define K_F168 K(KT_FN, 177)
#define K_F169 K(KT_FN, 178)
#define K_F170 K(KT_FN, 179)
#define K_F171 K(KT_FN, 180)
#define K_F172 K(KT_FN, 181)
#define K_F173 K(KT_FN, 182)
#define K_F174 K(KT_FN, 183)
#define K_F175 K(KT_FN, 184)
#define K_F176 K(KT_FN, 185)
#define K_F177 K(KT_FN, 186)
#define K_F178 K(KT_FN, 187)
#define K_F179 K(KT_FN, 188)
#define K_F180 K(KT_FN, 189)
#define K_F181 K(KT_FN, 190)
#define K_F182 K(KT_FN, 191)
#define K_F183 K(KT_FN, 192)
#define K_F184 K(KT_FN, 193)
#define K_F185 K(KT_FN, 194)
#define K_F186 K(KT_FN, 195)
#define K_F187 K(KT_FN, 196)
#define K_F188 K(KT_FN, 197)
#define K_F189 K(KT_FN, 198)
#define K_F190 K(KT_FN, 199)
#define K_F191 K(KT_FN, 200)
#define K_F192 K(KT_FN, 201)
#define K_F193 K(KT_FN, 202)
#define K_F194 K(KT_FN, 203)
#define K_F195 K(KT_FN, 204)
#define K_F196 K(KT_FN, 205)
#define K_F197 K(KT_FN, 206)
#define K_F198 K(KT_FN, 207)
#define K_F199 K(KT_FN, 208)
#define K_F200 K(KT_FN, 209)
#define K_F201 K(KT_FN, 210)
#define K_F202 K(KT_FN, 211)
#define K_F203 K(KT_FN, 212)
#define K_F204 K(KT_FN, 213)
#define K_F205 K(KT_FN, 214)
#define K_F206 K(KT_FN, 215)
#define K_F207 K(KT_FN, 216)
#define K_F208 K(KT_FN, 217)
#define K_F209 K(KT_FN, 218)
#define K_F210 K(KT_FN, 219)
#define K_F211 K(KT_FN, 220)
#define K_F212 K(KT_FN, 221)
#define K_F213 K(KT_FN, 222)
#define K_F214 K(KT_FN, 223)
#define K_F215 K(KT_FN, 224)
#define K_F216 K(KT_FN, 225)
#define K_F217 K(KT_FN, 226)
#define K_F218 K(KT_FN, 227)
#define K_F219 K(KT_FN, 228)
#define K_F220 K(KT_FN, 229)
#define K_F221 K(KT_FN, 230)
#define K_F222 K(KT_FN, 231)
#define K_F223 K(KT_FN, 232)
#define K_F224 K(KT_FN, 233)
#define K_F225 K(KT_FN, 234)
#define K_F226 K(KT_FN, 235)
#define K_F227 K(KT_FN, 236)
#define K_F228 K(KT_FN, 237)
#define K_F229 K(KT_FN, 238)
#define K_F230 K(KT_FN, 239)
#define K_F231 K(KT_FN, 240)
#define K_F232 K(KT_FN, 241)
#define K_F233 K(KT_FN, 242)
#define K_F234 K(KT_FN, 243)
#define K_F235 K(KT_FN, 244)
#define K_F236 K(KT_FN, 245)
#define K_F237 K(KT_FN, 246)
#define K_F238 K(KT_FN, 247)
#define K_F239 K(KT_FN, 248)
#define K_F240 K(KT_FN, 249)
#define K_F241 K(KT_FN, 250)
#define K_F242 K(KT_FN, 251)
#define K_F243 K(KT_FN, 252)
#define K_F244 K(KT_FN, 253)
#define K_F245 K(KT_FN, 254)
#define K_UNDO K(KT_FN, 255)
#define K_HOLE K(KT_SPEC, 0)
#define K_ENTER K(KT_SPEC, 1)
#define K_SH_REGS K(KT_SPEC, 2)
#define K_SH_MEM K(KT_SPEC, 3)
#define K_SH_STAT K(KT_SPEC, 4)
#define K_BREAK K(KT_SPEC, 5)
#define K_CONS K(KT_SPEC, 6)
#define K_CAPS K(KT_SPEC, 7)
#define K_NUM K(KT_SPEC, 8)
#define K_HOLD K(KT_SPEC, 9)
#define K_SCROLLFORW K(KT_SPEC, 10)
#define K_SCROLLBACK K(KT_SPEC, 11)
#define K_BOOT K(KT_SPEC, 12)
#define K_CAPSON K(KT_SPEC, 13)
#define K_COMPOSE K(KT_SPEC, 14)
#define K_SAK K(KT_SPEC, 15)
#define K_DECRCONSOLE K(KT_SPEC, 16)
#define K_INCRCONSOLE K(KT_SPEC, 17)
#define K_SPAWNCONSOLE K(KT_SPEC, 18)
#define K_BARENUMLOCK K(KT_SPEC, 19)
#define K_ALLOCATED K(KT_SPEC, 126)
#define K_NOSUCHMAP K(KT_SPEC, 127)
#define K_P0 K(KT_PAD, 0)
#define K_P1 K(KT_PAD, 1)
#define K_P2 K(KT_PAD, 2)
#define K_P3 K(KT_PAD, 3)
#define K_P4 K(KT_PAD, 4)
#define K_P5 K(KT_PAD, 5)
#define K_P6 K(KT_PAD, 6)
#define K_P7 K(KT_PAD, 7)
#define K_P8 K(KT_PAD, 8)
#define K_P9 K(KT_PAD, 9)
#define K_PPLUS K(KT_PAD, 10)
#define K_PMINUS K(KT_PAD, 11)
#define K_PSTAR K(KT_PAD, 12)
#define K_PSLASH K(KT_PAD, 13)
#define K_PENTER K(KT_PAD, 14)
#define K_PCOMMA K(KT_PAD, 15)
#define K_PDOT K(KT_PAD, 16)
#define K_PPLUSMINUS K(KT_PAD, 17)
#define K_PPARENL K(KT_PAD, 18)
#define K_PPARENR K(KT_PAD, 19)
#define NR_PAD 20
#define K_DGRAVE K(KT_DEAD, 0)
#define K_DACUTE K(KT_DEAD, 1)
#define K_DCIRCM K(KT_DEAD, 2)
#define K_DTILDE K(KT_DEAD, 3)
#define K_DDIERE K(KT_DEAD, 4)
#define K_DCEDIL K(KT_DEAD, 5)
#define K_DMACRON K(KT_DEAD, 6)
#define K_DBREVE K(KT_DEAD, 7)
#define K_DABDOT K(KT_DEAD, 8)
#define K_DABRING K(KT_DEAD, 9)
#define K_DDBACUTE K(KT_DEAD, 10)
#define K_DCARON K(KT_DEAD, 11)
#define K_DOGONEK K(KT_DEAD, 12)
#define K_DIOTA K(KT_DEAD, 13)
#define K_DVOICED K(KT_DEAD, 14)
#define K_DSEMVOICED K(KT_DEAD, 15)
#define K_DBEDOT K(KT_DEAD, 16)
#define K_DHOOK K(KT_DEAD, 17)
#define K_DHORN K(KT_DEAD, 18)
#define K_DSTROKE K(KT_DEAD, 19)
#define K_DABCOMMA K(KT_DEAD, 20)
#define K_DABREVCOMMA K(KT_DEAD, 21)
#define K_DDBGRAVE K(KT_DEAD, 22)
#define K_DINVBREVE K(KT_DEAD, 23)
#define K_DBECOMMA K(KT_DEAD, 24)
#define K_DCURRENCY K(KT_DEAD, 25)
#define K_DGREEK K(KT_DEAD, 26)
#define NR_DEAD 27
#define K_DOWN K(KT_CUR, 0)
#define K_LEFT K(KT_CUR, 1)
#define K_RIGHT K(KT_CUR, 2)
#define K_UP K(KT_CUR, 3)
#define K_SHIFT K(KT_SHIFT, KG_SHIFT)
#define K_CTRL K(KT_SHIFT, KG_CTRL)
#define K_ALT K(KT_SHIFT, KG_ALT)
#define K_ALTGR K(KT_SHIFT, KG_ALTGR)
#define K_SHIFTL K(KT_SHIFT, KG_SHIFTL)
#define K_SHIFTR K(KT_SHIFT, KG_SHIFTR)
#define K_CTRLL K(KT_SHIFT, KG_CTRLL)
#define K_CTRLR K(KT_SHIFT, KG_CTRLR)
#define K_CAPSSHIFT K(KT_SHIFT, KG_CAPSSHIFT)
#define K_ASC0 K(KT_ASCII, 0)
#define K_ASC1 K(KT_ASCII, 1)
#define K_ASC2 K(KT_ASCII, 2)
#define K_ASC3 K(KT_ASCII, 3)
#define K_ASC4 K(KT_ASCII, 4)
#define K_ASC5 K(KT_ASCII, 5)
#define K_ASC6 K(KT_ASCII, 6)
#define K_ASC7 K(KT_ASCII, 7)
#define K_ASC8 K(KT_ASCII, 8)
#define K_ASC9 K(KT_ASCII, 9)
#define K_HEX0 K(KT_ASCII, 10)
#define K_HEX1 K(KT_ASCII, 11)
#define K_HEX2 K(KT_ASCII, 12)
#define K_HEX3 K(KT_ASCII, 13)
#define K_HEX4 K(KT_ASCII, 14)
#define K_HEX5 K(KT_ASCII, 15)
#define K_HEX6 K(KT_ASCII, 16)
#define K_HEX7 K(KT_ASCII, 17)
#define K_HEX8 K(KT_ASCII, 18)
#define K_HEX9 K(KT_ASCII, 19)
#define K_HEXa K(KT_ASCII, 20)
#define K_HEXb K(KT_ASCII, 21)
#define K_HEXc K(KT_ASCII, 22)
#define K_HEXd K(KT_ASCII, 23)
#define K_HEXe K(KT_ASCII, 24)
#define K_HEXf K(KT_ASCII, 25)
#define NR_ASCII 26
#define K_SHIFTLOCK K(KT_LOCK, KG_SHIFT)
#define K_CTRLLOCK K(KT_LOCK, KG_CTRL)
#define K_ALTLOCK K(KT_LOCK, KG_ALT)
#define K_ALTGRLOCK K(KT_LOCK, KG_ALTGR)
#define K_SHIFTLLOCK K(KT_LOCK, KG_SHIFTL)
#define K_SHIFTRLOCK K(KT_LOCK, KG_SHIFTR)
#define K_CTRLLLOCK K(KT_LOCK, KG_CTRLL)
#define K_CTRLRLOCK K(KT_LOCK, KG_CTRLR)
#define K_CAPSSHIFTLOCK K(KT_LOCK, KG_CAPSSHIFT)
#define K_SHIFT_SLOCK K(KT_SLOCK, KG_SHIFT)
#define K_CTRL_SLOCK K(KT_SLOCK, KG_CTRL)
#define K_ALT_SLOCK K(KT_SLOCK, KG_ALT)
#define K_ALTGR_SLOCK K(KT_SLOCK, KG_ALTGR)
#define K_SHIFTL_SLOCK K(KT_SLOCK, KG_SHIFTL)
#define K_SHIFTR_SLOCK K(KT_SLOCK, KG_SHIFTR)
#define K_CTRLL_SLOCK K(KT_SLOCK, KG_CTRLL)
#define K_CTRLR_SLOCK K(KT_SLOCK, KG_CTRLR)
#define K_CAPSSHIFT_SLOCK K(KT_SLOCK, KG_CAPSSHIFT)
#define NR_LOCK 9
#define K_BRL_BLANK K(KT_BRL, 0)
#define K_BRL_DOT1 K(KT_BRL, 1)
#define K_BRL_DOT2 K(KT_BRL, 2)
#define K_BRL_DOT3 K(KT_BRL, 3)
#define K_BRL_DOT4 K(KT_BRL, 4)
#define K_BRL_DOT5 K(KT_BRL, 5)
#define K_BRL_DOT6 K(KT_BRL, 6)
#define K_BRL_DOT7 K(KT_BRL, 7)
#define K_BRL_DOT8 K(KT_BRL, 8)
#define K_BRL_DOT9 K(KT_BRL, 9)
#define K_BRL_DOT10 K(KT_BRL, 10)
#define NR_BRL 11
#define MAX_DIACR 256
#endif

"""

```