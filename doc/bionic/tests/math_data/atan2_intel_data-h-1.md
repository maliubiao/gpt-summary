Response:
The user wants a summary of the functionality of the provided C source code file. This file seems to contain test data for the `atan2` function in Android's bionic library.

Therefore, the main functionality is to provide input values and expected output values for testing the `atan2` function.
这是目录为 `bionic/tests/math_data/atan2_intel_data.handroid` 的源代码文件的一部分，它属于 Android 的 C 库 (bionic)。从提供的内容来看，这个文件包含了大量的测试用例数据，用于测试 `atan2` 函数的实现。

**功能归纳：**

这个文件的主要功能是提供了一组预定义的输入值和对应的预期输出值，用于测试 `atan2` 函数在不同情况下的精度和正确性。

**更详细的解释：**

*   **测试数据:**  这个文件看起来像是一个数组，数组中的每个元素都是一个包含三个浮点数的结构体或元组。根据命名和常见的测试数据格式，我们可以推断：
    *   第一个浮点数可能是 `atan2` 函数的 `y` 参数。
    *   第二个浮点数可能是 `atan2` 函数的 `x` 参数。
    *   第三个浮点数是针对给定的 `y` 和 `x`，`atan2` 函数的预期返回值。

*   **覆盖各种场景:**  这些数据条目覆盖了 `atan2` 函数的各种输入场景，包括：
    *   正数、负数和零。
    *   非常小和非常大的数值（通过科学计数法表示，例如 `0x1.0p9` 表示 1.0 乘以 2 的 9 次方）。
    *   接近边界条件的值。
    *   一些特殊值，例如最小正数、最大有限数等。

*   **精度验证:**  通过比较 `atan2` 函数的实际输出和这些预期的输出值，可以验证函数在不同输入范围内的计算精度是否符合要求。

**与 Android 功能的关系：**

`atan2` 是一个标准的 C 库函数，用于计算给定直角三角形两条直角边 `y` 和 `x` 的反三角函数，返回弧度表示的角度。在 Android 系统中，`atan2` 函数被广泛应用于各种需要角度计算的场景，例如：

*   **图形和动画:** 在 2D 或 3D 图形渲染中，计算向量的角度，例如计算旋转角度。
*   **传感器处理:**  在处理来自加速度计、陀螺仪等传感器的原始数据时，可能需要计算角度信息。
*   **定位和地图:** 在 GPS 或其他定位服务中，计算方向或方位角。
*   **游戏开发:**  计算游戏对象之间的角度，例如射击方向。

**libc 函数的功能实现 (atan2)：**

`atan2(y, x)` 函数计算的是点 (x, y) 与原点之间的连线与正 x 轴之间的夹角，其返回值在 (-π, π] 范围内。

`atan2` 的具体实现通常会考虑以下情况：

1. **处理特殊值:** 例如，当 `x` 和 `y` 都是 0 时，结果是未定义的，但通常会返回 NaN (Not a Number)。需要处理正负零的情况。
2. **象限判断:** 根据 `x` 和 `y` 的符号确定角度所在的象限，以便返回正确的角度范围。
3. **利用 `atan` 函数:** `atan2` 的实现通常会调用 `atan(y/x)` 函数，但需要处理 `x` 为零的情况，以及根据象限调整 `atan` 的返回值。
4. **优化和精度:**  为了提高计算效率和精度，可能使用查表法、泰勒级数展开或其他数值计算方法进行优化。

**Dynamic Linker 的功能及处理过程 (这里的文件不直接涉及 Dynamic Linker)：**

你提供的代码片段本身并不涉及动态链接器的功能。这个文件是用于测试目的的静态数据文件，它会被编译到测试程序中。

然而，`atan2` 函数本身是 `libc.so` 的一部分，它是一个共享库，需要在程序运行时由动态链接器加载和链接。

**so 布局样本和链接的处理过程（以 `libc.so` 为例）：**

假设 `libc.so` 的布局如下（简化）：

```
libc.so:
    .text:  // 包含可执行代码
        [... 其他函数的代码 ...]
        atan2:  // atan2 函数的代码
            ...
    .data:  // 包含已初始化的全局变量
        ...
    .rodata: // 包含只读数据，例如字符串常量、查找表等
        ...
    .symtab: // 符号表，包含导出的符号信息，例如函数名和地址
        atan2
        [... 其他符号 ...]
    .dynsym: // 动态符号表，用于动态链接
        atan2
        [... 其他动态符号 ...]
    .rel.dyn: // 动态重定位表
        ...
    .rel.plt: // PLT (Procedure Linkage Table) 重定位表
        ...
```

**链接的处理过程：**

1. **编译时：** 当你的程序调用 `atan2` 函数时，编译器会生成一个对 `atan2` 的未定义引用，并将其放在代码中。链接器在链接你的程序时，会查找所需的共享库 (`libc.so`)，并在你的程序中创建一个 PLT 条目以及相应的 GOT (Global Offset Table) 条目，用于在运行时解析 `atan2` 的地址。

2. **加载时：** 当 Android 系统加载你的程序时，动态链接器 (`/system/bin/linker` 或 `linker64`) 会被激活。

3. **解析符号：** 动态链接器会解析程序依赖的共享库，包括 `libc.so`。它会遍历 `libc.so` 的动态符号表 (`.dynsym`)，找到 `atan2` 的地址。

4. **重定位：** 动态链接器会使用重定位表 (`.rel.dyn` 和 `.rel.plt`) 更新程序中的 GOT 和 PLT 条目，将 `atan2` 的实际地址填入 GOT 中。

5. **首次调用：** 当程序首次调用 `atan2` 时，会跳转到 PLT 条目。PLT 条目会间接地通过 GOT 跳转到动态链接器的一个辅助函数。

6. **地址绑定：** 动态链接器的辅助函数会检查 `atan2` 的地址是否已解析（GOT 条目是否已填充）。如果未解析，则会执行符号查找和重定位。

7. **后续调用：** 一旦 `atan2` 的地址被解析，后续的调用会直接通过 PLT 和 GOT 跳转到 `atan2` 函数的实际地址，而无需再次调用动态链接器。

**假设输入与输出（从提供的代码片段中提取）：**

例如，对于以下数据条目：

```c
  { // Entry 286
    0x1.921fb54442d18469898cc51701b839a2p-1,
    0x1.0p9,
    0x1.0p9
  },
```

*   **假设输入:** `y` 为 `0x1.921fb54442d18469898cc51701b839a2p-1` (表示一个浮点数)，`x` 为 `0x1.0p9` (表示 512.0)。
*   **预期输出:** `atan2(y, x)` 的结果应该非常接近 `0x1.0p9` (表示 512.0)。

请注意，这里的“输出”是指 `atan2` 函数的返回值，即角度的弧度值。 代码中的第三个值是用于比较的参考值，可能并不是直接的 `atan2` 的返回值，而是一个用于精度判断的阈值或者相关的值。  仔细观察，第三个值通常比前两个值大，这暗示了它可能与精度或缩放有关。

**用户或编程常见的使用错误：**

*   **参数顺序错误:** 记住 `atan2` 的参数顺序是 `atan2(y, x)`，而不是 `atan2(x, y)`。如果搞错顺序，结果的角度会错误。
*   **单位混淆:** `atan2` 返回的是弧度值。用户可能期望得到角度值，需要进行转换（弧度转角度：`角度 = 弧度 * 180 / PI`）。
*   **象限理解错误:**  `atan` 函数的返回值范围是 `[-π/2, π/2]`，而 `atan2` 考虑了象限，返回值范围是 `(-π, π]`。用户如果不理解这一点，可能会对结果感到困惑。
*   **处理特殊情况不当:**  例如，当 `x` 和 `y` 都为 0 时，`atan2` 的结果是未定义的。用户需要根据应用场景处理这种情况。

**Android Framework 或 NDK 如何到达这里：**

1. **Android Framework/NDK 调用 `atan2`:**
    *   Android Framework (Java 代码) 可以通过 JNI (Java Native Interface) 调用 NDK (Native Development Kit) 编写的 C/C++ 代码。
    *   NDK 代码可以直接调用 `libc.so` 提供的 `atan2` 函数。

2. **示例场景：自定义 View 的旋转动画**
    *   **Framework (Java):**  一个自定义的 `View` 需要根据触摸事件旋转。`onTouchEvent` 中获取触摸点的坐标。
    *   **NDK (C++):**  通过 JNI 调用 NDK 中的一个函数来计算旋转角度。
    *   **NDK 代码:**
        ```c++
        #include <cmath>
        #include <jni.h>

        extern "C" JNIEXPORT jfloat JNICALL
        Java_com_example_myapp_MyView_calculateRotationAngle(JNIEnv *env, jobject /* this */,
                                                           jfloat x, jfloat y) {
            // 假设 View 的中心是原点 (0, 0)
            float angle = atan2(y, x);
            return angle; // 返回弧度值
        }
        ```

3. **动态链接:** 当这个 NDK 库被加载时，动态链接器会将 `atan2` 的调用链接到 `libc.so` 中的实现。

**Frida Hook 示例调试步骤：**

可以使用 Frida Hook 来拦截 `atan2` 函数的调用，查看其输入参数和返回值。

```python
import frida
import sys

package_name = "你的应用包名"

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"进程 '{package_name}' 未找到，请确保应用正在运行。")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "atan2"), {
    onEnter: function(args) {
        this.y = args[0];
        this.x = args[1];
        console.log("[atan2] y = " + this.y + ", x = " + this.x);
    },
    onLeave: function(retval) {
        console.log("[atan2] return value = " + retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**Frida Hook 步骤解释：**

1. **导入 Frida 库。**
2. **指定要 hook 的应用包名。**
3. **定义 `on_message` 函数来处理 Frida 发送的消息。**
4. **连接到 USB 设备并附加到目标应用进程。**
5. **编写 Frida 脚本：**
    *   使用 `Interceptor.attach` 拦截 `libc.so` 中名为 `atan2` 的导出函数。
    *   在 `onEnter` 函数中，记录 `atan2` 的输入参数 `y` (args[0]) 和 `x` (args[1])。
    *   在 `onLeave` 函数中，记录 `atan2` 的返回值 `retval`。
6. **创建并加载 Frida 脚本。**
7. **保持脚本运行，直到用户手动停止。**

运行这个 Frida 脚本后，当目标应用调用 `atan2` 函数时，你将在控制台中看到相应的输入参数和返回值，从而可以调试 `atan2` 的使用情况。

总结来说，`atan2_intel_data.handroid` 文件是 bionic 库中用于测试 `atan2` 函数实现的一组测试数据，涵盖了各种输入场景，以确保该函数在 Android 系统中的正确性和精度。

### 提示词
```
这是目录为bionic/tests/math_data/atan2_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```c
x1.921fb54442d18469898cc51701b839a2p-1,
    0x1.0p9,
    0x1.0p9
  },
  { // Entry 289
    -0x1.921fb54442d18469898cc51701b839a2p-1,
    -0x1.0p9,
    0x1.0p9
  },
  { // Entry 290
    0x1.dac670561bb4f68adfc88bd978751a06p-2,
    0x1.0p9,
    0x1.0p10
  },
  { // Entry 291
    -0x1.dac670561bb4f68adfc88bd978751a06p-2,
    -0x1.0p9,
    0x1.0p10
  },
  { // Entry 292
    0x1.1b6e192ebbe446c6d19aa220a39af320p0,
    0x1.0p10,
    0x1.0p9
  },
  { // Entry 293
    -0x1.1b6e192ebbe446c6d19aa220a39af320p0,
    -0x1.0p10,
    0x1.0p9
  },
  { // Entry 294
    0x1.921fb54442d18469898cc51701b839a2p-1,
    0x1.0p10,
    0x1.0p10
  },
  { // Entry 295
    -0x1.921fb54442d18469898cc51701b839a2p-1,
    -0x1.0p10,
    0x1.0p10
  },
  { // Entry 296
    0x1.ffffffffffffffffffffffffffffffffp-92,
    0x1.0p9,
    0x1.0p100
  },
  { // Entry 297
    -0x1.ffffffffffffffffffffffffffffffffp-92,
    -0x1.0p9,
    0x1.0p100
  },
  { // Entry 298
    0x1.ffffffffffffffffffffffffffffffffp-93,
    0x1.0p9,
    0x1.0p101
  },
  { // Entry 299
    -0x1.ffffffffffffffffffffffffffffffffp-93,
    -0x1.0p9,
    0x1.0p101
  },
  { // Entry 300
    0x1.ffffffffffffffffffffffffffffffffp-91,
    0x1.0p10,
    0x1.0p100
  },
  { // Entry 301
    -0x1.ffffffffffffffffffffffffffffffffp-91,
    -0x1.0p10,
    0x1.0p100
  },
  { // Entry 302
    0x1.ffffffffffffffffffffffffffffffffp-92,
    0x1.0p10,
    0x1.0p101
  },
  { // Entry 303
    -0x1.ffffffffffffffffffffffffffffffffp-92,
    -0x1.0p10,
    0x1.0p101
  },
  { // Entry 304
    0x1.921fb54442d18469898cc516f1b839a2p0,
    0x1.0p100,
    0x1.0p0
  },
  { // Entry 305
    -0x1.921fb54442d18469898cc516f1b839a2p0,
    -0x1.0p100,
    0x1.0p0
  },
  { // Entry 306
    0x1.921fb54442d18469898cc51681b839a2p0,
    0x1.0p100,
    0x1.0p3
  },
  { // Entry 307
    -0x1.921fb54442d18469898cc51681b839a2p0,
    -0x1.0p100,
    0x1.0p3
  },
  { // Entry 308
    0x1.921fb54442d18469898cc516f9b839a2p0,
    0x1.0p101,
    0x1.0p0
  },
  { // Entry 309
    -0x1.921fb54442d18469898cc516f9b839a2p0,
    -0x1.0p101,
    0x1.0p0
  },
  { // Entry 310
    0x1.921fb54442d18469898cc516c1b839a2p0,
    0x1.0p101,
    0x1.0p3
  },
  { // Entry 311
    -0x1.921fb54442d18469898cc516c1b839a2p0,
    -0x1.0p101,
    0x1.0p3
  },
  { // Entry 312
    0x1.921fb54442d18469898cc4f701b839a2p0,
    0x1.0p100,
    0x1.0p9
  },
  { // Entry 313
    -0x1.921fb54442d18469898cc4f701b839a2p0,
    -0x1.0p100,
    0x1.0p9
  },
  { // Entry 314
    0x1.921fb54442d18469898cc4d701b839a2p0,
    0x1.0p100,
    0x1.0p10
  },
  { // Entry 315
    -0x1.921fb54442d18469898cc4d701b839a2p0,
    -0x1.0p100,
    0x1.0p10
  },
  { // Entry 316
    0x1.921fb54442d18469898cc50701b839a2p0,
    0x1.0p101,
    0x1.0p9
  },
  { // Entry 317
    -0x1.921fb54442d18469898cc50701b839a2p0,
    -0x1.0p101,
    0x1.0p9
  },
  { // Entry 318
    0x1.921fb54442d18469898cc4f701b839a2p0,
    0x1.0p101,
    0x1.0p10
  },
  { // Entry 319
    -0x1.921fb54442d18469898cc4f701b839a2p0,
    -0x1.0p101,
    0x1.0p10
  },
  { // Entry 320
    0x1.921fb54442d18469898cc51701b839a2p-1,
    0x1.0p100,
    0x1.0p100
  },
  { // Entry 321
    -0x1.921fb54442d18469898cc51701b839a2p-1,
    -0x1.0p100,
    0x1.0p100
  },
  { // Entry 322
    0x1.dac670561bb4f68adfc88bd978751a06p-2,
    0x1.0p100,
    0x1.0p101
  },
  { // Entry 323
    -0x1.dac670561bb4f68adfc88bd978751a06p-2,
    -0x1.0p100,
    0x1.0p101
  },
  { // Entry 324
    0x1.1b6e192ebbe446c6d19aa220a39af320p0,
    0x1.0p101,
    0x1.0p100
  },
  { // Entry 325
    -0x1.1b6e192ebbe446c6d19aa220a39af320p0,
    -0x1.0p101,
    0x1.0p100
  },
  { // Entry 326
    0x1.921fb54442d18469898cc51701b839a2p-1,
    0x1.0p101,
    0x1.0p101
  },
  { // Entry 327
    -0x1.921fb54442d18469898cc51701b839a2p-1,
    -0x1.0p101,
    0x1.0p101
  },
  { // Entry 328
    -0.0,
    -0x1.0p-1074,
    0x1.fffffffffffffp0
  },
  { // Entry 329
    0.0,
    0x1.0p-1074,
    0x1.fffffffffffffp0
  },
  { // Entry 330
    -0.0,
    -0x1.0p-1074,
    0x1.0p1
  },
  { // Entry 331
    0.0,
    0x1.0p-1074,
    0x1.0p1
  },
  { // Entry 332
    -0.0,
    -0x1.0p-1074,
    0x1.0000000000001p1
  },
  { // Entry 333
    0.0,
    0x1.0p-1074,
    0x1.0000000000001p1
  },
  { // Entry 334
    -0.0,
    -0.0,
    0x1.fffffffffffffp0
  },
  { // Entry 335
    -0.0,
    -0.0,
    0x1.0p1
  },
  { // Entry 336
    -0.0,
    -0.0,
    0x1.0000000000001p1
  },
  { // Entry 337
    0.0,
    0x1.0p-1074,
    0x1.fffffffffffffp0
  },
  { // Entry 338
    -0.0,
    -0x1.0p-1074,
    0x1.fffffffffffffp0
  },
  { // Entry 339
    0.0,
    0x1.0p-1074,
    0x1.0p1
  },
  { // Entry 340
    -0.0,
    -0x1.0p-1074,
    0x1.0p1
  },
  { // Entry 341
    0.0,
    0x1.0p-1074,
    0x1.0000000000001p1
  },
  { // Entry 342
    -0.0,
    -0x1.0p-1074,
    0x1.0000000000001p1
  },
  { // Entry 343
    0x1.ff55bb72cfde9c6d964f25b81c5c1aa2p-5,
    0x1.fffffffffffffp-4,
    0x1.fffffffffffffp0
  },
  { // Entry 344
    -0x1.ff55bb72cfde9c6d964f25b81c5c1aa2p-5,
    -0x1.fffffffffffffp-4,
    0x1.fffffffffffffp0
  },
  { // Entry 345
    0x1.ff55bb72cfde8c7d865f15c80c6b8bb0p-5,
    0x1.fffffffffffffp-4,
    0x1.0p1
  },
  { // Entry 346
    -0x1.ff55bb72cfde8c7d865f15c80c6b8bb0p-5,
    -0x1.fffffffffffffp-4,
    0x1.0p1
  },
  { // Entry 347
    0x1.ff55bb72cfde6c9d667ef5e7ef8476c1p-5,
    0x1.fffffffffffffp-4,
    0x1.0000000000001p1
  },
  { // Entry 348
    -0x1.ff55bb72cfde6c9d667ef5e7ef8476c1p-5,
    -0x1.fffffffffffffp-4,
    0x1.0000000000001p1
  },
  { // Entry 349
    0x1.ff55bb72cfdeac5da63f35a82ccb2c10p-5,
    0x1.0p-3,
    0x1.fffffffffffffp0
  },
  { // Entry 350
    -0x1.ff55bb72cfdeac5da63f35a82ccb2c10p-5,
    -0x1.0p-3,
    0x1.fffffffffffffp0
  },
  { // Entry 351
    0x1.ff55bb72cfde9c6d964f25b81c5c1aa2p-5,
    0x1.0p-3,
    0x1.0p1
  },
  { // Entry 352
    -0x1.ff55bb72cfde9c6d964f25b81c5c1aa2p-5,
    -0x1.0p-3,
    0x1.0p1
  },
  { // Entry 353
    0x1.ff55bb72cfde7c8d766f05d7fe7800bap-5,
    0x1.0p-3,
    0x1.0000000000001p1
  },
  { // Entry 354
    -0x1.ff55bb72cfde7c8d766f05d7fe7800bap-5,
    -0x1.0p-3,
    0x1.0000000000001p1
  },
  { // Entry 355
    0x1.ff55bb72cfdecc3dc61f55884da654e3p-5,
    0x1.0000000000001p-3,
    0x1.fffffffffffffp0
  },
  { // Entry 356
    -0x1.ff55bb72cfdecc3dc61f55884da654e3p-5,
    -0x1.0000000000001p-3,
    0x1.fffffffffffffp0
  },
  { // Entry 357
    0x1.ff55bb72cfdebc4db62f45983c3a3e7cp-5,
    0x1.0000000000001p-3,
    0x1.0p1
  },
  { // Entry 358
    -0x1.ff55bb72cfdebc4db62f45983c3a3e7cp-5,
    -0x1.0000000000001p-3,
    0x1.0p1
  },
  { // Entry 359
    0x1.ff55bb72cfde9c6d964f25b81c5c1aa2p-5,
    0x1.0000000000001p-3,
    0x1.0000000000001p1
  },
  { // Entry 360
    -0x1.ff55bb72cfde9c6d964f25b81c5c1aa2p-5,
    -0x1.0000000000001p-3,
    0x1.0000000000001p1
  },
  { // Entry 361
    -0x1.ff55bb72cfdecc3dc61f55884da654e3p-5,
    -0x1.0000000000001p-3,
    0x1.fffffffffffffp0
  },
  { // Entry 362
    0x1.ff55bb72cfdecc3dc61f55884da654e3p-5,
    0x1.0000000000001p-3,
    0x1.fffffffffffffp0
  },
  { // Entry 363
    -0x1.ff55bb72cfdebc4db62f45983c3a3e7cp-5,
    -0x1.0000000000001p-3,
    0x1.0p1
  },
  { // Entry 364
    0x1.ff55bb72cfdebc4db62f45983c3a3e7cp-5,
    0x1.0000000000001p-3,
    0x1.0p1
  },
  { // Entry 365
    -0x1.ff55bb72cfde9c6d964f25b81c5c1aa2p-5,
    -0x1.0000000000001p-3,
    0x1.0000000000001p1
  },
  { // Entry 366
    0x1.ff55bb72cfde9c6d964f25b81c5c1aa2p-5,
    0x1.0000000000001p-3,
    0x1.0000000000001p1
  },
  { // Entry 367
    -0x1.ff55bb72cfdeac5da63f35a82ccb2c10p-5,
    -0x1.0p-3,
    0x1.fffffffffffffp0
  },
  { // Entry 368
    0x1.ff55bb72cfdeac5da63f35a82ccb2c10p-5,
    0x1.0p-3,
    0x1.fffffffffffffp0
  },
  { // Entry 369
    -0x1.ff55bb72cfde9c6d964f25b81c5c1aa2p-5,
    -0x1.0p-3,
    0x1.0p1
  },
  { // Entry 370
    0x1.ff55bb72cfde9c6d964f25b81c5c1aa2p-5,
    0x1.0p-3,
    0x1.0p1
  },
  { // Entry 371
    -0x1.ff55bb72cfde7c8d766f05d7fe7800bap-5,
    -0x1.0p-3,
    0x1.0000000000001p1
  },
  { // Entry 372
    0x1.ff55bb72cfde7c8d766f05d7fe7800bap-5,
    0x1.0p-3,
    0x1.0000000000001p1
  },
  { // Entry 373
    -0x1.ff55bb72cfde9c6d964f25b81c5c1aa2p-5,
    -0x1.fffffffffffffp-4,
    0x1.fffffffffffffp0
  },
  { // Entry 374
    0x1.ff55bb72cfde9c6d964f25b81c5c1aa2p-5,
    0x1.fffffffffffffp-4,
    0x1.fffffffffffffp0
  },
  { // Entry 375
    -0x1.ff55bb72cfde8c7d865f15c80c6b8bb0p-5,
    -0x1.fffffffffffffp-4,
    0x1.0p1
  },
  { // Entry 376
    0x1.ff55bb72cfde8c7d865f15c80c6b8bb0p-5,
    0x1.fffffffffffffp-4,
    0x1.0p1
  },
  { // Entry 377
    -0x1.ff55bb72cfde6c9d667ef5e7ef8476c1p-5,
    -0x1.fffffffffffffp-4,
    0x1.0000000000001p1
  },
  { // Entry 378
    0x1.ff55bb72cfde6c9d667ef5e7ef8476c1p-5,
    0x1.fffffffffffffp-4,
    0x1.0000000000001p1
  },
  { // Entry 379
    0x1.a271f63e34fcf65ccd6e8d4040e2778cp-2,
    0x1.bb67ae8584ca9p-1,
    0x1.fffffffffffffp0
  },
  { // Entry 380
    -0x1.a271f63e34fcf65ccd6e8d4040e2778cp-2,
    -0x1.bb67ae8584ca9p-1,
    0x1.fffffffffffffp0
  },
  { // Entry 381
    0x1.a271f63e34fceab1a727ab70d0ce3998p-2,
    0x1.bb67ae8584ca9p-1,
    0x1.0p1
  },
  { // Entry 382
    -0x1.a271f63e34fceab1a727ab70d0ce3998p-2,
    -0x1.bb67ae8584ca9p-1,
    0x1.0p1
  },
  { // Entry 383
    0x1.a271f63e34fcd35b5a99e7d1f27d656cp-2,
    0x1.bb67ae8584ca9p-1,
    0x1.0000000000001p1
  },
  { // Entry 384
    -0x1.a271f63e34fcd35b5a99e7d1f27d656cp-2,
    -0x1.bb67ae8584ca9p-1,
    0x1.0000000000001p1
  },
  { // Entry 385
    0x1.a271f63e34fd03d610ccde17d587872dp-2,
    0x1.bb67ae8584caap-1,
    0x1.fffffffffffffp0
  },
  { // Entry 386
    -0x1.a271f63e34fd03d610ccde17d587872dp-2,
    -0x1.bb67ae8584caap-1,
    0x1.fffffffffffffp0
  },
  { // Entry 387
    0x1.a271f63e34fcf82aea85fc486529890cp-2,
    0x1.bb67ae8584caap-1,
    0x1.0p1
  },
  { // Entry 388
    -0x1.a271f63e34fcf82aea85fc486529890cp-2,
    -0x1.bb67ae8584caap-1,
    0x1.0p1
  },
  { // Entry 389
    0x1.a271f63e34fce0d49df838a986453485p-2,
    0x1.bb67ae8584caap-1,
    0x1.0000000000001p1
  },
  { // Entry 390
    -0x1.a271f63e34fce0d49df838a986453485p-2,
    -0x1.bb67ae8584caap-1,
    0x1.0000000000001p1
  },
  { // Entry 391
    0x1.a271f63e34fd114f542b2eef6a0548d3p-2,
    0x1.bb67ae8584cabp-1,
    0x1.fffffffffffffp0
  },
  { // Entry 392
    -0x1.a271f63e34fd114f542b2eef6a0548d3p-2,
    -0x1.bb67ae8584cabp-1,
    0x1.fffffffffffffp0
  },
  { // Entry 393
    0x1.a271f63e34fd05a42de44d1ff95d8a85p-2,
    0x1.bb67ae8584cabp-1,
    0x1.0p1
  },
  { // Entry 394
    -0x1.a271f63e34fd05a42de44d1ff95d8a85p-2,
    -0x1.bb67ae8584cabp-1,
    0x1.0p1
  },
  { // Entry 395
    0x1.a271f63e34fcee4de156898119e5b5a4p-2,
    0x1.bb67ae8584cabp-1,
    0x1.0000000000001p1
  },
  { // Entry 396
    -0x1.a271f63e34fcee4de156898119e5b5a4p-2,
    -0x1.bb67ae8584cabp-1,
    0x1.0000000000001p1
  },
  { // Entry 397
    -0x1.a271f63e34fd114f542b2eef6a0548d3p-2,
    -0x1.bb67ae8584cabp-1,
    0x1.fffffffffffffp0
  },
  { // Entry 398
    0x1.a271f63e34fd114f542b2eef6a0548d3p-2,
    0x1.bb67ae8584cabp-1,
    0x1.fffffffffffffp0
  },
  { // Entry 399
    -0x1.a271f63e34fd05a42de44d1ff95d8a85p-2,
    -0x1.bb67ae8584cabp-1,
    0x1.0p1
  },
  { // Entry 400
    0x1.a271f63e34fd05a42de44d1ff95d8a85p-2,
    0x1.bb67ae8584cabp-1,
    0x1.0p1
  },
  { // Entry 401
    -0x1.a271f63e34fcee4de156898119e5b5a4p-2,
    -0x1.bb67ae8584cabp-1,
    0x1.0000000000001p1
  },
  { // Entry 402
    0x1.a271f63e34fcee4de156898119e5b5a4p-2,
    0x1.bb67ae8584cabp-1,
    0x1.0000000000001p1
  },
  { // Entry 403
    -0x1.a271f63e34fd03d610ccde17d587872dp-2,
    -0x1.bb67ae8584caap-1,
    0x1.fffffffffffffp0
  },
  { // Entry 404
    0x1.a271f63e34fd03d610ccde17d587872dp-2,
    0x1.bb67ae8584caap-1,
    0x1.fffffffffffffp0
  },
  { // Entry 405
    -0x1.a271f63e34fcf82aea85fc486529890cp-2,
    -0x1.bb67ae8584caap-1,
    0x1.0p1
  },
  { // Entry 406
    0x1.a271f63e34fcf82aea85fc486529890cp-2,
    0x1.bb67ae8584caap-1,
    0x1.0p1
  },
  { // Entry 407
    -0x1.a271f63e34fce0d49df838a986453485p-2,
    -0x1.bb67ae8584caap-1,
    0x1.0000000000001p1
  },
  { // Entry 408
    0x1.a271f63e34fce0d49df838a986453485p-2,
    0x1.bb67ae8584caap-1,
    0x1.0000000000001p1
  },
  { // Entry 409
    -0x1.a271f63e34fcf65ccd6e8d4040e2778cp-2,
    -0x1.bb67ae8584ca9p-1,
    0x1.fffffffffffffp0
  },
  { // Entry 410
    0x1.a271f63e34fcf65ccd6e8d4040e2778cp-2,
    0x1.bb67ae8584ca9p-1,
    0x1.fffffffffffffp0
  },
  { // Entry 411
    -0x1.a271f63e34fceab1a727ab70d0ce3998p-2,
    -0x1.bb67ae8584ca9p-1,
    0x1.0p1
  },
  { // Entry 412
    0x1.a271f63e34fceab1a727ab70d0ce3998p-2,
    0x1.bb67ae8584ca9p-1,
    0x1.0p1
  },
  { // Entry 413
    -0x1.a271f63e34fcd35b5a99e7d1f27d656cp-2,
    -0x1.bb67ae8584ca9p-1,
    0x1.0000000000001p1
  },
  { // Entry 414
    0x1.a271f63e34fcd35b5a99e7d1f27d656cp-2,
    0x1.bb67ae8584ca9p-1,
    0x1.0000000000001p1
  },
  { // Entry 415
    0x1.e1fc084cd761a3aa77e521b9a803b2f2p-1,
    0x1.5f89e11a0441cp1,
    0x1.fffffffffffffp0
  },
  { // Entry 416
    -0x1.e1fc084cd761a3aa77e521b9a803b2f2p-1,
    -0x1.5f89e11a0441cp1,
    0x1.fffffffffffffp0
  },
  { // Entry 417
    0x1.e1fc084cd7619c0d50916d35af40b669p-1,
    0x1.5f89e11a0441cp1,
    0x1.0p1
  },
  { // Entry 418
    -0x1.e1fc084cd7619c0d50916d35af40b669p-1,
    -0x1.5f89e11a0441cp1,
    0x1.0p1
  },
  { // Entry 419
    0x1.e1fc084cd7618cd301ea042dbe396361p-1,
    0x1.5f89e11a0441cp1,
    0x1.0000000000001p1
  },
  { // Entry 420
    -0x1.e1fc084cd7618cd301ea042dbe396361p-1,
    -0x1.5f89e11a0441cp1,
    0x1.0000000000001p1
  },
  { // Entry 421
    0x1.e1fc084cd761aec15275b5d29ba21a09p-1,
    0x1.5f89e11a0441dp1,
    0x1.fffffffffffffp0
  },
  { // Entry 422
    -0x1.e1fc084cd761aec15275b5d29ba21a09p-1,
    -0x1.5f89e11a0441dp1,
    0x1.fffffffffffffp0
  },
  { // Entry 423
    0x1.e1fc084cd761a7242b22014ea2fa57ebp-1,
    0x1.5f89e11a0441dp1,
    0x1.0p1
  },
  { // Entry 424
    -0x1.e1fc084cd761a7242b22014ea2fa57ebp-1,
    -0x1.5f89e11a0441dp1,
    0x1.0p1
  },
  { // Entry 425
    0x1.e1fc084cd76197e9dc7a9846b22979b9p-1,
    0x1.5f89e11a0441dp1,
    0x1.0000000000001p1
  },
  { // Entry 426
    -0x1.e1fc084cd76197e9dc7a9846b22979b9p-1,
    -0x1.5f89e11a0441dp1,
    0x1.0000000000001p1
  },
  { // Entry 427
    0x1.e1fc084cd761b9d82d0649eb8e97a3bcp-1,
    0x1.5f89e11a0441ep1,
    0x1.fffffffffffffp0
  },
  { // Entry 428
    -0x1.e1fc084cd761b9d82d0649eb8e97a3bcp-1,
    -0x1.5f89e11a0441ep1,
    0x1.fffffffffffffp0
  },
  { // Entry 429
    0x1.e1fc084cd761b23b05b29567960b1c09p-1,
    0x1.5f89e11a0441ep1,
    0x1.0p1
  },
  { // Entry 430
    -0x1.e1fc084cd761b23b05b29567960b1c09p-1,
    -0x1.5f89e11a0441ep1,
    0x1.0p1
  },
  { // Entry 431
    0x1.e1fc084cd761a300b70b2c5fa570b2aep-1,
    0x1.5f89e11a0441ep1,
    0x1.0000000000001p1
  },
  { // Entry 432
    -0x1.e1fc084cd761a300b70b2c5fa570b2aep-1,
    -0x1.5f89e11a0441ep1,
    0x1.0000000000001p1
  },
  { // Entry 433
    -0x1.e1fc084cd761b9d82d0649eb8e97a3bcp-1,
    -0x1.5f89e11a0441ep1,
    0x1.fffffffffffffp0
  },
  { // Entry 434
    0x1.e1fc084cd761b9d82d0649eb8e97a3bcp-1,
    0x1.5f89e11a0441ep1,
    0x1.fffffffffffffp0
  },
  { // Entry 435
    -0x1.e1fc084cd761b23b05b29567960b1c09p-1,
    -0x1.5f89e11a0441ep1,
    0x1.0p1
  },
  { // Entry 436
    0x1.e1fc084cd761b23b05b29567960b1c09p-1,
    0x1.5f89e11a0441ep1,
    0x1.0p1
  },
  { // Entry 437
    -0x1.e1fc084cd761a300b70b2c5fa570b2aep-1,
    -0x1.5f89e11a0441ep1,
    0x1.0000000000001p1
  },
  { // Entry 438
    0x1.e1fc084cd761a300b70b2c5fa570b2aep-1,
    0x1.5f89e11a0441ep1,
    0x1.0000000000001p1
  },
  { // Entry 439
    -0x1.e1fc084cd761aec15275b5d29ba21a09p-1,
    -0x1.5f89e11a0441dp1,
    0x1.fffffffffffffp0
  },
  { // Entry 440
    0x1.e1fc084cd761aec15275b5d29ba21a09p-1,
    0x1.5f89e11a0441dp1,
    0x1.fffffffffffffp0
  },
  { // Entry 441
    -0x1.e1fc084cd761a7242b22014ea2fa57ebp-1,
    -0x1.5f89e11a0441dp1,
    0x1.0p1
  },
  { // Entry 442
    0x1.e1fc084cd761a7242b22014ea2fa57ebp-1,
    0x1.5f89e11a0441dp1,
    0x1.0p1
  },
  { // Entry 443
    -0x1.e1fc084cd76197e9dc7a9846b22979b9p-1,
    -0x1.5f89e11a0441dp1,
    0x1.0000000000001p1
  },
  { // Entry 444
    0x1.e1fc084cd76197e9dc7a9846b22979b9p-1,
    0x1.5f89e11a0441dp1,
    0x1.0000000000001p1
  },
  { // Entry 445
    -0x1.e1fc084cd761a3aa77e521b9a803b2f2p-1,
    -0x1.5f89e11a0441cp1,
    0x1.fffffffffffffp0
  },
  { // Entry 446
    0x1.e1fc084cd761a3aa77e521b9a803b2f2p-1,
    0x1.5f89e11a0441cp1,
    0x1.fffffffffffffp0
  },
  { // Entry 447
    -0x1.e1fc084cd7619c0d50916d35af40b669p-1,
    -0x1.5f89e11a0441cp1,
    0x1.0p1
  },
  { // Entry 448
    0x1.e1fc084cd7619c0d50916d35af40b669p-1,
    0x1.5f89e11a0441cp1,
    0x1.0p1
  },
  { // Entry 449
    -0x1.e1fc084cd7618cd301ea042dbe396361p-1,
    -0x1.5f89e11a0441cp1,
    0x1.0000000000001p1
  },
  { // Entry 450
    0x1.e1fc084cd7618cd301ea042dbe396361p-1,
    0x1.5f89e11a0441cp1,
    0x1.0000000000001p1
  },
  { // Entry 451
    0x1.921fb54442d18469898cc51701b839a2p-1,
    0x1.fffffffffffffp0,
    0x1.fffffffffffffp0
  },
  { // Entry 452
    -0x1.921fb54442d18469898cc51701b839a2p-1,
    -0x1.fffffffffffffp0,
    0x1.fffffffffffffp0
  },
  { // Entry 453
    0x1.921fb54442d17c69898cc517019839a2p-1,
    0x1.fffffffffffffp0,
    0x1.0p1
  },
  { // Entry 454
    -0x1.921fb54442d17c69898cc517019839a2p-1,
    -0x1.fffffffffffffp0,
    0x1.0p1
  },
  { // Entry 455
    0x1.921fb54442d16c69898cc517021839a2p-1,
    0x1.fffffffffffffp0,
    0x1.0000000000001p1
  },
  { // Entry 456
    -0x1.921fb54442d16c69898cc517021839a2p-1,
    -0x1.fffffffffffffp0,
    0x1.0000000000001p1
  },
  { // Entry 457
    0x1.921fb54442d18c69898cc51701d839a2p-1,
    0x1.0p1,
    0x1.fffffffffffffp0
  },
  { // Entry 458
    -0x1.921fb54442d18c69898cc51701d839a2p-1,
    -0x1.0p1,
    0x1.fffffffffffffp0
  },
  { // Entry 459
    0x1.921fb54442d18469898cc51701b839a2p-1,
    0x1.0p1,
    0x1.0p1
  },
  { // Entry 460
    -0x1.921fb54442d18469898cc51701b839a2p-1,
    -0x1.0p1,
    0x1.0p1
  },
  { // Entry 461
    0x1.921fb54442d17469898cc517023839a2p-1,
    0x1.0p1,
    0x1.0000000000001p1
  },
  { // Entry 462
    -0x1.921fb54442d17469898cc517023839a2p-1,
    -0x1.0p1,
    0x1.0000000000001p1
  },
  { // Entry 463
    0x1.921fb54442d19c69898cc517015839a2p-1,
    0x1.0000000000001p1,
    0x1.fffffffffffffp0
  },
  { // Entry 464
    -0x1.921fb54442d19c69898cc517015839a2p-1,
    -0x1.0000000000001p1,
    0x1.fffffffffffffp0
  },
  { // Entry 465
    0x1.921fb54442d19469898cc517013839a2p-1,
    0x1.0000000000001p1,
    0x1.0p1
  },
  { // Entry 466
    -0x1.921fb54442d19469898cc517013839a2p-1,
    -0x1.0000000000001p1,
    0x1.0p1
  },
  { // Entry 467
    0x1.921fb54442d18469898cc51701b839a2p-1,
    0x1.0000000000001p1,
    0x1.0000000000001p1
  },
  { // Entry 468
    -0x1.921fb54442d18469898cc51701b839a2p-1,
    -0x1.0000000000001p1,
    0x1.0000000000001p1
  },
  { // Entry 469
    0x1.fffffffffffffd5555555555555bbbbbp-28,
    0x1.fffffffffffffp-27,
    0x1.fffffffffffffp0
  },
  { // Entry 470
    -0x1.fffffffffffffd5555555555555bbbbbp-28,
    -0x1.fffffffffffffp-27,
    0x1.fffffffffffffp0
  },
  { // Entry 471
    0x1.ffffffffffffed5555555555559bbbbbp-28,
    0x1.fffffffffffffp-27,
    0x1.0p1
  },
  { // Entry 472
    -0x1.ffffffffffffed5555555555559bbbbbp-28,
    -0x1.fffffffffffffp-27,
    0x1.0p1
  },
  { // Entry 473
    0x1.ffffffffffffcd5555555555591bbbbbp-28,
    0x1.fffffffffffffp-27,
    0x1.0000000000001p1
  },
  { // Entry 474
    -0x1.ffffffffffffcd5555555555591bbbbbp-28,
    -0x1.fffffffffffffp-27,
    0x1.0000000000001p1
  },
  { // Entry 475
    0x1.00000000000006aaaaaaaaaaaacdddddp-27,
    0x1.0p-26,
    0x1.fffffffffffffp0
  },
  { // Entry 476
    -0x1.00000000000006aaaaaaaaaaaacdddddp-27,
    -0x1.0p-26,
    0x1.fffffffffffffp0
  },
  { // Entry 477
    0x1.fffffffffffffd5555555555555bbbbbp-28,
    0x1.0p-26,
    0x1.0p1
  },
  { // Entry 478
    -0x1.fffffffffffffd5555555555555bbbbbp-28,
    -0x1.0p-26,
    0x1.0p1
  },
  { // Entry 479
    0x1.ffffffffffffdd555555555557dbbbbbp-28,
    0x1.0p-26,
    0x1.0000000000001p1
  },
  { // Entry 480
    -0x1.ffffffffffffdd555555555557dbbbbbp-28,
    -0x1.0p-26,
    0x1.0000000000001p1
  },
  { // Entry 481
    0x1.00000000000016aaaaaaaaaaab0dddddp-27,
    0x1.0000000000001p-26,
    0x1.fffffffffffffp0
  },
  { // Entry 482
    -0x1.00000000000016aaaaaaaaaaab0dddddp-27,
    -0x1.0000000000001p-26,
    0x1.fffffffffffffp0
  },
  { // Entry 483
    0x1.0000000000000eaaaaaaaaaaaa6dddddp-27,
    0x1.0000000000001p-26,
    0x1.0p1
  },
  { // Entry 484
    -0x1.0000000000000eaaaaaaaaaaaa6dddddp-27,
    -0x1.0000000000001p-26,
    0x1.0p1
  },
  { // Entry 485
    0x1.fffffffffffffd5555555555555bbbbbp-28,
    0x1.0000000000001p-26,
    0x1.0000000000001p1
  },
  { // Entry 486
    -0x1.fffffffffffffd5555555555555bbbbbp-28,
    -0x1.0000000000001p-26,
    0x1.0000000000001p1
  },
  { // Entry 487
    -0x1.2d97c7f3321d234f272993d1414a2b39p1,
    -0x1.0p-1074,
    -0x1.0p-1074
  },
  { // Entry 488
    0x1.2d97c7f3321d234f272993d1414a2b39p1,
    0x1.0p-1074,
    -0x1.0p-1074
  },
  { // Entry 489
    -0x1.921fb54442d18469898cc51701b839a2p0,
    -0x1.0p-1074,
    -0.0
  },
  { // Entry 490
    0x1.921fb54442d18469898cc51701b839a2p0,
    0x1.0p-1074,
    -0.0
  },
  { // Entry 491
    -0x1.921fb54442d18469898cc51701b839a2p-1,
    -0x1.0p-1074,
    0x1.0p-1074
  },
  { // Entry 492
    0x1.921fb54442d18469898cc51701b839a2p-1,
    0x1.0p-1074,
    0x1.0p-1074
  },
  { // Entry 493
    -0x1.921fb54442d18469898cc51701b839a2p1,
    -0.0,
    -0x1.0p-1074
  },
  { // Entry 494
    -0x1.921fb54442d18469898cc51701b839a2p1,
    -0.0,
    -0.0
  },
  { // Entry 495
    -0.0,
    -0.0,
    0x1.0p-1074
  },
  { // Entry 496
    0x1.2d97c7f3321d234f272993d1414a2b39p1,
    0x1.0p-1074,
    -0x1.0p-1074
  },
  { // Entry 497
    -0x1.2d97c7f3321d234f272993d1414a2b39p1,
    -0x1.0p-1074,
    -0x1.0p-1074
  },
  { // Entry 498
    0x1.921fb54442d18469898cc51701b839a2p0,
    0x1.0p-1074,
    -0.0
  },
  { // Entry 499
    -0x1.921fb54442d18469898cc51701b839a2p0,
    -0x1.0p-1074,
    -0.0
  },
  { // Entry 500
    0x1.921fb54442d18469898cc51701b839a2p-1,
    0x1.0p-1074,
    0x1.0p-1074
  },
  { // Entry 501
    -0x1.921fb54442d18469898cc51701b839a2p-1,
    -0x1.0p-1074,
    0x1.0p-1074
  },
  { // Entry 502
    -0.0,
    -0x1.0p-1074,
    0x1.fffffffffffffp1023
  },
  { // Entry 503
    0.0,
    0x1.0p-1074,
    0x1.fffffffffffffp1023
  },
  { // Entry 504
    -0.0,
    -0.0,
    0x1.fffffffffffffp1023
  },
  { // Entry 505
    0.0,
    0x1.0p-1074,
    0x1.fffffffffffffp1023
  },
  { // Entry 506
    -0.0,
    -0x1.0p-1074,
    0x1.fffffffffffffp1023
  },
  { // Entry 507
    -0x1.921fb54442d18469898cc51701b839a2p1,
    -0x1.0p-1074,
    -0x1.fffffffffffffp1023
  },
  { // Entry 508
    0x1.921fb54442d18469898cc51701b839a2p1,
    0x1.0p-1074,
    -0x1.fffffffffffffp1023
  },
  { // Entry 509
    -0x1.921fb54442d18469898cc51701b839a2p1,
    -0.0,
    -0x1.fffffffffffffp1023
  },
  { // Entry 510
    0x1.921fb54442d18469898cc51701b839a2p1,
    0x1.0p-1074,
    -0x1.fffffffffffffp1023
  },
  { // Entry 511
    -0x1.921fb54442d18469898cc51701b839a2p1,
    -0x1.0p-1074,
    -0x1.fffffffffffffp1023
  },
  { // Entry 512
    0x1.921fb54442d18469898cc51701b839a2p0,
    0x1.fffffffffffffp1023,
    -0x1.0p-1074
  },
  { // Entry 513
    -0x1.921fb54442d18469898cc51701b839a2p0,
    -0x1.fffffffffffffp1023,
    -0x1.0p-1074
  },
  { // Entry 514
    0x1.921fb54442d18469898cc51701b839a2p0,
    0x1.fffffffffffffp1023,
    -0.0
  },
  { // Entry 515
    -0x1.921fb54442d18469898cc51701b839a2p0,
    -0x1.fffffffffffffp1023,
    -0.0
  },
  { // Entry 516
    0x1.921fb54442d18469898cc51701b839a2p0,
    0x1.fffffffffffffp1023,
    0x1.0p-1074
  },
  { // Entry 517
    -0x1.921fb54442d18469898cc51701b839a2p0,
    -0x1.fffffffffffffp1023,
    0x1.0p-1074
  },
  { // Entry 518
    -0x1.921fb54442d18469898cc51701b839a2p0,
    -0x1.fffffffffffffp1023,
    -0x1.0p-1074
  },
  { // Entry 519
    0x1.921fb54442d18469898cc51701b839a2p0,
    0x1.fffffffffffffp1023,
    -0x1.0p-1074
  },
  { // Entry 520
    -0x1.921fb54442d18469898cc51701b839a2p0,
    -0x1.fffffffffffffp1023,
    -0.0
  },
  { // Entry 521
    0x1.921fb54442d18469898cc51701b839a2p0,
    0x1.fffffffffffffp1023,
    -0.0
  },
  { // Entry 522
    -0x1.921fb54442d18469898cc51701b839a2p0,
    -0x1.fffffffffffffp1023,
    0x1.0p-1074
  },
  { // Entry 523
    0x1.921fb54442d18469898cc51701b839a2p0,
    0x1.fffffffffffffp1023,
    0x1.0p-1074
  },
  { // Entry 524
    0x1.921fb54442d18469898cc51701b839a2p-1,
    0x1.fffffffffffffp1023,
    0x1.fffffffffffffp1023
  },
  { // Entry 525
    -0x1.921fb54442d18469898cc51701b839a2p-1,
    -0x1.fffffffffffffp1023,
    0x1.fffffffffffffp1023
  },
  { // Entry 526
    -0x1.2d97c7f3321d234f272993d1414a2b39p1,
    -0x1.fffffffffffffp1023,
    -0x1.fffffffffffffp1023
  },
  { // Entry 527
    0x1.2d97c7f3321d234f272993d1414a2b39p1,
    0x1.fffffffffffffp1023,
    -0x1.fffffffffffffp1023
  },
  { // Entry 528
    0x1.ffffffffffffffffffffffffffff5555p-57,
    0x1.fffffffffffffp0,
    0x1.fffffffffffffp56
  },
  { // Entry 529
    -0x1.ffffffffffffffffffffffffffff5555p-57,
    -0x1.fffffffffffffp0,
    0x1.fffffffffffffp56
  },
  { // Entry 530
    0x1.ffffffffffffefffffffffffffff5555p-57,
    0x1.fffffffffffffp0,
    0x1.0p57
  },
  { // Entry 531
    -0x1.ffffffffffffefffffffffffffff5555p-57,
    -0x1.fffffffffffffp0,
    0x1.0p57
  },
  { // Entry 532
    0x1.ffffffffffffd0000000000002ff5555p-57,
    0x1.fffffffffffffp0,
    0x1.0000000000001p57
  },
  { // Entry 533
    -0x1.ffffffffffffd0000000000002ff5555p-57,
    -0x1.fffffffffffffp0,
    0x1.0000000000001p57
  },
  { // Entry 534
    0x1.000000000000080000000000003faaaap-56,
    0x1.0p1,
    0x1.fffffffffffffp56
  },
  { // Entry 535
    -0x1.000000000000080000000000003faaaap-56,
    -0x1.0p1,
    0x1.fffffffffffffp56
  },
  { // Entry 536
    0x1.ffffffffffffffffffffffffffff5555p-57,
    0x1.0p1,
    0x1.0p57
  },
  { // Entry 537
    -0x1.ffffffffffffffffffffffffffff5555p-57,
    -0x1.0p1,
    0x1.0p57
  },
  { // Entry 538
    0x1.ffffffffffffe0000000000001ff5555p-57,
    0x1.0p1,
    0x1.0000000000001p57
  },
  { // Entry 539
    -0x1.ffffffffffffe0000000000001ff5555p-57,
    -0x1.0p1,
    0x1.0000000000001p57
  },
  { // Entry 540
    0x1.00000000000018000000000000bfaaaap-56,
    0x1.0000000000001p1,
    0x1.fffffffffffffp56
  },
  { // Entry 541
    -0x1.00000000000018000000000000bfaaaap-56,
    -0x1.0000000000001p1,
    0x1.fffffffffffffp56
  },
  { // Entry 542
    0x1.0000000000000fffffffffffffffaaaap-56,
    0x1.0000000000001p1,
    0x1.0p57
  },
  { // Entry 543
    -0x1.0000000000000fffffffffffffffaaaap-56,
    -0x1.0000000000001p1,
    0x1.0p57
  },
  { // Entry 544
    0x1.ffffffffffffffffffffffffffff5555p-57,
    0x1.0000000000001p1,
    0x1.0000000000001p57
  },
  { // Entry 545
    -0x1.ffffffffffffffffffffffffffff5555p-57,
    -0x1.0000000000001p1,
    0x1.0000000000001p57
  },
  { // Entry 546
    -0x1.00000000000018000000000000bfaaaap-56,
    -0x1.0000000000001p1,
    0x1.fffffffffffffp56
  },
  { // Entry 547
    0x1.00000000000018000000000000bfaaaap-56,
    0x1.0000000000001p1,
    0x1.fffffffffffffp56
  },
  { // Entry 548
    -0x1.0000000000000fffffffffffffffaaaap-56,
    -0x1.0000000000001p1,
    0x1.0p57
  },
  { // Entry 549
    0x1.0000000000000fffffffffffffffaaaap-56,
    0x1.0000000000001p1,
    0x1.0p57
  },
  { // Entry 550
    -0x1.ffffffffffffffffffffffffffff5555p-57,
    -0x1.0000000000001p1,
    0x1.0000000000001p57
  },
  { // Entry 551
    0x1.ffffffffffffffffffffffffffff5555p-57,
    0x1.0000000000001p1,
    0x1.0000000000001p57
  },
  { // Entry 552
    -0x1.000000000000080000000000003faaaap-56,
    -0x1.0p1,
    0x1.fffffffffffffp56
  },
  { // Entry 553
    0x1.000000000000080000000000003faaaap-56,
    0x1.0p1,
    0x1.fffffffffffffp56
  },
  { // Entry 554
    -0x1.ffffffffffffffffffffffffffff5555p-57,
    -0x1.0p1,
    0x1.0p57
  },
  { // Entry 555
    0x1.ffffffffffffffffffffffffffff5555p-57,
    0x1.0p1,
    0x1.0p57
  },
  { // Entry 556
    -0x1.ffffffffffffe0000000000001ff5555p-57,
    -0x1.0p1,
    0x1.0000000000001p57
  },
  { // Entry 557
    0x1.ffffffffffffe0000000000001ff5555p-57,
    0x1.0p1,
    0x1.0000000000001p57
  },
  { // Entry 558
    -0x1.ffffffffffffffffffffffffffff5555p-57,
    -0x1.fffffffffffffp0,
    0x1.fffffffffffffp56
  },
  { // Entry 559
    0x1.ffffffffffffffffffffffffffff5555p-57,
    0x1.fffffffffffffp0,
    0x1.fffffffffffffp56
  },
  { // Entry 560
    -0x1.ffffffffffffefffffffffffffff5555p-57,
    -0x1.fffffffffffffp0,
    0x1.0p57
  },
  { // Entry 561
    0x1.ffffffffffffefffffffffffffff5555p-57,
    0x1.fffffffffffffp0,
    0x1.0p57
  },
  { // Entry 562
    -0x1.ffffffffffffd0000000000002ff5555p-57,
    -0x1.fffffffffffffp0,
    0x1.0000000000001p57
  },
  { // Entry 563
    0x1.ffffffffffffd0000000000002ff5555p-57,
    0x1.fffffffffffffp0,
    0x1.0000000000001p57
  },
  { // Entry 564
    0x1.fffffffffffffff555555555555555bbp-31,
    0x1.fffffffffffffp1,
    0x1.fffffffffffffp31
  },
  { // Entry 565
    -0x1.fffffffffffffff555555555555555bbp-31,
    -0x1.fffffffffffffp1,
    0x1.fffffffffffffp31
  },
  { // Entry 566
    0x1.ffffffffffffeff555555555555655bbp-31,
    0x1.fffffffffffffp1,
    0x1.0p32
  },
  { // Entry 567
    -0x1.ffffffffffffeff555555555555655bbp-31,
    -0x1.fffffffffffffp1,
    0x1.0p32
  },
  { // Entry 568
    0x1.ffffffffffffcff555555555585855bbp-31,
    0x1.fffffffffffffp1,
    0x1.0000000000001p32
  },
  { // Entry 569
    -0x1.ffffffffffffcff555555555585855bbp-31,
    -0x1.fffffffffffffp1,
    0x1.0000000000001p32
  },
  { // Entry 570
    0x1.00000000000007faaaaaaaaaaaea2addp-30,
    0x1.0p2,
    0x1.fffffffffffffp31
  },
  { // Entry 571
    -0x1.00000000000007faaaaaaaaaaaea2addp-30,
    -0x1.0p2,
    0x1.fffffffffffffp31
  },
  { // Entry 572
    0x1.fffffffffffffff555555555555555bbp-31,
    0x1.0p2,
    0x1.0p32
  },
  { // Entry 573
    -0x1.fffffffffffffff555555555555555bbp-31,
    -0x1.0p2,
    0x1.0p32
  },
  { // Entry 574
    0x1.ffffffffffffdff555555555575755bbp-31,
    0x1.0p2,
    0x1.0000000000001p32
  },
  { // Entry 575
    -0x1.ffffffffffffdff555555555575755bbp-31,
    -0x1.0p2,
    0x1.0000000000001p32
  },
  { // Entry 576
    0x1.00000000000017faaaaaaaaaab692addp-30,
    0x1.0000000000001p2,
    0x1.fffffffffffffp31
  },
  { // Entry 577
    -0x1.00000000000017faaaaaaaaaab692addp-30,
    -0x1.0000000000001p2,
    0x1.fffffffffffffp31
  },
  { // Entry 578
    0x1.0000000000000ffaaaaaaaaaaaa9aaddp-30,
    0x1.0000000000001p2,
    0x1.0p32
  },
  { // Entry 579
    -0x1.0000000000000ffaaaaaaaaaaaa9aaddp-30,
    -0x1.0000000000001p2,
    0x1.0p32
  },
  { // Entry 580
    0x1.fffffffffffffff555555555555555bbp-31,
    0x1.0000000000001p2,
    0x1.0000000000001p32
  },
  { // Entry 581
    -0x1.fffffffffffffff555555555555555bbp-31,
    -0x1.0000000000001p2,
    0x1.0000000000001p32
  },
  { // Entry 582
    -0x1.00000000000017faaaaaaaaaab692addp-30,
    -0x1.0000000000001p-2,
    0x1.fffffffffffffp27
  },
  { // Entry 583
    0x1.00000000000017faaaaaaaaaab692addp-30,
    0x1.0000000000001p-2,
    0x1.fffffffffffffp27
  },
  { // Entry 584
    -0x1.0000000000000ffaaaaaaaaaaaa9aaddp-30,
    -0x1.0000000000001p-2,
    0x1.0p28
  },
  { // Entry 585
    0x1.0000000000000ffaaaaaaaaaaaa9aaddp-30,
    0x1.0000000000001p-2,
    0x1.0p28
  },
  { // Entry 586
    -0x1.fffffffffffffff555555555555555bbp-31,
    -0x1.0000000000001p-2,
    0x1.0000000000001p28
  },
  { // Entry 587
    0x1.fffffffffffffff555555555555555bbp-31,
    0x1.0000000000001p-2,
    0x1.0000000000001p28
  },
  { // Entry 588
    -0x1.00000000000007faaaaaaaaaaaea2addp-30,
    -0x1.0p-2,
    0x1.fffffffffffffp27
  },
  { // Entry 589
    0x1.00000000000007faaaaaaaaaaaea2addp-30,
    0x1.0p-2,
    0x1.fffffffffffffp27
  },
  { // Entry 590
    -0x1.fffffffffffffff555555555555555bbp-31,
    -0x1.0p-2,
    0x1.0p28
  },
  { // Entry 591
    0x1.fffffffffffffff555555555555555bbp-31,
    0x1.0p-2,
    0x1.0p28
  },
  { // Entry 592
    -0x1.ffffffffffffdff555555555575755bbp-31,
    -0x1.0p-2,
    0x1.0000000000001p28
  },
  { // Entry 593
    0x1.ffffffffffffdff555555555575755bbp-31,
    0x1.0p-2,
    0x1.0000000000001p28
  },
  { // Entry 594
    -0x1.fffffffffffffff555555555555555bbp-31,
    -0x1.fffffffffffffp-3,
    0x1.fffffffffffffp27
  },
  { // Entry 595
    0x1.fffffffffffffff555555555555555bbp-31,
    0x1.fffffffffffffp-3,
    0x1.fffffffffffffp27
  },
  { // Entry 596
    -0x1.ffffffffffffeff555555555555655bbp-31,
    -0x1.fffffffffffffp-3,
    0x1.0p28
  },
  { // Entry 597
    0x1.ffffffffffffeff555555555555655
```