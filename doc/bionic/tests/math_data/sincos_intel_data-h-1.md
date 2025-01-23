Response:
The user has provided a snippet of a C source file containing floating-point data, likely used for testing the `sincos` function in Android's bionic library. The request asks for a summary of the file's function.

**Thinking Process:**

1. **Identify the data structure:** The code consists of a series of nested curly braces `{}`, indicating a data structure. Each outer set of braces likely represents an entry, and each inner set contains three floating-point numbers.

2. **Relate to the file name:** The file name "sincos_intel_data.handroid" strongly suggests that this data is used to test the `sin` and `cos` functions (or a combined `sincos` function) on Intel architectures within the Android environment. The ".handroid" might indicate a specific format or origin.

3. **Analyze the data:** The three floating-point numbers in each entry likely represent:
    * Input angle for the `sincos` function.
    * Expected sine value for that angle.
    * Expected cosine value for that angle.

4. **Consider the purpose of test data:** Test data like this is crucial for verifying the accuracy and correctness of mathematical functions. It's often generated using high-precision calculations or reference implementations.

5. **Formulate the summary:** Based on the above points, the file's main function is to provide test vectors for the `sincos` function in Android's bionic library, specifically targeting Intel architectures. Each entry defines an input angle and the corresponding expected sine and cosine values.

6. **Refine the summary:**  Mentioning the data format (array of structures) can add detail. Also, acknowledge that these are *expected* values for verification.
这是目录为 `bionic/tests/math_data/sincos_intel_data.handroid` 的源代码文件的第 2 部分，包含了一系列的C语言结构体数组元素。根据文件名推测，这个文件是用于测试 `sin` 和 `cos` 函数的，并且是针对 Intel 架构的 Android 系统。

**归纳一下它的功能：**

这部分代码定义了一个用于测试 `sincos` 函数的数据集的一部分。具体来说，它包含了一系列预先计算好的输入角度以及对应的预期正弦和余弦值。每个花括号 `{}` 内部包含了三个浮点数，分别代表一个测试用例的：

1. **输入角度 (以弧度表示)**
2. **预期的正弦值**
3. **预期的余弦值**

这些数据用于验证 bionic 库中 `sincos` 函数在给定输入下的计算结果是否与预期值一致，从而确保该函数在 Intel 架构上的正确性和精度。

**更详细的解释：**

该文件很可能是一个大型数组的一部分，数组中的每个元素都定义了一个 `sincos` 函数的测试用例。  测试框架会读取这些数据，将第一个浮点数作为 `sincos` 函数的输入，然后比较函数返回的 sin 和 cos 值与数据中的第二和第三个浮点数，以判断测试是否通过。

**与 Android 功能的关系举例说明：**

在 Android 系统中，很多底层的操作和上层的应用都依赖于精确的数学计算。例如：

* **图形渲染 (Framework)：**  `sin` 和 `cos` 函数被广泛用于 2D 和 3D 图形的旋转、缩放、平移等变换。例如，在绘制一个旋转的动画时，就需要计算不同角度的正弦和余弦值来确定图形上每个点的坐标。
* **传感器数据处理 (Framework/NDK)：**  在处理陀螺仪、加速度计等传感器数据时，可能需要使用三角函数进行坐标转换、姿态解算等。
* **游戏开发 (NDK)：**  游戏中的物体运动轨迹、碰撞检测、视角控制等都可能涉及到三角函数的计算。

**每一个 libc 函数的功能是如何实现的：**

这里的文件本身不包含 libc 函数的实现，它只是测试数据。`sin` 和 `cos` 函数的实现通常会使用各种数学技巧和算法来提高效率和精度，例如：

* **泰勒级数展开:**  这是计算三角函数的一种基本方法，通过将函数展开成无穷级数来逼近其值。
* **切比雪夫逼近:**  使用切比雪夫多项式来逼近函数，可以在给定的误差范围内使用更少的项，从而提高计算效率。
* **范围归约:**  利用三角函数的周期性，将输入的角度值规约到较小的区间（例如 [0, π/2]），然后在该区间内进行计算，最后根据象限调整符号。
* **查找表:**  对于一些精度要求不高的情况，可以使用预先计算好的查找表来快速获取近似值。

现代的 `sin` 和 `cos` 实现通常会结合多种方法，针对不同的输入范围和精度要求选择最优的算法。这些实现往往是高度优化的，并会考虑到特定硬件平台的特性（例如 SIMD 指令）。

**对于涉及 dynamic linker 的功能：**

这个数据文件本身不涉及 dynamic linker。Dynamic linker (在 Android 中主要是 `linker64` 或 `linker`) 的主要职责是在程序启动时将程序依赖的共享库加载到内存中，并解析和处理库之间的符号引用关系。

**so 布局样本：**

假设一个使用了 `sin` 和 `cos` 函数的 Native 代码库 (`libnative.so`)，其可能依赖于 bionic 提供的数学库 (`libm.so`)。其内存布局可能如下所示：

```
[内存地址范围]    libnative.so (包含程序代码和数据段)
[内存地址范围]    libm.so       (包含 sin, cos 等数学函数的代码)
[内存地址范围]    linker64      (动态链接器本身的代码)
```

**链接的处理过程：**

1. **编译链接阶段：** 当 `libnative.so` 被编译和链接时，编译器会识别出对 `sin` 和 `cos` 函数的调用，并在其符号表中记录下这些未定义的符号。链接器会标记这些符号需要从外部库解析。

2. **加载时链接 (Dynamic Linking)：**
   - 当 Android 系统加载 `libnative.so` 时，dynamic linker (`linker64`) 也被启动。
   - `linker64` 会读取 `libnative.so` 的头部信息，找到其依赖的共享库列表（例如 `libm.so`）。
   - `linker64` 会尝试加载这些依赖库到内存中。如果库已经加载，则跳过。
   - `linker64` 会解析 `libnative.so` 中未定义的符号（例如 `sin`, `cos`）。它会在 `libm.so` 的导出符号表中查找匹配的符号。
   - 一旦找到匹配的符号，`linker64` 会更新 `libnative.so` 中的相应调用地址，使其指向 `libm.so` 中 `sin` 和 `cos` 函数的实际地址。这个过程称为 **符号重定位 (Symbol Relocation)**。

**如果做了逻辑推理，请给出假设输入与输出：**

这里的文件是数据，不是逻辑代码。但我们可以假设一个使用这些数据的测试程序：

**假设输入：** 测试程序从该文件中读取一个条目，例如：

```
{ -0x1.2383ca8078e58477cd5fb1d9de031dcep-2, 0x1.ead07cc6356964e27a1036d2f8b158f7p-1, -0x1.279a74590331ap-2, }
```

**预期输出：** 测试程序会将 `-0x1.2383ca8078e58477cd5fb1d9de031dcep-2` (这是一个十六进制浮点数，大约等于 -0.284444) 作为 `sincos` 函数的输入。  `sincos` 函数应该返回一个包含 sin 和 cos 值的结构体或两个独立的浮点数。测试程序会将 `sincos` 的返回值与 `0x1.ead07cc6356964e27a1036d2f8b158f7p-1` (大约等于 0.92489) 和 `-0x1.279a74590331ap-2` (大约等于 -0.0175) 进行比较。如果差异在一定的误差范围内，则该测试用例通过。

**如果涉及用户或者编程常见的使用错误，请举例说明：**

* **精度问题：** 用户可能会期望 `sin` 和 `cos` 函数返回绝对精确的值，但浮点数运算本身存在精度限制。进行比较时需要考虑一定的误差容忍度。
* **角度单位混淆：**  `sin` 和 `cos` 函数通常接受弧度作为输入，但用户可能会错误地使用角度制，导致结果错误。
* **输入范围：** 虽然数学上 `sin` 和 `cos` 的定义域是所有实数，但在实际实现中，对于非常大的输入值，可能会发生精度损失或计算效率降低。
* **未包含头文件：** 在 C/C++ 中使用 `sin` 和 `cos` 函数需要包含 `<math.h>` 头文件，忘记包含会导致编译错误。

**说明 android framework or ndk 是如何一步步的到达这里：**

1. **Android Framework 调用 (Java)：**  在 Android Framework 层，例如在 `android.graphics.Canvas` 中进行图形变换时，可能会调用到 Native 代码来实现底层的渲染操作。

2. **JNI 调用 (Framework -> NDK)：** Framework 层通过 JNI (Java Native Interface) 调用到 NDK (Native Development Kit) 中编译的 C/C++ 代码。

3. **NDK 代码调用 libc 数学函数：**  NDK 中的 C/C++ 代码，比如一个自定义的图形库或者游戏引擎，可能会直接调用 bionic 库提供的 `sin` 和 `cos` 函数。例如：

   ```c++
   #include <cmath>
   #include <android/log.h>

   extern "C" JNIEXPORT void JNICALL
   Java_com_example_myapp_MyRenderer_renderFrame(JNIEnv* env, jobject /* this */, float angle) {
       float s = std::sin(angle);
       float c = std::cos(angle);
       __android_log_print(ANDROID_LOG_DEBUG, "MyRenderer", "sin(%f) = %f, cos(%f) = %f", angle, s, angle, c);
       // ... 使用 s 和 c 进行图形渲染 ...
   }
   ```

4. **链接到 libm.so：**  当 NDK 代码被编译成共享库时，链接器会将对 `std::sin` 和 `std::cos` 的调用链接到 bionic 提供的 `libm.so` 中的实现。

5. **测试 (bionic/tests)：** 为了确保 `libm.so` 中 `sin` 和 `cos` 函数的正确性，Android 的 bionic 库会包含一系列测试用例，这些测试用例的数据就可能来源于像 `sincos_intel_data.handroid` 这样的文件。

**Frida Hook 示例调试这些步骤：**

可以使用 Frida hook NDK 代码中对 `sin` 或 `cos` 函数的调用，或者 hook bionic 库中的实现来进行调试。

**Hook NDK 代码：**

假设要 hook 上面的 `Java_com_example_myapp_MyRenderer_renderFrame` 函数中对 `std::sin` 的调用：

```python
import frida
import sys

package_name = "com.example.myapp"

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except Exception as e:
    print(f"Error attaching to process: {e}")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName(null, "sin"), {
    onEnter: function(args) {
        console.log("[+] Calling sin with argument: " + args[0]);
        this.arg = args[0];
    },
    onLeave: function(retval) {
        console.log("[+] sin returned: " + retval + " for input: " + this.arg);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

这个 Frida 脚本会 hook 所有被调用的 `sin` 函数，并打印出其输入参数和返回值。

**Hook bionic 库中的 sin 函数：**

需要找到 `libm.so` 的加载地址以及 `sin` 函数在 `libm.so` 中的偏移地址。可以使用 `adb shell cat /proc/[pid]/maps` 获取进程的内存映射信息，然后使用工具（如 `objdump` 或 IDA）查看 `libm.so` 的符号表找到 `sin` 函数的偏移。

```python
import frida
import sys

package_name = "com.example.myapp"
libm_name = "libm.so"
sin_offset = 0xXXXXXXXX # 替换为 sin 函数在 libm.so 中的实际偏移

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except Exception as e:
    print(f"Error attaching to process: {e}")
    sys.exit(1)

script_code = """
var libm_base = Module.findBaseAddress("{}");
if (libm_base) {
    var sin_address = libm_base.add({});
    Interceptor.attach(sin_address, {
        onEnter: function(args) {
            console.log("[+] Calling bionic sin with argument: " + args[0]);
            this.arg = args[0];
        },
        onLeave: function(retval) {
            console.log("[+] bionic sin returned: " + retval + " for input: " + this.arg);
        }
    });
} else {
    console.log("[-] Could not find base address of {}");
}
""".format(libm_name, sin_offset, libm_name)

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

这个脚本会直接 hook bionic 库中的 `sin` 函数。

通过这些 Frida hook 示例，可以在运行时观察 `sin` 和 `cos` 函数的调用情况，包括输入参数和返回值，从而帮助理解 Framework、NDK 以及 bionic 库之间的交互。

### 提示词
```
这是目录为bionic/tests/math_data/sincos_intel_data.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
{ // Entry 235
    -0x1.2383ca8078e58477cd5fb1d9de031dcep-2,
    0x1.ead07cc6356964e27a1036d2f8b158f7p-1,
    -0x1.279a74590331ap-2,
  },
  { // Entry 236
    0x1.2383ca8078e58477cd5fb1d9de031dcep-2,
    0x1.ead07cc6356964e27a1036d2f8b158f7p-1,
    0x1.279a74590331ap-2,
  },
  { // Entry 237
    -0x1.d4c5bc11d2371af2fe25ef5ede2766a3p-3,
    0x1.f26840e7b2188f7a0cc661a0ede3728bp-1,
    -0x1.d8f7208e6b829p-3,
  },
  { // Entry 238
    0x1.d4c5bc11d2371af2fe25ef5ede2766a3p-3,
    0x1.f26840e7b2188f7a0cc661a0ede3728bp-1,
    0x1.d8f7208e6b829p-3,
  },
  { // Entry 239
    -0x1.60f3faaf43023d3c7863ae06d4d59774p-3,
    0x1.f856d48db797dec0b79e1353409dc3f2p-1,
    -0x1.62b9586ad0a1ep-3,
  },
  { // Entry 240
    0x1.60f3faaf43023d3c7863ae06d4d59774p-3,
    0x1.f856d48db797dec0b79e1353409dc3f2p-1,
    0x1.62b9586ad0a1ep-3,
  },
  { // Entry 241
    -0x1.d7ea3de45a9d6563ac005c0c5bad8c50p-4,
    0x1.fc97283a424797215f8a8d1967736c9bp-1,
    -0x1.d8f7208e6b826p-4,
  },
  { // Entry 242
    0x1.d7ea3de45a9d6563ac005c0c5bad8c50p-4,
    0x1.fc97283a424797215f8a8d1967736c9bp-1,
    0x1.d8f7208e6b826p-4,
  },
  { // Entry 243
    -0x1.d8b3df489987a6fe0eead008e720aa22p-5,
    0x1.ff259b7ab9f4f9a8cb9f1c333272e409p-1,
    -0x1.d8f7208e6b82dp-5,
  },
  { // Entry 244
    0x1.d8b3df489987a6fe0eead008e720aa22p-5,
    0x1.ff259b7ab9f4f9a8cb9f1c333272e409p-1,
    0x1.d8f7208e6b82dp-5,
  },
  { // Entry 245
    0x1.d8b3df489987a6fe0eead008e720aa22p-5,
    0x1.ff259b7ab9f4f9a8cb9f1c333272e409p-1,
    0x1.d8f7208e6b82dp-5,
  },
  { // Entry 246
    -0x1.d8b3df489987a6fe0eead008e720aa22p-5,
    0x1.ff259b7ab9f4f9a8cb9f1c333272e409p-1,
    -0x1.d8f7208e6b82dp-5,
  },
  { // Entry 247
    0x1.d7ea3de45a9dd4a4bccd1a8c048faf4cp-4,
    0x1.fc97283a424795847294654a1d8a08edp-1,
    0x1.d8f7208e6b82dp-4,
  },
  { // Entry 248
    -0x1.d7ea3de45a9dd4a4bccd1a8c048faf4cp-4,
    0x1.fc97283a424795847294654a1d8a08edp-1,
    -0x1.d8f7208e6b82dp-4,
  },
  { // Entry 249
    0x1.60f3faaf43027c4752f564f9d0818fe8p-3,
    0x1.f856d48db797dbfecfa8b4cd3be44027p-1,
    0x1.62b9586ad0a22p-3,
  },
  { // Entry 250
    -0x1.60f3faaf43027c4752f564f9d0818fe8p-3,
    0x1.f856d48db797dbfecfa8b4cd3be44027p-1,
    -0x1.62b9586ad0a22p-3,
  },
  { // Entry 251
    0x1.d4c5bc11d23759400642e5a1efdc0f85p-3,
    0x1.f26840e7b2188bd0814e3dfc7f6f3f87p-1,
    0x1.d8f7208e6b82dp-3,
  },
  { // Entry 252
    -0x1.d4c5bc11d23759400642e5a1efdc0f85p-3,
    0x1.f26840e7b2188bd0814e3dfc7f6f3f87p-1,
    -0x1.d8f7208e6b82dp-3,
  },
  { // Entry 253
    0x1.2383ca8078e5a324d52c1530742cd4f5p-2,
    0x1.ead07cc6356960546ae634ef62621fb2p-1,
    0x1.279a74590331cp-2,
  },
  { // Entry 254
    -0x1.2383ca8078e5a324d52c1530742cd4f5p-2,
    0x1.ead07cc6356960546ae634ef62621fb2p-1,
    -0x1.279a74590331cp-2,
  },
  { // Entry 255
    0x1.5bac064658f3b27a28572bea256195efp-2,
    0x1.e1960261829852ca662ca27d518c2fa9p-1,
    0x1.62b9586ad0a22p-2,
  },
  { // Entry 256
    -0x1.5bac064658f3b27a28572bea256195efp-2,
    0x1.e1960261829852ca662ca27d518c2fa9p-1,
    -0x1.62b9586ad0a22p-2,
  },
  { // Entry 257
    0x1.92aba90aaf274209efaed08e34071e3bp-2,
    0x1.d6c0b125791cf983d53efaa7d45e291ep-1,
    0x1.9dd83c7c9e128p-2,
  },
  { // Entry 258
    -0x1.92aba90aaf274209efaed08e34071e3bp-2,
    0x1.d6c0b125791cf983d53efaa7d45e291ep-1,
    -0x1.9dd83c7c9e128p-2,
  },
  { // Entry 259
    0x1.c853c78462de635b10a2b93afd75da26p-2,
    0x1.ca59c6fa3d9cdb17530927aff1b33abbp-1,
    0x1.d8f7208e6b82ep-2,
  },
  { // Entry 260
    -0x1.c853c78462de635b10a2b93afd75da26p-2,
    0x1.ca59c6fa3d9cdb17530927aff1b33abbp-1,
    -0x1.d8f7208e6b82ep-2,
  },
  { // Entry 261
    0x1.fc769b77e588495a6f642ca24e4ed3fcp-2,
    0x1.bc6bd861e13de309428e00f7bef6c3ecp-1,
    0x1.0a0b02501c799p-1,
  },
  { // Entry 262
    -0x1.fc769b77e588495a6f642ca24e4ed3fcp-2,
    0x1.bc6bd861e13de309428e00f7bef6c3ecp-1,
    -0x1.0a0b02501c799p-1,
  },
  { // Entry 263
    0x1.295463e769281640ae026f50fc45e301p-1,
    0x1.a0d1f8a9a791f9dff5c993af4908264dp-1,
    0x1.3d3e35834faccp-1,
  },
  { // Entry 264
    -0x1.295463e769281640ae026f50fc45e301p-1,
    0x1.a0d1f8a9a791f9dff5c993af4908264dp-1,
    -0x1.3d3e35834faccp-1,
  },
  { // Entry 265
    0x1.3aacff95a311f899a0e279535e81c4ecp-1,
    0x1.93e2948233fd0f69e3918982148f8265p-1,
    0x1.52e1f6ad9c27cp-1,
  },
  { // Entry 266
    -0x1.3aacff95a311f899a0e279535e81c4ecp-1,
    0x1.93e2948233fd0f69e3918982148f8265p-1,
    -0x1.52e1f6ad9c27cp-1,
  },
  { // Entry 267
    0x1.4b75ba096fa5192442b7950f960f8006p-1,
    0x1.863a850e43900997e76be80405437377p-1,
    0x1.6885b7d7e8a2cp-1,
  },
  { // Entry 268
    -0x1.4b75ba096fa5192442b7950f960f8006p-1,
    0x1.863a850e43900997e76be80405437377p-1,
    -0x1.6885b7d7e8a2cp-1,
  },
  { // Entry 269
    0x1.5ba6e6a8e706245f97e28af3ddb700f6p-1,
    0x1.77e008d0775e9fc38e3f492f8e93ff51p-1,
    0x1.7e297902351dcp-1,
  },
  { // Entry 270
    -0x1.5ba6e6a8e706245f97e28af3ddb700f6p-1,
    0x1.77e008d0775e9fc38e3f492f8e93ff51p-1,
    -0x1.7e297902351dcp-1,
  },
  { // Entry 271
    0x1.6b391e25bc269ea1c1a40de62fbc03b4p-1,
    0x1.68d9afe052d21e50560f9ffb6cc1b945p-1,
    0x1.93cd3a2c8198cp-1,
  },
  { // Entry 272
    -0x1.6b391e25bc269ea1c1a40de62fbc03b4p-1,
    0x1.68d9afe052d21e50560f9ffb6cc1b945p-1,
    -0x1.93cd3a2c8198cp-1,
  },
  { // Entry 273
    0x1.7a2541dfd4e727b86dd309664186ec6bp-1,
    0x1.592e58ea0a9f1b4fddbaaf868fe47911p-1,
    0x1.a970fb56ce13cp-1,
  },
  { // Entry 274
    -0x1.7a2541dfd4e727b86dd309664186ec6bp-1,
    0x1.592e58ea0a9f1b4fddbaaf868fe47911p-1,
    -0x1.a970fb56ce13cp-1,
  },
  { // Entry 275
    0x1.88647f26a6e0cd95cb991f7ffe61a02ep-1,
    0x1.48e52e0a65bce4d9d62a31293f7d41c1p-1,
    0x1.bf14bc811a8ecp-1,
  },
  { // Entry 276
    -0x1.88647f26a6e0cd95cb991f7ffe61a02ep-1,
    0x1.48e52e0a65bce4d9d62a31293f7d41c1p-1,
    -0x1.bf14bc811a8ecp-1,
  },
  { // Entry 277
    0x1.95f05257dbcb384a5e326857376dd801p-1,
    0x1.3805a188200a254247f30462c36acf6ap-1,
    0x1.d4b87dab6709cp-1,
  },
  { // Entry 278
    -0x1.95f05257dbcb384a5e326857376dd801p-1,
    0x1.3805a188200a254247f30462c36acf6ap-1,
    -0x1.d4b87dab6709cp-1,
  },
  { // Entry 279
    0x1.a2c289d9d0558764921a4de355f9448cp-1,
    0x1.26976a6c4e0fbabb84632bd99feec9c6p-1,
    0x1.ea5c3ed5b384cp-1,
  },
  { // Entry 280
    -0x1.a2c289d9d0558764921a4de355f9448cp-1,
    0x1.26976a6c4e0fbabb84632bd99feec9c6p-1,
    -0x1.ea5c3ed5b384cp-1,
  },
  { // Entry 281
    0x1.c1e9883373d7ecc48c92dc8875505f7ep-1,
    0x1.e8c405f36f85b7f5d6a38dfd4a692341p-2,
    0x1.12bd9173c07abp0,
  },
  { // Entry 282
    -0x1.c1e9883373d7ecc48c92dc8875505f7ep-1,
    0x1.e8c405f36f85b7f5d6a38dfd4a692341p-2,
    -0x1.12bd9173c07abp0,
  },
  { // Entry 283
    0x1.d294d1f96c7ef26e203c5b309a55671fp-1,
    0x1.a5a4ccf40d9cb25f16ad97e480c4b483p-2,
    0x1.257b22e780f56p0,
  },
  { // Entry 284
    -0x1.d294d1f96c7ef26e203c5b309a55671fp-1,
    0x1.a5a4ccf40d9cb25f16ad97e480c4b483p-2,
    -0x1.257b22e780f56p0,
  },
  { // Entry 285
    0x1.e0c04a94e17335d073052a0394b9e1c3p-1,
    0x1.6043621b13bd3f904b3b876df5b2c6f4p-2,
    0x1.3838b45b41701p0,
  },
  { // Entry 286
    -0x1.e0c04a94e17335d073052a0394b9e1c3p-1,
    0x1.6043621b13bd3f904b3b876df5b2c6f4p-2,
    -0x1.3838b45b41701p0,
  },
  { // Entry 287
    0x1.ec5883b7b6cf70a577dd9160d0f8e9d5p-1,
    0x1.18fee96a1a5762fc6770ff168e06ab3ep-2,
    0x1.4af645cf01eacp0,
  },
  { // Entry 288
    -0x1.ec5883b7b6cf70a577dd9160d0f8e9d5p-1,
    0x1.18fee96a1a5762fc6770ff168e06ab3ep-2,
    -0x1.4af645cf01eacp0,
  },
  { // Entry 289
    0x1.f54d971881ad82629bd84d214194e8ddp-1,
    0x1.a0723a95492ce998457fb7a0d09a6385p-3,
    0x1.5db3d742c2657p0,
  },
  { // Entry 290
    -0x1.f54d971881ad82629bd84d214194e8ddp-1,
    0x1.a0723a95492ce998457fb7a0d09a6385p-3,
    -0x1.5db3d742c2657p0,
  },
  { // Entry 291
    0x1.fb933c40107fe83fd16c1789e27f69f7p-1,
    0x1.0cab9115640b9d9d466723bbd5d589bep-3,
    0x1.707168b682e02p0,
  },
  { // Entry 292
    -0x1.fb933c40107fe83fd16c1789e27f69f7p-1,
    0x1.0cab9115640b9d9d466723bbd5d589bep-3,
    -0x1.707168b682e02p0,
  },
  { // Entry 293
    0x1.ff20d961624e77daef329b4029c362dep-1,
    0x1.ddd1ec25e201f538925bf5bcf7c7df6ep-5,
    0x1.832efa2a435adp0,
  },
  { // Entry 294
    -0x1.ff20d961624e77daef329b4029c362dep-1,
    0x1.ddd1ec25e201f538925bf5bcf7c7df6ep-5,
    -0x1.832efa2a435adp0,
  },
  { // Entry 295
    0x1.fff18f24f3e4b69592294f206d7b32c2p-1,
    -0x1.e6669a270c56d3a08d91cc2721f92fe1p-7,
    0x1.95ec8b9e03d58p0,
  },
  { // Entry 296
    -0x1.fff18f24f3e4b69592294f206d7b32c2p-1,
    -0x1.e6669a270c56d3a08d91cc2721f92fe1p-7,
    -0x1.95ec8b9e03d58p0,
  },
  { // Entry 297
    0x1.fe043f57369d6a52fa33f0119ec4da19p-1,
    -0x1.682f3cc3c7a08da2ce02a41cdc7bed86p-4,
    0x1.a8aa1d11c44ffp0,
  },
  { // Entry 298
    -0x1.fe043f57369d6a52fa33f0119ec4da19p-1,
    -0x1.682f3cc3c7a08da2ce02a41cdc7bed86p-4,
    -0x1.a8aa1d11c44ffp0,
  },
  { // Entry 299
    0x1.b3d3695acc4136b2d44714f9b38419b4p-1,
    0x1.0cb3469a29ea66d4031be769702aad5cp-1,
    0x1.04aff6d330942p0,
  },
  { // Entry 300
    -0x1.b3d3695acc4136b2d44714f9b38419b4p-1,
    0x1.0cb3469a29ea66d4031be769702aad5cp-1,
    -0x1.04aff6d330942p0,
  },
  { // Entry 301
    0x1.b3d41972dc8063994f63413d5e4d8e4bp-1,
    0x1.0cb228fa7f8117c82e61cf5393341c64p-1,
    0x1.04b09e98dcdb4p0,
  },
  { // Entry 302
    -0x1.b3d41972dc8063994f63413d5e4d8e4bp-1,
    0x1.0cb228fa7f8117c82e61cf5393341c64p-1,
    -0x1.04b09e98dcdb4p0,
  },
  { // Entry 303
    0x1.b3d4c98a318fb66f821d7286ae7dce7bp-1,
    0x1.0cb10b5a61b05a73e78a3e4447baf514p-1,
    0x1.04b1465e89226p0,
  },
  { // Entry 304
    -0x1.b3d4c98a318fb66f821d7286ae7dce7bp-1,
    0x1.0cb10b5a61b05a73e78a3e4447baf514p-1,
    -0x1.04b1465e89226p0,
  },
  { // Entry 305
    0x1.b3d579a0cb6ee393ff75b58ffe16d13fp-1,
    0x1.0cafedb9d078a984086928aa40d2e4a5p-1,
    0x1.04b1ee2435698p0,
  },
  { // Entry 306
    -0x1.b3d579a0cb6ee393ff75b58ffe16d13fp-1,
    0x1.0cafedb9d078a984086928aa40d2e4a5p-1,
    -0x1.04b1ee2435698p0,
  },
  { // Entry 307
    0x1.b3d629b6aa1d9f65aad1a2fc932c8bcbp-1,
    0x1.0caed018cbda7fa59c631cd55b31aa8dp-1,
    0x1.04b295e9e1b0ap0,
  },
  { // Entry 308
    -0x1.b3d629b6aa1d9f65aad1a2fc932c8bcbp-1,
    0x1.0caed018cbda7fa59c631cd55b31aa8dp-1,
    -0x1.04b295e9e1b0ap0,
  },
  { // Entry 309
    0x1.b3d6d9cbcd9b9e43b7fc7fd428a44dd8p-1,
    0x1.0cadb27753d65785e06d0e464006149ep-1,
    0x1.04b33daf8df7cp0,
  },
  { // Entry 310
    -0x1.b3d6d9cbcd9b9e43b7fc7fd428a44dd8p-1,
    0x1.0cadb27753d65785e06d0e464006149ep-1,
    -0x1.04b33daf8df7cp0,
  },
  { // Entry 311
    0x1.b3d789e035e8948dab275dfe546c5b08p-1,
    0x1.0cac94d5686cabd2430c20fdf2855b47p-1,
    0x1.04b3e5753a3eep0,
  },
  { // Entry 312
    -0x1.b3d789e035e8948dab275dfe546c5b08p-1,
    0x1.0cac94d5686cabd2430c20fdf2855b47p-1,
    -0x1.04b3e5753a3eep0,
  },
  { // Entry 313
    0x1.b3d839f3e30436a358e93cbdcb2bb367p-1,
    0x1.0cab7733099df738645574cd482ef4b2p-1,
    0x1.04b48d3ae6860p0,
  },
  { // Entry 314
    -0x1.b3d839f3e30436a358e93cbdcb2bb367p-1,
    0x1.0cab7733099df738645574cd482ef4b2p-1,
    -0x1.04b48d3ae6860p0,
  },
  { // Entry 315
    0x1.b3d8ea06d4ee0684f5741ec777ed88e0p-1,
    0x1.0caa5990376b061ec1cf3890f1b8e1e3p-1,
    0x1.04b5350092ccfp0,
  },
  { // Entry 316
    -0x1.b3d8ea06d4ee0684f5741ec777ed88e0p-1,
    0x1.0caa5990376b061ec1cf3890f1b8e1e3p-1,
    -0x1.04b5350092ccfp0,
  },
  { // Entry 317
    -0.0,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.0p-1074,
  },
  { // Entry 318
    0.0,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.0p-1074,
  },
  { // Entry 319
    -0.0,
    0x1.p0,
    -0.0,
  },
  { // Entry 320
    0.0,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.0p-1074,
  },
  { // Entry 321
    -0.0,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.0p-1074,
  },
  { // Entry 322
    0x1.1773d561fd5065d0e9607a728a39eed2p-1,
    0x1.ad02c771c35ed5f01089a00c6a27e0cfp-1,
    0x1.279a74590331bp-1,
  },
  { // Entry 323
    -0x1.1773d561fd5065d0e9607a728a39eed2p-1,
    0x1.ad02c771c35ed5f01089a00c6a27e0cfp-1,
    -0x1.279a74590331bp-1,
  },
  { // Entry 324
    0x1.1773d561fd507338ff9c088d80c680dbp-1,
    0x1.ad02c771c35ecd3471de9021e6c3b92bp-1,
    0x1.279a74590331cp-1,
  },
  { // Entry 325
    -0x1.1773d561fd507338ff9c088d80c680dbp-1,
    0x1.ad02c771c35ecd3471de9021e6c3b92bp-1,
    -0x1.279a74590331cp-1,
  },
  { // Entry 326
    0x1.1773d561fd5080a115d796a8770d35efp-1,
    0x1.ad02c771c35ec478d333803762f450d5p-1,
    0x1.279a74590331dp-1,
  },
  { // Entry 327
    -0x1.1773d561fd5080a115d796a8770d35efp-1,
    0x1.ad02c771c35ec478d333803762f450d5p-1,
    -0x1.279a74590331dp-1,
  },
  { // Entry 328
    0x1.f95b8e7107418c11c94d4a54a9da9b7ap-1,
    -0x1.48d1ddd2b2b3f8c21b9421e65b380735p-3,
    0x1.bb67ae8584ca9p0,
  },
  { // Entry 329
    -0x1.f95b8e7107418c11c94d4a54a9da9b7ap-1,
    -0x1.48d1ddd2b2b3f8c21b9421e65b380735p-3,
    -0x1.bb67ae8584ca9p0,
  },
  { // Entry 330
    0x1.f95b8e71074186ee81d5ff89d8fae545p-1,
    -0x1.48d1ddd2b2b47718ff3063b6bd981099p-3,
    0x1.bb67ae8584caap0,
  },
  { // Entry 331
    -0x1.f95b8e71074186ee81d5ff89d8fae545p-1,
    -0x1.48d1ddd2b2b47718ff3063b6bd981099p-3,
    -0x1.bb67ae8584caap0,
  },
  { // Entry 332
    0x1.f95b8e71074181cb3a5eb4bf0621d381p-1,
    -0x1.48d1ddd2b2b4f56fe2cca5871eaf4820p-3,
    0x1.bb67ae8584cabp0,
  },
  { // Entry 333
    -0x1.f95b8e71074181cb3a5eb4bf0621d381p-1,
    -0x1.48d1ddd2b2b4f56fe2cca5871eaf4820p-3,
    -0x1.bb67ae8584cabp0,
  },
  { // Entry 334
    0x1.b1d8305321615ac938cff02be9f25085p-2,
    0x1.cfc6cfa52ad9f9911db4ca0d45fdb0b3p-1,
    0x1.bffffffffffffp-2,
  },
  { // Entry 335
    -0x1.b1d8305321615ac938cff02be9f25085p-2,
    0x1.cfc6cfa52ad9f9911db4ca0d45fdb0b3p-1,
    -0x1.bffffffffffffp-2,
  },
  { // Entry 336
    0x1.b1d83053216169476f4d1982b9b14ab1p-2,
    0x1.cfc6cfa52ad9f62d6d5423ca8339a00ap-1,
    0x1.cp-2,
  },
  { // Entry 337
    -0x1.b1d83053216169476f4d1982b9b14ab1p-2,
    0x1.cfc6cfa52ad9f62d6d5423ca8339a00ap-1,
    -0x1.cp-2,
  },
  { // Entry 338
    0x1.b1d83053216177c5a5ca42d98955275ap-2,
    0x1.cfc6cfa52ad9f2c9bcf37d87c05892f5p-1,
    0x1.c000000000001p-2,
  },
  { // Entry 339
    -0x1.b1d83053216177c5a5ca42d98955275ap-2,
    0x1.cfc6cfa52ad9f2c9bcf37d87c05892f5p-1,
    -0x1.c000000000001p-2,
  },
  { // Entry 340
    0x1.44eb381cf3869ea71ccb36863e4ea65bp-1,
    0x1.8bb105a5dc90104051d08cb965631807p-1,
    0x1.5ffffffffffffp-1,
  },
  { // Entry 341
    -0x1.44eb381cf3869ea71ccb36863e4ea65bp-1,
    0x1.8bb105a5dc90104051d08cb965631807p-1,
    -0x1.5ffffffffffffp-1,
  },
  { // Entry 342
    0x1.44eb381cf386ab04a4f8656abea80b83p-1,
    0x1.8bb105a5dc900618f80fa51d303c69p-1,
    0x1.6p-1,
  },
  { // Entry 343
    -0x1.44eb381cf386ab04a4f8656abea80b83p-1,
    0x1.8bb105a5dc900618f80fa51d303c69p-1,
    -0x1.6p-1,
  },
  { // Entry 344
    0x1.44eb381cf386b7622d25944f3eb035dcp-1,
    0x1.8bb105a5dc8ffbf19e4ebd80fab2cdb8p-1,
    0x1.6000000000001p-1,
  },
  { // Entry 345
    -0x1.44eb381cf386b7622d25944f3eb035dcp-1,
    0x1.8bb105a5dc8ffbf19e4ebd80fab2cdb8p-1,
    -0x1.6000000000001p-1,
  },
  { // Entry 346
    0x1.dad902fa8ac864fd8afa0bdc609ded19p-1,
    0x1.7ef4842f0bcd11686aaf6f21c9aa8354p-2,
    0x1.2ffffffffffffp0,
  },
  { // Entry 347
    -0x1.dad902fa8ac864fd8afa0bdc609ded19p-1,
    0x1.7ef4842f0bcd11686aaf6f21c9aa8354p-2,
    -0x1.2ffffffffffffp0,
  },
  { // Entry 348
    0x1.dad902fa8ac870f52f1b843ac83bc3edp-1,
    0x1.7ef4842f0bccd60d4a501dc8bc4b57b3p-2,
    0x1.3p0,
  },
  { // Entry 349
    -0x1.dad902fa8ac870f52f1b843ac83bc3edp-1,
    0x1.7ef4842f0bccd60d4a501dc8bc4b57b3p-2,
    -0x1.3p0,
  },
  { // Entry 350
    0x1.dad902fa8ac87cecd33cfc992dfec1bep-1,
    0x1.7ef4842f0bcc9ab229f0cc6fad6d378dp-2,
    0x1.3000000000001p0,
  },
  { // Entry 351
    -0x1.dad902fa8ac87cecd33cfc992dfec1bep-1,
    0x1.7ef4842f0bcc9ab229f0cc6fad6d378dp-2,
    -0x1.3000000000001p0,
  },
  { // Entry 352
    0x1.4b707a7acdecf90a188d0230fad3ad58p-1,
    -0x1.863efa361dc2294e929b9515fb34f9bap-1,
    0x1.37fffffffffffp1,
  },
  { // Entry 353
    -0x1.4b707a7acdecf90a188d0230fad3ad58p-1,
    -0x1.863efa361dc2294e929b9515fb34f9bap-1,
    -0x1.37fffffffffffp1,
  },
  { // Entry 354
    0x1.4b707a7acdecc84239463e78b312fa10p-1,
    -0x1.863efa361dc252bca1eaeed39749bed7p-1,
    0x1.380p1,
  },
  { // Entry 355
    -0x1.4b707a7acdecc84239463e78b312fa10p-1,
    -0x1.863efa361dc252bca1eaeed39749bed7p-1,
    -0x1.380p1,
  },
  { // Entry 356
    0x1.4b707a7acdec977a59ff7ac0662484ddp-1,
    -0x1.863efa361dc27c2ab13a48912d45880bp-1,
    0x1.3800000000001p1,
  },
  { // Entry 357
    -0x1.4b707a7acdec977a59ff7ac0662484ddp-1,
    -0x1.863efa361dc27c2ab13a48912d45880bp-1,
    -0x1.3800000000001p1,
  },
  { // Entry 358
    0x1.066e7eb76f5c6678fd8325a81f1925c6p-4,
    0x1.fef2b2d21cf6c106e86ff9395f8204a0p-1,
    0x1.069c8b46b3792p-4,
  },
  { // Entry 359
    -0x1.066e7eb76f5c6678fd8325a81f1925c6p-4,
    0x1.fef2b2d21cf6c106e86ff9395f8204a0p-1,
    -0x1.069c8b46b3792p-4,
  },
  { // Entry 360
    0x1.05e4761ab8d8f0a7dba834000f236650p-3,
    0x1.fbcbe693bd8ec85723b6cb55e4f5e78fp-1,
    0x1.069c8b46b3792p-3,
  },
  { // Entry 361
    -0x1.05e4761ab8d8f0a7dba834000f236650p-3,
    0x1.fbcbe693bd8ec85723b6cb55e4f5e78fp-1,
    -0x1.069c8b46b3792p-3,
  },
  { // Entry 362
    0x1.877e2cd4f6fd9ba498e327053032734fp-3,
    0x1.f68eebfcbb5e841900e2542f7c24bab0p-1,
    0x1.89ead0ea0d35bp-3,
  },
  { // Entry 363
    -0x1.877e2cd4f6fd9ba498e327053032734fp-3,
    0x1.f68eebfcbb5e841900e2542f7c24bab0p-1,
    -0x1.89ead0ea0d35bp-3,
  },
  { // Entry 364
    0x1.03be06f97cbee47698539f977cadbe7ep-2,
    0x1.ef4145b4aecffbdaaffb78ffb49ac9bdp-1,
    0x1.069c8b46b3792p-2,
  },
  { // Entry 365
    -0x1.03be06f97cbee47698539f977cadbe7ep-2,
    0x1.ef4145b4aecffbdaaffb78ffb49ac9bdp-1,
    -0x1.069c8b46b3792p-2,
  },
  { // Entry 366
    0x1.42abba8c72fbb8ca96f79aa4bb03584ep-2,
    0x1.e5eaa286fbbc670dbf6392d7c98ab0a0p-1,
    0x1.4843ae1860576p-2,
  },
  { // Entry 367
    -0x1.42abba8c72fbb8ca96f79aa4bb03584ep-2,
    0x1.e5eaa286fbbc670dbf6392d7c98ab0a0p-1,
    -0x1.4843ae1860576p-2,
  },
  { // Entry 368
    0x1.8045fe64e62dc3d686d976d7d5a7c689p-2,
    0x1.da94d54dd4c0876e18ee97c70d1a4a94p-1,
    0x1.89ead0ea0d35ap-2,
  },
  { // Entry 369
    -0x1.8045fe64e62dc3d686d976d7d5a7c689p-2,
    0x1.da94d54dd4c0876e18ee97c70d1a4a94p-1,
    -0x1.89ead0ea0d35ap-2,
  },
  { // Entry 370
    0x1.bc4c04d71abbeea5ab064ecfbf54c613p-2,
    0x1.cd4bca9cb5c715302001e446cc93a7bcp-1,
    0x1.cb91f3bbba13ep-2,
  },
  { // Entry 371
    -0x1.bc4c04d71abbeea5ab064ecfbf54c613p-2,
    0x1.cd4bca9cb5c715302001e446cc93a7bcp-1,
    -0x1.cb91f3bbba13ep-2,
  },
  { // Entry 372
    0x1.f67ea975b86a01510e6bde3778138934p-2,
    0x1.be1d7c3534c40331fddf243d8a0a56b0p-1,
    0x1.069c8b46b3791p-1,
  },
  { // Entry 373
    -0x1.f67ea975b86a01510e6bde3778138934p-2,
    0x1.be1d7c3534c40331fddf243d8a0a56b0p-1,
    -0x1.069c8b46b3791p-1,
  },
  { // Entry 374
    0x1.175059bf0d42524ecb0bf4243b55973dp-1,
    0x1.ad19e2535aa9678bd5fdafc68817700bp-1,
    0x1.27701caf89e83p-1,
  },
  { // Entry 375
    -0x1.175059bf0d42524ecb0bf4243b55973dp-1,
    0x1.ad19e2535aa9678bd5fdafc68817700bp-1,
    -0x1.27701caf89e83p-1,
  },
  { // Entry 376
    0x1.323b8b1fb4ba21dd12cce820e156a4fcp-1,
    0x1.9a52e2e0fbcb3a3f4bde6f6ec27767a9p-1,
    0x1.4843ae1860575p-1,
  },
  { // Entry 377
    -0x1.323b8b1fb4ba21dd12cce820e156a4fcp-1,
    0x1.9a52e2e0fbcb3a3f4bde6f6ec27767a9p-1,
    -0x1.4843ae1860575p-1,
  },
  { // Entry 378
    0x1.4be4979c5efb306c1a77024032849b52p-1,
    0x1.85dc3ea1bbce9a8085f66593a87b7e2ep-1,
    0x1.69173f8136c67p-1,
  },
  { // Entry 379
    -0x1.4be4979c5efb306c1a77024032849b52p-1,
    0x1.85dc3ea1bbce9a8085f66593a87b7e2ep-1,
    -0x1.69173f8136c67p-1,
  },
  { // Entry 380
    0x1.643080d67acc1332c64a85612cacafb9p-1,
    0x1.6fcb7c6b8b919af3dda53094c9a27aabp-1,
    0x1.89ead0ea0d359p-1,
  },
  { // Entry 381
    -0x1.643080d67acc1332c64a85612cacafb9p-1,
    0x1.6fcb7c6b8b919af3dda53094c9a27aabp-1,
    -0x1.89ead0ea0d359p-1,
  },
  { // Entry 382
    0x1.7b05b7b6c612e5b08d5efe49a46e21a1p-1,
    0x1.5837d2817cf303ef6dae69faeb0f015ep-1,
    0x1.aabe6252e3a4bp-1,
  },
  { // Entry 383
    -0x1.7b05b7b6c612e5b08d5efe49a46e21a1p-1,
    0x1.5837d2817cf303ef6dae69faeb0f015ep-1,
    -0x1.aabe6252e3a4bp-1,
  },
  { // Entry 384
    0x1.904c37505de48fa8e76287960fd44594p-1,
    0x1.3f3a0e28bedd40445858f823e150264bp-1,
    0x1.cb91f3bbba13dp-1,
  },
  { // Entry 385
    -0x1.904c37505de48fa8e76287960fd44594p-1,
    0x1.3f3a0e28bedd40445858f823e150264bp-1,
    -0x1.cb91f3bbba13dp-1,
  },
  { // Entry 386
    0x1.a3ed9e252938a14c79c575639c15a91dp-1,
    0x1.24ec799171642dbd24d259005822bd25p-1,
    0x1.ec6585249082fp-1,
  },
  { // Entry 387
    -0x1.a3ed9e252938a14c79c575639c15a91dp-1,
    0x1.24ec799171642dbd24d259005822bd25p-1,
    -0x1.ec6585249082fp-1,
  },
  { // Entry 388
    0x1.b5d545b109bf935594036798cf40c9b0p-1,
    0x1.096ac02ec42c85b7b10afed9202785b9p-1,
    0x1.069c8b46b3791p0,
  },
  { // Entry 389
    -0x1.b5d545b109bf935594036798cf40c9b0p-1,
    0x1.096ac02ec42c85b7b10afed9202785b9p-1,
    -0x1.069c8b46b3791p0,
  },
  { // Entry 390
    0x1.c5f058230e7fd14d3e5e315349f699efp-1,
    0x1.d9a3a336edb7613df062e86a32d09fe1p-2,
    0x1.170653fb1eb0ap0,
  },
  { // Entry 391
    -0x1.c5f058230e7fd14d3e5e315349f699efp-1,
    0x1.d9a3a336edb7613df062e86a32d09fe1p-2,
    -0x1.170653fb1eb0ap0,
  },
  { // Entry 392
    0x1.d42de42dce1346a03d1f6abf0eba9022p-1,
    0x1.9e7f8652b47582afd29744293170c07cp-2,
    0x1.27701caf89e83p0,
  },
  { // Entry 393
    -0x1.d42de42dce1346a03d1f6abf0eba9022p-1,
    0x1.9e7f8652b47582afd29744293170c07cp-2,
    -0x1.27701caf89e83p0,
  },
  { // Entry 394
    0x1.e07eeeda109cb504afcca860d4b5dd32p-1,
    0x1.61a76077aee07bb349ca76cf700913d1p-2,
    0x1.37d9e563f51fcp0,
  },
  { // Entry 395
    -0x1.e07eeeda109cb504afcca860d4b5dd32p-1,
    0x1.61a76077aee07bb349ca76cf700913d1p-2,
    -0x1.37d9e563f51fcp0,
  },
  { // Entry 396
    0x1.ead6834909b93371faf3beaddbd60eddp-1,
    0x1.235b331d8f748e20fb6ddb6a708dba10p-2,
    0x1.4843ae1860575p0,
  },
  { // Entry 397
    -0x1.ead6834909b93371faf3beaddbd60eddp-1,
    0x1.235b331d8f748e20fb6ddb6a708dba10p-2,
    -0x1.4843ae1860575p0,
  },
  { // Entry 398
    0x1.f329c0558e967e4cab58d0fa572d62d2p-1,
    0x1.c7b90e3024593da8449963cfe08dde85p-3,
    0x1.58ad76cccb8eep0,
  },
  { // Entry 399
    -0x1.f329c0558e967e4cab58d0fa572d62d2p-1,
    0x1.c7b90e3024593da8449963cfe08dde85p-3,
    -0x1.58ad76cccb8eep0,
  },
  { // Entry 400
    0x1.f96fe405f1ac5dc9cf343508067bfcaep-1,
    0x1.46dc4f4ce83da727ea048cc7d2f276d1p-3,
    0x1.69173f8136c67p0,
  },
  { // Entry 401
    -0x1.f96fe405f1ac5dc9cf343508067bfcaep-1,
    0x1.46dc4f4ce83da727ea048cc7d2f276d1p-3,
    -0x1.69173f8136c67p0,
  },
  { // Entry 402
    0x1.fda254c27a01f4786c149d6a7779cc3ap-1,
    0x1.894f70befbb99ab7df9d1790a28f48adp-4,
    0x1.79810835a1fe0p0,
  },
  { // Entry 403
    -0x1.fda254c27a01f4786c149d6a7779cc3ap-1,
    0x1.894f70befbb99ab7df9d1790a28f48adp-4,
    -0x1.79810835a1fe0p0,
  },
  { // Entry 404
    0x1.ffbca846c4fc997f1a381420208884e0p-1,
    0x1.069107ae9332f95fa2c5ceeadfb29f77p-5,
    0x1.89ead0ea0d359p0,
  },
  { // Entry 405
    -0x1.ffbca846c4fc997f1a381420208884e0p-1,
    0x1.069107ae9332f95fa2c5ceeadfb29f77p-5,
    -0x1.89ead0ea0d359p0,
  },
  { // Entry 406
    0x1.ffbca846c4fc9f30bfb458ef2091c8eep-1,
    -0x1.069107ae9327e0731a748c21f03b5efcp-5,
    0x1.9a54999e786d2p0,
  },
  { // Entry 407
    -0x1.ffbca846c4fc9f30bfb458ef2091c8eep-1,
    -0x1.069107ae9327e0731a748c21f03b5efcp-5,
    -0x1.9a54999e786d2p0,
  },
  { // Entry 408
    0x1.fda254c27a0205875f271435f827160cp-1,
    -0x1.894f70befbb41417dff843e81fac388bp-4,
    0x1.aabe6252e3a4bp0,
  },
  { // Entry 409
    -0x1.fda254c27a0205875f271435f827160cp-1,
    -0x1.894f70befbb41417dff843e81fac388bp-4,
    -0x1.aabe6252e3a4bp0,
  },
  { // Entry 410
    0x1.f96fe405f1ac7a241e02e58b0cbf3ae7p-1,
    -0x1.46dc4f4ce83ae9ab1cc1b2367cb753ebp-3,
    0x1.bb282b074edc4p0,
  },
  { // Entry 411
    -0x1.f96fe405f1ac7a241e02e58b0cbf3ae7p-1,
    -0x1.46dc4f4ce83ae9ab1cc1b2367cb753ebp-3,
    -0x1.bb282b074edc4p0,
  },
  { // Entry 412
    0x1.f329c0558e96a5d48272ad4c49ec53b8p-1,
    -0x1.c7b90e30245688e099860e8d4fff601cp-3,
    0x1.cb91f3bbba13dp0,
  },
  { // Entry 413
    -0x1.f329c0558e96a5d48272ad4c49ec53b8p-1,
    -0x1.c7b90e30245688e099860e8d4fff601cp-3,
    -0x1.cb91f3bbba13dp0,
  },
  { // Entry 414
    0x1.ead6834909b965fdc4b0ceffc0f285c6p-1,
    -0x1.235b331d8f7339841a517312d0d347fbp-2,
    0x1.dbfbbc70254b6p0,
  },
  { // Entry 415
    -0x1.ead6834909b965fdc4b0ceffc0f285c6p-1,
    -0x1.235b331d8f7339841a517312d0d347fbp-2,
    -0x1.dbfbbc70254b6p0,
  },
  { // Entry 416
    0x1.e07eeeda109cf25f400cd5f46acec887p-1,
    -0x1.61a76077aedf2e43aca418f7a2e1324dp-2,
    0x1.ec6585249082fp0,
  },
  { // Entry 417
    -0x1.e07eeeda109cf25f400cd5f46acec887p-1,
    -0x1.61a76077aedf2e43aca418f7a2e1324dp-2,
    -0x1.ec6585249082fp0,
  },
  { // Entry 418
    0x1.d42de42dce138e890939e56c439ded90p-1,
    -0x1.9e7f8652b4743dcc3c3568baff8bf9ebp-2,
    0x1.fccf4dd8fbba8p0,
  },
  { // Entry 419
    -0x1.d42de42dce138e890939e56c439ded90p-1,
    -0x1.9e7f8652b4743dcc3c3568baff8bf9ebp-2,
    -0x1.fccf4dd8fbba8p0,
  },
  { // Entry 420
    0x1.c5f058230e8014ab83ece0c3a638c079p-1,
    -0x1.d9a3a336edb65efa30e1a6679aa064c2p-2,
    0x1.069c8b46b3791p1,
  },
  { // Entry 421
    -0x1.c5f058230e8014ab83ece0c3a638c079p-1,
    -0x1.d9a3a336edb65efa30e1a6679aa064c2p-2,
    -0x1.069c8b46b3791p1,
  },
  { // Entry 422
    0x1.b5d545b109bfce3fc4d77001afe2f2b6p-1,
    -0x1.096ac02ec42c24880a5951788cb383c8p-1,
    0x1.0ed16fa0e914ep1,
  },
  { // Entry 423
    -0x1.b5d545b109bfce3fc4d77001afe2f2b6p-1,
    -0x1.096ac02ec42c24880a5951788cb383c8p-1,
    -0x1.0ed16fa0e914ep1,
  },
  { // Entry 424
    0x1.a3ed9e252938d92a5553b3c09d2bddd3p-1,
    -0x1.24ec79917163dda65afd8109f59cb465p-1,
    0x1.170653fb1eb0bp1,
  },
  { // Entry 425
    -0x1.a3ed9e252938d92a5553b3c09d2bddd3p-1,
    -0x1.24ec79917163dda65afd8109f59cb465p-1,
    -0x1.170653fb1eb0bp1,
  },
  { // Entry 426
    0x1.904c37505de4b8975dd2730e196ddfc3p-1,
    -0x1.3f3a0e28bedd0cf0c4bfbd8c82a3baafp-1,
    0x1.1f3b3855544c8p1,
  },
  { // Entry 427
    -0x1.904c37505de4b8975dd2730e196ddfc3p-1,
    -0x1.3f3a0e28bedd0cf0c4bfbd8c82a3baafp-1,
    -0x1.1f3b3855544c8p1,
  },
  { // Entry 428
    0x1.7b05b7b6c612fc4fda3812b1f1348389p-1,
    -0x1.5837d2817cf2eb069035552dc3ae834cp-1,
    0x1.27701caf89e85p1,
  },
  { // Entry 429
    -0x1.7b05b7b6c612fc4fda3812b1f1348389p-1,
    -0x1.5837d2817cf2eb069035552dc3ae834cp-1,
    -0x1.27701caf89e85p1,
  },
  { // Entry 430
    0x1.643080d67acc14620672dda6241ea305p-1,
    -0x1.6fcb7c6b8b9199ce2f17dd3ee86b3b9ap-1,
    0x1.2fa50109bf842p1,
  },
  { // Entry 431
    -0x1.643080d67acc14620672dda6241ea305p-1,
    -0x1.6fcb7c6b8b9199ce2f17dd3ee86b3b9ap-1,
    -0x1.2fa50109bf842p1,
  },
  { // Entry 432
    0x1.4be4979c5efb194fc82ac367fedf93bcp-1,
    -0x1.85dc3ea1bbceae2d294421e8c7350f8cp-1,
    0x1.37d9e563f51ffp1,
  },
  { // Entry 433
    -0x1.4be4979c5efb194fc82ac367fedf93bcp-1,
    -0x1.85dc3ea1bbceae2d294421e8c7350f8cp-1,
    -0x1.37d9e563f51ffp1,
  },
  { // Entry 434
    0x1.323b8b1fb4b9efe5075ede8049a85c3dp-1,
    -0x1.9a52e2e0fbcb5f8a3f55c274f9ec754bp-1,
    0x1.400ec9be2abbcp1,
  },
  { // Entry 435
    -0x1.323b8b1fb4b9efe5075ede8049a85c3dp-1,
    -0x1.9a52e2e0fbcb5f8a3f55c274f9ec754bp-1,
    -0x1.400ec9be2abbcp1,
  },
  { // Entry 436
    0x1.175059bf0d42033bbcf598c88b176e61p-1,
    -0x1.ad19e2535aa99b049ac0b5858c5d381fp-1,
    0x1.4843ae1860579p1,
  },
  { // Entry 437
    -0x1.175059bf0d42033bbcf598c88b176e61p-1,
    -0x1.ad19e2535aa99b049ac0b5858c5d381fp-1,
    -0x1.4843ae1860579p1,
  },
  { // Entry 438
    0x1.f67ea975b8692521f77d6754b302c5c4p-2,
    -0x1.be1d7c3534c44132ab1c4130cbe9dfa0p-1,
    0x1.5078927295f36p1,
  },
  { // Entry 439
    -0x1.f67ea975b8692521f77d6754b302c5c4p-2,
    -0x1.be1d7c3534c44132ab1c4130cbe9dfa0p-1,
    -0x1.5078927295f36p1,
  },
  { // Entry 440
    0x1.bc4c04d71abad14efc29a66342ada723p-2,
    -0x1.cd4bca9cb5c759e4d6dc8601ec3d84b6p-1,
    0x1.58ad76cccb8f3p1,
  },
  { // Entry 441
    -0x1.bc4c04d71abad14efc29a66342ada723p-2,
    -0x1.cd4bca9cb5c759e4d6dc8601ec3d84b6p-1,
    -0x1.58ad76cccb8f3p1,
  },
  { // Entry 442
    0x1.8045fe64e62c62f57f077ea251e2f2dcp-2,
    -0x1.da94d54dd4c0cedccd73684994422740p-1,
    0x1.60e25b27012b0p1,
  },
  { // Entry 443
    -0x1.8045fe64e62c62f57f077ea251e2f2dcp-2,
    -0x1.da94d54dd4c0cedccd73684994422740p-1,
    -0x1.60e25b27012b0p1,
  },
  { // Entry 444
    0x1.42abba8c72fa12be920b316627512e41p-2,
    -0x1.e5eaa286fbbcad1e4a6373392e679669p-1,
    0x1.69173f8136c6dp1,
  },
  { // Entry 445
    -0x1.42abba8c72fa12be920b316627512e41p-2,
    -0x1.e5eaa286fbbcad1e4a6373392e679669p-1,
    -0x1.69173f8136c6dp1,
  },
  { // Entry 446
    0x1.03be06f97cbcf866021e5a5c62c6b07ep-2,
    -0x1.ef4145b4aed03c5f1d39763b1eee6ed8p-1,
    0x1.714c23db6c62ap1,
  },
  { // Entry 447
    -0x1.03be06f97cbcf866021e5a5c62c6b07ep-2,
    -0x1.ef4145b4aed03c5f1d39763b1eee6ed8p-1,
    -0x1.714c23db6c62ap1,
  },
  { // Entry 448
    0x1.877e2cd4f6f94710f2776775b01c73dbp-3,
    -0x1.f68eebfcbb5eba124d8cc48fd1beb04dp-1,
    0x1.79810835a1fe7p1,
  },
  { // Entry 449
    -0x1.877e2cd4f6f94710f2776775b01c73dbp-3,
    -0x1.f68eebfcbb5eba124d8cc48fd1beb04dp-1,
    -0x1.79810835a1fe7p1,
  },
  { // Entry 450
    0x1.05e4761ab8d421719567717f76712867p-3,
    -0x1.fbcbe693bd8ef006f5ff02210dfe0619p-1,
    0x1.81b5ec8fd79a4p1,
  },
  { // Entry 451
    -0x1.05e4761ab8d421719567717f76712867p-3,
    -0x1.fbcbe693bd8ef006f5ff02210dfe0619p-1,
    -0x1.81b5ec8fd79a4p1,
  },
  { // Entry 452
    0x1.066e7eb76f5dd2ea19b6991e8a1a3634p-4,
    -0x1.fef2b2d21cf6be1a2c7ea665ef1f874ep-1,
    0x1.89ead0ea0d35bp1,
  },
  { // Entry 453
    -0x1.066e7eb76f5dd2ea19b6991e8a1a3634p-4,
    -0x1.fef2b2d21cf6be1a2c7ea665ef1f874ep-1,
    -0x1.89ead0ea0d35bp1,
  },
  { // Entry 454
    0x1.03be06f97cbf09cc0badbdae803d7b4ep-2,
    0x1.ef4145b4aecff6f58edecf24955428c1p-1,
    -0x1.81b5ec8fd799fp2,
  },
  { // Entry 455
    -0x1.03be06f97cbf09cc0badbdae803d7b4ep-2,
    0x1.ef4145b4aecff6f58edecf24955428c1p-1,
    0x1.81b5ec8fd799fp2,
  },
  { // Entry 456
    0x1.f67ea975b86a22f2348778824f95d84ap-2,
    0x1.be1d7c3534c3f9b9b35619280049de85p-1,
    -0x1.714c23db6c626p2,
  },
  { // Entry 457
    -0x1.f67ea975b86a22f2348778824f95d84ap-2,
    0x1.be1d7c3534c3f9b9b35619280049de85p-1,
    0x1.714c23db6c626p2,
  },
  { // Entry 458
    0x1.643080d67acc210fa27e9247a8286220p-1,
    0x1.6fcb7c6b8b918d86fc83d612a6587eddp-1,
    -0x1.60e25b27012adp2,
  },
  { // Entry 459
    -0x1.643080d67acc210fa27e9247a8286220p-1,
    0x1.6fcb7c6b8b918d86fc83d612a6587eddp-1,
    0x1.60e25b27012adp2,
  },
  { // Entry 460
    0x1.b5d545b109bf950b419702972b94f8fap-1,
    0x1.096ac02ec42c82e5b225185bd6c757d5p-1,
    -0x1.5078927295f34p2,
  },
  { // Entry 461
    -0x1.b5d545b109bf950b419702972b94f8fap-1,
    0x1.096ac02ec42c82e5b225185bd6c757d5p-1,
    0x1.5078927295f34p2,
  },
  { // Entry 462
    0x1.ead6834909b9346234dbb601d0486cf2p-1,
    0x1.235b331d8f7487ce2db97819fae7777cp-2,
    -0x1.400ec9be2abbbp2,
  },
  { // Entry 463
    -0x1.ead6834909b9346234dbb601d0486cf2p-1,
    0x1.235b331d8f7487ce2db97819fae7777cp-2,
    0x1.400ec9be2abbbp2,
  },
  { // Entry 464
    0x1.ffbca846c4fc999a29dc1d6b2d7cb413p-1,
    0x1.069107ae9332c4a1cd2dc033b8d50598p-5,
    -0x1.2fa50109bf842p2,
  },
  { // Entry 465
    -0x1.ffbca846c4fc999a29dc1d6b2d7cb413p-1,
    0x1.069107ae9332c4a1cd2dc033b8d50598p-5,
    0x1.2fa50109bf842p2,
  },
  { // Entry 466
    0x1.f329c0558e96a518a2af3ae7800a5b65p-1,
    -0x1.c7b90e30245695bd1ec170f45feeb1ffp-3,
    -0x1.1f3b3855544c9p2,
  },
  { // Entry 467
    -0x1.f329c0558e96a518a2af3ae7800a5b65p-1,
    -0x1.c7b90e30245695bd1ec170f45feeb1ffp-3,
    0x1.1f3b3855544c9p2,
  },
  { // Entry 468
    0x1.c5f058230e8021f21bd0ac2c0f6809a9p-1,
    -0x1.d9a3a336edb62c1541b8584cd6c00f87p-2,
    -0x1.0ed16fa0e9150p2,
  },
  { // Entry 469
    -0x1.c5f058230e8021f21bd0ac2c0f6809a9p-1,
    -0x1.d9a3a336edb62c1541b8584cd6c00f87p-2,
    0x1.0ed16fa0e9150p2,
  },
  { // Entry 470
    0x1.7b05b7b6c61365a9ac9e908b8e5d3ce4p-1,
    -0x1.5837d2817cf27705cac7881fb569ffc7p-1,
    -0x1.fccf4dd8fbbaep1,
  },
  { // Entry 471
    -0x1.7b05b7b6c61365a9ac9e908b8e5d3ce4p-1,
    -0x1.5837d2817cf27705cac7881fb569ffc7p-1,
    0x1.fccf4dd8fbbaep1,
  },
  { // Entry 472
    0x1.175059bf0d42f1d6b391f07f96f2353dp-1,
    -0x1.ad19e2535aa8ffb40066d78aef71fabdp-1,
    -0x1.dbfbbc70254bcp1,
  },
  { // Entry 473
    -0x1.175059bf0d42f1d6b391f07f96f2353dp-1,
    -0x1.ad19e2535aa8ffb40066d78aef71fabdp-1,
    0x1
```