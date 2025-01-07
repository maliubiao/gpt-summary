Response:
The user wants a summary of the functionality of the provided code snippet, which is part 3 of a 4-part analysis. Given that this is part 3, the assumption is that parts 1 and 2 provided context about the file and its role.

Looking at the content of part 3, it's a large array of numerical data. The structure suggests it's an array of structs, with each struct containing three floating-point numbers represented in hexadecimal. The naming convention "sincos_intel_data.handroid" and the bionic path suggest this data is related to sine and cosine calculations within Android's math library. The "intel_data" part hints that it might be specific to Intel architectures or a way to validate sincos implementations against known good values, possibly from Intel.

Therefore, the primary function of this code snippet is to provide a dataset for testing or validation of sine and cosine functions.

**Summary for Part 3:**

This code snippet defines a large array of floating-point numbers. Each entry in the array likely represents a test case for sine and cosine functions, potentially storing the input angle and the corresponding sine and cosine values. This data is likely used within Android's bionic library to verify the accuracy and correctness of its `sin` and `cos` implementations.
这是第3部分，包含了一个C++风格的数组的定义和初始化。这个数组名为匿名，但是其内容很明显是一系列用于测试三角函数 `sin` 和 `cos` 的数据。

**功能归纳:**

这个代码片段的主要功能是**提供一组预先计算好的、用于测试 `sin` 和 `cos` 函数的输入和输出数据**。

**详细解释:**

这个数组的每一个元素都是一个包含三个 `double` 类型浮点数的结构体（或者可以理解为简单的三元组）。这三个数字很可能分别代表：

1. **输入角度 (x):**  这是 `sin` 和 `cos` 函数的输入值。
2. **`sin(x)` 的期望输出值:** 对应于输入角度的 sine 值。
3. **`cos(x)` 的期望输出值:** 对应于输入角度的 cosine 值。

这些数据以十六进制浮点数的形式表示，例如 `0x1.42abba8c72fd22194793246b8d19960ap-2`。 这种表示方式可以精确地表达浮点数，避免了十进制到二进制转换可能带来的精度损失。

**与 Android 功能的关系举例说明:**

在 Android 的 bionic 库中，`sin` 和 `cos` 函数是基础的数学运算。为了确保这些函数在各种输入情况下都能返回正确的结果，开发者需要进行大量的测试。 `sincos_intel_data.handroid` 文件中的数据很可能被用于以下目的：

* **单元测试:**  在开发或修改 `sin` 和 `cos` 函数的实现时，可以使用这些数据来验证新实现的正确性。可以将函数的计算结果与这些预期的输出值进行比较，判断是否存在误差。
* **回归测试:**  当代码库进行更改后，可以通过重新运行使用这些数据的测试来确保之前的正确性没有被破坏。
* **性能测试（间接）:** 虽然这些数据主要是为了验证正确性，但如果测试覆盖了各种输入范围，也可以间接帮助发现在特定输入下性能不佳的情况。

**libc 函数的实现 (本段代码不涉及 libc 函数的实现):**

这个代码片段本身不涉及任何 libc 函数的实现。它只是一个数据文件。负责使用这些数据的测试代码会调用 libc 中的 `sin` 和 `cos` 函数，并将结果与这里提供的数据进行对比。

**dynamic linker 的功能 (本段代码不涉及 dynamic linker):**

这个代码片段与动态链接器没有直接关系。动态链接器负责在程序运行时加载和链接共享库。这个数据文件会被编译到 bionic 库的测试程序中，不需要动态链接。

**逻辑推理与假设输入输出 (基于数据推测):**

假设我们取数组中的一个条目：

```
{ // Entry 474
    0x1.42abba8c72fd22194793246b8d19960ap-2,
    -0x1.e5eaa286fbbc2b129238160df30ce704p-1,
    -0x1.bb282b074edcap1,
  },
```

* **假设输入:**  输入角度 `x` 的十六进制表示是 `0x1.42abba8c72fd22194793246b8d19960ap-2`。  将其转换为十进制，大约是 0.3161649676。
* **预期输出:**
    * `sin(x)` 的期望值是 `-0x1.e5eaa286fbbc2b129238160df30ce704p-1`，转换为十进制大约是 -0.916941446。
    * `cos(x)` 的期望值是 `-0x1.bb282b074edcap1`，转换为十进制大约是 -3.679900465。

**用户或编程常见的使用错误 (本段代码不涉及用户直接使用):**

由于这个文件是测试数据，用户或程序员不会直接使用它。但是，在编写测试代码时，可能会出现以下错误：

* **数据解析错误:** 在读取和解析这些十六进制浮点数时，可能会出现格式错误或解析逻辑错误，导致读取的数据不正确。
* **精度比较错误:** 在比较计算结果和预期结果时，需要考虑浮点数的精度问题。直接使用 `==` 进行比较可能会因为精度差异而导致测试失败。应该使用一个小的误差范围 (epsilon) 进行比较。

**Android framework or NDK 如何到达这里:**

1. **Android Framework/NDK 调用:**  Android 应用或 Native 代码 (通过 NDK) 可能会调用标准 C 库 (libc) 中的 `sin()` 或 `cos()` 函数。
2. **libc 实现:** bionic 库提供了这些函数的具体实现。
3. **测试与验证:**  为了确保 `sin()` 和 `cos()` 函数的正确性，bionic 库的开发者会编写单元测试。
4. **使用测试数据:** 这些单元测试程序会读取 `bionic/tests/math_data/sincos_intel_data.handroid` 文件中的数据。
5. **执行测试:** 测试程序会针对每一组输入角度，调用 bionic 的 `sin()` 和 `cos()` 函数，并将计算结果与文件中提供的预期结果进行比较。

**Frida Hook 示例调试步骤:**

虽然这个文件是数据，我们不能直接 hook 它。但是我们可以 hook `sin` 或 `cos` 函数的实现，并观察测试程序是如何使用这些数据的。以下是一个使用 Frida hook `sin` 函数的示例：

```javascript
// 假设你的目标进程正在运行使用了 bionic 库
// 获取 sin 函数的地址
const sinPtr = Module.findExportByName("libm.so", "sin");

if (sinPtr) {
  Interceptor.attach(sinPtr, {
    onEnter: function(args) {
      const inputAngle = args[0].toDouble();
      console.log(`[+] Calling sin with input: ${inputAngle}`);
      // 你可以在这里设置断点或者记录更多信息
    },
    onLeave: function(retval) {
      const result = retval.toDouble();
      console.log(`[+] sin returned: ${result}`);
    }
  });
  console.log("[+] Hooked sin function");
} else {
  console.log("[-] sin function not found");
}
```

**调试步骤:**

1. **运行包含 sincos 测试的 Android 程序或测试套件。**  你需要找到或编写一个会调用 `sin` 或 `cos` 且会使用这些测试数据的程序。
2. **使用 Frida 连接到目标进程。**
3. **运行上面的 Frida Script。** 这个脚本会 hook `libm.so` 中的 `sin` 函数。
4. **观察控制台输出。** 当测试程序运行时，Frida 会打印出 `sin` 函数的输入参数和返回值。通过观察输入参数，你可以看到测试程序正在使用哪些角度值，这些值应该与 `sincos_intel_data.handroid` 文件中的第一个值相对应。

通过类似的 hook 方法，你可以观察 `cos` 函数，或者更深入地 hook 测试框架，了解它是如何读取和使用这些数据的。

**总结（针对第 3 部分）：**

这部分代码定义了一个用于测试 `sin` 和 `cos` 函数的**静态数据集**。它包含了大量的输入角度以及对应的预期 sine 和 cosine 值，用于验证 Android 系统 bionic 库中这些数学函数的正确性和精度。开发者会编写测试程序来加载这些数据，调用 bionic 的 `sin` 和 `cos` 函数，并将计算结果与数据集中的期望值进行比较，从而确保数学运算的准确性。

Prompt: 
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
这是第3部分，共4部分，请归纳一下它的功能

"""
.dbfbbc70254bcp1,
  },
  { // Entry 474
    0x1.42abba8c72fd22194793246b8d19960ap-2,
    -0x1.e5eaa286fbbc2b129238160df30ce704p-1,
    -0x1.bb282b074edcap1,
  },
  { // Entry 475
    -0x1.42abba8c72fd22194793246b8d19960ap-2,
    -0x1.e5eaa286fbbc2b129238160df30ce704p-1,
    0x1.bb282b074edcap1,
  },
  { // Entry 476
    0x1.066e7eb76f62b5f4563de26dca890017p-4,
    -0x1.fef2b2d21cf6b40ff3b530ce8dc0d8a7p-1,
    -0x1.9a54999e786d8p1,
  },
  { // Entry 477
    -0x1.066e7eb76f62b5f4563de26dca890017p-4,
    -0x1.fef2b2d21cf6b40ff3b530ce8dc0d8a7p-1,
    0x1.9a54999e786d8p1,
  },
  { // Entry 478
    -0x1.877e2cd4f6fa42586875c5250a169e48p-3,
    -0x1.f68eebfcbb5eadd65c261cd803990ae1p-1,
    -0x1.79810835a1fe6p1,
  },
  { // Entry 479
    0x1.877e2cd4f6fa42586875c5250a169e48p-3,
    -0x1.f68eebfcbb5eadd65c261cd803990ae1p-1,
    0x1.79810835a1fe6p1,
  },
  { // Entry 480
    -0x1.bc4c04d71aba5dfc098278f168bbd962p-2,
    -0x1.cd4bca9cb5c775a99729f7ad95b7dce3p-1,
    -0x1.58ad76cccb8f4p1,
  },
  { // Entry 481
    0x1.bc4c04d71aba5dfc098278f168bbd962p-2,
    -0x1.cd4bca9cb5c775a99729f7ad95b7dce3p-1,
    0x1.58ad76cccb8f4p1,
  },
  { // Entry 482
    -0x1.4be4979c5efa871d30ae1cfa66389199p-1,
    -0x1.85dc3ea1bbcf2aa2e21ec586d5497e35p-1,
    -0x1.37d9e563f5202p1,
  },
  { // Entry 483
    0x1.4be4979c5efa871d30ae1cfa66389199p-1,
    -0x1.85dc3ea1bbcf2aa2e21ec586d5497e35p-1,
    0x1.37d9e563f5202p1,
  },
  { // Entry 484
    -0x1.a3ed9e25293822168958cce1e09f7c11p-1,
    -0x1.24ec79917164e41addd4bacd4420f9fbp-1,
    -0x1.170653fb1eb10p1,
  },
  { // Entry 485
    0x1.a3ed9e25293822168958cce1e09f7c11p-1,
    -0x1.24ec79917164e41addd4bacd4420f9fbp-1,
    0x1.170653fb1eb10p1,
  },
  { // Entry 486
    -0x1.e07eeeda109c62b340dc36e92169648dp-1,
    -0x1.61a76077aee23b11f0c673f638003b0ap-2,
    -0x1.ec6585249083cp0,
  },
  { // Entry 487
    0x1.e07eeeda109c62b340dc36e92169648dp-1,
    -0x1.61a76077aee23b11f0c673f638003b0ap-2,
    0x1.ec6585249083cp0,
  },
  { // Entry 488
    -0x1.fda254c27a01dd954db3aea505e49453p-1,
    -0x1.894f70befbc104b706e85cf4c1c96a52p-4,
    -0x1.aabe6252e3a58p0,
  },
  { // Entry 489
    0x1.fda254c27a01dd954db3aea505e49453p-1,
    -0x1.894f70befbc104b706e85cf4c1c96a52p-4,
    0x1.aabe6252e3a58p0,
  },
  { // Entry 490
    -0x1.f96fe405f1aca02e8f4fd433e59aa973p-1,
    0x1.46dc4f4ce8373c7c44f13b57363edd3bp-3,
    -0x1.69173f8136c74p0,
  },
  { // Entry 491
    0x1.f96fe405f1aca02e8f4fd433e59aa973p-1,
    0x1.46dc4f4ce8373c7c44f13b57363edd3bp-3,
    0x1.69173f8136c74p0,
  },
  { // Entry 492
    -0x1.d42de42dce13ef040bb1040e3148d7dep-1,
    0x1.9e7f8652b47289e53fccd54955db4552p-2,
    -0x1.27701caf89e90p0,
  },
  { // Entry 493
    0x1.d42de42dce13ef040bb1040e3148d7dep-1,
    0x1.9e7f8652b47289e53fccd54955db4552p-2,
    0x1.27701caf89e90p0,
  },
  { // Entry 494
    -0x1.904c37505de5930812e3a2a94feaa51bp-1,
    0x1.3f3a0e28bedbfb066b67abd9c338409ep-1,
    -0x1.cb91f3bbba157p-1,
  },
  { // Entry 495
    0x1.904c37505de5930812e3a2a94feaa51bp-1,
    0x1.3f3a0e28bedbfb066b67abd9c338409ep-1,
    0x1.cb91f3bbba157p-1,
  },
  { // Entry 496
    -0x1.323b8b1fb4bb626dd40cacd74963ac6cp-1,
    0x1.9a52e2e0fbca4b00c72daa3cdaca257cp-1,
    -0x1.4843ae186058ep-1,
  },
  { // Entry 497
    0x1.323b8b1fb4bb626dd40cacd74963ac6cp-1,
    0x1.9a52e2e0fbca4b00c72daa3cdaca257cp-1,
    0x1.4843ae186058ep-1,
  },
  { // Entry 498
    -0x1.8045fe64e6308bb5c6ce35f834b93c63p-2,
    0x1.da94d54dd4bff753d988c1755e2ffc04p-1,
    -0x1.89ead0ea0d38ap-2,
  },
  { // Entry 499
    0x1.8045fe64e6308bb5c6ce35f834b93c63p-2,
    0x1.da94d54dd4bff753d988c1755e2ffc04p-1,
    0x1.89ead0ea0d38ap-2,
  },
  { // Entry 500
    -0x1.05e4761ab8dec44ed0fa30d335049c40p-3,
    0x1.fbcbe693bd8e98423207e36587d942b7p-1,
    -0x1.069c8b46b37f0p-3,
  },
  { // Entry 501
    0x1.05e4761ab8dec44ed0fa30d335049c40p-3,
    0x1.fbcbe693bd8e98423207e36587d942b7p-1,
    0x1.069c8b46b37f0p-3,
  },
  { // Entry 502
    0x1.05e4761ab8d31d00e656372c5c04aa6ep-3,
    0x1.fbcbe693bd8ef86c1565b3453036e55ep-1,
    0x1.069c8b46b3734p-3,
  },
  { // Entry 503
    -0x1.05e4761ab8d31d00e656372c5c04aa6ep-3,
    0x1.fbcbe693bd8ef86c1565b3453036e55ep-1,
    -0x1.069c8b46b3734p-3,
  },
  { // Entry 504
    0x1.8045fe64e62b19a094399502afb76e5cp-2,
    0x1.da94d54dd4c11187405ada7f04e5b171p-1,
    0x1.89ead0ea0d32cp-2,
  },
  { // Entry 505
    -0x1.8045fe64e62b19a094399502afb76e5cp-2,
    0x1.da94d54dd4c11187405ada7f04e5b171p-1,
    -0x1.89ead0ea0d32cp-2,
  },
  { // Entry 506
    0x1.323b8b1fb4b907c416d23b04e0ec0e72p-1,
    0x1.9a52e2e0fbcc0cc83b843bae58c6cdf8p-1,
    0x1.4843ae186055fp-1,
  },
  { // Entry 507
    -0x1.323b8b1fb4b907c416d23b04e0ec0e72p-1,
    0x1.9a52e2e0fbcc0cc83b843bae58c6cdf8p-1,
    -0x1.4843ae186055fp-1,
  },
  { // Entry 508
    0x1.904c37505de3be2ace17ca5487750231p-1,
    0x1.3f3a0e28bede46f65ca5b5c19ad99dd7p-1,
    0x1.cb91f3bbba128p-1,
  },
  { // Entry 509
    -0x1.904c37505de3be2ace17ca5487750231p-1,
    0x1.3f3a0e28bede46f65ca5b5c19ad99dd7p-1,
    -0x1.cb91f3bbba128p-1,
  },
  { // Entry 510
    0x1.d42de42dce12b82466f2fcb63b294751p-1,
    0x1.9e7f8652b478066eec563f835097f148p-2,
    0x1.27701caf89e78p0,
  },
  { // Entry 511
    -0x1.d42de42dce12b82466f2fcb63b294751p-1,
    0x1.9e7f8652b478066eec563f835097f148p-2,
    -0x1.27701caf89e78p0,
  },
  { // Entry 512
    0x1.f96fe405f1ac259bf192fd1cf64e2f12p-1,
    0x1.46dc4f4ce843151b9d14e561879e5fe3p-3,
    0x1.69173f8136c5cp0,
  },
  { // Entry 513
    -0x1.f96fe405f1ac259bf192fd1cf64e2f12p-1,
    0x1.46dc4f4ce843151b9d14e561879e5fe3p-3,
    -0x1.69173f8136c5cp0,
  },
  { // Entry 514
    0x1.fda254c27a02275432d77dd6f9704644p-1,
    -0x1.894f70befba9211b0dcaa4dca450670fp-4,
    0x1.aabe6252e3a40p0,
  },
  { // Entry 515
    -0x1.fda254c27a02275432d77dd6f9704644p-1,
    -0x1.894f70befba9211b0dcaa4dca450670fp-4,
    -0x1.aabe6252e3a40p0,
  },
  { // Entry 516
    0x1.e07eeeda109d6bf0c935fa10b1280c6dp-1,
    -0x1.61a76077aedc99952438421f820a2befp-2,
    0x1.ec65852490824p0,
  },
  { // Entry 517
    -0x1.e07eeeda109d6bf0c935fa10b1280c6dp-1,
    -0x1.61a76077aedc99952438421f820a2befp-2,
    -0x1.ec65852490824p0,
  },
  { // Entry 518
    0x1.a3ed9e252939d9793fb2f6f75e5c76e7p-1,
    -0x1.24ec799171626e36709cfcf7c7752332p-1,
    0x1.170653fb1eb04p1,
  },
  { // Entry 519
    -0x1.a3ed9e252939d9793fb2f6f75e5c76e7p-1,
    -0x1.24ec799171626e36709cfcf7c7752332p-1,
    -0x1.170653fb1eb04p1,
  },
  { // Entry 520
    0x1.4be4979c5efccfe78ea0b6afb0cbba37p-1,
    -0x1.85dc3ea1bbcd38cbfeb4370d5405eebap-1,
    0x1.37d9e563f51f6p1,
  },
  { // Entry 521
    -0x1.4be4979c5efccfe78ea0b6afb0cbba37p-1,
    -0x1.85dc3ea1bbcd38cbfeb4370d5405eebap-1,
    -0x1.37d9e563f51f6p1,
  },
  { // Entry 522
    0x1.bc4c04d71abfc5df69589a45d5e3196ep-2,
    -0x1.cd4bca9cb5c628709388a39fc84591d1p-1,
    0x1.58ad76cccb8e8p1,
  },
  { // Entry 523
    -0x1.bc4c04d71abfc5df69589a45d5e3196ep-2,
    -0x1.cd4bca9cb5c628709388a39fc84591d1p-1,
    -0x1.58ad76cccb8e8p1,
  },
  { // Entry 524
    0x1.877e2cd4f70609b1f062295b64aed4bdp-3,
    -0x1.f68eebfcbb5e1b070b564037f5571a39p-1,
    0x1.79810835a1fdap1,
  },
  { // Entry 525
    -0x1.877e2cd4f70609b1f062295b64aed4bdp-3,
    -0x1.f68eebfcbb5e1b070b564037f5571a39p-1,
    -0x1.79810835a1fdap1,
  },
  { // Entry 526
    -0x1.066e7eb76f4ac293f46486dc328d450bp-4,
    -0x1.fef2b2d21cf6e544ab7795aed10d9fa7p-1,
    0x1.9a54999e786ccp1,
  },
  { // Entry 527
    0x1.066e7eb76f4ac293f46486dc328d450bp-4,
    -0x1.fef2b2d21cf6e544ab7795aed10d9fa7p-1,
    -0x1.9a54999e786ccp1,
  },
  { // Entry 528
    -0x1.42abba8c72f770595ffe3135a0e0ad83p-2,
    -0x1.e5eaa286fbbd1d135e216c49a9f7e5dap-1,
    0x1.bb282b074edbep1,
  },
  { // Entry 529
    0x1.42abba8c72f770595ffe3135a0e0ad83p-2,
    -0x1.e5eaa286fbbd1d135e216c49a9f7e5dap-1,
    -0x1.bb282b074edbep1,
  },
  { // Entry 530
    -0x1.175059bf0d406e2fe014e880dd29cfacp-1,
    -0x1.ad19e2535aaaa2ac87056b6d7776e97ap-1,
    0x1.dbfbbc70254b0p1,
  },
  { // Entry 531
    0x1.175059bf0d406e2fe014e880dd29cfacp-1,
    -0x1.ad19e2535aaaa2ac87056b6d7776e97ap-1,
    -0x1.dbfbbc70254b0p1,
  },
  { // Entry 532
    -0x1.7b05b7b6c6116155f0dc551e316e1e0bp-1,
    -0x1.5837d2817cf4af8e5e59b13b4aa9b5e3p-1,
    0x1.fccf4dd8fbba2p1,
  },
  { // Entry 533
    0x1.7b05b7b6c6116155f0dc551e316e1e0bp-1,
    -0x1.5837d2817cf4af8e5e59b13b4aa9b5e3p-1,
    -0x1.fccf4dd8fbba2p1,
  },
  { // Entry 534
    -0x1.c5f058230e7ebeb7616779e16fa9b537p-1,
    -0x1.d9a3a336edbb7de64a2183cb27be4b5bp-2,
    0x1.0ed16fa0e914ap2,
  },
  { // Entry 535
    0x1.c5f058230e7ebeb7616779e16fa9b537p-1,
    -0x1.d9a3a336edbb7de64a2183cb27be4b5bp-2,
    -0x1.0ed16fa0e914ap2,
  },
  { // Entry 536
    -0x1.f329c0558e95fa333d5d2d44d654777cp-1,
    -0x1.c7b90e30246248b7a0c2c87a3dd25224p-3,
    0x1.1f3b3855544c3p2,
  },
  { // Entry 537
    0x1.f329c0558e95fa333d5d2d44d654777cp-1,
    -0x1.c7b90e30246248b7a0c2c87a3dd25224p-3,
    -0x1.1f3b3855544c3p2,
  },
  { // Entry 538
    -0x1.ffbca846c4fcb237c2947b35b037a2p-1,
    0x1.069107ae9302caf2068b48842afdf051p-5,
    0x1.2fa50109bf83cp2,
  },
  { // Entry 539
    0x1.ffbca846c4fcb237c2947b35b037a2p-1,
    0x1.069107ae9302caf2068b48842afdf051p-5,
    -0x1.2fa50109bf83cp2,
  },
  { // Entry 540
    -0x1.ead6834909ba0ee69b31e1970df1bb8bp-1,
    0x1.235b331d8f6ec74aa3de5aed15fa3f68p-2,
    0x1.400ec9be2abb5p2,
  },
  { // Entry 541
    0x1.ead6834909ba0ee69b31e1970df1bb8bp-1,
    0x1.235b331d8f6ec74aa3de5aed15fa3f68p-2,
    -0x1.400ec9be2abb5p2,
  },
  { // Entry 542
    -0x1.b5d545b109c1232b61dd28d8035d95cbp-1,
    0x1.096ac02ec429f225c99b89bb4c9e5d3ep-1,
    0x1.5078927295f2ep2,
  },
  { // Entry 543
    0x1.b5d545b109c1232b61dd28d8035d95cbp-1,
    0x1.096ac02ec429f225c99b89bb4c9e5d3ep-1,
    -0x1.5078927295f2ep2,
  },
  { // Entry 544
    -0x1.643080d67ace48c0dd1fe3a06bbc4bf5p-1,
    0x1.6fcb7c6b8b8f773e3b421dded6fc1f26p-1,
    0x1.60e25b27012a7p2,
  },
  { // Entry 545
    0x1.643080d67ace48c0dd1fe3a06bbc4bf5p-1,
    0x1.6fcb7c6b8b8f773e3b421dded6fc1f26p-1,
    -0x1.60e25b27012a7p2,
  },
  { // Entry 546
    -0x1.f67ea975b86f5d4aa92716cc077473a7p-2,
    0x1.be1d7c3534c280dab43dced670330b63p-1,
    0x1.714c23db6c620p2,
  },
  { // Entry 547
    0x1.f67ea975b86f5d4aa92716cc077473a7p-2,
    0x1.be1d7c3534c280dab43dced670330b63p-1,
    -0x1.714c23db6c620p2,
  },
  { // Entry 548
    -0x1.03be06f97cc4d78fdccbca1d40e86011p-2,
    0x1.ef4145b4aecf342709a3b19320d1b194p-1,
    0x1.81b5ec8fd7999p2,
  },
  { // Entry 549
    0x1.03be06f97cc4d78fdccbca1d40e86011p-2,
    0x1.ef4145b4aecf342709a3b19320d1b194p-1,
    -0x1.81b5ec8fd7999p2,
  },
  { // Entry 550
    0x1.efb26ef930c4c3fa3245963c1dcec0a6p-5,
    0x1.ff0fd2c96adfbae576981ee4b34769dep-1,
    0x1.effffffffffffp-5,
  },
  { // Entry 551
    -0x1.efb26ef930c4c3fa3245963c1dcec0a6p-5,
    0x1.ff0fd2c96adfbae576981ee4b34769dep-1,
    -0x1.effffffffffffp-5,
  },
  { // Entry 552
    0x1.efb26ef930c4d3f2b0dbe1931ba5ae64p-5,
    0x1.ff0fd2c96adfbad5f904a71b2d210a2ap-1,
    0x1.fp-5,
  },
  { // Entry 553
    -0x1.efb26ef930c4d3f2b0dbe1931ba5ae64p-5,
    0x1.ff0fd2c96adfbad5f904a71b2d210a2ap-1,
    -0x1.fp-5,
  },
  { // Entry 554
    0x1.efb26ef930c4e3eb2f722cea197c2036p-5,
    0x1.ff0fd2c96adfbac67b712f51a6fa2ab3p-1,
    0x1.f000000000001p-5,
  },
  { // Entry 555
    -0x1.efb26ef930c4e3eb2f722cea197c2036p-5,
    0x1.ff0fd2c96adfbac67b712f51a6fa2ab3p-1,
    -0x1.f000000000001p-5,
  },
  { // Entry 556
    0x1.f6baaa131de633ad4e0e7d6465d12a05p-4,
    0x1.fc210055467fe5c8f76e75fd7083818cp-1,
    0x1.f7fffffffffffp-4,
  },
  { // Entry 557
    -0x1.f6baaa131de633ad4e0e7d6465d12a05p-4,
    0x1.fc210055467fe5c8f76e75fd7083818cp-1,
    -0x1.f7fffffffffffp-4,
  },
  { // Entry 558
    0x1.f6baaa131de6438e5611279864fe7663p-4,
    0x1.fc210055467fe58a20193399b3bc0dd2p-1,
    0x1.f80p-4,
  },
  { // Entry 559
    -0x1.f6baaa131de6438e5611279864fe7663p-4,
    0x1.fc210055467fe58a20193399b3bc0dd2p-1,
    -0x1.f80p-4,
  },
  { // Entry 560
    0x1.f6baaa131de6536f5e13d1cc6429cc07p-4,
    0x1.fc210055467fe54b48c3f135f6f29df7p-1,
    0x1.f800000000001p-4,
  },
  { // Entry 561
    -0x1.f6baaa131de6536f5e13d1cc6429cc07p-4,
    0x1.fc210055467fe54b48c3f135f6f29df7p-1,
    -0x1.f800000000001p-4,
  },
  { // Entry 562
    0x1.4a8c3b4e9c7ff00a36e061a0d2295093p-3,
    0x1.f94984b2552e19e7329413b8c2e8dc51p-1,
    0x1.4bfffffffffffp-3,
  },
  { // Entry 563
    -0x1.4a8c3b4e9c7ff00a36e061a0d2295093p-3,
    0x1.f94984b2552e19e7329413b8c2e8dc51p-1,
    -0x1.4bfffffffffffp-3,
  },
  { // Entry 564
    0x1.4a8c3b4e9c7fffd48305f44a42f5f50fp-3,
    0x1.f94984b2552e1941ec766c6a82ece4a3p-1,
    0x1.4c0p-3,
  },
  { // Entry 565
    -0x1.4a8c3b4e9c7fffd48305f44a42f5f50fp-3,
    0x1.f94984b2552e1941ec766c6a82ece4a3p-1,
    -0x1.4c0p-3,
  },
  { // Entry 566
    0x1.4a8c3b4e9c800f9ecf2b86f3b3bd6f5ap-3,
    0x1.f94984b2552e189ca658c51c42e907cep-1,
    0x1.4c00000000001p-3,
  },
  { // Entry 567
    -0x1.4a8c3b4e9c800f9ecf2b86f3b3bd6f5ap-3,
    0x1.f94984b2552e189ca658c51c42e907cep-1,
    -0x1.4c00000000001p-3,
  },
  { // Entry 568
    0x1.2e9cd95baba325fe6067233d4496aaacp-2,
    0x1.e921dd42f09ba868603ea376f6e2d012p-1,
    0x1.3333333333332p-2,
  },
  { // Entry 569
    -0x1.2e9cd95baba325fe6067233d4496aaacp-2,
    0x1.e921dd42f09ba868603ea376f6e2d012p-1,
    -0x1.3333333333332p-2,
  },
  { // Entry 570
    0x1.2e9cd95baba335476f513ac221d078c7p-2,
    0x1.e921dd42f09ba60b268bec1fb0878a42p-1,
    0x1.3333333333333p-2,
  },
  { // Entry 571
    -0x1.2e9cd95baba335476f513ac221d078c7p-2,
    0x1.e921dd42f09ba60b268bec1fb0878a42p-1,
    -0x1.3333333333333p-2,
  },
  { // Entry 572
    0x1.2e9cd95baba344907e3b5246fef75d15p-2,
    0x1.e921dd42f09ba3adecd934c86a0db254p-1,
    0x1.3333333333334p-2,
  },
  { // Entry 573
    -0x1.2e9cd95baba344907e3b5246fef75d15p-2,
    0x1.e921dd42f09ba3adecd934c86a0db254p-1,
    -0x1.3333333333334p-2,
  },
  { // Entry 574
    0x1.3faefc7a5466ef3045c3f1be716ad568p-1,
    0x1.8feedb86bf0ef3158f8a1dcbef49d123p-1,
    0x1.594317acc4ef8p-1,
  },
  { // Entry 575
    -0x1.3faefc7a5466ef3045c3f1be716ad568p-1,
    0x1.8feedb86bf0ef3158f8a1dcbef49d123p-1,
    -0x1.594317acc4ef8p-1,
  },
  { // Entry 576
    0x1.3faefc7a5466fbafbca027b6e8db8c04p-1,
    0x1.8feedb86bf0ee91817a64b28b79e5119p-1,
    0x1.594317acc4ef9p-1,
  },
  { // Entry 577
    -0x1.3faefc7a5466fbafbca027b6e8db8c04p-1,
    0x1.8feedb86bf0ee91817a64b28b79e5119p-1,
    -0x1.594317acc4ef9p-1,
  },
  { // Entry 578
    0x1.3faefc7a5467082f337c5daf5ffc56e2p-1,
    0x1.8feedb86bf0edf1a9fc278857f8ed559p-1,
    0x1.594317acc4efap-1,
  },
  { // Entry 579
    -0x1.3faefc7a5467082f337c5daf5ffc56e2p-1,
    0x1.8feedb86bf0edf1a9fc278857f8ed559p-1,
    -0x1.594317acc4efap-1,
  },
  { // Entry 580
    0x1.6888a4e134b2def5bea51f4cd7d647c6p-1,
    0x1.6b898fa9efb5dd6f9e17e3442d59b241p-1,
    0x1.8ffffffffffffp-1,
  },
  { // Entry 581
    -0x1.6888a4e134b2def5bea51f4cd7d647c6p-1,
    0x1.6b898fa9efb5dd6f9e17e3442d59b241p-1,
    -0x1.8ffffffffffffp-1,
  },
  { // Entry 582
    0x1.6888a4e134b2ea520b226eca8694b3a2p-1,
    0x1.6b898fa9efb5d22b58f0d99e9634931ap-1,
    0x1.9p-1,
  },
  { // Entry 583
    -0x1.6888a4e134b2ea520b226eca8694b3a2p-1,
    0x1.6b898fa9efb5d22b58f0d99e9634931ap-1,
    -0x1.9p-1,
  },
  { // Entry 584
    0x1.6888a4e134b2f5ae579fbe4834f8fd55p-1,
    0x1.6b898fa9efb5c6e713c9cff8feb4918fp-1,
    0x1.9000000000001p-1,
  },
  { // Entry 585
    -0x1.6888a4e134b2f5ae579fbe4834f8fd55p-1,
    0x1.6b898fa9efb5c6e713c9cff8feb4918fp-1,
    -0x1.9000000000001p-1,
  },
  { // Entry 586
    -0.0,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.0p-1074,
  },
  { // Entry 587
    0.0,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.0p-1074,
  },
  { // Entry 588
    -0.0,
    0x1.p0,
    -0.0,
  },
  { // Entry 589
    0.0,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    0x1.0p-1074,
  },
  { // Entry 590
    -0.0,
    0x1.ffffffffffffffffffffffffffffffffp-1,
    -0x1.0p-1074,
  },
  { // Entry 591
    0x1.91f65f10dd812a0b95ff71871ab48207p-5,
    0x1.ff621e3796d7de4a8ab7d7cd8488f499p-1,
    0x1.921fb54442d17p-5,
  },
  { // Entry 592
    -0x1.91f65f10dd812a0b95ff71871ab48207p-5,
    0x1.ff621e3796d7de4a8ab7d7cd8488f499p-1,
    -0x1.921fb54442d17p-5,
  },
  { // Entry 593
    0x1.91f65f10dd813a06a6f12e3dd9a6a41ep-5,
    0x1.ff621e3796d7de3dfb04df46987f6450p-1,
    0x1.921fb54442d18p-5,
  },
  { // Entry 594
    -0x1.91f65f10dd813a06a6f12e3dd9a6a41ep-5,
    0x1.ff621e3796d7de3dfb04df46987f6450p-1,
    -0x1.921fb54442d18p-5,
  },
  { // Entry 595
    0x1.91f65f10dd814a01b7e2eaf4989861b7p-5,
    0x1.ff621e3796d7de316b51e6bfac75542fp-1,
    0x1.921fb54442d19p-5,
  },
  { // Entry 596
    -0x1.91f65f10dd814a01b7e2eaf4989861b7p-5,
    0x1.ff621e3796d7de316b51e6bfac75542fp-1,
    -0x1.921fb54442d19p-5,
  },
  { // Entry 597
    0x1.917a6bc29b42a9cd2e787ee00ca8f8e3p-4,
    0x1.fd88da3d12525a208898cf58ded0eeb3p-1,
    0x1.921fb54442d17p-4,
  },
  { // Entry 598
    -0x1.917a6bc29b42a9cd2e787ee00ca8f8e3p-4,
    0x1.fd88da3d12525a208898cf58ded0eeb3p-1,
    -0x1.921fb54442d17p-4,
  },
  { // Entry 599
    0x1.917a6bc29b42b9b9754a67729f79346bp-4,
    0x1.fd88da3d125259ee594b5705767ab649p-1,
    0x1.921fb54442d18p-4,
  },
  { // Entry 600
    -0x1.917a6bc29b42b9b9754a67729f79346bp-4,
    0x1.fd88da3d125259ee594b5705767ab649p-1,
    -0x1.921fb54442d18p-4,
  },
  { // Entry 601
    0x1.917a6bc29b42c9a5bc1c50053247de78p-4,
    0x1.fd88da3d125259bc29fddeb20e228056p-1,
    0x1.921fb54442d19p-4,
  },
  { // Entry 602
    -0x1.917a6bc29b42c9a5bc1c50053247de78p-4,
    0x1.fd88da3d125259bc29fddeb20e228056p-1,
    -0x1.921fb54442d19p-4,
  },
  { // Entry 603
    0x1.8f8b83c69a60975f98453886f953a0e5p-3,
    0x1.f6297cff75cb03ab1fced6337e35a245p-1,
    0x1.921fb54442d17p-3,
  },
  { // Entry 604
    -0x1.8f8b83c69a60975f98453886f953a0e5p-3,
    0x1.f6297cff75cb03ab1fced6337e35a245p-1,
    -0x1.921fb54442d17p-3,
  },
  { // Entry 605
    0x1.8f8b83c69a60a710e42d3435516ddaccp-3,
    0x1.f6297cff75cb02e35a0cf2e64de60626p-1,
    0x1.921fb54442d18p-3,
  },
  { // Entry 606
    -0x1.8f8b83c69a60a710e42d3435516ddaccp-3,
    0x1.f6297cff75cb02e35a0cf2e64de60626p-1,
    -0x1.921fb54442d18p-3,
  },
  { // Entry 607
    0x1.8f8b83c69a60b6c230152fe3a981d686p-3,
    0x1.f6297cff75cb021b944b0f991d8e9161p-1,
    0x1.921fb54442d19p-3,
  },
  { // Entry 608
    -0x1.8f8b83c69a60b6c230152fe3a981d686p-3,
    0x1.f6297cff75cb021b944b0f991d8e9161p-1,
    -0x1.921fb54442d19p-3,
  },
  { // Entry 609
    0x1.87de2a6aea961a3e9dedea57fe7e6514p-2,
    0x1.d906bcf328d46672d9c1a865898e5966p-1,
    0x1.921fb54442d17p-2,
  },
  { // Entry 610
    -0x1.87de2a6aea961a3e9dedea57fe7e6514p-2,
    0x1.d906bcf328d46672d9c1a865898e5966p-1,
    -0x1.921fb54442d17p-2,
  },
  { // Entry 611
    0x1.87de2a6aea962906d3d5839ea1a5bcf0p-2,
    0x1.d906bcf328d463631d6cd2905d4b13f5p-1,
    0x1.921fb54442d18p-2,
  },
  { // Entry 612
    -0x1.87de2a6aea962906d3d5839ea1a5bcf0p-2,
    0x1.d906bcf328d463631d6cd2905d4b13f5p-1,
    -0x1.921fb54442d18p-2,
  },
  { // Entry 613
    0x1.87de2a6aea9637cf09bd1ce544b496eap-2,
    0x1.d906bcf328d460536117fcbb30ea3e17p-1,
    0x1.921fb54442d19p-2,
  },
  { // Entry 614
    -0x1.87de2a6aea9637cf09bd1ce544b496eap-2,
    0x1.d906bcf328d460536117fcbb30ea3e17p-1,
    -0x1.921fb54442d19p-2,
  },
  { // Entry 615
    0x1.6a09e667f3bcba99afb0135729457874p-1,
    0x1.6a09e667f3bcd777b6461376ab523242p-1,
    0x1.921fb54442d17p-1,
  },
  { // Entry 616
    -0x1.6a09e667f3bcba99afb0135729457874p-1,
    0x1.6a09e667f3bcd777b6461376ab523242p-1,
    -0x1.921fb54442d17p-1,
  },
  { // Entry 617
    0x1.6a09e667f3bcc5e9fee352f50fd3f4e9p-1,
    0x1.6a09e667f3bccc276712d3d8c5502387p-1,
    0x1.921fb54442d18p-1,
  },
  { // Entry 618
    -0x1.6a09e667f3bcc5e9fee352f50fd3f4e9p-1,
    0x1.6a09e667f3bccc276712d3d8c5502387p-1,
    -0x1.921fb54442d18p-1,
  },
  { // Entry 619
    0x1.6a09e667f3bcd13a4e169292f607eee5p-1,
    0x1.6a09e667f3bcc0d717df943adef39253p-1,
    0x1.921fb54442d19p-1,
  },
  { // Entry 620
    -0x1.6a09e667f3bcd13a4e169292f607eee5p-1,
    0x1.6a09e667f3bcc0d717df943adef39253p-1,
    -0x1.921fb54442d19p-1,
  },
  { // Entry 621
    0x1.fffffffffffffffffffffffffe5f56ffp-1,
    0x1.469898cc51701b839a252049c0b8b50bp-52,
    0x1.921fb54442d17p0,
  },
  { // Entry 622
    -0x1.fffffffffffffffffffffffffe5f56ffp-1,
    0x1.469898cc51701b839a252049c0b8b50bp-52,
    -0x1.921fb54442d17p0,
  },
  { // Entry 623
    0x1.ffffffffffffffffffffffffffec8831p-1,
    0x1.1a62633145c06e0e6894812704419fa8p-54,
    0x1.921fb54442d18p0,
  },
  { // Entry 624
    -0x1.ffffffffffffffffffffffffffec8831p-1,
    0x1.1a62633145c06e0e6894812704419fa8p-54,
    -0x1.921fb54442d18p0,
  },
  { // Entry 625
    0x1.ffffffffffffffffffffffffff79b963p-1,
    -0x1.72cece675d1fc8f8cbb5bf6c7dbcfba0p-53,
    0x1.921fb54442d19p0,
  },
  { // Entry 626
    -0x1.ffffffffffffffffffffffffff79b963p-1,
    -0x1.72cece675d1fc8f8cbb5bf6c7dbcfba0p-53,
    -0x1.921fb54442d19p0,
  },
  { // Entry 627
    0x1.469898cc51701b839a252049bfaeed42p-51,
    -0x1.fffffffffffffffffffffffff97d5bffp-1,
    0x1.921fb54442d17p1,
  },
  { // Entry 628
    -0x1.469898cc51701b839a252049bfaeed42p-51,
    -0x1.fffffffffffffffffffffffff97d5bffp-1,
    -0x1.921fb54442d17p1,
  },
  { // Entry 629
    0x1.1a62633145c06e0e689481270436e2edp-53,
    -0x1.ffffffffffffffffffffffffffb220c5p-1,
    0x1.921fb54442d18p1,
  },
  { // Entry 630
    -0x1.1a62633145c06e0e689481270436e2edp-53,
    -0x1.ffffffffffffffffffffffffffb220c5p-1,
    -0x1.921fb54442d18p1,
  },
  { // Entry 631
    -0x1.72cece675d1fc8f8cbb5bf6c7d5bbc5cp-52,
    -0x1.fffffffffffffffffffffffffde6e58cp-1,
    0x1.921fb54442d19p1,
  },
  { // Entry 632
    0x1.72cece675d1fc8f8cbb5bf6c7d5bbc5cp-52,
    -0x1.fffffffffffffffffffffffffde6e58cp-1,
    -0x1.921fb54442d19p1,
  },
  { // Entry 633
    -0x1.469898cc51701b839a252049bb87ce1bp-50,
    0x1.ffffffffffffffffffffffffe5f56ffep-1,
    0x1.921fb54442d17p2,
  },
  { // Entry 634
    0x1.469898cc51701b839a252049bb87ce1bp-50,
    0x1.ffffffffffffffffffffffffe5f56ffep-1,
    -0x1.921fb54442d17p2,
  },
  { // Entry 635
    -0x1.1a62633145c06e0e68948127040bf003p-52,
    0x1.fffffffffffffffffffffffffec88317p-1,
    0x1.921fb54442d18p2,
  },
  { // Entry 636
    0x1.1a62633145c06e0e68948127040bf003p-52,
    0x1.fffffffffffffffffffffffffec88317p-1,
    -0x1.921fb54442d18p2,
  },
  { // Entry 637
    0x1.72cece675d1fc8f8cbb5bf6c7bd6bf4dp-51,
    0x1.fffffffffffffffffffffffff79b9631p-1,
    0x1.921fb54442d19p2,
  },
  { // Entry 638
    -0x1.72cece675d1fc8f8cbb5bf6c7bd6bf4dp-51,
    0x1.fffffffffffffffffffffffff79b9631p-1,
    -0x1.921fb54442d19p2,
  },
  { // Entry 639
    -0x1.469898cc51701b839a252049aaeb5182p-49,
    0x1.ffffffffffffffffffffffff97d5bff8p-1,
    0x1.921fb54442d17p3,
  },
  { // Entry 640
    0x1.469898cc51701b839a252049aaeb5182p-49,
    0x1.ffffffffffffffffffffffff97d5bff8p-1,
    -0x1.921fb54442d17p3,
  },
  { // Entry 641
    -0x1.1a62633145c06e0e689481270360245cp-51,
    0x1.fffffffffffffffffffffffffb220c5ep-1,
    0x1.921fb54442d18p3,
  },
  { // Entry 642
    0x1.1a62633145c06e0e689481270360245cp-51,
    0x1.fffffffffffffffffffffffffb220c5ep-1,
    -0x1.921fb54442d18p3,
  },
  { // Entry 643
    0x1.72cece675d1fc8f8cbb5bf6c75c2cb0ep-50,
    0x1.ffffffffffffffffffffffffde6e58c4p-1,
    0x1.921fb54442d19p3,
  },
  { // Entry 644
    -0x1.72cece675d1fc8f8cbb5bf6c75c2cb0ep-50,
    0x1.ffffffffffffffffffffffffde6e58c4p-1,
    -0x1.921fb54442d19p3,
  },
  { // Entry 645
    -0x1.469898cc51701b839a25204968795f1cp-48,
    0x1.fffffffffffffffffffffffe5f56ffe1p-1,
    0x1.921fb54442d17p4,
  },
  { // Entry 646
    0x1.469898cc51701b839a25204968795f1cp-48,
    0x1.fffffffffffffffffffffffe5f56ffe1p-1,
    -0x1.921fb54442d17p4,
  },
  { // Entry 647
    -0x1.1a62633145c06e0e6894812700b0f5bfp-50,
    0x1.ffffffffffffffffffffffffec88317ap-1,
    0x1.921fb54442d18p4,
  },
  { // Entry 648
    0x1.1a62633145c06e0e6894812700b0f5bfp-50,
    0x1.ffffffffffffffffffffffffec88317ap-1,
    -0x1.921fb54442d18p4,
  },
  { // Entry 649
    0x1.72cece675d1fc8f8cbb5bf6c5d72fa11p-49,
    0x1.ffffffffffffffffffffffff79b96313p-1,
    0x1.921fb54442d19p4,
  },
  { // Entry 650
    -0x1.72cece675d1fc8f8cbb5bf6c5d72fa11p-49,
    0x1.ffffffffffffffffffffffff79b96313p-1,
    -0x1.921fb54442d19p4,
  },
  { // Entry 651
    -0x1.469898cc51701b839a2520485eb19584p-47,
    0x1.fffffffffffffffffffffff97d5bff87p-1,
    0x1.921fb54442d17p5,
  },
  { // Entry 652
    0x1.469898cc51701b839a2520485eb19584p-47,
    0x1.fffffffffffffffffffffff97d5bff87p-1,
    -0x1.921fb54442d17p5,
  },
  { // Entry 653
    -0x1.1a62633145c06e0e68948126f5f43b4cp-49,
    0x1.ffffffffffffffffffffffffb220c5e9p-1,
    0x1.921fb54442d18p5,
  },
  { // Entry 654
    0x1.1a62633145c06e0e68948126f5f43b4cp-49,
    0x1.ffffffffffffffffffffffffb220c5e9p-1,
    -0x1.921fb54442d18p5,
  },
  { // Entry 655
    0x1.72cece675d1fc8f8cbb5bf6bfc33b61fp-48,
    0x1.fffffffffffffffffffffffde6e58c4cp-1,
    0x1.921fb54442d19p5,
  },
  { // Entry 656
    -0x1.72cece675d1fc8f8cbb5bf6bfc33b61fp-48,
    0x1.fffffffffffffffffffffffde6e58c4cp-1,
    -0x1.921fb54442d19p5,
  },
  { // Entry 657
    -0x1.469898cc51701b839a25204437926f25p-46,
    0x1.ffffffffffffffffffffffe5f56ffe1dp-1,
    0x1.921fb54442d17p6,
  },
  { // Entry 658
    0x1.469898cc51701b839a25204437926f25p-46,
    0x1.ffffffffffffffffffffffe5f56ffe1dp-1,
    -0x1.921fb54442d17p6,
  },
  { // Entry 659
    -0x1.1a62633145c06e0e68948126cb01517dp-48,
    0x1.fffffffffffffffffffffffec88317a7p-1,
    0x1.921fb54442d18p6,
  },
  { // Entry 660
    0x1.1a62633145c06e0e68948126cb01517dp-48,
    0x1.fffffffffffffffffffffffec88317a7p-1,
    -0x1.921fb54442d18p6,
  },
  { // Entry 661
    0x1.72cece675d1fc8f8cbb5bf6a7736a658p-47,
    0x1.fffffffffffffffffffffff79b963131p-1,
    0x1.921fb54442d19p6,
  },
  { // Entry 662
    -0x1.72cece675d1fc8f8cbb5bf6a7736a658p-47,
    0x1.fffffffffffffffffffffff79b963131p-1,
    -0x1.921fb54442d19p6,
  },
  { // Entry 663
    -0x1.469898cc51701b839a2520339b15d5aap-45,
    0x1.ffffffffffffffffffffff97d5bff874p-1,
    0x1.921fb54442d17p7,
  },
  { // Entry 664
    0x1.469898cc51701b839a2520339b15d5aap-45,
    0x1.ffffffffffffffffffffff97d5bff874p-1,
    -0x1.921fb54442d17p7,
  },
  { // Entry 665
    -0x1.1a62633145c06e0e689481261f35aa43p-47,
    0x1.fffffffffffffffffffffffb220c5e9dp-1,
    0x1.921fb54442d18p7,
  },
  { // Entry 666
    0x1.1a62633145c06e0e689481261f35aa43p-47,
    0x1.fffffffffffffffffffffffb220c5e9dp-1,
    -0x1.921fb54442d18p7,
  },
  { // Entry 667
    0x1.72cece675d1fc8f8cbb5bf646342673ap-46,
    0x1.ffffffffffffffffffffffde6e58c4c6p-1,
    0x1.921fb54442d19p7,
  },
  { // Entry 668
    -0x1.72cece675d1fc8f8cbb5bf646342673ap-46,
    0x1.ffffffffffffffffffffffde6e58c4c6p-1,
    -0x1.921fb54442d19p7,
  },
  { // Entry 669
    0x1.6a09e667f3bcffa60c0f53340fd24904p-1,
    -0x1.6a09e667f3bc926b59e6d399bd1b906cp-1,
    0x1.2d97c7f3321d1p1,
  },
  { // Entry 670
    -0x1.6a09e667f3bcffa60c0f53340fd24904p-1,
    -0x1.6a09e667f3bc926b59e6d399bd1b906cp-1,
    -0x1.2d97c7f3321d1p1,
  },
  { // Entry 671
    0x1.6a09e667f3bcd264cf4254bc7ab0c9fap-1,
    -0x1.6a09e667f3bcbfac96b3d2115a3c3e21p-1,
    0x1.2d97c7f3321d2p1,
  },
  { // Entry 672
    -0x1.6a09e667f3bcd264cf4254bc7ab0c9fap-1,
    -0x1.6a09e667f3bcbfac96b3d2115a3c3e21p-1,
    -0x1.2d97c7f3321d2p1,
  },
  { // Entry 673
    0x1.6a09e667f3bca52392755644dfe72357p-1,
    -0x1.6a09e667f3bcecedd380d088f1b4c43cp-1,
    0x1.2d97c7f3321d3p1,
  },
  { // Entry 674
    -0x1.6a09e667f3bca52392755644dfe72357p-1,
    -0x1.6a09e667f3bcecedd380d088f1b4c43cp-1,
    -0x1.2d97c7f3321d3p1,
  },
  { // Entry 675
    -0x1.6a09e667f3bc8c2df1b752b606a0a472p-1,
    -0x1.6a09e667f3bd05e3743ed417c44fba46p-1,
    0x1.f6a7a2955385dp1,
  },
  { // Entry 676
    0x1.6a09e667f3bc8c2df1b752b606a0a472p-1,
    -0x1.6a09e667f3bd05e3743ed417c44fba46p-1,
    -0x1.f6a7a2955385dp1,
  },
  { // Entry 677
    -0x1.6a09e667f3bcb96f2e84512da488ff2dp-1,
    -0x1.6a09e667f3bcd8a23771d5a02ff5e843p-1,
    0x1.f6a7a2955385ep1,
  },
  { // Entry 678
    0x1.6a09e667f3bcb96f2e84512da488ff2dp-1,
    -0x1.6a09e667f3bcd8a23771d5a02ff5e843p-1,
    -0x1.f6a7a2955385ep1,
  },
  { // Entry 679
    -0x1.6a09e667f3bce6b06b514fa53cc9324fp-1,
    -0x1.6a09e667f3bcab60faa4d72895f3eea5p-1,
    0x1.f6a7a2955385fp1,
  },
  { // Entry 680
    0x1.6a09e667f3bce6b06b514fa53cc9324fp-1,
    -0x1.6a09e667f3bcab60faa4d72895f3eea5p-1,
    -0x1.f6a7a2955385fp1,
  },
  { // Entry 681
    -0x1.ffffffffffffffffffffffffe8b27b6ap-1,
    -0x1.34f272993d1414a2b39bd8374c1d1631p-50,
    0x1.2d97c7f3321d1p2,
  },
  { // Entry 682
    0x1.ffffffffffffffffffffffffe8b27b6ap-1,
    -0x1.34f272993d1414a2b39bd8374c1d1631p-50,
    -0x1.2d97c7f3321d1p2,
  },
  { // Entry 683
    -0x1.ffffffffffffffffffffffffff50c9bdp-1,
    -0x1.a79394c9e8a0a5159cdec1ba86377c92p-53,
    0x1.2d97c7f3321d2p2,
  },
  { // Entry 684
    0x1.ffffffffffffffffffffffffff50c9bdp-1,
    -0x1.a79394c9e8a0a5159cdec1ba86377c92p-53,
    -0x1.2d97c7f3321d2p2,
  },
  { // Entry 685
    -0x1.fffffffffffffffffffffffff5ef1810p-1,
    0x1.961b1acd85d7d6ba98c84f915bbcbc6cp-51,
    0x1.2d97c7f3321d3p2,
  },
  { // Entry 686
    0x1.fffffffffffffffffffffffff5ef1810p-1,
    0x1.961b1acd85d7d6ba98c84f915bbcbc6cp-51,
    -0x1.2d97c7f3321d3p2,
  },
  { // Entry 687
    -0x1.6a09e667f3bd3962193b5373069ba0c2p-1,
    0x1.6a09e667f3bc58af4cbad35aabb200f4p-1,
    0x1.5fdbbe9bba774p2,
  },
  { // Entry 688
    0x1.6a09e667f3bd3962193b5373069ba0c2p-1,
    0x1.6a09e667f3bc58af4cbad35aabb200f4p-1,
    -0x1.5fdbbe9bba774p2,
  },
  { // Entry 689
    -0x1.6a09e667f3bcdedf9fa15683e51f7e60p-1,
    0x1.6a09e667f3bcb331c654d049eeba380fp-1,
    0x1.5fdbbe9bba775p2,
  },
  { // Entry 690
    0x1.6a09e667f3bcdedf9fa15683e51f7e60p-1,
    0x1.6a09e667f3bcb331c654d049eeba380fp-1,
    -0x1.5fdbbe9bba775p2,
  },
  { // Entry 691
    -0x1.6a09e667f3bc845d26075994ad02bd98p-1,
    0x1.6a09e667f3bd0db43feecd391b21d0c4p-1,
    0x1.5fdbbe9bba776p2,
  },
  { // Entry 692
    0x1.6a09e667f3bc845d26075994ad02bd98p-1,
    0x1.6a09e667f3bd0db43feecd391b21d0c4p-1,
    -0x1.5fdbbe9bba776p2,
  },
  { // Entry 693
    0x1.6a09e667f3bc5271e48b5276f438579fp-1,
    0x1.6a09e667f3bd3f9f816ad456ba1a54a9p-1,
    0x1.c463abeccb2bap2,
  },
  { // Entry 694
    -0x1.6a09e667f3bc5271e48b5276f438579fp-1,
    0x1.6a09e667f3bd3f9f816ad456ba1a54a9p-1,
    -0x1.c463abeccb2bap2,
  },
  { // Entry 695
    0x1.6a09e667f3bcacf45e254f6638cfe8c6p-1,
    0x1.6a09e667f3bce51d07d0d7679a2d8c53p-1,
    0x1.c463abeccb2bbp2,
  },
  { // Entry 696
    -0x1.6a09e667f3bcacf45e254f6638cfe8c6p-1,
    0x1.6a09e667f3bce51d07d0d7679a2d8c53p-1,
    -0x1.c463abeccb2bbp2,
  },
  { // Entry 697
    0x1.6a09e667f3bd0776d7bf4c5566c6db87p-1,
    0x1.6a09e667f3bc8a9a8e36da7863a02597p-1,
    0x1.c463abeccb2bcp2,
  },
  { // Entry 698
    -0x1.6a09e667f3bd0776d7bf4c5566c6db87p-1,
    0x1.6a09e667f3bc8a9a8e36da7863a02597p-1,
    -0x1.c463abeccb2bcp2,
  },
  { // Entry 699
    0x1.ffffffffffffffffffffffffe31174f5p-1,
    0x1.583ebeff65cc226480ae685c2ad9afdap-50,
    0x1.f6a7a2955385dp2,
  },
  { // Entry 700
    -0x1.ffffffffffffffffffffffffe31174f5p-1,
    0x1.583ebeff65cc226480ae685c2ad9afdap-50,
    -0x1.f6a7a2955385dp2,
  },
  { // Entry 701
    0x1.fffffffffffffffffffffffffe194cd4p-1,
    0x1.60fafbfd9730899202b9a170c4e6a849p-52,
    0x1.f6a7a2955385ep2,
  },
  { // Entry 702
    -0x1.fffffffffffffffffffffffffe194cd4p-1,
    0x1.60fafbfd9730899202b9a170c4e6a849p-52,
    -0x1.f6a7a2955385ep2,
  },
  { // Entry 703
    0x1.fffffffffffffffffffffffff92124b4p-1,
    -0x1.4f8282013467bb36fea32f479bd48f4ap-51,
    0x1.f6a7a2955385fp2,
  },
  { // Entry 704
    -0x1.fffffffffffffffffffffffff92124b4p-1,
    -0x1.4f8282013467bb36fea32f479bd48f4ap-51,
    -0x1.f6a7a2955385fp2,
  },
  { // Entry 705
    0x1.6a09e667f3bdfae1dcce4f18665681c6p-1,
    -0x1.6a09e667f3bb972f8927d7b46c737485p-1,
    0x1.1475cc9eedeffp3,
  },
  { // Entry 706
    -0x1.6a09e667f3bdfae1dcce4f18665681c6p-1,
    -0x1.6a09e667f3bb972f8927d7b46c737485p-1,
    -0x1.1475cc9eedeffp3,
  },
  { // Entry 707
    0x1.6a09e667f3bd45dce99a553a6d7d8065p-1,
    -0x1.6a09e667f3bc4c347c5bd1933ca3261fp-1,
    0x1.1475cc9eedfp3,
  },
  { // Entry 708
    -0x1.6a09e667f3bd45dce99a553a6d7d8065p-1,
    -0x1.6a09e667f3bc4c347c5bd1933ca3261fp-1,
    -0x1.1475cc9eedfp3,
  },
  { // Entry 709
    0x1.6a09e667f3bc90d7f6665b5c1a22056ap-1,
    -0x1.6a09e667f3bd01396f8fcb71b2505e1fp-1,
    0x1.1475cc9eedf01p3,
  },
  { // Entry 710
    -0x1.6a09e667f3bc90d7f6665b5c1a22056ap-1,
    -0x1.6a09e667f3bd01396f8fcb71b2505e1fp-1,
    -0x1.1475cc9eedf01p3,
  },
  { // Entry 711
    0x1.34f272993d1414a2b39bd8373e0d6b94p-49,
    -0x1.ffffffffffffffffffffffffa2c9eda8p-1,
    0x1.2d97c7f3321d1p3,
  },
  { // Entry 712
    -0x1.34f272993d1414a2
"""


```