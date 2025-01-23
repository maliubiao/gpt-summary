Response:
The user wants a summary of the functionality of the provided C code snippet, which is a part of Frida's dynamic instrumentation tool. I need to identify the key features demonstrated in this code and explain their relevance to reverse engineering, low-level system interaction, and potential user errors.

Here's a breakdown of the code's functionality:

1. **Instruction Parsing:** The code extensively uses `Instruction.parse()` to dissect machine code instructions. This is crucial for understanding and manipulating program behavior at a low level.
2. **Instruction Generation:**  The code demonstrates the use of `X86Writer`, `ArmWriter`, `ThumbWriter`, and `Arm64Writer` to generate machine code. This is fundamental for runtime code patching and modification.
3. **Code Relocation:** The `X86Relocator` and `Arm64Relocator` are used to move blocks of code from one memory location to another, adjusting instruction pointers as needed. This is important for inserting custom code without disrupting existing program flow.
4. **Symbol Resolution:**  The `DebugSymbol` class is used to resolve memory addresses to function names and vice versa. This is essential for understanding program structure and identifying interesting functions to hook.
5. **Native Function Invocation:** The `NativeFunction` class allows calling native code functions from JavaScript. This enables interacting with the target process's existing functionality.
6. **Native Function Interception (Hooking):** The `Interceptor` class is used to intercept calls to native functions, allowing for inspection and modification of arguments and return values.
7. **Error Handling:** The code includes checks for potential errors, such as trying to write code to an undersized buffer.
8. **Architecture-Specific Code:** The code uses `#if defined` blocks to handle differences between various processor architectures (x86, ARM, ARM64).

I will structure the response to address each of the user's requirements: functionality, relation to reverse engineering, low-level knowledge, logical reasoning (input/output), common user errors, and debugging hints.
这是frida动态插桩工具源代码文件的一部分，主要集中在 **指令的解析和生成** 以及 **对本地函数进行调用和拦截** 的功能测试。以下是其功能的详细列举和说明：

**1. 指令的解析 (Instruction Parsing):**

* **功能:** 代码演示了如何使用 `Instruction.parse()` 方法来解析不同架构（ARM, ARM64）的机器码指令。它可以识别指令的助记符 (mnemonic) 和操作数 (operands)，并提取操作数的类型、值、访问方式 (读/写) 以及其他属性 (如位移、立即数、寄存器等)。
* **与逆向的关系:** 这是逆向工程的核心技术之一。通过解析指令，可以理解程序执行的流程、数据操作以及函数调用关系。
    * **举例:**  通过解析 `ldr` 指令，可以知道从哪个内存地址读取数据到哪个寄存器。解析 `bl` 指令可以知道目标函数的地址。
* **二进制底层知识:** 这涉及到对不同架构指令集 (如 ARM, ARM64) 的编码格式和含义的理解。例如，不同的指令有不同的操作码和操作数编码方式。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:** 一段 ARM 机器码，例如 `0xe590002a` (对应 `ldr r0, [pc, #42]`)。
    * **预期输出:**  解析后的指令对象，其中 `mnemonic` 为 `"ldr"`，操作数包含一个寄存器 `"r0"` 和一个内存地址 `"pc"` 加偏移 `42`。

**2. 指令的生成 (Instruction Generation):**

* **功能:** 代码展示了如何使用 `X86Writer`, `ArmWriter`, `Arm64Writer` 等类来生成机器码指令。这允许在运行时动态地修改程序的代码。
* **与逆向的关系:**  在逆向分析中，有时需要在目标程序中插入自定义的代码片段，例如插入 hook 代码或修改函数行为。指令生成是实现这一点的关键。
    * **举例:**  使用 `cw.putMovRegU32('eax', 42)` 可以生成将立即数 42 移动到 EAX 寄存器的指令。
* **二进制底层知识:**  需要了解目标架构的指令编码格式，才能正确地生成有效的机器码。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:**  JavaScript 代码 `cw.putMovRegU32('eax', 42);`
    * **预期输出:**  在内存中生成对应的 x86 机器码，例如 `0xb8 2a 00 00 00`。

**3. 代码重定位 (Code Relocation):**

* **功能:**  代码展示了 `X86Relocator` 和 `Arm64Relocator` 的使用，可以将一段已有的机器码从一个内存地址复制到另一个地址，并自动调整指令中的地址引用，例如跳转目标地址。
* **与逆向的关系:**  在代码插桩时，如果需要将原始代码移动到新的位置，就需要进行重定位，以保证代码中的跳转和地址访问仍然正确。
    * **举例:**  将一个函数的前几条指令复制到 hook 代码中，需要重定位这些指令，使得跳转指令的目标地址在新位置上仍然有效。
* **二进制底层知识:**  需要理解不同类型的指令中地址的编码方式，以及如何根据代码的偏移来调整这些地址。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:**  一段包含跳转指令的 x86 机器码，以及目标内存地址。
    * **预期输出:**  在目标地址生成的新代码段，其中的跳转指令的目标地址已经根据偏移进行了调整。

**4. 符号解析 (Symbol Resolution):**

* **功能:** 代码展示了如何使用 `DebugSymbol` 类，通过内存地址查找对应的函数名 (`DebugSymbol.fromAddress`)，或者通过函数名查找其地址 (`DebugSymbol.fromName`)。
* **与逆向的关系:**  符号信息对于理解程序结构至关重要。它可以帮助逆向工程师快速定位关键函数和变量。
    * **举例:**  通过 `DebugSymbol.fromAddress(0x...)` 可以知道某个内存地址对应哪个函数。
* **Linux/Android 框架知识:**  这涉及到操作系统如何加载和管理动态链接库 (DLLs/shared objects) 以及如何维护符号表。
* **用户操作到达这里:** 用户通常会使用 Frida 的 API 来获取函数或模块的符号信息，例如在脚本中使用 `Module.findExportByName()` 或 `DebugSymbol.fromName()`。

**5. 本地函数调用 (Native Function Invocation):**

* **功能:** 代码演示了如何使用 `NativeFunction` 类来创建一个 JavaScript 函数对象，该对象可以调用目标进程中的本地函数。可以指定函数的参数类型和返回值类型。
* **与逆向的关系:**  允许在不修改目标程序的情况下，调用其内部的函数，这在分析函数行为或利用现有功能时非常有用。
    * **举例:**  创建一个 `NativeFunction` 对象来调用 `malloc` 函数，可以在目标进程的堆上分配内存。
* **用户或编程常见错误:**
    * **参数类型或返回值类型声明错误:** 如果声明的类型与实际函数签名不符，可能导致崩溃或不可预测的结果。例如，将一个 `int` 参数声明为 `pointer`。
    * **ABI 不匹配:**  在某些平台上，需要指定正确的调用约定 (ABI)，否则参数传递可能出错。
* **用户操作到达这里:** 用户会在 Frida 脚本中使用 `new NativeFunction()` 来包装目标进程中的函数。

**6. 本地函数拦截/Hook (Native Function Interception):**

* **功能:** 代码演示了如何使用 `Interceptor.attach()` 方法来拦截对本地函数的调用。可以指定 `onEnter` 和 `onLeave` 回调函数，在函数调用前后执行自定义的 JavaScript 代码，可以访问和修改函数的参数和返回值。
* **与逆向的关系:**  这是动态分析中最强大的技术之一，可以用来监控函数调用、修改函数行为、注入自定义逻辑等。
    * **举例:**  拦截 `open` 函数的调用，可以记录程序打开的文件名。
* **Linux/Android 内核及框架知识:**  涉及到操作系统如何处理函数调用以及 Frida 如何在运行时修改程序的执行流程。在底层，Frida 可能使用诸如代码注入、trampoline hooking 等技术。
* **用户操作到达这里:** 用户会在 Frida 脚本中使用 `Interceptor.attach()` 来hook感兴趣的函数。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:**  拦截 `target_function_int` 函数，`onEnter` 回调中打印 ">"，`onLeave` 回调中打印 "<"，然后调用 `target_function_int(42)`。
    * **预期输出:**  控制台输出 ">", "<", 然后是 `target_function_int(42)` 的返回值。
* **用户或编程常见错误:**
    * **在 `onEnter` 或 `onLeave` 中修改了不应该修改的值:** 例如，错误地修改了函数参数，导致程序行为异常。
    * **回调函数中的逻辑错误:**  例如，回调函数中抛出异常，可能会导致拦截失败或目标程序崩溃。

**7. 错误处理 (Error Handling):**

* **功能:** 代码中使用了 `EXPECT_ERROR_MESSAGE_WITH` 来测试在某些情况下是否会抛出预期的错误。例如，尝试使用过小的缓冲区创建 `X86Writer`。
* **用户或编程常见错误:**  这直接关联到用户在使用 Frida API 时可能遇到的错误，例如内存分配不足、参数类型错误等。
* **用户操作到达这里:**  用户在编写 Frida 脚本时可能会遇到这些错误，Frida 会给出相应的错误提示。

**8. 架构特定代码 (Architecture-Specific Code):**

* **功能:** 代码使用 `#if defined` 来区分不同的 CPU 架构，并执行相应的测试代码。这表明 Frida 能够处理多种不同的架构。
* **二进制底层知识:**  反映了不同架构在指令集、寄存器、调用约定等方面的差异。

**本部分的功能归纳:**

这部分代码主要测试了 Frida 在 **指令级操作** 和 **本地函数交互** 方面的核心功能。具体来说，它测试了：

* **解析和理解机器码指令的能力。**
* **生成不同架构机器码的能力。**
* **在运行时重定位代码段的能力。**
* **将内存地址和函数名相互转换的能力。**
* **从 JavaScript 代码调用本地函数的能力。**
* **在 JavaScript 代码中拦截和修改本地函数调用的能力。**
* **对用户可能产生的错误进行处理和报告的能力。**

这些功能是 Frida 作为动态插桩工具的基础，使得用户能够在运行时对目标进程进行深入的分析和修改。

### 提示词
```
这是目录为frida/subprojects/frida-gum/tests/gumjs/script.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共11部分，请归纳一下它的功能
```

### 源代码
```c
e);"
      "send(operands[1].access);"
      "const disp = operands[1].value.disp;"
      "send(ldr.address.add(4 + disp).readU32());"

      "const bl = Instruction.parse(ldr.next);"
      "send(bl.mnemonic);"
      "operands = bl.operands;"
      "send(operands[0].type);"
      "send(ptr(operands[0].value).equals(code.add(64)));"

      "const sxtb = Instruction.parse(bl.next);"
      "send(sxtb.mnemonic);"
      "operands = sxtb.operands;"
      "send(typeof operands[0].shift);"
      "send(operands[1].shift.type);"
      "send(operands[1].shift.value);"

      "const vdup = Instruction.parse(sxtb.next);"
      "send(vdup.mnemonic);"
      "operands = vdup.operands;"
      "send(typeof operands[0].vectorIndex);"
      "send(operands[1].vectorIndex);"

      "const aw = new ArmWriter(code);"
      "aw.putInstruction(0xe00380f7);" /* strd r8, sb, [r3], -r7 */
      "aw.flush();"

      "const strdeq = Instruction.parse(code);"
      "send(strdeq.mnemonic);"
      "operands = strdeq.operands;"
      "send(operands[0].subtracted);"
      "send(operands[1].subtracted);"
      "send(operands[2].subtracted);"
      "send(operands[3].subtracted);");

  EXPECT_SEND_MESSAGE_WITH ("\"ldr\"");
  EXPECT_SEND_MESSAGE_WITH ("2");
  EXPECT_SEND_MESSAGE_WITH ("\"reg\"");
  EXPECT_SEND_MESSAGE_WITH ("\"r0\"");
  EXPECT_SEND_MESSAGE_WITH ("\"w\"");
  EXPECT_SEND_MESSAGE_WITH ("\"mem\"");
  EXPECT_SEND_MESSAGE_WITH ("\"pc\"");
  EXPECT_SEND_MESSAGE_WITH ("1");
  EXPECT_SEND_MESSAGE_WITH ("\"r\"");
  EXPECT_SEND_MESSAGE_WITH ("42");

  EXPECT_SEND_MESSAGE_WITH ("\"bl\"");
  EXPECT_SEND_MESSAGE_WITH ("\"imm\"");
  EXPECT_SEND_MESSAGE_WITH ("true");

  EXPECT_SEND_MESSAGE_WITH ("\"sxtb.w\"");
  EXPECT_SEND_MESSAGE_WITH ("\"undefined\"");
  EXPECT_SEND_MESSAGE_WITH ("\"ror\"");
  EXPECT_SEND_MESSAGE_WITH ("16");

  EXPECT_SEND_MESSAGE_WITH ("\"vdup.8\"");
  EXPECT_SEND_MESSAGE_WITH ("\"undefined\"");
  EXPECT_SEND_MESSAGE_WITH ("1");

  EXPECT_SEND_MESSAGE_WITH ("\"strd\"");
  EXPECT_SEND_MESSAGE_WITH ("false");
  EXPECT_SEND_MESSAGE_WITH ("false");
  EXPECT_SEND_MESSAGE_WITH ("false");
  EXPECT_SEND_MESSAGE_WITH ("true");
#elif defined (HAVE_ARM64)
  COMPILE_AND_LOAD_SCRIPT (
      "const code = Memory.alloc(Process.pageSize);"

      "const cw = new Arm64Writer(code);"
      "cw.putLdrRegU64('x0', 42);"
      "cw.putStrRegRegOffset('x0', 'x7', 32);"
      "cw.putInstruction(0xcb422020);" /* sub x0, x1, x2, lsr #8 */
      "cw.putInstruction(0x8b230841);" /* add x1, x2, w3, uxtb #2 */
      "cw.putInstruction(0x4ee28420);" /* add.2d v0, v1, v2 */
      "cw.putInstruction(0x9eae00e5);" /* fmov.d x5, v7[1] */
      "cw.flush();"

      "const ldr = Instruction.parse(code);"
      "send(ldr.mnemonic);"
      "let operands = ldr.operands;"
      "send(operands.length);"
      "send(operands[0].type);"
      "send(operands[0].value);"
      "send(operands[0].access);"
      "send(operands[1].type);"
      "send(operands[1].access);"
      "send(ptr(operands[1].value).readU64().valueOf());"

      "const str = Instruction.parse(ldr.next);"
      "send(str.mnemonic);"
      "operands = str.operands;"
      "send(operands[1].type);"
      "const memProps = Object.keys(operands[1].value);"
      "memProps.sort();"
      "send(memProps);"
      "send(operands[1].value.base);"
      "send(operands[1].value.disp);"

      "const sub = Instruction.parse(str.next);"
      "send(sub.mnemonic);"
      "operands = sub.operands;"
      "send(typeof operands[0].shift);"
      "send(typeof operands[1].shift);"
      "send(operands[2].shift.type);"
      "send(operands[2].shift.value);"

      "const add = Instruction.parse(sub.next);"
      "send(add.mnemonic);"
      "operands = add.operands;"
      "send(typeof operands[0].ext);"
      "send(typeof operands[1].ext);"
      "send(operands[2].ext);"

      "const vadd = Instruction.parse(add.next);"
      "send(vadd.mnemonic);"
      "operands = vadd.operands;"
      "send(operands[0].vas);"
      "send(operands[1].vas);"
      "send(operands[2].vas);"

      "const fmov = Instruction.parse(vadd.next);"
      "send(fmov.mnemonic);"
      "operands = fmov.operands;"
      "send(typeof operands[0].vectorIndex);"
      "send(operands[1].vectorIndex);");

  EXPECT_SEND_MESSAGE_WITH ("\"ldr\"");
  EXPECT_SEND_MESSAGE_WITH ("2");
  EXPECT_SEND_MESSAGE_WITH ("\"reg\"");
  EXPECT_SEND_MESSAGE_WITH ("\"x0\"");
  EXPECT_SEND_MESSAGE_WITH ("\"w\"");
  EXPECT_SEND_MESSAGE_WITH ("\"imm\"");
  EXPECT_SEND_MESSAGE_WITH ("\"r\"");
  EXPECT_SEND_MESSAGE_WITH ("42");

  EXPECT_SEND_MESSAGE_WITH ("\"str\"");
  EXPECT_SEND_MESSAGE_WITH ("\"mem\"");
  EXPECT_SEND_MESSAGE_WITH ("[\"base\",\"disp\"]");
  EXPECT_SEND_MESSAGE_WITH ("\"x7\"");
  EXPECT_SEND_MESSAGE_WITH ("32");

  EXPECT_SEND_MESSAGE_WITH ("\"sub\"");
  EXPECT_SEND_MESSAGE_WITH ("\"undefined\"");
  EXPECT_SEND_MESSAGE_WITH ("\"undefined\"");
  EXPECT_SEND_MESSAGE_WITH ("\"lsr\"");
  EXPECT_SEND_MESSAGE_WITH ("8");

  EXPECT_SEND_MESSAGE_WITH ("\"add\"");
  EXPECT_SEND_MESSAGE_WITH ("\"undefined\"");
  EXPECT_SEND_MESSAGE_WITH ("\"undefined\"");
  EXPECT_SEND_MESSAGE_WITH ("\"uxtb\"");

  EXPECT_SEND_MESSAGE_WITH ("\"add\"");
  EXPECT_SEND_MESSAGE_WITH ("\"2d\"");
  EXPECT_SEND_MESSAGE_WITH ("\"2d\"");
  EXPECT_SEND_MESSAGE_WITH ("\"2d\"");

  EXPECT_SEND_MESSAGE_WITH ("\"fmov\"");
  EXPECT_SEND_MESSAGE_WITH ("\"undefined\"");
  EXPECT_SEND_MESSAGE_WITH ("1");
#else
  g_print ("<skipping, missing code for current architecture> ");
#endif
}

TESTCASE (instruction_can_be_generated)
{
#if defined (HAVE_I386)
  COMPILE_AND_LOAD_SCRIPT (
      "const callback = new NativeCallback((a, b) => {"
      "  return a * b;"
      "}, 'int', ['int', 'int']);"

      "const page = Memory.alloc(Process.pageSize);"

      "Memory.patchCode(page, 64, code => {"
        "const cw = new X86Writer(code, { pc: page });"

        "cw.putMovRegU32('eax', 42);"

        "const stackAlignOffset = Process.pointerSize;"
        "cw.putSubRegImm('xsp', stackAlignOffset);"

        "cw.putCallAddressWithArguments(callback, ['eax', 7]);"

        "cw.putAddRegImm('xsp', stackAlignOffset);"

        "cw.putJmpShortLabel('badger');"

        "cw.putMovRegU32('eax', 43);"

        "cw.putLabel('badger');"
        "cw.putRet();"

        "cw.flush();"
        "send(cw.offset > 30);"
      "});"

      "const f = new NativeFunction(page, 'int', []);"
      "send(f());");

  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("294");
  EXPECT_NO_MESSAGES ();

  COMPILE_AND_LOAD_SCRIPT (
      "const code = Memory.alloc(16);"
      "const cw = new X86Writer(code);"
      "cw.putMovRegU32('rax', 42);");
  EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER, "Error: invalid argument");
#else
  g_print ("<skipping, missing code for current architecture> ");
#endif
}

TESTCASE (instruction_can_be_relocated)
{
#if defined (HAVE_I386)
  COMPILE_AND_LOAD_SCRIPT (
      "const page = Memory.alloc(Process.pageSize);"

      "const impl1 = page.add(0);"
      "const impl2 = page.add(64);"

      "Memory.patchCode(impl1, 16, code => {"
        "const cw = new X86Writer(code, { pc: impl1 });"
        "cw.putMovRegU32('eax', 42);"
        "cw.putRet();"
        "cw.flush();"
      "});"

      "Memory.patchCode(impl2, 16, code => {"
        "const cw = new X86Writer(code, { pc: impl2 });"
        "const rl = new X86Relocator(impl1, cw);"

        "send(rl.input);"

        "send(rl.readOne());"
        "send(rl.input.toString());"
        "send(rl.writeOne());"

        "send(rl.eob);"
        "send(rl.eoi);"

        "send(rl.readOne());"
        "send(rl.input.toString());"
        "send(rl.writeOne());"

        "send(rl.readOne());"
        "send(rl.eob);"
        "send(rl.eoi);"

        "cw.flush();"
      "});"

      "const f = new NativeFunction(impl2, 'int', []);"
      "send(f());");

  EXPECT_SEND_MESSAGE_WITH ("null");

  EXPECT_SEND_MESSAGE_WITH ("5");
  EXPECT_SEND_MESSAGE_WITH ("\"mov eax, 0x2a\"");
  EXPECT_SEND_MESSAGE_WITH ("true");

  EXPECT_SEND_MESSAGE_WITH ("false");
  EXPECT_SEND_MESSAGE_WITH ("false");

  EXPECT_SEND_MESSAGE_WITH ("6");
  EXPECT_SEND_MESSAGE_WITH ("\"ret\"");
  EXPECT_SEND_MESSAGE_WITH ("true");

  EXPECT_SEND_MESSAGE_WITH ("0");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");

  EXPECT_SEND_MESSAGE_WITH ("42");

  EXPECT_NO_MESSAGES ();
#else
  g_print ("<skipping, missing code for current architecture> ");
#endif
}

TESTCASE (code_writer_should_not_flush_on_gc)
{
#if defined (HAVE_I386)
  COMPILE_AND_LOAD_SCRIPT (
      "const page = Memory.alloc(Process.pageSize);"
      "let writer = new X86Writer(page);"
      "writer.putJmpShortLabel('later');"
      "writer.putBreakpoint();"
      "writer.putLabel('later');"
      "writer.putRet();"
      "Memory.protect(page, Process.pageSize, '---');"
      "writer = null;"
      "gc();");
  EXPECT_NO_MESSAGES ();
#elif defined (HAVE_ARM)
  COMPILE_AND_LOAD_SCRIPT (
      "const page = Memory.alloc(Process.pageSize);"
      "let writer = new ArmWriter(page);"
      "writer.putBLabel('later');"
      "writer.putBrkImm(42);"
      "writer.putLabel('later');"
      "writer.putMovRegReg('pc', 'lr');"
      "Memory.protect(page, Process.pageSize, '---');"
      "writer = null;"
      "gc();");
  EXPECT_NO_MESSAGES ();

  COMPILE_AND_LOAD_SCRIPT (
      "const page = Memory.alloc(Process.pageSize);"
      "let writer = new ThumbWriter(page);"
      "writer.putBLabel('later');"
      "writer.putBkptImm(42);"
      "writer.putLabel('later');"
      "writer.putPopRegs(['pc']);"
      "Memory.protect(page, Process.pageSize, '---');"
      "writer = null;"
      "gc();");
  EXPECT_NO_MESSAGES ();
#elif defined (HAVE_ARM64)
  COMPILE_AND_LOAD_SCRIPT (
      "const page = Memory.alloc(Process.pageSize);"
      "let writer = new Arm64Writer(page);"
      "writer.putBLabel('later');"
      "writer.putBrkImm(42);"
      "writer.putLabel('later');"
      "writer.putRet();"
      "Memory.protect(page, Process.pageSize, '---');"
      "writer = null;"
      "gc();");
  EXPECT_NO_MESSAGES ();
#elif defined (HAVE_MIPS)
  COMPILE_AND_LOAD_SCRIPT (
      "const page = Memory.alloc(Process.pageSize);"
      "let writer = new MipsWriter(page);"
      "writer.putJLabel('later');"
      "writer.putBreak(42);"
      "writer.putLabel('later');"
      "writer.putRet();"
      "Memory.protect(page, Process.pageSize, '---');"
      "writer = null;"
      "gc();");
  EXPECT_NO_MESSAGES ();
#else
  g_print ("<skipping, missing code for current architecture> ");
#endif
}

TESTCASE (code_writer_should_flush_on_reset)
{
  const gchar * test_reset =
      "const size = writer.offset;"
      "const before = new Uint8Array(page.readByteArray(size));"
      "writer.reset(page);"
      "const after = new Uint8Array(page.readByteArray(size));"
      "send(after.join(',') !== before.join(','));";

#if defined (HAVE_I386)
  COMPILE_AND_LOAD_SCRIPT (
      "const page = Memory.alloc(Process.pageSize);"
      "const writer = new X86Writer(page);"
      "writer.putJmpShortLabel('later');"
      "writer.putBreakpoint();"
      "writer.putLabel('later');"
      "writer.putRet();"
      "%s",
      test_reset);
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();
#elif defined (HAVE_ARM)
  COMPILE_AND_LOAD_SCRIPT (
      "const page = Memory.alloc(Process.pageSize);"
      "const writer = new ArmWriter(page);"
      "writer.putBLabel('later');"
      "writer.putBrkImm(13);"
      "writer.putBrkImm(37);"
      "writer.putLabel('later');"
      "writer.putMovRegReg('pc', 'lr');"
      "%s",
      test_reset);
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();

  COMPILE_AND_LOAD_SCRIPT (
      "const page = Memory.alloc(Process.pageSize);"
      "const writer = new ThumbWriter(page);"
      "writer.putBLabel('later');"
      "writer.putBkptImm(13);"
      "writer.putBkptImm(37);"
      "writer.putLabel('later');"
      "writer.putPopRegs(['pc']);"
      "%s",
      test_reset);
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();
#elif defined (HAVE_ARM64)
  COMPILE_AND_LOAD_SCRIPT (
      "const page = Memory.alloc(Process.pageSize);"
      "const writer = new Arm64Writer(page);"
      "writer.putBLabel('later');"
      "writer.putBrkImm(42);"
      "writer.putLabel('later');"
      "writer.putRet();"
      "%s",
      test_reset);
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();
#elif defined (HAVE_MIPS)
  COMPILE_AND_LOAD_SCRIPT (
      "const page = Memory.alloc(Process.pageSize);"
      "const writer = new MipsWriter(page);"
      "writer.putJLabel('later');"
      "writer.putBreak(42);"
      "writer.putLabel('later');"
      "writer.putRet();"
      "%s",
      test_reset);
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();
#else
  g_print ("<skipping, missing code for current architecture> ");
#endif
}

TESTCASE (code_writer_should_flush_on_dispose)
{
  const gchar * test_dispose =
      "const size = writer.offset;"
      "const before = new Uint8Array(page.readByteArray(size));"
      "writer.dispose();"
      "const after = new Uint8Array(page.readByteArray(size));"
      "send(after.join(',') !== before.join(','));";

#if defined (HAVE_I386)
  COMPILE_AND_LOAD_SCRIPT (
      "const page = Memory.alloc(Process.pageSize);"
      "const writer = new X86Writer(page);"
      "writer.putJmpShortLabel('later');"
      "writer.putBreakpoint();"
      "writer.putLabel('later');"
      "writer.putRet();"
      "%s",
      test_dispose);
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();
#elif defined (HAVE_ARM)
  COMPILE_AND_LOAD_SCRIPT (
      "const page = Memory.alloc(Process.pageSize);"
      "const writer = new ArmWriter(page);"
      "writer.putBLabel('later');"
      "writer.putBrkImm(13);"
      "writer.putBrkImm(37);"
      "writer.putLabel('later');"
      "writer.putMovRegReg('pc', 'lr');"
      "%s",
      test_dispose);
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();

  COMPILE_AND_LOAD_SCRIPT (
      "const page = Memory.alloc(Process.pageSize);"
      "const writer = new ThumbWriter(page);"
      "writer.putBLabel('later');"
      "writer.putBkptImm(13);"
      "writer.putBkptImm(37);"
      "writer.putLabel('later');"
      "writer.putPopRegs(['pc']);"
      "%s",
      test_dispose);
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();
#elif defined (HAVE_ARM64)
  COMPILE_AND_LOAD_SCRIPT (
      "const page = Memory.alloc(Process.pageSize);"
      "const writer = new Arm64Writer(page);"
      "writer.putBLabel('later');"
      "writer.putBrkImm(42);"
      "writer.putLabel('later');"
      "writer.putRet();"
      "%s",
      test_dispose);
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();
#elif defined (HAVE_MIPS)
  COMPILE_AND_LOAD_SCRIPT (
      "const page = Memory.alloc(Process.pageSize);"
      "const writer = new MipsWriter(page);"
      "writer.putJLabel('later');"
      "writer.putBreak(42);"
      "writer.putLabel('later');"
      "writer.putRet();"
      "%s",
      test_dispose);
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();
#else
  g_print ("<skipping, missing code for current architecture> ");
#endif
}

TESTCASE (code_relocator_should_expose_input_instruction)
{
#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  COMPILE_AND_LOAD_SCRIPT (
      "const code = Memory.alloc(4);"
      "code.writeByteArray([0x55, 0x48, 0x8b, 0xec]);"

      "const page = Memory.alloc(Process.pageSize);"
      "const writer = new X86Writer(page);"
      "const relocator = new X86Relocator(code, writer);"

      "send(relocator.input);"
      "send(relocator.peekNextWriteInsn());"

      "send(relocator.readOne());"
      "let insn = relocator.input;"
      "send(insn.toString());"
      "send(insn.address.equals(code));"
      "send(insn.next.equals(code.add(1)));"
      "relocator.writeOne();"

      "send(relocator.readOne());"
      "insn = relocator.peekNextWriteInsn();"
      "send(insn.toString());"
      "send(insn.address.equals(code.add(1)));"
      "send(insn.next.equals(code.add(4)));");

  EXPECT_SEND_MESSAGE_WITH ("null");
  EXPECT_SEND_MESSAGE_WITH ("null");

  EXPECT_SEND_MESSAGE_WITH ("1");
  EXPECT_SEND_MESSAGE_WITH ("\"push rbp\"");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");

  EXPECT_SEND_MESSAGE_WITH ("4");
  EXPECT_SEND_MESSAGE_WITH ("\"mov rbp, rsp\"");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
#elif defined (HAVE_ARM64)
  COMPILE_AND_LOAD_SCRIPT (
      "const code = Memory.alloc(8);"
      "code.writeU32(0xb9400ae8);"
      "code.add(4).writeU32(0x3100051f);"

      "const page = Memory.alloc(Process.pageSize);"
      "const writer = new Arm64Writer(page);"
      "const relocator = new Arm64Relocator(code, writer);"

      "send(relocator.input);"
      "send(relocator.peekNextWriteInsn());"

      "send(relocator.readOne());"
      "let insn = relocator.input;"
      "send(insn.toString());"
      "send(insn.address.equals(code));"
      "send(insn.next.equals(code.add(4)));"
      "relocator.writeOne();"

      "send(relocator.readOne());"
      "insn = relocator.peekNextWriteInsn();"
      "send(insn.toString());"
      "send(insn.address.equals(code.add(4)));"
      "send(insn.next.equals(code.add(8)));");

  EXPECT_SEND_MESSAGE_WITH ("null");
  EXPECT_SEND_MESSAGE_WITH ("null");

  EXPECT_SEND_MESSAGE_WITH ("4");
  EXPECT_SEND_MESSAGE_WITH ("\"ldr w8, [x23, #8]\"");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");

  EXPECT_SEND_MESSAGE_WITH ("8");
  EXPECT_SEND_MESSAGE_WITH ("\"cmn w8, #1\"");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
#else
  g_print ("<skipping, missing code for current architecture> ");
#endif
}

TESTCASE (address_can_be_resolved_to_symbol)
{
#ifdef HAVE_ANDROID
  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }
#endif

  COMPILE_AND_LOAD_SCRIPT (
      "const sym = DebugSymbol.fromAddress(" GUM_PTR_CONST ");"
      "send(sym.name);"
      "send(sym.toString().indexOf(sym.name) !== -1);"
      "send(JSON.stringify(sym) !== \"{}\");",
      target_function_int);
  EXPECT_SEND_MESSAGE_WITH ("\"target_function_int\"");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (name_can_be_resolved_to_symbol)
{
  gchar * expected;

#ifdef HAVE_ANDROID
  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }
#endif

  COMPILE_AND_LOAD_SCRIPT (
      "send(DebugSymbol.fromName(\"target_function_int\").address);");
  expected = g_strdup_printf ("\"0x%" G_GINT64_MODIFIER "x\"",
      GUM_ADDRESS (target_function_int));
  EXPECT_SEND_MESSAGE_WITH (expected);
  g_free (expected);
  EXPECT_NO_MESSAGES ();
}

TESTCASE (function_can_be_found_by_name)
{
#ifdef HAVE_ANDROID
  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }
#endif

  COMPILE_AND_LOAD_SCRIPT ("send("
      "!DebugSymbol.getFunctionByName(\"g_thread_new\").isNull()"
  ");"
  "send("
      "DebugSymbol.getFunctionByName(\"g_thread_!@#$\")"
  ");");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER,
      "Error: unable to find function with name 'g_thread_!@#$'");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (functions_can_be_found_by_name)
{
#ifdef HAVE_ANDROID
  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }
#endif

  COMPILE_AND_LOAD_SCRIPT ("send("
      "DebugSymbol.findFunctionsNamed(\"g_thread_new\").length >= 1"
  ");");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (functions_can_be_found_by_matching)
{
#ifdef HAVE_ANDROID
  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }
#endif

  COMPILE_AND_LOAD_SCRIPT ("send("
      "DebugSymbol.findFunctionsMatching(\"gum_symbol_details_from*\")"
          ".length >= 1"
  ");");
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (native_function_can_be_invoked)
{
  gchar str[7];

  COMPILE_AND_LOAD_SCRIPT (
      "const f = new NativeFunction(" GUM_PTR_CONST ", 'int', []);"
      "send(f());",
      gum_get_answer_to_life_universe_and_everything);
  EXPECT_SEND_MESSAGE_WITH ("42");
  EXPECT_NO_MESSAGES ();

  strcpy (str, "badger");
  COMPILE_AND_LOAD_SCRIPT (
      "const toupper = new NativeFunction(" GUM_PTR_CONST ", "
          "'int', ['pointer', 'int']);"
      "send(toupper(" GUM_PTR_CONST ", 3));"
      "send(toupper(" GUM_PTR_CONST ", -1));",
      gum_toupper, str, str);
  EXPECT_SEND_MESSAGE_WITH ("3");
  EXPECT_SEND_MESSAGE_WITH ("-6");
  EXPECT_NO_MESSAGES ();
  g_assert_cmpstr (str, ==, "BADGER");

  COMPILE_AND_LOAD_SCRIPT (
      "const sum = new NativeFunction(" GUM_PTR_CONST ", "
          "'int', ['pointer', 'pointer', 'float']);"
      "send(sum(ptr(3), ptr(4), 42.0));",
      gum_add_pointers_and_float_fixed);
  EXPECT_SEND_MESSAGE_WITH ("49");
  EXPECT_NO_MESSAGES ();

#ifdef HAVE_WINDOWS
  COMPILE_AND_LOAD_SCRIPT (
      "const impl = Module.getExportByName(\"user32.dll\", \"GetKeyState\");"
      "const f = new NativeFunction(impl, 'int16', ['int']);"
      "const result = f(0x41);"
      "send(typeof result);");
  EXPECT_SEND_MESSAGE_WITH ("\"number\"");
  EXPECT_NO_MESSAGES ();
#endif

  COMPILE_AND_LOAD_SCRIPT (
      "const classify = new NativeFunction(" GUM_PTR_CONST ", "
          "'int64', ['int64']);"
      "send(classify(int64(\"-42\")));"
      "send(classify(int64(\"0\")));"
      "send(classify(int64(\"42\")));",
      gum_classify_timestamp);
  EXPECT_SEND_MESSAGE_WITH ("\"-1\"");
  EXPECT_SEND_MESSAGE_WITH ("\"0\"");
  EXPECT_SEND_MESSAGE_WITH ("\"1\"");
  EXPECT_NO_MESSAGES ();

  COMPILE_AND_LOAD_SCRIPT (
      "const square = new NativeFunction(" GUM_PTR_CONST ", "
          "'uint64', ['uint64']);"
      "send(square(uint64(\"2\")));"
      "send(square(uint64(\"4\")));"
      "send(square(uint64(\"6\")));",
      gum_square);
  EXPECT_SEND_MESSAGE_WITH ("\"4\"");
  EXPECT_SEND_MESSAGE_WITH ("\"16\"");
  EXPECT_SEND_MESSAGE_WITH ("\"36\"");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (native_function_can_be_invoked_with_size_t)
{
  gchar arg[23];
  gchar ret[23];

  /*
   * Per specs “size_t” is an unsigned integer type defined in stddef.h.
   * Per recommendation “size_t” shall be able to represent the largest
   * possible object size:
   *
   *     The types used for “size_t” and “ptrdiff_t” should not have an
   *     integer conversion rank greater than that of “signed long int”
   *     unless the implementation supports objects large enough to make
   *     this necessary.
   *
   * The largest possible size is defined by SIZE_MAX (stddef.h).
   * The minimum value for SIZE_MAX definitions is 65535 (ref C99, 7.18.3),
   * which implies that the smallest possible “size_t” conversion would be
   * 16bit (depends on architecture implementation and compiler).
   *
   * Conclusion: If the maximum object size of an implementation corresponds to
   * the address-width, it could be assumed that SIZE_MAX will not exceed
   * UINT64_MAX, for architectures in Frida's scope. This again means, that for
   * the JavaScript runtimes all possible “size_t” values could be represented
   * as “uint64” (as 64bit SIZE_MAX of 1844674407370955161UL would exceed the
   * limits of JavaScript “Number.MAX_SAFE_INTEGER”).
   * For the native part, on the other hand, “size_t” values cannot be encoded
   * in uint64 per se, instead this has to be done depending on the
   * implementation's value of SIZE_MAX.
   *
   * SIZE_WIDTH    JS size_t        Native size_t
   * 64            uint64    <->    uint64
   * 32            uint64    <->    uint32 (temporary guint64 during conversion)
   * 16            uint64    <->    uint16 (temporary guint64 during conversion)
   *
   * For GLib, the definition of gsize is very simplified (compared to C99):
   *
   *     > usually 32 bit wide on a 32-bit platform and 64 bit wide on a 64-bit
   *     > platform”
   *
   * Ref: https://developer.gnome.org/glib/stable/glib-Basic-Types.html#gsize
   *
   * Implementation of “ssize_t” is analogous.
   *
   * SIZE_WIDTH    JS ssize_t       Native ssize_t
   * 64            int64     <->    int64
   * 32            int64     <->    int32 (temporary gint64 during conversion)
   * 16            int64     <->    int16 (temporary gint64 during conversion)
   *
   * Additional notes:
   *
   * 1) ssize_t seems to be POSIX defined, but not C99.
   * 2) ptrdiff_t is not implemented (but C99 defined) ... normally ssize_t
   *    should be able to store ptrdiff_t, but this requires further testing
   * 3) Focus was put on size_t implementation, which is tested and working.
   *    ssize_t/ptrdiff_t are not in main scope and require additional testing
   *    (+ implementation of ptrdiff_t, if not casted to size_t). The test for
   *    “ssize_t” uses a simple pass-through function which is called with
   *    a) PTRDIFF_MAX and b) PTRDIFF_MIN
   *
   * External:
   *
   * - Discussion on SSIZE_MAX weirdness:
   *   https://sourceware.org/bugzilla/show_bug.cgi?id=13575
   */

  sprintf (ret, "\"%" G_GSIZE_MODIFIER "u\"", (gsize) SIZE_MAX);
  COMPILE_AND_LOAD_SCRIPT (
      "const getSizeMax = new NativeFunction(" GUM_PTR_CONST ", 'size_t', []);"
      "send(getSizeMax());",
      gum_get_size_max);
  EXPECT_SEND_MESSAGE_WITH (ret);
  EXPECT_NO_MESSAGES ();

  sprintf (arg, "%" G_GSIZE_MODIFIER "u", (gsize) (SIZE_MAX - 1));
  COMPILE_AND_LOAD_SCRIPT (
      "const addSize = new NativeFunction(" GUM_PTR_CONST ", 'size_t', "
          "['size_t']);"
      "send(addSize(uint64(\"%s\")));",
      gum_add_size, arg);
  EXPECT_SEND_MESSAGE_WITH (ret);
  EXPECT_NO_MESSAGES ();

  sprintf (arg, "%" G_GSIZE_MODIFIER "u", (gsize) SIZE_MAX);
  COMPILE_AND_LOAD_SCRIPT (
      "const testSizeMax = new NativeFunction(" GUM_PTR_CONST ", 'bool', "
          "['size_t']);"
      "send(testSizeMax(uint64(\"%s\")) === 1);",
      gum_test_size_max, arg);
  EXPECT_SEND_MESSAGE_WITH ("true");
  EXPECT_NO_MESSAGES ();

  sprintf (arg, "%" G_GSIZE_MODIFIER "u", (gsize) SIZE_MAX);
  sprintf (ret, "\"%" G_GSIZE_MODIFIER "u\"", (gsize) SIZE_MAX);
  COMPILE_AND_LOAD_SCRIPT (
      "const passSize = new NativeFunction(" GUM_PTR_CONST ", 'size_t', "
          "['size_t']);"
      "send(passSize(uint64(\"%s\")));",
      gum_pass_size, arg);
  EXPECT_SEND_MESSAGE_WITH (ret);
  EXPECT_NO_MESSAGES ();

#ifndef _MSC_VER
  sprintf (arg, "%td", (ptrdiff_t) PTRDIFF_MAX);
  sprintf (ret, "\"%td\"", (ptrdiff_t) PTRDIFF_MAX);
  COMPILE_AND_LOAD_SCRIPT (
      "const passSSize = new NativeFunction(" GUM_PTR_CONST ", 'ssize_t', "
          "['ssize_t']);"
      "send(passSSize(int64(\"%s\")));",
      gum_pass_ssize, arg);
  EXPECT_SEND_MESSAGE_WITH (ret);
  EXPECT_NO_MESSAGES ();

  sprintf (arg, "%" G_GSIZE_MODIFIER"d", (gsize) PTRDIFF_MIN);
  sprintf (ret, "\"%" G_GSIZE_MODIFIER "d\"", (gsize) PTRDIFF_MIN);
  COMPILE_AND_LOAD_SCRIPT (
      "const passSSize = new NativeFunction(" GUM_PTR_CONST ", 'ssize_t', "
          "['ssize_t']);"
      "send(passSSize(int64(\"%s\")));",
      gum_pass_ssize, arg);
  EXPECT_SEND_MESSAGE_WITH (ret);
  EXPECT_NO_MESSAGES ();
#endif
}

static size_t
gum_get_size_max (void)
{
  return SIZE_MAX;
}

static gboolean
gum_test_size_max (size_t sz)
{
  return SIZE_MAX == sz;
}

static size_t
gum_add_size (size_t sz)
{
  return sz + (size_t) 1;
}

static size_t
gum_pass_size (size_t sz)
{
  return sz;
}

#ifndef _MSC_VER

static size_t
gum_pass_ssize (ssize_t ssz)
{
  return ssz;
}

#endif

TESTCASE (native_function_can_be_intercepted_when_thread_is_ignored)
{
  GumInterceptor * interceptor;
  GMainContext * js_context;
  GSource * source;

  interceptor = gum_interceptor_obtain ();

  js_context = gum_script_scheduler_get_js_context (
      gum_script_backend_get_scheduler ());

  source = g_idle_source_new ();
  g_source_set_callback (source, (GSourceFunc) ignore_thread,
      g_object_ref (interceptor), g_object_unref);
  g_source_attach (source, js_context);
  g_source_unref (source);

  COMPILE_AND_LOAD_SCRIPT (
      "const impl = " GUM_PTR_CONST ";"
      "Interceptor.attach(impl, {"
      "  onEnter(args) {"
      "    send('>');"
      "  },"
      "  onLeave(retval) {"
      "    send('<');"
      "  }"
      "});"
      "Interceptor.flush();"
      "const f = new NativeFunction(impl, 'int', ['int']);"
      "send(f(42));",
      target_function_nested_a);

  EXPECT_SEND_MESSAGE_WITH ("\">\"");
  EXPECT_SEND_MESSAGE_WITH ("\"<\"");
  EXPECT_SEND_MESSAGE_WITH ("16855020");
  EXPECT_NO_MESSAGES ();

  source = g_idle_source_new ();
  g_source_set_callback (source, (GSourceFunc) unignore_thread,
      g_object_ref (interceptor), g_object_unref);
  g_source_attach (source, js_context);
  g_source_unref (source);

  g_object_unref (interceptor);
}

static gboolean
ignore_thread (GumInterceptor * interceptor)
{
  gum_interceptor_ignore_current_thread (interceptor);

  return FALSE;
}

static gboolean
unignore_thread (GumInterceptor * interceptor)
{
  gum_interceptor_unignore_current_thread (interceptor);

  return FALSE;
}

TESTCASE (native_function_can_not_be_intercepted_when_traps_are_none)
{
  GumInterceptor * interceptor;

  interceptor = gum_interceptor_obtain ();

  COMPILE_AND_LOAD_SCRIPT (
      "const aImpl = " GUM_PTR_CONST ";"
      "const bImpl = " GUM_PTR_CONST ";"
      "const cImpl = " GUM_PTR_CONST ";"
      "Interceptor.attach(aImpl, {"
      "  onEnter(args) {"
      "    send('a>');"
      "  },"
      "  onLeave(retval) {"
      "    send('a<');"
      "  }"
      "});"
      "Interceptor.attach(bImpl, {"
      "  onEnter(args) {"
      "    send('b>');"
      "  },"
      "  onLeave(retval) {"
      "    send('b<');"
      "  }"
      "});"
      "Interceptor.attach(cImpl, {"
      "  onEnter(args) {"
      "    send('c>');"
      "  },"
      "  onLeave(retval) {"
      "    send('c<');"
      "  }"
      "});"
      "Interceptor.flush();"
      "const f = new NativeFunction(aImpl, 'int', ['int'], { traps: 'none' });"
      "send(f(42));",
      target_function_nested_a,
      target_function_nested_b,
      target_function_nested_c);

  EXPECT_SEND_MESSAGE_WITH ("16855020");
  EXPECT_NO_MESSAGES ();

  g_object_unref (interceptor);
}

TESTCASE (native_function_should_implement_call_and_apply)
{
  COMPILE_AND_LOAD_SCRIPT (
      "const f = new NativeFunction(" GUM_PTR_CONST ", 'int', []);"
      "send(f.call());"
      "send(f.call(f));"
      "send(f.apply(f));"
      "send(f.apply(f, undefined));"
      "send(f.apply(f, null));"
      "send(f.apply(f, []));",
      gum_get_answer_to_life_universe_and_everything);
  EXPECT_SEND_MESSAGE_WITH ("42");
  EXPECT_SEND_MESSAGE_WITH ("42");
  EXPECT_SEND_MESSAGE_WITH ("42");
  EXPECT_SEND_MESSAGE_WITH ("42");
  EXPECT_SEND_MESSAGE_WITH ("42");
  EXPECT_SEND_MESSAGE_WITH ("42");
  EXPECT_NO_MESSAGES ();

  COMPILE_AND_LOAD_SCRIPT (
      "const f = new NativeFunction(" GUM_PTR_CONST ", 'int', ['int']);"
      "send(NativeFunction.prototype.call(f, 42));"
      "send(NativeFunction.prototype.apply(f, [42]));"
      "send(f.call(undefined, 42));"
      "send(f.apply(undefined, [42]));"
      "send(f.call(null, 42));"
      "send(f.apply(null, [42]));"
      "send(f.call(f, 42));"
      "send(f.apply(f, [42]));"
      "send(f.call(ptr(" GUM_PTR_CONST "), 42));"
      "send(f.apply(ptr(" GUM_PTR_CONST "), [42]));",
      target_function_int, target_function_nested_a, target_function_nested_a);
  EXPECT_SEND_MESSAGE_WITH ("1890");
  EXPECT_SEND_MESSAGE_WITH ("1890");
  EXPECT_SEND_MESSAGE_WITH ("1890");
  EXPECT_SEND_MESSAGE_WITH ("1890");
  EXPECT_SEND_MESSAGE_WITH ("1890");
  EXPECT_SEND_MESSAGE_WITH ("1890");
  EXPECT_SEND_MESSAGE_WITH ("1890");
  EXPECT_SEND_MESSAGE_WITH ("1890");
  EXPECT_SEND_MESSAGE_WITH ("16855020");
  EXPECT_SEND_MESSAGE_WITH ("16855020");
  EXPECT_NO_MESSAGES ();

  COMPILE_AND_LOAD_SCRIPT (
      "const f = new NativeFunction(" GUM_PTR_CONST ", 'pointer', "
      "    ['pointer', 'int']);"
      "send(f.call(null, ptr(4), 3));"
      "send(f.apply(null, [ptr(4), 3]));",
      target_function_base_plus_offset);
  EXPECT_SEND_MESSAGE_WITH ("\"0x7\"");
  EXPECT_SEND_MESSAGE_WITH ("\"0x7\"");
  EXPECT_NO_MESSAGES ();
}

TESTCASE (native_function_crash_results_in_exception)
{
  if (!check_exception_handling_testable ())
    return;

  COMPILE_AND_LOAD_SCRIPT (
      "const targetWithString = new NativeFunction(" GUM_PTR_CONST ", "
          "'pointer', ['pointer'], {"
          "abi: 'default',"
          "scheduling: 'exclusive',"
          "exceptions: 'steal',"
      "});"
      "try {"
      "  targetWithStr
```