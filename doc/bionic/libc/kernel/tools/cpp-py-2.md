Response:
Let's break down the thought process for answering the request about `cpp.py`.

**1. Understanding the Core Request:**

The primary goal is to analyze the provided Python code (`cpp.py`) and explain its functionality within the context of Android's Bionic library. The request specifically asks for:

* Functionality listing.
* Relationship to Android.
* Detailed explanations of libc functions (though the code *doesn't* implement libc functions, this requires careful phrasing).
* Dynamic linker relevance (similarly, the code *doesn't* directly deal with the dynamic linker).
* Logic inference (this pertains to the code's logic for pre-processing).
* Common user errors (related to using the pre-processor).
* How Android Framework/NDK reach this code.
* Frida hook examples.
* A summary of the code's function (for this, the third part of the request).

**2. Initial Code Scan and High-Level Purpose:**

The code contains classes like `CppStringTokenizer`, `CppExpr`, `Block`, `BlockParser`, and `OptimizerTests`. The presence of `#if`, `#ifdef`, `#else`, `#elif`, `#endif` directives and tests like `test_if1`, `test_if0`, etc., strongly suggest that this code is a **C preprocessor** or a component thereof. It's designed to handle conditional compilation directives.

**3. Deconstructing Key Components:**

* **`CppStringTokenizer`:**  Likely responsible for breaking the input C/C++ code into tokens.
* **`CppExpr`:**  Probably handles the evaluation of expressions within `#if` and `#elif` directives.
* **`Block`:**  Represents a block of code, possibly with associated preprocessor directives.
* **`BlockParser`:**  Parses the token stream and groups tokens into `Block` objects, identifying preprocessor directives.
* **`optimize_if0`, `optimize_if01`:** These functions clearly implement the core logic of conditional compilation, deciding which blocks of code to keep or discard based on the evaluation of `#if` conditions.
* **`Block.optimizeAll`:**  The entry point for the optimization process.
* **`Block.removeStructs`, `Block.removeVarsAndFuncs`, `Block.replaceTokens`:**  Additional pre-processing steps, likely for stripping or transforming code before final compilation.
* **`OptimizerTests`, `RemoveStructsTests`, `FullPathTest`:**  Unit tests to verify the functionality of the preprocessor.

**4. Connecting to Android and Bionic:**

The initial context states the file is part of Android's Bionic library. This immediately suggests the code's purpose is to preprocess C/C++ source code *before* it's compiled into the Bionic library itself. This is a crucial step in any significant C/C++ project, as it allows for platform-specific code, debugging flags, etc.

**5. Addressing Specific Request Points:**

* **Functionality Listing:**  Based on the component analysis, I can list the functionalities: tokenizing, parsing preprocessor directives, evaluating expressions, optimizing conditional blocks, removing structs/vars/funcs, replacing tokens.
* **Relationship to Android:**  Explain that it's part of Bionic's build process, handling conditional compilation for the C library, math library, and dynamic linker. Examples of Android-specific conditional compilation can be guessed at (architecture, API level, debugging).
* **Libc Functions:**  Crucially, the code *doesn't* implement libc functions. The answer needs to clarify that this is a *preprocessor* for libc, not the libc itself. It manipulates source code *before* it becomes libc code.
* **Dynamic Linker:**  Similar to libc, this code doesn't directly handle dynamic linking. It preprocesses the source code of the dynamic linker. Providing a sample SO layout and linking process isn't directly relevant to this specific Python script. Acknowledge this and explain its role in *preparing* the dynamic linker's source.
* **Logic Inference:** Describe how `optimize_if0` and `optimize_if01` work, focusing on the rules for handling `#if 0`, `#if 1`, `#else`, and `#elif`. Provide simple examples of input and output to illustrate the logic.
* **User Errors:**  Think about common mistakes developers make with preprocessor directives (unmatched `#if`/`#endif`, incorrect expressions, unintended consequences of macro definitions).
* **Android Framework/NDK Path:**  Outline the build process: NDK compilation involves using a toolchain which includes a preprocessor. The Android Framework build also involves compiling native code, which would utilize a preprocessor.
* **Frida Hooks:** Since this is a Python script used *during the build process*, not something running on an Android device, directly hooking with Frida isn't the primary use case. However, the *output* of this script (the preprocessed C/C++ code) is what gets compiled. Acknowledge the indirect relationship and suggest where Frida could be used (hooking the *compiled* libc functions).
* **Summary (Part 3):**  Reiterate the core function: a C preprocessor for Bionic, handling conditional compilation, macro expansion, and code stripping/transformation.

**6. Structuring the Answer:**

Organize the answer clearly, using headings and bullet points to address each part of the request systematically. Use clear and concise language, avoiding overly technical jargon where possible.

**7. Refinement and Review:**

Read through the generated answer to ensure accuracy, completeness, and clarity. Check that it directly addresses all aspects of the original request. For instance, the initial thought might be to go deep into the parsing logic, but the request emphasizes *functionality* and its relation to Android.

By following this breakdown, the answer accurately reflects the purpose and function of the provided Python code within the context of Android's Bionic library. The key is to correctly identify it as a *preprocessor* and to distinguish its role from the actual implementation of libc functions or the dynamic linker.
好的，这是对 `bionic/libc/kernel/tools/cpp.py` 文件功能的归纳总结：

**核心功能：C 预处理器**

`cpp.py` 文件实现了一个 C 预处理器的核心功能，专门用于处理 Android Bionic 库的内核头文件。它的主要任务是在编译内核头文件之前，根据预定义的宏和条件编译指令，对这些文件进行转换和优化。

**具体功能点：**

1. **词法分析 (Tokenization)：**
   - `CppStringTokenizer` 类负责将输入的 C/C++ 代码字符串分解成一个个的词法单元 (tokens)，例如标识符、关键字、运算符、数字、字符串等。

2. **表达式求值 (Expression Evaluation)：**
   - `CppExpr` 类用于解析和评估 `#if` 和 `#elif` 指令中的表达式。它能够处理简单的逻辑运算、比较运算以及宏的展开。

3. **代码块解析 (Block Parsing)：**
   - `Block` 类表示代码中的一个块，它可以是一个独立的语句、一个预处理指令或者由预处理指令分隔的代码段。
   - `BlockParser` 类负责将词法单元流解析成 `Block` 对象的列表，并识别出预处理指令，例如 `#if`, `#ifdef`, `#ifndef`, `#else`, `#elif`, `#endif`, `#define` 等。

4. **条件编译处理 (Conditional Compilation)：**
   - 核心功能，通过解析 `#if`, `#ifdef`, `#ifndef`, `#else`, `#elif`, `#endif` 等指令，根据条件表达式的结果决定哪些代码块应该保留，哪些应该移除。
   - `optimize_if0` 和 `optimize_if01` 函数实现了条件编译的优化逻辑。它们能够识别出永远为真或永远为假的条件编译块，并进行相应的处理：
     - `#if 0 ... #endif`:  移除整个代码块。
     - `#if 1 ... #endif`: 保留整个代码块。
     - 处理 `#else` 和 `#elif` 分支，根据之前的 `#if` 或 `#elif` 条件结果进行转换。

5. **宏定义处理 (Macro Definition)：**
   -  虽然代码中没有显式看到宏展开的具体实现，但预处理器的核心功能之一就是处理宏定义。`Block.optimizeAll(macros)` 方法中的 `macros` 参数表明它可以接收外部定义的宏，并在处理条件编译时使用。

6. **结构体移除 (Struct Removal)：**
   - `Block.removeStructs(structs)` 方法允许移除指定的结构体定义。这在为用户空间生成精简的头文件时非常有用，可以去除内核特定的结构体。

7. **变量和函数移除 (Variable and Function Removal)：**
   - `Block.removeVarsAndFuncs(keep)` 方法允许移除除了 `keep` 集合中指定的变量和函数之外的所有变量和函数定义。这有助于提取特定的 API 或接口。

8. **Token 替换 (Token Replacement)：**
   - `Block.replaceTokens(replacements)` 方法允许进行 token 的替换。例如，可以将内核中使用的宏名替换为用户空间使用的宏名。

9. **代码输出 (Code Output)：**
   - `Block.write(out)` 方法将处理后的代码块写回到输出流。

**与 Android 功能的关系举例：**

在 Android Bionic 库的构建过程中，内核头文件通常包含大量的平台特定和内部实现细节。为了向用户空间 (例如应用程序通过 NDK 访问) 提供稳定且精简的 API，需要对这些头文件进行预处理。`cpp.py` 就扮演着这个角色。

* **移除内核特定的结构体：** 内核中定义的某些结构体可能包含用户空间不关心的成员或使用了用户空间不可见的类型。`removeStructs` 功能可以移除这些结构体，避免编译错误或 API 暴露不必要的细节。例如，移除包含内核内部锁机制的结构体。
* **替换宏定义：** 内核中使用的宏定义可能与用户空间的宏定义冲突或命名风格不一致。`replaceTokens` 功能可以将内核的宏名替换为用户空间使用的宏名，保持一致性。例如，将内核的 `_NSIG` 替换为用户空间的 `__SIGRTMAX`。
* **条件编译处理：**  内核头文件经常使用条件编译来适配不同的硬件架构或内核配置。`cpp.py` 可以根据构建环境预定义的宏，选择性地保留或移除特定的代码段。例如，针对不同的 CPU 架构定义不同的硬件寄存器地址。

**libc 函数功能实现：**

**需要注意的是，`cpp.py` 本身并没有实现任何 libc 函数的功能。** 它是一个预处理工具，作用于 C/C++ 源代码，为后续的编译过程做准备。它处理的是预处理指令，而不是 C 语言的核心语法和语义。

**dynamic linker 功能：**

同样，`cpp.py` 本身并不直接涉及 dynamic linker 的功能实现。但是，它可以被用来预处理 dynamic linker 的源代码。

**so 布局样本和链接处理过程（不适用）：**

由于 `cpp.py` 是一个预处理器，它在编译链接阶段之前运行，因此不涉及 `.so` 文件的布局或链接处理过程。`.so` 文件的布局和链接是由链接器 (ld) 完成的。

**逻辑推理、假设输入与输出：**

让我们看一个 `optimize_if0` 和 `optimize_if01` 的逻辑推理示例：

**假设输入：**

```c
#define FEATURE_A 1

#if FEATURE_A
int good_var = 1;
#else
int bad_var = 2;
#endif

#if 0
void unused_function() {
  // ...
}
#endif
```

**处理过程 (简述)：**

1. **`BlockParser`** 将代码解析成 `Block` 对象，识别出 `#if`, `#else`, `#endif` 等指令。
2. **`optimizeAll`** 方法被调用，并传入宏定义 `{"FEATURE_A": "1"}`。
3. 处理第一个 `#if FEATURE_A` 块：
   - `CppExpr` 评估 `FEATURE_A` 的值为真 (1)。
   - `optimize_if01` 识别出这是一个 `#if 1` 的情况。
   - 保留 `#if FEATURE_A` 和 `int good_var = 1;` 代码块。
   - 移除 `#else` 和 `int bad_var = 2;` 代码块。
   - 保留 `#endif`。
4. 处理第二个 `#if 0` 块：
   - `optimize_if01` 识别出这是一个 `#if 0` 的情况。
   - 移除 `#if 0`, `void unused_function() { ... }`, `#endif` 整个代码块。

**假设输出：**

```c
#define FEATURE_A 1

#if FEATURE_A
int good_var = 1;
#endif
```

**用户或编程常见的使用错误：**

1. **`#if` 和 `#endif` 不匹配：** 忘记添加 `#endif` 或者嵌套的 `#if` 结构不正确，会导致预处理错误。

   ```c
   #if defined(DEBUG)
   void debug_log(const char* msg) { /* ... */ } // 缺少 #endif
   ```

2. **`#ifdef` 或 `#ifndef` 使用错误的宏名：**  拼写错误或者假设了未定义的宏。

   ```c
   #ifnde MY_MACRO // 拼写错误，应该是 #ifndef
   // ...
   #endif
   ```

3. **`#if` 表达式过于复杂或包含未定义的标识符：** 导致表达式无法正确评估。

   ```c
   #if (VERSION > CURRENT_VERSION) // 如果 CURRENT_VERSION 未定义
   // ...
   #endif
   ```

4. **宏定义的值不是常量表达式：** 在 `#if` 中使用的宏必须展开为常量表达式。

   ```c
   int get_version() { return 10; }
   #define VERSION get_version()
   #if VERSION > 5 // 错误，VERSION 不是常量
   // ...
   #endif
   ```

**Android Framework or NDK 如何到达这里，给出 Frida hook 示例调试这些步骤：**

`cpp.py` 通常在 Android 系统或 NDK 的构建过程中被调用，作为编译工具链的一部分。

1. **Android Framework 构建：** 当构建 Android Framework 的 native 组件（例如 system services, HALs）时，构建系统 (通常是 Soong) 会调用编译器 (如 clang) 来编译 C/C++ 代码。编译器在编译之前会调用预处理器。`cpp.py` 可以作为自定义的预处理器被集成到构建系统中。

2. **NDK 构建：** 使用 NDK 构建应用程序的 native 代码时，NDK 的工具链也包含了预处理器。虽然 NDK 默认使用 clang 的内置预处理器，但理论上可以替换成自定义的预处理器。

**Frida Hook 示例（虽然 `cpp.py` 是构建时工具，但我们可以模拟调试思路）：**

由于 `cpp.py` 是一个 Python 脚本，直接使用 Frida hook 运行中的 Android 进程是不适用的。Frida 通常用于 hook 运行在 Android 设备上的 native 代码。

**调试思路 (如果想观察预处理过程)：**

1. **修改构建系统：** 在 Android 的构建系统 (例如 `Android.bp` 文件) 中，找到编译 native 代码的步骤。
2. **插入调试输出：**  修改构建脚本，在调用预处理器之前或之后，打印出相关的中间文件或环境变量。
3. **修改 `cpp.py` 添加日志：** 在 `cpp.py` 关键的函数（如 `optimizeAll`，`parse`）中添加 `print` 语句或使用 `logging` 模块输出中间状态，例如处理了哪些宏，移除了哪些代码块。
4. **重构 `cpp.py` 成可独立运行的脚本：** 可以将 `cpp.py` 修改成可以接收命令行参数（例如要预处理的文件和宏定义），然后独立运行它，方便调试。

**总结：**

`cpp.py` 是 Android Bionic 构建过程中一个重要的 C 预处理器，它负责解析和转换内核头文件，根据条件编译指令和宏定义，生成适合用户空间使用的精简且一致的头文件。它通过词法分析、表达式求值、代码块解析和优化等步骤，实现了条件编译、结构体移除、变量/函数移除和 token 替换等功能，为后续的编译链接过程做准备。

Prompt: 
```
这是目录为bionic/libc/kernel/tools/cpp.pyandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第3部分，共3部分，请归纳一下它的功能

"""
t an endif since we started with an elif.
                    result += blocks[j:j+1]
                i = j + 1
            elif dir_ == "else":
                # convert 'else' into 'if 1'
                logging.debug("convert 'if 0' .. 'else' into 'if 1' (lines %d "
                              "to %d)", blocks[i].lineno, blocks[j-1].lineno)
                if start_dir == "elif":
                    blocks[j].directive = "elif"
                else:
                    blocks[j].directive = "if"
                blocks[j].expr = CppExpr(CppStringTokenizer("1").tokens)
                i = j
            elif dir_ == "elif":
                # convert 'elif' into 'if'
                logging.debug("convert 'if 0' .. 'elif' into 'if'")
                if start_dir == "elif":
                    blocks[j].directive = "elif"
                else:
                    blocks[j].directive = "if"
                i = j
            continue

        # if 1 => find corresponding endif and remove/transform them
        k = find_matching_endif(blocks, j + 1)
        if k >= n:
            # unterminated #if 1, finish here
            logging.debug("unterminated 'if 1'")
            result += blocks[j+1:k]
            break

        start_dir = blocks[j].directive
        dir_ = blocks[k].directive
        if dir_ == "endif":
            logging.debug("convert 'if 1' .. 'endif' (lines %d to %d)",
                          blocks[j].lineno, blocks[k].lineno)
            if start_dir == "elif":
                # Add the elif in to the results and convert it to an elif 1.
                blocks[j].tokens = CppStringTokenizer("1").tokens
                result += blocks[j:j+1]
            result += optimize_if01(blocks[j+1:k])
            if start_dir == "elif":
                # Add the endif in to the results.
                result += blocks[k:k+1]
            i = k + 1
        elif dir_ == "else":
            # convert 'else' into 'if 0'
            logging.debug("convert 'if 1' .. 'else' (lines %d to %d)",
                          blocks[j].lineno, blocks[k].lineno)
            if start_dir == "elif":
                # Add the elif in to the results and convert it to an elif 1.
                blocks[j].tokens = CppStringTokenizer("1").tokens
                result += blocks[j:j+1]
            result += optimize_if01(blocks[j+1:k])
            if start_dir == "elif":
                blocks[k].directive = "elif"
            else:
                blocks[k].directive = "if"
            blocks[k].expr = CppExpr(CppStringTokenizer("0").tokens)
            i = k
        elif dir_ == "elif":
            # convert 'elif' into 'if 0'
            logging.debug("convert 'if 1' .. 'elif' (lines %d to %d)",
                          blocks[j].lineno, blocks[k].lineno)
            result += optimize_if01(blocks[j+1:k])
            blocks[k].expr = CppExpr(CppStringTokenizer("0").tokens)
            i = k
    return result

class OptimizerTests(unittest.TestCase):
    def parse(self, text, macros=None):
        out = utils.StringOutput()
        blocks = BlockParser().parse(CppStringTokenizer(text))
        blocks.optimizeAll(macros)
        blocks.write(out)
        return out.get()

    def test_if1(self):
        text = """\
#if 1
#define  GOOD
#endif
"""
        expected = """\
#define GOOD
"""
        self.assertEqual(self.parse(text), expected)

    def test_if0(self):
        text = """\
#if 0
#define  SHOULD_SKIP1
#define  SHOULD_SKIP2
#endif
"""
        expected = ""
        self.assertEqual(self.parse(text), expected)

    def test_if1_else(self):
        text = """\
#if 1
#define  GOOD
#else
#define  BAD
#endif
"""
        expected = """\
#define GOOD
"""
        self.assertEqual(self.parse(text), expected)

    def test_if0_else(self):
        text = """\
#if 0
#define  BAD
#else
#define  GOOD
#endif
"""
        expected = """\
#define GOOD
"""
        self.assertEqual(self.parse(text), expected)

    def test_if_elif1(self):
        text = """\
#if defined(something)
#define EXISTS
#elif 1
#define GOOD
#endif
"""
        expected = """\
#ifdef something
#define EXISTS
#elif 1
#define GOOD
#endif
"""
        self.assertEqual(self.parse(text), expected)

    def test_if_elif1_macro(self):
        text = """\
#if defined(something)
#define EXISTS
#elif defined(WILL_BE_ONE)
#define GOOD
#endif
"""
        expected = """\
#ifdef something
#define EXISTS
#elif 1
#define GOOD
#endif
"""
        self.assertEqual(self.parse(text, {"WILL_BE_ONE": "1"}), expected)


    def test_if_elif1_else(self):
        text = """\
#if defined(something)
#define EXISTS
#elif 1
#define GOOD
#else
#define BAD
#endif
"""
        expected = """\
#ifdef something
#define EXISTS
#elif 1
#define GOOD
#endif
"""
        self.assertEqual(self.parse(text), expected)

    def test_if_elif1_else_macro(self):
        text = """\
#if defined(something)
#define EXISTS
#elif defined(WILL_BE_ONE)
#define GOOD
#else
#define BAD
#endif
"""
        expected = """\
#ifdef something
#define EXISTS
#elif 1
#define GOOD
#endif
"""
        self.assertEqual(self.parse(text, {"WILL_BE_ONE": "1"}), expected)


    def test_if_elif1_else_macro(self):
        text = """\
#if defined(something)
#define EXISTS
#elif defined(WILL_BE_ONE)
#define GOOD
#else
#define BAD
#endif
"""
        expected = """\
#ifdef something
#define EXISTS
#elif 1
#define GOOD
#endif
"""
        self.assertEqual(self.parse(text, {"WILL_BE_ONE": "1"}), expected)

    def test_macro_set_to_undefined_single(self):
        text = """\
#if defined(__KERNEL__)
#define BAD_KERNEL
#endif
"""
        expected = ""
        macros = {"__KERNEL__": kCppUndefinedMacro}
        self.assertEqual(self.parse(text, macros), expected)

    def test_macro_set_to_undefined_if(self):
        text = """\
#if defined(__KERNEL__) || !defined(__GLIBC__) || (__GLIBC__ < 2)
#define CHECK
#endif
"""
        expected = """\
#if !defined(__GLIBC__) || __GLIBC__ < 2
#define CHECK
#endif
"""
        macros = {"__KERNEL__": kCppUndefinedMacro}
        self.assertEqual(self.parse(text, macros), expected)

    def test_endif_comment_removed(self):
        text = """\
#ifndef SIGRTMAX
#define SIGRTMAX 123
#endif /* SIGRTMAX */
"""
        expected = """\
#ifndef SIGRTMAX
#define SIGRTMAX 123
#endif
"""
        self.assertEqual(self.parse(text), expected)

    def test_multilevel_if0(self):
        text = """\
#if 0
#if 1
#define  BAD_6
#endif
#endif
"""
        expected = ""
        self.assertEqual(self.parse(text), expected)

class RemoveStructsTests(unittest.TestCase):
    def parse(self, text, structs):
        out = utils.StringOutput()
        blocks = BlockParser().parse(CppStringTokenizer(text))
        blocks.removeStructs(structs)
        blocks.write(out)
        return out.get()

    def test_remove_struct_from_start(self):
        text = """\
struct remove {
  int val1;
  int val2;
};
struct something {
  struct timeval val1;
  struct timeval val2;
};
"""
        expected = """\
struct something {
  struct timeval val1;
  struct timeval val2;
};
"""
        self.assertEqual(self.parse(text, {"remove": None}), expected)

    def test_remove_struct_from_end(self):
        text = """\
struct something {
  struct timeval val1;
  struct timeval val2;
};
struct remove {
  int val1;
  int val2;
};
"""
        expected = """\
struct something {
  struct timeval val1;
  struct timeval val2;
};
"""
        self.assertEqual(self.parse(text, {"remove": None}), expected)

    def test_remove_minimal_struct(self):
        text = """\
struct remove {
};
"""
        expected = "";
        self.assertEqual(self.parse(text, {"remove": None}), expected)

    def test_remove_struct_with_struct_fields(self):
        text = """\
struct something {
  struct remove val1;
  struct remove val2;
};
struct remove {
  int val1;
  struct something val3;
  int val2;
};
"""
        expected = """\
struct something {
  struct remove val1;
  struct remove val2;
};
"""
        self.assertEqual(self.parse(text, {"remove": None}), expected)

    def test_remove_consecutive_structs(self):
        text = """\
struct keep1 {
  struct timeval val1;
  struct timeval val2;
};
struct remove1 {
  int val1;
  int val2;
};
struct remove2 {
  int val1;
  int val2;
  int val3;
};
struct keep2 {
  struct timeval val1;
  struct timeval val2;
};
"""
        expected = """\
struct keep1 {
  struct timeval val1;
  struct timeval val2;
};
struct keep2 {
  struct timeval val1;
  struct timeval val2;
};
"""
        self.assertEqual(self.parse(text, {"remove1": None, "remove2": None}), expected)

    def test_remove_multiple_structs(self):
        text = """\
struct keep1 {
  int val;
};
struct remove1 {
  int val1;
  int val2;
};
struct keep2 {
  int val;
};
struct remove2 {
  struct timeval val1;
  struct timeval val2;
};
struct keep3 {
  int val;
};
"""
        expected = """\
struct keep1 {
  int val;
};
struct keep2 {
  int val;
};
struct keep3 {
  int val;
};
"""
        self.assertEqual(self.parse(text, {"remove1": None, "remove2": None}), expected)

    def test_remove_struct_with_inline_structs(self):
        text = """\
struct remove {
  int val1;
  int val2;
  struct {
    int val1;
    struct {
      int val1;
    } level2;
  } level1;
};
struct something {
  struct timeval val1;
  struct timeval val2;
};
"""
        expected = """\
struct something {
  struct timeval val1;
  struct timeval val2;
};
"""
        self.assertEqual(self.parse(text, {"remove": None}), expected)

    def test_remove_struct_across_blocks(self):
        text = """\
struct remove {
  int val1;
  int val2;
#ifdef PARAMETER1
  PARAMETER1
#endif
#ifdef PARAMETER2
  PARAMETER2
#endif
};
struct something {
  struct timeval val1;
  struct timeval val2;
};
"""
        expected = """\
struct something {
  struct timeval val1;
  struct timeval val2;
};
"""
        self.assertEqual(self.parse(text, {"remove": None}), expected)

    def test_remove_struct_across_blocks_multiple_structs(self):
        text = """\
struct remove1 {
  int val1;
  int val2;
#ifdef PARAMETER1
  PARAMETER1
#endif
#ifdef PARAMETER2
  PARAMETER2
#endif
};
struct remove2 {
};
struct something {
  struct timeval val1;
  struct timeval val2;
};
"""
        expected = """\
struct something {
  struct timeval val1;
  struct timeval val2;
};
"""
        self.assertEqual(self.parse(text, {"remove1": None, "remove2": None}), expected)

    def test_remove_multiple_struct_and_add_includes(self):
        text = """\
struct remove1 {
  int val1;
  int val2;
};
struct remove2 {
  struct timeval val1;
  struct timeval val2;
};
"""
        expected = """\
#include <bits/remove1.h>
#include <bits/remove2.h>
"""
        self.assertEqual(self.parse(text, {"remove1": "bits/remove1.h", "remove2": "bits/remove2.h"}), expected)


class FullPathTest(unittest.TestCase):
    """Test of the full path parsing."""

    def parse(self, text, keep=None):
        if not keep:
            keep = set()
        out = utils.StringOutput()
        blocks = BlockParser().parse(CppStringTokenizer(text))

        blocks.removeStructs(kernel_structs_to_remove)
        blocks.removeVarsAndFuncs(keep)
        blocks.replaceTokens(kernel_token_replacements)
        blocks.optimizeAll(None)

        blocks.write(out)
        return out.get()

    def test_function_removed(self):
        text = """\
static inline __u64 function()
{
}
"""
        expected = ""
        self.assertEqual(self.parse(text), expected)

    def test_function_removed_with_struct(self):
        text = """\
static inline struct something* function()
{
}
"""
        expected = ""
        self.assertEqual(self.parse(text), expected)

    def test_function_kept(self):
        text = """\
static inline __u64 function()
{
}
"""
        expected = """\
static inline __u64 function() {
}
"""
        self.assertEqual(self.parse(text, set(["function"])), expected)

    def test_var_removed(self):
        text = "__u64 variable;"
        expected = ""
        self.assertEqual(self.parse(text), expected)

    def test_var_kept(self):
        text = "__u64 variable;"
        expected = "__u64 variable;\n"
        self.assertEqual(self.parse(text, set(["variable"])), expected)

    def test_keep_function_typedef(self):
        text = "typedef void somefunction_t(void);"
        expected = "typedef void somefunction_t(void);\n"
        self.assertEqual(self.parse(text), expected)

    def test_struct_keep_attribute(self):
        text = """\
struct something_s {
  __u32 s1;
  __u32 s2;
} __attribute__((packed));
"""
        expected = """\
struct something_s {
  __u32 s1;
  __u32 s2;
} __attribute__((packed));
"""
        self.assertEqual(self.parse(text), expected)

    def test_function_keep_attribute_structs(self):
        text = """\
static __inline__ struct some_struct1 * function(struct some_struct2 * e) {
}
"""
        expected = """\
static __inline__ struct some_struct1 * function(struct some_struct2 * e) {
}
"""
        self.assertEqual(self.parse(text, set(["function"])), expected)

    def test_struct_after_struct(self):
        text = """\
struct first {
};

struct second {
  unsigned short s1;
#define SOMETHING 8
  unsigned short s2;
};
"""
        expected = """\
struct first {
};
struct second {
  unsigned short s1;
#define SOMETHING 8
  unsigned short s2;
};
"""
        self.assertEqual(self.parse(text), expected)

    def test_other_not_removed(self):
        text = """\
typedef union {
  __u64 tu1;
  __u64 tu2;
} typedef_name;

union {
  __u64 u1;
  __u64 u2;
};

struct {
  __u64 s1;
  __u64 s2;
};

enum {
  ENUM1 = 0,
  ENUM2,
};

__extension__ typedef __signed__ long long __s64;
"""
        expected = """\
typedef union {
  __u64 tu1;
  __u64 tu2;
} typedef_name;
union {
  __u64 u1;
  __u64 u2;
};
struct {
  __u64 s1;
  __u64 s2;
};
enum {
  ENUM1 = 0,
  ENUM2,
};
__extension__ typedef __signed__ long long __s64;
"""

        self.assertEqual(self.parse(text), expected)

    def test_semicolon_after_function(self):
        text = """\
static inline __u64 function()
{
};

struct should_see {
        __u32                           field;
};
"""
        expected = """\
struct should_see {
  __u32 field;
};
"""
        self.assertEqual(self.parse(text), expected)

    def test_define_in_middle_keep(self):
        text = """\
enum {
  ENUM0 = 0x10,
  ENUM1 = 0x20,
#define SOMETHING SOMETHING_ELSE
  ENUM2 = 0x40,
};
"""
        expected = """\
enum {
  ENUM0 = 0x10,
  ENUM1 = 0x20,
#define SOMETHING SOMETHING_ELSE
  ENUM2 = 0x40,
};
"""
        self.assertEqual(self.parse(text), expected)

    def test_define_in_middle_remove(self):
        text = """\
static inline function() {
#define SOMETHING1 SOMETHING_ELSE1
  i = 0;
  {
    i = 1;
  }
#define SOMETHING2 SOMETHING_ELSE2
}
"""
        expected = """\
#define SOMETHING1 SOMETHING_ELSE1
#define SOMETHING2 SOMETHING_ELSE2
"""
        self.assertEqual(self.parse(text), expected)

    def test_define_in_middle_force_keep(self):
        text = """\
static inline function() {
#define SOMETHING1 SOMETHING_ELSE1
  i = 0;
  {
    i = 1;
  }
#define SOMETHING2 SOMETHING_ELSE2
}
"""
        expected = """\
static inline function() {
#define SOMETHING1 SOMETHING_ELSE1
  i = 0;
 {
    i = 1;
  }
#define SOMETHING2 SOMETHING_ELSE2
}
"""
        self.assertEqual(self.parse(text, set(["function"])), expected)

    def test_define_before_remove(self):
        text = """\
#define SHOULD_BE_KEPT NOTHING1
#define ANOTHER_TO_KEEP NOTHING2
static inline function() {
#define SOMETHING1 SOMETHING_ELSE1
  i = 0;
  {
    i = 1;
  }
#define SOMETHING2 SOMETHING_ELSE2
}
"""
        expected = """\
#define SHOULD_BE_KEPT NOTHING1
#define ANOTHER_TO_KEEP NOTHING2
#define SOMETHING1 SOMETHING_ELSE1
#define SOMETHING2 SOMETHING_ELSE2
"""
        self.assertEqual(self.parse(text), expected)

    def test_extern_C(self):
        text = """\
#if defined(__cplusplus)
extern "C" {
#endif

struct something {
};

#if defined(__cplusplus)
}
#endif
"""
        expected = """\
#ifdef __cplusplus
extern "C" {
#endif
struct something {
};
#ifdef __cplusplus
}
#endif
"""
        self.assertEqual(self.parse(text), expected)

    def test_macro_definition_removed(self):
        text = """\
#define MACRO_FUNCTION_NO_PARAMS static inline some_func() {}
MACRO_FUNCTION_NO_PARAMS()

#define MACRO_FUNCTION_PARAMS(a) static inline some_func() { a; }
MACRO_FUNCTION_PARAMS(a = 1)

something that should still be kept
MACRO_FUNCTION_PARAMS(b)
"""
        expected = """\
#define MACRO_FUNCTION_NO_PARAMS static inline some_func() { }
#define MACRO_FUNCTION_PARAMS(a) static inline some_func() { a; }
something that should still be kept
"""
        self.assertEqual(self.parse(text), expected)

    def test_verify_timeval_itemerval(self):
        text = """\
struct __kernel_old_timeval {
  struct something val;
};
struct __kernel_old_itimerval {
  struct __kernel_old_timeval val;
};
struct fields {
  struct __kernel_old_timeval timeval;
  struct __kernel_old_itimerval itimerval;
};
"""
        expected = """\
struct fields {
  struct timeval timeval;
  struct itimerval itimerval;
};
#include <linux/time.h>
"""
        self.assertEqual(self.parse(text), expected)

    def test_var_definition(self):
        # If we're definining the whole thing, it's probably worth keeping.
        text = """\
static const char *kString = "hello world";
static const int kInteger = 42;
"""
        expected = """\
static const char * kString = "hello world";
static const int kInteger = 42;
"""
        self.assertEqual(self.parse(text), expected)

    def test_struct_array_definition(self):
        text = """\
struct descriptor {
  int args;
  int size;
};
static const struct descriptor[] = {
  {0, 0},
  {1, 12},
  {0, 42},
};
"""
        expected = """\
struct descriptor {
  int args;
  int size;
};
static const struct descriptor[] = {
 {
    0, 0
  }
 , {
    1, 12
  }
 , {
    0, 42
  }
 ,
};
"""
        self.assertEqual(self.parse(text), expected)

    def test_array_definition(self):
        text = """\
static const char *arr[] = {
  "foo",
  "bar",
  "baz",
};

static int another_arr[5] = { 1, 2, 3, 4, 5};
"""
        expected = """\
static const char * arr[] = {
  "foo", "bar", "baz",
};
static int another_arr[5] = {
  1, 2, 3, 4, 5
};
"""
        self.assertEqual(self.parse(text), expected)

    def test_token_replacement(self):
        text = """\
#define SIGRTMIN 32
#define SIGRTMAX _NSIG
#define SIGRTMAX(a,class) some_func(a, class)
"""
        expected = """\
#define __SIGRTMIN 32
#define __SIGRTMAX _KERNEL__NSIG
#define __SIGRTMAX(a,__linux_class) some_func(a, __linux_class)
"""
        self.assertEqual(self.parse(text), expected)


if __name__ == '__main__':
    unittest.main()

"""


```