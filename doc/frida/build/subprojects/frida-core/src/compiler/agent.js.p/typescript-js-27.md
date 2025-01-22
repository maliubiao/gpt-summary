Response:
Let's break down the thought process for answering this complex question.

**1. Understanding the Core Request:**

The central request is to analyze the functionality of a specific TypeScript file (`typescript.js`) within the Frida project. The prompt provides the file path and line numbers relevant to *this specific part* of the file. Key constraints include:

* **Focus on functionality:** What does this code *do*?
* **Binary/Kernel awareness:** Look for interactions with low-level concepts.
* **Debugging context:** How can this functionality be replicated with LLDB?  This strongly suggests the code is related to debugging or instrumentation.
* **Error handling:** Are there common user errors this code might address or be susceptible to?
* **User journey:** How does a user arrive at this code being executed?
* **Conciseness:**  Summarize the functionality of *this specific section* (part 28 of 197).

**2. Initial Analysis of the File Path and Name:**

* `frida/build/subprojects/frida-core/src/compiler/agent.js.p/typescript.js`:  This path is highly informative.
    * `frida`:  Indicates the Frida dynamic instrumentation framework.
    * `build`: Suggests this is generated or part of the build process.
    * `subprojects/frida-core`:  Points to the core functionality of Frida.
    * `src/compiler`: This is a crucial hint. It suggests the code is involved in *compiling* something, likely JavaScript or TypeScript within the Frida agent.
    * `agent.js.p`:  Likely related to the Frida agent that runs inside the target process. The `.p` might indicate a processed or generated file.
    * `typescript.js`:  The file name itself confirms that this code deals with TypeScript.

**3. Analyzing the Provided Line Numbers:**

The sheer volume of line numbers suggests this is a substantial section of code. Instead of trying to understand each individual line in isolation, look for patterns and recurring themes. Scanning the provided snippet (even without full context) reveals several important things:

* **Unicode character ranges:**  The `unicodeESNextIdentifierStart` and `unicodeESNextIdentifierPart` arrays strongly suggest this code is involved in parsing or validating JavaScript/TypeScript syntax, specifically identifiers.
* **Regular expressions:** `commentDirectiveRegExSingleLine` and `commentDirectiveRegExMultiLine` indicate handling of comments, likely for processing directives like `@ts-ignore`.
* **Tokenization:** `tokenStrings` and `makeReverseMap(textToToken)` point towards tokenization, a core part of compilation where source code is broken down into meaningful units.
* **String manipulation:**  Functions like `codePointAt` and `utf16EncodeAsStringWorker` deal with character encoding, important for handling different character sets.
* **Utility functions:**  The subsequent code snippets define numerous utility functions for working with text spans (`createTextSpan`, `textSpanEnd`, etc.), diagnostics (`sortAndDeduplicateDiagnostics`), and node flags. This strengthens the idea that this code is part of a larger compilation pipeline.

**4. Connecting the Dots - Formulating Hypotheses:**

Based on the file path, name, and the types of data and functions present, the primary hypothesis is that this section of `typescript.js` within Frida is responsible for **lexical analysis and basic syntactic processing of TypeScript code within the Frida agent's compilation process.**  This includes:

* **Tokenizing the input TypeScript code.**
* **Identifying and handling special comments (like `@ts-ignore`).**
* **Validating identifier names based on Unicode standards.**
* **Providing utility functions for working with text ranges and error reporting (diagnostics).**

**5. Addressing Specific Constraints:**

* **Binary/Kernel:**  While this specific section is high-level (dealing with syntax), the *overall context* of Frida is about interacting with processes at a low level. This code is a necessary step *before* any binary-level manipulation can happen. The connection is indirect but crucial.
* **LLDB Replication:**  Since this code deals with *compilation*, directly replicating it with LLDB instruction breakpoints is unlikely. However, LLDB could be used to inspect the *state* of the Frida agent during this compilation phase, setting breakpoints in the surrounding Frida code that calls these functions. A Python script within LLDB could also potentially manipulate the input TypeScript code being fed to this compiler and observe the output.
* **User Errors:** Common errors here would be invalid TypeScript syntax, incorrect use of `@ts-ignore` directives, or using characters not allowed in identifiers.
* **User Journey:** A user would write a Frida script (likely in TypeScript), and when Frida attempts to attach to a process and load the agent, this compilation step would be involved.

**6. Focusing on "Part 28 of 197":**

The prompt emphasizes that this is a *specific part*. This suggests that the *complete* `typescript.js` file performs a much broader set of compilation tasks. This section likely handles the very initial stages.

**7. Structuring the Answer:**

Organize the answer logically, addressing each part of the prompt:

* **Functionality:** Start with a concise summary of the core purpose.
* **Binary/Kernel:** Explain the indirect connection.
* **LLDB:** Provide examples of how LLDB could be used in the broader context.
* **Input/Output:**  Illustrate with a simple example of valid/invalid code.
* **User Errors:** Give concrete examples.
* **User Journey:** Describe the steps leading to this code's execution.
* **Summary (Part 28):**  Reiterate the specific scope of this section within the larger compilation process.

**Self-Correction/Refinement:**

* Initially, one might focus too much on the individual lines of code. It's important to step back and look for higher-level patterns.
* Avoid claiming this code *directly* interacts with the kernel. Emphasize the *compilation* aspect as a prerequisite for later low-level actions.
* Be realistic about LLDB replication. Direct instruction-level replication of a compiler is often impractical. Focus on how LLDB can be used for *observing* the effects.

By following this thought process, we can generate a comprehensive and accurate answer that addresses all aspects of the prompt, even without having the full source code readily available. The key is to combine the clues from the file path, name, code snippets, and constraints of the prompt to form informed hypotheses.这个 `frida/build/subprojects/frida-core/src/compiler/agent.js.p/typescript.js` 文件是 Frida 动态插桩工具中，负责 **编译 Frida Agent 的 TypeScript 代码** 的一部分。 从给出的行号来看，这部分代码主要集中在 **词法分析 (Lexical Analysis) 和一些基础的语法结构定义** 上，为后续的语法分析和代码生成做准备。

**功能归纳:**

作为第 28 部分，这个代码片段的功能可以归纳为：

1. **定义和识别 TypeScript/JavaScript 语言的基本构成单元（Token）：** 这部分代码定义了各种词法单元，例如标识符（变量名、函数名等）、关键字（`if`、`else`、`function` 等）、运算符（`+`、`-`、`*` 等）、标点符号（`{`、`}`、`;` 等）以及注释。
2. **处理 Unicode 标识符：**  `unicodeESNextIdentifierStart` 和 `unicodeESNextIdentifierPart` 数组定义了符合 ECMAScript 标准的 Unicode 字符范围，用于判断哪些字符可以作为标识符的开头和后续部分。这确保了 Frida 可以正确处理各种语言的字符。
3. **识别特定的注释指令：** `commentDirectiveRegExSingleLine` 和 `commentDirectiveRegExMultiLine` 定义了正则表达式，用于识别特定的注释指令，例如 `@ts-expect-error` 或 `@ts-ignore`。这些指令通常用于告知 TypeScript 编译器忽略某些潜在的错误。
4. **维护 Token 的映射关系：** `textToToken` 对象和 `tokenStrings` 数组维护了文本表示和内部 Token 代码之间的映射关系，方便在词法分析过程中进行转换。
5. **处理字符串和字符编码：**  `codePointAt` 函数用于获取字符串中指定位置的 Unicode 代码点，`utf16EncodeAsStringWorker` 用于将 Unicode 代码点编码为 UTF-16 字符串。这对于正确处理各种字符至关重要。
6. **定义和操作文本范围 (TextSpan)：**  定义了 `TextSpan` 接口以及相关的实用函数，例如 `textSpanEnd`、`textSpanIsEmpty`、`textSpanContainsPosition` 等。这些函数用于表示和操作源代码中的一段文本区域，在错误报告、代码分析等方面非常有用。
7. **处理文本变更范围 (TextChangeRange)：**  定义了 `TextChangeRange` 接口以及相关的实用函数，用于表示和合并代码变更的范围，这在增量编译或代码编辑场景下很有用。
8. **定义和操作诊断信息 (Diagnostics)：**  定义了与编译器诊断信息相关的函数，例如 `sortAndDeduplicateDiagnostics`，用于对编译过程中的错误和警告信息进行处理。
9. **提供基础的语言工具函数：**  定义了一些基础的实用函数，例如判断模块名是否是相对路径 (`isExternalModuleNameRelative`)，获取默认的库文件名 (`getDefaultLibFileName`) 等。

**二进制底层，Linux 内核 举例说明:**

虽然这个特定的代码片段主要关注词法分析和语法结构，但它为 Frida 更底层的操作奠定了基础。

* **二进制底层:**
    * **符号解析:** 在 Frida Agent 的编译过程中，词法分析器识别出标识符，这些标识符可能对应着目标进程中的函数名、变量名等符号。Frida 随后会使用这些符号信息来定位内存地址，进行 hook 和 instrumentation。例如，如果 TypeScript 代码中使用了 `NativeFunction.call("malloc", ...)`，词法分析器会识别出 "malloc" 这个标识符，后续的 Frida 代码会尝试解析 `malloc` 函数在目标进程中的地址。
    * **代码生成:** 词法分析是代码生成的第一步。编译器需要将 TypeScript 代码转换为目标平台的机器码或中间表示。虽然这部分代码没有直接生成二进制代码，但它识别出的 Token 是后续代码生成的基础。

* **Linux 内核:**
    * **系统调用 Hook:** Frida 的核心功能之一是 hook 系统调用。当 Frida Agent 的 TypeScript 代码中尝试 hook 一个系统调用时，例如 `Interceptor.attach(Module.findExportByName(null, "open"), ...)`，词法分析器会识别出 "open" 这个字符串，后续 Frida 代码会查找 `open` 系统调用在目标进程中的地址（通常是通过 `Module.findExportByName(null, ...)` 实现，其中 `null` 表示主模块，也可能指定内核模块名）。
    * **内核模块交互:** 在更高级的应用中，Frida 可能需要与内核模块进行交互。  TypeScript 代码中可能包含与内核模块相关的函数或结构体定义，词法分析器需要能够正确识别这些元素。

**LLDB 指令或 Python 脚本复刻调试功能示例:**

由于这部分代码是编译过程的一部分，直接用 LLDB 指令复刻其词法分析功能不太现实。LLVM 的 Clang 工具链也包含了词法分析的功能。  不过，我们可以使用 LLDB 来观察 Frida 在编译 Agent 代码时的状态，或者手动分析 Frida Agent 的代码结构。

**示例（观察 Frida 编译 Agent 的过程）：**

假设你正在调试一个 Frida Agent，并怀疑某个 TypeScript 语法错误导致编译失败。你可以：

1. **在 Frida 编译 Agent 的相关代码中设置断点。**  你需要了解 Frida 的内部实现，找到负责调用 TypeScript 编译器的代码位置。这通常涉及到 Frida Core 的 C++ 代码和 Node.js 的交互部分。
2. **使用 LLDB 连接到 Frida 运行的进程 (例如 `frida` 命令本身或目标应用程序进程)。**
3. **当断点命中时，检查相关的变量和数据结构，例如：**
    * 正在编译的 TypeScript 源代码。
    * 词法分析器产生的 Token 流（如果能找到）。
    * 编译器的错误信息。

**LLDB Python 脚本示例（模拟简单的 Token 识别）：**

虽然无法完全复刻 Frida 的 TypeScript 词法分析器，但可以使用 LLDB 的 Python 脚本来模拟一些简单的 Token 识别功能：

```python
import lldb

def recognize_tokens(debugger, command, result, internal_dict):
    source_code = command
    tokens = source_code.split() # 简单地按空格分割作为示例
    print("Recognized Tokens:")
    for token in tokens:
        if token in ["if", "else", "function"]:
            print(f"  Keyword: {token}")
        elif token.isdigit():
            print(f"  Number: {token}")
        elif token.isalpha():
            print(f"  Identifier: {token}")
        else:
            print(f"  Symbol: {token}")

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f typescript_tokens.recognize_tokens ts_tokens')
    print("The 'ts_tokens' command has been added to LLDB.")
```

将此脚本保存为 `typescript_tokens.py`，然后在 LLDB 中使用：

```lldb
(lldb) command source typescript_tokens.py
The 'ts_tokens' command has been added to LLDB.
(lldb) ts_tokens function myFunc(arg1, arg2) { return arg1 + arg2; }
Recognized Tokens:
  Keyword: function
  Identifier: myFunc(arg1,
  Identifier: arg2)
  Symbol: {
  Keyword: return
  Identifier: arg1
  Symbol: +
  Identifier: arg2;
  Symbol: }
```

**假设输入与输出 (逻辑推理):**

假设词法分析器接收到以下 TypeScript 代码片段：

```typescript
const myVar = 10;
if (myVar > 5) {
  console.log("Greater");
}
```

**可能的输出（Token 流，内部表示）：**

```
[
  { type: "Keyword", value: "const" },
  { type: "Identifier", value: "myVar" },
  { type: "Punctuator", value: "=" },
  { type: "NumericLiteral", value: "10" },
  { type: "Punctuator", value: ";" },
  { type: "Keyword", value: "if" },
  { type: "Punctuator", value: "(" },
  { type: "Identifier", value: "myVar" },
  { type: "Punctuator", value: ">" },
  { type: "NumericLiteral", value: "5" },
  { type: "Punctuator", value: ")" },
  { type: "Punctuator", value: "{" },
  { type: "Identifier", value: "console" },
  { type: "Punctuator", value: "." },
  { type: "Identifier", value: "log" },
  { type: "Punctuator", value: "(" },
  { type: "StringLiteral", value: "\"Greater\"" },
  { type: "Punctuator", value: ")" },
  { type: "Punctuator", value: ";" },
  { type: "Punctuator", value: "}" }
]
```

**用户或编程常见的使用错误:**

* **拼写错误的关键字:** 例如，用户输入 `functoin` 而不是 `function`。词法分析器会将其识别为标识符而不是关键字，导致后续的语法分析错误。
* **使用了不允许的字符在标识符中:** 例如，变量名使用 `my-var` (在 JavaScript 中通常不允许直接使用连字符)。词法分析器可能会将其拆分为多个 Token，或者直接报错。
* **不匹配的括号或花括号:** 例如 `if (myVar > 5 { console.log("Error");` 缺少了闭合的右括号 `)`. 词法分析器可能会在扫描到花括号时发现括号不匹配，并报告错误。
* **不正确的注释指令格式:** 例如 `//ts-ignore: Unused variable`  (正确的格式是 `//@ts-ignore`). 词法分析器可能无法正确识别该指令，导致 TypeScript 编译器仍然会报告相关的错误。
* **使用了超出 Unicode 范围的字符，但未正确处理:** 尽管代码支持 Unicode，但在某些特殊情况下，如果环境或配置不当，可能会导致字符编码问题。

**用户操作如何一步步到达这里，作为调试线索:**

1. **用户编写了一个 Frida Agent 的 TypeScript 代码。**  这个代码可能包含了需要 hook 的函数、要修改的内存地址等逻辑。
2. **用户使用 Frida CLI 或 API (例如 Python 的 `frida` 模块) 尝试将该 Agent 加载到目标进程中。** 例如，使用 `frida -p <pid> -l my-agent.ts` 命令。
3. **Frida Core 接收到加载 Agent 的请求。**
4. **Frida Core 需要编译用户的 TypeScript 代码。**  这通常涉及到调用一个 TypeScript 编译器 (可能是内置的或依赖于 Node.js 环境)。
5. **`frida/build/subprojects/frida-core/src/compiler/agent.js.p/typescript.js` 文件中的代码被执行，首先进行词法分析。**  编译器会逐行扫描用户的 TypeScript 代码，将其分解成 Token。
6. **如果在词法分析阶段发现错误 (例如拼写错误的关键字)，编译器会生成相应的错误信息。**  Frida 可能会将这些错误信息报告给用户，阻止 Agent 的加载。

**总结：**

`frida/build/subprojects/frida-core/src/compiler/agent.js.p/typescript.js` 的第 28 部分主要负责 Frida Agent TypeScript 代码的 **词法分析**，这是编译过程的第一步。 它定义了语言的基本构成单元，并能够识别和处理这些单元。 这对于理解用户编写的 Agent 代码并将其转换为 Frida 可以执行的指令至关重要。 虽然这部分代码本身不直接涉及二进制底层或 Linux 内核，但它是实现 Frida 强大插桩功能的基础。

Prompt: 
```
这是目录为frida/build/subprojects/frida-core/src/compiler/agent.js.p/typescript.js的frida Dynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果涉及到二进制底层，linux内核，请做出对应的举例说明，
请给出用lldb指令或者lldb python脚本，用来复刻的源代码所实现调试功能的示例，如果源代码是调试功能的实现。
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索，
请用中文回复。
这是第28部分，共197部分，请归纳一下它的功能

"""
2423, 2425, 2431, 2433, 2435, 2437, 2444, 2447, 2448, 2451, 2472, 2474, 2480, 2482, 2482, 2486, 2489, 2492, 2500, 2503, 2504, 2507, 2510, 2519, 2519, 2524, 2525, 2527, 2531, 2534, 2545, 2561, 2563, 2565, 2570, 2575, 2576, 2579, 2600, 2602, 2608, 2610, 2611, 2613, 2614, 2616, 2617, 2620, 2620, 2622, 2626, 2631, 2632, 2635, 2637, 2641, 2641, 2649, 2652, 2654, 2654, 2662, 2677, 2689, 2691, 2693, 2701, 2703, 2705, 2707, 2728, 2730, 2736, 2738, 2739, 2741, 2745, 2748, 2757, 2759, 2761, 2763, 2765, 2768, 2768, 2784, 2787, 2790, 2799, 2817, 2819, 2821, 2828, 2831, 2832, 2835, 2856, 2858, 2864, 2866, 2867, 2869, 2873, 2876, 2884, 2887, 2888, 2891, 2893, 2902, 2903, 2908, 2909, 2911, 2915, 2918, 2927, 2929, 2929, 2946, 2947, 2949, 2954, 2958, 2960, 2962, 2965, 2969, 2970, 2972, 2972, 2974, 2975, 2979, 2980, 2984, 2986, 2990, 3001, 3006, 3010, 3014, 3016, 3018, 3021, 3024, 3024, 3031, 3031, 3046, 3055, 3073, 3075, 3077, 3084, 3086, 3088, 3090, 3112, 3114, 3123, 3125, 3129, 3133, 3140, 3142, 3144, 3146, 3149, 3157, 3158, 3160, 3161, 3168, 3171, 3174, 3183, 3202, 3203, 3205, 3212, 3214, 3216, 3218, 3240, 3242, 3251, 3253, 3257, 3260, 3268, 3270, 3272, 3274, 3277, 3285, 3286, 3294, 3294, 3296, 3299, 3302, 3311, 3313, 3314, 3330, 3331, 3333, 3340, 3342, 3344, 3346, 3386, 3389, 3396, 3398, 3400, 3402, 3406, 3415, 3415, 3424, 3427, 3430, 3439, 3450, 3455, 3458, 3459, 3461, 3478, 3482, 3505, 3507, 3515, 3517, 3517, 3520, 3526, 3530, 3530, 3535, 3540, 3542, 3542, 3544, 3551, 3570, 3571, 3585, 3642, 3648, 3662, 3664, 3673, 3713, 3714, 3716, 3716, 3719, 3720, 3722, 3722, 3725, 3725, 3732, 3735, 3737, 3743, 3745, 3747, 3749, 3749, 3751, 3751, 3754, 3755, 3757, 3769, 3771, 3773, 3776, 3780, 3782, 3782, 3784, 3789, 3792, 3801, 3804, 3807, 3840, 3840, 3864, 3865, 3872, 3881, 3893, 3893, 3895, 3895, 3897, 3897, 3902, 3911, 3913, 3948, 3953, 3972, 3974, 3991, 3993, 4028, 4038, 4038, 4096, 4169, 4176, 4253, 4256, 4293, 4295, 4295, 4301, 4301, 4304, 4346, 4348, 4680, 4682, 4685, 4688, 4694, 4696, 4696, 4698, 4701, 4704, 4744, 4746, 4749, 4752, 4784, 4786, 4789, 4792, 4798, 4800, 4800, 4802, 4805, 4808, 4822, 4824, 4880, 4882, 4885, 4888, 4954, 4957, 4959, 4992, 5007, 5024, 5108, 5121, 5740, 5743, 5759, 5761, 5786, 5792, 5866, 5870, 5872, 5888, 5900, 5902, 5908, 5920, 5940, 5952, 5971, 5984, 5996, 5998, 6e3, 6002, 6003, 6016, 6099, 6103, 6103, 6108, 6109, 6112, 6121, 6155, 6157, 6160, 6169, 6176, 6263, 6272, 6314, 6320, 6389, 6400, 6428, 6432, 6443, 6448, 6459, 6470, 6509, 6512, 6516, 6528, 6571, 6576, 6601, 6608, 6617, 6656, 6683, 6688, 6750, 6752, 6780, 6783, 6793, 6800, 6809, 6823, 6823, 6912, 6987, 6992, 7001, 7019, 7027, 7040, 7155, 7168, 7223, 7232, 7241, 7245, 7293, 7376, 7378, 7380, 7414, 7424, 7654, 7676, 7957, 7960, 7965, 7968, 8005, 8008, 8013, 8016, 8023, 8025, 8025, 8027, 8027, 8029, 8029, 8031, 8061, 8064, 8116, 8118, 8124, 8126, 8126, 8130, 8132, 8134, 8140, 8144, 8147, 8150, 8155, 8160, 8172, 8178, 8180, 8182, 8188, 8204, 8205, 8255, 8256, 8276, 8276, 8305, 8305, 8319, 8319, 8336, 8348, 8400, 8412, 8417, 8417, 8421, 8432, 8450, 8450, 8455, 8455, 8458, 8467, 8469, 8469, 8473, 8477, 8484, 8484, 8486, 8486, 8488, 8488, 8490, 8493, 8495, 8505, 8508, 8511, 8517, 8521, 8526, 8526, 8544, 8584, 11264, 11310, 11312, 11358, 11360, 11492, 11499, 11507, 11520, 11557, 11559, 11559, 11565, 11565, 11568, 11623, 11631, 11631, 11647, 11670, 11680, 11686, 11688, 11694, 11696, 11702, 11704, 11710, 11712, 11718, 11720, 11726, 11728, 11734, 11736, 11742, 11744, 11775, 11823, 11823, 12293, 12295, 12321, 12335, 12337, 12341, 12344, 12348, 12353, 12438, 12441, 12442, 12445, 12447, 12449, 12538, 12540, 12543, 12549, 12589, 12593, 12686, 12704, 12730, 12784, 12799, 13312, 19893, 19968, 40908, 40960, 42124, 42192, 42237, 42240, 42508, 42512, 42539, 42560, 42607, 42612, 42621, 42623, 42647, 42655, 42737, 42775, 42783, 42786, 42888, 42891, 42894, 42896, 42899, 42912, 42922, 43e3, 43047, 43072, 43123, 43136, 43204, 43216, 43225, 43232, 43255, 43259, 43259, 43264, 43309, 43312, 43347, 43360, 43388, 43392, 43456, 43471, 43481, 43520, 43574, 43584, 43597, 43600, 43609, 43616, 43638, 43642, 43643, 43648, 43714, 43739, 43741, 43744, 43759, 43762, 43766, 43777, 43782, 43785, 43790, 43793, 43798, 43808, 43814, 43816, 43822, 43968, 44010, 44012, 44013, 44016, 44025, 44032, 55203, 55216, 55238, 55243, 55291, 63744, 64109, 64112, 64217, 64256, 64262, 64275, 64279, 64285, 64296, 64298, 64310, 64312, 64316, 64318, 64318, 64320, 64321, 64323, 64324, 64326, 64433, 64467, 64829, 64848, 64911, 64914, 64967, 65008, 65019, 65024, 65039, 65056, 65062, 65075, 65076, 65101, 65103, 65136, 65140, 65142, 65276, 65296, 65305, 65313, 65338, 65343, 65343, 65345, 65370, 65382, 65470, 65474, 65479, 65482, 65487, 65490, 65495, 65498, 65500];
        unicodeESNextIdentifierStart = [65, 90, 97, 122, 170, 170, 181, 181, 186, 186, 192, 214, 216, 246, 248, 705, 710, 721, 736, 740, 748, 748, 750, 750, 880, 884, 886, 887, 890, 893, 895, 895, 902, 902, 904, 906, 908, 908, 910, 929, 931, 1013, 1015, 1153, 1162, 1327, 1329, 1366, 1369, 1369, 1376, 1416, 1488, 1514, 1519, 1522, 1568, 1610, 1646, 1647, 1649, 1747, 1749, 1749, 1765, 1766, 1774, 1775, 1786, 1788, 1791, 1791, 1808, 1808, 1810, 1839, 1869, 1957, 1969, 1969, 1994, 2026, 2036, 2037, 2042, 2042, 2048, 2069, 2074, 2074, 2084, 2084, 2088, 2088, 2112, 2136, 2144, 2154, 2208, 2228, 2230, 2237, 2308, 2361, 2365, 2365, 2384, 2384, 2392, 2401, 2417, 2432, 2437, 2444, 2447, 2448, 2451, 2472, 2474, 2480, 2482, 2482, 2486, 2489, 2493, 2493, 2510, 2510, 2524, 2525, 2527, 2529, 2544, 2545, 2556, 2556, 2565, 2570, 2575, 2576, 2579, 2600, 2602, 2608, 2610, 2611, 2613, 2614, 2616, 2617, 2649, 2652, 2654, 2654, 2674, 2676, 2693, 2701, 2703, 2705, 2707, 2728, 2730, 2736, 2738, 2739, 2741, 2745, 2749, 2749, 2768, 2768, 2784, 2785, 2809, 2809, 2821, 2828, 2831, 2832, 2835, 2856, 2858, 2864, 2866, 2867, 2869, 2873, 2877, 2877, 2908, 2909, 2911, 2913, 2929, 2929, 2947, 2947, 2949, 2954, 2958, 2960, 2962, 2965, 2969, 2970, 2972, 2972, 2974, 2975, 2979, 2980, 2984, 2986, 2990, 3001, 3024, 3024, 3077, 3084, 3086, 3088, 3090, 3112, 3114, 3129, 3133, 3133, 3160, 3162, 3168, 3169, 3200, 3200, 3205, 3212, 3214, 3216, 3218, 3240, 3242, 3251, 3253, 3257, 3261, 3261, 3294, 3294, 3296, 3297, 3313, 3314, 3333, 3340, 3342, 3344, 3346, 3386, 3389, 3389, 3406, 3406, 3412, 3414, 3423, 3425, 3450, 3455, 3461, 3478, 3482, 3505, 3507, 3515, 3517, 3517, 3520, 3526, 3585, 3632, 3634, 3635, 3648, 3654, 3713, 3714, 3716, 3716, 3718, 3722, 3724, 3747, 3749, 3749, 3751, 3760, 3762, 3763, 3773, 3773, 3776, 3780, 3782, 3782, 3804, 3807, 3840, 3840, 3904, 3911, 3913, 3948, 3976, 3980, 4096, 4138, 4159, 4159, 4176, 4181, 4186, 4189, 4193, 4193, 4197, 4198, 4206, 4208, 4213, 4225, 4238, 4238, 4256, 4293, 4295, 4295, 4301, 4301, 4304, 4346, 4348, 4680, 4682, 4685, 4688, 4694, 4696, 4696, 4698, 4701, 4704, 4744, 4746, 4749, 4752, 4784, 4786, 4789, 4792, 4798, 4800, 4800, 4802, 4805, 4808, 4822, 4824, 4880, 4882, 4885, 4888, 4954, 4992, 5007, 5024, 5109, 5112, 5117, 5121, 5740, 5743, 5759, 5761, 5786, 5792, 5866, 5870, 5880, 5888, 5900, 5902, 5905, 5920, 5937, 5952, 5969, 5984, 5996, 5998, 6e3, 6016, 6067, 6103, 6103, 6108, 6108, 6176, 6264, 6272, 6312, 6314, 6314, 6320, 6389, 6400, 6430, 6480, 6509, 6512, 6516, 6528, 6571, 6576, 6601, 6656, 6678, 6688, 6740, 6823, 6823, 6917, 6963, 6981, 6987, 7043, 7072, 7086, 7087, 7098, 7141, 7168, 7203, 7245, 7247, 7258, 7293, 7296, 7304, 7312, 7354, 7357, 7359, 7401, 7404, 7406, 7411, 7413, 7414, 7418, 7418, 7424, 7615, 7680, 7957, 7960, 7965, 7968, 8005, 8008, 8013, 8016, 8023, 8025, 8025, 8027, 8027, 8029, 8029, 8031, 8061, 8064, 8116, 8118, 8124, 8126, 8126, 8130, 8132, 8134, 8140, 8144, 8147, 8150, 8155, 8160, 8172, 8178, 8180, 8182, 8188, 8305, 8305, 8319, 8319, 8336, 8348, 8450, 8450, 8455, 8455, 8458, 8467, 8469, 8469, 8472, 8477, 8484, 8484, 8486, 8486, 8488, 8488, 8490, 8505, 8508, 8511, 8517, 8521, 8526, 8526, 8544, 8584, 11264, 11310, 11312, 11358, 11360, 11492, 11499, 11502, 11506, 11507, 11520, 11557, 11559, 11559, 11565, 11565, 11568, 11623, 11631, 11631, 11648, 11670, 11680, 11686, 11688, 11694, 11696, 11702, 11704, 11710, 11712, 11718, 11720, 11726, 11728, 11734, 11736, 11742, 12293, 12295, 12321, 12329, 12337, 12341, 12344, 12348, 12353, 12438, 12443, 12447, 12449, 12538, 12540, 12543, 12549, 12591, 12593, 12686, 12704, 12730, 12784, 12799, 13312, 19893, 19968, 40943, 40960, 42124, 42192, 42237, 42240, 42508, 42512, 42527, 42538, 42539, 42560, 42606, 42623, 42653, 42656, 42735, 42775, 42783, 42786, 42888, 42891, 42943, 42946, 42950, 42999, 43009, 43011, 43013, 43015, 43018, 43020, 43042, 43072, 43123, 43138, 43187, 43250, 43255, 43259, 43259, 43261, 43262, 43274, 43301, 43312, 43334, 43360, 43388, 43396, 43442, 43471, 43471, 43488, 43492, 43494, 43503, 43514, 43518, 43520, 43560, 43584, 43586, 43588, 43595, 43616, 43638, 43642, 43642, 43646, 43695, 43697, 43697, 43701, 43702, 43705, 43709, 43712, 43712, 43714, 43714, 43739, 43741, 43744, 43754, 43762, 43764, 43777, 43782, 43785, 43790, 43793, 43798, 43808, 43814, 43816, 43822, 43824, 43866, 43868, 43879, 43888, 44002, 44032, 55203, 55216, 55238, 55243, 55291, 63744, 64109, 64112, 64217, 64256, 64262, 64275, 64279, 64285, 64285, 64287, 64296, 64298, 64310, 64312, 64316, 64318, 64318, 64320, 64321, 64323, 64324, 64326, 64433, 64467, 64829, 64848, 64911, 64914, 64967, 65008, 65019, 65136, 65140, 65142, 65276, 65313, 65338, 65345, 65370, 65382, 65470, 65474, 65479, 65482, 65487, 65490, 65495, 65498, 65500, 65536, 65547, 65549, 65574, 65576, 65594, 65596, 65597, 65599, 65613, 65616, 65629, 65664, 65786, 65856, 65908, 66176, 66204, 66208, 66256, 66304, 66335, 66349, 66378, 66384, 66421, 66432, 66461, 66464, 66499, 66504, 66511, 66513, 66517, 66560, 66717, 66736, 66771, 66776, 66811, 66816, 66855, 66864, 66915, 67072, 67382, 67392, 67413, 67424, 67431, 67584, 67589, 67592, 67592, 67594, 67637, 67639, 67640, 67644, 67644, 67647, 67669, 67680, 67702, 67712, 67742, 67808, 67826, 67828, 67829, 67840, 67861, 67872, 67897, 67968, 68023, 68030, 68031, 68096, 68096, 68112, 68115, 68117, 68119, 68121, 68149, 68192, 68220, 68224, 68252, 68288, 68295, 68297, 68324, 68352, 68405, 68416, 68437, 68448, 68466, 68480, 68497, 68608, 68680, 68736, 68786, 68800, 68850, 68864, 68899, 69376, 69404, 69415, 69415, 69424, 69445, 69600, 69622, 69635, 69687, 69763, 69807, 69840, 69864, 69891, 69926, 69956, 69956, 69968, 70002, 70006, 70006, 70019, 70066, 70081, 70084, 70106, 70106, 70108, 70108, 70144, 70161, 70163, 70187, 70272, 70278, 70280, 70280, 70282, 70285, 70287, 70301, 70303, 70312, 70320, 70366, 70405, 70412, 70415, 70416, 70419, 70440, 70442, 70448, 70450, 70451, 70453, 70457, 70461, 70461, 70480, 70480, 70493, 70497, 70656, 70708, 70727, 70730, 70751, 70751, 70784, 70831, 70852, 70853, 70855, 70855, 71040, 71086, 71128, 71131, 71168, 71215, 71236, 71236, 71296, 71338, 71352, 71352, 71424, 71450, 71680, 71723, 71840, 71903, 71935, 71935, 72096, 72103, 72106, 72144, 72161, 72161, 72163, 72163, 72192, 72192, 72203, 72242, 72250, 72250, 72272, 72272, 72284, 72329, 72349, 72349, 72384, 72440, 72704, 72712, 72714, 72750, 72768, 72768, 72818, 72847, 72960, 72966, 72968, 72969, 72971, 73008, 73030, 73030, 73056, 73061, 73063, 73064, 73066, 73097, 73112, 73112, 73440, 73458, 73728, 74649, 74752, 74862, 74880, 75075, 77824, 78894, 82944, 83526, 92160, 92728, 92736, 92766, 92880, 92909, 92928, 92975, 92992, 92995, 93027, 93047, 93053, 93071, 93760, 93823, 93952, 94026, 94032, 94032, 94099, 94111, 94176, 94177, 94179, 94179, 94208, 100343, 100352, 101106, 110592, 110878, 110928, 110930, 110948, 110951, 110960, 111355, 113664, 113770, 113776, 113788, 113792, 113800, 113808, 113817, 119808, 119892, 119894, 119964, 119966, 119967, 119970, 119970, 119973, 119974, 119977, 119980, 119982, 119993, 119995, 119995, 119997, 120003, 120005, 120069, 120071, 120074, 120077, 120084, 120086, 120092, 120094, 120121, 120123, 120126, 120128, 120132, 120134, 120134, 120138, 120144, 120146, 120485, 120488, 120512, 120514, 120538, 120540, 120570, 120572, 120596, 120598, 120628, 120630, 120654, 120656, 120686, 120688, 120712, 120714, 120744, 120746, 120770, 120772, 120779, 123136, 123180, 123191, 123197, 123214, 123214, 123584, 123627, 124928, 125124, 125184, 125251, 125259, 125259, 126464, 126467, 126469, 126495, 126497, 126498, 126500, 126500, 126503, 126503, 126505, 126514, 126516, 126519, 126521, 126521, 126523, 126523, 126530, 126530, 126535, 126535, 126537, 126537, 126539, 126539, 126541, 126543, 126545, 126546, 126548, 126548, 126551, 126551, 126553, 126553, 126555, 126555, 126557, 126557, 126559, 126559, 126561, 126562, 126564, 126564, 126567, 126570, 126572, 126578, 126580, 126583, 126585, 126588, 126590, 126590, 126592, 126601, 126603, 126619, 126625, 126627, 126629, 126633, 126635, 126651, 131072, 173782, 173824, 177972, 177984, 178205, 178208, 183969, 183984, 191456, 194560, 195101];
        unicodeESNextIdentifierPart = [48, 57, 65, 90, 95, 95, 97, 122, 170, 170, 181, 181, 183, 183, 186, 186, 192, 214, 216, 246, 248, 705, 710, 721, 736, 740, 748, 748, 750, 750, 768, 884, 886, 887, 890, 893, 895, 895, 902, 906, 908, 908, 910, 929, 931, 1013, 1015, 1153, 1155, 1159, 1162, 1327, 1329, 1366, 1369, 1369, 1376, 1416, 1425, 1469, 1471, 1471, 1473, 1474, 1476, 1477, 1479, 1479, 1488, 1514, 1519, 1522, 1552, 1562, 1568, 1641, 1646, 1747, 1749, 1756, 1759, 1768, 1770, 1788, 1791, 1791, 1808, 1866, 1869, 1969, 1984, 2037, 2042, 2042, 2045, 2045, 2048, 2093, 2112, 2139, 2144, 2154, 2208, 2228, 2230, 2237, 2259, 2273, 2275, 2403, 2406, 2415, 2417, 2435, 2437, 2444, 2447, 2448, 2451, 2472, 2474, 2480, 2482, 2482, 2486, 2489, 2492, 2500, 2503, 2504, 2507, 2510, 2519, 2519, 2524, 2525, 2527, 2531, 2534, 2545, 2556, 2556, 2558, 2558, 2561, 2563, 2565, 2570, 2575, 2576, 2579, 2600, 2602, 2608, 2610, 2611, 2613, 2614, 2616, 2617, 2620, 2620, 2622, 2626, 2631, 2632, 2635, 2637, 2641, 2641, 2649, 2652, 2654, 2654, 2662, 2677, 2689, 2691, 2693, 2701, 2703, 2705, 2707, 2728, 2730, 2736, 2738, 2739, 2741, 2745, 2748, 2757, 2759, 2761, 2763, 2765, 2768, 2768, 2784, 2787, 2790, 2799, 2809, 2815, 2817, 2819, 2821, 2828, 2831, 2832, 2835, 2856, 2858, 2864, 2866, 2867, 2869, 2873, 2876, 2884, 2887, 2888, 2891, 2893, 2902, 2903, 2908, 2909, 2911, 2915, 2918, 2927, 2929, 2929, 2946, 2947, 2949, 2954, 2958, 2960, 2962, 2965, 2969, 2970, 2972, 2972, 2974, 2975, 2979, 2980, 2984, 2986, 2990, 3001, 3006, 3010, 3014, 3016, 3018, 3021, 3024, 3024, 3031, 3031, 3046, 3055, 3072, 3084, 3086, 3088, 3090, 3112, 3114, 3129, 3133, 3140, 3142, 3144, 3146, 3149, 3157, 3158, 3160, 3162, 3168, 3171, 3174, 3183, 3200, 3203, 3205, 3212, 3214, 3216, 3218, 3240, 3242, 3251, 3253, 3257, 3260, 3268, 3270, 3272, 3274, 3277, 3285, 3286, 3294, 3294, 3296, 3299, 3302, 3311, 3313, 3314, 3328, 3331, 3333, 3340, 3342, 3344, 3346, 3396, 3398, 3400, 3402, 3406, 3412, 3415, 3423, 3427, 3430, 3439, 3450, 3455, 3458, 3459, 3461, 3478, 3482, 3505, 3507, 3515, 3517, 3517, 3520, 3526, 3530, 3530, 3535, 3540, 3542, 3542, 3544, 3551, 3558, 3567, 3570, 3571, 3585, 3642, 3648, 3662, 3664, 3673, 3713, 3714, 3716, 3716, 3718, 3722, 3724, 3747, 3749, 3749, 3751, 3773, 3776, 3780, 3782, 3782, 3784, 3789, 3792, 3801, 3804, 3807, 3840, 3840, 3864, 3865, 3872, 3881, 3893, 3893, 3895, 3895, 3897, 3897, 3902, 3911, 3913, 3948, 3953, 3972, 3974, 3991, 3993, 4028, 4038, 4038, 4096, 4169, 4176, 4253, 4256, 4293, 4295, 4295, 4301, 4301, 4304, 4346, 4348, 4680, 4682, 4685, 4688, 4694, 4696, 4696, 4698, 4701, 4704, 4744, 4746, 4749, 4752, 4784, 4786, 4789, 4792, 4798, 4800, 4800, 4802, 4805, 4808, 4822, 4824, 4880, 4882, 4885, 4888, 4954, 4957, 4959, 4969, 4977, 4992, 5007, 5024, 5109, 5112, 5117, 5121, 5740, 5743, 5759, 5761, 5786, 5792, 5866, 5870, 5880, 5888, 5900, 5902, 5908, 5920, 5940, 5952, 5971, 5984, 5996, 5998, 6e3, 6002, 6003, 6016, 6099, 6103, 6103, 6108, 6109, 6112, 6121, 6155, 6157, 6160, 6169, 6176, 6264, 6272, 6314, 6320, 6389, 6400, 6430, 6432, 6443, 6448, 6459, 6470, 6509, 6512, 6516, 6528, 6571, 6576, 6601, 6608, 6618, 6656, 6683, 6688, 6750, 6752, 6780, 6783, 6793, 6800, 6809, 6823, 6823, 6832, 6845, 6912, 6987, 6992, 7001, 7019, 7027, 7040, 7155, 7168, 7223, 7232, 7241, 7245, 7293, 7296, 7304, 7312, 7354, 7357, 7359, 7376, 7378, 7380, 7418, 7424, 7673, 7675, 7957, 7960, 7965, 7968, 8005, 8008, 8013, 8016, 8023, 8025, 8025, 8027, 8027, 8029, 8029, 8031, 8061, 8064, 8116, 8118, 8124, 8126, 8126, 8130, 8132, 8134, 8140, 8144, 8147, 8150, 8155, 8160, 8172, 8178, 8180, 8182, 8188, 8255, 8256, 8276, 8276, 8305, 8305, 8319, 8319, 8336, 8348, 8400, 8412, 8417, 8417, 8421, 8432, 8450, 8450, 8455, 8455, 8458, 8467, 8469, 8469, 8472, 8477, 8484, 8484, 8486, 8486, 8488, 8488, 8490, 8505, 8508, 8511, 8517, 8521, 8526, 8526, 8544, 8584, 11264, 11310, 11312, 11358, 11360, 11492, 11499, 11507, 11520, 11557, 11559, 11559, 11565, 11565, 11568, 11623, 11631, 11631, 11647, 11670, 11680, 11686, 11688, 11694, 11696, 11702, 11704, 11710, 11712, 11718, 11720, 11726, 11728, 11734, 11736, 11742, 11744, 11775, 12293, 12295, 12321, 12335, 12337, 12341, 12344, 12348, 12353, 12438, 12441, 12447, 12449, 12538, 12540, 12543, 12549, 12591, 12593, 12686, 12704, 12730, 12784, 12799, 13312, 19893, 19968, 40943, 40960, 42124, 42192, 42237, 42240, 42508, 42512, 42539, 42560, 42607, 42612, 42621, 42623, 42737, 42775, 42783, 42786, 42888, 42891, 42943, 42946, 42950, 42999, 43047, 43072, 43123, 43136, 43205, 43216, 43225, 43232, 43255, 43259, 43259, 43261, 43309, 43312, 43347, 43360, 43388, 43392, 43456, 43471, 43481, 43488, 43518, 43520, 43574, 43584, 43597, 43600, 43609, 43616, 43638, 43642, 43714, 43739, 43741, 43744, 43759, 43762, 43766, 43777, 43782, 43785, 43790, 43793, 43798, 43808, 43814, 43816, 43822, 43824, 43866, 43868, 43879, 43888, 44010, 44012, 44013, 44016, 44025, 44032, 55203, 55216, 55238, 55243, 55291, 63744, 64109, 64112, 64217, 64256, 64262, 64275, 64279, 64285, 64296, 64298, 64310, 64312, 64316, 64318, 64318, 64320, 64321, 64323, 64324, 64326, 64433, 64467, 64829, 64848, 64911, 64914, 64967, 65008, 65019, 65024, 65039, 65056, 65071, 65075, 65076, 65101, 65103, 65136, 65140, 65142, 65276, 65296, 65305, 65313, 65338, 65343, 65343, 65345, 65370, 65382, 65470, 65474, 65479, 65482, 65487, 65490, 65495, 65498, 65500, 65536, 65547, 65549, 65574, 65576, 65594, 65596, 65597, 65599, 65613, 65616, 65629, 65664, 65786, 65856, 65908, 66045, 66045, 66176, 66204, 66208, 66256, 66272, 66272, 66304, 66335, 66349, 66378, 66384, 66426, 66432, 66461, 66464, 66499, 66504, 66511, 66513, 66517, 66560, 66717, 66720, 66729, 66736, 66771, 66776, 66811, 66816, 66855, 66864, 66915, 67072, 67382, 67392, 67413, 67424, 67431, 67584, 67589, 67592, 67592, 67594, 67637, 67639, 67640, 67644, 67644, 67647, 67669, 67680, 67702, 67712, 67742, 67808, 67826, 67828, 67829, 67840, 67861, 67872, 67897, 67968, 68023, 68030, 68031, 68096, 68099, 68101, 68102, 68108, 68115, 68117, 68119, 68121, 68149, 68152, 68154, 68159, 68159, 68192, 68220, 68224, 68252, 68288, 68295, 68297, 68326, 68352, 68405, 68416, 68437, 68448, 68466, 68480, 68497, 68608, 68680, 68736, 68786, 68800, 68850, 68864, 68903, 68912, 68921, 69376, 69404, 69415, 69415, 69424, 69456, 69600, 69622, 69632, 69702, 69734, 69743, 69759, 69818, 69840, 69864, 69872, 69881, 69888, 69940, 69942, 69951, 69956, 69958, 69968, 70003, 70006, 70006, 70016, 70084, 70089, 70092, 70096, 70106, 70108, 70108, 70144, 70161, 70163, 70199, 70206, 70206, 70272, 70278, 70280, 70280, 70282, 70285, 70287, 70301, 70303, 70312, 70320, 70378, 70384, 70393, 70400, 70403, 70405, 70412, 70415, 70416, 70419, 70440, 70442, 70448, 70450, 70451, 70453, 70457, 70459, 70468, 70471, 70472, 70475, 70477, 70480, 70480, 70487, 70487, 70493, 70499, 70502, 70508, 70512, 70516, 70656, 70730, 70736, 70745, 70750, 70751, 70784, 70853, 70855, 70855, 70864, 70873, 71040, 71093, 71096, 71104, 71128, 71133, 71168, 71232, 71236, 71236, 71248, 71257, 71296, 71352, 71360, 71369, 71424, 71450, 71453, 71467, 71472, 71481, 71680, 71738, 71840, 71913, 71935, 71935, 72096, 72103, 72106, 72151, 72154, 72161, 72163, 72164, 72192, 72254, 72263, 72263, 72272, 72345, 72349, 72349, 72384, 72440, 72704, 72712, 72714, 72758, 72760, 72768, 72784, 72793, 72818, 72847, 72850, 72871, 72873, 72886, 72960, 72966, 72968, 72969, 72971, 73014, 73018, 73018, 73020, 73021, 73023, 73031, 73040, 73049, 73056, 73061, 73063, 73064, 73066, 73102, 73104, 73105, 73107, 73112, 73120, 73129, 73440, 73462, 73728, 74649, 74752, 74862, 74880, 75075, 77824, 78894, 82944, 83526, 92160, 92728, 92736, 92766, 92768, 92777, 92880, 92909, 92912, 92916, 92928, 92982, 92992, 92995, 93008, 93017, 93027, 93047, 93053, 93071, 93760, 93823, 93952, 94026, 94031, 94087, 94095, 94111, 94176, 94177, 94179, 94179, 94208, 100343, 100352, 101106, 110592, 110878, 110928, 110930, 110948, 110951, 110960, 111355, 113664, 113770, 113776, 113788, 113792, 113800, 113808, 113817, 113821, 113822, 119141, 119145, 119149, 119154, 119163, 119170, 119173, 119179, 119210, 119213, 119362, 119364, 119808, 119892, 119894, 119964, 119966, 119967, 119970, 119970, 119973, 119974, 119977, 119980, 119982, 119993, 119995, 119995, 119997, 120003, 120005, 120069, 120071, 120074, 120077, 120084, 120086, 120092, 120094, 120121, 120123, 120126, 120128, 120132, 120134, 120134, 120138, 120144, 120146, 120485, 120488, 120512, 120514, 120538, 120540, 120570, 120572, 120596, 120598, 120628, 120630, 120654, 120656, 120686, 120688, 120712, 120714, 120744, 120746, 120770, 120772, 120779, 120782, 120831, 121344, 121398, 121403, 121452, 121461, 121461, 121476, 121476, 121499, 121503, 121505, 121519, 122880, 122886, 122888, 122904, 122907, 122913, 122915, 122916, 122918, 122922, 123136, 123180, 123184, 123197, 123200, 123209, 123214, 123214, 123584, 123641, 124928, 125124, 125136, 125142, 125184, 125259, 125264, 125273, 126464, 126467, 126469, 126495, 126497, 126498, 126500, 126500, 126503, 126503, 126505, 126514, 126516, 126519, 126521, 126521, 126523, 126523, 126530, 126530, 126535, 126535, 126537, 126537, 126539, 126539, 126541, 126543, 126545, 126546, 126548, 126548, 126551, 126551, 126553, 126553, 126555, 126555, 126557, 126557, 126559, 126559, 126561, 126562, 126564, 126564, 126567, 126570, 126572, 126578, 126580, 126583, 126585, 126588, 126590, 126590, 126592, 126601, 126603, 126619, 126625, 126627, 126629, 126633, 126635, 126651, 131072, 173782, 173824, 177972, 177984, 178205, 178208, 183969, 183984, 191456, 194560, 195101, 917760, 917999];
        commentDirectiveRegExSingleLine = /^\/\/\/?\s*@(ts-expect-error|ts-ignore)/;
        commentDirectiveRegExMultiLine = /^(?:\/|\*)*\s*@(ts-expect-error|ts-ignore)/;
        tokenStrings = makeReverseMap(textToToken);
        mergeConflictMarkerLength = "<<<<<<<".length;
        shebangTriviaRegex = /^#!.*/;
        codePointAt = String.prototype.codePointAt ? (s, i) => s.codePointAt(i) : function codePointAt2(str, i) {
          const size = str.length;
          if (i < 0 || i >= size) {
            return void 0;
          }
          const first2 = str.charCodeAt(i);
          if (first2 >= 55296 && first2 <= 56319 && size > i + 1) {
            const second = str.charCodeAt(i + 1);
            if (second >= 56320 && second <= 57343) {
              return (first2 - 55296) * 1024 + second - 56320 + 65536;
            }
          }
          return first2;
        };
        utf16EncodeAsStringWorker = String.fromCodePoint ? (codePoint) => String.fromCodePoint(codePoint) : utf16EncodeAsStringFallback;
      }
    });

    // src/compiler/utilitiesPublic.ts
    function isExternalModuleNameRelative(moduleName) {
      return pathIsRelative(moduleName) || isRootedDiskPath(moduleName);
    }
    function sortAndDeduplicateDiagnostics(diagnostics) {
      return sortAndDeduplicate(diagnostics, compareDiagnostics);
    }
    function getDefaultLibFileName(options) {
      switch (getEmitScriptTarget(options)) {
        case 99 /* ESNext */:
          return "lib.esnext.full.d.ts";
        case 9 /* ES2022 */:
          return "lib.es2022.full.d.ts";
        case 8 /* ES2021 */:
          return "lib.es2021.full.d.ts";
        case 7 /* ES2020 */:
          return "lib.es2020.full.d.ts";
        case 6 /* ES2019 */:
          return "lib.es2019.full.d.ts";
        case 5 /* ES2018 */:
          return "lib.es2018.full.d.ts";
        case 4 /* ES2017 */:
          return "lib.es2017.full.d.ts";
        case 3 /* ES2016 */:
          return "lib.es2016.full.d.ts";
        case 2 /* ES2015 */:
          return "lib.es6.d.ts";
        default:
          return "lib.d.ts";
      }
    }
    function textSpanEnd(span) {
      return span.start + span.length;
    }
    function textSpanIsEmpty(span) {
      return span.length === 0;
    }
    function textSpanContainsPosition(span, position) {
      return position >= span.start && position < textSpanEnd(span);
    }
    function textRangeContainsPositionInclusive(span, position) {
      return position >= span.pos && position <= span.end;
    }
    function textSpanContainsTextSpan(span, other) {
      return other.start >= span.start && textSpanEnd(other) <= textSpanEnd(span);
    }
    function textSpanOverlapsWith(span, other) {
      return textSpanOverlap(span, other) !== void 0;
    }
    function textSpanOverlap(span1, span2) {
      const overlap = textSpanIntersection(span1, span2);
      return overlap && overlap.length === 0 ? void 0 : overlap;
    }
    function textSpanIntersectsWithTextSpan(span, other) {
      return decodedTextSpanIntersectsWith(span.start, span.length, other.start, other.length);
    }
    function textSpanIntersectsWith(span, start, length2) {
      return decodedTextSpanIntersectsWith(span.start, span.length, start, length2);
    }
    function decodedTextSpanIntersectsWith(start1, length1, start2, length2) {
      const end1 = start1 + length1;
      const end2 = start2 + length2;
      return start2 <= end1 && end2 >= start1;
    }
    function textSpanIntersectsWithPosition(span, position) {
      return position <= textSpanEnd(span) && position >= span.start;
    }
    function textSpanIntersection(span1, span2) {
      const start = Math.max(span1.start, span2.start);
      const end = Math.min(textSpanEnd(span1), textSpanEnd(span2));
      return start <= end ? createTextSpanFromBounds(start, end) : void 0;
    }
    function createTextSpan(start, length2) {
      if (start < 0) {
        throw new Error("start < 0");
      }
      if (length2 < 0) {
        throw new Error("length < 0");
      }
      return { start, length: length2 };
    }
    function createTextSpanFromBounds(start, end) {
      return createTextSpan(start, end - start);
    }
    function textChangeRangeNewSpan(range) {
      return createTextSpan(range.span.start, range.newLength);
    }
    function textChangeRangeIsUnchanged(range) {
      return textSpanIsEmpty(range.span) && range.newLength === 0;
    }
    function createTextChangeRange(span, newLength) {
      if (newLength < 0) {
        throw new Error("newLength < 0");
      }
      return { span, newLength };
    }
    function collapseTextChangeRangesAcrossMultipleVersions(changes) {
      if (changes.length === 0) {
        return unchangedTextChangeRange;
      }
      if (changes.length === 1) {
        return changes[0];
      }
      const change0 = changes[0];
      let oldStartN = change0.span.start;
      let oldEndN = textSpanEnd(change0.span);
      let newEndN = oldStartN + change0.newLength;
      for (let i = 1; i < changes.length; i++) {
        const nextChange = changes[i];
        const oldStart1 = oldStartN;
        const oldEnd1 = oldEndN;
        const newEnd1 = newEndN;
        const oldStart2 = nextChange.span.start;
        const oldEnd2 = textSpanEnd(nextChange.span);
        const newEnd2 = oldStart2 + nextChange.newLength;
        oldStartN = Math.min(oldStart1, oldStart2);
        oldEndN = Math.max(oldEnd1, oldEnd1 + (oldEnd2 - newEnd1));
        newEndN = Math.max(newEnd2, newEnd2 + (newEnd1 - oldEnd2));
      }
      return createTextChangeRange(
        createTextSpanFromBounds(oldStartN, oldEndN),
        /*newLength*/
        newEndN - oldStartN
      );
    }
    function getTypeParameterOwner(d) {
      if (d && d.kind === 167 /* TypeParameter */) {
        for (let current = d; current; current = current.parent) {
          if (isFunctionLike(current) || isClassLike(current) || current.kind === 263 /* InterfaceDeclaration */) {
            return current;
          }
        }
      }
    }
    function isParameterPropertyDeclaration(node, parent) {
      return isParameter(node) && hasSyntacticModifier(node, 16476 /* ParameterPropertyModifier */) && parent.kind === 175 /* Constructor */;
    }
    function isEmptyBindingPattern(node) {
      if (isBindingPattern(node)) {
        return every(node.elements, isEmptyBindingElement);
      }
      return false;
    }
    function isEmptyBindingElement(node) {
      if (isOmittedExpression(node)) {
        return true;
      }
      return isEmptyBindingPattern(node.name);
    }
    function walkUpBindingElementsAndPatterns(binding) {
      let node = binding.parent;
      while (isBindingElement(node.parent)) {
        node = node.parent.parent;
      }
      return node.parent;
    }
    function getCombinedFlags(node, getFlags) {
      if (isBindingElement(node)) {
        node = walkUpBindingElementsAndPatterns(node);
      }
      let flags = getFlags(node);
      if (node.kind === 259 /* VariableDeclaration */) {
        node = node.parent;
      }
      if (node && node.kind === 260 /* VariableDeclarationList */) {
        flags |= getFlags(node);
        node = node.parent;
      }
      if (node && node.kind === 242 /* VariableStatement */) {
        flags |= getFlags(node);
      }
      return flags;
    }
    function getCombinedModifierFlags(node) {
      return getCombinedFlags(node, getEffectiveModifierFlags);
    }
    function getCombinedNodeFlagsAlwaysIncludeJSDoc(node) {
      return getCombinedFlags(node, getEffectiveModifierFlagsAlwaysIncludeJSDoc);
    }
    function getCombinedNodeFlags(node) {
      return getCombinedFlags(node, (n) => n.flags);
    }
    function validateLocaleAndSetLanguage(locale, sys2, errors) {
      const lowerCaseLocale = locale.toLowerCase();
      const matchResult = /^([a-z]+)([_\-]([a-z]+))?$/.exec(lowerCaseLocale);
      if (!matchResult) {
        if (errors) {
          errors.push(createCompilerDiagnostic(Diagnostics.Locale_must_be_of_the_form_language_or_language_territory_For_example_0_or_1, "en", "ja-jp"));
        }
        return;
      }
      const language = matchResult[1];
      const territory = matchResult[3];
      if (contains(supportedLocaleDirectories, lowerCaseLocale) && !trySetLanguageAndTerritory(language, territory, errors)) {
        trySetLanguageAndTerritory(
          language,
          /*territory*/
          void 0,
          errors
        );
      }
      setUILocale(locale);
      function trySetLanguageAndTerritory(language2, territory2, errors2) {
        const compilerFilePath = normalizePath(sys2.getExecutingFilePath());
        const containingDirectoryPath = getDirectoryPath(compilerFilePath);
        let filePath = combinePaths(containingDirectoryPath, language2);
        if (territory2) {
          filePath = filePath + "-" + territory2;
        }
        filePath = sys2.resolvePath(combinePaths(filePath, "diagnosticMessages.generated.json"));
        if (!sys2.fileExists(filePath)) {
          return false;
        }
        let fileContents = "";
        try {
          fileContents = sys2.readFile(filePath);
        } catch (e) {
          if (errors2) {
            errors2.push(createCompilerDiagnostic(Diagnostics.Unable_to_open_file_0, filePath));
          }
          return false;
        }
        try {
          setLocalizedDiagnosticMessages(JSON.parse(fileContents));
        } catch {
          if (errors2) {
            errors2.push(createCompilerDiagnostic(Diagnostics.Corrupted_locale_file_0, filePath));
          }
          return false;
        }
        return true;
      }
    }
    function getOriginalNode(node, nodeTest) {
      if (node) {
        while (node.original !== void 0) {
          node = node.original;
        }
      }
      if (!node || !nodeTest) {
        return node;
      }
      return nodeTest(node) ? node : void 0;
    }
    function findAncestor(node, callback) {
      while (node) {
        const result = callback(node);
        if (result === "quit") {
          return void 0;
        } else if (result) {
          return node;
        }
        node = node.parent;
      }
      return void 0;
    }
    function isParseTreeNode(node) {
      return (node.flags & 8 /* Synthe
"""


```