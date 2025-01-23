Response:
Let's break down the thought process for analyzing this Python script.

**1. Initial Understanding - The Big Picture:**

The first step is to recognize the file path: `frida/subprojects/frida-clr/releng/meson/docs/refman/generatorman.py`. Keywords here are "frida," "meson," "docs," and "refman."  This immediately suggests the script is involved in generating documentation for Frida, likely using the Meson build system, and specifically for a reference manual. The ".py" extension confirms it's a Python script.

**2. Core Functionality - Identifying the Main Actors:**

Scanning the imports reveals key classes and modules:

* `re`: Regular expressions, suggesting text manipulation and pattern matching.
* `pathlib.Path`:  Working with file paths in a more object-oriented way.
* `generatorbase.GeneratorBase`: Inheritance, meaning `GeneratorMan` extends existing functionality for generating something.
* `model`: This is crucial. It imports `ReferenceManual`, `Function`, `Object`, `PosArg`, `VarArgs`, and `Kwarg`. This signals that the script works with a structured representation of documentation elements – likely parsed from some input source.
* `typing as T`: Type hinting, making the code more readable and maintainable.

The `GeneratorMan` class itself is the central actor. Its constructor takes a `ReferenceManual` and an output path. The `generate()` method is clearly the main execution point.

**3. Deconstructing the `ManPage` Class:**

The `ManPage` class is self-contained and focused on formatting text as a Unix man page. Keywords like `.TH`, `.SH`, `.SS`, `.P`, `.RS`, `.RE`, `.br`, etc., are standard troff/man page directives. This confirms the script's purpose: generating man pages. The `bold()` and `italic()` static methods are helpers for formatting.

**4. Analyzing `GeneratorMan` Methods - Step-by-Step:**

Now, we examine the methods within `GeneratorMan`, focusing on their individual contributions:

* **`__init__`:**  Basic initialization, storing the `ReferenceManual`, output path, and a flag for modules.
* **`generate_description`:** This is where the magic happens for formatting text. The use of regular expressions (`re.sub`) to handle `[[italic]]`, `[link](target)`, and `*bold*` markup is evident. The handling of code blocks (` ``` `) and lists is also important.
* **`function_name`:** Simple helper to construct function names with optional object context.
* **`generate_function_signature`:** Formats the function signature in a man-page-friendly way, handling long signatures with indentation.
* **`base_info`:** Collects common information like deprecation and "since" notes.
* **`generate_function_arg`:** Formats the details of a function argument (name, type, required status, default value, etc.).
* **`generate_function_argument_section`:** Groups and formats arguments (positional, variable, optional, keyword).
* **`generate_sub_sub_section`:** Formats subsections within a function or object description.
* **`generate_function`:** Orchestrates the generation of a function's documentation, calling other formatting methods.
* **`generate_object`:**  Handles the documentation for objects, including inheritance, return/extension relationships.
* **`generate`:** The main driver. It creates a `ManPage` object, sets up the basic structure (NAME, DESCRIPTION), iterates through functions and objects, and calls their respective generation methods. It also handles the "SEE ALSO" section for links.

**5. Connecting to Reverse Engineering and Low-Level Concepts:**

As each method is analyzed, the prompt's specific questions come into play:

* **Reverse Engineering:**  The script *generates documentation*. The documentation is *for* Frida, a dynamic instrumentation toolkit used heavily in reverse engineering. Thus, the *output* of this script directly assists reverse engineers in understanding Frida's API.
* **Binary/Low-Level:** Frida interacts deeply with process memory and system calls. While this script *doesn't* directly manipulate binaries, it documents the tools that *do*. The documentation will describe functions and objects used to interact with low-level aspects of a running process.
* **Linux/Android Kernel/Framework:** Frida is often used on Linux and Android. The documentation will describe functions that interact with concepts specific to these platforms (e.g., process management, memory allocation).
* **Logic and Assumptions:** The script assumes a well-structured input (`ReferenceManual`). The output is deterministic based on this input.
* **User Errors:** The script itself is for *generating* documentation. User errors would likely occur *before* this, in the creation of the input `ReferenceManual`. However, potential errors *within* the script could involve incorrect formatting or missing information in the input data.
* **User Journey:**  The user is likely a Frida developer or someone contributing to Frida's documentation. They would modify or create the input data that this script consumes. The Meson build system would then invoke this script to generate the man pages.

**6. Refinement and Examples:**

After the initial analysis, concrete examples are needed to illustrate the connections to reverse engineering and low-level concepts. This involves thinking about specific Frida use cases and how the documented API enables them. For instance, `Memory.readByteArray()` is a clear example of low-level memory access relevant to reverse engineering.

**7. Structuring the Answer:**

Finally, the information needs to be organized logically to address all parts of the prompt clearly and concisely. Using headings and bullet points helps improve readability.

By following this methodical approach – starting with the big picture and gradually drilling down into specifics, while constantly relating back to the prompt's questions – we can develop a comprehensive and accurate analysis of the Python script.
这个Python脚本 `generatorman.py` 的主要功能是**根据Frida的API定义生成 Unix man page 格式的参考文档**。它属于 Frida 项目中，专门为 Frida-CLR（Common Language Runtime，用于支持 .NET 平台）相关的 API 生成参考手册。

下面详细列举其功能并结合你的问题进行说明：

**1. 功能概述:**

* **解析 API 模型:** 该脚本接收一个 `ReferenceManual` 对象作为输入。这个对象包含了 Frida API 的结构化描述，包括函数、对象、参数、返回值等等。这个 `ReferenceManual` 对象很可能由其他脚本或模块从某种定义文件（例如，可能是某种自定义格式或从代码注释中提取）解析而来。
* **生成 Man Page 结构:** 脚本使用 `ManPage` 类来构建 man page 的基本结构，例如标题、章节、子章节、段落、缩进等。
* **格式化文档内容:**  脚本负责将 API 模型中的信息转换成 man page 的文本格式。这包括：
    * 函数和对象名称
    * 函数签名（参数列表、返回值）
    * 参数的详细描述（类型、是否必选、默认值等）
    * 函数和对象的详细描述
    * 示例代码
    * 注意事项和警告
    * 交叉引用和链接
* **处理 Markdown 风格的标记:**  `generate_description` 函数能够解析并转换一些简单的 Markdown 风格的标记，例如：
    * `[[text]]` 转换为斜体
    * `[link text](target)` 转换为带链接的斜体
    * `*bold text*` 转换为粗体
    * ```code``` 包裹的代码块会进行特殊处理，例如识别 "meson" 代码块并去除首行。
* **输出 Man Page 文件:** 最终，脚本将生成的 man page 内容写入到指定的文件中。

**2. 与逆向方法的关联及举例:**

该脚本本身不直接参与逆向操作。它的作用是为 Frida 提供文档，而 Frida 是一款强大的动态 instrumentation 工具，被广泛应用于逆向工程、安全研究等领域。

**举例说明:**

一个逆向工程师想要使用 Frida 拦截 .NET 程序中的某个函数调用，并修改其参数。他需要知道 Frida-CLR 提供了哪些 API 来实现这个目标。

* **操作步骤:** 逆向工程师会查阅 Frida 的文档，很可能就会找到由 `generatorman.py` 生成的 man page。
* **文档作用:** 在 man page 中，他可以找到 `Frida.Clr.Method` 对象，以及该对象提供的 `hook` 方法。文档会详细说明 `hook` 方法的参数（例如，回调函数），返回值，以及如何使用它来拦截函数调用。
* **底层关联:**  文档中描述的 `hook` 方法，在 Frida 的底层实现中，会涉及到动态修改目标进程的内存，修改函数入口点的指令，跳转到 Frida 提供的回调函数中执行。这些都是典型的逆向工程中使用的技术。

**3. 涉及到二进制底层，Linux, Android内核及框架的知识及举例:**

虽然脚本本身是高级语言 Python 编写的，但它生成的文档是关于 Frida 的，而 Frida 的工作原理 deeply 涉及到以下知识：

* **二进制底层:**
    * Frida 能够在运行时读取和修改目标进程的内存，这涉及到对目标进程的内存布局、指令编码（例如，x86, ARM 等架构的指令集）的理解。
    * 文档中可能会描述一些与内存操作相关的 API，例如读取或写入特定地址的内存，这些操作直接对应于二进制层面的操作。
    * **例子:** 文档可能会描述 `Memory.readByteArray(address, length)` 函数，该函数直接涉及到读取指定内存地址的二进制数据。
* **Linux 内核及框架:**
    * 在 Linux 上，Frida 依赖于 ptrace 系统调用或其他进程间通信机制来实现 attach 到目标进程、注入代码、拦截函数等功能。
    * 文档中描述的某些 Frida 功能可能直接或间接地依赖于 Linux 特有的 API 或概念，例如进程 ID，信号处理等。
    * **例子:**  文档可能会提到使用 `Process.getModuleByName()` 来获取指定模块的加载地址，这涉及到对 Linux 进程地址空间的理解。
* **Android 内核及框架:**
    * 在 Android 上，Frida 经常用于分析和修改 APK 包的行为。这涉及到对 Android Runtime (ART) 或 Dalvik 虚拟机、Binder 通信机制、系统服务的理解。
    * Frida-CLR 特别与 Mono 运行时相关，而 Mono 在 Android 上也有应用。文档中描述的 API 可能涉及到与 Mono 虚拟机交互的细节。
    * **例子:** 文档可能会描述如何使用 Frida-CLR 的 API 来 hook Android 应用程序中用 C# 编写的部分逻辑。

**4. 逻辑推理及假设输入与输出:**

脚本的主要逻辑是遍历 `ReferenceManual` 对象中的函数和对象，并根据其属性生成 man page 格式的文本。

**假设输入:**

假设 `ReferenceManual` 对象中包含一个名为 `Memory` 的对象，该对象有一个名为 `readByteArray` 的方法，其定义如下：

```python
# 简化的表示，实际的 ReferenceManual 对象结构会更复杂
class ReferenceManual:
    def __init__(self):
        self.objects = [
            Object(
                name="Memory",
                description="Provides access to the process's memory.",
                methods=[
                    Function(
                        name="readByteArray",
                        description="Reads a sequence of bytes from memory.",
                        posargs=[
                            PosArg(name="address", type=TypeInfo(raw="NativePointer"), description="The memory address to read from."),
                            PosArg(name="length", type=TypeInfo(raw="int"), description="The number of bytes to read."),
                        ],
                        returns=TypeInfo(raw="bytes"),
                        example="""
                        var data = Memory.readByteArray(ptr("0x12345678"), 16);
                        console.log(data);
                        """
                    )
                ]
            )
        ]
```

**预期输出 (部分):**

```
.SS Memory()
.P
\fBextends: \fR
.br
.P
Provides access to the process's memory.
.nl
.SS Memory.readByteArray()
.P
\fIbytes\fR Memory.readByteArray(address, length)
.nl
.P
\fBSYNOPSIS\fR
.RS 4
\fIbytes\fR Memory.readByteArray(address, length)
.RE
.nl
.P
\fBDESCRIPTION\fR
.RS 4
Reads a sequence of bytes from memory.
.RE
.nl
.P
\fBPOSARGS\fR
.RS 4
\fBaddress\fR
\fINativePointer\fR, \fBrequired\fR
.br
.RS 2
The memory address to read from.
.RE
.nl
\fBlength\fR
\fIint\fR, \fBrequired\fR
.br
.RS 2
The number of bytes to read.
.RE
.nl
.RE
.nl
.P
\fBEXAMPLE\fR
.RS 4
var data = Memory.readByteArray(ptr("0x12345678"), 16);
.br
console.log(data);
.RE
.RE
```

**5. 用户或编程常见的使用错误及举例:**

由于该脚本的主要功能是生成文档，因此直接的用户操作错误可能不多。常见的使用错误更多会发生在：

* **`ReferenceManual` 对象的构建:** 如果构建 `ReferenceManual` 对象的脚本或过程存在错误，例如 API 定义不完整、类型信息错误、描述缺失等，那么生成的 man page 也会包含这些错误。
    * **例子:**  如果某个函数的参数类型在 `ReferenceManual` 中被错误地定义为 `string` 而实际上是 `int`，那么生成的文档也会有这个错误。
* **Markdown 标记错误:**  在 API 的描述或示例中使用了错误的 Markdown 标记，`generate_description` 函数可能无法正确解析，导致文档格式混乱。
    * **例子:**  使用了 `**bold text**` 而不是 `*bold text*`，或者链接的格式不正确 `[text](target)`。
* **输出路径错误:**  如果脚本执行时指定的输出路径不存在或没有写入权限，会导致 man page 文件生成失败。

**6. 用户操作是如何一步步的到达这里，作为调试线索:**

通常，开发者或维护者不会直接手动运行 `generatorman.py`。它通常是构建系统（例如 Meson）的一部分。以下是可能的操作步骤：

1. **修改 Frida 的 API 定义:** 开发者可能修改了 Frida-CLR 相关的代码，添加了新的 API，修改了现有 API 的功能或参数。这些修改会体现在某种 API 定义文件或代码注释中。
2. **更新 `ReferenceManual` 的生成过程:**  可能有其他的脚本或工具负责解析这些 API 定义并生成 `ReferenceManual` 对象。开发者可能需要更新这些脚本以反映 API 的更改。
3. **触发构建过程:**  开发者会运行 Meson 构建命令（例如 `meson compile` 或 `ninja`）。
4. **Meson 执行 `generatorman.py`:**  在构建配置中，Meson 会识别出需要生成 man page 文档，并调用 `generatorman.py` 脚本，将生成的 `ReferenceManual` 对象作为输入，并指定输出路径。
5. **生成 man page 文件:** `generatorman.py` 读取 `ReferenceManual` 对象，按照其逻辑生成 man page 内容，并写入到指定的输出文件中。

**作为调试线索:**

如果生成的 man page 文档出现错误或与预期的 API 不符，调试线索可以从以下几个方面入手：

* **检查 API 定义:**  确认 Frida 的代码或 API 定义文件是否正确描述了 API。
* **检查 `ReferenceManual` 生成过程:**  查看生成 `ReferenceManual` 对象的脚本，确认其是否正确解析了 API 定义并构建了正确的对象模型。
* **检查 `generatorman.py` 的逻辑:**  如果以上两个步骤都没问题，那么可能需要检查 `generatorman.py` 脚本本身是否存在 bug，例如格式化逻辑错误、对 API 模型的解析错误等。
* **查看 Meson 构建配置:**  确认 Meson 是否正确配置了 man page 的生成过程，包括是否正确调用了 `generatorman.py`，并传递了正确的参数。

总而言之，`generatorman.py` 是 Frida 文档生成流程中的一个关键环节，它负责将结构化的 API 信息转化为用户可以查阅的 man page 文档，为 Frida 的使用者提供了重要的参考。 虽然它本身是用高级语言编写，但它所服务的对象 Frida，以及其生成的文档内容，都与逆向工程、二进制底层、操作系统内核及框架等底层技术紧密相关。

### 提示词
```
这是目录为frida/subprojects/frida-clr/releng/meson/docs/refman/generatorman.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
import re
from pathlib import Path

from .generatorbase import GeneratorBase
from .model import (
    ReferenceManual,
    Function,
    Object,
    PosArg,
    VarArgs,
    Kwarg,
)

import typing as T


class ManPage:
    def __init__(self, path: Path):
        self.path = path
        self.text = ""

    def reset_font(self) -> None:
        self.text += ".P\n"

    def title(self, name: str, section: int) -> None:
        import datetime

        date = datetime.date.today()
        self.reset_font()
        self.text += f'.TH "{name}" "{section}" "{date}"\n'

    def section(self, name: str) -> None:
        self.reset_font()
        self.text += f".SH {name}\n"

    def subsection(self, name: str) -> None:
        self.reset_font()
        self.text += f".SS {name}\n"

    def par(self, text: str) -> None:
        self.reset_font()
        self.text += f"{text}\n"

    def indent(self, amount: int = 4) -> None:
        self.text += f".RS {amount}\n"

    def unindent(self) -> None:
        self.text += ".RE\n"

    def br(self) -> None:
        self.text += ".br\n"

    def nl(self) -> None:
        self.text += "\n"

    def line(self, text: str) -> None:
        if text and text[0] in [".", "'"]:
            self.text += "\\"
        self.text += f"{text}\n"

    def inline(self, text: str) -> None:
        self.text += f"{text}"

    def write(self) -> None:
        self.path.write_text(self.text, encoding="utf-8")

    @staticmethod
    def bold(text: str) -> str:
        return f"\\fB{text}\\fR"

    @staticmethod
    def italic(text: str) -> str:
        return f"\\fI{text}\\fR"


class GeneratorMan(GeneratorBase):
    def __init__(
        self, manual: ReferenceManual, out: Path, enable_modules: bool
    ) -> None:
        super().__init__(manual)
        self.out = out
        self.enable_modules = enable_modules
        self.links: T.List[str] = []

    def generate_description(self, page: ManPage, desc: str) -> None:
        def italicise(match: T.Match[str]) -> str:
            v = match.group(1)
            if v[0] == "@":
                v = v[1:]

            return ManPage.italic(v)

        desc = re.sub(re.compile(r"\[\[(.*?)\]\]", re.DOTALL), italicise, desc)

        def linkify(match: T.Match[str]) -> str:
            replacement = ManPage.italic(match.group(1))

            if match.group(2)[0] != "#":
                if match.group(2) in self.links:
                    num = self.links.index(match.group(2))
                else:
                    self.links.append(match.group(2))
                    num = len(self.links)

                replacement += f"[{num}]"

            return replacement

        desc = re.sub(re.compile(r"\[(.*?)\]\((.*?)\)", re.DOTALL), linkify, desc)

        def bold(match: T.Match[str]) -> str:
            return ManPage.bold(match.group(1))

        desc = re.sub(re.compile(r"\*(.*?)\*"), bold, desc)

        isCode = False
        for chunk in desc.split("```"):
            if isCode:
                page.indent()
                lines = chunk.strip().split("\n")
                if lines[0] == "meson":
                    lines = lines[1:]

                for line in lines:
                    page.line(line)
                    page.br()
                page.unindent()
            else:
                inList = False
                for line in chunk.strip().split("\n"):
                    if len(line) == 0:
                        page.nl()
                        if inList:
                            page.nl()
                            inList = False
                    elif line[0:2] in ["- ", "* "]:
                        if inList:
                            page.nl()
                            page.br()
                        else:
                            inList = True

                        page.inline(line.strip() + " ")
                    elif inList and line[0] == " ":
                        page.inline(line.strip() + " ")
                    else:
                        inList = False
                        page.line(line)

                if inList:
                    page.nl()

            isCode = not isCode

    def function_name(self, f: Function, o: Object = None) -> str:
        name = ""
        if o is not None:
            name += f"{o.name}."

        name += f.name
        return name

    def generate_function_signature(
        self, page: ManPage, f: Function, o: Object = None
    ) -> None:
        args = []

        if f.posargs:
            args += [arg.name for arg in f.posargs]

        if f.varargs:
            args += [f.varargs.name + "..."]

        if f.optargs:
            args += [f"[{arg.name}]" for arg in f.optargs]

        for kwarg in self.sorted_and_filtered(list(f.kwargs.values())):
            kw = kwarg.name + ":"
            if kwarg.default:
                kw += " " + ManPage.bold(kwarg.default)
            args += [kw]

        ret = ManPage.italic(f.returns.raw) + " "

        prefix = f"{ret}{self.function_name(f, o)}("
        sig = ", ".join(args)
        suffix = ")"

        if len(prefix) + len(sig) + len(suffix) > 70:
            page.line(prefix)
            page.br()
            page.indent()
            for arg in args:
                page.line(arg + ",")
                page.br()
            page.unindent()
            page.line(suffix)
        else:
            page.line(prefix + sig + suffix)

    def base_info(
        self, x: T.Union[PosArg, VarArgs, Kwarg, Function, Object]
    ) -> T.List[str]:
        info = []
        if x.deprecated:
            info += [ManPage.bold("deprecated") + f" since {x.deprecated}"]
        if x.since:
            info += [f"since {x.since}"]

        return info

    def generate_function_arg(
        self,
        page: ManPage,
        arg: T.Union[PosArg, VarArgs, Kwarg],
        isOptarg: bool = False,
    ) -> None:
        required = (
            arg.required
            if isinstance(arg, Kwarg)
            else not isOptarg and not isinstance(arg, VarArgs)
        )

        page.line(ManPage.bold(arg.name))

        info = [ManPage.italic(arg.type.raw)]

        if required:
            info += [ManPage.bold("required")]
        if isinstance(arg, (PosArg, Kwarg)) and arg.default:
            info += [f"default: {arg.default}"]
        if isinstance(arg, VarArgs):
            mn = 0 if arg.min_varargs < 0 else arg.min_varargs
            mx = "N" if arg.max_varargs < 0 else arg.max_varargs
            info += [f"{mn}...{mx} times"]

        info += self.base_info(arg)

        page.line(", ".join(info))

        page.br()
        page.indent(2)
        self.generate_description(page, arg.description.strip())
        page.unindent()
        page.nl()

    def generate_function_argument_section(
        self,
        page: ManPage,
        name: str,
        args: T.Sequence[T.Union[PosArg, VarArgs, Kwarg]],
        isOptarg: bool = False,
    ) -> None:
        if not args:
            return

        page.line(ManPage.bold(name))
        page.indent()
        for arg in args:
            self.generate_function_arg(page, arg, isOptarg)
        page.unindent()

    def generate_sub_sub_section(
        self, page: ManPage, name: str, text: T.List[str], process: bool = True
    ) -> None:
        page.line(ManPage.bold(name))
        page.indent()
        if process:
            for line in text:
                self.generate_description(page, line.strip())
        else:
            page.line("\n\n".join([line.strip() for line in text]))
        page.unindent()

    def generate_function(self, page: ManPage, f: Function, obj: Object = None) -> None:
        page.subsection(self.function_name(f, obj) + "()")
        page.indent(0)

        page.line(ManPage.bold("SYNOPSIS"))
        page.indent()
        self.generate_function_signature(page, f, obj)

        info = self.base_info(f)
        if info:
            page.nl()
            page.line(", ".join(info))
        page.unindent()
        page.nl()

        self.generate_sub_sub_section(page, "DESCRIPTION", [f.description])
        page.nl()

        self.generate_function_argument_section(page, "POSARGS", f.posargs)
        if f.varargs:
            self.generate_function_argument_section(page, "VARARGS", [f.varargs])
        self.generate_function_argument_section(page, "OPTARGS", f.optargs, True)
        self.generate_function_argument_section(
            page, "KWARGS", self.sorted_and_filtered(list(f.kwargs.values()))
        )

        if f.notes:
            self.generate_sub_sub_section(page, "NOTES", f.notes)
        if f.warnings:
            self.generate_sub_sub_section(page, "WARNINGS", f.warnings)
        if f.example:
            self.generate_sub_sub_section(page, "EXAMPLE", [f.example])

        page.unindent()

    def generate_object(self, page: ManPage, obj: Object) -> None:
        page.subsection(obj.name)
        page.indent(2)

        info = self.base_info(obj)
        if info:
            page.line(", ".join(info))
            page.br()

        if obj.extends:
            page.line(ManPage.bold("extends: ") + obj.extends)
            page.br()

        ret = [x.name for x in self.sorted_and_filtered(obj.returned_by)]
        if ret:
            page.line(ManPage.bold("returned_by: ") + ", ".join(ret))
            page.br()

        ext = [x.name for x in self.sorted_and_filtered(obj.extended_by)]
        if ext:
            page.line(ManPage.bold("extended_by: ") + ", ".join(ext))
            page.br()

        page.nl()

        self.generate_description(page, obj.description.strip())
        page.nl()

        if obj.notes:
            self.generate_sub_sub_section(page, "NOTES", obj.notes)
        if obj.warnings:
            self.generate_sub_sub_section(page, "WARNINGS", obj.warnings)
        if obj.example:
            self.generate_sub_sub_section(page, "EXAMPLE", [obj.example])

        page.unindent()

    def generate(self) -> None:
        page = ManPage(self.out)

        page.title("meson-reference", 3)

        page.section("NAME")
        page.par(
            f"meson-reference v{self._extract_meson_version()}"
            + " - a reference for meson functions and objects"
        )

        page.section("DESCRIPTION")
        self.generate_description(
            page,
            """This manual is divided into two sections, *FUNCTIONS* and *OBJECTS*.  *FUNCTIONS* contains a reference for all meson functions and methods.  Methods are denoted by [[object_name]].[[method_name]]().  *OBJECTS* contains additional information about each object.""",
        )

        page.section("FUNCTIONS")
        for f in self.sorted_and_filtered(self.functions):
            self.generate_function(page, f)

        for obj in self.sorted_and_filtered(self.objects):
            for f in self.sorted_and_filtered(obj.methods):
                self.generate_function(page, f, obj)

        page.section("OBJECTS")
        for obj in self.sorted_and_filtered(self.objects):
            self.generate_object(page, obj)

        page.section("SEE ALSO")
        for i in range(len(self.links)):
            link = self.links[i]
            page.line(f"[{i + 1}] {link}")
            page.br()

        page.write()
```