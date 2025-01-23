Response:
Let's break down the thought process for analyzing this Python script. The goal is to understand its functionality and connect it to broader concepts like reverse engineering, low-level details, and common usage errors.

**1. Initial Understanding - What's the Big Picture?**

The first lines provide crucial context: "目录为frida/releng/meson/docs/refman/generatorman.py的fridaDynamic instrumentation tool的源代码文件". This tells us:

* **Tool:** Frida, a dynamic instrumentation tool. This immediately suggests a connection to reverse engineering and interacting with running processes.
* **Purpose:** Generating man pages (indicated by the filename and class name `ManPage`).
* **Input:** Likely structured data representing Frida's API (functions, objects, etc.). The import of `ReferenceManual`, `Function`, `Object`, etc., confirms this.
* **Output:** Man page formatted text files.
* **Technology:** Meson build system (from the path).

**2. Deconstructing the Code - Key Components:**

* **`ManPage` Class:** This class handles the generation of man page syntax. The methods like `title`, `section`, `par`, `bold`, and `italic` clearly map to man page formatting elements. This class is a building block, focused on the *how* of formatting.

* **`GeneratorMan` Class:** This is the core logic. It orchestrates the process of taking the structured API data and using the `ManPage` class to produce the output.

    * **`__init__`:** Initializes the generator, taking the API model (`ReferenceManual`), output path, and module enabling flag as input.
    * **`generate_description`:**  This is a crucial function. It processes the textual descriptions from the API model, applying formatting like italics (`[[...]]`), links (`[...]()`), and bolding (`*...*`). The regular expressions are key here for identifying these patterns. This suggests the input API data uses a simple markup language.
    * **`function_name` and `generate_function_signature`:**  These focus on generating the function/method signature in the man page, including argument types and formatting.
    * **`generate_function_arg` and `generate_function_argument_section`:** Handle formatting and displaying function/method arguments and their details.
    * **`generate_function` and `generate_object`:**  These are high-level functions that structure the information for individual functions and objects in the man page. They call the lower-level formatting functions.
    * **`generate`:**  The main entry point. It creates a `ManPage` object, sets up the basic sections (NAME, DESCRIPTION, FUNCTIONS, OBJECTS, SEE ALSO), iterates through the API model (functions and objects), calls the appropriate generation methods, and finally writes the output to a file.

**3. Connecting to the Prompts:**

Now, let's address each of the prompt's requirements:

* **Functionality:**  List the actions the code performs. This involves summarizing the purpose of each key method and the overall goal of the script (generating man pages from Frida's API definition).

* **Relationship to Reverse Engineering:**  This requires connecting the tool's purpose (man page generation) to Frida's core function. Frida *is* a reverse engineering tool. Its man pages document its API, which is used for dynamic instrumentation in reverse engineering tasks. Examples would be using Frida functions to inspect memory or intercept function calls.

* **Binary/Low-Level/Kernel/Framework Knowledge:** This requires identifying elements that touch on these areas, even indirectly. The script itself doesn't directly manipulate binaries, but it documents Frida's API, which *does*. Therefore, mentioning Frida's capabilities in these domains (memory manipulation, hooking, interaction with Android internals) and how the man pages facilitate understanding those capabilities is key.

* **Logical Reasoning (Input/Output):**  Consider what the script *takes* as input and *produces* as output. The input is the `ReferenceManual` object (a model of Frida's API). The output is a formatted man page file. A simple example would be a function definition in the input model and the corresponding formatted section in the output man page.

* **User/Programming Errors:**  Think about potential problems a developer using this *script* might encounter, or errors in the *input* data. Examples include incorrect output paths, malformed API data that breaks the regular expressions, or issues with the template markup.

* **User Operation and Debugging:**  Trace the steps a user might take to end up needing to understand this script. This usually involves the software development lifecycle – making changes, encountering errors, and needing to debug the build process. The context of Meson build system is important here.

**4. Refinement and Structuring:**

After the initial analysis, organize the information logically under the headings provided by the prompt. Use clear and concise language. Provide specific code examples where relevant. Explain the *why* behind the connections (e.g., *why* man pages are useful for reverse engineering).

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Focus heavily on the `ManPage` class.
* **Correction:** Realize the `GeneratorMan` class is the core logic and needs more attention. The `ManPage` class is a utility.
* **Initial thought:**  The script doesn't directly interact with binaries.
* **Correction:**  While the script itself doesn't, it generates documentation *for* a tool that does. Emphasize the *indirect* connection and the knowledge the man pages provide.
* **Initial thought:**  Overly technical explanations of man page syntax.
* **Correction:** Focus on the *purpose* of the syntax (formatting, clarity for the user).

By following this breakdown, combining code analysis with an understanding of the broader context of Frida and reverse engineering, we can arrive at a comprehensive and accurate answer to the prompt.
这是一个名为 `generatorman.py` 的 Python 源代码文件，位于 Frida 动态 instrumentation 工具的 `frida/releng/meson/docs/refman/` 目录下。它的主要功能是**根据 Frida 的 API 定义生成 man page 格式的参考手册**。

让我们详细列举其功能，并根据要求进行分析：

**功能列表:**

1. **读取 Frida API 定义:**  虽然代码中没有直接读取 API 定义文件的操作，但它接收一个 `ReferenceManual` 对象作为输入 (`manual: ReferenceManual`)。这个 `ReferenceManual` 对象很可能是在其他地方解析 Frida 的 API 定义文件（例如，可能是某种结构化的数据格式，如 JSON 或 YAML）后创建的。

2. **生成 man page 结构:**  代码中的 `ManPage` 类封装了生成 man page 格式文本的功能。它提供了诸如添加标题 (`title`)、节 (`section`)、子节 (`subsection`)、段落 (`par`)、缩进 (`indent`/`unindent`)、换行 (`br`/`nl`)、内联文本 (`inline`)、加粗 (`bold`) 和斜体 (`italic`) 等方法。

3. **格式化描述文本:** `generate_description` 方法负责处理 API 定义中的描述文本，并将其转换为 man page 格式。它支持以下格式：
    * **斜体:** `[[text]]` 会被转换为 `\fItext\fR` (man page 的斜体标记)。
    * **链接:** `[text](link)` 会被转换为带有脚注引用的斜体文本。链接会被添加到 SEE ALSO 节。
    * **粗体:** `*text*` 会被转换为 `\fBtext\fR` (man page 的粗体标记)。
    * **代码块:** 使用 ``` 分隔的代码块会被正确缩进和格式化。如果代码块的第一行是 "meson"，则会被忽略。
    * **列表:** `- ` 或 `* ` 开头的行会被识别为列表项。

4. **生成函数签名:** `generate_function_signature` 方法根据 `Function` 对象的信息生成函数的 man page 格式签名，包括返回值类型、函数名、参数列表（包括位置参数、可变参数、可选参数和关键字参数）。它还会根据签名长度进行排版，如果过长会分行显示。

5. **生成函数参数描述:** `generate_function_arg` 方法用于生成函数参数的详细描述，包括参数名、类型、是否必需、默认值、可变参数的范围以及任何相关的注释或警告。

6. **生成函数和方法文档:** `generate_function` 方法将 `Function` 对象的所有信息（签名、描述、参数、示例、注释、警告）组合起来，生成完整的函数或方法的 man page 文档。

7. **生成对象文档:** `generate_object` 方法用于生成 `Object` 对象的文档，包括对象的描述、继承关系、被哪些函数返回或扩展等信息，并递归地处理对象的方法。

8. **生成 SEE ALSO 节:**  `generate` 方法会收集在描述文本中找到的所有链接，并在 man page 的末尾生成 "SEE ALSO" 节，列出这些链接及其对应的脚注编号。

9. **主生成流程:** `generate` 方法是入口点，它创建 `ManPage` 对象，设置 man page 的各个节（NAME, DESCRIPTION, FUNCTIONS, OBJECTS, SEE ALSO），遍历 `ReferenceManual` 中的函数和对象，并调用相应的生成方法。

**与逆向方法的关系及举例说明:**

此脚本本身并不直接执行逆向操作，但它是 Frida 工具链的一部分，而 Frida 是一个强大的动态 instrumentation 工具，广泛应用于逆向工程。`generatorman.py` 生成的 man page 提供了 Frida API 的详细文档，这对于逆向工程师理解和使用 Frida 至关重要。

**举例说明:**

假设逆向工程师想要使用 Frida 的 `Memory.readByteArray()` 函数来读取目标进程的内存。如果没有文档，他们需要通过阅读 Frida 的源代码或进行大量的实验来了解该函数的使用方法。

通过 `generatorman.py` 生成的 man page，逆向工程师可以快速查阅 `Memory.readByteArray()` 的文档，了解其参数（例如，要读取的内存地址和大小）、返回值类型以及任何相关的注意事项或示例。例如，他们可能会看到类似以下的 man page 内容：

```
.SS Memory.readByteArray()
.PP
.B SYNOPSIS
.RS 4
\fIArrayBuffer\fR Memory.readByteArray(\fBaddress\fR, \fBlength\fR)
.RE
.PP
.B DESCRIPTION
.RS 4
Reads a chunk of memory.
.RE
.PP
.B POSARGS
.RS 4
.B address
\fINativePointer\fR, \fBrequired\fR
The memory address to read from.
.br
.br
.B length
\fINumber\fR, \fBrequired\fR
The number of bytes to read.
.RE
.PP
.B RETURNS
.RS 4
An ArrayBuffer containing the data read from memory.
.RE
```

这样的文档极大地提高了逆向工程师使用 Frida 的效率，使他们能够更快速地理解和应用 Frida 的功能来分析目标程序。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明:**

虽然 `generatorman.py` 本身是一个高级的 Python 脚本，其生成的文档描述的 Frida API 背后涉及到大量的底层知识。

**举例说明:**

* **二进制底层:**  Frida 的 `Memory` 模块允许用户直接读写目标进程的内存。这需要理解进程的内存布局、地址空间、数据表示（例如，字节序）。`generatorman.py` 生成的 `Memory.readByteArray()` 文档就涉及到如何从指定的内存地址读取指定长度的字节数组，这直接关联到二进制数据的操作。

* **Linux/Android 内核:** Frida 可以 hook 系统调用和内核函数。例如，Frida 可以拦截 `open()` 系统调用来监控文件访问，或 hook `malloc()` 来跟踪内存分配。`generatorman.py` 生成的关于 Frida 中处理进程、线程、模块、内存等的 API 文档，都间接反映了对操作系统内核概念的抽象和封装。

* **Android 框架:** 在 Android 上，Frida 可以 hook Java 方法和 Native 代码，访问 Dalvik/ART 虚拟机内部结构。例如，可以 hook `android.app.Activity` 的生命周期方法。`generatorman.py` 生成的关于 Frida 操作 Java 虚拟机和 Native 层的 API 文档，就涉及到对 Android 框架的理解。

**逻辑推理及假设输入与输出:**

`generatorman.py` 的逻辑主要是遍历 `ReferenceManual` 对象中的数据并按照 man page 的格式进行组织和输出。

**假设输入:**

假设 `ReferenceManual` 对象包含以下一个简单的函数定义：

```python
Function(
    name="my_function",
    description="This is a test function.",
    returns=TypeRef(raw="void"),
    posargs=[
        PosArg(name="arg1", type=TypeRef(raw="int"), description="The first argument."),
        PosArg(name="arg2", type=TypeRef(raw="string"), description="The second argument."),
    ],
    example="my_function(1, 'hello')"
)
```

**预期输出 (部分):**

```
.SS my_function()
.PP
.B SYNOPSIS
.RS 4
\fIvoid\fR my_function(\fBarg1\fR, \fBarg2\fR)
.RE
.PP
.B DESCRIPTION
.RS 4
This is a test function.
.RE
.PP
.B POSARGS
.RS 4
.B arg1
\fIint\fR, \fBrequired\fR
The first argument.
.br
.br
.B arg2
\fIstring\fR, \fBrequired\fR
The second argument.
.RE
.PP
.B EXAMPLE
.RS 4
my_function(1, 'hello')
.RE
```

**用户或编程常见的使用错误及举例说明:**

1. **API 定义不完整或有误:** 如果 `ReferenceManual` 对象中的 API 定义信息不完整或有错误（例如，描述缺失、参数类型错误），生成的 man page 也将是不准确的。

2. **描述文本格式错误:** 用户在编写 API 定义的描述文本时，如果使用了 `generate_description` 方法无法识别的格式标记（例如，拼写错误的标记），这些标记将不会被正确转换，可能导致 man page 显示异常。例如，使用了 `{{text}}` 而不是 `[[text]]` 来表示斜体。

3. **输出路径错误:** 如果在调用 `GeneratorMan` 时提供的输出路径 `out` 不存在或没有写入权限，程序将会报错。

4. **依赖的 `ReferenceManual` 对象未正确生成:** `generatorman.py` 依赖于其他步骤生成 `ReferenceManual` 对象。如果生成 `ReferenceManual` 的过程出错，`generatorman.py` 将无法生成正确的 man page。

**用户操作是如何一步步的到达这里，作为调试线索。**

1. **开发者修改 Frida 源代码:** 假设 Frida 的开发者修改了某个核心功能，例如添加了一个新的 API 函数或修改了现有函数的行为。

2. **更新 API 定义:** 为了反映这些更改，开发者需要更新 Frida 的 API 定义文件。这可能是手动编辑一个结构化数据文件，或者运行一个从源代码提取 API 信息的工具。

3. **构建 Frida 文档:**  Frida 的构建系统（很可能使用 Meson，从文件路径可以看出）会检测到 API 定义文件的更新。构建系统会调用 `generatorman.py` 脚本，并将解析后的 API 定义数据（作为 `ReferenceManual` 对象）传递给它。

4. **执行 `generatorman.py`:**  Meson 构建系统会执行 `generatorman.py` 脚本，指定输出 man page 文件的路径。

5. **生成 man page 文件:** `generatorman.py` 读取 `ReferenceManual` 对象，遍历其中的函数和对象信息，并使用 `ManPage` 类的方法生成 man page 格式的文本，最后将文本写入到指定的输出文件。

6. **用户查看文档:**  最终，Frida 的用户可以通过 `man frida-reference` 命令或者在 Frida 的官方网站上查看生成的 man page，了解 Frida 的最新 API。

**作为调试线索:**

如果生成的 man page 存在问题（例如，函数描述不正确、参数信息缺失），调试线索通常会从以下几个方面入手：

* **检查 API 定义文件:** 确认 API 定义文件中关于该函数或对象的信息是否正确且完整。
* **检查 `generatorman.py` 的逻辑:**  查看 `generate_function`、`generate_object` 和相关的格式化方法是否正确处理了 API 定义中的数据。
* **检查正则表达式:**  如果描述文本的格式有问题，需要检查 `generate_description` 方法中使用的正则表达式是否能正确匹配和转换相应的标记。
* **检查 `ReferenceManual` 对象的生成过程:**  如果 `ReferenceManual` 对象本身包含错误的数据，需要回溯到生成该对象的步骤进行调试。
* **查看构建系统的日志:**  构建系统的日志可能会提供关于 `generatorman.py` 执行过程中的错误信息。

总而言之，`frida/releng/meson/docs/refman/generatorman.py` 是 Frida 文档生成流程中的关键一环，它负责将结构化的 API 定义转换为用户友好的 man page 格式，这对于 Frida 的使用者来说至关重要，尤其是在进行逆向工程时需要快速查阅 API 文档的情况下。

### 提示词
```
这是目录为frida/releng/meson/docs/refman/generatorman.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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