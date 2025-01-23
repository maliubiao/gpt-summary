Response:
Let's break down the thought process for analyzing this Python script.

**1. Initial Understanding - What's the Big Picture?**

The very first line tells us this is `modulate.py`, a tool for Frida. Frida is a dynamic instrumentation toolkit. This immediately suggests the tool will likely interact with running processes or modify binary files in a way that affects their execution. The description mentions ELF and Mach-O, key executable formats on Linux and macOS respectively.

**2. Deconstructing the Code - Function by Function (or Logical Block):**

I'd start by looking at the `main()` function. This is the entry point.

*   **Argument Parsing:**  `argparse` is used. I scan for the arguments and their meanings:
    *   `input`: Path to the binary file.
    *   `--move`:  Seems to be the core manipulation functionality. It takes a "what" (constructor/destructor), a function name, and a "where" (first/last). This strongly hints at reordering function calls.
    *   `--output`: Where the modified binary is saved.
    *   `--nm`, `--readelf`, `--otool`: Paths to external tools. This immediately signals that the script analyzes binary structure.
    *   `--endian`: Specifies the byte order. Important for interpreting binary data.
    *   The `>>>`/`<<<` block: This is unusual. It's designed to pass raw arguments to the external tools. This is a power-user feature for flexibility.

*   **Input Validation:** Checks if `--output` is provided with `--move`, and validates the `what` and `where` arguments.

*   **Toolchain Handling:**  The `Toolchain` class is instantiated. The script allows overriding the default paths to `nm`, `readelf`, and `otool`.

*   **Magic Number Check:** Checks for `MZ` (Windows executable). If it's a Windows binary, it just copies the file. This signifies the tool primarily works with ELF and Mach-O.

*   **`ModuleEditor`:** This looks like the central class for manipulating the binaries. It's initialized based on the input file, endianness, and toolchain.

*   **Applying Moves:**  The loop iterates through the `--move` arguments and calls methods on the `ModuleEditor` (`editor.constructors.move_first()`, etc.).

*   **Dumping or Saving:** If no `--move` is specified, it dumps information. Otherwise, it saves the modified binary.

*   **Error Handling:** Uses `try...except` to catch errors.

Next, I'd examine the `ModuleEditor` class:

*   **Initialization:**  Loads the binary, determines its layout using the `Layout` class, and reads constructor/destructor function pointers.

*   **`dump()`:**  Prints the constructor and destructor function pointers.

*   **`save()`:** Creates a temporary file, copies the original binary, writes the modified function pointer data, and then renames the temporary file. This is a safe way to update files.

*   **`_read_function_pointer_section()`:** This is crucial. It reads the raw bytes representing function pointers and interprets them based on the binary format (ELF or Mach-O). It handles relocation entries (`.rela.dyn` in ELF) which are essential for dynamically linked libraries. It also deals with Apple's pointer authentication on ARM64.

*   **`_write_function_pointer_vector()`:** Writes the modified function pointer data back to the binary. It also handles Apple's pointer authentication.

*   **`_enumerate_rela_dyn_entries()`:** Parses the relocation table in ELF binaries.

Then, the `Toolchain`, `Layout`, `Symbols`, `Section`, `FunctionPointerVector`, `FunctionNotFound`, and `FunctionPointer` classes are examined to understand their roles in the overall process. The `Layout` class's `from_file` method is particularly important as it uses external tools to analyze the binary structure.

**3. Connecting to the Prompts:**

Now, I'd go through the specific questions in the prompt:

*   **Functionality:** Summarize the actions performed by the `main()` function and the `ModuleEditor`.

*   **Relationship to Reverse Engineering:** The ability to inspect and modify constructor/destructor order is directly related to reverse engineering. Think about how changing the order of initialization or cleanup can affect program behavior or reveal hidden logic.

*   **Binary/Kernel/Framework Knowledge:** Identify the code sections that deal with ELF and Mach-O parsing, endianness, relocation entries, and architecture-specific details like ARM64 pointer authentication.

*   **Logical Reasoning:** Find places where assumptions are made or logic is applied based on the input. The `>>>`/`<<<` mechanism is a good example. The conditional logic for ELF vs. Mach-O is another.

*   **User Errors:** Consider what could go wrong. Incorrect file paths, wrong arguments to `--move`, specifying a function that doesn't exist, trying to modify a Windows binary, etc.

*   **User Journey:** Imagine how a user might arrive at using this tool. They might be analyzing malware, trying to understand how a specific library initializes, or perhaps patching a binary. The debugging aspect comes from trying to understand why something isn't working as expected with the binary.

**4. Refining and Structuring the Answer:**

Finally, I'd organize the findings into a clear and structured answer, using headings and bullet points to make it easy to read and understand. I'd provide concrete examples where possible to illustrate the concepts. For instance, when explaining relocation, I'd briefly say why it's necessary.

**Self-Correction/Refinement during the Process:**

*   **Initial Thought:** "This seems like just a simple binary editor."
*   **Correction:**  "No, it's more specific. It focuses on the order of constructor and destructor calls. The parsing of ELF/Mach-O headers and relocation tables indicates a deeper understanding of binary structure."

*   **Initial Thought:**  "The `>>>`/`<<<` thing is weird and probably not important."
*   **Correction:** "It's a clever way to pass complex arguments to the underlying tools, adding significant flexibility, even if it's not the most common use case."

*   **Initial Thought:** "Just list the functions and their descriptions."
*   **Correction:** "The prompt asks for *relationships* to reverse engineering, *connections* to low-level knowledge, and *examples*. I need to go beyond simple descriptions and explain *why* these things are relevant."

By following these steps, moving from a high-level understanding to detailed code analysis, and then specifically addressing each part of the prompt, I can generate a comprehensive and accurate explanation of the `modulate.py` script.
好的，让我们来详细分析一下 `frida/subprojects/frida-core/tools/modulate.py` 这个 Frida 动态 instrumentation 工具的源代码文件。

**功能列举:**

`modulate.py` 的主要功能是**检查和操作 ELF 和 Mach-O 模块（即可执行文件或库文件）**。更具体地说，它允许你：

1. **查看模块的构造函数和析构函数列表及其地址和名称。**  它能解析 ELF 和 Mach-O 格式的特定节区（section）来提取这些信息。
2. **重新排序模块的构造函数和析构函数的执行顺序。**  你可以将特定的构造函数或析构函数移动到列表的开头或末尾。
3. **依赖外部工具链：**  它使用 `nm`、`readelf` (对于 ELF 文件) 和 `otool` (对于 Mach-O 文件) 这些外部工具来解析二进制文件的结构和符号信息。
4. **处理不同的字节序 (Endianness)：**  允许指定目标模块的字节序，以便正确解析数据。
5. **处理符号信息：**  利用符号表来将函数地址转换为函数名称，方便用户理解。
6. **处理重定位表 (Relocation Table)：**  对于动态链接的 ELF 文件，它能正确处理 `.rela.dyn` 节区中的重定位信息，以获取真实的函数地址。
7. **处理 macOS 上 ARM64 架构的指针认证 (Pointer Authentication)：**  能识别和处理苹果在 ARM64 架构上引入的指针认证机制，确保操作的正确性。

**与逆向方法的关系及举例说明:**

`modulate.py` 是一个非常典型的服务于逆向工程的工具，因为它允许在不重新编译程序的情况下修改程序的行为。以下是几个相关的例子：

*   **控制初始化顺序：**  在逆向分析一个复杂的程序时，了解模块的初始化顺序至关重要。有时，特定的漏洞或行为可能发生在特定的初始化阶段。使用 `modulate.py`，你可以将某个可疑的构造函数移动到最前面，以便在程序启动时首先执行它，从而更容易地观察其行为。

    **举例：** 假设你正在逆向一个使用了多个库的应用程序。你怀疑某个库的初始化函数存在漏洞。你可以使用 `modulate.py` 将该库的构造函数移动到最前面，这样在调试器中设置断点，就能更早地命中该函数，进行详细分析。

    ```bash
    python modulate.py target_binary --move constructor vulnerable_library_init first --output modified_binary
    ```

*   **影响资源释放顺序：**  类似地，析构函数的执行顺序也会影响程序的行为，尤其是在资源管理方面。你可以尝试将某个析构函数移动到最后执行，观察是否会导致资源泄漏或其他问题。

    **举例：**  如果你怀疑某个库的析构函数没有正确释放资源，你可以将其移动到最后执行，然后监控程序的内存使用情况。如果内存持续增长，可能就印证了你的怀疑。

    ```bash
    python modulate.py target_binary --move destructor problematic_library_cleanup last --output modified_binary
    ```

*   **绕过某些初始化检查：**  有些程序可能会在构造函数中进行一些安全检查或环境初始化。通过调整构造函数的顺序，你可以尝试绕过这些检查，以便进一步探索程序的其他功能或漏洞。

    **举例：**  一个游戏可能在某个构造函数中检查是否为正版授权。你可以尝试将其移动到最后，看看是否可以在未通过授权检查的情况下运行游戏的其他部分。

*   **动态插桩的辅助：**  `modulate.py` 修改后的二进制文件可以作为 Frida 插桩的目标。例如，你可以先使用 `modulate.py` 将某个关键的构造函数移动到前面，然后使用 Frida 脚本在该构造函数中注入代码，进行更细粒度的监控和操作。

**涉及二进制底层、Linux、Android 内核及框架的知识的举例说明:**

`modulate.py` 的实现需要深入理解二进制文件的底层结构和操作系统的一些概念：

*   **ELF 和 Mach-O 文件格式：**  工具需要解析 ELF 和 Mach-O 文件的头部信息、节区表、符号表、重定位表等结构。例如，它需要知道构造函数和析构函数的指针通常存储在 `.init_array` 和 `.fini_array` 节区（对于 ELF）或 `__DATA.__mod_init_func` 和 `__DATA.__mod_term_func` 节区（对于 Mach-O）中。

    **代码示例：**  `Layout.from_file` 方法中，可以看到它使用 `readelf` 和 `otool` 来获取节区信息，并使用正则表达式 (`elf_section_pattern`, `macho_section_pattern`) 来解析这些工具的输出。

*   **字节序 (Endianness)：**  不同的 CPU 架构使用不同的字节序来存储多字节数据。工具需要知道目标文件的字节序，才能正确地读取和写入函数指针的值。

    **代码示例：**  `ModuleEditor` 的初始化方法接受 `endian` 参数，并根据其值设置 `layout.pointer_format` 和 `layout.u32_format`，用于 `struct.unpack` 和 `struct.pack`。

*   **符号表：**  符号表将函数和全局变量的名称映射到它们的地址。工具使用符号表来将读取到的函数指针地址转换为用户可读的函数名称。

    **代码示例：**  `Symbols.from_file` 方法使用 `nm` 工具来获取符号信息，并将其存储在 `self.items` 字典中。`ModuleEditor._read_function_pointer_section` 方法使用 `layout.symbols.find(address)` 来查找函数地址对应的名称。

*   **重定位表 (Relocation Table)：**  对于动态链接的库，函数的最终地址在加载时才能确定。重定位表包含了需要被修正的地址信息。工具需要解析重定位表，才能获取到构造函数和析构函数的真实地址。

    **代码示例：**  `ModuleEditor._read_function_pointer_section` 方法中，如果检测到 `.rela.dyn` 节区，会遍历该节区，并根据重定位信息更新函数指针的值。

*   **进程内存布局：**  理解程序在内存中的布局，包括代码段、数据段等，有助于理解构造函数和析构函数在程序执行过程中的作用。

*   **macOS ARM64 的指针认证 (Pointer Authentication)：**  苹果在 ARM64 架构上引入了指针认证机制，以提高安全性。工具需要特殊处理这种机制，才能正确地读取和修改函数指针。

    **代码示例：**  在 `ModuleEditor._read_function_pointer_section` 和 `_write_function_pointer_vector` 方法中，可以看到针对 `is_apple_arm64` 的特殊处理逻辑，用于处理指针认证相关的位。

**逻辑推理及假设输入与输出:**

`modulate.py` 的核心逻辑在于解析二进制文件，定位到存储构造函数和析构函数指针的节区，然后根据用户的指令修改这些指针的顺序。

**假设输入：**

*   `input_file`: 一个 ELF 格式的共享库 `libtest.so`。
*   `--move constructor init_function_b first`: 将名为 `init_function_b` 的构造函数移动到最前面。
*   `--move destructor cleanup_function_a last`: 将名为 `cleanup_function_a` 的析构函数移动到最后。
*   `--output output_file`: 将修改后的文件保存为 `modified_libtest.so`。

**逻辑推理过程：**

1. **解析输入文件：**  `modulate.py` 使用 `readelf` 解析 `libtest.so`，获取其节区表和符号表。
2. **定位目标节区：**  根据 ELF 文件格式的约定，找到 `.init_array` (构造函数) 和 `.fini_array` (析构函数) 节区。
3. **读取函数指针：**  从这两个节区读取函数指针的值。
4. **查找函数名称：**  使用符号表将读取到的函数指针地址与函数名称关联起来。
5. **执行移动操作：**
    *   在构造函数列表中找到名为 `init_function_b` 的项，将其从当前位置移除，并插入到列表的开头。
    *   在析构函数列表中找到名为 `cleanup_function_a` 的项，将其从当前位置移除，并添加到列表的末尾。
6. **写入修改后的文件：**  将原始文件内容复制到 `modified_libtest.so`，然后将修改后的构造函数和析构函数指针列表写回到对应的节区。

**预期输出 (modified_libtest.so)：**

*   `modified_libtest.so` 的 `.init_array` 节区中，`init_function_b` 对应的函数指针将位于最前面。
*   `modified_libtest.so` 的 `.fini_array` 节区中，`cleanup_function_a` 对应的函数指针将位于最后面。
*   其他构造函数和析构函数的顺序相对于原始文件可能会发生变化，取决于 `init_function_b` 和 `cleanup_function_a` 在原始文件中的位置。

**涉及用户或编程常见的使用错误及举例说明:**

1. **指定不存在的函数名称：**  如果用户在 `--move` 参数中指定的函数名称在模块的符号表中不存在，程序会抛出 `FunctionNotFound` 异常。

    **举例：** `python modulate.py target_binary --move constructor non_existent_function first --output modified_binary`

    **错误信息：** `argument --move: no constructor named non_existent_function; possible options: ...` (列出实际存在的构造函数名称)。

2. **未指定输出文件：**  如果使用了 `--move` 参数但没有指定 `--output` 参数，程序会报错。

    **举例：** `python modulate.py target_binary --move constructor some_function first`

    **错误信息：** `the following arguments are required: --output`

3. **尝试修改 Windows PE 文件：**  该工具主要针对 ELF 和 Mach-O 文件。如果输入的是 Windows PE 文件，程序会直接复制文件，不做任何修改。

    **举例：** `python modulate.py windows_executable.exe --move constructor some_function first --output modified.exe`

    **结果：** `modified.exe` 将与 `windows_executable.exe` 完全相同。

4. **使用了错误的工具链路径：**  如果用户使用 `--nm`、`--readelf` 或 `--otool` 指定了错误的工具路径，程序可能无法正确解析二进制文件。

    **举例：** `python modulate.py target_binary --readelf /path/to/wrong/readelf ...`

    **结果：**  可能会抛出异常，因为错误的 `readelf` 工具无法正确解析文件，或者输出格式不符合预期。

5. **指定了错误的字节序：**  如果 `--endian` 参数与目标文件的实际字节序不符，程序可能会错误地解析函数指针的值。

    **举例：**  如果目标文件是小端序，但用户指定了 `--endian big`，则读取到的函数指针值可能是不正确的。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

假设用户想要调试一个共享库的初始化过程，并且怀疑某个构造函数的执行顺序有问题。以下是用户可能的操作步骤：

1. **发现问题：** 用户在运行依赖于该共享库的程序时，发现程序在初始化阶段出现异常或行为不符合预期。
2. **怀疑构造函数顺序：**  用户可能通过阅读代码或初步的动态分析，怀疑某个构造函数的执行时机不正确，导致后续的初始化失败。
3. **寻找工具：** 用户搜索或已知有 Frida 这样的动态插桩工具，并且知道 Frida 提供了一些用于操作二进制文件的工具。
4. **使用 `modulate.py` 查看构造函数：** 用户首先使用 `modulate.py` 查看目标共享库的构造函数列表及其顺序：

    ```bash
    python modulate.py /path/to/libtarget.so
    ```

    这将输出构造函数和析构函数的列表及其地址和名称。
5. **确定需要移动的函数：**  用户分析输出的列表，确定需要调整顺序的构造函数，例如 `suspicious_init_function`。
6. **使用 `--move` 参数修改顺序：** 用户使用 `--move` 参数将可疑的构造函数移动到最前面，以便优先执行：

    ```bash
    python modulate.py /path/to/libtarget.so --move constructor suspicious_init_function first --output /tmp/modified_libtarget.so
    ```
7. **替换原始库或加载修改后的库：** 用户可以将原始的共享库替换为修改后的版本（需要谨慎操作），或者在某些环境下，可以使用 `LD_PRELOAD` 等方式加载修改后的库。
8. **重新运行程序并调试：** 用户重新运行依赖于该库的程序，并使用调试器（如 GDB）附加到进程，观察程序的初始化过程。由于 `suspicious_init_function` 被移动到了最前面，用户可以更容易地在该函数中设置断点，检查其行为，并验证是否与之前怀疑的问题有关。
9. **根据调试结果调整：**  根据调试结果，用户可能需要进一步调整构造函数的顺序，或者采取其他逆向分析手段。

总而言之，`modulate.py` 是 Frida 工具链中一个强大且实用的工具，它允许逆向工程师在二进制层面灵活地控制程序的初始化和清理过程，为深入分析和调试提供了有力的支持。

### 提示词
```
这是目录为frida/subprojects/frida-core/tools/modulate.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
import argparse
import hashlib
import os
import re
import shutil
import struct
import subprocess
import sys


elf_class_pattern = re.compile(r"^\s+Class:\s+(.+)$", re.MULTILINE)
elf_machine_pattern = re.compile(r"^\s+Machine:\s+(.+)$", re.MULTILINE)
elf_section_pattern = re.compile(r"^\s+\[\s*\d+]\s+(\S+)?\s+[A-Z]\S+\s+(\S+)\s+(\S+)\s+(\S+)", re.MULTILINE)
macho_section_pattern = re.compile(r"^\s+sectname\s+(\w+)\n\s+segname\s+(\w+)\n\s+addr\s+0x([0-9a-f]+)\n\s+size\s+0x([0-9a-f]+)\n\s+offset\s+(\d+)$", re.MULTILINE)


def main():
    parser = argparse.ArgumentParser(description="Inspect and manipulate ELF and Mach-O modules.")

    parser.add_argument("input", metavar="/path/to/input/module", type=argparse.FileType("rb"))

    the_whats = ('constructor', 'destructor')
    the_wheres = ('first', 'last')

    parser.add_argument("--move", dest="moves", action='append', nargs=3,
        metavar=("|".join(the_whats), 'function_name', "|".join(the_wheres)), type=str, default=[])
    parser.add_argument("--output", metavar="/path/to/output/module", type=str)

    parser.add_argument("--nm", metavar="/path/to/nm", type=str, default=None)
    parser.add_argument("--readelf", metavar="/path/to/readelf", type=str, default=None)
    parser.add_argument("--otool", metavar="/path/to/otool", type=str, default=None)

    the_endians = ('big', 'little')
    parser.add_argument("--endian",  metavar=("|".join(the_endians)), type=str, default='little', choices=the_endians)

    raw_args = []
    tool_argvs = {}
    pending_raw_args = sys.argv[1:]
    while len(pending_raw_args) > 0:
        cur = pending_raw_args.pop(0)
        if cur == ">>>":
            tool_hash = hashlib.sha256()
            tool_argv = []
            while True:
                cur = pending_raw_args.pop(0)
                if cur == "<<<":
                    break
                tool_hash.update(cur.encode("utf-8"))
                tool_argv.append(cur)
            tool_id = tool_hash.hexdigest()
            tool_argvs[tool_id] = tool_argv
            raw_args.append(tool_id)
        else:
            raw_args.append(cur)

    args = parser.parse_args(raw_args)

    if args.input.name == "<stdin>":
        parser.error("reading from stdin is not supported")
    elif len(args.moves) > 0 and args.output is None:
        parser.error("no output file specified")

    for what, function_name, where in args.moves:
        if what not in the_whats:
            parser.error("argument --move: expected {}, got {}".format("|".join(the_whats), what))
        if where not in the_wheres:
            parser.error("argument --move: expected {}, got {}".format("|".join(the_wheres), where))

    toolchain = Toolchain()
    for tool in vars(toolchain).keys():
        path_or_tool_id = getattr(args, tool)
        if path_or_tool_id is not None:
            tool_argv = tool_argvs.get(path_or_tool_id, [path_or_tool_id])
            setattr(toolchain, tool, tool_argv)

    with open(args.input.name, "rb") as f:
        magic = f.read(2)
    if magic == b"MZ":
        # For now we will assume that no processing is needed for our Windows binaries.
        shutil.copy(args.input.name, args.output)
        return

    try:
        editor = ModuleEditor(args.input, args.endian, toolchain)
    except Exception as e:
        print(e, file=sys.stderr)
        sys.exit(1)

    for what, function_name, where in args.moves:
        function_pointers = getattr(editor, what + "s")
        move = getattr(function_pointers, "move_" + where)
        try:
            move(function_name)
        except FunctionNotFound as e:
            using_cxa_atexit = editor.layout.file_format == 'mach-o' and what == 'destructor' and len(e.searched_function_names) == 0
            if not using_cxa_atexit:
                parser.error(e)

    if len(args.moves) == 0:
        editor.dump()
    else:
        editor.save(args.output)


class ModuleEditor(object):
    def __init__(self, module, endian, toolchain):
        self.module = module
        self.endian = endian
        self.toolchain = toolchain

        layout = Layout.from_file(module.name, endian, toolchain)
        self.layout = layout

        sections = layout.sections
        self.constructors = self._read_function_pointer_section(sections.get(layout.constructors_section_name, None), "constructor")
        self.destructors = self._read_function_pointer_section(sections.get(layout.destructors_section_name, None), "destructor")

    def dump(self):
        for i, vector in enumerate([self.constructors, self.destructors]):
            if i > 0:
                print("")
            descriptions = [repr(e) for e in vector.elements]
            if len(descriptions) == 0:
                descriptions.append("(none)")
            print("# {}S\n\t{}".format(vector.label.upper(), "\n\t".join(descriptions)))

    def save(self, destination_path):
        temp_destination_path = destination_path + ".tmp"
        with open(temp_destination_path, "w+b") as destination:
            self.module.seek(0)
            shutil.copyfileobj(self.module, destination)

            self._write_function_pointer_vector(self.constructors, destination)
            self._write_function_pointer_vector(self.destructors, destination)

        shutil.move(temp_destination_path, destination_path)

    def _read_function_pointer_section(self, section, label):
        layout = self.layout

        if section is None:
            return FunctionPointerVector(label, None, None, [], 'pointers', layout)

        values = []
        data = self._read_section_data(section)

        if section.name.endswith("_offsets"):
            encoding = 'offsets'
            u32_size = 4
            u32_format = layout.u32_format
            for i in range(0, len(data), u32_size):
                (value,) = struct.unpack(u32_format, data[i:i + u32_size])
                values.append(value)
        else:
            encoding = 'pointers'
            pointer_size = layout.pointer_size
            pointer_format = layout.pointer_format
            for i in range(0, len(data), pointer_size):
                (value,) = struct.unpack(pointer_format, data[i:i + pointer_size])
                values.append(value)

            if layout.file_format == 'elf' and '.rela.dyn' in layout.sections:
                pending = {}
                for i, val in enumerate(values):
                    pending[section.virtual_address + (i * pointer_size)] = i

                reloc_section = layout.sections['.rela.dyn']
                for offset, r_offset in self._enumerate_rela_dyn_entries(reloc_section):
                    index = pending.pop(r_offset, None)
                    if index is not None:
                        r_addend_offset = reloc_section.file_offset + offset + (2 * pointer_size)
                        self.module.seek(r_addend_offset)
                        (value,) = struct.unpack(pointer_format, self.module.read(pointer_size))
                        values[index] = value

                assert len(pending) == 0

        elements = []
        is_macho = layout.file_format == 'mach-o'
        is_arm = layout.arch_name == 'arm'
        is_apple_arm64 = is_macho and layout.arch_name in ('arm64', 'arm64e')
        symbols = layout.symbols
        for value in values:
            if is_arm:
                address = value & ~1
            elif is_apple_arm64 and encoding == 'pointers':
                # Starting with arm64e, Apple uses the 13 upper bits to encode
                # pointer authentication properties, rebase vs bind, etc.
                top_8_bits     = (value << 13) & 0xff00000000000000
                bottom_43_bits =  value        & 0x000007ffffffffff

                sign_bit_set = (value & (1 << 42)) != 0
                if sign_bit_set:
                    sign_bits = 0x00fff80000000000
                else:
                    sign_bits = 0

                address = top_8_bits | sign_bits | bottom_43_bits
            else:
                address = value

            name = symbols.find(address)
            if name is None:
                name = f"sub_{address:x}"
            if is_macho and name.startswith("_"):
                name = name[1:]

            elements.append(FunctionPointer(value, name))

        return FunctionPointerVector(label, section.file_offset, section.virtual_address, elements, encoding, layout)

    def _read_section_data(self, section):
        self.module.seek(section.file_offset)
        return self.module.read(section.size)

    def _write_function_pointer_vector(self, vector, destination):
        if vector.file_offset is None:
            return

        layout = self.layout
        pointer_size = layout.pointer_size
        pointer_format = layout.pointer_format

        destination.seek(vector.file_offset)

        is_apple_arm64 = layout.file_format == 'mach-o' and layout.arch_name in ('arm64', 'arm64e')
        if is_apple_arm64 and vector.encoding == 'pointers':
            # Due to Apple's stateful rebasing logic we have to be careful so the upper 13 bits
            # are preserved, and we only reorder the values' lower 51 bits.
            for pointer in vector.elements:
                address = pointer.value

                (old_value,) = struct.unpack(pointer_format, destination.read(pointer_size))
                destination.seek(-pointer_size, os.SEEK_CUR)

                meta_bits = old_value & 0xfff8000000000000

                top_8_bits     = (address & 0xff00000000000000) >> 13
                bottom_43_bits =  address & 0x000007ffffffffff

                new_value = meta_bits | top_8_bits | bottom_43_bits

                destination.write(struct.pack(pointer_format, new_value))
        else:
            element_format = pointer_format if vector.encoding == 'pointers' else layout.u32_format
            for pointer in vector.elements:
                destination.write(struct.pack(element_format, pointer.value))

            if layout.file_format == 'elf' and '.rela.dyn' in layout.sections:
                assert vector.encoding == 'pointers'

                pending = {}
                for i, pointer in enumerate(vector.elements):
                    pending[vector.virtual_address + (i * pointer_size)] = pointer

                reloc_section = layout.sections['.rela.dyn']
                for offset, r_offset in self._enumerate_rela_dyn_entries(reloc_section):
                    pointer = pending.pop(r_offset, None)
                    if pointer is not None:
                        r_addend_offset = reloc_section.file_offset + offset + (2 * pointer_size)
                        destination.seek(r_addend_offset)
                        destination.write(struct.pack(pointer_format, pointer.value))

                assert len(pending) == 0

    def _enumerate_rela_dyn_entries(self, section):
        layout = self.layout
        pointer_format = layout.pointer_format
        pointer_size = layout.pointer_size

        data = self._read_section_data(section)
        offset = 0
        size = len(data)
        rela_item_size = 3 * pointer_size

        while offset != size:
            (r_offset,) = struct.unpack(pointer_format, data[offset:offset + pointer_size])
            yield (offset, r_offset)

            offset += rela_item_size


class Toolchain(object):
    def __init__(self):
        self.nm = ["nm"]
        self.readelf = ["readelf"]
        self.otool = ["otool"]

    def __repr__(self):
        return "Toolchain({})".format(", ".join([k + "=" + repr(v) for k, v in vars(self).items()]))


class Layout(object):
    @classmethod
    def from_file(cls, binary_path, endian, toolchain):
        with open(binary_path, "rb") as f:
            magic = f.read(4)
        file_format = 'elf' if magic == b"\x7fELF" else 'mach-o'

        env = make_non_localized_env()

        if file_format == 'elf':
            output = subprocess.check_output(toolchain.readelf + ["--file-header", "--section-headers", binary_path],
                                             env=env).decode('utf-8')

            elf_class = elf_class_pattern.search(output).group(1)
            elf_machine = elf_machine_pattern.search(output).group(1)

            pointer_size = 8 if elf_class == "ELF64" else 4
            arch_name = elf_machine.split(" ")[-1].replace("-", "_").lower()
            if arch_name == "aarch64":
                arch_name = "arm64"

            sections = {}
            for m in elf_section_pattern.finditer(output):
                name, address, offset, size = m.groups()
                sections[name] = Section(name, int(size, 16), int(address, 16), int(offset, 16))
        else:
            output = subprocess.check_output(toolchain.otool + ["-l", binary_path],
                                             env=env).decode('utf-8')

            arch_name = subprocess.check_output(["file", binary_path],
                                                env=env).decode('utf-8').rstrip().split(" ")[-1]
            if arch_name.startswith("arm_"):
                arch_name = 'arm'
            pointer_size = 8 if "64" in arch_name else 4

            sections = {}
            for m in macho_section_pattern.finditer(output):
                section_name, segment_name, address, size, offset = m.groups()
                name = segment_name + "." + section_name
                sections[name] = Section(name, int(size, 16), int(address, 16), int(offset, 10))

        symbols = Symbols.from_file(binary_path, pointer_size, toolchain)

        return Layout(file_format, arch_name, endian, pointer_size, sections, symbols)

    def __init__(self, file_format, arch_name, endian, pointer_size, sections, symbols):
        self.file_format = file_format
        self.arch_name = arch_name
        self.endian = endian
        self.pointer_size = pointer_size
        endian_format = "<" if endian == 'little' else ">"
        size_format = "I" if pointer_size == 4 else "Q"
        self.pointer_format = endian_format + size_format
        self.u32_format = endian_format + "I"

        self.sections = sections
        if file_format == 'elf':
            self.constructors_section_name = ".init_array"
            self.destructors_section_name = ".fini_array"
        else:
            if "__TEXT.__init_offsets" in sections:
                self.constructors_section_name = "__TEXT.__init_offsets"
                self.destructors_section_name = "__TEXT.__term_offsets"
            else:
                section_name = "__DATA_CONST" if "__DATA_CONST.__mod_init_func" in sections else "__DATA"
                self.constructors_section_name = section_name + ".__mod_init_func"
                self.destructors_section_name = section_name + ".__mod_term_func"

        self.symbols = symbols

    def __repr__(self):
        return "Layout(arch_name={}, endian={}, pointer_size={}, sections=<{} items>, symbols={}".format(
            self.arch_name,
            self.endian,
            self.pointer_size,
            len(self.sections),
            repr(self.symbols))


class Symbols(object):
    @classmethod
    def from_file(cls, binary_path, pointer_size, toolchain):
        raw_items = {}
        for line in subprocess.check_output(toolchain.nm + ["--format=posix", binary_path],
                                            env=make_non_localized_env()).decode('utf-8').split("\n"):
            tokens = line.rstrip().split(" ", 3)
            if len(tokens) < 3:
                continue

            name, type, raw_address = tokens[0:3]
            if type.lower() != 't' or name == "":
                continue

            address = int(raw_address, 16)
            if len(tokens) > 3:
                size = int(tokens[3], 16)
            else:
                size = 0

            if address in raw_items:
                (other_name, other_size) = raw_items[address]
                if size <= other_size:
                    continue

            raw_items[address] = (name, size)

        items = dict([(address, name) for address, (name, size) in raw_items.items()])

        return Symbols(items, pointer_size)

    def __init__(self, items, pointer_size):
        self.items = items
        self._pointer_size = pointer_size

    def __repr__(self):
        return "Symbols(items=<{} objects>".format(len(self.items))

    def find(self, address):
        return self.items.get(address, None)


class Section(object):
    def __init__(self, name, size, virtual_address, file_offset):
        self.name = name
        self.size = size
        self.virtual_address = virtual_address
        self.file_offset = file_offset

    def __repr__(self):
        return "Section({})".format(", ".join([k + "=" + repr(v) for k, v in vars(self).items() if v is not None]))


class FunctionPointerVector(object):
    def __init__(self, label, file_offset, virtual_address, elements, encoding, layout):
        self.label = label
        self.file_offset = file_offset
        self.virtual_address = virtual_address
        self.elements = elements
        self.encoding = encoding

        self._layout = layout

    def __repr__(self):
        return repr(self.elements)

    def move_first(self, name):
        e = self.elements.pop(self._index_of(name))
        self.elements.insert(0, e)

    def move_last(self, name):
        e = self.elements.pop(self._index_of(name))
        self.elements.append(e)

    def _index_of(self, name):
        function_names = [e.name for e in self.elements]

        if len(self.elements) == 0:
            raise FunctionNotFound("no {} functions defined".format(self.label), function_names)

        matches = [i for i, e in enumerate(self.elements) if e.name == name]
        if len(matches) == 0:
            raise FunctionNotFound("no {} named {}; possible options: {}".format(self.label, name, ", ".join(function_names)), function_names)

        return matches[0]


class FunctionNotFound(ValueError):
    def __init__(self, message, searched_function_names):
        super().__init__(message)
        self.searched_function_names = searched_function_names


class FunctionPointer(object):
    def __init__(self, value, name):
        self.value = value
        self.name = name

    def __repr__(self):
        return "FunctionPointer(value=0x{:x}, name=\"{}\")".format(self.value, self.name)


def make_non_localized_env():
    env = {}
    env.update(os.environ)
    env["LC_ALL"] = "C"
    return env


main()
```