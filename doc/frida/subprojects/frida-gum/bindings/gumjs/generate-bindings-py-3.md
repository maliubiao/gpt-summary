Response:
Let's break down the thought process for analyzing this Python script. The goal is to understand its function within the Frida ecosystem, specifically regarding dynamic instrumentation and reverse engineering.

**1. Initial Scan and Keyword Recognition:**

The first step is to quickly read through the code, looking for recognizable patterns and keywords related to the task. Some initial observations:

* **File path:** `frida/subprojects/frida-gum/bindings/gumjs/generate-bindings.py`. This immediately suggests it's involved in creating bindings, likely between Gum (Frida's lower-level instrumentation engine) and JavaScript (GumJS).
* **`generate_...` functions:**  Functions like `generate_api_reference`, `generate_enum_api_reference` strongly indicate that the script's purpose is to produce documentation or interface definitions.
* **Markdown (`.md`):**  The script generates `.md` files, further supporting the idea of documentation generation.
* **`Gum...` prefixes:**  These appear frequently (e.g., `GumAddress`, `GumX86Reg`). "Gum" is a key term in Frida, pointing to its core instrumentation library.
* **Architecture-specific handling:**  The script iterates over `architectures` and uses terms like `x86`, `arm`, `arm64`, `mips`, suggesting it handles platform differences.
* **Parsing logic:** Functions like `parse_api` and `parse_arg` imply the script reads some input (likely header files) and extracts information.
* **`Method`, `MethodArgument`, `Component`, `Api` classes:** These suggest an object-oriented approach to representing the structure of the API being processed.
* **`to_camel_case`:** This function is a common utility for converting naming conventions, often used when bridging C/C++ and JavaScript.

**2. Deeper Dive into Key Functions:**

Next, I'd focus on understanding the main functions and their roles:

* **`main` function:** This is the entry point. It configures logging, defines architectures, flavors, namespaces, and the core logic of iterating through components and generating output files. The `process_component` function is called for each component.
* **`process_component` function:** This function orchestrates the generation of different output files (`.md`, `.json`). It calls `parse_api` to extract API information and then uses `generate_api_reference` and `generate_enum_api_reference` to create the Markdown documentation.
* **`parse_api` function:** This function is crucial. It uses regular expressions (`re.finditer`) to find function declarations in `api_header`. It then parses the function name, return type, and arguments using `parse_arg`. The distinction between `static_methods` and `instance_methods` is important.
* **`parse_arg` function:** This function dissects the arguments of API functions, mapping C/C++ types to JavaScript/TypeScript representations. It also handles special cases (e.g., `$label`, `$array`).
* **`generate_api_reference` function:** This function takes the parsed API information and formats it into Markdown, describing the available methods and their arguments.
* **`generate_enum_api_reference` function:**  This handles the generation of documentation for enumerations.

**3. Connecting to Reverse Engineering and Underlying Concepts:**

With a basic understanding of the script's structure, I'd start connecting the pieces to the broader context of Frida and reverse engineering:

* **Dynamic Instrumentation:** The very name "frida" and the file path containing "gum" point to dynamic instrumentation. This script is generating the JavaScript interface for interacting with Frida's instrumentation capabilities.
* **Binary Underpinnings:**  The presence of architecture-specific logic (`x86`, `arm`, etc.), register types (`GumX86Reg`, `arm_reg`), and concepts like calling conventions directly link to the underlying binary execution and architecture.
* **Linux/Android Kernel/Framework:** While this specific script doesn't directly touch kernel code, the generated bindings are used to *interact* with and instrument processes running on these systems. The concepts of memory addresses, registers, and system calls are fundamental.
* **Logical Reasoning:** The script involves parsing, data transformation (C++ types to JavaScript types), and conditional logic (handling static vs. instance methods). The assumptions made during parsing (e.g., how arguments are separated) are examples of logical reasoning.

**4. Addressing Specific Questions:**

Now, I'd go through each of the specific questions in the prompt:

* **Functionality:** Summarize the main purpose – generating JavaScript bindings and API documentation for Frida's Gum library.
* **Relationship to Reverse Engineering:** Provide examples of how the generated API can be used for reverse engineering tasks like hooking functions, reading/writing memory, and inspecting registers.
* **Binary/Kernel/Framework Knowledge:**  Explain how the script's handling of architectures, registers, and calling conventions relates to these low-level concepts.
* **Logical Reasoning:** Give examples of assumptions made during parsing and the expected input/output.
* **User/Programming Errors:**  Think about common mistakes developers might make when using the generated API (e.g., incorrect argument types, typos in register names).
* **User Journey:** Describe the steps a developer would take to end up interacting with or needing to understand this script (e.g., wanting to extend Frida, contributing to the project, debugging binding issues).
* **Overall Function (Part 4):**  Summarize the script's role within the larger Frida project as a binding generator.

**5. Refinement and Structuring:**

Finally, I would organize the information into a clear and coherent answer, using headings and bullet points to improve readability. The process is iterative –  I might go back and forth between understanding specific code sections and connecting them to the bigger picture. For example, realizing the script generates `.md` files would prompt me to investigate the content generation functions like `generate_api_reference`.

By following these steps, we can effectively analyze the provided Python script and understand its function within the context of Frida and dynamic instrumentation.
好的，我们来详细分析一下 `frida/subprojects/frida-gum/bindings/gumjs/generate-bindings.py` 这个 Python 脚本的功能。

**功能归纳**

这个脚本的主要功能是：

**为 Frida 的 Gum 库生成 JavaScript 绑定代码和 API 文档。**

更具体地说，它做了以下几件事：

1. **读取 Gum 库的 C 头文件 (API 定义):**  脚本会读取 Gum 库中定义各种结构体、函数和枚举类型的 C 头文件。这些头文件描述了 Gum 库的接口。
2. **解析 API 定义:**  使用正则表达式等技术，脚本会解析这些头文件，提取出结构体、类、方法、参数、返回值等信息。
3. **生成 JavaScript 包装器代码:**  根据解析到的 API 信息，脚本会生成 JavaScript 代码，这些代码充当 Gum 库 C 函数的包装器。这样，JavaScript 代码就可以调用底层的 Gum 库功能。
4. **生成 API 参考文档:**  脚本还会生成 Markdown 格式的 API 参考文档 (`.md` 文件)，详细描述了 Gum 库中各个类、方法、枚举类型的用途、参数和返回值。
5. **处理不同架构:**  脚本能够处理不同的 CPU 架构（如 x86、ARM、ARM64、MIPS），为每种架构生成相应的绑定和文档。
6. **处理不同的 "flavor" (风格):**  脚本中存在 `flavor` 的概念，例如 "executor" 和 "interceptor"。这可能代表 Gum 库的不同模块或使用方式，脚本会为不同的 flavor 生成不同的绑定和文档。

**与逆向方法的关联及举例说明**

这个脚本生成的 JavaScript 绑定是 Frida 进行动态 instrumentation 的核心组成部分，而动态 instrumentation 是逆向工程中非常重要的技术。通过这些绑定，逆向工程师可以使用 JavaScript 代码来：

* **Hook 函数:**  拦截目标进程中的函数调用，在函数执行前后执行自定义的 JavaScript 代码。
    * **例子:**  假设要分析一个 Android 应用的加密算法，可以使用 Frida hook 该应用中负责加密的关键函数。通过生成的 JavaScript 绑定，你可以使用类似 `Interceptor.attach` 的 API 来实现 hook，并打印函数的参数和返回值，从而理解加密过程。
* **读取和修改内存:**  访问目标进程的内存空间，读取变量的值或修改代码逻辑。
    * **例子:**  在游戏逆向中，可能需要修改游戏中的金币或生命值。通过生成的绑定，可以使用 `Memory.read*` 和 `Memory.write*` 系列的 API 来读取和修改存储这些数值的内存地址。
* **跟踪寄存器:**  在代码执行的特定位置，获取 CPU 寄存器的值。
    * **例子:**  分析恶意软件时，可能需要跟踪关键指令执行前后寄存器的变化，以了解恶意行为的细节。生成的绑定提供了访问寄存器的接口，例如 `context.寄存器名`。
* **调用函数:**  在目标进程的上下文中调用任意函数。
    * **例子:**  如果逆向工程师想利用目标进程中已有的功能，可以使用生成的绑定调用相应的函数，而无需重新实现。
* **修改指令:**  动态修改目标进程的指令，例如跳过某些检查或修改函数行为。
    * **例子:**  破解软件的授权验证时，可以修改验证函数中的跳转指令，使其始终跳转到成功分支。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明**

这个脚本生成的绑定，其底层操作必然涉及到对二进制、操作系统内核和框架的理解：

* **二进制底层:**
    * **指令集架构 (ISA):**  脚本需要处理不同的架构 (x86, ARM 等)，这意味着生成的绑定需要知道如何表示不同架构下的寄存器、指令和调用约定。例如，`GumX86Reg`、`arm_reg` 等类型就对应了不同架构的寄存器。
    * **内存地址:**  Hook 函数、读写内存等操作都涉及到内存地址的概念。生成的 `NativePointer` 类型就是用来表示内存地址的。
    * **调用约定 (Calling Convention):**  不同的平台和编译器有不同的函数调用约定（如何传递参数、返回值等）。脚本中涉及到 `GumCallingConvention` 类型，用于处理不同调用约定的情况。
* **Linux/Android 内核:**
    * **系统调用 (Syscall):**  Frida 的底层操作最终会通过系统调用与操作系统内核交互。虽然这个脚本本身不直接涉及系统调用，但它生成的绑定为用户提供了间接操作系统底层能力的方式。
    * **进程内存管理:**  读取和修改目标进程内存需要理解操作系统如何管理进程的内存空间。
* **Android 框架:**
    * **ART/Dalvik 虚拟机:**  在 Android 平台上，Frida 经常用于 hook Java 层代码。这需要理解 Android 的运行时环境，例如 ART 虚拟机的内部结构和方法调用机制。虽然这个脚本主要关注 Gum 库，但 Gum 库本身可以用来支持对 Java 代码的 instrumentation。

**逻辑推理及假设输入与输出**

脚本的核心逻辑在于解析 C 头文件并将其映射到 JavaScript。

**假设输入:**

一个包含 Gum 库 API 定义的 C 头文件，例如 `gum/gum.h` 的一部分内容：

```c
typedef enum _GumCpuFamily {
  GUM_CPU_FAMILY_X86,
  GUM_CPU_FAMILY_ARM,
  GUM_CPU_FAMILY_ARM64
} GumCpuFamily;

typedef struct _GumAddressRange {
  gpointer base_address;
  gsize size;
} GumAddressRange;

GUM_API GumCpuFamily gum_process_get_cpu_family (void);
GUM_API GumAddressRange * gum_memory_map_find_region_containing (gpointer address);
```

**预期输出 (部分):**

* **JavaScript 代码 (例如在 `gum.js` 中):**

```javascript
/* ... */
const GumCpuFamily = {
  X86: 0,
  ARM: 1,
  ARM64: 2,
};

class AddressRange {
  constructor(handle) {
    this.handle = handle;
  }
  get baseAddress() {
    return new NativePointer(Module._gum_address_range_get_base_address(this.handle));
  }
  get size() {
    return Module._gum_address_range_get_size(this.handle).toNumber();
  }
}

function processGetCpuFamily() {
  return Module._gum_process_get_cpu_family();
}

function memoryMapFindRegionContaining(address) {
  const handle = Module._gum_memory_map_find_region_containing(address);
  return handle.isNull() ? null : new AddressRange(handle);
}
/* ... */
```

* **Markdown 文档 (例如 `gum.md`):**

```markdown
## Gum API Reference

### Enums

-   `CpuFamily`: `X86` `ARM` `ARM64`

### Functions

-   `processGetCpuFamily()`: Gets the CPU family of the current process.
-   `memoryMapFindRegionContaining(address)`: Finds the memory region containing the given address.
    -   `address`: `NativePointerValue`
```

**涉及用户或者编程常见的使用错误及举例说明**

用户在使用生成的 JavaScript 绑定时可能会犯以下错误：

* **类型不匹配:**  传递给函数的参数类型与期望的类型不符。
    * **例子:**  `memoryMapFindRegionContaining` 函数期望一个 `NativePointerValue` 类型的参数，如果用户传递了一个数字或字符串，就会导致错误。
* **忘记转换类型:**  某些 C 类型需要转换为 JavaScript 中对应的类型。
    * **例子:**  从 C 函数返回的 `gpointer` 通常需要转换为 `NativePointer` 对象才能在 JavaScript 中使用。忘记转换可能导致访问无效内存。
* **拼写错误:**  在调用函数或访问属性时拼写错误。
    * **例子:**  错误地将 `processGetCpuFamily()` 写成 `processGetCPUFamily()`。
* **异步操作未处理:**  某些 Frida 的操作是异步的，用户需要正确处理 Promise 或回调。虽然这个脚本主要生成同步绑定，但 Frida 的其他部分涉及到异步操作。
* **未加载模块:**  在使用某些 Gum 库的功能之前，可能需要确保相关的模块已经加载。

**说明用户操作是如何一步步的到达这里，作为调试线索**

一个想要修改或调试 `generate-bindings.py` 脚本的开发者，可能经历了以下步骤：

1. **遇到 Frida 的问题:**  开发者在使用 Frida 进行逆向时，可能发现 Gum 库的某个功能没有相应的 JavaScript 绑定，或者现有的绑定存在 bug。
2. **查看 Frida 源代码:**  为了解决问题或添加新功能，开发者会查看 Frida 的源代码，定位到 Gum 库相关的部分 (`frida-gum`)。
3. **找到绑定生成脚本:**  在 `frida-gum` 的目录结构中，会找到 `bindings/gumjs/generate-bindings.py` 这个脚本，意识到它是负责生成 JavaScript 绑定的。
4. **分析脚本逻辑:**  开发者会阅读脚本的代码，理解它是如何读取 C 头文件、解析 API 信息并生成 JavaScript 代码和文档的。
5. **修改脚本 (可选):**  如果开发者想要添加新的绑定或修复 bug，可能会修改这个脚本，例如添加对新 C 类型或函数的处理。
6. **运行脚本:**  修改后，开发者会运行这个脚本，重新生成 JavaScript 绑定代码和文档。
7. **测试修改:**  开发者会编写 Frida 脚本来测试新生成的绑定是否工作正常。
8. **调试脚本:**  如果生成的绑定有问题，开发者可能会使用 Python 调试器 (如 `pdb`) 来调试 `generate-bindings.py` 脚本，检查解析过程或代码生成逻辑是否存在错误。

**归纳一下它的功能 (作为第 4 部分的总结)**

总而言之，`frida/subprojects/frida-gum/bindings/gumjs/generate-bindings.py` 脚本在 Frida 项目中扮演着至关重要的角色。它的主要功能是 **自动化地将 Gum 库的 C 接口转换为易于在 JavaScript 中使用的绑定**，并 **生成相应的 API 文档**。这极大地简化了 Frida 用户使用 Gum 库进行底层动态 instrumentation 的过程，使得逆向工程师能够方便地通过 JavaScript 代码与目标进程进行交互，执行诸如 hook 函数、读写内存、操作寄存器等关键的逆向分析任务。 该脚本的正确运行是 Frida 强大功能的基石之一。

### 提示词
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/generate-bindings.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共4部分，请归纳一下它的功能
```

### 源代码
```python
""
        elif method.name == "sign":
            description = "sign the given pointer value"

        p = {}
        p.update(params)
        p.update({
            "method_name": method.name_js,
            "method_arglist": ", ".join(arg_names),
            "method_description": description,
        })

        lines.extend("""\
-   `{method_name}({method_arglist})`: {method_description}
""".format(**p).split("\n"))

    return {
        "{0}-{1}.md".format(flavor, name): "\n".join(lines),
    }

def generate_enum_api_reference(name, arch, flavor, api):
    lines = [
        "## {0} enum types".format(arch_names[arch]),
        "",
    ]

    for name, type, prefix, values in writer_enums[arch]:
        display_name = to_camel_case("_".join(name.split("_")[1:]), start_high=True)

        lines.extend(reflow_enum_bulletpoint("-   {0}: `{1}`".format(display_name, "` `".join(values))))

    lines.append("")

    return {
        "{0}-enums.md".format(arch): "\n".join(lines),
    }

def reflow_enum_bulletpoint(bulletpoint):
    result = [bulletpoint]

    indent = 3 * " "

    while True:
        last_line = result[-1]
        if len(last_line) < 80:
            break

        cutoff_index = last_line.rindex("` `", 0, 81) + 1
        before = last_line[:cutoff_index]
        after = indent + last_line[cutoff_index:]

        result[-1] = before
        result.append(after)

    return result

def make_indefinite(noun):
    return make_indefinite_qualifier(noun) + " " + noun

def make_indefinite_qualifier(noun):
    noun_lc = noun.lower()

    exceptions = [
        "ld",
        "lf",
        "rd",
        "x",
    ]
    for prefix in exceptions:
        if noun_lc.startswith(prefix):
            return "an"

    return "an" if noun_lc[0] in ("a", "e", "i", "o", "u") else "a"

class Component(object):
    def __init__(self, name, arch, flavor, namespace):
        self.name = name
        self.arch = arch
        self.flavor = flavor
        self.wrapper_struct_name = to_camel_case("gum_{0}_{1}_{2}".format(namespace, flavor, name), start_high=True)
        self.wrapper_function_prefix = "gum_{0}_{1}_{2}".format(namespace, flavor, name)
        self.impl_struct_name = to_camel_case("gum_{0}_{1}".format(flavor, name), start_high=True)
        self.impl_function_prefix = "gum_{0}_{1}".format(flavor, name)
        self.gumjs_class_name = flavor.title() + name.title()
        self.gumjs_field_prefix = "{0}_{1}".format(flavor, name)
        self.gumjs_function_prefix = "gumjs_{0}_{1}".format(flavor, name)
        self.module_struct_name = to_camel_case("gum_{0}_code_{1}".format(namespace, name), start_high=True)
        self.register_type = "GumX86Reg" if arch == "x86" else arch + "_reg"

class Api(object):
    def __init__(self, static_methods, instance_methods):
        self.static_methods = static_methods
        self.instance_methods = instance_methods

        native_register_type = None
        for method in instance_methods:
            reg_types = [arg.type for arg in method.args if arg.type_converter == "register"]
            if len(reg_types) > 0:
                native_register_type = reg_types[0]
                break
        self.native_register_type = native_register_type

class Method(object):
    def __init__(self, name, return_type, args):
        is_put_array = name.startswith("put_") and name.endswith("_array")
        if is_put_array:
            name = name[:-6]
        is_put_call = is_put_array and name.startswith("put_call_")
        is_put_regs = is_put_array and "_regs" in name

        self.name = name
        self.name_js = to_camel_case(name, start_high=False)

        self.is_put_array = is_put_array
        if is_put_array:
            args.pop(len(args) - 2)

        self.is_put_call = is_put_call
        if is_put_call:
            self.needs_calling_convention_arg = args[0].type == "GumCallingConvention"
            if self.needs_calling_convention_arg:
                args.pop(0)
        else:
            self.needs_calling_convention_arg = False

        self.is_put_regs = is_put_regs

        self.return_type = return_type
        if return_type == "void" or (return_type == "gboolean" and name.startswith("put_")):
            self.return_type_ts = "void"
        elif return_type == "gboolean":
            self.return_type_ts = "boolean"
        elif return_type == "guint":
            self.return_type_ts = "number"
        elif return_type in ("gpointer", "GumAddress"):
            self.return_type_ts = "NativePointer"
        elif return_type == "cs_insn *":
            self.return_type_ts = "Instruction | null"
        else:
            raise ValueError("Unsupported return type: {0}".format(return_type))
        self.args = args

class MethodArgument(object):
    def __init__(self, type, name, arch):
        self.type = type

        name_raw = None
        converter = None

        if type in ("GumX86Reg", "arm_reg", "arm64_reg", "mips_reg"):
            self.type_raw = "const gchar *"
            self.type_format = "s"
            self.type_ts = to_camel_case("x86_register" if type == "GumX86Reg" else type.replace("_reg", "_register"), start_high=True)
            converter = "register"
        elif type in ("arm_sysreg",):
            self.type_raw = "const gchar *"
            self.type_format = "s"
            self.type_ts = "ArmSystemRegister"
            converter = "system_register"
        elif type in ("gint", "gint8", "gint16", "gint32"):
            self.type_raw = "gint"
            self.type_format = "i"
            self.type_ts = "number"
        elif type in ("guint", "guint8", "guint16", "guint32"):
            self.type_raw = "guint"
            self.type_format = "u"
            self.type_ts = "number"
        elif type == "gint64":
            self.type_raw = type
            self.type_format = "q"
            self.type_ts = "number | Int64"
        elif type == "guint64":
            self.type_raw = type
            self.type_format = "Q"
            self.type_ts = "number | UInt64"
        elif type == "gssize":
            self.type_raw = type
            self.type_format = "z"
            self.type_ts = "number | Int64 | UInt64"
        elif type == "gsize":
            self.type_raw = type
            self.type_format = "Z"
            self.type_ts = "number | Int64 | UInt64"
        elif type in ("gpointer", "gconstpointer", "gconstpointer *"):
            self.type_raw = type
            self.type_format = "p"
            self.type_ts = "NativePointerValue"
        elif type == "GumAddress":
            self.type_raw = "gpointer"
            self.type_format = "p"
            self.type_ts = "NativePointerValue"
            converter = "address"
        elif type == "$label":
            self.type_raw = "const gchar *"
            self.type_format = "s"
            self.type_ts = "string"
            converter = "label"
        elif type == "$array":
            self.type_raw = "GBytes *"
            self.type_format = "B~"
            self.type_ts = "ArrayBuffer | number[] | string"
            converter = "bytes"
        elif type == "x86_insn":
            self.type_raw = "const gchar *"
            self.type_format = "s"
            self.type_ts = "X86InstructionId"
            converter = "instruction_id"
        elif type == "GumCallingConvention":
            self.type_raw = "const gchar *"
            self.type_format = "s"
            self.type_ts = "CallingConvention"
            converter = "calling_convention"
        elif type in ("const GumArgument *", "const arm_reg *"):
            self.type_raw = "$array"
            self.type_format = "A"
            if type == "const GumArgument *":
                self.type_ts = arch.title() + "CallArgument[]"
            else:
                self.type_ts = "ArmRegister[]"
            name = "items"
            name_raw = "items_value"
        elif type == "GumBranchHint":
            self.type_raw = "const gchar *"
            self.type_format = "s"
            self.type_ts = "X86BranchHint"
            converter = "branch_hint"
        elif type == "GumX86PtrTarget":
            self.type_raw = "const gchar *"
            self.type_format = "s"
            self.type_ts = "X86PointerTarget"
            converter = "pointer_target"
        elif type in ("arm_cc", "arm64_cc"):
            self.type_raw = "const gchar *"
            self.type_format = "s"
            self.type_ts = "ArmConditionCode" if type == "arm_cc" else "Arm64ConditionCode"
            converter = "condition_code"
        elif type == "arm_shifter":
            self.type_raw = "const gchar *"
            self.type_format = "s"
            self.type_ts = "ArmShifter"
            converter = "shifter"
        elif type == "GumArm64IndexMode":
            self.type_raw = "const gchar *"
            self.type_format = "s"
            self.type_ts = "Arm64IndexMode"
            converter = "index_mode"
        elif type == "GumRelocationScenario":
            self.type_raw = "const gchar *"
            self.type_format = "s"
            self.type_ts = "RelocationScenario"
            converter = "relocator_scenario"
        else:
            raise ValueError("Unhandled type: {0}".format(type))

        self.type_converter = converter

        if name_raw is None:
            name_raw = name if converter is None else "raw_{0}".format(name)

        self.name = name
        self.name_js = to_camel_case(name, start_high=False)
        self.name_raw = name_raw

    def name_raw_for_cpp(self):
        if self.type == "$label":
            return "raw_{0}".format(self.name)
        return self.name_raw

    def type_raw_for_cpp(self):
        if self.type_format == "s":
            return "std::string"
        return self.type_raw

    def type_format_for_cpp(self):
        if self.type_format == "s":
            return "S"
        return self.type_format

    def type_converter_for_cpp(self):
        if self.type == "$label":
            return "label"
        return self.type_converter

def parse_api(name, arch, flavor, api_header, options):
    static_methods = []
    instance_methods = []

    self_type = "{0} * ".format(to_camel_case("gum_{0}_{1}".format(flavor, name), start_high=True))
    ignored_methods = set(options.get('ignore', []))

    put_methods = [(m.group(2), m.group(1), m.group(3)) for m in re.finditer(r"GUM_API ([\w *]+) gum_{0}_{1}_([\w]+) \(([^)]+)\);".format(flavor, name), api_header)]
    for method_name, return_type, raw_arglist in put_methods:
        if method_name in ignored_methods:
            continue

        raw_args = [raw_arg.strip() for raw_arg in raw_arglist.replace("\n", " ").split(", ")]
        if raw_args[-1] == "...":
            continue

        is_static = not raw_args[0].startswith(self_type)

        if not is_static:
            raw_args = raw_args[1:]

        if not is_static and method_name == "put_bytes":
            args = [MethodArgument("$array", "data", arch)]
        else:
            args = [parse_arg(raw_arg, arch) for raw_arg in raw_args]

        method = Method(method_name, return_type, args)
        if is_static:
            static_methods.append(method)
        else:
            instance_methods.append(method)

    return Api(static_methods, instance_methods)

def parse_arg(raw_arg, arch):
    tokens = raw_arg.split(" ")
    raw_type = " ".join(tokens[0:-1])
    name = tokens[-1]
    if raw_type == "gconstpointer":
        if name in ("id", "label_id"):
            return MethodArgument("$label", name, arch)
        return MethodArgument(raw_type, name, arch)
    return MethodArgument(raw_type, name, arch)

def to_camel_case(name, start_high):
    result = ""
    uppercase_next = start_high
    for c in name:
        if c == "_":
            uppercase_next = True
        elif uppercase_next:
            result += c.upper()
            uppercase_next = False
        else:
            result += c.lower()
    return result


if __name__ == '__main__':
    main(sys.argv)
```