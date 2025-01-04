Response:
The user wants a functional summary of the provided Python code, specifically focusing on its relevance to reverse engineering, low-level details (binary, OS kernels, frameworks), logical reasoning, common user errors, and debugging context within the Frida framework.

**Plan:**

1. **Identify the core function:** The code is a part of the Ninja backend for the Meson build system, specifically within the Frida Gum project. Its main role is to translate Meson build descriptions into Ninja build files.
2. **Analyze each function/code block for its purpose:**  Go through the code, understanding what each part does in the context of generating Ninja build rules.
3. **Connect to reverse engineering (if applicable):** Look for code related to compiling, linking, and generating artifacts, which are key steps in preparing code for reverse engineering.
4. **Identify low-level aspects:** Search for interactions with compilers, linkers, and system paths, which often involve binary manipulation, OS specifics, and potentially kernel/framework dependencies.
5. **Pinpoint logical reasoning:**  Look for conditional logic, loops, and data transformations that indicate decision-making within the code.
6. **Anticipate user errors:** Think about how incorrect configuration or usage could lead to issues in the build process.
7. **Establish the user's path to this code:** Consider the high-level actions a user takes that eventually trigger this specific part of the build process.
8. **Summarize the overall functionality.**
这是 `ninjabackend.py` 文件的第四部分，主要负责将 Meson 构建描述转换为 Ninja 构建系统的具体规则和构建步骤。它专注于处理各种编程语言（如 Rust, Swift, C, C++, Fortran 等）的目标构建过程，并生成相应的 Ninja 构建文件条目。

**功能归纳：**

1. **处理 Rust 目标:**
   - `generate_rust_target`:  负责生成 Rust 目标的构建规则。
   - 它会确定 Rust 编译器的调用参数，包括 crate 类型、链接参数、依赖项等。
   - 它还会考虑 Rustup 安装带来的 sysroot 路径问题，并将其添加到链接参数中。
   - 对于 `proc-macro` 类型的 crate，它会记录动态库路径。
   - 最后，它会创建一个 `NinjaBuildElement` 对象来表示该 Rust 目标的构建步骤。

2. **处理 Swift 目标:**
   - `generate_swift_target`: 负责生成 Swift 目标的构建规则。
   - 它会确定 Swift 编译器的调用参数，包括模块名称、优化级别、调试信息、头文件路径、外部依赖等。
   - 它会区分 Swift 源代码文件和其他类型的资源文件。
   - 它会处理 Swift 模块的依赖关系，并生成相应的模块导入路径。
   - 它会为静态库和动态库生成不同的链接参数。
   - 最后，它也会创建一个 `NinjaBuildElement` 对象来表示 Swift 目标的构建步骤。

3. **定义构建规则的辅助方法:**
   - `get_rule_suffix`:  根据目标机器类型返回规则后缀（例如 `_FOR_BUILD`）。
   - `get_compiler_rule_name`: 生成编译器规则的名称。
   - `compiler_to_rule_name`: 根据编译器对象获取对应的规则名称。
   - `compiler_to_pch_rule_name`:  获取预编译头文件的规则名称。

4. **处理 Swift 模块和依赖:**
   - `swift_module_file_name`:  生成 Swift 模块文件的名称。
   - `target_swift_modulename`: 获取 Swift 目标的模块名称。
   - `determine_swift_dep_modules`:  确定当前 Swift 目标依赖的其他 Swift 模块。
   - `determine_swift_external_dep_link_args`:  确定 Swift 目标外部依赖的链接参数。
   - `get_swift_link_deps`: 获取 Swift 目标链接的内部目标文件。
   - `split_swift_generated_sources`:  区分 Swift 目标生成的源代码和其他类型的文件。

5. **生成静态链接规则:**
   - `generate_static_link_rules`:  生成静态链接器的 Ninja 构建规则。
   - 它会处理不同平台的静态链接器命令和参数。
   - 特别处理了 macOS 上 `ar` 命令和 `ranlib` 的用法。
   - 它会根据配置决定是否使用链接池来限制并行链接任务的数量。

6. **生成动态链接规则:**
   - `generate_dynamic_link_rules`: 生成动态链接器的 Ninja 构建规则。
   - 它会为不同的编程语言配置不同的链接器命令和参数。
   - 针对 AIX 系统，有特殊的共享库打包处理。
   - 它还定义了 `SHSYM` 规则，用于生成符号文件（通常用于 Windows 平台的动态库）。

7. **生成各种语言的编译规则:**
   - 提供了针对 Java (`generate_java_compile_rule`)、C# (`generate_cs_compile_rule`)、Vala (`generate_vala_compile_rules`)、Cython (`generate_cython_compile_rules`)、Rust (`generate_rust_compile_rules`) 和 Swift (`generate_swift_compile_rules`) 的编译规则生成方法。
   - 这些方法会根据编译器的特性生成相应的 Ninja 构建规则，包括编译器命令、参数、依赖项处理等。

8. **处理 Fortran 依赖:**
   - `use_dyndeps_for_fortran`: 判断是否使用 Ninja 的动态依赖扫描特性来处理 Fortran 模块依赖。
   - `generate_fortran_dep_hack`:  为旧版本 Ninja 提供 Fortran 依赖处理的 workaround。
   - `scan_fortran_module_outputs`: 扫描 Fortran 源代码，提取模块和子模块的定义信息。
   - `get_fortran_deps`:  获取 Fortran 目标所需的模块依赖文件。

9. **处理 LLVM IR 编译:**
   - `generate_llvm_ir_compile_rule`: 生成 LLVM IR 编译规则。

10. **通用的编译规则生成方法:**
    - `generate_compile_rule_for`:  根据语言名称和编译器对象生成通用的编译规则。
    - `generate_pch_rule_for`: 生成预编译头文件的编译规则。

11. **生成模块扫描规则:**
    - `generate_scanner_rules`: 生成用于扫描模块依赖的规则。

12. **生成所有编译规则:**
    - `generate_compile_rules`: 遍历所有编译器，生成对应的编译规则。

13. **处理生成器列表 (GeneratedList):**
    - `generate_generator_list_rules`: 处理 `GeneratedList` 类型的构建目标，生成相应的 Ninja 构建规则。
    - `replace_paths`: 替换命令参数中的特殊路径占位符。
    - `generate_genlist_for_target`:  为特定的 `GeneratedList` 生成构建规则，处理输入、输出、依赖、自定义命令等。

14. **获取链接参数:**
    - `get_no_stdlib_link_args`: 获取禁用标准库的链接参数。

15. **处理调试信息 (Debug Info):**
    - `get_compile_debugfile_args`:  获取编译时生成调试文件的参数（例如 MSVC 的 PDB 文件）。

**与逆向方法的关系：**

* **编译和链接过程:**  这个文件直接参与了将源代码编译和链接成可执行文件或库的过程。逆向工程通常需要分析这些最终产物。理解构建过程有助于逆向工程师理解目标文件的结构、依赖关系和可能的编译优化。
* **符号文件生成 (`generate_dynamic_link_rules` 中的 `SHSYM`):** 符号文件对于逆向工程至关重要，它提供了函数名、变量名等信息，使得反汇编代码更易读懂。该文件负责生成这些符号文件。
* **理解目标文件结构:**  通过理解构建规则，逆向工程师可以推断出目标文件（如 ELF 或 PE 文件）的各个 section 的用途和内容，例如 `.text` (代码段), `.data` (数据段), `.rodata` (只读数据段) 等。
* **依赖关系分析:** 构建规则中定义了目标文件的依赖关系，这对于逆向工程中理解模块之间的交互非常有用。

**举例说明：**

* **假设逆向一个使用了 Rust 编写的 Frida 插件。**  `generate_rust_target` 函数生成的 Ninja 构建规则会包含 Rust 编译器的调用命令，例如 `rustc src/lib.rs --crate-type cdylib ...`。逆向工程师可以通过查看这些命令来了解编译器的选项、链接的库以及生成的动态库的类型。
* **假设逆向一个使用了 Swift 编写的 Frida 模块。** `generate_swift_target` 函数会生成类似 `swiftc -emit-module ...` 和链接命令。逆向工程师可以从中了解到 Swift 编译器的参数，以及链接了哪些 Swift 模块。
* **假设逆向一个使用了 C++ 编写的 Frida 组件。**  `generate_compile_rule_for` 函数生成的规则会包含 C++ 编译器的调用，例如 `g++ -c src/main.cpp -o build/src/main.o ...`。逆向工程师可以通过分析编译选项（例如优化级别 `-O2` 或调试信息 `-g`) 来理解编译过程对最终二进制文件的影响。

**涉及二进制底层，Linux, Android 内核及框架的知识：**

* **链接器参数 (`-C link-arg`)**: `generate_rust_target` 中处理 `rpath` 的部分直接涉及到二进制文件的加载和动态链接。`rpath` 指定了动态链接器在运行时查找共享库的路径，这对于理解 Linux 和 Android 系统如何加载库至关重要。
* **动态库和共享库 (`isinstance(target, build.SharedLibrary)`)**: 代码中多次涉及到共享库的构建和链接，这需要理解操作系统（如 Linux 和 Android）的动态链接机制，包括符号解析、依赖关系处理等。
* **目标文件格式 (ELF, PE, Mach-O):** 虽然代码本身没有直接操作二进制文件，但它生成的构建规则最终会产生这些格式的文件。理解这些格式对于逆向工程至关重要。
* **系统调用和 ABI (Application Binary Interface):** Frida 作为动态 instrumentation 工具，其底层实现涉及到系统调用和对目标进程的内存操作。理解目标平台的 ABI 可以帮助理解 Frida 如何与目标进程交互。
* **Android 框架:** 如果 Frida 的目标是 Android 应用，那么构建过程可能涉及到 Android SDK 和 NDK，生成的库可能会与 Android 框架交互。

**举例说明：**

* **Linux 的 `rpath`:**  `generate_rust_target` 中添加 `-C link-arg=-Wl,-rpath,...` 到 Rust 编译器的链接参数中，这指示链接器将指定的路径嵌入到生成的动态库中。在 Linux 系统中，当加载该动态库时，动态链接器会首先在这些路径中查找依赖的共享库。
* **Android 的 `DT_RUNPATH`:** 类似于 Linux 的 `rpath`，Android 也使用 `DT_RUNPATH` 来指定动态库的查找路径。
* **符号文件 (.so, .pdb):** `generate_dynamic_link_rules` 中的 `SHSYM` 规则用于生成 Windows 平台上的 PDB 文件，这些文件包含了调试符号信息。在 Linux 上，通常使用 `.so` 文件中的符号表。

**逻辑推理：**

* **假设输入:**  一个 Meson 构建描述文件，定义了一个 Rust 动态库目标 `my_plugin`。
* **输出:**  `generate_rust_target` 函数会根据这个输入，生成一系列 Ninja 构建规则，例如：
   ```ninja
   rule rust_COMPILER
     command = rustc $ARGS $in
     description = Compiling Rust source $in
     deps = gcc
     depfile = $targetdep

   build my_plugin.so: rust_COMPILER src/lib.rs
     ARGS = --crate-type cdylib -C link-arg=-Wl,-rpath,'$ORIGIN/../lib' ...
     targetdep = my_plugin.so.d
     cratetype = cdylib
   ```
* **推理过程:** `generate_rust_target` 函数会分析 `my_plugin` 目标的属性（例如 crate 类型是 `cdylib`），并根据 Rust 编译器的要求，生成相应的命令行参数。它还会根据目标的依赖关系添加额外的构建步骤。

**用户或编程常见的使用错误：**

* **依赖项缺失:** 如果 Meson 构建描述中声明了某个依赖项，但该依赖项没有被正确安装或配置，`generate_rust_target` 或其他相关函数生成的构建规则将无法找到该依赖项，导致编译或链接失败。例如，如果一个 Rust crate 依赖了 `openssl`，但系统中没有安装 `openssl-dev` 包，构建就会出错。
* **路径配置错误:**  如果 Meson 项目的 `meson.build` 文件中配置了错误的头文件搜索路径或库文件搜索路径，编译器或链接器将无法找到所需的资源。
* **编译器版本不兼容:**  如果使用的编译器版本与项目要求的版本不一致，可能会导致编译错误或链接错误。
* **Rust 特定的错误:**
    * **`Cargo.toml` 配置错误:** 如果 Rust 项目的 `Cargo.toml` 文件中存在错误，例如依赖项版本冲突，Rust 编译器将会报错，并导致构建失败。
    * **不正确的 crate 类型:** 如果将一个应该编译为动态库的 crate 错误地配置为静态库，链接过程会出错。

**用户操作如何一步步到达这里作为调试线索：**

1. **用户执行 `meson setup build` 命令:**  这个命令会读取 `meson.build` 文件，并根据用户的配置生成构建系统所需的文件，包括 Ninja 的构建文件。
2. **Meson 解析 `meson.build` 文件:** Meson 会分析项目中的目标 (targets)，包括 Rust 库、Swift 模块等。
3. **对于 Rust 目标:** Meson 会调用相应的构建后端模块，最终会到达 `frida/subprojects/frida-gum/releng/meson/mesonbuild/backend/ninjabackend.py` 文件中的 `generate_rust_target` 函数。
4. **`generate_rust_target` 函数被调用:** 该函数接收 Rust 目标的信息作为输入，并生成相应的 Ninja 构建规则。
5. **用户执行 `ninja` 命令:** Ninja 会读取生成的构建文件，并按照规则执行编译和链接操作。
6. **如果构建失败:** 用户可以查看 Ninja 的输出，其中会包含编译器或链接器的错误信息，以及执行的命令。这些命令正是 `ninjabackend.py` 中生成的。

**调试线索：**

* 查看生成的 `build.ninja` 文件，搜索与特定目标相关的构建规则，可以了解 Meson 生成了哪些编译和链接命令。
* 比对生成的命令与编译器或链接器的官方文档，可以判断是否存在参数错误或遗漏。
* 检查 Meson 的配置输出，确保依赖项和路径配置正确。
* 如果涉及到 Rust，检查 `Cargo.toml` 文件和 Rust 编译器的错误信息。

总而言之，`ninjabackend.py` 的这一部分是 Frida 构建系统中至关重要的一部分，它负责将高级的构建描述转换为底层的构建指令，使得 Ninja 能够高效地完成软件的编译和链接过程。 理解它的功能有助于深入理解 Frida 的构建过程，并为逆向工程和问题排查提供有价值的信息。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/releng/meson/mesonbuild/backend/ninjabackend.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共6部分，请归纳一下它的功能

"""
                     target.build_rpath,
                                       target.install_rpath))
            # ... but then add rustc's sysroot to account for rustup
            # installations
            for rpath_arg in rpath_args:
                args += ['-C', 'link-arg=' + rpath_arg + ':' + os.path.join(rustc.get_sysroot(), 'lib')]

        proc_macro_dylib_path = None
        if getattr(target, 'rust_crate_type', '') == 'proc-macro':
            proc_macro_dylib_path = os.path.abspath(os.path.join(target.subdir, target.get_filename()))

        self._add_rust_project_entry(target.name,
                                     os.path.abspath(os.path.join(self.environment.build_dir, main_rust_file)),
                                     args,
                                     bool(target.subproject),
                                     proc_macro_dylib_path,
                                     project_deps)

        compiler_name = self.compiler_to_rule_name(rustc)
        element = NinjaBuildElement(self.all_outputs, target_name, compiler_name, main_rust_file)
        if orderdeps:
            element.add_orderdep(orderdeps)
        if deps:
            element.add_dep(deps)
        element.add_item('ARGS', args)
        element.add_item('targetdep', depfile)
        element.add_item('cratetype', cratetype)
        self.add_build(element)
        if isinstance(target, build.SharedLibrary):
            self.generate_shsym(target)
        self.create_target_source_introspection(target, rustc, args, [main_rust_file], [])

    @staticmethod
    def get_rule_suffix(for_machine: MachineChoice) -> str:
        return PerMachine('_FOR_BUILD', '')[for_machine]

    @classmethod
    def get_compiler_rule_name(cls, lang: str, for_machine: MachineChoice, mode: str = 'COMPILER') -> str:
        return f'{lang}_{mode}{cls.get_rule_suffix(for_machine)}'

    @classmethod
    def compiler_to_rule_name(cls, compiler: Compiler) -> str:
        return cls.get_compiler_rule_name(compiler.get_language(), compiler.for_machine, compiler.mode)

    @classmethod
    def compiler_to_pch_rule_name(cls, compiler: Compiler) -> str:
        return cls.get_compiler_rule_name(compiler.get_language(), compiler.for_machine, 'PCH')

    def swift_module_file_name(self, target):
        return os.path.join(self.get_target_private_dir(target),
                            self.target_swift_modulename(target) + '.swiftmodule')

    def target_swift_modulename(self, target):
        return target.name

    def determine_swift_dep_modules(self, target):
        result = []
        for l in target.link_targets:
            if self.is_swift_target(l):
                result.append(self.swift_module_file_name(l))
        return result

    def determine_swift_external_dep_link_args(self, target, swiftc):
        args = []
        for dep in target.get_external_deps():
            args += swiftc.get_dependency_link_args(dep)
        for d in target.get_dependencies():
            if isinstance(d, build.StaticLibrary):
                for dep in d.get_external_deps():
                    args += swiftc.get_dependency_link_args(dep)

        deduped_args = []
        seen_libs = set()
        for arg in args:
            if arg.startswith("-l"):
                if arg not in seen_libs:
                    deduped_args.append(arg)
                    seen_libs.add(arg)
            else:
                deduped_args.append(arg)
        return deduped_args

    def get_swift_link_deps(self, target):
        result = []
        for l in target.link_targets:
            result.append(self.get_target_filename(l))
        return result

    def split_swift_generated_sources(self, target):
        all_srcs = self.get_target_generated_sources(target)
        srcs = []
        others = []
        for i in all_srcs:
            if i.endswith('.swift'):
                srcs.append(i)
            else:
                others.append(i)
        return srcs, others

    def generate_swift_target(self, target):
        module_name = self.target_swift_modulename(target)
        swiftc = target.compilers['swift']
        abssrc = []
        relsrc = []
        abs_headers = []
        header_imports = []
        for i in target.get_sources():
            if swiftc.can_compile(i):
                rels = i.rel_to_builddir(self.build_to_src)
                abss = os.path.normpath(os.path.join(self.environment.get_build_dir(), rels))
                relsrc.append(rels)
                abssrc.append(abss)
            elif self.environment.is_header(i):
                relh = i.rel_to_builddir(self.build_to_src)
                absh = os.path.normpath(os.path.join(self.environment.get_build_dir(), relh))
                abs_headers.append(absh)
                header_imports += swiftc.get_header_import_args(absh)
            else:
                raise InvalidArguments(f'Swift target {target.get_basename()} contains a non-swift source file.')
        os.makedirs(self.get_target_private_dir_abs(target), exist_ok=True)
        compile_args = swiftc.get_mod_gen_args()
        compile_args += swiftc.get_compile_only_args()
        compile_args += swiftc.get_optimization_args(target.get_option(OptionKey('optimization')))
        compile_args += swiftc.get_debug_args(target.get_option(OptionKey('debug')))
        compile_args += swiftc.get_module_args(module_name)
        compile_args += self.build.get_project_args(swiftc, target.subproject, target.for_machine)
        compile_args += self.build.get_global_args(swiftc, target.for_machine)
        for i in reversed(target.get_include_dirs()):
            for d in i.expand_incdirs(self.environment.get_build_dir()):
                srctreedir = os.path.normpath(os.path.join(self.environment.get_build_dir(), self.build_to_src, d.source))
                compile_args += swiftc.get_include_args(srctreedir, i.is_system)
                if d.build is not None:
                    buildtreedir = os.path.normpath(os.path.join(self.environment.get_build_dir(), d.build))
                    compile_args += swiftc.get_include_args(buildtreedir, i.is_system)
        for dep in reversed(target.get_external_deps()):
            if not dep.found():
                continue
            compile_args += swiftc.get_dependency_compile_args(dep)
        compile_args += target.get_extra_args('swift')
        link_args = swiftc.get_output_args(os.path.join(self.environment.get_build_dir(), self.get_target_filename(target)))
        link_args += self.build.get_project_link_args(swiftc, target.subproject, target.for_machine)
        link_args += self.build.get_global_link_args(swiftc, target.for_machine)
        rundir = self.get_target_private_dir(target)
        out_module_name = self.swift_module_file_name(target)
        in_module_files = self.determine_swift_dep_modules(target)
        abs_module_dirs = self.determine_swift_dep_dirs(target)
        module_includes = []
        for x in abs_module_dirs:
            module_includes += swiftc.get_include_args(x, False)
        link_deps = self.get_swift_link_deps(target)
        abs_link_deps = [os.path.join(self.environment.get_build_dir(), x) for x in link_deps]
        for d in target.link_targets:
            reldir = self.get_target_dir(d)
            if reldir == '':
                reldir = '.'
            link_args += ['-L', os.path.normpath(os.path.join(self.environment.get_build_dir(), reldir))]
        link_args += self.determine_swift_external_dep_link_args(target, swiftc)
        link_args += target.link_args
        (rel_generated, other_generated) = self.split_swift_generated_sources(target)
        abs_generated = [os.path.join(self.environment.get_build_dir(), x) for x in rel_generated]
        # We need absolute paths because swiftc needs to be invoked in a subdir
        # and this is the easiest way about it.
        objects = [] # Relative to swift invocation dir
        rel_objects = [] # Relative to build.ninja
        for i in abssrc + abs_generated:
            base = os.path.basename(i)
            oname = os.path.splitext(base)[0] + '.o'
            objects.append(oname)
            rel_objects.append(os.path.join(self.get_target_private_dir(target), oname))

        rulename = self.compiler_to_rule_name(swiftc)

        elem = NinjaBuildElement(self.all_outputs, [out_module_name] + rel_objects, rulename, abssrc)
        elem.add_dep(in_module_files + rel_generated + other_generated)
        elem.add_dep(abs_headers)
        elem.add_item('ARGS', compile_args + header_imports + abs_generated + module_includes)
        elem.add_item('RUNDIR', rundir)
        self.add_build(elem)
        if isinstance(target, build.StaticLibrary):
            elem = self.generate_link(target, self.get_target_filename(target),
                                      rel_objects, self.build.static_linker[target.for_machine])
            self.add_build(elem)
        else:
            elem = NinjaBuildElement(self.all_outputs, self.get_target_filename(target), rulename, [])
            elem.add_dep(rel_objects)
            elem.add_dep(link_deps)
            elem.add_dep([self.get_dependency_filename(t) for t in target.link_depends])
            if isinstance(target, build.Executable):
                link_args += swiftc.get_std_exe_link_args()
            else:
                link_args += swiftc.get_std_shared_lib_link_args()
            elem.add_item('ARGS', link_args + objects + abs_link_deps)
            elem.add_item('RUNDIR', rundir)
            self.add_build(elem)
        # Introspection information
        self.create_target_source_introspection(target, swiftc, compile_args + header_imports + module_includes, relsrc, rel_generated)

    def _rsp_options(self, tool: T.Union['Compiler', 'StaticLinker', 'DynamicLinker']) -> T.Dict[str, T.Union[bool, RSPFileSyntax]]:
        """Helper method to get rsp options.

        rsp_file_syntax() is only guaranteed to be implemented if
        can_linker_accept_rsp() returns True.
        """
        options = {'rspable': tool.can_linker_accept_rsp()}
        if options['rspable']:
            options['rspfile_quote_style'] = tool.rsp_file_syntax()
        return options

    def generate_static_link_rules(self):
        num_pools = self.environment.coredata.options[OptionKey('backend_max_links')].value
        if 'java' in self.environment.coredata.compilers.host:
            self.generate_java_link()
        for for_machine in MachineChoice:
            static_linker = self.build.static_linker[for_machine]
            if static_linker is None:
                continue
            rule = 'STATIC_LINKER{}'.format(self.get_rule_suffix(for_machine))
            cmdlist: T.List[T.Union[str, NinjaCommandArg]] = []
            args = ['$in']
            # FIXME: Must normalize file names with pathlib.Path before writing
            #        them out to fix this properly on Windows. See:
            # https://github.com/mesonbuild/meson/issues/1517
            # https://github.com/mesonbuild/meson/issues/1526
            if isinstance(static_linker, ArLikeLinker) and not mesonlib.is_windows():
                # `ar` has no options to overwrite archives. It always appends,
                # which is never what we want. Delete an existing library first if
                # it exists. https://github.com/mesonbuild/meson/issues/1355
                cmdlist = execute_wrapper + [c.format('$out') for c in rmfile_prefix]
            cmdlist += static_linker.get_exelist()
            cmdlist += ['$LINK_ARGS']
            cmdlist += NinjaCommandArg.list(static_linker.get_output_args('$out'), Quoting.none)
            # The default ar on MacOS (at least through version 12), does not
            # add extern'd variables to the symbol table by default, and
            # requires that apple's ranlib be called with a special flag
            # instead after linking
            if static_linker.id == 'applear':
                # This is a bit of a hack, but we assume that that we won't need
                # an rspfile on MacOS, otherwise the arguments are passed to
                # ranlib, not to ar
                cmdlist.extend(args)
                args = []
                # Ensure that we use the user-specified ranlib if any, and
                # fallback to just picking up some ranlib otherwise
                ranlib = self.environment.lookup_binary_entry(for_machine, 'ranlib')
                if ranlib is None:
                    ranlib = ['ranlib']
                cmdlist.extend(['&&'] + ranlib + ['-c', '$out'])
            description = 'Linking static target $out'
            if num_pools > 0:
                pool = 'pool = link_pool'
            else:
                pool = None

            options = self._rsp_options(static_linker)
            self.add_rule(NinjaRule(rule, cmdlist, args, description, **options, extra=pool))

    def generate_dynamic_link_rules(self):
        num_pools = self.environment.coredata.options[OptionKey('backend_max_links')].value
        for for_machine in MachineChoice:
            complist = self.environment.coredata.compilers[for_machine]
            for langname, compiler in complist.items():
                if langname in {'java', 'vala', 'rust', 'cs', 'cython'}:
                    continue
                rule = '{}_LINKER{}'.format(langname, self.get_rule_suffix(for_machine))
                command = compiler.get_linker_exelist()
                args = ['$ARGS'] + NinjaCommandArg.list(compiler.get_linker_output_args('$out'), Quoting.none) + ['$in', '$LINK_ARGS']
                description = 'Linking target $out'
                if num_pools > 0:
                    pool = 'pool = link_pool'
                else:
                    pool = None

                options = self._rsp_options(compiler)
                self.add_rule(NinjaRule(rule, command, args, description, **options, extra=pool))
            if self.environment.machines[for_machine].is_aix():
                rule = 'AIX_LINKER{}'.format(self.get_rule_suffix(for_machine))
                description = 'Archiving AIX shared library'
                cmdlist = compiler.get_command_to_archive_shlib()
                args = []
                options = {}
                self.add_rule(NinjaRule(rule, cmdlist, args, description, **options, extra=None))

        args = self.environment.get_build_command() + \
            ['--internal',
             'symbolextractor',
             self.environment.get_build_dir(),
             '$in',
             '$IMPLIB',
             '$out']
        symrule = 'SHSYM'
        symcmd = args + ['$CROSS']
        syndesc = 'Generating symbol file $out'
        synstat = 'restat = 1'
        self.add_rule(NinjaRule(symrule, symcmd, [], syndesc, extra=synstat))

    def generate_java_compile_rule(self, compiler):
        rule = self.compiler_to_rule_name(compiler)
        command = compiler.get_exelist() + ['$ARGS', '$in']
        description = 'Compiling Java object $in'
        self.add_rule(NinjaRule(rule, command, [], description))

    def generate_cs_compile_rule(self, compiler: 'CsCompiler') -> None:
        rule = self.compiler_to_rule_name(compiler)
        command = compiler.get_exelist()
        args = ['$ARGS', '$in']
        description = 'Compiling C Sharp target $out'
        self.add_rule(NinjaRule(rule, command, args, description,
                                rspable=mesonlib.is_windows(),
                                rspfile_quote_style=compiler.rsp_file_syntax()))

    def generate_vala_compile_rules(self, compiler):
        rule = self.compiler_to_rule_name(compiler)
        command = compiler.get_exelist() + ['$ARGS', '$in']
        description = 'Compiling Vala source $in'
        self.add_rule(NinjaRule(rule, command, [], description, extra='restat = 1'))

    def generate_cython_compile_rules(self, compiler: 'Compiler') -> None:
        rule = self.compiler_to_rule_name(compiler)
        description = 'Compiling Cython source $in'
        command = compiler.get_exelist()

        depargs = compiler.get_dependency_gen_args('$out', '$DEPFILE')
        depfile = '$out.dep' if depargs else None

        args = depargs + ['$ARGS', '$in']
        args += NinjaCommandArg.list(compiler.get_output_args('$out'), Quoting.none)
        self.add_rule(NinjaRule(rule, command + args, [],
                                description,
                                depfile=depfile,
                                extra='restat = 1'))

    def generate_rust_compile_rules(self, compiler):
        rule = self.compiler_to_rule_name(compiler)
        command = compiler.get_exelist() + ['$ARGS', '$in']
        description = 'Compiling Rust source $in'
        depfile = '$targetdep'
        depstyle = 'gcc'
        self.add_rule(NinjaRule(rule, command, [], description, deps=depstyle,
                                depfile=depfile))

    def generate_swift_compile_rules(self, compiler):
        rule = self.compiler_to_rule_name(compiler)
        full_exe = self.environment.get_build_command() + [
            '--internal',
            'dirchanger',
            '$RUNDIR',
        ]
        invoc = full_exe + compiler.get_exelist()
        command = invoc + ['$ARGS', '$in']
        description = 'Compiling Swift source $in'
        self.add_rule(NinjaRule(rule, command, [], description))

    def use_dyndeps_for_fortran(self) -> bool:
        '''Use the new Ninja feature for scanning dependencies during build,
        rather than up front. Remove this and all old scanning code once Ninja
        minimum version is bumped to 1.10.'''
        return mesonlib.version_compare(self.ninja_version, '>=1.10.0')

    def generate_fortran_dep_hack(self, crstr: str) -> None:
        if self.use_dyndeps_for_fortran():
            return
        rule = f'FORTRAN_DEP_HACK{crstr}'
        if mesonlib.is_windows():
            cmd = ['cmd', '/C']
        else:
            cmd = ['true']
        self.add_rule_comment(NinjaComment('''Workaround for these issues:
https://groups.google.com/forum/#!topic/ninja-build/j-2RfBIOd_8
https://gcc.gnu.org/bugzilla/show_bug.cgi?id=47485'''))
        self.add_rule(NinjaRule(rule, cmd, [], 'Dep hack', extra='restat = 1'))

    def generate_llvm_ir_compile_rule(self, compiler):
        if self.created_llvm_ir_rule[compiler.for_machine]:
            return
        rule = self.get_compiler_rule_name('llvm_ir', compiler.for_machine)
        command = compiler.get_exelist()
        args = ['$ARGS'] + NinjaCommandArg.list(compiler.get_output_args('$out'), Quoting.none) + compiler.get_compile_only_args() + ['$in']
        description = 'Compiling LLVM IR object $in'

        options = self._rsp_options(compiler)

        self.add_rule(NinjaRule(rule, command, args, description, **options))
        self.created_llvm_ir_rule[compiler.for_machine] = True

    def generate_compile_rule_for(self, langname, compiler):
        if langname == 'java':
            self.generate_java_compile_rule(compiler)
            return
        if langname == 'cs':
            if self.environment.machines.matches_build_machine(compiler.for_machine):
                self.generate_cs_compile_rule(compiler)
            return
        if langname == 'vala':
            self.generate_vala_compile_rules(compiler)
            return
        if langname == 'rust':
            self.generate_rust_compile_rules(compiler)
            return
        if langname == 'swift':
            self.generate_swift_compile_rules(compiler)
            return
        if langname == 'cython':
            self.generate_cython_compile_rules(compiler)
            return
        crstr = self.get_rule_suffix(compiler.for_machine)
        options = self._rsp_options(compiler)
        if langname == 'fortran':
            self.generate_fortran_dep_hack(crstr)
            # gfortran does not update the modification time of *.mod files, therefore restat is needed.
            # See also: https://github.com/ninja-build/ninja/pull/2275
            options['extra'] = 'restat = 1'
        rule = self.compiler_to_rule_name(compiler)
        if langname == 'cuda':
            # for cuda, we manually escape target name ($out) as $CUDA_ESCAPED_TARGET because nvcc doesn't support `-MQ` flag
            depargs = NinjaCommandArg.list(compiler.get_dependency_gen_args('$CUDA_ESCAPED_TARGET', '$DEPFILE'), Quoting.none)
        else:
            depargs = NinjaCommandArg.list(compiler.get_dependency_gen_args('$out', '$DEPFILE'), Quoting.none)
        command = compiler.get_exelist()
        args = ['$ARGS'] + depargs + NinjaCommandArg.list(compiler.get_output_args('$out'), Quoting.none) + compiler.get_compile_only_args() + ['$in']
        description = f'Compiling {compiler.get_display_language()} object $out'
        if compiler.get_argument_syntax() == 'msvc':
            deps = 'msvc'
            depfile = None
        else:
            deps = 'gcc'
            depfile = '$DEPFILE'
        self.add_rule(NinjaRule(rule, command, args, description, **options,
                                deps=deps, depfile=depfile))

    def generate_pch_rule_for(self, langname, compiler):
        if langname not in {'c', 'cpp'}:
            return
        rule = self.compiler_to_pch_rule_name(compiler)
        depargs = compiler.get_dependency_gen_args('$out', '$DEPFILE')

        if compiler.get_argument_syntax() == 'msvc':
            output = []
        else:
            output = NinjaCommandArg.list(compiler.get_output_args('$out'), Quoting.none)

        if 'mwcc' in compiler.id:
            output[0].s = '-precompile'
            command = compiler.get_exelist() + ['$ARGS'] + depargs + output + ['$in'] # '-c' must be removed
        else:
            command = compiler.get_exelist() + ['$ARGS'] + depargs + output + compiler.get_compile_only_args() + ['$in']
        description = 'Precompiling header $in'
        if compiler.get_argument_syntax() == 'msvc':
            deps = 'msvc'
            depfile = None
        else:
            deps = 'gcc'
            depfile = '$DEPFILE'
        self.add_rule(NinjaRule(rule, command, [], description, deps=deps,
                                depfile=depfile))

    def generate_scanner_rules(self):
        rulename = 'depscan'
        if rulename in self.ruledict:
            # Scanning command is the same for native and cross compilation.
            return
        command = self.environment.get_build_command() + \
            ['--internal', 'depscan']
        args = ['$picklefile', '$out', '$in']
        description = 'Module scanner.'
        rule = NinjaRule(rulename, command, args, description)
        self.add_rule(rule)

    def generate_compile_rules(self):
        for for_machine in MachineChoice:
            clist = self.environment.coredata.compilers[for_machine]
            for langname, compiler in clist.items():
                if compiler.get_id() == 'clang':
                    self.generate_llvm_ir_compile_rule(compiler)
                self.generate_compile_rule_for(langname, compiler)
                self.generate_pch_rule_for(langname, compiler)
                for mode in compiler.get_modes():
                    self.generate_compile_rule_for(langname, mode)

    def generate_generator_list_rules(self, target):
        # CustomTargets have already written their rules and
        # CustomTargetIndexes don't actually get generated, so write rules for
        # GeneratedLists here
        for genlist in target.get_generated_sources():
            if isinstance(genlist, (build.CustomTarget, build.CustomTargetIndex)):
                continue
            self.generate_genlist_for_target(genlist, target)

    def replace_paths(self, target, args, override_subdir=None):
        if override_subdir:
            source_target_dir = os.path.join(self.build_to_src, override_subdir)
        else:
            source_target_dir = self.get_target_source_dir(target)
        relout = self.get_target_private_dir(target)
        args = [x.replace("@SOURCE_DIR@", self.build_to_src).replace("@BUILD_DIR@", relout)
                for x in args]
        args = [x.replace("@CURRENT_SOURCE_DIR@", source_target_dir) for x in args]
        args = [x.replace("@SOURCE_ROOT@", self.build_to_src).replace("@BUILD_ROOT@", '.')
                for x in args]
        args = [x.replace('\\', '/') for x in args]
        return args

    def generate_genlist_for_target(self, genlist: build.GeneratedList, target: build.BuildTarget) -> None:
        for x in genlist.depends:
            if isinstance(x, build.GeneratedList):
                self.generate_genlist_for_target(x, target)
        generator = genlist.get_generator()
        subdir = genlist.subdir
        exe = generator.get_exe()
        infilelist = genlist.get_inputs()
        outfilelist = genlist.get_outputs()
        extra_dependencies = self.get_target_depend_files(genlist)
        for i, curfile in enumerate(infilelist):
            if len(generator.outputs) == 1:
                sole_output = os.path.join(self.get_target_private_dir(target), outfilelist[i])
            else:
                sole_output = f'{curfile}'
            infilename = curfile.rel_to_builddir(self.build_to_src, self.get_target_private_dir(target))
            base_args = generator.get_arglist(infilename)
            outfiles = genlist.get_outputs_for(curfile)
            outfiles = [os.path.join(self.get_target_private_dir(target), of) for of in outfiles]
            if generator.depfile is None:
                rulename = 'CUSTOM_COMMAND'
                args = base_args
            else:
                rulename = 'CUSTOM_COMMAND_DEP'
                depfilename = generator.get_dep_outname(infilename)
                depfile = os.path.join(self.get_target_private_dir(target), depfilename)
                args = [x.replace('@DEPFILE@', depfile) for x in base_args]
            args = [x.replace("@INPUT@", infilename).replace('@OUTPUT@', sole_output)
                    for x in args]
            args = self.replace_outputs(args, self.get_target_private_dir(target), outfilelist)
            # We have consumed output files, so drop them from the list of remaining outputs.
            if len(generator.outputs) > 1:
                outfilelist = outfilelist[len(generator.outputs):]
            args = self.replace_paths(target, args, override_subdir=subdir)
            cmdlist, reason = self.as_meson_exe_cmdline(exe,
                                                        self.replace_extra_args(args, genlist),
                                                        capture=outfiles[0] if generator.capture else None,
                                                        env=genlist.env)
            abs_pdir = os.path.join(self.environment.get_build_dir(), self.get_target_dir(target))
            os.makedirs(abs_pdir, exist_ok=True)

            elem = NinjaBuildElement(self.all_outputs, outfiles, rulename, infilename)
            elem.add_dep([self.get_target_filename(x) for x in generator.depends])
            if generator.depfile is not None:
                elem.add_item('DEPFILE', depfile)
            if len(extra_dependencies) > 0:
                elem.add_dep(extra_dependencies)

            if len(generator.outputs) == 1:
                what = f'{sole_output!r}'
            else:
                # since there are multiple outputs, we log the source that caused the rebuild
                what = f'from {sole_output!r}'
            if reason:
                reason = f' (wrapped by meson {reason})'
            elem.add_item('DESC', f'Generating {what}{reason}')

            if isinstance(exe, build.BuildTarget):
                elem.add_dep(self.get_target_filename(exe))
            elem.add_item('COMMAND', cmdlist)
            self.add_build(elem)

    def scan_fortran_module_outputs(self, target):
        """
        Find all module and submodule made available in a Fortran code file.
        """
        if self.use_dyndeps_for_fortran():
            return
        compiler = None
        # TODO other compilers
        for lang, c in self.environment.coredata.compilers.host.items():
            if lang == 'fortran':
                compiler = c
                break
        if compiler is None:
            self.fortran_deps[target.get_basename()] = {}
            return

        modre = re.compile(FORTRAN_MODULE_PAT, re.IGNORECASE)
        submodre = re.compile(FORTRAN_SUBMOD_PAT, re.IGNORECASE)
        module_files = {}
        submodule_files = {}
        for s in target.get_sources():
            # FIXME, does not work for Fortran sources generated by
            # custom_target() and generator() as those are run after
            # the configuration (configure_file() is OK)
            if not compiler.can_compile(s):
                continue
            filename = s.absolute_path(self.environment.get_source_dir(),
                                       self.environment.get_build_dir())
            # Fortran keywords must be ASCII.
            with open(filename, encoding='ascii', errors='ignore') as f:
                for line in f:
                    modmatch = modre.match(line)
                    if modmatch is not None:
                        modname = modmatch.group(1).lower()
                        if modname in module_files:
                            raise InvalidArguments(
                                f'Namespace collision: module {modname} defined in '
                                f'two files {module_files[modname]} and {s}.')
                        module_files[modname] = s
                    else:
                        submodmatch = submodre.match(line)
                        if submodmatch is not None:
                            # '_' is arbitrarily used to distinguish submod from mod.
                            parents = submodmatch.group(1).lower().split(':')
                            submodname = parents[0] + '_' + submodmatch.group(2).lower()

                            if submodname in submodule_files:
                                raise InvalidArguments(
                                    f'Namespace collision: submodule {submodname} defined in '
                                    f'two files {submodule_files[submodname]} and {s}.')
                            submodule_files[submodname] = s

        self.fortran_deps[target.get_basename()] = {**module_files, **submodule_files}

    def get_fortran_deps(self, compiler: FortranCompiler, src: Path, target) -> T.List[str]:
        """
        Find all module and submodule needed by a Fortran target
        """
        if self.use_dyndeps_for_fortran():
            return []

        dirname = Path(self.get_target_private_dir(target))
        tdeps = self.fortran_deps[target.get_basename()]
        srcdir = Path(self.source_dir)

        mod_files = _scan_fortran_file_deps(src, srcdir, dirname, tdeps, compiler)
        return mod_files

    def get_no_stdlib_link_args(self, target, linker):
        if hasattr(linker, 'language') and linker.language in self.build.stdlibs[target.for_machine]:
            return linker.get_no_stdlib_link_args()
        return []

    def get_compile_debugfile_args(self, compiler, target, objfile):
        # The way MSVC uses PDB files is documented exactly nowhere so
        # the following is what we have been able to decipher via
        # reverse engineering.
        #
        # Each object file gets the path of its PDB file written
        # inside it.  This can be either the final PDB (for, say,
        # foo.exe) or an object pdb (for foo.obj). If the former, then
        # each compilation step locks the pdb file for writing, which
        # is a bottleneck and object files from one target cannot be
        # used in a different target. The latter seems to be the
        # sensible one (and what Unix does) but there is a catch.  If
        # you try to use precompiled headers MSVC will error out
        # because both source and pch pdbs go in the same file and
        # they must be the same.
        #
        # This means:
        #
        # - pch files must be compiled anew for every object file (negating
        #   the entire point of having them in the first place)
        # - when using pch, output must go to the target pdb
        #
        # Since both of these are broken in some way, use the one that
        # works for each target. This unfortunately means that you
        # can't combine pch and object extraction in a single target.
        #
        # PDB files also lead to filename collisions. A target foo.exe
        # has a corresponding foo.pdb. A shared library foo.dll _also_
        # has pdb 
"""


```