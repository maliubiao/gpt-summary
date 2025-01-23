Response:
My thinking process to arrive at the summary of `ninjabackend.py` went through several stages:

1. **Understanding the Context:** The initial prompt clearly states this is a source code file for the Ninja backend of the Frida dynamic instrumentation tool. This immediately tells me the core function will be about *generating Ninja build files*. Ninja is a build system that focuses on speed, so efficiency in generating these files is likely a key concern.

2. **Initial Code Scan (High-Level):** I quickly scanned the code looking for key classes, methods, and patterns. I noticed:
    *  Lots of methods related to specific languages (`generate_rust_target`, `generate_swift_target`, `generate_java_compile_rule`, etc.). This suggests the file handles building projects with different programming languages.
    *  Methods with names like `generate_compile_rules`, `generate_static_link_rules`, `generate_dynamic_link_rules`. This confirms the file is responsible for defining how different build actions are performed.
    *  Use of the term "target" frequently, indicating the file processes the build targets defined in the Meson project.
    *  Interaction with "compiler" objects, suggesting it knows how to invoke compilers for various languages.
    *  Methods dealing with dependencies (`determine_swift_dep_modules`, `get_fortran_deps`), indicating it manages how build order is determined.
    *  The presence of "rules" and the `add_rule` method points to the core function of generating Ninja build rules.
    *  The `NinjaBuildElement` class seems to be a data structure for representing a build step.

3. **Focusing on Key Functionality (Medium-Level):**  I started to connect the dots and form hypotheses about the file's core responsibilities:
    * **Target Processing:** It iterates through build targets defined in the Meson project.
    * **Rule Generation:**  It translates Meson's build definitions into specific Ninja build rules. This includes defining the commands to execute (compilers, linkers, custom commands), dependencies, and outputs.
    * **Language Support:**  It has specific logic for handling different programming languages (C, C++, Rust, Swift, Java, etc.), taking into account their specific compilation and linking needs.
    * **Dependency Management:**  It figures out the dependencies between targets and source files, ensuring the build happens in the correct order. This includes both internal (within the project) and external dependencies (libraries).
    * **Custom Commands:** It supports arbitrary commands defined by the user in the Meson build definition.
    * **Ninja Integration:**  It interacts with Ninja-specific concepts like rules, pools, and response files.

4. **Identifying Specific Examples and Concepts (Low-Level - Drawing from the Code Snippet):**  I looked for concrete examples within the provided code to illustrate the higher-level functionalities:
    * **Rust Example:** The `generate_rust_target` method shows how Rust projects are compiled, including setting up rpaths, handling proc macros, and using `rustc`. This directly relates to reverse engineering as understanding how Rust binaries are linked is crucial for analysis.
    * **Swift Example:** `generate_swift_target` demonstrates how Swift modules are built, including handling dependencies and module imports. This is relevant to understanding the structure of Swift applications.
    * **Linker Rules:** The `generate_static_link_rules` and `generate_dynamic_link_rules` methods show how static and shared libraries are created, involving linker commands and handling platform-specific differences (like `ar` on macOS). This is fundamental to reverse engineering as understanding linking is vital for dissecting binaries.
    * **Dependency Tracking:** The Fortran dependency handling (`scan_fortran_module_outputs`, `get_fortran_deps`) shows an example of how the backend deals with complex language-specific dependency tracking.
    * **Response Files:** The `_rsp_options` method and mentions of `rspable` illustrate how the backend handles very long command lines by writing arguments to a file, a common technique in build systems.
    * **Ninja Build Element:** This class clearly encapsulates the information needed for a single Ninja build rule.

5. **Synthesizing the Summary:**  Finally, I organized the identified functionalities into a coherent summary, grouping related aspects and using clear and concise language. I tried to follow the prompt's instructions to highlight connections to reverse engineering, low-level concepts, and common errors (though the provided snippet didn't directly show error handling). I also made sure to address the "user operation" aspect by explaining how Meson's configuration and target definitions lead to this code being executed.

Essentially, my process was a top-down and bottom-up approach, starting with the overall purpose and then drilling down into specific examples to solidify understanding, and then back up to synthesize a comprehensive summary. The prompt's specific questions guided my analysis and ensured I covered the relevant aspects of the code.
这是 frida 动态 instrumentation 工具的源代码文件 `frida/subprojects/frida-qml/releng/meson/mesonbuild/backend/ninjabackend.py` 的第 4 部分，总共 6 部分。从提供的代码片段来看，这个 Python 文件是 Meson 构建系统的一个后端实现，专门用于生成 Ninja 构建文件。Ninja 是一个专注于速度的小型构建系统。

**功能归纳:**

这个代码片段主要负责将 Meson 的构建描述（例如目标、依赖、编译器选项等）转换为 Ninja 构建系统能够理解的 `build.ninja` 文件。其核心功能可以归纳为以下几点：

1. **目标编译和链接规则生成:** 针对不同的编程语言（Rust, Swift, Java, C#, Vala, Cython, Fortran 等），生成对应的编译和链接规则。这些规则定义了如何将源代码编译成目标文件，以及如何将目标文件链接成可执行文件或库文件。

2. **语言特定的处理:**  针对不同语言的特性，进行特定的处理。例如：
    * **Rust:**  处理 `rustup` 安装的 sysroot 路径，添加 proc-macro 的依赖。
    * **Swift:**  处理模块依赖，外部依赖链接参数，以及 Swift 特有的编译和链接选项。
    * **Fortran:**  处理 Fortran 模块依赖，并针对 `gfortran` 的特性添加 `restat = 1` 选项以解决模块文件修改时间不更新的问题。
    * **MSVC:** 特殊处理 MSVC 的依赖扫描和 PDB 文件生成。

3. **依赖关系管理:**  处理目标之间的依赖关系，确保构建顺序正确。这包括内部依赖（项目内的其他目标）和外部依赖（系统库或第三方库）。

4. **自定义命令支持:**  支持 Meson 中定义的自定义命令（`custom_target` 和 `generator`），并将其转换为 Ninja 的构建规则。

5. **预编译头文件 (PCH) 支持:**  生成预编译头文件的构建规则，以提高编译速度。

6. **响应文件 (rsp) 处理:**  对于参数过多的情况，生成响应文件以避免命令行长度限制。

7. **符号文件生成 (SHSYM):** 对于共享库，生成符号文件的规则。

8. **生成器列表 (GeneratedList) 处理:**  处理通过生成器动态生成源文件的场景。

**与逆向方法的关联举例说明:**

* **二进制结构理解:**  了解链接过程对于逆向工程至关重要。这个文件生成了链接命令，可以帮助逆向工程师理解目标文件是如何组合成最终的可执行文件或库文件的。例如，查看 `generate_static_link_rules` 和 `generate_dynamic_link_rules` 可以了解静态库和共享库的链接方式，这有助于理解二进制文件的结构和依赖关系。
* **符号信息:**  `generate_shsym` 函数生成符号文件，这些符号文件包含了函数名、变量名等信息，对于逆向工程中的符号恢复和分析非常有帮助。了解符号文件的生成过程可以更好地利用这些信息。
* **依赖关系分析:**  逆向工程中，理解目标文件的依赖关系对于分析其功能和行为至关重要。这个文件处理了各种依赖关系，生成的 Ninja 文件清晰地展示了这些依赖，有助于逆向工程师进行分析。例如，观察 `determine_swift_dep_modules` 和 `get_swift_link_deps` 可以了解 Swift 模块之间的依赖关系。
* **Rust 的 proc-macro:**  `generate_rust_target` 中处理 proc-macro 的部分，可以帮助理解 Rust 宏在编译时的展开和链接方式，这对于逆向使用了大量宏的 Rust 代码很有帮助。

**涉及二进制底层、Linux、Android 内核及框架的知识举例说明:**

* **Rpath 处理 (Linux):** `generate_rust_target` 中处理 `target.build_rpath` 和 `target.install_rpath` 的部分，涉及到 Linux 下的运行时库搜索路径 (Rpath)。这与理解 Linux 下动态链接库的加载机制密切相关，是理解二进制底层运行的基础。
* **动态链接库链接参数:**  `generate_dynamic_link_rules` 生成的链接命令中会包含 `-L` 和 `-l` 等参数，这些是标准的 Linux 下动态链接库的链接参数。
* **静态链接库的处理:** `generate_static_link_rules`  展示了如何使用 `ar` 或类似工具创建静态链接库，这涉及到对目标文件进行归档的底层操作。
* **符号提取 (SHSYM):**  `generate_dynamic_link_rules` 中生成的 `SHSYM` 规则，涉及到从共享库中提取符号信息，这对于理解动态链接库的接口和依赖至关重要，也与操作系统底层的符号管理机制有关。
* **Android 相关的知识可能体现在 Frida 的其他部分**，因为这个文件是 Frida-QML 子项目的一部分，可能涉及到 QML 引擎与 Frida 核心的交互。虽然当前代码片段没有直接体现 Android 内核或框架的知识，但其生成的构建结果最终会部署到目标平台，可能包括 Android。

**逻辑推理的假设输入与输出:**

**假设输入:** 一个 Meson 构建定义，描述了一个名为 `mylib` 的 Rust 共享库目标，依赖于另一个名为 `utils` 的静态库目标。

**预期输出 (部分 Ninja 构建文件内容):**

```ninja
rule RUST_COMPILER
  command = rustc $ARGS $in
  description = Compiling Rust source $in
  deps = gcc
  depfile = $targetdep

build subprojects/mylib/mylib.rlib: RUST_COMPILER mylib.rs | subprojects/utils/libutils.a
  ARGS = ... (Rust 编译参数)
  targetdep = subprojects/mylib/mylib.d

rule C_LINKER
  command = cc $ARGS $LINK_ARGS $in -o $out
  description = Linking target $out

build mylib.so: C_LINKER subprojects/mylib/mylib.rlib
  ARGS = -shared
  LINK_ARGS = -L. -lutils ... (链接参数，包含依赖的静态库路径)
```

**用户或编程常见的使用错误举例说明:**

* **依赖循环:** 如果 Meson 构建定义中存在循环依赖（例如，目标 A 依赖于目标 B，而目标 B 又依赖于目标 A），这个后端会根据 Meson 的处理结果生成相应的 Ninja 文件，但 Ninja 在构建时会报错。用户可能错误地定义了依赖关系。
* **源文件路径错误:** 如果 Meson 构建定义中指定的源文件路径不存在，这个后端会尝试生成构建规则，但 Ninja 在执行编译时会找不到文件。用户需要仔细检查 Meson 构建定义中的路径。
* **编译器选项错误:** 用户在 Meson 中传递了无效的编译器选项，这个后端会将其传递给 Ninja，最终导致编译器报错。用户需要熟悉所用编译器的选项。
* **自定义命令错误:**  用户定义的自定义命令执行失败（例如，脚本不存在或权限不足），Ninja 会报告错误。用户需要确保自定义命令的正确性。

**用户操作如何一步步到达这里作为调试线索:**

1. **用户编写 Meson 构建文件 (meson.build):**  用户首先需要创建描述项目结构和构建规则的 `meson.build` 文件。
2. **用户运行 `meson setup builddir`:** 用户在命令行中运行 `meson setup builddir` 命令，Meson 会读取 `meson.build` 文件并进行配置。
3. **Meson 配置阶段:** 在配置阶段，Meson 会解析构建定义，检查依赖，并生成一个内部的构建表示。
4. **Meson 后端选择:**  由于用户没有显式指定后端，Meson 会根据系统环境或默认设置选择 Ninja 后端。
5. **`ninjabackend.py` 执行:** Meson 调用 `ninjabackend.py` 脚本，并将内部的构建表示传递给它。
6. **目标遍历和规则生成:** `ninjabackend.py` 中的代码会遍历所有的构建目标，并调用相应的方法（例如 `generate_rust_target`, `generate_swift_target` 等）来生成 Ninja 构建规则。
7. **写入 `build.ninja` 文件:**  最终，生成的 Ninja 构建规则会被写入到 `builddir/build.ninja` 文件中。

如果用户在构建过程中遇到问题，例如编译错误或链接错误，他们可以查看 `build.ninja` 文件，了解具体的编译和链接命令，以及依赖关系，从而找到调试线索。例如，检查某个目标的 `build` 行可以查看其依赖项和使用的编译器命令。

总而言之，`ninjabackend.py` 是 Meson 构建系统的核心组件，负责将高级的构建描述转换为底层的构建指令，使得 Ninja 能够高效地执行构建过程。它需要深入理解各种编程语言的编译和链接流程，以及底层操作系统的工作原理。

### 提示词
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/backend/ninjabackend.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共6部分，请归纳一下它的功能
```

### 源代码
```python
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
```