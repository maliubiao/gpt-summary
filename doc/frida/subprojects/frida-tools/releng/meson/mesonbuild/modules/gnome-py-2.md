Response:
The user wants to understand the functionality of the `gnome.py` file within the Frida project, specifically focusing on how it relates to reverse engineering, low-level aspects, and potential user errors. I need to go through the code snippets provided and analyze each function.

**Plan:**

1. **Identify Functions:** List all the functions defined in the provided code.
2. **Analyze Functionality:** For each function, determine its purpose based on its name, arguments, and the operations it performs.
3. **Reverse Engineering Relevance:**  Consider if the function's actions are directly or indirectly helpful in reverse engineering. Frida is a dynamic instrumentation tool, and this file seems to handle build processes for GNOME-related components. Documentation generation and code generation can be useful in understanding the target application.
4. **Low-Level/Kernel/Framework Relevance:** Check if the function interacts with build tools or processes that are related to compiling or linking, which can involve understanding how binaries are structured.
5. **Logical Inference:**  Look for conditional logic or data transformations and try to infer the input and output.
6. **User Errors:** Identify common mistakes a user might make when using these functions based on the arguments they expect.
7. **User Path to Code:**  Think about how a developer using Frida might end up triggering the execution of code within this file. It's likely part of the build process when including GNOME components.
8. **Summarize Functionality (Part 3):** Consolidate the findings for the provided code snippets.
好的，这是frida项目 `frida/subprojects/frida-tools/releng/meson/mesonbuild/modules/gnome.py` 源代码文件的第三部分，让我们来分析一下它的功能：

**已提供的代码段中的功能归纳：**

这段代码主要定义了 `gnome` meson 模块中的以下函数，这些函数用于构建和管理 GNOME 项目相关的各种工件：

*   **`gtkdoc(self, state, args, kwargs)`:**  用于处理 `gtkdoc` 文档的生成。它使用 `gtkdoc` 工具族（如 `gtkdoc-scan`, `gtkdoc-mkdb` 等）来扫描源代码、创建文档数据库和生成 HTML 文档。
*   **`_get_build_args(self, c_args, inc_dirs, deps, state, depends)`:**  一个辅助函数，用于构建传递给 `gtkdoc` 等工具的编译和链接参数，包括 C 预处理宏、包含路径和依赖库。
*   **`gtkdoc_html_dir(self, state, args, kwargs)`:**  返回 `gtk-doc` 生成的 HTML 文档的默认安装目录。
*   **`gdbus_codegen(self, state, args, kwargs)`:**  用于调用 `gdbus-codegen` 工具，根据 GDBus XML 接口定义文件生成 C 代码（头文件和源文件）。
*   **`mkenums(self, state, args, kwargs)`:**  用于调用 `glib-mkenums` 工具，根据输入文件（通常包含枚举类型的定义）生成 C 代码的枚举类型声明和定义。
*   **`mkenums_simple(self, state, args, kwargs)`:**  提供了一种更简化的方式来调用 `glib-mkenums`，通过预定义的模板来生成枚举类型的头文件和源文件。
*   **`_make_mkenum_impl(self, state, sources, output, cmd, *, install=False, install_dir=None, depends=None)`:**  `mkenums` 和 `mkenums_simple` 函数的内部实现，负责创建实际的 `CustomTarget` 来执行 `glib-mkenums` 命令。
*   **`genmarshal(self, state, args, kwargs)`:** 用于调用 `glib-genmarshal` 工具，根据输入文件生成 GObject 属性序列化和反序列化的胶水代码。

**功能详细说明和与逆向的相关性：**

1. **`gtkdoc`**:
    *   **功能:**  自动生成 C 代码的 API 文档。
    *   **逆向相关性:**  生成的文档可以帮助逆向工程师理解目标库或框架的 API 和用法，无需完全依赖反汇编代码。文档提供了函数、结构体、枚举等的说明，是理解代码功能的重要参考。
    *   **举例:**  假设你正在逆向一个使用 GTK 的应用程序。如果该应用程序的构建系统使用了 `gnome.gtkdoc`，你可以查看生成的 HTML 文档来了解 GTK 库中特定函数的参数、返回值和作用，而不用直接去分析 GTK 的二进制代码。

2. **`_get_build_args`**:
    *   **功能:**  为构建命令准备编译和链接参数。
    *   **逆向相关性:** 虽然不直接参与逆向过程，但理解构建参数可以帮助逆向工程师了解代码是如何编译的，例如使用了哪些宏定义、包含了哪些头文件路径、链接了哪些库。这些信息有助于理解代码的上下文和依赖关系。
    *   **举例:**  如果构建参数中包含了某个特定的宏定义，逆向工程师在分析反汇编代码时可以注意到条件编译的影响。

3. **`gtkdoc_html_dir`**:
    *   **功能:**  提供 `gtk-doc` HTML 文档的默认安装路径。
    *   **逆向相关性:**  方便逆向工程师找到生成的文档。

4. **`gdbus_codegen`**:
    *   **功能:**  根据 GDBus XML 接口描述文件生成 C 代码。
    *   **逆向相关性:**  GDBus 常用于进程间通信。生成的 C 代码定义了接口的代理和骨架，逆向工程师可以通过分析这些代码来了解应用程序或服务提供的接口和消息格式，从而理解其通信协议和功能。
    *   **假设输入:** 一个名为 `org.example.MyInterface.xml` 的 GDBus 接口描述文件。
    *   **可能输出:**  `org-example-MyInterface.c` 和 `org-example-MyInterface.h` 包含了接口的 C 代码实现。

5. **`mkenums`**:
    *   **功能:**  根据输入文件生成 C 语言的枚举类型定义。
    *   **逆向相关性:**  枚举类型通常用于表示状态、选项等。通过分析生成的枚举类型定义，逆向工程师可以更容易地理解程序中的各种状态和标志的含义，这比直接分析数字常量更直观。
    *   **假设输入:** 一个包含枚举值定义的文件 `my_enums.txt`。
    *   **可能输出:**  `my-enums.h` 或 `my-enums.c` 包含了 `my_enums.txt` 中定义的枚举类型的 C 代码。

6. **`mkenums_simple`**:
    *   **功能:**  简化版的 `mkenums`，使用预定义的模板生成枚举类型。
    *   **逆向相关性:**  与 `mkenums` 类似，帮助理解程序中的枚举类型。

7. **`_make_mkenum_impl`**:
    *   **功能:**  实际执行 `glib-mkenums` 命令。
    *   **逆向相关性:**  不直接相关，但它是 `mkenums` 和 `mkenums_simple` 功能的基础。

8. **`genmarshal`**:
    *   **功能:**  生成用于序列化和反序列化 GObject 属性的代码。
    *   **逆向相关性:**  GObject 是 GNOME 中常用的对象模型。生成的代码处理对象的属性的编码和解码。逆向工程师可以通过分析这些代码来了解对象的结构和属性的类型，以及它们是如何在内存中表示和在不同组件之间传递的。这对于理解对象的状态和行为至关重要。

**二进制底层、Linux、Android 内核及框架的知识：**

*   **二进制底层:**  这些函数最终会影响生成的二进制代码的结构。例如，`gdbus_codegen` 生成的代码涉及到函数调用、数据结构定义，这些都会被编译成机器码。`genmarshal` 生成的代码处理内存中的数据布局和字节流的转换。
*   **Linux:** 这些工具（`gtkdoc`, `gdbus-codegen`, `glib-mkenums`, `glib-genmarshal`）通常是 Linux 系统上的标准开发工具。它们依赖于 Linux 的文件系统、进程管理等概念。
*   **Android 内核及框架:**  虽然这些函数主要是为 GNOME 项目设计的，但如果 Frida 用于分析 Android 上的 GNOME 组件或使用了类似 GObject 模型的框架，那么这些工具的输出可能会间接地涉及到 Android 框架的理解。例如，Android 的某些组件也可能使用 Binder 进行进程间通信，其概念与 GDBus 有相似之处。

**逻辑推理的假设输入与输出：**

*   **`gtkdoc` 假设输入:**  源代码文件，包含特定的注释格式，以及一个主 SGML 或 XML 文件描述文档结构。
*   **`gtkdoc` 可能输出:**  HTML 格式的 API 文档。
*   **`gdbus_codegen` 假设输入:**  一个描述 D-Bus 接口的 XML 文件。
*   **`gdbus_codegen` 可能输出:**  C 语言的头文件和源文件，包含了用于访问和实现该 D-Bus 接口的函数和数据结构。
*   **`mkenums` 假设输入:**  一个文本文件，每行列出一个枚举值的名称（可能带有可选的值和注释）。
*   **`mkenums` 可能输出:**  C 语言的头文件和/或源文件，包含了 `enum` 类型的定义。
*   **`genmarshal` 假设输入:**  一个或多个描述 GObject 类型及其属性的头文件。
*   **`genmarshal` 可能输出:**  C 语言的头文件和源文件，包含了用于序列化和反序列化指定 GObject 类型的函数。

**用户或编程常见的使用错误：**

*   **`gtkdoc`:**
    *   **错误的 `main_sgml` 或 `main_xml` 路径:**  导致 `gtkdoc` 无法找到文档的入口点。
    *   **`src_dir` 中缺少头文件:** `gtkdoc-scan` 无法找到需要文档化的符号。
    *   **文档注释格式不正确:** `gtkdoc` 无法解析注释并生成正确的文档。
*   **`gdbus_codegen`:**
    *   **XML 文件格式错误:**  `gdbus-codegen` 无法解析 XML 接口定义。
    *   **命名冲突:**  生成的代码与其他代码中的符号冲突。
    *   **缺少依赖:**  生成的代码依赖于 GLib 库。
*   **`mkenums`:**
    *   **输入文件格式错误:**  `glib-mkenums` 无法正确解析枚举值。
    *   **前缀冲突:**  指定的前缀与其他符号冲突。
    *   **模板文件路径错误:** 如果使用了自定义模板，路径不正确会导致生成失败。
*   **`genmarshal`:**
    *   **输入头文件路径错误:** `glib-genmarshal` 找不到需要处理的 GObject 类型定义。
    *   **类型不匹配:**  输入头文件中定义的类型与 `glib-genmarshal` 的期望不符。
    *   **前缀冲突:**  生成的函数名与其他函数名冲突。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **配置构建系统:**  用户在 Frida 工具的构建配置文件 (通常是 `meson.build`) 中使用了 `gnome` 模块提供的函数，例如 `gnome.gtkdoc()`, `gnome.gdbus_codegen()` 等。
2. **执行构建命令:**  用户执行 Meson 构建命令 (例如 `meson build`，然后在 `build` 目录下执行 `ninja`)。
3. **Meson 解析构建文件:** Meson 读取并解析 `meson.build` 文件。当遇到 `gnome.gtkdoc()` 等函数调用时，Meson 会加载 `frida/subprojects/frida-tools/releng/meson/mesonbuild/modules/gnome.py` 模块。
4. **执行模块代码:**  Meson 执行 `gnome.py` 中被调用的函数，传递相应的参数（例如，源文件列表、输出目录等）。
5. **调用外部工具:**  这些函数内部会调用外部工具，如 `gtkdoc-scan`、`gdbus-codegen`、`glib-mkenums`、`glib-genmarshal`。
6. **生成构建目标:**  Meson 将这些外部工具的调用转化为构建系统可以理解的目标 (targets)，并添加到构建图中。
7. **构建系统执行:**  构建系统（如 Ninja）根据构建图执行相应的命令，生成文档、代码等。

**作为调试线索:** 如果构建过程中涉及到 GNOME 相关的组件，并且出现了与文档生成、GDBus 代码生成或枚举类型生成相关的错误，那么调试线索就会指向 `frida/subprojects/frida-tools/releng/meson/mesonbuild/modules/gnome.py` 文件以及其调用的外部工具。例如，如果 `gtkdoc` 报错找不到源文件，那么需要检查 `gnome.gtkdoc()` 函数调用中 `src_dir` 参数是否正确。

总而言之，这段代码是 Frida 构建系统中用于处理 GNOME 项目特定构建任务的关键部分，它通过 Meson 框架集成了一系列 GNOME 开发工具，自动化了文档生成、代码生成等过程。理解这些功能有助于理解 Frida 工具自身的构建过程，以及它如何与使用了 GNOME 技术的目标应用程序进行交互。

Prompt: 
```
这是目录为frida/subprojects/frida-tools/releng/meson/mesonbuild/modules/gnome.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共4部分，请归纳一下它的功能

"""
       l_data = build.Data([m_file], m_install_dir, m_install_dir,
                                        mesonlib.FileMode(), state.subproject, install_tag='doc')
                targets.append(l_data)

            po_file = l + '.po'
            po_args: T.List[T.Union[ExternalProgram, Executable, OverrideProgram, str]] = [
                msgmerge, '-q', '-o',
                os.path.join('@SOURCE_ROOT@', l_subdir, po_file),
                os.path.join('@SOURCE_ROOT@', l_subdir, po_file), pot_file]
            potarget = build.RunTarget(f'help-{project_id}-{l}-update-po',
                                       po_args, [pottarget], l_subdir, state.subproject,
                                       state.environment)
            targets.append(potarget)
            potargets.append(potarget)

            gmo_file = project_id + '-' + l + '.gmo'
            gmotarget = CustomTarget(
                f'help-{project_id}-{l}-gmo',
                l_subdir,
                state.subproject,
                state.environment,
                [msgfmt, '@INPUT@', '-o', '@OUTPUT@'],
                [po_file],
                [gmo_file],
                state.is_build_only_subproject,
                install_tag=['doc'],
                description='Generating yelp doc {}',
            )
            targets.append(gmotarget)

            mergetarget = CustomTarget(
                f'help-{project_id}-{l}',
                l_subdir,
                state.subproject,
                state.environment,
                [itstool, '-m', os.path.join(l_subdir, gmo_file), '--lang', l, '-o', '@OUTDIR@', '@INPUT@'],
                sources_files,
                sources,
                state.is_build_only_subproject,
                extra_depends=[gmotarget],
                install=True,
                install_dir=[l_install_dir],
                install_tag=['doc'],
                description='Generating yelp doc {}',
            )
            targets.append(mergetarget)

        allpotarget = build.AliasTarget(f'help-{project_id}-update-po', potargets,
                                        state.subdir, state.subproject, state.environment)
        targets.append(allpotarget)

        return ModuleReturnValue(None, targets)

    @typed_pos_args('gnome.gtkdoc', str)
    @typed_kwargs(
        'gnome.gtkdoc',
        KwargInfo('c_args', ContainerTypeInfo(list, str), since='0.48.0', default=[], listify=True),
        KwargInfo('check', bool, default=False, since='0.52.0'),
        KwargInfo('content_files', ContainerTypeInfo(list, (str, mesonlib.File, GeneratedList, CustomTarget, CustomTargetIndex)), default=[], listify=True),
        KwargInfo(
            'dependencies',
            ContainerTypeInfo(list, (Dependency, build.SharedLibrary, build.StaticLibrary)),
            listify=True, default=[]),
        KwargInfo('expand_content_files', ContainerTypeInfo(list, (str, mesonlib.File)), default=[], listify=True),
        KwargInfo('fixxref_args', ContainerTypeInfo(list, str), default=[], listify=True),
        KwargInfo('gobject_typesfile', ContainerTypeInfo(list, (str, mesonlib.File)), default=[], listify=True),
        KwargInfo('html_args', ContainerTypeInfo(list, str), default=[], listify=True),
        KwargInfo('html_assets', ContainerTypeInfo(list, (str, mesonlib.File)), default=[], listify=True),
        KwargInfo('ignore_headers', ContainerTypeInfo(list, str), default=[], listify=True),
        KwargInfo(
            'include_directories',
            ContainerTypeInfo(list, (str, build.IncludeDirs)),
            listify=True, default=[]),
        KwargInfo('install', bool, default=True),
        KwargInfo('install_dir', ContainerTypeInfo(list, str), default=[], listify=True),
        KwargInfo('main_sgml', (str, NoneType)),
        KwargInfo('main_xml', (str, NoneType)),
        KwargInfo('mkdb_args', ContainerTypeInfo(list, str), default=[], listify=True),
        KwargInfo(
            'mode', str, default='auto', since='0.37.0',
            validator=in_set_validator({'xml', 'sgml', 'none', 'auto'})),
        KwargInfo('module_version', str, default='', since='0.48.0'),
        KwargInfo('namespace', str, default='', since='0.37.0'),
        KwargInfo('scan_args', ContainerTypeInfo(list, str), default=[], listify=True),
        KwargInfo('scanobjs_args', ContainerTypeInfo(list, str), default=[], listify=True),
        KwargInfo('src_dir', ContainerTypeInfo(list, (str, build.IncludeDirs)), listify=True, required=True),
    )
    def gtkdoc(self, state: 'ModuleState', args: T.Tuple[str], kwargs: 'GtkDoc') -> ModuleReturnValue:
        modulename = args[0]
        main_file = kwargs['main_sgml']
        main_xml = kwargs['main_xml']
        if main_xml is not None:
            if main_file is not None:
                raise InvalidArguments('gnome.gtkdoc: main_xml and main_sgml are exclusive arguments')
            main_file = main_xml
        moduleversion = kwargs['module_version']
        targetname = modulename + ('-' + moduleversion if moduleversion else '') + '-doc'
        command = state.environment.get_build_command()

        namespace = kwargs['namespace']

        # Ensure we have a C compiler even in C++ projects.
        state.add_language('c', MachineChoice.HOST)

        def abs_filenames(files: T.Iterable['FileOrString']) -> T.Iterator[str]:
            for f in files:
                if isinstance(f, mesonlib.File):
                    yield f.absolute_path(state.environment.get_source_dir(), state.environment.get_build_dir())
                else:
                    yield os.path.join(state.environment.get_source_dir(), state.subdir, f)

        src_dirs = kwargs['src_dir']
        header_dirs: T.List[str] = []
        for src_dir in src_dirs:
            if isinstance(src_dir, build.IncludeDirs):
                header_dirs.extend(src_dir.to_string_list(state.environment.get_source_dir(),
                                                          state.environment.get_build_dir()))
            else:
                header_dirs.append(src_dir)

        t_args: T.List[str] = [
            '--internal', 'gtkdoc',
            '--sourcedir=' + state.environment.get_source_dir(),
            '--builddir=' + state.environment.get_build_dir(),
            '--subdir=' + state.subdir,
            '--headerdirs=' + '@@'.join(header_dirs),
            '--mainfile=' + main_file,
            '--modulename=' + modulename,
            '--moduleversion=' + moduleversion,
            '--mode=' + kwargs['mode']]
        for tool in ['scan', 'scangobj', 'mkdb', 'mkhtml', 'fixxref']:
            program_name = 'gtkdoc-' + tool
            program = state.find_program(program_name)
            path = program.get_path()
            assert path is not None, "This shouldn't be possible since program should be found"
            t_args.append(f'--{program_name}={path}')
        if namespace:
            t_args.append('--namespace=' + namespace)
        exe_wrapper = state.environment.get_exe_wrapper()
        if exe_wrapper:
            t_args.append('--run=' + ' '.join(exe_wrapper.get_command()))
        t_args.append(f'--htmlargs={"@@".join(kwargs["html_args"])}')
        t_args.append(f'--scanargs={"@@".join(kwargs["scan_args"])}')
        t_args.append(f'--scanobjsargs={"@@".join(kwargs["scanobjs_args"])}')
        t_args.append(f'--gobjects-types-file={"@@".join(abs_filenames(kwargs["gobject_typesfile"]))}')
        t_args.append(f'--fixxrefargs={"@@".join(kwargs["fixxref_args"])}')
        t_args.append(f'--mkdbargs={"@@".join(kwargs["mkdb_args"])}')
        t_args.append(f'--html-assets={"@@".join(abs_filenames(kwargs["html_assets"]))}')

        depends: T.List['build.GeneratedTypes'] = []
        content_files = []
        for s in kwargs['content_files']:
            if isinstance(s, (CustomTarget, CustomTargetIndex)):
                depends.append(s)
                for o in s.get_outputs():
                    content_files.append(os.path.join(state.environment.get_build_dir(),
                                                      state.backend.get_target_dir(s),
                                                      o))
            elif isinstance(s, mesonlib.File):
                content_files.append(s.absolute_path(state.environment.get_source_dir(),
                                                     state.environment.get_build_dir()))
            elif isinstance(s, GeneratedList):
                depends.append(s)
                for gen_src in s.get_outputs():
                    content_files.append(os.path.join(state.environment.get_source_dir(),
                                                      state.subdir,
                                                      gen_src))
            else:
                content_files.append(os.path.join(state.environment.get_source_dir(),
                                                  state.subdir,
                                                  s))
        t_args += ['--content-files=' + '@@'.join(content_files)]

        t_args.append(f'--expand-content-files={"@@".join(abs_filenames(kwargs["expand_content_files"]))}')
        t_args.append(f'--ignore-headers={"@@".join(kwargs["ignore_headers"])}')
        t_args.append(f'--installdir={"@@".join(kwargs["install_dir"])}')
        build_args, new_depends = self._get_build_args(kwargs['c_args'], kwargs['include_directories'],
                                                       kwargs['dependencies'], state, depends)
        t_args.extend(build_args)
        new_depends.extend(depends)
        custom_target = CustomTarget(
            targetname,
            state.subdir,
            state.subproject,
            state.environment,
            command + t_args,
            [],
            [f'{modulename}-decl.txt'],
            state.is_build_only_subproject,
            build_always_stale=True,
            extra_depends=new_depends,
            description='Generating gtkdoc {}',
        )
        alias_target = build.AliasTarget(targetname, [custom_target], state.subdir, state.subproject, state.environment)
        if kwargs['check']:
            check_cmd = state.find_program('gtkdoc-check')
            check_env = ['DOC_MODULE=' + modulename,
                         'DOC_MAIN_SGML_FILE=' + main_file]
            check_args = (targetname + '-check', check_cmd)
            check_workdir = os.path.join(state.environment.get_build_dir(), state.subdir)
            state.test(check_args, env=check_env, workdir=check_workdir, depends=[custom_target])
        res: T.List[T.Union[build.Target, mesonlib.ExecutableSerialisation]] = [custom_target, alias_target]
        if kwargs['install']:
            res.append(state.backend.get_executable_serialisation(command + t_args, tag='doc'))
        return ModuleReturnValue(custom_target, res)

    def _get_build_args(self, c_args: T.List[str], inc_dirs: T.List[T.Union[str, build.IncludeDirs]],
                        deps: T.List[T.Union[Dependency, build.SharedLibrary, build.StaticLibrary]],
                        state: 'ModuleState',
                        depends: T.Sequence[T.Union[build.BuildTarget, 'build.GeneratedTypes']]) -> T.Tuple[
                                T.List[str], T.List[T.Union[build.BuildTarget, 'build.GeneratedTypes', 'FileOrString', build.StructuredSources]]]:
        args: T.List[str] = []
        cflags = c_args.copy()
        deps_cflags, internal_ldflags, external_ldflags, _gi_includes, new_depends = \
            self._get_dependencies_flags(deps, state, depends, include_rpath=True)

        cflags.extend(deps_cflags)
        cflags.extend(state.get_include_args(inc_dirs))
        ldflags: T.List[str] = []
        ldflags.extend(internal_ldflags)
        ldflags.extend(external_ldflags)

        cflags.extend(state.environment.coredata.get_external_args(MachineChoice.HOST, 'c'))
        ldflags.extend(state.environment.coredata.get_external_link_args(MachineChoice.HOST, 'c'))
        compiler = state.environment.coredata.compilers[MachineChoice.HOST]['c']

        compiler_flags = self._get_langs_compilers_flags(state, [('c', compiler)])
        cflags.extend(compiler_flags[0])
        ldflags.extend(compiler_flags[1])
        ldflags.extend(compiler_flags[2])
        if compiler:
            args += ['--cc=%s' % join_args(compiler.get_exelist())]
            args += ['--ld=%s' % join_args(compiler.get_linker_exelist())]
        if cflags:
            args += ['--cflags=%s' % join_args(cflags)]
        if ldflags:
            args += ['--ldflags=%s' % join_args(ldflags)]

        return args, new_depends

    @noKwargs
    @typed_pos_args('gnome.gtkdoc_html_dir', str)
    def gtkdoc_html_dir(self, state: 'ModuleState', args: T.Tuple[str], kwargs: 'TYPE_kwargs') -> str:
        return os.path.join('share/gtk-doc/html', args[0])

    @typed_pos_args('gnome.gdbus_codegen', str, optargs=[(str, mesonlib.File, CustomTarget, CustomTargetIndex, GeneratedList)])
    @typed_kwargs(
        'gnome.gdbus_codegen',
        _BUILD_BY_DEFAULT.evolve(since='0.40.0'),
        DEPENDENCY_SOURCES_KW.evolve(since='0.46.0'),
        KwargInfo('extra_args', ContainerTypeInfo(list, str), since='0.47.0', default=[], listify=True),
        KwargInfo('interface_prefix', (str, NoneType)),
        KwargInfo('namespace', (str, NoneType)),
        KwargInfo('object_manager', bool, default=False),
        KwargInfo(
            'annotations', ContainerTypeInfo(list, (list, str)),
            default=[],
            validator=annotations_validator,
            convertor=lambda x: [x] if x and isinstance(x[0], str) else x,
        ),
        KwargInfo('install_header', bool, default=False, since='0.46.0'),
        KwargInfo('docbook', (str, NoneType)),
        KwargInfo(
            'autocleanup', str, default='default', since='0.47.0',
            validator=in_set_validator({'all', 'none', 'objects'})),
        INSTALL_DIR_KW.evolve(since='0.46.0')
    )
    def gdbus_codegen(self, state: 'ModuleState', args: T.Tuple[str, T.Optional[T.Union['FileOrString', build.GeneratedTypes]]],
                      kwargs: 'GdbusCodegen') -> ModuleReturnValue:
        namebase = args[0]
        xml_files: T.List[T.Union['FileOrString', build.GeneratedTypes]] = [args[1]] if args[1] else []
        cmd: T.List[T.Union['ToolType', str]] = [self._find_tool(state, 'gdbus-codegen')]
        cmd.extend(kwargs['extra_args'])

        # Autocleanup supported?
        glib_version = self._get_native_glib_version(state)
        if not mesonlib.version_compare(glib_version, '>= 2.49.1'):
            # Warn if requested, silently disable if not
            if kwargs['autocleanup'] != 'default':
                mlog.warning(f'Glib version ({glib_version}) is too old to support the \'autocleanup\' '
                             'kwarg, need 2.49.1 or newer')
        else:
            # Handle legacy glib versions that don't have autocleanup
            ac = kwargs['autocleanup']
            if ac == 'default':
                ac = 'all'
            cmd.extend(['--c-generate-autocleanup', ac])

        if kwargs['interface_prefix'] is not None:
            cmd.extend(['--interface-prefix', kwargs['interface_prefix']])
        if kwargs['namespace'] is not None:
            cmd.extend(['--c-namespace', kwargs['namespace']])
        if kwargs['object_manager']:
            cmd.extend(['--c-generate-object-manager'])
        xml_files.extend(kwargs['sources'])
        build_by_default = kwargs['build_by_default']

        # Annotations are a bit ugly in that they are a list of lists of strings...
        for annot in kwargs['annotations']:
            cmd.append('--annotate')
            cmd.extend(annot)

        targets = []
        install_header = kwargs['install_header']
        install_dir = kwargs['install_dir'] or state.environment.coredata.get_option(mesonlib.OptionKey('includedir'))
        assert isinstance(install_dir, str), 'for mypy'

        output = namebase + '.c'
        # Added in https://gitlab.gnome.org/GNOME/glib/commit/e4d68c7b3e8b01ab1a4231bf6da21d045cb5a816 (2.55.2)
        # Fixed in https://gitlab.gnome.org/GNOME/glib/commit/cd1f82d8fc741a2203582c12cc21b4dacf7e1872 (2.56.2)
        if mesonlib.version_compare(glib_version, '>= 2.56.2'):
            c_cmd = cmd + ['--body', '--output', '@OUTPUT@', '@INPUT@']
        else:
            if kwargs['docbook'] is not None:
                docbook = kwargs['docbook']

                cmd += ['--generate-docbook', docbook]

            # https://git.gnome.org/browse/glib/commit/?id=ee09bb704fe9ccb24d92dd86696a0e6bb8f0dc1a
            if mesonlib.version_compare(glib_version, '>= 2.51.3'):
                cmd += ['--output-directory', '@OUTDIR@', '--generate-c-code', namebase, '@INPUT@']
            else:
                self._print_gdbus_warning()
                cmd += ['--generate-c-code', '@OUTDIR@/' + namebase, '@INPUT@']
            c_cmd = cmd

        cfile_custom_target = CustomTarget(
            output,
            state.subdir,
            state.subproject,
            state.environment,
            c_cmd,
            xml_files,
            [output],
            state.is_build_only_subproject,
            build_by_default=build_by_default,
            description='Generating gdbus source {}',
        )
        targets.append(cfile_custom_target)

        output = namebase + '.h'
        if mesonlib.version_compare(glib_version, '>= 2.56.2'):
            hfile_cmd = cmd + ['--header', '--output', '@OUTPUT@', '@INPUT@']
            depends = []
        else:
            hfile_cmd = cmd
            depends = [cfile_custom_target]

        hfile_custom_target = CustomTarget(
            output,
            state.subdir,
            state.subproject,
            state.environment,
            hfile_cmd,
            xml_files,
            [output],
            state.is_build_only_subproject,
            build_by_default=build_by_default,
            extra_depends=depends,
            install=install_header,
            install_dir=[install_dir],
            install_tag=['devel'],
            description='Generating gdbus header {}',
        )
        targets.append(hfile_custom_target)

        if kwargs['docbook'] is not None:
            docbook = kwargs['docbook']
            # The docbook output is always ${docbook}-${name_of_xml_file}
            output = namebase + '-docbook'
            outputs = []
            for f in xml_files:
                outputs.append('{}-{}'.format(docbook, os.path.basename(str(f))))

            if mesonlib.version_compare(glib_version, '>= 2.56.2'):
                docbook_cmd = cmd + ['--output-directory', '@OUTDIR@', '--generate-docbook', docbook, '@INPUT@']
                depends = []
            else:
                docbook_cmd = cmd
                depends = [cfile_custom_target]

            docbook_custom_target = CustomTarget(
                output,
                state.subdir,
                state.subproject,
                state.environment,
                docbook_cmd,
                xml_files,
                outputs,
                state.is_build_only_subproject,
                build_by_default=build_by_default,
                extra_depends=depends,
                description='Generating gdbus docbook {}',
            )
            targets.append(docbook_custom_target)

        return ModuleReturnValue(targets, targets)

    @typed_pos_args('gnome.mkenums', str)
    @typed_kwargs(
        'gnome.mkenums',
        *_MK_ENUMS_COMMON_KWS,
        DEPENDS_KW,
        KwargInfo(
            'sources',
            ContainerTypeInfo(list, (str, mesonlib.File, CustomTarget, CustomTargetIndex,
                                     GeneratedList)),
            listify=True,
            required=True,
        ),
        KwargInfo('c_template', (str, mesonlib.File, NoneType)),
        KwargInfo('h_template', (str, mesonlib.File, NoneType)),
        KwargInfo('comments', (str, NoneType)),
        KwargInfo('eprod', (str, NoneType)),
        KwargInfo('fhead', (str, NoneType)),
        KwargInfo('fprod', (str, NoneType)),
        KwargInfo('ftail', (str, NoneType)),
        KwargInfo('vhead', (str, NoneType)),
        KwargInfo('vprod', (str, NoneType)),
        KwargInfo('vtail', (str, NoneType)),
    )
    def mkenums(self, state: 'ModuleState', args: T.Tuple[str], kwargs: 'MkEnums') -> ModuleReturnValue:
        basename = args[0]

        c_template = kwargs['c_template']
        if isinstance(c_template, mesonlib.File):
            c_template = c_template.absolute_path(state.environment.source_dir, state.environment.build_dir)
        h_template = kwargs['h_template']
        if isinstance(h_template, mesonlib.File):
            h_template = h_template.absolute_path(state.environment.source_dir, state.environment.build_dir)

        cmd: T.List[str] = []
        known_kwargs = ['comments', 'eprod', 'fhead', 'fprod', 'ftail',
                        'identifier_prefix', 'symbol_prefix',
                        'vhead', 'vprod', 'vtail']
        for arg in known_kwargs:
            # Mypy can't figure out that this TypedDict index is correct, without repeating T.Literal for the entire list
            if kwargs[arg]:                                         # type: ignore
                cmd += ['--' + arg.replace('_', '-'), kwargs[arg]]  # type: ignore

        targets: T.List[CustomTarget] = []

        h_target: T.Optional[CustomTarget] = None
        if h_template is not None:
            h_output = os.path.basename(os.path.splitext(h_template)[0])
            # We always set template as the first element in the source array
            # so --template consumes it.
            h_cmd = cmd + ['--template', '@INPUT@']
            h_sources: T.List[T.Union[FileOrString, 'build.GeneratedTypes']] = [h_template]
            h_sources.extend(kwargs['sources'])
            h_target = self._make_mkenum_impl(
                state, h_sources, h_output, h_cmd, install=kwargs['install_header'],
                install_dir=kwargs['install_dir'])
            targets.append(h_target)

        if c_template is not None:
            c_output = os.path.basename(os.path.splitext(c_template)[0])
            # We always set template as the first element in the source array
            # so --template consumes it.
            c_cmd = cmd + ['--template', '@INPUT@']
            c_sources: T.List[T.Union[FileOrString, 'build.GeneratedTypes']] = [c_template]
            c_sources.extend(kwargs['sources'])

            depends = kwargs['depends'].copy()
            if h_target is not None:
                depends.append(h_target)
            c_target = self._make_mkenum_impl(
                state, c_sources, c_output, c_cmd, depends=depends)
            targets.insert(0, c_target)

        if c_template is None and h_template is None:
            generic_cmd = cmd + ['@INPUT@']
            target = self._make_mkenum_impl(
                state, kwargs['sources'], basename, generic_cmd,
                install=kwargs['install_header'],
                install_dir=kwargs['install_dir'])
            return ModuleReturnValue(target, [target])
        else:
            return ModuleReturnValue(targets, targets)

    @FeatureNew('gnome.mkenums_simple', '0.42.0')
    @typed_pos_args('gnome.mkenums_simple', str)
    @typed_kwargs(
        'gnome.mkenums_simple',
        *_MK_ENUMS_COMMON_KWS,
        KwargInfo(
            'sources',
            ContainerTypeInfo(list, (str, mesonlib.File)),
            listify=True,
            required=True,
        ),
        KwargInfo('header_prefix', str, default=''),
        KwargInfo('function_prefix', str, default=''),
        KwargInfo('body_prefix', str, default=''),
        KwargInfo('decorator', str, default=''),
    )
    def mkenums_simple(self, state: 'ModuleState', args: T.Tuple[str], kwargs: 'MkEnumsSimple') -> ModuleReturnValue:
        hdr_filename = f'{args[0]}.h'
        body_filename = f'{args[0]}.c'

        header_prefix = kwargs['header_prefix']
        decl_decorator = kwargs['decorator']
        func_prefix = kwargs['function_prefix']
        body_prefix = kwargs['body_prefix']

        cmd: T.List[str] = []
        if kwargs['identifier_prefix']:
            cmd.extend(['--identifier-prefix', kwargs['identifier_prefix']])
        if kwargs['symbol_prefix']:
            cmd.extend(['--symbol-prefix', kwargs['symbol_prefix']])

        c_cmd = cmd.copy()
        # Maybe we should write our own template files into the build dir
        # instead, but that seems like much more work, nice as it would be.
        fhead = ''
        if body_prefix != '':
            fhead += '%s\n' % body_prefix
        fhead += '#include "%s"\n' % hdr_filename
        for hdr in self.interpreter.source_strings_to_files(kwargs['sources']):
            hdr_path = os.path.relpath(hdr.relative_name(), state.subdir)
            fhead += f'#include "{hdr_path}"\n'
        fhead += textwrap.dedent(
            '''
            #define C_ENUM(v) ((gint) v)
            #define C_FLAGS(v) ((guint) v)
            ''')
        c_cmd.extend(['--fhead', fhead])

        c_cmd.append('--fprod')
        c_cmd.append(textwrap.dedent(
            '''
            /* enumerations from "@basename@" */
            '''))

        c_cmd.append('--vhead')
        c_cmd.append(textwrap.dedent(
            f'''
            GType
            {func_prefix}@enum_name@_get_type (void)
            {{
            static gsize gtype_id = 0;
            static const G@Type@Value values[] = {{'''))

        c_cmd.extend(['--vprod', '    { C_@TYPE@(@VALUENAME@), "@VALUENAME@", "@valuenick@" },'])

        c_cmd.append('--vtail')
        c_cmd.append(textwrap.dedent(
            '''    { 0, NULL, NULL }
            };
            if (g_once_init_enter (&gtype_id)) {
                GType new_type = g_@type@_register_static (g_intern_static_string ("@EnumName@"), values);
                g_once_init_leave (&gtype_id, new_type);
            }
            return (GType) gtype_id;
            }'''))
        c_cmd.append('@INPUT@')

        c_file = self._make_mkenum_impl(state, kwargs['sources'], body_filename, c_cmd)

        # .h file generation
        h_cmd = cmd.copy()

        h_cmd.append('--fhead')
        h_cmd.append(textwrap.dedent(
            f'''#pragma once

            #include <glib-object.h>
            {header_prefix}

            G_BEGIN_DECLS
            '''))

        h_cmd.append('--fprod')
        h_cmd.append(textwrap.dedent(
            '''
            /* enumerations from "@basename@" */
            '''))

        h_cmd.append('--vhead')
        h_cmd.append(textwrap.dedent(
            f'''
            {decl_decorator}
            GType {func_prefix}@enum_name@_get_type (void);
            #define @ENUMPREFIX@_TYPE_@ENUMSHORT@ ({func_prefix}@enum_name@_get_type())'''))

        h_cmd.append('--ftail')
        h_cmd.append(textwrap.dedent(
            '''
            G_END_DECLS'''))
        h_cmd.append('@INPUT@')

        h_file = self._make_mkenum_impl(
            state, kwargs['sources'], hdr_filename, h_cmd,
            install=kwargs['install_header'],
            install_dir=kwargs['install_dir'])

        return ModuleReturnValue([c_file, h_file], [c_file, h_file])

    def _make_mkenum_impl(
            self,
            state: 'ModuleState',
            sources: T.Sequence[T.Union[str, mesonlib.File, CustomTarget, CustomTargetIndex, GeneratedList]],
            output: str,
            cmd: T.List[str],
            *,
            install: bool = False,
            install_dir: T.Optional[T.Sequence[T.Union[str, bool]]] = None,
            depends: T.Optional[T.Sequence[T.Union[CustomTarget, CustomTargetIndex, BuildTarget]]] = None
            ) -> build.CustomTarget:
        real_cmd: T.List[T.Union[str, 'ToolType']] = [self._find_tool(state, 'glib-mkenums')]
        real_cmd.extend(cmd)
        _install_dir = install_dir or state.environment.coredata.get_option(mesonlib.OptionKey('includedir'))
        assert isinstance(_install_dir, str), 'for mypy'

        return CustomTarget(
            output,
            state.subdir,
            state.subproject,
            state.environment,
            real_cmd,
            sources,
            [output],
            state.is_build_only_subproject,
            capture=True,
            install=install,
            install_dir=[_install_dir],
            install_tag=['devel'],
            extra_depends=depends,
            # https://github.com/mesonbuild/meson/issues/973
            absolute_paths=True,
            description='Generating GObject enum file {}',
        )

    @typed_pos_args('gnome.genmarshal', str)
    @typed_kwargs(
        'gnome.genmarshal',
        DEPEND_FILES_KW.evolve(since='0.61.0'),
        DEPENDS_KW.evolve(since='0.61.0'),
        INSTALL_KW.evolve(name='install_header'),
        INSTALL_DIR_KW,
        KwargInfo('extra_args', ContainerTypeInfo(list, str), listify=True, default=[]),
        KwargInfo('internal', bool, default=False),
        KwargInfo('nostdinc', bool, default=False),
        KwargInfo('prefix', (str, NoneType)),
        KwargInfo('skip_source', bool, default=False),
        KwargInfo('sources', ContainerTypeInfo(list, (str, mesonlib.File), allow_empty=False), listify=True, required=True),
        KwargInfo('stdinc', bool, default=False),
        KwargInfo('valist_marshallers', bool, default=False),
    )
    def genmarshal(self, state: 'ModuleState', args: T.Tuple[str], kwargs: 'GenMarshal') -> ModuleReturnValue:
        output = args[0]
        sources = kwargs['sources']

        new_genmarshal = mesonlib.version_compare(self._get_native_glib_version(state), '>= 2.53.3')

        cmd: T.List[T.Union['ToolType', str]] = [self._find_tool(state, 'glib-genmarshal')]
        if kwargs['prefix']:
            cmd.extend(['--prefix', kwargs['prefix']])
        if kwargs['extra_args']:
            if new_genmarshal:
                cmd.extend(kwargs['extra_args'])
            else:
                mlog.warning('The current version of GLib does not support extra arguments \n'
                             'for glib-genmarshal. You need at least GLib 2.53.3. See ',
                             mlog.bold('https://github.com/mesonbuild/meson/pull/2049'),
                             once=True, fatal=False)
        for k in ['internal', 'nostdinc', 'skip_source', 'stdinc', 'valist_marshallers']:
            # Mypy can't figure out that this TypedDict index is correct, without repeating T.Literal for the entire list
            if kwargs[k]:                                            # type: ignore
                cmd.append(f'--{k.replace("_", "-")}')

        install_header = kwargs['install_header']
        capture = False

        # https://github.com/GNOME/glib/commit/0fbc98097fac4d3e647684f344e508abae109fdf
        if mesonlib.version_compare(self._get_native_glib_version(state), '>= 2.51.0'):
            cmd += ['--output', '@OUTPUT@']
        else:
            capture = True

        header_file = output + '.h'
        h_cmd = cmd + ['--header', '@INPUT@']
        if new_genmarshal:
            h_cmd += ['--pragma-once']
        header = CustomTarget(
            output + '_h',
            state.subdir,
            state.subproject,
            state.environment,
            h_cmd,
            sources,
            [header_file],
            state.is_build_only_subproject,
            install=install_header,
            install_dir=[kwargs['install_dir']] if kwargs['install_dir'] else [],
            install_tag=['devel'],
            capture=capture,
            depend_files=kwargs['depend_files'],
            description='Generating glib marshaller header {}',
        )

        c_cmd = cmd + ['--body', '@INPUT@']
        extra_deps: T.List[CustomTarget] = []
        if mesonlib.version_compare(self._get_native_glib_version(state), '>= 2.53.4'):
            # Silence any warnings about missing prototypes
            c_cmd += ['--include-header', header_file]
            extra_deps.append(header)
        body = CustomTarget(
            output + '_c',
            state.subdir,
            state.subproject,
            state.environment,
            c_cmd,
            sources,
            [f'{output}.c'],
            state.is_build_only_subproject,
            capture=capture,
            depend_files=kwargs['depend_files'],
            extra_depends=extra_deps,
            description='Generating glib marshaller source {}',
        )

        rv = [body, header]
        return ModuleReturnValue(rv, rv)

    def _extract_vapi_packages(self, state: 'ModuleState', packages: T.List[T.Union[InternalDependen
"""


```