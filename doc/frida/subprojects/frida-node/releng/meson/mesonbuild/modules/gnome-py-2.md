Response:
The user wants a summary of the Python code provided, focusing on its functionality within the context of Frida, reverse engineering, low-level details, and potential user errors.

**Plan:**

1. **Identify the core functionality:** Analyze the code blocks and function calls to understand the main purpose of the module.
2. **Connect to reverse engineering:**  Determine if any of the functionalities directly assist in or relate to reverse engineering techniques.
3. **Highlight low-level aspects:** Look for interactions with system-level concepts like binaries, kernels, and specific operating system features.
4. **Infer logic and provide examples:** Analyze functions for conditional logic and parameter handling to create hypothetical input/output scenarios.
5. **Identify potential user errors:** Pinpoint common mistakes users might make when using the module's functions.
6. **Trace user interaction:**  Describe how a user might navigate the Frida project to reach this specific module.
7. **Summarize the overall function:**  Concisely describe the purpose of the code.
这是`frida/subprojects/frida-node/releng/meson/mesonbuild/modules/gnome.py`文件中代码片段的功能归纳：

**核心功能:**

这段代码是 Meson 构建系统中 `gnome` 模块的一部分，它提供了一系列用于与 GNOME 开发相关的工具集成的函数。 这些函数允许开发者在 Meson 构建过程中方便地使用 GNOME 的代码生成工具，例如：

* **`gnome.yelp()`:**  用于构建和安装 Yelp 文档。它处理翻译文件（`.po`），将其编译成二进制的 `.gmo` 文件，并最终将它们与源文档合并以生成可安装的帮助文档。
* **`gnome.gtkdoc()`:** 用于生成 GTK 文档。它调用 `gtkdoc-scan`、`gtkdoc-mkdb`、`gtkdoc-mkhtml` 等工具来扫描源代码，创建文档数据库，并生成 HTML 格式的文档。
* **`gnome.gtkdoc_html_dir()`:** 提供 GTK 文档 HTML 安装目录的路径。
* **`gnome.gdbus_codegen()`:**  用于使用 `gdbus-codegen` 工具从 GDBus XML 接口描述文件生成 C 代码的头文件和源文件。
* **`gnome.mkenums()`:**  用于使用 `glib-mkenums` 工具从源代码生成 C 语言的枚举定义。
* **`gnome.mkenums_simple()`:** 提供一个更简化的方式来使用 `glib-mkenums` 生成枚举定义。
* **`gnome.genmarshal()`:** 用于使用 `glib-genmarshal` 工具从类型定义生成 GObject 属性的 marshaller 函数。

**与逆向方法的关系及举例:**

这些功能本身不直接用于执行逆向工程。然而，生成的文档和代码可以 **辅助** 逆向分析：

* **`gnome.gtkdoc()`:** 生成的 GTK 文档（通常是 HTML）包含了 API 的详细信息，包括函数、结构体、枚举等的定义和用法。逆向工程师可以通过查阅这些文档，更快地理解目标程序中使用的 GTK 库的功能和接口，从而辅助逆向分析。例如，当逆向一个使用 GTK 编写的 GUI 应用程序时，可以查看 `gtkdoc` 生成的文档来了解某个 GTK 组件的行为。
* **`gnome.gdbus_codegen()`:** 生成的 C 代码定义了 GDBus 接口的代理和骨架代码。逆向工程师可以通过分析这些代码，了解程序中使用的 D-Bus 接口的细节，包括方法名、信号、属性等，从而理解进程间的通信方式。例如，逆向一个使用 D-Bus 与其他服务通信的程序时，可以查看生成的代码来了解具体的通信协议。
* **`gnome.mkenums()` 和 `gnome.mkenums_simple()`:** 生成的枚举定义可以帮助逆向工程师理解程序中使用的常量值及其含义。例如，如果逆向过程中发现一个函数使用了特定的整数值，通过查看生成的枚举定义，可能可以确定这个值代表的具体状态或选项。
* **`gnome.genmarshal()`:** 生成的 marshaller 代码处理 GObject 属性的序列化和反序列化。逆向工程师分析这些代码可以了解对象属性的结构和数据类型，这对于理解对象的状态和行为很有帮助。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例:**

* **二进制底层:**
    * **`.gmo` 文件 (由 `gnome.yelp()` 生成):**  是编译后的二进制翻译文件，用于实现软件的本地化。
    * **可执行文件 (通过构建系统):**  虽然这段代码本身不直接操作二进制，但它是构建过程的一部分，最终会生成可执行的二进制文件。逆向工程的对象通常就是这些二进制文件。

* **Linux:**
    * **D-Bus (与 `gnome.gdbus_codegen()` 相关):** D-Bus 是 Linux 系统上常用的进程间通信 (IPC) 机制。`gdbus-codegen` 生成的代码用于与 D-Bus 服务进行交互。
    * **Yelp 文档路径:**  `gnome.yelp()` 中涉及的文件安装路径通常是符合 Linux 文件系统层级标准 (FHS) 的，例如 `/share/help/`.
    * **GTK 库:** 这些工具服务于 GTK 库的开发，而 GTK 是一个跨平台的 GUI 工具包，在 Linux 上被广泛使用。

* **Android 内核及框架:**
    * 虽然这段代码是 GNOME 相关的，但如果 Frida 被用于分析 Android 上的 GNOME 或使用了类似技术的应用，那么理解 D-Bus 或 GLib/GObject 的概念仍然是相关的。Android 框架本身也使用了 Binder 等 IPC 机制，其概念与 D-Bus 有相似之处。
    * **Frida 的应用场景:** Frida 常用于 Android 平台的动态 Instrumentation，这段代码属于 Frida 项目的一部分，表明 Frida 可能会与使用了 GNOME 技术栈的应用或库进行交互。

**逻辑推理、假设输入与输出:**

**`gnome.yelp()` 示例:**

* **假设输入:**
    * `project_id`: "my_app"
    * `pot_file`: "my_app.pot"
    * `langs`: ["zh_CN", "fr"]
    * `sources_files`: ["index.page", "about.page"]
    * `m_files`: ["my_app-zh_CN.po", "my_app-fr.po"]
    * `m_install_dir`: "help/my_app"

* **输出 (构建目标):**
    * `help-my_app-zh_CN-update-po`:  运行 `msgmerge` 更新中文翻译文件。
    * `help-my_app-zh_CN-gmo`: 将中文 `.po` 文件编译成 `my_app-zh_CN.gmo`。
    * `help-my_app-zh_CN`: 使用 `itstool` 将中文翻译合并到源文档。
    * `help-my_app-fr-update-po`: 运行 `msgmerge` 更新法文翻译文件。
    * `help-my_app-fr-gmo`: 将法文 `.po` 文件编译成 `my_app-fr.gmo`。
    * `help-my_app-fr`: 使用 `itstool` 将法文翻译合并到源文档。
    * `help-my_app-update-po`:  别名目标，用于更新所有语言的翻译。

**`gnome.gdbus_codegen()` 示例:**

* **假设输入:**
    * `namebase`: "com_example_MyInterface"
    * `xml_file`: "com.example.MyInterface.xml"
    * `interface_prefix`: "ComExample"
    * `namespace`: "com_example"

* **输出 (生成的文件):**
    * `com_example_MyInterface.c`: 包含 GDBus 接口的 C 代码实现。
    * `com_example_MyInterface.h`: 包含 GDBus 接口的 C 头文件定义。

**涉及用户或编程常见的使用错误及举例:**

* **`gnome.gtkdoc()`:**
    * **错误的 `main_sgml` 或 `main_xml` 路径:** 如果指定的主文档文件不存在或路径错误，会导致 `gtkdoc` 工具执行失败。
    * **`main_xml` 和 `main_sgml` 同时指定:** 代码中明确指出这两个参数是互斥的，同时指定会导致构建错误。
    * **缺少依赖:** 如果 `content_files` 中引用的文件不存在或对应的构建目标尚未完成，会导致构建失败。

* **`gnome.gdbus_codegen()`:**
    * **XML 文件格式错误:** 如果提供的 XML 接口描述文件不符合 `gdbus-codegen` 的语法要求，会导致代码生成失败。
    * **命名冲突:**  如果 `interface_prefix` 或 `namespace` 与已有的符号冲突，可能导致编译错误。

* **`gnome.mkenums()` 和 `gnome.mkenums_simple()`:**
    * **模板文件不存在:** 如果指定了 `c_template` 或 `h_template`，但文件不存在，会导致工具执行失败。
    * **源文件格式错误:**  `glib-mkenums` 需要特定的源文件格式来解析枚举值，格式错误会导致解析失败。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **Frida 项目开发:** 用户正在开发或维护 Frida 项目中的 `frida-node` 组件。
2. **构建系统配置:** Frida 使用 Meson 作为其构建系统。用户需要配置 `meson.build` 文件来定义如何构建 `frida-node` 的各个部分。
3. **集成 GNOME 工具:**  `frida-node` 的某些部分可能依赖于或需要与 GNOME 的库或工具进行交互。为了在构建过程中使用这些工具，开发者需要在 `meson.build` 文件中调用 `gnome` 模块提供的函数。
4. **调用 `gnome` 模块的函数:**  在 `meson.build` 文件中，开发者会根据需要调用 `gnome.yelp()`, `gnome.gtkdoc()`, `gnome.gdbus_codegen()`, `gnome.mkenums()` 等函数，并传递相应的参数，例如源文件、输出路径、依赖项等。
5. **Meson 执行:**  当用户运行 `meson` 命令来配置构建时，Meson 会解析 `meson.build` 文件，并执行相应的构建步骤，包括调用 `gnome` 模块中的 Python 函数。
6. **遇到构建问题:**  如果构建过程中出现与 GNOME 工具相关的问题，例如找不到工具、参数错误、文件缺失等，开发者可能会查看 `frida/subprojects/frida-node/releng/meson/mesonbuild/modules/gnome.py` 这个文件来理解这些函数的具体实现和参数含义，以便排查问题。例如，如果 `gtkdoc` 命令执行失败，开发者可能会查看 `gnome.gtkdoc()` 函数的实现，检查传递给 `gtkdoc` 工具的参数是否正确。

**功能归纳:**

总而言之，`frida/subprojects/frida-node/releng/meson/mesonbuild/modules/gnome.py` 模块在 Frida 的构建过程中扮演着集成 GNOME 开发工具的角色。它提供了一系列便捷的函数，用于自动化生成文档、代码以及处理本地化资源，从而简化了与 GNOME 生态系统相关的构建任务。虽然这些功能不直接用于逆向，但它们生成的工件可以为逆向工程师提供有价值的信息，帮助理解目标程序的结构和行为。

Prompt: 
```
这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/modules/gnome.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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