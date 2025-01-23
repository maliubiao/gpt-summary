Response:
The user wants a summary of the functionalities present in the provided Python code snippet. I need to analyze the code, identify its main purposes, and then formulate a concise summary. The user also requested specific examples related to reverse engineering, binary interaction, kernel/framework knowledge, logical inference, and common usage errors. Finally, I need to explain how a user's actions might lead to this code being executed, serving as a debugging context.

Here's a breakdown of the code's functionality:

1. **Path and Symbol Handling:** The `_build_just_symbols_dirs` method processes command-line arguments to extract directories containing symbols, ensuring they are valid directories.
2. **RPATH Calculation:** The `rpaths_for_non_system_absolute_shared_libraries` method determines the necessary RPATHs for shared libraries that are not located in system directories. It considers dependencies and avoids redundant or system paths.
3. **RPATH Determination:** The `determine_rpath_dirs` method decides the RPATH directories based on the build layout option.
4. **Filename Canonicalization:** The `canonicalize_filename` method creates a standardized and potentially shortened filename, handling long paths and replacing special characters.
5. **Object Filename Generation:** The `object_filename_from_source` method generates the name for an object file based on the source file and target information. It handles generated sources and different language conventions.
6. **Extracted Objects Handling:** The `_determine_ext_objs` method identifies and processes extracted object files, considering precompiled headers and unity builds.
7. **Precompiled Header Arguments:** The `get_pch_include_args` method retrieves compiler arguments related to precompiled headers.
8. **MSVC PCH Object Name:** The `get_msvc_pch_objname` method determines the object filename for precompiled headers when using MSVC.
9. **MSVC PCH Implementation Creation:** The `create_msvc_pch_implementation` method creates the source file for a precompiled header when using MSVC.
10. **PCH Usage Check:** The `target_uses_pch` method checks if precompiled headers are enabled for a target.
11. **Extra Argument Escaping:** The `escape_extra_args` method escapes backslashes in define arguments.
12. **Standard Library Argument Handling:** The `get_no_stdlib_args` method determines arguments to exclude the standard library.
13. **Basic Compiler Arguments Generation:** The `generate_basic_compiler_args` method assembles fundamental compiler arguments based on target options, project settings, and dependencies.
14. **Link Argument Generation:** The `build_target_link_arguments` method creates linker arguments for linking with other build targets.
15. **MinGW Extra Path Handling:** The `get_mingw_extra_paths` method retrieves extra paths relevant for MinGW builds.
16. **DLL Path Search:** The `search_dll_path` method attempts to locate the directory containing a DLL based on a link argument.
17. **DLL Path Extraction:** The `extract_dll_paths` method finds the paths to all required DLLs for a target on Windows-like systems.
18. **Windows Extra Path Determination:** The `determine_windows_extra_paths` method identifies the locations of DLLs required by a target on Windows.
19. **Benchmark and Test File Writing:** The `write_benchmark_file` and `write_test_file` methods serialize benchmark and test information to files.
20. **Test Serialisation Creation:** The `create_test_serialisation` method prepares test information for serialization, including command construction, dependency analysis, and environment setup.
21. **Test Serialisation Writing:** The `write_test_serialisation` method writes the serialized test information to a file.
22. **Target Relative Path Construction:** The `construct_target_rel_paths` method generates relative paths to target outputs.
23. **Dependency Manifest Installation Generation:** The `generate_depmf_install` method creates instructions for installing a dependency manifest file.
24. **Regeneration File List Retrieval:** The `get_regen_filelist` method retrieves a list of files that trigger a build definition regeneration when modified.
25. **Regeneration Information Generation:** The `generate_regen_info` method creates and saves information about files needed for regeneration.
26. **Clock Skew Check:** The `check_clock_skew` method verifies that file timestamps are not in the future.
27. **Build Target to Command Array Conversion:** The `build_target_to_cmd_array` method converts a build target or external program into a command array.
28. **Extra Argument Replacement:** The `replace_extra_args` method replaces placeholders with extra arguments.
29. **Output Replacement:** The `replace_outputs` method replaces placeholders with the actual output paths.
30. **Default Build Target Retrieval:** The `get_build_by_default_targets` method returns targets marked for building by default.
31. **Test-like Target Retrieval:** The `get_testlike_targets` method returns build targets associated with tests or benchmarks.

Based on this analysis, I can now formulate the summary and examples.
这是 frida 动态 instrumentation 工具中 `frida/subprojects/frida-python/releng/meson/mesonbuild/backend/backends.py` 文件的部分源代码。这个代码片段主要负责处理构建过程中的一些底层细节，特别是与编译、链接和测试执行相关的任务。

**它的主要功能可以归纳为:**

1. **处理符号文件路径:** 从命令行参数中提取并验证符号文件所在的目录。
2. **计算非系统共享库的 RPATH:**  为不在系统目录中的共享库计算必要的 RPATH (Runtime Path)，以便程序运行时能找到这些库。这涉及到分析依赖关系，排除系统路径，并处理不同操作系统下的路径表示。
3. **确定 RPATH 目录:** 根据构建布局选项，决定最终的 RPATH 目录。
4. **规范化文件名:**  将文件名进行规范化处理，例如处理长路径和特殊字符，生成一个更简洁的版本，用于内部表示。
5. **生成目标文件名称:** 根据源文件和目标信息生成目标文件的名称，需要考虑不同语言和生成文件的特殊情况。
6. **处理提取的Object文件:**  处理从其他编译单元中提取出来的目标文件，例如处理预编译头文件和 Unity 构建。
7. **获取预编译头文件的包含参数:**  为编译器生成使用预编译头文件所需的包含路径和参数。
8. **创建 MSVC 预编译头文件实现:**  当使用 MSVC 编译器时，创建预编译头文件的实现源文件。
9. **检查目标是否使用预编译头文件:**  判断一个构建目标是否启用了预编译头文件。
10. **转义额外的编译器参数:**  对额外的编译器参数进行转义，例如处理定义中的反斜杠。
11. **获取禁用标准库的参数:**  根据目标和编译器，获取禁用标准库的编译器参数。
12. **生成基本的编译器参数:**  为构建目标生成基本的编译器参数，包括优化级别、调试信息、警告级别等，并考虑项目和全局参数。
13. **构建目标链接参数:**  生成用于链接构建目标的参数，包括库文件的前缀。
14. **处理 MinGW 的额外路径:**  在 MinGW 环境下，获取额外的程序和库文件搜索路径。
15. **搜索 DLL 路径:**  在 Windows 环境下，根据链接参数搜索 DLL 文件的路径。
16. **提取 DLL 路径:**  在 Windows 环境下，提取构建目标所需的所有 DLL 文件的路径。
17. **确定 Windows 的额外路径:**  在 Windows 环境下，确定运行可执行文件所需的额外 DLL 搜索路径。
18. **写入基准测试和测试文件:**  将基准测试和测试用例的信息序列化到文件中。
19. **创建测试序列化数据:**  将测试用例的信息组织成可序列化的数据结构，包括执行命令、依赖关系、环境变量等。
20. **写入测试序列化数据:**  将测试用例的序列化数据写入文件。
21. **构建目标相对路径:**  构建指向构建目标输出文件的相对路径。
22. **生成依赖清单安装信息:**  生成安装依赖清单文件的相关信息。
23. **获取需要重新生成构建文件的列表:**  列出所有文件的路径，当这些文件发生更改时，需要重新配置构建系统。
24. **生成重新生成信息:**  创建并保存用于重新生成构建系统的信息。
25. **检查时钟偏移:**  检查关键文件的修改时间戳，防止时钟偏移导致构建问题。
26. **将构建目标转换为命令数组:**  将构建目标或外部程序转换为可执行的命令数组。
27. **替换额外的参数:**  将参数列表中的占位符替换为实际的额外参数。
28. **替换输出路径:**  将参数列表中的占位符替换为实际的输出文件路径。
29. **获取默认构建的目标:**  获取标记为默认构建的构建目标。
30. **获取类似测试的目标:**  获取与测试或基准测试相关的构建目标。

**与逆向方法的关系及举例说明:**

这个代码片段本身不是直接用于逆向的工具，但它为构建用于逆向的工具（如 Frida 本身）提供了基础。

* **RPATH 处理:** 逆向工程师经常需要分析程序的依赖关系。了解 RPATH 的计算方式有助于理解程序运行时如何加载动态链接库。例如，如果一个恶意软件使用了非标准的库加载路径，逆向工程师可以通过分析其 RPATH 来定位这些库。
* **符号文件路径:** 调试和逆向分析严重依赖符号文件。此代码片段处理符号文件的路径，确保构建系统能找到它们，这对于生成包含调试信息的二进制文件至关重要，而这些信息对于逆向分析是宝贵的。例如，在使用 gdb 或 lldb 调试 Frida 自身时，正确的符号文件路径是必不可少的。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明:**

* **RPATH:** RPATH 是 Linux 等类 Unix 系统中用于指定动态链接库搜索路径的机制。代码中处理 RPATH 的部分需要理解 Linux 下动态链接器的工作原理。例如，`rpaths_for_non_system_absolute_shared_libraries` 方法会判断库文件是否在系统目录下，这需要了解哪些是常见的系统库目录。
* **DLL 路径处理 (Windows):**  Windows 没有 RPATH 的概念，但需要处理 DLL 的搜索路径。代码中的 `determine_windows_extra_paths` 和相关方法体现了对 Windows PE 文件格式和加载器行为的理解。例如，需要考虑 DLL 是否与可执行文件在同一目录，或者在 PATH 环境变量指定的路径中。
* **目标文件和链接:**  代码中生成目标文件名称和链接参数的部分与二进制文件的编译和链接过程直接相关，需要理解编译器和链接器的工作原理，以及不同操作系统下的目标文件格式（如 ELF, Mach-O, PE）。
* **测试执行:** 代码中处理测试执行的部分，特别是环境变量的设置（如 `LD_LIBRARY_PATH`），与 Linux 系统下运行程序的方式有关。例如，在运行依赖于特定动态链接库的测试程序时，可能需要设置 `LD_LIBRARY_PATH` 来指向这些库所在的目录。

**逻辑推理的假设输入与输出:**

假设输入一个构建目标 `my_shared_lib`，它依赖于一个绝对路径的共享库 `/opt/mylibs/libfoo.so`。

* **假设输入 (到 `rpaths_for_non_system_absolute_shared_libraries`):**  构建目标 `my_shared_lib`，其 `external_deps` 包含一个依赖项，该依赖项的 `link_args` 包含 `/opt/mylibs/libfoo.so`。
* **逻辑推理:**
    * 代码会判断 `/opt/mylibs/libfoo.so` 是绝对路径。
    * 代码会判断 `/opt/mylibs` 不是系统目录（假设 `/opt/mylibs` 不在常见的系统库路径中）。
    * 代码会添加到 RPATH 列表中。
* **预期输出:** `rpaths_for_non_system_absolute_shared_libraries` 方法会返回一个包含 `/opt/mylibs` 的列表。

**涉及用户或编程常见的使用错误及举例说明:**

* **错误的符号文件路径:** 用户可能使用 `--just-symbols` 参数指定了一个不存在的目录或一个文件，`_build_just_symbols_dirs` 方法会捕获这种情况并抛出 `MesonException`。
    * **用户操作:** 在运行 Meson 构建命令时，使用错误的 `--just-symbols /path/to/nonexistent/dir`。
    * **结果:**  Meson 会抛出异常，提示用户指定的路径不是一个有效的目录。
* **循环依赖导致无限 RPATH 计算:**  如果构建目标之间存在循环依赖，可能会导致 `rpaths_for_non_system_absolute_shared_libraries` 方法陷入无限递归。Meson 的其他部分通常会检测循环依赖，但理论上如果存在某种边缘情况，可能会导致问题。
    * **用户操作:**  在 `meson.build` 文件中定义了循环依赖的库。
    * **结果:** 虽然 Meson 通常会报错，但在某些复杂情况下，可能导致程序运行缓慢或崩溃。

**用户操作如何一步步到达这里，作为调试线索:**

1. **用户编写 `meson.build` 文件:**  用户定义了项目结构、依赖关系、构建目标等。
2. **用户运行 `meson` 命令配置构建:**  Meson 读取 `meson.build` 文件，并根据用户的配置生成构建系统。在这个过程中，会解析依赖关系，确定需要链接的库。
3. **用户运行 `ninja` (或其他构建工具) 进行编译和链接:**  构建工具根据 Meson 生成的构建文件执行编译和链接命令。
4. **当构建链接共享库或可执行文件时:**  `backends.py` 中的相关方法会被调用，例如 `rpaths_for_non_system_absolute_shared_libraries` 会被调用来计算需要添加到链接器命令中的 RPATH 参数。
5. **当构建包含测试用例的项目时:**  `create_test_serialisation` 和 `write_test_serialisation` 等方法会被调用，将测试用例的信息写入文件，供测试运行器使用。
6. **在调试构建系统本身的问题时:**  开发者可能会直接查看 `backends.py` 的代码，例如当链接器报告找不到共享库时，可能会怀疑 RPATH 的计算是否有问题，从而查看 `rpaths_for_non_system_absolute_shared_libraries` 的实现。

**归纳其功能 (第 2 部分):**

这部分代码主要负责 **构建过程中与链接和测试执行相关的核心逻辑**。它处理了动态链接库的运行时路径 (RPATH) 的计算、Windows 下 DLL 路径的管理、目标文件的命名、测试用例的组织和序列化，以及构建系统重新生成所需的依赖信息。 这些功能是构建工具的关键组成部分，确保构建出的软件能够正确链接依赖库并在运行时找到它们，并且能够正确地执行和管理测试用例。

### 提示词
```
这是目录为frida/subprojects/frida-python/releng/meson/mesonbuild/backend/backends.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```python
if Path(dir).is_dir():
                        dirs.add(dir)
            symbols_match = symbols_regex.match(arg)
            if symbols_match:
                for dir in symbols_match.group(1).split(':'):
                    # Prevent usage of --just-symbols to specify rpath
                    if Path(dir).is_dir():
                        raise MesonException(f'Invalid arg for --just-symbols, {dir} is a directory.')
        return dirs

    @lru_cache(maxsize=None)
    def rpaths_for_non_system_absolute_shared_libraries(self, target: build.BuildTarget, exclude_system: bool = True) -> 'ImmutableListProtocol[str]':
        paths: OrderedSet[str] = OrderedSet()
        srcdir = self.environment.get_source_dir()

        for dep in target.external_deps:
            if dep.type_name not in {'library', 'pkgconfig', 'cmake'}:
                continue
            for libpath in dep.link_args:
                # For all link args that are absolute paths to a library file, add RPATH args
                if not os.path.isabs(libpath):
                    continue
                libdir = os.path.dirname(libpath)
                if exclude_system and self._libdir_is_system(libdir, target.compilers, self.environment):
                    # No point in adding system paths.
                    continue
                # Don't remove rpaths specified in LDFLAGS.
                if libdir in self.get_external_rpath_dirs(target):
                    continue
                # Windows doesn't support rpaths, but we use this function to
                # emulate rpaths by setting PATH
                # .dll is there for mingw gcc
                # .so's may be extended with version information, e.g. libxyz.so.1.2.3
                if not (
                    os.path.splitext(libpath)[1] in {'.dll', '.lib', '.so', '.dylib'}
                    or re.match(r'.+\.so(\.|$)', os.path.basename(libpath))
                ):
                    continue

                try:
                    commonpath = os.path.commonpath((libdir, srcdir))
                except ValueError: # when paths are on different drives on Windows
                    commonpath = ''

                if commonpath == srcdir:
                    rel_to_src = libdir[len(srcdir) + 1:]
                    assert not os.path.isabs(rel_to_src), f'rel_to_src: {rel_to_src} is absolute'
                    paths.add(os.path.join(self.build_to_src, rel_to_src))
                else:
                    paths.add(libdir)
            # Don't remove rpaths specified by the dependency
            paths.difference_update(self.get_rpath_dirs_from_link_args(dep.link_args))
        for i in chain(target.link_targets, target.link_whole_targets):
            if isinstance(i, build.BuildTarget):
                paths.update(self.rpaths_for_non_system_absolute_shared_libraries(i, exclude_system))
        return list(paths)

    # This may take other types
    def determine_rpath_dirs(self, target: T.Union[build.BuildTarget, build.CustomTarget, build.CustomTargetIndex]
                             ) -> T.Tuple[str, ...]:
        result: OrderedSet[str]
        if self.environment.coredata.get_option(OptionKey('layout')) == 'mirror':
            # Need a copy here
            result = OrderedSet(target.get_link_dep_subdirs())
        else:
            result = OrderedSet()
            result.add('meson-out')
        if isinstance(target, build.BuildTarget):
            result.update(self.rpaths_for_non_system_absolute_shared_libraries(target))
            target.rpath_dirs_to_remove.update([d.encode('utf-8') for d in result])
        return tuple(result)

    @staticmethod
    def canonicalize_filename(fname: str) -> str:
        parts = Path(fname).parts
        hashed = ''
        if len(parts) > 5:
            temp = '/'.join(parts[-5:])
            # is it shorter to hash the beginning of the path?
            if len(fname) > len(temp) + 41:
                hashed = hashlib.sha1(fname.encode('utf-8')).hexdigest() + '_'
                fname = temp
        for ch in ('/', '\\', ':'):
            fname = fname.replace(ch, '_')
        return hashed + fname

    def object_filename_from_source(self, target: build.BuildTarget, source: 'FileOrString', targetdir: T.Optional[str] = None) -> str:
        assert isinstance(source, mesonlib.File)
        if isinstance(target, build.CompileTarget):
            return target.sources_map[source]
        build_dir = self.environment.get_build_dir()
        rel_src = source.rel_to_builddir(self.build_to_src)

        # foo.vala files compile down to foo.c and then foo.c.o, not foo.vala.o
        if rel_src.endswith(('.vala', '.gs')):
            # See description in generate_vala_compile for this logic.
            if source.is_built:
                if os.path.isabs(rel_src):
                    rel_src = rel_src[len(build_dir) + 1:]
                rel_src = os.path.relpath(rel_src, self.get_target_private_dir(target))
            else:
                rel_src = os.path.basename(rel_src)
            # A meson- prefixed directory is reserved; hopefully no-one creates a file name with such a weird prefix.
            gen_source = 'meson-generated_' + rel_src[:-5] + '.c'
        elif source.is_built:
            if os.path.isabs(rel_src):
                rel_src = rel_src[len(build_dir) + 1:]
            # A meson- prefixed directory is reserved; hopefully no-one creates a file name with such a weird prefix.
            gen_source = 'meson-generated_' + os.path.relpath(rel_src, self.get_target_private_dir(target))
        else:
            if os.path.isabs(rel_src):
                # Use the absolute path directly to avoid file name conflicts
                gen_source = rel_src
            else:
                gen_source = os.path.relpath(os.path.join(build_dir, rel_src),
                                             os.path.join(self.environment.get_source_dir(), target.get_source_subdir()))
        machine = self.environment.machines[target.for_machine]
        ret = self.canonicalize_filename(gen_source) + '.' + machine.get_object_suffix()
        if targetdir is not None:
            return os.path.join(targetdir, ret)
        return ret

    def _determine_ext_objs(self, extobj: 'build.ExtractedObjects', proj_dir_to_build_root: str) -> T.List[str]:
        result: T.List[str] = []

        targetdir = self.get_target_private_dir(extobj.target)

        # Merge sources and generated sources
        raw_sources = list(extobj.srclist)
        for gensrc in extobj.genlist:
            for r in gensrc.get_outputs():
                path = self.get_target_generated_dir(extobj.target, gensrc, r)
                dirpart, fnamepart = os.path.split(path)
                raw_sources.append(File(True, dirpart, fnamepart))

        # Filter out headers and all non-source files
        sources: T.List['FileOrString'] = []
        for s in raw_sources:
            if self.environment.is_source(s):
                sources.append(s)
            elif self.environment.is_object(s):
                result.append(s.relative_name())

        # MSVC generate an object file for PCH
        if extobj.pch and self.target_uses_pch(extobj.target):
            for lang, pch in extobj.target.pch.items():
                compiler = extobj.target.compilers[lang]
                if compiler.get_argument_syntax() == 'msvc':
                    objname = self.get_msvc_pch_objname(lang, pch)
                    result.append(os.path.join(proj_dir_to_build_root, targetdir, objname))

        # extobj could contain only objects and no sources
        if not sources:
            return result

        # With unity builds, sources don't map directly to objects,
        # we only support extracting all the objects in this mode,
        # so just return all object files.
        if extobj.target.is_unity:
            compsrcs = classify_unity_sources(extobj.target.compilers.values(), sources)
            sources = []
            unity_size = extobj.target.get_option(OptionKey('unity_size'))
            assert isinstance(unity_size, int), 'for mypy'

            for comp, srcs in compsrcs.items():
                if comp.language in LANGS_CANT_UNITY:
                    sources += srcs
                    continue
                for i in range((len(srcs) + unity_size - 1) // unity_size):
                    _src = self.get_unity_source_file(extobj.target,
                                                      comp.get_default_suffix(), i)
                    sources.append(_src)

        for osrc in sources:
            objname = self.object_filename_from_source(extobj.target, osrc, targetdir)
            objpath = os.path.join(proj_dir_to_build_root, objname)
            result.append(objpath)

        return result

    def get_pch_include_args(self, compiler: 'Compiler', target: build.BuildTarget) -> T.List[str]:
        args: T.List[str] = []
        pchpath = self.get_target_private_dir(target)
        includeargs = compiler.get_include_args(pchpath, False)
        p = target.get_pch(compiler.get_language())
        if p:
            args += compiler.get_pch_use_args(pchpath, p[0])
        return includeargs + args

    def get_msvc_pch_objname(self, lang: str, pch: T.List[str]) -> str:
        if len(pch) == 1:
            # Same name as in create_msvc_pch_implementation() below.
            return f'meson_pch-{lang}.obj'
        return os.path.splitext(pch[1])[0] + '.obj'

    def create_msvc_pch_implementation(self, target: build.BuildTarget, lang: str, pch_header: str) -> str:
        # We have to include the language in the file name, otherwise
        # pch.c and pch.cpp will both end up as pch.obj in VS backends.
        impl_name = f'meson_pch-{lang}.{lang}'
        pch_rel_to_build = os.path.join(self.get_target_private_dir(target), impl_name)
        # Make sure to prepend the build dir, since the working directory is
        # not defined. Otherwise, we might create the file in the wrong path.
        pch_file = os.path.join(self.build_dir, pch_rel_to_build)
        os.makedirs(os.path.dirname(pch_file), exist_ok=True)

        content = f'#include "{os.path.basename(pch_header)}"'
        pch_file_tmp = pch_file + '.tmp'
        with open(pch_file_tmp, 'w', encoding='utf-8') as f:
            f.write(content)
        mesonlib.replace_if_different(pch_file, pch_file_tmp)
        return pch_rel_to_build

    def target_uses_pch(self, target: build.BuildTarget) -> bool:
        try:
            return T.cast('bool', target.get_option(OptionKey('b_pch')))
        except KeyError:
            return False

    @staticmethod
    def escape_extra_args(args: T.List[str]) -> T.List[str]:
        # all backslashes in defines are doubly-escaped
        extra_args: T.List[str] = []
        for arg in args:
            if arg.startswith(('-D', '/D')):
                arg = arg.replace('\\', '\\\\')
            extra_args.append(arg)

        return extra_args

    def get_no_stdlib_args(self, target: 'build.BuildTarget', compiler: 'Compiler') -> T.List[str]:
        if compiler.language in self.build.stdlibs[target.for_machine]:
            return compiler.get_no_stdinc_args()
        return []

    def generate_basic_compiler_args(self, target: build.BuildTarget, compiler: 'Compiler') -> 'CompilerArgs':
        # Create an empty commands list, and start adding arguments from
        # various sources in the order in which they must override each other
        # starting from hard-coded defaults followed by build options and so on.
        commands = compiler.compiler_args()

        copt_proxy = target.get_options()
        # First, the trivial ones that are impossible to override.
        #
        # Add -nostdinc/-nostdinc++ if needed; can't be overridden
        commands += self.get_no_stdlib_args(target, compiler)
        # Add things like /NOLOGO or -pipe; usually can't be overridden
        commands += compiler.get_always_args()
        # warning_level is a string, but mypy can't determine that
        commands += compiler.get_warn_args(T.cast('str', target.get_option(OptionKey('warning_level'))))
        # Add -Werror if werror=true is set in the build options set on the
        # command-line or default_options inside project(). This only sets the
        # action to be done for warnings if/when they are emitted, so it's ok
        # to set it after or get_warn_args().
        if target.get_option(OptionKey('werror')):
            commands += compiler.get_werror_args()
        # Add compile args for c_* or cpp_* build options set on the
        # command-line or default_options inside project().
        commands += compiler.get_option_compile_args(copt_proxy)

        optimization = target.get_option(OptionKey('optimization'))
        assert isinstance(optimization, str), 'for mypy'
        commands += compiler.get_optimization_args(optimization)

        debug = target.get_option(OptionKey('debug'))
        assert isinstance(debug, bool), 'for mypy'
        commands += compiler.get_debug_args(debug)

        # Add compile args added using add_project_arguments()
        commands += self.build.get_project_args(compiler, target.subproject, target.for_machine)
        # Add compile args added using add_global_arguments()
        # These override per-project arguments
        commands += self.build.get_global_args(compiler, target.for_machine)
        # Compile args added from the env: CFLAGS/CXXFLAGS, etc, or the cross
        # file. We want these to override all the defaults, but not the
        # per-target compile args.
        commands += self.environment.coredata.get_external_args(target.for_machine, compiler.get_language())
        # Using both /Z7 or /ZI and /Zi at the same times produces a compiler warning.
        # We do not add /Z7 or /ZI by default. If it is being used it is because the user has explicitly enabled it.
        # /Zi needs to be removed in that case to avoid cl's warning to that effect (D9025 : overriding '/Zi' with '/ZI')
        if ('/Zi' in commands) and (('/ZI' in commands) or ('/Z7' in commands)):
            commands.remove('/Zi')
        # Always set -fPIC for shared libraries
        if isinstance(target, build.SharedLibrary):
            commands += compiler.get_pic_args()
        # Set -fPIC for static libraries by default unless explicitly disabled
        if isinstance(target, build.StaticLibrary) and target.pic:
            commands += compiler.get_pic_args()
        elif isinstance(target, (build.StaticLibrary, build.Executable)) and target.pie:
            commands += compiler.get_pie_args()
        # Add compile args needed to find external dependencies. Link args are
        # added while generating the link command.
        # NOTE: We must preserve the order in which external deps are
        # specified, so we reverse the list before iterating over it.
        for dep in reversed(target.get_external_deps()):
            if not dep.found():
                continue

            if compiler.language == 'vala':
                if dep.type_name == 'pkgconfig':
                    assert isinstance(dep, dependencies.ExternalDependency)
                    if dep.name == 'glib-2.0' and dep.version_reqs is not None:
                        for req in dep.version_reqs:
                            if req.startswith(('>=', '==')):
                                commands += ['--target-glib', req[2:].lstrip()]
                                break
                    commands += ['--pkg', dep.name]
                elif isinstance(dep, dependencies.ExternalLibrary):
                    commands += dep.get_link_args('vala')
            else:
                commands += compiler.get_dependency_compile_args(dep)
            # Qt needs -fPIC for executables
            # XXX: We should move to -fPIC for all executables
            if isinstance(target, build.Executable):
                commands += dep.get_exe_args(compiler)
            # For 'automagic' deps: Boost and GTest. Also dependency('threads').
            # pkg-config puts the thread flags itself via `Cflags:`
        # Fortran requires extra include directives.
        if compiler.language == 'fortran':
            for lt in chain(target.link_targets, target.link_whole_targets):
                priv_dir = self.get_target_private_dir(lt)
                commands += compiler.get_include_args(priv_dir, False)
        return commands

    def build_target_link_arguments(self, compiler: 'Compiler', deps: T.List[build.Target]) -> T.List[str]:
        args: T.List[str] = []
        for d in deps:
            if not d.is_linkable_target():
                raise RuntimeError(f'Tried to link with a non-library target "{d.get_basename()}".')
            arg = self.get_target_filename_for_linking(d)
            if not arg:
                continue
            if compiler.get_language() == 'd':
                arg = '-Wl,' + arg
            else:
                arg = compiler.get_linker_lib_prefix() + arg
            args.append(arg)
        return args

    def get_mingw_extra_paths(self, target: build.BuildTarget) -> T.List[str]:
        paths: OrderedSet[str] = OrderedSet()
        # The cross bindir
        root = self.environment.properties[target.for_machine].get_root()
        if root:
            paths.add(os.path.join(root, 'bin'))
        # The toolchain bindir
        sys_root = self.environment.properties[target.for_machine].get_sys_root()
        if sys_root:
            paths.add(os.path.join(sys_root, 'bin'))
        # Get program and library dirs from all target compilers
        if isinstance(target, build.BuildTarget):
            for cc in target.compilers.values():
                paths.update(cc.get_program_dirs(self.environment))
                paths.update(cc.get_library_dirs(self.environment))
        return list(paths)

    @staticmethod
    @lru_cache(maxsize=None)
    def search_dll_path(link_arg: str) -> T.Optional[str]:
        if link_arg.startswith(('-l', '-L')):
            link_arg = link_arg[2:]

        p = Path(link_arg)
        if not p.is_absolute():
            return None

        try:
            p = p.resolve(strict=True)
        except FileNotFoundError:
            return None

        for f in p.parent.glob('*.dll'):
            # path contains dlls
            return str(p.parent)

        if p.is_file():
            p = p.parent
        # Heuristic: replace *last* occurence of '/lib'
        binpath = Path('/bin'.join(p.as_posix().rsplit('/lib', maxsplit=1)))
        for _ in binpath.glob('*.dll'):
            return str(binpath)

        return None

    @classmethod
    @lru_cache(maxsize=None)
    def extract_dll_paths(cls, target: build.BuildTarget) -> T.Set[str]:
        """Find paths to all DLLs needed for a given target, since
        we link against import libs, and we don't know the actual
        path of the DLLs.

        1. If there are DLLs in the same directory than the .lib dir, use it
        2. If there is a sibbling directory named 'bin' with DLLs in it, use it
        """
        results = set()
        for dep in target.external_deps:

            if dep.type_name == 'pkgconfig':
                # If by chance pkg-config knows the bin dir...
                bindir = dep.get_variable(pkgconfig='bindir', default_value='')
                if bindir:
                    results.add(bindir)
                    continue

            results.update(filter(None, map(cls.search_dll_path, dep.link_args)))  # pylint: disable=bad-builtin

        for i in chain(target.link_targets, target.link_whole_targets):
            if isinstance(i, build.BuildTarget):
                results.update(cls.extract_dll_paths(i))

        return results

    def determine_windows_extra_paths(
            self, target: T.Union[build.BuildTarget, build.CustomTarget, build.CustomTargetIndex, programs.ExternalProgram, mesonlib.File, str],
            extra_bdeps: T.Sequence[T.Union[build.BuildTarget, build.CustomTarget]]) -> T.List[str]:
        """On Windows there is no such thing as an rpath.

        We must determine all locations of DLLs that this exe
        links to and return them so they can be used in unit
        tests.
        """
        result: T.Set[str] = set()
        prospectives: T.Set[build.BuildTargetTypes] = set()
        if isinstance(target, build.BuildTarget):
            prospectives.update(target.get_transitive_link_deps())
            # External deps
            result.update(self.extract_dll_paths(target))

        for bdep in extra_bdeps:
            prospectives.add(bdep)
            if isinstance(bdep, build.BuildTarget):
                prospectives.update(bdep.get_transitive_link_deps())
        # Internal deps
        for ld in prospectives:
            dirseg = os.path.join(self.environment.get_build_dir(), self.get_target_dir(ld))
            result.add(dirseg)
        if (isinstance(target, build.BuildTarget) and
                not self.environment.machines.matches_build_machine(target.for_machine)):
            result.update(self.get_mingw_extra_paths(target))
        return list(result)

    def write_benchmark_file(self, datafile: T.BinaryIO) -> None:
        self.write_test_serialisation(self.build.get_benchmarks(), datafile)

    def write_test_file(self, datafile: T.BinaryIO) -> None:
        self.write_test_serialisation(self.build.get_tests(), datafile)

    def create_test_serialisation(self, tests: T.List['Test']) -> T.List[TestSerialisation]:
        arr: T.List[TestSerialisation] = []
        for t in sorted(tests, key=lambda tst: -1 * tst.priority):
            exe = t.get_exe()
            if isinstance(exe, programs.ExternalProgram):
                cmd = exe.get_command()
            else:
                cmd = [os.path.join(self.environment.get_build_dir(), self.get_target_filename(exe))]
            if isinstance(exe, (build.BuildTarget, programs.ExternalProgram)):
                test_for_machine = exe.for_machine
            else:
                # E.g. an external verifier or simulator program run on a generated executable.
                # Can always be run without a wrapper.
                test_for_machine = MachineChoice.BUILD

            # we allow passing compiled executables to tests, which may be cross built.
            # We need to consider these as well when considering whether the target is cross or not.
            for a in t.cmd_args:
                if isinstance(a, build.BuildTarget):
                    if a.for_machine is MachineChoice.HOST:
                        test_for_machine = MachineChoice.HOST
                        break

            is_cross = self.environment.is_cross_build(test_for_machine)
            exe_wrapper = self.environment.get_exe_wrapper()
            machine = self.environment.machines[exe.for_machine]
            if machine.is_windows() or machine.is_cygwin():
                extra_bdeps: T.List[T.Union[build.BuildTarget, build.CustomTarget]] = []
                if isinstance(exe, build.CustomTarget):
                    extra_bdeps = list(exe.get_transitive_build_target_deps())
                extra_paths = self.determine_windows_extra_paths(exe, extra_bdeps)
                for a in t.cmd_args:
                    if isinstance(a, build.BuildTarget):
                        for p in self.determine_windows_extra_paths(a, []):
                            if p not in extra_paths:
                                extra_paths.append(p)
            else:
                extra_paths = []

            cmd_args: T.List[str] = []
            depends: T.Set[build.Target] = set(t.depends)
            if isinstance(exe, build.Target):
                depends.add(exe)
            for a in t.cmd_args:
                if isinstance(a, build.Target):
                    depends.add(a)
                elif isinstance(a, build.CustomTargetIndex):
                    depends.add(a.target)

                if isinstance(a, mesonlib.File):
                    a = os.path.join(self.environment.get_build_dir(), a.rel_to_builddir(self.build_to_src))
                    cmd_args.append(a)
                elif isinstance(a, str):
                    cmd_args.append(a)
                elif isinstance(a, (build.Target, build.CustomTargetIndex)):
                    cmd_args.extend(self.construct_target_rel_paths(a, t.workdir))
                else:
                    raise MesonException('Bad object in test command.')

            t_env = copy.deepcopy(t.env)
            if not machine.is_windows() and not machine.is_cygwin() and not machine.is_darwin():
                ld_lib_path: T.Set[str] = set()
                for d in depends:
                    if isinstance(d, build.BuildTarget):
                        for l in d.get_all_link_deps():
                            if isinstance(l, build.SharedLibrary):
                                ld_lib_path.add(os.path.join(self.environment.get_build_dir(), l.get_output_subdir()))
                if ld_lib_path:
                    t_env.prepend('LD_LIBRARY_PATH', list(ld_lib_path), ':')

            ts = TestSerialisation(t.get_name(), t.project_name, t.suite, cmd, is_cross,
                                   exe_wrapper, self.environment.need_exe_wrapper(),
                                   t.is_parallel, cmd_args, t_env,
                                   t.should_fail, t.timeout, t.workdir,
                                   extra_paths, t.protocol, t.priority,
                                   isinstance(exe, (build.Target, build.CustomTargetIndex)),
                                   isinstance(exe, build.Executable),
                                   [x.get_id() for x in depends],
                                   self.environment.coredata.version,
                                   t.verbose)
            arr.append(ts)
        return arr

    def write_test_serialisation(self, tests: T.List['Test'], datafile: T.BinaryIO) -> None:
        pickle.dump(self.create_test_serialisation(tests), datafile)

    def construct_target_rel_paths(self, t: T.Union[build.Target, build.CustomTargetIndex], workdir: T.Optional[str]) -> T.List[str]:
        target_dir = self.get_target_dir(t)
        # ensure that test executables can be run when passed as arguments
        if isinstance(t, build.Executable) and workdir is None:
            target_dir = target_dir or '.'

        if isinstance(t, build.BuildTarget):
            outputs = [t.get_filename()]
        else:
            assert isinstance(t, (build.CustomTarget, build.CustomTargetIndex))
            outputs = t.get_outputs()

        outputs = [os.path.join(target_dir, x) for x in outputs]
        if workdir is not None:
            assert os.path.isabs(workdir)
            outputs = [os.path.join(self.environment.get_build_dir(), x) for x in outputs]
            outputs = [os.path.relpath(x, workdir) for x in outputs]
        return outputs

    def generate_depmf_install(self, d: InstallData) -> None:
        depmf_path = self.build.dep_manifest_name
        if depmf_path is None:
            option_dir = self.environment.coredata.get_option(OptionKey('licensedir'))
            assert isinstance(option_dir, str), 'for mypy'
            if option_dir:
                depmf_path = os.path.join(option_dir, 'depmf.json')
            else:
                return
        ifilename = os.path.join(self.environment.get_build_dir(), 'depmf.json')
        ofilename = os.path.join(self.environment.get_prefix(), depmf_path)
        odirname = os.path.join(self.environment.get_prefix(), os.path.dirname(depmf_path))
        out_name = os.path.join('{prefix}', depmf_path)
        out_dir = os.path.join('{prefix}', os.path.dirname(depmf_path))
        mfobj = {'type': 'dependency manifest', 'version': '1.0',
                 'projects': {k: v.to_json() for k, v in self.build.dep_manifest.items()}}
        with open(ifilename, 'w', encoding='utf-8') as f:
            f.write(json.dumps(mfobj))
        # Copy file from, to, and with mode unchanged
        d.data.append(InstallDataBase(ifilename, ofilename, out_name, None, '',
                                      tag='devel', data_type='depmf'))
        for m in self.build.dep_manifest.values():
            for ifilename, name in m.license_files:
                ofilename = os.path.join(odirname, name.relative_name())
                out_name = os.path.join(out_dir, name.relative_name())
                d.data.append(InstallDataBase(ifilename, ofilename, out_name, None,
                                              m.subproject, tag='devel', data_type='depmf'))

    def get_regen_filelist(self) -> T.List[str]:
        '''List of all files whose alteration means that the build
        definition needs to be regenerated.'''
        deps = OrderedSet([str(Path(self.build_to_src) / df)
                           for df in self.interpreter.get_build_def_files()])
        if self.environment.is_cross_build():
            deps.update(self.environment.coredata.cross_files)
        deps.update(self.environment.coredata.config_files)
        deps.add('meson-private/coredata.dat')
        self.check_clock_skew(deps)
        return list(deps)

    def generate_regen_info(self) -> None:
        deps = self.get_regen_filelist()
        regeninfo = RegenInfo(self.environment.get_source_dir(),
                              self.environment.get_build_dir(),
                              deps)
        filename = os.path.join(self.environment.get_scratch_dir(),
                                'regeninfo.dump')
        with open(filename, 'wb') as f:
            pickle.dump(regeninfo, f)

    def check_clock_skew(self, file_list: T.Iterable[str]) -> None:
        # If a file that leads to reconfiguration has a time
        # stamp in the future, it will trigger an eternal reconfigure
        # loop.
        import time
        now = time.time()
        for f in file_list:
            absf = os.path.join(self.environment.get_build_dir(), f)
            ftime = os.path.getmtime(absf)
            delta = ftime - now
            # On Windows disk time stamps sometimes point
            # to the future by a minuscule amount, less than
            # 0.001 seconds. I don't know why.
            if delta > 0.001:
                raise MesonException(f'Clock skew detected. File {absf} has a time stamp {delta:.4f}s in the future.')

    def build_target_to_cmd_array(self, bt: T.Union[build.BuildTarget, programs.ExternalProgram]) -> T.List[str]:
        if isinstance(bt, build.BuildTarget):
            arr = [os.path.join(self.environment.get_build_dir(), self.get_target_filename(bt))]
        else:
            arr = bt.get_command()
        return arr

    def replace_extra_args(self, args: T.List[str], genlist: 'build.GeneratedList') -> T.List[str]:
        final_args: T.List[str] = []
        for a in args:
            if a == '@EXTRA_ARGS@':
                final_args += genlist.get_extra_args()
            else:
                final_args.append(a)
        return final_args

    def replace_outputs(self, args: T.List[str], private_dir: str, output_list: T.List[str]) -> T.List[str]:
        newargs: T.List[str] = []
        regex = re.compile(r'@OUTPUT(\d+)@')
        for arg in args:
            m = regex.search(arg)
            while m is not None:
                index = int(m.group(1))
                src = f'@OUTPUT{index}@'
                arg = arg.replace(src, os.path.join(private_dir, output_list[index]))
                m = regex.search(arg)
            newargs.append(arg)
        return newargs

    def get_build_by_default_targets(self) -> 'T.OrderedDict[str, T.Union[build.BuildTarget, build.CustomTarget]]':
        result: 'T.OrderedDict[str, T.Union[build.BuildTarget, build.CustomTarget]]' = OrderedDict()
        # Get all build and custom targets that must be built by default
        for name, b in self.build.get_targets().items():
            if b.build_by_default:
                result[name] = b
        return result

    def get_testlike_targets(self, benchmark: bool = False) -> T.OrderedDict[str, T.Union[build.BuildTarget, build.CustomTarget]]:
        result: T.OrderedDict[str, T.Union[build.BuildTarget, build.CustomTarget]] = OrderedDict()
        targets = self.build.get_benchmarks() if benchmark else self.build.get_tests()
        for t in targets:
            exe = t.exe
            if isinstance(exe, (build.CustomTarget, build.BuildTarget)):
                result[exe.get_id()] = exe
            for arg in t.cmd_args:
                if not isinstance(arg, (build.CustomTarget, build.BuildTarget)):
                    continue
                result[arg.get_id()]
```