Response:
The user wants a summary of the functionalities of the provided Python code snippet. I need to analyze the code and extract its core responsibilities. The user is particularly interested in how these functionalities relate to reverse engineering, low-level programming (Linux, Android kernel/framework), logical inference, common user errors, and debugging.

Here's a breakdown of the thought process:

1. **Identify the Core Purpose:** The code is part of the `backends.py` file in the Frida dynamic instrumentation tool's Meson build system. This suggests its primary role is to handle backend-specific build processes.

2. **Analyze Individual Functions:** I will go through each function and determine its purpose.

3. **Categorize Functionalities:**  Based on the function's purpose, I will categorize it according to the user's specific interests:
    * **Reverse Engineering:** Look for functions dealing with shared libraries, RPATHs, DLL paths, and potentially anything related to executable linking and loading.
    * **Binary/Low-Level (Linux/Android):**  Functions dealing with object files, compiler arguments (like `-fPIC`), RPATHs (common on Linux), and handling of shared libraries. Android relevance might be implicit in the general shared library handling or if there's explicit mention of Android.
    * **Logical Inference:** Look for conditional logic, especially in functions that determine build behavior based on different inputs or configurations.
    * **User Errors:**  Identify functions that validate user input or handle potential misconfigurations.
    * **Debugging:**  Consider how the functions contribute to making the build process understandable and debuggable. The generation of test files is a clear debugging aid.

4. **Provide Examples:** For each relevant category, I will provide concrete examples based on the code.

5. **Trace User Operations:** I will infer the user actions that could lead to the execution of these functions, primarily focusing on the build process triggered by Meson.

6. **Formulate Assumptions and Outputs:** Where logical inference is involved, I'll provide hypothetical inputs and expected outputs to illustrate the function's behavior.

7. **Address the "Part 2" Request:**  Explicitly state that the summary is for the provided code snippet, which is part 2 of a larger file.

**Detailed Function Analysis and Categorization:**

* **`get_external_rpath_dirs`:**  Related to reverse engineering (RPATHs are crucial for locating shared libraries at runtime).
* **`get_rpath_dirs_from_link_args`:**  Also related to RPATHs and reverse engineering.
* **`rpaths_for_non_system_absolute_shared_libraries`:** Directly related to reverse engineering, Linux shared libraries.
* **`determine_rpath_dirs`:**  Core function for setting up RPATHs, thus relevant to reverse engineering and Linux systems.
* **`canonicalize_filename`:**  Potentially relevant to low-level details of how object files are named and organized.
* **`object_filename_from_source`:** Directly related to the binary level and how source files are transformed into object files.
* **`_determine_ext_objs`:** Deals with extracting object files, crucial for understanding the binary structure of the project.
* **`get_pch_include_args`:**  Relevant to compiler behavior and low-level compilation details.
* **`get_msvc_pch_objname` and `create_msvc_pch_implementation`:**  Windows-specific, but still low-level details of compilation.
* **`target_uses_pch`:**  Configuration related to precompiled headers.
* **`escape_extra_args`:**  String manipulation for compiler arguments.
* **`get_no_stdlib_args`:**  Relevant to low-level linking and understanding dependencies.
* **`generate_basic_compiler_args`:**  Central to the compilation process and understanding how compiler flags are set, directly impacting the generated binary.
* **`build_target_link_arguments`:**  Key to linking and creating the final executable or library.
* **`get_mingw_extra_paths`:** Windows-specific path handling.
* **`search_dll_path` and `extract_dll_paths`:** Crucial for understanding Windows DLL dependencies, relevant to reverse engineering on Windows.
* **`determine_windows_extra_paths`:** Windows-specific, but helps in understanding how the runtime environment is set up.
* **`write_benchmark_file` and `write_test_file`:**  Related to testing and quality assurance.
* **`create_test_serialisation` and `write_test_serialisation`:**  Serialization of test information.
* **`construct_target_rel_paths`:**  File path manipulation.
* **`generate_depmf_install`:** Generation of dependency manifests.
* **`get_regen_filelist` and `generate_regen_info`:**  Related to the build system's management of dependencies and rebuild triggers.
* **`check_clock_skew`:** Error handling for a specific build issue.
* **`build_target_to_cmd_array`:**  Converting build targets into executable commands.
* **`replace_extra_args` and `replace_outputs`:** String manipulation for command construction.
* **`get_build_by_default_targets` and `get_testlike_targets`:**  Identifying specific types of build targets.

**Self-Correction/Refinement:** Initially, I might have focused too much on just the "reverse engineering" aspect. However, after analyzing all the functions, it's clear that the code covers a broader range of build system responsibilities, including compilation, linking, dependency management, and testing. I need to ensure the summary reflects this wider scope. Also, explicitly mentioning the relationship to Meson is important for context.

By following this thought process, I can generate a comprehensive and accurate summary that addresses all the user's requirements.
这是 frida 动态插桩工具的构建系统中 `backends.py` 文件的一部分，主要负责处理构建后端的具体实现细节，例如如何生成链接库的运行时路径（RPATH），如何确定目标文件的名称，以及如何生成测试相关的配置信息。

**以下是代码片段的功能归纳：**

1. **计算和管理运行时库路径 (RPATHs)：**
   - `get_external_rpath_dirs`:  获取外部依赖项中指定的运行时库路径。
   - `get_rpath_dirs_from_link_args`: 从链接参数中提取运行时库路径。
   - `rpaths_for_non_system_absolute_shared_libraries`:  为非系统绝对路径的共享库确定运行时库路径。这对于确保动态链接器在运行时能找到所需的共享库至关重要。
   - `determine_rpath_dirs`: 确定目标（例如可执行文件或共享库）的运行时库路径。

2. **处理目标文件名：**
   - `canonicalize_filename`:  规范化文件名，以避免特殊字符或过长路径导致的问题。
   - `object_filename_from_source`:  根据源文件生成对应的目标文件（.o 或 .obj）的名称。
   - `_determine_ext_objs`:  确定提取对象文件列表，包括处理预编译头文件（PCH）。

3. **处理预编译头文件 (PCH)：**
   - `get_pch_include_args`: 获取使用预编译头文件所需的编译器参数。
   - `get_msvc_pch_objname`:  获取 MSVC 编译器预编译头文件的目标文件名。
   - `create_msvc_pch_implementation`:  创建 MSVC 编译器预编译头文件的实现文件。
   - `target_uses_pch`:  检查目标是否使用预编译头文件。

4. **处理编译器参数：**
   - `escape_extra_args`:  转义额外的编译器参数。
   - `get_no_stdlib_args`:  获取禁用标准库包含路径的编译器参数。
   - `generate_basic_compiler_args`:  生成基本的编译器参数，包括优化级别、调试信息、包含路径等。

5. **处理链接器参数：**
   - `build_target_link_arguments`:  生成链接目标所需的链接器参数。

6. **处理 Windows 平台特定的路径问题：**
   - `get_mingw_extra_paths`:  获取 MinGW 环境下额外的路径。
   - `search_dll_path`:  搜索 DLL 文件的路径。
   - `extract_dll_paths`:  提取目标依赖的 DLL 文件的路径。
   - `determine_windows_extra_paths`:  确定 Windows 平台下额外的路径，用于查找 DLL 文件。

7. **生成测试相关文件：**
   - `write_benchmark_file`:  写入基准测试文件。
   - `write_test_file`: 写入测试文件。
   - `create_test_serialisation`: 创建测试用例的序列化表示。
   - `write_test_serialisation`: 将测试用例序列化数据写入文件。
   - `construct_target_rel_paths`: 构建目标文件相对于工作目录的相对路径。

8. **处理依赖清单：**
   - `generate_depmf_install`:  生成依赖清单的安装信息。

9. **处理构建定义文件的变更：**
   - `get_regen_filelist`: 获取需要重新生成构建定义的文件列表。
   - `generate_regen_info`: 生成重新构建所需的信息。
   - `check_clock_skew`: 检查文件时间戳是否存在时钟偏差问题。

10. **辅助函数：**
    - `build_target_to_cmd_array`: 将构建目标转换为命令行数组。
    - `replace_extra_args`: 替换命令参数中的 `@EXTRA_ARGS@` 占位符。
    - `replace_outputs`: 替换命令参数中的 `@OUTPUTn@` 占位符。
    - `get_build_by_default_targets`: 获取默认需要构建的目标。
    - `get_testlike_targets`: 获取类似测试的目标（包括基准测试）。

**与逆向方法的关联及举例：**

- **运行时库路径 (RPATHs) 的管理：**  在逆向分析中，理解目标程序依赖哪些共享库以及这些库的加载路径至关重要。RPATH 的设置决定了动态链接器在运行时搜索共享库的顺序。如果 RPATH 设置不当，可能导致程序无法找到所需的库。
    - **举例：** 如果要逆向一个使用了自定义共享库的程序，可以通过分析其构建过程，查看 `rpaths_for_non_system_absolute_shared_libraries` 函数如何为该程序设置 RPATH，从而了解该程序在运行时会去哪些目录查找这些自定义库。

- **Windows DLL 路径的处理：** 在 Windows 平台，由于没有 RPATH 的概念，需要通过环境变量 `PATH` 或应用程序目录来查找 DLL。`extract_dll_paths` 和 `determine_windows_extra_paths` 函数的功能与逆向分析中确定程序依赖的 DLL 文件及其加载路径息息相关。
    - **举例：** 逆向一个 Windows 可执行文件时，可以使用工具查看其导入表，了解其依赖的 DLL。通过分析构建过程，可以理解 `determine_windows_extra_paths` 函数是如何将这些 DLL 所在的目录添加到测试运行时的路径中的，这有助于理解程序运行时的依赖关系。

**涉及二进制底层，Linux, Android内核及框架的知识及举例：**

- **目标文件和对象文件：** `object_filename_from_source` 函数涉及到将源代码编译成机器码的目标文件。理解目标文件的结构（例如 ELF 或 Mach-O 格式）是二进制分析的基础。
    - **举例：** 当分析一个程序的性能瓶颈时，可能需要查看编译器生成的目标文件，了解特定代码段的机器码实现。`object_filename_from_source` 函数帮助定位这些目标文件。

- **运行时库路径 (RPATH) (Linux)：** RPATH 是 Linux 等类 Unix 系统中动态链接器用于查找共享库的一种机制。`determine_rpath_dirs` 函数直接涉及到 RPATH 的设置。
    - **举例：** 在分析一个 Linux 恶意软件时，理解其 RPATH 设置可以揭示其可能加载的恶意共享库的路径。

- **`-fPIC` 编译器选项：**  虽然代码中没有直接出现 `-fPIC`，但在 `generate_basic_compiler_args` 函数中，可以看到针对共享库会添加与位置无关代码相关的编译器参数 (`compiler.get_pic_args()`)，而 `-fPIC` 是生成位置无关代码的常见选项。位置无关代码是共享库正常工作的基础。
    - **举例：**  在逆向分析共享库时，了解其是否以位置无关代码编译，可以推断其在内存中的加载方式。

**逻辑推理的假设输入与输出：**

- **假设输入到 `rpaths_for_non_system_absolute_shared_libraries` 函数的是一个 `BuildTarget` 对象，该目标链接了一个位于 `/opt/mylibs/libcustom.so` 的共享库。**
- **输出：** 该函数可能会返回一个包含 `/opt/mylibs` 的列表，作为该目标的 RPATH 路径。 这是因为该函数的目标是为非系统绝对路径的共享库添加 RPATH。

**涉及用户或编程常见的使用错误及举例：**

- **错误的 `--just-symbols` 参数：**  在 `get_external_rpath_dirs` 函数中，代码会检查 `--just-symbols` 参数，并抛出 `MesonException` 如果用户尝试用它来指定一个目录。
    - **举例：** 用户可能错误地使用了 `--just-symbols /opt/mylibs`，期望将 `/opt/mylibs` 添加到 RPATH 中，但实际上 `--just-symbols` 应该用于指定包含调试符号的目录或文件。Meson 会阻止这种错误用法。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户执行 `meson build` 命令配置构建系统。** Meson 会读取 `meson.build` 文件，解析构建目标和依赖关系。
2. **用户执行 `ninja` 或 `meson compile` 命令开始编译。**
3. **在编译过程中，Meson 会调用相应的后端（例如 Ninja）来执行编译和链接操作。**
4. **当需要链接生成共享库或可执行文件时，后端需要确定运行时库的路径。**
5. **此时，`backends.py` 文件中的相关函数（例如 `determine_rpath_dirs`，`rpaths_for_non_system_absolute_shared_libraries`）会被调用。**
6. **如果构建过程中涉及到外部依赖，`get_external_rpath_dirs` 和 `get_rpath_dirs_from_link_args` 等函数会被调用来处理外部依赖项的 RPATH 信息。**
7. **如果目标是 Windows 可执行文件，并且依赖于 DLL，`extract_dll_paths` 和 `determine_windows_extra_paths` 等函数会被调用来确定 DLL 的搜索路径.**

作为调试线索，如果构建过程中出现与链接库找不到或者测试执行时找不到依赖库的问题，可以检查 `backends.py` 中 RPATH 和 DLL 路径相关的函数的执行情况，查看生成的构建命令中 RPATH 的设置是否正确，或者测试运行时的环境变量是否包含了正确的 DLL 路径。

**代码片段的功能归纳：**

总而言之，这段代码片段是 frida 构建系统的核心部分，专注于处理构建过程中的后端细节，特别是关于**目标文件命名、运行时库路径管理（RPATH 和 Windows DLL 路径）、编译器和链接器参数处理以及测试用例生成**等方面。它确保了 frida 项目能够正确地编译、链接和运行，并提供了生成测试用例的基础设施。

Prompt: 
```
这是目录为frida/subprojects/frida-core/releng/meson/mesonbuild/backend/backends.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共4部分，请归纳一下它的功能

"""
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
"""


```