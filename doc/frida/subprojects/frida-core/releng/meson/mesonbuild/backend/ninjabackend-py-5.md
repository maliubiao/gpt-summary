Response:
The user wants to understand the functionality of the provided Python code snippet, which is a part of the `ninjabackend.py` file in the Frida project. This file seems to be responsible for generating Ninja build files.

Here's a breakdown of the request and a plan to address it:

1. **List the functions:** Identify the main functions in the provided code.
2. **Explain their purpose:** Describe what each function does.
3. **Relate to reverse engineering:**  Analyze if any function has a direct or indirect connection to reverse engineering tasks.
4. **Explain binary/kernel aspects:** Check if the code interacts with binary files, Linux/Android kernels, or frameworks.
5. **Illustrate logical reasoning:**  If any function involves conditional logic or decision-making, provide example inputs and outputs.
6. **Identify common user errors:**  Point out potential mistakes users might make that could lead to this code being executed or related errors.
7. **Describe the user path:**  Explain how a user's actions in Frida might lead to the execution of this code.
8. **Summarize overall function:** Provide a concise summary of the code's role.

**Detailed Plan for each point:**

1. **List the functions:**
   - `generate_link`
   - `get_dependency_filename`
   - `generate_shlib_aliases`
   - `generate_custom_target_clean`
   - `generate_gcov_clean`
   - `get_user_option_args`
   - `generate_dist`
   - `generate_scanbuild`
   - `generate_clangtool`
   - `generate_clangformat`
   - `generate_clangtidy`
   - `generate_tags`
   - `generate_utils`
   - `generate_ending`
   - `get_introspection_data`
   - `_scan_fortran_file_deps` (though this is a helper function, it's relevant to understand the context)

2. **Explain their purpose:**  For each function, infer its purpose based on its name, arguments, and the operations performed within it.

3. **Relate to reverse engineering:**  Focus on functions that deal with linking, shared libraries, debugging symbols, and code analysis tools (like scan-build, clang-tidy). Linking is a fundamental part of creating executable binaries that are then subject to reverse engineering. Shared libraries are common targets in reverse engineering. Debug symbols are used in debugging and can be present in binaries. Code analysis tools help identify potential vulnerabilities or behavior in code.

4. **Explain binary/kernel aspects:** Analyze functions that interact with linkers, handle shared libraries (which are OS-level concepts), deal with debug symbols (present in binaries), or interact with tools that analyze code at a low level. The `generate_link` function is key here, as it directly involves the linker.

5. **Illustrate logical reasoning:** Look for `if` statements and conditional logic. For example, in `generate_link`, the linker rule depends on whether the target is a static or shared library.

6. **Identify common user errors:** Think about mistakes users might make when defining build targets, dependencies, or linker arguments that could lead to issues during the Ninja file generation process. For instance, providing incorrect library paths or names.

7. **Describe the user path:** Consider the typical Frida workflow: specifying targets for instrumentation, building Frida, and then running it. The code snippet relates to the build process. Meson is the build system used by Frida, so user configurations in `meson.build` files are the starting point.

8. **Summarize overall function:** Combine the understanding of individual functions to describe the overall role of this code within Frida's build system.

**Self-Correction/Refinement:**

- Initially, I might focus too much on the specific details of each function. I need to balance this with providing a high-level overview and relating it back to the user's request regarding reverse engineering, binary internals, etc.
- The `_scan_fortran_file_deps` function seems out of place in the main part of the snippet, suggesting it might be a helper function. I should address its purpose but not give it undue weight in the overall summary.
- It's important to avoid making assumptions about the user's level of technical expertise. Explanations should be clear and concise.
This Python code snippet is part of the `NinjaBackend` class in Meson, the build system used by Frida. This class is responsible for generating `build.ninja` files, which are then used by the Ninja build tool to execute the actual compilation and linking steps of the Frida project.

Here's a breakdown of its functions:

**Core Functionality: Generating Ninja Build Rules**

The primary goal of this code is to translate Meson's build definitions (targets, dependencies, options, etc.) into a set of rules and commands that Ninja can understand and execute. Each function in this snippet contributes to defining specific types of build actions within the `build.ninja` file.

**Specific Functions and their Purposes:**

* **`generate_link(self, target, outname, obj_list, linker, extra_args=None, stdlib_args=None)`:** This function is central to the linking process. It generates the Ninja rule for linking object files (`obj_list`) into an executable or library (`outname`) using the specified `linker`. It handles various linking flags, library dependencies, runtime paths, and debug information.

* **`get_dependency_filename(self, t)`:**  Determines the filename of a dependency, whether it's another build target (like a shared library), a built file, or a source file. It ensures the correct path is used in the Ninja build file.

* **`generate_shlib_aliases(self, target, outdir)`:** For shared libraries, this function creates symbolic links (aliases) with different version numbers. This is a common practice for managing library versions on Unix-like systems.

* **`generate_custom_target_clean(self, trees)`:** Generates a Ninja rule to clean up the output directories of custom build targets. This involves calling a Meson internal script to handle the cleanup.

* **`generate_gcov_clean(self)`:**  Generates Ninja rules to clean up gcov coverage data files (`.gcno` and `.gcda`). This is used when code coverage analysis is enabled.

* **`get_user_option_args(self)`:** Retrieves the user-defined options passed to Meson (e.g., `-Doption=value`) and formats them as command-line arguments.

* **`generate_dist(self)`:** Creates a Ninja rule to generate distribution packages (e.g., source tarballs).

* **`generate_scanbuild(self)`:**  Sets up a Ninja rule to run `scan-build`, a static analysis tool from the LLVM project, to detect potential bugs.

* **`generate_clangtool(self, name, extra_arg=None)`:** A helper function to generate Ninja rules for various Clang tools like `clang-format` and `clang-tidy`.

* **`generate_clangformat(self)`:** Generates Ninja rules to run `clang-format` for code formatting and optionally check for formatting issues.

* **`generate_clangtidy(self)`:** Generates Ninja rules to run `clang-tidy` for static code analysis and optionally apply fixes.

* **`generate_tags(self, tool, target_name)`:** Creates Ninja rules to generate tag files (like `TAGS`, `ctags`, `cscope`) for source code navigation.

* **`generate_utils(self)`:** Groups together the generation of rules for various utility tasks like static analysis, code formatting, and uninstalling.

* **`generate_ending(self)`:** Generates the final Ninja rules for default targets (`all`), testing prerequisites, cleaning, and regenerating the build system itself.

* **`get_introspection_data(self, target_id, target)`:** Provides data for introspection, allowing other parts of Meson or external tools to query information about build targets.

* **`_scan_fortran_file_deps(self, src, srcdir, dirname, tdeps, compiler)`:** This is a helper function specifically for scanning Fortran source files for dependencies (using `use`, `include`, `module`, `submodule` directives).

**Relationship to Reverse Engineering:**

Several parts of this code are directly relevant to reverse engineering, as they deal with the creation of the binaries that are often the target of reverse engineering efforts:

* **`generate_link`:** This function is fundamental. It dictates how the linker combines compiled code into executables (`frida`, Frida gadgets) and shared libraries (`frida-core.node`, architecture-specific agent libraries). Reverse engineers often analyze these linked binaries. The linker flags and library dependencies specified here influence the final structure and functionality of these binaries. For example, flags related to position-independent code (PIC) are crucial for shared libraries, which are heavily used in Frida.
    * **Example:** When building Frida's core library (`frida-core.node`), this function will be called with the object files generated from the C/C++ source code, the linker specific to the target platform, and various linker flags (e.g., `-shared` on Linux, `/DLL` on Windows) to produce the shared library. Reverse engineers will then analyze this `frida-core.node` library.

* **`generate_shlib_aliases`:** Understanding how shared library versions are managed is important in reverse engineering, especially when dealing with older or multiple versions of Frida components.

* **`generate_scanbuild`, `generate_clangtidy`:** While not directly part of the final binary creation, these functions indicate the use of static analysis tools during Frida's development. Knowing the types of checks performed can sometimes provide insights into potential vulnerabilities or areas of interest for reverse engineers.

* **Debug Symbols Handling (within `generate_link`):** The code explicitly handles the generation of debug symbols (`/DEBUG` and PDB files on MSVC). These symbols are invaluable for reverse engineers using debuggers to understand the program's execution flow and data structures.

**Involvement of Binary 底层 (Low-Level), Linux, Android Kernel, and Framework Knowledge:**

This code interacts heavily with low-level concepts and OS-specific details:

* **Binary 底层:** The entire linking process is a fundamental part of binary creation. The code manipulates linker flags, which directly influence the binary's structure, memory layout, and how it interacts with the operating system.
    * **Example:** The code adds runtime paths (`rpath`) to the linked binaries. This is a low-level mechanism on Linux and other Unix-like systems to tell the dynamic linker where to find shared libraries at runtime.

* **Linux:** The handling of shared library aliases and runtime paths (`rpath`) is specific to Linux and other Unix-like systems. The use of symbolic links for library versioning is a standard Linux practice.
    * **Example:** The `generate_shlib_aliases` function uses `os.symlink`, a Linux/Unix system call, to create the versioned library links.

* **Android Kernel and Framework:** While not explicitly manipulating kernel code in this snippet, the generation of shared libraries and executables is essential for Frida's operation on Android. Frida relies on injecting into processes, which involves understanding the Android framework's process model and how shared libraries are loaded. The linker settings produced by this code contribute to the correct loading and execution of Frida components within the Android environment.
    * **Example:** When building Frida's agent for Android, the linker will be instructed (via flags generated by `generate_link`) to create a shared library suitable for loading into Android applications.

**Logical Reasoning (Hypothetical Input and Output):**

Let's consider the `generate_link` function with a simplified example:

**Hypothetical Input:**

* `target`: A `build.BuildTarget` object representing a shared library named `mylib`.
* `outname`: "libmylib.so"
* `obj_list`: ["obj/mylib.o", "obj/myotherfile.o"]
* `linker`: A `Compiler` object for GCC.

**Logical Reasoning within `generate_link`:**

1. The code checks if `target` is a `build.StaticLibrary`. In this case, it's not, so it proceeds to the `else` block.
2. It checks if `target` is a `build.SharedLibrary`, which is true. It might call `self.generate_shsym(target)` (not shown in the snippet).
3. It determines the linker rule suffix based on the target machine.
4. It constructs a list of linker commands, starting with compiler arguments, base link arguments, optimization flags, and target-specific arguments (like `-shared` for shared libraries).
5. It adds runtime path arguments based on `target.rpath_dirs_to_remove`, `target.build_rpath`, and `target.install_rpath`.
6. It iterates through dependencies and adds their link arguments.
7. Finally, it creates a `NinjaBuildElement` with the output filename, the linker rule, the object files, and the constructed link command.

**Hypothetical Output (a snippet from `build.ninja`):**

```ninja
rule C_LINKER_x86_64
  command = gcc -o $out $in $LINK_ARGS
  description = Linking target mylib

build libmylib.so: C_LINKER_x86_64 obj/mylib.o obj/myotherfile.o
  LINK_ARGS = -shared -Wl,-rpath,'$ORIGIN' ... (other linker flags and library dependencies)
```

**Common User or Programming Errors:**

Users or developers working on Frida could encounter issues that lead to this code being executed, and errors in this code can cause build failures:

* **Incorrectly defined dependencies in `meson.build`:** If a target depends on another library or target that isn't properly specified, the `generate_link` function might not include the necessary linker flags or library paths, resulting in linking errors.
    * **Example:** Forgetting to add `dependency('zlib')` when building a component that uses zlib.
* **Incorrectly specified linker arguments:**  While less common for end-users, developers modifying the build system could introduce incorrect linker flags that cause build failures or create malformed binaries.
* **Path issues:** Problems with finding libraries or include files can lead to linker errors, and this code is responsible for constructing the paths used during linking.
* **Operating system or environment inconsistencies:** Differences in available linkers, system libraries, or environment variables can sometimes lead to build issues that trace back to the generated Ninja files.

**User Operations Leading Here (Debugging Clues):**

A user's interaction with Frida starts with defining what to build and how:

1. **Modifying `meson.build` files:** Users or developers might change the build configuration, adding new targets, dependencies, or build options.
2. **Running `meson setup`:** This command parses the `meson.build` files and uses the backend (in this case, Ninja) to generate the `build.ninja` file. The code snippet is part of this process.
3. **Running `ninja`:** This command executes the build steps defined in `build.ninja`. If there are errors during compilation or linking, the user would see error messages related to the commands generated by this Python code.
4. **Debugging build failures:** If a build fails, developers would examine the generated `build.ninja` file to understand the exact commands that were executed and failed. They might trace back to the Python code that generated those commands to identify the root cause of the issue.

**归纳一下它的功能 (Summary of its Functionality):**

This code snippet, part of the `NinjaBackend` class in Meson, is responsible for **generating the `build.ninja` file that dictates how Frida is built**. It translates Meson's high-level build descriptions into low-level build commands for the Ninja build tool. Key aspects include:

* **Orchestrating the linking process:** Defining how object files are combined into executables and libraries, including specifying necessary linker flags and dependencies.
* **Managing shared library versions:** Creating symbolic links for different versions of shared libraries.
* **Handling cleanup tasks:** Defining how to remove build artifacts.
* **Integrating development tools:** Setting up rules for running static analysis and code formatting tools.
* **Generating the overall build process:** Defining the default build targets and the steps to regenerate the build system itself.

In essence, this code bridges the gap between Frida's build configuration and the actual commands executed to compile and link the project, making it a critical component of Frida's build system.

### 提示词
```
这是目录为frida/subprojects/frida-core/releng/meson/mesonbuild/backend/ninjabackend.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第6部分，共6部分，请归纳一下它的功能
```

### 源代码
```python
[:]
        cmd += prelinker.get_prelink_args(prelink_name, obj_list)

        cmd = self.replace_paths(target, cmd)
        elem.add_item('COMMAND', cmd)
        elem.add_item('description', f'Prelinking {prelink_name}.')
        self.add_build(elem)
        return [prelink_name]

    def generate_link(self, target: build.BuildTarget, outname, obj_list, linker: T.Union['Compiler', 'StaticLinker'], extra_args=None, stdlib_args=None):
        extra_args = extra_args if extra_args is not None else []
        stdlib_args = stdlib_args if stdlib_args is not None else []
        implicit_outs = []
        if isinstance(target, build.StaticLibrary):
            linker_base = 'STATIC'
        else:
            linker_base = linker.get_language() # Fixme.
        if isinstance(target, build.SharedLibrary):
            self.generate_shsym(target)
        crstr = self.get_rule_suffix(target.for_machine)
        linker_rule = linker_base + '_LINKER' + crstr
        # Create an empty commands list, and start adding link arguments from
        # various sources in the order in which they must override each other
        # starting from hard-coded defaults followed by build options and so on.
        #
        # Once all the linker options have been passed, we will start passing
        # libraries and library paths from internal and external sources.
        commands = linker.compiler_args()
        # First, the trivial ones that are impossible to override.
        #
        # Add linker args for linking this target derived from 'base' build
        # options passed on the command-line, in default_options, etc.
        # These have the lowest priority.
        if isinstance(target, build.StaticLibrary):
            commands += linker.get_base_link_args(target.get_options())
        else:
            commands += compilers.get_base_link_args(target.get_options(),
                                                     linker,
                                                     isinstance(target, build.SharedModule),
                                                     self.environment.get_build_dir())
        # Add -nostdlib if needed; can't be overridden
        commands += self.get_no_stdlib_link_args(target, linker)
        # Add things like /NOLOGO; usually can't be overridden
        commands += linker.get_linker_always_args()
        # Add buildtype linker args: optimization level, etc.
        commands += linker.get_optimization_link_args(target.get_option(OptionKey('optimization')))
        # Add /DEBUG and the pdb filename when using MSVC
        if target.get_option(OptionKey('debug')):
            commands += self.get_link_debugfile_args(linker, target)
            debugfile = self.get_link_debugfile_name(linker, target)
            if debugfile is not None:
                implicit_outs += [debugfile]
        # Add link args specific to this BuildTarget type, such as soname args,
        # PIC, import library generation, etc.
        commands += self.get_target_type_link_args(target, linker)
        # Archives that are copied wholesale in the result. Must be before any
        # other link targets so missing symbols from whole archives are found in those.
        if not isinstance(target, build.StaticLibrary):
            commands += self.get_link_whole_args(linker, target)

        if not isinstance(target, build.StaticLibrary):
            # Add link args added using add_project_link_arguments()
            commands += self.build.get_project_link_args(linker, target.subproject, target.for_machine)
            # Add link args added using add_global_link_arguments()
            # These override per-project link arguments
            commands += self.build.get_global_link_args(linker, target.for_machine)
            # Link args added from the env: LDFLAGS. We want these to override
            # all the defaults but not the per-target link args.
            commands += self.environment.coredata.get_external_link_args(target.for_machine, linker.get_language())

        # Now we will add libraries and library paths from various sources

        # Set runtime-paths so we can run executables without needing to set
        # LD_LIBRARY_PATH, etc in the environment. Doesn't work on Windows.
        if has_path_sep(target.name):
            # Target names really should not have slashes in them, but
            # unfortunately we did not check for that and some downstream projects
            # now have them. Once slashes are forbidden, remove this bit.
            target_slashname_workaround_dir = os.path.join(
                os.path.dirname(target.name),
                self.get_target_dir(target))
        else:
            target_slashname_workaround_dir = self.get_target_dir(target)
        (rpath_args, target.rpath_dirs_to_remove) = (
            linker.build_rpath_args(self.environment,
                                    self.environment.get_build_dir(),
                                    target_slashname_workaround_dir,
                                    self.determine_rpath_dirs(target),
                                    target.build_rpath,
                                    target.install_rpath))
        commands += rpath_args

        # Add link args to link to all internal libraries (link_with:) and
        # internal dependencies needed by this target.
        if linker_base == 'STATIC':
            # Link arguments of static libraries are not put in the command
            # line of the library. They are instead appended to the command
            # line where the static library is used.
            dependencies = []
        else:
            dependencies = target.get_dependencies()
        internal = self.build_target_link_arguments(linker, dependencies)
        commands += internal
        # Only non-static built targets need link args and link dependencies
        if not isinstance(target, build.StaticLibrary):
            # For 'automagic' deps: Boost and GTest. Also dependency('threads').
            # pkg-config puts the thread flags itself via `Cflags:`

            commands += linker.get_target_link_args(target)
            # External deps must be last because target link libraries may depend on them.
            for dep in target.get_external_deps():
                # Extend without reordering or de-dup to preserve `-L -l` sets
                # https://github.com/mesonbuild/meson/issues/1718
                commands.extend_preserving_lflags(linker.get_dependency_link_args(dep))
            for d in target.get_dependencies():
                if isinstance(d, build.StaticLibrary):
                    for dep in d.get_external_deps():
                        commands.extend_preserving_lflags(linker.get_dependency_link_args(dep))

        # Add link args specific to this BuildTarget type that must not be overridden by dependencies
        commands += self.get_target_type_link_args_post_dependencies(target, linker)

        # Add link args for c_* or cpp_* build options. Currently this only
        # adds c_winlibs and cpp_winlibs when building for Windows. This needs
        # to be after all internal and external libraries so that unresolved
        # symbols from those can be found here. This is needed when the
        # *_winlibs that we want to link to are static mingw64 libraries.
        if isinstance(linker, Compiler):
            # The static linker doesn't know what language it is building, so we
            # don't know what option. Fortunately, it doesn't care to see the
            # language-specific options either.
            #
            # We shouldn't check whether we are making a static library, because
            # in the LTO case we do use a real compiler here.
            commands += linker.get_option_link_args(target.get_options())

        dep_targets = []
        dep_targets.extend(self.guess_external_link_dependencies(linker, target, commands, internal))

        # Add libraries generated by custom targets
        custom_target_libraries = self.get_custom_target_provided_libraries(target)
        commands += extra_args
        commands += custom_target_libraries
        commands += stdlib_args # Standard library arguments go last, because they never depend on anything.
        dep_targets.extend([self.get_dependency_filename(t) for t in dependencies])
        dep_targets.extend([self.get_dependency_filename(t)
                            for t in target.link_depends])
        elem = NinjaBuildElement(self.all_outputs, outname, linker_rule, obj_list, implicit_outs=implicit_outs)
        elem.add_dep(dep_targets + custom_target_libraries)
        elem.add_item('LINK_ARGS', commands)
        self.create_target_linker_introspection(target, linker, commands)
        return elem

    def get_dependency_filename(self, t):
        if isinstance(t, build.SharedLibrary):
            return self.get_target_shsym_filename(t)
        elif isinstance(t, mesonlib.File):
            if t.is_built:
                return t.relative_name()
            else:
                return t.absolute_path(self.environment.get_source_dir(),
                                       self.environment.get_build_dir())
        return self.get_target_filename(t)

    def generate_shlib_aliases(self, target, outdir):
        for alias, to, tag in target.get_aliases():
            aliasfile = os.path.join(outdir, alias)
            abs_aliasfile = os.path.join(self.environment.get_build_dir(), outdir, alias)
            try:
                os.remove(abs_aliasfile)
            except Exception:
                pass
            try:
                os.symlink(to, abs_aliasfile)
            except NotImplementedError:
                mlog.debug("Library versioning disabled because symlinks are not supported.")
            except OSError:
                mlog.debug("Library versioning disabled because we do not have symlink creation privileges.")
            else:
                self.implicit_meson_outs.append(aliasfile)

    def generate_custom_target_clean(self, trees: T.List[str]) -> str:
        e = self.create_phony_target('clean-ctlist', 'CUSTOM_COMMAND', 'PHONY')
        d = CleanTrees(self.environment.get_build_dir(), trees)
        d_file = os.path.join(self.environment.get_scratch_dir(), 'cleantrees.dat')
        e.add_item('COMMAND', self.environment.get_build_command() + ['--internal', 'cleantrees', d_file])
        e.add_item('description', 'Cleaning custom target directories')
        self.add_build(e)
        # Write out the data file passed to the script
        with open(d_file, 'wb') as ofile:
            pickle.dump(d, ofile)
        return 'clean-ctlist'

    def generate_gcov_clean(self) -> None:
        gcno_elem = self.create_phony_target('clean-gcno', 'CUSTOM_COMMAND', 'PHONY')
        gcno_elem.add_item('COMMAND', mesonlib.get_meson_command() + ['--internal', 'delwithsuffix', '.', 'gcno'])
        gcno_elem.add_item('description', 'Deleting gcno files')
        self.add_build(gcno_elem)

        gcda_elem = self.create_phony_target('clean-gcda', 'CUSTOM_COMMAND', 'PHONY')
        gcda_elem.add_item('COMMAND', mesonlib.get_meson_command() + ['--internal', 'delwithsuffix', '.', 'gcda'])
        gcda_elem.add_item('description', 'Deleting gcda files')
        self.add_build(gcda_elem)

    def get_user_option_args(self):
        cmds = []
        for (k, v) in self.environment.coredata.options.items():
            if k.is_project():
                cmds.append('-D' + str(k) + '=' + (v.value if isinstance(v.value, str) else str(v.value).lower()))
        # The order of these arguments must be the same between runs of Meson
        # to ensure reproducible output. The order we pass them shouldn't
        # affect behavior in any other way.
        return sorted(cmds)

    def generate_dist(self) -> None:
        elem = self.create_phony_target('dist', 'CUSTOM_COMMAND', 'PHONY')
        elem.add_item('DESC', 'Creating source packages')
        elem.add_item('COMMAND', self.environment.get_build_command() + ['dist'])
        elem.add_item('pool', 'console')
        self.add_build(elem)

    def generate_scanbuild(self) -> None:
        if not environment.detect_scanbuild():
            return
        if 'scan-build' in self.all_outputs:
            return
        cmd = self.environment.get_build_command() + \
            ['--internal', 'scanbuild', self.environment.source_dir, self.environment.build_dir, self.build.get_subproject_dir()] + \
            self.environment.get_build_command() + ['setup'] + self.get_user_option_args()
        elem = self.create_phony_target('scan-build', 'CUSTOM_COMMAND', 'PHONY')
        elem.add_item('COMMAND', cmd)
        elem.add_item('pool', 'console')
        self.add_build(elem)

    def generate_clangtool(self, name: str, extra_arg: T.Optional[str] = None) -> None:
        target_name = 'clang-' + name
        extra_args = []
        if extra_arg:
            target_name += f'-{extra_arg}'
            extra_args.append(f'--{extra_arg}')
        if not os.path.exists(os.path.join(self.environment.source_dir, '.clang-' + name)) and \
                not os.path.exists(os.path.join(self.environment.source_dir, '_clang-' + name)):
            return
        if target_name in self.all_outputs:
            return
        cmd = self.environment.get_build_command() + \
            ['--internal', 'clang' + name, self.environment.source_dir, self.environment.build_dir] + \
            extra_args
        elem = self.create_phony_target(target_name, 'CUSTOM_COMMAND', 'PHONY')
        elem.add_item('COMMAND', cmd)
        elem.add_item('pool', 'console')
        self.add_build(elem)

    def generate_clangformat(self) -> None:
        if not environment.detect_clangformat():
            return
        self.generate_clangtool('format')
        self.generate_clangtool('format', 'check')

    def generate_clangtidy(self) -> None:
        import shutil
        if not shutil.which('clang-tidy'):
            return
        self.generate_clangtool('tidy')
        self.generate_clangtool('tidy', 'fix')

    def generate_tags(self, tool: str, target_name: str) -> None:
        import shutil
        if not shutil.which(tool):
            return
        if target_name in self.all_outputs:
            return
        cmd = self.environment.get_build_command() + \
            ['--internal', 'tags', tool, self.environment.source_dir]
        elem = self.create_phony_target(target_name, 'CUSTOM_COMMAND', 'PHONY')
        elem.add_item('COMMAND', cmd)
        elem.add_item('pool', 'console')
        self.add_build(elem)

    # For things like scan-build and other helper tools we might have.
    def generate_utils(self) -> None:
        self.generate_scanbuild()
        self.generate_clangformat()
        self.generate_clangtidy()
        self.generate_tags('etags', 'TAGS')
        self.generate_tags('ctags', 'ctags')
        self.generate_tags('cscope', 'cscope')
        cmd = self.environment.get_build_command() + ['--internal', 'uninstall']
        elem = self.create_phony_target('uninstall', 'CUSTOM_COMMAND', 'PHONY')
        elem.add_item('COMMAND', cmd)
        elem.add_item('pool', 'console')
        self.add_build(elem)

    def generate_ending(self) -> None:
        for targ, deps in [
                ('all', self.get_build_by_default_targets()),
                ('meson-test-prereq', self.get_testlike_targets()),
                ('meson-benchmark-prereq', self.get_testlike_targets(True))]:
            targetlist = []
            # These must also be built by default.
            # XXX: Sometime in the future these should be built only before running tests.
            if targ == 'all':
                targetlist.extend(['meson-test-prereq', 'meson-benchmark-prereq'])
            for t in deps.values():
                # Add the first output of each target to the 'all' target so that
                # they are all built
                #Add archive file if shared library in AIX for build all.
                if isinstance(t, build.SharedLibrary) and t.aix_so_archive:
                    if self.environment.machines[t.for_machine].is_aix():
                        linker, stdlib_args = self.determine_linker_and_stdlib_args(t)
                        t.get_outputs()[0] = linker.get_archive_name(t.get_outputs()[0])
                targetlist.append(os.path.join(self.get_target_dir(t), t.get_outputs()[0]))

            elem = NinjaBuildElement(self.all_outputs, targ, 'phony', targetlist)
            self.add_build(elem)

        elem = self.create_phony_target('clean', 'CUSTOM_COMMAND', 'PHONY')
        elem.add_item('COMMAND', self.ninja_command + ['-t', 'clean'])
        elem.add_item('description', 'Cleaning')

        # If we have custom targets in this project, add all their outputs to
        # the list that is passed to the `cleantrees.py` script. The script
        # will manually delete all custom_target outputs that are directories
        # instead of files. This is needed because on platforms other than
        # Windows, Ninja only deletes directories while cleaning if they are
        # empty. https://github.com/mesonbuild/meson/issues/1220
        ctlist = []
        for t in self.build.get_targets().values():
            if isinstance(t, build.CustomTarget):
                # Create a list of all custom target outputs
                for o in t.get_outputs():
                    ctlist.append(os.path.join(self.get_target_dir(t), o))
        if ctlist:
            elem.add_dep(self.generate_custom_target_clean(ctlist))

        if OptionKey('b_coverage') in self.environment.coredata.options and \
           self.environment.coredata.options[OptionKey('b_coverage')].value:
            self.generate_gcov_clean()
            elem.add_dep('clean-gcda')
            elem.add_dep('clean-gcno')
        self.add_build(elem)

        deps = self.get_regen_filelist()
        elem = NinjaBuildElement(self.all_outputs, 'build.ninja', 'REGENERATE_BUILD', deps)
        elem.add_item('pool', 'console')
        self.add_build(elem)

        # If these files used to be explicitly created, they need to appear on the build graph somehow,
        # otherwise cleandead deletes them. See https://github.com/ninja-build/ninja/issues/2299
        if self.implicit_meson_outs:
            elem = NinjaBuildElement(self.all_outputs, 'meson-implicit-outs', 'phony', self.implicit_meson_outs)
            self.add_build(elem)

        elem = NinjaBuildElement(self.all_outputs, 'reconfigure', 'REGENERATE_BUILD', 'PHONY')
        elem.add_item('pool', 'console')
        self.add_build(elem)

        elem = NinjaBuildElement(self.all_outputs, deps, 'phony', '')
        self.add_build(elem)

    def get_introspection_data(self, target_id: str, target: build.Target) -> T.List[T.Dict[str, T.Union[bool, str, T.List[T.Union[str, T.Dict[str, T.Union[str, T.List[str], bool]]]]]]]:
        data = self.introspection_data.get(target_id)
        if not data:
            return super().get_introspection_data(target_id, target)

        return list(data.values())


def _scan_fortran_file_deps(src: Path, srcdir: Path, dirname: Path, tdeps, compiler) -> T.List[str]:
    """
    scan a Fortran file for dependencies. Needs to be distinct from target
    to allow for recursion induced by `include` statements.er

    It makes a number of assumptions, including

    * `use`, `module`, `submodule` name is not on a continuation line

    Regex
    -----

    * `incre` works for `#include "foo.f90"` and `include "foo.f90"`
    * `usere` works for legacy and Fortran 2003 `use` statements
    * `submodre` is for Fortran >= 2008 `submodule`
    """

    incre = re.compile(FORTRAN_INCLUDE_PAT, re.IGNORECASE)
    usere = re.compile(FORTRAN_USE_PAT, re.IGNORECASE)
    submodre = re.compile(FORTRAN_SUBMOD_PAT, re.IGNORECASE)

    mod_files = []
    src = Path(src)
    with src.open(encoding='ascii', errors='ignore') as f:
        for line in f:
            # included files
            incmatch = incre.match(line)
            if incmatch is not None:
                incfile = src.parent / incmatch.group(1)
                # NOTE: src.parent is most general, in particular for CMake subproject with Fortran file
                # having an `include 'foo.f'` statement.
                if incfile.suffix.lower()[1:] in compiler.file_suffixes:
                    mod_files.extend(_scan_fortran_file_deps(incfile, srcdir, dirname, tdeps, compiler))
            # modules
            usematch = usere.match(line)
            if usematch is not None:
                usename = usematch.group(1).lower()
                if usename == 'intrinsic':  # this keeps the regex simpler
                    continue
                if usename not in tdeps:
                    # The module is not provided by any source file. This
                    # is due to:
                    #   a) missing file/typo/etc
                    #   b) using a module provided by the compiler, such as
                    #      OpenMP
                    # There's no easy way to tell which is which (that I
                    # know of) so just ignore this and go on. Ideally we
                    # would print a warning message to the user but this is
                    # a common occurrence, which would lead to lots of
                    # distracting noise.
                    continue
                srcfile = srcdir / tdeps[usename].fname
                if not srcfile.is_file():
                    if srcfile.name != src.name:  # generated source file
                        pass
                    else:  # subproject
                        continue
                elif srcfile.samefile(src):  # self-reference
                    continue

                mod_name = compiler.module_name_to_filename(usename)
                mod_files.append(str(dirname / mod_name))
            else:  # submodules
                submodmatch = submodre.match(line)
                if submodmatch is not None:
                    parents = submodmatch.group(1).lower().split(':')
                    assert len(parents) in {1, 2}, (
                        'submodule ancestry must be specified as'
                        f' ancestor:parent but Meson found {parents}')

                    ancestor_child = '_'.join(parents)
                    if ancestor_child not in tdeps:
                        raise MesonException("submodule {} relies on ancestor module {} that was not found.".format(submodmatch.group(2).lower(), ancestor_child.split('_', maxsplit=1)[0]))
                    submodsrcfile = srcdir / tdeps[ancestor_child].fname
                    if not submodsrcfile.is_file():
                        if submodsrcfile.name != src.name:  # generated source file
                            pass
                        else:  # subproject
                            continue
                    elif submodsrcfile.samefile(src):  # self-reference
                        continue
                    mod_name = compiler.module_name_to_filename(ancestor_child)
                    mod_files.append(str(dirname / mod_name))
    return mod_files
```