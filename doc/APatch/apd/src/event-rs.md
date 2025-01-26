响应:

```
好的，我现在要分析用户提供的Rust代码，并按照要求回答问题。首先，我需要理解这段代码的功能，它是APatch项目的一部分，主要负责Android内核和系统的修补。APatch类似于Magisk，支持内核模块和系统模块的注入。代码文件路径是event.rs，看起来是处理不同事件的核心逻辑。

首先，用户希望按照执行顺序列举功能，共10步。我需要通读代码，找出主要的函数和调用关系，确定执行流程。然后，如果可能的话，用shell代码举例说明功能。此外，还要考虑命令行参数处理、文件系统访问痕迹以及生成的Android外部进程可见的痕迹。

首先，代码中有几个关键函数：mount_systemlessly、on_post_data_fs、run_stage、on_services、on_boot_completed、start_uid_listener等。这些函数可能对应不同的启动阶段或事件处理。

从入口点来看，on_post_data_fs可能是处理post-fs-data阶段的动作，这在Magisk中也是类似的阶段。接着是mount_systemlessly，负责挂载模块到系统分区。然后是run_stage执行各个阶段的脚本，如post-mount、service、boot-completed等。此外，还有UID监听器的启动，用于监视应用安装和权限变化。

接下来，我需要确定这些函数的执行顺序。例如，在Android启动过程中，post-fs-data阶段较早，然后是post-mount、services，最后是boot-completed。因此，执行顺序可能如下：

1. 初始化环境，设置权限和SELinux上下文。
2. 处理post-fs-data阶段，挂载模块。
3. 执行post-fs-data.d脚本。
4. 挂载overlay文件系统，应用模块修改。
5. 执行post-mount阶段脚本。
6. 处理服务启动（services阶段）。
7. 启动UID监听器监控应用安装。
8. 执行boot-completed阶段脚本。
9. 清理临时文件和标志。
10. 日志记录和错误处理。

关于shell代码示例，比如挂载模块的操作可能涉及创建镜像文件、格式化为ext4、挂载到指定目录，并复制模块文件。例如：

```shell
mkfs.ext4 -b 1024 /path/to/tmp_module.img
mount -t ext4 /path/to/tmp_module.img /module_dir
cp -R /module_update_dir/* /module_dir/
```

处理命令行参数方面，例如在on_post_data_fs中调用magiskpolicy，传递参数来应用SELinux策略。文件系统访问方面，代码涉及创建、删除、移动模块目录，设置xattr属性，挂载overlayfs等，这些操作会在/data/adb/下生成模块文件、日志文件，以及可能的临时镜像文件。

生成的痕迹可能包括：/data/adb/ap目录下的模块和日志，/system的overlay挂载点，/proc/mounts中的挂载信息，以及进程列表中运行的passkeyd或magiskpolicy进程。

需要注意的是，代码中的mount_systemlessly函数会根据模块配置生成overlay挂载，可能修改/system、/vendor等分区，但以只读方式覆盖。同时，日志文件如dmesg.log和logcat.log会被记录在特定目录，这些都可能被用户或检测工具发现。

总结步骤时，需要将初始化、挂载模块、执行脚本、启动服务等步骤按顺序排列，并注意各阶段之间的依赖关系。同时，要考虑安全模式和模块禁用情况下的不同处理路径。
```
### 按执行顺序的功能分析 (10步)

1. **初始化SELinux策略**  
   调用`magiskpolicy --magisk --live`动态注入SELinux规则，修复权限上下文(`restorecon`)

2. **创建日志环境**  
   在`/data/adb/apatch/log/`创建日志目录，清理旧日志文件，启动`logcat`和`dmesg`日志捕获进程

3. **安全模式检测**  
   检查是否进入安全模式(`is_safe_mode`)，若启用则跳过模块挂载并禁用所有模块

4. **模块更新处理**  
   检测`/data/adb/apatch/update`更新标志，将临时模块目录内容移动到正式目录，创建模块镜像文件(ext4格式)

5. **模块挂载决策**  
   根据`/data/adb/apatch/litemode`文件存在性选择挂载方式：OverlayFS或Bind Mount

6. **OverlayFS挂载**  
   通过`mount_systemlessly`函数构建层级目录，将模块内容挂载到`/system`等分区。示例Shell：
```bash
# 假设模块路径 /data/adb/modules/example/system
lowerdir="/data/adb/modules/example/system"
mount -t overlay overlay -o lowerdir=$lowerdir /system
```

7. **执行生命周期脚本**  
   按顺序执行各阶段脚本：
   ```shell
   # 示例脚本路径
   /data/adb/apatch/post-fs-data.d/*.sh
   /data/adb/apatch/service.d/*.sh
   /data/adb/apatch/boot-completed.d/*.sh
   ```

8. **属性监听器启动**  
   运行`/data/adb/passkeyd uid-listener`监控`/data/system/packages.list.tmp`文件变更

9. **临时文件清理**  
   删除`/data/adb/apatch/.update`等临时标志文件，卸载临时tmpfs

10. **内核模块加载**  
    通过`KERNELPATCH_VERSION`环境变量验证内核补丁版本，加载内核模块(`kmod`)

---

### 文件系统痕迹分析

1. **模块镜像文件**  
   ```bash
   /data/adb/apatch/modules.img  # ext4格式的模块容器
   ```

2. **OverlayFS挂载点**  
   通过`cat /proc/mounts`可见类似挂载信息：
   ```
   overlay /system overlay rw,lowerdir=/data/adb/apatch/... 0 0
   ```

3. **XATTR属性标记**  
   使用`getfattr -d <file>`可查看模块文件的`security.selinux`属性

4. **进程列表痕迹**  
   ```bash
   ps -A | grep -E 'magiskpolicy|passkeyd|timeout'  # 可见相关进程
   ```

---

### 输入输出推理示例

**场景：模块更新**  
输入：在`/data/adb/apatch/update`目录放置新模块  
代码行为：
1. 计算模块总大小 → 输出日志`Total size: xxx bytes`
2. 创建并格式化ext4镜像 → 调用`mkfs.ext4`生成文件
3. 挂载镜像到临时目录 → `mount -t ext4 modules.img /mnt`
4. 复制文件保留SELinux上下文 → `cp -a --preserve=context`

**参数处理示例**  
当处理`on_post_data_fs`时：
```rust
let args = ["/data/adb/ap/bin/magiskpolicy", "--magisk", "--live"];
fork_for_result("/data/adb/ap/bin/magiskpolicy", &args, &superkey);
```
对应实际执行：
```bash
magiskpolicy --magisk --live  # 修改当前SELinux策略
```
提示器:

这是路径为APatch/apd/src/event.rs的apatch `The patching of Android kernel and Android system`实现的一部分，
它的项目描述如下`
A new kernel-based root solution for Android devices.
APM: Support for modules similar to Magisk.
KPM: Support for modules that allow you to inject any code into the kernel (Provides kernel function inline-hook and syscall-table-hook).
APatch relies on KernelPatch.
The APatch UI and the APModule source code have been derived and modified from KernelSU.
` 
请按照最可能的执行顺序(非行号)列举一下它的功能, 建议10步，　
如果你能推理出它是什么功能的实现，请用shell代码举例, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，涉及到对文件系统的访问，请详细介绍一下，
如果这个程序生成了哪些android外部进程可以看到的痕迹，请提示一下，
请用中文回答。

```rust
use crate::m_mount;
use crate::module;
use crate::supercall::fork_for_result;
use crate::utils::{ensure_dir_exists, ensure_file_exists, get_work_dir, switch_cgroups};
use crate::{
    assets, defs, mount, restorecon, supercall,
    supercall::{init_load_package_uid_config, init_load_su_path, refresh_ap_package_list},
    utils::{self, ensure_clean_dir},
};
use anyhow::{bail, ensure, Context, Result};
use extattr::{lgetxattr, lsetxattr, Flags as XattrFlags};
use log::{info, warn};
use notify::event::{ModifyKind, RenameMode};
use notify::{Config, Event, EventKind, INotifyWatcher, RecursiveMode, Watcher};
use rustix::{fd::AsFd, fs::CWD, mount::*};
use std::ffi::CStr;
use std::fs::{remove_dir_all, rename};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{collections::HashMap, thread};
use std::{env, fs, io};
use walkdir::WalkDir;

fn copy_with_xattr(src: &Path, dest: &Path) -> io::Result<()> {
    fs::copy(src, dest)?;

    if let Ok(xattr_value) = lgetxattr(src, "security.selinux") {
        lsetxattr(dest, "security.selinux", &xattr_value, XattrFlags::empty())?;
    }

    Ok(())
}

fn copy_dir_with_xattr(src: &Path, dest: &Path) -> io::Result<()> {
    for entry in WalkDir::new(src) {
        let entry = entry?;
        let rel_path = entry
            .path()
            .strip_prefix(src)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        let target_path = dest.join(rel_path);
        if entry.file_type().is_dir() {
            fs::create_dir_all(&target_path)?;
        } else if entry.file_type().is_file() {
            copy_with_xattr(entry.path(), &target_path)?;
        }
    }
    Ok(())
}

fn mount_partition(partition_name: &str, lowerdir: &Vec<String>) -> Result<()> {
    if lowerdir.is_empty() {
        warn!("partition: {partition_name} lowerdir is empty");
        return Ok(());
    }

    let partition = format!("/{partition_name}");

    // if /partition is a symlink and linked to /system/partition, then we don't need to overlay it separately
    if Path::new(&partition).read_link().is_ok() {
        warn!("partition: {partition} is a symlink");
        return Ok(());
    }

    let mut workdir = None;
    let mut upperdir = None;
    let system_rw_dir = Path::new(defs::SYSTEM_RW_DIR);
    if system_rw_dir.exists() {
        workdir = Some(system_rw_dir.join(partition_name).join("workdir"));
        upperdir = Some(system_rw_dir.join(partition_name).join("upperdir"));
    }

    mount::mount_overlay(&partition, lowerdir, workdir, upperdir)
}

pub fn mount_systemlessly(module_dir: &str, is_img: bool) -> Result<()> {
    // construct overlay mount params
    if !is_img {
        info!("fallback to modules.img");
        let module_update_dir = defs::MODULE_DIR;
        let module_dir = defs::MODULE_MOUNT_DIR;
        let tmp_module_img = defs::MODULE_UPDATE_TMP_IMG;
        let tmp_module_path = Path::new(tmp_module_img);

        ensure_clean_dir(module_dir)?;
        info!("- Preparing image");
        if tmp_module_path.exists() {
            //if it have update,remove tmp file
            std::fs::remove_file(tmp_module_path)?;
        }
        let total_size = calculate_total_size(Path::new(module_update_dir))?; //create modules adapt size
        info!(
            "Total size of files in '{}': {} bytes",
            tmp_module_path.display(),
            total_size
        );
        let grow_size = 128 * 1024 * 1024 + total_size;
        fs::File::create(tmp_module_img)
            .context("Failed to create ext4 image file")?
            .set_len(grow_size)
            .context("Failed to extend ext4 image")?;
        let result = Command::new("mkfs.ext4")
            .arg("-b")
            .arg("1024")
            .arg(tmp_module_img)
            .stdout(std::process::Stdio::piped())
            .output()?;
        ensure!(
            result.status.success(),
            "Failed to format ext4 image: {}",
            String::from_utf8(result.stderr).unwrap()
        );
        info!("Checking Image");
        module::check_image(tmp_module_img)?;
        info!("- Mounting image");
        mount::AutoMountExt4::try_new(tmp_module_img, module_dir, false)
            .with_context(|| "mount module image failed".to_string())?;
        info!("mounted {} to {}", tmp_module_img, module_dir);
        let _ = restorecon::setsyscon(module_dir);
        let command_string = format!(
            "cp --preserve=context -R {}* {};",
            module_update_dir, module_dir
        );
        let args = vec!["-c", &command_string];
        let _ = utils::run_command("sh", &args, None)?.wait()?;
        mount_systemlessly(module_dir, true)?;
        return Ok(());
    }
    let dir = fs::read_dir(module_dir);
    let Ok(dir) = dir else {
        bail!("open {} failed", defs::MODULE_DIR);
    };

    let mut system_lowerdir: Vec<String> = Vec::new();

    let partition = vec!["vendor", "product", "system_ext", "odm", "oem"];
    let mut partition_lowerdir: HashMap<String, Vec<String>> = HashMap::new();
    for ele in &partition {
        partition_lowerdir.insert((*ele).to_string(), Vec::new());
    }

    for entry in dir.flatten() {
        let module = entry.path();
        if !module.is_dir() {
            continue;
        }
        let disabled = module.join(defs::DISABLE_FILE_NAME).exists();
        if disabled {
            info!("module: {} is disabled, ignore!", module.display());
            continue;
        }
        let skip_mount = module.join(defs::SKIP_MOUNT_FILE_NAME).exists();
        if skip_mount {
            info!("module: {} skip_mount exist, skip!", module.display());
            continue;
        }

        let module_system = Path::new(&module).join("system");
        if module_system.is_dir() {
            system_lowerdir.push(format!("{}", module_system.display()));
        }

        for part in &partition {
            // if /partition is a mountpoint, we would move it to $MODPATH/$partition when install
            // otherwise it must be a symlink and we don't need to overlay!
            let part_path = Path::new(&module).join(part);
            if part_path.is_dir() {
                if let Some(v) = partition_lowerdir.get_mut(*part) {
                    v.push(format!("{}", part_path.display()));
                }
            }
        }
    }

    // mount /system first
    if let Err(e) = mount_partition("system", &system_lowerdir) {
        warn!("mount system failed: {:#}", e);
        //ensure_file_exists(format!("{}",defs::BIND_MOUNT_FILE))?;
        //ensure_clean_dir(defs::MODULE_DIR)?;
        //info!("bind_mount enable,overlayfs is not work,clear module_dir");
    }

    // mount other partitions
    for (k, v) in partition_lowerdir {
        if let Err(e) = mount_partition(&k, &v) {
            warn!("mount {k} failed: {:#}", e);
        }
    }

    Ok(())
}

pub fn systemless_bind_mount(module_dir: &str) -> Result<()> {
    //let propagation_flags = MountPropagationFlags::PRIVATE;

    //let combined_flags = MountFlags::empty() | MountFlags::from_bits_truncate(propagation_flags.bits());
    // set tmp_path prvate
    //mount("tmpfs",utils::get_tmp_path(),"tmpfs",combined_flags,"")?;

    // construct bind mount params
    m_mount::magic_mount()?;
    Ok(())
}

pub fn calculate_total_size(path: &Path) -> std::io::Result<u64> {
    let mut total_size = 0;
    if path.is_dir() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if file_type.is_file() {
                total_size += entry.metadata()?.len();
            } else if file_type.is_dir() {
                total_size += calculate_total_size(&entry.path())?;
            }
        }
    }
    Ok(total_size)
}
pub fn move_file(module_update_dir: &str, module_dir: &str) -> Result<()> {
    for entry in fs::read_dir(module_update_dir)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let file_name_str = file_name.to_string_lossy();

        if entry.path().is_dir() {
            let source_path = Path::new(module_update_dir).join(file_name_str.as_ref());
            let target_path = Path::new(module_dir).join(file_name_str.as_ref());
            if target_path.exists() {
                info!(
                    "Removing existing folder in target directory: {}",
                    file_name_str
                );
                remove_dir_all(&target_path)?;
            }

            info!("Moving {} to target directory", file_name_str);
            rename(&source_path, &target_path)?;
        }
    }
    return Ok(());
}
pub fn on_post_data_fs(superkey: Option<String>) -> Result<()> {
    utils::umask(0);
    use std::process::Stdio;
    #[cfg(unix)]
    init_load_package_uid_config(&superkey);

    init_load_su_path(&superkey);

    let args = ["/data/adb/ap/bin/magiskpolicy", "--magisk", "--live"];
    fork_for_result("/data/adb/ap/bin/magiskpolicy", &args, &superkey);

    info!("Re-privilege apd profile after injecting sepolicy");
    supercall::privilege_apd_profile(&superkey);

    if utils::has_magisk() {
        warn!("Magisk detected, skip post-fs-data!");
        return Ok(());
    }

    // Create log environment
    if !Path::new(defs::APATCH_LOG_FOLDER).exists() {
        fs::create_dir(defs::APATCH_LOG_FOLDER).expect("Failed to create log folder");
        let permissions = fs::Permissions::from_mode(0o700);
        fs::set_permissions(defs::APATCH_LOG_FOLDER, permissions)
            .expect("Failed to set permissions");
    }
    let mut command_string = format!(
        "rm -rf {}*.old.log; for file in {}*; do mv \"$file\" \"$file.old.log\"; done",
        defs::APATCH_LOG_FOLDER,
        defs::APATCH_LOG_FOLDER
    );
    let mut args = vec!["-c", &command_string];
    // for all file to .old
    let result = utils::run_command("sh", &args, None)?.wait()?;
    if result.success() {
        info!("Successfully deleted .old files.");
    } else {
        info!("Failed to delete .old files.");
    }
    let logcat_path = format!("{}locat.log", defs::APATCH_LOG_FOLDER);
    let dmesg_path = format!("{}dmesg.log", defs::APATCH_LOG_FOLDER);
    let bootlog = std::fs::File::create(dmesg_path)?;
    args = vec![
        "-s",
        "9",
        "120s",
        "logcat",
        "-b",
        "main,system,crash",
        "-f",
        &logcat_path,
        "logcatcher-bootlog:S",
        "&",
    ];
    let _ = unsafe {
        std::process::Command::new("timeout")
            .process_group(0)
            .pre_exec(|| {
                utils::switch_cgroups();
                Ok(())
            })
            .args(args)
            .spawn()
    };
    args = vec!["-s", "9", "120s", "dmesg", "-w"];
    let result = unsafe {
        std::process::Command::new("timeout")
            .process_group(0)
            .pre_exec(|| {
                utils::switch_cgroups();
                Ok(())
            })
            .args(args)
            .stdout(Stdio::from(bootlog))
            .spawn()
    };

    let key = "KERNELPATCH_VERSION";
    match env::var(key) {
        Ok(value) => println!("{}: {}", key, value),
        Err(_) => println!("{} not found", key),
    }

    let key = "KERNEL_VERSION";
    match env::var(key) {
        Ok(value) => println!("{}: {}", key, value),
        Err(_) => println!("{} not found", key),
    }

    let safe_mode = utils::is_safe_mode(superkey.clone());

    if safe_mode {
        // we should still mount modules.img to `/data/adb/modules` in safe mode
        // becuase we may need to operate the module dir in safe mode
        warn!("safe mode, skip common post-fs-data.d scripts");
        if let Err(e) = crate::module::disable_all_modules() {
            warn!("disable all modules failed: {}", e);
        }
    } else {
        // Then exec common post-fs-data scripts
        if let Err(e) = crate::module::exec_common_scripts("post-fs-data.d", true) {
            warn!("exec common post-fs-data scripts failed: {}", e);
        }
    }
    let module_update_dir = defs::MODULE_UPDATE_TMP_DIR; //save module place
    let module_dir = defs::MODULE_DIR; // run modules place
    let module_update_flag = Path::new(defs::WORKING_DIR).join(defs::UPDATE_FILE_NAME); // if update ,there will be renew modules file
    assets::ensure_binaries().with_context(|| "binary missing")?;

    let tmp_module_img = defs::MODULE_UPDATE_TMP_IMG;
    let tmp_module_path = Path::new(tmp_module_img);
    move_file(module_update_dir, module_dir)?;
    info!("remove update flag");
    let _ = fs::remove_file(module_update_flag);
    if tmp_module_path.exists() {
        //if it have update,remove tmp file
        std::fs::remove_file(tmp_module_path)?;
    }

    let lite_file = Path::new(defs::LITEMODE_FILE);

    if safe_mode {
        warn!("safe mode, skip post-fs-data scripts and disable all modules!");
        if let Err(e) = crate::module::disable_all_modules() {
            warn!("disable all modules failed: {}", e);
        }
        return Ok(());
    }

    if let Err(e) = module::prune_modules() {
        warn!("prune modules failed: {}", e);
    }

    if let Err(e) = restorecon::restorecon() {
        warn!("restorecon failed: {}", e);
    }

    // load sepolicy.rule
    if crate::module::load_sepolicy_rule().is_err() {
        warn!("load sepolicy.rule failed");
    }
    if lite_file.exists() {
        info!("litemode runing skip mount tempfs")
    } else {
        if let Err(e) = mount::mount_tmpfs(utils::get_tmp_path()) {
            warn!("do temp dir mount failed: {}", e);
        }
    }

    // exec modules post-fs-data scripts
    // TODO: Add timeout
    if let Err(e) = crate::module::exec_stage_script("post-fs-data", true) {
        warn!("exec post-fs-data scripts failed: {}", e);
    }

    // load system.prop
    if let Err(e) = crate::module::load_system_prop() {
        warn!("load system.prop failed: {}", e);
    }

    if lite_file.exists() {
        info!("litemode runing skip mount state")
    } else {
        if utils::should_enable_overlay()? {
            // mount module systemlessly by overlay
            let work_dir = get_work_dir();
            let tmp_dir = PathBuf::from(work_dir.clone());
            ensure_dir_exists(&tmp_dir)?;
            mount(
                defs::AP_OVERLAY_SOURCE,
                &tmp_dir,
                "tmpfs",
                MountFlags::empty(),
                "",
            )
            .context("mount tmp")?;
            mount_change(&tmp_dir, MountPropagationFlags::PRIVATE).context("make tmp private")?;
            let dir_names = vec!["vendor", "product", "system_ext", "odm", "oem", "system"];
            let dir = fs::read_dir(module_dir)?;
            for entry in dir.flatten() {
                let module_path = entry.path();
                let disabled = module_path.join(defs::DISABLE_FILE_NAME).exists();
                if disabled {
                    info!("module: {} is disabled, ignore!", module_path.display());
                    continue;
                }
                if module_path.is_dir() {
                    let module_name = module_path.file_name().unwrap().to_string_lossy();
                    let module_dest = Path::new(&work_dir).join(module_name.as_ref());

                    for sub_dir in dir_names.iter() {
                        let sub_dir_path = module_path.join(sub_dir);
                        if sub_dir_path.exists() && sub_dir_path.is_dir() {
                            let sub_dir_dest = module_dest.join(sub_dir);
                            fs::create_dir_all(&sub_dir_dest)?;

                            copy_dir_with_xattr(&sub_dir_path, &sub_dir_dest)?;
                        }
                    }
                }
            }
            if let Err(e) = mount_systemlessly(&get_work_dir(), false) {
                warn!("do systemless mount failed: {}", e);
            }
            if let Err(e) = unmount(&tmp_dir, UnmountFlags::DETACH) {
                log::error!("failed to unmount tmp {}", e);
            }
        } else {
            if let Err(e) = systemless_bind_mount(module_dir) {
                warn!("do systemless bind_mount failed: {}", e);
            }
        }
    }

    run_stage("post-mount", superkey, true);

    env::set_current_dir("/").with_context(|| "failed to chdir to /")?;

    Ok(())
}

fn run_stage(stage: &str, superkey: Option<String>, block: bool) {
    utils::umask(0);

    if utils::has_magisk() {
        warn!("Magisk detected, skip {stage}");
        return;
    }

    if utils::is_safe_mode(superkey) {
        warn!("safe mode, skip {stage} scripts");
        if let Err(e) = crate::module::disable_all_modules() {
            warn!("disable all modules failed: {}", e);
        }
        return;
    }

    if let Err(e) = crate::module::exec_common_scripts(&format!("{stage}.d"), block) {
        warn!("Failed to exec common {stage} scripts: {e}");
    }
    if let Err(e) = crate::module::exec_stage_script(stage, block) {
        warn!("Failed to exec {stage} scripts: {e}");
    }
}

pub fn on_services(superkey: Option<String>) -> Result<()> {
    info!("on_services triggered!");
    run_stage("service", superkey, false);

    Ok(())
}

fn run_uid_monitor() {
    info!("Trigger run_uid_monitor!");

    let mut command = &mut Command::new("/data/adb/passkeyd");
    {
        command = command.process_group(0);
        command = unsafe {
            command.pre_exec(|| {
                // ignore the error?
                switch_cgroups();
                Ok(())
            })
        };
    }
    command = command.arg("uid-listener");

    command
        .spawn()
        .map(|_| ())
        .expect("[run_uid_monitor] Failed to run uid monitor");
}

pub fn on_boot_completed(superkey: Option<String>) -> Result<()> {
    info!("on_boot_completed triggered!");

    run_uid_monitor();
    run_stage("boot-completed", superkey, false);

    Ok(())
}

pub fn start_uid_listener() -> Result<()> {
    info!("start_uid_listener triggered!");
    println!("[start_uid_listener] Registering...");

    // create inotify instance
    const SYS_PACKAGES_LIST_TMP: &str = "/data/system/packages.list.tmp";
    let sys_packages_list_tmp = PathBuf::from(&SYS_PACKAGES_LIST_TMP);
    let dir: PathBuf = sys_packages_list_tmp.parent().unwrap().into();

    let (tx, rx) = std::sync::mpsc::channel();
    let tx_clone = tx.clone();
    let mutex = Arc::new(Mutex::new(()));

    let mut watcher = INotifyWatcher::new(
        move |ev: notify::Result<Event>| match ev {
            Ok(Event {
                kind: EventKind::Modify(ModifyKind::Name(RenameMode::Both)),
                paths,
                ..
            }) => {
                if paths.contains(&sys_packages_list_tmp) {
                    info!("[uid_monitor] System packages list changed, sending to tx...");
                    tx_clone.send(false).unwrap()
                }
            }
            Err(err) => warn!("inotify error: {err}"),
            _ => (),
        },
        Config::default(),
    )?;

    watcher.watch(dir.as_ref(), RecursiveMode::NonRecursive)?;

    let mut debounce = false;
    while let Ok(delayed) = rx.recv() {
        if delayed {
            debounce = false;
            let skey = CStr::from_bytes_with_nul(b"su\0")
                .expect("[start_uid_listener] CStr::from_bytes_with_nul failed");
            refresh_ap_package_list(&skey, &mutex);
        } else if !debounce {
            thread::sleep(Duration::from_secs(1));
            debounce = true;
            tx.send(true).unwrap();
        }
    }

    Ok(())
}

"""



