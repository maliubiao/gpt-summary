响应:

```
嗯，我现在需要分析这个APatch的util_functions.sh脚本的功能，并按照执行顺序列举步骤。首先，我应该通读代码，看看每个函数的作用，然后尝试理清它们的执行流程。

这个脚本是APatch项目的一部分，APatch类似于Magisk，支持内核和系统补丁。根据项目描述，它涉及模块管理和内核钩子。那这个脚本可能是用于安装或修补boot镜像的辅助函数集合。

首先，看到脚本开头定义了很多函数，比如ui_print、toupper、grep_cmdline、grep_prop等。这些应该是工具函数，用于输出信息、处理字符串、获取属性值等。接下来是一些重要的函数，比如getvar、is_mounted、abort、set_nvbase，这些可能用于设置环境变量、检查挂载状态、错误处理等。

然后是setup_flashable和ensure_bb函数，看起来是确保BusyBox可用，并设置刷机环境。可能是在刷机模式（如TWRP Recovery）下运行时的初始化步骤。接下来是recovery_actions和recovery_cleanup，处理恢复模式下的挂载和清理，比如绑定设备、设置LD路径等。

find_block函数用于查找块设备，可能在挂载分区时使用。get_current_slot和get_next_slot处理A/B分区的槽位信息，这在支持无缝更新的设备上很重要。find_boot_image查找boot镜像的位置，比如boot_a或boot_b分区。

flash_image函数负责将新镜像刷入指定块设备，处理不同的压缩格式和块设备类型。mount_partitions挂载系统分区，检查是否以system-as-root方式启动，这在Android 10及以上常见。get_flags获取一些标志，比如是否加密、是否保留dm-verity等。

install_apatch函数看起来是核心，调用boot_patch.sh来修补boot镜像，然后刷入。check_data检查/data分区是否可用和是否解密，设置NVBASE路径。api_level_arch_detect检测API级别和CPU架构，这对于后续操作的正确性很重要。remove_system_su移除系统原有的su，防止冲突。run_migrations处理备份和迁移旧数据。

现在要整理执行顺序。假设这个脚本被其他脚本调用，比如安装脚本。通常，刷机流程可能如下：

1. 初始化环境，设置工具函数，如ui_print、错误处理。
2. 确保BusyBox可用，可能重新执行脚本以确保环境正确。
3. 在恢复模式下设置OUTFD，处理恢复模式特有的挂载和路径。
4. 挂载必要的分区，比如/system、/vendor等，检查system-as-root。
5. 检测当前槽位（A/B分区），确定boot镜像的位置。
6. 检查数据分区状态，是否加密，设置存储路径。
7. 获取设备信息，如API级别、CPU架构。
8. 移除已有的SU或root解决方案，避免冲突。
9. 修补boot镜像，包括处理verity、加密标志等。
10. 刷入修补后的boot镜像，进行备份和迁移。

可能涉及的具体步骤：

- 设置输出和工具函数。
- 检查运行环境（是否在恢复模式）。
- 挂载系统分区，确定分区结构。
- 检测当前槽位，找到对应的boot分区。
- 处理加密和verity设置。
- 备份原始boot镜像。
- 修补boot镜像，可能修改内核或添加模块支持。
- 刷入新的boot镜像。
- 清理临时文件，恢复挂载点。

例如，当用户执行安装时，脚本可能首先调用mount_partitions来挂载系统，然后find_boot_image确定boot位置，接着install_apatch进行修补和刷写。过程中会处理A/B分区，确保刷入正确的槽位。

关于生成的痕迹，APatch可能会在/data/adb目录下存放模块和配置，修改boot分区，并在/data/magisk_backup_*备份原始镜像。外部进程可能看到这些文件和修改后的boot分区，以及可能加载的内核模块。
```
### 按执行顺序的功能步骤分析：

1. **环境初始化与工具加载**  
   初始化`ui_print`等输出工具，加载字符串处理、属性解析、挂载检查等基础函数。

2. **BusyBox环境确保**  
   通过`ensure_bb`检测并确保BusyBox可用，重新以BusyBox解释器执行脚本。

3. **Recovery模式适配**  
   `setup_flashable`设置输出描述符`OUTFD`，处理Recovery下的随机数设备绑定和库路径。

4. **分区挂载与结构检测**  
   `mount_partitions`挂载`/system`，判断`system-as-root`和动态分区，设置`SYSTEM_AS_ROOT`等标志。

5. **A/B槽位判定**  
   `get_current_slot`从内核参数或属性获取当前启动槽（如`_a`/`_b`），影响分区路径。

6. **Boot镜像定位**  
   `find_boot_image`遍历块设备名（`boot`、`kernel`等）和`fstab`，确定`BOOTIMAGE`设备路径。

7. **设备状态检测**  
   `get_flags`检查加密状态、`vbmeta`分区，决定是否保留`dm-verity`或强制加密标志。

8. **旧Root方案清理**  
   `remove_system_su`删除系统内置的SuperSU等文件，避免与新补丁冲突。

9. **Boot镜像修补与刷入**  
   `install_apatch`调用`boot_patch.sh`修改镜像，`flash_image`写入设备，处理压缩和NAND类型。

10. **备份与数据迁移**  
    `run_migrations`将旧备份移动到`/data/magisk_backup_*`，按SHA1分类存储。

---

### 关键功能Shell代码示例（模拟Boot修补）

```bash
# 模拟流程：找到boot分区，备份，修补并刷入
#!/system/bin/sh

# 引入util_functions.sh
source /path/to/util_functions.sh

# 挂载分区
mount_partitions

# 获取当前槽位
get_current_slot

# 查找boot镜像
find_boot_image
echo "Boot image located at: $BOOTIMAGE"

# 备份原始boot
backup_dir="/data/backup_$(date +%s)"
mkdir -p $backup_dir
dd if=$BOOTIMAGE of=$backup_dir/boot_orig.img

# 修补boot（假设已有new-boot.img）
flash_image new-boot.img $BOOTIMAGE
```

**输入/输出假设：**  
- 输入：修补后的`new-boot.img`文件。  
- 输出：`BOOTIMAGE`分区被更新，备份存放在`/data/backup_<timestamp>`。

---

### 文件系统访问与参数处理细节

- **`find_block`处理逻辑**  
  遍历`/dev/block`、`/sys/dev/block`，匹配分区名（如`boot`），支持`PARTNAME`和`DEVNAME`两种查找方式。  
  示例命令：`find_block boot_a` → 输出`/dev/block/sda1`。

- **`flash_image`参数**  
  第一个参数为镜像路径，第二个为块设备。自动处理`.gz`压缩，根据设备类型（块/字符/NAND）选择`dd`或`nandwrite`。

---

### Android外部可见痕迹

1. **分区修改**  
   Boot分区的修改可通过`fastboot getvar all`或校验哈希检测。

2. **文件痕迹**  
   - `/data/adb/apatch/`: 配置和模块存储目录。  
   - `/data/magisk_backup_*/`: 原始镜像备份。  
   - `/cache/apatch.log`: 可能的日志残留（如果脚本启用日志记录）。

3. **进程特征**  
   APatch守护进程或内核模块（如`kpatch`相关进程）可能在`ps`或`lsmod`中可见。
提示器:

这是路径为APatch/app/src/main/assets/util_functions.sh的apatch `The patching of Android kernel and Android system`实现的一部分，
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

```bash
#!/system/bin/sh
#######################################################################################
# Helper Functions (credits to topjohnwu)
#######################################################################################
APATCH_VER='0.10.4'
APATCH_VER_CODE=164

ui_print() {
  if $BOOTMODE; then
    echo "$1"
  else
    echo -e "ui_print $1\nui_print" >> /proc/self/fd/$OUTFD
  fi
}

toupper() {
  echo "$@" | tr '[:lower:]' '[:upper:]'
}

grep_cmdline() {
  local REGEX="s/^$1=//p"
  { echo $(cat /proc/cmdline)$(sed -e 's/[^"]//g' -e 's/""//g' /proc/cmdline) | xargs -n 1; \
    sed -e 's/ = /=/g' -e 's/, /,/g' -e 's/"//g' /proc/bootconfig; \
  } 2>/dev/null | sed -n "$REGEX"
}

grep_prop() {
  local REGEX="s/^$1=//p"
  shift
  local FILES=$@
  [ -z "$FILES" ] && FILES='/system/build.prop'
  cat $FILES 2>/dev/null | dos2unix | sed -n "$REGEX" | head -n 1
}

getvar() {
  local VARNAME=$1
  local VALUE
  local PROPPATH='/data/.magisk /cache/.magisk'
  [ ! -z $MAGISKTMP ] && PROPPATH="$MAGISKTMP/.magisk/config $PROPPATH"
  VALUE=$(grep_prop $VARNAME $PROPPATH)
  [ ! -z $VALUE ] && eval $VARNAME=\$VALUE
}

is_mounted() {
  grep -q " $(readlink -f $1) " /proc/mounts 2>/dev/null
  return $?
}
abort() {
  ui_print "$1"
  $BOOTMODE || recovery_cleanup
  [ ! -z $MODPATH ] && rm -rf $MODPATH
  rm -rf $TMPDIR
  exit 1
}
set_nvbase() {
  NVBASE="$1"
  MAGISKBIN="$1/magisk"
}

print_title() {
  local len line1len line2len bar
  line1len=$(echo -n $1 | wc -c)
  line2len=$(echo -n $2 | wc -c)
  len=$line2len
  [ $line1len -gt $line2len ] && len=$line1len
  len=$((len + 2))
  bar=$(printf "%${len}s" | tr ' ' '*')
  ui_print "$bar"
  ui_print " $1 "
  [ "$2" ] && ui_print " $2 "
  ui_print "$bar"
}
setup_flashable() {
  ensure_bb
  $BOOTMODE && return
  if [ -z $OUTFD ] || readlink /proc/$$/fd/$OUTFD | grep -q /tmp; then
    # We will have to manually find out OUTFD
    for FD in $(ls /proc/$$/fd); do
      if readlink /proc/$$/fd/$FD | grep -q pipe; then
        if ps | grep -v grep | grep -qE " 3 $FD |status_fd=$FD"; then
          OUTFD=$FD
          break
        fi
      fi
    done
  fi
  recovery_actions
}

ensure_bb() {
  if set -o | grep -q standalone; then
    # We are definitely in busybox ash
    set -o standalone
    return
  fi

  # Find our busybox binary
  local bb
  if [ -f $TMPDIR/busybox ]; then
    bb=$TMPDIR/busybox
  elif [ -f $MAGISKBIN/busybox ]; then
    bb=$MAGISKBIN/busybox
  else
    abort "! Cannot find BusyBox"
  fi
  chmod 755 $bb

  # Busybox could be a script, make sure /system/bin/sh exists
  if [ ! -f /system/bin/sh ]; then
    umount -l /system 2>/dev/null
    mkdir -p /system/bin
    ln -s $(command -v sh) /system/bin/sh
  fi

  export ASH_STANDALONE=1

  # Find our current arguments
  # Run in busybox environment to ensure consistent results
  # /proc/<pid>/cmdline shall be <interpreter> <script> <arguments...>
  local cmds="$($bb sh -c "
  for arg in \$(tr '\0' '\n' < /proc/$$/cmdline); do
    if [ -z \"\$cmds\" ]; then
      # Skip the first argument as we want to change the interpreter
      cmds=\"sh\"
    else
      cmds=\"\$cmds '\$arg'\"
    fi
  done
  echo \$cmds")"

  # Re-exec our script
  echo $cmds | $bb xargs $bb
  exit
}
recovery_actions() {
  # Make sure random won't get blocked
  mount -o bind /dev/urandom /dev/random
  # Unset library paths
  OLD_LD_LIB=$LD_LIBRARY_PATH
  OLD_LD_PRE=$LD_PRELOAD
  OLD_LD_CFG=$LD_CONFIG_FILE
  unset LD_LIBRARY_PATH
  unset LD_PRELOAD
  unset LD_CONFIG_FILE
}
recovery_cleanup() {
  local DIR
  ui_print "- Unmounting partitions"
  (
  if [ ! -d /postinstall/tmp ]; then
    umount -l /system
    umount -l /system_root
  fi
  umount -l /vendor
  umount -l /persist
  umount -l /metadata
  for DIR in /apex /system /system_root; do
    if [ -L "${DIR}_link" ]; then
      rmdir $DIR
      mv -f ${DIR}_link $DIR
    fi
  done
  umount -l /dev/random
  ) 2>/dev/null
  [ -z $OLD_LD_LIB ] || export LD_LIBRARY_PATH=$OLD_LD_LIB
  [ -z $OLD_LD_PRE ] || export LD_PRELOAD=$OLD_LD_PRE
  [ -z $OLD_LD_CFG ] || export LD_CONFIG_FILE=$OLD_LD_CFG
}

find_block() {
  local BLOCK DEV DEVICE DEVNAME PARTNAME UEVENT
  for BLOCK in "$@"; do
    DEVICE=$(find /dev/block \( -type b -o -type c -o -type l \) -iname $BLOCK | head -n 1) 2>/dev/null
    if [ ! -z $DEVICE ]; then
      readlink -f $DEVICE
      return 0
    fi
  done
  # Fallback by parsing sysfs uevents
  for UEVENT in /sys/dev/block/*/uevent; do
    DEVNAME=$(grep_prop DEVNAME $UEVENT)
    PARTNAME=$(grep_prop PARTNAME $UEVENT)
    for BLOCK in "$@"; do
      if [ "$(toupper $BLOCK)" = "$(toupper $PARTNAME)" ]; then
        echo /dev/block/$DEVNAME
        return 0
      fi
    done
  done
  # Look just in /dev in case we're dealing with MTD/NAND without /dev/block devices/links
  for DEV in "$@"; do
    DEVICE=$(find /dev \( -type b -o -type c -o -type l \) -maxdepth 1 -iname $DEV | head -n 1) 2>/dev/null
    if [ ! -z $DEVICE ]; then
      readlink -f $DEVICE
      return 0
    fi
  done
  return 1
}

# After calling this method, the following variables will be set:
# SLOT
get_current_slot() {
  # Check A/B slot
  SLOT=$(grep_cmdline androidboot.slot_suffix)
  if [ -z $SLOT ]; then
    SLOT=$(grep_cmdline androidboot.slot)
    [ -z $SLOT ] || SLOT=_${SLOT}
  fi
  if [ -z $SLOT ]; then
    SLOT=$(getprop ro.boot.slot_suffix)
  fi
  [ "$SLOT" = "normal" ] && unset SLOT
  [ -z $SLOT ] || echo "SLOT=$SLOT"
}

# After calling this method, the following variables will be set:
# SLOT
# This is used after OTA
get_next_slot() {
  # Check A/B slot
  SLOT=$(grep_cmdline androidboot.slot_suffix)
  if [ -z $SLOT ]; then
    SLOT=$(grep_cmdline androidboot.slot)
    [ -z $SLOT ] || SLOT=_${SLOT}
  fi
  if [ -z $SLOT ]; then
    SLOT=$(getprop ro.boot.slot_suffix)
  fi
   [ -z $SLOT ] && { >&2 echo "can't determined next boot slot! check your devices is A/B"; exit 1; }
   [ "$SLOT" = "normal" ] &&  { >&2 echo "can't determined next boot slot! check your devices is A/B"; exit 1; }
  if [[ $SLOT == *_a ]]; then
    SLOT='_b'
  else
    SLOT='_a'
  fi
  echo "SLOT=$SLOT"
}

find_boot_image() {
  if [ ! -z $SLOT ]; then
    BOOTIMAGE=$(find_block "boot$SLOT")
  fi
  if [ -z $BOOTIMAGE ]; then
    BOOTIMAGE=$(find_block kern-a android_boot kernel bootimg boot lnx boot_a)
  fi
  if [ -z $BOOTIMAGE ]; then
    # Lets see what fstabs tells me
    BOOTIMAGE=$(grep -v '#' /etc/*fstab* | grep -E '/boot(img)?[^a-zA-Z]' | grep -oE '/dev/[a-zA-Z0-9_./-]*' | head -n 1)
  fi
  [ -z $BOOTIMAGE ] || echo "BOOTIMAGE=$BOOTIMAGE"
}

flash_image() {
  local CMD1
  case "$1" in
    *.gz) CMD1="gzip -d < '$1' 2>/dev/null";;
    *)    CMD1="cat '$1'";;
  esac
  if [ -b "$2" ]; then {
      local img_sz=$(stat -c '%s' "$1")
      local blk_sz=$(blockdev --getsize64 "$2")
      local blk_bs=$(blockdev --getbsz "$2")
      [ "$img_sz" -gt "$blk_sz" ] && return 1
      blockdev --setrw "$2"
      local blk_ro=$(blockdev --getro "$2")
      [ "$blk_ro" -eq 1 ] && return 2
      eval "$CMD1" | dd of="$2" bs="$blk_bs" iflag=fullblock conv=notrunc,fsync 2>/dev/null
      sync
  } elif [ -c "$2" ]; then {
      flash_eraseall "$2" >&2
      eval "$CMD1" | nandwrite -p "$2" - >&2
  } else {
      echo "- Not block or char device, storing image"
      eval "$CMD1" > "$2" 2>/dev/null
  } fi
  return 0
}

setup_mntpoint() {
  local POINT=$1
  [ -L $POINT ] && mv -f $POINT ${POINT}_link
  if [ ! -d $POINT ]; then
    rm -f $POINT
    mkdir -p $POINT
  fi
}

mount_name() {
  local PART=$1
  local POINT=$2
  local FLAG=$3
  setup_mntpoint $POINT
  is_mounted $POINT && return
  # First try mounting with fstab
  mount $FLAG $POINT 2>/dev/null
  if ! is_mounted $POINT; then
    local BLOCK=$(find_block $PART)
    mount $FLAG $BLOCK $POINT || return
  fi
  ui_print "- Mounting $POINT"
}

mount_ro_ensure() {
  # We handle ro partitions only in recovery
  $BOOTMODE && return
  local PART=$1
  local POINT=$2
  mount_name "$PART" $POINT '-o ro'
  is_mounted $POINT || abort "! Cannot mount $POINT"
}

# After calling this method, the following variables will be set:
# SLOT, SYSTEM_AS_ROOT, LEGACYSAR
mount_partitions() {
  # Check A/B slot
  SLOT=$(grep_cmdline androidboot.slot_suffix)
  if [ -z $SLOT ]; then
    SLOT=$(grep_cmdline androidboot.slot)
    [ -z $SLOT ] || SLOT=_${SLOT}
  fi
  [ "$SLOT" = "normal" ] && unset SLOT
  [ -z $SLOT ] || ui_print "- Current boot slot: $SLOT"

  # Mount ro partitions
  if is_mounted /system_root; then
    umount /system 2>/dev/null
    umount /system_root 2>/dev/null
  fi
  mount_ro_ensure "system$SLOT app$SLOT" /system
  if [ -f /system/init -o -L /system/init ]; then
    SYSTEM_AS_ROOT=true
    setup_mntpoint /system_root
    if ! mount --move /system /system_root; then
      umount /system
      umount -l /system 2>/dev/null
      mount_ro_ensure "system$SLOT app$SLOT" /system_root
    fi
    mount -o bind /system_root/system /system
  else
    if grep ' / ' /proc/mounts | grep -qv 'rootfs' || grep -q ' /system_root ' /proc/mounts; then
      SYSTEM_AS_ROOT=true
    else
      SYSTEM_AS_ROOT=false
    fi
  fi
  $SYSTEM_AS_ROOT && ui_print "- Device is system-as-root"

  LEGACYSAR=false
  if $BOOTMODE; then
    grep ' / ' /proc/mounts | grep -q '/dev/root' && LEGACYSAR=true
  else
    # Recovery mode, assume devices that don't use dynamic partitions are legacy SAR
    local IS_DYNAMIC=false
    if grep -q 'androidboot.super_partition' /proc/cmdline; then
      IS_DYNAMIC=true
    elif [ -n "$(find_block super)" ]; then
      IS_DYNAMIC=true
    fi
    if $SYSTEM_AS_ROOT && ! $IS_DYNAMIC; then
      LEGACYSAR=true
      ui_print "- Legacy SAR, force kernel to load rootfs"
    fi
  fi
}

get_flags() {
  if grep ' /data ' /proc/mounts | grep -q 'dm-'; then
    ISENCRYPTED=true
  elif [ "$(getprop ro.crypto.state)" = "encrypted" ]; then
    ISENCRYPTED=true
  elif [ "$DATA" = "false" ]; then
    # No data access means unable to decrypt in recovery
    ISENCRYPTED=true
  else
    ISENCRYPTED=false
  fi
  if [ -n "$(find_block vbmeta vbmeta_a)" ]; then
    PATCHVBMETAFLAG=false
  else
    PATCHVBMETAFLAG=true
    ui_print "- No vbmeta partition, patch vbmeta in boot image"
  fi

  # Overridable config flags with safe defaults
  getvar KEEPVERITY
  getvar KEEPFORCEENCRYPT
  getvar RECOVERYMODE
  if [ -z $KEEPVERITY ]; then
    if $SYSTEM_AS_ROOT; then
      KEEPVERITY=true
      ui_print "- System-as-root, keep dm-verity"
    else
      KEEPVERITY=false
    fi
  fi
  if [ -z $KEEPFORCEENCRYPT ]; then
    if $ISENCRYPTED; then
      KEEPFORCEENCRYPT=true
      ui_print "- Encrypted data, keep forceencrypt"
    else
      KEEPFORCEENCRYPT=false
    fi
  fi
  [ -z $RECOVERYMODE ] && RECOVERYMODE=false
}

install_apatch() {
  cd $MAGISKBIN

  # Source the boot patcher
  SOURCEDMODE=true
  . ./boot_patch.sh "$BOOTIMAGE"
  ui_print "- Flashing new boot image"
  flash_image new-boot.img "$BOOTIMAGE"
  case $? in
    1)
      abort "! Insufficient partition size"
      ;;
    2)
      abort "! $BOOTIMAGE is read only"
      ;;
  esac
  ./magiskboot cleanup
  rm -f new-boot.img

  run_migrations
}

check_data() {
  DATA=false
  DATA_DE=false
  if grep ' /data ' /proc/mounts | grep -vq 'tmpfs'; then
    # Test if data is writable
    touch /data/.rw && rm /data/.rw && DATA=true
    # Test if data is decrypted
    $DATA && [ -d /data/adb ] && touch /data/adb/.rw && rm /data/adb/.rw && DATA_DE=true
    $DATA_DE && [ -d /data/adb/magisk ] || mkdir /data/adb/magisk || DATA_DE=false
  fi
  set_nvbase "/data"
  $DATA || set_nvbase "/cache/data_adb"
  $DATA_DE && set_nvbase "/data/adb"
}

api_level_arch_detect() {
  API=$(grep_get_prop ro.build.version.sdk)
  ABI=$(grep_get_prop ro.product.cpu.abi)
  if [ "$ABI" = "x86" ]; then
    ARCH=x86
    ABI32=x86
    IS64BIT=false
  elif [ "$ABI" = "arm64-v8a" ]; then
    ARCH=arm64
    ABI32=armeabi-v7a
    IS64BIT=true
  elif [ "$ABI" = "x86_64" ]; then
    ARCH=x64
    ABI32=x86
    IS64BIT=true
  else
    ARCH=arm
    ABI=armeabi-v7a
    ABI32=armeabi-v7a
    IS64BIT=false
  fi
}

remove_system_su() {
  [ -d /postinstall/tmp ] && POSTINST=/postinstall
  cd $POSTINST/system
  if [ -f bin/su -o -f xbin/su ] && [ ! -f /su/bin/su ]; then
    ui_print "- Removing system installed root"
    blockdev --setrw /dev/block/mapper/system$SLOT 2>/dev/null
    mount -o rw,remount $POSTINST/system
    # SuperSU
    cd bin
    if [ -e .ext/.su ]; then
      mv -f app_process32_original app_process32 2>/dev/null
      mv -f app_process64_original app_process64 2>/dev/null
      mv -f install-recovery_original.sh install-recovery.sh 2>/dev/null
      if [ -e app_process64 ]; then
        ln -sf app_process64 app_process
      elif [ -e app_process32 ]; then
        ln -sf app_process32 app_process
      fi
    fi
    # More SuperSU, SuperUser & ROM su
    cd ..
    rm -rf .pin bin/.ext etc/.installed_su_daemon etc/.has_su_daemon \
    xbin/daemonsu xbin/su xbin/sugote xbin/sugote-mksh xbin/supolicy \
    bin/app_process_init bin/su /cache/su lib/libsupol.so lib64/libsupol.so \
    su.d etc/init.d/99SuperSUDaemon etc/install-recovery.sh /cache/install-recovery.sh \
    .supersu /cache/.supersu /data/.supersu \
    app/Superuser.apk app/SuperSU /cache/Superuser.apk
  elif [ -f /cache/su.img -o -f /data/su.img -o -d /data/su -o -d /data/adb/su ]; then
    ui_print "- Removing systemless installed root"
    umount -l /su 2>/dev/null
    rm -rf /cache/su.img /data/su.img /data/su /data/adb/su /data/adb/suhide \
    /cache/.supersu /data/.supersu /cache/supersu_install /data/supersu_install
  fi
  cd $TMPDIR
}

run_migrations() {
  local LOCSHA1
  local TARGET
  # Legacy app installation
  local BACKUP=$MAGISKBIN/stock_boot*.gz
  if [ -f $BACKUP ]; then
    cp $BACKUP /data
    rm -f $BACKUP
  fi

  # Legacy backup
  for gz in /data/stock_boot*.gz; do
    [ -f $gz ] || break
    LOCSHA1=$(basename $gz | sed -e 's/stock_boot_//' -e 's/.img.gz//')
    [ -z $LOCSHA1 ] && break
    mkdir /data/magisk_backup_${LOCSHA1} 2>/dev/null
    mv $gz /data/magisk_backup_${LOCSHA1}/boot.img.gz
  done

  # Stock backups
  LOCSHA1=$SHA1
  for name in boot dtb dtbo dtbs; do
    BACKUP=$MAGISKBIN/stock_${name}.img
    [ -f $BACKUP ] || continue
    if [ $name = 'boot' ]; then
      LOCSHA1=$($MAGISKBIN/magiskboot sha1 $BACKUP)
      mkdir /data/magisk_backup_${LOCSHA1} 2>/dev/null
    fi
    TARGET=/data/magisk_backup_${LOCSHA1}/${name}.img
    cp $BACKUP $TARGET
    rm -f $BACKUP
    gzip -9f $TARGET
  done
}
"""



