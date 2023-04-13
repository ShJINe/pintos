#include "threads/loader.h"

#### Kernel loader.

#### This code should be stored in the first sector of a hard disk.
#### When the BIOS runs, it loads this code at physical address
#### 0x7c00-0x7e00 (512 bytes) and jumps to the beginning of it,
#### in real mode.  The loader loads the kernel into memory and jumps
#### to its entry point, which is the start function in start.S.
####
#### The BIOS passes in the drive that the loader was read from as
#### DL, with floppy drives numbered 0x00, 0x01, ... and hard drives
#### numbered 0x80, 0x81, ...  We want to support booting a kernel on
#### a different drive from the loader, so we don't take advantage of
#### this.

# Runs in real mode, which is a 16-bit segment.
	.code16

# Set up segment registers.
# Set stack to grow downward from 60 kB (after boot, the kernel
# continues to use this stack for its initial thread).

	sub %ax, %ax
	mov %ax, %ds
	mov %ax, %ss
	mov $0xf000, %esp  # 61,440B

# Configure serial port so we can report progress without connected VGA.
# See [IntrList] for details.
	sub %dx, %dx			# Serial port 0.
	mov $0xe3, %al			# 9600 bps, N-8-1.
					# AH is already 0 (Initialize Port).
	int $0x14			# Destroys AX.

	call puts
	.string "PiLo"

#### Read the partition table on each system hard disk and scan for a
#### partition of type 0x20, which is the type that we use for a
#### Pintos kernel.
####
#### Read [Partitions] for a description of the partition table format
#### that we parse.
####
#### We print out status messages to show the disk and partition being
#### scanned, e.g. hda1234 as we scan four partitions on the first
#### hard disk.

	mov $0x80, %dl			# Hard disk 0.
# 读取mbr
read_mbr:
	sub %ebx, %ebx			# Sector 0.
	mov $0x2000, %ax		# Use 0x20000 for buffer.
	mov %ax, %es			# 缓冲区基地址
	call read_sector
	jc no_such_drive

	# Print hd[a-z].
	call puts
	.string " hd"
	mov %dl, %al
	add $'a' - 0x80, %al
	call putc # 输出驱动设备号，hda，hdb，hdc等等

	# Check for MBR signature--if not present, it's not a
	# partitioned hard disk.
	cmpw $0xaa55, %es:510   # 检查是否是aa55，是否是可启动设备
	jne next_drive

	mov $446, %si			# Offset of partition table entry 1. si->分区表
	mov $'1', %al
# 查看分区表
check_partition:
	# Is it an unused partition?
	cmpl $0, %es:(%si)
	je next_partition

	# Print [1-4].
	call putc # 输出hda1，hda2，hda3

	# Is it a Pintos kernel partition?
	cmpb $0x20, %es:4(%si) # 分区格式为0x20->pintos自带分区
	jne next_partition

	# Is it a bootable partition?
	cmpb $0x80, %es:(%si) # 是否是激活分区
	je load_kernel

next_partition:
	# No match for this partition, go on to the next one.
	add $16, %si			# Offset to next partition table entry. 跳过该分区
	inc %al
	cmp $510, %si           # 分区表最后一项
	jb check_partition

next_drive:
	# No match on this drive, go on to the next one.
	inc %dl
	jnc read_mbr

no_such_drive:
no_boot_partition:
	# Didn't find a Pintos kernel partition anywhere, give up.
	call puts
	.string "\rNot found\r"

	# Notify BIOS that boot failed.  See [IntrList].
	int $0x18

#### We found a kernel.  The kernel's drive is in DL.  The partition
#### table entry for the kernel's partition is at ES:SI.  Our job now
#### is to read the kernel from disk and jump to its start address.

load_kernel:
	call puts
	.string "\rLoading"

	# Figure out number of sectors to read.  A Pintos kernel is
	# just an ELF format object, which doesn't have an
	# easy-to-read field to identify its own size (see [ELF1]).
	# But we limit Pintos kernels to 512 kB for other reasons, so
	# it's easy enough to just read the entire contents of the
	# partition or 512 kB from disk, whichever is smaller.
	mov %es:12(%si), %ecx		# EBP = number of sectors           es：缓冲地址，si：分区表项的偏移地址，12->第13字节，本分区的扇区数量（4字节）
	cmp $1024, %ecx			# Cap size at 512 kB
	jbe 1f
	mov $1024, %cx
1:

	mov %es:8(%si), %ebx		# EBX = first sector                es：缓冲地址，si：分区表项的偏移地址，8->第9字节，本分区起始逻辑扇区地址（4字节）
	mov $0x2000, %ax		# Start load address: 0x20000

next_sector:
	# Read one sector into memory.
	mov %ax, %es			# ES:0000 -> load address 
	call read_sector        # 读取扇区系统调用
	jc read_failed          # 有错误信息时c位置1

	# Print '.' as progress indicator once every 16 sectors == 8 kB.  一个扇区大小是512B，16个扇区是8KB
	test $15, %bl   # 为0时才不会跳转，要求bl低四位全为0。每16次读取打印一个点
	jnz 1f
	call puts
	.string "."
1:

	# Advance memory pointer and disk sector.  advance：前进
	add $0x20, %ax    # 因为es是段寄存器，这里实际上向前移动了0x200=512B
	inc %bx
	loop next_sector  # 循环次数由cx给出，该分区中的所有扇区

	call puts
	.string "\r"

#### Transfer control to the kernel that we loaded.  We read the start
#### address out of the ELF header (see [ELF1]) and convert it from a
#### 32-bit linear address into a 16:16 segment:offset address for
#### real mode, then jump to the converted address.  The 80x86 doesn't
#### have an instruction to jump to an absolute segment:offset kept in
#### registers, so in fact we store the address in a temporary memory
#### location, then jump indirectly through that location.  To save 4
#### bytes in the loader, we reuse 4 bytes of the loader's code for
#### this temporary pointer.

	mov $0x2000, %ax
	mov %ax, %es
	mov %es:0x18, %dx  # 0x18(16+2+2+4)指向EFI文件(kernel)的entry地址(4字节)
	mov %dx, start
	movw $0x2000, start + 2 # 复用entry地址的高16位，作为段地址
	ljmp *start

read_failed:
start:
	# Disk sector read failed.
	call puts
1:	.string "\rBad read\r"

	# Notify BIOS that boot failed.  See [IntrList].
	int $0x18

#### Print string subroutine.  To save space in the loader, this
#### subroutine takes its null-terminated string argument from the
#### code stream just after the call, and then returns to the byte
#### just after the terminating null.  This subroutine preserves all
#### general-purpose registers.

# 该函数基于以下假设：1.puts后是string，2.以call的方式调用puts
puts:	xchg %si, %ss:(%esp)  # 每个puts后面都跟着.string，因此执行call时，esp指向的是下一条指令的地址，也就是字符串的首地址
	push %ax
next_char:
	mov %cs:(%si), %al
	inc %si
	test %al, %al  # 按位与测试al是否为0
	jz 1f  #若为0(结束符)，则返回
	call putc
	jmp next_char
1:	pop %ax
	xchg %si, %ss:(%esp)
	ret

#### Character output subroutine.  Prints the character in AL to the
#### VGA display and serial port 0, using BIOS services (see
#### [IntrList]).  Preserves all general-purpose registers.
####
#### If called upon to output a carriage return, this subroutine
#### automatically supplies the following line feed.

putc:	pusha

1:	sub %bh, %bh			# Page 0.
	mov $0x0e, %ah			# Teletype output service.
	int $0x10

	mov $0x01, %ah			# Serial port output service.
	sub %dx, %dx			# Serial port 0.
2:	int $0x14			# Destroys AH.
	test $0x80, %ah			# Output timed out?
	jz 3f
	movw $0x9090, 2b		# Turn "int $0x14" above into NOPs.

3:
	cmp $'\r', %al
	jne popa_ret  # 返回
	mov $'\n', %al  # 遇到回车自动补充一个换行
	jmp 1b

#### Sector read subroutine.  Takes a drive number in DL (0x80 = hard
#### disk 0, 0x81 = hard disk 1, ...) and a sector number in EBX, and
#### reads the specified sector into memory at ES:0000.  Returns with
#### carry set on error, clear otherwise.  Preserves all
#### general-purpose registers.

# 读取扇区子程序，DL中存放驱动设备号，EBX中存放扇区号，ES:AX分别存放缓冲区的段基址和偏移，
# 错误存放在进位标志中

read_sector:
	pusha
	sub %ax, %ax
	push %ax			# LBA sector number [48:63]
	push %ax			# LBA sector number [32:47]
	push %ebx			# LBA sector number [0:31] 扇区的位置

	push %es			# Buffer segment
	push %ax			# Buffer offset (always 0) 缓冲区的位置

	push $1				# Number of sectors to read 读取扇区的个数

	push $16			# Packet size 数据包大小，传递参数的数量

	mov $0x42, %ah			# Extended read  扩展读取INT 0x13中断（AH=0x42），这使得它能够读取更大的扇区。
	mov %sp, %si			# DS:SI -> packet
	int $0x13			# Error code in CF
	popa				# Pop 16 bytes, preserve flags 弹出16bytes的值（前面压栈的所有参数）
popa_ret:
	popa            # 弹出pusha保存的8个通用寄存器
	ret				# Error code still in CF

#### Command-line arguments and their count.
#### This is written by the `pintos' utility and read by the kernel.
#### The loader itself does not do anything with the command line.
	.org LOADER_ARG_CNT - LOADER_BASE
	.fill LOADER_ARG_CNT_LEN, 1, 0

	.org LOADER_ARGS - LOADER_BASE
	.fill LOADER_ARGS_LEN, 1, 0

#### Partition table.
	.org LOADER_PARTS - LOADER_BASE
	.fill LOADER_PARTS_LEN, 1, 0

#### Boot-sector signature for BIOS inspection.
	.org LOADER_SIG - LOADER_BASE
	.word 0xaa55
