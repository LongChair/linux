#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/interrupt.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/mm.h>
#include <linux/major.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/io.h>
#include <linux/uaccess.h>
#include <linux/platform_device.h>
#include <linux/of_reserved_mem.h>
#include <linux/dma-contiguous.h>
#include <linux/mman.h>
#include <linux/slab.h>

// Module version
#define VERSION_MINOR 0

// Names / devices and general config

#define DRIVER_NAME     "jpeghwdec"
#define MODULE_NAME     DRIVER_NAME
#define DEVICE_NAME     DRIVER_NAME
#define DEBUG_LOGFILE 	"/storage/jpeghwdec.log"


#define MEM_INPUT_MAX_SIZE      (4  * 1024 * 1024)	// Maximum JPEG input data size
#define MEM_OUTPUT_MAX_SIZE     (4  * 3840 * 2160)	// Maximum decoded output size (4k)
#define MEM_TOTAL_ALLOC		(40 * 1024 * 1024)

// types definition
typedef struct
{
  unsigned long mem_address;
  char *ptr;
  int width;
  int height;
} image_info_s;

typedef struct
{
  struct page *mem_pages;
  unsigned long start;
  unsigned long size;
  image_info_s input;
  image_info_s output;
} reserved_mem_s;

typedef struct
{
  struct class *device_class;
  struct device *device;
  int version_major;

} device_info_s;

// Variables
static device_info_s device_info;
static reserved_mem_s reserved_mem;

//////////////////////////////////////////////////
// Log functions
//////////////////////////////////////////////////
static struct file* logfile = NULL;	// Current logfile pointer
static loff_t log_pos = 0;		// Current logfile position


// this function writes in a user file
void debug_log(char *prefix, char *format, ...)
{
  char logstr[300];
  char fullstr[512];
  va_list args;
  mm_segment_t old_fs;

  if (!logfile)
  {
    logfile = filp_open(DEBUG_LOGFILE, O_RDWR | O_CREAT, 0644);
    if (!logfile) return;
  }

  va_start(args, format);
  vsprintf(logstr, format, args);
  sprintf(fullstr,"%s : %s", prefix, logstr);
  va_end (args);

  old_fs = get_fs();
  set_fs(KERNEL_DS);
  vfs_write(logfile, fullstr, strlen(fullstr), &log_pos);
  set_fs(old_fs);
}

// this function writes in the kernel log
void system_log(int logtype, char *prefix, char *format, ...)
{
  char logstr[300];
  char fullstr[512];
  va_list args;

  va_start(args, format);
  vsprintf(logstr, format, args);
  sprintf(fullstr,"%s : %s", prefix, logstr);
  va_end (args);

  if (logtype==0)
    pr_alert("%s", fullstr);
  else
    pr_err("%s", fullstr);
}

//#define JPEGHWDECODER_DEBUG
#ifdef JPEGHWDECODER_DEBUG
#define log_info(fmt, arg...)  	debug_log("info", fmt, ## arg)
#define log_error(fmt, arg...) 	debug_log("error", fmt, ## arg)
#else
#define log_info(fmt, arg...) 	pr_alert(DRIVER_NAME ": " fmt "\n", ## arg)
#define log_error(fmt, arg...)  pr_err(DRIVER_NAME ": " fmt "\n", ## arg)
#endif

//////////////////////////////////////////////////
// File operations functions
//////////////////////////////////////////////////
static int jpeghwdec_mmap(struct file *filp, struct vm_area_struct *vma)
{
  int ret = 0;
  log_info("mmap called, start =%lx", vma->vm_start);
  return ret;
}

static long jpeghwdec_ioctl(struct file *file, unsigned int cmd, ulong arg)
{
  int ret = 0;
  return ret;
}

static int jpeghwdec_open(struct inode *inode, struct file *file)
{
  int ret = 0;
  log_info("device openned");
  return ret;
}

static int jpeghwdec_release(struct inode *inode, struct file *file)
{
  int ret = 0;
  log_info("device released");
  return ret;
}

static ssize_t jpeghwdec_read(struct file *filp,
   char *buffer,    /* The buffer to fill with data */
   size_t length,   /* The length of the buffer     */
   loff_t *offset)  /* Our offset in the file       */
{
  return length;
}

static ssize_t jpeghwdec_write(struct file *filp,
   const char *buff,
   size_t len,
   loff_t *off)
{
   int bytes = copy_from_user(reserved_mem.input.ptr, buff, len);
   log_info("wrote %ld bytes to input memory at 0x%lx", bytes, (unsigned long)reserved_mem.input.ptr);

   return len - bytes;
}

static const struct file_operations jpeghwdec_fops =
{
  .owner = THIS_MODULE,
  .open = jpeghwdec_open,
  .mmap = jpeghwdec_mmap,
  .read = jpeghwdec_read,
  .write = jpeghwdec_write,
  .release = jpeghwdec_release,
  .unlocked_ioctl = jpeghwdec_ioctl,
};

//////////////////////////////////////////////////
// Probe and remove functions
//////////////////////////////////////////////////
static int jpeghwdec_probe(struct platform_device *pdev)
{
  int ret;
  // reset out static structures
  memset(&reserved_mem, 0, sizeof(reserved_mem));
  memset(&device_info, 0, sizeof(device_info));

  // gets the work memory area
//  ret = of_reserved_mem_device_init(&pdev->dev);
//  if (ret != 0)
//  {
//     log_error("failed to retrieve reserved memory.");
//     return -EFAULT;
//  }
//  log_info("reserved memory retrieved successfully.");

  reserved_mem.input.ptr = kmalloc(MEM_TOTAL_ALLOC, GFP_DMA | GFP_KERNEL);


  log_info("allocated memory pool @0x%lx (0x%x bytes)", reserved_mem.start, MEM_TOTAL_ALLOC);
  log_info("- input buffer is at 0x%lx", reserved_mem.input.mem_address);
  log_info("- output buffer is at 0x%lx", reserved_mem.output.mem_address);
  log_info("- input buffer mapped to 0x%lx", (long unsigned )reserved_mem.input.ptr);
  log_info("- output buffer mapped to 0x%lx", (long unsigned)reserved_mem.output.ptr);

  device_info.version_major = register_chrdev(0, DEVICE_NAME, &jpeghwdec_fops);
  if (device_info.version_major < 0)
  {
     log_error("can't register major for device");
     return ret;
  }

  device_info.device_class = class_create(THIS_MODULE, DEVICE_NAME);
  if (!device_info.device_class)
  {
    log_error("failed to create class");
    return -EFAULT;
  }

  device_info.device = device_create(device_info.device_class, NULL,
                                        MKDEV(device_info.version_major, VERSION_MINOR),
                                        NULL, DEVICE_NAME);
  if (!device_info.device)
  {
    log_error("failed to create device %s", DEVICE_NAME);
    return -EFAULT;
  }

  log_info("driver probed successfully");
  return 0;
}

static int jpeghwdec_remove(struct platform_device *pdev)
{
  device_destroy(device_info.device_class, MKDEV(device_info.version_major, VERSION_MINOR));

  class_destroy(device_info.device_class);

  unregister_chrdev(device_info.version_major, DEVICE_NAME);

  return 0;
}
//////////////////////////////////////////////////
// Reserved memory operations
//////////////////////////////////////////////////
static int jpegwdec_mem_device_init(struct reserved_mem *rmem, struct device *dev)
{
	reserved_mem.start = rmem->base;
	reserved_mem.input.mem_address = reserved_mem.start;
	reserved_mem.output.mem_address = reserved_mem.start + MEM_INPUT_MAX_SIZE;
	reserved_mem.input.ptr = (char*)phys_to_virt(reserved_mem.input.mem_address);
	reserved_mem.output.ptr =(char*)phys_to_virt(reserved_mem.output.mem_address);

	return 0;
}

static const struct reserved_mem_ops rmem_jpegwdec_ops = {
	.device_init = jpegwdec_mem_device_init,
};

static int __init jpeghwdec_mem_setup(struct reserved_mem *rmem)
{
	rmem->ops = &rmem_jpegwdec_ops;
	return 0;
}

//////////////////////////////////////////////////
// Module Init / Exit functions
//////////////////////////////////////////////////
static const struct of_device_id jpeghwdec_dt_match[] =
{
  {
    .compatible = "amlogic, jpeghwdec",
  },
  {},
};

static struct platform_driver jpeghwdec_driver =
{
  .probe = jpeghwdec_probe,
  .remove = jpeghwdec_remove,
  .driver =
  {
    .name = DRIVER_NAME,
    .owner = THIS_MODULE,
    .of_match_table = jpeghwdec_dt_match,
  }
};

static int __init jpeghwdec_init(void)
{
  log_info("driver initialization starts.");
  if (platform_driver_register(&jpeghwdec_driver))
  {
    log_error("failed to register jpeghwdec module");
    return -ENODEV;
  }

  log_info("driver inited successfully.");
  return 0;
}

static void __exit jpeghwdec_exit(void)
{
  platform_driver_unregister(&jpeghwdec_driver);
  log_info("driver exited.");
  return;
}

module_init(jpeghwdec_init);
module_exit(jpeghwdec_exit);

//////////////////////////////////////////////////
// Module declaration
//////////////////////////////////////////////////

RESERVEDMEM_OF_DECLARE(jpeghwdec, "amlogic, jpeghwdec-mem", jpeghwdec_mem_setup);
MODULE_DESCRIPTION("HW JPEG decoder driver");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Lionel CHAZALLON <LongChair@hotmail.com>");
