#include <iostream>
using namespace std;

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

/* Minimal definition of disklabel, so we don't have to include
 * asm/disklabel.h (confuses make)
 */
#ifndef MAXPARTITIONS
#define MAXPARTITIONS   8                       /* max. # of partitions */
#endif

#ifndef u8
#define u8 unsigned char
#endif

#ifndef u16
#define u16 unsigned short
#endif

#ifndef u32
#define u32 unsigned int
#endif

struct disklabel {
    u32	d_magic;				/* must be DISKLABELMAGIC */
    u16	d_type, d_subtype;
    u8	d_typename[16];
    u8	d_packname[16];
    u32	d_secsize;
    u32	d_nsectors;
    u32	d_ntracks;
    u32	d_ncylinders;
    u32	d_secpercyl;
    u32	d_secprtunit;
    u16	d_sparespertrack;
    u16	d_sparespercyl;
    u32	d_acylinders;
    u16	d_rpm, d_interleave, d_trackskew, d_cylskew;
    u32	d_headswitch, d_trkseek, d_flags;
    u32	d_drivedata[5];
    u32	d_spare[5];
    u32	d_magic2;				/* must be DISKLABELMAGIC */
    u16	d_checksum;
    u16	d_npartitions;
    u32	d_bbsize, d_sbsize;
    struct d_partition {
	u32	p_size;
	u32	p_offset;
	u32	p_fsize;
	u8	p_fstype;
	u8	p_frag;
	u16	p_cpg;
    } d_partitions[MAXPARTITIONS];
};


typedef union __bootblock {
    struct {
        char			__pad1[64];
        struct disklabel	__label;
    } __u1;
    struct {
	unsigned long		__pad2[63];
	unsigned long		__checksum;
    } __u2;
    char		bootblock_bytes[512];
    unsigned long	bootblock_quadwords[64];
} bootblock;

#define	bootblock_label		__u1.__label
#define bootblock_checksum	__u2.__checksum

int main(int argc, char ** argv)
{
    bootblock		bootblock_from_disk;
    bootblock		bootloader_image;
    int			dev, fd;
    int			i;
    int			nread;

    /* Make sure of the arg count */
    if(argc != 3) {
	fprintf(stderr, "Usage: %s device lxboot\n", argv[0]);
	exit(0);
    }

    /* First, open the device and make sure it's accessible */
    dev = open(argv[1], O_RDWR);
    if(dev < 0) {
	perror(argv[1]);
	exit(0);
    }

    /* Now open the lxboot and make sure it's reasonable */
    fd = open(argv[2], O_RDONLY);
    if(fd < 0) {
	perror(argv[2]);
	close(dev);
	exit(0);
    }

    /* Read in the lxboot */
    nread = read(fd, &bootloader_image, sizeof(bootblock));
    if(nread != sizeof(bootblock)) {
	perror("lxboot read");
	fprintf(stderr, "expected %zd, got %d\n", sizeof(bootblock), nread);
	exit(0);
    }

    /* Read in the bootblock from disk. */
    nread = read(dev, &bootblock_from_disk, sizeof(bootblock));
    if(nread != sizeof(bootblock)) {
	perror("bootblock read");
	fprintf(stderr, "expected %zd, got %d\n", sizeof(bootblock), nread);
	exit(0);
    }

    /* Swap the bootblock's disklabel into the bootloader */
    bootloader_image.bootblock_label = bootblock_from_disk.bootblock_label;

    /* Calculate the bootblock checksum */
    bootloader_image.bootblock_checksum = 0;
    for(i = 0; i < 63; i++) {
	bootloader_image.bootblock_checksum += 
			bootloader_image.bootblock_quadwords[i];
    }

    /* Write the whole thing out! */
    lseek(dev, 0L, SEEK_SET);
    if(write(dev, &bootloader_image, sizeof(bootblock)) != sizeof(bootblock)) {
	perror("bootblock write");
	exit(0);
    }

    close(fd);
    close(dev);
    exit(0);
}

# define elf_phdr elf64_phdr
# define elf_check_arch(x) ((x)->e_machine == EM_ALPHA)
#endif

/* bootfile size must be multiple of BLOCK_SIZE: */
#define BLOCK_SIZE	512

const char * prog_name;


static void
usage (void)
{
    fprintf(stderr,
	    "usage: %s [-v] -p file primary\n"
	    "       %s [-vb] file [secondary]\n", prog_name, prog_name);
    exit(1);
}


int
main (int argc, char *argv[])
{
    size_t nwritten, tocopy, n, mem_size, fil_size, pad = 0;
    int fd, ofd, i, j, verbose = 0, primary = 0;
    char buf[8192], *inname;
    struct exec * aout;		/* includes file & aout header */
    long offset;
#ifdef __ELF__
    struct elfhdr *elf;
    struct elf_phdr *elf_phdr;	/* program header */
    unsigned long long e_entry;
#endif

    prog_name = argv[0];

    for (i = 1; i < argc && argv[i][0] == '-'; ++i) {
	for (j = 1; argv[i][j]; ++j) {
	    switch (argv[i][j]) {
	      case 'v':
		  verbose = ~verbose;
		  break;

	      case 'b':
		  pad = BLOCK_SIZE;
		  break;

	      case 'p':
		  primary = 1;		/* make primary bootblock */
		  break;
	    }
	}
    }

    if (i >= argc) {
	usage();
    }
    inname = argv[i++];

    fd = open(inname, O_RDONLY);
    if (fd == -1) {
	perror("open");
	exit(1);
    }

    ofd = 1;
    if (i < argc) {
	ofd = open(argv[i++], O_WRONLY | O_CREAT | O_TRUNC, 0666);
	if (ofd == -1) {
	    perror("open");
	    exit(1);
	}
    }

    if (primary) {
	/* generate bootblock for primary loader */

	unsigned long bb[64], sum = 0;
	struct stat st;
	off_t size;
	int i;

	if (ofd == 1) {
	    usage();
	}

	if (fstat(fd, &st) == -1) {
	    perror("fstat");
	    exit(1);
	}

	size = (st.st_size + BLOCK_SIZE - 1) & ~(BLOCK_SIZE - 1);
	memset(bb, 0, sizeof(bb));
	strcpy((char *) bb, "Linux SRM bootblock");
	bb[60] = size / BLOCK_SIZE;	/* count */
	bb[61] = 1;			/* starting sector # */
	bb[62] = 0;			/* flags---must be 0 */
	for (i = 0; i < 63; ++i) {
	    sum += bb[i];
	}
	bb[63] = sum;
	if (write(ofd, bb, sizeof(bb)) != sizeof(bb)) {
	    perror("boot-block write");
	    exit(1);
	}
	printf("%lu\n", size);
	return 0;
    }

    /* read and inspect exec header: */

    if (read(fd, buf, sizeof(buf)) < 0) {
	perror("read");
	exit(1);
    }

#ifdef __ELF__
    elf = (struct elfhdr *) buf;

    if (elf->e_ident[0] == 0x7f && strncmp((char *)elf->e_ident + 1, "ELF", 3) == 0) {
	if (elf->e_type != ET_EXEC) {
	    fprintf(stderr, "%s: %s is not an ELF executable\n",
		    prog_name, inname);
	    exit(1);
	}
	if (!elf_check_arch(elf)) {
	    fprintf(stderr, "%s: is not for this processor (e_machine=%d)\n",
		    prog_name, elf->e_machine);
	    exit(1);
	}
	if (elf->e_phnum != 1) {
	    fprintf(stderr,
		    "%s: %d program headers (forgot to link with -N?)\n",
		    prog_name, elf->e_phnum);
	}

	e_entry = elf->e_entry;

	lseek(fd, elf->e_phoff, SEEK_SET);
	if (read(fd, buf, sizeof(*elf_phdr)) != sizeof(*elf_phdr)) {
	    perror("read");
	    exit(1);
	}

	elf_phdr = (struct elf_phdr *) buf;
	offset	 = elf_phdr->p_offset;
	mem_size = elf_phdr->p_memsz;
	fil_size = elf_phdr->p_filesz;

	/* work around ELF bug: */
	if (elf_phdr->p_vaddr < e_entry) {
	    unsigned long delta = e_entry - elf_phdr->p_vaddr;
	    offset   += delta;
	    mem_size -= delta;
	    fil_size -= delta;
	    elf_phdr->p_vaddr += delta;
	}

	if (verbose) {
	    fprintf(stderr, "%s: extracting %#016lx-%#016lx (at %lx)\n",
		    prog_name, (long) elf_phdr->p_vaddr,
		    elf_phdr->p_vaddr + fil_size, offset);
	}
    } else
#endif
    {
	aout = (struct exec *) buf;

	if (!(aout->fh.f_flags & COFF_F_EXEC)) {
	    fprintf(stderr, "%s: %s is not in executable format\n",
		    prog_name, inname);
	    exit(1);
	}

	if (aout->fh.f_opthdr != sizeof(aout->ah)) {
	    fprintf(stderr, "%s: %s has unexpected optional header size\n",
		    prog_name, inname);
	    exit(1);
	}

	if (N_MAGIC(*aout) != OMAGIC) {
	    fprintf(stderr, "%s: %s is not an OMAGIC file\n",
		    prog_name, inname);
	    exit(1);
	}
	offset = N_TXTOFF(*aout);
	fil_size = aout->ah.tsize + aout->ah.dsize;
	mem_size = fil_size + aout->ah.bsize;

	if (verbose) {
	    fprintf(stderr, "%s: extracting %#016lx-%#016lx (at %lx)\n",
		    prog_name, aout->ah.text_start,
		    aout->ah.text_start + fil_size, offset);
	}
    }

    if (lseek(fd, offset, SEEK_SET) != offset) {
	perror("lseek");
	exit(1);
    }

    if (verbose) {
	fprintf(stderr, "%s: copying %lu byte from %s\n",
		prog_name, (unsigned long) fil_size, inname);
    }

    tocopy = fil_size;
    while (tocopy > 0) {
	n = tocopy;
	if (n > sizeof(buf)) {
	    n = sizeof(buf);
	}
	tocopy -= n;
	if ((size_t) read(fd, buf, n) != n) {
	    perror("read");
	    exit(1);
	}
	do {
	    nwritten = write(ofd, buf, n);
	    if ((ssize_t) nwritten == -1) {
		perror("write");
		exit(1);
	    }
	    n -= nwritten;
	} while (n > 0);
    }

    if (pad) {
	mem_size = ((mem_size + pad - 1) / pad) * pad;
    }

    tocopy = mem_size - fil_size;
    if (tocopy > 0) {
	fprintf(stderr,
		"%s: zero-filling bss and aligning to %lu with %lu bytes\n",
		prog_name, pad, (unsigned long) tocopy);

	memset(buf, 0x00, sizeof(buf));
	do {
	    n = tocopy;
	    if (n > sizeof(buf)) {
		n = sizeof(buf);
	    }
	    nwritten = write(ofd, buf, n);
	    if ((ssize_t) nwritten == -1) {
		perror("write");
		exit(1);
	    }
	    tocopy -= nwritten;
	} while (tocopy > 0);
    }
    return 0;
}
 extern unsigned long switch_to_osf_pal(unsigned long nr,
	struct pcb_struct * pcb_va, struct pcb_struct * pcb_pa,
	unsigned long *vptb);
struct hwrpb_struct *hwrpb = INIT_HWRPB;
static struct pcb_struct pcb_va[1];

/*
 * Find a physical address of a virtual object..
 *
 * This is easy using the virtual page table address.
 */

static inline void *
find_pa(unsigned long *vptb, void *ptr)
{
	unsigned long address = (unsigned long) ptr;
	unsigned long result;

	result = vptb[address >> 13];
	result >>= 32;
	result <<= 13;
	result |= address & 0x1fff;
	return (void *) result;
}	

/*
 * This function moves into OSF/1 pal-code, and has a temporary
 * PCB for that. The kernel proper should replace this PCB with
 * the real one as soon as possible.
 *
 * The page table muckery in here depends on the fact that the boot
 * code has the L1 page table identity-map itself in the second PTE
 * in the L1 page table. Thus the L1-page is virtually addressable
 * itself (through three levels) at virtual address 0x200802000.
 */

#define VPTB	((unsigned long *) 0x200000000)
#define L1	((unsigned long *) 0x200802000)

void
pal_init(void)
{
	unsigned long i, rev;
	struct percpu_struct * percpu;
	struct pcb_struct * pcb_pa;

	/* Create the dummy PCB.  */
	pcb_va->ksp = 0;
	pcb_va->usp = 0;
	pcb_va->ptbr = L1[1] >> 32;
	pcb_va->asn = 0;
	pcb_va->pcc = 0;
	pcb_va->unique = 0;
	pcb_va->flags = 1;
	pcb_va->res1 = 0;
	pcb_va->res2 = 0;
	pcb_pa = find_pa(VPTB, pcb_va);

	/*
	 * a0 = 2 (OSF)
	 * a1 = return address, but we give the asm the vaddr of the PCB
	 * a2 = physical addr of PCB
	 * a3 = new virtual page table pointer
	 * a4 = KSP (but the asm sets it)
	 */
	srm_printk("Switching to OSF PAL-code .. ");

	i = switch_to_osf_pal(2, pcb_va, pcb_pa, VPTB);
	if (i) {
		srm_printk("failed, code %ld\n", i);
		__halt();
	}

	percpu = (struct percpu_struct *)
		(INIT_HWRPB->processor_offset + (unsigned long) INIT_HWRPB);
	rev = percpu->pal_revision = percpu->palcode_avail[2];

	srm_printk("Ok (rev %lx)\n", rev);

	tbia(); /* do it directly in case we are SMP */
}

static inline long openboot(void)
{
	char bootdev[256];
	long result;

	result = callback_getenv(ENV_BOOTED_DEV, bootdev, 255);
	if (result < 0)
		return result;
	return callback_open(bootdev, result & 255);
}

static inline long close(long dev)
{
	return callback_close(dev);
}

static inline long load(long dev, unsigned long addr, unsigned long count)
{
	char bootfile[256];
	extern char _end;
	long result, boot_size = &_end - (char *) BOOT_ADDR;

	result = callback_getenv(ENV_BOOTED_FILE, bootfile, 255);
	if (result < 0)
		return result;
	result &= 255;
	bootfile[result] = '\0';
	if (result)
		srm_printk("Boot file specification (%s) not implemented\n",
		       bootfile);
	return callback_read(dev, count, (void *)addr, boot_size/512 + 1);
}

/*
 * Start the kernel.
 */
static void runkernel(void)
{
	__asm__ __volatile__(
		"bis %1,%1,$30\n\t"
		"bis %0,%0,$26\n\t"
		"ret ($26)"
		: /* no outputs: it doesn't even return */
		: "r" (START_ADDR),
		  "r" (PAGE_SIZE + INIT_STACK));
}

void start_kernel(void)
{
	long i;
	long dev;
	int nbytes;
	char envval[256];

	srm_printk("Linux/AXP bootloader for Linux " UTS_RELEASE "\n");
	if (INIT_HWRPB->pagesize != 8192) {
		srm_printk("Expected 8kB pages, got %ldkB\n", INIT_HWRPB->pagesize >> 10);
		return;
	}
	pal_init();
	dev = openboot();
	if (dev < 0) {
		srm_printk("Unable to open boot device: %016lx\n", dev);
		return;
	}
	dev &= 0xffffffff;
	srm_printk("Loading vmlinux ...");
	i = load(dev, START_ADDR, KERNEL_SIZE);
	close(dev);
	if (i != KERNEL_SIZE) {
		srm_printk("Failed (%lx)\n", i);
		return;
	}

	nbytes = callback_getenv(ENV_BOOTED_OSFLAGS, envval, sizeof(envval));
	if (nbytes < 0) {
		nbytes = 0;
	}
	envval[nbytes] = '\0';
	strcpy((char*)ZERO_PGE, envval);

	srm_printk(" Ok\nNow booting the kernel\n");
	runkernel();
	for (i = 0 ; i < 0x100000000 ; i++)
		/* nothing */;
	__halt();
}
