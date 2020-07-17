/*
 * hexudmp.c
 *
 * hexdumpmem is hexdump-like tool to dump memory and write memory. When 
 * developing a system on a SoC, I usually need to dump or write 
 * memory-map registers of the SoC for debugging. I write this program
 * to do it on my developing Android phone. 
 *
 * Copyright (C) 2013 Chih-Chyuan Hwang
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/errno.h>
#include <string.h>

#define DEFAULT_DUMP_LEN 368
#define DEFAULT_DUMP_SZ 4
#define DEV_MEM "/dev/mem"
#define DUMP_BYTE_PER_LINE 16

#define ROUND_DOWN(__value, __align) ((__value) & ~((__align) - 1))
#define ROUND_UP(__value, __align) (((__value) + (__align) - 1) & ~((__align) - 1))
#define LOGV(f, args...) fprintf(stdout, f, ## args)
#define LOGD(f, args...) do { if (debug) fprintf(stderr, f, ## args); } while (0)
#define LOGE(f, args...) fprintf(stderr, "Error: " f, ## args)
#define OUTPUT(f, args...) fprintf(stdout, f, ## args)

static int debug;

static const struct option options[] =
{
	{ "address", 1, 0, 'a' },
	{ "size", 1, 0, 's' },
	{ "len", 1, 0, 'l' },
	{ "write", 1, 0, 'w' },
	{ "debug", 0, 0, 'd' },
	{ "help", 0, 0, 'h' },
	{ NULL, 0, 0, 0 },
};

static const char *optstr = "a:s:l:w:dh";

static void usage(void)
{
	LOGV("Usage: hexdumpmem [options] -a|--address <memory address (hex) to dump>\n");
	LOGV("   or: hexdumpmem -w <fill pattern (hex)> [options] -a|--address <memory address (hex) to fill>\n");
	LOGV("Options:\n");
	LOGV("  -s, --size <size>         Select the size of dump/fill unit\n");
	LOGV("  -l, --len <length (hex)>  Select the length of the dump/fill region\n");
	LOGV("  -d, --debug               Enable the debug log\n");
	LOGV("  -h, --help                Show help message and exit\n");
}

static unsigned char readb(const void *addr)
{
	return *(volatile unsigned char *)addr;
}

static void writeb(unsigned char val, void *addr)
{
	*(volatile unsigned char *)addr = val;
}

static unsigned short readw(const void *addr)
{
	return *(volatile unsigned short *)addr;
}

static void writew(unsigned short val, void *addr)
{
	*(volatile unsigned short *)addr = val;
}

static unsigned int readl(const void *addr)
{
	return *(volatile unsigned int *)addr;
}

static void writel(unsigned int val, void *addr)
{
	*(volatile unsigned int *)addr = val;
}

static int memdump(const void *map, unsigned int addr, 
			unsigned int len, unsigned int size)
{
	unsigned char *ptr = (unsigned char *)map;
	unsigned int start, end, line, byte;

	if (!map) {
		LOGE("Invalid map pointer\n");
		return -1;
	}
	if (!len) {
		LOGE("Invalid length\n");
		return -1;
	}
	if (size != 1 && size != 2 && size != 4) {
		LOGE("Invalid size\n");
		return -1;
	}

	start = ROUND_DOWN(addr, DUMP_BYTE_PER_LINE);
	end = ROUND_UP(addr + len, DUMP_BYTE_PER_LINE);
	LOGD("Dump memory 0x%08X ~ 0x%08X\n", start, end);

	LOGD("Before adjust, ptr = %p\n", ptr);
	ptr += start - ROUND_DOWN(addr, getpagesize());
	LOGD("After adjust, ptr = %p\n", ptr);

	switch (size) {
	case 1:
		OUTPUT("%-8s   %2X %2X %2X %2X %2X %2X %2X %2X ",
			"addr", 0, 1, 2, 3, 4, 5, 6, 7);
		OUTPUT("%2X %2X %2X %2X %2X %2X %2X %2X\n", 
			8, 9, 10, 11, 12, 13, 14, 15);
		OUTPUT("==============================");
		OUTPUT("============================\n");
		break;

	case 2:
		OUTPUT("%-8s   %4X %4X %4X %4X %4X %4X %4X %4X\n",
			"addr", 0, 2, 4, 6, 8, 10, 12, 14);
		OUTPUT("==============================");
		OUTPUT("====================\n");
		break;

	case 4:
		OUTPUT("%-8s   %8X %8X %8X %8X\n", "addr", 0, 4, 8, 12);
		OUTPUT("==============================================\n");
		break;

	default:
		break;
	}

	for (line = 0; line < (end - start); line += DUMP_BYTE_PER_LINE) {
		OUTPUT("%08Xh: ", start + line);
		for (byte = 0; byte < DUMP_BYTE_PER_LINE; byte += size) {
			switch (size) {
			case 1:
				OUTPUT("%02X ", readb(ptr + line + byte));
				break;

			case 2:
				OUTPUT("%04X ", readw(ptr + line + byte));
				break;

			case 4:
				OUTPUT("%08X ", readl(ptr + line + byte));
				break;
			default:
				break;
			}
		}
		OUTPUT("\n");
	}

	return 0;
}

static int memfill(void *map, unsigned int addr, unsigned int len, 
			unsigned int size, unsigned int val)
{
	unsigned char *ptr = (unsigned char *)map;
	unsigned int byte;

	if (!map) {
		LOGE("Invalid map pointer\n");
		return -1;
	}
	if (!len) {
		LOGE("Invalid length\n");
		return -1;
	}
	if (size != 1 && size != 2 && size != 4) {
		LOGE("Invalid size\n");
		return -1;
	}
	if (addr & (size - 1)) {
		LOGE("address and size are not aligned\n");
		return -1;
	}

	LOGD("Before adjust, map = %p\n", map);
	ptr += addr - ROUND_DOWN(addr, getpagesize());
	LOGD("After adjust, map = %p\n", map);

	for (byte = 0; byte < len; byte += size) {
		switch (size) {
		case 1:
			LOGD("Write 0x%02X to *(%p)\n", 
				(unsigned char)val, ptr + byte);
			writeb(val, ptr + byte);
			break;

		case 2:
			LOGD("Write 0x%02X to *(%p)\n", 
				(unsigned short)val, ptr + byte);
			writew(val, ptr + byte);
			break;

		case 4:
			LOGD("Write 0x%02X to *(%p)\n", 
				(unsigned int)val, ptr + byte);
			writel(val, ptr + byte);
			break;

		default:
			break;
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	int loptidx, c, fd, err = 0;
	unsigned int addr = 0xffffffff;
	unsigned int len = DEFAULT_DUMP_LEN, size = DEFAULT_DUMP_SZ;
	unsigned int wr = 0, val;
	void *map;

	for (;;) {
		c = getopt_long(argc, argv, optstr, options, &loptidx);
		if (c == -1)
			break;

		switch (c) {
		case 'a':
			addr = strtoul(optarg, NULL, 16);
			break;

		case 's':
			size = atoi(optarg);
			break;

		case 'l':
			len = strtoul(optarg, NULL, 16);
			break;

		case 'w':
			wr = 1;
			val = strtoul(optarg, NULL, 16);
			break;

		case 'd':
			debug = 1;
			break;

		case 'h':
			usage();
			return 0;

		default:
			LOGE("Unknown argument: %c\n", c);
			break;
		}
	}

	if (argc != optind || addr == 0xffffffff) {
		LOGE("Invalid arguments or missing input address\n");
		usage();
		return -1;
	}
	LOGV("Memory region 0x%08x ~ 0x%08x\n", addr, addr + len - 1);
	LOGD("addr = 0x%08x, len = 0x%08x, size = %d\n", addr, len, size);
	LOGD("wr = %d, val = 0x%08x\n", wr, val);

	fd = open(DEV_MEM, O_RDWR | O_SYNC);
	if (fd == -1) {
		LOGE("Fail to open %s (%s)\n", DEV_MEM, strerror(errno));
		return -1;
	}

	LOGD("mmap 0x%08x ~ 0x%08x\n",
		ROUND_DOWN(addr, getpagesize()),
		ROUND_DOWN(addr, getpagesize()) + ROUND_UP(len, getpagesize()));
	map = mmap(NULL, ROUND_UP(len, getpagesize()), PROT_READ | PROT_WRITE, 
			MAP_SHARED, fd, ROUND_DOWN(addr, getpagesize()));
	if (map == MAP_FAILED) {
		LOGE("mmap failed (%s)\n", strerror(errno));
		err = -1;
		goto exit;
	}
	close(fd);

	if (!wr) {
		err = memdump(map, addr, len, size);
	} else {
		err = memfill(map, addr, len, size, val);
	}

	munmap(map, ROUND_UP(len, getpagesize()));

exit:
	return err;
}
