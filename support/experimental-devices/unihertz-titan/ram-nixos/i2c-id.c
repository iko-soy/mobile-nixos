// SPDX-License-Identifier: MIT
/*
 * titan-i2c-id: read identification registers of the two devices that
 * answered on the Titan's I2C bus at 0x11011000 (adapter i2c-1;
 * native-i2c-scan-trial.adoc). Each read is one combined transfer that
 * writes only the register's address and then reads; the table below is
 * everything the tool can do. It refuses unless i2c-1 is that controller.
 * Every read buffer starts filled with SENTINEL, so a read whose data never
 * reached memory prints SENTINEL rather than zeros (native-i2c-id-trial.adoc).
 */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/i2c.h>
#include <linux/i2c-dev.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#define SENTINEL 0xa5

struct id_read {
	unsigned short address;
	unsigned char reg;
	unsigned short length;
	const char *what;
};

static const struct id_read reads[] = {
	{ 0x2c, 0x00, 1, "chip ID of QST's QMC6308 family, 80; axis data on QMC6983 and QMC7983" },
	{ 0x2c, 0x0d, 1, "chip ID of QST's QMC6983, ff, and QMC7983, 31" },
	{ 0x60, 0x0c, 2, "ID word, low byte first, of CM36686 and VCNL4040, low byte 86; white data on VCNL4035" },
	{ 0x60, 0x0e, 2, "ID word, low byte first, of VCNL4035, low byte 80" },
};

int main(void)
{
	static const char adapter[] = "/sys/bus/i2c/devices/i2c-1";
	static const char suffix[] = "/11011000.i2c/i2c-1";
	char path[PATH_MAX];
	unsigned long funcs;
	struct stat st;
	size_t i, length;
	int fd, failed = 0;

	setvbuf(stdout, NULL, _IOLBF, 0);
	if (!realpath(adapter, path) || (length = strlen(path)) < sizeof(suffix) - 1 ||
	    strcmp(path + length - (sizeof(suffix) - 1), suffix) != 0) {
		fprintf(stderr, "titan-i2c-id: i2c-1 is not the controller at 11011000\n");
		return 2;
	}
	fd = open("/dev/i2c-1", O_RDWR);
	if (fd < 0) {
		perror("titan-i2c-id: /dev/i2c-1");
		return 2;
	}
	if (fstat(fd, &st) < 0 || !S_ISCHR(st.st_mode) || major(st.st_rdev) != 89 || minor(st.st_rdev) != 1) {
		fprintf(stderr, "titan-i2c-id: /dev/i2c-1 is not the I2C device 89:1\n");
		close(fd);
		return 2;
	}
	if (ioctl(fd, I2C_FUNCS, &funcs) < 0) {
		fprintf(stderr, "titan-i2c-id: I2C_FUNCS: %s\n", strerror(errno));
		close(fd);
		return 2;
	}
	if (!(funcs & I2C_FUNC_I2C)) {
		fprintf(stderr, "titan-i2c-id: the adapter cannot do combined transfers\n");
		close(fd);
		return 2;
	}
	printf("each read buffer starts as %02x\n", SENTINEL);
	for (i = 0; i < sizeof(reads) / sizeof(reads[0]); i++) {
		unsigned char reg = reads[i].reg, data[2] = { SENTINEL, SENTINEL };
		struct i2c_msg messages[2] = {
			{ .addr = reads[i].address, .flags = 0, .len = 1, .buf = &reg },
			{ .addr = reads[i].address, .flags = I2C_M_RD, .len = reads[i].length, .buf = data },
		};
		struct i2c_rdwr_ioctl_data transfer = { .msgs = messages, .nmsgs = 2 };
		unsigned short j;
		int ret;

		if (reads[i].length > sizeof(data)) {
			fprintf(stderr, "titan-i2c-id: read longer than its buffer\n");
			close(fd);
			return 2;
		}
		printf("0x%02x register 0x%02x: ", reads[i].address, reads[i].reg);
		/* Keep the record of which read was under way if it hangs. */
		fflush(stdout);
		ret = ioctl(fd, I2C_RDWR, &transfer);
		if (ret != 2) {
			int error = ret < 0 ? errno : 0;

			printf("failed: returned %d, %s\n", ret, error ? strerror(error) : "short transfer");
			failed = 1;
			/* A missing answer leaves the bus idle; anything else may not. */
			if (error == ENXIO)
				continue;
			break;
		}
		for (j = 0; j < reads[i].length; j++)
			printf("%02x ", data[j]);
		printf("(%s)\n", reads[i].what);
	}
	close(fd);
	return failed;
}
