// StellarStellaris - main.c
/*
 * Much code yoinked from:
 * https://0x00sec.org/t/linux-infecting-running-processes/1097
 * https://man7.org/linux/man-pages/man2/process_vm_readv.2.html
 * https://github.com/eklitzke/ptrace-call-userspace
 * https://nullprogram.com/blog/2016/09/03/
 * https://ancat.github.io/python/2019/01/01/python-ptrace.html
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <asm/ldt.h>

#include <sys/user.h>
#include <sys/reg.h>

#include <sys/uio.h>

#include "pdlsym.h"



int main (int argc, char *argv[]){
	pid_t target;
	struct user_regs_struct regs;
	int syscall;
	long dst;
	unsigned long addr;
	unsigned char buf[1];

	if (argc != 2){
		fprintf(stderr, "Usage:\n\t%s pid\n", argv[0]);
		exit(1);
	}

	target = atoi(argv[1]);
	printf ("+ Attempting to attach to process %d\n", target);
	if ((ptrace (PTRACE_ATTACH, target, NULL, NULL)) < 0){
		fprintf(stderr, "+ Failed to attach to process\n");
		perror("ptrace(ATTACH):");
		exit(1);
	}

	printf ("+ Waiting for process...\n");
	wait (NULL);


	printf("+ Getting process registers\n");
	if ((ptrace (PTRACE_GETREGS, target, NULL, &regs)) < 0){
		perror ("ptrace(GETREGS):");
		exit (1);
	}
					        
	printf("+ DEBUG: Current RIP: 0x%llx \n", regs.rip );

	char file[64];
	sprintf(file, "/proc/%ld/mem", (long)target);
	int fd = open(file, O_RDWR);

	/* Game version magic string */
	addr = 0x0000000002332FBF; 
	unsigned char version_buf[14];
	unsigned char expected_version[] = "Butler v2.8.1";
	pread(fd, &version_buf, sizeof(version_buf), addr);
	if(strcmp(&expected_version, &version_buf) != 0){
		fprintf(stderr, "\nFATAL ERROR: Invalid version string, aborting!\n");
		exit(1);
	}

	printf("+ DEBUG: Version string: %s \n", version_buf);


	/* Patch out ParticleUpdate */
	addr = 0x0000000001e71b90; //_ZN18CPdxParticleObject13RenderBucketsEP9CGraphicsPK7CCamerai
	pread(fd, &buf, sizeof(buf), addr);
	printf("+ DEBUG: CPdxParticleObject::RenderBuckets addr: 0x%02hhx\n", *buf);

	//buf[0] = 0xc3; 
	buf[0] = 0x55;
	pwrite(fd, &buf, sizeof(buf), addr);


	addr = 0x00000000021229a0; //ParticleUpdate
	pread(fd, &buf, sizeof(buf), addr);
	printf("+ DEBUG: ParticleUpdate addr: 0x%02hhx\n", *buf);


	//buf[0] = 0xc3;
	buf[0] = 0x55;
	pwrite(fd, &buf, sizeof(buf), addr);



	/* CGuiObject::KillObject bug */

	addr = 0x00000000021db6f0; //CGui::PerFrameUpdate
	pread(fd, &buf, sizeof(buf), addr);
	printf("+ DEBUG: CGui::PerFrameUpdate addr: 0x%02hhx\n", *buf);

	//buf[0] = 0xc3;
        buf[0] = 0x41;
	pwrite(fd, &buf, sizeof(buf), addr);
	
	addr = 0x00000000021dab10; //CGui::HandelInput
	pread(fd, &buf, sizeof(buf), addr);
	printf("+ DEBUG: CGui::HandelInput addr: 0x%02hhx\n", *buf);

	//buf[0] = 0xc3;
	buf[0] = 0x55;
	pwrite(fd, &buf, sizeof(buf), addr);



	/* COutliner Related improvements */

	addr = 0x00000000018bc900; //COutliner::InternalUpdate
	pread(fd, &buf, sizeof(buf), addr);
	printf("+ DEBUG: COutliner::InternalUpdate addr: 0x%02hhx\n", *buf);

	//buf[0] = 0xc3;
	buf[0] = 0x55;
	pwrite(fd, &buf, sizeof(buf), addr);

	

	close(fd);

	ptrace(PTRACE_DETACH, target, NULL, NULL);
	return 0;
}
