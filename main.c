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
	struct user_regs_struct regs_backup;
	int syscall;
	long dst;
	unsigned long addr;
	unsigned char buf[1];
	unsigned char backup_rip_code[2];
	const unsigned char replacement_rip_code[2] = {0x0f, 0x05};

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

	printf("+ Getting backup process registers\n");
	if ((ptrace (PTRACE_GETREGS, target, NULL, &regs_backup)) < 0){
                perror ("ptrace(GETREGS):");
                exit (1);
        }
					        
	printf("+ DEBUG: Current RIP: 0x%llx \n", regs.rip );

	char file[64];
	sprintf(file, "/proc/%ld/mem", (long)target);
	int fd = open(file, O_RDWR);

	/* Game version magic string */
	//addr = 0x2332FBF; //Butler v2.8.1
	//addr = 0x260a6c6; //Dick v3.0.1
	addr = 0x260a818; //Dick v3.0.2
	//
	//unsigned char version_buf[14];
	//unsigned char expected_version[] = "Butler v2.8.1";
	//unsigned char version_buf[12];
	//unsigned char expected_version[] = "Dick v3.0.1";
	const char  expected_version[] = "Dick v3.0.2";
	char version_buf[sizeof(expected_version)];

	pread(fd, &version_buf, sizeof(version_buf), addr);
	if(strcmp(expected_version, version_buf) != 0){
		fprintf(stderr, "\nFATAL ERROR: Invalid version string, aborting!\n");
		exit(1);
	}

	printf("+ Found Version string: %s \n", version_buf);

	regs.rax = 0x9;	// sys_mmap
	regs.rdi = 0x0;		// offset
	regs.rsi = 100*1000;	// size (100KB)
	regs.rdx = 0x7;		// map permissions
	regs.r10 = 0x22;	// anonymous
	regs.r8 = 0x0;		// fd
	regs.r9 = 0x0;		// fd

	printf("+ Setting registers for mmap, executable space\n");

	if ((ptrace (PTRACE_SETREGS, target, NULL, &regs)) < 0){
		perror ("ptrace(SETREGS):");
		exit(1);
	}

	printf("+ Backing up %lu bytes at RIP: 0x%02llx\n", sizeof(backup_rip_code), regs.rip);
	pread(fd, &backup_rip_code, sizeof(backup_rip_code), regs.rip);
	printf("+ Backed up: 0x");
	for(int i=0; i< sizeof(backup_rip_code); i++){
		printf("%02x", backup_rip_code[i]);
	}
	printf("\n");

	printf("+ Writing syscall to RIP\n");
	pwrite(fd, &replacement_rip_code, sizeof(replacement_rip_code), regs.rip);


	printf("+ Single stepping pid: %d\n", target);

	if ((ptrace (PTRACE_SINGLESTEP, target, NULL, NULL)) < 0){
		perror("ptrace(SINGLESTEP):");
		exit(1);
	}

	printf("+ Waiting for process...\n");
	wait(NULL);

	printf("+ Getting post-mmap process registers\n");
        if ((ptrace (PTRACE_GETREGS, target, NULL, &regs)) < 0){
		perror ("ptrace(GETREGS):");
		exit (1);
	}
	
	unsigned long long rwx_addr = regs.rax;
	unsigned long long this_addr;

	printf("+ RWX hopefully created @%02llx\n", rwx_addr);

	printf("+ Restoring Registers from backup\n");

	if ((ptrace (PTRACE_SETREGS, target, NULL, &regs_backup)) < 0){
		perror ("ptrace(SETREGS):");
		exit(1);
        }

	printf("+ Restoring RIP code from backup\n");
	pwrite(fd, &backup_rip_code, sizeof(backup_rip_code), regs_backup.rip);

/*
	//We are back to normal execution with our own shiny memory allocation for executable code.
	this_addr = rwx_addr+10000;
	const unsigned char CGuiObject_KillObject_asm[] = {
		0xc6, 0x87, 0xb0, 0x00, 0x00, 0x00, 0x01, 	// mov BYTE PTR [rdi+0xb0], 0x1
		0x53,						// push rbx
		0x48, 0x31, 0xdb,				// xor rbx, rbx
		0x48, 0xb8, 					// movabs with no address
		((this_addr) & 0xFF), 				// Our address for the list of deleting objects (actual list +0x10)
		((this_addr>>8) & 0xFF),	
		((this_addr>>16) & 0xFF),
		((this_addr>>24) & 0xFF),
		((this_addr>>32) & 0xFF),
		((this_addr>>40) & 0xFF),
		((this_addr>>48) & 0xFF),
		((this_addr>>56) & 0xFF),
		0x48, 0x8b, 0x58, 0x08,				// mov rbx, qword PTR [rax+0x8] (# of objects in list)
		0x48, 0x89, 0x3c, 0xd8,				// mov qword PTR rax+rbx*0x8], rdi
		0x48, 0xff, 0xc3,				// inc rbx
		0x48, 0x89, 0x58, 0x08,				// mov qword ptr [rax+0x8], rbx
		0x5b,						// pop rbx
		0x58,						// pop rax
		0xc3						// ret
	};

	printf("+ Writing CGuiObject::KillObject replacement, bytes: %lu to addr: 0x%02llx\n", sizeof(CGuiObject_KillObject_asm), (rwx_addr+0x100));
	pwrite(fd, &CGuiObject_KillObject_asm, sizeof(CGuiObject_KillObject_asm), rwx_addr+0x100);

	const unsigned char init_val[] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	//initialize to 0x02 to our first object ends up at this_addr+0x2*0x8
	pwrite(fd, &init_val, sizeof(init_val), this_addr+0x8);

	this_addr = rwx_addr +0x100;
	const unsigned char CGuiObject_KillObject_asm_jmp[] = {
		0x50, 						//push rax
		0x48, 0xb8,					//movabs
		((this_addr) & 0xFF),                           // Our address for the jmp
                ((this_addr>>8) & 0xFF),
                ((this_addr>>16) & 0xFF),
                ((this_addr>>24) & 0xFF),
                ((this_addr>>32) & 0xFF),
                ((this_addr>>40) & 0xFF),
                ((this_addr>>48) & 0xFF),
                ((this_addr>>56) & 0xFF),
		0xff, 0xe0
	};							//jmp rax

	printf("+ Overriding CGuiObject::KillObject with jmp, bytes: %lu\n", sizeof(CGuiObject_KillObject_asm_jmp));
	pwrite(fd, &CGuiObject_KillObject_asm_jmp, sizeof(CGuiObject_KillObject_asm_jmp), 0x00000000021e3470);

	this_addr = rwx_addr+10000;
	const unsigned char CTextBox_KillObject_asm[] = {
		0x58,						//pop rax
		0x48, 0x8b, 0x07,				//call qword ptr [rax+0x78]
		0xc6, 0x83, 0xb0, 0x00, 0x00, 0x00, 0x01,	//mov byte ptr [rbx+0xb0], 0x1
		0x50,						//push rax
		0x57,						//push rdi
		0x48, 0x31, 0xff,				//xor rdi, rdi
		0x48, 0x89, 0xdf,				//mov rdi, rbx
		0x48, 0x31, 0xdb,				//xor rbx, rbx
		0x48, 0xb8,					//movabs rax,
		((this_addr) & 0xFF),                           // Our address for the list of deleting objects (actual list +0x10)
                ((this_addr>>8) & 0xFF),
                ((this_addr>>16) & 0xFF),
                ((this_addr>>24) & 0xFF),
                ((this_addr>>32) & 0xFF),
                ((this_addr>>40) & 0xFF),
                ((this_addr>>48) & 0xFF),
                ((this_addr>>56) & 0xFF),
		0x48, 0x8b, 0x58, 0x08,				//mov rbx, qword ptr [rax+0x8]
		0x48, 0x89, 0x3c, 0xd8,				//mov qword ptr [rax+rbx*8, rdi
		0x48, 0xff, 0xc3,				//inc rbx
		0x48, 0x89, 0x58, 0x08,				//mov qword ptr [rax+0x8], rbx
		0x5f,						//pop rdi
		0x58,						//pop rax
		0x5b,						//pop rbx
		0xc3						//ret
	};

	printf("+ Writing CTextBox::KillObject replacement, bytes: %lu to addr: 0x%02llx\n", sizeof(CTextBox_KillObject_asm), (rwx_addr+0x150));
        pwrite(fd, &CTextBox_KillObject_asm, sizeof(CTextBox_KillObject_asm), rwx_addr+0x150);
	
	this_addr = rwx_addr+0x150;
	const unsigned char CTextBox_KillObject_asm_jmp[] = {
		0x50,						//push rax
		0x48, 0xb8,					//movabs rax,
		((this_addr) & 0xFF),                           // Our address for the jmp target
                ((this_addr>>8) & 0xFF),
                ((this_addr>>16) & 0xFF),
                ((this_addr>>24) & 0xFF),
                ((this_addr>>32) & 0xFF),
                ((this_addr>>40) & 0xFF),
                ((this_addr>>48) & 0xFF),
                ((this_addr>>56) & 0xFF),
		0xff, 0xe0					//jmp rax
	};

	printf("+ Overriding CTextBox::KillObject with jmp, bytes: %lu\n", sizeof(CTextBox_KillObject_asm_jmp));
        pwrite(fd, &CTextBox_KillObject_asm_jmp, sizeof(CTextBox_KillObject_asm_jmp), 0x00000000022166ab);

        this_addr = rwx_addr+10000;
        const unsigned char CSpinner_KillObject_asm[] = {
		0x53,						//push rbx
		0xc6, 0x87, 0xb0, 0x00, 0x00, 0x00, 0x01,	//mov byte ptr [rdi+0xb0], x0x1
                0x48, 0xb8,                                     //movabs rax,
                ((this_addr) & 0xFF),                           // Our address for the list of deleting objects (actual list +0x10)
                ((this_addr>>8) & 0xFF),
                ((this_addr>>16) & 0xFF),
                ((this_addr>>24) & 0xFF),
                ((this_addr>>32) & 0xFF),
                ((this_addr>>40) & 0xFF),
                ((this_addr>>48) & 0xFF),
                ((this_addr>>56) & 0xFF),
                0x48, 0x8b, 0x58, 0x08,                         //mov rbx, qword ptr [rax+0x8]
                0x48, 0x89, 0x3c, 0xd8,                         //mov qword ptr [rax+rbx*8, rdi
                0x48, 0xff, 0xc3,                               //inc rbx
                0x48, 0x89, 0x58, 0x08,                         //mov qword ptr [rax+0x8], rbx
		0x58,						//pop rax
		0x48, 0x89, 0xfb,				//mov rbx, rdi
		0x48, 0x8b, 0xbb, 0x28, 0x01, 0x00, 0x00,	//mov rdi, qword ptr [rbx+0x128]
		0x53,						//push rbx
		0x48, 0x31, 0xdb,				//xor rbx,rbx
		0xbb, 0x6d, 0x43, 0x20, 0x02,			//mov ebx, 0x220436d - jmp back to the remainder of the stubbed function, right on our pop rbx
		0xff, 0xe3					//jmp rbx

        };

        printf("+ Writing CSpinner::KillObject replacement, bytes: %lu to addr: 0x%02llx\n", sizeof(CSpinner_KillObject_asm), (rwx_addr+0x200));
        pwrite(fd, &CSpinner_KillObject_asm, sizeof(CSpinner_KillObject_asm), rwx_addr+0x200);

        this_addr = rwx_addr+0x200;
        const unsigned char CSpinner_KillObject_asm_jmp[] = {
                0x50,                                           //push rax
                0x48, 0xb8,                                     //movabs rax,
                ((this_addr) & 0xFF),                           // Our address for the jmp target
                ((this_addr>>8) & 0xFF),
                ((this_addr>>16) & 0xFF),
                ((this_addr>>24) & 0xFF),
                ((this_addr>>32) & 0xFF),
                ((this_addr>>40) & 0xFF),
                ((this_addr>>48) & 0xFF),
                ((this_addr>>56) & 0xFF),
                0xff, 0xe0,                                      //jmp rax
		0x5b,						//pop rbx
		0x90, 0x90, 0x90, 0x90				//nop nop nop nop
        };

        printf("+ Overriding CSpinner::KillObject with jmp, bytes: %lu\n", sizeof(CSpinner_KillObject_asm_jmp));
        pwrite(fd, &CSpinner_KillObject_asm_jmp, sizeof(CSpinner_KillObject_asm_jmp), 0x0000000002204360);

*/


	const unsigned char CFleetView_Update_asm[] = {
		0x48, 0x31, 0xc0,					  //xor rax,rax
		0xb8, 0x84, 0x3b, 0x40, 0x03,                             //mov    $0x3403b84,%eax
		0x83, 0x38, 0x00,                                         //cmpl   $0x0,(%rax)
		0x74, 0x05,                                               //je    +0x5
		0x48, 0x83, 0xc4, 0x08,                                   //add,    $0x8,%rsp
		0xc3,                                                     //retq   
		0x58,							  // pop rax
		0x55,                                                     //push   %rbp
		0x41, 0x57,                                               //push   %r15
		0x41, 0x56,                                               //push   %r14
		0x41, 0x55,                                               //push   %r13
		0x41, 0x54,                                               //push   %r12
		0x53,                                                     //push   %rbx
		0x48, 0x81, 0xec, 0x08, 0x01, 0x00, 0x00,                 //sub    $0x108,%rsp
		0x50,                                                     //push   %rax
		0xc3                                                      //ret
	};
        
	printf("+ Writing CFleetView::Update replacement, bytes: %lu to addr: 0x%02llx\n", sizeof(CFleetView_Update_asm), (rwx_addr+0x250));
	pwrite(fd, &CFleetView_Update_asm, sizeof(CFleetView_Update_asm), rwx_addr+0x250);

	this_addr = rwx_addr+0x250;
	const unsigned char CFleetView_Update_asm_jmp[] = {                 
		0x48, 0x31, 0xc0,                                       //xor    %rax,%rax
		0x48, 0xb8,                                    		//movabs rax,
                ((this_addr) & 0xFF),                           	// Our address for the jmp target
                ((this_addr>>8) & 0xFF),
                ((this_addr>>16) & 0xFF),
                ((this_addr>>24) & 0xFF),
                ((this_addr>>32) & 0xFF),
                ((this_addr>>40) & 0xFF),
                ((this_addr>>48) & 0xFF),
                ((this_addr>>56) & 0xFF),
		0xff, 0xd0,                                                //callq  *%rax
		0x90, 0x90					//nop nop
	};

	printf("+ Overriding CFleetView::Update with jmp, bytes: %lu\n", sizeof(CFleetView_Update_asm_jmp));
	pwrite(fd, &CFleetView_Update_asm_jmp, sizeof(CFleetView_Update_asm_jmp), 0x197c940);



	const unsigned char CMapIconManager_UpdateGalacticObjectIcons_asm[] = {                     
		0x48, 0x31, 0xc0,                                         //xor    %rax,%rax
		0xb8, 0x84, 0x3b, 0x40, 0x03,                             //mov    $0x3403b84,%eax
		0x83, 0x38, 0x01,                                         //cmpl   $0x1,(%rax)
		0x74, 0x05,                                               //je     .+0x5
		0x48, 0x83, 0xc4, 0x08,                                   //add,    $0x8,%rsp
		0xc3,                                                     //retq   
		0x58,                                                     //pop    %rax
		0x55,                                                     //push   %rbp
		0x48, 0x89, 0xe5,                                         //mov    %rsp,%rbp
		0x41, 0x57,                                               //push   %r15
		0x41, 0x56,                                               //push   %r14
		0x41, 0x55,                                               //push   %r13
		0x41, 0x54,                                               //push   %r12
		0x53,                                                     //push   %rbx
		0x48, 0x83, 0xec, 0x38,                                   //sub    $0x38,%rsp
		0x50,                                                     //push   %rax
		0xc3                                                      //ret
	};


        printf("+ Writing CMapIconManager::UpdateGalacticObjectIcons replacement, bytes: %lu to addr: 0x%02llx\n", sizeof(CMapIconManager_UpdateGalacticObjectIcons_asm), (rwx_addr+0x300));
        pwrite(fd, &CMapIconManager_UpdateGalacticObjectIcons_asm, sizeof(CMapIconManager_UpdateGalacticObjectIcons_asm), rwx_addr+0x300);

	this_addr = rwx_addr+0x300;
	
	const unsigned char CMapIconManager_UpdateGalacticObjectIcons_asm_jmp[] = {                    
		0x48, 0x31, 0xc0,                                       //xor    %rax,%rax
		0x48, 0xb8,                                             //movabs rax,
                ((this_addr) & 0xFF),                           // Our address for the jmp target
                ((this_addr>>8) & 0xFF),
                ((this_addr>>16) & 0xFF),
                ((this_addr>>24) & 0xFF),
                ((this_addr>>32) & 0xFF),
                ((this_addr>>40) & 0xFF),
                ((this_addr>>48) & 0xFF),
                ((this_addr>>56) & 0xFF),
		0xff, 0xd0,                                               //callq  *%rax
		0x90, 0x90						// nop nop
	};

        printf("+ Overriding CMapIconManager::UpdateGalacticObjectIcons with jmp, bytes: %lu\n", sizeof(CMapIconManager_UpdateGalacticObjectIcons_asm_jmp));
        pwrite(fd, &CMapIconManager_UpdateGalacticObjectIcons_asm_jmp, sizeof(CMapIconManager_UpdateGalacticObjectIcons_asm_jmp), 0x1d86640);




/*
 * 	This seems to disable particle effects on it's own, not sure if it's a useful change though, disabling for now.

	addr = 0x2140310; //CPdxParticleObject::RenderBuckets(CGraphics*, CCamera const*, int)
	pread(fd, &buf, sizeof(buf), addr);
	printf("+ DEBUG: CPdxParticleObject::RenderBuckets addr: 0x%02hhx\n", *buf);

	buf[0] = 0xc3; 
	//buf[0] = 0x55;
	pwrite(fd, &buf, sizeof(buf), addr);
*/
/*	
 *	This being patched out causes particle something's to leak, frame rate decreases over time by wasting time in ParticleIsDone()
	addr = 0x23fa080; //ParticleUpdate
	pread(fd, &buf, sizeof(buf), addr);
	printf("+ DEBUG: ParticleUpdate addr: 0x%02hhx\n", *buf);


	buf[0] = 0xc3;
	//buf[0] = 0x55;
	pwrite(fd, &buf, sizeof(buf), addr);
*/

	addr = 0x1bdbec0; // CShipGraphics::Update
	pread(fd, &buf, sizeof(buf), addr);
	printf("+ DEBUG: CShipGraphics::Update addr: 0x%02hhx\n", *buf);
	buf[0] = 0xc3;
	//buf[0] = 0x55;
	pwrite(fd, &buf, sizeof(buf), addr);



/*
	//DEBUG changes that break stuff

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



	addr = 0x00000000018bc900; //COutliner::InternalUpdate
	pread(fd, &buf, sizeof(buf), addr);
	printf("+ DEBUG: COutliner::InternalUpdate addr: 0x%02hhx\n", *buf);

	//buf[0] = 0xc3;
	buf[0] = 0x55;
	pwrite(fd, &buf, sizeof(buf), addr);

*/

	close(fd);

	ptrace(PTRACE_DETACH, target, NULL, NULL);
	return 0;
}
