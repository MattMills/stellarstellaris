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
#include "pmparser.h"



uintptr_t find_remote_symbol(pid_t pid, const char *mangled_symbol, const char *demangled_symbol ){

	void *base = (void *)0x400000; // Static for now, might need to be dynamic in the future
        uintptr_t  *target_addr = pdlsym(base, mangled_symbol);

        if(target_addr != 0){
                printf("+ Found target address for %s at %02lx\n", demangled_symbol, (uintptr_t) target_addr);
        }else{
                fprintf(stderr, "!!! Fatal Error: Failed to find address for function %s (%s)\n", demangled_symbol, mangled_symbol);
		ptrace(PTRACE_DETACH, pid, NULL, NULL);
                exit(1);
        }

	return (uintptr_t) target_addr;
}


int main (int argc, char *argv[]){
	pid_t target;
	struct user_regs_struct regs;
	struct user_regs_struct regs_backup;
	int syscall;
	int status = 0;
	long dst;
	unsigned long addr;
	uintptr_t target_addr;
	unsigned char buf[1];
	unsigned char backup_rip_code[2];
	const unsigned char replacement_rip_code[2] = {0x0f, 0x05};

	if (argc != 2){
		fprintf(stderr, "Usage:\n\t%s pid\n", argv[0]);
		exit(1);
	}

	target = (pid_t) atoi(argv[1]);


	pdlsym_init(target);

	printf ("+ Attempting to attach to process %d\n", target);
	if ((ptrace (PTRACE_ATTACH, target, NULL, NULL)) < 0){
		fprintf(stderr, "+ Failed to attach to process\n");
		perror("ptrace(ATTACH):");
		exit(1);
	}

	printf ("+ Waiting for process...\n");
	do {
            int w = waitpid(-1, &status, 0);
            if (w == -1) {
                perror("waitpid error :");
                exit(EXIT_FAILURE);
            }

            if (WIFEXITED(status)) {
                printf("exited, status=%d\n", WEXITSTATUS(status));
            } else if (WIFSIGNALED(status)) {
                printf("killed by signal %d\n", WTERMSIG(status));
            } else if (WIFSTOPPED(status)) {
                printf("stopped by signal %d\n", WSTOPSIG(status));
		if(WSTOPSIG(status) == 11){
			ptrace (PTRACE_GETREGS, target, NULL, &regs);
			printf("\n\n!!! FATAL: sigsegv rip: 0x%llx\n\n", regs.rip);
			exit(EXIT_FAILURE);
		}
            } else if (WIFCONTINUED(status)) {
                printf("continued\n");
            }
        } while (!WIFEXITED(status) && !WIFSIGNALED(status)  && !WIFSTOPPED(status));
	printf("-  DEBUG: wait status: %d\n", status);


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
		fprintf(stderr, "\n!!! FATAL ERROR: Invalid version string, aborting!\n");
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
	do {
            int w = waitpid(-1, &status, 0);
            if (w == -1) {
                perror("waitpid error :");
                exit(EXIT_FAILURE);
            }

            if (WIFEXITED(status)) {
                printf("exited, status=%d\n", WEXITSTATUS(status));
            } else if (WIFSIGNALED(status)) {
                printf("killed by signal %d\n", WTERMSIG(status));
            } else if (WIFSTOPPED(status)) {
                printf("stopped by signal %d\n", WSTOPSIG(status));
            } else if (WIFCONTINUED(status)) {
                printf("continued\n");
            }
        } while (!WIFEXITED(status) && !WIFSIGNALED(status) && !WIFSTOPPED(status));
        printf("-  DEBUG: wait status: %d\n", status);

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


	//We are back to normal execution with our own shiny memory allocation for executable code.
	//
	
	if( /* ::KillObject() */ 0 ){
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
	
		target_addr =  find_remote_symbol(target, "_ZN10CGuiObject10KillObjectEv", "CGuiObject::KillObject()");
		printf("+ Overriding CGuiObject::KillObject with jmp, bytes: %lu\n", sizeof(CGuiObject_KillObject_asm_jmp));
		pwrite(fd, &CGuiObject_KillObject_asm_jmp, sizeof(CGuiObject_KillObject_asm_jmp), target_addr);
	
		this_addr = rwx_addr+10000;
		const unsigned char CTextBox_KillObject_asm[] = {
			0x58,						//pop rax
			0x53,                                           //push   %rbx
			0x48, 0x89, 0xfb,                                         //mov    %rdi,%rbx
			0x48, 0x8b, 0xbb, 0xc8, 0x00, 0x00, 0x00,                 //mov    0xc8(%rbx),%rdi
			0x48, 0x8b, 0x07,                                         //mov    (%rdi),%rax
			0xff, 0x90, 0xf8, 0x00, 0x00, 0x00,                       //callq  *0xf8(%rax)
			0x48, 0x8b, 0xbb, 0xc8, 0x00, 0x00, 0x00,                 //mov    0xc8(%rbx),%rdi
			0x48, 0x8b, 0x07,                                         //mov    (%rdi),%rax
			0xff, 0x50, 0x78,                                         //callq  *0x78(%rax)
			0xc6, 0x83, 0xb0, 0x00, 0x00, 0x00, 0x01,                 //movb   $0x1,0xb0(%rbx)
			0x50,                                                     //push   %rax
			0x57,                                                     //push   %rdi
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
	
		this_addr = rwx_addr+0x200;
		printf("+ Writing CTextBox::KillObject replacement, bytes: %lu to addr: 0x%02llx\n", sizeof(CTextBox_KillObject_asm), this_addr);
	        pwrite(fd, &CTextBox_KillObject_asm, sizeof(CTextBox_KillObject_asm), this_addr);
		
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
	
		target_addr =  find_remote_symbol(target, "_ZN8CTextBox10KillObjectEv", "CTextBox::KillObject()");
		printf("+ Overriding CTextBox::KillObject with jmp, bytes: %lu\n", sizeof(CTextBox_KillObject_asm_jmp));
	        pwrite(fd, &CTextBox_KillObject_asm_jmp, sizeof(CTextBox_KillObject_asm_jmp), target_addr);
	
	        this_addr = rwx_addr+10000;
	        const unsigned char CSpinner_KillObject_asm[] = {
	                0x48, 0xb8,                                     //movabs rax,
	                ((this_addr) & 0xFF),                           // Our address for the list of deleting objects (actual list +0x10)
	                ((this_addr>>8) & 0xFF),
	                ((this_addr>>16) & 0xFF),
	                ((this_addr>>24) & 0xFF),
	                ((this_addr>>32) & 0xFF),
	                ((this_addr>>40) & 0xFF),
	                ((this_addr>>48) & 0xFF),
	                ((this_addr>>56) & 0xFF),
			0x48, 0x8b, 0x58, 0x08,                                   //mov    0x8(%rax),%rbx
			0x48, 0x89, 0x3c, 0xd8,                                   //mov    %rdi,(%rax,%rbx,8)
			0x48, 0xff, 0xc3,                                         //inc    %rbx
			0x48, 0x89, 0x58, 0x08,                                   //mov    %rbx,0x8(%rax)
			0x48, 0x89, 0xfb,                                         //mov    %rdi,%rbx
			0xc6, 0x83, 0xb0, 0x00, 0x00, 0x00, 0x01,                 //movb   $0x1,0xb0(%rbx)
			0x48, 0x8b, 0xbb, 0x28, 0x01, 0x00, 0x00,                 //mov    0x128(%rbx),%rdi
			0xc3                                                      //
	
	        };
	
		this_addr = rwx_addr+0x300;
	        printf("+ Writing CSpinner::KillObject replacement, bytes: %lu to addr: 0x%02llx\n", sizeof(CSpinner_KillObject_asm), this_addr);
	        pwrite(fd, &CSpinner_KillObject_asm, sizeof(CSpinner_KillObject_asm), this_addr);
	
	        const unsigned char CSpinner_KillObject_asm_jmp[] = {
			0x53,                                                     //push   %rbx
	                0x48, 0xb8,                                     //movabs rax,
	                ((this_addr) & 0xFF),                           // Our address for the jmp target
	                ((this_addr>>8) & 0xFF),
	                ((this_addr>>16) & 0xFF),
	                ((this_addr>>24) & 0xFF),
	                ((this_addr>>32) & 0xFF),
	                ((this_addr>>40) & 0xFF),
	                ((this_addr>>48) & 0xFF),
	                ((this_addr>>56) & 0xFF),
	                0xff, 0xd0,                                      //callq rax
			0x90, 0x90, 0x90, 0x90, 0x90			// nop nop nop nop nop
	        };
	
		target_addr =  find_remote_symbol(target, "_ZN8CSpinner10KillObjectEv", "CSpinner::KillObject()");
	        printf("+ Overriding CSpinner::KillObject with jmp, bytes: %lu\n", sizeof(CSpinner_KillObject_asm_jmp));
	        pwrite(fd, &CSpinner_KillObject_asm_jmp, sizeof(CSpinner_KillObject_asm_jmp), target_addr);
	}


	if( /*CFleetView_Update*/ 1){

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
	
	        this_addr = rwx_addr+0x400;
	
		printf("+ Writing CFleetView::Update replacement, bytes: %lu to addr: 0x%02llx\n", sizeof(CFleetView_Update_asm), this_addr);
		pwrite(fd, &CFleetView_Update_asm, sizeof(CFleetView_Update_asm), this_addr);
	
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
		
		target_addr =  find_remote_symbol(target, "_ZN10CFleetView6UpdateEv", "CFleetView::Update()");
		printf("+ Overriding CFleetView::Update (%lu) with jmp, bytes: %lu\n", target_addr, sizeof(CFleetView_Update_asm_jmp));
		pwrite(fd, &CFleetView_Update_asm_jmp, sizeof(CFleetView_Update_asm_jmp), target_addr);

	}

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


	this_addr = rwx_addr+0x500;
        printf("+ Writing CMapIconManager::UpdateGalacticObjectIcons replacement, bytes: %lu to addr: 0x%02llx\n", sizeof(CMapIconManager_UpdateGalacticObjectIcons_asm), this_addr);
        pwrite(fd, &CMapIconManager_UpdateGalacticObjectIcons_asm, sizeof(CMapIconManager_UpdateGalacticObjectIcons_asm), this_addr);

	
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

	target_addr =  find_remote_symbol(target, "_ZN15CMapIconManager25UpdateGalacticObjectIconsEv", "CMapIconManager::UpdateGalacticObjectIcons()");
        printf("+ Overriding CMapIconManager::UpdateGalacticObjectIcons with jmp, bytes: %lu\n", sizeof(CMapIconManager_UpdateGalacticObjectIcons_asm_jmp));
        pwrite(fd, &CMapIconManager_UpdateGalacticObjectIcons_asm_jmp, sizeof(CMapIconManager_UpdateGalacticObjectIcons_asm_jmp), (uintptr_t) target_addr);


	const unsigned char CPlanetView_Update_asm[] = {
		0x48, 0x31, 0xc0,                                         //xor    %rax,%rax
		0xb8, 0x84, 0x3b, 0x40, 0x03,                             //mov    $0x3403b84,%eax
		0x83, 0x38, 0x02,                                         //cmpl   $0x2,(%rax)
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
		0x48, 0x81, 0xec, 0x08, 0x05, 0x00, 0x00,                 //sub    $0x508,%rsp
		0x50,                                                     //push   %rax
		0xc3                                                      //ret
	};
        
	this_addr = rwx_addr+0x600;

	printf("+ Writing CPlanetView::Update replacement, bytes: %lu to addr: 0x%02llx\n", sizeof(CPlanetView_Update_asm), (this_addr));
        pwrite(fd, &CPlanetView_Update_asm, sizeof(CPlanetView_Update_asm), this_addr);
                                          
	const unsigned char CPlanetView_Update_asm_jmp[] = {                 
		0x48, 0x31, 0xc0,                                         //xor    %rax,%rax
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
		0x90,                                                     //nop
		0x90, 0x90, 0x90, 0x90                                                      //nop nopnopnop
	};

	target_addr =  find_remote_symbol(target, "_ZN11CPlanetView6UpdateEv", "CPlanetView::Update()");
	printf("+ Overriding CPlanetView::Update with jmp, bytes: %lu\n", sizeof(CPlanetView_Update_asm_jmp));
        pwrite(fd, &CPlanetView_Update_asm_jmp, sizeof(CPlanetView_Update_asm_jmp),  target_addr);



	target_addr =  find_remote_symbol(target, "_ZN18CPdxParticleObject13RenderBucketsEP9CGraphicsPK7CCamerai", "CPdxParticleObject::RenderBuckets(CGraphics*, CCamera const*, int)");
	pread(fd, &buf, sizeof(buf),  target_addr);
	printf("-  DEBUG: CPdxParticleObject::RenderBuckets addr: 0x%02hhx\n", *buf);

	buf[0] = 0xc3;   // ret
	//buf[0] = 0x55; //
	pwrite(fd, &buf, sizeof(buf), target_addr);


	target_addr =  find_remote_symbol(target, "_ZN13CShipGraphics6UpdateEffR23CEntityGarbageCollectorPK15CGalacticObject", "CShipGraphics::Update(float, float, CEntityGarbageCollector&, CGalacticObject const*)");
	pread(fd, &buf, sizeof(buf),  target_addr);
	printf("-  DEBUG: CShipGraphics::Update addr: 0x%02hhx\n", *buf);
	buf[0] = 0xc3;
	//buf[0] = 0x55;
	pwrite(fd, &buf, sizeof(buf), target_addr);



/*
	//DEBUG changes that break stuff

	addr = 0x00000000021db6f0; //CGui::PerFrameUpdate
	pread(fd, &buf, sizeof(buf), addr);
	printf("-  DEBUG: CGui::PerFrameUpdate addr: 0x%02hhx\n", *buf);

	//buf[0] = 0xc3;
        buf[0] = 0x41;
	pwrite(fd, &buf, sizeof(buf), addr);
	
	addr = 0x00000000021dab10; //CGui::HandelInput
	pread(fd, &buf, sizeof(buf), addr);
	printf("-  DEBUG: CGui::HandelInput addr: 0x%02hhx\n", *buf);

	//buf[0] = 0xc3;
	buf[0] = 0x55;
	pwrite(fd, &buf, sizeof(buf), addr);



	addr = 0x00000000018bc900; //COutliner::InternalUpdate
	pread(fd, &buf, sizeof(buf), addr);
	printf("-  DEBUG: COutliner::InternalUpdate addr: 0x%02hhx\n", *buf);

	//buf[0] = 0xc3;
	buf[0] = 0x55;
	pwrite(fd, &buf, sizeof(buf), addr);

*/

	//Addresses of remote functions
	const uintptr_t pthread_create_addr = 	find_remote_symbol(target, "pthread_create", 	"pthread_create");
	const uintptr_t usleep_addr =		find_remote_symbol(target, "usleep", 		"usleep");
	const uintptr_t pthread_self_addr = 	find_remote_symbol(target, "pthread_self",	"pthread_self");
	const uintptr_t time_addr = 		find_remote_symbol(target, "time", 		"time");
	const uintptr_t printf_addr = 		find_remote_symbol(target, "printf",		"printf");
	const uintptr_t render2dtree_addr = 	rwx_addr+0xb00;
	const uintptr_t loadstub_addr = 	rwx_addr+0x2000;

	this_addr = rwx_addr+0x700;
	const unsigned char printf_string[] = "THREAD %ld @ %llx frame: %ld\n";
	pwrite(fd, &printf_string, sizeof(printf_string), this_addr);
	const uintptr_t printf_string_addr = this_addr;

	this_addr = rwx_addr+0x800;
	const unsigned char render_thread_asm[] = {
		0x55,                                                           //push   rbp
		0x48, 0x89, 0xe5,                                               //mov    rbp, rsp
		0x48, 0x83, 0xec, 0x20,                                         //sub    rsp, 0x20
		0x48, 0x89, 0x7d, 0xf8,                                         //mov    -0x8(%rbp), rdi
		0xbf, 0x40, 0x42, 0x0f, 0x00,                                   //mov    $0xf4240,%edi
                0x48, 0xb8,                                                     //movabs rax,
                ((usleep_addr) & 0xFF),                                         // Our address for the jmp target
                ((usleep_addr>>8) & 0xFF),
                ((usleep_addr>>16) & 0xFF),
                ((usleep_addr>>24) & 0xFF),
                ((usleep_addr>>32) & 0xFF),
                ((usleep_addr>>40) & 0xFF),
                ((usleep_addr>>48) & 0xFF),
		((usleep_addr>>56) & 0xFF),
		0xff, 0xd0,                                               	//callq  *%rax


		0x89, 0x45, 0xf4,                                               //mov    %eax,-0xc(%rbp)
		0x48, 0xb8,                                                     //movabs rax,
                ((pthread_self_addr) & 0xFF),                                   // Our address for the jmp target
                ((pthread_self_addr>>8) & 0xFF),
                ((pthread_self_addr>>16) & 0xFF),
                ((pthread_self_addr>>24) & 0xFF),
                ((pthread_self_addr>>32) & 0xFF),
                ((pthread_self_addr>>40) & 0xFF),
                ((pthread_self_addr>>48) & 0xFF),
                ((pthread_self_addr>>56) & 0xFF),
                0xff, 0xd0,                                                    //callq  *%rax
		0x31, 0xc9,                                                    //xor    %ecx,%ecx
		0x89, 0xcf,                                                    //mov    %ecx,%edi
		0x48, 0x89, 0x45, 0xe8,                                        //mov    %rax,-0x18(%rbp)

		0x49, 0xbf,                                                    //movabs r15,
                ((render2dtree_addr) & 0xFF),                                  // Our address for the
                ((render2dtree_addr>>8) & 0xFF),
                ((render2dtree_addr>>16) & 0xFF),
                ((render2dtree_addr>>24) & 0xFF),
                ((render2dtree_addr>>32) & 0xFF),
                ((render2dtree_addr>>40) & 0xFF),
                ((render2dtree_addr>>48) & 0xFF),
                ((render2dtree_addr>>56) & 0xFF),
		0x49, 0x8b, 0x4f, 0x30,						//mov rcx, qword ptr [r15+0x30]
		0x48, 0xbf,                                                    //movabs rdi,
                ((printf_string_addr) & 0xFF),                                 // Our address for the jmp target
                ((printf_string_addr>>8) & 0xFF),
                ((printf_string_addr>>16) & 0xFF),
                ((printf_string_addr>>24) & 0xFF),
                ((printf_string_addr>>32) & 0xFF),
                ((printf_string_addr>>40) & 0xFF),
                ((printf_string_addr>>48) & 0xFF),
                ((printf_string_addr>>56) & 0xFF),
		0x4c, 0x89, 0xfa,						//mov rdx, r15
		0x48, 0x8b, 0x75, 0xe8,                                        //mov    -0x18(%rbp),%rsi
		0x48, 0xbb,                                                    //movabs rbx,
                ((printf_addr) & 0xFF),                                        // Our address for the jmp target
                ((printf_addr>>8) & 0xFF),
                ((printf_addr>>16) & 0xFF),
                ((printf_addr>>24) & 0xFF),
                ((printf_addr>>32) & 0xFF),
                ((printf_addr>>40) & 0xFF),
                ((printf_addr>>48) & 0xFF),
                ((printf_addr>>56) & 0xFF),
                0xff, 0xd3,                                                    //callq  *%rbx
		0x89, 0x45, 0xe4,                                              //mov    %eax,-0x1c(%rbp)
                0x48, 0xbb,                                                     //movabs rbx,
                ((loadstub_addr) & 0xFF),                                 // Our address for the jmp target
                ((loadstub_addr>>8) & 0xFF),
                ((loadstub_addr>>16) & 0xFF),
                ((loadstub_addr>>24) & 0xFF),
                ((loadstub_addr>>32) & 0xFF),
                ((loadstub_addr>>40) & 0xFF),
                ((loadstub_addr>>48) & 0xFF),
                ((loadstub_addr>>56) & 0xFF),
                0xff, 0xd3,                                                     //callq  *%rbx

		0x48, 0xb8,                                                    //movabs rax,
                ((this_addr) & 0xFF),                                          // Our address for the jmp target
                ((this_addr>>8) & 0xFF),
                ((this_addr>>16) & 0xFF),
                ((this_addr>>24) & 0xFF),
                ((this_addr>>32) & 0xFF),
                ((this_addr>>40) & 0xFF),
                ((this_addr>>48) & 0xFF),
                ((this_addr>>56) & 0xFF),
		0x48, 0x83, 0xc4, 0x20,                                       //add    rsp,0x20
		0x5d,                                                         //pop rbp
                0xff, 0xe0,                                                   //jmp  *%rax
		0xcc							      //int3
	};

	printf("+ Writing render_thread_asm, bytes: %lu @ 0x%02llx\n", sizeof(render_thread_asm), (this_addr));
	pwrite(fd, &render_thread_asm, sizeof(render_thread_asm), this_addr);

	const uintptr_t render_thread_addr = rwx_addr+0x800;
        const uintptr_t thread_id_addr = rwx_addr+0x8;

	this_addr = rwx_addr+0xa00;
	const unsigned char thread_init_asm[] = {
		0x90, 0x90,							//nop nop
		0x55,								// push   rbp
		0x6a, 0x00,							// push 0x0
		0x48, 0x89, 0xe5,						// mov    rsp, rbp
		0x48, 0x83, 0xec, 0x20,     					// sub    rsp,0x20
		0x31, 0xc0,                                                     // xor    eax,eax
		0x89, 0xc1,                                                     // mov    ecx,eax
		0x89, 0x7d, 0xfc,						// mov dword ptr [rbp-0x4, edi
		0x48, 0x89, 0x75, 0xf0,						// mov qword ptr [rbp-0x10], rsi
		//0x48, 0x89, 0xce,        					// mov    rsi,rcx
		//0x48, 0x31, 0xc9,						// xor rcx,rcx
		0x48, 0x31, 0xf6,						// xor rsi, rsi
		
		0x48, 0xba,                                                     // movabs rdx,
                ((render_thread_addr) & 0xFF),                                  // Our address for the jmp target
                ((render_thread_addr>>8) & 0xFF),
                ((render_thread_addr>>16) & 0xFF),
                ((render_thread_addr>>24) & 0xFF),
                ((render_thread_addr>>32) & 0xFF),
                ((render_thread_addr>>40) & 0xFF),
                ((render_thread_addr>>48) & 0xFF),
                ((render_thread_addr>>56) & 0xFF),
		0x48, 0xbf,                                                     //movabs rdi,
                ((thread_id_addr) & 0xFF),                                      // Our address for the jmp target
                ((thread_id_addr>>8) & 0xFF),
                ((thread_id_addr>>16) & 0xFF),
                ((thread_id_addr>>24) & 0xFF),
                ((thread_id_addr>>32) & 0xFF),
                ((thread_id_addr>>40) & 0xFF),
                ((thread_id_addr>>48) & 0xFF),
                ((thread_id_addr>>56) & 0xFF),
		0x48, 0xbb,                                                     //movabs rbx,
                ((pthread_create_addr) & 0xFF),                                 // Our address for the jmp target
                ((pthread_create_addr>>8) & 0xFF),
                ((pthread_create_addr>>16) & 0xFF),
                ((pthread_create_addr>>24) & 0xFF),
                ((pthread_create_addr>>32) & 0xFF),
                ((pthread_create_addr>>40) & 0xFF),
                ((pthread_create_addr>>48) & 0xFF),
                ((pthread_create_addr>>56) & 0xFF),
                0xff, 0xd3,                                               	//callq  *%rbx
		0x45, 0x31, 0xc0,        				  	//xor    r8d,r8d
		0x89, 0x45, 0xec,					  	//mov    DWORD PTR [rbp-0x14],eax
		0x44, 0x89, 0xc0,						//mov    eax,r8d
		0x48, 0x83, 0xc4, 0x20,     					//add    rsp,0x20
		0x5d,								// pop rbp
		0x5d,							  	// pop rbp
		0xcc,								//int3 (breakpoint interrupt)
		0xc3

	};

	printf("+ Writing thread_init_asm, bytes: %lu to addr: 0x%02llx\n", sizeof(thread_init_asm), (this_addr));
	pwrite(fd, &thread_init_asm, sizeof(thread_init_asm), this_addr-2);


	this_addr = rwx_addr+0xb00;

	const unsigned char cguigraphics_render2dtree_asm[] = {                          //_start 
		0x55,                                                     //push   %rbp
		0x41, 0x57,                                               //push   %r15
		0x41, 0x56,                                               //push   %r14
		0x41, 0x55,                                               //push   %r13
		0x41, 0x54,                                               //push   %r12
		0x53,                                                     //push   %rbx
		0x48, 0x83, 0xec, 0x78,                                   //sub    $0x78,%rsp
		0x49, 0xbf,                                               //movabs r15,
                ((this_addr) & 0xFF),                                     // Our address for the jmp target
                ((this_addr>>8) & 0xFF),
                ((this_addr>>16) & 0xFF),
                ((this_addr>>24) & 0xFF),
                ((this_addr>>32) & 0xFF),
                ((this_addr>>40) & 0xFF),
                ((this_addr>>48) & 0xFF),
                ((this_addr>>56) & 0xFF),
		0x4d, 0x89, 0x07,                                         //mov    %r8,(%r15)
		0x4d, 0x89, 0x4f, 0x08,                                   //mov    %r9,0x8(%r15)
		0x49, 0x89, 0x7f, 0x10,                                   //mov    %rdi,0x10(%r15)
		0x49, 0x89, 0x77, 0x18,                                   //mov    %rsi,0x18(%r15)
		0x49, 0x89, 0x57, 0x20,                                   //mov    %rdx,0x20(%r15)
		0x49, 0x89, 0x4f, 0x28,                                   //mov    %rcx,0x28(%r15)
		0x49, 0xff, 0x47, 0x30,                                   //incq   0x30(%r15)
		0x48, 0x83, 0xc4, 0x78,                                   //a0xdd,    $0x78,%rsp
		/*
		0x57,							  //push rdi
                0xbf, 0x7D, 0x00, 0x00, 0x00,                                   //mov    $0x3e8,%edi
                0x48, 0xb8,                                                     //movabs rax,
                ((usleep_addr) & 0xFF),                                         // Our address for the jmp target
                ((usleep_addr>>8) & 0xFF),
                ((usleep_addr>>16) & 0xFF),
                ((usleep_addr>>24) & 0xFF),
                ((usleep_addr>>32) & 0xFF),
                ((usleep_addr>>40) & 0xFF),
                ((usleep_addr>>48) & 0xFF),
                ((usleep_addr>>56) & 0xFF),
                0xff, 0xd0,                                                     //callq  *%rax
		0x5f,							  // pop rdi
		*/
		0x5b,                                                     //pop    %rbx
		0x41, 0x5c,                                               //pop    %r12
		0x41, 0x5d,                                               //pop    %r13
		0x41, 0x5e,                                               //pop    %r14
		0x41, 0x5f,                                               //pop    %r15
		0x5d,                                                     //pop    %rbp
		0xc3                                                      //retq 
	};

	printf("+ CGuiGraphics::Render2dTree(...) write allocation: 0x%llx\n", this_addr);
	target_addr =  find_remote_symbol(target, "_ZNK12CGuiGraphics12Render2dTreeERK8CMatrix4IfEP16CGraphicalObjectPK17SScissorRectangleR6CArrayIS5_EPSA_SC_", "CGuiGraphics::Render2dTree(...)");

	uintptr_t that_addr = rwx_addr + 0xc00;
	printf("+ Backing up CGuiGraphics::Render2dTree(...) source: 0x%lx, dest: 0x%lx\n", target_addr, that_addr);

	printf("+ Seeking for ret in CGuiGraphics::Render2dTree(..) @ 0x%lx\n", target_addr);

	char search_buf[100];
	char * ptr_chr;
	int i = target_addr;
	for( ; i-target_addr <= 0x5000 ; i += sizeof(search_buf)){
		pread(fd, &search_buf, sizeof(search_buf), i);
		ptr_chr = (char*) memchr(&search_buf, 0xc3, sizeof(search_buf));
		if(ptr_chr != NULL){
			printf("-  ret found at %lx\n", ptr_chr-search_buf+i );
			pwrite(fd, &search_buf, ptr_chr-search_buf+1, that_addr+i-target_addr);
			break;
		}else{
			printf("-  no @ %x\n", i);
			pwrite(fd, &search_buf, sizeof(search_buf), that_addr+i-target_addr);
		}
	}

	if(ptr_chr == NULL){
		printf("!!! FATAL: Failed to find ret in CGuiGraphics::Render2dTree()\n");
		exit(1);
	}

	printf("-  Final length: %lu\n", (ptr_chr-search_buf+i+1-target_addr));



        printf("+ Overriding CGuiGraphics::Render2dTree(...) with stub, bytes: %lu @%lx\n", sizeof(cguigraphics_render2dtree_asm), target_addr);
        pwrite(fd, &cguigraphics_render2dtree_asm, sizeof(cguigraphics_render2dtree_asm),  target_addr);


	const unsigned char cguigraphics_render2dtree_loadstub_asm[] = {                       //_loadstub 
		0x55,                                                     //push   %rbp
		0x49, 0xbf,                                               //movabs r15,
                ((this_addr) & 0xFF),                                     // Our address for the jmp target
                ((this_addr>>8) & 0xFF),
                ((this_addr>>16) & 0xFF),
                ((this_addr>>24) & 0xFF),
                ((this_addr>>32) & 0xFF),
                ((this_addr>>40) & 0xFF),
                ((this_addr>>48) & 0xFF),
                ((this_addr>>56) & 0xFF),
		0x4d, 0x8b, 0x07,                                         //mov    (%r15),%r8
		0x4d, 0x8b, 0x4f, 0x08,                                   //mov    0x8(%r15),%r9
		0x49, 0x8b, 0x7f, 0x10,                                   //mov    0x10(%r15),%rdi
		0x49, 0x8b, 0x77, 0x18,                                   //mov    0x18(%r15),%rsi
		0x49, 0x8b, 0x57, 0x20,                                   //mov    0x20(%r15),%rdx
		0x49, 0x8b, 0x4f, 0x28,                                   //mov    0x28(%r15),%rcx
		0x49, 0x81, 0xc7, 0x00, 0x01, 0x00, 0x00,                 //a0xdd,    $0x100,%r15
		0x41, 0xff, 0xd7,                                         //callq  *%r15
		0x5d,                                                     //pop    %rbp
		0xc3                                                      //retq   
			 
	};

	this_addr = rwx_addr+0x2000;
	printf("+ Writing CGuiGraphics::Render2dTree( LOADSTUB ), bytes: %lu @%llx\n", sizeof(cguigraphics_render2dtree_loadstub_asm), this_addr);
	pwrite(fd, &cguigraphics_render2dtree_loadstub_asm, sizeof(cguigraphics_render2dtree_loadstub_asm),  this_addr);

	/* Run thread_init in remote context */

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

	this_addr = rwx_addr+0xa00; // Address for thread_init
	regs.rip = this_addr;
	printf("+ process register rip: %llx\n", regs.rip);
	printf("+ process register rip: %llx, rax: %llx, rbx: %llx, rcx: %llx, rdx: %llx, rsp: %llx, rbp: %llx, rsi: %llx, rdi: %llx, r12: %llx, r13: %llx, r14: %llx, r15: %llx\n", regs.rip, regs.rax, regs.rbx, regs.rcx, regs.rdx, regs.rsp, regs.rbp, regs.rsi, regs.rdi, regs.r12, regs.r13, regs.r14, regs.r15);

	if ((ptrace (PTRACE_SETREGS, target, NULL, &regs)) < 0){
                perror ("ptrace(SETREGS):");
                exit(1);
        }
	

	//while(regs.rip != this_addr+sizeof(thread_init_asm)-2){
	if ((ptrace (PTRACE_CONT, target, NULL, NULL)) < 0){
                perror("ptrace(CONT):");
                exit(1);
        }

        printf("+ Waiting for process...\n");
        
        do {
            int w = waitpid(-1, &status, 0);
            if (w == -1) {
                perror("waitpid error :");
                exit(EXIT_FAILURE);
            }

            if (WIFEXITED(status)) {
                printf("exited, status=%d\n", WEXITSTATUS(status));
            } else if (WIFSIGNALED(status)) {
                printf("killed by signal %d\n", WTERMSIG(status));
            } else if (WIFSTOPPED(status)) {
                printf("stopped by signal %d\n", WSTOPSIG(status));
                if(WSTOPSIG(status) == 11){
                        ptrace (PTRACE_GETREGS, target, NULL, &regs);
                        printf("\n\n!!! FATAL: sigsegv rip: 0x%llx, rsp: 0x%llx, rbp: 0x%llx\n\n", regs.rip, regs.rsp, regs.rbp);
                        exit(EXIT_FAILURE);
                }
            } else if (WIFCONTINUED(status)) {
                printf("continued\n");
            }
        } while (!WIFEXITED(status) && !WIFSIGNALED(status)  && !WIFSTOPPED(status));

        printf("-  DEBUG: wait status: %d\n", status);

	printf("+ Getting process registers\n");
        if ((ptrace (PTRACE_GETREGS, target, NULL, &regs)) < 0){
	        perror ("ptrace(GETREGS):");
	        exit (1);
	}

	printf("+ process register rip: %llx, rax: %llx, rbx: %llx, rcx: %llx, rdx: %llx, rsp: %llx, rbp: %llx, rsi: %llx, rdi: %llx, r12: %llx, r13: %llx, r14: %llx, r15: %llx\n", regs.rip, regs.rax, regs.rbx, regs.rcx, regs.rdx, regs.rsp, regs.rbp, regs.rsi, regs.rdi, regs.r12, regs.r13, regs.r14, regs.r15);

	//}
	printf("+ Restoring Registers from backup\n");

        if ((ptrace (PTRACE_SETREGS, target, NULL, &regs_backup)) < 0){
	        perror ("ptrace(SETREGS):");
	        exit(1);
	}

	if ((ptrace (PTRACE_CONT, target, NULL, NULL)) < 0){
	        perror("ptrace(CONT):");
	        exit(1);
        }


	close(fd);

	ptrace(PTRACE_DETACH, target, NULL, NULL);
	pdlsym_exit();
	return 0;
}
