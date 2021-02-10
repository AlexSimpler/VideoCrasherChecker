#include <windows.h>
#include <stdio.h>
#include <iostream>

bool hasExt(const char* path, const char* ext) {
    char* ext1 = new char[strlen(path)];
	for(int i = 0;i < strlen(path);i++){
		if((char)path[i] == '.'){
		     strcpy(ext1++, &path[i]);
		     break;
		}
	}
	return strcmp(ext1, ext) == 0;
}

DWORD findSig(BYTE* _buffer, DWORD _length, LPCSTR _sig, bool reverse=false){
	DWORD     offset      = 0;
	BYTE*     buffer      = reverse ? ((BYTE*)_buffer)+_length-1 : (BYTE*)_buffer;
	
	BYTE*     signature   = reverse ? ((BYTE*)_sig)+strlen(_sig)-1 : (BYTE*)_sig;
	BYTE*     originalSig = signature;
	
	for(;offset < _length; (reverse ? --buffer : ++buffer), ++offset){
		
	    if(*buffer == *signature) reverse ? --signature : ++signature;
	    else signature = originalSig;
		if(reverse ? (signature == (originalSig-strlen(_sig)-1)) : ((signature - originalSig) >= strlen(_sig))) {
				return reverse ? (DWORD)abs((int)offset-(int)_length) : offset-strlen(_sig)+1;
		}

	}
	return NULL;
}

int main(int argc, char* argv[]) {
	if(argc < 2)
	{
		printf("Usage: VideoCrasherChecker video.mp4");
		return EXIT_FAILURE;
	}

	if(strlen(argv[1]) < 1) 
	{
		printf("Usage: VideoCrasherChecker video.mp4");
		return EXIT_FAILURE;
	}
	
	if(!hasExt(argv[1], "mp4")) {
		printf("\x1B[31m[+] Please provide a valid mp4 file.\033[0m");
		return EXIT_FAILURE;
	}

	HANDLE hFile = CreateFileA((LPCSTR)argv[1], GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    
    if(hFile < 0) return -1;
	
	DWORD  fileSize = GetFileSize(hFile, NULL);//no high order doubleword
	PVOID  mem      = VirtualAlloc(NULL, (SIZE_T)fileSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	
	if(!mem){
		printf("\x1B[31m[+] Failed to alloc mem\033[0m");
		return EXIT_FAILURE;
	}
	
	DWORD bytesRead    = NULL;
	if(!ReadFile(hFile, mem, fileSize, &bytesRead, NULL))
	{
		printf("\x1B[31m[+] Failed reading the file.\033[0m");
		return EXIT_FAILURE;
	}
	
	LPCSTR  signature1 = "\x62\x75\x64\x74\x61\x00\x00\x00\x5A\x73\x6B\x69\x70"; 
	DWORD   offset     = findSig((BYTE*)mem, fileSize, signature1, true);

	if(offset){
		printf("\x1B[31m[+] Found strange object at offset: 0x%x\033[0m\n", offset);
		printf("\x1B[31m[+] Might crash discord!\033[0m");
	} else {
		printf("\x1B[32m[+] Everything ok!\033[0m");
	}
	
	std::cout << std::endl;
	std::cin.get();
	VirtualFree(mem, fileSize, MEM_RELEASE);
                  CloseHandle(hFile);
	
	return EXIT_SUCCESS;
}