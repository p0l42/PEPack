#pragma once

#include <windows.h>
#include <winternl.h>
#include <iostream>

#define _TEST 1

typedef NTSTATUS(__stdcall* pfnZwUnmapViewOfSection)(
	IN HANDLE ProcessHandle,
	IN LPVOID BaseAddress
	);

class Shell {
public:
	Shell() {
		char* currentFile[200] = { 0 };
		getCurrentFile((LPSTR)currentFile, 200);
		readFile((LPCSTR)currentFile);
		unpackProg((LPSTR)currentFile);
	}
	~Shell() {
		free(this->_src_file);
		free(this->_image_file);
		free(this->_mem_file);
	}
	void getCurrentFile(LPSTR fileName, DWORD len) {
		GetModuleFileNameA(NULL, fileName, len);
	}

	void decryptData(PBYTE pData, DWORD dwLen) {
		for (int i = 0; i < dwLen; i++) {
			pData[i] ^= 0x88;
		}
	}

	void readFile(LPCSTR fileName) {
		OFSTRUCT of = { 0 };
		HANDLE hFile = (HANDLE)OpenFile(fileName, &of, OF_READ);
		if (hFile == INVALID_HANDLE_VALUE) {
			printf("%d\n", GetLastError());
			CloseHandle(hFile);
			return;
		}
		DWORD dwFileSize = GetFileSize(hFile, NULL);
		this->_file_size = dwFileSize;
		this->_mem_file = (PBYTE)malloc(dwFileSize);
		memset(this->_mem_file, 0, dwFileSize);
		DWORD dwByteToRead = dwFileSize;
		DWORD dwByteReads = 0;
		PBYTE tmp = this->_mem_file;
		do {
			ReadFile(hFile, tmp, dwByteToRead, &dwByteReads, NULL);
			if (dwByteReads == 0) {
				break;
			}
			dwByteToRead -= dwByteReads;
			tmp += dwByteReads;
		} while (dwByteToRead > 0);
		//TODO check pe fingerprint
		CloseHandle(hFile);
	}

	void unpackProg(LPSTR fileName) {

		PBYTE pImage = this->_mem_file;
		PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pImage;
		PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pImage + pDos->e_lfanew);
		PIMAGE_SECTION_HEADER pSec = (PIMAGE_SECTION_HEADER)((PBYTE)pNt + sizeof(IMAGE_NT_HEADERS));
		for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
			if (!strcmp((char*)pSec->Name, ".date")) {
				//maybe need to be fixed
				//maybe not, because mapped in mem according to its header
				this->_src_size = pSec->SizeOfRawData;
				this->_src_file = (PBYTE)malloc(this->_src_size);
				memset(this->_src_file, 0, this->_src_size);
				memcpy(this->_src_file, (void*)(this->_mem_file + pSec->PointerToRawData), this->_src_size);
				decryptData(this->_src_file, this->_src_size);
				this->_image_file = FileToImage(this->_src_file);
				migrateProcess(this->_image_file, fileName);
				break;
			}
			pSec++;
		}
	}

	void migrateProcess(PBYTE pImage, LPSTR fileName) {

		//do not use pointer maybe easier
		STARTUPINFO si = { 0 };
		PROCESS_INFORMATION stProc;
		si.cb = sizeof(si);
		CreateProcessA(NULL, fileName, NULL, NULL, FALSE, CREATE_SUSPENDED,
			NULL, NULL, (LPSTARTUPINFOA)&si, &stProc);
		CONTEXT stContext;
		stContext.ContextFlags = CONTEXT_FULL;
		GetThreadContext(stProc.hThread, &stContext);
		char* pImageBaseOffset = (char*)stContext.Rdx + 0x10;
		DWORD64 dwUnpackImageBase;
		SIZE_T byteSize;
		ReadProcessMemory(stProc.hProcess, pImageBaseOffset, &dwUnpackImageBase, 8, &byteSize);
		pfnZwUnmapViewOfSection UnmapView = (pfnZwUnmapViewOfSection)GetProcAddress(LoadLibraryA("ntdll.dll"), "ZwUnmapViewOfSection");
		UnmapView(stProc.hProcess, (LPVOID)dwUnpackImageBase);

		PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pImage;
		PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pImage + pDos->e_lfanew);
		LPVOID status = VirtualAllocEx(stProc.hProcess,
			(LPVOID)pNt->OptionalHeader.ImageBase, pNt->OptionalHeader.SizeOfImage,
			MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (status) {
			SIZE_T bytewrite;
			WriteProcessMemory(stProc.hProcess, status, pImage, pNt->OptionalHeader.SizeOfImage, &bytewrite);
			//fix peb
			WriteProcessMemory(stProc.hProcess, (LPVOID)dwUnpackImageBase, status, 8, &bytewrite);
			stContext.Rcx = pNt->OptionalHeader.ImageBase + pNt->OptionalHeader.AddressOfEntryPoint;
			SetThreadContext(stProc.hThread, &stContext);
		}
		else {
			status = VirtualAllocEx(stProc.hProcess, NULL, pNt->OptionalHeader.SizeOfImage,
				MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			fixRelocation();
		}
		ResumeThread(stProc.hThread);
		TerminateProcess(stProc.hProcess, 0);
	}

	//todo fixed relocation
	//if you're interested in it
	//follow my another project called LoadModule
	void fixRelocation() {
	}

	PBYTE FileToImage(PBYTE pFile) {
		//TODO check if it's a pe
		PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pFile;
		PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pFile + pDos->e_lfanew);
		
		PBYTE pImage = (PBYTE)malloc(pNt->OptionalHeader.SizeOfImage);
		memset(pImage, 0, pNt->OptionalHeader.SizeOfImage);
		//headers
		memcpy(pImage, pFile, pNt->OptionalHeader.SizeOfHeaders);
		//section
		PBYTE tmpBuffer = pImage;
		PBYTE tmpSrc = pFile;
		PIMAGE_SECTION_HEADER pSec = (PIMAGE_SECTION_HEADER)((PBYTE)pNt + sizeof(IMAGE_NT_HEADERS));
		for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
			DWORD dwVirtualAddr = pSec->VirtualAddress;
			DWORD dwSize = pSec->SizeOfRawData;
			DWORD dwFileAddr = pSec->PointerToRawData;
			memcpy(tmpBuffer + dwVirtualAddr, tmpSrc + dwFileAddr, dwSize);
			pSec++;
		}
		return pImage;
	}

	
private:
	PBYTE _mem_file;
	PBYTE _src_file;
	PBYTE _image_file;
	DWORD _file_size;
	DWORD _src_size;
};