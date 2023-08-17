#pragma once

#include <windows.h>
#include <iostream>
#include <winternl.h>

class AddShell {


public:
	AddShell(LPCSTR fileName, LPCSTR srcName, LPCSTR saveName) {
		readFile(fileName, srcName);
		addSection();
		saveFile(saveName);
	}
	~AddShell() {
		free(this->_shell_file);
		free(this->_src_file);
		free(this->_new_buffer);
	}

	void readFile(LPCSTR fileName, LPCSTR srcName) {
		OFSTRUCT of = { 0 };
		OFSTRUCT of2 = { 0 };
		HANDLE hFile = (HANDLE)OpenFile(fileName, &of, OF_READ);
		HANDLE hSrc = (HANDLE)OpenFile(srcName, &of2, OF_READ);
		if (hFile == INVALID_HANDLE_VALUE) {
			printf("%d\n", GetLastError());
			CloseHandle(hFile);
			CloseHandle(hSrc);
			return;
		}
		if (hSrc == INVALID_HANDLE_VALUE) {
			printf("%d\n", GetLastError());
			CloseHandle(hFile);
			CloseHandle(hSrc);
			return;
		}
		DWORD dwFileSize = GetFileSize(hFile, NULL);
		DWORD dwSrcSize = GetFileSize(hSrc, NULL);
		this->_shell_size = dwFileSize;
		this->_shell_file = (PBYTE)malloc(dwFileSize);
		memset(this->_shell_file, 0, dwFileSize);
		this->_src_size = dwSrcSize;
		this->_src_file = (PBYTE)malloc(dwSrcSize);
		memset(this->_src_file, 0, dwSrcSize);
		DWORD dwByteToRead = dwFileSize;
		DWORD dwByteReads = 0;
		PBYTE tmp = this->_shell_file;
		do {
			ReadFile(hFile, tmp, dwByteToRead, &dwByteReads, NULL);
			if (dwByteReads == 0) {
				break;
			}
			dwByteToRead -= dwByteReads;
			tmp += dwByteReads;
		} while (dwByteToRead > 0);
		dwByteToRead = dwSrcSize;
		dwByteReads = 0;
		tmp = this->_src_file;
		do {
			ReadFile(hSrc, tmp, dwByteToRead, &dwByteReads, NULL);
			if (dwByteReads == 0) {
				break;
			}
			dwByteToRead -= dwByteReads;
			tmp += dwByteReads;
		} while (dwByteToRead > 0);
		//TODO check pe fingerprint
		CloseHandle(hFile);
		CloseHandle(hSrc);
	}

	void saveFile(LPCSTR fileName) {
		HANDLE hFile = CreateFileA(fileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE) {
			printf("%d\n", GetLastError());
			CloseHandle(hFile);
			return;
		}
		DWORD dwByteToWrite = this->_fix_size;
		DWORD dwByteWrites = 0;
		PBYTE tmpBuffer = this->_new_buffer;
		do {
			WriteFile(hFile, tmpBuffer, dwByteToWrite, &dwByteWrites, NULL);
			dwByteToWrite -= dwByteWrites;
			tmpBuffer -= dwByteWrites;
		} while (dwByteToWrite > 0);
		CloseHandle(hFile);
	}

	void encryptData(PBYTE pImage, DWORD dwSize) {
		for (int i = 0; i < dwSize; i++) {
			pImage[i] ^= 0x88;
		}
	}

	void addSection() {


		//attention: if the align is not 0x1000, you should modify this manually
		DWORD dwSectionSize = this->alignImage(this->_src_size, 0x1000);
		this->_fix_size = this->_shell_size + dwSectionSize;
		this->_new_buffer = (PBYTE)malloc(this->_fix_size);
		PBYTE pImage = this->_new_buffer;
		this->encryptData(this->_src_file, this->_src_size);
		PBYTE dataBuffer = this->_src_file;
		memset(this->_new_buffer, 0, this->_fix_size);
		memcpy(pImage, this->_shell_file, this->_shell_size);
		memcpy(pImage + this->_shell_size, dataBuffer, this->_src_size);

		PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pImage;
		PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pImage + pDos->e_lfanew);
		
		
		PIMAGE_SECTION_HEADER pSec = (PIMAGE_SECTION_HEADER) ((PBYTE)pNt + sizeof(IMAGE_NT_HEADERS));
		PBYTE pText = NULL;
		PIMAGE_SECTION_HEADER pLast = pSec;
		DWORD dwSectionNum = pNt->FileHeader.NumberOfSections;
		while (dwSectionNum) {
			if (!strcmp((char*)pSec->Name, ".data")) {
				pText = (PBYTE)pSec;
			}
			if (dwSectionNum == 1) {
				pLast = pSec;
			}
			dwSectionNum--;
			pSec++;
		}
		memcpy(pSec, pText, sizeof(IMAGE_SECTION_HEADER));

		
		pNt->FileHeader.NumberOfSections += 1;
		pNt->OptionalHeader.SizeOfImage += dwSectionSize;
		pSec->Name[4] = 'e';
		pSec->Misc.VirtualSize = dwSectionSize;
		pSec->SizeOfRawData = dwSectionSize;
		pSec->PointerToRawData = pLast->PointerToRawData + pLast->SizeOfRawData;
		pSec->VirtualAddress = this->alignImage(pLast->VirtualAddress + 
			(pLast->Misc.VirtualSize > pLast->SizeOfRawData? pLast->Misc.VirtualSize: pLast->SizeOfRawData), 0x1000);
		
	}

	void FOAtoRVA(DWORD foa, DWORD* rva) {
		PBYTE pImage = this->_new_buffer;
		PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pImage;
		PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pImage + pDos->e_lfanew);
		if (foa < pNt->OptionalHeader.SizeOfHeaders) {
			*rva = foa;
			return;
		}
		PIMAGE_SECTION_HEADER pSec = (PIMAGE_SECTION_HEADER)((PBYTE)pNt + sizeof(IMAGE_NT_HEADERS));
		for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
			if (foa >= pSec->PointerToRawData && foa <= (pSec->PointerToRawData + pSec->SizeOfRawData)) {
				*rva = foa + pSec->VirtualAddress - pSec->PointerToRawData;
				return;
			}
			pSec += 1;
		}
	}

	//maybe always 0x200
	DWORD alignFile(DWORD data, DWORD fileAlign) {
		return data % fileAlign == 0 ? data : ((data / fileAlign + 1) * fileAlign);
	}

	//maybe always 0x1000
	DWORD alignImage(DWORD data, DWORD imageAlign) {
		return data % imageAlign == 0 ? data : ((data / imageAlign + 1) * imageAlign);
	}

	//maybe compress and decompress
	void compressData() {
		
	}
	void decompressData() {
	
	}

private:
	PBYTE _shell_file;
	PBYTE _new_buffer;
	PBYTE _src_file;
	DWORD _shell_size;
	DWORD _src_size;
	DWORD _fix_size;
};