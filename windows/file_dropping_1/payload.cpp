/*
These tests check CAPEs ability to detect and
fetch dropped files in various situations.

Tests are assumed to run in a disposable VM snapshot,
so cleanup is not mandatory.
*/

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <vector>
#include <ktmw32.h> // Kernel Transaction Manager

#pragma comment(lib, "KtmW32.lib")

HANDLE CreateFileWithContent(const char* filename, const char* content) {
	HANDLE hFile = CreateFileA(filename, GENERIC_WRITE,
		0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile != INVALID_HANDLE_VALUE) {
		DWORD written;
		WriteFile(hFile, content, strlen(content), &written, NULL);
		return hFile;
	}
	return NULL;
}


void DoBasicFileTests() 
{
	// This function is intentionally left empty.
	// Test 1: Basic test for fetching a file written to the working dir
	// In the first test, we give CAPE some time to fetch the file
	const char* flag1filename = "FLAG_FILEDROP_1A_FLAG";
	const char* flag1content = "FLAG_FILEDROP_1B_FLAG\n\x00";

	HANDLE hFile1 = CreateFileWithContent(flag1filename, (char*)flag1content);
	if (hFile1) {
		CloseHandle(hFile1);
		Sleep(5000);
		DeleteFileA(flag1filename);
	}

	Sleep(2000);

	// Test 2: See if CAPE can fetch a file that is deleted immediately
	const char* flag2filename = "FLAG_FILEDROP_2A_FLAG";
	const char* flag2content = "FLAG_FILEDROP_2B_FLAG\n\x00";
	HANDLE hFile2 = CreateFileWithContent(flag2filename, (char*)flag2content);
	if (hFile2) {
		CloseHandle(hFile2);
		DeleteFileA(flag2filename);
	}

	Sleep(2000);

	// Test 3: Will it get content if we never close the file handle?
	const char* flag3filename = "FLAG_FILEDROP_3A_FLAG";
	const char* flag3content = "FLAG_FILEDROP_3B_FLAG\n\x00";

	HANDLE hFile3 = CreateFileWithContent(flag3filename, (char*)flag3content);
}



void DoBasicDirectoryTests()
{
	// Test 4: See how directories are handled
	// outer directory + file
	const char* flag4dirnameA = "FLAG_DIRDROP_1A_FLAG";
	const char* flag4filenameA = "FLAG_DIRDROP_1B_FLAG";
	const char* flag4contentA = "FLAG_DIRDROP_1C_FLAG";
	char file4APath[MAX_PATH];
	_snprintf_s(file4APath, MAX_PATH, "%s\\%s", flag4dirnameA, flag4filenameA);


	// inner directory + file
	const char* flag4dirnameB = "FLAG_DIRDROP_1D_FLAG";
	const char* flag4filenameB = "FLAG_DIRDROP_1E_FLAG";
	const char* flag4contentB = "FLAG_DIRDROP_1F_FLAG";
	char directory4BPath[MAX_PATH];
	char file4BPath[MAX_PATH];
	_snprintf_s(directory4BPath, MAX_PATH, "%s\\%s", flag4dirnameA, flag4dirnameB);
	_snprintf_s(file4BPath, MAX_PATH, "%s\\%s", directory4BPath, flag4filenameB);

	if (CreateDirectoryA(flag4dirnameA, NULL))
	{
		HANDLE hFile4a = CreateFileWithContent(file4APath, (char*)flag4contentA);
		if (CreateDirectoryA(directory4BPath, NULL))
		{
			Sleep(2000);
			HANDLE hFile4b = CreateFileWithContent(file4BPath, (char*)flag4contentB);
			if (hFile4b)
			{
				CloseHandle(hFile4b);
				DeleteFileA(file4BPath);
				RemoveDirectoryA(directory4BPath);
			}
		}
		CloseHandle(hFile4a);
		DeleteFileA(file4APath);
		RemoveDirectoryA(flag4dirnameA);
	}
}


void DoTransactedFileTests() {

	//Test 1: See if CAPE picks up files dropped to disk in a transaction
	const wchar_t* fileName1 = L"FLAG_TRANSACTION_1A_FLAG";
	const char* data1 = "FLAG_TRANSACTION_1B_FLAG\n\x00";
	wchar_t* transactionName = (wchar_t* )L"CAPE_Tx_Test1";
	HANDLE hTransaction1 = CreateTransaction(NULL, 0, 0, 0, 0, 0, transactionName);

	if (hTransaction1 != INVALID_HANDLE_VALUE) {
		HANDLE hFile = CreateFileTransactedW(fileName1, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
			FILE_ATTRIBUTE_NORMAL, NULL, hTransaction1, NULL, NULL);

		if (hFile != INVALID_HANDLE_VALUE) {
			DWORD written;
			WriteFile(hFile, data1, (DWORD)strlen(data1), &written, NULL);
			CommitTransaction(hTransaction1);
			CloseHandle(hFile);
		}
		CloseHandle(hTransaction1);
	}



	// Test 2: See if CAPE picks up files written in a transaction that is rolled back
	// We read the file to assert that the data is there before rollback
	// Debatable applicability to dropped file detection
	const wchar_t* fileName2 = L"FLAG_TRANSACTION_2A_FLAG";
	const char* data2 = "FLAG_TRANSACTION_2B_FLAG\n\x00";	
	wchar_t* transactionName2 = (wchar_t*)L"CAPE_Tx_Test2";
	HANDLE hTransaction2 = CreateTransaction(NULL, 0, 0, 0, 0, 0, transactionName2);

	if (hTransaction2 != INVALID_HANDLE_VALUE) {
		HANDLE hFile = CreateFileTransactedW(fileName2, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 
			NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL, 
			hTransaction2, NULL, NULL);

		if (hFile != INVALID_HANDLE_VALUE) {
			DWORD written, bytesRead;
			WriteFile(hFile, data2, (DWORD)strlen(data2), &written, NULL);

			char readBuf[100] = { 0 };
			if (ReadFile(hFile, readBuf, sizeof(readBuf) - 1, &bytesRead, NULL)) {
				printf("[+] Verified: Data read from within transaction: %s\n", readBuf);
			}

			Sleep(2000);
			RollbackTransaction(hTransaction2);
			CloseHandle(hFile);
		}
		CloseHandle(hTransaction2);
	}


}


int main() {

	DoBasicFileTests();
	DoBasicDirectoryTests();
	DoTransactedFileTests();

	return 0;
}