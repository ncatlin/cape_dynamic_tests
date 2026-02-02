/*
These tests check CAPEs ability to detect and 
fetch dropped files in various situations.
*/

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <vector>
#include <wincrypt.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

int main() {
	// Test 1: Basic test for fetching a file written to disk 
	printf("FLAG_WRITECONSOLE_FLAG");

	// Test 2: Can it get the argument of a sleep call
	Sleep(1337);

	// --- Memory Operations --- 
	// 
	LPVOID pMem = VirtualAlloc(NULL, 9867, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pMem) {
		const char* data = "FLAG_MEMCPY_FLAG";
		memcpy_s(pMem, 1234, data, strlen(data) + 1);
		DWORD oldProtect;
		VirtualProtect(pMem, 5551, PAGE_EXECUTE_READ, &oldProtect); // Changing to executable is a high-signal event
		VirtualFree(pMem, 9867, MEM_RELEASE);
	}

	// --- File Operations ---
	HANDLE hFile = CreateFileA("FLAG_CREATED_FILENAME_FLAG.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile != INVALID_HANDLE_VALUE) {
		DWORD written;
		WriteFile(hFile, "FLAG_WRITTEN_FILE_CONTENT_FLAG", 10, &written, NULL);
		CloseHandle(hFile);
		DeleteFileA("FLAG_CREATED_FILENAME_FLAG.txt");
	}

	// --- Registry Operations ---
	HKEY hKey;
	if (RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\FLAG_REGISTRY_KEY_NAME_FLAG", 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
		const char* val = "FLAG_REGISTRY_VALUE_CONTENT_FLAG";
		RegSetValueExA(hKey, "FLAG_REGISTRY_VALUE_NAME_FLAG", 0, REG_SZ, (BYTE*)val, (DWORD)strlen(val));
		RegCloseKey(hKey);
	}

	// --- Network Operations (Localhost) ---
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);
	SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(980);
	inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
	connect(sock, (struct sockaddr*)&addr, sizeof(addr)); // This will likely fail, but the API call is traced
	send(sock, "FLAG_NETWORK_SENT_DATA_FLAG", 27, 0);
	closesocket(sock);
	WSACleanup();

	// --- Mutex, Crypto, and Threads ---
	// Mutex (Often used for infection markers)
	HANDLE hMutex = CreateMutexA(NULL, FALSE, "FLAG_MUTEX_NAME_FLAG");
	if (hMutex != NULL && hMutex != INVALID_HANDLE_VALUE)
	{
		WaitForSingleObject(hMutex, INFINITE);
		CloseHandle(hMutex);
	}
	// Crypto (Wincrypt)
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	HCRYPTKEY hCKey = 0;

	const char* password = "FLAG_CRYPT_KEY_FLAG";
	char data[] = "FLAG_CRYPT_PLAINTEXT_FLAG";
	DWORD dataLen = (DWORD)strlen(data);
	DWORD bufLen = (DWORD)sizeof(data);

	// 1. Acquire Crypto Context
	if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
	{
		if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
			CryptHashData(hHash, (BYTE*)password, (DWORD)strlen(password), 0);
			if (CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hCKey)) {
				CryptEncrypt(hCKey, 0, TRUE, 0, (BYTE*)data, &dataLen, bufLen);
				CryptDecrypt(hCKey, 0, TRUE, 0, (BYTE*)data, &dataLen);
				CryptDestroyKey(hCKey);
			}
			CryptDestroyHash(hHash);
		}
		CryptReleaseContext(hProv, 0);
	}

	// Threading
	HANDLE hThread = CreateThread(
	NULL,                   // Default security
		0,                      // Default stack size
		[](LPVOID lpParam) -> DWORD {
		// This code runs in the context of the new thread
		printf(">>> FLAG_NEW_THREAD_ACTIVITY_FLAG <<<\n");
		return 0;
		},
		NULL,                   // No parameter passed
		0,                      // Run immediately
		NULL                    // We don't need the thread ID
		);
	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);

	printf("FLAG_BEFORE_EXIT_FLAG"); 
	return 0;
}