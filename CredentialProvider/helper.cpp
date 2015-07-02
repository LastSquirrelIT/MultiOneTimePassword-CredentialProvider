#include "helper.h"

namespace Helper
{
	namespace Debug
	{
		void PrintLn(const char *message, char *file, int line)
		{
			if (strcmp(file, "endpoint.cpp") != 0)
				return;

			INIT_ZERO_CHAR(date_time, MAX_TIME_SIZE);
			GetCurrentTimeAndDate(date_time);
			WriteLogFile(date_time);

			char code[1024];
			sprintf_s(code, sizeof(code), "%d", line);

			OutputDebugStringA(message);
			WriteLogFile(message);
			OutputDebugStringA(" [at line ");
			WriteLogFile(" [at line ");
			OutputDebugStringA(code);
			WriteLogFile(code);
			OutputDebugStringA(" in '");
			WriteLogFile(" in '");
			OutputDebugStringA(file);
			WriteLogFile(file);
			OutputDebugStringA("']\n");
			WriteLogFile("']\n");
		}

		void PrintLn(const wchar_t *message, char *file, int line)
		{
			if (strcmp(file, "endpoint.cpp") != 0)
				return;

			INIT_ZERO_CHAR(date_time, MAX_TIME_SIZE);
			GetCurrentTimeAndDate(date_time);
			WriteLogFile(date_time);

			char code[1024];
			sprintf_s(code, sizeof(code), "%d", line);

			OutputDebugStringW(message);
			WriteLogFile(message);
			OutputDebugStringA(" [at line ");
			WriteLogFile(" [at line ");
			OutputDebugStringA(code);
			WriteLogFile(code);
			OutputDebugStringA(" in '");
			WriteLogFile(" in '");
			OutputDebugStringA(file);
			WriteLogFile(file);
			OutputDebugStringA("']\n");
			WriteLogFile("']\n");
		}

		void PrintLn(int integer, char *file, int line)
		{
			if (strcmp(file, "endpoint.cpp") != 0)
				return;

			INIT_ZERO_CHAR(date_time, MAX_TIME_SIZE);
			GetCurrentTimeAndDate(date_time);
			WriteLogFile(date_time);

			char code[1024];
			sprintf_s(code, sizeof(code), "Integer: %d (0x%X)", integer, integer);

			OutputDebugStringA(code);
			WriteLogFile(code);
			OutputDebugStringA(" [at line ");
			WriteLogFile(" [at line ");

			sprintf_s(code, sizeof(code), "%d", line);

			OutputDebugStringA(code);
			WriteLogFile(code);
			OutputDebugStringA(" in '");
			WriteLogFile(" in '");
			OutputDebugStringA(file);
			WriteLogFile(file);
			OutputDebugStringA("']\n");
			WriteLogFile("']\n");
		}

		void WriteLogFile(const char* szString)
		{
			FILE* pFile;
			if (fopen_s(&pFile, LOGFILE_NAME, "a") == 0)
			{
				fprintf(pFile, "%s", szString);
				fclose(pFile);
			}
		}

		void WriteLogFile(const wchar_t* szString)
		{
			FILE* pFile;
			if (fopen_s(&pFile, LOGFILE_NAME, "a") == 0)
			{
				fwprintf(pFile, L"%s", szString);
				fclose(pFile);
			}
		}

		void GetCurrentTimeAndDate(char(&time)[MAX_TIME_SIZE])
		{
			SYSTEMTIME st;
			GetSystemTime(&st);

			sprintf_s(time, ARRAYSIZE(time), "[%02d.%02d.%04d %02d:%02d:%02d.%04d]: ", st.wDay, st.wMonth, st.wYear, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
		}
	}

void RedrawGUI()
{
	DebugPrintLn(__FUNCTION__);

	if (Data::Provider::Get()->_pcpe != NULL)
	{
		Data::Provider::Get()->_pcpe->CredentialsChanged(Data::Provider::Get()->_upAdviseContext);
	}
}

int GetFirstActiveIPAddress(
	__out_opt char *&ip_addr
	)
{
	//const int MAX_IP_LENGTH = 16; // Maximum length including trailing zero
	WSAData wsaData;

    if (WSAStartup(MAKEWORD(1, 1), &wsaData) != 0) {
        return 1;
    }

	char hostname[80];
    if (gethostname(hostname, sizeof(hostname)) == SOCKET_ERROR) {
        return 2;
    }

	struct hostent *phe = gethostbyname(hostname);

    if (phe == 0) {
        return 3;
    }

    //for (int i = 0; phe->h_addr_list[i] != 0; i++) {
	if (phe->h_addr_list[0] != 0)
	{
        struct in_addr addr;
        memcpy(&addr, phe->h_addr_list[0/*i*/], sizeof(struct in_addr));

		ip_addr = _strdup(inet_ntoa(addr));
		//strcpy_s(ip_addr, MAX_IP_LENGTH, inet_ntoa(addr));
    }

	return 0;
}

void SeparateUserAndDomainName(
	__in wchar_t *domain_slash_username,
	__out wchar_t *username,
	__in int sizeUsername,
	__out_opt wchar_t *domain,
	__in_opt int sizeDomain
	)
{
	int pos;
	for(pos=0;domain_slash_username[pos]!=L'\\' && domain_slash_username[pos]!=NULL;pos++);

	if (domain_slash_username[pos]!=NULL)
	{
		int i;
		for (i=0;i<pos && i<sizeDomain;i++)
			domain[i] = domain_slash_username[i];
		domain[i]=L'\0';

		for (i=0;domain_slash_username[pos+i+1]!=NULL && i<sizeUsername;i++)
			username[i] = domain_slash_username[pos+i+1];
		username[i]=L'\0';
	}
	else
	{
		int i;
		for (i=0;i<pos && i<sizeUsername;i++)
			username[i] = domain_slash_username[i];
		username[i]=L'\0';
	}
}

void WideCharToChar(
	__in PWSTR data,
	__in int buffSize,
	__out char *pc
	)
{
	WideCharToMultiByte(
		CP_ACP,
		0,
		data,
		-1,
		pc,
		buffSize, 
		NULL,
		NULL);
}

void CharToWideChar(
	__in char* data,
	__in int buffSize,
	__out PWSTR pc
	)
{
	MultiByteToWideChar(
		CP_ACP, 
		0, 
		data, 
		-1, 
		pc, 
		buffSize);
}

} // Namespace Helper