/* ============================================================================
*
*                            PUBLIC DOMAIN NOTICE
*               National Center for Biotechnology Information
*
*  This software/database is a "United States Government Work" under the
*  terms of the United States Copyright Act.  It was written as part of
*  the author's official duties as a United States Government employee and
*  thus cannot be copyrighted.  This software/database is freely available
*  to the public for use. The National Library of Medicine and the U.S.
*  Government have not placed any restriction on its use or reproduction.
*
*  Although all reasonable efforts have been taken to ensure the accuracy
*  and reliability of the software and data, the NLM and the U.S.
*  Government do not and cannot warrant the performance or results that
*  may be obtained by using this software or data. The NLM and the U.S.
*  Government disclaim all warranties, express or implied, including
*  warranties of performance, merchantability or fitness for any particular
*  purpose.
*
*  Please cite the author in any work or product based on this material.
*
* ===========================================================================*/

#include <windows.h>
#include <stdio.h>
#include <shlwapi.h>
#include <sys/stat.h>

#define BUFSIZE (1024 * 8)
#define MAX_CMD (8191)
#define THREAD_COUNT (2)

static const char sExtensionExe[] = ".exe";
static const char sExtensionIni[] = ".ini";
static const char sIniSectionName[] = "cgi_log";
static const char sIniKeyApplication[] = "application";
static const char sIniKeyLogfile[] = "logfile";
static const char sIniDefaultLogfile[] = "cgi_log.log";
static const char sIniLogdir[] = "logdir";
static const char sIniDefaultLogdir[] = "logs";

typedef struct
{
    HANDLE in;
    HANDLE out;
    HANDLE log;
} ThreadContext;

static const char* sVariables[] = {
    "ALL_HTTP",
    "ALL_RAW",
    "AUTH_TYPE",
    "CONTENT_LENGTH",
    "CONTENT_TYPE",
    "DOCUMENT_ROOT",
    "GATEWAY_INTERFACE",
    "HTTP_ACCEPT",
    "HTTP_ACCEPT_CHARSET",
    "HTTP_ACCEPT_ENCODING",
    "HTTP_ACCEPT_LANGUAGE",
    "HTTP_ACCEPT_DATETIME",
    "HTTP_AUTHORIZATION",
    "HTTP_CACHE_CONTROL",
    "HTTP_CAF",
    "HTTP_CAF_EXTERNAL",
    "HTTP_CAF_PROXIED_HOST",
    "HTTP_CAF_RELAY",
    "HTTP_CONNECTION",
    "HTTP_COOKIE",
    "HTTP_CONTENT_LENGTH",
    "HTTP_CONTENT_MD5",
    "HTTP_CONTENT_TYPE",
    "HTTP_DATE",
    "HTTP_EMAIL",
    "HTTP_EXPECT",
    "HTTP_FED_EMAIL",
    "HTTP_FED_FIRSTNAME",
    "HTTP_FED_LASTNAME",
    "HTTP_FED_LOA",
    "HTTP_FED_MAPPING_COMMONS_USERNAME",
    "HTTP_FED_MAPPING_NIHEXT_USERNAME",
    "HTTP_FED_ORG",
    "HTTP_FED_ORIG_EMAIL",
    "HTTP_FED_PERSIST_ID",
    "HTTP_FED_UPN",
    "HTTP_FROM",
    "HTTP_HHS_DESCRIPTION",
    "HTTP_HHS_EMPLOYEEID",
    "HTTP_HHS_SAMACCOUNTNAME",
    "HTTP_HOST",
    "HTTP_IF_MATCH",
    "HTTP_IF_MODIFIED_SINCE",
    "HTTP_IF_NONE_MATCH",
    "HTTP_IF_RANGE",
    "HTTP_IF_UNMODIFIED_SINCE",
    "HTTP_LDAP_ALL_HHSID",
    "HTTP_MAX_FORWARDS",
    "HTTP_ORIGIN",
    "HTTP_PRAGMA",
    "HTTP_PROXY_AUTHORIZATION",
    "HTTP_RANGE",
    "HTTP_REFERER",
    "HTTP_SM_AUTHDIROID",
    "HTTP_SM_AUTHDIRNAME",
    "HTTP_SM_AUTHDIRNAMESPACE",
    "HTTP_SM_AUTHDIRSERVER",
    "HTTP_SM_AUTHREASON",
    "HTTP_SM_AUTHTYPE",
    "HTTP_SM_REALM",
    "HTTP_SM_REALMOID",
    "HTTP_SM_SDOMAIN",
    "HTTP_SM_SERVERIDENTITYSPEC",
    "HTTP_SM_SERVERSESSIONID",
    "HTTP_SM_SERVERSESSIONSPEC",
    "HTTP_SM_SESSIONDRIFT",
    "HTTP_SM_TIMETOEXPIRE",
    "HTTP_SM_TRANSACTIONID",
    "HTTP_SM_UNIVERSALID",
    "HTTP_SM_USER",
    "HTTP_SM_USERDN",
    "HTTP_SP_USER",
    "HTTP_TE",
    "HTTP_USER_AGENT",
    "HTTP_USER_AUTH_LEVEL",
    "HTTP_USER_AUTH_TYPE",
    "HTTP_USER_AUTHN_LOA",
    "HTTP_USER_AUTHN_SOURCE",
    "HTTP_USER_EMAIL",
    "HTTP_USER_FIRSTNAME",
    "HTTP_USER_LASTNAME",
    "HTTP_USER_LOA",
    "HTTP_USER_ORG",
    "HTTP_USER_TELEPHONE",
    "HTTP_USER_UPN",
    "HTTP_UPGRADE",
    "HTTP_VIA",
    "HTTP_WARNING",
    "HTTP_X_FORWARDED_FOR",
    "HTTP_X_FORWARDED_HOST",
    "HTTP_X_FORWARDED_SERVER",
    "HTTP_X_FORWARDED_URI",
    "HTTP_X_FWD_IP_ADDR",
    "HTTPS",
    "PATH",
    "PATH_INFO",
    "PATH_TRANSLATED",
    "QUERY_STRING",
    "REMOTE_ADDR",
    "REMOTE_HOST",
    "REMOTE_IDENT",
    "REMOTE_PORT",
    "REMOTE_USER",
    "REQUEST_METHOD",
    "REQUEST_URI",
    "SCRIPT_FILENAME",
    "SCRIPT_NAME",
    "SCRIPT_URL",
    "SCRIPT_URI",
    "SERVER_ADDR",
    "SERVER_ADMIN",
    "SERVER_NAME",
    "SERVER_PORT",
    "SERVER_PROTOCOL",
    "SERVER_SIGNATURE",
    "SERVER_SOFTWARE"
};

static void sBreak()
{
    struct _stat st;
    while(!_stat(".cgi_log.brk", &st))
        Sleep(1000);
}

static void errorExit(const char* message)
{
    /*TODO: add logging*/
    exit(EXIT_FAILURE);
}

static BOOL stringStartsWithIgnoreCase(LPCSTR s, SIZE_T s_len, LPCSTR start)
{
    SIZE_T i;
    BOOL ret = TRUE;
    for( i = 0; *start && i < s_len; ++i, ++start ) {
	ret &= (tolower(s[i]) == tolower(*start));
    }
    return ret;
}

LPCSTR getEnvironmentVariableDefinition(LPCSTR variable, LPCH envStrings)
{
    LPCSTR ret = 0;
    SIZE_T len;
    LPCH env;
    BOOL bStartsWith;

    for(env = envStrings; 0 != (len = strlen(env)); env += len + 1) {
        bStartsWith = stringStartsWithIgnoreCase(env, len, variable);
	if(bStartsWith && '=' == env[strlen(variable)]) {
	    ret = env;
	    break;
	}
    }
    return ret;
}

static void makeHandleUninheritable(HANDLE* handle)
{
    // Ensure the read handle to the pipe for STDOUT is not inherited.
    if( !SetHandleInformation(*handle, HANDLE_FLAG_INHERIT, 0) ) {
        errorExit("SetHandleInformation");
    }

    /*
    // For Windows version before 2000 there was not SetHandleInformation
    // So the solution was to create a duplicate uninheritable copy
    // of a handle and then close the original
    HANDLE process;
    HANDLE newHandle;
    process = GetCurrentProcess();
    if( !DuplicateHandle(process, *handle, process, &newHandle, 0, FALSE,
	DUPLICATE_SAME_ACCESS) )
    {
	errorExit("DupliateHandle");
    }
    if( !CloseHandle(*handle) ) {
	errorExit("CloseHandle");
    }
    *handle = newHandle;
    */
}

static void createChildProcess(const char* commandLine, HANDLE childStdinPipe,
    HANDLE childStdoutPipe, HANDLE childStderrPipe)
{
    PROCESS_INFORMATION processInformation = {0};
    STARTUPINFO startupInformation = {0};

    // Set up members of the STARTUPINFO structure.
    // This structure specifies the STDIN and STDOUT handles for redirection.
    startupInformation.cb = sizeof(STARTUPINFO);
    startupInformation.dwFlags = STARTF_USESTDHANDLES;
    startupInformation.hStdInput = childStdinPipe;
    startupInformation.hStdOutput = childStdoutPipe;
    startupInformation.hStdError = childStderrPipe;

    // Create the child process.
    if( !CreateProcess(NULL, (char*)commandLine, NULL, NULL, TRUE, 0, NULL,
	NULL, &startupInformation, &processInformation) )
    {
        errorExit("CreateProcess");
    }
    CloseHandle(processInformation.hProcess);
    CloseHandle(processInformation.hThread);
}

static void copyPipedInput(HANDLE out, HANDLE in, HANDLE log)
{
    BYTE buffer[BUFSIZE];
    DWORD bytesRead;
    DWORD bytesWritten;
    DWORD lastError;
    BOOL success;

    for (;;)
    {
	success = ReadFile(in, buffer, sizeof(buffer), &bytesRead, NULL);
	if( !success ){
	    if( ERROR_BROKEN_PIPE == (lastError = GetLastError()) ) {
		// If ReadFile returns FALSE and GetLastError returns ERROR_BROKEN_PIPE
		// it means there are no more bytes in the pipe and the sender has closed
		// its handle. That is indicator of the end of transmission.
		break;
	    }
	    else {
		errorExit("ReadFile");
	    }
	}
	if( 0 == bytesRead ) {
	    // If ReadFile returned successfully but without data it also indicates
	    // the end of transmission.
	    break;
	}

	if( log != INVALID_HANDLE_VALUE ) {
	    WriteFile(log, buffer, bytesRead, &bytesWritten, NULL);
	}

	if( !WriteFile(out, buffer, bytesRead, &bytesWritten, NULL) ) {
	    if( ERROR_NO_DATA == (lastError = GetLastError()) ) {
		// If WriteFile returns FALSE and GetLastError returns ERROR_NO_DATA
		// it indicates that the pipe is closed.
		break;
	    }
	    else {
		errorExit("WriteFile");
	    }
	}
    }
}

static DWORD WINAPI senderThreadFunction(ThreadContext* ctx)
{
    if(INVALID_HANDLE_VALUE != ctx->out && INVALID_HANDLE_VALUE != ctx->in) {
	copyPipedInput(ctx->out, ctx->in, ctx->log);
    }
    if( INVALID_HANDLE_VALUE != ctx->out && !CloseHandle(ctx->out) ) {
	errorExit("CloseHandle");
    }
    if( INVALID_HANDLE_VALUE != ctx->log && !CloseHandle(ctx->log) ) {
	errorExit("CloseHandle");
    }
    return 1;
}

int main(int argc, char** argv)
{
    CHAR iniFilePath[MAX_PATH + 1];
    CHAR aux[MAX_PATH + 2];
    CHAR childCmdLine[MAX_CMD + 1];
    CHAR logBuffer[MAX_CMD*2 + 1];
    CHAR* childExe = aux;
    CHAR* logfilePath = aux;
    CHAR* logfilePathEnd;
    CHAR* logBufferEnd = logBuffer;
    LPSTR childCmdLineEnd;
    LPSTR dirNameEnd;
    LPSTR fileNameEnd;
    LPCSTR variableDefinition;
    LPCH envStrings;
    DWORD size;
    HANDLE childStdinReadPipe;
    HANDLE childStdinWritePipe;
    HANDLE childStdoutReadPipe;
    HANDLE childStdoutWritePipe;
    HANDLE childStderrReadPipe;
    HANDLE childStderrWritePipe;
    HANDLE currentStdin;
    HANDLE currentStdout;
    HANDLE currentStderr;
    HANDLE threads[THREAD_COUNT];
    HANDLE logFile;
    HANDLE stdinLogFile;
    HANDLE stdoutLogFile;
    SECURITY_ATTRIBUTES securityAttributes;
    ThreadContext senderStdinCtx;
    ThreadContext receiverStderrCtx;
    DWORD threadId;
    int i;

    sBreak();

    //GetModuleFileName(NULL, iniFilePath, sizeof iniFilePath);
    strcpy_s(iniFilePath, sizeof iniFilePath, argv[0]);
    dirNameEnd = PathFindFileName(iniFilePath);
    strncpy_s(childExe, sizeof aux, dirNameEnd, sizeof iniFilePath);
    strncat_s(childExe, sizeof aux, sExtensionExe, sizeof sExtensionExe);
    // iniFilePath: replace extension with .ini
    fileNameEnd = PathFindExtension(dirNameEnd);
    memcpy(fileNameEnd, sExtensionIni, sizeof sExtensionIni);

    // Get child process command line
    size = GetPrivateProfileString(sIniSectionName,
	sIniKeyApplication, childExe, childExe, sizeof aux, iniFilePath);
    if(size == sizeof aux - 1) {
	errorExit("Too long child exe path");
    }
    memcpy(childCmdLine, iniFilePath, dirNameEnd-iniFilePath);
    childCmdLineEnd = childCmdLine + (dirNameEnd-iniFilePath);
    memcpy(childCmdLineEnd, childExe, size);
    childCmdLineEnd += size;

    for(i = 1; i < argc; ++i) {
	size_t len;
	*childCmdLineEnd = ' ';
	++childCmdLineEnd;
	len = strlen(argv[i]);
	memcpy(childCmdLineEnd, argv[i], len);
	childCmdLineEnd += len;
    }
    *childCmdLineEnd = 0;

    // Get log file path
    memcpy(logfilePath, iniFilePath, dirNameEnd-iniFilePath);
    size = GetPrivateProfileString(sIniSectionName, sIniKeyLogfile,
	sIniDefaultLogfile, logfilePath + (dirNameEnd-iniFilePath),
	(DWORD)(sizeof aux - (dirNameEnd-iniFilePath)), iniFilePath);
    if( size == sizeof aux - (dirNameEnd-iniFilePath) - 1 ) {
	errorExit("Too long log file path");
    }
    logFile = CreateFile(logfilePath, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS,
	FILE_ATTRIBUTE_NORMAL, NULL);

    // Get environment variables
    envStrings = GetEnvironmentStrings();
    for( i = 0; i < sizeof sVariables / sizeof *sVariables; ++i ) {
	if( 0 != (variableDefinition
	    = getEnvironmentVariableDefinition(sVariables[i], envStrings)) )
	{
	    logBufferEnd += sprintf_s(logBufferEnd,
		logBuffer + sizeof logBuffer - logBufferEnd, "\x0d\x0aset %s", variableDefinition);
	}
    }
    FreeEnvironmentStrings(envStrings);

    // Get stdin logfile path
    size = GetPrivateProfileString(sIniSectionName, sIniLogdir,
	sIniDefaultLogdir, logfilePath + (dirNameEnd-iniFilePath),
	(DWORD)(sizeof aux - (dirNameEnd-iniFilePath)), iniFilePath);
    if( size == sizeof aux - (dirNameEnd-iniFilePath) - 1 ) {
	errorExit("Too long logdir path");
    }
    logfilePathEnd = logfilePath + size + (dirNameEnd-iniFilePath);
    *logfilePathEnd = '\\';
    ++logfilePathEnd;

    do {
	sprintf_s(logfilePathEnd, logfilePath + sizeof aux - logfilePathEnd, "%04x.in", rand());
	stdinLogFile = CreateFile(logfilePath, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW,
	    FILE_ATTRIBUTE_NORMAL, NULL);
    } while( INVALID_HANDLE_VALUE == stdinLogFile && ERROR_FILE_EXISTS == GetLastError() );
    if( INVALID_HANDLE_VALUE == stdinLogFile ) {
	errorExit("Cannot create stdin log file");
    }
    logfilePathEnd += 5;

    sprintf_s(logfilePathEnd, logfilePath + sizeof aux - logfilePathEnd, "out");
    stdoutLogFile = CreateFile(logfilePath, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW,
	FILE_ATTRIBUTE_NORMAL, NULL);
    if( INVALID_HANDLE_VALUE == stdoutLogFile ) {
	errorExit("Cannot create stdin log file");
    }

    logBufferEnd += sprintf_s(logBufferEnd, logBuffer + sizeof logBuffer - logBufferEnd,
	"\x0d\x0a\x0d\x0a%s <%s\x0d\x0a", childCmdLine, logfilePath);
    WriteFile(logFile, logBuffer, (DWORD)(logBufferEnd - logBuffer), &size, NULL);

    // Set the bInheritHandle flag so pipe handles are inherited.
    securityAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
    securityAttributes.bInheritHandle = TRUE;
    securityAttributes.lpSecurityDescriptor = NULL;

    // Create a pipe for the child process's STDIN, STDOUT and STDERR.
    if( !CreatePipe(&childStdinReadPipe, &childStdinWritePipe, &securityAttributes, 0) ) {
        errorExit("Stdin CreatePipe");
    }
    if( !CreatePipe(&childStdoutReadPipe, &childStdoutWritePipe, &securityAttributes, 0) ) {
        errorExit("StdoutRd CreatePipe");
    }
    if( !CreatePipe(&childStderrReadPipe, &childStderrWritePipe, &securityAttributes, 0) ) {
        errorExit("StdoutRd CreatePipe");
    }

    makeHandleUninheritable(&childStdinWritePipe);
    makeHandleUninheritable(&childStdoutReadPipe);
    makeHandleUninheritable(&childStderrReadPipe);

    if(INVALID_HANDLE_VALUE == (currentStdin = GetStdHandle(STD_INPUT_HANDLE))) {
        if( !CloseHandle(childStdinReadPipe) ) {
	    errorExit("CloseHandle");
	}
	childStdinReadPipe = INVALID_HANDLE_VALUE;
    }
    if(INVALID_HANDLE_VALUE == (currentStdout = GetStdHandle(STD_OUTPUT_HANDLE))) {
        if( !CloseHandle(childStdoutWritePipe) ) {
	    errorExit("CloseHandle");
	}
	childStdoutWritePipe = INVALID_HANDLE_VALUE;
    }
    if(INVALID_HANDLE_VALUE == (currentStderr = GetStdHandle(STD_ERROR_HANDLE))) {
        if( !CloseHandle(childStderrWritePipe) ) {
	    errorExit("CloseHandle");
	}
	childStderrWritePipe = INVALID_HANDLE_VALUE;
    }

    // Create the child process.
    createChildProcess(childCmdLine, childStdinReadPipe,
	childStdoutWritePipe, childStderrWritePipe);

    if( INVALID_HANDLE_VALUE != childStdinReadPipe && !CloseHandle(childStdinReadPipe) ) errorExit("CloseHandle");
    if( INVALID_HANDLE_VALUE != childStdoutWritePipe && !CloseHandle(childStdoutWritePipe) ) errorExit("CloseHandle");
    if( INVALID_HANDLE_VALUE != childStderrWritePipe && !CloseHandle(childStderrWritePipe) ) errorExit("CloseHandle");

    senderStdinCtx.log = stdinLogFile;
    senderStdinCtx.in = currentStdin;
    senderStdinCtx.out = childStdinWritePipe;
    threads[0] = CreateThread(NULL, 0, senderThreadFunction,
	&senderStdinCtx, 0, &threadId);
    if( !threads[0] ) {
	errorExit("CreateThread");
    }

    receiverStderrCtx.log = INVALID_HANDLE_VALUE;
    receiverStderrCtx.in = childStderrReadPipe;
    receiverStderrCtx.out = currentStderr;
    threads[1] = CreateThread(NULL, 0, senderThreadFunction,
	&receiverStderrCtx, 0, &threadId);
    if( !threads[1] ) {
	errorExit("CreateThread");
    }

    copyPipedInput(currentStdout, childStdoutReadPipe, stdoutLogFile);

    if( WAIT_FAILED == WaitForMultipleObjects(THREAD_COUNT, threads, TRUE, INFINITE) ) {
	errorExit("WaitForSingleObject");
    }

    if( !CloseHandle(childStdoutReadPipe) ) {
	errorExit("CloseHandle");
    }
    if( !CloseHandle(stdoutLogFile) ) {
	errorExit("CloseHandle");
    }
    if( !CloseHandle(logFile) ) {
	errorExit("CloseHandle");
    }

    return EXIT_SUCCESS;
}
