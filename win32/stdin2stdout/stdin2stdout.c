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
#include <string.h>

#define BUFSIZE 4096
#define STDERRBUFSIZE 256

static const char sStartMessage[] = "-----BEGIN TRANSMISSION-----\n";
static const char sFinishMessage[] = "-----END TRANSMISSION-----\n";
static const char sStderrMessage[] = "%Id bytes copied\n";

int main(int argc, char** argv)
{
    BYTE buffer[BUFSIZE];
    HANDLE stdinHandle;
    HANDLE stdoutHandle;
    HANDLE stderrHandle;
    SIZE_T bytesCopied;
    DWORD bytesRead;
    DWORD bytesWritten;
    BOOL success;
    BOOL verbose;

    verbose = (2 <= argc && 0 == strcmp(argv[1], "-v"));

    stdinHandle = GetStdHandle(STD_INPUT_HANDLE);
    stdoutHandle = GetStdHandle(STD_OUTPUT_HANDLE);
    stderrHandle = GetStdHandle(STD_ERROR_HANDLE);

    if( INVALID_HANDLE_VALUE == stdinHandle || INVALID_HANDLE_VALUE == stdoutHandle
	|| INVALID_HANDLE_VALUE == stderrHandle)
    {
	exit(EXIT_FAILURE);
    }

    if( verbose ) {
	WriteFile(stdoutHandle, sStartMessage, sizeof(sStartMessage)-1, &bytesWritten, NULL);
    }

    for( bytesCopied = 0;; bytesCopied += bytesWritten )
    {
	// Read from STDIN. Stop on error or no data which means EOF.
	success = ReadFile(stdinHandle, buffer, BUFSIZE, &bytesRead, NULL);

	if( !success ) {
	    if( ERROR_BROKEN_PIPE == GetLastError() ) {
		// If ReadFile returns FALSE and GetLastError returns ERROR_BROKEN_PIPE
		// it means there are no more bytes in the pipe and the sender has closed
		// its handle. That is indicator of the end of the transmission.
		break;
	    }
	    else {
		Sleep(1000);
		continue;
	    }
	}
	else if( 0 == bytesRead ) {
	    // success and 0 == bytesRead means EOF
	    break;
	}

	success = WriteFile(stdoutHandle, buffer, bytesRead, &bytesWritten, NULL);

	if( !success ) {
	    break;
	}
    }

    if( verbose ) {
	char stderrBuffer[STDERRBUFSIZE];
	int stderrBytes;
	WriteFile(stdoutHandle, sFinishMessage, sizeof(sFinishMessage)-1, &bytesWritten, NULL);
	stderrBytes = sprintf_s(stderrBuffer, sizeof stderrBuffer, sStderrMessage, bytesCopied);
	WriteFile(stderrHandle, stderrBuffer, stderrBytes, &bytesWritten, NULL);
    }

    return EXIT_SUCCESS;
}
