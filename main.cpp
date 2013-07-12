/******************************************************************************
Copyright (c) 2013, Florian Wininger, Etienne Bergeron
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
	* Redistributions of source code must retain the above copyright
	  notice, this list of conditions and the following disclaimer.
	* Redistributions in binary form must reproduce the above copyright
	  notice, this list of conditions and the following disclaimer in the
	  documentation and/or other materials provided with the distribution.
	* Neither the name of the <organization> nor the
	  names of its contributors may be used to endorse or promote products
	  derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
******************************************************************************/

#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>

#define INITGUID
#include <guiddef.h>
#include <evntcons.h>
#include <tdh.h>

#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <vector>

#include "Event.h"
#include "EventsList.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "tdh.lib")

//
// ETW-CTF converter GUID: Specify to CTF consumer that source come from ETW.
//
DEFINE_GUID ( /* 29cb3580-13c6-4c85-a4cb-a2c0ffa68890 */
	ETWConverterGuid,
	0x29CB3580,
	0x13C6,
	0x4C85,
	0xA4, 0xCB, 0xA2, 0xC0, 0xFF, 0xA6, 0x88, 0x90
	);


#define MAX_GUID_STRING_LENGTH 38
#define MAX_NAME 256

namespace {

	void WINAPI ProcessEvent(PEVENT_RECORD pEvent);
	DWORD GetEventInformation(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO & pInfo);
	DWORD PrintProperties(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, LPWSTR pStructureName, USHORT StructIndex);
	void PrintMapString(PEVENT_MAP_INFO pMapInfo, PBYTE pData);
	DWORD GetArraySize(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, PUSHORT ArraySize);
	DWORD GetMapInfo(PEVENT_RECORD pEvent, LPWSTR pMapName, DWORD DecodingSource, PEVENT_MAP_INFO & pMapInfo);
	void RemoveTrailingSpace(PEVENT_MAP_INFO pMapInfo);

	EVENT_TRACE_LOGFILE trace;
	FILE* stream = NULL;
	FILE* metadata = NULL;

	EventsList* eventslist = NULL;

	// Used to determine the data size of property values that contain a
	// Pointer value. The value will be 4 or 8.
	USHORT g_PointerSize = 0;

	/* Write 1 Byte value */
	void WriteUInt8(uint8_t value) {
		fwrite(&value, sizeof(uint8_t), 1, stream);
	}

	/* Write 2 Bytes value */
	void WriteUInt16(uint16_t value) {
		fwrite(&value, sizeof(uint16_t), 1, stream);
	}

	/* Write 4 Bytes value */
	void WriteUInt32(uint32_t value) {
		fwrite(&value, sizeof(uint32_t), 1, stream);
	}

	/* Write 8 Bytes value */
	void WriteUInt64(uint64_t value) {
		fwrite(&value, sizeof(uint64_t), 1, stream);
	}

	/* Write 8 Bytes value */
	void WriteUInt64(LARGE_INTEGER value) {
		WriteUInt32(value.LowPart);
		WriteUInt32(value.HighPart);
	}

	/* Write N Bytes value */
	void WriteBytes(uint8_t* value, size_t len) {
		fwrite(value, sizeof(uint8_t), len, stream);
	}

	/* Write GUID */
	void WriteGUID(GUID guid) {
		// TODO(etienneb) : Validate babeltrace / eclipse
		// it seem babeltrace parse raw byte, not endianness.
		// see: http://en.wikipedia.org/wiki/Globally_unique_identifier
		// I think UUID are big endian, but MS GUID are native.
#if 0
		WriteUInt32(guid.Data1);
		WriteUInt16(guid.Data2);
		WriteUInt16(guid.Data3);
		WriteBytes(guid.Data4, 8);
#else
		WriteUInt8(static_cast<uint8_t>(guid.Data1 >> 24));
		WriteUInt8(static_cast<uint8_t>(guid.Data1 >> 16));
		WriteUInt8(static_cast<uint8_t>(guid.Data1 >> 8));
		WriteUInt8(static_cast<uint8_t>(guid.Data1));

		WriteUInt8(static_cast<uint8_t>(guid.Data2 >> 8));
		WriteUInt8(static_cast<uint8_t>(guid.Data2));

		WriteUInt8(static_cast<uint8_t>(guid.Data3 >> 8));
		WriteUInt8(static_cast<uint8_t>(guid.Data3));

		WriteBytes(guid.Data4, 8);
#endif
	}

	void WritePacketHeader() {
		// Output trace.header.magic.
		WriteUInt32(0xC1FC1FC1);

		// Output trace.header.uuid.
		WriteGUID(ETWConverterGuid);
	}

	void WritePacketContext(PEVENT_TRACE_LOGFILE pTrace) {
		// Output trace.context.timestamp_begin/end.
		WriteUInt64(pTrace->LogfileHeader.StartTime);
		WriteUInt64(pTrace->LogfileHeader.EndTime);
	}

	/* Convert wstring with \null character to a standard string */
	// TODO : buffer overflow fix
	void convertString(char* o_buffer, LPWSTR i_string, int length = -1)
	{
		int i = 0 ;
		while(i_string[i] != L'\0')
		{
			o_buffer[i] = i_string[i];
			i++;

			if(length !=-1 && i >= length)
				break;
		}
		o_buffer[i] = '\0';
	}

	void WriteEvent(PEVENT_RECORD pEvent) {
		DWORD status = ERROR_SUCCESS;
		PTRACE_EVENT_INFO pInfo = NULL;
		LPWSTR pwsEventGuid = NULL;
		//    ULONGLONG TimeStamp = 0;
		//    ULONGLONG Nanoseconds = 0;
		//    SYSTEMTIME st;
		//    SYSTEMTIME stLocal;
		//    FILETIME ft;

		// Process the event. The pEvent->UserData member is a pointer to
		// the event specific data, if it exists.
		status = GetEventInformation(pEvent, pInfo);

		if (ERROR_SUCCESS != status) {
			wprintf(L"GetEventInformation failed with %lu\n", status);
			goto cleanup;
		}

		// Determine whether the event is defined by a MOF class, in an
		// instrumentation manifest, or a WPP template; to use TDH to decode
		// the event, it must be defined by one of these three sources.

		if (DecodingSourceWbem == pInfo->DecodingSource)  // MOF class
		{
			HRESULT hr = StringFromCLSID(pInfo->EventGuid, &pwsEventGuid);

			if (FAILED(hr))
			{
				wprintf(L"StringFromCLSID failed with 0x%x\n", hr);
				status = hr;
				goto cleanup;
			}

			//        wprintf(L"\nEvent GUID: %s\n", pwsEventGuid);
			CoTaskMemFree(pwsEventGuid);
			pwsEventGuid = NULL;

			//        wprintf(L"Event version: %d\n", pEvent->EventHeader.EventDescriptor.Version);
			//        wprintf(L"Event type: %d\n", pEvent->EventHeader.EventDescriptor.Opcode);
		}
		else if (DecodingSourceXMLFile == pInfo->DecodingSource) // Instrumentation manifest
		{
			//        wprintf(L"Event ID: %d\n", pInfo->EventDescriptor.Id);
		}
		else // Not handling the WPP case
		{
			goto cleanup;
		}

		// Print the time stamp for when the event occurred.
		/*
		ft.dwHighDateTime = pEvent->EventHeader.TimeStamp.HighPart;
		ft.dwLowDateTime = pEvent->EventHeader.TimeStamp.LowPart;

		FileTimeToSystemTime(&ft, &st);
		SystemTimeToTzSpecificLocalTime(NULL, &st, &stLocal);

		TimeStamp = pEvent->EventHeader.TimeStamp.QuadPart;
		Nanoseconds = (TimeStamp % 10000000) * 100;

		wprintf(L"%02d/%02d/%02d %02d:%02d:%02d.%I64u\n", 
		stLocal.wMonth, stLocal.wDay, stLocal.wYear, stLocal.wHour, stLocal.wMinute, stLocal.wSecond, Nanoseconds);
		*/
		// If the event contains event-specific data use TDH to extract
		// the event data. For this example, to extract the data, the event 
		// must be defined by a MOF class or an instrumentation manifest.

		// Need to get the PointerSize for each event to cover the case where you are
		// consuming events from multiple log files that could have been generated on 
		// different architectures. Otherwise, you could have accessed the pointer
		// size when you opened the trace above (see pHeader->PointerSize).

		if (EVENT_HEADER_FLAG_32_BIT_HEADER == (pEvent->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER)) {
			g_PointerSize = 4;
		}
		else {
			g_PointerSize = 8;
		}

		// Print the event data for all the top-level properties. Metadata for all the
		// top-level properties come before structure member properties in the
		// property information array. If the EVENT_HEADER_FLAG_STRING_ONLY flag is set,
		// the event data is a null-terminated string, so just print it.

		if (EVENT_HEADER_FLAG_STRING_ONLY == (pEvent->EventHeader.Flags & EVENT_HEADER_FLAG_STRING_ONLY))
		{
			wprintf(L"ERROR EVENT HEADER FLAG STRING ONLY\n");
			wprintf(L"%s\n", (LPWSTR)pEvent->UserData);
		}
		else
		{
			for (USHORT i = 0; i < pInfo->TopLevelPropertyCount; i++)
			{
				status = PrintProperties(pEvent, pInfo, i, NULL, 0);
				if (ERROR_SUCCESS != status)
				{
					wprintf(L"Printing top level properties failed.\n");
					goto cleanup;
				}
			}
		}

cleanup:

		if (pInfo)
		{
			free(pInfo);
		}

	}

	// Print the property.

	DWORD FormatAndPrintData(PEVENT_RECORD pEvent, USHORT InType, USHORT OutType, PBYTE pData, DWORD DataSize, PEVENT_MAP_INFO pMapInfo)
	{
		UNREFERENCED_PARAMETER(pEvent);

		DWORD status = ERROR_SUCCESS;

		switch (InType)
		{
		case TDH_INTYPE_UNICODESTRING:
		case TDH_INTYPE_COUNTEDSTRING:
		case TDH_INTYPE_REVERSEDCOUNTEDSTRING:
		case TDH_INTYPE_NONNULLTERMINATEDSTRING:
			{
				size_t StringLength = 0;

				if (TDH_INTYPE_COUNTEDSTRING == InType)
				{
					StringLength = *(PUSHORT)pData;
				}
				else if (TDH_INTYPE_REVERSEDCOUNTEDSTRING == InType)
				{
					StringLength = MAKEWORD(HIBYTE((PUSHORT)pData), LOBYTE((PUSHORT)pData));
				}
				else if (TDH_INTYPE_NONNULLTERMINATEDSTRING == InType)
				{
					StringLength = DataSize;
				}
				else
				{
					StringLength = wcslen((LPWSTR)pData);
				}

				char* buffer = new char[StringLength+1];
				convertString(buffer,(LPWSTR)pData,StringLength);
				WriteBytes((uint8_t*)buffer,StringLength+1); // +1 for the \0
				delete buffer;
				break;
			}
		case TDH_INTYPE_ANSISTRING:
		case TDH_INTYPE_COUNTEDANSISTRING:
		case TDH_INTYPE_REVERSEDCOUNTEDANSISTRING:
		case TDH_INTYPE_NONNULLTERMINATEDANSISTRING:
			{
				size_t StringLength = 0;

				if (TDH_INTYPE_COUNTEDANSISTRING == InType)
				{
					StringLength = *(PUSHORT)pData;
				}
				else if (TDH_INTYPE_REVERSEDCOUNTEDANSISTRING == InType)
				{
					StringLength = MAKEWORD(HIBYTE((PUSHORT)pData), LOBYTE((PUSHORT)pData));
				}
				else if (TDH_INTYPE_NONNULLTERMINATEDANSISTRING == InType)
				{
					StringLength = DataSize;
				}
				else
				{
					StringLength = strlen((LPSTR)pData);
				}

				WriteBytes((uint8_t*)pData,StringLength+1); // +1 for the \0
				break;
			}
		case TDH_INTYPE_INT8:
			WriteUInt8(*(PCHAR)pData);
			break;
		case TDH_INTYPE_UINT8:
			WriteUInt8(*(PBYTE)pData);
			break;
		case TDH_INTYPE_INT16:
			WriteUInt16(*(PSHORT)pData);
			break;
		case TDH_INTYPE_UINT16:
			WriteUInt16(*(PUSHORT)pData);
			break;
		case TDH_INTYPE_INT32:
			WriteUInt32(*(PLONG)pData);
			break;
		case TDH_INTYPE_UINT32:
			{
				if (pMapInfo)
				{
					//TODO : FIXE THE MAPINFO ?
					wprintf(L"ERROR TDH_INTYPE_UINT32 PMAPINFO\n");
					//PrintMapString(pMapInfo, pData);
				}
				else {
					WriteUInt32(*(PULONG)pData);
				}
				break;
			}
		case TDH_INTYPE_INT64:
			WriteUInt64(*(PLONGLONG)pData);
			break;
		case TDH_INTYPE_UINT64:
			WriteUInt64(*(PULONGLONG)pData);
			break;
		case TDH_INTYPE_FLOAT:
			wprintf(L"ERROR TDH_INTYPE_FLOAT : %f\n", *(PFLOAT)pData);
			break;
		case TDH_INTYPE_DOUBLE:
			wprintf(L"ERROR TDH_INTYPE_DOUBLE : %I64f\n", *(DOUBLE*)pData);
			break;
		case TDH_INTYPE_BOOLEAN:
			wprintf(L"ERROR TDH_INTYPE_BOOLEAN : %s\n", (0 == (PBOOL)pData) ? L"false" : L"true");
			break;
		case TDH_INTYPE_BINARY:
			{
				wprintf(L"TDH_INTYPE_BINARY\n");
				break;

				/*            if (TDH_OUTTYPE_IPV6 == OutType)
				{
				WCHAR IPv6AddressAsString[46];
				PIPV6ADDRTOSTRING fnRtlIpv6AddressToString;

				fnRtlIpv6AddressToString = (PIPV6ADDRTOSTRING)GetProcAddress(
				GetModuleHandle(L"ntdll"), "RtlIpv6AddressToStringW");

				if (NULL == fnRtlIpv6AddressToString)
				{
				wprintf(L"GetProcAddress failed with %lu.\n", status = GetLastError());
				goto cleanup;
				}

				fnRtlIpv6AddressToString((IN6_ADDR*)pData, IPv6AddressAsString);

				wprintf(L"%s\n", IPv6AddressAsString);
				}
				else
				{
				for (DWORD i = 0; i < DataSize; i++)
				{
				wprintf(L"%.2x", pData[i]);
				}

				wprintf(L"\n");
				}

				break;*/
			}
		case TDH_INTYPE_GUID:
			WriteGUID(*(GUID*)pData);
			break;
		case TDH_INTYPE_POINTER:
		case TDH_INTYPE_SIZET:
			{
				if (4 == g_PointerSize)
				{
					//wprintf(L"0x%x\n", *(PULONG)pData);
					WriteUInt32(*(PULONG)pData);
				}
				else
				{
					//wprintf(L"0x%x\n", *(PULONGLONG)pData);
					WriteUInt64(*(PULONGLONG)pData);
				}

				break;
			}
		case TDH_INTYPE_FILETIME:
			break;
		case TDH_INTYPE_SYSTEMTIME:
			break;
		case TDH_INTYPE_SID:
			{
				wprintf(L"ERROR TDH_INTYPE_SID\n");
				break ;

				/* WCHAR UserName[MAX_NAME];
				WCHAR DomainName[MAX_NAME];
				DWORD cchUserSize = MAX_NAME;
				DWORD cchDomainSize = MAX_NAME;
				SID_NAME_USE eNameUse;

				if (!LookupAccountSid(NULL, (PSID)pData, UserName, &cchUserSize, DomainName, &cchDomainSize, &eNameUse))
				{
				if (ERROR_NONE_MAPPED == status)
				{
				wprintf(L"Unable to locate account for the specified SID\n");
				status = ERROR_SUCCESS;
				}
				else
				{
				wprintf(L"LookupAccountSid failed with %lu\n", status = GetLastError());
				}

				goto cleanup;
				}
				else
				{
				wprintf(L"%s\\%s\n", DomainName, UserName);
				}
				break;*/
			}
		case TDH_INTYPE_HEXINT32:
			WriteUInt32(*(PULONG)pData);
			break;
		case TDH_INTYPE_HEXINT64:
			WriteUInt64(*(PULONGLONG)pData);
			break;
		case TDH_INTYPE_UNICODECHAR:
			WriteUInt8(*(PWCHAR)pData);
			break;
		case TDH_INTYPE_ANSICHAR:
			WriteUInt8(*(PCHAR)pData);
			break;
		case TDH_INTYPE_WBEMSID:
			{
				//wprintf(L"ERROR TDH_INTYPE_WBEMSID\n");
				//break ;

				WCHAR UserName[MAX_NAME];
				WCHAR DomainName[MAX_NAME];
				DWORD cchUserSize = MAX_NAME;
				DWORD cchDomainSize = MAX_NAME;
				SID_NAME_USE eNameUse;

				if ((PULONG)pData > 0)
				{
					// A WBEM SID is actually a TOKEN_USER structure followed
					// by the SID. The size of the TOKEN_USER structure differs
					// depending on whether the events were generated on a 32-bit
					// or 64-bit architecture. Also the structure is aligned
					// on an 8-byte boundary, so its size is 8 bytes on a
					// 32-bit computer and 16 bytes on a 64-bit computer.
					// Doubling the pointer size handles both cases.

					pData += g_PointerSize * 2;

					if (!LookupAccountSid(NULL, (PSID)pData, UserName, &cchUserSize, DomainName, &cchDomainSize, &eNameUse))
					{
						if (ERROR_NONE_MAPPED == status)
						{
							wprintf(L"Unable to locate account for the specified SID\n");
							status = ERROR_SUCCESS;
						}
						else
						{
							wprintf(L"LookupAccountSid failed with %lu\n", status = GetLastError());
						}

						goto cleanup;
					}
					else
					{
						//wprintf(L"%s\\%s\n", DomainName, UserName);
						char* buffer = new char[MAX_NAME*2];

						int i = 0, j = 0;
						while (DomainName[i] != L'\0')
						{
							buffer[i] = DomainName[i] ;
							i++;
						}
						buffer[i] = '\\';
						i++;
						while (UserName[j] != L'\0')
						{
							buffer[i + j] = UserName[j];
							j++ ;
						}
						buffer[i+j] = '\0';

						WriteBytes((uint8_t*)buffer, i + j + 1);
						delete buffer;
					}
				}
				break;
			}

		default:
			status = ERROR_NOT_FOUND;
		}

cleanup:

		return status;
	}

	DWORD PrintProperties(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, LPWSTR pStructureName, USHORT StructIndex)
	{
		DWORD status = ERROR_SUCCESS;
		DWORD LastMember = 0;  // Last member of a structure
		USHORT ArraySize = 0;
		PEVENT_MAP_INFO pMapInfo = NULL;
		PROPERTY_DATA_DESCRIPTOR DataDescriptors[2];
		ULONG DescriptorsCount = 0;
		DWORD PropertySize = 0;
		PBYTE pData = NULL;

		// Get the size of the array if the property is an array.
		status = GetArraySize(pEvent, pInfo, i, &ArraySize);

		for (USHORT k = 0; k < ArraySize; k++)
		{
			//wprintf(L"%*s%s: ", (pStructureName) ? 4 : 0, L"", (LPWSTR)((PBYTE)(pInfo) + pInfo->EventPropertyInfoArray[i].NameOffset));

			// If the property is a structure, print the members of the structure.
			if ((pInfo->EventPropertyInfoArray[i].Flags & PropertyStruct) == PropertyStruct)
			{
				wprintf(L"\n");

				LastMember = pInfo->EventPropertyInfoArray[i].structType.StructStartIndex +
					pInfo->EventPropertyInfoArray[i].structType.NumOfStructMembers;

				for (USHORT j = pInfo->EventPropertyInfoArray[i].structType.StructStartIndex; j < LastMember; j++)
				{
					status = PrintProperties(pEvent, pInfo, j, (LPWSTR)((PBYTE)(pInfo) + pInfo->EventPropertyInfoArray[i].NameOffset), k);
					if (ERROR_SUCCESS != status)
					{
						wprintf(L"Printing the members of the structure failed.\n");
						goto cleanup;
					}
				}
			}
			else
			{
				ZeroMemory(&DataDescriptors, sizeof(DataDescriptors));

				// To retrieve a member of a structure, you need to specify an array of descriptors.
				// The first descriptor in the array identifies the name of the structure and the second
				// descriptor defines the member of the structure whose data you want to retrieve.

				if (pStructureName)
				{
					DataDescriptors[0].PropertyName = (ULONGLONG)pStructureName;
					DataDescriptors[0].ArrayIndex = StructIndex;
					DataDescriptors[1].PropertyName = (ULONGLONG)((PBYTE)(pInfo) + pInfo->EventPropertyInfoArray[i].NameOffset);
					DataDescriptors[1].ArrayIndex = k;
					DescriptorsCount = 2;
				}
				else
				{
					DataDescriptors[0].PropertyName = (ULONGLONG)((PBYTE)(pInfo) + pInfo->EventPropertyInfoArray[i].NameOffset);
					DataDescriptors[0].ArrayIndex = k;
					DescriptorsCount = 1;
				}

				// The TDH API does not support IPv6 addresses. If the output type is TDH_OUTTYPE_IPV6,
				// you will not be able to consume the rest of the event. If you try to consume the
				// remainder of the event, you will get ERROR_EVT_INVALID_EVENT_DATA.

				if (TDH_INTYPE_BINARY == pInfo->EventPropertyInfoArray[i].nonStructType.InType &&
					TDH_OUTTYPE_IPV6 == pInfo->EventPropertyInfoArray[i].nonStructType.OutType)
				{
					wprintf(L"The event contains an IPv6 address. Skipping event.\n");
					status = ERROR_EVT_INVALID_EVENT_DATA;
					break;
				}
				else
				{
					status = TdhGetPropertySize(pEvent, 0, NULL, DescriptorsCount, &DataDescriptors[0], &PropertySize);

					if (ERROR_SUCCESS != status)
					{
						wprintf(L"TdhGetPropertySize failed with %lu\n", status);
						goto cleanup;
					}

					pData = (PBYTE)malloc(PropertySize);

					if (NULL == pData)
					{
						wprintf(L"Failed to allocate memory for property data\n");
						status = ERROR_OUTOFMEMORY;
						goto cleanup;
					}

					status = TdhGetProperty(pEvent, 0, NULL, DescriptorsCount, &DataDescriptors[0], PropertySize, pData);

					// Get the name/value mapping if the property specifies a value map.

					status = GetMapInfo(pEvent,
						(PWCHAR)((PBYTE)(pInfo) + pInfo->EventPropertyInfoArray[i].nonStructType.MapNameOffset),
						pInfo->DecodingSource,
						pMapInfo);

					if (ERROR_SUCCESS != status)
					{
						wprintf(L"GetMapInfo failed\n");
						goto cleanup;
					}

					status = FormatAndPrintData(pEvent,
						pInfo->EventPropertyInfoArray[i].nonStructType.InType,
						pInfo->EventPropertyInfoArray[i].nonStructType.OutType,
						pData,
						PropertySize,
						pMapInfo
						);

					if (ERROR_SUCCESS != status)
					{
						wprintf(L"GetMapInfo failed\n");
						goto cleanup;
					}

					if (pData)
					{
						free(pData);
						pData = NULL;
					}

					if (pMapInfo)
					{
						free(pMapInfo);
						pMapInfo = NULL;
					}
				}
			}
		}

cleanup:

		if (pData)
		{
			free(pData);
			pData = NULL;
		}

		if (pMapInfo)
		{
			free(pMapInfo);
			pMapInfo = NULL;
		}

		return status;
	}


	void PrintMapString(PEVENT_MAP_INFO pMapInfo, PBYTE pData)
	{
		BOOL MatchFound = FALSE;

		if ((pMapInfo->Flag & EVENTMAP_INFO_FLAG_MANIFEST_VALUEMAP) == EVENTMAP_INFO_FLAG_MANIFEST_VALUEMAP ||
			((pMapInfo->Flag & EVENTMAP_INFO_FLAG_WBEM_VALUEMAP) == EVENTMAP_INFO_FLAG_WBEM_VALUEMAP &&
			(pMapInfo->Flag & (~EVENTMAP_INFO_FLAG_WBEM_VALUEMAP)) != EVENTMAP_INFO_FLAG_WBEM_FLAG))
		{
			if ((pMapInfo->Flag & EVENTMAP_INFO_FLAG_WBEM_NO_MAP) == EVENTMAP_INFO_FLAG_WBEM_NO_MAP)
			{
				wprintf(L"%s\n", (LPWSTR)((PBYTE)pMapInfo + pMapInfo->MapEntryArray[*(PULONG)pData].OutputOffset));
			}
			else
			{
				for (DWORD i = 0; i < pMapInfo->EntryCount; i++)
				{
					if (pMapInfo->MapEntryArray[i].Value == *(PULONG)pData)
					{
						wprintf(L"%s\n", (LPWSTR)((PBYTE)pMapInfo + pMapInfo->MapEntryArray[i].OutputOffset));
						MatchFound = TRUE;
						break;
					}
				}

				if (FALSE == MatchFound)
				{
					wprintf(L"%lu\n", *(PULONG)pData);
				}
			}
		}
		else if ((pMapInfo->Flag & EVENTMAP_INFO_FLAG_MANIFEST_BITMAP) == EVENTMAP_INFO_FLAG_MANIFEST_BITMAP ||
			(pMapInfo->Flag & EVENTMAP_INFO_FLAG_WBEM_BITMAP) == EVENTMAP_INFO_FLAG_WBEM_BITMAP ||
			((pMapInfo->Flag & EVENTMAP_INFO_FLAG_WBEM_VALUEMAP) == EVENTMAP_INFO_FLAG_WBEM_VALUEMAP &&
			(pMapInfo->Flag & (~EVENTMAP_INFO_FLAG_WBEM_VALUEMAP)) == EVENTMAP_INFO_FLAG_WBEM_FLAG))
		{
			if ((pMapInfo->Flag & EVENTMAP_INFO_FLAG_WBEM_NO_MAP) == EVENTMAP_INFO_FLAG_WBEM_NO_MAP)
			{
				DWORD BitPosition = 0;

				for (DWORD i = 0; i < pMapInfo->EntryCount; i++)
				{
					if ((*(PULONG)pData & (BitPosition = (1 << i))) == BitPosition)
					{
						wprintf(L"%s%s",
							(MatchFound) ? L" | " : L"",
							(LPWSTR)((PBYTE)pMapInfo + pMapInfo->MapEntryArray[i].OutputOffset));

						MatchFound = TRUE;
					}
				}

			}
			else
			{
				for (DWORD i = 0; i < pMapInfo->EntryCount; i++)
				{
					if ((pMapInfo->MapEntryArray[i].Value & *(PULONG)pData) == pMapInfo->MapEntryArray[i].Value)
					{
						wprintf(L"%s%s",
							(MatchFound) ? L" | " : L"",
							(LPWSTR)((PBYTE)pMapInfo + pMapInfo->MapEntryArray[i].OutputOffset));

						MatchFound = TRUE;
					}
				}
			}

			if (MatchFound)
			{
				wprintf(L"\n");
			}
			else
			{
				wprintf(L"%lu\n", *(PULONG)pData);
			}
		}
	}


	// Get the size of the array. For MOF-based events, the size is specified in the declaration or using
	// the MAX qualifier. For manifest-based events, the property can specify the size of the array
	// using the count attribute. The count attribute can specify the size directly or specify the name
	// of another property in the event data that contains the size.

	DWORD GetArraySize(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, USHORT i, PUSHORT ArraySize)
	{
		DWORD status = ERROR_SUCCESS;
		PROPERTY_DATA_DESCRIPTOR DataDescriptor;
		DWORD PropertySize = 0;

		if ((pInfo->EventPropertyInfoArray[i].Flags & PropertyParamCount) == PropertyParamCount)
		{
			DWORD Count = 0;  // Expects the count to be defined by a UINT16 or UINT32
			DWORD j = pInfo->EventPropertyInfoArray[i].countPropertyIndex;
			ZeroMemory(&DataDescriptor, sizeof(PROPERTY_DATA_DESCRIPTOR));
			DataDescriptor.PropertyName = (ULONGLONG)((PBYTE)(pInfo) + pInfo->EventPropertyInfoArray[j].NameOffset);
			DataDescriptor.ArrayIndex = ULONG_MAX;
			status = TdhGetPropertySize(pEvent, 0, NULL, 1, &DataDescriptor, &PropertySize);
			status = TdhGetProperty(pEvent, 0, NULL, 1, &DataDescriptor, PropertySize, (PBYTE)&Count);
			*ArraySize = (USHORT)Count;
		}
		else
		{
			*ArraySize = pInfo->EventPropertyInfoArray[i].count;
		}

		return status;
	}


	// Both MOF-based events and manifest-based events can specify name/value maps. The
	// map values can be integer values or bit values. If the property specifies a value
	// map, get the map.

	DWORD GetMapInfo(PEVENT_RECORD pEvent, LPWSTR pMapName, DWORD DecodingSource, PEVENT_MAP_INFO & pMapInfo)
	{
		DWORD status = ERROR_SUCCESS;
		DWORD MapSize = 0;

		// Retrieve the required buffer size for the map info.

		status = TdhGetEventMapInformation(pEvent, pMapName, pMapInfo, &MapSize);

		if (ERROR_INSUFFICIENT_BUFFER == status)
		{
			pMapInfo = (PEVENT_MAP_INFO) malloc(MapSize);
			if (pMapInfo == NULL)
			{
				wprintf(L"Failed to allocate memory for map info (size=%lu).\n", MapSize);
				status = ERROR_OUTOFMEMORY;
				goto cleanup;
			}

			// Retrieve the map info.

			status = TdhGetEventMapInformation(pEvent, pMapName, pMapInfo, &MapSize);
		}

		if (ERROR_SUCCESS == status)
		{
			if (DecodingSourceXMLFile == DecodingSource)
			{
				RemoveTrailingSpace(pMapInfo);
			}
		}
		else
		{
			if (ERROR_NOT_FOUND == status)
			{
				status = ERROR_SUCCESS; // This case is okay.
			}
			else
			{
				wprintf(L"TdhGetEventMapInformation failed with 0x%x.\n", status);
			}
		}

cleanup:

		return status;
	}

	// The mapped string values defined in a manifest will contain a trailing space
	// in the EVENT_MAP_ENTRY structure. Replace the trailing space with a null-
	// terminating character, so that the bit mapped strings are correctly formatted.

	void RemoveTrailingSpace(PEVENT_MAP_INFO pMapInfo)
	{
		SIZE_T ByteLength = 0;

		for (DWORD i = 0; i < pMapInfo->EntryCount; i++)
		{
			ByteLength = (wcslen((LPWSTR)((PBYTE)pMapInfo + pMapInfo->MapEntryArray[i].OutputOffset)) - 1) * 2;
			*((LPWSTR)((PBYTE)pMapInfo + (pMapInfo->MapEntryArray[i].OutputOffset + ByteLength))) = L'\0';
		}
	}


	// Get the metadata for the event.

	DWORD GetEventInformation(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO & pInfo)
	{
		DWORD status = ERROR_SUCCESS;
		DWORD BufferSize = 0;

		// Retrieve the required buffer size for the event metadata.

		status = TdhGetEventInformation(pEvent, 0, NULL, pInfo, &BufferSize);

		if (ERROR_INSUFFICIENT_BUFFER == status)
		{
			pInfo = (TRACE_EVENT_INFO*) malloc(BufferSize);
			if (pInfo == NULL)
			{
				wprintf(L"Failed to allocate memory for event info (size=%lu).\n", BufferSize);
				status = ERROR_OUTOFMEMORY;
				goto cleanup;
			}

			// Retrieve the event metadata.
			status = TdhGetEventInformation(pEvent, 0, NULL, pInfo, &BufferSize);
		}

		if (ERROR_SUCCESS != status)
		{
			wprintf(L"TdhGetEventInformation failed with 0x%x.\n", status);
		}

cleanup:

		return status;
	}


	// BufferCallback function.
	ULONG WINAPI ProcessBuffer(PEVENT_TRACE_LOGFILE pTrace) {
#if 0
		fprintf(metadata, "env {\n");
		fprintf(metadata, "  BuffersRead = %lu;\n", pTrace->BuffersRead);
		fprintf(metadata, "  CurrentTime = %lu;\n", pTrace->CurrentTime);
		fprintf(metadata, "  BufferSize = %lu;\n", pTrace->LogfileHeader.BufferSize);
		fprintf(metadata, "  BuffersWritten = %lu;\n", pTrace->LogfileHeader.BuffersWritten);
		fprintf(metadata, "  BuffersLost = %lu;\n", pTrace->LogfileHeader.BuffersLost);
		fprintf(metadata, "  EventsLost =  %lu;\n", pTrace->LogfileHeader.EventsLost);
		fprintf(metadata, "  NumberOfProcessor = %lu;\n", pTrace->LogfileHeader.NumberOfProcessors);
		fprintf(metadata, "  CpuSpeedInMHz = %lu;\n", pTrace->LogfileHeader.CpuSpeedInMHz);
		fprintf(metadata, "  StartBuffers = %lu;\n", pTrace->LogfileHeader.StartBuffers);
		fprintf(metadata, "  PointerSize = %lu;\n", pTrace->LogfileHeader.PointerSize);
		fprintf(metadata, "  StartTime = %lu;\n", pTrace->LogfileHeader.StartTime);
		fprintf(metadata, "  EndTime = %lu;\n", pTrace->LogfileHeader.EndTime);
		fprintf(metadata, "};\n\n");
#endif

		if (stream != NULL)
			fclose(stream);

		char filename[128];
		sprintf(filename, "ctf/stream%04d", pTrace->BuffersRead);
		stream = fopen(filename, "wb");
		if (stream == NULL) {
			fprintf(stderr, "Cannot open output stream '%s'.\n", filename);
			return FALSE;
		}

		WritePacketHeader();
		WritePacketContext(pTrace);

		return TRUE;
	}

	/*
	This Function is execute for each event by the Windows API
	*/
	void WINAPI ProcessEvent(PEVENT_RECORD pEvent) {
		if (stream == NULL)
			return;

		if (IsEqualGUID(pEvent->EventHeader.ProviderId, EventTraceGuid) &&
			pEvent->EventHeader.EventDescriptor.Opcode == EVENT_TRACE_TYPE_INFO) {
				return ; // Skip this event.
		}

		Event* pevent = new Event(pEvent);

		// If error the metadata can't be read
		if(pevent->error())
			return ;

		int index = -1;
		if(eventslist->add(pevent))
		{
			index = eventslist->getIndex(pevent);
		}
		else
		{
			index = eventslist->getIndex(pevent);
			delete pevent;
		}

		char buffer[64*1024];
		DWORD buffer_size = sizeof(buffer);
		PTRACE_EVENT_INFO pInfo = reinterpret_cast<PTRACE_EVENT_INFO>(&buffer[0]);

		DWORD status = TdhGetEventInformation(pEvent, 0, NULL, pInfo, &buffer_size);

		// Output stream.header.timestamp.
		WriteUInt64(pEvent->EventHeader.TimeStamp);

		// Output stream.header.id.
		WriteUInt32(index+1);

		// Output stream.context.ev_*.
		WriteUInt16(pEvent->EventHeader.EventDescriptor.Id);
		WriteUInt8(pEvent->EventHeader.EventDescriptor.Version);
		WriteUInt8(pEvent->EventHeader.EventDescriptor.Channel);
		WriteUInt8(pEvent->EventHeader.EventDescriptor.Level);
		WriteUInt8(pEvent->EventHeader.EventDescriptor.Opcode);
		WriteUInt16(pEvent->EventHeader.EventDescriptor.Task);
		WriteUInt64(pEvent->EventHeader.EventDescriptor.Keyword);

		// Output stream.context.pid/tid/cpu_id.
		WriteUInt32(pEvent->EventHeader.ProcessId);
		WriteUInt32(pEvent->EventHeader.ThreadId);
		WriteUInt8(pEvent->BufferContext.ProcessorNumber);
		WriteUInt16(pEvent->BufferContext.LoggerId);

		// Output stream.context.uuid.
		WriteGUID(pEvent->EventHeader.ProviderId);
		WriteGUID(pEvent->EventHeader.ActivityId);

		// Output stream.context.header_type.
		WriteUInt16(pEvent->EventHeader.HeaderType);

		// Output stream.context.header_flags.
		WriteUInt16(pEvent->EventHeader.Flags);
		WriteUInt16(pEvent->EventHeader.Flags);

		// Output stream.context.header_properties.
		WriteUInt16(pEvent->EventHeader.EventProperty);
		WriteUInt16(pEvent->EventHeader.EventProperty);

		// Output event.dummy.
		WriteUInt32(0xDEADC0DE);

		// Output cpuid
		WriteUInt8(pEvent->BufferContext.ProcessorNumber);

		if (index==-1)
			return;

		// Decode the packet payload.
		WriteEvent(pEvent);
	}

}  // namespace

int wmain(int argc, wchar_t** argv) {

	std::vector<TRACEHANDLE> handles;

	eventslist = new EventsList();

	CreateDirectory(L"ctf", NULL);

	for (int i = 1; i < argc; ++i) {
		wprintf(L"Processing %ls...\n", argv[i]);
		memset(&trace, 0, sizeof(trace));
		trace.LogFileName = static_cast<LPWSTR>(argv[i]);
		trace.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD;
		trace.BufferCallback = ProcessBuffer;
		trace.EventRecordCallback = ProcessEvent;

		TRACEHANDLE th = OpenTrace(&trace);
		if (th == INVALID_PROCESSTRACE_HANDLE) {
			fprintf(stderr, "OpenTrace failed with %u\n", GetLastError());
			continue;
		}

		handles.push_back(th);
	}

	ULONG status = ProcessTrace(&handles[0], 1, 0, 0);
	if (status != ERROR_SUCCESS)
		fprintf(stderr, "ProcessTrace failed with %u\n", status);

	for (std::vector<TRACEHANDLE>::iterator it = handles.begin(); it != handles.end(); ++it) {
		CloseTrace(*it);
	}

	if (stream != NULL)
		fclose(stream);

	// Output Metadata.
	metadata = fopen("ctf/metadata", "wb");
	if (metadata == NULL) {
		fprintf(stderr, "Cannot open output metadata.\n");
		return -1;
	}

	eventslist->printMetadata(metadata,trace);

	// Close metadata
	fclose(metadata);

	delete eventslist;

	return 0;
}
