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

#include "Event.h"
#include <guiddef.h>
#include <evntcons.h>

#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <stdio.h>

#pragma comment(lib, "tdh.lib")

namespace {
	/*	Convert a GUID to a String format */
	void GuidToString(const GUID& guid, char* buffer) {
		sprintf(buffer, "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
			guid.Data1,
			guid.Data2,
			guid.Data3,
			guid.Data4[0],
			guid.Data4[1],
			guid.Data4[2],
			guid.Data4[3],
			guid.Data4[4],
			guid.Data4[5],
			guid.Data4[6],
			guid.Data4[7]);
	}

} //namespace

/* Convert Wstring with \null caracter to a standard string */
// TODO(florian) : buffer overflow fix
void convertString(char* o_buffer, LPWSTR i_string, int length = -1)
{
	int i = 0 ;
	while(i_string[i] != L'\0')
	{
		o_buffer[i] = i_string[i];
		i++;
		if(length !=-1 && i >= length) break;
	}
	o_buffer[i] = '\0' ;
}

// EVENTFIELD CLASS

bool Eventfield::equals(Eventfield* i_eventfield)
{
	return (type == i_eventfield->type && (name.compare(i_eventfield->name) == 0));
}


// EVENT CLASS

Event::Event(PEVENT_RECORD pEvent)
{
	init = true;
	load(pEvent);
	renameField();
}

Event::~Event()
{
	for(int i=0;i<fields.size();i++)
		delete fields[i];
}

void Event::load(PEVENT_RECORD pEvent)
{
	char buffer[64*1024];
	DWORD buffer_size = sizeof(buffer);
	PTRACE_EVENT_INFO pInfo = reinterpret_cast<PTRACE_EVENT_INFO>(&buffer[0]);

	DWORD status = TdhGetEventInformation(pEvent, 0, NULL, pInfo, &buffer_size);

	switch (status) {
	case ERROR_SUCCESS: break;
	case ERROR_NOT_FOUND: 
		return ; // don't see the error
		wprintf(L"  Info : NOT_FOUND  ");
		char string[100];
		GuidToString(pEvent->EventHeader.ProviderId,string);
		printf("%s",string);
		wprintf(L" \n");
		return;
	case ERROR_INSUFFICIENT_BUFFER:
		wprintf(L"  Info : INSUFFICIENT BUFFER SPACE (required: %u)\n", buffer_size);
		return;
	case ERROR_INVALID_PARAMETER:
		wprintf(L"  Info : INVALID_PARAMETER\n");
		return;
	case ERROR_WMI_SERVER_UNAVAILABLE:
		wprintf(L"  Info : WMI_SERVER_UNAVAILABLE\n");
		return;
	default:
		wprintf(L"  Info : FAILED\n");
		return;
	}

	if (pInfo->DecodingSource != DecodingSourceWbem &&
		pInfo->DecodingSource != DecodingSourceXMLFile) {
			return;
	}

	guid = pInfo->EventGuid;
	opcode = pEvent->EventHeader.EventDescriptor.Opcode;
	version= pEvent->EventHeader.EventDescriptor.Version;
	eventid= pEvent->EventHeader.EventDescriptor.Id;


	if(pInfo->OpcodeNameOffset > 0) 
	{
		char buffer[128];
		convertString(buffer, (LPWSTR)((PBYTE)(pInfo) + pInfo->OpcodeNameOffset));
		name = buffer;
	}

	for (USHORT i = 0; i < pInfo->TopLevelPropertyCount; i++) 
	{
		status = loadEventField(pInfo, i, 0);
		if (ERROR_SUCCESS != status)
		{
			wprintf(L"Printing metadata for top-level properties failed.\n");
			return;
		}
	}

	init = false;
}

bool Event::sameID(Event* i_event)
{
	return (opcode == i_event->opcode
		&& guid == i_event->guid
		&& version == i_event->version
		&& eventid == i_event->eventid); 
}

bool Event::equals(Event* i_event)
{
	// Test the identificator element
	if(!sameID(i_event)) return false;

	// Test the number of field
	if(fields.size() != i_event->fields.size()) return false;

	for(size_t i=0; i<fields.size() ; ++i)
	{
		if(!fields[i]->equals(i_event->fields[i])) return false;
	}

	return true ;
}


void Event::PrintMetadata(FILE* metadata, int id)
{
	fprintf(metadata,"event {\n");
	fprintf(metadata,"  id = %d;\n",id);

	if(name.size() >0)
		fprintf(metadata,"  name = \"%s\";\n",name.c_str());
	else
		fprintf(metadata,"  name = \"%d\";\n",opcode);

	// event Fields
	fprintf(metadata,"  fields := struct {\n");
	fprintf(metadata,"    xint32  dummy;\n");
	fprintf(metadata,"    uint8   cpuid;\n");

	for (size_t i = 0; i < fields.size() ; i++)
	{
		switch (fields[i]->type) {
		case Eventfield::BIT:
			fprintf(metadata,"    bit     ");
			break;
		case Eventfield::BIT5:
			fprintf(metadata,"    bit5    ");
			break;
		case Eventfield::BIT7:
			fprintf(metadata,"    bit7    ");
			break;
		case Eventfield::BIT13:
			fprintf(metadata,"    bit13   ");
			break;
		case Eventfield::INT8:
			fprintf(metadata,"    int8    ");
			break;
		case Eventfield::INT16:
			fprintf(metadata,"    int16   ");
			break;
		case Eventfield::INT32:
			fprintf(metadata,"    int32   ");
			break;
		case Eventfield::INT64:
			fprintf(metadata,"    int64   ");
			break;
		case Eventfield::UINT8:
			fprintf(metadata,"    uint8   ");
			break;
		case Eventfield::UINT16:
			fprintf(metadata,"    uint16  ");
			break;
		case Eventfield::UINT32:
			fprintf(metadata,"    uint32  ");
			break;
		case Eventfield::UINT64:
			fprintf(metadata,"    uint64  ");
			break;
		case Eventfield::XINT8:
			fprintf(metadata,"    xint8   ");
			break;
		case Eventfield::XINT16:
			fprintf(metadata,"    xint16  ");
			break;
		case Eventfield::XINT32:
			fprintf(metadata,"    xint32  ");
			break;
		case Eventfield::XINT64:
			fprintf(metadata,"    xint64  ");
			break;
		case Eventfield::STRING:
			fprintf(metadata,"    string  ");
			break;
		case Eventfield::GUID:
			fprintf(metadata,"    struct  uuid  ");
			break;
		default:
			wprintf(L"  ERROR : PRINT METADATA ERROR\n");
			break;		
		}
		fprintf(metadata,"%s;\n",fields[i]->name.c_str());
	}
	fprintf(metadata,"  };\n");
	fprintf(metadata,"};\n\n");
}


DWORD Event::loadEventField(TRACE_EVENT_INFO* pinfo, DWORD i, USHORT indent)
{
	Eventfield* field = new Eventfield() ;

	DWORD status = ERROR_SUCCESS;
	DWORD j = 0;
	DWORD lastMember = 0;  // Last member of a structure

	// If the property is an array, the property can define the array size or it can
	// point to another property whose value defines the array size. The PropertyParamCount
	// flag tells you where the array size is defined.

	if ((pinfo->EventPropertyInfoArray[i].Flags & PropertyParamCount) == PropertyParamCount)
	{
		j = pinfo->EventPropertyInfoArray[i].countPropertyIndex;
		wprintf(L"ERROR : (array size is defined by %s)\n", (LPWSTR)((PBYTE)(pinfo) + pinfo->EventPropertyInfoArray[j].NameOffset));
		status = ERROR_BAD_FORMAT ;
	}
	else
	{
		if (pinfo->EventPropertyInfoArray[i].count > 1) 
		{
			field->type = Eventfield::STRING;
			char buffer[128];
			convertString(buffer, (LPWSTR)((PBYTE)(pinfo) + pinfo->EventPropertyInfoArray[i].NameOffset));
			field->name = buffer;
		}
	}

	// If the property is a buffer, the property can define the buffer size or it can
	// point to another property whose value defines the buffer size. The PropertyParamLength
	// flag tells you where the buffer size is defined.

	if ((pinfo->EventPropertyInfoArray[i].Flags & PropertyParamLength) == PropertyParamLength)
	{
		j = pinfo->EventPropertyInfoArray[i].lengthPropertyIndex;
		wprintf(L"ERROR : (size is defined by %s)\n", (LPWSTR)((PBYTE)(pinfo) + pinfo->EventPropertyInfoArray[j].NameOffset));
		status = ERROR_BAD_FORMAT;
	}
	else
	{
		// Variable length properties such as structures and some strings do not have
		// length definitions.

		if (pinfo->EventPropertyInfoArray[i].length > 0) {
			bool err = false ;

			switch (pinfo->EventPropertyInfoArray[i].nonStructType.InType) {
			case TDH_INTYPE_NULL: break;
			//case TDH_INTYPE_UNICODESTRING:  break;
			//case TDH_INTYPE_ANSISTRING:  break;
			case TDH_INTYPE_INT8: 
				field->type = Eventfield::INT8;
				break;
			case TDH_INTYPE_UINT8:
				field->type = Eventfield::UINT8;
				break;
			case TDH_INTYPE_INT16:
				field->type = Eventfield::INT16;
				break;
			case TDH_INTYPE_UINT16:
				field->type = Eventfield::UINT16;
				break;
			case TDH_INTYPE_INT32:
				field->type = Eventfield::INT32;
				break;
			case TDH_INTYPE_UINT32:
				field->type = Eventfield::UINT32;
				break;
			case TDH_INTYPE_INT64:
				field->type = Eventfield::INT64;
				break;
			case TDH_INTYPE_UINT64:
				field->type = Eventfield::UINT64;
				break;
			//case TDH_INTYPE_FLOAT: break;
			//case TDH_INTYPE_DOUBLE: break;
			//case TDH_INTYPE_BOOLEAN: break;
			//case TDH_INTYPE_BINARY: break;
			case TDH_INTYPE_GUID: 	  
				field->type = Eventfield::GUID;
				break;
			case TDH_INTYPE_SIZET:
			case TDH_INTYPE_POINTER:
				if(pinfo->EventPropertyInfoArray[i].length == 4)
					field->type = Eventfield::XINT32;
				else
					field->type = Eventfield::XINT64;
				break;
			//case TDH_INTYPE_FILETIME:  break;
			//case TDH_INTYPE_SYSTEMTIME:  break;
			//case TDH_INTYPE_SID: break;
			case TDH_INTYPE_HEXINT32:   
				field->type = Eventfield::XINT32;
				break;
			case TDH_INTYPE_HEXINT64: 
				field->type = Eventfield::XINT64;
				break;
			// DONT TOUCH THIS CASE ARE IS FOR ARRAY
			case TDH_INTYPE_UNICODECHAR : 
				err = true ;
				status = ERROR_BAD_FORMAT;
				break ;			  

			default: 
				wprintf(L"  %*s%s\n", indent, L"", (LPWSTR)((PBYTE)(pinfo) + pinfo->EventPropertyInfoArray[i].NameOffset));
				err = true ;
				status = ERROR_BAD_FORMAT;
				break;
			}

			if(!err) 
			{
				char buffer[100];
				convertString(buffer, (LPWSTR)((PBYTE)(pinfo) + pinfo->EventPropertyInfoArray[i].NameOffset));
				field->name = buffer;
			}
		}
		else
		{
			field->type = Eventfield::STRING;
			char buffer[128];
			convertString(buffer, (LPWSTR)((PBYTE)(pinfo) + pinfo->EventPropertyInfoArray[i].NameOffset));
			field->name = buffer;
		}
	}

	// If the property is a structure, print the members of the structure.

	if ((pinfo->EventPropertyInfoArray[i].Flags & PropertyStruct) == PropertyStruct)
	{
		/*wprintf(L"%*s(The property is a structure and has the following %hu members:)\n", 4, L"",
		pinfo->EventPropertyInfoArray[i].structType.NumOfStructMembers);

		lastMember = pinfo->EventPropertyInfoArray[i].structType.StructStartIndex + 
		pinfo->EventPropertyInfoArray[i].structType.NumOfStructMembers;

		for (j = pinfo->EventPropertyInfoArray[i].structType.StructStartIndex; j < lastMember; j++)
		{
		loadEventField(pinfo, j, 4);
		}*/
		wprintf(L"ERREUR : TYPE STRUCTURE\n") ;
		status = ERROR_BAD_FORMAT ;
	}
	else
	{
		// You can use InType to determine the data type of the member and OutType
		// to determine the output format of the data.

		if (pinfo->EventPropertyInfoArray[i].nonStructType.MapNameOffset)
		{
			// You can pass the name to the TdhGetEventMapInformation function to 
			// retrieve metadata about the value map.

			wprintf(L"%*s(Map attribute name is %s)\n", indent, L"", 
				(PWCHAR)((PBYTE)(pinfo) + pinfo->EventPropertyInfoArray[i].nonStructType.MapNameOffset));
			status = ERROR_BAD_FORMAT ;
		}
	}

	if(status == ERROR_SUCCESS) 
	{
		fields.push_back(field) ;
	}
	else
	{
		delete field ;
	}

	return status;
}

// TODO(florian) test of this fonction
void Event::renameField()
{
	for(size_t i=0;i<fields.size();++i)
	{
		size_t index = existField(fields[i]);
		if(index != i) // field already exist
			fields[i]->name += "_" + i ;
	}
}

size_t Event::existField(Eventfield* field)
{
	for(size_t i=0;i<fields.size();++i) 
	{
		if(fields[i]->name.compare(field->name)==0) return i;
	}
	return -1;
}