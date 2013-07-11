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

#include "EventsList.h"

#define MAX_GUID_STRING_LENGTH 38

// ETW-CTF converter GUID: Specify to CTF consumer that source come from ETW.
DEFINE_GUID ( /* 29cb3580-13c6-4c85-a4cb-a2c0ffa68890 */
	ETWConverterGuid,
	0x29CB3580,
	0x13C6,
	0x4C85,
	0xA4, 0xCB, 0xA2, 0xC0, 0xFF, 0xA6, 0x88, 0x90
	);

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

EventsList::EventsList()
{}

EventsList::~EventsList()
{
	for(int i=0;i<events.size();i++)
		delete events[i];
}


bool EventsList::add(Event* pevent)
{
	if(isExist(pevent)) return false;

	events.push_back(pevent);
	return true;
}

bool EventsList::isExist(Event* pevent)
{
	for(int i=0; i<events.size();++i)
	{
		if(pevent->equals(events[i])) 
			return true;
	}
	return false;
}

int EventsList::getIndex(Event* pevent)
{
	for(int i=0; i<events.size();++i)
	{
		if(pevent->equals(events[i])) 
			return i;
	}
	return -1;
}

void EventsList::printMetadata(FILE* metadata,EVENT_TRACE_LOGFILE trace)
{
	fprintf(metadata, "/* CTF 1.8 */\n");
	fprintf(metadata,
		"typealias integer { size = 1;  align = 1; signed = false; } := bit;\n"
		"typealias integer { size = 5;  align = 1; signed = false; } := bit5;\n"
		"typealias integer { size = 7;  align = 1; signed = false; } := bit7;\n"
		"typealias integer { size = 13; align = 1; signed = false; } := bit13;\n"
		"typealias integer { size = 15; align = 1; signed = false; } := bit15;\n"
		"typealias integer { size = 8;  align = 8; signed = true;  } := int8;\n"
		"typealias integer { size = 16; align = 8; signed = true;  } := int16;\n"
		"typealias integer { size = 32; align = 8; signed = true;  } := int32;\n"
		"typealias integer { size = 64; align = 8; signed = true;  } := int64;\n"
		"typealias integer { size = 8;  align = 8; signed = false; } := uint8;\n"
		"typealias integer { size = 16; align = 8; signed = false; } := uint16;\n"
		"typealias integer { size = 32; align = 8; signed = false; } := uint32;\n"
		"typealias integer { size = 64; align = 8; signed = false; } := uint64;\n"
		"typealias integer { size = 8;  align = 8; signed = false; base = 16; } := xint8;\n"
		"typealias integer { size = 16; align = 8; signed = false; base = 16; } := xint16;\n"
		"typealias integer { size = 32; align = 8; signed = false; base = 16; } := xint32;\n"
		"typealias integer { size = 64; align = 8; signed = false; base = 16; } := xint64;\n"
		"\n\n");

	fprintf(metadata,
		"struct uuid {\n"
		"  xint32 Data1;\n"
		"  xint16 Data2;\n"
		"  xint16 Data3;\n"
		"  xint64 Data4;\n"
		"};\n\n");

	fprintf(metadata,
		"enum event_header_type : uint16 {\n"
		"  EXT_TYPE_NONE,\n"
		"  EXT_TYPE_RELATED_ACTIVITYID,\n"
		"  EXT_TYPE_SID,\n"
		"  EXT_TYPE_TS_ID,\n"
		"  EXT_TYPE_INSTANCE_INFO,\n"
		"  EXT_TYPE_STACK_TRACE32,\n"
		"  EXT_TYPE_STACK_TRACE64\n"
		"};\n\n");

	fprintf(metadata,
		"struct event_header_flags {\n"
		"  bit7 unused;\n"
		"  bit FLAG_CLASSIC_HEADER;\n"
		"  bit FLAG_64_BIT_HEADER;\n"
		"  bit FLAG_32_BIT_HEADER;\n"
		"  bit FLAG_NO_CPUTIME;\n"
		"  bit FLAG_TRACE_MESSAGE;\n"
		"  bit FLAG_STRING_ONLY;\n"
		"  bit FLAG_PRIVATE_SESSION;\n"
		"  bit FLAG_EXTENDED_INFO;\n"
		"};\n\n");

	fprintf(metadata,
		"struct event_header_properties {\n"
		"  bit13 unused;\n"
		"  bit EVENT_HEADER_PROPERTY_LEGACY_EVENTLOG;\n"
		"  bit EVENT_HEADER_PROPERTY_FORWARDED_XML;\n"
		"  bit EVENT_HEADER_PROPERTY_XML;\n"
		"};\n\n");

	fprintf(metadata, "env {\n");
	//fprintf(metadata, "  BufferSize = %lu;\n", trace.LogfileHeader.BufferSize);
	fprintf(metadata, "  BuffersWritten = %lu;\n", trace.LogfileHeader.BuffersWritten);
	//fprintf(metadata, "  BuffersLost = %lu;\n", trace.LogfileHeader.BuffersLost);
	//fprintf(metadata, "  EventsLost =  %lu;\n", trace.LogfileHeader.EventsLost);
	fprintf(metadata, "  NumberOfProcessor = %lu;\n", trace.LogfileHeader.NumberOfProcessors);
	fprintf(metadata, "  CpuSpeedInMHz = %lu;\n", trace.LogfileHeader.CpuSpeedInMHz);
	//fprintf(metadata, "  StartBuffers = %lu;\n", trace.LogfileHeader.StartBuffers);
	fprintf(metadata, "  PointerSize = %lu;\n", trace.LogfileHeader.PointerSize);
	fprintf(metadata, "  StartTime = %lu;\n", trace.LogfileHeader.StartTime);
	fprintf(metadata, "  EndTime = %lu;\n", trace.LogfileHeader.EndTime);
	fprintf(metadata, "};\n\n");

	char converter_guid[MAX_GUID_STRING_LENGTH];
	GuidToString(ETWConverterGuid, converter_guid);

	fprintf(metadata,
		"trace {\n"
		"  major = 1;\n"
		"  minor = 8;\n"
		"  uuid  = \"%s\";\n"
		"  byte_order = le;\n"
		"  packet.header := struct {\n"
		"    uint32  magic;\n"
		"    xint8   uuid[16];\n"
		"  };\n"
		"};\n\n", converter_guid);

	fprintf(metadata,
		"stream {\n"
		"  packet.context := struct {\n"
		"    uint64  timestamp_begin;\n"
		"    uint64  timestamp_end;\n"
		"  };\n"
		"  event.header := struct {\n"
		"    uint64  timestamp;\n"
		"    uint32  id;\n"
		"  };\n"
		"  event.context := struct {\n"
		"    uint16  ev_id;\n"
		"    uint8   ev_version;\n"
		"    uint8   ev_channel;\n"
		"    uint8   ev_level;\n"
		"    uint8   ev_opcode;\n"
		"    uint16  ev_task;\n"
		"    xint64  ev_keyword;\n"
		"    uint32  pid;\n"
		"    uint32  tid;\n"
		"    uint8   cpu_id;\n"
		"    uint16  logger_id;\n"
		"    struct  uuid provider_id;\n"
		"    struct  uuid activity_id;\n"
		"    enum    event_header_type header_type;\n"
		"    xint16  header_flags;\n"
		"    struct  event_header_flags header_flags_decoded;\n"
		"    xint16  header_properties;\n"
		"    struct  event_header_properties header_properties_decoded;\n"
		"  };\n"
		"};\n\n");

	fprintf(metadata,
		"event {\n"
		"  id = 0;\n"
		"  name = \"evt-dummy\";\n"
		"  fields := struct {\n"
		"    xint32  dummy;\n"
		"    uint8   cpuid;\n"
		"  };\n"
		"};\n\n");


	for(int i=0;i<events.size();++i)
	{
		events[i]->PrintMetadata(metadata,i+1);
	}

}

