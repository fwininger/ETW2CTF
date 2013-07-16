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

#define WIN32_LEAN_AND_MEAN
#include <windows.h>  // NO LINT
//Turns the DEFINE_GUID for EventTraceGuid into a const.
#define INITGUID
#include <guiddef.h>
#include <evntcons.h>
#include <tdh.h>

#include "ETWConsumer.h"

#include <cassert>
#include <iostream>
#include <sstream>

#pragma comment(lib, "tdh.lib")

namespace etw2ctf {

namespace {

// Specify to CTF consumer that source come from ETW.
// ETW2CTF GUID {29cb3580-13c6-4c85-a4cb-a2c0ffa68890}.
const GUID ETWConverterGuid = { 0x29CB3580, 0x13C6, 0x4C85,
  { 0xA4, 0xCB, 0xA2, 0xC0, 0xFF, 0xA6, 0x88, 0x90 }};

//  Convert a GUID to a String format.
std::string GuidToString(const GUID& guid) {
  const int kMAX_GUID_STRING_LENGTH = 38;
  char buffer[kMAX_GUID_STRING_LENGTH];
  sprintf_s(buffer, kMAX_GUID_STRING_LENGTH,
    "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
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
  return std::string(buffer);
}

std::string convertString(wchar_t* pstr) {
  std::wstring wstr(pstr);
  return std::string(wstr.begin(), wstr.end());
}

void WriteLargeInteger(Metadata::Packet& packet, LARGE_INTEGER value) {
  packet.WriteUInt32(value.LowPart);
  packet.WriteUInt32(value.HighPart);
}

void WriteGUID(Metadata::Packet& packet, GUID guid) {
  // TODO(etienneb) : Validate babeltrace / eclipse
  // it seem babeltrace parse raw byte, not endianness.
  // see: http://en.wikipedia.org/wiki/Globally_unique_identifier
  // I think UUID are big endian, but MS GUID are native.
#if 0
  packet.WriteUInt32(guid.Data1);
  packet.WriteUInt16(guid.Data2);
  packet.WriteUInt16(guid.Data3);
  packet.WriteBytes(guid.Data4, 8);
#else
  packet.WriteUInt8(static_cast<uint8_t>(guid.Data1 >> 24));
  packet.WriteUInt8(static_cast<uint8_t>(guid.Data1 >> 16));
  packet.WriteUInt8(static_cast<uint8_t>(guid.Data1 >> 8));
  packet.WriteUInt8(static_cast<uint8_t>(guid.Data1));

  packet.WriteUInt8(static_cast<uint8_t>(guid.Data2 >> 8));
  packet.WriteUInt8(static_cast<uint8_t>(guid.Data2));

  packet.WriteUInt8(static_cast<uint8_t>(guid.Data3 >> 8));
  packet.WriteUInt8(static_cast<uint8_t>(guid.Data3));

  packet.WriteBytes(guid.Data4, 8);
#endif
}

}  // namespace

bool ETWConsumer::GetBufferName(PEVENT_TRACE_LOGFILEW pTrace,
                                std::wstring* name) const {
  if (!pTrace)
    return false;

  std::wstringstream ss;
  ss << L"stream" << pTrace->BuffersRead;

  *name = ss.str();
  return true;
}

bool ETWConsumer::ConsumeAllEvents() {
  // Open all trace files.
  std::vector<TRACEHANDLE> handles;
  for (size_t i = 0; i < traces_.size(); ++i) {
    EVENT_TRACE_LOGFILE trace;
    ::memset(&trace, 0, sizeof(trace));
    trace.LogFileName = const_cast<LPWSTR>(traces_[i].c_str());
    trace.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD;
    trace.BufferCallback = buffer_callback_;
    trace.EventRecordCallback = event_callback_;

    TRACEHANDLE th = ::OpenTrace(&trace);
    if (th == INVALID_PROCESSTRACE_HANDLE) {
      DWORD error = ::GetLastError();
      std::wcerr << L"OpenTrace failed with error " << error << std::endl;
      return false;
    }

    handles.push_back(th);
  }

  if (handles.empty())
    return false;

  // Reserve some memory space for internal buffer.
  data_property_buffer_.resize(1024);
  formatted_property_buffer_.resize(1024);
  map_info_buffer_.resize(1024);
  packet_info_buffer_.resize(64*1024);

  bool valid = true;
  ULONG status = ::ProcessTrace(&handles[0], 1, 0, 0);
  if (status != ERROR_SUCCESS) {
    std::wcerr << L"ProcessTrace failed with error " << status << std::endl;
    valid = false;
  }

  // Close all trace files.
  for (size_t i = 0; i < handles.size(); ++i)
    ::CloseTrace(handles[i]);

  // Free unused memory.
  data_property_buffer_.clear();
  formatted_property_buffer_.clear();
  map_info_buffer_.clear();
  packet_info_buffer_.clear();

  return valid;
}

// This function is executed for each stream.
void ETWConsumer::ProcessHeader(Metadata::Packet& packet) {
  // Output trace.header.magic.
  packet.WriteUInt32(0xC1FC1FC1);

  // Output trace.header.uuid.
  WriteGUID(packet, ETWConverterGuid);
}

// This function is executed before each buffer.
bool ETWConsumer::ProcessBuffer(PEVENT_TRACE_LOGFILEW pTrace) {
  stream_context_emitted_ = false;
  return true;
}

// This function is executed for each event.
bool ETWConsumer::ProcessEvent(Metadata::Packet& packet, PEVENT_RECORDW pEvent) {
  // Skip tracing events.
  if (IsEqualGUID(pEvent->EventHeader.ProviderId, EventTraceGuid) &&
    pEvent->EventHeader.EventDescriptor.Opcode == EVENT_TRACE_TYPE_INFO) {
      return false;
  }

  if (!stream_context_emitted_) {
    // TODO(bergeret): Export stream context information here, and revomve it
    //     from the packet fields. I need to validate the information first.
    // Output trace.context.timestamp_begin/end.
    //WriteLargeInteger(packet, pTrace->LogfileHeader.StartTime);
    //WriteLargeInteger(packet, pTrace->LogfileHeader.EndTime);
  }

  // Output stream.header.timestamp.
  WriteLargeInteger(packet, pEvent->EventHeader.TimeStamp);

  // Output stream.header.id.
  size_t event_id = 0;
  size_t event_id_position = packet.size();
  packet.WriteUInt32(event_id);

  // Output stream.context.ev_*.
  packet.WriteUInt16(pEvent->EventHeader.EventDescriptor.Id);
  packet.WriteUInt8(pEvent->EventHeader.EventDescriptor.Version);
  packet.WriteUInt8(pEvent->EventHeader.EventDescriptor.Channel);
  packet.WriteUInt8(pEvent->EventHeader.EventDescriptor.Level);
  packet.WriteUInt8(pEvent->EventHeader.EventDescriptor.Opcode);
  packet.WriteUInt16(pEvent->EventHeader.EventDescriptor.Task);
  packet.WriteUInt64(pEvent->EventHeader.EventDescriptor.Keyword);

  // Output stream.context.pid/tid/cpu_id.
  packet.WriteUInt32(pEvent->EventHeader.ProcessId);
  packet.WriteUInt32(pEvent->EventHeader.ThreadId);
  packet.WriteUInt8(pEvent->BufferContext.ProcessorNumber);
  packet.WriteUInt16(pEvent->BufferContext.LoggerId);

  // Output stream.context.uuid.
  WriteGUID(packet, pEvent->EventHeader.ProviderId);
  WriteGUID(packet, pEvent->EventHeader.ActivityId);

  // Output stream.context.header_type.
  packet.WriteUInt16(pEvent->EventHeader.HeaderType);

  // Output stream.context.header_flags.
  packet.WriteUInt16(pEvent->EventHeader.Flags);
  packet.WriteUInt16(pEvent->EventHeader.Flags);

  // Output stream.context.header_properties.
  packet.WriteUInt16(pEvent->EventHeader.EventProperty);
  packet.WriteUInt16(pEvent->EventHeader.EventProperty);

  // TODO(bergeret): This field is used to debug the trace parsing.
  //    Each event has this field, and the value must be DEADC0DE.
  //    It will be removed later.
  // Output event.dummy.
  packet.WriteUInt32(0xDEADC0DE);

  // Output cpu_id.
  packet.WriteUInt8(pEvent->BufferContext.ProcessorNumber);

  // Decode the packet payload.
  Metadata::Event descr;
  size_t payload_position = packet.size();

  if (!DecodePayload(packet, descr, pEvent)) {
    // On failure, remove packet data and metadata, and send the raw payload.
    descr.Reset();
    packet.Reset(payload_position);
    if (!SendRawPayload(packet, descr, pEvent))
      return false;
  }

  // Update the event_id, now we have the full layout information.
  event_id = metadata_.getEventID(descr);
  packet.UpdateUInt32(event_id_position, event_id);

  // This flag must be turned true only when the packet is emitted.
  stream_context_emitted_ = true;

  return true;
}

bool ETWConsumer::SendRawPayload(
    Metadata::Packet& packet, Metadata::Event& descr, PEVENT_RECORDW pEvent) {

  // Get raw data pointer and size.
  USHORT length = pEvent->UserDataLength;
  PVOID data = pEvent->UserData;

  // Create the metadata fields.
  Metadata::Field field_size(Metadata::Field::UINT16, "size");
  Metadata::Field field_data(Metadata::Field::BINARY_VAR, "data", "size");
  descr.AddField(field_size);
  descr.AddField(field_data);

  // Write data.
  packet.WriteUInt16(length);
  packet.WriteBytes(static_cast<uint8_t*>(data), length);

  return true;
}

bool ETWConsumer::DecodePayload(
    Metadata::Packet& packet, Metadata::Event& descr, PEVENT_RECORDW pevent) {

  // If the EVENT_HEADER_FLAG_STRING_ONLY flag is set, the event data is a
  // null-terminated string. Those events are generated via EventWriteString
  // function.
  if ((pevent->EventHeader.Flags & EVENT_HEADER_FLAG_STRING_ONLY) != 0) {
    // Write string data.
    LPWSTR wptr = (LPWSTR)pevent->UserData;
    std::string str = convertString(wptr);
    packet.WriteString(str);

    // Create the metadata fields.
    Metadata::Field field_data(Metadata::Field::STRING, "data");
    descr.AddField(field_data); 
    return true;
  }

  // Decode the metadata via trace data helper (TDH) using
  // TdhGetEventInformation.
  DWORD buffer_size = packet_info_buffer_.size();
  PTRACE_EVENT_INFO pinfo =
      reinterpret_cast<PTRACE_EVENT_INFO>(&packet_info_buffer_[0]);

  DWORD status = TdhGetEventInformation(pevent, 0, NULL, pinfo, &buffer_size);
  if (status == ERROR_INSUFFICIENT_BUFFER) {
    // The internal buffer is too small, resize it and try again.
    packet_info_buffer_.resize(buffer_size);
    pinfo = reinterpret_cast<PTRACE_EVENT_INFO>(&packet_info_buffer_[0]);
    status = TdhGetEventInformation(pevent, 0, NULL, pinfo, &buffer_size);
  }

  if (status != ERROR_SUCCESS)
    return false;

  // Filter the encoding we don't know how to handle.
  if (pinfo->DecodingSource != DecodingSourceWbem &&
      pinfo->DecodingSource != DecodingSourceXMLFile) {
      return false;
  }

  // Retrieve event descriptor information.
  descr.set_info(pinfo->EventGuid,
                 pevent->EventHeader.EventDescriptor.Opcode,
                 pevent->EventHeader.EventDescriptor.Version,
                 pevent->EventHeader.EventDescriptor.Id);

  // Retrieve event opcode name.
  if (pinfo->OpcodeNameOffset > 0) {
    LPWSTR opcode_ptr = (LPWSTR)&packet_info_buffer_[pinfo->OpcodeNameOffset];
    std::string opcode_name = convertString(opcode_ptr);
    descr.set_name(opcode_name);
  }

  // Decode each field.
  for (size_t i = 0; i < pinfo->TopLevelPropertyCount; ++i) {
    if (!DecodePayloadField(packet, descr, pevent, pinfo, i)) {
      // TODO(bergeret): We should have a fallback that send the field raw.
      return false;
    }
  }

  return true;
}

bool ETWConsumer::DecodePayloadField(Metadata::Packet& packet,
                                     Metadata::Event& descr,
                                     PEVENT_RECORDW pevent,
                                     PTRACE_EVENT_INFO pinfo,
                                     unsigned int field_index) {
  // Retrieve the field to decode.
  const EVENT_PROPERTY_INFO& field =
      pinfo->EventPropertyInfoArray[field_index];
  size_t count = pinfo->EventPropertyInfoArray[field_index].count;
  size_t length = pinfo->EventPropertyInfoArray[field_index].length;
  size_t flags = pinfo->EventPropertyInfoArray[field_index].Flags;
  PBYTE raw_info = (PBYTE)pinfo;

  // Retrieve field name.
  assert(field.NameOffset != 0);
  size_t name_offset = field.NameOffset;
  LPWSTR name_ptr = (LPWSTR)(&raw_info[name_offset]);
  std::string field_name = convertString(name_ptr);

  // TODO(bergeret) : Handle aggregate types (struct, array, ...).
  if (flags != 0) {
    std::cout << "Skip flags:" << flags << std::endl;
    return false;
  }

  if (count != 1) {
    std::cout << "Skip count:" << count << std::endl;
    return false;
  }

  // Not an aggregate type.
  unsigned int in_type = field.nonStructType.InType;
  unsigned int out_type = field.nonStructType.OutType;
  size_t map_name_offset = field.nonStructType.MapNameOffset;
  PROPERTY_DATA_DESCRIPTOR data_descriptors[2];
  unsigned int descriptor_count = 0;

  data_descriptors[0].PropertyName = (ULONGLONG)((PBYTE)(pinfo) + field.NameOffset);
  data_descriptors[0].ArrayIndex = 0;
  descriptor_count = 1;
 
  // Determine the property size.
  ULONG property_size = 0;
  ULONG status = TdhGetPropertySize(pevent, 0, NULL, descriptor_count,
      &data_descriptors[0], &property_size);
  if (status != ERROR_SUCCESS)
    return false;

  // Get a pointer to a buffer large enough to hold the property.
  if (property_size >= data_property_buffer_.size())
    data_property_buffer_.resize(property_size);
  PBYTE raw_data = reinterpret_cast<PBYTE>(&data_property_buffer_[0]);

  // Retrieve the property.
  status = TdhGetProperty(pevent, 0, NULL, descriptor_count,
     &data_descriptors[0], property_size, raw_data);
  if (status != ERROR_SUCCESS)
    return false;

  // Try to decode the property with in/out type.
  Metadata::Field::FIELDTYPE field_type = Metadata::Field::INVALID;
  switch (in_type) {
    case TDH_INTYPE_UNICODESTRING:
      packet.WriteString(convertString((LPWSTR)raw_data));
      descr.AddField(Metadata::Field(Metadata::Field::STRING, field_name));
      return true;

    case TDH_INTYPE_ANSISTRING:
      packet.WriteString((const char*)raw_data);
      descr.AddField(Metadata::Field(Metadata::Field::STRING, field_name));
      return true;

    case TDH_INTYPE_INT8:
    case TDH_INTYPE_UINT8:
      switch (out_type) {
        case TDH_OUTTYPE_HEXINT8:
          field_type = Metadata::Field::XINT8;
          break;
        case TDH_OUTTYPE_BYTE:
          field_type = Metadata::Field::INT8;
          break;
        case TDH_OUTTYPE_UNSIGNEDBYTE:
          field_type = Metadata::Field::UINT8;
          break;
        default:
          if (in_type == TDH_INTYPE_INT8)
            field_type = Metadata::Field::INT8;
          else
            field_type = Metadata::Field::UINT8;
          break;
      }

      if (property_size == 1) {
        packet.WriteUInt8(*reinterpret_cast<uint8_t*>(raw_data));
        descr.AddField(Metadata::Field(field_type, field_name));
        return true;
      }
      break;

    case TDH_INTYPE_INT16:
    case TDH_INTYPE_UINT16:
      switch (out_type) {
        case TDH_OUTTYPE_HEXINT16:
          field_type = Metadata::Field::XINT16;
          break;
        case TDH_OUTTYPE_SHORT:
          field_type = Metadata::Field::INT16;
          break;
        case TDH_OUTTYPE_UNSIGNEDSHORT:
          field_type = Metadata::Field::UINT16;
          break;
        default:
          if (in_type == TDH_INTYPE_INT16)
            field_type = Metadata::Field::INT16;
          else
            field_type = Metadata::Field::UINT16;
          break;
      }

      if (property_size == 2) {
        packet.WriteUInt16(*reinterpret_cast<uint16_t*>(raw_data));
        descr.AddField(Metadata::Field(field_type, field_name));
        return true;
      }
      break;

    case TDH_INTYPE_INT32:
    case TDH_INTYPE_UINT32:
      switch (out_type) {
        case TDH_OUTTYPE_HEXINT32:
          field_type = Metadata::Field::XINT32;
          break;
        case TDH_OUTTYPE_INT:
          field_type = Metadata::Field::INT32;
          break;
        case TDH_OUTTYPE_UNSIGNEDINT:
          field_type = Metadata::Field::UINT32;
          break;
        default:
          if (in_type == TDH_INTYPE_INT32)
            field_type = Metadata::Field::INT32;
          else
            field_type = Metadata::Field::UINT32;
          break;
      }
      
      if (property_size == 4) {
        packet.WriteUInt32(*reinterpret_cast<uint32_t*>(raw_data));
        descr.AddField(Metadata::Field(field_type, field_name));
        return true;
      }
      break;

    case TDH_INTYPE_INT64:
    case TDH_INTYPE_UINT64:
      switch (out_type) {
        case TDH_OUTTYPE_HEXINT64:
          field_type = Metadata::Field::XINT64;
          break;
        default:
          if (in_type == TDH_INTYPE_INT64)
            field_type = Metadata::Field::INT64;
          else
            field_type = Metadata::Field::UINT64;
          break;
      }

      if (property_size == 8) {
        packet.WriteUInt64(*reinterpret_cast<uint64_t*>(raw_data));
        descr.AddField(Metadata::Field(field_type, field_name));
        return true;
      }
      break;

    case TDH_INTYPE_BOOLEAN:
      if (property_size == 1) {
        packet.WriteUInt8(*reinterpret_cast<uint8_t*>(raw_data) != 0);
        descr.AddField(Metadata::Field(Metadata::Field::UINT8, field_name));
        return true;
      }
      else if (property_size == 4) {
        packet.WriteUInt8(*reinterpret_cast<uint32_t*>(raw_data) != 0);
        descr.AddField(Metadata::Field(Metadata::Field::UINT8, field_name));
        return true;
      }
      break;

    case TDH_INTYPE_GUID:
      if (property_size == 16) {
        packet.WriteBytes(raw_data, 16);
        descr.AddField(Metadata::Field(Metadata::Field::GUID, field_name));
        return true;
      }
      break;

    case TDH_INTYPE_POINTER:
      if (property_size == 4) {
        packet.WriteUInt32(*reinterpret_cast<uint32_t*>(raw_data));
        descr.AddField(Metadata::Field(Metadata::Field::XINT32, field_name));
        return true;
      } else if (property_size == 8) {
        packet.WriteUInt64(*reinterpret_cast<uint64_t*>(raw_data));
        descr.AddField(Metadata::Field(Metadata::Field::XINT64, field_name));
        return true;
      }
      break;
    
    case TDH_INTYPE_WBEMSID:
#if 0
      {
        const int kMAX_NAME = 256;
        WCHAR UserName[kMAX_NAME];
        WCHAR DomainName[kMAX_NAME];
        DWORD cchUserSize = kMAX_NAME;
        DWORD cchDomainSize = kMAX_NAME;
        SID_NAME_USE eNameUse;

        std::cout << "SSID?" << std::endl;

        // A WBEM SID is actually a TOKEN_USER structure followed by the SID.
        // The size of the TOKEN_USER structure differs depending on whether
        // the events were generated on a 32-bit or 64-bit architecture. 

        // Add token and pointer re-alignment (same than adding twice pointer size).
        PBYTE psid = raw_data + pointer_size * 2;

        if (!LookupAccountSid(NULL, (PSID)psid, UserName, &cchUserSize,
            DomainName, &cchDomainSize, &eNameUse)) {
          return false;
        }
           
        std::stringstream ss;
        ss << convertString(DomainName) << "\\" << convertString(UserName);

        packet.WriteString(ss.str());
        descr.AddField(Metadata::Field(Metadata::Field::STRING, field_name));

        std::cout << "SSID:" << ss.str() << std::endl;
      }
      return true;
#endif
      break;
  }
 
  return false;
}

bool ETWConsumer::SerializeMetadata(std::ostream& out) const {
  out << "/* CTF 1.8 */\n";

  out <<
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
    "\n\n";

  out <<
    "struct uuid {\n"
    "  xint32 Data1;\n"
    "  xint16 Data2;\n"
    "  xint16 Data3;\n"
    "  xint64 Data4;\n"
    "};\n\n";

  out <<
    "enum event_header_type : uint16 {\n"
    "  EXT_TYPE_NONE,\n"
    "  EXT_TYPE_RELATED_ACTIVITYID,\n"
    "  EXT_TYPE_SID,\n"
    "  EXT_TYPE_TS_ID,\n"
    "  EXT_TYPE_INSTANCE_INFO,\n"
    "  EXT_TYPE_STACK_TRACE32,\n"
    "  EXT_TYPE_STACK_TRACE64\n"
    "};\n\n";

  out <<
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
    "};\n\n";

  out <<
    "struct event_header_properties {\n"
    "  bit13 unused;\n"
    "  bit EVENT_HEADER_PROPERTY_LEGACY_EVENTLOG;\n"
    "  bit EVENT_HEADER_PROPERTY_FORWARDED_XML;\n"
    "  bit EVENT_HEADER_PROPERTY_XML;\n"
    "};\n\n";

  std::string guid_str = GuidToString(ETWConverterGuid);

  out <<
    "trace {\n"
    "  major = 1;\n"
    "  minor = 8;\n"
    "  uuid  = \"" << guid_str << "\";\n"
    "  byte_order = le;\n"
    "  packet.header := struct {\n"
    "    uint32  magic;\n"
    "    xint8   uuid[16];\n"
    "  };\n"
    "};\n\n";

  out <<
    "stream {\n"
    //"  packet.context := struct {\n"
    //"    uint64  timestamp_begin;\n"
    //"    uint64  timestamp_end;\n"
    //"  };\n"
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
    "};\n\n";

  out <<
    "event {\n"
    "  id = 0;\n"
    "  name = \"unknown\";\n"
    "  fields := struct {\n"
    "    xint32  dummy;\n"
    "    uint8   cpuid;\n"
    "  };\n"
    "};\n\n";

  for (size_t i = 0; i < metadata_.size(); ++i) {
    size_t event_id = i + 1;
    if (!SerializeMetadataEvent(out, metadata_.at(i), event_id))
      return false;
  }

  return true;
}

bool ETWConsumer::SerializeMetadataEvent(
    std::ostream& out, const Metadata::Event& descr, size_t event_id) const {

  out
    << "event {\n"
    << "  id = " << event_id << ";\n";

  if (descr.name().empty())
    out << "  name = \"event" << event_id << "\";\n";
  else
    out << "  name = \"" << descr.name() << "\";\n";

  // Event Fields
  out
    <<"  fields := struct {\n"
    << "    xint32  dummy;\n"
    << "    uint8   cpuid;\n";

  for (size_t i = 0; i < descr.size(); ++i) {
    if (!SerializeMetadataField(out, descr.at(i)))
      return false;
  }
  out <<"  };\n";

  out <<"};\n\n";

  return true;
}

bool ETWConsumer::SerializeMetadataField(std::ostream& out,
                                         const Metadata::Field& field) const {
  switch (field.type()) {
  case Metadata::Field::STRUCT_BEGIN:
    out << "    struct   " << field.name() << "{\n";
    return true;
  case Metadata::Field::STRUCT_END:
    out << "    };\n";
    return true;
  case Metadata::Field::BINARY_FIXED:
    out << "    uint8   " << field.name()
        << "[" << field.size() << "]"
        << ";\n";
    return true;
  case Metadata::Field::BINARY_VAR:
    out << "    uint8   " << field.name()
        << "[" << field.field_size() << "]"
        << ";\n";
    return true;
  case Metadata::Field::BIT:
    out << "    bit     " << field.name() << ";\n";
    return true;
  case Metadata::Field::BIT5:
    out << "    bit5    " << field.name() << ";\n";
    return true;
  case Metadata::Field::BIT7:
    out << "    bit7    " << field.name() << ";\n";
    return true;
  case Metadata::Field::BIT13:
    out << "    bit13   " << field.name() << ";\n";
    return true;
  case Metadata::Field::INT8:
    out << "    int8    " << field.name() << ";\n";
    return true;
  case Metadata::Field::INT16:
    out << "    int16   " << field.name() << ";\n";
    return true;
  case Metadata::Field::INT32:
    out << "    int32   " << field.name() << ";\n";
    return true;
  case Metadata::Field::INT64:
    out << "    int64   " << field.name() << ";\n";
    return true;
  case Metadata::Field::UINT8:
    out << "    uint8   " << field.name() << ";\n";
    return true;
  case Metadata::Field::UINT16:
    out << "    uint16  " << field.name() << ";\n";
    return true;
  case Metadata::Field::UINT32:
    out << "    uint32  " << field.name() << ";\n";
    return true;
  case Metadata::Field::UINT64:
    out << "    uint64  " << field.name() << ";\n";
    return true;
  case Metadata::Field::XINT8:
    out << "    xint8   " << field.name() << ";\n";
    return true;
  case Metadata::Field::XINT16:
    out << "    xint16  " << field.name() << ";\n";
    return true;
  case Metadata::Field::XINT32:
    out << "    xint32  " << field.name() << ";\n";
    return true;
  case Metadata::Field::XINT64:
    out << "    xint64  " << field.name() << ";\n";
    return true;
  case Metadata::Field::STRING:
    out << "    string  " << field.name() << ";\n";
    return true;
  case Metadata::Field::GUID:
    out << "    struct  uuid  "<< field.name() << ";\n";
    return true;
  }

  return false;
}

}  //namespace etw2ctf
