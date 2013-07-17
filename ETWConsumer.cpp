// Copyright (c) 2013, Florian Wininger, Etienne Bergeron
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//   * Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//   * Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in the
//     documentation and/or other materials provided with the distribution.
//   * Neither the name of the <organization> nor the
//     names of its contributors may be used to endorse or promote products
//     derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
// THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

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

//  Convert a GUID to a string representation.
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

std::string convertString(const wchar_t* pstr) {
  std::wstring wstr(pstr);
  return std::string(wstr.begin(), wstr.end());
}

void EncodeLargeInteger(Metadata::Packet& packet, const LARGE_INTEGER& value) {
  packet.EncodeUInt32(value.LowPart);
  packet.EncodeUInt32(value.HighPart);
}

void EncodeGUID(Metadata::Packet& packet, const GUID& guid) {
  packet.EncodeUInt8(static_cast<uint8_t>(guid.Data1 >> 24));
  packet.EncodeUInt8(static_cast<uint8_t>(guid.Data1 >> 16));
  packet.EncodeUInt8(static_cast<uint8_t>(guid.Data1 >> 8));
  packet.EncodeUInt8(static_cast<uint8_t>(guid.Data1));

  packet.EncodeUInt8(static_cast<uint8_t>(guid.Data2 >> 8));
  packet.EncodeUInt8(static_cast<uint8_t>(guid.Data2));

  packet.EncodeUInt8(static_cast<uint8_t>(guid.Data3 >> 8));
  packet.EncodeUInt8(static_cast<uint8_t>(guid.Data3));

  packet.EncodeBytes(guid.Data4, 8);
}

}  // namespace

bool ETWConsumer::GetBufferName(PEVENT_TRACE_LOGFILEW ptrace,
                                std::wstring* name) const {
  assert(name != NULL);

  if (!ptrace)
    return false;

  std::wstringstream ss;
  ss << L"stream" << ptrace->BuffersRead;

  *name = ss.str();
  return true;
}

bool ETWConsumer::ConsumeAllEvents() {
  // Open all trace files, and keep handles in a vector.
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

  // If no trace files, leave with an error.
  if (handles.empty())
    return false;

  // Reserve some memory space for internal buffer.
  data_property_buffer_.resize(1024);
  formatted_property_buffer_.resize(1024);
  map_info_buffer_.resize(1024);
  packet_info_buffer_.resize(64*1024);

  // Ask the ETW API to consume all traces and calls the registered callbacks.
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
  const uint32_t kCtfMagicNumber = 0xC1FC1FC1;

  // Output trace.header.magic.
  packet.EncodeUInt32(kCtfMagicNumber);

  // Output trace.header.uuid.
  EncodeGUID(packet, ETWConverterGuid);
}

// This function is executed before each buffer.
bool ETWConsumer::ProcessBuffer(PEVENT_TRACE_LOGFILEW ptrace) {
  assert(ptrace != NULL);
  return true;
}

// This function is executed for each event.
bool ETWConsumer::ProcessEvent(PEVENT_RECORD pevent,
                               Metadata::Packet& packet) {
  assert(pevent != NULL);

  // Skip tracing events.
  if (IsEqualGUID(pevent->EventHeader.ProviderId, EventTraceGuid) &&
      pevent->EventHeader.EventDescriptor.Opcode == EVENT_TRACE_TYPE_INFO) {
    return false;
  }
  // Output stream.header.timestamp.
  EncodeLargeInteger(packet, pevent->EventHeader.TimeStamp);

  // Output stream.header.id, and keep track of the current position to update
  // it later when the payload is fully decoded and can be bound to a valid
  // unique event id.
  size_t event_id = 0;
  size_t event_id_position = packet.size();
  packet.EncodeUInt32(event_id);

  // Output stream.context.ev_*.
  packet.EncodeUInt16(pevent->EventHeader.EventDescriptor.Id);
  packet.EncodeUInt8(pevent->EventHeader.EventDescriptor.Version);
  packet.EncodeUInt8(pevent->EventHeader.EventDescriptor.Channel);
  packet.EncodeUInt8(pevent->EventHeader.EventDescriptor.Level);
  packet.EncodeUInt8(pevent->EventHeader.EventDescriptor.Opcode);
  packet.EncodeUInt16(pevent->EventHeader.EventDescriptor.Task);
  packet.EncodeUInt64(pevent->EventHeader.EventDescriptor.Keyword);

  // Output stream.context.pid/tid/cpu_id.
  packet.EncodeUInt32(pevent->EventHeader.ProcessId);
  packet.EncodeUInt32(pevent->EventHeader.ThreadId);
  packet.EncodeUInt8(pevent->BufferContext.ProcessorNumber);
  packet.EncodeUInt16(pevent->BufferContext.LoggerId);

  // Output stream.context.uuid.
  EncodeGUID(packet, pevent->EventHeader.ProviderId);
  EncodeGUID(packet, pevent->EventHeader.ActivityId);

  // Output stream.context.header_type.
  packet.EncodeUInt16(pevent->EventHeader.HeaderType);

  // Output stream.context.header_flags.
  packet.EncodeUInt16(pevent->EventHeader.Flags);
  packet.EncodeUInt16(pevent->EventHeader.Flags);

  // Output stream.context.header_properties.
  packet.EncodeUInt16(pevent->EventHeader.EventProperty);
  packet.EncodeUInt16(pevent->EventHeader.EventProperty);

  // Output cpu_id.
  packet.EncodeUInt8(pevent->BufferContext.ProcessorNumber);

  // Decode the packet payload.
  Metadata::Event descr;
  size_t payload_position = packet.size();

  if (!DecodePayload(pevent, packet, descr)) {
    // On failure, remove packet data and metadata, and send the raw payload.
    descr.Reset();
    packet.Reset(payload_position);
    if (!SendRawPayload(pevent, packet, descr))
      return false;
  }

  // Update the event_id, now we have the full layout information.
  event_id = metadata_.GetIdForEvent(descr);
  packet.UpdateUInt32(event_id_position, event_id);

  return true;
}

bool ETWConsumer::SendRawPayload(PEVENT_RECORD pevent,
    Metadata::Packet& packet, Metadata::Event& descr) {
  assert(pevent != NULL);

  // Get raw data pointer and size.
  USHORT length = pevent->UserDataLength;
  PVOID data = pevent->UserData;

  // Create the metadata fields.
  Metadata::Field field_size(Metadata::Field::UINT16, "size");
  Metadata::Field field_data(Metadata::Field::BINARY_VAR, "data", "size");
  descr.AddField(field_size);
  descr.AddField(field_data);

  // Encode the length and the payload.
  packet.EncodeUInt16(length);
  packet.EncodeBytes(static_cast<uint8_t*>(data), length);

  return true;
}

bool ETWConsumer::DecodePayload(
     PEVENT_RECORD pevent, Metadata::Packet& packet, Metadata::Event& descr) {
  assert(pevent != NULL);

  // If the EVENT_HEADER_FLAG_STRING_ONLY flag is set, the event data is a
  // null-terminated string. Those events are generated via EventWriteString
  // function.
  if ((pevent->EventHeader.Flags & EVENT_HEADER_FLAG_STRING_ONLY) != 0) {
    // Write string data.
    LPWSTR wptr = (LPWSTR)pevent->UserData;
    std::string str = convertString(wptr);
    packet.EncodeString(str);

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

  // Filter the decoding source we don't know how to handle.
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
    if (!DecodePayloadField(pevent, pinfo, i, packet, descr)) {
      // TODO(bergeret): We should have a fallback that send the field raw.
      return false;
    }
  }

  return true;
}

bool ETWConsumer::DecodePayloadField(PEVENT_RECORD pevent,
                                     PTRACE_EVENT_INFO pinfo,
                                     unsigned int field_index,
                                     Metadata::Packet& packet,
                                     Metadata::Event& descr) {
  assert(pevent != NULL);
  assert(pinfo != NULL);

  // Retrieve the field to decode.
  const EVENT_PROPERTY_INFO& field =
      pinfo->EventPropertyInfoArray[field_index];

  // Retrieve field information.
  size_t count = pinfo->EventPropertyInfoArray[field_index].count;
  size_t length = pinfo->EventPropertyInfoArray[field_index].length;
  size_t flags = pinfo->EventPropertyInfoArray[field_index].Flags;
  PBYTE raw_info = (PBYTE)pinfo;

  // Retrieve field name.
  assert(field.NameOffset != 0);
  size_t name_offset = field.NameOffset;
  LPWSTR name_ptr = (LPWSTR)(&raw_info[name_offset]);
  std::string field_name = convertString(name_ptr);

  // TODO(bergeret): Handle aggregate types (struct, array, ...).
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

  data_descriptors[0].PropertyName =
      (ULONGLONG)((PBYTE)(pinfo) + field.NameOffset);
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
  Metadata::Field::FieldType field_type = Metadata::Field::INVALID;
  switch (in_type) {
    case TDH_INTYPE_UNICODESTRING:
      packet.EncodeString(convertString((LPWSTR)raw_data));
      descr.AddField(Metadata::Field(Metadata::Field::STRING, field_name));
      return true;

    case TDH_INTYPE_ANSISTRING:
      packet.EncodeString((const char*)raw_data);
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
          if (in_type == TDH_INTYPE_INT8) {
            field_type = Metadata::Field::INT8;
          } else {
            field_type = Metadata::Field::UINT8;
          }
          break;
      }

      if (property_size == 1) {
        packet.EncodeUInt8(*reinterpret_cast<uint8_t*>(raw_data));
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
          if (in_type == TDH_INTYPE_INT16) {
            field_type = Metadata::Field::INT16;
          } else {
            field_type = Metadata::Field::UINT16;
          }
          break;
      }

      if (property_size == 2) {
        packet.EncodeUInt16(*reinterpret_cast<uint16_t*>(raw_data));
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
          if (in_type == TDH_INTYPE_INT32) {
            field_type = Metadata::Field::INT32;
          } else {
            field_type = Metadata::Field::UINT32;
          }
          break;
      }

      if (property_size == 4) {
        packet.EncodeUInt32(*reinterpret_cast<uint32_t*>(raw_data));
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
          if (in_type == TDH_INTYPE_INT64) {
            field_type = Metadata::Field::INT64;
          } else {
            field_type = Metadata::Field::UINT64;
          }
          break;
      }

      if (property_size == 8) {
        packet.EncodeUInt64(*reinterpret_cast<uint64_t*>(raw_data));
        descr.AddField(Metadata::Field(field_type, field_name));
        return true;
      }
      break;

    case TDH_INTYPE_BOOLEAN:
      if (property_size == 1) {
        packet.EncodeUInt8(*reinterpret_cast<uint8_t*>(raw_data) != 0);
        descr.AddField(Metadata::Field(Metadata::Field::UINT8, field_name));
        return true;
      } else if (property_size == 4) {
        packet.EncodeUInt8(*reinterpret_cast<uint32_t*>(raw_data) != 0);
        descr.AddField(Metadata::Field(Metadata::Field::UINT8, field_name));
        return true;
      }
      break;

    case TDH_INTYPE_GUID:
      if (property_size == 16) {
        packet.EncodeBytes(raw_data, 16);
        descr.AddField(Metadata::Field(Metadata::Field::GUID, field_name));
        return true;
      }
      break;

    case TDH_INTYPE_POINTER:
      if (property_size == 4) {
        packet.EncodeUInt32(*reinterpret_cast<uint32_t*>(raw_data));
        descr.AddField(Metadata::Field(Metadata::Field::XINT32, field_name));
        return true;
      } else if (property_size == 8) {
        packet.EncodeUInt64(*reinterpret_cast<uint64_t*>(raw_data));
        descr.AddField(Metadata::Field(Metadata::Field::XINT64, field_name));
        return true;
      }
      break;
  }

  return false;
}

bool ETWConsumer::SerializeMetadata(std::string* result) const {
  std::stringstream out;

  out << "/* CTF 1.8 */\n";

  // Define 'bit' type.
  out << "typealias integer "
      << "{ size = 1; align = 1; signed = false; } "
      << ":= bit;\n";

  // Define 'bit1' to 'bit32' types.
  for (int i = 1; i < 32; ++i) {
    out << "typealias integer { "
        << "size = " << i << "; "
        << "align = 1; "
        << "signed = false; "
        << "} := bit" << i << ";\n";
  }

  // Produce each standard size: 1, 2, 4 and 8 bytes.
  for (int i = 0; i < 4; ++i) {
    int size = (1 << i) * 8;

    // Define 'intX' type.
    out << "typealias integer { "
        << "size = " << size << "; "
        << "align = 8; "
        << "signed = true; "
        << "} := int" << size << ";\n";

    // Define 'uintX' type.
    out << "typealias integer { "
        << "size = " << size << "; "
        << "align = 8; "
        << "signed = false; "
        << "} := uint" << size << ";\n";

    // Define 'xintX' type.
    out << "typealias integer { "
        << "size = " << size << "; "
        << "align = 8; "
        << "signed = false; "
        << "base = 16; "
        << "} := xint" << size << ";\n";
  }
  out << "\n";

  out << "struct uuid {\n"
      << "  xint32 Data1;\n"
      << "  xint16 Data2;\n"
      << "  xint16 Data3;\n"
      << "  xint64 Data4;\n"
      << "};\n\n";

  out << "enum event_header_type : uint16 {\n"
      << "  EXT_TYPE_NONE,\n"
      << "  EXT_TYPE_RELATED_ACTIVITYID,\n"
      << "  EXT_TYPE_SID,\n"
      << "  EXT_TYPE_TS_ID,\n"
      << "  EXT_TYPE_INSTANCE_INFO,\n"
      << "  EXT_TYPE_STACK_TRACE32,\n"
      << "  EXT_TYPE_STACK_TRACE64\n"
      << "};\n\n";

  out << "struct event_header_flags {\n"
      << "  bit7 unused;\n"
      << "  bit FLAG_CLASSIC_HEADER;\n"
      << "  bit FLAG_64_BIT_HEADER;\n"
      << "  bit FLAG_32_BIT_HEADER;\n"
      << "  bit FLAG_NO_CPUTIME;\n"
      << "  bit FLAG_TRACE_MESSAGE;\n"
      << "  bit FLAG_STRING_ONLY;\n"
      << "  bit FLAG_PRIVATE_SESSION;\n"
      << "  bit FLAG_EXTENDED_INFO;\n"
      << "};\n\n";

  out << "struct event_header_properties {\n"
      << "  bit13 unused;\n"
      << "  bit EVENT_HEADER_PROPERTY_LEGACY_EVENTLOG;\n"
      << "  bit EVENT_HEADER_PROPERTY_FORWARDED_XML;\n"
      << "  bit EVENT_HEADER_PROPERTY_XML;\n"
      << "};\n\n";

  std::string guid_str = GuidToString(ETWConverterGuid);

  out << "trace {\n"
      << "  major = 1;\n"
      << "  minor = 8;\n"
      << "  uuid  = \"" << guid_str << "\";\n"
      << "  byte_order = le;\n"
      << "  packet.header := struct {\n"
      << "    uint32  magic;\n"
      << "    xint8   uuid[16];\n"
      << "  };\n"
      << "};\n\n";

  out << "stream {\n"
      << "  event.header := struct {\n"
      << "    uint64  timestamp;\n"
      << "    uint32  id;\n"
      << "  };\n"
      << "  event.context := struct {\n"
      << "    uint16  ev_id;\n"
      << "    uint8   ev_version;\n"
      << "    uint8   ev_channel;\n"
      << "    uint8   ev_level;\n"
      << "    uint8   ev_opcode;\n"
      << "    uint16  ev_task;\n"
      << "    xint64  ev_keyword;\n"
      << "    uint32  pid;\n"
      << "    uint32  tid;\n"
      << "    uint8   cpu_id;\n"
      << "    uint16  logger_id;\n"
      << "    struct  uuid provider_id;\n"
      << "    struct  uuid activity_id;\n"
      << "    enum    event_header_type header_type;\n"
      << "    xint16  header_flags;\n"
      << "    struct  event_header_flags header_flags_decoded;\n"
      << "    xint16  header_properties;\n"
      << "    struct  event_header_properties header_properties_decoded;\n"
      << "  };\n"
      << "};\n\n";

  out << "event {\n"
      << "  id = 0;\n"
      << "  name = \"unknown\";\n"
      << "  fields := struct {\n"
      << "    uint8   cpuid;\n"
      << "  };\n"
      << "};\n\n";

  // For each event layout in our dictionary, produce the CTF metadata.
  for (size_t i = 0; i < metadata_.size(); ++i) {
    size_t event_id = i + 1;
    const Metadata::Event& descr = metadata_.GetEventWithId(i);
    if (!SerializeMetadataEvent(out, descr, event_id))
      return false;
  }

  // Commit the results.
  *result = out.str();
  return true;
}

bool ETWConsumer::SerializeMetadataEvent(
    std::stringstream& out, const Metadata::Event& descr, size_t event_id) const {

  out << "event {\n"
      << "  id = " << event_id << ";\n";

  if (descr.name().empty()) {
    out << "  name = \"event" << event_id << "\";\n";
  } else {
    out << "  name = \"" << descr.name() << "\";\n";
  }

  // Event Fields
  out <<"  fields := struct {\n"
      << "    uint8   cpuid;\n";

  for (size_t i = 0; i < descr.size(); ++i) {
    if (!SerializeMetadataField(out, descr.at(i)))
      return false;
  }
  out <<"  };\n";

  out <<"};\n\n";

  return true;
}

bool ETWConsumer::SerializeMetadataField(std::stringstream& out,
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

}  // namespace etw2ctf
