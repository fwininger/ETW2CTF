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
//
// Implementation of the ETW consumer.

#ifndef ETW2CTF_ETWCONSUMER_H
#define ETW2CTF_ETWCONSUMER_H

// Restrict the import to the windows basic includes.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>  // NO LINT
// Turns the DEFINE_GUID for EventTraceGuid into a const.
#define INITGUID
#include <guiddef.h>
#include <evntcons.h>
#include <tdh.h>

#include <string>
#include <vector>

#include "Metadata.h"

namespace etw2ctf {

// The ETW consumer uses the windows API to consume ETW events. By using the
// Trace Data Helper (THD), the converter decodes payloads and events layout.
// Decoded payloads are serialized into CTF packets.
class ETWConsumer {
 public:
  typedef void (WINAPI *ProcessEventCallback)(PEVENT_RECORD pEvent);
  typedef ULONG (WINAPI *ProcessBufferCallback)(PEVENT_TRACE_LOGFILE pTrace);

  // Check whether the list of registered trace is empty.
  // @returns true when there is not traces to consume, false otherwise.
  bool Empty() const { return traces_.empty(); }

  // Add a trace file for consuming.
  // @param filename the trace file.
  void AddTraceFile(std::wstring filename) {
    traces_.push_back(filename);
  }

  // Set the global event callback called by the Windows API.
  // This callback must be a trampoline to this->ProcessEvent(...).
  // @param ec the callback called for each event.
  void SetEventCallback(ProcessEventCallback ec) {
    event_callback_ = ec;
  }

  // Set the global buffer callback called by the Windows API.
  // This callback must be a trampoline to this->ProcessBuffer(...).
  // @param bc the callback called for each buffer.
  void SetBufferCallback(ProcessBufferCallback bc) {
    buffer_callback_ = bc;
  }

  // Consume all registered trace files.
  // @returns true on success, false if an error occurred.
  bool ConsumeAllEvents();

  // For a given ETW buffer, produce a unique CTF stream name.
  // @param ptrace the ETW buffer information.
  // @param name receives the stream name.
  // @returns true on success, false otherwise.
  bool GetBufferName(PEVENT_TRACE_LOGFILE ptrace, std::wstring* name) const;

  // Callback called at each stream opening, and append CTF stream header.
  // @param packet the packet to encode the stream header.
  // @returns true on success, false otherwise.
  void ProcessHeader(Metadata::Packet& packet);

  // Callback called for each ETW event. The ETW event is serialized into a
  // CTF packet.
  // @param pevent the ETW event to convert.
  // @param packet on success, contains the serialized CTF event.
  // @returns true on success, false otherwise.
  bool ProcessEvent(PEVENT_RECORD pevent, Metadata::Packet& packet);

  // Callback called at the beginning of each ETW buffer.
  // @param ptrace the ETW buffer information.
  // @returns true on success, false otherwise.
  bool ProcessBuffer(PEVENT_TRACE_LOGFILE ptrace);

  // Serialize the metadata to the CTF text representation.
  // @param results on success, receives the metadata text representation.
  // @returns true on success, false otherwise.
  bool SerializeMetadata(std::string* results) const;

 private:
  bool DecodePayload(
      PEVENT_RECORD pevent, Metadata::Packet& packet, Metadata::Event& descr);
  bool SendRawPayload(
      PEVENT_RECORD pevent, Metadata::Packet& packet, Metadata::Event& descr);

  bool DecodePayloadField(PEVENT_RECORD pevent, PTRACE_EVENT_INFO pinfo,
      unsigned int field, Metadata::Packet& packet, Metadata::Event& descr);

  bool SerializeMetadataEvent(std::stringstream& out,
                              const Metadata::Event& descr, size_t id) const;
  bool SerializeMetadataField(std::stringstream& out,
                              const Metadata::Field& field) const;

  // Trace files to consume.
  std::vector<std::wstring> traces_;

  // Callbacks to register to the ETW API.
  ProcessEventCallback event_callback_;
  ProcessBufferCallback buffer_callback_;

  // The dictionary of event layouts.
  Metadata metadata_;

  // Temporary buffer used to hold raw data produced by the ETW API.
  std::vector<char> data_property_buffer_;
  std::vector<char> formatted_property_buffer_;
  std::vector<char> map_info_buffer_;
  std::vector<char> packet_info_buffer_;
};

}  // namespace etw2ctf

#endif  // ETW2CTF_ETWCONSUMER_H
