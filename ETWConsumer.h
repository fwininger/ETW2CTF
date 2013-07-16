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
#ifndef ETW2CTF_ETWCONSUMER_H
#define ETW2CTF_ETWCONSUMER_H

#include "Metadata.h"

#include <string>
#include <vector>

// Some missing definition and typedef from the windows API.
typedef unsigned long ULONG;
#define FALSE 0
#define TRUE 1
#define WINAPI      __stdcall

// Incomplete definitions.
typedef struct _EVENT_RECORD *PEVENT_RECORDW;
typedef struct _EVENT_TRACE_LOGFILEW *PEVENT_TRACE_LOGFILEW;
typedef struct _TRACE_EVENT_INFO *PTRACE_EVENT_INFO;

typedef void (WINAPI *ProcessEventCallback)(PEVENT_RECORDW pEvent);
typedef ULONG (WINAPI *ProcessBufferCallback)(PEVENT_TRACE_LOGFILEW pTrace);

namespace etw2ctf {

class ETWConsumer {
 public:
  ETWConsumer() : stream_context_emitted_(false) {
  }

  bool Empty() const { return traces_.empty(); }

  void AddTraceFile(std::wstring filename) {
    traces_.push_back(filename);
  }

  void SetEventCallback(ProcessEventCallback ec) {
    event_callback_ = ec;
  }

  void SetBufferCallback(ProcessBufferCallback bc) {
    buffer_callback_ = bc;
  }

  bool ConsumeAllEvents();

  bool GetBufferName(PEVENT_TRACE_LOGFILEW pTrace, std::wstring* name) const;

  void ProcessHeader(Metadata::Packet& packet);
  bool ProcessEvent(Metadata::Packet& packet, PEVENT_RECORDW pEvent);
  bool ProcessBuffer(PEVENT_TRACE_LOGFILEW pTrace);

  bool SerializeMetadata(std::ostream& stream) const;

 private:
  bool DecodePayload(
    Metadata::Packet& packet, Metadata::Event& descr, PEVENT_RECORDW pEvent);
  bool SendRawPayload(
    Metadata::Packet& packet, Metadata::Event& descr, PEVENT_RECORDW pEvent);

  bool DecodePayloadField(Metadata::Packet& packet, Metadata::Event& descr,
    PEVENT_RECORDW pEvent, PTRACE_EVENT_INFO pinfo, unsigned int field);

  bool SerializeMetadataEvent(std::ostream& out,
                              const Metadata::Event& descr, size_t id) const;
  bool SerializeMetadataField(std::ostream& out,
                              const Metadata::Field& field) const;

  std::vector<std::wstring> traces_;
  ProcessEventCallback event_callback_;
  ProcessBufferCallback buffer_callback_;

  Metadata metadata_;
  bool stream_context_emitted_;

  std::vector<char> data_property_buffer_;
  std::vector<char> formatted_property_buffer_;
  std::vector<char> map_info_buffer_;
  std::vector<char> packet_info_buffer_;

};

}  // namespace etw2ctf

#endif  // ETW2CTF_ETWCONSUMER_H
