// Copyright (c) 2013 The ETW2CTF Authors.
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
// ETW2CTF translates a trace file from ETW (Event Tracing for Windows) trace
// file format to the CTF (Common Trace Format) trace file format.
//
// ETW (Event Tracing for windows) provides the ability to trace Windows kernel
// and user-space application for debugging or profiling. ETL files are binary
// encoded file format, but ETW provides an API to retrieve the events format.
//
// See: http://msdn.microsoft.com/en-us/library/windows/desktop/bb968803(v=vs.85).aspx
//
// The performance SDK (an optional include from the Microsoft SDK) provides
// performance analysis tools to gather ETW traces. The SDK also installs some
// manifest to describe performance events.
//
// See: http://msdn.microsoft.com/en-us/performance/cc825801.aspx
//
// Common Trace Format is a self-describing file format used for tracing tools
// interoperability.
//
// See: http://www.efficios.com/ctf

#include <iostream>
#include <string>

#include "converter/ctf_producer.h"
#include "converter/etw_consumer.h"
#include "converter/metadata.h"

namespace {

using converter::Metadata;

converter::ETWConsumer consumer;
converter::CTFProducer producer;

void WINAPI ProcessEvent(PEVENT_RECORD pevent) {
  assert(pevent != NULL);

  consumer.ProcessEvent(pevent);

  while (consumer.IsFullPacketReady()) {
     // Write the full packet into the current stream.
     Metadata::Packet output;
     consumer.BuildFullPacket(&output);
     const char* raw = reinterpret_cast<const char*>(output.raw_bytes());
     if (!producer.Write(raw, output.size())) {
       std::cerr << "Cannot write packet into stream." << std::endl;
       return;
     }
  }
}

void FlushEvents() {
  while (!consumer.IsSendingQueueEmpty()) {
     // Write the full packet into the current stream.
     Metadata::Packet output;
     consumer.BuildFullPacket(&output);
     const char* raw = reinterpret_cast<const char*>(output.raw_bytes());
     if (!producer.Write(raw, output.size())) {
       std::cerr << "Cannot write packet into stream." << std::endl;
       return;
     }
  }
}

ULONG WINAPI ProcessBuffer(PEVENT_TRACE_LOGFILEW ptrace) {
  assert(ptrace != NULL);

  // Close the previous stream.
  producer.CloseStream();

  // Open the next buffer.
  std::wstring stream_name;
  if (!consumer.GetBufferName(ptrace, &stream_name)) {
    std::wcerr << L"Cannot get buffer name." << std::endl;
    return FALSE;
  }

  if (!producer.OpenStream(stream_name)) {
    std::wcerr << L"Cannot open output stream: \"" << stream_name << L"\""
               << std::endl;
    return FALSE;
  }

  if (!consumer.ProcessBuffer(ptrace))
    return FALSE;

  return TRUE;
}

bool FileExists(const std::wstring& path) {
  DWORD attrib = GetFileAttributes(path.c_str());
  return (attrib != INVALID_FILE_ATTRIBUTES &&
         !(attrib & FILE_ATTRIBUTE_DIRECTORY));
}

struct Options {
  bool help;
  bool overwrite;
  std::wstring output;
  bool split_buffer;
  size_t packet_size;
  std::vector<std::wstring> files;
};

void DefaultOptions(Options* options) {
  assert(options != NULL);
  options->help = false;
  options->output = L"ctf";
  options->overwrite = false;
  options->split_buffer = false;
  options->packet_size = 4096;
}

bool ParseOptions(int argc, wchar_t** argv, Options* options) {
  assert(argv != NULL);
  assert(options != NULL);

  // Activate help when no arguments.
  if (argc == 1) {
    options->help = true;
    return true;
  }

  for (int i = 1; i < argc; ++i) {
    std::wstring arg(argv[i]);

    // Not an option, push it as a file to process.
    if (!arg.empty() && arg[0] != '-') {

      // Check whether the file exists.
      if (!FileExists(arg)) {
        std::wcerr << "File doesn't exist: \"" << arg << "\"" << std::endl;
        return false;
      }
      options->files.push_back(arg);
      continue;
    }

    // Next argument may be a parameter.
    std::wstring param;
    if (i + 1 < argc)
      param = argv[i + 1];

    if (arg == L"-h" || arg == L"--help") {
      options->help = true;
      continue;
    }

    if (arg == L"--output" && !param.empty()) {
      options->output = param;
      ++i;
      continue;
    }

    if (arg == L"--overwrite") {
      options->overwrite = true;
      continue;
    }

    if (arg == L"--split-buffer") {
      options->split_buffer = true;
      continue;
    }

    if (arg == L"--packet-size") {
      std::string p(param.begin(), param.end());
      int size = atoi(p.c_str());
      if (size <= 1) {
        std::wcerr << "Invalid packet size '" << param << "'" << std::endl;
        return false;
      }
      ++i;
      options->packet_size = size;
      continue;
    }

    std::wcerr << L"Unknown argument: \"" << arg << L"\"" << std::endl;
    return false;
  }

  return true;
}

void PrintUsage() {
  std::wcerr
      << "\n"
      << "  USAGE: etw2ctf [options] <traces.etl>*\n"
      << "\n"
      << "  [options]\n"
      << "    --help\n"
      << "        Print this message.\n"
      << "    --output [dir]\n"
      << "        Specify the output directory for the produced CTF trace.\n"
      << "    --overwrite\n"
      << "        Overwrite the output directory.\n"
      << "    --split-buffer\n"
      << "        Split each ETW buffers in a separate CTF stream.\n"
      << "    --packet-size <size>\n"
      << "        Split CTF stream into CTF packets of <size> bytes.\n"
      << "\n"
      << std::endl;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
  struct Options options;

  // Initialize options with default values.
  DefaultOptions(&options);

  // Parse command-line options.
  if (!ParseOptions(argc, argv, &options))
    return -1;

  // Print usage when requested or command-line empty.
  if (options.help) {
    PrintUsage();
    return 0;
  }

  // Open the output folder.
  if (!producer.OpenFolder(options.output, options.overwrite)) {
    std::wcerr << L"Cannot open output directory \"" << options.output << L"\""
               << std::endl;
    return -1;
  }

  // Add traces to be consumed to the consumer.
  for (std::vector<std::wstring>::iterator it = options.files.begin();
       it != options.files.end();
       ++it) {
    consumer.AddTraceFile(*it);
  }

  // No trace files to consume.
  if (consumer.Empty())
    return 0;

  consumer.SetEventCallback(ProcessEvent);
  if (options.split_buffer)
    consumer.SetBufferCallback(ProcessBuffer);

  consumer.set_packet_maximal_size(options.packet_size);

  // Consume trace files.
  if (!producer.OpenStream(L"stream")) {
    std::wcerr << L"Cannot open output stream." << std::endl;
    return -1;
  }

  // Consume all events. The ETW API will call our registered callbacks on
  // each buffer and each event. Callbacks forward the processing to the
  // consumer via ProcessEvent and ProcessBuffer. After the processing of each
  // event by the consumer, the packet (encoded event) is written to the
  // producer.
  if (!consumer.ConsumeAllEvents()) {
    std::wcerr << L"Could not consume traces files." << std::endl;
    return -1;
  }
  FlushEvents();
  producer.CloseStream();

  // Serialize the metadata build during events processing.
  if (!producer.OpenStream(L"metadata")) {
    std::wcerr << L"Cannot open metadata stream." << std::endl;
    return -1;
  }

  std::string metadata;
  if (!consumer.SerializeMetadata(&metadata))
    return -1;
  if (!producer.Write(metadata.c_str(), metadata.size()))
    return -1;
  producer.CloseStream();

  return 0;
}
