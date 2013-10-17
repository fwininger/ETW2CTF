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
// Implementation of the CTF stream management.

#ifndef CONVERTER_CTFPRODUCER_H_
#define CONVERTER_CTFPRODUCER_H_

// Restrict the import to the windows basic includes.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>  // NOLINT

#include <cstdint>
#include <fstream>
#include <vector>

namespace converter {

// This class implements the CTF stream management.
//
// A CTF trace is a folder with a single metadata text file and multiple
// stream files.
//
// Example:
//
//  CTFProducer encoder;
//  encoder.OpenFolder(L"ctf", true);
//  encoder.OpenStream(L"stream1");
//  while (...)
//    encoder.Write(buffer, length);
//  encoder.CloseStream();
//
class CTFProducer {
 public:
  // Forward declaration.
  class Packet;

  // Open the CTF root folder.
  // @param folder the root folder of the trace file.
  // @param overwrite if |folder| already exists, this flag indicates if the
  //     folder must be erased first.
  // @returns true on success, false otherwise.
  bool OpenFolder(const std::wstring& folder, bool overwrite);

  // Open and change the active output stream.
  // @param name the name of the stream.
  // @returns true on success, false otherwise.
  bool OpenStream(const std::wstring& name);

  // Close the active output stream.
  // @returns true on success, false otherwise.
  bool CloseStream();

  // Write bytes to the active output stream.
  // @param raw the bytes to write.
  // @param length the number of bytes to write.
  // @returns true on success, false otherwise.
  bool Write(const char* raw, size_t length);

 private:
  // The CTF root folder.
  std::wstring folder_;

  // The active output stream.
  std::ofstream stream_;
};

}  // namespace converter

#endif  // CONVERTER_CTF_PRODUCER_H_
