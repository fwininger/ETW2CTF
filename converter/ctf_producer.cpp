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

#include "converter/ctf_producer.h"

#include <cassert>
#include <iostream>
#include <sstream>
#include <string>

namespace converter {

bool CTFProducer::OpenFolder(const std::wstring& folder, bool overwrite) {
  if (!folder_.empty() || folder.empty())
    return false;
  folder_ = folder;

  // Try to create the folder.
  if (CreateDirectory(folder_.c_str(), NULL) == TRUE)
    return true;

  // We cannot overwrite the folder.
  if (!overwrite || GetLastError() != ERROR_ALREADY_EXISTS)
    return false;

  // Erase all files in the folder.
  bool erase_all_sucessful = true;
  WIN32_FIND_DATA FindFileData;
  std::wstring pattern = folder + L"\\*";
  HANDLE hFind = FindFirstFile(pattern.c_str(), &FindFileData);
  while (hFind != INVALID_HANDLE_VALUE) {
    std::wstring filename = FindFileData.cFileName;
    std::wstring path = folder + L"\\" + filename;

    // Erase the current file.
    if (filename != L"." && filename != L".." &&
        DeleteFile(path.c_str()) == FALSE) {
      std::wcerr << L"Could not erase file \"" << path << L"\"" << std::endl;
      erase_all_sucessful = false;
    }

    // Move to the next file.
    if (!FindNextFile(hFind, &FindFileData)) {
      FindClose(hFind);
      hFind = INVALID_HANDLE_VALUE;
    }
  }

  // Returns success when all files are removed.
  return erase_all_sucessful;
}

bool CTFProducer::OpenStream(const std::wstring& filename) {
  assert(!stream_.is_open());

  std::wstringstream ss;
  ss << folder_ << L"\\" << filename;

  stream_.open(ss.str(),
      std::ofstream::out | std::ofstream::trunc | std::ofstream::binary);
  return stream_.good();
}

bool CTFProducer::CloseStream() {
  if (!stream_.is_open())
    return false;
  stream_.close();

  if (stream_.fail())
    return false;

  return true;
}

bool CTFProducer::Write(const char* raw, size_t length) {
  assert(raw != NULL);

  if (!stream_.is_open())
    return false;
  assert(stream_.good());
  stream_.write(raw, length);

  return true;
}

}  // namespace converter
