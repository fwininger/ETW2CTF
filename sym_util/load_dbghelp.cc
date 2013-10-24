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

// Restrict the import to the windows basic includes.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>  // NOLINT

#include "sym_util/load_dbghelp.h"

#include <string>
#include <vector>

namespace sym_util {

bool LoadDbgHelp() {
  const wchar_t* kXperfFilename = L"xperf.exe";
  const std::wstring kDirSeparator(L"\\");
  const std::wstring kDbgHelpFilename(L"dbghelp.dll");
  const std::wstring kDebuggersDirname(L"Debuggers");
#ifdef _WIN64
  const std::wstring kArchitectureDirName(L"x64");
#else
  const std::wstring kArchitectureDirName(L"x86");
#endif
  // Indicates whether DbgHelp has already been loaded using this function.
  static bool wpt_dbghelp_loaded = false;

  if (wpt_dbghelp_loaded)
    return true;

  // Check whether DbgHelp is already in memory.
  if (::GetModuleHandleW(kDbgHelpFilename.c_str()))
    return wpt_dbghelp_loaded;

  // Find the installation directory of Windows Performance Toolkit.
  std::vector<wchar_t> xperf_filename_buffer(MAX_PATH);
  DWORD search_path_ret = ::SearchPathW(NULL, kXperfFilename, NULL,
                                        xperf_filename_buffer.size(),
                                        &xperf_filename_buffer[0], NULL);
  if (search_path_ret > xperf_filename_buffer.size()) {
    // Try again with a bigger buffer for the path.
    xperf_filename_buffer.resize(search_path_ret);
    search_path_ret = ::SearchPathW(NULL, kXperfFilename, NULL,
                                    xperf_filename_buffer.size(),
                                    &xperf_filename_buffer[0], NULL);
  }

  if (search_path_ret == 0 || search_path_ret > xperf_filename_buffer.size())
    return false;

  std::wstring xperf_filename(&xperf_filename_buffer[0]);
  size_t xperf_filename_index = xperf_filename.find_last_of(kDirSeparator);
  std::wstring wpt_installation_dir =
      xperf_filename.substr(0, xperf_filename_index);

  // Try to load DbgHelp from the WPT installation directory.
  std::wstring dbghelp_full_path =
      wpt_installation_dir + kDirSeparator + kDbgHelpFilename;
  if (::LoadLibraryExW(dbghelp_full_path.c_str(), NULL, 0)) {
    wpt_dbghelp_loaded = true;
    return true;
  }

  // Try to load DbgHelp from
  // "{WPT installation directory}\..\Debuggers\{x86|x64}\".
  dbghelp_full_path = wpt_installation_dir + kDirSeparator + L".." +
      kDirSeparator + kDebuggersDirname + kDirSeparator + kArchitectureDirName +
      kDirSeparator + kDbgHelpFilename;
  if (::LoadLibraryExW(dbghelp_full_path.c_str(), NULL, 0)) {
    wpt_dbghelp_loaded = true;
    return true;
  }

  // TODO(fdoray): Check whether the DbgHelp library can be loaded from other
  // locations.

  // Try to load the default DbgHelp library, which cannot communicate with a
  // symbol server. It can still get symbols from local symbol files.
  ::LoadLibraryExW(kDbgHelpFilename.c_str(), NULL, 0);
  return false;
}

}  // namespace sym_util
