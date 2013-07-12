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

#ifndef EVENT_H
#define EVENT_H

#include <windows.h>
#include <stdlib.h>
#include <string>
#include <vector>
#include <tdh.h>

class Eventfield
{

public :
	// Fieldtype
	enum FIELDTYPE {
		BIT, BIT5, BIT7, BIT13,
		INT8, INT16, INT32, INT64,
		UINT8, UINT16, UINT32, UINT64,
		XINT8, XINT16, XINT32, XINT64,
		STRING, GUID
	};

public :
	// Type of the eventfield
	FIELDTYPE type;

	// Field Name
	string name;

public :
	// equals
	bool equals(Eventfield* i_eventfield);

};

class Event
{
	GUID guid;
	UCHAR opcode;
	UCHAR version;
	UCHAR eventid;

	// List of eventfield
	vector<Eventfield*> fields;

	// Name of the event
	string name;

	// error status, true if the event has error
	bool init;

public:
	// Constructor
	Event::Event(PEVENT_RECORD);

	Event::~Event();

	// Test the guid, opcode, version, eventid
	bool sameID(Event*);

	// Complet equality
	bool equals(Event*);

	// Print Metadata
	void PrintMetadata(FILE* metadata, int id);

	// return true if the event has an error
	bool error() { return init; }

private:

	// initalize the event
	void load(PEVENT_RECORD);

	DWORD loadEventField(TRACE_EVENT_INFO* pinfo, DWORD i, USHORT indent);

	void renameField();

	// return -1 if not found
	// else return the position in the vector
	size_t existField(Eventfield*);

};

#endif // EVENT_H