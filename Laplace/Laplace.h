#ifndef _LAPLACE_H_
#define _LAPLACE_H_

#define _WIN32_DCOM
 #define WIN32_LEAN_AND_MEAN
#define Exit exit

#include <windows.h>
#include <wbemidl.h>
#include <iostream>
#include <math.h>
#include <string.h>
#include <cstdlib>
#include <cstring>
#include <process.h>
#include <tlhelp32.h>
#include <unistd.h>
#include <stdargs.h>
 #include <iphlpapi.h>
 
#include "Syscall.h"

using namespace std;

#pragma comment(lib, "wbemuuid")
#pragma comment(lib, "Iphlpapi")
#pragma comment(lib, "WS2_32")
#pragma comment(lib, "netapi32.lib")

struct GLOBAL_VAR{
	BOOL CON_REALIZED = FALSE;
	}extern GLOB, *PGLOB = &GLOB;

template<class T>
struct node {
	node<T>* next;
	T data;
};

template<class T>
class LinkedList
{
public:
	node<T>* first;
	node<T>* last;
	LinkedList<T>() {
		first = NULL;
		last = NULL;
	}

	void add(T data) {
		if(!first) {
			first = new node<T>;
			first->data = data;
			first->next = NULL;
			last = first;
		} 
        else {
			if(last == first) {
				last = new node<T>;
				last->data = data;
				last->next = NULL;
				first->next = last;
			} 
            else {
				node<T>* insdata = new node<T>;
				insdata->data = data;
				insdata->next = NULL;
				last->next = insdata;
				last = insdata;
			}
		}
	}

	T get(int index) {
		if(index == 0) {
			
			return this->first->data;
		} 
        else {
			
			node<T>* curr = this->first;
			for(int i = 0; i < index; ++i) {
				curr = curr->next;
			}
			return curr->data;
		}
	}

	T operator[](int index) {
		return get(index);
	}

};

const unsigned char payload = { };

static BOOL CHECK_VM();
static BOOL CHECK_SPEC_VM_INFO();
static DWORD WINAPI WAIT_SVTIME(LPVOID lpstart);
BOOL CHECK_ALLOC_ERROR(int arg, short DATA_TYPE_ID BOOL RETURN,...);
#endif
