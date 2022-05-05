#ifndef _TYPES_H_
#define _TYPES_H_

#include <windows.h>
#include <stddef.h>

#if defined(_MSC_VER)

typedef	LARGE_INTEGER			large_int_t;

#if(_MSC_VER < 1300)

typedef	SIZE_T				size_t;
typedef signed char			int8_t;
typedef signed short		int16_t;
typedef signed int			int32_t;
typedef long long			int64_t

typedef unsigned char		uint8_t;
typedef unsigned short		uint16_t;
typedef unsigned int		uint32_t;
typedef unsigned long long	uint64_t;

#else

#ifndef __cplusplus
//	typedef	SIZE_T				size_t;
#endif

typedef signed __int8		int8_t;
typedef signed __int16		int16_t;
typedef signed __int32		int32_t;
typedef signed __int64		int64_t;

typedef unsigned __int8		uint8_t;
typedef unsigned __int16	uint16_t;
typedef unsigned __int32	uint32_t;
typedef unsigned __int64	uint64_t;

typedef signed long			long_t;
typedef unsigned long		ulong_t;
typedef unsigned char		uchar_t;
typedef unsigned short		ushort_t;

#endif
#if defined(_WIN64)

typedef signed __int64    	intptr_t;
typedef unsigned __int64  	uintptr_t;
typedef	unsigned __int64	size_t;

#else

typedef signed int   		intptr_t;
typedef unsigned int 		uintptr_t;

#endif
#else

#include <sys/types.h>
#include <stdint.h>

#endif

// size_t should be: The maximum number of bytes to which a pointer 
// can point. Use for a count that must span the full range of a pointer.
// typedef unsigned short wchar_t

typedef unsigned int bool_t;

/* should be uppercase but let's make an exception */
#ifndef __cplusplus
#define true 	1
#define false 	0
#endif

#ifndef __cplusplus
#define NULL    ((void *)0)
#define null	((void *)0)
#endif

#if 1
#ifndef offsetof
#define offsetof(s,m) (size_t)&(((s *)0)->m)
#endif
#endif

#ifndef countof
#define countof(a) (sizeof(a) / sizeof(a[0]))
#endif

#define roundup(a, b) \
	(((ulong_t)(a) + (ulong_t)(b) - 1) & ~((ulong_t)(b) - 1))

#define LOW32(l) ((uint32_t)(((uint64_t)(l)) & 0xffffffff))
#define HIGH32(l) ((uint32_t)((((uint64_t)(l)) >> 32) & 0xffffffff))

/*

/* token paste */
#define PASTE_INTERNAL(a, b) a##b 

/* level of indirection for recursive expansion */
#define PASTE_TOKEN(a, b) PASTE_INTERNAL(a, b) 

/* virtual function pointer for vtables */
#define VFUNC(ret_type, name, ...) \
	ret_type (__thiscall* name)(void* object_ptr, __VA_ARGS__);

/* dummy function pointer for vtables */
#define DFUNC() \
	VFUNC(void, PASTE_TOKEN(dummy_function_, __LINE__));

/* virtual function call */
#define VCALL(obj, name, ...) \
	obj->vtable->##name(obj, __VA_ARGS__)


#endif //_TYPES_H_