#ifndef _CUSTOM_HOOK_DESC_H_
#define _CUSTOM_HOOK_DESC_H_

#include <unknwn.h>

class CustomProcedureDesc : public IUnknown
{
public:
    virtual int __stdcall GetAPIName(char* buf, int size) = 0;
    virtual int __stdcall GetAPIModuleName(char* buf, int size) = 0;
    virtual const void* __stdcall GetCustomFuncAddress() = 0;
};

//------------------------------------------------------------------------------
class CustomProcHookDescEnum : public IUnknown
{
public:
    virtual void __stdcall Reset() = 0;
    virtual bool __stdcall Next(CustomProcedureDesc** desc) = 0;
};

//------------------------------------------------------------------------------
typedef int (__stdcall* CustomProcHookDescEnumCreateFunc)(
    CustomProcHookDescEnum**);

//------------------------------------------------------------------------------
typedef int (__stdcall IUnknown::* CustomMethod)();

struct CustomMethodTable
{
    CustomMethod Method;
    enum { kIgnore, kTargetProcedure, kFactory } MethodType;
};

enum FactoryProcSignature
{
    kR_stdcall_0,
    kR_stdcall_1,
    kR_stdcall_2,
    kR_stdcall_3,
    kR_stdcall_4,
    kR_stdcall_5,
    kR_stdcall_6,
    kR_stdcall_7,
    kR_stdcall_8,
    kR_stdcall_9,
    kR_cdecl_0,
    kR_fastcall_0,
    kN_stdcall_0,
};

class COMFactoryAPIDesc : public IUnknown
{
public:
    virtual int __stdcall EnumFactoryAPI(COMFactoryAPIDesc** desc) = 0;
    virtual int __stdcall GetFactoryProcedureName(char* buf, int size) = 0;
    virtual int __stdcall GetCOMObjSeqNum() = 0;
    virtual FactoryProcSignature __stdcall GetFactoryProcSignature() = 0;
};

class COMHookFactoryDescEnum : public IUnknown
{
public:
    virtual void __stdcall Reset() = 0;
    virtual bool __stdcall Next(COMFactoryAPIDesc** desc) = 0;
};

class CustomCOMHookDesc : public IUnknown
{
public:
    virtual int __stdcall EnumFactoryAPI(COMHookFactoryDescEnum** descEnum) = 0;
    virtual int __stdcall GetInterfaceName(char* buf, int size) = 0;
    virtual int __stdcall GetAPIModuleName(char* buf, int size) = 0;
    virtual int __stdcall GetCustomMethods(CustomMethodTable* table,
                                           int count) = 0;
};

class CustomCOMHookDescEnum : public IUnknown
{
public:
    virtual void __stdcall Reset() = 0;
    virtual bool __stdcall Next(CustomCOMHookDesc** desc) = 0;
};

//------------------------------------------------------------------------------
typedef int (__stdcall* CustomCOMHookDescEnumCreateFunc)(
    CustomCOMHookDescEnum**);
#endif  // _CUSTOM_HOOK_DESC_H_