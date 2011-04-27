#ifndef _INJECTOR_H_
#define _INJECTOR_H_

#include <boost/shared_ptr.hpp>

class Injector
{
public:
    static Injector* __stdcall CreateHookGetMessageInjector(void* host);

    virtual ~Injector();

    virtual int Inject(int processID) = 0;

protected:
    Injector(void* host);

    void* getHookCoreModule() const { return hookCore_.get(); }
    const void* getHookProc() const { return hookProc_; }

private:
    boost::shared_ptr<void> hookCore_;
    const void* hookProc_;
};

//------------------------------------------------------------------------------
class HookGetMessageInjector : public Injector
{
public:
    virtual ~HookGetMessageInjector();

    virtual int Inject(int processID);

protected:
    friend class Injector;
    HookGetMessageInjector(void* host);

private:
    boost::shared_ptr<void> hookHandle_;
};

#endif  // _INJECTOR_H_