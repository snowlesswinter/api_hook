#ifndef _INTRUSIVE_PTR_HELPER_H_
#define _INTRUSIVE_PTR_HELPER_H_

#include "boost/intrusive_ptr.hpp"
#include <unknwn.h>

namespace kugou
{
class CNonDelegatingUnknown;
}

class CUnknown;

namespace boost
{
template <typename T>
inline void intrusive_ptr_add_ref(T* p) { p->AddRef(); }

template <typename T>
inline void intrusive_ptr_release(T* p) { p->Release(); }

template <>
inline void intrusive_ptr_add_ref(kugou::CNonDelegatingUnknown* p)
{
    reinterpret_cast<IUnknown*>(p)->AddRef();
}

template <>
inline void intrusive_ptr_release(kugou::CNonDelegatingUnknown* p)
{
    reinterpret_cast<IUnknown*>(p)->Release();
}

template <>
inline void intrusive_ptr_add_ref(CUnknown* p)
{
    reinterpret_cast<IUnknown*>(p)->AddRef();
}

template <>
inline void intrusive_ptr_release(CUnknown* p)
{
    reinterpret_cast<IUnknown*>(p)->Release();
}
}

#endif  // _INTRUSIVE_PTR_HELPER_H_