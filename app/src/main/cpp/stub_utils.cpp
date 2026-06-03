#include "utils/RefBase.h"
#include "utils/String16.h"
#include "utils/String8.h"
#include "utils/StrongPointer.h"

namespace android {

RefBase::RefBase() : mRefs(nullptr) {}
RefBase::~RefBase() {}
void RefBase::incStrong(const void *) const {}
void RefBase::incStrongRequireStrong(const void *) const {}
void RefBase::decStrong(const void *) const {}
void RefBase::forceIncStrong(const void *) const {}
RefBase::weakref_type *RefBase::createWeak(const void *) const { return nullptr; }
RefBase::weakref_type *RefBase::getWeakRefs() const { return nullptr; }
void RefBase::onFirstRef() {}
void RefBase::onLastStrongRef(const void *) {}
bool RefBase::onIncStrongAttempted(uint32_t, const void *) { return false; }
void RefBase::onLastWeakRef(const void *) {}
void RefBase::extendObjectLifetime(int) {}
RefBase *RefBase::weakref_type::refBase() const { return nullptr; }
void RefBase::weakref_type::incWeak(const void *) {}
void RefBase::weakref_type::incWeakRequireWeak(const void *) {}
void RefBase::weakref_type::decWeak(const void *) {}
bool RefBase::weakref_type::attemptIncStrong(const void *) { return false; }
bool RefBase::weakref_type::attemptIncWeak(const void *) { return false; }
void sp_report_race() {}

String8::String8() {}
String8::~String8() {}
String16::String16() {}
String16::String16(const String16 &) {}
String16::String16(String16 &&) noexcept {}
String16::String16(const char *) {}
String16::String16(const char16_t *, size_t) {}
String16::~String16() {}

} // namespace android
