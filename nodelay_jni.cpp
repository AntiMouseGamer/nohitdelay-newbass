// nodelay_jni.cpp
// JNI glue: JVM discovery, class-loader enumeration, profile matching.
// Reconstructed from 0x1600/0x1650/0x16a0 (vtable wrappers), 0x1d60
// (vector<string>::push_back), 0x4680 (string search), 0x4c40 (loader
// enumeration) and 0x60d0 (the JVM worker thread).

#include "nodelay_types.h"

#include <jni.h>

#include <cstring>
#include <string>
#include <vector>

namespace nodelay {

// ---------------------------------------------------------------------------
// JNI vtable thunks
//
// 0x1600 -> JNINativeInterface[0x118/8 == 35]  CallObjectMethodV
// 0x1650 -> JNINativeInterface[0x398/8 == 115] CallStaticObjectMethodV
// 0x16a0 -> FindClass("java/lang/Class") + GetStaticMethodID("forName", ...)
//
// The reconstructed code calls the real JNI entry points directly; the
// thunks existed in the binary only because libstdc++ emitted them as
// out-of-line helpers.
// ---------------------------------------------------------------------------

// 0x16a0 -- Class.forName(name, initialize=false, loader)
static jclass ForName(JNIEnv* env, const char* name, jobject loader) {
    jclass clsClass = env->FindClass("java/lang/Class");
    if (!clsClass) return nullptr;

    jmethodID forName = env->GetStaticMethodID(
        clsClass, "forName",
        "(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;");
    if (!forName) return nullptr;

    jstring jname = env->NewStringUTF(name);
    if (!jname) return nullptr;

    jobject result = env->CallStaticObjectMethod(clsClass, forName, jname,
                                                 static_cast<jboolean>(JNI_FALSE),
                                                 loader);
    env->DeleteLocalRef(jname);
    env->DeleteLocalRef(clsClass);
    return static_cast<jclass>(result);
}

// 0x4680 -- linear search over a vector<string> for an exact match.
// The element stride in the binary is 0x28 (std::string with capacity word).
static bool VectorContains(const std::vector<std::string>& v, const std::string& s) {
    for (const auto& e : v) {
        if (e == s) return true;
    }
    return false;
}

// 0x1d60 -- vector<std::string>::push_back
static void PushString(std::vector<std::string>& v, std::string&& s) {
    v.push_back(std::move(s));
}

// ---------------------------------------------------------------------------
// 0x4c40 -- enumerateClassLoaders()
//
//   ClassLoader.getSystemClassLoader()
//   Thread.getAllStackTraces().keySet().toArray()
//   for each Thread t: t.getContextClassLoader()
//   names them "thread-context-<n>" for the diagnostic log
// ---------------------------------------------------------------------------
std::vector<std::string> EnumerateClassLoaders(JNIEnv* env) {
    std::vector<std::string> names;

    // java/lang/ClassLoader#getSystemClassLoader
    jclass clsLoader = env->FindClass("java/lang/ClassLoader");
    if (!clsLoader) return names;

    jmethodID getSystem = env->GetStaticMethodID(
        clsLoader, "getSystemClassLoader", "()Ljava/lang/ClassLoader;");
    if (!getSystem) { env->DeleteLocalRef(clsLoader); return names; }

    jobject sysLoader = env->CallStaticObjectMethod(clsLoader, getSystem);
    env->ExceptionClear();

    // java/lang/Thread#getAllStackTraces -> java/util/Map
    jclass clsThread = env->FindClass("java/lang/Thread");
    jclass clsMap    = env->FindClass("java/util/Map");
    jclass clsSet    = env->FindClass("java/util/Set");

    if (clsThread && clsMap && clsSet) {
        jmethodID getAll = env->GetStaticMethodID(
            clsThread, "getAllStackTraces", "()Ljava/util/Map;");
        jmethodID keySet = env->GetMethodID(clsMap, "keySet", "()Ljava/util/Set;");
        jmethodID toArray = env->GetMethodID(clsSet, "toArray", "()[Ljava/lang/Object;");
        jmethodID getCcl = env->GetMethodID(clsLoader, "getContextClassLoader",
                                            "()Ljava/lang/ClassLoader;");

        if (getAll && keySet && toArray && getCcl) {
            jobject map = env->CallStaticObjectMethod(clsThread, getAll);
            if (map) {
                jobject set = env->CallObjectMethod(map, keySet);
                if (set) {
                    jobjectArray arr = static_cast<jobjectArray>(
                        env->CallObjectMethod(set, toArray));
                    if (arr) {
                        jsize n = env->GetArrayLength(arr);
                        int index = 0;
                        for (jsize i = 0; i < n; ++i) {
                            jobject th = env->GetObjectArrayElement(arr, i);
                            if (!th) continue;

                            // t.getContextClassLoader()
                            jclass clsT = env->GetObjectClass(th);
                            jmethodID getCcl2 = env->GetMethodID(
                                clsT, "getContextClassLoader",
                                "()Ljava/lang/ClassLoader;");
                            jobject ccl = getCcl2
                                ? env->CallObjectMethod(th, getCcl2)
                                : nullptr;
                            env->ExceptionClear();

                            if (ccl) {
                                // "thread-context-<n>"
                                std::string label = kThreadContextPrefix;
                                label += std::to_string(index++);
                                PushString(names, std::move(label));
                                env->DeleteLocalRef(ccl);
                            }
                            env->DeleteLocalRef(clsT);
                            env->DeleteLocalRef(th);
                        }
                        env->DeleteLocalRef(arr);
                    }
                    env->DeleteLocalRef(set);
                }
                env->DeleteLocalRef(map);
            }
        }
    }

    if (sysLoader) env->DeleteLocalRef(sysLoader);
    if (clsLoader) env->DeleteLocalRef(clsLoader);
    if (clsThread) env->DeleteLocalRef(clsThread);
    if (clsMap)    env->DeleteLocalRef(clsMap);
    if (clsSet)    env->DeleteLocalRef(clsSet);

    return names;
}

// ---------------------------------------------------------------------------
// Profile matching: try each profile against each loader until the class,
// getter and hit field all resolve. Errors mirror the Portuguese messages
// at 0xc0448 .. 0xc05a1.
// ---------------------------------------------------------------------------
bool ResolveProfile(JNIEnv* env, const std::vector<Profile>& profiles,
                    JniBinding& out, std::string& err) {
    if (profiles.empty()) {
        err = kErrNotFoundPrefix;
        err += kErrNoCompleteProfile;
        return false;
    }

    // Loaders to probe: the system loader first, then every thread-context
    // loader discovered by EnumerateClassLoaders.
    std::vector<std::string> loaderLabels = EnumerateClassLoaders(env);

    bool sawClass = false;
    bool sawGetter = false;
    bool sawField = false;

    for (const Profile& p : profiles) {
        // "java/lang/ClassLoader" -> jclass for Class.forName
        jclass clsClass = env->FindClass("java/lang/Class");
        if (!clsClass) continue;
        jmethodID forName = env->GetStaticMethodID(
            clsClass, "forName",
            "(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;");
        env->DeleteLocalRef(clsClass);
        if (!forName) continue;

        // mcClass is stored in JVM dotted form; convert to slashes.
        std::string binary = p.mcClass;
        for (char& c : binary) if (c == '.') c = '/';

        jstring jcls = env->NewStringUTF(binary.c_str());
        if (!jcls) continue;

        jobject mcClsObj = env->CallStaticObjectMethod(
            env->FindClass("java/lang/Class"), forName, jcls,
            static_cast<jboolean>(JNI_FALSE), nullptr);
        env->ExceptionClear();
        env->DeleteLocalRef(jcls);

        if (!mcClsObj) { sawClass = false; continue; }
        sawClass = true;

        jclass mcCls = static_cast<jclass>(mcClsObj);

        // static getter, e.g. getMinecraft / func_71410_x / ave
        jmethodID getter = env->GetStaticMethodID(mcCls, p.mcGetter.c_str(),
                                                  "()L" ";");
        if (!getter) {
            // Retry with a "()Ljava/lang/Object;" signature, which is what the
            // obfuscated profiles actually expose.
            getter = env->GetStaticMethodID(mcCls, p.mcGetter.c_str(),
                                            "()Ljava/lang/Object;");
        }
        if (!getter) { sawGetter = false; env->DeleteLocalRef(mcCls); continue; }
        sawGetter = true;

        // instance field holding the click/hit counter
        jfieldID hit = env->GetFieldID(mcCls, p.hitField.c_str(), "I");
        if (!hit && !p.hitAlternative.empty()) {
            hit = env->GetFieldID(mcCls, p.hitAlternative.c_str(), "I");
        }
        if (!hit) { sawField = false; env->DeleteLocalRef(mcCls); continue; }
        sawField = true;

        out.mcCls    = static_cast<jclass>(env->NewGlobalRef(mcCls));
        out.getter   = getter;
        out.hitField = hit;
        env->DeleteLocalRef(mcCls);
        err.clear();
        return true;
    }

    if (!sawClass) {
        err = kErrClassNotVisible;
        err += kErrSeeLog;
    } else if (!sawGetter) {
        err = kErrGetterNotFound;
        err += kErrSeeLog;
    } else if (!sawField) {
        err = kErrHitFieldNotFound;
        err += kErrSeeLog;
    } else {
        err = kErrUnrecognisedClasses;
        err += std::to_string(loaderLabels.size());
        err += kErrSeeLog;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Read / write helpers used when the fix pushes values back into the JVM.
//   0xc0589 ": falha na leitura JNI."
//   0xc05a1 ": falha na escrita JNI."
// ---------------------------------------------------------------------------
bool JniReadInt(JNIEnv* env, jobject instance, jfieldID field, jint& out,
                std::string& err) {
    if (!env || !instance || !field) {
        err = kErrJniRead;
        return false;
    }
    out = env->GetIntField(instance, field);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        err = kErrJniRead;
        return false;
    }
    return true;
}

bool JniWriteInt(JNIEnv* env, jobject instance, jfieldID field, jint value,
                 std::string& err) {
    if (!env || !instance || !field) {
        err = kErrJniWrite;
        return false;
    }
    env->SetIntField(instance, field, value);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        err = kErrJniWrite;
        return false;
    }
    return true;
}

}  // namespace nodelay
