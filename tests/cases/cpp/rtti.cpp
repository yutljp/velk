// RTTI, fixed and virtual bases, typed handlers, nested handlers and cleanup.
#if defined(_WIN32)
#define EXPORT extern "C" __declspec(dllexport)
#define IMPORT __declspec(dllimport)
#else
#define EXPORT extern "C" __attribute__((visibility("default")))
#define IMPORT
#endif

IMPORT int imported_value(int);
struct Root {
    int number;
    __attribute__((noinline)) explicit Root(int value);
    virtual int value() const;
    virtual ~Root();
};
struct Single : Root {
    __attribute__((noinline)) explicit Single(int value);
    int value() const override;
    ~Single() override;
};
struct Other {
    virtual int other() const;
    virtual ~Other();
};
struct Multiple : Root, Other {
    __attribute__((noinline)) explicit Multiple(int value);
    int value() const override;
    int other() const override;
    ~Multiple() override;
};
struct Virtual : virtual Root {
    int extra;
    __attribute__((noinline)) explicit Virtual(int value);
    int value() const override;
    ~Virtual() override;
};
struct Error { int code; };

Root::Root(int value) : number(value) {}
int Root::value() const { return number; }
Root::~Root() {}
Single::Single(int value) : Root(value) {}
int Single::value() const { return number + 1; }
static volatile int destroyed;
Single::~Single() { destroyed++; }
int Other::other() const { return 7; }
Other::~Other() {}
Multiple::Multiple(int value) : Root(value) {}
int Multiple::value() const { return number + 2; }
int Multiple::other() const { return number + 3; }
Multiple::~Multiple() {}
Virtual::Virtual(int value) : Root(value), extra(4) {}
int Virtual::value() const { return number + extra; }
Virtual::~Virtual() {}

EXPORT __attribute__((noinline)) int dispatch(const Root *object) { return object->value(); }
EXPORT int dispatch_multiple(const Multiple *object) { return object->other(); }
EXPORT int single(int value) { Single object(value); return dispatch(&object); }
EXPORT int multiple(int value) { Multiple object(value); return dispatch(&object) + object.other(); }
EXPORT int virtual_base(int value) { Virtual object(value); return dispatch(&object); }
EXPORT int catch_one(int value) {
    try { return imported_value(value); }
    catch (const Error &error) { return error.code; }
}
EXPORT int catch_many(int value) {
    try { return imported_value(value); }
    catch (const Error &error) { return error.code + 1; }
    catch (int error) { return error + 2; }
    catch (...) { return -1; }
}
EXPORT int catch_nested(int value) {
    try {
        try { return imported_value(value); }
        catch (int error) { return imported_value(error); }
    } catch (const Error &error) { return error.code + 3; }
}
EXPORT int catch_cleanup(int value) {
    try { Single object(value); return imported_value(object.value()); }
    catch (...) { return -2; }
}

void operator delete(void *) noexcept {}
void operator delete(void *, __SIZE_TYPE__) noexcept {}
