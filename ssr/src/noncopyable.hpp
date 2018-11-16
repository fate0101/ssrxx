#ifndef noncopyable_hpp
#define noncopyable_hpp


class noncopyable {

public:
 noncopyable() = default;
 noncopyable(const noncopyable&) = delete;
 noncopyable& operator=(const noncopyable&) = delete;
};

#endif
