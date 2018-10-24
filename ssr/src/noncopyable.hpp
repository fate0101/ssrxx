#ifndef noncopyable_hpp
#define noncopyable_hpp


class noncopyable {

protected:
 noncopyable() = default;
 noncopyable(const noncopyable&) = delete;
 noncopyable& operator=(const noncopyable&) = delete;
};

#endif