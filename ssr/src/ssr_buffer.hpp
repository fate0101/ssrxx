#ifndef ssr_buffer_hpp
#define ssr_buffer_hpp

// system
#include <string>
#include <assert.h>


namespace ssr {

class SSRBuffer{

public:
	SSRBuffer():base_(nullptr), ptr_(nullptr), size_(0) {

	}

	SSRBuffer(size_t size) :base_(nullptr), ptr_(nullptr), size_(0) {
		alloc(size);
	}

	virtual ~SSRBuffer() {
		if (base_) delete[] base_;
	}

	void  clear() {
		// Force the buffer to be empty
		ptr_ = base_;
		dealloc(1024);
	}

	size_t  del(size_t dsize) {
		// Trying to byte off more than ya can chew - eh?
		if (dsize > size())
			return 0;

		// all that we have 
		if (dsize > len())
			dsize = len();


		if (dsize)
		{
			// Slide the buffer back - like sinking the data
			memmove(base_, base_ + dsize, size() - dsize);

			ptr_ -= dsize;
		}

		dealloc(len());

		return dsize;
	}

	int scan(const char* text, size_t pos) {
		if (pos > this->len())
			return -1;

		char* finded = (char*)strstr((char*)(base_ + pos), (char*)text);

		int offset = 0;

		if (finded)
			offset = (finded - base_) + strlen((char*)text);

		return offset;
	}

	bool insert(const char* text, size_t len) {
		realloc(len + this->len());

		memmove(base_ + len, base_, this->size() - len);

		memcpy(base_, text, len);

		// Advance Pointer
		ptr_ += len;

		return len;
	}

	bool insert(std::string& str) {
		size_t size = str.length();
		return insert(str.c_str(), size);
	}

	size_t  read(char* text, size_t len) {
		// Trying to byte off more than ya can chew - eh?
		if (len > size())
			return 0;

		// all that we have 
		if (len > this->len())
			len = this->len();


		if (len){
			// Copy over required amount and its not up to us
			// to terminate the buffer - got that!!!
			memcpy(text, base_, len);

			// Slide the buffer back - like sinking the data
			memmove(base_, base_ + len, size() - len);

			ptr_ -= len;
		}

		dealloc(this->len());

		return len;
	}

	bool write(const char* text, size_t len) {

		realloc(len + this->len());

		memcpy(ptr_, text, len);

		// Advance Pointer
		ptr_ += len;

		return len;
	}

	bool write(std::string& str) {
		size_t size = str.length();
		return write(str.c_str(), size);
	}

	size_t len() {
		if (base_ == nullptr)
			return 0;

		int nsize =
			ptr_ - base_;
		return nsize;
	}

	void copy(SSRBuffer& buffer) {
		size_t rsize = buffer.size();
		size_t len = buffer.len();
		clear();
		realloc(rsize);

		ptr_ = base_ + len;

		memcpy(base_, buffer.get(), buffer.len());
	}

	char* get(size_t pos = 0) {
		if (pos > size())
		{
			return nullptr;
		}
		return base_ + pos;
	}

	size_t alloc(size_t size) {
		if (size < this->size() - len())
		{
			return size_;
		}
		return realloc(size + len());
	}

	// so bad func
	// int flush(size_t len) {
		// if (len + this->len() > this->size())
		// {
		// 	return -1;
		// }
		// if (len <= 0)
		// {
		// 	return 0;
		// }
		// ptr_ += len;
		// return this->len();
	//}

	int setlen(size_t len) {
		if (len > this->size())
			return -1;

		if (len < 0)
			abort();

		ptr_ = base_ + len;
		return this->len();
	}


	size_t size() {
		return size_;
	}

	size_t realloc(size_t nsize) {
		if (nsize < size())
			return 0;

		// ¶ÔÆë
		size_t rsize = (size_t)ceil(nsize / 1024.0) * 1024;

		char* nbuffer = new char[rsize] {0};

		assert(nbuffer);

		size_t bsize = len();

		

		if (base_) {
			memcpy(nbuffer, base_, bsize);
			delete[] base_;
		}

		base_ = nbuffer;
		ptr_ = base_ + bsize;
		size_ = nsize;
		return size_;
	}

	size_t dealloc(size_t desize) {
		if (desize < this->len())
			return 0;

		// Allocate new size
		size_t nsize = (size_t)ceil(desize / 1024.0) * 1024;

		if (nsize < size_)
			return 0;

		// New Copy Data Over
		char* nbuffer = new char[nsize] {0};
		assert(nbuffer);

		size_t len = this->len();

		memcpy(nbuffer, base_, len);

		delete[] base_;

		// Hand over the pointer
		base_ = nbuffer;

		// Realign position pointer
		ptr_ = base_ + len;

		size_ = nsize;

		return size_;
	}

protected:
	char*  base_;
	char*  ptr_;
	size_t size_;

};


}  // ssr

#endif  // ssr_buffer_hpp