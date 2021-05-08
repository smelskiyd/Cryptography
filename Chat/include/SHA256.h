#pragma once
#include <string>
#include <climits>
#include <vector>
#include <cstring>

using Byte = unsigned char;

class SHA256 {
  private:
	const static unsigned int k[];
	const static Byte kEndMessageByte = Byte(128);
	const static Byte kZeroByte = Byte(0);
	const static unsigned int kBlockSize = 512;
	const static unsigned int kNumRounds = 64;

	unsigned int h[8];

	void init();
    Byte* preprocess(Byte* message, unsigned int message_bytes);
	void processBlock(Byte *message, int start, unsigned int *w);

  public:
	unsigned int* hash(std::string message);
};
