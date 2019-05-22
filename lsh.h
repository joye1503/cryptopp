// lsh.h - written and placed in public domain by Jeffrey Walton.
//         Based on public domain code in lsh256.c and lsh512.c from
//         South Korea National Security Research Institute.

#ifndef CRYPTOPP_LSH_H
#define CRYPTOPP_LSH_H

/// \file lsh.h
/// \brief Classes for the LSH message digest
/// \since Crypto++ 8.0

#include "config.h"
#include "iterhash.h"

NAMESPACE_BEGIN(CryptoPP)

/// \brief LSH224 message digest
/// \since Crypto++ 8.0
/// \sa <a href="http://www.cryptopp.com/wiki/LSH">LSH</a>
class LSH224 : public IteratedHashWithStaticTransform<word32, BigEndian, 64, 32, LSH224>
{
public:
	static void InitState(HashWordType *state);
	static void Transform(word32 *digest, const word32 *data);
	void TruncatedFinal(byte *hash, size_t size);
	CRYPTOPP_STATIC_CONSTEXPR const char* StaticAlgorithmName() {return "LSH224";}
};

/// \brief LSH256 message digest
/// \since Crypto++ 8.0
/// \sa <a href="http://www.cryptopp.com/wiki/LSH">LSH</a>
class LSH256 : public IteratedHashWithStaticTransform<word32, BigEndian, 64, 32, LSH256>
{
public:
	static void InitState(HashWordType *state);
	static void Transform(word32 *digest, const word32 *data);
	void TruncatedFinal(byte *hash, size_t size);
	CRYPTOPP_STATIC_CONSTEXPR const char* StaticAlgorithmName() {return "LSH256";}
};

/// \brief LSH384 message digest
/// \since Crypto++ 8.0
/// \sa <a href="http://www.cryptopp.com/wiki/LSH">LSH</a>
class LSH384 : public IteratedHashWithStaticTransform<word64, BigEndian, 128, 64, LSH384>
{
public:
	static void InitState(HashWordType *state);
	static void Transform(word64 *digest, const word64 *data);
	void TruncatedFinal(byte *hash, size_t size);
	CRYPTOPP_STATIC_CONSTEXPR const char* StaticAlgorithmName() {return "LSH384";}
};

/// \brief LSH512 message digest
/// \since Crypto++ 8.0
/// \sa <a href="http://www.cryptopp.com/wiki/LSH">LSH</a>
class LSH512 : public IteratedHashWithStaticTransform<word64, BigEndian, 128, 64, LSH512>
{
public:
	static void InitState(HashWordType *state);
	static void Transform(word64 *digest, const word64 *data);
	void TruncatedFinal(byte *hash, size_t size);
	CRYPTOPP_STATIC_CONSTEXPR const char* StaticAlgorithmName() {return "LSH512";}
};

NAMESPACE_END

#endif
