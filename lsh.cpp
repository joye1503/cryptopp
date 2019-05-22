// lsh.cpp - written and placed in public domain by Jeffrey Walton.
//           Based on public domain code in lsh256.c and lsh512.c from
//           South Korea National Security Research Institute.
//
// This is the from the original introductory comment:

/*
 * Copyright (c) 2016 NSR (National Security Research Institute)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 */

#include "pch.h"
#include "config.h"

#include "lsh.h"
#include "misc.h"

ANONYMOUS_NAMESPACE_BEGIN

ANONYMOUS_NAMESPACE_END

NAMESPACE_BEGIN(CryptoPP)

#if defined(CRYPTOPP_DEBUG) && !defined(CRYPTOPP_DOXYGEN_PROCESSING)
void LSH_TestInstantiations()
{
	LSH224 x1;
	LSH256 x2;
	LSH384 y1;
	LSH512 y2;
}
#endif

void LSH224::InitState(HashWordType *state)
{
    CRYPTOPP_UNUSED(state);
}

void LSH224::TruncatedFinal(byte *hash, size_t size)
{
	CRYPTOPP_ASSERT(hash != NULLPTR);
	ThrowIfInvalidTruncatedSize(size);

    CRYPTOPP_UNUSED(hash);
    CRYPTOPP_UNUSED(size);

	Restart();		// reinit for next use
}

// LSH basic transformation. Transforms state based on block.
void LSH224::Transform(word32 *digest, const word32 *block)
{
	CRYPTOPP_ASSERT(digest != NULLPTR);
	CRYPTOPP_ASSERT(block != NULLPTR);

    CRYPTOPP_UNUSED(digest);
    CRYPTOPP_UNUSED(block);
}

void LSH256::InitState(HashWordType *state)
{
    CRYPTOPP_UNUSED(state);
}

void LSH256::TruncatedFinal(byte *hash, size_t size)
{
	CRYPTOPP_ASSERT(hash != NULLPTR);
	ThrowIfInvalidTruncatedSize(size);

    CRYPTOPP_UNUSED(hash);
    CRYPTOPP_UNUSED(size);

	Restart();		// reinit for next use
}

// LSH basic transformation. Transforms state based on block.
void LSH256::Transform(word32 *digest, const word32 *block)
{
	CRYPTOPP_ASSERT(digest != NULLPTR);
	CRYPTOPP_ASSERT(block != NULLPTR);

    CRYPTOPP_UNUSED(digest);
    CRYPTOPP_UNUSED(block);
}

void LSH384::InitState(HashWordType *state)
{
    CRYPTOPP_UNUSED(state);
}

void LSH384::TruncatedFinal(byte *hash, size_t size)
{
	CRYPTOPP_ASSERT(hash != NULLPTR);
	ThrowIfInvalidTruncatedSize(size);

    CRYPTOPP_UNUSED(hash);
    CRYPTOPP_UNUSED(size);

	Restart();		// reinit for next use
}

// LSH basic transformation. Transforms state based on block.
void LSH384::Transform(word64 *digest, const word64 *block)
{
	CRYPTOPP_ASSERT(digest != NULLPTR);
	CRYPTOPP_ASSERT(block != NULLPTR);

    CRYPTOPP_UNUSED(digest);
    CRYPTOPP_UNUSED(block);
}

void LSH512::InitState(HashWordType *state)
{
    CRYPTOPP_UNUSED(state);
}

void LSH512::TruncatedFinal(byte *hash, size_t size)
{
	CRYPTOPP_ASSERT(hash != NULLPTR);
	ThrowIfInvalidTruncatedSize(size);

    CRYPTOPP_UNUSED(hash);
    CRYPTOPP_UNUSED(size);

	Restart();		// reinit for next use
}

// LSH basic transformation. Transforms state based on block.
void LSH512::Transform(word64 *digest, const word64 *block)
{
	CRYPTOPP_ASSERT(digest != NULLPTR);
	CRYPTOPP_ASSERT(block != NULLPTR);

    CRYPTOPP_UNUSED(digest);
    CRYPTOPP_UNUSED(block);
}

NAMESPACE_END
