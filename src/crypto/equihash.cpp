// Copyright (c) 2016 Jack Grigg
// Copyright (c) 2016 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Implementation of the Equihash Proof-of-Work algorithm.
//
// Reference
// =========
// Alex Biryukov and Dmitry Khovratovich
// Equihash: Asymmetric Proof-of-Work Based on the Generalized Birthday Problem
// NDSS ’16, 21-24 February 2016, San Diego, CA, USA
// https://www.internetsociety.org/sites/default/files/blogs-media/equihash-asymmetric-proof-of-work-based-generalized-birthday-problem.pdf

#include "crypto/equihash.h"
#include "util.h"

#include <algorithm>
#include <cmath>
#include <iostream>
#include <stdexcept>

template<unsigned int N, unsigned int K>
int Equihash<N,K>::InitialiseState(eh_HashState& base_state)
{
    unsigned int n = N;
    unsigned int k = K;
    unsigned char personalization[crypto_generichash_blake2b_PERSONALBYTES] = {};
    memcpy(personalization, "ZcashPOW", 8);
    memcpy(personalization+8,  &n, 4);
    memcpy(personalization+12, &k, 4);
    return crypto_generichash_blake2b_init_salt_personal(&base_state,
                                                         NULL, 0, // No key.
                                                         N/8,
                                                         NULL,    // No salt.
                                                         personalization);
}

void GenerateHash(const eh_HashState& base_state, size_t len, eh_index i, unsigned char* hash)
{
    eh_HashState state;
    state = base_state;
    crypto_generichash_blake2b_update(&state, (unsigned char*) &i, sizeof(eh_index));
    crypto_generichash_blake2b_final(&state, hash, len);
}

void EhIndexToArray(const eh_index i, unsigned char* array)
{
    assert(sizeof(eh_index) == 4);
    array[0] = (i >> 24) & 0xFF;
    array[1] = (i >> 16) & 0xFF;
    array[2] = (i >>  8) & 0xFF;
    array[3] =  i        & 0xFF;
}

eh_index ArrayToEhIndex(const unsigned char* array)
{
    assert(sizeof(eh_index) == 4);
    eh_index ret {array[0]};
    ret <<= 8;
    ret |= array[1];
    ret <<= 8;
    ret |= array[2];
    ret <<= 8;
    ret |= array[3];
    return ret;
}

eh_trunc TruncateIndex(const eh_index i, const unsigned int ilen)
{
    // Truncate to 8 bits
    assert(sizeof(eh_trunc) == 1);
    return (i >> (ilen - 8)) & 0xff;
}

eh_index UntruncateIndex(const eh_trunc t, const eh_index r, const unsigned int ilen)
{
    eh_index i{t};
    return (i << (ilen - 8)) | r;
}

// Checks if the intersection of a and b is empty
bool DistinctIndices(std::vector<eh_index> a, std::vector<eh_index> b)
{
    std::sort(a.begin(), a.end());
    std::sort(b.begin(), b.end());

    unsigned int i = 0;
    for (unsigned int j = 0; j < b.size(); j++) {
        while (a[i] < b[j]) {
            i++;
            if (i == a.size()) { return true; }
        }
        assert(a[i] >= b[j]);
        if (a[i] == b[j]) { return false; }
    }
    return true;
}

template<size_t WIDTH>
StepRow<WIDTH>::StepRow(unsigned int n, const eh_HashState& base_state, eh_index i)
{
    GenerateHash(base_state, n/8, i, hash);
}

template<size_t WIDTH> template<size_t W>
StepRow<WIDTH>::StepRow(const StepRow<W>& a)
{
    assert(W <= WIDTH);
    std::copy(a.hash, a.hash+W, hash);
}

template<size_t WIDTH>
FullStepRow<WIDTH>::FullStepRow(unsigned int n, const eh_HashState& base_state, eh_index i) :
        StepRow<WIDTH> {n, base_state, i}
{
    EhIndexToArray(i, hash+(n/8));
}

template<size_t WIDTH> template<size_t W>
FullStepRow<WIDTH>::FullStepRow(const FullStepRow<W>& a, const FullStepRow<W>& b, size_t len, size_t lenIndices, int trim) :
        StepRow<WIDTH> {a}
{
    assert(len+lenIndices <= W);
    assert(len-trim+(2*lenIndices) <= WIDTH);
    for (int i = trim; i < len; i++)
        hash[i-trim] = a.hash[i] ^ b.hash[i];
    if (a.IndicesBefore(b, len)) {
        std::copy(a.hash+len, a.hash+len+lenIndices, hash+len-trim);
        std::copy(b.hash+len, b.hash+len+lenIndices, hash+len-trim+lenIndices);
    } else {
        std::copy(b.hash+len, b.hash+len+lenIndices, hash+len-trim);
        std::copy(a.hash+len, a.hash+len+lenIndices, hash+len-trim+lenIndices);
    }
}

template<size_t WIDTH>
FullStepRow<WIDTH>& FullStepRow<WIDTH>::operator=(const FullStepRow<WIDTH>& a)
{
    std::copy(a.hash, a.hash+WIDTH, hash);
    return *this;
}

template<size_t WIDTH>
bool StepRow<WIDTH>::IsZero(size_t len)
{
    char res = 0;
    for (int i = 0; i < len; i++)
        res |= hash[i];
    return res == 0;
}

template<size_t WIDTH>
std::vector<eh_index> FullStepRow<WIDTH>::GetIndices(size_t len, size_t lenIndices) const
{
    std::vector<eh_index> ret;
    for (int i = 0; i < lenIndices; i += sizeof(eh_index)) {
        ret.push_back(ArrayToEhIndex(hash+len+i));
    }
    return ret;
}

template<size_t WIDTH>
bool HasCollision(StepRow<WIDTH>& a, StepRow<WIDTH>& b, int l)
{
    bool res = true;
    for (int j = 0; j < l; j++)
        res &= a.hash[j] == b.hash[j];
    return res;
}

template<size_t WIDTH>
TruncatedStepRow<WIDTH>::TruncatedStepRow(eh_index i) :
        StepRow<WIDTH> { }
{
    EhIndexToArray(i, hash);
}

// Assumes the TruncatedStepRow contains no XORed hash and full indices
template<size_t WIDTH>
bool GenerateXor(const eh_HashState& base_state, const TruncatedStepRow<WIDTH>& a, size_t len, size_t lenIndices, unsigned char* hash)
{
    assert(lenIndices <= WIDTH);
    unsigned char tmp[len];
    std::fill(hash, hash+len, 0);
    for (int i = 0; i < lenIndices; i += sizeof(eh_index)) {
        GenerateHash(base_state, len, ArrayToEhIndex(a.hash+i), tmp);
        for (int j = 0; j < len; j++)
            hash[j] ^= tmp[j];
    }
}

// Assumes the TruncatedStepRows contain no XORed hash and full indices
template<size_t WIDTH> template<size_t W>
TruncatedStepRow<WIDTH>::TruncatedStepRow(const eh_HashState& base_state, const TruncatedStepRow<W>& a, const TruncatedStepRow<W>& b, size_t len, size_t lenIndices, int trim, size_t ilen) :
        StepRow<WIDTH> {a}
{
    assert(lenIndices <= W);
    unsigned char a_hash[len];
    unsigned char b_hash[len];

    GenerateXor(base_state, a, len, lenIndices, a_hash);
    GenerateXor(base_state, b, len, lenIndices, b_hash);

    for (int i = trim; i < len; i++)
        hash[i-trim] = a_hash[i] ^ b_hash[i];

    int j = 0;
    if (a.IndicesBefore(b)) {
        for (int i = 0; i < lenIndices; i += sizeof(eh_index)) {
            hash[len-trim+(j++)] = TruncateIndex(ArrayToEhIndex(a.hash+i), ilen);
        }
        for (int i = 0; i < lenIndices; i += sizeof(eh_index)) {
            hash[len-trim+(j++)] = TruncateIndex(ArrayToEhIndex(b.hash+i), ilen);
        }
    } else {
        for (int i = 0; i < lenIndices; i += sizeof(eh_index)) {
            hash[len-trim+(j++)] = TruncateIndex(ArrayToEhIndex(b.hash+i), ilen);
        }
        for (int i = 0; i < lenIndices; i += sizeof(eh_index)) {
            hash[len-trim+(j++)] = TruncateIndex(ArrayToEhIndex(a.hash+i), ilen);
        }
    }
}

template<size_t WIDTH> template<size_t W>
TruncatedStepRow<WIDTH>::TruncatedStepRow(const TruncatedStepRow<W>& a, const TruncatedStepRow<W>& b, size_t len, size_t lenIndices, int trim) :
        StepRow<WIDTH> {a}
{
    assert(len+lenIndices <= W);
    assert(len-trim+(2*lenIndices) <= WIDTH);
    for (int i = trim; i < len; i++)
        hash[i-trim] = a.hash[i] ^ b.hash[i];
    if (a.IndicesBefore(b, len, lenIndices)) {
        std::copy(a.hash+len, a.hash+len+lenIndices, hash+len-trim);
        std::copy(b.hash+len, b.hash+len+lenIndices, hash+len-trim+lenIndices);
    } else {
        std::copy(b.hash+len, b.hash+len+lenIndices, hash+len-trim);
        std::copy(a.hash+len, a.hash+len+lenIndices, hash+len-trim+lenIndices);
    }
}

template<size_t WIDTH>
TruncatedStepRow<WIDTH>& TruncatedStepRow<WIDTH>::operator=(const TruncatedStepRow<WIDTH>& a)
{
    std::copy(a.hash, a.hash+WIDTH, hash);
    return *this;
}

template<size_t WIDTH>
std::vector<eh_index> TruncatedStepRow<WIDTH>::GetIndices(size_t lenIndices) const
{
    std::vector<eh_index> ret;
    for (int i = 0; i < lenIndices; i += sizeof(eh_index)) {
        ret.push_back(ArrayToEhIndex(hash+i));
    }
    return ret;
}

template<size_t WIDTH>
eh_trunc* TruncatedStepRow<WIDTH>::GetTruncatedIndices(size_t len, size_t lenIndices) const
{
    eh_trunc* p = new eh_trunc[lenIndices];
    std::copy(hash+len, hash+len+lenIndices, p);
    return p;
}

// Assumes the TruncatedStepRows contain no XORed hash and full indices
template<size_t WIDTH>
bool HashingHasCollision(const eh_HashState& base_state, TruncatedStepRow<WIDTH>& a, TruncatedStepRow<WIDTH>& b, size_t len, size_t lenIndices, int l)
{
    assert(l <= len);
    unsigned char a_hash[len];
    unsigned char b_hash[len];

    GenerateXor(base_state, a, len, lenIndices, a_hash);
    GenerateXor(base_state, b, len, lenIndices, b_hash);

    bool res = true;
    for (int j = 0; j < l; j++)
        res &= a_hash[j] == b_hash[j];
    return res;
}

template<size_t Len> template<size_t W>
bool CompareTSR<Len>::operator()(const TruncatedStepRow<W>& a, const TruncatedStepRow<W>& b)
{
    GenerateXor(base_state, a, Len, lenIndices, a_hash);
    GenerateXor(base_state, b, Len, lenIndices, b_hash);
    return memcmp(a_hash, b_hash, Len) < 0;
}

template<unsigned int N, unsigned int K>
std::set<std::vector<eh_index>> Equihash<N,K>::BasicSolve(const eh_HashState& base_state)
{
    eh_index init_size { 1 << (CollisionBitLength + 1) };

    // 1) Generate first list
    LogPrint("pow", "Generating first list\n");
    size_t hashLen = N/8;
    size_t lenIndices = sizeof(eh_index);
    std::vector<FullStepRow<FullWidth>> X;
    X.reserve(init_size);
    for (eh_index i = 0; i < init_size; i++) {
        X.emplace_back(N, base_state, i);
    }

    // 3) Repeat step 2 until 2n/(k+1) bits remain
    for (int r = 1; r < K && X.size() > 0; r++) {
        LogPrint("pow", "Round %d:\n", r);
        // 2a) Sort the list
        LogPrint("pow", "- Sorting list\n");
        std::sort(X.begin(), X.end(), CompareSR(hashLen));

        LogPrint("pow", "- Finding collisions\n");
        int i = 0;
        int posFree = 0;
        std::vector<FullStepRow<FullWidth>> Xc;
        while (i < X.size() - 1) {
            // 2b) Find next set of unordered pairs with collisions on the next n/(k+1) bits
            int j = 1;
            while (i+j < X.size() &&
                    HasCollision(X[i], X[i+j], CollisionByteLength)) {
                j++;
            }

            // 2c) Calculate tuples (X_i ^ X_j, (i, j))
            for (int l = 0; l < j - 1; l++) {
                for (int m = l + 1; m < j; m++) {
                    if (DistinctIndices(X[i+l], X[i+m], hashLen, lenIndices)) {
                        Xc.emplace_back(X[i+l], X[i+m], hashLen, lenIndices, CollisionByteLength);
                    }
                }
            }

            // 2d) Store tuples on the table in-place if possible
            while (posFree < i+j && Xc.size() > 0) {
                X[posFree++] = Xc.back();
                Xc.pop_back();
            }

            i += j;
        }

        // 2e) Handle edge case where final table entry has no collision
        while (posFree < X.size() && Xc.size() > 0) {
            X[posFree++] = Xc.back();
            Xc.pop_back();
        }

        if (Xc.size() > 0) {
            // 2f) Add overflow to end of table
            X.insert(X.end(), Xc.begin(), Xc.end());
        } else if (posFree < X.size()) {
            // 2g) Remove empty space at the end
            X.erase(X.begin()+posFree, X.end());
            X.shrink_to_fit();
        }

        hashLen -= CollisionByteLength;
        lenIndices *= 2;
    }

    // k+1) Find a collision on last 2n(k+1) bits
    LogPrint("pow", "Final round:\n");
    std::set<std::vector<eh_index>> solns;
    if (X.size() > 1) {
        LogPrint("pow", "- Sorting list\n");
        std::sort(X.begin(), X.end(), CompareSR(hashLen));
        LogPrint("pow", "- Finding collisions\n");
        for (int i = 0; i < X.size() - 1; i++) {
            FullStepRow<FinalFullWidth> res(X[i], X[i+1], hashLen, lenIndices, 0);
            if (res.IsZero(hashLen) && DistinctIndices(X[i], X[i+1], hashLen, lenIndices)) {
                solns.insert(res.GetIndices(hashLen, 2*lenIndices));
            }
        }
    } else
        LogPrint("pow", "- List is empty\n");

    return solns;
}

template<size_t WIDTH>
void CollideBranches(std::vector<FullStepRow<WIDTH>>& X, const size_t hlen, const size_t lenIndices, const unsigned int clen, const unsigned int ilen, const eh_trunc lt, const eh_trunc rt)
{
    int i = 0;
    int posFree = 0;
    std::vector<FullStepRow<WIDTH>> Xc;
    while (i < X.size() - 1) {
        // 2b) Find next set of unordered pairs with collisions on the next n/(k+1) bits
        int j = 1;
        while (i+j < X.size() &&
                HasCollision(X[i], X[i+j], clen)) {
            j++;
        }

        // 2c) Calculate tuples (X_i ^ X_j, (i, j))
        for (int l = 0; l < j - 1; l++) {
            for (int m = l + 1; m < j; m++) {
                if (DistinctIndices(X[i+l], X[i+m], hlen, lenIndices)) {
                    if (IsValidBranch(X[i+l], hlen, ilen, lt) && IsValidBranch(X[i+m], hlen, ilen, rt)) {
                        Xc.emplace_back(X[i+l], X[i+m], hlen, lenIndices, clen);
                    } else if (IsValidBranch(X[i+m], hlen, ilen, lt) && IsValidBranch(X[i+l], hlen, ilen, rt)) {
                        Xc.emplace_back(X[i+m], X[i+l], hlen, lenIndices, clen);
                    }
                }
            }
        }

        // 2d) Store tuples on the table in-place if possible
        while (posFree < i+j && Xc.size() > 0) {
            X[posFree++] = Xc.back();
            Xc.pop_back();
        }

        i += j;
    }

    // 2e) Handle edge case where final table entry has no collision
    while (posFree < X.size() && Xc.size() > 0) {
        X[posFree++] = Xc.back();
        Xc.pop_back();
    }

    if (Xc.size() > 0) {
        // 2f) Add overflow to end of table
        X.insert(X.end(), Xc.begin(), Xc.end());
    } else if (posFree < X.size()) {
        // 2g) Remove empty space at the end
        X.erase(X.begin()+posFree, X.end());
        X.shrink_to_fit();
    }
}

template<unsigned int N, unsigned int K>
std::set<std::vector<eh_index>> Equihash<N,K>::OptimisedSolve(const eh_HashState& base_state)
{
    eh_index init_size { 1 << (CollisionBitLength + 1) };

    // First run the algorithm with truncated indices

    eh_index soln_size { 1 << K };
    std::vector<eh_trunc*> partialSolns;
    {

        // 1) Generate first list
        LogPrint("pow", "Generating first list\n");
        bool trunc = false;
        bool truncNext = false;
        size_t lenFullIndices = sizeof(eh_index);
        size_t hashLen = N/8;
        size_t lenIndices = sizeof(eh_trunc);
        std::vector<TruncatedStepRow<TruncatedWidth>> Xt;
        Xt.reserve(init_size);
        for (eh_index i = 0; i < init_size; i++) {
            Xt.emplace_back(i);
        }

        // 3) Repeat step 2 until 2n/(k+1) bits remain
        for (int r = 1; r < K && Xt.size() > 0; r++) {
            LogPrint("pow", "Round %d:\n", r);
            // ...) When trimmed indices plus the truncated XOR becomes smaller
            //      than the full index tuple, switch to truncating indices
            if (!trunc && (hashLen + (sizeof(eh_trunc)*(1<<(r-1)))) <
                                     (sizeof(eh_index)*(1<<(r-1)))) {
                LogPrint("pow", "- Switching to truncating indices\n");
                truncNext = true;
            }

            // 2a) Sort the list
            LogPrint("pow", "- Sorting list\n");
            if (trunc) {
                std::sort(Xt.begin(), Xt.end(), CompareSR(hashLen));
            } else {
                std::sort(Xt.begin(), Xt.end(), CompareTSR<N/8>(base_state, lenFullIndices));
            }

            LogPrint("pow", "- Finding collisions\n");
            int i = 0;
            int posFree = 0;
            std::vector<TruncatedStepRow<TruncatedWidth>> Xc;
            while (i < Xt.size() - 1) {
                // 2b) Find next set of unordered pairs with collisions on the next n/(k+1) bits
                int j = 1;
                while (i+j < Xt.size() && (trunc ?
                        HasCollision(Xt[i], Xt[i+j], CollisionByteLength) :
                        HashingHasCollision(base_state, Xt[i], Xt[i+j], N/8, lenFullIndices, N/8-hashLen+CollisionByteLength))) {
                    j++;
                }

                // 2c) Calculate tuples (X_i ^ X_j, (i, j))
                for (int l = 0; l < j - 1; l++) {
                    for (int m = l + 1; m < j; m++) {
                        if (trunc) {
                            // We truncated, so don't check for distinct indices here
                            Xc.emplace_back(Xt[i+l], Xt[i+m], hashLen, lenIndices, CollisionByteLength);
                        } else if (DistinctIndices(Xt[i+l], Xt[i+m], lenIndices)) {
                            if (truncNext) {
                                // Change to storing XOR and truncating indices
                                Xc.emplace_back(base_state, Xt[i+l], Xt[i+m], N/8, lenFullIndices, N/8-hashLen+CollisionByteLength, CollisionBitLength + 1);
                            } else {
                                Xc.emplace_back(Xt[i+l], Xt[i+m], 0, lenFullIndices, 0);
                            }
                        }
                    }
                }

                // 2d) Store tuples on the table in-place if possible
                while (posFree < i+j && Xc.size() > 0) {
                    Xt[posFree++] = Xc.back();
                    Xc.pop_back();
                }

                i += j;
            }

            // 2e) Handle edge case where final table entry has no collision
            while (posFree < Xt.size() && Xc.size() > 0) {
                Xt[posFree++] = Xc.back();
                Xc.pop_back();
            }

            if (Xc.size() > 0) {
                // 2f) Add overflow to end of table
                Xt.insert(Xt.end(), Xc.begin(), Xc.end());
            } else if (posFree < Xt.size()) {
                // 2g) Remove empty space at the end
                Xt.erase(Xt.begin()+posFree, Xt.end());
                Xt.shrink_to_fit();
            }

            trunc = truncNext;
            lenFullIndices *= 2;
            hashLen -= CollisionByteLength;
            lenIndices *= 2;
        }

        // k+1) Find a collision on last 2n(k+1) bits
        LogPrint("pow", "Final round:\n");
        if (Xt.size() > 1) {
            LogPrint("pow", "- Sorting list\n");
            std::sort(Xt.begin(), Xt.end(), CompareSR(hashLen));
            LogPrint("pow", "- Finding collisions\n");
            for (int i = 0; i < Xt.size() - 1; i++) {
                TruncatedStepRow<FinalTruncatedWidth> res(Xt[i], Xt[i+1], hashLen, lenIndices, 0);
                if (res.IsZero(hashLen)) {
                    partialSolns.push_back(res.GetTruncatedIndices(hashLen, 2*lenIndices));
                }
            }
        } else
            LogPrint("pow", "- List is empty\n");

    } // Ensure Xt goes out of scope and is destroyed

    LogPrint("pow", "Found %d partial solutions\n", partialSolns.size());

    // Now for each solution run the algorithm again to recreate the indices
    LogPrint("pow", "Culling solutions\n");
    std::set<std::vector<eh_index>> solns;
    eh_index recreate_size { UntruncateIndex(1, 0, CollisionBitLength + 1) };
    int invalidCount = 0;
    for (eh_trunc* partialSoln : partialSolns) {
        // 1) Generate first list of possibilities
        size_t hashLen = N/8;
        size_t lenIndices = sizeof(eh_index);
        std::vector<std::vector<FullStepRow<FinalFullWidth>>> X;
        X.reserve(soln_size);
        for (eh_index i = 0; i < soln_size; i++) {
            std::vector<FullStepRow<FinalFullWidth>> ic;
            ic.reserve(recreate_size);
            for (eh_index j = 0; j < recreate_size; j++) {
                eh_index newIndex { UntruncateIndex(partialSoln[i], j, CollisionBitLength + 1) };
                ic.emplace_back(N, base_state, newIndex);
            }
            X.push_back(ic);
        }

        // 3) Repeat step 2 for each level of the tree
        for (int r = 0; X.size() > 1; r++) {
            std::vector<std::vector<FullStepRow<FinalFullWidth>>> Xc;
            Xc.reserve(X.size()/2);

            // 2a) For each pair of lists:
            for (int v = 0; v < X.size(); v += 2) {
                // 2b) Merge the lists
                std::vector<FullStepRow<FinalFullWidth>> ic(X[v]);
                ic.reserve(X[v].size() + X[v+1].size());
                ic.insert(ic.end(), X[v+1].begin(), X[v+1].end());
                std::sort(ic.begin(), ic.end(), CompareSR(hashLen));
                CollideBranches(ic, hashLen, lenIndices, CollisionByteLength, CollisionBitLength + 1, partialSoln[(1<<r)*v], partialSoln[(1<<r)*(v+1)]);

                // 2v) Check if this has become an invalid solution
                if (ic.size() == 0)
                    goto invalidsolution;

                Xc.push_back(ic);
            }

            X = Xc;
            hashLen -= CollisionByteLength;
            lenIndices *= 2;
        }

        // We are at the top of the tree
        assert(X.size() == 1);
        for (FullStepRow<FinalFullWidth> row : X[0]) {
            solns.insert(row.GetIndices(hashLen, lenIndices));
        }
        goto deletesolution;

invalidsolution:
        invalidCount++;

deletesolution:
        delete[] partialSoln;
    }
    LogPrint("pow", "- Number of invalid solutions found: %d\n", invalidCount);

    return solns;
}

template<unsigned int N, unsigned int K>
bool Equihash<N,K>::IsValidSolution(const eh_HashState& base_state, std::vector<eh_index> soln)
{
    eh_index soln_size { 1 << K };
    if (soln.size() != soln_size) {
        LogPrint("pow", "Invalid solution size: %d\n", soln.size());
        return false;
    }

    std::vector<FullStepRow<FinalFullWidth>> X;
    X.reserve(soln_size);
    for (eh_index i : soln) {
        X.emplace_back(N, base_state, i);
    }

    size_t hashLen = N/8;
    size_t lenIndices = sizeof(eh_index);
    while (X.size() > 1) {
        std::vector<FullStepRow<FinalFullWidth>> Xc;
        for (int i = 0; i < X.size(); i += 2) {
            if (!HasCollision(X[i], X[i+1], CollisionByteLength)) {
                LogPrint("pow", "Invalid solution: invalid collision length between StepRows\n");
                LogPrint("pow", "X[i]   = %s\n", X[i].GetHex(hashLen));
                LogPrint("pow", "X[i+1] = %s\n", X[i+1].GetHex(hashLen));
                return false;
            }
            if (X[i+1].IndicesBefore(X[i], hashLen)) {
                return false;
                LogPrint("pow", "Invalid solution: Index tree incorrectly ordered\n");
            }
            if (!DistinctIndices(X[i], X[i+1], hashLen, lenIndices)) {
                LogPrint("pow", "Invalid solution: duplicate indices\n");
                return false;
            }
            Xc.emplace_back(X[i], X[i+1], hashLen, lenIndices, CollisionByteLength);
        }
        X = Xc;
        hashLen -= CollisionByteLength;
        lenIndices *= 2;
    }

    assert(X.size() == 1);
    return X[0].IsZero(hashLen);
}

// Explicit instantiations for Equihash<96,5>
template int Equihash<96,5>::InitialiseState(eh_HashState& base_state);
template std::set<std::vector<eh_index>> Equihash<96,5>::BasicSolve(const eh_HashState& base_state);
template std::set<std::vector<eh_index>> Equihash<96,5>::OptimisedSolve(const eh_HashState& base_state);
template bool Equihash<96,5>::IsValidSolution(const eh_HashState& base_state, std::vector<eh_index> soln);

// Explicit instantiations for Equihash<48,5>
template int Equihash<48,5>::InitialiseState(eh_HashState& base_state);
template std::set<std::vector<eh_index>> Equihash<48,5>::BasicSolve(const eh_HashState& base_state);
template std::set<std::vector<eh_index>> Equihash<48,5>::OptimisedSolve(const eh_HashState& base_state);
template bool Equihash<48,5>::IsValidSolution(const eh_HashState& base_state, std::vector<eh_index> soln);
