// Copyright (c) 2016 Jack Grigg
// Copyright (c) 2016 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <algorithm>
#include <cassert>

// Checks if the intersection of a.indices and b.indices is empty
template<size_t WIDTH>
bool DistinctIndices(const FullStepRow<WIDTH>& a, const FullStepRow<WIDTH>& b, size_t len, size_t lenIndices)
{
    std::vector<eh_index> aSrt = a.GetIndices(len, lenIndices);
    std::vector<eh_index> bSrt = b.GetIndices(len, lenIndices);
    return DistinctIndices(aSrt, bSrt);
}

// Checks if the intersection of a.indices and b.indices is empty
// Assumes the TruncatedStepRows contain no XORed hash and full indices
template<size_t WIDTH>
bool DistinctIndices(const TruncatedStepRow<WIDTH>& a, const TruncatedStepRow<WIDTH>& b, size_t lenIndices)
{
    std::vector<eh_index> aSrt = a.GetIndices(lenIndices);
    std::vector<eh_index> bSrt = b.GetIndices(lenIndices);
    return DistinctIndices(aSrt, bSrt);
}

template<size_t WIDTH>
bool IsValidBranch(const FullStepRow<WIDTH>& a, const size_t len, const unsigned int ilen, const eh_trunc t)
{
    return TruncateIndex(ArrayToEhIndex(a.hash+len), ilen) == t;
}
