// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.25;

/// @title ExponentiationGateVectors
///
/// @notice Reference vectors for the Solidity port of plonky2's
///         `ExponentiationGate` (see
///         `contracts/lib/polygon-plonky2/plonky2/src/gates/exponentiation.rs`).
///
/// @dev    GENERATED. Every `expected` array is the output of plonky2's own
///         `Gate::eval_unfiltered` on the paired `wires` array — the values
///         were NOT re-derived by hand in Solidity. The generator is a
///         throw-away Rust binary (kept out of the repo, see
///         `doc/tasks/exponentiation-gate-notes.md` §Validation for the exact
///         source) that links the pinned `polygon-plonky2` submodule, lifts
///         each base-field wire into `QuadraticExtension<Goldilocks>`, calls
///         `eval_unfiltered`, asserts the `c1` component stays zero (it must,
///         because every wire is a lifted base-field value) and prints `c0`.
///
///         Wire layout per vector (n = num_power_bits):
///           [0]              base
///           [1 .. 1+n)       power_bits (little-endian)
///           [1+n]            output
///           [2+n .. 2+2n)    intermediate_values
library ExponentiationGateVectors {
    /// V1 satisfying n=5 base=2 power=13 (output must be 2^13=8192)
    /// nonZeroConstraints = 0
    function v1() internal pure returns (uint256 n, uint256[] memory wires, uint256[] memory expected) {
        n = 5;
        wires = new uint256[](12);
        wires[0] = 2;
        wires[1] = 1;
        wires[2] = 0;
        wires[3] = 1;
        wires[4] = 1;
        wires[5] = 0;
        wires[6] = 8192;
        wires[7] = 1;
        wires[8] = 2;
        wires[9] = 8;
        wires[10] = 64;
        wires[11] = 8192;
        expected = new uint256[](6);
    }

    /// V2 UNSAT n=5 wrong intermediate_value[2]
    /// nonZeroConstraints = 2
    function v2() internal pure returns (uint256 n, uint256[] memory wires, uint256[] memory expected) {
        n = 5;
        wires = new uint256[](12);
        wires[0] = 2;
        wires[1] = 1;
        wires[2] = 0;
        wires[3] = 1;
        wires[4] = 1;
        wires[5] = 0;
        wires[6] = 8192;
        wires[7] = 1;
        wires[8] = 2;
        wires[9] = 9;
        wires[10] = 64;
        wires[11] = 8192;
        expected = new uint256[](6);
        expected[2] = 18446744069414584320;
        expected[3] = 17;
    }

    /// V3 UNSAT n=5 wrong output
    /// nonZeroConstraints = 1
    function v3() internal pure returns (uint256 n, uint256[] memory wires, uint256[] memory expected) {
        n = 5;
        wires = new uint256[](12);
        wires[0] = 2;
        wires[1] = 1;
        wires[2] = 0;
        wires[3] = 1;
        wires[4] = 1;
        wires[5] = 0;
        wires[6] = 8193;
        wires[7] = 1;
        wires[8] = 2;
        wires[9] = 8;
        wires[10] = 64;
        wires[11] = 8192;
        expected = new uint256[](6);
        expected[5] = 1;
    }

    /// V4 satisfying n=4 NON-BOOLEAN bits (no booleanity constraint)
    /// nonZeroConstraints = 0
    function v4() internal pure returns (uint256 n, uint256[] memory wires, uint256[] memory expected) {
        n = 4;
        wires = new uint256[](10);
        wires[0] = 1311768467463790320;
        wires[1] = 3;
        wires[2] = 0;
        wires[3] = 1;
        wires[4] = 7;
        wires[5] = 16550884178291972696;
        wires[6] = 9182379272246532234;
        wires[7] = 14056541213537274827;
        wires[8] = 10545788360759439085;
        wires[9] = 16550884178291972696;
        expected = new uint256[](5);
    }

    /// V5 satisfying n=66 random base + random boolean bits
    /// nonZeroConstraints = 0
    function v5() internal pure returns (uint256 n, uint256[] memory wires, uint256[] memory expected) {
        n = 66;
        wires = new uint256[](134);
        wires[0] = 15977249004024963792;
        wires[1] = 0;
        wires[2] = 1;
        wires[3] = 0;
        wires[4] = 0;
        wires[5] = 0;
        wires[6] = 0;
        wires[7] = 0;
        wires[8] = 1;
        wires[9] = 0;
        wires[10] = 0;
        wires[11] = 0;
        wires[12] = 1;
        wires[13] = 1;
        wires[14] = 0;
        wires[15] = 0;
        wires[16] = 1;
        wires[17] = 1;
        wires[18] = 0;
        wires[19] = 0;
        wires[20] = 0;
        wires[21] = 1;
        wires[22] = 1;
        wires[23] = 1;
        wires[24] = 0;
        wires[25] = 1;
        wires[26] = 0;
        wires[27] = 1;
        wires[28] = 0;
        wires[29] = 0;
        wires[30] = 1;
        wires[31] = 0;
        wires[32] = 0;
        wires[33] = 0;
        wires[34] = 0;
        wires[35] = 0;
        wires[36] = 0;
        wires[37] = 1;
        wires[38] = 0;
        wires[39] = 1;
        wires[40] = 0;
        wires[41] = 1;
        wires[42] = 0;
        wires[43] = 0;
        wires[44] = 0;
        wires[45] = 0;
        wires[46] = 0;
        wires[47] = 1;
        wires[48] = 1;
        wires[49] = 0;
        wires[50] = 0;
        wires[51] = 1;
        wires[52] = 0;
        wires[53] = 0;
        wires[54] = 1;
        wires[55] = 0;
        wires[56] = 1;
        wires[57] = 0;
        wires[58] = 0;
        wires[59] = 0;
        wires[60] = 1;
        wires[61] = 0;
        wires[62] = 0;
        wires[63] = 1;
        wires[64] = 1;
        wires[65] = 1;
        wires[66] = 1;
        wires[67] = 14995826821639838443;
        wires[68] = 15977249004024963792;
        wires[69] = 5744290381756689572;
        wires[70] = 10355413999767222965;
        wires[71] = 17235660293567679972;
        wires[72] = 344766636035480001;
        wires[73] = 9820078043220380599;
        wires[74] = 13127534321080255641;
        wires[75] = 17707003240272356692;
        wires[76] = 6974860312521735387;
        wires[77] = 8192352049173065842;
        wires[78] = 13066173458272625281;
        wires[79] = 11761832042390067147;
        wires[80] = 7703570608873368286;
        wires[81] = 671933825190702923;
        wires[82] = 5032222067009987429;
        wires[83] = 8498269171102104820;
        wires[84] = 9122359476022663042;
        wires[85] = 914119491639181555;
        wires[86] = 786963090374026518;
        wires[87] = 11245005792686967415;
        wires[88] = 17489108719538647672;
        wires[89] = 12791324300071723591;
        wires[90] = 10211804171030218872;
        wires[91] = 12804582627905694771;
        wires[92] = 1911522140165245073;
        wires[93] = 12635331154706129990;
        wires[94] = 2441012097855967122;
        wires[95] = 17079346952873683933;
        wires[96] = 3760029117475956168;
        wires[97] = 2392757742335968935;
        wires[98] = 10596395094064461930;
        wires[99] = 11806839169328115114;
        wires[100] = 13795585445336321205;
        wires[101] = 2406492611906002453;
        wires[102] = 6712650718595427340;
        wires[103] = 11324688242619723826;
        wires[104] = 12101128329784252957;
        wires[105] = 7021574844686015814;
        wires[106] = 1573942712604734795;
        wires[107] = 9128011964819706513;
        wires[108] = 14287160755542597886;
        wires[109] = 13486504918171888162;
        wires[110] = 4191697542050019758;
        wires[111] = 3605776254206642242;
        wires[112] = 10104859570037221388;
        wires[113] = 1548865457039542419;
        wires[114] = 7374208264979035156;
        wires[115] = 13370793737511569545;
        wires[116] = 13096221957965530844;
        wires[117] = 12791949985450251043;
        wires[118] = 3660229569451936613;
        wires[119] = 8081269712410083158;
        wires[120] = 12220177208407154777;
        wires[121] = 13784254654109082227;
        wires[122] = 9992132589067877300;
        wires[123] = 9178404222969987722;
        wires[124] = 15940322942134187827;
        wires[125] = 10340052457922554169;
        wires[126] = 4649587957172036564;
        wires[127] = 17798372934487717744;
        wires[128] = 10509637591346782777;
        wires[129] = 3399315819087885000;
        wires[130] = 13707166078905795614;
        wires[131] = 7143053828562992960;
        wires[132] = 15204644471397832059;
        wires[133] = 14995826821639838443;
        expected = new uint256[](67);
    }

    /// V6 UNSAT n=66 wrong intermediate_value[40]
    /// nonZeroConstraints = 2
    function v6() internal pure returns (uint256 n, uint256[] memory wires, uint256[] memory expected) {
        n = 66;
        wires = new uint256[](134);
        wires[0] = 15977249004024963792;
        wires[1] = 0;
        wires[2] = 1;
        wires[3] = 0;
        wires[4] = 0;
        wires[5] = 0;
        wires[6] = 0;
        wires[7] = 0;
        wires[8] = 1;
        wires[9] = 0;
        wires[10] = 0;
        wires[11] = 0;
        wires[12] = 1;
        wires[13] = 1;
        wires[14] = 0;
        wires[15] = 0;
        wires[16] = 1;
        wires[17] = 1;
        wires[18] = 0;
        wires[19] = 0;
        wires[20] = 0;
        wires[21] = 1;
        wires[22] = 1;
        wires[23] = 1;
        wires[24] = 0;
        wires[25] = 1;
        wires[26] = 0;
        wires[27] = 1;
        wires[28] = 0;
        wires[29] = 0;
        wires[30] = 1;
        wires[31] = 0;
        wires[32] = 0;
        wires[33] = 0;
        wires[34] = 0;
        wires[35] = 0;
        wires[36] = 0;
        wires[37] = 1;
        wires[38] = 0;
        wires[39] = 1;
        wires[40] = 0;
        wires[41] = 1;
        wires[42] = 0;
        wires[43] = 0;
        wires[44] = 0;
        wires[45] = 0;
        wires[46] = 0;
        wires[47] = 1;
        wires[48] = 1;
        wires[49] = 0;
        wires[50] = 0;
        wires[51] = 1;
        wires[52] = 0;
        wires[53] = 0;
        wires[54] = 1;
        wires[55] = 0;
        wires[56] = 1;
        wires[57] = 0;
        wires[58] = 0;
        wires[59] = 0;
        wires[60] = 1;
        wires[61] = 0;
        wires[62] = 0;
        wires[63] = 1;
        wires[64] = 1;
        wires[65] = 1;
        wires[66] = 1;
        wires[67] = 14995826821639838443;
        wires[68] = 15977249004024963792;
        wires[69] = 5744290381756689572;
        wires[70] = 10355413999767222965;
        wires[71] = 17235660293567679972;
        wires[72] = 344766636035480001;
        wires[73] = 9820078043220380599;
        wires[74] = 13127534321080255641;
        wires[75] = 17707003240272356692;
        wires[76] = 6974860312521735387;
        wires[77] = 8192352049173065842;
        wires[78] = 13066173458272625281;
        wires[79] = 11761832042390067147;
        wires[80] = 7703570608873368286;
        wires[81] = 671933825190702923;
        wires[82] = 5032222067009987429;
        wires[83] = 8498269171102104820;
        wires[84] = 9122359476022663042;
        wires[85] = 914119491639181555;
        wires[86] = 786963090374026518;
        wires[87] = 11245005792686967415;
        wires[88] = 17489108719538647672;
        wires[89] = 12791324300071723591;
        wires[90] = 10211804171030218872;
        wires[91] = 12804582627905694771;
        wires[92] = 1911522140165245073;
        wires[93] = 12635331154706129990;
        wires[94] = 2441012097855967122;
        wires[95] = 17079346952873683933;
        wires[96] = 3760029117475956168;
        wires[97] = 2392757742335968935;
        wires[98] = 10596395094064461930;
        wires[99] = 11806839169328115114;
        wires[100] = 13795585445336321205;
        wires[101] = 2406492611906002453;
        wires[102] = 6712650718595427340;
        wires[103] = 11324688242619723826;
        wires[104] = 12101128329784252957;
        wires[105] = 7021574844686015814;
        wires[106] = 1573942712604734795;
        wires[107] = 9128011964819706513;
        wires[108] = 14287160755542597893;
        wires[109] = 13486504918171888162;
        wires[110] = 4191697542050019758;
        wires[111] = 3605776254206642242;
        wires[112] = 10104859570037221388;
        wires[113] = 1548865457039542419;
        wires[114] = 7374208264979035156;
        wires[115] = 13370793737511569545;
        wires[116] = 13096221957965530844;
        wires[117] = 12791949985450251043;
        wires[118] = 3660229569451936613;
        wires[119] = 8081269712410083158;
        wires[120] = 12220177208407154777;
        wires[121] = 13784254654109082227;
        wires[122] = 9992132589067877300;
        wires[123] = 9178404222969987722;
        wires[124] = 15940322942134187827;
        wires[125] = 10340052457922554169;
        wires[126] = 4649587957172036564;
        wires[127] = 17798372934487717744;
        wires[128] = 10509637591346782777;
        wires[129] = 3399315819087885000;
        wires[130] = 13707166078905795614;
        wires[131] = 7143053828562992960;
        wires[132] = 15204644471397832059;
        wires[133] = 14995826821639838443;
        expected = new uint256[](67);
        expected[40] = 18446744069414584314;
        expected[41] = 5284121780236014538;
    }

    /// V7 satisfying n=1 base=9 bit=1
    /// nonZeroConstraints = 0
    function v7() internal pure returns (uint256 n, uint256[] memory wires, uint256[] memory expected) {
        n = 1;
        wires = new uint256[](4);
        wires[0] = 9;
        wires[1] = 1;
        wires[2] = 9;
        wires[3] = 9;
        expected = new uint256[](2);
    }

}
