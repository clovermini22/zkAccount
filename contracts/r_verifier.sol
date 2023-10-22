// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;
library Pairing {
    struct G1Point {
        uint X;
        uint Y;
    }
    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint[2] X;
        uint[2] Y;
    }
    /// @return the generator of G1
    function P1() pure internal returns (G1Point memory) {
        return G1Point(1, 2);
    }
    /// @return the generator of G2
    function P2() pure internal returns (G2Point memory) {
        return G2Point(
            [10857046999023057135944570762232829481370756359578518086990519993285655852781,
             11559732032986387107991004021392285783925812861821192530917403151452391805634],
            [8495653923123431417604973247489272438418190587263600148770280649306958101930,
             4082367875863433681332203403145435568316851327593401208105741076214120093531]
        );
    }
    /// @return the negation of p, i.e. p.addition(p.negate()) should be zero.
    function negate(G1Point memory p) pure internal returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }
    /// @return r the sum of two points of G1
    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
    }


    /// @return r the product of a point on G1 and a scalar, i.e.
    /// p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p.
    function scalar_mul(G1Point memory p, uint s) internal view returns (G1Point memory r) {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require (success);
    }
    /// @return the result of computing the pairing check
    /// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
    /// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
    /// return true.
    function pairing(G1Point[] memory p1, G2Point[] memory p2) internal view returns (bool) {
        require(p1.length == p2.length);
        uint elements = p1.length;
        uint inputSize = elements * 6;
        uint[] memory input = new uint[](inputSize);
        for (uint i = 0; i < elements; i++)
        {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[1];
            input[i * 6 + 3] = p2[i].X[0];
            input[i * 6 + 4] = p2[i].Y[1];
            input[i * 6 + 5] = p2[i].Y[0];
        }
        uint[1] memory out;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
        return out[0] != 0;
    }
    /// Convenience method for a pairing check for two pairs.
    function pairingProd2(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for three pairs.
    function pairingProd3(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](3);
        G2Point[] memory p2 = new G2Point[](3);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for four pairs.
    function pairingProd4(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2,
            G1Point memory d1, G2Point memory d2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p1[3] = d1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        p2[3] = d2;
        return pairing(p1, p2);
    }
}

contract Verifier {
    using Pairing for *;
    struct VerifyingKey {
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }
    struct Proof {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G1Point c;
    }
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.alpha = Pairing.G1Point(uint256(0x0e51d8cdbc902e1ac82d615134c2fa6da7f35a345d55c28afb7bebf44991e33e), uint256(0x157d9173a1a2948ca799d9f17cc551e1faeaf49760fac7bef98b82ddfdc1d1dd));
        vk.beta = Pairing.G2Point([uint256(0x172b85aace9f03a91a10d382dcd8c571eb2f1e4f3bd694956d1f87d8818973a5), uint256(0x2689c8f21b854406dc6337e3c587ea5e963b3906123a700518ae92a1b5a06657)], [uint256(0x0302ca82753e6ad93644c9804ebd4c25e6cd19a5dbde7890d214697bd62c938c), uint256(0x0607b8d92b47de014db61e3c6177b2f5b3f8e9bcdbc4dc79ff3482e34a952505)]);
        vk.gamma = Pairing.G2Point([uint256(0x21a1d7c635a5c3a1dfa33b7053aaf360474f8801f494e524145ce63a444c4c64), uint256(0x09a8b7141ebd5d11f420304955999f366dce1ffe190e36dd000f6caa53be0446)], [uint256(0x1fea02f10833e3a9fb8362f41eabadb7191f0fc9c7d091b6e6d4cbdb2a8c0434), uint256(0x13aca12e5b6a76c0a9169053f51b1a9fe0a92b4519d386bc3e731b3953e51cc4)]);
        vk.delta = Pairing.G2Point([uint256(0x0b84c90eb44517825891812394076d1181fde043346327f79e3d4eacad7404e1), uint256(0x04dd25e02689d1769500cf0f9ce0ab060c157a2eab2dc26c3fa92a542a98d1fb)], [uint256(0x13b90098284e72fa2200bd51b4f390cc30a9bfd0c29542e798890c66b9b16ab3), uint256(0x19f76714e332b1287c8a5c6d2d2fcd576cc58cfc5e3722269e914457cc0ea97f)]);
        vk.gamma_abc = new Pairing.G1Point[](21);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x1f67f9b301df5e1873793c1f5bd8b3c427c3c7046994abddcf61b1345d47aa93), uint256(0x14fcd8766d09f61542791e0bebd8e6c75d81974db194788463de66aab626cea9));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x1773ad7eaeb63eecf9c9b97688bb1a99d88404eb4e22a904bb88c9198cb56fb2), uint256(0x068d05f58a04b53d30c36b3b2867341ffc44ae5454128e000255292fd656e89b));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x2f452ee45165de874431ad9390af189d0d8dc568dd18ceb04451fa386783a62b), uint256(0x20fdc9abacf8c8be9f8b4ab5d0e69945db9cf6e14794c42509fdb53512119f94));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x2d4cabf44d0218a5fa59555ad6966bf5541a894d5243252147546293751810fc), uint256(0x05d303c08d4d34e55b9e61753ceccccf5cc7025357c1b5611c6a1da62873771a));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x0daccaa0771738449b6bc657a2701ea9e161ac589d45d0477d637d131c792f47), uint256(0x2be34e95a2faa7fbda4c5187209cd11cab9dd486fd80fcd3a69e5c9c6b8b153e));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x07f28385031184eba2f6f1b62ef30f2862dda9536d11ed28e5ee254bb2f53412), uint256(0x132c04f0d5493860a65daaf5acaf23911590ba18b1b3a4275031a4a982fbc0a3));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x0c5d98117c5de8ecf14c96cd2884344ab5a50eb1562a260d8f7d4bc789e6f306), uint256(0x0e12eeb23d2355a47b56d8bca0d53f20966eafda82368b8f1afa15a7d3498384));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x0d6affe090ca4c38c27297bd1f61a65c6bc68b48e5d0f318d22fe6646f1549f9), uint256(0x12e9075085e3c79c125633c3bcddc1123ed318ec49e773d00240f8e2c26567cf));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x148e2e9d886c158ac4defe15fd4a4f757b751281af8eeb8e24847f1bc2882291), uint256(0x2f4c3eab938eff935010b99e951997b4ac249dfcd1c72eb8e1ddaf0fafe769f5));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x28cf8ea683d703ef39040e4d9e4fd111725fcb3cba34fa6536c4ae9b65109005), uint256(0x28c77ce3552e1f78160f61b37476307f9d7b640f206a4b07508875a8a2263839));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x127a439d1fd4273eb16a95358b6dd14855fd48a3536599757f1a93593eef12cf), uint256(0x2181e6cfa754b78e61a53b269720b012a35935542c0baabbe24b34696931292c));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x1a64f69cfb4f987fd3d7b42b3c4b972bda3325c2cf970641409b9275740f0fe3), uint256(0x135bdfa5c8cba4bdc324e782783919305ae8979852322e001f30c2571b34060a));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x2407373f98e9d62e77d4a2923faa38e4a90133479d9a3ead34ac3d8e62f44ec3), uint256(0x09cc79d546969408d6ade33c4900ddbbc5b59e216888559255cae45e8cd0a639));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x242706bef982d1775f6485cce2f53fe561247ae2ff9f1f8c77ee45f7fb536219), uint256(0x09085b7d30f324a613f512f869903e629b8ddef9dea24973094fdaffa498ebef));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x2717f658625ff7fcb084ab7881b3507f8c0283c796b609b4ed1691bacaae5d3a), uint256(0x266f595ebab4df52751631678d36559a29e43de47e1429f193687b1479227abb));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x2b9d8e8d25b9b3744dff190d5371eee3f06616adfd085a9e015144814b20c0c0), uint256(0x1cb4c295567d2fcd5d87ed61c5fa0070960cb4e590887ac344d6895d3b0ebfc0));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x283853610fee514a2d7d1ac40706efa32d9524c5c133dc5aa3422f36e087c3ac), uint256(0x0145e3982baa812daf6a55cb282290a37dd50da9158624131e8691664449ff02));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x1e641e89a926a7f11a01a306eaea4bb9f8c19997414673fc87d440758549d5a4), uint256(0x14c097d2213b14eee3387d486e30cd2a3afa49d265d204c66fda78cab3fbec1f));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x1337c5849e524d4c8f361e646c48bc1649cb97a0d74cc74c33fa8e8cc27d6b87), uint256(0x206b3ec1e32fa597b0543ce79ff5b99c05ea38257350676feb6e03cc123d3383));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x197acee8f5a82d8ee1aae3c3d1b0fec600ecf918fc626db22b4a8cb88709d0ce), uint256(0x2b97f90d74dafb509a3065a16d61d8e78594d69293560b0c99e58a8547ef32c0));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x0c2305cf96107f35ea7df331da76e5334a03e7ecb543f2e1e4a855a894e39263), uint256(0x05c4fd521c4e59a29d7ed750f1dc5d288cc7b83f7bfe4b98eaa555ab9ade1144));
    }
    function verify(uint[] memory input, Proof memory proof) internal view returns (uint) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.gamma_abc.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.gamma_abc[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.gamma_abc[0]);
        if(!Pairing.pairingProd4(
             proof.a, proof.b,
             Pairing.negate(vk_x), vk.gamma,
             Pairing.negate(proof.c), vk.delta,
             Pairing.negate(vk.alpha), vk.beta)) return 1;
        return 0;
    }
    function verifyTx(
            Proof memory proof, uint[20] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](20);
        
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            return true;
        } else {
            return false;
        }
    }
}
