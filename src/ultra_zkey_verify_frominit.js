/*
    Copyright 2018 0KIMS association.

    This file is part of snarkJS.

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

import * as binFileUtils from "@iden3/binfileutils";
import * as zkeyUtils from "./ultra_zkey_utils.js";
import {hashG1, hashPubKeyDelta1, hashPubKeyDelta2} from "./ultra_zkey_utils.js";
import {getCurveFromQ as getCurve} from "./curves.js";
import Blake2b from "blake2b-wasm";
import * as misc from "./misc.js";
import {hashToG2 as hashToG2} from "./keypair.js";
import {BigBuffer, ChaCha, Scalar} from "ffjavascript";

const sameRatio = misc.sameRatio;


export default async function ultraPhase2verifyFromInit(initFileName, pTauFileName, zkeyFileName, logger) {
    let sr;
    await Blake2b.ready();

    const {fd, sections} = await binFileUtils.readBinFile(zkeyFileName, "zkey", 2);
    const zkey = await zkeyUtils.readHeader(fd, sections, false);
    if (zkey.protocol !== "ultragroth") {
        throw new Error("zkey file is not groth16");
    }

    const curve = await getCurve(zkey.q);
    const sG1 = curve.G1.F.n8 * 2;

    const mpcParams = await zkeyUtils.readMPCParams(fd, curve, sections);

    const accumulatedHasher1 = Blake2b(64);
    const accumulatedHasher2 = Blake2b(64);
    accumulatedHasher1.update(mpcParams.csHash);
    accumulatedHasher2.update(mpcParams.csHash);

    let curDelta1 = curve.G1.g;
    let curDelta2 = curve.G1.g;
    for (let i = 0; i < mpcParams.contributions.length; i++) {
        const c = mpcParams.contributions[i];
        const ourHasher1 = misc.cloneHasher(accumulatedHasher1);
        const ourHasher2 = misc.cloneHasher(accumulatedHasher2);

        hashG1(ourHasher1, curve, c.delta1.g1_s);
        hashG1(ourHasher1, curve, c.delta1.g1_sx);
        hashG1(ourHasher2, curve, c.delta2.g1_s);
        hashG1(ourHasher2, curve, c.delta2.g1_sx);

        if (!misc.hashIsEqual(ourHasher1.digest(), c.transcript1)) {
            console.log(`INVALID(${i}): Inconsistent transcript1 `);
            return false;
        }

        if (!misc.hashIsEqual(ourHasher2.digest(), c.transcript2)) {
            console.log(`INVALID(${i}): Inconsistent transcript2 `);
            return false;
        }

        const delta1_g2_sp = hashToG2(curve, c.transcript1);
        const delta2_g2_sp = hashToG2(curve, c.transcript2);

        sr = await sameRatio(curve, c.delta1.g1_s, c.delta1.g1_sx, delta1_g2_sp, c.delta1.g2_spx);
        if (sr !== true) {
            console.log(`INVALID(${i}): delta1 public key G1 and G2 do not have the same ration `);
            return false;
        }

        sr = await sameRatio(curve, c.delta2.g1_s, c.delta2.g1_sx, delta2_g2_sp, c.delta2.g2_spx);
        if (sr !== true) {
            console.log(`INVALID(${i}): delta2 public key G1 and G2 do not have the same ration `);
            return false;
        }

        sr = await sameRatio(curve, curDelta1, c.delta1After, delta1_g2_sp, c.delta1.g2_spx);
        if (sr !== true) {
            console.log(`INVALID(${i}): delta1After does not fillow the public key `);
            return false;
        }

        sr = await sameRatio(curve, curDelta2, c.delta2After, delta2_g2_sp, c.delta2.g2_spx);
        if (sr !== true) {
            console.log(`INVALID(${i}): delta2After does not fillow the public key `);
            return false;
        }

        if (c.type === 1) {
            const rng = await misc.rngFromBeaconParams(c.beaconHash, c.numIterationsExp);
            const expected_prvKey1 = curve.Fr.fromRng(rng);
            const expected_delta1_g1_s = curve.G1.toAffine(curve.G1.fromRng(rng));
            const expected_delta1_g1_sx = curve.G1.toAffine(curve.G1.timesFr(expected_delta1_g1_s, expected_prvKey1));

            const expected_prvKey2 = curve.Fr.fromRng(rng);
            const expected_delta2_g1_s = curve.G1.toAffine(curve.G1.fromRng(rng));
            const expected_delta2_g1_sx = curve.G1.toAffine(curve.G1.timesFr(expected_delta2_g1_s, expected_prvKey2));

            if (curve.G1.eq(expected_delta1_g1_s, c.delta1.g1_s) !== true) {
                console.log(`INVALID(${i}): Key of the beacon does not match. delta1 g1_s `);
                return false;
            }
            if (curve.G1.eq(expected_delta1_g1_sx, c.delta1.g1_sx) !== true) {
                console.log(`INVALID(${i}): Key of the beacon does not match. delta1 g1_sx `);
                return false;
            }
            if (curve.G1.eq(expected_delta2_g1_s, c.delta2.g1_s) !== true) {
                console.log(`INVALID(${i}): Key of the beacon does not match. delta2 g1_s `);
                return false;
            }
            if (curve.G1.eq(expected_delta2_g1_sx, c.delta2.g1_sx) !== true) {
                console.log(`INVALID(${i}): Key of the beacon does not match. delta2 g1_sx `);
                return false;
            }
        }

        hashPubKeyDelta1(accumulatedHasher1, curve, c);
        hashPubKeyDelta2(accumulatedHasher2, curve, c);

        const contributionHasher = Blake2b(64);
        hashPubKeyDelta1(contributionHasher, curve, c);
        hashPubKeyDelta2(contributionHasher, curve, c);

        c.contributionHash = contributionHasher.digest();

        curDelta1 = c.delta1After;
        curDelta2 = c.delta2After;
    }

    const {fd: fdInit, sections: sectionsInit} = await binFileUtils.readBinFile(initFileName, "zkey", 2);
    const zkeyInit = await zkeyUtils.readHeader(fdInit, sectionsInit, false);

    if (zkeyInit.protocol !== "ultragroth") {
        throw new Error("zkeyinit file is not ultragroth");
    }

    if ((!Scalar.eq(zkeyInit.q, zkey.q))
        || (!Scalar.eq(zkeyInit.r, zkey.r))
        || (zkeyInit.n8q !== zkey.n8q)
        || (zkeyInit.n8r !== zkey.n8r)) {
        if (logger) logger.error("INVALID:  Different curves");
        return false;
    }

    if ((zkeyInit.nVars !== zkey.nVars)
        || (zkeyInit.nPublic !== zkey.nPublic)
        || (zkeyInit.domainSize !== zkey.domainSize)
        || (zkeyInit.nIndexesC1 !== zkey.nIndexesC1)
        || (zkeyInit.nIndexesC2 !== zkey.nIndexesC2)
        || (zkeyInit.randIdx !== zkey.randIdx)) {
        if (logger) logger.error("INVALID:  Different circuit parameters");
        return false;
    }

    if (!curve.G1.eq(zkey.vk_alpha_1, zkeyInit.vk_alpha_1)) {
        if (logger) logger.error("INVALID:  Invalid alpha1");
        return false;
    }
    if (!curve.G1.eq(zkey.vk_beta_1, zkeyInit.vk_beta_1)) {
        if (logger) logger.error("INVALID:  Invalid beta1");
        return false;
    }
    if (!curve.G2.eq(zkey.vk_beta_2, zkeyInit.vk_beta_2)) {
        if (logger) logger.error("INVALID:  Invalid beta2");
        return false;
    }
    if (!curve.G2.eq(zkey.vk_gamma_2, zkeyInit.vk_gamma_2)) {
        if (logger) logger.error("INVALID:  Invalid gamma2");
        return false;
    }
    if (!curve.G1.eq(zkey.vk_delta_c1_1, curDelta1)) {
        if (logger) logger.error("INVALID:  Invalid delta_c1_1");
        return false;
    }
    if (!curve.G1.eq(zkey.vk_delta_c2_1, curDelta2)) {
        if (logger) logger.error("INVALID:  Invalid delta_c2_1");
        return false;
    }
    sr = await sameRatio(curve, curve.G1.g, curDelta1, curve.G2.g, zkey.vk_delta_c1_2);
    if (sr !== true) {
        if (logger) logger.error("INVALID:  Invalid delta_c1_2");
        return false;
    }
    sr = await sameRatio(curve, curve.G1.g, curDelta2, curve.G2.g, zkey.vk_delta_c2_2);
    if (sr !== true) {
        if (logger) logger.error("INVALID:  Invalid delta_c2_2");
        return false;
    }

    const mpcParamsInit = await zkeyUtils.readMPCParams(fdInit, curve, sectionsInit);
    if (!misc.hashIsEqual(mpcParams.csHash, mpcParamsInit.csHash)) {
        if (logger) logger.error("INVALID:  Circuit does not match");
        return false;
    }

    // Check sizes of sections
    if (sections[8][0].size !== sG1 * zkey.nIndexesC1) {
        if (logger) logger.error("INVALID:  Invalid C1 section size");
        return false;
    }

    if (sections[9][0].size !== sG1 * zkey.nIndexesC2) {
        if (logger) logger.error("INVALID:  Invalid C2 section size");
        return false;
    }

    if (sections[10][0].size !== 4 * zkey.nIndexesC1) {
        if (logger) logger.error("INVALID:  Invalid IndexesC1 section size");
        return false;
    }

    if (sections[11][0].size !== 4 * zkey.nIndexesC2) {
        if (logger) logger.error("INVALID:  Invalid IndexesC2 section size");
        return false;
    }

    if (sections[12][0].size !== sG1 * (zkey.domainSize)) {
        if (logger) logger.error("INVALID:  Invalid H section size");
        return false;
    }

    let ss;
    ss = await binFileUtils.sectionIsEqual(fd, sections, fdInit, sectionsInit, 3);
    if (!ss) {
        if (logger) logger.error("INVALID:  IC section is not identical");
        return false;
    }

    ss = await binFileUtils.sectionIsEqual(fd, sections, fdInit, sectionsInit, 4);
    if (!ss) {
        if (logger) logger.error("Coeffs section is not identical");
        return false;
    }

    ss = await binFileUtils.sectionIsEqual(fd, sections, fdInit, sectionsInit, 5);
    if (!ss) {
        if (logger) logger.error("A section is not identical");
        return false;
    }

    ss = await binFileUtils.sectionIsEqual(fd, sections, fdInit, sectionsInit, 6);
    if (!ss) {
        if (logger) logger.error("B1 section is not identical");
        return false;
    }

    ss = await binFileUtils.sectionIsEqual(fd, sections, fdInit, sectionsInit, 7);
    if (!ss) {
        if (logger) logger.error("B2 section is not identical");
        return false;
    }

    ss = await binFileUtils.sectionIsEqual(fd, sections, fdInit, sectionsInit, 10);
    if (!ss) {
        if (logger) logger.error("IndexesC1 section is not identical");
        return false;
    }

    ss = await binFileUtils.sectionIsEqual(fd, sections, fdInit, sectionsInit, 11);
    if (!ss) {
        if (logger) logger.error("IndexesC2 section is not identical");
        return false;
    }

    // Check C1
    sr = await sectionHasSameRatio("G1", fdInit, sectionsInit, fd, sections, 8, zkey.vk_delta_c1_2, zkeyInit.vk_delta_c1_2, "C1 section");
    if (sr !== true) {
        if (logger) logger.error("C1 section does not match");
        return false;
    }

    // Check C1
    sr = await sectionHasSameRatio("G1", fdInit, sectionsInit, fd, sections, 9, zkey.vk_delta_c2_2, zkeyInit.vk_delta_c2_2, "C2 section");
    if (sr !== true) {
        if (logger) logger.error("C2 section does not match");
        return false;
    }

    // Check H
    sr = await sameRatioH();
    if (sr !== true) {
        if (logger) logger.error("H section does not match");
        return false;
    }

    if (logger) logger.info(misc.formatHash(mpcParams.csHash, "Circuit Hash: "));

    await fd.close();
    await fdInit.close();

    for (let i = mpcParams.contributions.length - 1; i >= 0; i--) {
        const c = mpcParams.contributions[i];
        if (logger) logger.info("-------------------------");
        if (logger) logger.info(misc.formatHash(c.contributionHash, `contribution #${i + 1} ${c.name ? c.name : ""}:`));
        if (c.type === 1) {
            if (logger) logger.info(`Beacon generator: ${misc.byteArray2hex(c.beaconHash)}`);
            if (logger) logger.info(`Beacon iterations Exp: ${c.numIterationsExp}`);
        }
    }
    if (logger) logger.info("-------------------------");

    if (logger) logger.info("ZKey Ok!");

    return true;


    async function sectionHasSameRatio(groupName, fd1, sections1, fd2, sections2, idSection, g2sp, g2spx, sectionName) {
        const MAX_CHUNK_SIZE = 1 << 20;
        const G = curve[groupName];
        const sG = G.F.n8 * 2;
        await binFileUtils.startReadUniqueSection(fd1, sections1, idSection);
        await binFileUtils.startReadUniqueSection(fd2, sections2, idSection);

        let R1 = G.zero;
        let R2 = G.zero;

        const nPoints = sections1[idSection][0].size / sG;

        for (let i = 0; i < nPoints; i += MAX_CHUNK_SIZE) {
            if (logger) logger.debug(`Same ratio check ${sectionName}:  ${i}/${nPoints}`);
            const n = Math.min(nPoints - i, MAX_CHUNK_SIZE);
            const bases1 = await fd1.read(n * sG);
            const bases2 = await fd2.read(n * sG);

            const scalars = misc.getRandomBytes(4 * n);

            const r1 = await G.multiExpAffine(bases1, scalars);
            const r2 = await G.multiExpAffine(bases2, scalars);

            R1 = G.add(R1, r1);
            R2 = G.add(R2, r2);
        }
        await binFileUtils.endReadSection(fd1);
        await binFileUtils.endReadSection(fd2);

        if (nPoints === 0) return true;

        sr = await sameRatio(curve, R1, R2, g2sp, g2spx);
        if (sr !== true) return false;

        return true;
    }

    async function sameRatioH() {
        const MAX_CHUNK_SIZE = 1 << 20;
        const G = curve.G1;
        const Fr = curve.Fr;
        const sG = G.F.n8 * 2;

        const {fd: fdPTau, sections: sectionsPTau} = await binFileUtils.readBinFile(pTauFileName, "ptau", 1);

        let buff_r = new BigBuffer(zkey.domainSize * zkey.n8r);

        const seed = new Array(8);
        for (let i = 0; i < 8; i++) {
            seed[i] = misc.readUInt32BE(misc.getRandomBytes(4), 0);
        }
        const rng = new ChaCha(seed);
        for (let i = 0; i < zkey.domainSize - 1; i++) {   // Note that last one is zero
            const e = Fr.fromRng(rng);
            Fr.toRprLE(buff_r, i * zkey.n8r, e);
        }
        Fr.toRprLE(buff_r, (zkey.domainSize - 1) * zkey.n8r, Fr.zero);

        let R1 = G.zero;
        for (let i = 0; i < zkey.domainSize; i += MAX_CHUNK_SIZE) {
            if (logger) logger.debug(`H Verification(tau):  ${i}/${zkey.domainSize}`);
            const n = Math.min(zkey.domainSize - i, MAX_CHUNK_SIZE);

            const buff1 = await fdPTau.read(sG * n, sectionsPTau[2][0].p + zkey.domainSize * sG + i * sG);
            const buff2 = await fdPTau.read(sG * n, sectionsPTau[2][0].p + i * sG);

            const buffB = await batchSubtract(buff1, buff2);
            const buffS = buff_r.slice(i * zkey.n8r, (i + n) * zkey.n8r);
            const r = await G.multiExpAffine(buffB, buffS);

            R1 = G.add(R1, r);
        }

        // Calculate odd coefficients in transformed domain

        buff_r = await Fr.batchToMontgomery(buff_r);
        // const first = curve.Fr.neg(curve.Fr.inv(curve.Fr.e(2)));
        // Works*2   const first = curve.Fr.neg(curve.Fr.e(2));


        let first;

        if (zkey.power < Fr.s) {
            first = Fr.neg(Fr.e(2));
        } else {
            const small_m = 2 ** Fr.s;
            const shift_to_small_m = Fr.exp(Fr.shift, small_m);
            first = Fr.sub(shift_to_small_m, Fr.one);
        }

        // const inc = curve.Fr.inv(curve.PFr.w[zkey.power+1]);
        const inc = zkey.power < Fr.s ? Fr.w[zkey.power + 1] : Fr.shift;
        buff_r = await Fr.batchApplyKey(buff_r, first, inc);
        buff_r = await Fr.fft(buff_r);
        buff_r = await Fr.batchFromMontgomery(buff_r);

        await binFileUtils.startReadUniqueSection(fd, sections, 12);
        let R2 = G.zero;
        for (let i = 0; i < zkey.domainSize; i += MAX_CHUNK_SIZE) {
            if (logger) logger.debug(`H Verification(lagrange):  ${i}/${zkey.domainSize}`);
            const n = Math.min(zkey.domainSize - i, MAX_CHUNK_SIZE);

            const buff = await fd.read(sG * n);
            const buffS = buff_r.slice(i * zkey.n8r, (i + n) * zkey.n8r);
            const r = await G.multiExpAffine(buff, buffS);

            R2 = G.add(R2, r);
        }
        await binFileUtils.endReadSection(fd);

        sr = await sameRatio(curve, R1, R2, zkey.vk_delta_c2_2, zkeyInit.vk_delta_c2_2);
        if (sr !== true) return false;

        return true;
    }

    async function batchSubtract(buff1, buff2) {
        const sG = curve.G1.F.n8 * 2;
        const nPoints = buff1.byteLength / sG;
        const concurrency = curve.tm.concurrency;
        const nPointsPerThread = Math.floor(nPoints / concurrency);
        const opPromises = [];
        for (let i = 0; i < concurrency; i++) {
            let n;
            if (i < concurrency - 1) {
                n = nPointsPerThread;
            } else {
                n = nPoints - i * nPointsPerThread;
            }
            if (n == 0) continue;

            const subBuff1 = buff1.slice(i * nPointsPerThread * sG1, (i * nPointsPerThread + n) * sG1);
            const subBuff2 = buff2.slice(i * nPointsPerThread * sG1, (i * nPointsPerThread + n) * sG1);
            opPromises.push(batchSubtractThread(subBuff1, subBuff2));
        }

        const result = await Promise.all(opPromises);

        const fullBuffOut = new Uint8Array(nPoints * sG);
        let p = 0;
        for (let i = 0; i < result.length; i++) {
            fullBuffOut.set(result[i][0], p);
            p += result[i][0].byteLength;
        }

        return fullBuffOut;
    }

    async function batchSubtractThread(buff1, buff2) {
        const sG1 = curve.G1.F.n8 * 2;
        const sGmid = curve.G1.F.n8 * 3;
        const nPoints = buff1.byteLength / sG1;
        const task = [];
        task.push({cmd: "ALLOCSET", var: 0, buff: buff1});
        task.push({cmd: "ALLOCSET", var: 1, buff: buff2});
        task.push({cmd: "ALLOC", var: 2, len: nPoints * sGmid});
        for (let i = 0; i < nPoints; i++) {
            task.push({
                cmd: "CALL",
                fnName: "g1m_subAffine",
                params: [
                    {var: 0, offset: i * sG1},
                    {var: 1, offset: i * sG1},
                    {var: 2, offset: i * sGmid},
                ]
            });
        }
        task.push({
            cmd: "CALL", fnName: "g1m_batchToAffine", params: [
                {var: 2},
                {val: nPoints},
                {var: 2},
            ]
        });
        task.push({cmd: "GET", out: 0, var: 2, len: nPoints * sG1});

        return await curve.tm.queueAction(task);
    }
}
