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

// Format
// ======
// Header(1)
//      prover_type (1337 for UltraGroth)
// HeaderUltraGroth(2)
//      n8q (the number of bytes needed to hold field order)
//      q (field order)
//      n8r (the number of bytes needed to hold group order)
//      r (group order)
//      n_vars (number of all the witness vars)
//      n_pubs (number of public inputs + outputs)
//      domain_size (2 ** (log2(n_constraints + n_pubs) + 1))
//      n_indexes_c1
//      n_indexes_c2
//      rand_idx
//      alpha_1
//      beta_1
//      beta_2
//      gamma_2
//      delta_c1_1
//      delta_c1_2
//      delta_c2_1
//      delta_c2_2
// IC(3)
// Coeffs(4)
// PointsA(5)
// PointsB1(6)
// PointsB2(7)
// PointsC1(8)
// PointsC2(9)
// IndexesC1(10)
// IndexesC2(11)
// PointsH(12)
// Contributions(13)

import {F1Field, Scalar} from "ffjavascript";
import * as binFileUtils from "@iden3/binfileutils";

import {getCurveFromQ as getCurve} from "./curves.js";
import {log2} from "./misc.js";
import {ULTRAGROTH_PROTOCOL_ID} from "./zkey_constants.js";

export async function writeHeader(fd, zkey) {
    // Write the header
    await binFileUtils.startWriteSection(fd, 1);

    await fd.writeULE32(ULTRAGROTH_PROTOCOL_ID);

    await binFileUtils.endWriteSection(fd);

    // Write the UltraGroth header section
    await binFileUtils.startWriteSection(fd, 2);

    const curve = await getCurve(zkey.q);
    const primeQ = curve.q;
    const primeR = curve.r;
    const n8q = (Math.floor((Scalar.bitLength(primeQ) - 1) / 64) + 1) * 8;
    const n8r = (Math.floor((Scalar.bitLength(primeR) - 1) / 64) + 1) * 8;

    await fd.writeULE32(n8q);
    await binFileUtils.writeBigInt(fd, primeQ, n8q);
    await fd.writeULE32(n8r);
    await binFileUtils.writeBigInt(fd, primeR, n8r);

    await fd.writeULE32(zkey.nVars);
    await fd.writeULE32(zkey.nPublic);
    await fd.writeULE32(zkey.domainSize);
    await fd.writeULE32(zkey.nIndexesC1);
    await fd.writeULE32(zkey.nIndexesC2);
    await fd.writeULE32(zkey.randIdx);

    await writeG1(fd, curve, zkey.vk_alpha_1);
    await writeG1(fd, curve, zkey.vk_beta_1);
    await writeG2(fd, curve, zkey.vk_beta_2);
    await writeG2(fd, curve, zkey.vk_gamma_2);
    await writeG1(fd, curve, zkey.vk_delta_c1_1);
    await writeG2(fd, curve, zkey.vk_delta_c1_2);
    await writeG1(fd, curve, zkey.vk_delta_c2_1);
    await writeG2(fd, curve, zkey.vk_delta_c2_2);

    await binFileUtils.endWriteSection(fd);
}

export async function writeZKey(fileName, zkey) {
    const fd = await binFileUtils.createBinFile(fileName, "zkey", 1, 12);

    await writeHeader(fd, zkey);

    // Write Pols (A and B (C can be omitted))
    const n8r = (Math.floor((Scalar.bitLength(zkey.r) - 1) / 64) + 1) * 8;
    const Rr = Scalar.mod(Scalar.shl(1, n8r * 8), zkey.r);
    const R2r = Scalar.mod(Scalar.mul(Rr, Rr), zkey.r);

    zkey.ccoefs = zkey.ccoefs.filter(c => c.matrix < 2);
    zkey.ccoefs.sort((a, b) => a.constraint - b.constraint);

    await binFileUtils.startWriteSection(fd, 4);

    await fd.writeULE32(zkey.ccoefs.length);
    for (let i = 0; i < zkey.ccoefs.length; i++) {
        const coef = zkey.ccoefs[i];
        await fd.writeULE32(coef.matrix);
        await fd.writeULE32(coef.constraint);
        await fd.writeULE32(coef.signal);
        await writeFr2(coef.value);
    }

    await binFileUtils.endWriteSection(fd);

    const curve = getCurve(zkey.q);

    // Write IC Section
    await binFileUtils.startWriteSection(fd, 3);

    for (let i = 0; i <= zkey.nPublic; i++) {
        await writeG1(fd, curve, zkey.IC[i]);
    }

    await binFileUtils.endWriteSection(fd);

    // Write A
    await binFileUtils.startWriteSection(fd, 5);

    for (let i = 0; i < zkey.nVars; i++) {
        await writeG1(fd, curve, zkey.A[i]);
    }

    await binFileUtils.endWriteSection(fd);

    // Write B1
    await binFileUtils.startWriteSection(fd, 6);

    for (let i = 0; i < zkey.nVars; i++) {
        await writeG1(fd, curve, zkey.B1[i]);
    }

    await binFileUtils.endWriteSection(fd);

    // Write B2
    await binFileUtils.startWriteSection(fd, 7);

    for (let i = 0; i < zkey.nVars; i++) {
        await writeG2(fd, curve, zkey.B2[i]);
    }

    await binFileUtils.endWriteSection(fd);

    // Write C1 (part 1 of private indexes)
    await binFileUtils.startWriteSection(fd, 8);

    for (let i = 0; i < zkey.nIndexesC1; i++) {
        await writeG1(fd, curve, zkey.C1[i]);
    }

    await binFileUtils.endWriteSection(fd);

    // Write C2 (part 2 of private indexes)
    await binFileUtils.startWriteSection(fd, 9);

    for (let i = 0; i < zkey.nIndexesC2; i++) {
        await writeG1(fd, curve, zkey.C2[i]);
    }

    await binFileUtils.endWriteSection(fd);

    // Write C1 indexes
    await binFileUtils.startWriteSection(fd, 10);

    for (let i = 0; i < zkey.nIndexesC1; i++) {
        await fd.writeULE32(zkey.indexesC1[i]);
    }

    await binFileUtils.endWriteSection(fd);

    // Write C2 indexes
    await binFileUtils.startWriteSection(fd, 11);

    for (let i = 0; i < zkey.nIndexesC2; i++) {
        await fd.writeULE32(zkey.indexesC2[i]);
    }

    await binFileUtils.endWriteSection(fd);

    // Write H points
    await binFileUtils.startWriteSection(fd, 10);

    for (let i = 0; i < zkey.domainSize; i++) {
        await writeG1(fd, curve, zkey.hExps[i]);
    }

    await binFileUtils.endWriteSection(fd);

    await fd.close();

    async function writeFr2(n) {
        // Convert to montgomery
        n = Scalar.mod(Scalar.mul(n, R2r), zkey.r);

        await binFileUtils.writeBigInt(fd, n, n8r);
    }
}

async function writeG1(fd, curve, p) {
    const buff = new Uint8Array(curve.G1.F.n8 * 2);
    curve.G1.toRprLEM(buff, 0, p);
    await fd.write(buff);
}

async function writeG2(fd, curve, p) {
    const buff = new Uint8Array(curve.G2.F.n8 * 2);
    curve.G2.toRprLEM(buff, 0, p);
    await fd.write(buff);
}

async function readG1(fd, curve, toObject) {
    const buff = await fd.read(curve.G1.F.n8 * 2);
    const res = curve.G1.fromRprLEM(buff, 0);
    return toObject ? curve.G1.toObject(res) : res;
}

async function readG2(fd, curve, toObject) {
    const buff = await fd.read(curve.G2.F.n8 * 2);
    const res = curve.G2.fromRprLEM(buff, 0);
    return toObject ? curve.G2.toObject(res) : res;
}

export async function readHeader(fd, sections, toObject, options) {
    // Read Header
    await binFileUtils.startReadUniqueSection(fd, sections, 1);
    const protocolId = await fd.readULE32();
    await binFileUtils.endReadSection(fd);

    if (protocolId === ULTRAGROTH_PROTOCOL_ID) {
        return await readHeaderUltraGroth(fd, sections, toObject, options);
    } else {
        throw new Error("Protocol not supported: ");
    }
}

async function readHeaderUltraGroth(fd, sections, toObject, options) {
    const zkey = {};

    zkey.protocol = "ultragroth";

    // Read UltraGroth Header
    await binFileUtils.startReadUniqueSection(fd, sections, 2);

    const n8q = await fd.readULE32();
    zkey.n8q = n8q;
    zkey.q = await binFileUtils.readBigInt(fd, n8q);

    const n8r = await fd.readULE32();
    zkey.n8r = n8r;
    zkey.r = await binFileUtils.readBigInt(fd, n8r);

    zkey.curve = await getCurve(zkey.q, options);
    zkey.nVars = await fd.readULE32();
    zkey.nPublic = await fd.readULE32();
    zkey.domainSize = await fd.readULE32();
    zkey.nIndexesC1 = await fd.readULE32();
    zkey.nIndexesC2 = await fd.readULE32();
    zkey.randIdx = await fd.readULE32();
    zkey.power = log2(zkey.domainSize);
    zkey.vk_alpha_1 = await readG1(fd, zkey.curve, toObject);
    zkey.vk_beta_1 = await readG1(fd, zkey.curve, toObject);
    zkey.vk_beta_2 = await readG2(fd, zkey.curve, toObject);
    zkey.vk_gamma_2 = await readG2(fd, zkey.curve, toObject);
    zkey.vk_delta_c1_1 = await readG1(fd, zkey.curve, toObject);
    zkey.vk_delta_c1_2 = await readG2(fd, zkey.curve, toObject);
    zkey.vk_delta_c2_1 = await readG1(fd, zkey.curve, toObject);
    zkey.vk_delta_c2_2 = await readG2(fd, zkey.curve, toObject);

    await binFileUtils.endReadSection(fd);

    return zkey;
}

export async function readZKey(fileName, toObject) {
    const {fd, sections} = await binFileUtils.readBinFile(fileName, "zkey", 1);

    const zkey = await readHeader(fd, sections, toObject);

    const Fr = new F1Field(zkey.r);
    const Rr = Scalar.mod(Scalar.shl(1, zkey.n8r * 8), zkey.r);
    const Rri = Fr.inv(Rr);
    const Rri2 = Fr.mul(Rri, Rri);

    const curve = await getCurve(zkey.q);

    // Read IC Section
    await binFileUtils.startReadUniqueSection(fd, sections, 3);

    zkey.IC = [];
    for (let i = 0; i <= zkey.nPublic; i++) {
        const P = await readG1(fd, curve, toObject);
        zkey.IC.push(P);
    }

    await binFileUtils.endReadSection(fd);

    // Read Coeffs
    await binFileUtils.startReadUniqueSection(fd, sections, 4);
    const nCCoeffs = await fd.readULE32();
    zkey.ccoefs = [];
    for (let i = 0; i < nCCoeffs; i++) {
        const m = await fd.readULE32();
        const c = await fd.readULE32();
        const s = await fd.readULE32();
        const v = await readFr2(toObject);
        zkey.ccoefs.push({
            matrix: m,
            constraint: c,
            signal: s,
            value: v
        });
    }
    await binFileUtils.endReadSection(fd);

    // Read A points
    ///////////
    await binFileUtils.startReadUniqueSection(fd, sections, 5);
    zkey.A = [];
    for (let i = 0; i < zkey.nVars; i++) {
        zkey.A[i] = await readG1(fd, curve, toObject);
    }
    await binFileUtils.endReadSection(fd);

    // Read B1
    ///////////
    await binFileUtils.startReadUniqueSection(fd, sections, 6);
    zkey.B1 = [];
    for (let i = 0; i < zkey.nVars; i++) {
        zkey.B1[i] = await readG1(fd, curve, toObject);
    }
    await binFileUtils.endReadSection(fd);


    // Read B2 points
    ///////////
    await binFileUtils.startReadUniqueSection(fd, sections, 7);
    zkey.B2 = [];
    for (let i = 0; i < zkey.nVars; i++) {
        zkey.B2[i] = await readG2(fd, curve, toObject);
    }
    await binFileUtils.endReadSection(fd);

    // Read C1 points
    await binFileUtils.startReadUniqueSection(fd, sections, 8);
    zkey.C1 = [];
    for (let i = 0; i < zkey.nIndexesC1; i++) {
        zkey.C1[i] = await readG1(fd, curve, toObject);
    }
    await binFileUtils.endReadSection(fd);

    // Read C2 points
    await binFileUtils.startReadUniqueSection(fd, sections, 9);
    zkey.C2 = [];
    for (let i = 0; i < zkey.nIndexesC2; i++) {
        zkey.C2[i] = await readG1(fd, curve, toObject);
    }
    await binFileUtils.endReadSection(fd);

    // C1 Indexes
    await binFileUtils.startReadUniqueSection(fd, sections, 10);
    zkey.indexesC1 = [];
    for (let i = 0; i < zkey.nIndexesC1; i++) {
        zkey.indexesC1[i] = await fd.readULE32();
    }
    await binFileUtils.endReadSection(fd);

    // C2 Indexes
    await binFileUtils.startReadUniqueSection(fd, sections, 11);
    zkey.indexesC2 = [];
    for (let i = 0; i < zkey.nIndexesC2; i++) {
        zkey.indexesC2[i] = await fd.readULE32();
    }
    await binFileUtils.endReadSection(fd);

    // Read H points
    ///////////
    await binFileUtils.startReadUniqueSection(fd, sections, 12);
    zkey.hExps = [];
    for (let i = 0; i < zkey.domainSize; i++) {
        const H = await readG1(fd, curve, toObject);
        zkey.hExps.push(H);
    }
    await binFileUtils.endReadSection(fd);

    await fd.close();

    return zkey;

    async function readFr2(/* toObject */) {
        const n = await binFileUtils.readBigInt(fd, zkey.n8r);
        return Fr.mul(n, Rri2);
    }
}

async function readContribution(fd, curve, toObject) {
    const c = {delta1: {}, delta2: {}};
    c.delta1After = await readG1(fd, curve, toObject);
    c.delta1.g1_s = await readG1(fd, curve, toObject);
    c.delta1.g1_sx = await readG1(fd, curve, toObject);
    c.delta1.g2_spx = await readG2(fd, curve, toObject);
    c.transcript1 = await fd.read(64);
    c.delta2After = await readG1(fd, curve, toObject);
    c.delta2.g1_s = await readG1(fd, curve, toObject);
    c.delta2.g1_sx = await readG1(fd, curve, toObject);
    c.delta2.g2_spx = await readG2(fd, curve, toObject);
    c.transcript2 = await fd.read(64);
    c.type = await fd.readULE32();

    const paramLength = await fd.readULE32();
    const curPos = fd.pos;
    let lastType = 0;
    while (fd.pos - curPos < paramLength) {
        const buffType = await fd.read(1);
        if (buffType[0] <= lastType) throw new Error("Parameters in the contribution must be sorted");
        lastType = buffType[0];
        if (buffType[0] === 1) {     // Name
            const buffLen = await fd.read(1);
            const buffStr = await fd.read(buffLen[0]);
            c.name = new TextDecoder().decode(buffStr);
        } else if (buffType[0] === 2) {
            const buffExp = await fd.read(1);
            c.numIterationsExp = buffExp[0];
        } else if (buffType[0] === 3) {
            const buffLen = await fd.read(1);
            c.beaconHash = await fd.read(buffLen[0]);
        } else {
            throw new Error("Parameter not recognized");
        }
    }
    if (fd.pos !== curPos + paramLength) {
        throw new Error("Parameters do not match");
    }

    return c;
}


export async function readMPCParams(fd, curve, sections) {
    await binFileUtils.startReadUniqueSection(fd, sections, 13);
    const res = {contributions: []};
    res.csHash = await fd.read(64);
    const n = await fd.readULE32();
    for (let i = 0; i < n; i++) {
        const c = await readContribution(fd, curve);
        res.contributions.push(c);
    }
    await binFileUtils.endReadSection(fd);

    return res;
}

async function writeContribution(fd, curve, c) {
    await writeG1(fd, curve, c.delta1After);
    await writeG1(fd, curve, c.delta1.g1_s);
    await writeG1(fd, curve, c.delta1.g1_sx);
    await writeG2(fd, curve, c.delta1.g2_spx);
    await fd.write(c.transcript1);
    await writeG1(fd, curve, c.delta2After);
    await writeG1(fd, curve, c.delta2.g1_s);
    await writeG1(fd, curve, c.delta2.g1_sx);
    await writeG2(fd, curve, c.delta2.g2_spx);
    await fd.write(c.transcript2);
    await fd.writeULE32(c.type || 0);

    const params = [];
    if (c.name) {
        params.push(1);      // Param Name
        const nameData = new TextEncoder("utf-8").encode(c.name.substring(0, 64));
        params.push(nameData.byteLength);
        for (let i = 0; i < nameData.byteLength; i++) params.push(nameData[i]);
    }
    if (c.type === 1) {
        params.push(2);      // Param numIterationsExp
        params.push(c.numIterationsExp);

        params.push(3);      // Beacon Hash
        params.push(c.beaconHash.byteLength);
        for (let i = 0; i < c.beaconHash.byteLength; i++) params.push(c.beaconHash[i]);
    }
    if (params.length > 0) {
        const paramsBuff = new Uint8Array(params);
        await fd.writeULE32(paramsBuff.byteLength);
        await fd.write(paramsBuff);
    } else {
        await fd.writeULE32(0);
    }

}

export async function writeMPCParams(fd, curve, mpcParams) {
    await binFileUtils.startWriteSection(fd, 13);
    await fd.write(mpcParams.csHash);
    await fd.writeULE32(mpcParams.contributions.length);
    for (let i = 0; i < mpcParams.contributions.length; i++) {
        await writeContribution(fd, curve, mpcParams.contributions[i]);
    }
    await binFileUtils.endWriteSection(fd);
}

export function hashG1(hasher, curve, p) {
    const buff = new Uint8Array(curve.G1.F.n8 * 2);
    curve.G1.toRprUncompressed(buff, 0, p);
    hasher.update(buff);
}

export function hashG2(hasher, curve, p) {
    const buff = new Uint8Array(curve.G2.F.n8 * 2);
    curve.G2.toRprUncompressed(buff, 0, p);
    hasher.update(buff);
}

export function hashPubKeyDelta1(hasher, curve, c) {
    hashG1(hasher, curve, c.delta1After);
    hashG1(hasher, curve, c.delta1.g1_s);
    hashG1(hasher, curve, c.delta1.g1_sx);
    hashG2(hasher, curve, c.delta1.g2_spx);
    hasher.update(c.transcript1);
}

export function hashPubKeyDelta2(hasher, curve, c) {
    hashG1(hasher, curve, c.delta2After);
    hashG1(hasher, curve, c.delta2.g1_s);
    hashG1(hasher, curve, c.delta2.g1_sx);
    hashG2(hasher, curve, c.delta2.g2_spx);
    hasher.update(c.transcript2);
}
