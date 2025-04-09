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
import * as utils from "./ultra_zkey_utils.js";
import {getCurveFromQ as getCurve} from "./curves.js";
import * as misc from "./misc.js";
import Blake2b from "blake2b-wasm";
import {hashToG2 as hashToG2} from "./keypair.js";
import {applyKeyToSection} from "./mpc_applykey.js";


export default async function ultraBeacon(zkeyNameOld, zkeyNameNew, name, beaconHashStr, numIterationsExp, logger) {
    await Blake2b.ready();

    const beaconHash = misc.hex2ByteArray(beaconHashStr);
    if ((beaconHash.byteLength === 0)
        || (beaconHash.byteLength * 2 !== beaconHashStr.length)) {
        if (logger) logger.error("Invalid Beacon Hash. (It must be a valid hexadecimal sequence)");
        return false;
    }
    if (beaconHash.length >= 256) {
        if (logger) logger.error("Maximum length of beacon hash is 255 bytes");
        return false;
    }

    numIterationsExp = parseInt(numIterationsExp);
    if ((numIterationsExp < 10) || (numIterationsExp > 63)) {
        if (logger) logger.error("Invalid numIterationsExp. (Must be between 10 and 63)");
        return false;
    }

    const {fd: fdOld, sections: sections} = await binFileUtils.readBinFile(zkeyNameOld, "zkey", 2);
    const zkey = await zkeyUtils.readHeader(fdOld, sections);

    if (zkey.protocol !== "ultragroth") {
        throw new Error("zkey file is not ultragroth");
    }

    const curve = await getCurve(zkey.q);

    const mpcParams = await zkeyUtils.readMPCParams(fdOld, curve, sections);

    const fdNew = await binFileUtils.createBinFile(zkeyNameNew, "zkey", 1, 13);

    const rng = await misc.rngFromBeaconParams(beaconHash, numIterationsExp);

    const transcript1Hasher = Blake2b(64);
    const transcript2Hasher = Blake2b(64);
    transcript1Hasher.update(mpcParams.csHash);
    transcript2Hasher.update(mpcParams.csHash);

    for (let i = 0; i < mpcParams.contributions.length; i++) {
        zkeyUtils.hashPubKeyDelta1(transcript1Hasher, curve, mpcParams.contributions[i]);
        zkeyUtils.hashPubKeyDelta2(transcript2Hasher, curve, mpcParams.contributions[i]);
    }

    const curContribution = {};
    curContribution.delta1 = {};
    curContribution.delta1.prvKey = curve.Fr.fromRng(rng);
    curContribution.delta1.g1_s = curve.G1.toAffine(curve.G1.fromRng(rng));
    curContribution.delta1.g1_sx = curve.G1.toAffine(curve.G1.timesFr(curContribution.delta1.g1_s, curContribution.delta1.prvKey));
    utils.hashG1(transcript1Hasher, curve, curContribution.delta1.g1_s);
    utils.hashG1(transcript1Hasher, curve, curContribution.delta1.g1_sx);
    curContribution.transcript1 = transcript1Hasher.digest();
    curContribution.delta1.g2_sp = hashToG2(curve, curContribution.transcript1);
    curContribution.delta1.g2_spx = curve.G2.toAffine(curve.G2.timesFr(curContribution.delta1.g2_sp, curContribution.delta1.prvKey));

    curContribution.delta2 = {};
    curContribution.delta2.prvKey = curve.Fr.fromRng(rng);
    curContribution.delta2.g1_s = curve.G1.toAffine(curve.G1.fromRng(rng));
    curContribution.delta2.g1_sx = curve.G1.toAffine(curve.G1.timesFr(curContribution.delta2.g1_s, curContribution.delta2.prvKey));
    utils.hashG1(transcript2Hasher, curve, curContribution.delta2.g1_s);
    utils.hashG1(transcript2Hasher, curve, curContribution.delta2.g1_sx);
    curContribution.transcript2 = transcript2Hasher.digest();
    curContribution.delta2.g2_sp = hashToG2(curve, curContribution.transcript2);
    curContribution.delta2.g2_spx = curve.G2.toAffine(curve.G2.timesFr(curContribution.delta2.g2_sp, curContribution.delta2.prvKey));

    zkey.vk_delta_c1_1 = curve.G1.timesFr(zkey.vk_delta_c1_1, curContribution.delta1.prvKey);
    zkey.vk_delta_c1_2 = curve.G2.timesFr(zkey.vk_delta_c1_2, curContribution.delta1.prvKey);
    zkey.vk_delta_c2_1 = curve.G1.timesFr(zkey.vk_delta_c2_1, curContribution.delta2.prvKey);
    zkey.vk_delta_c2_2 = curve.G2.timesFr(zkey.vk_delta_c2_2, curContribution.delta2.prvKey);

    curContribution.delta1After = zkey.vk_delta_c1_1;
    curContribution.delta2After = zkey.vk_delta_c2_1;

    curContribution.type = 1;
    curContribution.numIterationsExp = numIterationsExp;
    curContribution.beaconHash = beaconHash;

    if (name) curContribution.name = name;

    mpcParams.contributions.push(curContribution);

    await zkeyUtils.writeHeader(fdNew, zkey);

    // IC
    await binFileUtils.copySection(fdOld, sections, fdNew, 3);

    // Coeffs (Keep original)
    await binFileUtils.copySection(fdOld, sections, fdNew, 4);

    // A Section
    await binFileUtils.copySection(fdOld, sections, fdNew, 5);

    // B1 Section
    await binFileUtils.copySection(fdOld, sections, fdNew, 6);

    // B2 Section
    await binFileUtils.copySection(fdOld, sections, fdNew, 7);

    const invDelta1 = curve.Fr.inv(curContribution.delta1.prvKey);
    await applyKeyToSection(fdOld, sections, fdNew, 8, curve, "G1", invDelta1, curve.Fr.e(1), "C1 Section", logger);

    const invDelta2 = curve.Fr.inv(curContribution.delta2.prvKey);
    await applyKeyToSection(fdOld, sections, fdNew, 9, curve, "G1", invDelta2, curve.Fr.e(1), "C2 Section", logger);

    // IndexesC1 Section
    await binFileUtils.copySection(fdOld, sections, fdNew, 10);

    // IndexesC2 Section
    await binFileUtils.copySection(fdOld, sections, fdNew, 11);

    await applyKeyToSection(fdOld, sections, fdNew, 12, curve, "G1", invDelta2, curve.Fr.e(1), "H Section", logger);

    await zkeyUtils.writeMPCParams(fdNew, curve, mpcParams);

    await fdOld.close();
    await fdNew.close();

    const contributionHasher = Blake2b(64);
    zkeyUtils.hashPubKeyDelta1(contributionHasher, curve, curContribution);
    zkeyUtils.hashPubKeyDelta2(contributionHasher, curve, curContribution);

    const contributionHash = contributionHasher.digest();

    if (logger) logger.info(misc.formatHash(contributionHash, "Contribution Hash: "));

    return contributionHash;
}
