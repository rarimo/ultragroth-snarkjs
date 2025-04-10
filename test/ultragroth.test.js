import * as ultragroth from "../src/ultra_zkey.js";
import { getCurveFromName } from "../src/curves.js";
import path from "path";
import assert from "assert";

describe.only("UltraGroth test suite", function () {
    const r1csFilename = path.join("test", "ultragroth", "seheavy_lookup.r1cs");
    const indexesFilename = path.join("test", "ultragroth", "seheavy_indexes.json");
    const ptauFilename = path.join("test", "ultragroth", "powersOfTau28_hez_final_20.ptau");
    const zkey1Filename = path.join("test", "ultragroth", "seheavy_lookup_1.zkey");
    const zkey2Filename = path.join("test", "ultragroth", "seheavy_lookup_2.zkey");
    const zkey3Filename = path.join("test", "ultragroth", "seheavy_lookup_3.zkey");
    const zkeyFinalFilename = path.join("test", "ultragroth", "seheavy_lookup_final.zkey");

    this.timeout(1000000000);

    let curve;

    before(async () => {
        curve = await getCurveFromName("bn128");
    });

    after(async () => {
        await curve.terminate();
    });

    it("ultragroth zkey generation", async () => {
        await ultragroth.newUltraZKey(r1csFilename, ptauFilename, zkey1Filename, indexesFilename);
        await ultragroth.ultraPhase2contribute(zkey1Filename, zkey2Filename, "contribution1", "entropy1");
        await ultragroth.ultraPhase2contribute(zkey2Filename, zkey3Filename, "contribution2", "entropy2");
        await ultragroth.ultraBeacon(zkey3Filename, zkeyFinalFilename, "beacon", "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 10);

        const isValid = await ultragroth.ultraPhase2verifyFromInit(zkey1Filename, ptauFilename, zkeyFinalFilename);

        assert(isValid);
    });
});
