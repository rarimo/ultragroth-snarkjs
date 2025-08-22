import * as ultragroth from "../src/ultra_zkey.js";
import { getCurveFromName } from "../src/curves.js";
import ultraZkeyExportVerificationKey from "../src/ultra_zkey_export_verificationkey.js";
import path from "path";
import assert from "assert";
import fs from "fs";

function requireEnv(varName) {
    const val = process.env[varName];
    if (!val) {
        throw new Error(`Missing required environment variable: ${varName}`);
    }
    return val;
}

describe.only("UltraGroth test suite", function () {
    const r1csFilename = requireEnv("R1CS");
    const indexesFilename = requireEnv("INDEXES");
    const ptauFilename = requireEnv("PTAU");
    const outDir = requireEnv("OUT_DIR");
    const outName = requireEnv("OUT_NAME");

    const zkey1Filename = path.join(outDir, `${outName}_1.zkey`);
    const zkey2Filename = path.join(outDir, `${outName}_2.zkey`);
    const zkey3Filename = path.join(outDir, `${outName}_3.zkey`);
    const zkeyFinalFilename = path.join(outDir, `${outName}_final.zkey`);
    const vkeyFilename = path.join(outDir, `${outName}_vkey.json`);

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
        const vKeyData = await ultraZkeyExportVerificationKey(zkeyFinalFilename);
        fs.writeFileSync(vkeyFilename, JSON.stringify(vKeyData));

        const isValid = await ultragroth.ultraPhase2verifyFromInit(zkey1Filename, ptauFilename, zkeyFinalFilename);

        assert(isValid);
    });
});