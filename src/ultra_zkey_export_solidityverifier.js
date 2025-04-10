import ejs from "ejs";

import exportVerificationKey from "./ultra_zkey_export_verificationkey.js";
import fs from "fs";
import path from "path";

export default async function ultraExportSolidityVerifier(zKeyName, verifierName, logger) {
    const verificationKey = await exportVerificationKey(zKeyName, logger);
    verificationKey.verifier_id = path.parse(verifierName).name;

    let template = fs.readFileSync(path.join("../templates", "verifier_ultragroth.sol.ejs"), "utf8");
    const verifierCode = ejs.render(template, verificationKey);

    fs.writeFileSync(verifierName, verifierCode, "utf-8");
}
