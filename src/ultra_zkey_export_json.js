import { readZKey as readZKey } from "./ultra_zkey_utils.js";
import { utils } from "ffjavascript";

export default async function ultraZkeyExportJson(zkeyFileName) {

    const zKey = await readZKey(zkeyFileName, true);
    delete zKey.curve;
    delete zKey.F;

    return utils.stringifyBigInts(zKey);
}
