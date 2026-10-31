/** Offline synthetic cases only; no user-selected target or operational key. */
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { runSuite } from './lab.mjs';

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  if (process.argv.length !== 2) {
    process.stderr.write('No input arguments accepted; fixed synthetic cases only.\n');
    process.exitCode = 2;
  } else {
    try {
      const report = await runSuite();
      process.stdout.write(JSON.stringify(report, null, 2) + '\n');
      if (report.test_result !== 'PASS') process.exitCode = 1;
    } catch {
      process.stderr.write('Runtime boundary experiment failed; no successful report produced.\n');
      process.exitCode = 1;
    }
  }
}
