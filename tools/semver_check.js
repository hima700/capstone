/**
 * Batch semver helper for the SBOM CVE pipeline.
 *
 * Reads a JSON array from stdin. Each element is an object with an "op" field:
 *
 *   { "op": "satisfies", "version": "1.2.3", "range": ">=1.0.0 <2.0.0" }
 *     -> returns true / false / null (null = parse failure)
 *
 *   { "op": "compare", "a": "1.2.3", "b": "2.0.0" }
 *     -> returns -1 / 0 / 1 / null
 *
 *   { "op": "sort", "versions": ["3.0.0", "1.0.0", "2.0.0"] }
 *     -> returns sorted array (ascending) or null
 *
 * Writes a JSON array of results to stdout (one result per input element).
 */

const semver = require('semver');

let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => { input += chunk; });
process.stdin.on('end', () => {
  let checks;
  try {
    checks = JSON.parse(input);
  } catch (e) {
    process.stderr.write('Invalid JSON input: ' + e.message + '\n');
    process.exit(1);
  }

  const results = checks.map(c => {
    try {
      switch (c.op) {
        case 'satisfies':
          return semver.satisfies(c.version, c.range, { includePrerelease: false });
        case 'compare':
          return semver.compare(c.a, c.b);
        case 'sort':
          return c.versions.slice().sort(semver.compare);
        default:
          return null;
      }
    } catch {
      return null;
    }
  });

  process.stdout.write(JSON.stringify(results));
});
