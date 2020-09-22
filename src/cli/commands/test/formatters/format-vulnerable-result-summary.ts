import { Options, TestOptions } from '../../../../lib/types';

export function summariseVulnerableResults(
  vulnerableResults,
  options: Options & TestOptions,
): string {
  const vulnsLength = vulnerableResults.length;
  if (vulnsLength) {
    if (options.iac) {
      return `, ${vulnsLength} contained issues.`;
    } else if (options.showVulnPaths) {
      return `, ${vulnsLength} contained vulnerable paths.`;
    }
    return `, ${vulnsLength} had issues.`;
  }

  if (options.showVulnPaths) {
    return ', no vulnerable paths were found.';
  }

  return ', no issues were found.';
}
