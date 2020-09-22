import chalk from 'chalk';
import { CustomError } from './custom-error';

export function NotSupportedIacFileErrorMsg(atLocations: string[]): string {
  const locationsStr = atLocations.join(', ');

  return (
    'Not supported infrastructure as code target files in ' +
    locationsStr +
    '.\nPlease see our documentation for supported target files (currently we support Kubernetes files only): ' +
    chalk.underline(
      'https://support.snyk.io/hc/en-us/articles/360006368877-Scan-and-fix-security-issues-in-your-Kubernetes-configuration-files',
    ) +
    ' and make sure you are in the right directory.'
  );
}

export function IllegalIacFileErrorMsg(atLocations: string[]): string {
  const locationsStr = atLocations.join(', ');
  return (
    'Illegal infrastructure as code target file ' +
    locationsStr +
    '.\nPlease see our documentation for supported target files (currently we support Kubernetes files only): ' +
    chalk.underline(
      'https://support.snyk.io/hc/en-us/articles/360006368877-Scan-and-fix-security-issues-in-your-Kubernetes-configuration-files',
    ) +
    ' and make sure you are in the right directory.'
  );
}

export function IacErrorWithMessage(errorMsg: string): CustomError {
  const error = new CustomError(errorMsg);
  error.code = 422;
  error.userMessage = errorMsg;
  return error;
}

export function IllegalTerraformFileError(
  atLocations: string[],
  reason: string,
): CustomError {
  const locationsStr = atLocations.join(', ');
  const errorMsg =
    `Illegal Terraform target file ${locationsStr} \nValidation Error Reason: ${reason}` +
    '.\nPlease see our documentation for supported target files (currently we support Kubernetes files only): ' +
    chalk.underline(
      'https://support.snyk.io/hc/en-us/articles/360006368877-Scan-and-fix-security-issues-in-your-Kubernetes-configuration-files',
    ) +
    ' and make sure you are in the right directory.';

  const error = new CustomError(errorMsg);
  error.code = 422;
  error.userMessage = errorMsg;
  return error;
}
