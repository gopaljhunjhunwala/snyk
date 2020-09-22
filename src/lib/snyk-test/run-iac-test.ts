import * as fs from 'fs';
import * as path from 'path';
import * as pathUtil from 'path';
import { TestResult } from './legacy';
import { IacTestResponse } from './iac-test-result';
import * as snyk from '..';
import { isCI } from '../is-ci';
import * as common from './common';
import * as config from '../config';
import { Options, TestOptions } from '../types';
import { Payload } from './types';
import { IacScan } from './payload-schema';
import { SEVERITY } from './legacy';
import * as pathLib from 'path';
import { projectTypeByFileType, IacFileTypes } from '../iac/constants';

export async function parseIacTestResult(
  res: IacTestResponse,
  targetFile: string | undefined,
  projectName: any,
  severityThreshold?: SEVERITY,
  //TODO(orka): future - return a proper type
): Promise<TestResult> {
  const meta = (res as any).meta || {};

  severityThreshold =
    severityThreshold === SEVERITY.LOW ? undefined : severityThreshold;

  return {
    ...res,
    vulnerabilities: [],
    dependencyCount: 0,
    licensesPolicy: null,
    ignoreSettings: null,
    targetFile,
    projectName,
    org: meta.org,
    policy: meta.policy,
    isPrivate: !meta.isPublic,
    severityThreshold,
  };
}

export async function assembleIacLocalPayloads(
  root: string,
  options: Options & TestOptions,
): Promise<Payload[]> {
  const payloads: Payload[] = [];
  // Forcing options.path to be a string as pathUtil requires is to be stringified

  if (!options.iacDirFiles) {
    const targetFile = pathLib.resolve(root, '.');
    const targetFileRelativePath = targetFile
      ? pathUtil.join(pathUtil.resolve(`${options.path}`), targetFile)
      : '';
    const fileType = pathLib.extname(root).substr(1);
    const payload = assembleIacLocalPayload(
      fileType,
      targetFile,
      targetFileRelativePath,
      options,
    );
    return [payload];
  }

  for (const iacFile of options.iacDirFiles) {
    if (iacFile.projectType) {
      const targetFile = iacFile.filePath;
      const payload = assembleIacLocalPayload(
        iacFile.fileType,
        targetFile,
        targetFile,
        options,
      );
      payloads.push(payload);
    }
  }

  return payloads;
}

function assembleIacLocalPayload(
  fileType: string,
  targetFile: string,
  targetFileRelativePath: string,
  options: Options & TestOptions,
): Payload {
  const fileContent = fs.readFileSync(targetFile, 'utf8');
  const projectType = projectTypeByFileType[fileType];

  const body: IacScan = {
    data: {
      fileContent,
      fileType: fileType as IacFileTypes,
    },
    targetFile,
    type: projectType,
    //TODO(orka): future - support policy
    policy: '',
    targetFileRelativePath: `${targetFileRelativePath}`, // Forcing string
    originalProjectName: path.basename(path.dirname(targetFile)),
    projectNameOverride: options.projectName,
  };
  const payload: Payload = {
    method: 'POST',
    url: config.API + (options.vulnEndpoint || '/test-iac'),
    json: true,
    headers: {
      'x-is-ci': isCI(),
      authorization: 'token ' + (snyk as any).api,
    },
    qs: common.assembleQueryString(options),
    body,
  };

  return payload;
}
