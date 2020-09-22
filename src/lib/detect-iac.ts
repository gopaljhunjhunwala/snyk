import * as fs from 'fs';
import * as pathLib from 'path';
import * as debugLib from 'debug';
import { isLocalFolder, localFileSuppliedButNotFound } from './detect';
import {
  IacErrorWithMessage,
  IllegalIacFileErrorMsg,
  CustomError,
} from './errors';
import {
  validateK8sFile,
  makeValidateTerraformRequest,
} from './iac/iac-parser';
import {
  projectTypeByFileType,
  IacProjectType,
  IacFileTypes,
} from './iac/constants';
import {
  SupportLocalFileOnlyIacError,
  UnsupportedOptionFileIacError,
  IacDirectoryWithoutAnyIacFileError,
} from './errors/unsupported-options-iac-error';
import { IllegalTerraformFileError } from './errors/invalid-iac-file';
import { Options, TestOptions, IacFileInDirectory } from './types';

const debug = debugLib('snyk-detect-iac');

export async function detectIacProject(
  root: string,
  options: Options & TestOptions,
): Promise<string> {
  if (options.file) {
    debug('Iac - --file specified ' + options.file);
    throw UnsupportedOptionFileIacError(options.file);
  }

  if (isLocalFolder(root)) {
    return await getFolderProjectType(root, options);
  }

  if (localFileSuppliedButNotFound(root, '.') || !fs.existsSync(root)) {
    throw SupportLocalFileOnlyIacError();
  }

  const filePath = pathLib.resolve(root, '.');
  return getProjectTypeForIacFile(filePath);
}

async function getProjectTypeForIacFile(filePath: string) {
  const fileContent = fs.readFileSync(filePath, 'utf-8');
  const fileType = pathLib.extname(filePath).substr(1);
  const fileName = pathLib.basename(filePath);
  const projectType = projectTypeByFileType[fileType];
  switch (projectType) {
    case IacProjectType.K8S: {
      const { isValidFile, reason } = validateK8sFile(
        fileContent,
        filePath,
        fileName,
      );
      if (!isValidFile) {
        throw IacErrorWithMessage(reason);
      }
      break;
    }
    case IacProjectType.TERRAFORM: {
      const { isValidFile, reason } = await makeValidateTerraformRequest(
        fileContent,
      );
      if (!isValidFile) {
        throw IllegalTerraformFileError([fileName], reason);
      }
      break;
    }
    default:
      throw IacErrorWithMessage(IllegalIacFileErrorMsg([fileName]));
  }

  return projectType;
}

async function getFolderProjectType(
  root: string,
  options: Options & TestOptions,
) {
  const iacFiles: IacFileInDirectory[] = [];
  const files = fs.readdirSync(root);

  for (const fileName of files) {
    const ext = pathLib.extname(fileName).substr(1);
    if (Object.keys(projectTypeByFileType).includes(ext)) {
      const filePath = pathLib.resolve(root, fileName);

      await getProjectTypeForIacFile(filePath)
        .then((projectType) => {
          iacFiles.push({
            filePath,
            projectType,
            fileType: ext as IacFileTypes,
          });
        })
        .catch((err: CustomError) => {
          iacFiles.push({
            filePath,
            fileType: ext as IacFileTypes,
            failureReason: err.userMessage,
          });
        });
    }
  }

  if (iacFiles.length === 0) {
    throw IacDirectoryWithoutAnyIacFileError();
  }

  options.iacDirFiles = iacFiles;

  //We return here K8S be default as we want the test flow to continue as IaC projectType
  return IacProjectType.K8S;
}
