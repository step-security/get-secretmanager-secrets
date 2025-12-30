/*
 * Copyright 2020 Google LLC
 * Copyright 2025 StepSecurity
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import {
  exportVariable,
  getInput,
  setFailed,
  setOutput,
  setSecret,
  info,
  error,
} from '@actions/core';
import { errorMessage, parseBoolean } from '@google-github-actions/actions-utils';

import { Client } from './client';
import { parseSecretsRefs } from './reference';
import axios, { isAxiosError } from 'axios';

async function validateSubscription(): Promise<void> {
  const API_URL = `https://agent.api.stepsecurity.io/v1/github/${process.env.GITHUB_REPOSITORY}/actions/subscription`;

  try {
    await axios.get(API_URL, { timeout: 3000 });
  } catch (err) {
    if (isAxiosError(err) && err.response?.status === 403) {
      error('Subscription is not valid. Reach out to support@stepsecurity.io');
      process.exit(1);
    } else {
      info('Timeout or API not reachable. Continuing to next step.');
    }
  }
}

/**
 * Executes the main action. It includes the main business logic and is the
 * primary entry point. It is documented inline.
 */
async function run(): Promise<void> {
  try {
    await validateSubscription();
    const universe = getInput('universe');
    const secretsInput = getInput('secrets', { required: true });
    const minMaskLength = parseInt(getInput('min_mask_length'));
    const exportEnvironment = parseBoolean(getInput('export_to_environment'));
    const encoding = (getInput('encoding') || 'utf8') as BufferEncoding;

    // Create an API client.
    const client = new Client({
      universe: universe,
    });

    // Parse all the provided secrets into references.
    const secretsRefs = parseSecretsRefs(secretsInput);

    // Access and export each secret.
    for (const ref of secretsRefs) {
      const value = await client.accessSecret(ref, encoding);

      // Split multiline secrets by line break and mask each line.
      // Read more here: https://github.com/actions/runner/issues/161
      value.split(/\r\n|\r|\n/g).forEach((line) => {
        // Only mask sufficiently long values. There's a risk in masking
        // extremely short values in that it will make output completely
        // unreadable.
        if (line && line.length >= minMaskLength) {
          setSecret(line);
        }
      });

      setOutput(ref.output, value);

      if (exportEnvironment) {
        exportVariable(ref.output, value);
      }
    }
  } catch (err) {
    const msg = errorMessage(err);
    setFailed(`step-security/get-secretmanager-secrets failed with: ${msg}`);
  }
}

if (require.main === module) {
  run();
}
