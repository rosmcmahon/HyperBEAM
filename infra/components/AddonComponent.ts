import * as pulumi from '@pulumi/pulumi'
import * as docker from '@pulumi/docker'
import * as path from 'path'
import { execSync } from 'child_process'
import { naming, type Config } from '../../../../Config'

export interface AddonComponentArgs {
	config: Config
	stackName: string
}

export class AddonComponent extends pulumi.ComponentResource {

	constructor(name: string, args: AddonComponentArgs, opts?: pulumi.ComponentResourceOptions) {
		super('shepherd:addon:AddonComponent', name, {}, opts)

		const childOpts = { ...opts, parent: this }
		const { config, stackName } = args
		const n = (s: string) => naming(stackName, s)

		const hyperbeamDir = path.join(import.meta.dirname, '../../')
		let gitSha = 'unknown'
		try {
			gitSha = execSync('git rev-parse HEAD', { cwd: hyperbeamDir, encoding: 'utf8' }).trim()
		} catch {
			/* .git missing or not a repo; Dockerfile defaults GIT_SHA to unknown */
		}

		new docker.Image(`image-${name}`, {
			build: {
				context: hyperbeamDir,
				builderVersion: docker.BuilderVersion.BuilderBuildKit,
				platform: config.buildPlatform ?? 'linux/amd64',
				target: 'hyperbeam',
				args: { GIT_SHA: gitSha },
			},
			imageName: n(name),
			skipPush: true,
		}, childOpts)

		this.registerOutputs({})
	}
}
