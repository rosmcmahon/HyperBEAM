import * as pulumi from '@pulumi/pulumi'
import * as docker from '@pulumi/docker'
import * as path from 'path'
import { execSync } from 'child_process'
import { naming, type Config } from '../../../../Config'
import { lokiLogDriver, lokiLogOpts } from '../../../../infra/components/lokiLogConfig'

export interface AddonComponentArgs {
    config: Config
    stackName: string
    networkName: pulumi.Output<string>
}

export class AddonComponent extends pulumi.ComponentResource {

    constructor(name: string, args: AddonComponentArgs, opts?: pulumi.ComponentResourceOptions) {
        super('shepherd:addon:AddonComponent', name, {}, opts)

        const childOpts = { ...opts, parent: this }
        const { config, stackName, networkName } = args

        const hyperbeamDir = path.join(import.meta.dirname, '../../')
        let gitSha = 'unknown'
        try {
            gitSha = execSync('git rev-parse HEAD', { cwd: hyperbeamDir, encoding: 'utf8' }).trim()
        } catch {
            /* .git missing or not a repo; Dockerfile defaults GIT_SHA to unknown */
        }

        const image = new docker.Image(`image-${name}`, {
            build: {
                context: hyperbeamDir,
                builderVersion: docker.BuilderVersion.BuilderBuildKit,
                platform: config.buildPlatform ?? 'linux/amd64',
                target: 'hyperbeam',
                args: { GIT_SHA: gitSha },
            },
            imageName: naming(stackName, name),
            skipPush: true,
        }, childOpts)

        const volume = new docker.Volume(`${name}-data`, {
            name: naming(stackName, `${name}-data`),
        }, { ...childOpts, retainOnDelete: true })

        new docker.Container(name, {
            name: naming(stackName, name),
            image: image.repoDigest,
            networksAdvanced: [{ name: networkName }],
            volumes: [{ volumeName: volume.name, containerPath: '/data' }],
            ports: [{ internal: 8734, external: 8734, ip: '127.0.0.1' }],
            ulimits: [{ name: 'nofile', soft: 65536, hard: 65536 }],
            logDriver: lokiLogDriver,
            logOpts: lokiLogOpts,
            restart: 'unless-stopped',
        }, { ...childOpts, dependsOn: [image] })

        this.registerOutputs({})
    }
}
