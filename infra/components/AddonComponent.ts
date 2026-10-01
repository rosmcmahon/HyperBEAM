import * as pulumi from '@pulumi/pulumi'
import * as docker from '@pulumi/docker'
import * as path from 'path'
import * as fs from 'fs'
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

        /* copycat fully indexes each block (bundles at every depth) once it has `confirmations` blocks on
         * top, retrying unfinished blocks back to `retryDepth` below the tip. with `match-index-every`,
         * GraphQL block queries list every item of a fully indexed block and error on an unfinished one. */
        const extConfig = config.externalConfig?.[name] ?? {}
        const confirmations = extConfig.COPYCAT_CONFIRMATIONS ?? '1'
        const retryDepth = extConfig.COPYCAT_RETRY_DEPTH ?? '20'
        const interval = extConfig.COPYCAT_INTERVAL ?? '1-minute'
        /* full mode caches every item's data (~18 GB/day); start.sh clears the cache past this size */
        const maxCacheGB = extConfig.HB_MAX_CACHE_GB ?? '50'
        const copycatCron = [
            `/~cron@1.0/every?interval=${interval}`,
            'cron-path=/~copycat@1.0/arweave',
            'mode=full',
            `from=-${confirmations}`,
            `to=-${retryDepth}`,
            'reindex=false',
            'include-proofs=false',
            'include-block-index=true',
        ].join('&')
        /* JSON keeps option types; the node falls back to defaults if this fails to load */
        const nodeConfig = JSON.stringify({ 'match-index-every': true }, null, 2)
        const startScript = fs.readFileSync(path.join(import.meta.dirname, '../start.sh'), 'utf-8')

        const volume = new docker.Volume(`${name}-data`, {
            name: naming(stackName, `${name}-data`),
        }, { ...childOpts, retainOnDelete: true })

        new docker.Container(name, {
            name: naming(stackName, name),
            image: image.repoDigest,
            networksAdvanced: [{ name: networkName }],
            volumes: [{ volumeName: volume.name, containerPath: '/data' }],
            uploads: [
                { file: '/opt/hb/shepherd-config.json', content: nodeConfig },
                { file: '/opt/hb/shepherd-start.sh', content: startScript, permissions: '0755' },
            ],
            envs: [
                'HB_CONFIG=/opt/hb/shepherd-config.json',
                `HB_CRONS=${copycatCron}`,
                `HB_MAX_CACHE_GB=${maxCacheGB}`,
            ],
            entrypoints: ['/opt/hb/shepherd-start.sh', '/opt/hb/bin/hb', 'foreground'],
            ports: [{ internal: 8734, external: 8734, ip: '127.0.0.1' }],
            ulimits: [{ name: 'nofile', soft: 65536, hard: 65536 }],
            logDriver: lokiLogDriver,
            logOpts: lokiLogOpts,
            restart: 'unless-stopped',
        }, { ...childOpts, dependsOn: [image] })

        this.registerOutputs({})
    }
}
