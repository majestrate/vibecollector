// scripts/clean.ts
import { rm, readdir } from 'node:fs/promises'
import { join, resolve } from 'node:path'

const root = process.cwd()

/** Directories to remove outright. */
const dirs = [
  'dist',
  'coverage',
  'node_modules/.vite',
  'node_modules/.tmp',
]

/** Individual files to remove. */
const files = ['.eslintcache']

async function clean() {
  const targets: string[] = [...dirs, ...files]

  // tsc -b leaves these anywhere in the tree; grab the root-level ones.
  for (const entry of await readdir(root)) {
    if (entry.endsWith('.tsbuildinfo')) targets.push(entry)
  }

  const dryRun = process.argv.includes('--dry-run')

  for (const target of targets) {
    const path = resolve(root, target)
    if (dryRun) {
      console.log(`[clean] would remove ${target}`)
      continue
    }
    await rm(path, { recursive: true, force: true })
    console.log(`[clean] removed ${target}`)
  }
}

await clean()
