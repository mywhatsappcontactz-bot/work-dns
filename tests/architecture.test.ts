import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';

describe('Architectural Boundary Enforcement', () => {
  const repoRoot = path.resolve(__dirname, '..');
  const modulesDir = path.join(repoRoot, 'packages', 'modules');

  function getTsFiles(dir: string): string[] {
    if (!fs.existsSync(dir)) return [];
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    let files: string[] = [];

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name !== 'node_modules' && entry.name !== 'dist') {
          files = files.concat(getTsFiles(fullPath));
        }
      } else if (entry.isFile() && (entry.name.endsWith('.ts') || entry.name.endsWith('.tsx'))) {
        files.push(fullPath);
      }
    }
    return files;
  }

  it('forbids cross-module imports between packages/modules/*', () => {
    if (!fs.existsSync(modulesDir)) return;

    const moduleFolders = fs.readdirSync(modulesDir, { withFileTypes: true })
      .filter((d) => d.isDirectory())
      .map((d) => d.name);

    for (const moduleFolder of moduleFolders) {
      const modulePath = path.join(modulesDir, moduleFolder, 'src');
      const files = getTsFiles(modulePath);

      for (const file of files) {
        const content = fs.readFileSync(file, 'utf8');
        const importLines = content.split('\n').filter((l) => l.trim().startsWith('import '));

        for (const line of importLines) {
          // Check for forbidden cross-module imports
          for (const otherModule of moduleFolders) {
            if (otherModule !== moduleFolder) {
              const forbiddenPkg = `@work-dns/module-${otherModule}`;
              expect(
                line.includes(forbiddenPkg) || line.includes(`../${otherModule}`),
                `Architectural Violation in ${path.relative(repoRoot, file)}: Modules cannot import sibling module '${otherModule}' (Zero Cross-Module Imports rule). Line: "${line.trim()}"`
              ).toBe(false);
            }
          }
        }
      }
    }
  });

  it('forbids modules from importing internal private files of core packages', () => {
    if (!fs.existsSync(modulesDir)) return;

    const moduleFolders = fs.readdirSync(modulesDir, { withFileTypes: true })
      .filter((d) => d.isDirectory())
      .map((d) => d.name);

    for (const moduleFolder of moduleFolders) {
      const modulePath = path.join(modulesDir, moduleFolder, 'src');
      const files = getTsFiles(modulePath);

      for (const file of files) {
        const content = fs.readFileSync(file, 'utf8');
        const importLines = content.split('\n').filter((l) => l.trim().startsWith('import '));

        for (const line of importLines) {
          // Disallow imports from private /src/ paths of core packages
          expect(
            line.includes('/src/') && (line.includes('@work-dns/') || line.includes('../../packages/')),
            `Architectural Violation in ${path.relative(repoRoot, file)}: Modules must import public package roots, never internal /src/ files. Line: "${line.trim()}"`
          ).toBe(false);
        }
      }
    }
  });
});
