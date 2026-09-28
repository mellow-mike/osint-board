// Match captured HTTP inputs using HTTP Archive's maintained engine.
// No page code is executed and this runner makes no network requests.
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(process.argv[2]);
const signals = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));
const engine = require(path.join(root, 'src/js/wappalyzer.js'));
const technologies = {};
for (const file of fs.readdirSync(path.join(root, 'src/technologies')).sort()) {
  if (file.endsWith('.json')) {
    Object.assign(technologies, JSON.parse(fs.readFileSync(path.join(root, 'src/technologies', file), 'utf8')));
  }
}
engine.setCategories(JSON.parse(fs.readFileSync(path.join(root, 'src/categories.json'), 'utf8')));
engine.setTechnologies(technologies);
const detections = engine.analyze(signals);
let resolved = engine.resolve(detections);
const analyzed = new Set(engine.technologies.map(({ name }) => name));
// Dependency-gated signatures wait until their required technology/category is
// detected. Iterate to resolve chains, matching each eligible signature once.
for (let pass = 0; pass < Object.keys(technologies).length; pass++) {
  const names = new Set(resolved.map(({ name }) => name));
  const categories = new Set(resolved.flatMap(({ categories }) => categories.map(({ id }) => id)));
  const eligible = [
    ...engine.requires.filter(({ name }) => names.has(name)).flatMap(({ technologies }) => technologies),
    ...engine.categoryRequires.filter(({ categoryId }) => categories.has(categoryId))
      .flatMap(({ technologies }) => technologies),
  ];
  const pending = [...new Map(eligible.map((tech) => [tech.name, tech])).values()]
    .filter(({ name }) => !analyzed.has(name));
  if (!pending.length) break;
  pending.forEach(({ name }) => analyzed.add(name));
  detections.push(...engine.analyze(signals, pending));
  resolved = engine.resolve(detections);
}
process.stdout.write(JSON.stringify({ technologies: resolved }) + '\n');
