const fs = require('fs');

const INPUT_FILE  = './requisitions_beauty.js';
const OUTPUT_FILE = 'script_desobfuscado.js';
const ARRAY_FILE  = './array_final.json';
const DICTIONARY_FILE = './decoded_formatted.json';
const OFFSET = 0x14f;

fs.readFileSync(ARRAY_FILE, 'utf-8');
const dicionario = JSON.parse(fs.readFileSync(ARRAY_FILE, 'utf-8'));
const STRINGS = dicionario;
const DICIONARIO = JSON.parse(fs.readFileSync(DICTIONARY_FILE, 'utf-8'));

let code = fs.readFileSync(INPUT_FILE, 'utf8');


code = code.replace(
  /_0x[a-f0-9]+\(\s*(0x[a-f0-9]+)\s*\)/gi,
  (match, hex) => {
    const index = parseInt(hex, 16) - OFFSET;
    const value = STRINGS[index];

    if (value === undefined) {
      // deixa como está se algo sair do range
      return match;
    }

    return JSON.stringify(value);
  }
);

for (const [key, value] of Object.entries(DICIONARIO)) {
  const search = JSON.stringify(key);
  const replacement = JSON.stringify(value);
  // Substitui todas as ocorrências da chave pelo valor
  code = code.split(search).join(replacement);
}


fs.writeFileSync(OUTPUT_FILE, code, 'utf8');

console.log(`[+] Arquivo desobfuscado salvo como ${OUTPUT_FILE}.`);