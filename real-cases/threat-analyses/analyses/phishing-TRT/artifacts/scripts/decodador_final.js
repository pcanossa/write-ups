const fs = require('fs');

const JSDeobfuscator = {
  // 1. Extrai os arrays de strings ofuscadas
  extractStringArrays: function(code) {
    const arrays = {};
    const arrayPattern = /function\s+(\w+)\s*\(\s*\)\s*{[\s\S]*?const\s+\w+\s*=\s*\[([^\]]+)\];[\s\S]*?return\s+\w+;/g;
    
    let match;
    while ((match = arrayPattern.exec(code)) !== null) {
      const funcName = match[1];
      const arrayContent = match[2];
      const strings = [];
      const stringPattern = /'([^']+)'|"([^"]+)"/g;
      
      let strMatch;
      while ((strMatch = stringPattern.exec(arrayContent)) !== null) {
        strings.push(strMatch[1] || strMatch[2]);
      }
      arrays[funcName] = strings;
    }
    return arrays;
  },

  // 2. Extrai funções de mapeamento
  extractMappingFunctions: function(code) {
    const mappings = {};
    const mapPattern = /function\s+(\w+)\s*\([^)]+\)\s*{[\s\S]*?(\w+)\s*=\s*(\w+)\s*-\s*(0x[\da-f]+);[\s\S]*?let\s+\w+\s*=\s*(\w+)\[(\w+)\];[\s\S]*?return\s+\w+;/g;
    
    let match;
    while ((match = mapPattern.exec(code)) !== null) {
      mappings[match[1]] = {
        arrayName: match[5],
        offset: parseInt(match[4], 16)
      };
    }
    return mappings;
  },

  // 3. Decodifica chamadas de função
  decodeFunctionCalls: function(code, arrays, mappings) {
    let decoded = code;
    Object.keys(mappings).forEach(funcName => {
      const mapping = mappings[funcName];
      const stringArray = arrays[mapping.arrayName];
      if (!stringArray) return;

      const callPattern = new RegExp(`${funcName}\\s*\\(\\s*(0x[\\da-f]+)\\s*\\)`, 'gi');
      decoded = decoded.replace(callPattern, (match, hexValue) => {
        const index = parseInt(hexValue, 16) - mapping.offset;
        if (index >= 0 && index < stringArray.length) {
          return `"${stringArray[index]}"`;
        }
        return match;
      });
    });
    return decoded;
  },

  // 4. Decodifica Base64 (Versão Node.js)
  decodeBase64Strings: function(code) {
    const base64Pattern = /'([A-Za-z0-9+/=]{20,})'/g;
    return code.replace(base64Pattern, (match, base64) => {
      try {
        const decoded = Buffer.from(base64, 'base64').toString('utf-8');
        if (/^[\x20-\x7E\s]*$/.test(decoded)) {
          return `"${decoded}" /* Base64 Decoded */`;
        }
      } catch (e) {}
      return match;
    });
  },

  // 5. Simplifica expressões
  simplifyExpressions: function(code) {
    let simplified = code.replace(/- -/g, '+');
    simplified = simplified.replace(/0x([0-9a-f])\b/gi, (match, hex) => {
      return parseInt(hex, 16).toString();
    });
    return simplified;
  },

  // 6. Limpa IIFE
  cleanIIFE: function(code) {
    return code.replace(/\(function\s*\(\)\s*{\s*}\)\(\);?/g, '');
  },

  // 7. Renomeia variáveis
  renameVariables: function(code) {
    const varMap = new Map();
    let counter = 0;
    const varPattern = /_0x[a-f0-9]{4,6}/g;
    const matches = code.match(varPattern);
    
    if (matches) {
      const uniqueVars = [...new Set(matches)];
      uniqueVars.forEach(varName => {
        varMap.set(varName, `var_${counter++}`);
      });
      
      varMap.forEach((newName, oldName) => {
        const regex = new RegExp(oldName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g');
        code = code.replace(regex, newName);
      });
    }
    return code;
  },

  // 8. Formatação
  formatCode: function(code) {
    let indentLevel = 0;
    const lines = [];
    let currentLine = '';
    
    for (let i = 0; i < code.length; i++) {
      const char = code[i];
      const nextChar = code[i + 1];
      
      if (char === '{') {
        currentLine += char;
        lines.push('  '.repeat(indentLevel) + currentLine.trim());
        currentLine = '';
        indentLevel++;
      } else if (char === '}') {
        if (currentLine.trim()) lines.push('  '.repeat(indentLevel) + currentLine.trim());
        indentLevel--;
        currentLine = char + (nextChar === ',' || nextChar === ';' ? code[++i] : '');
        lines.push('  '.repeat(indentLevel) + currentLine.trim());
        currentLine = '';
      } else if (char === ';' && nextChar !== '\n') {
        currentLine += char;
        lines.push('  '.repeat(indentLevel) + currentLine.trim());
        currentLine = '';
      } else if (char !== '\n') {
        currentLine += char;
      }
    }
    if (currentLine.trim()) lines.push('  '.repeat(indentLevel) + currentLine.trim());
    return lines.join('\n');
  },

  // Orquestrador
  run: function(inputCode) {
    const arrays = this.extractStringArrays(inputCode);
    const mappings = this.extractMappingFunctions(inputCode);
    
    let output = this.decodeFunctionCalls(inputCode, arrays, mappings);
    output = this.decodeBase64Strings(output);
    output = this.simplifyExpressions(output);
    output = this.cleanIIFE(output);
    output = this.renameVariables(output);
    return this.formatCode(output);
  }
};

// --- LOGICA DE EXECUÇÃO ---

const inputFile = './script_desobfuscado.js';
const outputFile = './script_final.js';

try {
  if (!fs.existsSync(inputFile)) {
    throw new Error(`Arquivo de entrada não encontrado: ${inputFile}`);
  }

  const obfuscatedCode = fs.readFileSync(inputFile, 'utf8');
  console.log(`[*] Analisando: ${inputFile}...`);
  
  const result = JSDeobfuscator.run(obfuscatedCode);
  
  fs.writeFileSync(outputFile, result);
  console.log(`[+] Sucesso! Código decodificado salvo em: ${outputFile}`);
} catch (err) {
  console.error(`[-] Erro ao processar o arquivo: ${err.message}`);
}