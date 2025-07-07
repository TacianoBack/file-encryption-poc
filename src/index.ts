import * as fs from 'fs';
import * as crypto from 'crypto';

function helloWorld(): void {
  console.log('Hello, World!');
}

// Função para criptografar um arquivo usando streams
export function encryptFile({
  inputPath,
  outputPath,
  password
}: {
  inputPath: string;
  outputPath: string;
  password: string;
}): Promise<void> {
  return new Promise((resolve, reject) => {
    const algorithm = 'aes-256-cbc';
    const key = crypto.scryptSync(password, 'salt', 32);
    const iv = crypto.randomBytes(16);

    const input = fs.createReadStream(inputPath);
    const output = fs.createWriteStream(outputPath);
    output.write(iv); // Escreve o IV no início do arquivo

    const cipher = crypto.createCipheriv(algorithm, key, iv);
    input.pipe(cipher).pipe(output);

    output.on('finish', resolve);
    output.on('error', reject);
    input.on('error', reject);
  });
}

helloWorld();

// Exemplo de uso da função encryptFile
const inputPath = './test-file.zip';
const outputPath = './test-file.zip.enc';
const password = 'senha-forte';

encryptFile({ inputPath, outputPath, password })
  .then(() => {
    console.log('Arquivo criptografado com sucesso:', outputPath);
  })
  .catch((err) => {
    console.error('Erro ao criptografar o arquivo:', err);
  });

