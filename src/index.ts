import * as fs from "fs";
import * as crypto from "crypto";
import * as dotenv from "dotenv";

dotenv.config();

// Função para gerar um salt aleatório
export function generateSalt(length: number = 16): Buffer {
  return crypto.randomBytes(length);
}

const SALT_LENGTH = 16;
const IV_LENGTH = 16;
const ALGORITHM = "aes-256-cbc";
const DEFAULT_PASSWORD = process.env.PASSWORD || "senha-forte";

// Função para criptografar um arquivo usando streams
export function encryptFile({
  inputPath,
  outputPath,
  password,
}: {
  inputPath: string;
  outputPath: string;
  password: string;
}): Promise<void> {
  return new Promise((resolve, reject) => {
    const salt = generateSalt(SALT_LENGTH);
    const iv = crypto.randomBytes(IV_LENGTH);
    const key = crypto.scryptSync(password, salt, 32);
    const input = fs.createReadStream(inputPath);
    const output = fs.createWriteStream(outputPath);
    // Escreve salt + IV no início do arquivo
    output.write(Buffer.concat([salt, iv]), (err) => {
      if (err) return reject(err);
      const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
      input.pipe(cipher).pipe(output, { end: true });
      output.on("finish", resolve);
      output.on("error", reject);
      input.on("error", reject);
    });
  });
}

// Função para descriptografar um arquivo usando streams
export function decryptFile({
  inputPath,
  outputPath,
  password,
}: {
  inputPath: string;
  outputPath: string;
  password: string;
}): Promise<void> {
  return new Promise((resolve, reject) => {
    const fd = fs.openSync(inputPath, "r");
    const salt = Buffer.alloc(SALT_LENGTH);
    const iv = Buffer.alloc(IV_LENGTH);
    fs.readSync(fd, salt, 0, SALT_LENGTH, 0);
    fs.readSync(fd, iv, 0, IV_LENGTH, SALT_LENGTH);
    fs.closeSync(fd);
    const key = crypto.scryptSync(password, salt, 32);
    const input = fs.createReadStream(inputPath, {
      start: SALT_LENGTH + IV_LENGTH,
    });
    const output = fs.createWriteStream(outputPath);
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    input.pipe(decipher).pipe(output);
    output.on("finish", resolve);
    output.on("error", reject);
    input.on("error", reject);
  });
}

function runEncrypt() {
  const inputPath = process.env.INPUT_FILE || "./test-file.zip";
  const outputPath = process.env.OUTPUT_FILE || "./test-file.zip.enc";

  return encryptFile({
    inputPath,
    outputPath,
    password: DEFAULT_PASSWORD,
  }).then(() => {
    console.log("Arquivo criptografado com sucesso:", outputPath);
  });
}

function runDecrypt() {
  const outputPath = process.env.OUTPUT_FILE || "./test-file.zip.enc";
  const decryptedOutputPath =
    process.env.DECRYPTED_FILE || "./test-file-decrypted.zip";
  return decryptFile({
    inputPath: outputPath,
    outputPath: decryptedOutputPath,
    password: DEFAULT_PASSWORD,
  }).then(() => {
    console.log("Arquivo descriptografado com sucesso:", decryptedOutputPath);
  });
}

if (String(process.env?.TEST) !== "true") {
  runEncrypt()
    .then(() => runDecrypt())
    .catch((err) => {
      console.error("Erro ao criptografar/descriptografar o arquivo:", err);
    });
}
